// Package collect gathers Active Directory objects from a domain controller
// over LDAP and writes a SharpHound-compatible collection (the same JSON the
// adX GUI ingests). It runs remotely and leaves nothing on the target.
//
// This first version collects the object graph and group membership. ACL-based
// edges (GenericAll, DCSync, …), sessions and local admin come in later slices.
package collect

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

type Config struct {
	Domain   string // corp.local
	DC       string // host or IP of a domain controller
	User     string // sAMAccountName, UPN, or DOMAIN\user
	Password string
	Hash     string // NT hash (or LM:NT) for pass-the-hash
	NTLM     bool   // force NTLM bind with the password
	Ccache   string // Kerberos ccache path (pass-the-ticket / local)
	Kerberos bool   // Kerberos auth using the password
	Krb5Conf string // path to krb5.conf (generated if empty)
	LDAPS    bool
	Port     int
	Insecure bool // skip TLS certificate verification
	OutDir   string
}

// kind mirrors the object types the GUI understands.
type entry struct {
	dn    string
	sid   string
	guid  string
	kind  string // user, computer, group, domain, ou, gpo, container
	attrs map[string][]string
	sd    []byte // raw nTSecurityDescriptor
	rbcd  []byte // raw msDS-AllowedToActOnBehalfOfOtherIdentity
}

func (e *entry) first(a string) string {
	if v := e.attrs[a]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (e *entry) id() string {
	switch e.kind {
	case "ou", "gpo", "container", "certtemplate", "enterpriseca":
		return e.guid
	}
	return e.sid
}

const (
	uacDisabled      = 0x0002
	uacDontReqPreath = 0x400000
	uacTrustedDeleg  = 0x80000  // TRUSTED_FOR_DELEGATION (unconstrained)
	uacTrustedToAuth = 0x1000000 // TRUSTED_TO_AUTH_FOR_DELEGATION
)

var attrs = []string{
	"objectSid", "objectGUID", "sAMAccountName", "sAMAccountType", "distinguishedName",
	"objectClass", "userAccountControl", "servicePrincipalName", "member", "primaryGroupID",
	"operatingSystem", "dNSHostName", "msDS-AllowedToDelegateTo", "msDS-Behavior-Version",
	"ms-DS-MachineAccountQuota", "displayName", "description", "adminCount", "pwdLastSet",
	"lastLogonTimestamp", "whenCreated", "gPLink", "msDS-AllowedToActOnBehalfOfOtherIdentity",
	"nTSecurityDescriptor", "sIDHistory",
}

// Run performs the collection and writes a zip into cfg.OutDir.
func Run(cfg Config) (string, error) {
	conn, err := dial(cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	baseDN, domainFQDN, err := resolveBase(conn, cfg.Domain)
	if err != nil {
		return "", err
	}
	fmt.Printf("  bound to %s, base %s\n", cfg.DC, baseDN)

	entries, err := search(conn, baseDN)
	if err != nil {
		return "", err
	}
	fmt.Printf("  pulled %d objects\n", len(entries))

	if adcs := collectADCS(conn); len(adcs) > 0 {
		fmt.Printf("  pulled %d ADCS objects\n", len(adcs))
		entries = append(entries, adcs...)
	}

	readGUIDs := schemaReadGUIDs(conn)
	if len(readGUIDs) > 0 {
		fmt.Printf("  resolved %d LAPS/gMSA schema GUIDs\n", len(readGUIDs))
	}
	c := &converter{domainFQDN: strings.ToUpper(domainFQDN), byDN: map[string]*entry{}, sidType: map[string]string{}, tmplByCN: map[string]string{}, readGUIDs: readGUIDs}
	for _, e := range entries {
		if e.dn != "" {
			c.byDN[strings.ToUpper(e.dn)] = e
		}
		if e.sid != "" {
			c.sidType[e.sid] = typeName(e.kind)
		}
		if e.kind == "domain" {
			c.domainSID = e.sid
		}
		if e.kind == "certtemplate" {
			c.tmplByCN[strings.ToUpper(e.first("cn"))] = e.guid
		}
	}

	files := c.build(entries)
	return writeZip(cfg.OutDir, domainFQDN, files)
}

func dial(cfg Config) (*ldap.Conn, error) {
	port := cfg.Port
	scheme := "ldap"
	if cfg.LDAPS {
		scheme = "ldaps"
		if port == 0 {
			port = 636
		}
	} else if port == 0 {
		port = 389
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, cfg.DC, port)
	var conn *ldap.Conn
	var err error
	if cfg.LDAPS {
		conn, err = ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.Insecure, ServerName: cfg.DC}))
	} else {
		conn, err = ldap.DialURL(url)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", url, err)
	}
	conn.SetTimeout(30 * time.Second)
	if err := authenticate(conn, cfg); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func authenticate(conn *ldap.Conn, cfg Config) error {
	switch {
	case cfg.Ccache != "" || cfg.Kerberos:
		cl, err := krbClient(cfg)
		if err != nil {
			return fmt.Errorf("kerberos setup: %w", err)
		}
		if err := conn.GSSAPIBind(cl, "ldap/"+cfg.DC, ""); err != nil {
			return fmt.Errorf("Kerberos bind to ldap/%s failed: %w", cfg.DC, err)
		}
	case cfg.Hash != "":
		hash := cfg.Hash
		if i := strings.LastIndexByte(hash, ':'); i >= 0 { // LM:NT -> NT
			hash = hash[i+1:]
		}
		if err := conn.NTLMBindWithHash(cfg.Domain, ntlmUser(cfg), hash); err != nil {
			return fmt.Errorf("NTLM pass-the-hash as %q failed: %w", ntlmUser(cfg), err)
		}
	case cfg.NTLM:
		if err := conn.NTLMBind(cfg.Domain, ntlmUser(cfg), cfg.Password); err != nil {
			return fmt.Errorf("NTLM bind as %q failed: %w", ntlmUser(cfg), err)
		}
	default:
		if err := conn.Bind(bindName(cfg), cfg.Password); err != nil {
			return fmt.Errorf("bind as %q failed: %w", bindName(cfg), err)
		}
	}
	return nil
}

// krbClient builds a GSSAPI client from a ccache (pass-the-ticket / local) or
// from the password, generating a minimal krb5.conf when none is supplied.
func krbClient(cfg Config) (*gssapi.Client, error) {
	conf, err := krb5ConfPath(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Ccache != "" {
		return gssapi.NewClientFromCCache(cfg.Ccache, conf)
	}
	return gssapi.NewClientWithPassword(ntlmUser(cfg), strings.ToUpper(cfg.Domain), cfg.Password, conf)
}

func krb5ConfPath(cfg Config) (string, error) {
	if cfg.Krb5Conf != "" {
		return cfg.Krb5Conf, nil
	}
	if _, err := os.Stat("/etc/krb5.conf"); err == nil {
		return "/etc/krb5.conf", nil
	}
	if cfg.Domain == "" {
		return "", fmt.Errorf("need -d <domain> (or -krb5conf) for Kerberos")
	}
	realm := strings.ToUpper(cfg.Domain)
	tmp, err := os.CreateTemp("", "adx-krb5-*.conf")
	if err != nil {
		return "", err
	}
	fmt.Fprintf(tmp, "[libdefaults]\n default_realm = %s\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\n[realms]\n %s = {\n  kdc = %s\n }\n",
		realm, realm, cfg.DC)
	tmp.Close()
	return tmp.Name(), nil
}

// ntlmUser strips any domain/UPN decoration to a bare sAMAccountName.
func ntlmUser(cfg Config) string {
	u := cfg.User
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i >= 0 {
		u = u[:i]
	}
	return u
}

func bindName(cfg Config) string {
	if strings.ContainsAny(cfg.User, "@\\") {
		return cfg.User
	}
	if cfg.Domain != "" {
		return cfg.User + "@" + cfg.Domain
	}
	return cfg.User
}

// resolveBase finds the default naming context and FQDN from RootDSE, falling
// back to the configured domain.
func resolveBase(conn *ldap.Conn, domain string) (baseDN, fqdn string, err error) {
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err == nil && len(res.Entries) > 0 {
		baseDN = res.Entries[0].GetAttributeValue("defaultNamingContext")
	}
	if baseDN == "" && domain != "" {
		for _, p := range strings.Split(domain, ".") {
			baseDN += "dc=" + p + ","
		}
		baseDN = strings.TrimRight(baseDN, ",")
	}
	if baseDN == "" {
		return "", "", fmt.Errorf("could not determine base DN; pass -d domain.fqdn")
	}
	// FQDN from DN components.
	var parts []string
	for _, c := range strings.Split(baseDN, ",") {
		if strings.HasPrefix(strings.ToLower(c), "dc=") {
			parts = append(parts, c[3:])
		}
	}
	fqdn = strings.Join(parts, ".")
	if fqdn == "" {
		fqdn = domain
	}
	return baseDN, fqdn, nil
}

func search(conn *ldap.Conn, baseDN string) ([]*entry, error) {
	// LDAP_SERVER_SD_FLAGS_OID asks the DC to return owner + DACL of the
	// security descriptor without SACL, which an unprivileged user can read.
	sdControl := ldap.NewControlString("1.2.840.113556.1.4.801", true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x07}))
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", attrs, []ldap.Control{sdControl})
	res, err := conn.SearchWithPaging(req, 1000)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	out := make([]*entry, 0, len(res.Entries))
	for _, le := range res.Entries {
		e := &entry{dn: le.DN, attrs: map[string][]string{}}
		for _, a := range le.Attributes {
			e.attrs[a.Name] = a.Values
		}
		if raw := le.GetRawAttributeValue("objectSid"); len(raw) > 0 {
			e.sid = decodeSID(raw)
		}
		if raw := le.GetRawAttributeValue("objectGUID"); len(raw) > 0 {
			e.guid = decodeGUID(raw)
		}
		e.sd = le.GetRawAttributeValue("nTSecurityDescriptor")
		e.rbcd = le.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		e.kind = classify(e)
		if e.kind != "" {
			out = append(out, e)
		}
	}
	return out, nil
}

func classify(e *entry) string {
	classes := map[string]bool{}
	for _, c := range e.attrs["objectClass"] {
		classes[strings.ToLower(c)] = true
	}
	switch {
	case classes["computer"]:
		return "computer"
	case classes["grouppolicycontainer"]:
		return "gpo"
	case classes["organizationalunit"]:
		return "ou"
	case classes["domaindns"]:
		return "domain"
	case classes["group"]:
		return "group"
	case classes["user"]:
		return "user"
	case classes["container"]:
		return "container"
	}
	return ""
}

// --- binary decoders ---

func decodeSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	rev := b[0]
	subCount := int(b[1])
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(b[i])
	}
	sid := fmt.Sprintf("S-%d-%d", rev, authority)
	for i := 0; i < subCount && 8+i*4+4 <= len(b); i++ {
		sub := binary.LittleEndian.Uint32(b[8+i*4:])
		sid += "-" + strconv.FormatUint(uint64(sub), 10)
	}
	return strings.ToUpper(sid)
}

func decodeGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		be16(b[8:10]), b[10:16]))
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
