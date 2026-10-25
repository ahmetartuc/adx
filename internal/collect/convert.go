package collect

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type converter struct {
	domainFQDN string
	domainSID  string
	byDN       map[string]*entry
	sidType    map[string]string
	tmplByCN   map[string]string // cert template CN (upper) -> GUID
	readGUIDs  map[string]string // schema GUID -> ReadLAPSPassword / ReadGMSAPassword
}

type outObj struct {
	ObjectIdentifier  string           `json:"ObjectIdentifier"`
	Properties        map[string]any   `json:"Properties"`
	Aces              []any            `json:"Aces"`
	Members           []ref            `json:"Members,omitempty"`
	PrimaryGroupSID      string `json:"PrimaryGroupSID,omitempty"`
	AllowedToDelegate    []ref  `json:"AllowedToDelegate,omitempty"`
	AllowedToAct         []ref  `json:"AllowedToAct,omitempty"`
	ChildObjects         []ref  `json:"ChildObjects,omitempty"`
	EnabledCertTemplates []ref  `json:"EnabledCertTemplates,omitempty"`
	IsDC                 bool   `json:"IsDC,omitempty"`
}

type ref struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type outFile struct {
	Meta map[string]any `json:"meta"`
	Data []*outObj      `json:"data"`
}

// build groups converted objects by type.
func (c *converter) build(entries []*entry) map[string]*outFile {
	files := map[string]*outFile{}
	add := func(typ string, o *outObj) {
		f := files[typ]
		if f == nil {
			f = &outFile{Meta: map[string]any{"type": typ, "version": 5}, Data: []*outObj{}}
			files[typ] = f
		}
		f.Data = append(f.Data, o)
	}
	for _, e := range entries {
		o := c.convert(e)
		if o == nil {
			continue
		}
		switch e.kind {
		case "user":
			add("users", o)
		case "computer":
			add("computers", o)
		case "group":
			add("groups", o)
		case "domain":
			add("domains", o)
		case "ou":
			add("ous", o)
		case "gpo":
			add("gpos", o)
		case "container":
			add("containers", o)
		case "certtemplate":
			add("certtemplates", o)
		case "enterpriseca":
			add("enterprisecas", o)
		}
	}
	for _, f := range files {
		f.Meta["count"] = len(f.Data)
	}
	return files
}

func (c *converter) convert(e *entry) *outObj {
	id := e.id()
	if id == "" {
		return nil
	}
	props := map[string]any{"domain": c.domainFQDN, "distinguishedname": strings.ToUpper(e.dn)}
	if c.domainSID != "" {
		props["domainsid"] = c.domainSID
	}
	setIf(props, "description", e.first("description"))
	setIf(props, "displayname", e.first("displayName"))
	if w := e.first("whenCreated"); w != "" {
		props["whencreated"] = w
	}
	o := &outObj{ObjectIdentifier: id, Properties: props, Aces: []any{}}

	uac, _ := strconv.Atoi(e.first("userAccountControl"))
	sam := e.first("sAMAccountName")

	switch e.kind {
	case "user", "computer":
		props["enabled"] = uac&uacDisabled == 0
		if e.first("userAccountControl") != "" {
			props["unconstraineddelegation"] = uac&uacTrustedDeleg != 0
			props["trustedtoauth"] = uac&uacTrustedToAuth != 0
			props["dontreqpreauth"] = uac&uacDontReqPreath != 0
		}
		props["admincount"] = e.first("adminCount") == "1"
		spns := e.attrs["servicePrincipalName"]
		props["hasspn"] = len(spns) > 0
		if len(spns) > 0 {
			props["serviceprincipalnames"] = spns
		}
		if pg := e.first("primaryGroupID"); pg != "" && c.domainSID != "" {
			o.PrimaryGroupSID = c.domainSID + "-" + pg
		}
		for _, dn := range e.attrs["msDS-AllowedToDelegateTo"] {
			_ = dn // SPN targets; resolved in a later slice
		}
		if e.kind == "computer" {
			props["name"] = c.computerName(e)
			props["operatingsystem"] = e.first("operatingSystem")
			o.IsDC = isDC(e)
			o.AllowedToAct = c.rbcdPrincipals(e) // msDS-AllowedToActOnBehalfOfOtherIdentity
		} else {
			props["name"] = strings.ToUpper(sam) + "@" + c.domainFQDN
		}
	case "group":
		props["name"] = strings.ToUpper(sam) + "@" + c.domainFQDN
		props["admincount"] = e.first("adminCount") == "1"
		o.Members = c.resolveRefs(e.attrs["member"])
	case "domain":
		props["name"] = c.domainFQDN
		if q := e.first("ms-DS-MachineAccountQuota"); q != "" {
			if n, err := strconv.Atoi(q); err == nil {
				props["machineaccountquota"] = n
			}
		}
		if lvl := e.first("msDS-Behavior-Version"); lvl != "" {
			props["functionallevel"] = lvl
		}
	case "ou":
		props["name"] = ouName(e, c.domainFQDN)
	case "gpo":
		props["name"] = strings.ToUpper(e.first("displayName")) + "@" + c.domainFQDN
	case "container":
		props["name"] = strings.ToUpper(sam) + "@" + c.domainFQDN
	case "certtemplate":
		c.certTemplate(e, props)
	case "enterpriseca":
		name := e.first("dNSHostName")
		if name == "" {
			name = e.first("name")
		}
		props["name"] = strings.ToUpper(name) + "@" + c.domainFQDN
		for _, cn := range e.attrs["certificateTemplates"] {
			if g := c.tmplByCN[strings.ToUpper(cn)]; g != "" {
				o.EnabledCertTemplates = append(o.EnabledCertTemplates, ref{ObjectIdentifier: g, ObjectType: "CertTemplate"})
			}
		}
	}
	o.Aces = c.aces(e)
	return o
}

// certTemplate maps the ESC-relevant template attributes.
func (c *converter) certTemplate(e *entry, props map[string]any) {
	disp := e.first("displayName")
	if disp == "" {
		disp = e.first("cn")
	}
	props["name"] = strings.ToUpper(disp) + "@" + c.domainFQDN
	nameFlag := atoiSafe(e.first("msPKI-Certificate-Name-Flag"))
	enrollFlag := atoiSafe(e.first("msPKI-Enrollment-Flag"))
	props["enrolleesuppliessubject"] = nameFlag&ctEnrolleeSuppliesSubject != 0
	props["requiresmanagerapproval"] = enrollFlag&ctPendAllRequests != 0
	props["authorizedsignatures"] = atoiSafe(e.first("msPKI-RA-Signature"))
	ekus := e.attrs["pKIExtendedKeyUsage"]
	auth := len(ekus) == 0
	for _, oid := range ekus {
		if clientAuthEKUs[oid] {
			auth = true
		}
	}
	props["authenticationenabled"] = auth
	if len(ekus) > 0 {
		props["ekus"] = ekus
	}
}

// rbcdPrincipals parses msDS-AllowedToActOnBehalfOfOtherIdentity (a security
// descriptor) into the principals allowed to act — i.e. RBCD sources.
func (c *converter) rbcdPrincipals(e *entry) []ref {
	if len(e.rbcd) < 20 {
		return nil
	}
	_, daclOff := parseSDHeader(e.rbcd)
	if daclOff == 0 || int(daclOff)+8 > len(e.rbcd) {
		return nil
	}
	var out []ref
	for _, a := range parseACL(e.rbcd[daclOff:]) {
		out = append(out, ref{ObjectIdentifier: a.sid, ObjectType: c.ptype(a.sid)})
	}
	return out
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// resolveRefs turns member DNs into typed references via the DN index.
func (c *converter) resolveRefs(dns []string) []ref {
	var out []ref
	for _, dn := range dns {
		if e, ok := c.byDN[strings.ToUpper(dn)]; ok && e.id() != "" {
			out = append(out, ref{ObjectIdentifier: e.id(), ObjectType: typeName(e.kind)})
		}
	}
	return out
}

func (c *converter) computerName(e *entry) string {
	if h := e.first("dNSHostName"); h != "" {
		return strings.ToUpper(h)
	}
	return strings.ToUpper(strings.TrimSuffix(e.first("sAMAccountName"), "$")) + "." + c.domainFQDN
}

func isDC(e *entry) bool {
	// UAC SERVER_TRUST_ACCOUNT (0x2000) marks a domain controller.
	uac, _ := strconv.Atoi(e.first("userAccountControl"))
	return uac&0x2000 != 0
}

func ouName(e *entry, domain string) string {
	for _, c := range strings.Split(e.dn, ",") {
		if strings.HasPrefix(strings.ToLower(c), "ou=") {
			return strings.ToUpper(c[3:]) + "@" + domain
		}
	}
	return strings.ToUpper(e.first("name")) + "@" + domain
}

func typeName(kind string) string {
	switch kind {
	case "user":
		return "User"
	case "computer":
		return "Computer"
	case "group":
		return "Group"
	case "domain":
		return "Domain"
	case "ou":
		return "OU"
	case "gpo":
		return "GPO"
	case "container":
		return "Container"
	case "certtemplate":
		return "CertTemplate"
	case "enterpriseca":
		return "EnterpriseCA"
	}
	return "Base"
}

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// writeZip writes one JSON file per type and zips them, SharpHound-style.
func writeZip(outDir, domain string, files map[string]*outFile) (string, error) {
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	stamp := time.Now().Format("20060102150405")
	zipPath := filepath.Join(outDir, fmt.Sprintf("%s_%s_adx.zip", stamp, strings.ToLower(domain)))
	zf, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	for typ, f := range files {
		w, err := zw.Create(fmt.Sprintf("%s_%s.json", stamp, typ))
		if err != nil {
			return "", err
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		if err := enc.Encode(f); err != nil {
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return zipPath, nil
}
