package collect

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// AD CS lives in the Configuration partition, not the domain partition.
var adcsAttrs = []string{
	"cn", "name", "displayName", "objectGUID", "objectClass", "nTSecurityDescriptor",
	"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
	"pKIExtendedKeyUsage", "certificateTemplates", "dNSHostName",
}

// collectADCS pulls certificate templates and enterprise CAs from the
// Configuration partition. Returns empty if AD CS is not present or not readable.
func collectADCS(conn *ldap.Conn) []*entry {
	configNC := rootDSEValue(conn, "configurationNamingContext")
	if configNC == "" {
		return nil
	}
	base := "CN=Public Key Services,CN=Services," + configNC
	sdControl := ldap.NewControlString("1.2.840.113556.1.4.801", true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x07}))
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(objectClass=pKICertificateTemplate)(objectClass=pKIEnrollmentService))", adcsAttrs, []ldap.Control{sdControl})
	res, err := conn.SearchWithPaging(req, 500)
	if err != nil {
		return nil // AD CS absent or unreadable; not fatal
	}
	var out []*entry
	for _, le := range res.Entries {
		e := &entry{dn: le.DN, attrs: map[string][]string{}}
		for _, a := range le.Attributes {
			e.attrs[a.Name] = a.Values
		}
		e.guid = decodeGUID(le.GetRawAttributeValue("objectGUID"))
		e.sd = le.GetRawAttributeValue("nTSecurityDescriptor")
		classes := map[string]bool{}
		for _, c := range e.attrs["objectClass"] {
			classes[strings.ToLower(c)] = true
		}
		switch {
		case classes["pkicertificatetemplate"]:
			e.kind = "certtemplate"
		case classes["pkienrollmentservice"]:
			e.kind = "enterpriseca"
		default:
			continue
		}
		if e.guid != "" {
			out = append(out, e)
		}
	}
	return out
}

// schemaReadGUIDs resolves the per-forest schemaIDGUIDs of the LAPS and gMSA
// password attributes, so ACEs that read them become ReadLAPSPassword /
// ReadGMSAPassword edges. The LAPS GUID is not well-known; it must be looked up.
func schemaReadGUIDs(conn *ldap.Conn) map[string]string {
	schemaNC := rootDSEValue(conn, "schemaNamingContext")
	if schemaNC == "" {
		return nil
	}
	req := ldap.NewSearchRequest(schemaNC, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=ms-LAPS-Password)(lDAPDisplayName=ms-LAPS-EncryptedPassword)(lDAPDisplayName=ms-DS-ManagedPassword))",
		[]string{"lDAPDisplayName", "schemaIDGUID"}, nil)
	res, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range res.Entries {
		g := strings.ToLower(decodeGUID(e.GetRawAttributeValue("schemaIDGUID")))
		if g == "" {
			continue
		}
		name := strings.ToLower(e.GetAttributeValue("lDAPDisplayName"))
		if name == "ms-ds-managedpassword" {
			out[g] = "ReadGMSAPassword"
		} else {
			out[g] = "ReadLAPSPassword"
		}
	}
	return out
}

func rootDSEValue(conn *ldap.Conn, attr string) string {
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{attr}, nil))
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	return res.Entries[0].GetAttributeValue(attr)
}

// Client-authentication EKUs that make a template usable for authentication.
var clientAuthEKUs = map[string]bool{
	"1.3.6.1.5.5.7.3.2":      true, // Client Authentication
	"1.3.6.1.5.2.3.4":        true, // PKINIT Client Authentication
	"1.3.6.1.4.1.311.20.2.2": true, // Smart Card Logon
	"2.5.29.37.0":            true, // Any Purpose
}

// Certificate-name and enrollment flag bits (MS-CRTD).
const (
	ctEnrolleeSuppliesSubject = 0x00000001
	ctPendAllRequests         = 0x00000002
)
