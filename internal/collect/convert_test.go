package collect

import (
	"bytes"
	"encoding/json"
	"testing"

	"adx/internal/analysis"
	"adx/internal/graph"
	"adx/internal/ingest"
)

// TestRoundTrip builds a collection from synthetic LDAP entries and feeds it
// through the GUI's own ingest + analysis, proving the output format is the one
// the app understands and that membership edges survive the trip.
func TestRoundTrip(t *testing.T) {
	dsid := "S-1-5-21-1"
	entries := []*entry{
		{dn: "DC=corp,DC=local", sid: dsid, kind: "domain", attrs: map[string][]string{
			"objectClass": {"domainDNS"}, "ms-DS-MachineAccountQuota": {"10"},
		}},
		{dn: "CN=JDOE,DC=corp,DC=local", sid: dsid + "-1001", kind: "user", attrs: map[string][]string{
			"objectClass": {"user"}, "sAMAccountName": {"JDOE"}, "userAccountControl": {"512"},
			"servicePrincipalName": {"HTTP/web"},
		}},
		{dn: "CN=ADMINS,DC=corp,DC=local", sid: dsid + "-512", kind: "group", attrs: map[string][]string{
			"objectClass": {"group"}, "sAMAccountName": {"DOMAIN ADMINS"},
			"member": {"CN=JDOE,DC=corp,DC=local"},
		}},
	}

	c := &converter{domainFQDN: "CORP.LOCAL", domainSID: dsid, byDN: map[string]*entry{}}
	for _, e := range entries {
		c.byDN[upper(e.dn)] = e
	}
	files := c.build(entries)

	g := graph.New()
	var st ingest.Stats
	for _, f := range files {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := ingest.LoadBytes(g, f.Meta["type"].(string)+".json", b, &st); err != nil {
			t.Fatalf("ingest %v: %v", f.Meta["type"], err)
		}
	}

	if len(g.Nodes) < 3 {
		t.Fatalf("want >=3 nodes, got %d", len(g.Nodes))
	}
	// JDOE must be a member of the admins group.
	if !g.HasEdge(dsid+"-1001", dsid+"-512", "MemberOf") {
		t.Fatalf("missing MemberOf edge JDOE -> DOMAIN ADMINS")
	}
	// hasspn should drive a kerberoast finding.
	m := analysis.Build(g)
	found := false
	for _, fnd := range m.Findings {
		if fnd.Technique == "kerberoast" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a kerberoast finding from the SPN user")
	}
}

func upper(s string) string { return string(bytes.ToUpper([]byte(s))) }
