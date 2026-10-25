package collect

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"adx/internal/analysis"
	"adx/internal/graph"
	"adx/internal/ingest"
)

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

// sidBytes builds the binary form of S-1-5-21-1-<rid>.
func sidBytes(rid uint32) []byte {
	b := []byte{1, 3, 0, 0, 0, 0, 0, 5} // rev=1, 3 subauths, authority 5
	b = append(b, le32(21)...)
	b = append(b, le32(1)...)
	b = append(b, le32(rid)...)
	return b
}

// allowedObjectACE builds an ACCESS_ALLOWED_OBJECT_ACE with one ObjectType GUID.
func allowedObjectACE(mask uint32, guid string, rid uint32) []byte {
	g := guidToBytes(guid)
	body := append(le32(mask), le32(0x1)...) // flags: ObjectType present
	body = append(body, g...)
	body = append(body, sidBytes(rid)...)
	size := 4 + len(body)
	ace := []byte{0x05, 0x00, byte(size), byte(size >> 8)}
	return append(ace, body...)
}

func allowedACE(mask uint32, rid uint32) []byte {
	body := append(le32(mask), sidBytes(rid)...)
	size := 4 + len(body)
	ace := []byte{0x00, 0x00, byte(size), byte(size >> 8)}
	return append(ace, body...)
}

// guidToBytes is the inverse of decodeGUID for the mixed-endian GUID form.
func guidToBytes(g string) []byte {
	// g like "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	hex := func(s string) []byte {
		out := make([]byte, len(s)/2)
		for i := 0; i < len(out); i++ {
			var v int
			for j := 0; j < 2; j++ {
				c := s[i*2+j]
				d := 0
				switch {
				case c >= '0' && c <= '9':
					d = int(c - '0')
				case c >= 'a' && c <= 'f':
					d = int(c-'a') + 10
				}
				v = v<<4 | d
			}
			out[i] = byte(v)
		}
		return out
	}
	p := [][]byte{hex(g[0:8]), hex(g[9:13]), hex(g[14:18]), hex(g[19:23]), hex(g[24:36])}
	b := make([]byte, 0, 16)
	// first three groups little-endian, last two big-endian
	b = append(b, p[0][3], p[0][2], p[0][1], p[0][0])
	b = append(b, p[1][1], p[1][0])
	b = append(b, p[2][1], p[2][0])
	b = append(b, p[3]...)
	b = append(b, p[4]...)
	return b
}

func buildACL(aces ...[]byte) []byte {
	var body []byte
	for _, a := range aces {
		body = append(body, a...)
	}
	size := 8 + len(body)
	acl := []byte{0x02, 0x00, byte(size), byte(size >> 8)}
	acl = append(acl, byte(len(aces)), byte(len(aces)>>8), 0, 0)
	return append(acl, body...)
}

// buildSD wraps a DACL into a security descriptor with the DACL at a known offset.
func buildSD(acl []byte) []byte {
	sd := make([]byte, 20)
	sd[0] = 1 // revision
	binary.LittleEndian.PutUint32(sd[16:20], 20) // DACL offset
	return append(sd, acl...)
}

func TestRightsMapping(t *testing.T) {
	// GenericAll via GENERIC_ALL bit.
	if got := rightsFor(rawACE{mask: rightGenericAll}, "group"); len(got) != 1 || got[0] != "GenericAll" {
		t.Fatalf("GenericAll: got %v", got)
	}
	// DCSync pair.
	gc := rightsFor(rawACE{mask: rightDSControl, objectType: guidGetChanges}, "domain")
	gca := rightsFor(rawACE{mask: rightDSControl, objectType: guidGetChangesAll}, "domain")
	if len(gc) != 1 || gc[0] != "GetChanges" || len(gca) != 1 || gca[0] != "GetChangesAll" {
		t.Fatalf("DCSync rights: %v %v", gc, gca)
	}
	// ForceChangePassword.
	if got := rightsFor(rawACE{mask: rightDSControl, objectType: guidForceChangePwd}, "user"); len(got) != 1 || got[0] != "ForceChangePassword" {
		t.Fatalf("FCP: %v", got)
	}
	// WriteDacl + WriteOwner from standard bits.
	got := rightsFor(rawACE{mask: rightWriteDacl | rightWriteOwner}, "user")
	if len(got) != 2 {
		t.Fatalf("WriteDacl/WriteOwner: %v", got)
	}
}

func TestParseSDEndToEnd(t *testing.T) {
	acl := buildACL(
		allowedObjectACE(rightDSControl, guidGetChanges, 1001),
		allowedObjectACE(rightDSControl, guidGetChangesAll, 1001),
		allowedACE(rightGenericAll, 1002),
	)
	c := &converter{sidType: map[string]string{}}
	e := &entry{kind: "domain", sd: buildSD(acl)}
	aces := c.aces(e)
	seen := map[string]bool{}
	for _, a := range aces {
		ao := a.(aceOut)
		seen[ao.RightName] = true
	}
	for _, want := range []string{"GetChanges", "GetChangesAll", "GenericAll"} {
		if !seen[want] {
			t.Fatalf("missing %s in parsed ACEs: %v", want, seen)
		}
	}
}

// TestDCSyncPipeline proves an SD with replication rights becomes a DCSync
// finding after the full collector -> ingest -> analysis path.
func TestDCSyncPipeline(t *testing.T) {
	dsid := "S-1-5-21-1"
	acl := buildACL(
		allowedObjectACE(rightDSControl, guidGetChanges, 1001),
		allowedObjectACE(rightDSControl, guidGetChangesAll, 1001),
	)
	entries := []*entry{
		{dn: "DC=corp,DC=local", sid: dsid, kind: "domain", sd: buildSD(acl),
			attrs: map[string][]string{"objectClass": {"domainDNS"}}},
		{dn: "CN=SVC,DC=corp,DC=local", sid: dsid + "-1001", kind: "user",
			attrs: map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"SVC_BACKUP"}, "userAccountControl": {"512"}}},
	}
	c := &converter{domainFQDN: "CORP.LOCAL", domainSID: dsid, byDN: map[string]*entry{}, sidType: map[string]string{}}
	for _, e := range entries {
		c.sidType[e.sid] = typeName(e.kind)
	}
	files := c.build(entries)

	g := graph.New()
	var st ingest.Stats
	for _, f := range files {
		b, _ := json.Marshal(f)
		if err := ingest.LoadBytes(g, f.Meta["type"].(string)+".json", b, &st); err != nil {
			t.Fatal(err)
		}
	}
	m := analysis.Build(g)
	for _, f := range m.Findings {
		if f.Technique == "dcsync" {
			return // success
		}
	}
	t.Fatalf("expected a DCSync finding from the replication-rights ACL")
}

// TestADCSAndRBCDPipeline proves a vulnerable template -> ESC1 finding and a
// computer with RBCD principals -> AllowedToAct edge.
func TestADCSAndRBCDPipeline(t *testing.T) {
	dsid := "S-1-5-21-1"
	// RBCD SD granting the helpdesk group (1005) the right to act on WEB.
	rbcd := buildSD(buildACL(allowedACE(rightGenericAll, 1005)))

	entries := []*entry{
		{dn: "DC=corp,DC=local", sid: dsid, kind: "domain", attrs: map[string][]string{"objectClass": {"domainDNS"}}},
		{dn: "CN=WEB,DC=corp,DC=local", sid: dsid + "-1100", kind: "computer", rbcd: rbcd,
			attrs: map[string][]string{"objectClass": {"computer"}, "sAMAccountName": {"WEB$"}, "userAccountControl": {"4096"}}},
		{dn: "CN=HELPDESK,DC=corp,DC=local", sid: dsid + "-1005", kind: "group",
			attrs: map[string][]string{"objectClass": {"group"}, "sAMAccountName": {"HELPDESK"}}},
		{dn: "CN=UserTemplate,CN=...,DC=corp,DC=local", guid: "11111111-2222-3333-4444-555555555555", kind: "certtemplate",
			attrs: map[string][]string{
				"objectClass": {"pKICertificateTemplate"}, "cn": {"UserTemplate"}, "displayName": {"UserTemplate"},
				"msPKI-Certificate-Name-Flag": {"1"}, "msPKI-Enrollment-Flag": {"0"}, "msPKI-RA-Signature": {"0"},
				"pKIExtendedKeyUsage": {"1.3.6.1.5.5.7.3.2"},
			}},
	}
	c := &converter{domainFQDN: "CORP.LOCAL", domainSID: dsid, byDN: map[string]*entry{}, sidType: map[string]string{}, tmplByCN: map[string]string{}}
	for _, e := range entries {
		if e.sid != "" {
			c.sidType[e.sid] = typeName(e.kind)
		}
	}
	files := c.build(entries)
	g := graph.New()
	var st ingest.Stats
	for _, f := range files {
		b, _ := json.Marshal(f)
		if err := ingest.LoadBytes(g, f.Meta["type"].(string)+".json", b, &st); err != nil {
			t.Fatal(err)
		}
	}
	if !g.HasEdge(dsid+"-1005", dsid+"-1100", "AllowedToAct") {
		t.Fatalf("missing RBCD AllowedToAct edge HELPDESK -> WEB")
	}
	m := analysis.Build(g)
	var esc1, rbcdF bool
	for _, f := range m.Findings {
		switch f.Technique {
		case "esc1":
			esc1 = true
		case "rbcd":
			rbcdF = true
		}
	}
	if !esc1 {
		t.Fatalf("expected an ESC1 finding from the vulnerable template")
	}
	if !rbcdF {
		t.Fatalf("expected an RBCD finding from the computer")
	}
}

// TestLAPSRead confirms a read ACE on a runtime-resolved LAPS GUID becomes a
// ReadLAPSPassword edge.
func TestLAPSRead(t *testing.T) {
	lapsGUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	c := &converter{sidType: map[string]string{}, readGUIDs: map[string]string{lapsGUID: "ReadLAPSPassword"}}
	acl := buildACL(allowedObjectACE(0x10, lapsGUID, 1115)) // ADS_RIGHT_DS_READ_PROP
	e := &entry{kind: "computer", sd: buildSD(acl)}
	var got bool
	for _, a := range c.aces(e) {
		if a.(aceOut).RightName == "ReadLAPSPassword" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected ReadLAPSPassword edge from LAPS read ACE")
	}
}
