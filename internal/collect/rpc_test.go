package collect

import (
	"encoding/json"
	"testing"

	"adx/internal/graph"
	"adx/internal/ingest"
)

// TestRPCEdges: local-group members on a computer become AdminTo / CanRDP /
// CanPSRemote edges after the collector -> ingest round-trip.
func TestRPCEdges(t *testing.T) {
	dsid := "S-1-5-21-7"
	c := &converter{domainFQDN: "CORP.LOCAL", domainSID: dsid, byDN: map[string]*entry{},
		sidType: map[string]string{dsid + "-1105": "User"}, tmplByCN: map[string]string{}}
	comp := &entry{sid: dsid + "-1000", kind: "computer",
		attrs:    map[string][]string{"objectClass": {"computer"}, "sAMAccountName": {"DC$"}},
		admins:   []string{dsid + "-512"},
		rdp:      []string{dsid + "-1105"},
		psremote: []string{dsid + "-1105"},
	}
	files := c.build([]*entry{comp})
	g := graph.New()
	var st ingest.Stats
	for _, f := range files {
		b, _ := json.Marshal(f)
		if err := ingest.LoadBytes(g, f.Meta["type"].(string)+".json", b, &st); err != nil {
			t.Fatal(err)
		}
	}
	checks := []struct{ from, kind string }{
		{dsid + "-512", "AdminTo"}, {dsid + "-1105", "CanRDP"}, {dsid + "-1105", "CanPSRemote"},
	}
	for _, c := range checks {
		if !g.HasEdge(c.from, dsid+"-1000", c.kind) {
			t.Fatalf("missing %s edge %s -> DC", c.kind, c.from)
		}
	}
}
