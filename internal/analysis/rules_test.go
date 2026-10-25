package analysis

import (
	"strings"
	"testing"

	"adx/internal/graph"
)

// TestComputerTakeoverCard: GenericAll over a DC computer yields an RBCD /
// shadow-cred takeover card and a path to the domain.
func TestComputerTakeoverCard(t *testing.T) {
	dsid := "S-1-5-21-9"
	g := graph.New()
	g.Upsert(&graph.Node{ID: dsid, Kind: graph.Domain, Name: "CORP.LOCAL", Domain: "CORP.LOCAL", Props: map[string]any{"name": "CORP.LOCAL"}})
	g.Upsert(&graph.Node{ID: dsid + "-1000", Kind: graph.User, Name: "BOB@CORP.LOCAL", Domain: "CORP.LOCAL", Props: map[string]any{"name": "BOB@CORP.LOCAL", "enabled": true}})
	g.Upsert(&graph.Node{ID: dsid + "-1001", Kind: graph.Computer, Name: "DC01.CORP.LOCAL", Domain: "CORP.LOCAL", Props: map[string]any{"name": "DC01.CORP.LOCAL", "isdc": true, "enabled": true}})
	g.AddEdge(dsid+"-1000", dsid+"-1001", "GenericAll", false)

	m := Build(g)
	var card *Finding
	for _, f := range m.Findings {
		if f.Technique == "rbcd" && strings.HasPrefix(f.Title, "Computer takeover") {
			card = f
		}
	}
	if card == nil {
		t.Fatalf("expected a computer-takeover card; got %v", titles(m.Findings))
	}
	joined := ""
	for _, c := range card.Commands.Linux {
		joined += c.Code + "\n"
	}
	if !strings.Contains(joined, "rbcd.py") || !strings.Contains(joined, "certipy shadow") {
		t.Fatalf("takeover card missing RBCD/shadow commands:\n%s", joined)
	}
	if !strings.Contains(card.Impact, "Domain Admin") {
		t.Fatalf("DC takeover should map to Domain Admin, got %q", card.Impact)
	}

	// Owning BOB should reach the domain.
	res := m.Evaluate([]string{dsid + "-1000"})
	var pathToDomain bool
	for _, ev := range res.Findings {
		if ev.Technique == "path" && ev.Status == Now {
			pathToDomain = true
		}
	}
	if !pathToDomain {
		t.Fatalf("expected a now-path to the domain from BOB")
	}
}

func titles(fs []*Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}
