// Package analysis turns the raw graph into attack findings: it derives the
// edges SharpHound does not emit (DCSync, CoerceToTGT, ESC1), marks tier zero,
// runs the detection rules and ranks findings against the owned principals.
package analysis

import (
	"sort"
	"strings"

	"adx/internal/graph"
)

type Model struct {
	G        *graph.Graph
	TierZero map[string]bool
	Domains  []string
	ToDomain map[string]*graph.Edge
	Findings []*Finding

	domainByName map[string]string
	domainBySID  map[string]string
	dcByDomain   map[string]string
}

// Well-known SIDs that SharpHound prefixes with the domain name.
var wellKnown = map[string]string{
	"S-1-5-11": "AUTHENTICATED USERS", "S-1-1-0": "EVERYONE", "S-1-5-32-544": "ADMINISTRATORS",
	"S-1-5-32-545": "USERS", "S-1-5-32-548": "ACCOUNT OPERATORS", "S-1-5-32-549": "SERVER OPERATORS",
	"S-1-5-32-550": "PRINT OPERATORS", "S-1-5-32-551": "BACKUP OPERATORS", "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
	"S-1-5-18": "LOCAL SYSTEM", "S-1-3-0": "CREATOR OWNER", "S-1-5-10": "PRINCIPAL SELF",
}

var tierZeroRIDs = map[string]bool{"512": true, "516": true, "518": true, "519": true, "526": true, "527": true, "498": true, "502": true}
var tierZeroWellKnown = map[string]bool{"S-1-5-32-544": true, "S-1-5-32-548": true, "S-1-5-32-549": true, "S-1-5-32-550": true, "S-1-5-32-551": true, "S-1-5-9": true, "S-1-5-18": true}

func rid(id string) string {
	if i := strings.LastIndexByte(id, '-'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// wellKnownSuffix returns "S-1-5-11" for "CORP.LOCAL-S-1-5-11".
func wellKnownSuffix(id string) string {
	if i := strings.Index(id, "-S-1-"); i >= 0 {
		return id[i+1:]
	}
	return ""
}

// Broad reports whether every authenticated user effectively holds this group.
func Broad(id string) bool {
	switch wellKnownSuffix(id) {
	case "S-1-5-11", "S-1-1-0", "S-1-5-32-545":
		return true
	}
	if strings.HasPrefix(id, "S-1-5-21-") {
		r := rid(id)
		return r == "513" || r == "515"
	}
	return false
}

func Build(g *graph.Graph) *Model {
	m := &Model{G: g, TierZero: map[string]bool{}, domainByName: map[string]string{}, domainBySID: map[string]string{}, dcByDomain: map[string]string{}}
	m.indexDomains()
	m.nameWellKnown()
	m.implicitMembership()
	m.markDCs()
	m.deriveEdges()
	m.markTierZero()
	m.ToDomain = g.ReverseBFS(m.Domains)
	m.detect()
	return m
}

func (m *Model) indexDomains() {
	for id, n := range m.G.Nodes {
		if n.Kind == graph.Domain {
			m.Domains = append(m.Domains, id)
			m.domainByName[n.Name] = id
			m.domainBySID[id] = id
		}
	}
	sort.Strings(m.Domains)
}

// DomainOf finds the domain node an object belongs to.
func (m *Model) DomainOf(n *graph.Node) string {
	if d, ok := m.domainByName[n.Domain]; ok {
		return d
	}
	if i := strings.LastIndexByte(n.ID, '-'); i > 0 {
		if d, ok := m.domainBySID[n.ID[:i]]; ok {
			return d
		}
	}
	if i := strings.Index(n.ID, "-S-1-"); i > 0 {
		if d, ok := m.domainByName[n.ID[:i]]; ok {
			return d
		}
	}
	if len(m.Domains) == 1 {
		return m.Domains[0]
	}
	return ""
}

func (m *Model) nameWellKnown() {
	for id, n := range m.G.Nodes {
		if n.Name != "" {
			continue
		}
		if s := wellKnownSuffix(id); s != "" {
			if name, ok := wellKnown[s]; ok {
				n.Name = name + "@" + id[:strings.Index(id, "-S-1-")]
				if n.Kind == graph.Base {
					n.Kind = graph.Group
				}
			}
		}
	}
}

// implicitMembership adds the memberships AD grants without storing them:
// every account is in Authenticated Users and Everyone.
func (m *Model) implicitMembership() {
	for id, n := range m.G.Nodes {
		if n.Kind != graph.User && n.Kind != graph.Computer {
			continue
		}
		dom := n.Domain
		if dom == "" {
			if d := m.DomainOf(n); d != "" {
				dom = m.G.Nodes[d].Name
			}
		}
		for _, s := range []string{"S-1-5-11", "S-1-1-0"} {
			gid := dom + "-" + s
			if _, ok := m.G.Nodes[gid]; ok {
				m.synthetic(id, gid, "MemberOf")
			}
		}
	}
}

func (m *Model) synthetic(from, to, kind string) {
	from, to = graph.NormID(from), graph.NormID(to)
	if from == "" || to == "" || from == to || m.G.HasEdge(from, to, kind) {
		return
	}
	if e := m.G.AddEdge(from, to, kind, false); e != nil {
		e.Synthetic = true
	}
}

func (m *Model) IsDC(n *graph.Node) bool {
	if n.Kind != graph.Computer {
		return false
	}
	if n.Bool("isdc") {
		return true
	}
	for _, e := range m.G.Out(n.ID) {
		if e.Kind == "MemberOf" && rid(e.To) == "516" {
			return true
		}
	}
	return false
}

func (m *Model) markDCs() {
	ids := make([]string, 0)
	for id, n := range m.G.Nodes {
		if m.IsDC(n) {
			n.Props["isdc"] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := m.G.Nodes[id]
		if d := m.DomainOf(n); d != "" {
			if _, ok := m.dcByDomain[d]; !ok {
				m.dcByDomain[d] = id
			}
			m.synthetic(id, d, "DCSync")
		}
	}
}

func (m *Model) deriveEdges() {
	g := m.G
	for _, d := range m.Domains {
		// DCSync needs both replication rights; they often come from different ACEs.
		rights := map[string]map[string]bool{}
		for _, e := range g.In(d) {
			if e.Kind == "GetChanges" || e.Kind == "GetChangesAll" {
				if rights[e.From] == nil {
					rights[e.From] = map[string]bool{}
				}
				rights[e.From][e.Kind] = true
			}
		}
		for p, r := range rights {
			if r["GetChanges"] && r["GetChangesAll"] {
				m.synthetic(p, d, "DCSync")
			}
		}
		// Admin groups own the domain whether or not their ACE was collected.
		dn := g.Nodes[d]
		for _, gid := range []string{d + "-512", d + "-519", dn.Name + "-S-1-5-32-544"} {
			if _, ok := g.Nodes[gid]; ok {
				m.synthetic(gid, d, "DomainAdmin")
			}
		}
	}
	for id, n := range g.Nodes {
		switch n.Kind {
		case graph.Computer:
			if n.Bool("unconstraineddelegation") && !n.Bool("isdc") && enabled(n) {
				if d := m.DomainOf(n); d != "" {
					m.synthetic(id, d, "CoerceToTGT")
				}
			}
		case graph.CertTemplate:
			if m.esc1(n) {
				if d := m.DomainOf(n); d != "" {
					m.synthetic(id, d, "ADCSESC1")
				}
			}
		}
	}
}

func enabled(n *graph.Node) bool {
	v, ok := n.Props["enabled"].(bool)
	return !ok || v
}

func (m *Model) esc1(t *graph.Node) bool {
	if !t.Bool("enrolleesuppliessubject") || t.Bool("requiresmanagerapproval") {
		return false
	}
	if sig, ok := t.Int("authorizedsignatures"); ok && sig > 0 {
		return false
	}
	if _, ok := t.Props["authenticationenabled"]; ok {
		if !t.Bool("authenticationenabled") {
			return false
		}
	} else if !clientAuthEKU(t) {
		return false
	}
	// When CAs were collected, the template must be published on one.
	hasCA := false
	for _, n := range m.G.Nodes {
		if n.Kind == graph.EnterpriseCA {
			hasCA = true
			break
		}
	}
	if hasCA {
		for _, e := range m.G.Out(t.ID) {
			if e.Kind == "PublishedTo" {
				return true
			}
		}
		return false
	}
	return true
}

var authEKUs = map[string]bool{
	"1.3.6.1.5.5.7.3.2": true, "1.3.6.1.5.2.3.4": true, "1.3.6.1.4.1.311.20.2.2": true, "2.5.29.37.0": true,
}

func clientAuthEKU(t *graph.Node) bool {
	for _, key := range []string{"effectiveekus", "ekus"} {
		list, ok := t.Props[key].([]any)
		if !ok {
			continue
		}
		if len(list) == 0 {
			return true
		}
		for _, v := range list {
			if s, _ := v.(string); authEKUs[s] {
				return true
			}
		}
	}
	return false
}

func (m *Model) markTierZero() {
	g := m.G
	queue := []string{}
	add := func(id string) {
		if !m.TierZero[id] {
			m.TierZero[id] = true
			queue = append(queue, id)
		}
	}
	for id, n := range g.Nodes {
		switch {
		case n.Kind == graph.Domain, n.Bool("isdc"), n.Bool("highvalue"), n.Bool("isTierZero"):
			add(id)
		case strings.HasPrefix(id, "S-1-5-21-") && tierZeroRIDs[rid(id)]:
			add(id)
		case tierZeroWellKnown[wellKnownSuffix(id)]:
			add(id)
		}
	}
	// Members of tier-zero groups are tier zero.
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, e := range g.In(id) {
			if e.Kind == "MemberOf" && !Broad(e.From) {
				add(e.From)
			}
		}
	}
}

// DCName returns a DC host name for commands.
func (m *Model) DCName(domain string) string {
	if dc, ok := m.dcByDomain[domain]; ok {
		return strings.ToLower(m.G.Nodes[dc].Name)
	}
	return "<dc-fqdn>"
}
