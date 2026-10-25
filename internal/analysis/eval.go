package analysis

import (
	"fmt"
	"sort"
	"strings"

	"adx/internal/graph"
)

type Status string

const (
	Now     Status = "now"     // reachable from owned without extra hops
	Entry   Status = "entry"   // an account to target: owning it opens a path to the crown jewels
	Reach   Status = "reach"   // reachable, but owned must first take some steps
	Blocked Status = "blocked" // no path from owned yet
)

// PathEdge is one hop in a rendered path.
type PathEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// EvalFinding is a finding scored against the current owned set.
type EvalFinding struct {
	*Finding
	Status    Status     `json:"status"`
	Path      []PathEdge `json:"path"`      // owned -> entry -> target
	Steps     int        `json:"hops"`      // non-free hops in Path (named "hops" to not clash with Finding.Steps)
	ToDomain  bool       `json:"toDomain"`  // target reaches a domain
	StepsToDA int        `json:"stepsToDA"` // steps all the way to a domain, if any
}

// Result is everything the UI needs for one owned set.
type Result struct {
	Owned        []string        `json:"owned"`
	StartLabel   string          `json:"startLabel"`
	Findings     []EvalFinding   `json:"findings"`
	NowCount     int             `json:"nowCount"`
	FastestID    string          `json:"fastestId"`
	FastestSteps int             `json:"fastestSteps"`
	Reachable    map[string]bool `json:"reachable"`
	Controlled   map[string]bool `json:"controlled"`
}

func edgesToPath(edges []*graph.Edge) []PathEdge {
	out := make([]PathEdge, 0, len(edges))
	for _, e := range edges {
		out = append(out, PathEdge{From: e.From, To: e.To, Kind: e.Kind})
	}
	return out
}

// Evaluate scores every finding from the owned principals.
func (m *Model) Evaluate(owned []string) *Result {
	norm := make([]string, 0, len(owned))
	for _, o := range owned {
		if _, ok := m.G.Nodes[graph.NormID(o)]; ok {
			norm = append(norm, graph.NormID(o))
		}
	}
	// With nothing owned, start from a standard domain foothold so the UI
	// answers the real question straight away: what can any authenticated user
	// reach? Marking an account owned switches to that account.
	start := norm
	startLabel := strings.Join(mapShort(m, norm), ", ")
	if len(start) == 0 {
		start = m.BroadPrincipals()
		startLabel = "any authenticated user"
	}
	controlled := m.G.MemberClosure(start) // start + their groups: held for free
	parent := m.G.BFS(start)               // everything reachable, with the hop in
	reachable := map[string]bool{}
	for k := range controlled {
		reachable[k] = true
	}
	for k := range parent {
		reachable[k] = true
	}

	res := &Result{Owned: norm, Reachable: reachable, Controlled: controlled, StartLabel: startLabel}
	res.Findings = make([]EvalFinding, 0, len(m.Findings))
	for _, f := range m.Findings {
		ev := EvalFinding{Finding: f}
		var prefix []*graph.Edge
		switch {
		case f.Entry == "" || controlled[f.Entry]:
			ev.Status = Now
		case reachable[f.Entry]:
			ev.Status = Reach
			prefix = graph.PathTo(parent, f.Entry)
		default:
			ev.Status = Blocked
		}
		// Intrinsic edges along the finding's own chain.
		var chainEdges []*graph.Edge
		for i := 0; i+1 < len(f.Chain); i++ {
			if e := m.edge(f.Chain[i], f.Chain[i+1]); e != nil {
				chainEdges = append(chainEdges, e)
			}
		}
		all := append(append([]*graph.Edge{}, prefix...), chainEdges...)
		ev.Path = edgesToPath(all)
		ev.Steps = graph.Steps(all)

		// Does the target reach a domain, and in how many steps total?
		if len(f.Chain) > 0 {
			target := f.Chain[len(f.Chain)-1]
			if m.node(target) != nil && m.node(target).Kind == graph.Domain {
				ev.ToDomain = true
				ev.StepsToDA = ev.Steps
			} else if e, ok := m.ToDomain[target]; ok {
				ev.ToDomain = true
				suffix := graph.PathFrom(m.ToDomain, target)
				ev.StepsToDA = ev.Steps + graph.Steps(suffix)
				_ = e
			}
		}
		res.Findings = append(res.Findings, ev)
	}

	// Inject shortest control paths from the foothold to the crown jewels.
	// This is the headline: the attack path the operator should take now.
	for _, t := range m.CrownTargets() {
		if controlled[t] {
			continue // already own it
		}
		if _, ok := parent[t]; !ok {
			continue // no path from the foothold
		}
		path := graph.PathTo(parent, t)
		if len(path) == 0 {
			continue
		}
		ev := EvalFinding{Finding: m.pathFinding(t, path, startLabel), Status: Now, Path: edgesToPath(path), Steps: graph.Steps(path), ToDomain: true, StepsToDA: graph.Steps(path)}
		res.Findings = append(res.Findings, ev)
	}

	// With nothing owned, answer "where do I start?": list the accounts whose
	// compromise opens a path to the crown jewels, nearest first.
	if len(norm) == 0 {
		crown := map[string]bool{}
		for _, t := range m.CrownTargets() {
			crown[t] = true
		}
		for id, n := range m.G.Nodes {
			if (n.Kind != graph.User && n.Kind != graph.Computer) || m.TierZero[id] || controlled[id] {
				continue
			}
			p := m.G.BFS([]string{id})
			best, bestTgt := -1, ""
			for t := range crown {
				if _, ok := p[t]; ok {
					if s := graph.Steps(graph.PathTo(p, t)); best == -1 || s < best {
						best, bestTgt = s, t
					}
				}
			}
			if best < 0 {
				continue
			}
			path := graph.PathTo(p, bestTgt)
			ev := EvalFinding{Finding: m.entryFinding(id, bestTgt, path), Status: Entry, Path: edgesToPath(path), Steps: best, ToDomain: true, StepsToDA: best}
			res.Findings = append(res.Findings, ev)
		}
	}

	statusRank := map[Status]int{Now: 0, Entry: 1, Reach: 2, Blocked: 3}
	pathRank := func(e EvalFinding) int {
		if e.Technique == "path" {
			return 0
		}
		return 1
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if statusRank[a.Status] != statusRank[b.Status] {
			return statusRank[a.Status] < statusRank[b.Status]
		}
		if pathRank(a) != pathRank(b) {
			return pathRank(a) < pathRank(b)
		}
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		return a.Steps < b.Steps
	})

	res.FastestSteps = 1 << 30
	for _, ev := range res.Findings {
		if ev.Status == Now {
			res.NowCount++
			// Only genuine compromise paths count as a route to the domain,
			// not enablers like MachineAccountQuota.
			if ev.ToDomain && ev.Severity != Med && ev.StepsToDA > 0 && ev.StepsToDA < res.FastestSteps {
				res.FastestSteps = ev.StepsToDA
				res.FastestID = ev.ID
			}
		}
	}
	if res.FastestID == "" {
		res.FastestSteps = 0
	}
	return res
}

func (m *Model) edge(from, to string) *graph.Edge {
	for _, e := range m.G.Out(from) {
		if e.To == to {
			return e
		}
	}
	return nil
}

func mapShort(m *Model, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.short(id))
	}
	return out
}

// BroadPrincipals are the groups every authenticated account effectively holds.
func (m *Model) BroadPrincipals() []string {
	var out []string
	for id := range m.G.Nodes {
		switch wellKnownSuffix(id) {
		case "S-1-5-11", "S-1-1-0":
			out = append(out, id)
			continue
		}
		if strings.HasPrefix(id, "S-1-5-21-") && rid(id) == "513" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// CrownTargets are the objects whose control ends the game: the domain and the
// built-in domain/enterprise admin groups.
func (m *Model) CrownTargets() []string {
	var out []string
	out = append(out, m.Domains...)
	for id, n := range m.G.Nodes {
		if n.Kind != graph.Group {
			continue
		}
		r := rid(id)
		if (strings.HasPrefix(id, "S-1-5-21-") && (r == "512" || r == "519")) || wellKnownSuffix(id) == "S-1-5-32-544" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

var hopVerb = map[string]string{
	"MemberOf": "is a member of", "Contains": "contains", "AdminTo": "is local admin on",
	"HasSession": "has a session to abuse on", "GenericAll": "has full control of",
	"GenericWrite": "can write properties of", "WriteDacl": "can rewrite the DACL of",
	"WriteOwner": "can take ownership of", "Owns": "owns", "AllExtendedRights": "has all extended rights over",
	"ForceChangePassword": "can reset the password of", "AddMember": "can add members to",
	"AddSelf": "can add itself to", "AddKeyCredentialLink": "can add shadow credentials to",
	"ReadLAPSPassword": "can read the LAPS password of", "ReadGMSAPassword": "can read the gMSA password of",
	"CanRDP": "can RDP to", "CanPSRemote": "can PSRemote to", "ExecuteDCOM": "can DCOM to",
	"SQLAdmin": "is SQL admin on", "WriteSPN": "can set an SPN on", "DCSync": "can DCSync",
	"CoerceToTGT": "can coerce a TGT from", "ADCSESC1": "can ESC1 against", "DomainAdmin": "is admin of",
	"AllowedToAct": "can RBCD against", "AllowedToDelegate": "can delegate to", "HasSIDHistory": "has SID history of",
}

func verb(kind string) string {
	if v, ok := hopVerb[kind]; ok {
		return v
	}
	return kind + " →"
}

func (m *Model) pathFinding(target string, path []*graph.Edge, startLabel string) *Finding {
	tgt := m.short(target)
	chain := []string{}
	if len(path) > 0 {
		chain = append(chain, path[0].From)
		for _, e := range path {
			chain = append(chain, e.To)
		}
	}
	steps := make([]string, 0, len(path))
	for _, e := range path {
		steps = append(steps, fmt.Sprintf("%s %s %s", m.short(e.From), verb(e.Kind), m.short(e.To)))
	}
	return &Finding{
		ID: "path:" + target, Technique: "path", Severity: Crit,
		Title: "Path to " + tgt, Anchor: target, Entry: "",
		Chain: chain,
		Why:   fmt.Sprintf("From %s there is a %d-step control path to %s. Each hop is an abusable right or membership; click the nodes to see the technique for each.", startLabel, graph.Steps(path), tgt),
		Steps: steps,
		Impact: "Full control of " + tgt + ". Game over for the domain.",
		Commands: Commands{},
	}
}

func (m *Model) entryFinding(src, target string, path []*graph.Edge) *Finding {
	from, tgt := m.short(src), m.short(target)
	chain := []string{}
	if len(path) > 0 {
		chain = append(chain, path[0].From)
		for _, e := range path {
			chain = append(chain, e.To)
		}
	}
	steps := make([]string, 0, len(path)+1)
	steps = append(steps, "Get initial access as "+from+" (phish, password spray, creds, a service exploit…).")
	for _, e := range path {
		steps = append(steps, fmt.Sprintf("%s %s %s", m.short(e.From), verb(e.Kind), m.short(e.To)))
	}
	return &Finding{
		ID: "entry:" + src, Technique: "entrypoint", Severity: Crit,
		Title: "Compromise " + from + " → " + tgt, Anchor: src, Entry: src,
		Chain: chain,
		Why:   fmt.Sprintf("%s is not reachable from a standard domain user, but owning it gives a %d-step path to %s. A high-value target for initial access. Mark it owned once you have it.", from, graph.Steps(path), tgt),
		Steps: steps,
		Impact: "A foothold on " + from + " leads to full control of " + tgt + ".",
		Commands: Commands{},
	}
}
