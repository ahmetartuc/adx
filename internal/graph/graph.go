// Package graph holds the in-memory Active Directory graph. There is no
// database: every node and edge lives in maps and slices, and path queries are
// plain breadth-first searches.
package graph

import (
	"strings"
)

type Kind string

const (
	Base         Kind = "Base"
	User         Kind = "User"
	Group        Kind = "Group"
	Computer     Kind = "Computer"
	Domain       Kind = "Domain"
	GPO          Kind = "GPO"
	OU           Kind = "OU"
	Container    Kind = "Container"
	CertTemplate Kind = "CertTemplate"
	EnterpriseCA Kind = "EnterpriseCA"
)

type Node struct {
	ID     string         `json:"id"`
	Kind   Kind           `json:"kind"`
	Name   string         `json:"name"`
	Domain string         `json:"domain,omitempty"`
	Props  map[string]any `json:"props,omitempty"`
}

func (n *Node) Bool(key string) bool {
	v, _ := n.Props[key].(bool)
	return v
}

func (n *Node) Str(key string) string {
	v, _ := n.Props[key].(string)
	return v
}

func (n *Node) Int(key string) (int, bool) {
	switch v := n.Props[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}

// Short returns the account-style name: "JDOE" for "JDOE@CORP.LOCAL" and
// "WEB02" for "WEB02.CORP.LOCAL".
func (n *Node) Short() string {
	name := n.Name
	if name == "" {
		return n.ID
	}
	if i := strings.IndexByte(name, '@'); i > 0 {
		return name[:i]
	}
	if n.Kind == Computer {
		if i := strings.IndexByte(name, '.'); i > 0 {
			return name[:i]
		}
	}
	return name
}

type Edge struct {
	ID        int    `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Kind      string `json:"kind"`
	Inherited bool   `json:"inherited,omitempty"`
	Synthetic bool   `json:"synthetic,omitempty"`
}

type Graph struct {
	Nodes map[string]*Node
	Edges []*Edge
	out   map[string][]*Edge
	in    map[string][]*Edge
	seen  map[string]*Edge
}

func New() *Graph {
	return &Graph{
		Nodes: map[string]*Node{},
		out:   map[string][]*Edge{},
		in:    map[string][]*Edge{},
		seen:  map[string]*Edge{},
	}
}

func NormID(id string) string { return strings.ToUpper(strings.TrimSpace(id)) }

// Upsert adds a node or merges it into an existing placeholder.
func (g *Graph) Upsert(n *Node) *Node {
	n.ID = NormID(n.ID)
	if old, ok := g.Nodes[n.ID]; ok {
		if n.Kind != Base {
			old.Kind = n.Kind
		}
		if n.Name != "" {
			old.Name = n.Name
		}
		if n.Domain != "" {
			old.Domain = n.Domain
		}
		if old.Props == nil {
			old.Props = map[string]any{}
		}
		for k, v := range n.Props {
			old.Props[k] = v
		}
		return old
	}
	if n.Props == nil {
		n.Props = map[string]any{}
	}
	g.Nodes[n.ID] = n
	return n
}

// Ensure returns the node with this ID, creating a placeholder when an edge
// references an object that was not collected.
func (g *Graph) Ensure(id string, kind Kind) *Node {
	id = NormID(id)
	if n, ok := g.Nodes[id]; ok {
		if n.Kind == Base && kind != Base {
			n.Kind = kind
		}
		return n
	}
	n := &Node{ID: id, Kind: kind, Props: map[string]any{}}
	g.Nodes[id] = n
	return n
}

func (g *Graph) AddEdge(from, to, kind string, inherited bool) *Edge {
	from, to = NormID(from), NormID(to)
	if from == "" || to == "" || from == to {
		return nil
	}
	key := from + "|" + to + "|" + kind
	if e, ok := g.seen[key]; ok {
		e.Inherited = e.Inherited && inherited
		return e
	}
	g.Ensure(from, Base)
	g.Ensure(to, Base)
	e := &Edge{ID: len(g.Edges), From: from, To: to, Kind: kind, Inherited: inherited}
	g.Edges = append(g.Edges, e)
	g.out[from] = append(g.out[from], e)
	g.in[to] = append(g.in[to], e)
	g.seen[key] = e
	return e
}

func (g *Graph) HasEdge(from, to, kind string) bool {
	_, ok := g.seen[NormID(from)+"|"+NormID(to)+"|"+kind]
	return ok
}

func (g *Graph) Out(id string) []*Edge { return g.out[id] }
func (g *Graph) In(id string) []*Edge  { return g.in[id] }
func (g *Graph) Edge(id int) *Edge     { return g.Edges[id] }

func (g *Graph) Counts() map[Kind]int {
	c := map[Kind]int{}
	for _, n := range g.Nodes {
		c[n.Kind]++
	}
	return c
}

// Traversable lists the edge kinds that transfer control: owning the source
// lets an attacker act as, or take over, the target.
var Traversable = map[string]bool{
	"MemberOf": true, "Contains": true, "GenericAll": true, "GenericWrite": true,
	"WriteDacl": true, "WriteOwner": true, "Owns": true, "ForceChangePassword": true,
	"AddMember": true, "AddSelf": true, "AllExtendedRights": true, "ReadLAPSPassword": true,
	"ReadGMSAPassword": true, "AddKeyCredentialLink": true, "AddAllowedToAct": true,
	"AllowedToAct": true, "AllowedToDelegate": true, "WriteAccountRestrictions": true,
	"WriteSPN": true, "AdminTo": true, "HasSession": true, "DCSync": true,
	"CanRDP": true, "CanPSRemote": true, "ExecuteDCOM": true, "SQLAdmin": true,
	"HasSIDHistory": true, "DumpSMSAPassword": true, "GPLink": true,
	"CoerceToTGT": true, "ADCSESC1": true, "DomainAdmin": true,
}

// Membership edges cost nothing: being in a group is already holding its rights.
func IsFree(kind string) bool { return kind == "MemberOf" }

func traversable(e *Edge) bool { return Traversable[e.Kind] }

// BFS walks traversable edges forward from the sources and returns, for every
// reached node, the edge it was reached through.
func (g *Graph) BFS(sources []string) map[string]*Edge {
	parent := map[string]*Edge{}
	visited := map[string]bool{}
	queue := make([]string, 0, len(sources))
	for _, s := range sources {
		if !visited[s] {
			visited[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range g.out[n] {
			if !traversable(e) || visited[e.To] {
				continue
			}
			visited[e.To] = true
			parent[e.To] = e
			queue = append(queue, e.To)
		}
	}
	return parent
}

// ReverseBFS walks traversable edges backwards from the targets and returns,
// for every node that can reach a target, the next edge toward it.
func (g *Graph) ReverseBFS(targets []string) map[string]*Edge {
	next := map[string]*Edge{}
	visited := map[string]bool{}
	queue := []string{}
	for _, t := range targets {
		visited[t] = true
		queue = append(queue, t)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range g.in[n] {
			if !traversable(e) || visited[e.From] {
				continue
			}
			visited[e.From] = true
			next[e.From] = e
			queue = append(queue, e.From)
		}
	}
	return next
}

// PathTo rebuilds the edge path to target from a BFS parent map.
func PathTo(parent map[string]*Edge, target string) []*Edge {
	var path []*Edge
	for n := target; ; {
		e, ok := parent[n]
		if !ok {
			break
		}
		path = append([]*Edge{e}, path...)
		n = e.From
		if len(path) > 64 {
			break
		}
	}
	return path
}

// PathFrom follows a ReverseBFS next-hop map from start to the target set.
func PathFrom(next map[string]*Edge, start string) []*Edge {
	var path []*Edge
	for n := start; ; {
		e, ok := next[n]
		if !ok || len(path) > 64 {
			break
		}
		path = append(path, e)
		n = e.To
	}
	return path
}

// MemberClosure returns the sources plus every group they belong to, directly
// or through nesting.
func (g *Graph) MemberClosure(sources []string) map[string]bool {
	set := map[string]bool{}
	queue := append([]string{}, sources...)
	for _, s := range sources {
		set[s] = true
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range g.out[n] {
			if e.Kind == "MemberOf" && !set[e.To] {
				set[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	return set
}

func Steps(path []*Edge) int {
	n := 0
	for _, e := range path {
		if !IsFree(e.Kind) {
			n++
		}
	}
	return n
}
