// Package ingest reads SharpHound / bloodhound-python output (legacy v4 and
// BloodHound CE v5+) into the in-memory graph.
package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"adx/internal/graph"
)

type file struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
		Count   int    `json:"count"`
	} `json:"meta"`
}

type ace struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

type ref struct {
	ID   string
	Type string
}

// refs accepts every shape SharpHound has used for a principal list: an array
// of SID strings, an array of {ObjectIdentifier, ObjectType} objects, or either
// of those wrapped in {"Results": [...], "Collected": true}.
type refs []ref

func (r *refs) UnmarshalJSON(b []byte) error {
	var wrapped struct {
		Results json.RawMessage `json:"Results"`
	}
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &wrapped); err != nil {
			return err
		}
		if len(wrapped.Results) == 0 || string(wrapped.Results) == "null" {
			return nil
		}
		b = wrapped.Results
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	for _, item := range raw {
		var s string
		if json.Unmarshal(item, &s) == nil {
			*r = append(*r, ref{ID: s})
			continue
		}
		var o map[string]any
		if json.Unmarshal(item, &o) != nil {
			continue
		}
		id := firstStr(o, "ObjectIdentifier", "MemberId", "ObjectId", "MemberSID")
		*r = append(*r, ref{ID: id, Type: firstStr(o, "ObjectType", "MemberType")})
	}
	return nil
}

type session struct{ User, Computer string }

type sessions []session

func (s *sessions) UnmarshalJSON(b []byte) error {
	var wrapped struct {
		Results json.RawMessage `json:"Results"`
	}
	if len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &wrapped); err != nil {
			return err
		}
		b = wrapped.Results
	}
	var raw []map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	for _, o := range raw {
		*s = append(*s, session{
			User:     firstStr(o, "UserSID", "UserId", "UserID"),
			Computer: firstStr(o, "ComputerSID", "ComputerId", "ComputerID"),
		})
	}
	return nil
}

type localGroup struct {
	Name             string `json:"Name"`
	ObjectIdentifier string `json:"ObjectIdentifier"`
	Results          refs   `json:"Results"`
}

type object struct {
	ObjectIdentifier     string         `json:"ObjectIdentifier"`
	Properties           map[string]any `json:"Properties"`
	Aces                 []ace          `json:"Aces"`
	Members              refs           `json:"Members"`
	PrimaryGroupSID      string         `json:"PrimaryGroupSID"`
	AllowedToDelegate    refs           `json:"AllowedToDelegate"`
	AllowedToAct         refs           `json:"AllowedToAct"`
	HasSIDHistory        refs           `json:"HasSIDHistory"`
	DumpSMSAPassword     refs           `json:"DumpSMSAPassword"`
	Sessions             sessions       `json:"Sessions"`
	PrivilegedSessions   sessions       `json:"PrivilegedSessions"`
	RegistrySessions     sessions       `json:"RegistrySessions"`
	LocalAdmins          refs           `json:"LocalAdmins"`
	RemoteDesktopUsers   refs           `json:"RemoteDesktopUsers"`
	PSRemoteUsers        refs           `json:"PSRemoteUsers"`
	DcomUsers            refs           `json:"DcomUsers"`
	LocalGroups          []localGroup   `json:"LocalGroups"`
	ChildObjects         refs           `json:"ChildObjects"`
	EnabledCertTemplates refs           `json:"EnabledCertTemplates"`
	Links                []struct {
		GUID       string `json:"GUID"`
		IsEnforced bool   `json:"IsEnforced"`
	} `json:"Links"`
	Trusts []map[string]any `json:"Trusts"`
	IsDC   *bool            `json:"IsDC"`
}

var typeKinds = map[string]graph.Kind{
	"users": graph.User, "groups": graph.Group, "computers": graph.Computer,
	"domains": graph.Domain, "gpos": graph.GPO, "ous": graph.OU,
	"containers": graph.Container, "certtemplates": graph.CertTemplate,
	"enterprisecas": graph.EnterpriseCA,
}

// Local group RIDs that grant access to the computer they live on.
var localGroupEdges = map[string]string{
	"544": "AdminTo", "555": "CanRDP", "580": "CanPSRemote", "562": "ExecuteDCOM",
}

// Stats summarises what a load added.
type Stats struct {
	Files   int            `json:"files"`
	Objects map[string]int `json:"objects"`
	Skipped []string       `json:"skipped,omitempty"`
}

func (s *Stats) add(kind string, n int) {
	if s.Objects == nil {
		s.Objects = map[string]int{}
	}
	s.Objects[kind] += n
}

// ReadJSON decodes one SharpHound JSON file into the graph. SharpHound writes
// UTF-8 with a byte-order mark, so skip a leading BOM before decoding.
func ReadJSON(g *graph.Graph, name string, r io.Reader, st *Stats) error {
	br := bufio.NewReader(r)
	if b, err := br.Peek(3); err == nil && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		_, _ = br.Discard(3)
	}
	var f file
	if err := json.NewDecoder(br).Decode(&f); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	typ := strings.ToLower(f.Meta.Type)
	kind, ok := typeKinds[typ]
	if !ok {
		st.Skipped = append(st.Skipped, fmt.Sprintf("%s (type %q not used yet)", name, f.Meta.Type))
		return nil
	}
	st.Files++
	for _, raw := range f.Data {
		var o object
		if err := json.Unmarshal(raw, &o); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if o.ObjectIdentifier == "" {
			continue
		}
		addObject(g, kind, &o)
	}
	st.add(typ, len(f.Data))
	return nil
}

func addObject(g *graph.Graph, kind graph.Kind, o *object) {
	props := o.Properties
	if props == nil {
		props = map[string]any{}
	}
	if o.IsDC != nil {
		props["isdc"] = *o.IsDC
	}
	if len(o.Trusts) > 0 {
		props["trusts"] = len(o.Trusts)
	}
	name, _ := props["name"].(string)
	dom, _ := props["domain"].(string)
	id := o.ObjectIdentifier
	g.Upsert(&graph.Node{ID: id, Kind: kind, Name: strings.ToUpper(name), Domain: strings.ToUpper(dom), Props: props})

	for _, a := range o.Aces {
		right := a.RightName
		if right == "Owner" {
			right = "Owns"
		}
		g.Ensure(a.PrincipalSID, kindOf(a.PrincipalType))
		g.AddEdge(a.PrincipalSID, id, right, a.IsInherited)
	}
	for _, m := range o.Members {
		g.Ensure(m.ID, kindOf(m.Type))
		g.AddEdge(m.ID, id, "MemberOf", false)
	}
	if o.PrimaryGroupSID != "" {
		g.Ensure(o.PrimaryGroupSID, graph.Group)
		g.AddEdge(id, o.PrimaryGroupSID, "MemberOf", false)
	}
	for _, t := range o.AllowedToDelegate {
		g.Ensure(t.ID, kindOf(t.Type))
		g.AddEdge(id, t.ID, "AllowedToDelegate", false)
	}
	for _, p := range o.AllowedToAct {
		g.Ensure(p.ID, kindOf(p.Type))
		g.AddEdge(p.ID, id, "AllowedToAct", false)
	}
	for _, t := range o.HasSIDHistory {
		g.AddEdge(id, t.ID, "HasSIDHistory", false)
	}
	for _, t := range o.DumpSMSAPassword {
		g.AddEdge(id, t.ID, "DumpSMSAPassword", false)
	}
	for _, list := range []sessions{o.Sessions, o.PrivilegedSessions, o.RegistrySessions} {
		for _, s := range list {
			comp := s.Computer
			if comp == "" {
				comp = id
			}
			g.Ensure(s.User, graph.User)
			g.AddEdge(comp, s.User, "HasSession", false)
		}
	}
	for edge, list := range map[string]refs{"AdminTo": o.LocalAdmins, "CanRDP": o.RemoteDesktopUsers, "CanPSRemote": o.PSRemoteUsers, "ExecuteDCOM": o.DcomUsers} {
		for _, p := range list {
			if isLocal(p.Type) {
				continue
			}
			g.Ensure(p.ID, kindOf(p.Type))
			g.AddEdge(p.ID, id, edge, false)
		}
	}
	for _, lg := range o.LocalGroups {
		rid := lg.ObjectIdentifier
		if i := strings.LastIndexByte(rid, '-'); i >= 0 {
			rid = rid[i+1:]
		}
		edge, ok := localGroupEdges[rid]
		if !ok {
			continue
		}
		for _, p := range lg.Results {
			if isLocal(p.Type) {
				continue
			}
			g.Ensure(p.ID, kindOf(p.Type))
			g.AddEdge(p.ID, id, edge, false)
		}
	}
	for _, c := range o.ChildObjects {
		g.Ensure(c.ID, kindOf(c.Type))
		g.AddEdge(id, c.ID, "Contains", false)
	}
	for _, l := range o.Links {
		g.Ensure(l.GUID, graph.GPO)
		g.AddEdge(l.GUID, id, "GPLink", false)
	}
	for _, t := range o.EnabledCertTemplates {
		g.Ensure(t.ID, graph.CertTemplate)
		g.AddEdge(t.ID, id, "PublishedTo", false)
	}
}

func isLocal(t string) bool {
	return strings.HasPrefix(strings.ToLower(t), "local")
}

func kindOf(t string) graph.Kind {
	switch strings.ToLower(t) {
	case "user":
		return graph.User
	case "group":
		return graph.Group
	case "computer":
		return graph.Computer
	case "domain":
		return graph.Domain
	case "gpo":
		return graph.GPO
	case "ou":
		return graph.OU
	case "container":
		return graph.Container
	case "certtemplate":
		return graph.CertTemplate
	case "enterpriseca":
		return graph.EnterpriseCA
	}
	return graph.Base
}

func firstStr(o map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := o[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
