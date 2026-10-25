// Package server exposes the in-memory model over HTTP and serves the embedded
// web UI. There is no database and no external service.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"adx/internal/analysis"
	"adx/internal/graph"
	"adx/internal/ingest"
)

type Server struct {
	mu        sync.RWMutex
	g         *graph.Graph
	model     *analysis.Model
	stats     ingest.Stats
	files     http.FileSystem
	lastBeat  atomic.Int64 // UnixNano of the last browser heartbeat
	byeAt     atomic.Int64 // UnixNano the page signalled it is unloading (0 = not)
	connected atomic.Bool  // a browser has connected at least once
}

func New(g *graph.Graph, stats ingest.Stats, webFS http.FileSystem) *Server {
	s := &Server{g: g, stats: stats, files: webFS}
	s.rebuild()
	return s
}

func (s *Server) rebuild() { s.model = analysis.Build(s.g) }

// alive is the browser heartbeat: the page pings it every couple of seconds.
// It also cancels a pending unload, so a reload (unload then immediate load)
// does not shut the app down.
func (s *Server) alive(w http.ResponseWriter, r *http.Request) {
	s.connected.Store(true)
	s.lastBeat.Store(time.Now().UnixNano())
	s.byeAt.Store(0)
	w.WriteHeader(http.StatusNoContent)
}

// bye is sent by the page as it unloads (tab closed, not merely hidden). It
// arms a short countdown; if no heartbeat clears it (a reload would), the app
// exits. Switching tabs fires no bye, so the app stays up.
func (s *Server) bye(w http.ResponseWriter, r *http.Request) {
	if s.connected.Load() {
		s.byeAt.Store(time.Now().UnixNano())
	}
	w.WriteHeader(http.StatusNoContent)
}

// WatchBrowser ties a local app to its browser window. After an unload signal
// it waits confirm (to survive reloads) then exits; a long heartbeat gap is a
// fallback for a browser that died without signalling.
func (s *Server) WatchBrowser(confirm time.Duration) {
	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for range t.C {
			if !s.connected.Load() {
				continue
			}
			bye := s.byeAt.Load()
			if bye != 0 && time.Since(time.Unix(0, bye)) > confirm {
				fmt.Println("\nBrowser closed — adX shutting down.")
				os.Exit(0)
			}
			if time.Since(time.Unix(0, s.lastBeat.Load())) > 30*time.Second {
				fmt.Println("\nNo browser for 30s — adX shutting down.")
				os.Exit(0)
			}
		}
	}()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", s.overview)
	mux.HandleFunc("/api/eval", s.eval)
	mux.HandleFunc("/api/node", s.nodeDetail)
	mux.HandleFunc("/api/search", s.search)
	mux.HandleFunc("/api/upload", s.upload)
	mux.HandleFunc("/api/clear", s.clear)
	mux.HandleFunc("/api/alive", s.alive)
	mux.HandleFunc("/api/bye", s.bye)
	// Never cache the UI: a stale app.js from a previous build is a common
	// source of confusing errors, and this is a local, tiny payload.
	fileSrv := http.FileServer(s.files)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		fileSrv.ServeHTTP(w, r)
	}))
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type nodeLite struct {
	S string `json:"s"` // short name
	K string `json:"k"` // kind
	T bool   `json:"t"` // tier zero
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nodes := make(map[string]nodeLite, len(s.g.Nodes))
	for id, n := range s.g.Nodes {
		nodes[id] = nodeLite{S: n.Short(), K: string(n.Kind), T: s.model.TierZero[id]}
	}
	counts := map[string]int{}
	for k, c := range s.g.Counts() {
		counts[string(k)] = c
	}
	domain := ""
	if len(s.model.Domains) > 0 {
		domain = s.g.Nodes[s.model.Domains[0]].Name
	}
	writeJSON(w, map[string]any{
		"meta": map[string]any{
			"domain":    domain,
			"counts":    counts,
			"edgeCount": len(s.g.Edges),
			"findings":  len(s.model.Findings),
			"files":     s.stats.Files,
			"skipped":   s.stats.Skipped,
			"empty":     len(s.g.Nodes) == 0,
		},
		"nodes": nodes,
	})
}

type ownedReq struct {
	Owned []string `json:"owned"`
	ID    string   `json:"id"`
}

func (s *Server) eval(w http.ResponseWriter, r *http.Request) {
	var req ownedReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, s.model.Evaluate(req.Owned))
}

func (s *Server) nodeDetail(w http.ResponseWriter, r *http.Request) {
	var req ownedReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.RLock()
	defer s.mu.RUnlock()
	id := graph.NormID(req.ID)
	n, ok := s.g.Nodes[id]
	if !ok {
		http.Error(w, "unknown node", 404)
		return
	}
	type rel struct {
		Node string `json:"node"`
		Kind string `json:"kind"`
	}
	var in, out []rel
	for _, e := range s.g.In(id) {
		in = append(in, rel{Node: e.From, Kind: e.Kind})
	}
	for _, e := range s.g.Out(id) {
		out = append(out, rel{Node: e.To, Kind: e.Kind})
	}
	var findings []string
	for _, f := range s.model.Findings {
		for _, c := range f.Chain {
			if c == id || f.Anchor == id {
				findings = append(findings, f.ID)
				break
			}
		}
	}
	res := s.model.Evaluate(req.Owned)
	status := "blocked"
	if res.Controlled[id] {
		status = "now"
	} else if res.Reachable[id] {
		status = "reach"
	}
	props := map[string]any{}
	for k, v := range n.Props {
		props[k] = v
	}
	writeJSON(w, map[string]any{
		"id": id, "short": n.Short(), "kind": string(n.Kind),
		"tierZero": s.model.TierZero[id], "props": props,
		"inbound": in, "outbound": out, "findings": findings, "status": status,
	})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("q")))
	s.mu.RLock()
	defer s.mu.RUnlock()
	type hit struct {
		ID, S, K string
		rank     int
	}
	var hits []hit
	for id, n := range s.g.Nodes {
		short := n.Short()
		if q == "" || strings.Contains(strings.ToUpper(short), q) {
			rank := 1
			if strings.HasPrefix(strings.ToUpper(short), q) {
				rank = 0
			}
			hits = append(hits, hit{id, short, string(n.Kind), rank})
		}
		if len(hits) > 400 {
			break
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].rank != hits[j].rank {
			return hits[i].rank < hits[j].rank
		}
		return hits[i].S < hits[j].S
	})
	if len(hits) > 25 {
		hits = hits[:25]
	}
	out := make([]map[string]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, map[string]string{"id": h.ID, "s": h.S, "k": h.K})
	}
	writeJSON(w, out)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		http.Error(w, "no file", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fh := range files {
		f, err := fh.Open()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := ingest.LoadBytes(s.g, fh.Filename, data, &s.stats); err != nil {
			http.Error(w, fmt.Sprintf("%s: %v", fh.Filename, err), 422)
			return
		}
	}
	s.rebuild()
	writeJSON(w, map[string]any{"ok": true, "files": s.stats.Files, "nodes": len(s.g.Nodes), "findings": len(s.model.Findings)})
}

// clear drops all loaded data, returning adX to the empty state.
func (s *Server) clear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.g = graph.New()
	s.stats = ingest.Stats{}
	s.rebuild()
	writeJSON(w, map[string]any{"ok": true})
}
