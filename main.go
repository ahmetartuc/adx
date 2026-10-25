// Command adX loads SharpHound / bloodhound-python collections into memory and
// serves a local web UI that flags attack paths. No database, no Docker.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"adx/internal/analysis"
	"adx/internal/graph"
	"adx/internal/ingest"
	"adx/internal/server"
)

//go:embed web/index.html web/app.js
var webFiles embed.FS

//go:embed web/sample/*.json
var sampleFiles embed.FS

var version = "0.2.0"

func main() {
	flag.Usage = usage
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve(os.Args[2:], true, false)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "demo" {
		serve(os.Args[2:], false, true)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "inspect" {
		inspect(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("adX", version)
		return
	}
	serve(os.Args[1:], false, false)
}

func usage() {
	fmt.Fprintf(os.Stderr, `adX %s — Active Directory eXplorer

Usage:
  adx [collection ...]        Open collections locally and launch the UI in your browser.
  adx serve [collection ...]  Run as a shared server (binds all interfaces, no browser).
  adx demo                    Launch with a built-in sample domain to explore.
  adx version

Collections may be SharpHound / bloodhound-python .zip, .7z, .tar.gz or .json
files, or a directory of them. With no collection, adX starts empty — drop a
file into the window, or use "Open collection…", to load one.

Flags:
  --listen ADDR    Address to bind (default 127.0.0.1:8899; serve: 0.0.0.0:8899)
  --no-open        Do not open a browser
`, version)
}

func serve(args []string, shared, demo bool) {
	fsFlags := flag.NewFlagSet("adx", flag.ExitOnError)
	defListen := "127.0.0.1:8899"
	if shared {
		defListen = "0.0.0.0:8899"
	}
	listen := fsFlags.String("listen", defListen, "address to bind")
	noOpen := fsFlags.Bool("no-open", shared, "do not open a browser")
	_ = fsFlags.Parse(args)
	paths := fsFlags.Args()
	explicitListen := false
	fsFlags.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			explicitListen = true
		}
	})

	g := graph.New()
	var stats ingest.Stats
	switch {
	case demo && len(paths) == 0:
		loadSample(g, &stats)
		fmt.Println("Loaded the built-in sample domain (corp.local).")
	case len(paths) == 0:
		fmt.Println("Starting empty — drop a collection into the window to load one.")
	default:
		for _, p := range paths {
			if err := ingest.LoadPath(g, p, &stats); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		}
	}
	fmt.Printf("Loaded %d nodes, %d edges from %d file(s).\n", len(g.Nodes), len(g.Edges), stats.Files)
	for _, s := range stats.Skipped {
		fmt.Println("  skipped:", s)
	}

	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	srv := server.New(g, stats, http.FS(sub))

	ln, err := listenWithFallback(*listen, explicitListen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot bind", *listen, "-", err)
		if !explicitListen {
			fmt.Fprintln(os.Stderr, "another adX may already be running; close it or pass --listen with a free port.")
		}
		os.Exit(1)
	}
	url := "http://" + browserAddr(ln.Addr().String())
	fmt.Printf("\n  adX is running at %s\n", url)
	if shared {
		fmt.Println("  Shared mode: anyone who can reach this address can view the data.")
	}
	// In local mode the app belongs to its browser window: quit when it closes.
	// Shared mode stays up for the team.
	if !shared {
		srv.WatchBrowser(2 * time.Second)
		fmt.Println("  Closes automatically when you close the browser tab (or Ctrl+C).")
	} else {
		fmt.Println("  Press Ctrl+C to stop.")
	}

	if !*noOpen {
		go func() { time.Sleep(400 * time.Millisecond); openBrowser(url) }()
	}
	httpSrv := &http.Server{Handler: srv.Handler()}
	if err := httpSrv.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "server stopped:", err)
	}
}

// listenWithFallback binds addr. If the port is busy and the user did not pick
// it explicitly, it tries the next few ports so a stray instance never blocks
// a double-click launch.
func listenWithFallback(addr string, explicit bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil || explicit {
		return ln, err
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return ln, err
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return ln, err
	}
	for p := port + 1; p <= port+20; p++ {
		if alt, e := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(p))); e == nil {
			fmt.Printf("Port %d was busy; using %d instead.\n", port, p)
			return alt, nil
		}
	}
	return ln, err
}

// inspect loads collections and prints diagnostics about the model, so we can
// see why rules fire (or do not) against real data.
func inspect(paths []string) {
	g := graph.New()
	var stats ingest.Stats
	for _, p := range paths {
		if err := ingest.LoadPath(g, p, &stats); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	m := analysis.Build(g)
	fmt.Printf("nodes=%d edges=%d files=%d\n", len(g.Nodes), len(g.Edges), stats.Files)
	fmt.Println("domains:", m.Domains)

	kinds := map[string]int{}
	for _, n := range g.Nodes {
		kinds[string(n.Kind)]++
	}
	fmt.Println("node kinds:", kinds)

	edgeKinds := map[string]int{}
	for _, e := range g.Edges {
		edgeKinds[e.Kind]++
	}
	fmt.Println("edge kinds:", edgeKinds)

	tz := 0
	for range m.TierZero {
		tz++
	}
	fmt.Println("tier-zero nodes:", tz)
	fmt.Println("findings:", len(m.Findings))
	for _, f := range m.Findings {
		fmt.Printf("  [%s] %s (entry=%s)\n", f.Severity, f.Title, f.Entry)
	}

	// Which single account, if compromised, opens a path to the crown jewels?
	crown := map[string]bool{}
	for _, t := range m.CrownTargets() {
		crown[t] = true
	}
	fmt.Println("\naccounts with a control path to a crown target (owning one = escalation):")
	type hit struct {
		name  string
		steps int
		tgt   string
	}
	var hits []hit
	for id, n := range g.Nodes {
		if n.Kind != graph.User || m.TierZero[id] {
			continue
		}
		parent := g.BFS([]string{id})
		best := -1
		bestTgt := ""
		for t := range crown {
			if p, ok := parent[t]; ok {
				_ = p
				s := graph.Steps(graph.PathTo(parent, t))
				if best == -1 || s < best {
					best, bestTgt = s, t
				}
			}
		}
		if best >= 0 {
			hits = append(hits, hit{n.Short(), best, g.Nodes[bestTgt].Short()})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].steps < hits[j].steps })
	for _, h := range hits {
		fmt.Printf("  %-28s %d steps -> %s\n", h.name, h.steps, h.tgt)
	}
	if len(hits) == 0 {
		fmt.Println("  (none — escalation here is not visible from the graph alone)")
	}
}

func loadSample(g *graph.Graph, stats *ingest.Stats) {
	entries, _ := sampleFiles.ReadDir("web/sample")
	for _, e := range entries {
		data, err := sampleFiles.ReadFile("web/sample/" + e.Name())
		if err != nil {
			continue
		}
		if err := ingest.LoadBytes(g, e.Name(), data, stats); err != nil {
			fmt.Fprintln(os.Stderr, "sample load error:", err)
		}
	}
}

func browserAddr(addr string) string {
	if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") {
		_, port, _ := net.SplitHostPort(addr)
		return "127.0.0.1:" + port
	}
	return addr
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	_ = exec.Command(cmd, append(args, url)...).Start()
}
