package ingest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bodgit/sevenzip"

	"adx/internal/graph"
)

// LoadPath loads a .zip, .7z, .tar.gz, .json file or a directory of them.
func LoadPath(g *graph.Graph, path string, st *Stats) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !supported(p) {
				return err
			}
			return LoadPath(g, p, st)
		})
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return LoadBytes(g, filepath.Base(path), data, st)
}

func supported(name string) bool {
	n := strings.ToLower(name)
	for _, ext := range []string{".zip", ".7z", ".json", ".tar.gz", ".tgz"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// LoadBytes detects the format from the content, not the name, so a renamed
// archive still loads.
func LoadBytes(g *graph.Graph, name string, data []byte, st *Stats) error {
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return loadZip(g, name, data, st)
	case bytes.HasPrefix(data, []byte("7z\xbc\xaf\x27\x1c")):
		return load7z(g, name, data, st)
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return loadTarGz(g, name, data, st)
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return ReadJSON(g, name, bytes.NewReader(trimmed), st)
	}
	return fmt.Errorf("%s: not a zip, 7z, tar.gz or SharpHound JSON file", name)
}

func loadZip(g *graph.Graph, name string, data []byte, st *Stats) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		if f.Flags&0x1 != 0 {
			return fmt.Errorf("%s: the zip is password protected; extract it first or collect without --zippassword", name)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%s/%s: %w", name, f.Name, err)
		}
		err = ReadJSON(g, name+"/"+f.Name, rc, st)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func load7z(g *graph.Graph, name string, data []byte, st *Stats) error {
	zr, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%s/%s: %w", name, f.Name, err)
		}
		err = ReadJSON(g, name+"/"+f.Name, rc, st)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func loadTarGz(g *graph.Graph, name string, data []byte, st *Stats) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	inner, err := io.ReadAll(gz)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	// A gzipped single JSON file is not a tar.
	if t := bytes.TrimLeft(inner, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		return ReadJSON(g, name, bytes.NewReader(t), st)
	}
	tr := tar.NewReader(bytes.NewReader(inner))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(strings.ToLower(h.Name), ".json") {
			continue
		}
		if err := ReadJSON(g, name+"/"+h.Name, tr, st); err != nil {
			return err
		}
	}
}
