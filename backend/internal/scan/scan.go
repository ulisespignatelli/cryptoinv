// Package scan recorre un directorio y aplica los detectores en paralelo. Solo lee archivos: nunca ejecuta,
// compila ni importa el contenido analizado, y no sigue enlaces simbolicos fuera de la raiz.
package scan

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/scan/detectors"
)

// Options configura el recorrido.
type Options struct {
	MaxFileBytes int64    // archivos mas grandes se saltean (por defecto 2 MiB)
	Workers      int      // por defecto, la cantidad de CPU
	Exclude      []string // patrones extra (glob sobre la ruta relativa o el nombre)
	Detectors    []detectors.Detector
}

// Hit es un uso crudo con su archivo y detector.
type Hit struct {
	Path     string
	Detector string
	Raw      detectors.Raw
}

// Result del recorrido.
type Result struct {
	Files      int
	Skipped    int
	Suppressed int // usos marcados con "cryptoinv:ignore" en la misma linea
	Hits       []Hit
}

// IgnoreMarker en un comentario de la misma linea descarta el uso (por ejemplo, codigo que solo
// reconoce tipos de clave). Conviene acompañarlo con el motivo: "// cryptoinv:ignore solo parsea".
const IgnoreMarker = "cryptoinv:ignore"

var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "target": true, ".venv": true, "venv": true, "__pycache__": true, ".terraform": true,
	".next": true, ".cache": true, ".idea": true, ".vscode": true, "coverage": true}

var binaryExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".jar": true, ".class": true, ".so": true, ".dll": true, ".exe": true,
	".woff": true, ".woff2": true, ".ttf": true, ".mp4": true, ".mp3": true, ".wasm": true, ".lock": false,
	".svg": true, ".map": true, ".min.js": true}

// Run recorre root y devuelve los usos encontrados, ordenados por ruta y linea.
func Run(ctx context.Context, root string, opt Options) (Result, error) {
	if opt.MaxFileBytes <= 0 {
		opt.MaxFileBytes = 2 << 20
	}
	if opt.Workers <= 0 {
		opt.Workers = runtime.NumCPU()
	}
	if opt.Detectors == nil {
		opt.Detectors = detectors.All()
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}

	paths := make(chan string, 256)
	var (
		mu  sync.Mutex
		res Result
		wg  sync.WaitGroup
	)
	for i := 0; i < opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				hits, suppressed, ok := scanFile(root, p, info.IsDir(), opt)
				mu.Lock()
				if ok {
					res.Files++
					res.Suppressed += suppressed
					res.Hits = append(res.Hits, hits...)
				} else {
					res.Skipped++
				}
				mu.Unlock()
			}
		}()
	}

	var walkErr error
	if !info.IsDir() {
		paths <- root
	} else {
		walkErr = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // archivo ilegible: se saltea
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				if p != root && (skipDirs[d.Name()] || excluded(rel, d.Name(), opt.Exclude)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || excluded(rel, d.Name(), opt.Exclude) {
				return nil // enlaces simbolicos, sockets, etc.
			}
			paths <- p
			return nil
		})
	}
	close(paths)
	wg.Wait()
	if walkErr != nil {
		return res, walkErr
	}
	sort.Slice(res.Hits, func(i, j int) bool {
		a, b := res.Hits[i], res.Hits[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Raw.Line != b.Raw.Line {
			return a.Raw.Line < b.Raw.Line
		}
		return a.Raw.Name < b.Raw.Name
	})
	return res, nil
}

func excluded(rel, name string, pats []string) bool {
	rel = filepath.ToSlash(rel)
	for _, p := range pats {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
		if ok, _ := filepath.Match(p, rel); ok || strings.HasPrefix(rel, strings.TrimSuffix(p, "/**")+"/") {
			return true
		}
	}
	return false
}

func scanFile(root, p string, isDir bool, opt Options) ([]Hit, int, bool) {
	low := strings.ToLower(p)
	for ext, bin := range binaryExts {
		if bin && strings.HasSuffix(low, ext) {
			return nil, 0, false
		}
	}
	st, err := os.Stat(p)
	if err != nil || st.Size() > opt.MaxFileBytes || st.Size() == 0 {
		return nil, 0, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, 0, false
	}
	isDER := strings.HasSuffix(low, ".der") || strings.HasSuffix(low, ".cer") || strings.HasSuffix(low, ".crt")
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if !isDER && bytes.IndexByte(head, 0) >= 0 {
		return nil, 0, false // binario
	}
	rel := filepath.Base(p)
	if isDir {
		rel, _ = filepath.Rel(root, p)
	}
	f := detectors.File{Path: filepath.ToSlash(rel), Data: data}
	var src []string
	if bytes.Contains(data, []byte(IgnoreMarker)) {
		src = strings.Split(string(data), "\n")
	}
	var hits []Hit
	suppressed := 0
	for _, d := range opt.Detectors {
		if !d.Match(f) {
			continue
		}
		for _, r := range d.Detect(f) {
			if src != nil && r.Line > 0 && r.Line <= len(src) && strings.Contains(src[r.Line-1], IgnoreMarker) {
				suppressed++
				continue
			}
			hits = append(hits, Hit{Path: f.Path, Detector: d.Name(), Raw: r})
		}
	}
	return hits, suppressed, true
}
