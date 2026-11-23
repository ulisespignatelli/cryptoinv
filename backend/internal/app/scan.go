// Package app tiene los casos de uso. Orquesta dominio, catalogo, riesgo y escaner, y habla con el mundo
// exterior solo a traves de interfaces (ports). Es lo que usan tanto la CLI como la API.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/catalog"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/risk"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/scan"
)

// Scanner ejecuta escaneos y evalua los hallazgos.
type Scanner struct {
	Catalog *catalog.Catalog
	Policy  risk.Policy
	Options scan.Options
	Now     func() time.Time
	// SkipTests descarta los usos en tests, fixtures y ejemplos.
	SkipTests bool
}

// NewScanner arma un Scanner con el catalogo embebido y la politica por defecto.
func NewScanner() *Scanner {
	return &Scanner{Catalog: catalog.MustLoad(), Policy: risk.DefaultPolicy(), Now: time.Now}
}

// ScanRequest describe que escanear.
type ScanRequest struct {
	Root  string
	Asset string // nombre del sistema; por defecto, el nombre de la carpeta
}

// Run escanea, resuelve cada uso contra el catalogo, evalua el riesgo y deduplica.
func (s *Scanner) Run(ctx context.Context, req ScanRequest) (domain.Scan, error) {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	abs, err := filepath.Abs(req.Root)
	if err != nil {
		return domain.Scan{}, err
	}
	asset := req.Asset
	if asset == "" {
		asset = filepath.Base(abs)
	}
	sc := domain.Scan{ID: newID(), Asset: asset, Root: abs, StartedAt: now().UTC()}
	res, err := scan.Run(ctx, abs, s.Options)
	if err != nil {
		return sc, err
	}
	sc.Files = res.Files
	sc.Findings = s.Evaluate(asset, res.Hits)
	sc.FinishedAt = now().UTC()
	return sc, nil
}

// Evaluate convierte usos crudos en hallazgos evaluados. Los nombres que el catalogo no conoce se
// descartan salvo que el detector los marque explicitamente como "unknown" (una clave que no pudo leer).
func (s *Scanner) Evaluate(asset string, hits []scan.Hit) []domain.Finding {
	seen := map[string]int{}
	var out []domain.Finding
	for _, h := range hits {
		r := h.Raw
		alg, ok := s.Catalog.Resolve(r.Name)
		if !ok {
			if r.Name != "unknown" {
				continue
			}
			alg = catalog.Algorithm{ID: "unknown", Name: "Desconocido", Primitive: "other", Quantum: domain.QuantumUnknown,
				Note: "No se pudo identificar el algoritmo; revisar a mano."}
		}
		prim := domain.Primitive(alg.Primitive)
		if r.Primitive != "" {
			prim = domain.Primitive(r.Primitive)
		}
		u := domain.Usage{
			AlgorithmID: alg.ID, KeyBits: r.KeyBits, Curve: r.Curve, Primitive: prim,
			Location: domain.Location{Path: h.Path, Line: r.Line, Column: r.Column},
			Asset:    asset, Detector: h.Detector, Context: r.Context, Evidence: r.Evidence, Confidence: r.Confidence,
			InTests: domain.IsTestPath(h.Path),
		}
		if u.InTests && s.SkipTests {
			continue
		}
		if r.Cert != nil {
			u.Certificate = &domain.CertInfo{Subject: r.Cert.Subject, Issuer: r.Cert.Issuer, SignatureAlg: r.Cert.SignatureAlg,
				NotBefore: time.Unix(r.Cert.NotBefore, 0).UTC(), NotAfter: time.Unix(r.Cert.NotAfter, 0).UTC(), SelfSigned: r.Cert.SelfSigned}
		}
		u.ID = domain.Fingerprint(asset, u.Location.Path, u.Location.Line, u.AlgorithmID, u.Context)
		f := domain.Finding{Usage: u, AlgorithmName: alg.Name, Assessment: risk.Assess(u, alg, s.Policy)}
		// Un mismo algoritmo en la misma linea es un solo uso; se queda el que tiene mas detalle.
		key := fmt.Sprintf("%s\x00%d\x00%s", u.Location.Path, u.Location.Line, u.AlgorithmID)
		if i, dup := seen[key]; dup {
			if detail(f) > detail(out[i]) {
				out[i] = f
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	SortFindings(out)
	return out
}

func detail(f domain.Finding) int {
	n := 0
	if f.KeyBits > 0 {
		n += 2
	}
	if f.Curve != "" {
		n += 2
	}
	if f.Certificate != nil {
		n += 4
	}
	return n + map[string]int{"alta": 1}[f.Confidence]
}

// SortFindings ordena por puntaje (desc), luego ruta y linea.
func SortFindings(fs []domain.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Assessment.Score != b.Assessment.Score {
			return a.Assessment.Score > b.Assessment.Score
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		return a.Location.Line < b.Location.Line
	})
}

// Summary agrega numeros para informes y para el panel.
type Summary struct {
	Asset       string         `json:"asset"`
	Files       int            `json:"files_scanned"`
	Findings    int            `json:"findings"`
	Readiness   int            `json:"readiness"`
	BySeverity  map[string]int `json:"by_severity"`
	ByQuantum   map[string]int `json:"by_quantum_status"`
	ByAlgorithm map[string]int `json:"by_algorithm"`
	Certs       int            `json:"certificates"`
	InTests     int            `json:"in_tests"`
}

// Summarize calcula el resumen de un escaneo.
func Summarize(sc domain.Scan) Summary {
	s := Summary{Asset: sc.Asset, Files: sc.Files, Findings: len(sc.Findings), Readiness: sc.Readiness(),
		BySeverity: map[string]int{}, ByQuantum: map[string]int{}, ByAlgorithm: map[string]int{}}
	certs := map[string]bool{}
	for _, f := range sc.Findings {
		s.BySeverity[string(f.Assessment.Severity)]++
		s.ByQuantum[string(f.Assessment.QuantumStatus)]++
		s.ByAlgorithm[f.AlgorithmName]++
		if f.InTests {
			s.InTests++
		}
		if f.Certificate != nil {
			certs[f.Location.Path+"#"+strings.TrimSpace(f.Certificate.Subject)] = true
		}
	}
	s.Certs = len(certs)
	return s
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
