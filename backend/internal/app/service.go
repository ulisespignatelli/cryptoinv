package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/risk"
)

// Service reune los casos de uso que exponen la API y el panel.
type Service struct {
	Repo    ScanRepository
	Scanner *Scanner
}

// Scan ejecuta un escaneo y lo guarda.
func (s *Service) Scan(ctx context.Context, req ScanRequest) (ScanMeta, error) {
	sc, err := s.Scanner.Run(ctx, req)
	if err != nil {
		return ScanMeta{}, err
	}
	if err := s.Repo.Save(ctx, sc); err != nil {
		return ScanMeta{}, err
	}
	return Meta(sc), nil
}

// Import guarda un escaneo hecho en otro lado (por ejemplo, en CI con --format json). Los hallazgos se
// vuelven a evaluar con el catalogo y la politica de este servidor para que todo sea comparable.
func (s *Service) Import(ctx context.Context, sc domain.Scan) (ScanMeta, error) {
	if sc.Asset == "" {
		return ScanMeta{}, errors.New("el escaneo no tiene activo")
	}
	if sc.ID == "" {
		sc.ID = newID()
	}
	if _, err := s.Repo.Get(ctx, sc.ID); err == nil {
		return ScanMeta{}, errors.New("ya existe un escaneo con ese ID")
	}
	for i, f := range sc.Findings {
		alg, ok := s.Scanner.Catalog.Get(f.AlgorithmID)
		if !ok {
			continue
		}
		sc.Findings[i].AlgorithmName = alg.Name
		sc.Findings[i].Assessment = risk.Assess(f.Usage, alg, s.Scanner.Policy)
	}
	SortFindings(sc.Findings)
	if err := s.Repo.Save(ctx, sc); err != nil {
		return ScanMeta{}, err
	}
	return Meta(sc), nil
}

// ---------------------------------------------------------------- Vista general

// Point es un punto de la evolucion de un activo.
type Point struct {
	ScanID    string    `json:"scan_id"`
	At        time.Time `json:"at"`
	Readiness int       `json:"readiness"`
	Findings  int       `json:"findings"`
}

// AssetStatus es el estado de un sistema segun su ultimo escaneo.
type AssetStatus struct {
	Asset    string    `json:"asset"`
	Latest   Summary   `json:"latest"`
	LatestID string    `json:"latest_scan_id"`
	LatestAt time.Time `json:"latest_at"`
	Scans    int       `json:"scans"`
	Trend    []Point   `json:"trend"` // del mas viejo al mas nuevo
}

// Overview es la portada del panel.
type Overview struct {
	Assets         []AssetStatus  `json:"assets"`
	Readiness      int            `json:"readiness"` // ponderada por cantidad de usos
	Findings       int            `json:"findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByQuantum      map[string]int `json:"by_quantum_status"`
	ByAlgorithm    map[string]int `json:"by_algorithm"`
	Certificates   int            `json:"certificates"`
	CatalogVersion string         `json:"catalog_version"`
}

// Overview combina el ultimo escaneo de cada activo.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	metas, err := s.Repo.List(ctx)
	if err != nil {
		return Overview{}, err
	}
	o := Overview{BySeverity: map[string]int{}, ByQuantum: map[string]int{}, ByAlgorithm: map[string]int{},
		CatalogVersion: s.Scanner.Catalog.Version, Assets: []AssetStatus{}}
	idx := map[string]int{}
	for _, m := range metas { // del mas nuevo al mas viejo
		i, ok := idx[m.Asset]
		if !ok {
			idx[m.Asset] = len(o.Assets)
			o.Assets = append(o.Assets, AssetStatus{Asset: m.Asset, Latest: m.Summary, LatestID: m.ID, LatestAt: m.StartedAt})
			i = len(o.Assets) - 1
		}
		a := &o.Assets[i]
		a.Scans++
		a.Trend = append([]Point{{ScanID: m.ID, At: m.StartedAt, Readiness: m.Summary.Readiness, Findings: m.Summary.Findings}}, a.Trend...)
	}
	ok := 0
	for _, a := range o.Assets {
		l := a.Latest
		o.Findings += l.Findings
		o.Certificates += l.Certs
		ok += l.Readiness * l.Findings
		for k, v := range l.BySeverity {
			o.BySeverity[k] += v
		}
		for k, v := range l.ByQuantum {
			o.ByQuantum[k] += v
		}
		for k, v := range l.ByAlgorithm {
			o.ByAlgorithm[k] += v
		}
	}
	o.Readiness = 100
	if o.Findings > 0 {
		o.Readiness = ok / o.Findings
	}
	sort.SliceStable(o.Assets, func(i, j int) bool { return o.Assets[i].Latest.Readiness < o.Assets[j].Latest.Readiness })
	return o, nil
}

// ---------------------------------------------------------------- Detalle e inventario

// ScanDetail es un escaneo con la comparacion contra el anterior del mismo activo.
type ScanDetail struct {
	ScanMeta
	PreviousID string `json:"previous_scan_id,omitempty"`
	New        int    `json:"new_findings"`
	Resolved   int    `json:"resolved_findings"`
}

// Detail devuelve un escaneo y cuantos hallazgos aparecieron o se resolvieron desde el anterior.
func (s *Service) Detail(ctx context.Context, id string) (ScanDetail, error) {
	sc, err := s.Repo.Get(ctx, id)
	if err != nil {
		return ScanDetail{}, err
	}
	d := ScanDetail{ScanMeta: Meta(sc)}
	metas, err := s.Repo.List(ctx)
	if err != nil {
		return d, err
	}
	for _, m := range metas {
		if m.Asset == sc.Asset && m.StartedAt.Before(sc.StartedAt) && m.ID != sc.ID {
			prev, err := s.Repo.Get(ctx, m.ID)
			if err != nil {
				break
			}
			d.PreviousID = m.ID
			d.New, d.Resolved = diff(prev.Findings, sc.Findings)
			break
		}
	}
	return d, nil
}

// diff compara por ubicacion + algoritmo (sin linea: mover codigo no es un hallazgo nuevo).
func diff(before, after []domain.Finding) (added, resolved int) {
	key := func(f domain.Finding) string { return f.Location.Path + "\x00" + f.AlgorithmID + "\x00" + f.Context }
	count := func(fs []domain.Finding) map[string]int {
		m := map[string]int{}
		for _, f := range fs {
			m[key(f)]++
		}
		return m
	}
	b, a := count(before), count(after)
	for k, n := range a {
		if n > b[k] {
			added += n - b[k]
		}
	}
	for k, n := range b {
		if n > a[k] {
			resolved += n - a[k]
		}
	}
	return
}

// Filter para el inventario. Los campos vacios no filtran.
type Filter struct {
	Severity  []string
	Quantum   []string
	Algorithm []string
	Detector  []string
	Query     string // busca en ruta, evidencia, contexto y algoritmo
	Tests     string // include (por defecto) | exclude | only
	Limit     int
	Offset    int
}

// FindingsPage es una pagina del inventario con conteos para los filtros.
type FindingsPage struct {
	Items  []domain.Finding          `json:"items"`
	Total  int                       `json:"total"`
	Facets map[string]map[string]int `json:"facets"` // severity, quantum_status, algorithm, detector
}

// Findings filtra y pagina los hallazgos de un escaneo.
func (s *Service) Findings(ctx context.Context, scanID string, f Filter) (FindingsPage, error) {
	sc, err := s.Repo.Get(ctx, scanID)
	if err != nil {
		return FindingsPage{}, err
	}
	return FilterFindings(sc.Findings, f), nil
}

// FilterFindings es la logica pura del inventario (tambien la replica el modo demo del panel).
func FilterFindings(all []domain.Finding, f Filter) FindingsPage {
	in := func(v string, set []string) bool {
		if len(set) == 0 {
			return true
		}
		for _, s := range set {
			if strings.EqualFold(s, v) {
				return true
			}
		}
		return false
	}
	q := strings.ToLower(strings.TrimSpace(f.Query))
	p := FindingsPage{Items: []domain.Finding{}, Facets: map[string]map[string]int{
		"severity": {}, "quantum_status": {}, "algorithm": {}, "detector": {}}}
	for _, x := range all {
		switch f.Tests {
		case "exclude":
			if x.InTests {
				continue
			}
		case "only":
			if !x.InTests {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(x.Location.Path+" "+x.Evidence+" "+x.Context+" "+x.AlgorithmName), q) {
			continue
		}
		sev, qs := string(x.Assessment.Severity), string(x.Assessment.QuantumStatus)
		// Cada faceta cuenta con los demas filtros aplicados, para que los numeros sean utiles.
		mSev, mQ, mAlg, mDet := in(sev, f.Severity), in(qs, f.Quantum), in(x.AlgorithmID, f.Algorithm), in(x.Detector, f.Detector)
		if mQ && mAlg && mDet {
			p.Facets["severity"][sev]++
		}
		if mSev && mAlg && mDet {
			p.Facets["quantum_status"][qs]++
		}
		if mSev && mQ && mDet {
			p.Facets["algorithm"][x.AlgorithmID]++
		}
		if mSev && mQ && mAlg {
			p.Facets["detector"][x.Detector]++
		}
		if mSev && mQ && mAlg && mDet {
			p.Total++
			p.Items = append(p.Items, x)
		}
	}
	if f.Offset > 0 {
		if f.Offset >= len(p.Items) {
			p.Items = []domain.Finding{}
		} else {
			p.Items = p.Items[f.Offset:]
		}
	}
	if f.Limit > 0 && len(p.Items) > f.Limit {
		p.Items = p.Items[:f.Limit]
	}
	return p
}

// Certificate es un certificado del inventario con su estado.
type Certificate struct {
	domain.CertInfo
	FindingID string `json:"finding_id"`
	Path      string `json:"path"`
	Line      int    `json:"line"`
	KeyAlg    string `json:"key_algorithm"`
	KeyBits   int    `json:"key_bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Severity  string `json:"severity"`
	Score     int    `json:"score"`
	DaysLeft  int    `json:"days_left"`
	InTests   bool   `json:"in_tests,omitempty"`
	WeakHash  bool   `json:"weak_signature_hash"`
}

// Certificates lista los certificados de un escaneo, los que vencen antes primero.
func (s *Service) Certificates(ctx context.Context, scanID string, now time.Time) ([]Certificate, error) {
	sc, err := s.Repo.Get(ctx, scanID)
	if err != nil {
		return nil, err
	}
	return CertificatesOf(sc, now), nil
}

// CertificatesOf es la logica pura de Certificates.
func CertificatesOf(sc domain.Scan, now time.Time) []Certificate {
	byKey := map[string]*Certificate{}
	var order []string
	for _, f := range sc.Findings {
		if f.Certificate == nil {
			continue
		}
		k := f.Location.Path + "#" + itoa(f.Location.Line)
		c, ok := byKey[k]
		if !ok {
			c = &Certificate{CertInfo: *f.Certificate, Path: f.Location.Path, Line: f.Location.Line, InTests: f.InTests,
				DaysLeft: int(f.Certificate.NotAfter.Sub(now).Hours() / 24)}
			byKey[k] = c
			order = append(order, k)
		}
		if f.AlgorithmID == "sha1" || f.AlgorithmID == "md5" {
			c.WeakHash = true
		} else {
			c.FindingID, c.KeyAlg, c.KeyBits, c.Curve = f.ID, f.AlgorithmName, f.KeyBits, f.Curve
		}
		if f.Assessment.Score > c.Score {
			c.Score, c.Severity = f.Assessment.Score, string(f.Assessment.Severity)
		}
	}
	out := make([]Certificate, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
