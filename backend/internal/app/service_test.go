package app

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/testutil"
)

// memRepo es un repositorio en memoria para probar los casos de uso sin disco.
type memRepo struct {
	mu sync.Mutex
	m  map[string]domain.Scan
}

func (r *memRepo) Save(_ context.Context, sc domain.Scan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]domain.Scan{}
	}
	r.m[sc.ID] = sc
	return nil
}
func (r *memRepo) Get(_ context.Context, id string) (domain.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sc, ok := r.m[id]
	if !ok {
		return sc, ErrNotFound
	}
	return sc, nil
}
func (r *memRepo) List(_ context.Context) ([]ScanMeta, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ScanMeta
	for _, sc := range r.m {
		out = append(out, Meta(sc))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}
func (r *memRepo) Delete(_ context.Context, id string) error { delete(r.m, id); return nil }

func newService(t *testing.T) (*Service, *time.Time) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	sc := NewScanner()
	sc.Now = func() time.Time { return now }
	sc.Policy.Now = func() time.Time { return now }
	return &Service{Repo: &memRepo{}, Scanner: sc}, &now
}

func TestOverviewTrendAndDiff(t *testing.T) {
	ctx := context.Background()
	svc, now := newService(t)
	dir := testutil.Project(t)
	first, err := svc.Scan(ctx, ScanRequest{Root: dir, Asset: "api"})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * time.Hour)
	testutil.Remove(t, dir, "app/hash.py") // se "arregla" el MD5
	second, _ := svc.Scan(ctx, ScanRequest{Root: dir, Asset: "api"})
	*now = now.Add(time.Hour)
	_, _ = svc.Scan(ctx, ScanRequest{Root: dir + "/deploy", Asset: "web"})

	o, err := svc.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Assets) != 2 {
		t.Fatalf("activos: %+v", o.Assets)
	}
	var api AssetStatus
	for _, a := range o.Assets {
		if a.Asset == "api" {
			api = a
		}
	}
	if api.Scans != 2 || len(api.Trend) != 2 || api.Trend[0].ScanID != first.ID || api.LatestID != second.ID {
		t.Fatalf("tendencia: %+v", api)
	}
	if o.Findings != o.Assets[0].Latest.Findings+o.Assets[1].Latest.Findings {
		t.Fatal("los totales suman el último escaneo de cada activo")
	}
	d, err := svc.Detail(ctx, second.ID)
	if err != nil || d.PreviousID != first.ID || d.Resolved != 1 || d.New != 0 {
		t.Fatalf("comparación: %v %+v", err, d)
	}
}

func TestFindingsFilter(t *testing.T) {
	ctx := context.Background()
	svc, _ := newService(t)
	m, _ := svc.Scan(ctx, ScanRequest{Root: testutil.Project(t), Asset: "api"})
	all, _ := svc.Findings(ctx, m.ID, Filter{})
	crit, _ := svc.Findings(ctx, m.ID, Filter{Severity: []string{"critica"}})
	if crit.Total == 0 || crit.Total >= all.Total {
		t.Fatalf("filtro severidad: %d de %d", crit.Total, all.Total)
	}
	for _, f := range crit.Items {
		if f.Assessment.Severity != domain.SevCritical {
			t.Fatal("se coló otra severidad")
		}
	}
	// La faceta de severidad no se achica por el propio filtro de severidad.
	if crit.Facets["severity"]["critica"] != crit.Total || len(crit.Facets["severity"]) < 2 {
		t.Fatalf("facetas: %+v", crit.Facets["severity"])
	}
	noTests, _ := svc.Findings(ctx, m.ID, Filter{Tests: "exclude"})
	only, _ := svc.Findings(ctx, m.ID, Filter{Tests: "only"})
	if noTests.Total+only.Total != all.Total || only.Total != 1 {
		t.Fatalf("tests: %d + %d != %d", noTests.Total, only.Total, all.Total)
	}
	q, _ := svc.Findings(ctx, m.ID, Filter{Query: "nginx"})
	if q.Total == 0 {
		t.Fatal("búsqueda por ruta")
	}
	page, _ := svc.Findings(ctx, m.ID, Filter{Limit: 2, Offset: 1})
	if len(page.Items) != 2 || page.Total != all.Total || page.Items[0].ID != all.Items[1].ID {
		t.Fatal("paginación")
	}
	if _, err := svc.Findings(ctx, "nope", Filter{}); err != ErrNotFound {
		t.Fatal("inexistente")
	}
}

func TestPlanAndCertificates(t *testing.T) {
	ctx := context.Background()
	svc, now := newService(t)
	m, _ := svc.Scan(ctx, ScanRequest{Root: testutil.Project(t), Asset: "api"})
	p, err := svc.Plan(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	waveOfAlg := map[string]int{}
	total := p.Excluded
	for _, w := range p.Waves {
		for _, it := range w.Items {
			waveOfAlg[it.AlgorithmID+"/"+it.Primitive] = w.Number
			total += it.Findings
			if it.Title == "" || it.Effort == "" || len(it.Locations) == 0 {
				t.Fatalf("tarea incompleta: %+v", it)
			}
		}
	}
	if total != m.Summary.Findings {
		t.Fatalf("el plan tiene que cubrir todos los usos: %d vs %d", total, m.Summary.Findings)
	}
	if waveOfAlg["md5/hash"] != 1 || waveOfAlg["ecdh/key-agree"] != 1 || waveOfAlg["sha1/hash"] != 3 {
		t.Fatalf("olas: %v", waveOfAlg)
	}
	if _, ok := waveOfAlg["mlkem/kem"]; ok {
		t.Fatal("ML-KEM no requiere acción")
	}
	certs, err := svc.Certificates(ctx, m.ID, *now)
	if err != nil || len(certs) != 1 || certs[0].KeyAlg == "" || certs[0].DaysLeft < 80 {
		t.Fatalf("certificados: %v %+v", err, certs)
	}
}
