package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/testutil"
)

func TestScanProject(t *testing.T) {
	s := NewScanner()
	s.Policy.Now = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	sc, err := s.Run(context.Background(), ScanRequest{Root: testutil.Project(t), Asset: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.Asset != "demo" || sc.Files < 4 {
		t.Fatalf("escaneo: %+v", sc)
	}
	has := func(alg, path string) *domain.Finding {
		for i, f := range sc.Findings {
			if f.AlgorithmID == alg && strings.HasPrefix(f.Location.Path, path) {
				return &sc.Findings[i]
			}
		}
		return nil
	}
	for _, c := range []struct{ alg, path string }{{"rsa", "certs/"}, {"rsa", "cmd/"}, {"mlkem", "cmd/"}, {"md5", "app/"},
		{"hybrid-kex", "deploy/"}, {"ecdh", "deploy/"}, {"tls12", "deploy/"}} {
		if has(c.alg, c.path) == nil {
			t.Errorf("falta %s en %s", c.alg, c.path)
		}
	}
	for _, f := range sc.Findings {
		if strings.HasPrefix(f.Location.Path, "node_modules/") || strings.HasPrefix(f.Location.Path, "img/") {
			t.Errorf("no debería analizar %s", f.Location.Path)
		}
		if strings.Contains(f.Location.Path, "\\") {
			t.Errorf("rutas siempre con /: %s", f.Location.Path)
		}
	}
	if c := has("rsa", "certs/"); c == nil || c.Certificate == nil || c.Certificate.Subject == "" {
		t.Fatal("el certificado debería traer sus metadatos")
	}
	// Ordenado de mayor a menor riesgo; RSA-1024 primero.
	if sc.Findings[0].AlgorithmID != "rsa" || sc.Findings[0].KeyBits != 1024 {
		t.Fatalf("primer hallazgo: %+v", sc.Findings[0])
	}
	if r := sc.Readiness(); r <= 0 || r >= 100 {
		t.Fatalf("preparación fuera de rango: %d", r)
	}
	if f := has("sha1", "cmd/main_test.go"); f == nil || !f.InTests {
		t.Fatalf("el uso en un test debería marcarse: %+v", f)
	}
	sum := Summarize(sc)
	if sum.Findings != len(sc.Findings) || sum.Certs != 1 || sum.InTests != 1 {
		t.Fatalf("resumen: %+v", sum)
	}
}

func TestFingerprintsAreStable(t *testing.T) {
	dir := testutil.Project(t)
	a, _ := NewScanner().Run(context.Background(), ScanRequest{Root: dir, Asset: "x"})
	b, _ := NewScanner().Run(context.Background(), ScanRequest{Root: dir, Asset: "x"})
	if len(a.Findings) != len(b.Findings) {
		t.Fatal("dos escaneos iguales deberían dar lo mismo")
	}
	ids := map[string]bool{}
	for _, f := range a.Findings {
		ids[f.ID] = true
	}
	for _, f := range b.Findings {
		if !ids[f.ID] {
			t.Fatalf("ID inestable: %s", f.ID)
		}
	}
}

func TestExcludeAndSkipTests(t *testing.T) {
	s := NewScanner()
	s.Options.Exclude = []string{"deploy/**", "*.py"}
	s.SkipTests = true
	sc, err := s.Run(context.Background(), ScanRequest{Root: testutil.Project(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range sc.Findings {
		if strings.HasPrefix(f.Location.Path, "deploy/") || strings.HasSuffix(f.Location.Path, ".py") || f.InTests {
			t.Errorf("debería estar excluido: %s", f.Location.Path)
		}
	}
}
