package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/adapters/store"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/testutil"
)

func setup(t *testing.T, cfg Config) (*Server, *app.Service, string) {
	t.Helper()
	repo, err := store.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := &app.Service{Repo: repo, Scanner: app.NewScanner()}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(svc, cfg), svc, testutil.Project(t)
}

func do(t *testing.T, h http.Handler, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "localhost:8080"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var csrf = map[string]string{"X-Requested-With": "cryptoinv"}

func TestScanFlow(t *testing.T) {
	h, _, dir := setup(t, Config{AllowScan: true, Loopback: true, Version: "test"})

	rec := do(t, h, "POST", "/api/v1/scans", map[string]string{"path": dir, "asset": "demo"}, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("crear: %d %s", rec.Code, rec.Body)
	}
	var meta app.ScanMeta
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta.ID == "" || meta.Summary.Findings == 0 {
		t.Fatalf("meta: %+v", meta)
	}
	for _, p := range []string{"/api/v1/health", "/api/v1/catalog", "/api/v1/overview", "/api/v1/scans", "/api/v1/scans/" + meta.ID,
		"/api/v1/scans/" + meta.ID + "/plan", "/api/v1/scans/" + meta.ID + "/certificates",
		"/api/v1/scans/" + meta.ID + "/findings?severity=critica,alta&tests=exclude&limit=5"} {
		if rec := do(t, h, "GET", p, nil, nil); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	var page app.FindingsPage
	_ = json.Unmarshal(do(t, h, "GET", "/api/v1/scans/"+meta.ID+"/findings?limit=2", nil, nil).Body.Bytes(), &page)
	if len(page.Items) != 2 || page.Total != meta.Summary.Findings {
		t.Fatalf("página: %d de %d", len(page.Items), page.Total)
	}
	for _, f := range []string{"cbom", "sarif", "json"} {
		rec := do(t, h, "GET", "/api/v1/scans/"+meta.ID+"/export?format="+f, nil, nil)
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "demo-") {
			t.Errorf("export %s: %d", f, rec.Code)
		}
	}
	if rec := do(t, h, "GET", "/api/v1/scans/"+meta.ID+"/export?format=xml", nil, nil); rec.Code != 400 {
		t.Error("formato inválido")
	}
	if rec := do(t, h, "GET", "/api/v1/scans/nope", nil, nil); rec.Code != 404 {
		t.Error("inexistente")
	}
	if rec := do(t, h, "GET", "/api/v1/nada", nil, nil); rec.Code != 404 {
		t.Error("ruta inexistente de la API")
	}
	if rec := do(t, h, "DELETE", "/api/v1/scans/"+meta.ID, nil, csrf); rec.Code != 204 {
		t.Errorf("borrar: %d", rec.Code)
	}
}

func TestSecurity(t *testing.T) {
	h, _, dir := setup(t, Config{AllowScan: true, Loopback: true, Token: "s3creto"})
	body := map[string]string{"path": dir}
	if rec := do(t, h, "POST", "/api/v1/scans", body, csrf); rec.Code != 401 {
		t.Errorf("sin token: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/v1/scans", body, map[string]string{"Authorization": "Bearer s3creto"}); rec.Code != 403 {
		t.Errorf("sin encabezado anti-CSRF: %d", rec.Code)
	}
	ok := map[string]string{"Authorization": "Bearer s3creto", "X-Requested-With": "cryptoinv"}
	if rec := do(t, h, "POST", "/api/v1/scans", body, ok); rec.Code != 201 {
		t.Errorf("con token: %d %s", rec.Code, rec.Body)
	}
	// DNS rebinding: un Host ajeno no puede hablar con el servidor local.
	req := httptest.NewRequest("GET", "/api/v1/overview", nil)
	req.Host = "evil.example:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("host ajeno: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Error("falta CSP")
	}
	if rec := do(t, h, "POST", "/api/v1/scans", map[string]string{"path": filepath.Join(dir, "no-existe")}, ok); rec.Code != 400 {
		t.Errorf("ruta inexistente: %d", rec.Code)
	}
	ro, _, _ := setup(t, Config{AllowScan: false, Loopback: true})
	if rec := do(t, ro, "POST", "/api/v1/scans", body, csrf); rec.Code != 403 {
		t.Errorf("--no-scan: %d", rec.Code)
	}
}

func TestImportAndSnapshot(t *testing.T) {
	h, svc, dir := setup(t, Config{Loopback: true})
	sc, err := svc.Scanner.Run(context.Background(), app.ScanRequest{Root: dir, Asset: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, "POST", "/api/v1/scans/import", sc, csrf); rec.Code != 201 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "POST", "/api/v1/scans/import", sc, csrf); rec.Code != 400 {
		t.Fatal("importar dos veces el mismo ID debería fallar")
	}
	out := t.TempDir()
	if err := WriteSnapshot(context.Background(), svc, out, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"overview.json", "scans.json", "catalog.json", "scans/" + sc.ID + ".json",
		"scans/" + sc.ID + "/findings.json", "scans/" + sc.ID + "/plan.json", "scans/" + sc.ID + "/certificates.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("falta %s", f)
		}
	}
}

func TestUIFallback(t *testing.T) {
	h, _, _ := setup(t, Config{Loopback: true})
	rec := do(t, h, "GET", "/", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "cryptoinv") {
		t.Fatalf("panel: %d", rec.Code)
	}
}
