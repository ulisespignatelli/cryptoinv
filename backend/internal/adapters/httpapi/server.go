// Package httpapi expone los casos de uso por HTTP (contrato en api/openapi.yaml) y sirve el panel web
// embebido en el binario.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/adapters/export"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// Config del servidor.
type Config struct {
	// Token, si no esta vacio, se exige como "Authorization: Bearer <token>" en las operaciones que
	// modifican datos. Es obligatorio cuando el servidor no escucha solo en localhost.
	Token string
	// AllowScan habilita POST /api/v1/scans (escanear rutas del equipo donde corre el servidor).
	AllowScan bool
	// Loopback indica que el servidor escucha solo en localhost: se valida el encabezado Host para
	// evitar ataques de DNS rebinding.
	Loopback bool
	Version  string
	Logger   *slog.Logger
	Now      func() time.Time
}

// Server es el handler HTTP.
type Server struct {
	svc *app.Service
	cfg Config
	mux *http.ServeMux
}

// New arma el servidor con todas las rutas.
func New(svc *app.Service, cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{svc: svc, cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/health", s.health)
	m.HandleFunc("GET /api/v1/catalog", s.catalog)
	m.HandleFunc("GET /api/v1/overview", s.overview)
	m.HandleFunc("GET /api/v1/scans", s.listScans)
	m.HandleFunc("POST /api/v1/scans", s.mutating(s.createScan))
	m.HandleFunc("POST /api/v1/scans/import", s.mutating(s.importScan))
	m.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	m.HandleFunc("DELETE /api/v1/scans/{id}", s.mutating(s.deleteScan))
	m.HandleFunc("GET /api/v1/scans/{id}/findings", s.findings)
	m.HandleFunc("GET /api/v1/scans/{id}/plan", s.plan)
	m.HandleFunc("GET /api/v1/scans/{id}/certificates", s.certificates)
	m.HandleFunc("GET /api/v1/scans/{id}/export", s.exportScan)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "ruta inexistente") })
	m.Handle("/", uiHandler())
}

// ServeHTTP aplica los middlewares comunes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.cfg.Now()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if s.cfg.Loopback && !loopbackHost(r.Host) {
		writeErr(w, http.StatusMisdirectedRequest, "host no permitido")
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	defer func() {
		if v := recover(); v != nil {
			s.cfg.Logger.Error("pánico", "error", v, "path", r.URL.Path)
			writeErr(rec, http.StatusInternalServerError, "error interno")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			s.cfg.Logger.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"ms", s.cfg.Now().Sub(start).Milliseconds())
		}
	}()
	s.mux.ServeHTTP(rec, r)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// mutating protege las operaciones que cambian datos: token (si hay) y defensa contra CSRF (el
// encabezado X-Requested-With no se puede mandar desde un formulario de otro sitio sin CORS, y el
// servidor no habilita CORS).
func (s *Server) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.cfg.Token {
			writeErr(w, http.StatusUnauthorized, "token inválido o ausente")
			return
		}
		if r.Header.Get("X-Requested-With") != "cryptoinv" {
			writeErr(w, http.StatusForbidden, "falta el encabezado X-Requested-With: cryptoinv")
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------- handlers

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "version": s.cfg.Version, "scan_enabled": s.cfg.AllowScan,
		"auth_required": s.cfg.Token != ""})
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	c := s.svc.Scanner.Catalog
	writeJSON(w, 200, map[string]any{"version": c.Version, "sources": c.Sources, "algorithms": c.All()})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	o, err := s.svc.Overview(r.Context())
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	list, err := s.svc.Repo.List(r.Context())
	if s.fail(w, err) {
		return
	}
	if a := r.URL.Query().Get("asset"); a != "" {
		var f []app.ScanMeta
		for _, m := range list {
			if m.Asset == a {
				f = append(f, m)
			}
		}
		list = f
	}
	if list == nil {
		list = []app.ScanMeta{}
	}
	writeJSON(w, 200, list)
}

type createScanReq struct {
	Path  string `json:"path"`
	Asset string `json:"asset"`
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowScan {
		writeErr(w, http.StatusForbidden, "este servidor no permite escanear rutas (iniciar sin --no-scan)")
		return
	}
	var req createScanReq
	if !decode(w, r, &req, 1<<16) {
		return
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path == "" {
		writeErr(w, http.StatusBadRequest, "falta path")
		return
	}
	abs, err := filepath.Abs(req.Path)
	if err == nil {
		_, err = os.Stat(abs)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "la ruta no existe o no se puede leer")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	meta, err := s.svc.Scan(ctx, app.ScanRequest{Root: abs, Asset: strings.TrimSpace(req.Asset)})
	if s.fail(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) importScan(w http.ResponseWriter, r *http.Request) {
	var sc domain.Scan
	if !decode(w, r, &sc, 64<<20) {
		return
	}
	meta, err := s.svc.Import(r.Context(), sc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, meta)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	d, err := s.svc.Detail(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	if s.fail(w, s.svc.Repo.Delete(r.Context(), r.PathValue("id"))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list := func(k string) []string {
		var out []string
		for _, v := range q[k] {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
		}
		return out
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	tests := q.Get("tests")
	if tests != "" && tests != "include" && tests != "exclude" && tests != "only" {
		writeErr(w, http.StatusBadRequest, "tests debe ser include, exclude u only")
		return
	}
	page, err := s.svc.Findings(r.Context(), r.PathValue("id"), app.Filter{Severity: list("severity"), Quantum: list("quantum_status"),
		Algorithm: list("algorithm"), Detector: list("detector"), Query: q.Get("q"), Tests: tests, Limit: limit, Offset: offset})
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, page)
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	p, err := s.svc.Plan(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	c, err := s.svc.Certificates(r.Context(), r.PathValue("id"), s.cfg.Now())
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) exportScan(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	ext := map[string]string{"cbom": "cdx.json", "sarif": "sarif", "json": "json"}[format]
	if ext == "" {
		writeErr(w, http.StatusBadRequest, "format debe ser cbom, sarif o json")
		return
	}
	sc, err := s.svc.Repo.Get(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, safeName(sc.Asset), sc.ID, ext))
	if err := export.Write(w, format, sc, s.svc.Scanner.Catalog, s.cfg.Version); err != nil {
		s.cfg.Logger.Error("export", "error", err)
	}
}

// ---------------------------------------------------------------- utilidades

func (s *Server) fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, app.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no encontrado")
		return true
	}
	s.cfg.Logger.Error("api", "error", err)
	writeErr(w, http.StatusInternalServerError, "error interno")
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "se espera application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON inválido")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func safeName(s string) string {
	b := []rune(s)
	for i, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			b[i] = '-'
		}
	}
	if len(b) == 0 {
		return "scan"
	}
	return string(b)
}
