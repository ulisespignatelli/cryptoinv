// Package export escribe un escaneo en distintos formatos: texto para la terminal, JSON propio,
// SARIF 2.1.0 (GitHub code scanning) y CycloneDX 1.6 CBOM (inventario criptografico estandar).
package export

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/catalog"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// Formats soportados.
var Formats = []string{"text", "json", "sarif", "cbom"}

// Write escribe el escaneo en el formato pedido.
func Write(w io.Writer, format string, sc domain.Scan, cat *catalog.Catalog, version string) error {
	switch format {
	case "text", "":
		return Text(w, sc, cat)
	case "json":
		return JSON(w, sc)
	case "sarif":
		return SARIF(w, sc, version)
	case "cbom":
		return CBOM(w, sc, cat, version)
	}
	return fmt.Errorf("formato desconocido %q (usar: %s)", format, strings.Join(Formats, ", "))
}

// JSON es el formato nativo: el escaneo completo mas el resumen.
func JSON(w io.Writer, sc domain.Scan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Schema  string      `json:"schema"`
		Summary app.Summary `json:"summary"`
		domain.Scan
	}{"cryptoinv/scan/v1", app.Summarize(sc), sc})
}

// Text es el informe para la terminal.
func Text(w io.Writer, sc domain.Scan, cat *catalog.Catalog) error {
	s := app.Summarize(sc)
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	p("cryptoinv — inventario criptográfico de %s\n", sc.Asset)
	p("%d archivos analizados · %d usos de criptografía (%d en pruebas) · preparación post-cuántica %d%%\n\n", s.Files, s.Findings,
		s.InTests, s.Readiness)
	if len(sc.Findings) == 0 {
		p("No se encontró criptografía.\n")
		return nil
	}
	p("Por severidad: ")
	for _, sev := range []domain.Severity{domain.SevCritical, domain.SevHigh, domain.SevMedium, domain.SevLow, domain.SevInfo} {
		p("%s %d  ", sev, s.BySeverity[string(sev)])
	}
	p("\n\nAlgoritmos:\n")
	type kv struct {
		k string
		v int
	}
	var algs []kv
	for k, v := range s.ByAlgorithm {
		algs = append(algs, kv{k, v})
	}
	sort.Slice(algs, func(i, j int) bool { return algs[i].v > algs[j].v || algs[i].v == algs[j].v && algs[i].k < algs[j].k })
	for _, a := range algs {
		p("  %-28s %d\n", a.k, a.v)
	}
	p("\nHallazgos (de mayor a menor urgencia):\n")
	for _, f := range sc.Findings {
		params := ""
		if f.KeyBits > 0 {
			params = fmt.Sprintf(" %d bits", f.KeyBits)
		}
		if f.Curve != "" {
			params += " " + f.Curve
		}
		tag := ""
		if f.InTests {
			tag = " (prueba)"
		}
		p("\n  [%s %d] %s%s — %s:%d%s\n", strings.ToUpper(string(f.Assessment.Severity)), f.Assessment.Score, f.AlgorithmName, params,
			f.Location.Path, f.Location.Line, tag)
		if f.Evidence != "" {
			p("    %s\n", f.Evidence)
		}
		for _, r := range f.Assessment.Reasons {
			p("    · %s\n", r)
		}
		if f.Assessment.Replacement != "" {
			p("    → reemplazo: %s\n", f.Assessment.Replacement)
		}
	}
	p("\nCatálogo %s · fuentes: NIST IR 8547, FIPS 203/204/205, SP 800-131A, CNSA 2.0\n", cat.Version)
	return nil
}
