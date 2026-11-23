// Comando cryptoinv: inventario criptografico y plan de migracion post-cuantica.
//
// Este archivo es la "raiz de composicion": el unico lugar que conoce todas las piezas y las conecta.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/adapters/export"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// version se completa al compilar: -ldflags "-X main.version=v0.1.0"
var version = "dev"

const usage = `cryptoinv — inventario criptográfico y preparación post-cuántica

Uso:
  cryptoinv scan [opciones] RUTA     escanea una carpeta o archivo
  cryptoinv catalog                  muestra el catálogo de algoritmos y fechas NIST
  cryptoinv version

Opciones de scan:
  --asset NOMBRE          nombre del sistema (por defecto, la carpeta)
  --format FORMATO        text | json | sarif | cbom  (por defecto text)
  --output ARCHIVO        escribe en un archivo en lugar de la salida estándar
  --shelf-life AÑOS       cuántos años tienen que seguir secretos los datos (por defecto 10)
  --migration-years AÑOS  cuánto tarda la organización en migrar (por defecto 3)
  --exclude PATRÓN        excluye rutas (se puede repetir)
  --skip-tests            ignora tests, fixtures y ejemplos (sin esta opción se
                          incluyen, marcados y con menos peso)
  --fail-on SEVERIDAD     termina con código 1 si hay hallazgos de esa severidad o mayor
                          (critica | alta | media | baja), útil en CI
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2, nil
	}
	switch args[0] {
	case "scan":
		return scanCmd(ctx, args[1:], stdout, stderr)
	case "catalog":
		return catalogCmd(stdout)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "cryptoinv", version)
		return 0, nil
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0, nil
	}
	fmt.Fprint(stderr, usage)
	return 2, fmt.Errorf("comando desconocido %q", args[0])
}

func scanCmd(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	asset := fs.String("asset", "", "")
	format := fs.String("format", "text", "")
	output := fs.String("output", "", "")
	shelf := fs.Int("shelf-life", 10, "")
	mig := fs.Int("migration-years", 3, "")
	failOn := fs.String("fail-on", "", "")
	skipTests := fs.Bool("skip-tests", false, "")
	var excludes multi
	fs.Var(&excludes, "exclude", "")
	if err := fs.Parse(reorder(args)); err != nil {
		return 2, nil
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2, errors.New("falta la RUTA a escanear")
	}
	if *shelf < 0 || *mig < 0 {
		return 2, errors.New("--shelf-life y --migration-years no pueden ser negativos")
	}

	s := app.NewScanner()
	s.Policy.ShelfLifeYears, s.Policy.MigrationYears = *shelf, *mig
	s.Options.Exclude = excludes
	s.SkipTests = *skipTests
	sc, err := s.Run(ctx, app.ScanRequest{Root: fs.Arg(0), Asset: *asset})
	if err != nil {
		return 1, err
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return 1, err
		}
		defer f.Close()
		w = f
	}
	if err := export.Write(w, *format, sc, s.Catalog, version); err != nil {
		return 2, err
	}
	if *output != "" {
		sum := app.Summarize(sc)
		fmt.Fprintf(stderr, "%d usos en %d archivos · preparación %d%% · escrito en %s\n", sum.Findings, sum.Files, sum.Readiness, *output)
	}
	if *failOn != "" {
		min := domain.Severity(strings.ToLower(*failOn)).Rank()
		if min == 0 {
			return 2, fmt.Errorf("--fail-on inválido %q", *failOn)
		}
		for _, f := range sc.Findings {
			if f.Assessment.Severity.Rank() >= min {
				return 1, nil
			}
		}
	}
	return 0, nil
}

var boolFlags = map[string]bool{"skip-tests": true}

// reorder permite poner las opciones despues de la ruta ("scan . --format json").
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !boolFlags[strings.TrimLeft(a, "-")] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func catalogCmd(w io.Writer) (int, error) {
	cat := app.NewScanner().Catalog
	fmt.Fprintf(w, "Catálogo %s\n\n%-12s %-22s %-14s %-10s %-10s %s\n", cat.Version, "ID", "NOMBRE", "CUÁNTICO", "DEPRECADO", "PROHIBIDO", "REEMPLAZO")
	for _, a := range cat.All() {
		d, p := "-", "-"
		if a.Deprecated > 0 {
			d = fmt.Sprint(a.Deprecated)
		}
		if a.Disallowed > 0 {
			p = fmt.Sprint(a.Disallowed)
		}
		fmt.Fprintf(w, "%-12s %-22s %-14s %-10s %-10s %s\n", a.ID, a.Name, a.Quantum, d, p, a.Replacement)
	}
	return 0, nil
}
