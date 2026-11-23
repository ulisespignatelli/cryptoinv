package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// Plan de migracion: agrupa los hallazgos en tareas concretas ("reemplazar ECDH por ML-KEM en 4
// archivos") y las ordena en tres olas.
//
//	Ola 1 — Ahora: lo que ya es inseguro hoy, lo que NIST ya prohibe, y el intercambio de claves
//	        vulnerable (lo cifrado hoy puede grabarse y descifrarse mañana).
//	Ola 2 — Antes de 2030: firmas y certificados vulnerables (fecha de desaprobacion de NIST IR 8547).
//	Ola 3 — Revisar: lo que no se pudo clasificar y lo que solo aparece en pruebas.

// PlanItem es una tarea del plan.
type PlanItem struct {
	ID          string            `json:"id"`
	Wave        int               `json:"wave"`
	Title       string            `json:"title"`
	Why         string            `json:"why"`
	AlgorithmID string            `json:"algorithm_id"`
	Algorithm   string            `json:"algorithm"`
	Primitive   string            `json:"primitive"`
	Replacement string            `json:"replacement"`
	Findings    int               `json:"findings"`
	Files       int               `json:"files"`
	MaxScore    int               `json:"max_score"`
	Severity    string            `json:"severity"`
	Effort      string            `json:"effort"` // S | M | L, por cantidad de archivos
	TestsOnly   bool              `json:"tests_only"`
	Locations   []domain.Location `json:"locations"` // hasta 8, las mas riesgosas
}

// Wave describe una ola.
type Wave struct {
	Number   int        `json:"number"`
	Title    string     `json:"title"`
	Deadline string     `json:"deadline"`
	Items    []PlanItem `json:"items"`
}

// MigrationPlan es el plan completo de un escaneo.
type MigrationPlan struct {
	ScanID   string `json:"scan_id"`
	Asset    string `json:"asset"`
	Waves    []Wave `json:"waves"`
	Excluded int    `json:"excluded"` // usos que no requieren accion (resistentes o aceptables)
}

// Plan arma el plan de migracion de un escaneo guardado.
func (s *Service) Plan(ctx context.Context, scanID string) (MigrationPlan, error) {
	sc, err := s.Repo.Get(ctx, scanID)
	if err != nil {
		return MigrationPlan{}, err
	}
	return BuildPlan(sc), nil
}

// BuildPlan es la logica pura del plan.
func BuildPlan(sc domain.Scan) MigrationPlan {
	p := MigrationPlan{ScanID: sc.ID, Asset: sc.Asset, Waves: []Wave{
		{Number: 1, Title: "Ahora", Deadline: "inmediato", Items: []PlanItem{}},
		{Number: 2, Title: "Antes de 2030", Deadline: "2030: NIST desaprueba los algoritmos vulnerables", Items: []PlanItem{}},
		{Number: 3, Title: "Revisar", Deadline: "sin fecha", Items: []PlanItem{}},
	}}
	type group struct {
		item  PlanItem
		files map[string]bool
		prod  bool
		locs  []domain.Finding
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range sc.Findings {
		wave, why := waveOf(f)
		if wave == 0 {
			p.Excluded++
			continue
		}
		key := fmt.Sprintf("%d|%s|%s", wave, f.AlgorithmID, f.Primitive)
		g, ok := groups[key]
		if !ok {
			g = &group{item: PlanItem{ID: key, Wave: wave, Why: why, AlgorithmID: f.AlgorithmID, Algorithm: f.AlgorithmName,
				Primitive: string(f.Primitive), Replacement: f.Assessment.Replacement}, files: map[string]bool{}}
			groups[key] = g
			order = append(order, key)
		}
		g.item.Findings++
		g.files[f.Location.Path] = true
		if !f.InTests {
			g.prod = true
		}
		if f.Assessment.Score > g.item.MaxScore {
			g.item.MaxScore, g.item.Severity = f.Assessment.Score, string(f.Assessment.Severity)
		}
		g.locs = append(g.locs, f)
	}
	for _, k := range order {
		g := groups[k]
		it := g.item
		it.Files = len(g.files)
		it.TestsOnly = !g.prod
		it.Effort = effort(it.Files)
		it.Title = title(it)
		sort.SliceStable(g.locs, func(i, j int) bool {
			if g.locs[i].InTests != g.locs[j].InTests {
				return !g.locs[i].InTests
			}
			return g.locs[i].Assessment.Score > g.locs[j].Assessment.Score
		})
		for i := 0; i < len(g.locs) && i < 8; i++ {
			it.Locations = append(it.Locations, g.locs[i].Location)
		}
		w := &p.Waves[it.Wave-1]
		w.Items = append(w.Items, it)
	}
	for i := range p.Waves {
		items := p.Waves[i].Items
		sort.SliceStable(items, func(a, b int) bool {
			if items[a].TestsOnly != items[b].TestsOnly {
				return !items[a].TestsOnly
			}
			if items[a].MaxScore != items[b].MaxScore {
				return items[a].MaxScore > items[b].MaxScore
			}
			return items[a].Files > items[b].Files
		})
	}
	return p
}

func waveOf(f domain.Finding) (int, string) {
	a := f.Assessment
	if f.InTests && a.QuantumStatus != domain.QuantumResistant && a.Severity.Rank() >= domain.SevLow.Rank() {
		return 3, "Solo en pruebas o ejemplos: actualizar cuando se migre el código real, para que los tests cubran los algoritmos nuevos."
	}
	switch a.QuantumStatus {
	case domain.ClassicallyBroken:
		return 1, "Ya es inseguro hoy, sin necesidad de una computadora cuántica."
	case domain.QuantumVulnerable:
		if a.Severity == domain.SevCritical {
			return 1, "Por debajo del mínimo aceptable hoy o fuera de los plazos de NIST."
		}
		switch f.Primitive {
		case domain.PrimKeyAgree, domain.PrimPKE, domain.PrimKEM:
			return 1, "Protege confidencialidad: el tráfico de hoy puede grabarse y descifrarse cuando exista la computadora cuántica."
		}
		return 2, "Firma o autenticación vulnerable: el recambio de claves y certificados lleva años y tiene que terminar antes de 2030."
	case domain.QuantumUnknown:
		return 3, "No se pudo identificar el algoritmo: revisar a mano."
	}
	if a.Severity.Rank() >= domain.SevMedium.Rank() {
		return 3, "Parámetros por debajo de lo recomendado."
	}
	return 0, ""
}

func effort(files int) string {
	switch {
	case files <= 3:
		return "S"
	case files <= 15:
		return "M"
	}
	return "L"
}

func title(it PlanItem) string {
	verb := map[string]string{"signature": "en firmas", "key-agree": "en intercambio de claves", "pke": "en cifrado",
		"kem": "en encapsulamiento", "hash": "como hash", "mac": "en MAC", "protocol": "como protocolo",
		"block-cipher": "como cifrado", "stream-cipher": "como cifrado", "ae": "como cifrado", "kdf": "en derivación de claves"}[it.Primitive]
	files := "1 archivo"
	if it.Files != 1 {
		files = fmt.Sprintf("%d archivos", it.Files)
	}
	if it.Primitive == "protocol" {
		return fmt.Sprintf("Deshabilitar %s (%s)", it.Algorithm, files)
	}
	return fmt.Sprintf("Reemplazar %s %s (%s)", it.Algorithm, verb, files)
}
