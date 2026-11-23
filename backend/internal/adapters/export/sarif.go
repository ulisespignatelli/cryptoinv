package export

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// SARIF 2.1.0: una regla por algoritmo, un resultado por uso. Los usos resistentes no se reportan (no
// requieren accion) para no llenar la pestaña de seguridad de ruido.
func SARIF(w io.Writer, sc domain.Scan, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		Help             msg            `json:"help"`
		Properties       map[string]any `json:"properties"`
	}
	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type physical struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}

	rules := map[string]rule{}
	var results []result
	for _, f := range sc.Findings {
		st := f.Assessment.QuantumStatus
		if st == domain.QuantumResistant {
			continue
		}
		id := "cryptoinv/" + f.AlgorithmID
		if _, ok := rules[id]; !ok {
			rules[id] = rule{ID: id, Name: f.AlgorithmName,
				ShortDescription: msg{fmt.Sprintf("Uso de %s (%s)", f.AlgorithmName, statusES(st))},
				Help:             msg{"Reemplazo recomendado: " + or(f.Assessment.Replacement, "revisar")},
				Properties: map[string]any{"tags": []string{"security", "cryptography", "post-quantum"},
					"security-severity": fmt.Sprintf("%.1f", float64(f.Assessment.Score)/10)}}
		}
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = f.Location.Path
		if f.Location.Line > 0 {
			loc.PhysicalLocation.Region = &region{StartLine: f.Location.Line, StartColumn: f.Location.Column}
		}
		results = append(results, result{RuleID: id, Level: level(f.Assessment.Severity),
			Message:   msg{f.AlgorithmName + params(f) + ": " + strings.Join(f.Assessment.Reasons, "; ")},
			Locations: []location{loc}, PartialFingerprints: map[string]string{"cryptoinv/v1": f.ID},
			Properties: map[string]any{"score": f.Assessment.Score, "quantum_status": st, "context": f.Context}})
	}
	ruleList := make([]rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	if results == nil {
		results = []result{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "cryptoinv", "version": version,
				"informationUri": "https://github.com/ulisespignatelli/cryptoinv", "rules": ruleList}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func level(s domain.Severity) string {
	switch s {
	case domain.SevCritical, domain.SevHigh:
		return "error"
	case domain.SevMedium:
		return "warning"
	}
	return "note"
}

func statusES(s domain.QuantumStatus) string {
	return map[domain.QuantumStatus]string{domain.QuantumVulnerable: "vulnerable a computación cuántica",
		domain.QuantumWeakened: "debilitado por computación cuántica", domain.QuantumResistant: "resistente",
		domain.ClassicallyBroken: "inseguro hoy", domain.QuantumUnknown: "desconocido"}[s]
}

func params(f domain.Finding) string {
	s := ""
	if f.KeyBits > 0 {
		s += fmt.Sprintf(" %d bits", f.KeyBits)
	}
	if f.Curve != "" {
		s += " " + f.Curve
	}
	return s
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
