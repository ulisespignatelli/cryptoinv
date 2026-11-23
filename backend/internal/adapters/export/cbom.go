package export

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/catalog"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// CBOM escribe un CycloneDX 1.6 con componentes "cryptographic-asset". Agrupa por algoritmo + parametros
// (un componente por "RSA-2048", "ECDSA P-256", ...) con todas las ocurrencias como evidencia, y un
// componente por certificado.
func CBOM(w io.Writer, sc domain.Scan, cat *catalog.Catalog, version string) error {
	type occurrence struct {
		Location string `json:"location"`
		Line     int    `json:"line,omitempty"`
		Offset   int    `json:"offset,omitempty"`
		Symbol   string `json:"symbol,omitempty"`
	}
	type component struct {
		Type             string              `json:"type"`
		BOMRef           string              `json:"bom-ref"`
		Name             string              `json:"name"`
		CryptoProperties map[string]any      `json:"cryptoProperties"`
		Evidence         map[string]any      `json:"evidence,omitempty"`
		Properties       []map[string]string `json:"properties,omitempty"`
	}

	byRef := map[string]*component{}
	var order []string
	for _, f := range sc.Findings {
		alg, _ := cat.Get(f.AlgorithmID)
		name := f.AlgorithmName + params(f)
		var ref string
		var cp map[string]any
		if f.Certificate != nil {
			ref = "crypto/certificate/" + slug(fmt.Sprintf("%s-%d", f.Location.Path, f.Location.Line))
			name = "certificado " + f.Certificate.Subject
			cp = map[string]any{"assetType": "certificate", "certificateProperties": map[string]any{
				"subjectName": f.Certificate.Subject, "issuerName": f.Certificate.Issuer,
				"notValidBefore": f.Certificate.NotBefore.Format(time.RFC3339), "notValidAfter": f.Certificate.NotAfter.Format(time.RFC3339),
				"certificateFormat": "X.509"}}
		} else if f.Primitive == domain.PrimProtocol {
			ref = "crypto/protocol/" + f.AlgorithmID
			cp = map[string]any{"assetType": "protocol", "protocolProperties": map[string]any{
				"type": "tls", "version": strings.TrimPrefix(strings.TrimPrefix(f.AlgorithmName, "TLS "), "TLS")}}
		} else {
			ref = "crypto/algorithm/" + slug(f.AlgorithmID+params(f))
			ap := map[string]any{"primitive": cdxPrimitive(f.Primitive), "cryptoFunctions": cryptoFunctions(f.Primitive),
				"nistQuantumSecurityLevel": alg.NISTLevel}
			if f.KeyBits > 0 {
				ap["parameterSetIdentifier"] = fmt.Sprint(f.KeyBits)
			}
			if f.Curve != "" {
				ap["curve"] = f.Curve
			}
			cp = map[string]any{"assetType": "algorithm", "algorithmProperties": ap}
		}
		c, ok := byRef[ref]
		if !ok {
			c = &component{Type: "cryptographic-asset", BOMRef: ref, Name: name, CryptoProperties: cp,
				Evidence: map[string]any{"occurrences": []occurrence{}},
				Properties: []map[string]string{
					{"name": "cryptoinv:quantum_status", "value": string(f.Assessment.QuantumStatus)},
					{"name": "cryptoinv:severity", "value": string(f.Assessment.Severity)},
					{"name": "cryptoinv:score", "value": fmt.Sprint(f.Assessment.Score)},
				}}
			if f.Certificate != nil {
				c.Properties = append(c.Properties,
					map[string]string{"name": "cryptoinv:signature_algorithm", "value": f.Certificate.SignatureAlg},
					map[string]string{"name": "cryptoinv:public_key", "value": f.AlgorithmName + params(f)})
			}
			if f.Assessment.DisallowedFrom > 0 {
				c.Properties = append(c.Properties, map[string]string{"name": "cryptoinv:nist_disallowed_after", "value": fmt.Sprint(f.Assessment.DisallowedFrom)})
			}
			if f.Assessment.Replacement != "" {
				c.Properties = append(c.Properties, map[string]string{"name": "cryptoinv:replacement", "value": f.Assessment.Replacement})
			}
			byRef[ref] = c
			order = append(order, ref)
		}
		occ := c.Evidence["occurrences"].([]occurrence)
		c.Evidence["occurrences"] = append(occ, occurrence{Location: f.Location.Path, Line: f.Location.Line, Symbol: f.Context})
	}
	sort.Strings(order)
	comps := make([]component, 0, len(order))
	for _, r := range order {
		comps = append(comps, *byRef[r])
	}
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + uuidFrom(sc.ID),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": sc.FinishedAt.Format(time.RFC3339),
			"tools":     map[string]any{"components": []any{map[string]any{"type": "application", "name": "cryptoinv", "version": version}}},
			"component": map[string]any{"type": "application", "bom-ref": "asset/" + slug(sc.Asset), "name": sc.Asset},
			"properties": []map[string]string{{"name": "cryptoinv:catalog_version", "value": cat.Version},
				{"name": "cryptoinv:readiness", "value": fmt.Sprint(sc.Readiness())}},
		},
		"components": comps,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func cdxPrimitive(p domain.Primitive) string {
	switch p {
	case domain.PrimSignature, domain.PrimKeyAgree, domain.PrimPKE, domain.PrimKEM, domain.PrimBlockCipher,
		domain.PrimStream, domain.PrimAE, domain.PrimHash, domain.PrimMAC, domain.PrimKDF:
		return string(p)
	}
	return "other"
}

func cryptoFunctions(p domain.Primitive) []string {
	switch p {
	case domain.PrimSignature:
		return []string{"sign", "verify"}
	case domain.PrimKeyAgree:
		return []string{"keyderive"}
	case domain.PrimKEM:
		return []string{"encapsulate", "decapsulate"}
	case domain.PrimHash:
		return []string{"digest"}
	case domain.PrimMAC:
		return []string{"tag"}
	case domain.PrimKDF:
		return []string{"keyderive"}
	case domain.PrimBlockCipher, domain.PrimStream, domain.PrimAE, domain.PrimPKE:
		return []string{"encrypt", "decrypt"}
	}
	return []string{"unknown"}
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func uuidFrom(id string) string {
	h := (id + strings.Repeat("0", 32))[:32]
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}
