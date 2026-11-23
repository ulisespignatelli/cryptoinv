// Package domain contiene el modelo del inventario criptografico. No depende de ningun otro paquete del
// proyecto: ni de la base de datos, ni de HTTP, ni de como se encuentran los usos. Todo lo demas depende
// de este paquete, nunca al reves.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Primitive es la funcion criptografica (alineada con CycloneDX 1.6, algorithmProperties.primitive).
type Primitive string

const (
	PrimSignature   Primitive = "signature"
	PrimKeyAgree    Primitive = "key-agree"
	PrimPKE         Primitive = "pke"
	PrimKEM         Primitive = "kem"
	PrimBlockCipher Primitive = "block-cipher"
	PrimStream      Primitive = "stream-cipher"
	PrimAE          Primitive = "ae"
	PrimHash        Primitive = "hash"
	PrimMAC         Primitive = "mac"
	PrimKDF         Primitive = "kdf"
	PrimProtocol    Primitive = "protocol"
	PrimOther       Primitive = "other"
)

// QuantumStatus resume como afecta una computadora cuantica a un algoritmo.
type QuantumStatus string

const (
	// Vulnerable: el algoritmo de Shor lo rompe (RSA, curvas elipticas, Diffie-Hellman, DSA).
	QuantumVulnerable QuantumStatus = "vulnerable"
	// Weakened: el algoritmo de Grover reduce su seguridad a la mitad; con tamanos adecuados sigue sirviendo.
	QuantumWeakened QuantumStatus = "weakened"
	// Resistant: disenado para resistir computadoras cuanticas (ML-KEM, ML-DSA, SLH-DSA) o simetrico fuerte.
	QuantumResistant QuantumStatus = "resistant"
	// Broken: ya es inseguro hoy, sin computadoras cuanticas (MD5, SHA-1 para firmas, DES, RC4).
	ClassicallyBroken QuantumStatus = "broken"
	QuantumUnknown    QuantumStatus = "unknown"
)

// Location indica donde se encontro un uso.
type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

// Usage es un uso concreto de criptografia encontrado en un activo.
type Usage struct {
	ID          string    `json:"id"`
	AlgorithmID string    `json:"algorithm_id"` // clave del catalogo: "rsa", "ecdsa", "aes", ...
	KeyBits     int       `json:"key_bits,omitempty"`
	Curve       string    `json:"curve,omitempty"`
	Primitive   Primitive `json:"primitive"`
	Location    Location  `json:"location"`
	Asset       string    `json:"asset"`                 // sistema o repositorio al que pertenece
	Detector    string    `json:"detector"`              // que detector lo encontro
	Context     string    `json:"context,omitempty"`     // API o configuracion: "crypto/rsa", "ssl_ciphers"
	Evidence    string    `json:"evidence,omitempty"`    // fragmento recortado, nunca material de claves
	Confidence  string    `json:"confidence"`            // alta | media | baja
	Certificate *CertInfo `json:"certificate,omitempty"` // solo para certificados X.509
	InTests     bool      `json:"in_tests,omitempty"`    // aparece en tests, fixtures o ejemplos
}

// CertInfo describe un certificado encontrado (nunca incluye claves privadas).
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SignatureAlg string    `json:"signature_algorithm"`
	SelfSigned   bool      `json:"self_signed"`
}

// IsTestPath indica si una ruta es de pruebas, fixtures o ejemplos (no llega a produccion).
func IsTestPath(path string) bool {
	p := "/" + strings.ToLower(path)
	for _, d := range []string{"/test/", "/tests/", "/__tests__/", "/testdata/", "/spec/", "/fixtures/", "/fixture/",
		"/examples/", "/example/", "/mocks/", "/testing/", "/e2e/", "/testutil/", "/testhelpers/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for _, seg := range segs[:len(segs)-1] {
		// "caddytest", "integrationtests", "cryptography_vectors", "test-vectors"
		if (strings.HasSuffix(seg, "test") || strings.HasSuffix(seg, "tests") || strings.Contains(seg, "vectors")) &&
			!map[string]bool{"latest": true, "contest": true, "attest": true, "protest": true}[seg] {
			return true
		}
	}
	base := segs[len(segs)-1]
	for _, suf := range []string{"_test.go", "_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", ".test.tsx",
		".spec.tsx", "test.java", "tests.java", "test.kt", "_spec.rb"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return strings.HasPrefix(base, "test_") || strings.HasPrefix(base, "conftest")
}

// Fingerprint identifica un uso de forma estable entre escaneos (no depende del orden de los archivos).
func Fingerprint(asset, path string, line int, algorithmID, context string) string {
	h := sha256.Sum256([]byte(asset + "\x00" + path + "\x00" + strconv.Itoa(line) + "\x00" + algorithmID + "\x00" + context))
	return hex.EncodeToString(h[:])[:20]
}

// Severity es la urgencia de migrar un uso.
type Severity string

const (
	SevCritical Severity = "critica"
	SevHigh     Severity = "alta"
	SevMedium   Severity = "media"
	SevLow      Severity = "baja"
	SevInfo     Severity = "info"
)

// Rank ordena las severidades (mayor = mas urgente).
func (s Severity) Rank() int {
	return map[Severity]int{SevCritical: 5, SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1}[s]
}

// Assessment es la evaluacion de riesgo de un uso.
type Assessment struct {
	Score          int           `json:"score"` // 0-100
	Severity       Severity      `json:"severity"`
	QuantumStatus  QuantumStatus `json:"quantum_status"`
	DeprecatedFrom int           `json:"deprecated_after,omitempty"` // año (NIST IR 8547)
	DisallowedFrom int           `json:"disallowed_after,omitempty"`
	Replacement    string        `json:"replacement,omitempty"`
	Reasons        []string      `json:"reasons"`
}

// Finding une un uso con su evaluacion: es lo que se muestra y se exporta.
type Finding struct {
	Usage
	AlgorithmName string     `json:"algorithm_name"`
	Assessment    Assessment `json:"assessment"`
}

// Scan es el resultado de un escaneo.
type Scan struct {
	ID         string    `json:"id"`
	Asset      string    `json:"asset"`
	Root       string    `json:"root"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Files      int       `json:"files_scanned"`
	Findings   []Finding `json:"findings"`
}

// Readiness es el porcentaje de usos que ya no dependen de criptografia vulnerable o rota.
func (s Scan) Readiness() int {
	if len(s.Findings) == 0 {
		return 100
	}
	ok := 0
	for _, f := range s.Findings {
		if st := f.Assessment.QuantumStatus; st == QuantumResistant || st == QuantumWeakened {
			ok++
		}
	}
	return ok * 100 / len(s.Findings)
}
