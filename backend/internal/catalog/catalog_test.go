package catalog

import (
	"testing"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

func TestCatalogLoadsAndResolvesAliases(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"RSA": "rsa", "x25519": "ecdh", "Ed25519": "eddsa", "SHA-1": "sha1", "ML-KEM-768": "mlkem",
		"X25519MLKEM768": "hybrid-kex", "TLSv1.0": "tls10", "DESede": "3des", "HS256": "hmac-sha2"}
	for in, want := range cases {
		a, ok := c.Resolve(in)
		if !ok || a.ID != want {
			t.Errorf("%s -> %v %s, esperaba %s", in, ok, a.ID, want)
		}
	}
}

func TestQuantumVulnerablePublicKeyHasNISTDates(t *testing.T) {
	c := MustLoad()
	for _, a := range c.All() {
		if a.Quantum == domain.QuantumVulnerable && a.ID != "dsa" && (a.Deprecated != 2030 || a.Disallowed != 2035) {
			t.Errorf("%s: fechas %d/%d, NIST IR 8547 final fija 2030/2035", a.ID, a.Deprecated, a.Disallowed)
		}
		if a.Note == "" {
			t.Errorf("%s: falta la explicación", a.ID)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, bad := range []string{`{`, `{"algorithms":[{"id":"x"}]}`,
		`{"algorithms":[{"id":"a","name":"A","primitive":"hash","quantum":"weakened"},{"id":"a","name":"B","primitive":"hash","quantum":"weakened"}]}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("debería rechazar %s", bad)
		}
	}
}
