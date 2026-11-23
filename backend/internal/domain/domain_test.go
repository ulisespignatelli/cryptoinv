package domain

import "testing"

func TestIsTestPath(t *testing.T) {
	yes := []string{"test/a.pem", "pkg/x_test.go", "src/__tests__/a.ts", "a/b.spec.ts", "tests/keys/k", "test_app.py",
		"src/test/java/FooTest.java", "internal/testdata/cert.pem", "examples/main.go", "caddytest/leaf.pem", "vectors/cryptography_vectors/x.pem"}
	no := []string{"cmd/main.go", "src/latest/a.go", "contest.py", "src/attestation.go", "testimony/x.go", "latest/a.pem"}
	for _, p := range yes {
		if !IsTestPath(p) {
			t.Errorf("%s debería ser de prueba", p)
		}
	}
	for _, p := range no {
		if IsTestPath(p) {
			t.Errorf("%s no es de prueba", p)
		}
	}
}

func TestReadiness(t *testing.T) {
	s := Scan{}
	if s.Readiness() != 100 {
		t.Fatal("sin hallazgos = 100%")
	}
	s.Findings = []Finding{{Assessment: Assessment{QuantumStatus: QuantumResistant}}, {Assessment: Assessment{QuantumStatus: QuantumVulnerable}}}
	if s.Readiness() != 50 {
		t.Fatal(s.Readiness())
	}
}
