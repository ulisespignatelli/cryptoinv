// Package testutil arma proyectos de prueba en carpetas temporales. Las claves se generan en cada
// ejecucion: el repositorio no guarda claves privadas.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Project crea un proyecto chico con criptografia de varios tipos y devuelve su ruta.
func Project(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "demo.ejemplo.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"certs/server.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"cmd/main.go": "package main\n\nimport (\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n\t\"crypto/mlkem\"\n)\n\n" +
			"func main() {\n\t_, _ = rsa.GenerateKey(rand.Reader, 1024)\n\t_, _ = mlkem.GenerateKey768()\n}\n",
		"app/hash.py":           "import hashlib\nh = hashlib.md5(b'x')\n",
		"deploy/nginx.conf":     "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519;\n",
		"cmd/main_test.go":      "package main\n\nimport \"crypto/sha1\"\n",
		"node_modules/lib/x.js": "crypto.createHash('md5')\n", // se ignora
		"img/logo.png":          "\x89PNG\x00\x00 rsa.GenerateKey(rand.Reader, 512)",
	}
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
