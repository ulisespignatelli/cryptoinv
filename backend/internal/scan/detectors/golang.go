package detectors

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// Golang combina el parser oficial (imports exactos, con linea) con reglas para parametros: tamaños de
// clave, curvas, versiones de TLS y grupos de intercambio.
type Golang struct{}

func (Golang) Name() string { return "go" }

func (Golang) Match(f File) bool { return f.Ext() == ".go" }

var goImports = map[string]string{
	"crypto/rsa": "RSA", "crypto/ecdsa": "ECDSA", "crypto/ed25519": "EdDSA", "crypto/ecdh": "ECDH", "crypto/dsa": "DSA",
	"crypto/md5": "MD5", "crypto/sha1": "SHA-1", "crypto/des": "DES", "crypto/rc4": "RC4", "crypto/mlkem": "ML-KEM",
	"golang.org/x/crypto/curve25519": "ECDH", "golang.org/x/crypto/ed25519": "EdDSA", "golang.org/x/crypto/blowfish": "Blowfish",
	"golang.org/x/crypto/md4": "MD5", "golang.org/x/crypto/chacha20poly1305": "ChaCha20-Poly1305",
	"github.com/cloudflare/circl/kem/mlkem": "ML-KEM", "github.com/cloudflare/circl/sign/mldsa": "ML-DSA",
}

var goRules = NewRules("go-rules", nil, []Rule{
	{Keywords: []string{"rsa.generatekey"}, Pattern: re(`\brsa\.GenerateKey\([^,]+,\s*(\d+)\s*\)`), Name: "RSA", BitsGroup: 1, Context: "rsa.GenerateKey"},
	{Keywords: []string{"elliptic.p"}, Pattern: re(`\belliptic\.(P224|P256|P384|P521)\(\)`), Name: "ECDSA", CurveGroup: 1, Context: "crypto/elliptic"},
	{Keywords: []string{"ecdh."}, Pattern: re(`\becdh\.(X25519|P256|P384|P521)\(\)`), Name: "ECDH", CurveGroup: 1, Context: "crypto/ecdh"},
	{Keywords: []string{"tls.version"}, Pattern: re(`\btls\.Version(TLS1[0-3]|SSL30)\b`), NameGroup: 1, Context: "crypto/tls",
		Transform: func(s string) string {
			if s == "SSL30" {
				return "SSLv3"
			}
			return "TLSv1." + s[4:]
		}},
	{Keywords: []string{"des.newtripledescipher"}, Pattern: re(`\bdes\.NewTripleDESCipher\(`), Name: "3DES", Context: "crypto/des"},
	{Keywords: []string{"x25519mlkem768"}, Pattern: re(`\btls\.X25519MLKEM768\b`), Name: "X25519MLKEM768", Context: "tls.CurvePreferences"},
	{Keywords: []string{"tls.curvep", "tls.x25519"}, Pattern: re(`\btls\.(X25519|CurveP256|CurveP384|CurveP521)\b`), Name: "ECDH",
		CurveGroup: 1, Context: "tls.CurvePreferences"},
	{Keywords: []string{"tls_rsa_with", "tls_ecdhe"}, Pattern: re(`\btls\.TLS_(?:ECDHE_(?:RSA|ECDSA)_)?(?:RSA_)?WITH_(3DES|RC4|AES|CHACHA20)\w*`),
		NameGroup: 1, Transform: CipherName, Context: "tls.CipherSuites", Confidence: "media"},
})

func (Golang) Detect(f File) []Raw {
	var out []Raw
	fset := token.NewFileSet()
	if af, err := parser.ParseFile(fset, f.Path, f.Data, parser.ImportsOnly); err == nil {
		src := lines(f.Data)
		for _, imp := range af.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name, ok := goImports[path]
			if !ok {
				continue
			}
			pos := fset.Position(imp.Pos())
			ev := path
			if pos.Line-1 < len(src) {
				ev = Evidence(src[pos.Line-1])
			}
			out = append(out, Raw{Name: name, Line: pos.Line, Column: pos.Column, Context: "import " + path,
				Evidence: ev, Confidence: "media"})
		}
	}
	for _, r := range goRules.Detect(f) {
		// Los literales de prueba en strings no cuentan: saltear lineas que son comentario.
		if strings.HasPrefix(strings.TrimSpace(r.Evidence), "//") {
			continue
		}
		out = append(out, r)
	}
	return out
}
