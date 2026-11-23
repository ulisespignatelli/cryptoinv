// Package detectors encuentra usos de criptografia en distintos tipos de archivo. Cada detector implementa
// la misma interfaz y no sabe nada de riesgo, catalogo ni persistencia: solo informa "que algoritmo
// aparece, donde y con que parametros". Sumar un lenguaje o formato nuevo es sumar un archivo aca.
package detectors

import (
	"path/filepath"
	"strings"
)

// File es un archivo a analizar.
type File struct {
	Path string // relativa a la raiz del escaneo, con "/"
	Data []byte
}

// Ext devuelve la extension en minusculas.
func (f File) Ext() string { return strings.ToLower(filepath.Ext(f.Path)) }

// Base devuelve el nombre del archivo en minusculas.
func (f File) Base() string { return strings.ToLower(filepath.Base(f.Path)) }

// Raw es un uso encontrado, con el nombre del algoritmo tal como aparece (el motor lo resuelve contra
// el catalogo).
type Raw struct {
	Name       string // "RSA", "ecdsa", "SHA-1", "X25519MLKEM768", ...
	KeyBits    int
	Curve      string
	Primitive  string // opcional: si el detector sabe para que se usa
	Line       int
	Column     int
	Context    string // API o directiva: "crypto/rsa", "ssl_protocols", "KeyPairGenerator"
	Evidence   string
	Confidence string // alta | media | baja
	Cert       *CertMeta
}

// CertMeta acompaña los usos que salen de un certificado.
type CertMeta struct {
	Subject, Issuer, SignatureAlg string
	NotBefore, NotAfter           int64 // unix
	SelfSigned                    bool
}

// Detector es la interfaz comun.
type Detector interface {
	Name() string
	Match(f File) bool
	Detect(f File) []Raw
}

// All devuelve los detectores incluidos, en el orden en que se aplican.
func All() []Detector {
	return []Detector{
		X509{}, Golang{}, SSH{}, TLSConfig{},
		NewRules("python", []string{".py"}, pythonRules),
		NewRules("java", []string{".java", ".kt", ".scala", ".groovy"}, javaRules),
		NewRules("javascript", []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}, jsRules),
		NewRules("iac", []string{".tf", ".tfvars", ".yaml", ".yml", ".json", ".hcl"}, iacRules),
		NewRules("jwt", nil, jwtRules), // cualquier archivo de texto
	}
}

// Evidence recorta una linea para mostrarla.
func Evidence(line string) string {
	s := strings.Join(strings.Fields(line), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}

// lines parte el contenido en lineas (sin copiar mas de lo necesario).
func lines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// CipherName normaliza nombres de cifrados de OpenSSL, Java o Node ("des-ede3-cbc", "AES/GCM/NoPadding",
// "DESede", "bf-cbc") a un nombre del catalogo.
func CipherName(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(l, '/'); i >= 0 {
		l = l[:i]
	}
	switch {
	case strings.HasPrefix(l, "aes"):
		return "AES"
	case strings.HasPrefix(l, "des-ede3"), strings.HasPrefix(l, "desede"), strings.HasPrefix(l, "des3"),
		strings.HasPrefix(l, "3des"), strings.HasPrefix(l, "tripledes"), l == "des-ede", strings.HasPrefix(l, "des-ede-"):
		return "3DES"
	case strings.HasPrefix(l, "des"):
		return "DES"
	case strings.HasPrefix(l, "rc4"), strings.HasPrefix(l, "arcfour"), strings.HasPrefix(l, "arc4"):
		return "RC4"
	case strings.HasPrefix(l, "bf"), strings.HasPrefix(l, "blowfish"):
		return "Blowfish"
	case strings.HasPrefix(l, "chacha20"), strings.HasPrefix(l, "xchacha20"):
		return "ChaCha20-Poly1305"
	case strings.HasPrefix(l, "rsa"):
		return "RSA"
	}
	return s
}
