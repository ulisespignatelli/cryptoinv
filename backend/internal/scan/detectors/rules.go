package detectors

import (
	"regexp"
	"strconv"
	"strings"
)

// Rule es una regla de deteccion por linea. Las reglas son datos: cada lenguaje es una tabla.
type Rule struct {
	Keywords   []string       // filtro rapido (en minusculas) antes de la expresion regular
	Pattern    *regexp.Regexp // patron
	Name       string         // algoritmo fijo, o vacio si sale de NameGroup / Multi
	NameGroup  int            // grupo con el nombre del algoritmo
	BitsGroup  int            // grupo con el tamaño de clave
	CurveGroup int            // grupo con la curva
	Transform  func(string) string
	Multi      func(m []string) []Raw // para reglas que producen varios usos (listas de imports, "SHA1withRSA")
	Context    string
	Primitive  string
	Confidence string
}

// Rules aplica una tabla de reglas a archivos con ciertas extensiones.
type Rules struct {
	name  string
	exts  map[string]bool
	rules []Rule
}

// NewRules crea un detector por reglas. exts nil = cualquier archivo de texto.
func NewRules(name string, exts []string, rules []Rule) Rules {
	var m map[string]bool
	if exts != nil {
		m = map[string]bool{}
		for _, e := range exts {
			m[e] = true
		}
	}
	return Rules{name: name, exts: m, rules: rules}
}

func (r Rules) Name() string { return r.name }

func (r Rules) Match(f File) bool { return r.exts == nil || r.exts[f.Ext()] }

func (r Rules) Detect(f File) []Raw {
	var out []Raw
	for i, line := range lines(f.Data) {
		if len(line) > 4000 {
			continue
		}
		low := strings.ToLower(line)
		for _, rule := range r.rules {
			if !anyIn(low, rule.Keywords) {
				continue
			}
			for _, idx := range rule.Pattern.FindAllStringSubmatchIndex(line, -1) {
				m := groups(line, idx)
				base := Raw{Line: i + 1, Column: idx[0] + 1, Context: rule.Context, Evidence: Evidence(line),
					Confidence: or(rule.Confidence, "alta"), Primitive: rule.Primitive}
				if rule.Multi != nil {
					for _, x := range rule.Multi(m) {
						x.Line, x.Column, x.Evidence = base.Line, base.Column, base.Evidence
						x.Context = or(x.Context, base.Context)
						x.Confidence = or(x.Confidence, base.Confidence)
						out = append(out, x)
					}
					continue
				}
				name := rule.Name
				if rule.NameGroup > 0 {
					name = m[rule.NameGroup]
				}
				if rule.Transform != nil {
					name = rule.Transform(name)
				}
				if name == "" {
					continue
				}
				base.Name = name
				if rule.BitsGroup > 0 {
					base.KeyBits, _ = strconv.Atoi(m[rule.BitsGroup])
				}
				if rule.CurveGroup > 0 {
					base.Curve = m[rule.CurveGroup]
				}
				out = append(out, base)
			}
		}
	}
	return out
}

func groups(s string, idx []int) []string {
	m := make([]string, len(idx)/2)
	for i := range m {
		if idx[2*i] >= 0 {
			m[i] = s[idx[2*i]:idx[2*i+1]]
		}
	}
	return m
}

func anyIn(low string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var re = regexp.MustCompile

// listMap convierte una lista de nombres ("rsa, ec, padding") usando un diccionario.
func listMap(list string, dict map[string]string, ctx string) []Raw {
	var out []Raw
	for _, part := range strings.Split(list, ",") {
		key := strings.TrimSpace(strings.Fields(strings.TrimSpace(part) + " ")[0])
		if name, ok := dict[key]; ok {
			out = append(out, Raw{Name: name, Context: ctx, Confidence: "media"})
		}
	}
	return out
}

// ---------------------------------------------------------------- Python

var pyAsym = map[string]string{"rsa": "RSA", "ec": "ECDSA", "dsa": "DSA", "ed25519": "EdDSA", "ed448": "EdDSA",
	"x25519": "ECDH", "x448": "ECDH", "dh": "DH"}
var pyCrypto = map[string]string{"RSA": "RSA", "ECC": "ECDSA", "DSA": "DSA", "DES": "DES", "DES3": "3DES", "ARC4": "RC4",
	"Blowfish": "Blowfish", "AES": "AES", "MD5": "MD5", "SHA1": "SHA-1", "ChaCha20_Poly1305": "ChaCha20-Poly1305"}

var pythonRules = []Rule{
	{Keywords: []string{"asymmetric"}, Pattern: re(`cryptography\.hazmat\.primitives\.asymmetric\s+import\s+\(?([\w ,]+)`),
		Multi: func(m []string) []Raw { return listMap(m[1], pyAsym, "cryptography") }},
	{Keywords: []string{"crypto"}, Pattern: re(`from\s+Crypto(?:dome)?\.(?:PublicKey|Cipher|Hash)\s+import\s+\(?([\w ,]+)`),
		Multi: func(m []string) []Raw { return listMap(m[1], pyCrypto, "pycryptodome") }},
	{Keywords: []string{"generate_private_key"}, Pattern: re(`\brsa\.generate_private_key\([^)]*key_size\s*=\s*(\d+)`),
		Name: "RSA", BitsGroup: 1, Context: "cryptography"},
	{Keywords: []string{"generate_private_key"}, Pattern: re(`\bec\.generate_private_key\(\s*ec\.(\w+)`),
		Name: "ECDSA", CurveGroup: 1, Context: "cryptography"},
	{Keywords: []string{"ecdh"}, Pattern: re(`\bec\.ECDH\(\)`), Name: "ECDH", Context: "cryptography"},
	{Keywords: []string{"rsa.generate"}, Pattern: re(`\bRSA\.generate\(\s*(\d+)`), Name: "RSA", BitsGroup: 1, Context: "pycryptodome"},
	{Keywords: []string{"hashlib"}, Pattern: re(`\bhashlib\.(md5|sha1)\(`), NameGroup: 1, Context: "hashlib"},
	{Keywords: []string{"hashlib"}, Pattern: re(`\bhashlib\.new\(\s*['"](md5|sha1)['"]`), NameGroup: 1, Context: "hashlib"},
	{Keywords: []string{"algorithms."}, Pattern: re(`\balgorithms\.(TripleDES|ARC4|Blowfish|AES|ChaCha20)\(`),
		NameGroup: 1, Transform: CipherName, Context: "cryptography"},
	{Keywords: []string{"tlsv1", "sslv3"}, Pattern: re(`\b(?:ssl\.PROTOCOL_|TLSVersion\.)(TLSv1(?:_[12])?|SSLv3)\b`),
		NameGroup: 1, Transform: func(s string) string { return strings.ReplaceAll(s, "_", ".") }, Context: "ssl"},
}

// ---------------------------------------------------------------- Java / JVM

var javaKeyAlg = map[string]string{"EC": "ECDSA", "RSA": "RSA", "DSA": "DSA", "DH": "DH", "DiffieHellman": "DH",
	"XDH": "ECDH", "X25519": "ECDH", "X448": "ECDH", "ECDH": "ECDH", "Ed25519": "EdDSA", "Ed448": "EdDSA", "EdDSA": "EdDSA",
	"ML-KEM": "ML-KEM", "ML-DSA": "ML-DSA", "SLH-DSA": "SLH-DSA", "RSASSA-PSS": "RSA"}

func javaInstance(m []string) []Raw {
	class, v := m[1], m[2]
	ctx := class + ".getInstance"
	one := func(name string) []Raw { return []Raw{{Name: name, Context: ctx}} }
	switch class {
	case "Signature":
		if i := strings.Index(strings.ToLower(v), "with"); i > 0 {
			hash, alg := v[:i], v[i+4:]
			out := one(javaKeyAlg[strings.Split(alg, "/")[0]])
			if out[0].Name == "" {
				out[0].Name = alg
			}
			if h := strings.ToUpper(hash); h == "MD5" || h == "SHA1" {
				out = append(out, Raw{Name: hash, Context: ctx})
			}
			return out
		}
		return one(or(javaKeyAlg[v], v))
	case "Cipher", "KeyGenerator":
		if strings.HasPrefix(strings.ToLower(v), "hmac") {
			return one("hmac-" + strings.ToLower(v[4:]))
		}
		return one(CipherName(v))
	case "Mac":
		return one("hmac-" + strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(v, "Hmac"), "HMAC")))
	case "MessageDigest":
		return one(v)
	case "SSLContext":
		if v == "TLS" || v == "Default" {
			return nil
		}
		return one(v)
	default: // KeyPairGenerator, KeyAgreement, KeyFactory
		return one(or(javaKeyAlg[v], v))
	}
}

var javaRules = []Rule{
	{Keywords: []string{"getinstance"}, Pattern: re(`\b(KeyPairGenerator|KeyAgreement|Signature|Cipher|MessageDigest|Mac|KeyGenerator|SSLContext|KeyFactory)\.getInstance\(\s*"([^"]+)"`),
		Multi: javaInstance},
	{Keywords: []string{"ecgenparameterspec"}, Pattern: re(`new\s+ECGenParameterSpec\(\s*"([^"]+)"`), Name: "ECDSA", CurveGroup: 1,
		Context: "ECGenParameterSpec", Confidence: "media"},
	{Keywords: []string{"rsakeygenparameterspec"}, Pattern: re(`new\s+RSAKeyGenParameterSpec\(\s*(\d+)`), Name: "RSA", BitsGroup: 1,
		Context: "RSAKeyGenParameterSpec"},
}

// ---------------------------------------------------------------- JavaScript / TypeScript

var jsKeyType = map[string]string{"rsa": "RSA", "rsa-pss": "RSA", "ec": "ECDSA", "ed25519": "EdDSA", "ed448": "EdDSA",
	"x25519": "ECDH", "x448": "ECDH", "dsa": "DSA", "dh": "DH"}

var jsRules = []Rule{
	{Keywords: []string{"generatekeypair"}, Pattern: re(`generateKeyPair(?:Sync)?\(\s*['"]([\w-]+)['"](?:.*?modulusLength\s*:\s*(\d+))?`),
		Multi: func(m []string) []Raw {
			n := jsKeyType[strings.ToLower(m[1])]
			if n == "" {
				return nil
			}
			bits, _ := strconv.Atoi(m[2])
			return []Raw{{Name: n, KeyBits: bits, Context: "crypto.generateKeyPair"}}
		}},
	{Keywords: []string{"moduluslength"}, Pattern: re(`modulusLength\s*:\s*(\d+)`), Name: "RSA", BitsGroup: 1,
		Context: "modulusLength", Confidence: "media"},
	{Keywords: []string{"createhash", "createhmac"}, Pattern: re(`create(?:Hash|Hmac)\(\s*['"]([\w-]+)['"]`), NameGroup: 1,
		Context: "crypto.createHash"},
	{Keywords: []string{"createcipher", "createdecipher"}, Pattern: re(`create(?:Cipher|Decipher)(?:iv)?\(\s*['"]([\w-]+)['"]`),
		NameGroup: 1, Transform: CipherName, Context: "crypto.createCipheriv"},
	{Keywords: []string{"name"}, Pattern: re(`\bname\s*:\s*['"](RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDSA|ECDH|Ed25519|X25519|AES-GCM|AES-CBC|AES-CTR)['"]`),
		NameGroup: 1, Context: "WebCrypto"},
	{Keywords: []string{"pki.rsa"}, Pattern: re(`pki\.rsa\.generateKeyPair\(\s*(?:\{\s*bits\s*:\s*)?(\d+)`), Name: "RSA", BitsGroup: 1,
		Context: "node-forge"},
	{Keywords: []string{"forge.md."}, Pattern: re(`forge\.md\.(md5|sha1)\b`), NameGroup: 1, Context: "node-forge"},
	{Keywords: []string{"tlsv1"}, Pattern: re(`(?:minVersion|maxVersion)\s*:\s*['"](TLSv1(?:\.[0-3])?)['"]`), NameGroup: 1, Context: "tls"},
	{Keywords: []string{"tlsv1"}, Pattern: re(`secureProtocol\s*:\s*['"](TLSv1(?:_[12])?)_method['"]`), NameGroup: 1,
		Transform: func(s string) string { return strings.ReplaceAll(s, "_", ".") }, Context: "tls"},
}

// ---------------------------------------------------------------- Infraestructura como codigo

func kmsSpec(m []string) []Raw {
	v := strings.ToUpper(m[1])
	ctx := "key_spec"
	switch {
	case strings.HasPrefix(v, "RSA_"):
		bits, _ := strconv.Atoi(strings.TrimPrefix(v, "RSA_"))
		return []Raw{{Name: "RSA", KeyBits: bits, Context: ctx}}
	case strings.HasPrefix(v, "ECC_"), strings.HasPrefix(v, "EC_"):
		return []Raw{{Name: "ECDSA", Curve: strings.TrimPrefix(strings.TrimPrefix(v, "ECC_"), "EC_"), Context: ctx}}
	case strings.HasPrefix(v, "ML_DSA"):
		return []Raw{{Name: "ML-DSA", Context: ctx}}
	case strings.HasPrefix(v, "HMAC_"):
		return []Raw{{Name: "HMAC-SHA256", Context: ctx}}
	}
	return nil
}

var iacRules = []Rule{
	{Keywords: []string{"rsa_bits"}, Pattern: re(`\brsa_bits\s*=\s*(\d+)`), Name: "RSA", BitsGroup: 1, Context: "tls_private_key"},
	{Keywords: []string{"ecdsa_curve"}, Pattern: re(`\becdsa_curve\s*=\s*"(\w+)"`), Name: "ECDSA", CurveGroup: 1, Context: "tls_private_key"},
	{Keywords: []string{"algorithm"}, Pattern: re(`\balgorithm"?\s*[:=]\s*"?(RSA|ECDSA|ED25519|Ed25519)"?\s*,?\s*$`), NameGroup: 1,
		Context: "algorithm", Confidence: "media"},
	{Keywords: []string{"key_spec", "keyspec", "key_algorithm", "keyalgorithm"},
		Pattern: re(`\b(?:customer_master_key_spec|key_spec|KeySpec|key_algorithm|keyAlgorithm)"?\s*[:=]\s*"?((?:RSA|ECC|EC)_\w+|ML_DSA_\w+|HMAC_\d+)`),
		Multi:   kmsSpec},
	{Keywords: []string{"tls"}, Pattern: re(`\b(?:min_tls_version|minimum_protocol_version|minimumTlsVersion|min_tls)"?\s*[:=]\s*"?(TLSv?1[._]?[0-3]?|1\.[0-3])"?`),
		NameGroup: 1, Transform: tlsVersion, Context: "min_tls_version"},
}

func tlsVersion(s string) string {
	s = strings.ToUpper(strings.NewReplacer("_", ".", "TLSV", "", "TLS", "").Replace(strings.ToUpper(s)))
	switch s {
	case "1", "1.0", "10":
		return "TLSv1.0"
	case "1.1", "11":
		return "TLSv1.1"
	case "1.2", "12":
		return "TLSv1.2"
	case "1.3", "13":
		return "TLSv1.3"
	}
	return ""
}

// ---------------------------------------------------------------- JWT / JOSE (cualquier archivo de texto)

var jwtRules = []Rule{
	{Keywords: []string{"alg"}, Pattern: re(`(?i)\b(?:alg|algorithm|algorithms|signing_?algorithm|jwt_?algorithm)["']?\s*[:=]\s*\[?\s*["']?(RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|HS256|HS384|HS512|EdDSA)\b`),
		NameGroup: 1, Context: "JWT",
		Transform: func(s string) string {
			switch strings.ToUpper(s[:2]) {
			case "RS", "PS":
				return "RSA"
			case "ES":
				return "ECDSA"
			case "HS":
				return "HS256"
			}
			return "EdDSA"
		}},
}
