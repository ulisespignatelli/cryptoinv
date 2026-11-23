package detectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Las claves de prueba se generan en cada ejecucion: el repositorio no guarda claves privadas.

type want struct {
	name  string
	bits  int
	curve string
	line  int
}

func run(t *testing.T, d Detector, path, src string) []Raw {
	t.Helper()
	f := File{Path: path, Data: []byte(src)}
	if !d.Match(f) {
		t.Fatalf("%s no acepta %s", d.Name(), path)
	}
	return d.Detect(f)
}

func expect(t *testing.T, got []Raw, ws ...want) {
	t.Helper()
	for _, w := range ws {
		found := false
		for _, g := range got {
			if strings.EqualFold(g.Name, w.name) && (w.bits == 0 || g.KeyBits == w.bits) &&
				(w.curve == "" || g.Curve == w.curve) && (w.line == 0 || g.Line == w.line) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("falta %+v en %s", w, dump(got))
		}
	}
}

func absent(t *testing.T, got []Raw, names ...string) {
	t.Helper()
	for _, n := range names {
		for _, g := range got {
			if strings.EqualFold(g.Name, n) {
				t.Errorf("no debería detectar %s: %+v", n, g)
			}
		}
	}
}

func dump(rs []Raw) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString("\n  " + r.Name + " bits=" + itoa(r.KeyBits) + " curve=" + r.Curve + " line=" + itoa(r.Line) + " ctx=" + r.Context)
	}
	return b.String()
}

func selfSigned(t *testing.T, key any, pub any, cn string) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestX509(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ek)
	pk8, _ := x509.MarshalPKCS8PrivateKey(edk)
	pub, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)

	bundle := string(selfSigned(t, rk, &rk.PublicKey, "api.ejemplo.test")) +
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	got := run(t, X509{}, "certs/bundle.pem", bundle)
	expect(t, got, want{name: "RSA", bits: 2048, line: 1}, want{name: "ECDSA", curve: "P-384"}, want{name: "EdDSA"})

	var cert *Raw
	for i := range got {
		if got[i].Cert != nil {
			cert = &got[i]
		}
		if strings.Contains(got[i].Evidence, "PRIVATE KEY-----") || strings.Contains(got[i].Evidence, "MII") {
			t.Fatalf("la evidencia no puede contener material de clave: %q", got[i].Evidence)
		}
	}
	if cert == nil || !cert.Cert.SelfSigned || !strings.Contains(cert.Cert.Subject, "api.ejemplo.test") {
		t.Fatalf("metadatos del certificado: %+v", cert)
	}
}

func TestX509IgnoresTextWithoutPEM(t *testing.T) {
	if got := (X509{}).Detect(File{Path: "a.pem", Data: []byte("nada")}); len(got) != 0 {
		t.Fatal(dump(got))
	}
}

func TestGo(t *testing.T) {
	src := `package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/tls"
	"crypto/elliptic"
)

func f() {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	_ = elliptic.P256()
	_ = &tls.Config{MinVersion: tls.VersionTLS11, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	// rsa.GenerateKey(rand.Reader, 512) en un comentario no cuenta
}
`
	got := run(t, Golang{}, "main.go", src)
	expect(t, got, want{name: "RSA", line: 5}, want{name: "MD5", line: 6}, want{name: "ML-KEM", line: 7},
		want{name: "RSA", bits: 1024, line: 13}, want{name: "ECDSA", curve: "P256"}, want{name: "TLSv1.1"},
		want{name: "X25519MLKEM768"})
	for _, g := range got {
		if g.KeyBits == 512 {
			t.Fatal("detectó código comentado")
		}
	}
}

func TestPython(t *testing.T) {
	src := `from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from Crypto.Cipher import DES3, AES
import hashlib
k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
e = ec.generate_private_key(ec.SECP256R1())
h = hashlib.sha1(b"x")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
`
	got := run(t, NewRules("python", []string{".py"}, pythonRules), "app.py", src)
	expect(t, got, want{name: "RSA", line: 1}, want{name: "ECDSA", line: 1}, want{name: "3DES", line: 2},
		want{name: "AES", line: 2}, want{name: "RSA", bits: 3072, line: 4}, want{name: "ECDSA", curve: "SECP256R1"},
		want{name: "sha1", line: 6}, want{name: "TLSv1", line: 7})
	absent(t, got, "padding")
}

func TestJava(t *testing.T) {
	src := `KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
g.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
Signature s = Signature.getInstance("SHA1withECDSA");
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
Cipher d = Cipher.getInstance("DESede/CBC/PKCS5Padding");
MessageDigest m = MessageDigest.getInstance("MD5");
KeyAgreement ka = KeyAgreement.getInstance("X25519");
KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM");
SSLContext tls = SSLContext.getInstance("TLS");
`
	got := run(t, NewRules("java", []string{".java"}, javaRules), "C.java", src)
	expect(t, got, want{name: "RSA", line: 1}, want{name: "RSA", bits: 1024, line: 2}, want{name: "ECDSA", line: 3},
		want{name: "SHA1", line: 3}, want{name: "AES", line: 4}, want{name: "3DES", line: 5}, want{name: "MD5", line: 6},
		want{name: "ECDH", line: 7}, want{name: "ML-KEM", line: 8})
	absent(t, got, "TLS")
}

func TestJavaScript(t *testing.T) {
	src := `const kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const e = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
crypto.createHash("md5").update(x);
const c = crypto.createCipheriv("des-ede3-cbc", k, iv);
await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
https.createServer({ minVersion: "TLSv1.1" });
`
	got := run(t, NewRules("javascript", []string{".js"}, jsRules), "s.js", src)
	expect(t, got, want{name: "RSA", bits: 2048, line: 1}, want{name: "ECDSA", line: 2}, want{name: "md5", line: 3},
		want{name: "3DES", line: 4}, want{name: "ECDSA", line: 5}, want{name: "TLSv1.1", line: 6})
}

func TestIaC(t *testing.T) {
	src := `resource "tls_private_key" "a" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}
resource "aws_kms_key" "b" {
  customer_master_key_spec = "RSA_2048"
}
resource "aws_kms_key" "c" {
  key_spec = "ML_DSA_65"
}
resource "azurerm_storage_account" "d" {
  min_tls_version = "TLS1_0"
}
`
	got := run(t, NewRules("iac", []string{".tf"}, iacRules), "main.tf", src)
	expect(t, got, want{name: "ECDSA", line: 2}, want{name: "ECDSA", curve: "P384", line: 3},
		want{name: "RSA", bits: 2048, line: 6}, want{name: "ML-DSA", line: 9}, want{name: "TLSv1.0", line: 12})
}

func TestJWT(t *testing.T) {
	src := "jwt:\n  algorithm: RS256\n" + `token = jwt.encode(p, k, algorithm="ES384")` + "\n" + `{"alg":"EdDSA","typ":"JWT"}` + "\n"
	got := run(t, NewRules("jwt", nil, jwtRules), "config.yaml", src)
	expect(t, got, want{name: "RSA", line: 2}, want{name: "ECDSA", line: 3}, want{name: "EdDSA", line: 4})
}

func TestSSHConfig(t *testing.T) {
	src := `# comentario: KexAlgorithms diffie-hellman-group1-sha1
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,diffie-hellman-group1-sha1
HostKey /etc/ssh/ssh_host_ed25519_key
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
Ciphers aes256-gcm@openssh.com,3des-cbc
MACs hmac-sha2-512,hmac-md5
`
	got := run(t, SSH{}, "etc/ssh/sshd_config", src)
	expect(t, got, want{name: "mlkem768x25519-sha256", line: 2}, want{name: "sntrup761x25519-sha512", line: 2},
		want{name: "X25519", line: 2}, want{name: "DH", line: 2}, want{name: "SHA-1", line: 2}, want{name: "EdDSA", line: 3},
		want{name: "RSA", line: 4}, want{name: "AES", line: 5}, want{name: "3DES", line: 5}, want{name: "MD5", line: 6})
	for _, g := range got {
		if g.Line == 1 {
			t.Fatal("detectó una línea comentada")
		}
	}
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func TestSSHPublicKeys(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	n := append([]byte{0}, rk.N.Bytes()...) // mpint positivo
	blob := append(append(sshString([]byte("ssh-rsa")), sshString(big.NewInt(int64(rk.E)).Bytes())...), sshString(n)...)
	src := "ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " usuario@ejemplo.test\n" +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVqZW1wbG8tbm8tZXMtdW5hLWNsYXZlLXJlYWw= otro\n"
	got := run(t, SSH{}, "home/u/.ssh/authorized_keys", src)
	expect(t, got, want{name: "RSA", bits: 1024, line: 1}, want{name: "EdDSA", line: 2})
	for _, g := range got {
		if strings.Contains(g.Evidence, "@") || strings.Contains(g.Evidence, "AAAA") {
			t.Fatalf("la evidencia no debe incluir la clave ni el comentario: %q", g.Evidence)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	src := `server {
    ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:RC4-MD5:!3DES:!aNULL';
    ssl_ecdh_curve X25519MLKEM768:X25519;
    # ssl_protocols SSLv3;
}
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
`
	got := run(t, TLSConfig{}, "nginx/site.conf", src)
	expect(t, got, want{name: "TLSv1.0", line: 2}, want{name: "TLSv1.2", line: 2}, want{name: "TLSv1.3", line: 2},
		want{name: "ECDH", line: 3}, want{name: "ECDSA", line: 3}, want{name: "DH", line: 3}, want{name: "RSA", line: 3},
		want{name: "SHA-1", line: 3}, want{name: "RC4", line: 3}, want{name: "MD5", line: 3},
		want{name: "X25519MLKEM768", line: 4}, want{name: "ECDH", line: 4},
		want{name: "TLSv1.2", line: 7}, want{name: "TLSv1.3", line: 7})
	for _, g := range got {
		if g.Line == 3 && g.Name == "3DES" {
			t.Fatal("!3DES está excluido, no es un uso")
		}
		if g.Line == 5 {
			t.Fatal("detectó una línea comentada")
		}
		if g.Line == 7 && (g.Name == "SSLv3" || g.Name == "TLSv1.0" || g.Name == "TLSv1.1") {
			t.Fatalf("Apache: %s está deshabilitado", g.Name)
		}
	}
}

func TestCipherName(t *testing.T) {
	cases := map[string]string{"aes-256-gcm": "AES", "AES/CBC/PKCS5Padding": "AES", "des-ede3-cbc": "3DES", "DESede": "3DES",
		"des-cbc": "DES", "rc4": "RC4", "arcfour256": "RC4", "bf-cbc": "Blowfish", "chacha20-poly1305@openssh.com": "ChaCha20-Poly1305"}
	for in, w := range cases {
		if got := CipherName(in); got != w {
			t.Errorf("CipherName(%q) = %q, quería %q", in, got, w)
		}
	}
}

func TestX509ByOID(t *testing.T) {
	// SubjectPublicKeyInfo de ML-DSA-65 y de ECDSA secp256k1 (curvas/algoritmos que crypto/x509 no interpreta).
	mk := func(alg string, params []byte) string {
		oid := func(s string) []byte {
			var o asn1.ObjectIdentifier
			for _, p := range strings.Split(s, ".") {
				n, _ := new(big.Int).SetString(p, 10)
				o = append(o, int(n.Int64()))
			}
			b, _ := asn1.Marshal(o)
			return b
		}
		algID := oid(alg)
		if params != nil {
			algID = append(algID, params...)
		}
		seq := func(b []byte) []byte {
			r, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: b})
			return r
		}
		bits, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24})
		der := seq(append(seq(algID), bits...))
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	k1, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
	got := run(t, X509{}, "k.pem", mk("2.16.840.1.101.3.4.3.18", nil)+mk("1.2.840.10045.2.1", k1))
	expect(t, got, want{name: "ML-DSA", curve: "ML-DSA-65"}, want{name: "ECDSA", curve: "secp256k1"})
}
