package detectors

import (
	"bytes"
	"crypto/dsa"     //nolint:staticcheck // cryptoinv:ignore solo reconoce el tipo de clave, no cifra ni firma
	"crypto/ecdh"    // cryptoinv:ignore solo reconoce el tipo de clave
	"crypto/ecdsa"   // cryptoinv:ignore solo reconoce el tipo de clave
	"crypto/ed25519" // cryptoinv:ignore solo reconoce el tipo de clave
	"crypto/rsa"     // cryptoinv:ignore solo reconoce el tipo de clave
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// X509 analiza certificados y claves en PEM/DER. Nunca copia material de clave a la evidencia: solo
// tipo, tamaño, curva y metadatos publicos del certificado.
type X509 struct{}

func (X509) Name() string { return "x509" }

var certExts = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".der": true, ".key": true, ".pub": false,
	".p8": true, ".csr": true}

func (X509) Match(f File) bool {
	if certExts[f.Ext()] {
		return true
	}
	return bytes.Contains(f.Data, []byte("-----BEGIN "))
}

func (X509) Detect(f File) []Raw {
	var out []Raw
	data := f.Data
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		if f.Ext() == ".der" || f.Ext() == ".cer" || f.Ext() == ".crt" {
			if c, err := x509.ParseCertificate(data); err == nil {
				return certRaws(c, 1)
			}
		}
		return nil
	}
	rest := data
	for {
		idx := bytes.Index(rest, []byte("-----BEGIN "))
		if idx < 0 {
			break
		}
		line := 1 + bytes.Count(data[:len(data)-len(rest)+idx], []byte("\n"))
		block, r := pem.Decode(rest[idx:])
		if block == nil {
			rest = rest[idx+11:]
			continue
		}
		rest = r
		out = append(out, pemRaws(block, line)...)
	}
	return out
}

func pemRaws(b *pem.Block, line int) []Raw {
	switch b.Type {
	case "CERTIFICATE":
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			return certRaws(c, line)
		}
	case "RSA PRIVATE KEY":
		if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
			return []Raw{keyRaw("RSA", k.N.BitLen(), "", line, b.Type)}
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
			return []Raw{keyRaw("ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name, line, b.Type)}
		}
		if c, ok := sec1Curve(b.Bytes); ok {
			return []Raw{keyRaw("ECDSA", 0, c, line, b.Type)}
		}
		r := keyRaw("ECDSA", 0, "", line, b.Type) // curva con parametros explicitos
		r.Confidence = "media"
		return []Raw{r}
	case "EC PARAMETERS", "DH PARAMETERS", "ENCRYPTED PRIVATE KEY":
		if b.Type == "DH PARAMETERS" {
			return []Raw{keyRaw("DH", 0, "", line, b.Type)}
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" {
			return []Raw{{Name: "unknown", Line: line, Context: b.Type, Evidence: "clave privada cifrada (el algoritmo no es visible)", Confidence: "baja"}}
		}
		return nil // los parametros acompañan a la clave, que se reporta aparte
	case "DSA PRIVATE KEY":
		return []Raw{keyRaw("DSA", 0, "", line, b.Type)}
	case "OPENSSH PRIVATE KEY":
		return []Raw{{Name: "RSA", Line: line, Context: b.Type, Evidence: "clave privada OpenSSH (tipo cifrado en el contenedor)",
			Confidence: "baja"}}
	case "PRIVATE KEY":
		if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
			return []Raw{anyKey(k, line, b.Type)}
		}
		if n, c, ok := oidKey(b.Bytes, true); ok {
			return []Raw{keyRaw(n, 0, c, line, b.Type)}
		}
	case "PUBLIC KEY":
		if k, err := x509.ParsePKIXPublicKey(b.Bytes); err == nil {
			return []Raw{anyKey(k, line, b.Type)}
		}
		if n, c, ok := oidKey(b.Bytes, false); ok {
			return []Raw{keyRaw(n, 0, c, line, b.Type)}
		}
	case "RSA PUBLIC KEY":
		if k, err := x509.ParsePKCS1PublicKey(b.Bytes); err == nil {
			return []Raw{keyRaw("RSA", k.N.BitLen(), "", line, b.Type)}
		}
	case "CERTIFICATE REQUEST":
		if c, err := x509.ParseCertificateRequest(b.Bytes); err == nil {
			r := anyKey(c.PublicKey, line, b.Type)
			return []Raw{r}
		}
	}
	// No se pudo interpretar (por ejemplo, una clave PEM cifrada): el tipo PEM igual dice la familia.
	for prefix, name := range map[string]string{"RSA ": "RSA", "DSA ": "DSA", "EC ": "ECDSA"} {
		if strings.HasPrefix(b.Type, prefix) {
			r := keyRaw(name, 0, "", line, b.Type)
			r.Confidence = "media"
			if _, enc := b.Headers["Proc-Type"]; enc {
				r.Evidence += " (cifrada)"
			}
			return []Raw{r}
		}
	}
	if strings.Contains(b.Type, "PRIVATE KEY") || strings.Contains(b.Type, "PUBLIC KEY") {
		return []Raw{{Name: "unknown", Line: line, Context: b.Type, Evidence: b.Type + " (no se pudo interpretar)", Confidence: "baja"}}
	}
	return nil
}

func anyKey(k any, line int, ctx string) Raw {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return keyRaw("RSA", v.N.BitLen(), "", line, ctx)
	case *rsa.PublicKey:
		return keyRaw("RSA", v.N.BitLen(), "", line, ctx)
	case *ecdsa.PrivateKey:
		return keyRaw("ECDSA", v.Curve.Params().BitSize, v.Curve.Params().Name, line, ctx)
	case *ecdsa.PublicKey:
		return keyRaw("ECDSA", v.Curve.Params().BitSize, v.Curve.Params().Name, line, ctx)
	case ed25519.PrivateKey, ed25519.PublicKey:
		return keyRaw("EdDSA", 256, "Ed25519", line, ctx)
	case *ecdh.PrivateKey, *ecdh.PublicKey:
		return keyRaw("ECDH", 256, "X25519", line, ctx)
	case *dsa.PublicKey:
		return keyRaw("DSA", v.P.BitLen(), "", line, ctx)
	}
	return Raw{Name: "unknown", Line: line, Context: ctx, Evidence: ctx, Confidence: "baja"}
}

func keyRaw(name string, bits int, curve string, line int, ctx string) Raw {
	ev := strings.ToLower(ctx) + ": " + name
	if bits > 0 {
		ev += " " + itoa(bits) + " bits"
	}
	if curve != "" {
		ev += " (" + curve + ")"
	}
	return Raw{Name: name, KeyBits: bits, Curve: curve, Line: line, Context: ctx, Evidence: ev, Confidence: "alta"}
}

func certRaws(c *x509.Certificate, line int) []Raw {
	meta := &CertMeta{Subject: c.Subject.String(), Issuer: c.Issuer.String(), SignatureAlg: c.SignatureAlgorithm.String(),
		NotBefore: c.NotBefore.Unix(), NotAfter: c.NotAfter.Unix(), SelfSigned: c.Subject.String() == c.Issuer.String()}
	k := anyKey(c.PublicKey, line, "CERTIFICATE")
	if k.Name == "unknown" {
		if n, cv, ok := oidKey(c.RawSubjectPublicKeyInfo, false); ok {
			k = keyRaw(n, 0, cv, line, "CERTIFICATE")
		} else {
			k.Evidence = "certificate: algoritmo no reconocido (" + spkiOID(c.RawSubjectPublicKeyInfo) + ")"
		}
	}
	k.Cert = meta
	k.Evidence = "certificado " + shortDN(meta.Subject) + ": clave " + strings.TrimPrefix(k.Evidence, "certificate: ") +
		", firmado con " + meta.SignatureAlg
	out := []Raw{k}
	// Hash de la firma: SHA-1 / MD5 en certificados es un hallazgo aparte.
	sa := strings.ToUpper(meta.SignatureAlg)
	switch {
	case strings.HasPrefix(sa, "SHA1"):
		out = append(out, Raw{Name: "SHA-1", Line: line, Context: "firma del certificado", Evidence: k.Evidence, Confidence: "alta", Cert: meta})
	case strings.HasPrefix(sa, "MD5"), strings.HasPrefix(sa, "MD2"):
		out = append(out, Raw{Name: "MD5", Line: line, Context: "firma del certificado", Evidence: k.Evidence, Confidence: "alta", Cert: meta})
	}
	return out
}

func shortDN(dn string) string {
	for _, p := range strings.Split(dn, ",") {
		if strings.HasPrefix(p, "CN=") {
			return p[3:]
		}
	}
	if dn == "" {
		return "(sin nombre)"
	}
	return dn
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
