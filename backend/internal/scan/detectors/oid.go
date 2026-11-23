package detectors

import (
	"encoding/asn1"
)

// Lectura minima de ASN.1 para claves que crypto/x509 no interpreta: curvas no NIST (secp256k1,
// brainpool), RSA-PSS, Ed448/X448 y claves post-cuanticas (ML-KEM, ML-DSA, SLH-DSA). Solo se lee el
// identificador del algoritmo; nunca se toca el material de la clave.

var oidAlgs = map[string]string{
	"1.2.840.113549.1.1.1": "RSA", "1.2.840.113549.1.1.10": "RSA", "1.2.840.10045.2.1": "ECDSA",
	"1.2.840.10040.4.1": "DSA", "1.2.840.113549.1.3.1": "DH", "1.2.840.10046.2.1": "DH",
	"1.3.101.110": "ECDH", "1.3.101.111": "ECDH", "1.3.101.112": "EdDSA", "1.3.101.113": "EdDSA",
	"2.16.840.1.101.3.4.4.1": "ML-KEM", "2.16.840.1.101.3.4.4.2": "ML-KEM", "2.16.840.1.101.3.4.4.3": "ML-KEM",
	"2.16.840.1.101.3.4.3.17": "ML-DSA", "2.16.840.1.101.3.4.3.18": "ML-DSA", "2.16.840.1.101.3.4.3.19": "ML-DSA",
}

var oidCurves = map[string]string{
	"1.2.840.10045.3.1.1": "secp192r1", "1.3.132.0.33": "P-224", "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384",
	"1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1", "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
	"1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
	"1.3.101.110": "X25519", "1.3.101.111": "X448", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
	"2.16.840.1.101.3.4.4.1": "ML-KEM-512", "2.16.840.1.101.3.4.4.2": "ML-KEM-768", "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

func init() {
	// SLH-DSA: 2.16.840.1.101.3.4.3.20 a .31
	for i := 20; i <= 31; i++ {
		oidAlgs["2.16.840.1.101.3.4.3."+itoa(i)] = "SLH-DSA"
	}
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// oidKey identifica PKCS#8 (PRIVATE KEY) o SubjectPublicKeyInfo (PUBLIC KEY) por OID.
func oidKey(der []byte, private bool) (name, curve string, ok bool) {
	var id algID
	if private {
		var k struct {
			Version int
			Alg     algID
			Key     []byte
		}
		if _, err := asn1.Unmarshal(der, &k); err != nil {
			return "", "", false
		}
		id = k.Alg
	} else {
		var k struct {
			Alg algID
			Key asn1.BitString
		}
		if _, err := asn1.Unmarshal(der, &k); err != nil {
			return "", "", false
		}
		id = k.Alg
	}
	oid := id.Algorithm.String()
	name, ok = oidAlgs[oid]
	if !ok {
		return "", "", false
	}
	curve = oidCurves[oid]
	if name == "ECDSA" && len(id.Parameters.FullBytes) > 0 {
		var c asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(id.Parameters.FullBytes, &c); err == nil {
			curve = or(oidCurves[c.String()], c.String())
		}
	}
	return name, curve, true
}

// sec1Curve lee la curva de una clave "EC PRIVATE KEY" (RFC 5915) aunque Go no la soporte.
func sec1Curve(der []byte) (string, bool) {
	var k struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil || len(k.Curve) == 0 {
		return "", false
	}
	return or(oidCurves[k.Curve.String()], k.Curve.String()), true
}

// spkiOID devuelve el OID del algoritmo de una SubjectPublicKeyInfo, para mostrarlo cuando no se conoce.
func spkiOID(der []byte) string {
	var k struct {
		Alg algID
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return "OID ilegible"
	}
	return "OID " + k.Alg.Algorithm.String()
}
