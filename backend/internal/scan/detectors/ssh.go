package detectors

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// SSH analiza configuracion de OpenSSH (sshd_config / ssh_config) y claves publicas (.pub,
// authorized_keys, known_hosts).
type SSH struct{}

func (SSH) Name() string { return "ssh" }

func (SSH) Match(f File) bool {
	b := f.Base()
	return b == "sshd_config" || b == "ssh_config" || strings.HasSuffix(b, ".pub") || b == "authorized_keys" ||
		b == "known_hosts" || strings.Contains(f.Path, "sshd_config.d/") || strings.Contains(f.Path, "ssh_config.d/")
}

var sshKex = map[string]string{
	"mlkem768x25519-sha256": "mlkem768x25519-sha256", "sntrup761x25519-sha512": "sntrup761x25519-sha512",
	"sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512", "curve25519-sha256": "X25519",
	"curve25519-sha256@libssh.org": "X25519", "ecdh-sha2-nistp256": "ECDH", "ecdh-sha2-nistp384": "ECDH",
	"ecdh-sha2-nistp521": "ECDH", "diffie-hellman-group1-sha1": "DH", "diffie-hellman-group14-sha1": "DH",
	"diffie-hellman-group14-sha256": "DH", "diffie-hellman-group16-sha512": "DH", "diffie-hellman-group18-sha512": "DH",
	"diffie-hellman-group-exchange-sha1": "DH", "diffie-hellman-group-exchange-sha256": "DH",
}

func sshKeyType(t string) (name, curve string) {
	t = strings.TrimPrefix(t, "sk-")
	switch {
	case strings.HasPrefix(t, "ssh-rsa"), strings.HasPrefix(t, "rsa-sha2"):
		return "RSA", ""
	case strings.HasPrefix(t, "ssh-ed25519"):
		return "EdDSA", "Ed25519"
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		c := strings.TrimPrefix(t, "ecdsa-sha2-")
		if i := strings.IndexByte(c, '@'); i > 0 {
			c = c[:i]
		}
		return "ECDSA", c
	case strings.HasPrefix(t, "ssh-dss"):
		return "DSA", ""
	}
	return "", ""
}

func (SSH) Detect(f File) []Raw {
	if strings.HasSuffix(f.Base(), "_config") || strings.Contains(f.Path, "_config.d/") {
		return sshConfig(f)
	}
	return sshKeys(f)
}

func sshConfig(f File) []Raw {
	var out []Raw
	for i, raw := range lines(f.Data) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(line, "=", " "))
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.TrimLeft(fields[1], "+-^")
		add := func(name, curve string) {
			out = append(out, Raw{Name: name, Curve: curve, Line: i + 1, Column: 1, Context: fields[0], Evidence: Evidence(raw), Confidence: "alta"})
		}
		switch key {
		case "kexalgorithms":
			for _, a := range strings.Split(val, ",") {
				if n, ok := sshKex[a]; ok {
					add(n, "")
				}
				if strings.HasSuffix(a, "-sha1") {
					add("SHA-1", "")
				}
			}
		case "hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "casignaturealgorithms":
			for _, a := range strings.Split(val, ",") {
				if n, c := sshKeyType(a); n != "" {
					add(n, c)
				}
			}
		case "hostkey":
			b := strings.ToLower(val)
			switch {
			case strings.Contains(b, "rsa"):
				add("RSA", "")
			case strings.Contains(b, "ed25519"):
				add("EdDSA", "Ed25519")
			case strings.Contains(b, "ecdsa"):
				add("ECDSA", "")
			case strings.Contains(b, "dsa"):
				add("DSA", "")
			}
		case "ciphers":
			for _, a := range strings.Split(val, ",") {
				add(CipherName(a), "")
			}
		case "macs":
			for _, a := range strings.Split(val, ",") {
				switch {
				case strings.HasPrefix(a, "hmac-md5"):
					add("MD5", "")
				case strings.HasPrefix(a, "hmac-sha1"):
					add("SHA-1", "")
				}
			}
		}
	}
	return out
}

func sshKeys(f File) []Raw {
	var out []Raw
	for i, raw := range lines(f.Data) {
		fields := strings.Fields(raw)
		for j, fld := range fields {
			name, curve := sshKeyType(fld)
			if name == "" || j+1 >= len(fields) {
				continue
			}
			bits := 0
			if name == "RSA" {
				bits = sshRSABits(fields[j+1])
			}
			ev := fld + " (clave publica"
			if bits > 0 {
				ev += ", " + itoa(bits) + " bits"
			}
			ev += ")" // nunca mostramos la clave ni el comentario (puede tener un mail)
			out = append(out, Raw{Name: name, Curve: curve, KeyBits: bits, Line: i + 1, Column: 1, Context: "clave publica SSH",
				Evidence: ev, Confidence: "alta"})
			break
		}
	}
	return out
}

// sshRSABits lee el modulo del blob ssh-rsa (string tipo, mpint e, mpint n).
func sshRSABits(b64 string) int {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0
	}
	read := func() []byte {
		if len(b) < 4 {
			return nil
		}
		n := binary.BigEndian.Uint32(b)
		if int(n) > len(b)-4 {
			b = nil
			return nil
		}
		v := b[4 : 4+n]
		b = b[4+n:]
		return v
	}
	read() // tipo
	read() // e
	n := read()
	for len(n) > 0 && n[0] == 0 {
		n = n[1:]
	}
	if len(n) == 0 {
		return 0
	}
	bits := len(n) * 8
	for m := n[0]; m&0x80 == 0; m <<= 1 {
		bits--
	}
	return bits
}
