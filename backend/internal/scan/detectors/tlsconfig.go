package detectors

import (
	"strings"
)

// TLSConfig analiza configuracion de servidores: nginx, Apache/httpd, HAProxy y openssl.cnf.
type TLSConfig struct{}

func (TLSConfig) Name() string { return "tls-config" }

func (TLSConfig) Match(f File) bool {
	b, p := f.Base(), strings.ToLower(f.Path)
	return f.Ext() == ".conf" || f.Ext() == ".cnf" || b == "nginx.conf" || b == "httpd.conf" || b == "haproxy.cfg" ||
		strings.Contains(p, "nginx/") || strings.Contains(p, "sites-available/") || strings.Contains(p, "sites-enabled/")
}

func (TLSConfig) Detect(f File) []Raw {
	var out []Raw
	for i, raw := range lines(f.Data) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimSuffix(line, ";")
		fields := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		vals := fields[1:]
		add := func(name string, ctx string) {
			out = append(out, Raw{Name: name, Line: i + 1, Column: 1, Context: ctx, Evidence: Evidence(raw), Confidence: "alta"})
		}
		switch key {
		case "sslprotocol", "sslproxyprotocol":
			// Apache: "all -SSLv3 -TLSv1" se evalua como conjunto.
			on := map[string]bool{}
			var order []string
			set := func(n string, v bool) {
				if _, ok := on[n]; !ok {
					order = append(order, n)
				}
				on[n] = v
			}
			for _, v := range vals {
				enable := !strings.HasPrefix(v, "-")
				v = strings.TrimLeft(v, "+-")
				if strings.EqualFold(v, "all") {
					for _, n := range []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"} {
						set(n, enable)
					}
				} else if n := protoName(v); n != "" {
					set(n, enable)
				}
			}
			for _, n := range order {
				if on[n] {
					add(n, fields[0])
				}
			}
		case "ssl_protocols", "ssl-default-bind-options", "ssl-default-server-options", "minprotocol", "ssl-min-ver":
			for _, v := range vals {
				if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "no-") {
					continue // protocolo deshabilitado explicitamente
				}
				v = strings.TrimPrefix(strings.TrimPrefix(v, "+"), "ssl-min-ver")
				if n := protoName(v); n != "" {
					add(n, fields[0])
				}
			}
		case "ssl_ciphers", "sslciphersuite", "ciphers", "ciphersuites", "ssl-default-bind-ciphers", "ssl-default-server-ciphers", "cipherstring":
			for _, n := range cipherList(strings.Join(vals, " ")) {
				add(n, fields[0])
			}
		case "ssl_ecdh_curve", "groups", "curves", "sslopensslconfcmd":
			for _, v := range vals {
				for _, g := range strings.Split(strings.Trim(v, `"`), ":") {
					switch strings.ToLower(g) {
					case "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024":
						add("X25519MLKEM768", fields[0])
					case "x25519", "x448", "prime256v1", "secp256r1", "secp384r1", "secp521r1", "p-256", "p-384", "p-521":
						add("ECDH", fields[0])
					}
				}
			}
		}
	}
	return out
}

func protoName(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "sslv3", "sslv2":
		return "SSLv3"
	case "tlsv1", "tlsv1.0":
		return "TLSv1.0"
	case "tlsv1.1":
		return "TLSv1.1"
	case "tlsv1.2":
		return "TLSv1.2"
	case "tlsv1.3":
		return "TLSv1.3"
	}
	return ""
}

// cipherList extrae algoritmos de una cadena de cifrados de OpenSSL ("ECDHE-RSA-AES128-GCM-SHA256:!RC4:...").
// Los elementos negados (!RC4, -DES) no cuentan como uso.
func cipherList(s string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, c := range strings.FieldsFunc(strings.Trim(s, `"'`), func(r rune) bool { return r == ':' || r == ',' || r == ' ' }) {
		if c == "" || c[0] == '!' || c[0] == '-' || c[0] == '@' {
			continue
		}
		u := strings.ToUpper(strings.TrimPrefix(c, "+"))
		parts := strings.Split(strings.ReplaceAll(u, "_", "-"), "-")
		has := func(p string) bool {
			for _, x := range parts {
				if x == p {
					return true
				}
			}
			return false
		}
		tls13 := strings.HasPrefix(u, "TLS-") || strings.HasPrefix(u, "TLS_")
		switch {
		case has("ECDHE") || has("EECDH"):
			add("ECDH")
		case has("DHE") || has("EDH"):
			add("DH")
		case !tls13 && (has("RSA") || has("AES") || has("AES128") || has("AES256") || has("DES") || has("RC4")):
			add("RSA") // intercambio por transporte RSA (sin forward secrecy)
		}
		if has("RSA") || has("ARSA") {
			add("RSA") // autenticacion
		}
		if has("ECDSA") {
			add("ECDSA")
		}
		switch {
		case has("3DES") || has("DES") && has("CBC3"):
			add("3DES")
		case has("DES"):
			add("DES")
		case has("RC4"):
			add("RC4")
		}
		if has("MD5") {
			add("MD5")
		}
		if u == "SHA" || strings.HasSuffix(u, "-SHA") {
			add("SHA-1")
		}
	}
	return out
}
