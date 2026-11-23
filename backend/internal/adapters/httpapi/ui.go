package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// El panel compilado (web/ → npm run build) queda en ui/dist y se embebe en el binario. Si no esta,
// se sirve una pagina que explica como compilarlo: el backend nunca depende de Node para compilar.
//
//go:embed ui
var uiFS embed.FS

func uiHandler() http.Handler {
	if dist, err := fs.Sub(uiFS, "ui/dist"); err == nil {
		if _, err := fs.Stat(dist, "index.html"); err == nil {
			return spa(dist)
		}
	}
	return placeholder()
}

// spa sirve archivos estaticos; cualquier ruta que no sea un archivo devuelve index.html.
func spa(dist fs.FS) http.Handler {
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(dist, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			p = "index.html"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // nombres con hash
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func placeholder() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "ui/placeholder.html"
		ct := "text/html; charset=utf-8"
		if r.URL.Path == "/placeholder.css" {
			name, ct = "ui/placeholder.css", "text/css"
		}
		b, _ := uiFS.ReadFile(name)
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
	})
}
