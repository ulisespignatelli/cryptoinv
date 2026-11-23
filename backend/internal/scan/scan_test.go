package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkSkipsAndSuppresses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.py", "import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'x')  # cryptoinv:ignore checksum de caché\n")
	write(t, dir, ".git/config", "hashlib.md5(b'x')\n")
	write(t, dir, "vendor/x.py", "hashlib.md5(b'x')\n")
	write(t, dir, "big.py", string(make([]byte, 10))+"hashlib.md5(b'x')\n") // contiene NUL: binario
	res, err := Run(context.Background(), dir, Options{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 || res.Hits[0].Path != "a.py" || res.Hits[0].Raw.Line != 2 {
		t.Fatalf("hits: %+v", res.Hits)
	}
	if res.Suppressed != 1 {
		t.Fatalf("suprimidos: %d", res.Suppressed)
	}
}

func TestSingleFileAndMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "k.go", "package k\n\nimport \"crypto/rsa\"\n")
	res, err := Run(context.Background(), filepath.Join(dir, "k.go"), Options{})
	if err != nil || len(res.Hits) != 1 || res.Hits[0].Path != "k.go" {
		t.Fatalf("archivo suelto: %v %+v", err, res.Hits)
	}
	if _, err := Run(context.Background(), filepath.Join(dir, "no-existe"), Options{}); err == nil {
		t.Fatal("una ruta inexistente debería fallar")
	}
}

func TestCancel(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.py", "hashlib.md5(b'x')\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, dir, Options{}); err == nil {
		t.Fatal("un contexto cancelado debería cortar el recorrido")
	}
}
