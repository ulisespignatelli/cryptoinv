package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/testutil"
)

func TestCLI(t *testing.T) {
	dir := testutil.Project(t)
	var out, errb bytes.Buffer
	code, err := run(context.Background(), []string{"scan", dir, "--format", "json", "--asset", "demo"}, &out, &errb)
	if err != nil || code != 0 || !strings.Contains(out.String(), `"asset": "demo"`) {
		t.Fatalf("code=%d err=%v out=%.200s", code, err, out.String())
	}
	out.Reset()
	code, _ = run(context.Background(), []string{"scan", "--fail-on", "critica", dir}, &out, &errb)
	if code != 1 {
		t.Fatalf("--fail-on critica con RSA-1024 debería devolver 1, devolvió %d", code)
	}
	code, _ = run(context.Background(), []string{"scan", dir, "--fail-on", "nada"}, &out, &errb)
	if code != 2 {
		t.Fatalf("severidad inválida debería devolver 2, devolvió %d", code)
	}
	out.Reset()
	if code, _ := run(context.Background(), []string{"scan", "--skip-tests", dir, "--format", "json"}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `"in_tests": 0`) {
		t.Fatalf("--skip-tests: %d %.300s", code, out.String())
	}
	if code, _ := run(context.Background(), []string{"catalog"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "mlkem") {
		t.Fatal("catalog")
	}
	if code, _ := run(context.Background(), []string{"scan"}, &out, &errb); code != 2 {
		t.Fatal("scan sin ruta debería devolver 2")
	}
}
