package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

func TestFileStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i, id := range []string{"a1", "b2", "c3"} {
		sc := domain.Scan{ID: id, Asset: "api", StartedAt: t0.Add(time.Duration(i) * time.Hour),
			Findings: []domain.Finding{{Usage: domain.Usage{ID: "f" + id, AlgorithmID: "rsa"}}}}
		if err := s.Save(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(ctx, domain.Scan{ID: "../escape"}); err == nil {
		t.Fatal("un ID con ruta debería rechazarse")
	}
	list, _ := s.List(ctx)
	if len(list) != 3 || list[0].ID != "c3" || list[0].Summary.Findings != 1 {
		t.Fatalf("lista: %+v", list)
	}
	// Reabrir: el indice se reconstruye desde disco.
	s2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(ctx, "b2")
	if err != nil || got.Asset != "api" || len(got.Findings) != 1 {
		t.Fatalf("get: %v %+v", err, got)
	}
	if err := s2.Delete(ctx, "b2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get(ctx, "b2"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("borrado: %v", err)
	}
	if _, err := s2.Get(ctx, "../../etc/passwd"); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("ruta inválida debería ser no encontrado")
	}
	if err := s2.Delete(ctx, "zz"); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("borrar inexistente")
	}
}
