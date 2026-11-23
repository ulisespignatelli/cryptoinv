package app

import (
	"context"
	"errors"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// ErrNotFound lo devuelven los repositorios cuando no existe lo pedido.
var ErrNotFound = errors.New("no encontrado")

// ScanMeta es un escaneo sin sus hallazgos: lo que se lista.
type ScanMeta struct {
	ID         string    `json:"id"`
	Asset      string    `json:"asset"`
	Root       string    `json:"root"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Summary    Summary   `json:"summary"`
}

// Meta resume un escaneo.
func Meta(sc domain.Scan) ScanMeta {
	return ScanMeta{ID: sc.ID, Asset: sc.Asset, Root: sc.Root, StartedAt: sc.StartedAt, FinishedAt: sc.FinishedAt, Summary: Summarize(sc)}
}

// ScanRepository es el puerto de persistencia. El dominio y los casos de uso no saben si detras hay
// archivos, SQLite o Postgres.
type ScanRepository interface {
	Save(ctx context.Context, sc domain.Scan) error
	Get(ctx context.Context, id string) (domain.Scan, error)
	// List devuelve todos los escaneos, del mas reciente al mas viejo.
	List(ctx context.Context) ([]ScanMeta, error)
	Delete(ctx context.Context, id string) error
}
