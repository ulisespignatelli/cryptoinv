package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
)

// WriteSnapshot guarda las respuestas de la API como archivos JSON estaticos. El panel los lee en modo
// demostracion (GitHub Pages, sin servidor) y aplica los filtros del inventario del lado del navegador:
//
//	overview.json  scans.json  catalog.json
//	scans/{id}.json  scans/{id}/findings.json  scans/{id}/plan.json  scans/{id}/certificates.json
func WriteSnapshot(ctx context.Context, svc *app.Service, dir string, now time.Time) error {
	write := func(rel string, v any) error {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o644)
	}
	o, err := svc.Overview(ctx)
	if err != nil {
		return err
	}
	if err := write("overview.json", o); err != nil {
		return err
	}
	list, err := svc.Repo.List(ctx)
	if err != nil {
		return err
	}
	if err := write("scans.json", list); err != nil {
		return err
	}
	c := svc.Scanner.Catalog
	if err := write("catalog.json", map[string]any{"version": c.Version, "sources": c.Sources, "algorithms": c.All()}); err != nil {
		return err
	}
	for _, m := range list {
		d, err := svc.Detail(ctx, m.ID)
		if err != nil {
			return err
		}
		page, err := svc.Findings(ctx, m.ID, app.Filter{})
		if err != nil {
			return err
		}
		plan, err := svc.Plan(ctx, m.ID)
		if err != nil {
			return err
		}
		certs, err := svc.Certificates(ctx, m.ID, now)
		if err != nil {
			return err
		}
		for rel, v := range map[string]any{"scans/" + m.ID + ".json": d, "scans/" + m.ID + "/findings.json": page,
			"scans/" + m.ID + "/plan.json": plan, "scans/" + m.ID + "/certificates.json": certs} {
			if err := write(rel, v); err != nil {
				return err
			}
		}
	}
	return nil
}
