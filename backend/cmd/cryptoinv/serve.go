package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/adapters/httpapi"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/adapters/store"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
)

func serveCmd(ctx context.Context, args []string, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	addr := fs.String("addr", "127.0.0.1:8080", "")
	data := fs.String("data", ".cryptoinv", "")
	token := fs.String("token", os.Getenv("CRYPTOINV_TOKEN"), "")
	noScan := fs.Bool("no-scan", false, "")
	if err := fs.Parse(reorder(args)); err != nil {
		return 2, nil
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return 2, fmt.Errorf("--addr inválido: %w", err)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loopback && *token == "" {
		return 2, errors.New("escuchar fuera de localhost exige --token (o CRYPTOINV_TOKEN)")
	}

	repo, err := store.OpenFileStore(*data)
	if err != nil {
		return 1, err
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := &app.Service{Repo: repo, Scanner: app.NewScanner()}
	for _, p := range fs.Args() {
		m, err := svc.Scan(ctx, app.ScanRequest{Root: p})
		if err != nil {
			return 1, fmt.Errorf("escaneando %s: %w", p, err)
		}
		log.Info("escaneo inicial", "activo", m.Asset, "usos", m.Summary.Findings, "preparacion", m.Summary.Readiness)
	}

	h := httpapi.New(svc, httpapi.Config{Token: *token, AllowScan: !*noScan, Loopback: loopback, Version: version, Logger: log})
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(stderr, "cryptoinv %s · panel en http://%s · datos en %s · Ctrl+C para salir\n", version, ln.Addr(), *data)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		return 0, nil
	case err := <-errc:
		return 1, err
	}
}

func snapshotCmd(ctx context.Context, args []string, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", ".cryptoinv", "")
	out := fs.String("out", "", "")
	if err := fs.Parse(reorder(args)); err != nil {
		return 2, nil
	}
	if *out == "" {
		return 2, errors.New("falta --out")
	}
	repo, err := store.OpenFileStore(*data)
	if err != nil {
		return 1, err
	}
	svc := &app.Service{Repo: repo, Scanner: app.NewScanner()}
	if err := httpapi.WriteSnapshot(ctx, svc, *out, time.Now()); err != nil {
		return 1, err
	}
	fmt.Fprintf(stderr, "snapshot escrito en %s\n", *out)
	return 0, nil
}
