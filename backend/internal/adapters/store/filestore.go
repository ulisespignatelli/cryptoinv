// Package store implementa el repositorio de escaneos.
//
// FileStore guarda un JSON por escaneo en una carpeta y mantiene un indice en memoria. No necesita
// dependencias externas ni servidor de base de datos, alcanza para miles de escaneos y es facil de
// respaldar. Otro adaptador (SQLite, Postgres) puede reemplazarlo sin tocar los casos de uso: solo
// tiene que cumplir app.ScanRepository.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// FileStore es un repositorio en disco.
type FileStore struct {
	dir   string
	mu    sync.RWMutex
	index map[string]app.ScanMeta
	cache map[string]domain.Scan // ultimos escaneos leidos (chico: se limpia al pasar de 16)
}

// OpenFileStore abre (o crea) el repositorio en dir.
func OpenFileStore(dir string) (*FileStore, error) {
	scans := filepath.Join(dir, "scans")
	if err := os.MkdirAll(scans, 0o700); err != nil {
		return nil, err
	}
	s := &FileStore{dir: scans, index: map[string]app.ScanMeta{}, cache: map[string]domain.Scan{}}
	entries, err := os.ReadDir(scans)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		sc, err := s.read(e.Name()[:len(e.Name())-5])
		if err != nil {
			return nil, fmt.Errorf("escaneo dañado %s: %w", e.Name(), err)
		}
		s.index[sc.ID] = app.Meta(sc)
	}
	return s, nil
}

func (s *FileStore) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *FileStore) read(id string) (domain.Scan, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return domain.Scan{}, err
	}
	var sc domain.Scan
	err = json.Unmarshal(b, &sc)
	return sc, err
}

// Save escribe de forma atomica (archivo temporal + rename).
func (s *FileStore) Save(_ context.Context, sc domain.Scan) error {
	if !validID.MatchString(sc.ID) {
		return fmt.Errorf("ID de escaneo inválido %q", sc.ID)
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tmp.Name(), s.path(sc.ID)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	s.index[sc.ID] = app.Meta(sc)
	s.cache[sc.ID] = sc
	return nil
}

// Get lee un escaneo completo.
func (s *FileStore) Get(_ context.Context, id string) (domain.Scan, error) {
	if !validID.MatchString(id) {
		return domain.Scan{}, app.ErrNotFound
	}
	s.mu.RLock()
	sc, cached := s.cache[id]
	_, known := s.index[id]
	s.mu.RUnlock()
	if cached {
		return sc, nil
	}
	if !known {
		return domain.Scan{}, app.ErrNotFound
	}
	sc, err := s.read(id)
	if errors.Is(err, os.ErrNotExist) {
		return domain.Scan{}, app.ErrNotFound
	}
	if err != nil {
		return domain.Scan{}, err
	}
	s.mu.Lock()
	if len(s.cache) >= 16 {
		s.cache = map[string]domain.Scan{}
	}
	s.cache[id] = sc
	s.mu.Unlock()
	return sc, nil
}

// List devuelve los escaneos del mas reciente al mas viejo.
func (s *FileStore) List(_ context.Context) ([]app.ScanMeta, error) {
	s.mu.RLock()
	out := make([]app.ScanMeta, 0, len(s.index))
	for _, m := range s.index {
		out = append(out, m)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.After(out[j].StartedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// Delete borra un escaneo.
func (s *FileStore) Delete(_ context.Context, id string) error {
	if !validID.MatchString(id) {
		return app.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.index[id]; !ok {
		return app.ErrNotFound
	}
	if err := os.Remove(s.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.index, id)
	delete(s.cache, id)
	return nil
}
