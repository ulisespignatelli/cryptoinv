// Package catalog es la base de conocimiento: que es cada algoritmo, como lo afecta la computacion
// cuantica, cuando queda desaprobado o prohibido y por que reemplazarlo. Son datos versionados (data.json),
// separados de la logica: cuando cambia una norma se actualiza el archivo, no el codigo.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

//go:embed data.json
var raw []byte

// Algorithm es una entrada del catalogo.
type Algorithm struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Family      string               `json:"family"`
	Primitive   domain.Primitive     `json:"primitive"`
	Quantum     domain.QuantumStatus `json:"quantum"`
	Deprecated  int                  `json:"deprecated_after,omitempty"`
	Disallowed  int                  `json:"disallowed_after,omitempty"`
	MinKeyBits  int                  `json:"min_key_bits,omitempty"` // por debajo, ya es debil hoy
	Replacement string               `json:"replacement,omitempty"`
	Note        string               `json:"note"`
	NISTLevel   int                  `json:"nist_quantum_level"` // 0 = vulnerable; 1-5 = nivel de seguridad cuantica
	Aliases     []string             `json:"aliases,omitempty"`
}

// File es el formato de data.json.
type File struct {
	Version    string      `json:"version"`
	Sources    []string    `json:"sources"`
	Algorithms []Algorithm `json:"algorithms"`
}

// Catalog permite buscar algoritmos por ID o alias.
type Catalog struct {
	Version string
	Sources []string
	byID    map[string]Algorithm
	alias   map[string]string
}

// Load lee el catalogo incluido en el binario.
func Load() (*Catalog, error) { return Parse(raw) }

// MustLoad es Load para el arranque: si el catalogo incluido es invalido, el programa no tiene sentido.
func MustLoad() *Catalog {
	c, err := Load()
	if err != nil {
		panic(err)
	}
	return c
}

// Parse valida y arma un catalogo a partir de JSON.
func Parse(data []byte) (*Catalog, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("catálogo inválido: %w", err)
	}
	c := &Catalog{Version: f.Version, Sources: f.Sources, byID: map[string]Algorithm{}, alias: map[string]string{}}
	for _, a := range f.Algorithms {
		if a.ID == "" || a.Name == "" || a.Primitive == "" || a.Quantum == "" {
			return nil, fmt.Errorf("catálogo: entrada incompleta %q", a.ID)
		}
		if _, dup := c.byID[a.ID]; dup {
			return nil, fmt.Errorf("catálogo: ID repetido %q", a.ID)
		}
		c.byID[a.ID] = a
		for _, al := range append([]string{a.ID, a.Name}, a.Aliases...) {
			c.alias[norm(al)] = a.ID
		}
	}
	return c, nil
}

func norm(s string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", "/", "").Replace(strings.ToLower(s))
}

// Get devuelve un algoritmo por ID.
func (c *Catalog) Get(id string) (Algorithm, bool) {
	a, ok := c.byID[id]
	return a, ok
}

// Resolve busca por ID, nombre o alias ("RSA", "ecdsa", "SHA-1", "x25519").
func (c *Catalog) Resolve(name string) (Algorithm, bool) {
	id, ok := c.alias[norm(name)]
	if !ok {
		return Algorithm{}, false
	}
	return c.byID[id], true
}

// All devuelve todos los algoritmos ordenados por ID.
func (c *Catalog) All() []Algorithm {
	out := make([]Algorithm, 0, len(c.byID))
	for _, a := range c.byID {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
