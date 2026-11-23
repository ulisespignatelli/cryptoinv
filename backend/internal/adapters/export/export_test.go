package export

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/app"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/testutil"
)

func scanFixture(t *testing.T) (domain.Scan, *app.Scanner) {
	t.Helper()
	s := app.NewScanner()
	sc, err := s.Run(context.Background(), app.ScanRequest{Root: testutil.Project(t), Asset: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	return sc, s
}

func TestCBOM(t *testing.T) {
	sc, s := scanFixture(t)
	var buf bytes.Buffer
	if err := CBOM(&buf, sc, s.Catalog, "test"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Serial      string `json:"serialNumber"`
		Components  []struct {
			Type   string `json:"type"`
			Ref    string `json:"bom-ref"`
			Crypto struct {
				AssetType string         `json:"assetType"`
				Alg       map[string]any `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
			Evidence struct {
				Occurrences []struct {
					Location string `json:"location"`
				} `json:"occurrences"`
			} `json:"evidence"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" || !strings.HasPrefix(doc.Serial, "urn:uuid:") {
		t.Fatalf("cabecera: %+v", doc)
	}
	types, refs := map[string]int{}, map[string]bool{}
	for _, c := range doc.Components {
		if c.Type != "cryptographic-asset" || len(c.Evidence.Occurrences) == 0 {
			t.Fatalf("componente inválido: %+v", c)
		}
		if refs[c.Ref] {
			t.Fatalf("bom-ref repetido: %s", c.Ref)
		}
		refs[c.Ref] = true
		types[c.Crypto.AssetType]++
		if c.Crypto.AssetType == "algorithm" && c.Crypto.Alg["primitive"] == "" {
			t.Fatalf("falta primitive: %+v", c)
		}
	}
	if types["algorithm"] == 0 || types["certificate"] != 1 || types["protocol"] == 0 {
		t.Fatalf("tipos de activo: %v", types)
	}
}

func TestSARIF(t *testing.T) {
	sc, _ := scanFixture(t)
	var buf bytes.Buffer
	if err := SARIF(&buf, sc, "test"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("sarif: %+v", doc)
	}
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "cryptoinv/mlkem" || r.RuleID == "cryptoinv/hybrid-kex" {
			t.Fatal("lo resistente no se reporta como problema")
		}
	}
}

func TestTextAndJSON(t *testing.T) {
	sc, s := scanFixture(t)
	var txt, js bytes.Buffer
	if err := Write(&txt, "text", sc, s.Catalog, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(txt.String(), "preparación post-cuántica") || !strings.Contains(txt.String(), "reemplazo") {
		t.Fatal(txt.String())
	}
	if err := Write(&js, "json", sc, s.Catalog, "test"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil || doc["schema"] != "cryptoinv/scan/v1" || doc["summary"] == nil {
		t.Fatalf("json: %v %v", err, doc["schema"])
	}
	if err := Write(&js, "xml", sc, s.Catalog, "test"); err == nil {
		t.Fatal("formato desconocido debería fallar")
	}
}
