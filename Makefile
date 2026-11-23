VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint scan-self cbom clean

build: ## Compila el binario en bin/
	cd backend && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/cryptoinv ./cmd/cryptoinv

test: ## Corre los tests con el detector de condiciones de carrera
	cd backend && go test -race -count=1 ./...

lint: ## Formato y análisis estático
	cd backend && test -z "$$(gofmt -l .)" && go vet ./...

scan-self: build ## Escanea este mismo repositorio
	./bin/cryptoinv scan . --asset cryptoinv --skip-tests

cbom: build ## Genera el CBOM (CycloneDX 1.6) de este repositorio
	./bin/cryptoinv scan . --asset cryptoinv --skip-tests --format cbom --output cbom.json

clean:
	rm -rf bin dist cbom.json results.sarif
