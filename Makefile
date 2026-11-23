VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-go web web-demo test test-go test-web lint api-types serve demo-data cbom clean

build: web build-go ## Panel + binario con el panel embebido

build-go: ## Solo el binario (sin recompilar el panel)
	cd backend && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/cryptoinv ./cmd/cryptoinv

web: ## Compila el panel dentro del backend (se embebe en el binario)
	cd web && npm ci && npm run build

web-demo: ## Compila la demo estática para GitHub Pages (web/dist)
	cd web && npm ci && npm run build:demo

test: test-go test-web

test-go:
	cd backend && go test -race -count=1 ./...

test-web:
	cd web && npm ci && npm run typecheck && npm test

lint:
	cd backend && test -z "$$(gofmt -l .)" && go vet ./...

api-types: ## Regenera los tipos de TypeScript desde api/openapi.yaml
	cd web && npm run gen:api

serve: build ## Levanta el panel en http://127.0.0.1:8080 escaneando este repositorio
	./bin/cryptoinv serve .

demo-data: build-go ## Regenera los datos de la demo desde escaneos guardados en .cryptoinv
	./bin/cryptoinv snapshot --data .cryptoinv --out web/demo-public/demo

cbom: build-go
	./bin/cryptoinv scan . --asset cryptoinv --skip-tests --format cbom --output cbom.json

clean:
	rm -rf bin dist cbom.json results.sarif web/dist backend/internal/adapters/httpapi/ui/dist
