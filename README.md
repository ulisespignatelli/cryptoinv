# cryptoinv

**Inventario criptográfico y plan de migración post-cuántica.**
*Cryptographic inventory and post-quantum migration planning: finds every use of cryptography in code, configuration, certificates and keys, scores how urgent it is to migrate, and exports a standard CycloneDX CBOM.*

[![CI](https://github.com/ulisespignatelli/cryptoinv/actions/workflows/ci.yml/badge.svg)](https://github.com/ulisespignatelli/cryptoinv/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8)
![CycloneDX](https://img.shields.io/badge/CBOM-CycloneDX%201.6-blue)
![SARIF](https://img.shields.io/badge/SARIF-2.1.0-green)

---

## El problema

El 27 de octubre de 2026 el NIST publicó la versión final de **IR 8547**, la hoja de ruta para dejar la criptografía que una computadora cuántica puede romper. RSA, ECDSA, EdDSA, ECDH y Diffie-Hellman quedan **desaprobados después de 2030 y prohibidos después de 2035**, con cualquier tamaño de clave. Los reemplazos ya están estandarizados: ML-KEM (FIPS 203), ML-DSA (FIPS 204) y SLH-DSA (FIPS 205).

El primer paso de cualquier migración es saber **dónde está la criptografía**. En una organización grande está repartida en miles de repositorios, configuraciones de servidores, certificados, claves SSH e infraestructura como código, y casi nadie tiene ese inventario. Además, lo que se cifra hoy puede grabarse y descifrarse cuando exista la computadora cuántica (*harvest now, decrypt later*), así que el intercambio de claves es urgente desde ya.

`cryptoinv` arma ese inventario, explica el riesgo de cada uso y lo exporta en los formatos que las plataformas de seguridad ya entienden.

## Qué hace

```
$ cryptoinv scan ./mi-servicio
cryptoinv — inventario criptográfico de mi-servicio
42 archivos analizados · 17 usos de criptografía (3 en pruebas) · preparación post-cuántica 24%

  [CRITICA 95] RSA 1024 bits — internal/auth/keys.go:31
    k, err := rsa.GenerateKey(rand.Reader, 1024)
    · RSA es vulnerable a una computadora cuántica (algoritmo de Shor)
    · clave de 1024 bits: por debajo del mínimo aceptable hoy (2048)
    → reemplazo: ML-DSA (FIPS 204) o SLH-DSA (FIPS 205) ...

  [ALTA 80] ECDH (incl. X25519) — deploy/nginx.conf:14
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:...
    · datos que deben protegerse 10 años + 3 de migración superan los 9 que faltan para 2035 (desigualdad de Mosca)
    · protege la confidencialidad: lo cifrado hoy puede grabarse y descifrarse mañana
    → reemplazo: ML-KEM (FIPS 203); en TLS 1.3, el grupo híbrido X25519MLKEM768
```

- **Detecta** criptografía en Go, Python, Java/Kotlin, JavaScript/TypeScript, certificados X.509 y claves (PEM/DER, incluidas ML-KEM, ML-DSA y SLH-DSA), OpenSSH (`sshd_config`, claves públicas), nginx/Apache/HAProxy/OpenSSL, Terraform/Kubernetes/KMS y algoritmos JWT.
- **Evalúa** cada uso con un puntaje de 0 a 100 que siempre explica sus motivos: estado cuántico, fechas del NIST, desigualdad de Mosca (cuánto tienen que durar secretos tus datos y cuánto tarda tu organización en migrar), confidencialidad frente a firma, tamaño de clave y si está en código de prueba.
- **Reconoce lo que ya está bien**: ML-KEM, el intercambio híbrido `X25519MLKEM768` o `mlkem768x25519-sha256` de OpenSSH cuentan como avance en el porcentaje de preparación.
- **Exporta** a CycloneDX 1.6 CBOM, SARIF 2.1.0 (pestaña Security de GitHub), JSON y texto.

## Uso

```bash
# Instalar (requiere Go 1.22+)
go install github.com/ulisespignatelli/cryptoinv/backend/cmd/cryptoinv@latest

# Escanear
cryptoinv scan .
cryptoinv scan . --skip-tests                          # sin tests, fixtures ni ejemplos
cryptoinv scan . --format cbom --output cbom.json      # inventario estándar
cryptoinv scan . --format sarif --output results.sarif # para GitHub code scanning
cryptoinv scan . --shelf-life 25 --migration-years 5   # datos de salud, banca, gobierno
cryptoinv scan . --fail-on critica                     # corta el CI si aparece algo crítico

# Ver el catálogo de algoritmos y fechas
cryptoinv catalog
```

Para descartar un uso que no es criptografía real (por ejemplo, código que solo reconoce el tipo de una clave), agregá un comentario en la misma línea con el motivo:

```go
import "crypto/rsa" // cryptoinv:ignore solo se usa para reconocer el tipo de clave
```

### En GitHub Actions

```yaml
- run: go install github.com/ulisespignatelli/cryptoinv/backend/cmd/cryptoinv@latest
- run: cryptoinv scan . --skip-tests --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif, category: cryptoinv }
```

Este mismo repositorio lo hace en su CI ([ci.yml](.github/workflows/ci.yml)).

## Probado en proyectos reales

Escaneos de repositorios públicos (noviembre de 2026):

| Proyecto | Archivos | Usos | En pruebas | Tiempo |
|---|---:|---:|---:|---:|
| FiloSottile/mkcert | 16 | 7 | 0 | 10 ms |
| jpadilla/pyjwt | 91 | 296 | 246 | 28 ms |
| auth0/node-jsonwebtoken | 84 | 117 | 114 | 32 ms |
| caddyserver/caddy | 777 | 88 | 48 | 127 ms |
| pyca/cryptography | 2115 | 1030 | 1025 | 337 ms |

Los CBOM generados validan sin errores contra el esquema oficial de CycloneDX 1.6, y los SARIF contra el de SARIF 2.1.0.

## Arquitectura

Monorepo con arquitectura hexagonal: el dominio no depende de nada y todo depende del dominio.

```
backend/
  cmd/cryptoinv/            CLI · raíz de composición
  internal/
    domain/                 modelo puro: Usage, Finding, Assessment, Scan
    catalog/                algoritmos y fechas NIST como datos (data.json embebido)
    risk/                   evaluación: función pura y explicada
    scan/                   recorrido concurrente de solo lectura
      detectors/            un archivo por lenguaje o formato; las reglas son tablas
    app/                    casos de uso (escanear, resumir)
    adapters/export/        texto, JSON, SARIF, CycloneDX CBOM
docs/adr/                   decisiones de arquitectura
```

| Decisión | Por qué |
|---|---|
| [Monorepo](docs/adr/0001-monorepo.md) | contrato, backend y frontend cambian juntos |
| [Hexagonal](docs/adr/0002-arquitectura-hexagonal.md) | el mismo motor sirve a CLI, API y CI |
| [Catálogo como datos](docs/adr/0003-catalogo-como-datos.md) | las fechas regulatorias cambian; el código no debería |
| [CBOM CycloneDX](docs/adr/0004-cbom-cyclonedx.md) | integrarse con lo que las organizaciones ya usan |
| [Seguridad del escáner](docs/adr/0005-seguridad-del-escaner.md) | correrlo sobre código ajeno sin riesgo |

El núcleo usa solo la biblioteca estándar de Go. El escáner nunca ejecuta lo que analiza y nunca copia material de claves a los informes; las claves de los tests se generan en cada ejecución.

```bash
make test    # tests con detector de condiciones de carrera
make lint    # gofmt + go vet
make build   # bin/cryptoinv
make cbom    # CBOM de este repositorio
```

## Hoja de ruta

- [x] Núcleo: dominio, catálogo NIST, evaluación de riesgo con Mosca
- [x] Escáner con 9 detectores · exportación CBOM, SARIF, JSON y texto · CLI
- [ ] API REST con contrato OpenAPI y persistencia (SQLite) para historial y comparación de escaneos
- [ ] Panel web (React + TypeScript): preparación por sistema, inventario, certificados, plan de migración · demo en GitHub Pages
- [ ] Plan de migración priorizado e informe ejecutivo

## Fuentes

- NIST IR 8547 (octubre de 2026), *Transition to Post-Quantum Cryptography Standards*
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- NIST SP 800-131A Rev. 2 · NSA CNSA 2.0
- RFC 8996 (TLS 1.0/1.1 obsoletos) · RFC 7465 (RC4 prohibido en TLS)
- CycloneDX 1.6 (CBOM) · OASIS SARIF 2.1.0

## Licencia

MIT
