# ADR 0003 — El catálogo de algoritmos es un dato versionado, no código

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
Las fechas y recomendaciones cambian (NIST IR 8547, SP 800-131A, CNSA 2.0). Si están repartidas en el código, actualizarlas es riesgoso y difícil de revisar.

## Decisión
`backend/internal/catalog/data.json` tiene cada algoritmo con su primitiva, estado cuántico, año de desaprobación y prohibición, tamaño mínimo de clave, reemplazo, nota en lenguaje claro y alias. Se embebe en el binario con `go:embed`, se valida al cargar (campos obligatorios, IDs únicos) y lleva versión y fuentes.

## Consecuencias
- Una actualización regulatoria es un cambio de datos revisable en un diff.
- La versión del catálogo viaja en cada informe y CBOM: se sabe con qué criterio se evaluó.
- Los detectores informan nombres tal como aparecen; la resolución por alias vive en un solo lugar.
