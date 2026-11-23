# ADR 0007 — Panel React por funcionalidades, con contrato generado y fuente de datos intercambiable

**Estado:** aceptada · **Fecha:** 2026-11

## Decisión
- **Contrato primero.** `api/openapi.yaml` es la fuente única. Los tipos de TypeScript se generan (`npm run gen:api`) y el CI falla si el contrato y los tipos no coinciden.
- **Por funcionalidad**, no por tipo de archivo: `features/overview`, `inventory`, `plan`, `certificates`, `scans`, `catalog`. Lo compartido vive en `shared/api` (datos), `shared/ui` (componentes) y `shared/lib` (lógica pura).
- **Fuente de datos intercambiable.** La interfaz `DataSource` tiene dos implementaciones: `httpSource` (API real) y `demoSource` (JSON estáticos generados con `cryptoinv snapshot`). Se elige al compilar; las pantallas no saben cuál usan. Así la demo de GitHub Pages es el mismo panel, con datos reales de proyectos públicos.
- **Estado del servidor con TanStack Query** (caché, reintentos, invalidación después de escanear). **Filtros en la URL**: un inventario filtrado se puede compartir o recargar.
- **Sin dependencias de UI:** componentes, gráficos (SVG) e íconos propios. Menos superficie de cadena de suministro y un panel de 77 KB comprimido.
- **Embebido en el binario** con `go:embed`. `cryptoinv serve` sirve API y panel desde el mismo origen, con CSP estricta (`default-src 'self'`), sin CORS, con defensa contra CSRF (`X-Requested-With`) y contra DNS rebinding (validación de `Host` cuando escucha en localhost).
- `HashRouter`: funciona igual embebido y en GitHub Pages, que no reescribe rutas.

## Consecuencias
- El backend compila sin Node: si el panel no está compilado, sirve una página que explica cómo hacerlo.
- La lógica de filtros existe en Go y en TypeScript (para la demo); un test en cada lado verifica el mismo comportamiento.
