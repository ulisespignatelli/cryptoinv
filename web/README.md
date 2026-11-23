# Panel web de cryptoinv

React + TypeScript + Vite. Arquitectura y decisiones: [ADR 0007](../docs/adr/0007-frontend.md).

```bash
npm ci
npm run dev        # http://localhost:5173, usa la API de `cryptoinv serve` en :8080
npm run build      # compila dentro del backend para embeberlo en el binario
npm run build:demo # demo estática (GitHub Pages) en dist/
npm test           # Vitest
npm run gen:api    # regenera los tipos desde ../api/openapi.yaml
```

```
src/
  app/          rutas, layout, estilos
  features/     una carpeta por pantalla
  shared/api/   contrato generado, fuentes de datos (API y demo), hooks de TanStack Query
  shared/ui/    componentes y gráficos propios
  shared/lib/   lógica pura (filtros, formatos, etiquetas)
demo-public/    datos de la demo: escaneos reales de proyectos públicos (`cryptoinv snapshot`)
```
