# ADR 0001 — Monorepo con backend, frontend y contrato

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
El sistema tiene un motor de escaneo y API en Go, un panel web en React y un contrato OpenAPI entre los dos. Separarlos en repositorios obliga a versionar y sincronizar el contrato a mano, y un cambio que toca las tres partes se reparte en varios pull requests.

## Decisión
Un solo repositorio:

```
backend/   Go: motor, detectores, casos de uso, API, CLI
web/       React + TypeScript: panel (etapa 4)
api/       openapi.yaml, fuente única del contrato (etapa 3)
docs/      decisiones de arquitectura y documentación
```

Cada parte tiene su propio módulo, herramientas y job de CI. El frontend se publica en GitHub Pages desde `web/dist` con Actions, en modo demostración con datos estáticos.

## Consecuencias
- Un cambio de contrato, backend y frontend entra en un solo pull request y se prueba junto.
- El binario de Go puede embeber el panel compilado: una sola descarga para usar todo.
- El CI tiene que filtrar por carpeta para no correr todo en cada cambio.
