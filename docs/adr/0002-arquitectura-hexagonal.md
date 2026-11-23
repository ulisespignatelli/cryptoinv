# ADR 0002 — Arquitectura hexagonal en el backend

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
El mismo motor se usa desde la CLI, desde la API y desde CI. La persistencia, los formatos de salida y los detectores van a crecer de forma independiente.

## Decisión
Dependencias hacia adentro, nunca hacia afuera:

```
domain     modelo puro (Usage, Finding, Assessment, Scan). No importa nada del proyecto.
catalog    datos de algoritmos y fechas NIST, embebidos y versionados.
risk       evaluación: función pura (uso + algoritmo + política → puntaje explicado).
scan       recorrido de archivos y detectores (solo lectura).
app        casos de uso: orquesta lo anterior. Lo usan la CLI y la API.
adapters   bordes: exportadores (texto, JSON, SARIF, CBOM); luego HTTP y SQLite.
cmd        raíz de composición: el único lugar que conecta todo.
```

## Consecuencias
- El riesgo se prueba sin archivos ni base de datos; los detectores, sin catálogo.
- Sumar un formato de salida o una base de datos no toca el dominio.
- El núcleo usa solo la biblioteca estándar de Go: menos superficie de cadena de suministro en una herramienta de seguridad.
