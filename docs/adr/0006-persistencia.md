# ADR 0006 — Persistencia detrás de un puerto, con archivos como primer adaptador

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
El panel necesita historial: comparar escaneos, ver la evolución de cada sistema. El plan inicial era SQLite.

## Decisión
- Los casos de uso dependen de la interfaz `app.ScanRepository` (`Save`, `Get`, `List`, `Delete`), no de una base concreta.
- El primer adaptador es `store.FileStore`: un JSON por escaneo, escrito de forma atómica (archivo temporal + `rename`), con un índice en memoria que se reconstruye al abrir. IDs validados para que no se puedan usar como rutas.
- Se descartó SQLite por ahora para mantener el binario sin dependencias externas ni cgo: se compila igual en Linux, Windows y macOS, y la carpeta de datos se respalda copiándola.

## Consecuencias
- Alcanza para miles de escaneos en un equipo o un servidor chico.
- Para varias instancias o consultas entre muchos sistemas, un adaptador de Postgres implementa la misma interfaz sin tocar dominio, casos de uso ni API.
- Los tests de casos de uso usan un repositorio en memoria.
