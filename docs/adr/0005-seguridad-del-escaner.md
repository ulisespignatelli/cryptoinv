# ADR 0005 — El escáner nunca ejecuta lo que analiza ni muestra material de claves

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
La herramienta se corre sobre repositorios ajenos y su salida se comparte (informes, CI, paneles).

## Decisión
- Solo lectura: no ejecuta, compila ni importa el código analizado; no sigue enlaces simbólicos; saltea binarios y archivos de más de 2 MiB.
- La evidencia de claves y certificados es solo metadato: tipo, tamaño, curva, sujeto, emisor y fechas. Nunca el contenido de la clave. De las claves SSH no se muestra el comentario (suele tener un correo).
- Las claves de prueba se generan en cada ejecución de los tests: el repositorio no guarda claves privadas.
- Un uso se puede descartar con `cryptoinv:ignore` en la misma línea, y el motivo queda escrito en el código.

## Consecuencias
- Es seguro correrlo en CI sobre pull requests de terceros.
- Un informe filtrado no expone secretos.
