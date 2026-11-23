# ADR 0004 — CycloneDX 1.6 CBOM como formato de intercambio

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
Las organizaciones ya tienen plataformas para SBOM y hallazgos. Un formato propio obligaría a integrar a mano.

## Decisión
- **CBOM CycloneDX 1.6** (`cryptographic-asset`, con `algorithm`, `certificate` y `protocol`) para el inventario. Un componente por algoritmo y parámetros (por ejemplo, RSA 2048) con todas sus ocurrencias como evidencia. El puntaje, el estado cuántico y el reemplazo van como propiedades `cryptoinv:*`.
- **SARIF 2.1.0** para hallazgos accionables (GitHub code scanning). Lo resistente no se reporta.
- **JSON propio** (`cryptoinv/scan/v1`) para la API y el panel.

Se eligió 1.6 y no 1.7 porque es la versión con más soporte en las herramientas actuales. Ambos formatos se validan contra sus esquemas oficiales.

## Consecuencias
- El inventario entra en Dependency-Track u otras plataformas sin código extra.
- Los IDs estables (`partialFingerprints`) evitan duplicados entre escaneos.
