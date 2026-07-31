# Changelog

## 3.0.0 — V3: Operación autenticada

- API FastAPI protegida con `X-API-Key` y comparación en tiempo constante;
- dashboard responsive de confianza, ejecuciones, ingesta, política y lineage;
- allowlist server-side de fuentes CSV sin rutas arbitrarias;
- respuestas sanitizadas sin rutas absolutas ni tokens de sujeto;
- CSP y headers defensivos, caché desactivada en la API y request IDs;
- bind local por defecto y consentimiento explícito para exposición en red;
- dependencias directas fijadas y assets empaquetados sin CDN;
- 49 pruebas acumuladas, incluidas 16 de operación y seguridad web.

## 2.0.0 — V2: Confianza operativa

- política JSON versionada y fingerprinted;
- reglas configurables para moneda, importe, base legal y productor;
- contrato V2 compatible con cabeceras V1;
- evaluación por ejecución de validez, cuarentena y duración;
- informe de confianza y señal de salida para automatización;
- migración automática y no destructiva de SQLite V1;
- 33 pruebas de regresión, evolución y operación.

## 1.0.0 — V1: Ingesta bajo contrato

- contrato versionado para eventos de pago sintéticos;
- normalización y validación determinista;
- pseudonimización HMAC-SHA256;
- ingesta SQLite idempotente;
- cuarentena sin PII en claro;
- ledger de ejecuciones y lineage por fila;
- CLI, documentación de seguridad y pruebas automatizadas.
