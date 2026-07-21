# Regulated Data Ops Platform

Plataforma evolutiva para operar datos de alto riesgo con contratos, evidencia
y controles verificables. V1 implementa una frontera de ingesta local para
eventos de pago completamente sintéticos.

## V1 — Ingesta bajo contrato

El pipeline:

1. identifica el archivo mediante SHA-256;
2. registra una ejecución auditable;
3. valida cada fila contra un contrato versionado;
4. pseudonimiza el correo con HMAC-SHA256;
5. convierte importes decimales a unidades menores;
6. carga eventos válidos de forma idempotente;
7. envía registros inválidos a cuarentena sin conservar PII en claro;
8. conserva lineage entre archivo, ejecución, fila y resultado.

## Ejecutar

    python -m unittest discover -s tests -v
    export REGULATED_DATA_HMAC_KEY="demo-key-with-at-least-16-characters"
    PYTHONPATH=src python -m regulated_data_ops.cli --database demo.db ingest examples/payments.csv
    PYTHONPATH=src python -m regulated_data_ops.cli --database demo.db status

La clave de demostración no debe utilizarse en producción.

## Resultado esperado del ejemplo

- dos pagos aceptados;
- un registro en cuarentena por importe inválido;
- ninguna dirección de correo almacenada en SQLite;
- una segunda ingesta produce duplicados, no nuevas filas.

## Qué demuestra

| Perfil | Evidencia |
| --- | --- |
| Data Engineer | contrato, ingesta, normalización, idempotencia y lineage |
| High-Risk Data | PII pseudonimizada y cuarentena minimizada |
| Regulated Environments | ejecución, fuente y decisión reconstruibles |
| Cybersecurity | clave externa, HMAC y modelo de amenazas |
| Senior Engineering | transacciones, fallos cerrados y ADR |

El arco completo V1–V5 está en docs/ROADMAP.md. La fuente abierta y su
transformación están documentadas en PROVENANCE.yaml.
