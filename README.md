# Regulated Data Ops Platform

Plataforma evolutiva para operar datos de alto riesgo con contratos, evidencia
y controles verificables. V2 convierte la ingesta segura de V1 en un sistema
que declara, mide y comunica su nivel de confianza operacional.

## V2 — Confianza operativa

| Control | Resultado verificable |
| --- | --- |
| Política versionada | reglas y SLO en `config/trust-policy.json`, con SHA-256 |
| Compatibilidad | los CSV V1 siguen funcionando sin modificación |
| Evolución de esquema | `source_system` es opcional y usa `legacy` por defecto |
| Calidad por ejecución | tasas de validez y cuarentena, duración y breaches |
| Señal para automatización | `trust-report --fail-on-breach` devuelve código 2 |
| Migración | una base V1 recibe columnas V2 sin perder pagos existentes |

Las reglas configurables limitan monedas, bases legales, importe máximo y
sistemas productores. Un cambio inválido en la política falla antes de iniciar
la ingesta.

## Probar

    python -m unittest discover -s tests -v
    export REGULATED_DATA_HMAC_KEY="demo-key-with-at-least-32-characters"
    PYTHONPATH=src python -m regulated_data_ops.cli policy-check config/trust-policy.json
    PYTHONPATH=src python -m regulated_data_ops.cli --database demo-v2.db ingest examples/payments-clean-v2.csv --policy config/trust-policy.json
    PYTHONPATH=src python -m regulated_data_ops.cli --database demo-v2.db trust-report --fail-on-breach
    PYTHONPATH=src python -m regulated_data_ops.cli --database demo-v2.db schema-status

La demo limpia produce dos pagos válidos, esquema `native` y confianza
`passing`. La clave de demostración no debe utilizarse en producción.

## Compatibilidad con V1

`examples/payments.csv` no incluye `source_system`. V2 lo acepta en modo
`backward-compatible`, asigna `legacy` y conserva el fingerprint contractual
histórico de V1. Campos desconocidos siguen fallando de forma cerrada.

## Qué demuestra

| Perfil | Evidencia |
| --- | --- |
| Data Engineer | contratos compatibles, migración, métricas e idempotencia |
| High-Risk Data | SLO explícitos, cuarentena observable y alertas |
| Regulated Environments | política y decisión reconstruibles por ejecución |
| Cybersecurity | PII pseudonimizada y configuración fail-closed |
| Senior Engineering | evolución sin romper consumidores anteriores |

V2 continúa siendo una demostración local con datos sintéticos. FastAPI,
autenticación y dashboard pertenecen a V3. El arco completo está en
`docs/ROADMAP.md`; la procedencia abierta está en `PROVENANCE.yaml`.
