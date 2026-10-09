# Regulated Data Ops Platform

Plataforma evolutiva para operar datos de alto riesgo con contratos, evidencia
y controles verificables. V3 convierte el motor de confianza de V2 en un
plano operativo autenticado: API FastAPI, dashboard responsive e ingestas
controladas desde una única superficie.

## V3 — Operación autenticada

| Capacidad | Comportamiento operativo |
| --- | --- |
| Autenticación | todos los endpoints de datos requieren `X-API-Key` |
| Dashboard | estado, SLO, ejecuciones, política, ingesta y lineage |
| Ingesta segura | sólo nombres CSV publicados dentro del directorio permitido |
| Minimización | la API omite rutas absolutas y `subject_token` |
| Endurecimiento web | CSP, anti-frame, no-sniff, no-referrer y `no-store` |
| Despliegue seguro | loopback por defecto; red externa exige consentimiento explícito |
| Compatibilidad | conserva contratos, CLI, migración y 33 pruebas de V1/V2 |

La clave de API se compara en tiempo constante y el frontend la conserva sólo
en `sessionStorage`. OpenAPI está desactivado por defecto. La fuente y la
política son configuración del servidor, no rutas controladas por el cliente.

## Probar V3

    python -m pip install -e ".[test]"
    python -m unittest discover -s tests -v
    export REGULATED_DATA_API_KEY="demo-api-key-with-at-least-32-characters"
    export REGULATED_DATA_HMAC_KEY="demo-hmac-key-with-at-least-32-characters"
    regulated-data-ops --database demo-v3.db serve \
      --ingestion-root examples \
      --policy config/trust-policy.json

Abre `http://127.0.0.1:8000`, introduce la clave de API y ejecuta
`payments-clean-v2.csv`. El resultado esperado es `passing`, dos filas
aceptadas y esquema `native`.

Las claves de demostración no deben utilizarse en producción. Para enlazar a
otra interfaz es obligatorio añadir `--allow-network`; esa opción no sustituye
TLS, un gateway, rate limiting ni gestión de secretos.

## API

| Método | Ruta | Uso |
| --- | --- | --- |
| `GET` | `/health` | liveness pública, sin datos operativos |
| `GET` | `/api/v1/status` | última ejecución y versión de esquema |
| `GET` | `/api/v1/trust-report` | ventana de SLO y ejecuciones sanitizadas |
| `GET` | `/api/v1/sources` | CSV sintéticos permitidos |
| `GET` | `/api/v1/policy` | política activa y fingerprint |
| `GET` | `/api/v1/lineage/{event_id}` | trazabilidad de un evento aceptado |
| `POST` | `/api/v1/ingestions` | ejecutar una fuente permitida |

Ejemplo directo:

    curl -H "X-API-Key: $REGULATED_DATA_API_KEY" \
      http://127.0.0.1:8000/api/v1/status

## Compatibilidad acumulada

V1 aporta contrato, idempotencia, cuarentena, pseudonimización y lineage. V2
añade política versionada, evolución compatible de esquema y SLO. V3 sólo
añade una superficie operativa; no cambia los fingerprints históricos ni
expone PII directa.

## Qué demuestra

| Perfil | Evidencia |
| --- | --- |
| Data Engineer | contratos compatibles, métricas, lineage e idempotencia |
| Full Stack | API autenticada y dashboard sin runtime frontend externo |
| High-Risk Data | selección de fuentes server-side y respuestas minimizadas |
| Cybersecurity | fail-closed, headers defensivos y límites de red explícitos |
| Senior Engineering | evolución V1→V3 con regresión y ADR por decisión |

El modelo de seguridad está en `THREAT_MODEL.md`, los controles de la API en
`docs/governance/API_SECURITY.md` y el arco completo en `docs/ROADMAP.md`.
