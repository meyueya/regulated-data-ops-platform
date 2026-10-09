# Regulated Data Ops Platform

Plataforma evolutiva para operar datos sintéticos de alto riesgo con contratos,
evidencia y controles verificables. V4 convierte la superficie operativa de V3
en una frontera regulada con identidad individual, RBAC, cifrado autenticado,
auditoría encadenada y retención controlada por política.

## V4 — Gobierno verificable

| Control | Evidencia ejecutable |
| --- | --- |
| Identidad | cada clave resuelve un `actor_id` individual; sólo se persiste SHA-256 |
| RBAC | `viewer`, `operator`, `auditor` y `admin` tienen permisos explícitos |
| Policy-as-code | roles, usuarios y retención viven en un JSON versionado y fingerprinted |
| Cifrado | AES-256-GCM protege rutas, errores y detalle de auditoría con AAD |
| Auditoría | actor, rol, acción, recurso, resultado y request ID quedan encadenados por hash |
| Inmutabilidad | triggers SQLite impiden `UPDATE` y `DELETE` del ledger de auditoría |
| Retención | preview por clase; ejecutar exige rol `admin` y fingerprint exacto |
| Compatibilidad | conserva contratos, idempotencia, SLO, API y migración V1–V3 |

El cifrado es de campos sensibles seleccionados, no cifrado integral del archivo
SQLite. Una implantación real puede añadir volumen cifrado o SQLCipher sin
cambiar el contrato de la aplicación.

## Probar V4

    python -m pip install -e ".[test]"
    python -m unittest discover -s tests -v
    regulated-data-ops governance-check config/governance-policy.json

    export REGULATED_DATA_HMAC_KEY="demo-hmac-key-with-at-least-32-characters"
    export REGULATED_DATA_ENCRYPTION_KEY="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

    regulated-data-ops --database demo-v4.db serve \
      --ingestion-root examples \
      --policy config/trust-policy.json \
      --governance config/governance-policy.json

Abre `http://127.0.0.1:8000`. Las claves locales de demostración son:

| Rol | Clave sintética |
| --- | --- |
| Viewer | `demo-viewer-key-00000000000000000001` |
| Operator | `demo-operator-key-000000000000000001` |
| Auditor | `demo-auditor-key-0000000000000000001` |
| Admin | `demo-admin-key-000000000000000000001` |

Son credenciales públicas y deliberadamente sintéticas; nunca deben reutilizarse.
Para generar una clave de cifrado nueva:

    python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; import base64; print(base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode())"

## Matriz de permisos

| Capacidad | Viewer | Operator | Auditor | Admin |
| --- | ---: | ---: | ---: | ---: |
| Estado y SLO | ✓ | ✓ | ✓ | ✓ |
| Fuentes e ingesta | — | ✓ | — | ✓ |
| Lineage | — | ✓ | ✓ | ✓ |
| Política y gobierno | — | — | ✓ | ✓ |
| Auditoría | — | — | ✓ | ✓ |
| Preview de retención | — | — | ✓ | ✓ |
| Ejecutar retención | — | — | — | ✓ |

## API acumulada

| Método | Ruta | Permiso |
| --- | --- | --- |
| `GET` | `/health` | pública, sin datos operativos |
| `GET` | `/api/v1/me` | `status:read` |
| `GET` | `/api/v1/status` | `status:read` |
| `GET` | `/api/v1/trust-report` | `trust:read` |
| `GET` | `/api/v1/sources` | `sources:read` |
| `GET` | `/api/v1/policy` | `policy:read` |
| `GET` | `/api/v1/governance` | `governance:read` |
| `GET` | `/api/v1/lineage/{event_id}` | `lineage:read` |
| `GET` | `/api/v1/audit-events` | `audit:read` |
| `GET` | `/api/v1/audit-integrity` | `audit:read` |
| `GET` | `/api/v1/retention-preview` | `retention:preview` |
| `POST` | `/api/v1/ingestions` | `ingestion:create` |
| `POST` | `/api/v1/retention-executions` | `retention:execute` |

## Compatibilidad acumulada

V1 aporta contrato, idempotencia, cuarentena y lineage. V2 añade reglas,
evolución compatible y SLO. V3 incorpora API y dashboard. V4 añade gobierno sin
cambiar los fingerprints históricos ni permitir PII directa en las respuestas.

## Qué demuestra

| Perfil | Evidencia |
| --- | --- |
| Data Engineer | contratos compatibles, métricas, lineage e idempotencia |
| Full Stack | API y dashboard adaptados a capacidades por rol |
| High-Risk Data | minimización, retención explícita y borrado trazable |
| Cybersecurity | RBAC, AES-GCM, secretos externos y auditoría inmutable |
| Regulated Environments | policy-as-code, segregación de funciones y evidencia reconstruible |
| Senior Engineering | evolución V1→V4 con migraciones, ADR y 66 pruebas acumuladas |

El modelo de seguridad está en `THREAT_MODEL.md`; la política de gobierno, en
`docs/governance/GOVERNANCE_POLICY.md`; y el arco, en `docs/ROADMAP.md`.
