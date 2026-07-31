# Política de confianza V2

`config/trust-policy.json` es un artefacto operativo versionado. Su fingerprint
se guarda en cada ejecución para reconstruir qué reglas y SLO estaban activos.

## Reglas

- `allowed_currencies`: monedas aceptadas;
- `allowed_lawful_bases`: bases de tratamiento permitidas;
- `maximum_amount`: techo decimal antes de normalizar a unidades menores;
- `allowed_source_systems`: productores declarados del evento.

## SLO

| Métrica | Definición | Umbral predeterminado |
| --- | --- | --- |
| valid rate | `(aceptados + duplicados) / total` | mínimo 0,95 |
| quarantine rate | `cuarentena / total` | máximo 0,05 |
| run duration | tiempo monotónico de la ejecución | máximo 5.000 ms |
| batch size | filas observadas | mínimo 1 |

Una ejecución puede completar la carga y quedar `breached`: el ledger conserva
ambos hechos. `trust-report --fail-on-breach` devuelve 2 para que un scheduler
o monitor active una alerta sin confundir la degradación con un error del CLI.
Los estados `no_data` e `insufficient_evidence` también producen código 2: la
ausencia de evidencia nunca se presenta como cumplimiento.

## Gestión del cambio

Todo cambio requiere revisión de código, incremento de `policy_version`,
pruebas de éxito y rechazo y actualización de la evidencia. Las ampliaciones
de esquema deben ser opcionales o introducir una nueva versión mayor; los
campos desconocidos nunca se aceptan silenciosamente.
