# Threat model — V1

## Activos

- datos de pago aceptados;
- identidad pseudonimizada del sujeto;
- evidencia de ejecuciones;
- clave HMAC;
- registros de cuarentena.

## Controles implementados

| Amenaza | Control V1 |
| --- | --- |
| PII expuesta en tablas | correo sustituido por HMAC-SHA256 |
| Duplicación por reintento | clave primaria por event_id |
| Registro inválido descartado | cuarentena con motivo y fingerprint |
| Fuente intercambiada | SHA-256 del archivo en cada ejecución |
| Deriva silenciosa de esquema | cabecera contractual fail-closed |
| Ingesta parcialmente aplicada | transacción por ejecución |
| Secreto en repositorio | clave suministrada externamente |

## Riesgos residuales

- SQLite no cifra el archivo en reposo;
- una clave débil permite ataques de diccionario;
- un administrador del host puede alterar la base;
- el ledger aún no usa encadenamiento criptográfico;
- no existe control de acceso por rol en V1.
