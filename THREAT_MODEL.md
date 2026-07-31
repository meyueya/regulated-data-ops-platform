# Threat model — V2

## Activos

- datos de pago aceptados e identidad pseudonimizada;
- evidencia de ejecuciones, calidad y lineage;
- clave HMAC;
- política de confianza y su fingerprint;
- compatibilidad entre contratos V1 y V2.

## Controles acumulados

| Amenaza | Control |
| --- | --- |
| PII expuesta en tablas | correo sustituido por HMAC-SHA256 |
| Duplicación por reintento | clave primaria e idempotencia conflictiva |
| Registro inválido descartado | cuarentena minimizada con motivo |
| Fuente o política intercambiada | SHA-256 de ambos artefactos por ejecución |
| Deriva silenciosa de esquema | compatibilidad explícita y fail-closed |
| Cambio que rompe V1 | fingerprint histórico y pruebas de regresión |
| Calidad degradada sin señal | SLO, breaches persistidos y código de salida 2 |
| Migración destructiva | `ALTER TABLE` aditivo con prueba de conservación |
| Secreto en repositorio | clave suministrada externamente |

## Límites y riesgos residuales

- SQLite no cifra el archivo en reposo;
- un administrador del host puede alterar la base o la política;
- el ledger aún no usa encadenamiento criptográfico;
- el SLO de duración es local y no representa una plataforma distribuida;
- no existe control de acceso por rol; se incorpora en V4;
- las alertas se exponen como señal de proceso, no se envían a terceros.
