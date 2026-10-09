# Security

## Data policy

Este repositorio usa únicamente datos sintéticos. No deben incorporarse
credenciales, datos de clientes, historiales financieros ni identificadores
reales.

## Claves

`REGULATED_DATA_HMAC_KEY` y `REGULATED_DATA_API_KEY` deben suministrarse
mediante variables de entorno o un gestor de secretos, tener al menos 32
caracteres en la demostración y ser diferentes por entorno y propósito. La
clave HMAC se rota mediante una migración explícita de tokens; la clave de API
se revoca en el gateway o gestor de secretos.

La base de datos no almacena claves ni el correo original. No se deben pasar
claves en URL, archivos versionados ni argumentos de proceso. V3 escucha sólo
en loopback salvo consentimiento explícito; una exposición real requiere TLS,
rate limiting y autenticación gestionada delante de la aplicación.
