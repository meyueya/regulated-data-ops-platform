# Security

## Data policy

Este repositorio usa únicamente datos sintéticos. No deben incorporarse
credenciales, datos de clientes, historiales financieros ni identificadores
reales.

## Claves

`REGULATED_DATA_HMAC_KEY` y `REGULATED_DATA_ENCRYPTION_KEY` deben suministrarse
mediante variables de entorno o un gestor de secretos y ser diferentes por
entorno y propósito. La clave HMAC se rota mediante una migración explícita de
tokens. La clave AES-GCM debe ser una codificación base64 URL-safe de 32 bytes
aleatorios y su rotación exige re-encriptar los campos protegidos.

Las API keys de cada actor se generan fuera del repositorio; la política sólo
almacena sus digests SHA-256. Las claves sintéticas documentadas son públicas y
no son válidas para producción. Ningún secreto debe viajar en URL, archivos
versionados o argumentos de proceso.

La base no almacena correos originales. V4 cifra campos sensibles seleccionados,
no el archivo SQLite completo. V4 escucha en loopback salvo consentimiento
explícito; una exposición real requiere TLS, rate limiting, gestión de secretos,
cifrado de volumen y autenticación gestionada delante de la aplicación.
