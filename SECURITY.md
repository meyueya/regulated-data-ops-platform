# Security

## Data policy

Este repositorio usa únicamente datos sintéticos. No deben incorporarse
credenciales, datos de clientes, historiales financieros ni identificadores
reales.

## Claves

REGULATED_DATA_HMAC_KEY debe suministrarse mediante variable de entorno o
gestor de secretos, tener al menos 32 caracteres en la demostración, ser
diferente por entorno y rotarse mediante una migración explícita de tokens.

La base de datos no almacena la clave ni el correo original.
