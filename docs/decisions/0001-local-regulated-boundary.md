# ADR-0001: comenzar por la frontera regulada local

## Decisión

V1 utiliza Python estándar y SQLite para demostrar semántica operacional antes
de añadir Airflow, Spark, nube o una interfaz web.

## Motivos

- contratos y fallos auditables sin infraestructura;
- reintentos baratos y deterministas;
- menor superficie de secretos y ataque;
- migración posterior sin cambiar el contrato de entrada.

## Alternativas rechazadas

- Copiar todo el stack upstream: ocultaría la contribución propia.
- Empezar con Spark: añadiría escala sin probar la semántica.
- Guardar filas inválidas completas: conservaría PII innecesaria.
- Usar MD5 como pseudónimo: no incorpora un secreto.
