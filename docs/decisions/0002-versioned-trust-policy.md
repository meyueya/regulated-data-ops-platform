# ADR-0002: política versionada y evolución compatible

## Decisión

V2 separa los parámetros operativos en JSON, genera el contrato activo desde
esa política y evalúa SLO al finalizar cada ejecución. El nuevo campo
`source_system` es opcional y usa `legacy` cuando recibe un CSV V1.

## Motivos

- las reglas cambian mediante revisión sin editar el motor de validación;
- el fingerprint vincula cada decisión con una política concreta;
- la compatibilidad se prueba como comportamiento, no como promesa;
- la migración aditiva permite abrir bases V1 sin perder filas;
- Python estándar mantiene una demo reproducible y sin dependencias de red.

## Alternativas rechazadas

- aceptar cualquier columna nueva: ocultaría deriva y posibles datos sensibles;
- exigir `source_system` inmediatamente: rompería productores V1;
- tratar todo breach como rollback: mezclaría calidad con atomicidad;
- usar YAML con una dependencia externa: no aporta valor en esta etapa local.
