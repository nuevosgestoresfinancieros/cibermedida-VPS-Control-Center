# Fase 1 - Inventario

## Objetivo

Descubrir el estado real del VPS en modo exclusivamente lectura y producir un inventario estructurado, minimizado y redactado.

## Restricción Principal

Fase 1 no debe modificar el VPS. No debe reiniciar servicios, cambiar configuraciones, instalar paquetes, consultar bases de datos de aplicación, leer secretos ni escribir datos operativos fuera de las ubicaciones aprobadas del proyecto.

## Áreas A Descubrir

- Ubuntu y sistema operativo estructurado.
- CPU.
- RAM y swap.
- Almacenamiento.
- Usuarios, solo si existe autorización y modelo de minimización.
- Servicios.
- systemd.
- Apache.
- PM2.
- Docker.
- Certificados, solo metadatos públicos.
- Proyectos.
- Repositorios Git.
- Bases de datos, sin credenciales ni consultas lógicas sensibles.
- Backups, solo catálogo/metadatos aprobados.
- Dominios.
- Puertos.
- Firewall, solo resumen aprobado.
- Runtimes.
- Dependencias operativas.
- Relaciones entre proyecto, servicio, puerto, dominio, certificado y base de datos.

## Flujo Seguro

La ejecución futura debe seguir este flujo:

```text
READ_SAFE
    ↓
normalización
    ↓
redacción
    ↓
schema validation
    ↓
secret scan
    ↓
revisión humana
```

`READ_SENSITIVE` y `READ_PRIVILEGED` no podrán ejecutarse automáticamente después de `READ_SAFE`. Requieren autorización humana explícita e independiente para cada bloque o comando lógico.

## Resultado Previsto

El resultado previsto por la especificación es:

```text
INVENTORY.json
```

`INVENTORY.json` no debe versionarse. En Fase 0 y preparación de Fase 1 solo se define su contrato en `schemas/inventory.schema.json` y su política de recolección en `policies/command-allowlist.md`.

## Reglas Para La Futura Ejecución

- Leer solo metadatos necesarios.
- No leer secretos ni contenidos sensibles.
- No inventar datos desconocidos.
- No almacenar outputs crudos de comandos.
- No almacenar logs crudos.
- No almacenar variables de entorno.
- No almacenar claves privadas, passwords, tokens, cookies, API keys ni credenciales de bases de datos.
- No leer backups, dumps ni archivos de usuario.
- Marcar datos no descubiertos con `collection_status` adecuado.
- Registrar `permission_denied` cuando el dato no pueda obtenerse por permisos.
- Registrar `not_collected` cuando el dato quede fuera del alcance autorizado.
- Registrar `excluded_for_security` cuando el dato exista potencialmente pero no deba recogerse.
- Registrar `not_available` cuando la tecnología o recurso no exista en el VPS.
- Registrar `unknown` cuando no pueda determinarse el estado sin ampliar alcance.
- Registrar `sensitivity_level` para cada entidad o dato persistido.
- Registrar `source_refs` con identificadores lógicos de comandos, nunca con salidas crudas.
- Separar observación, diagnóstico y ejecución.

## Estados De Recolección

- `collected`: dato obtenido y redactado si era necesario.
- `unknown`: no se pudo determinar con el alcance actual.
- `not_available`: componente o dato no presente.
- `permission_denied`: el sistema negó acceso sin elevar privilegios.
- `not_collected`: dato omitido porque no estaba autorizado en esta pasada.
- `excluded_for_security`: dato omitido deliberadamente por riesgo de secreto o información sensible.

## Niveles De Sensibilidad

- `public`: dato no sensible.
- `internal`: dato operativo interno.
- `sensitive`: dato que requiere minimización o redacción.
- `secret_excluded`: dato que no debe persistirse.

## Redacción

La redacción debe ejecutarse antes de persistir `INVENTORY.json`. Como mínimo debe cubrir:

- credenciales en URLs;
- tokens, API keys y passwords;
- claves privadas o bloques PEM;
- variables de entorno;
- IPs o redes cuando no sean necesarias completas;
- rutas privadas innecesarias;
- dominios o nombres internos cuando la política lo indique.

## Validación

La validación mínima futura debe incluir:

```text
git diff --check
jq empty schemas/inventory.schema.json
schema validation de INVENTORY.json contra schemas/inventory.schema.json
secret scan de INVENTORY.json
revisión humana
```

No deben instalarse dependencias durante Fase 1 sin autorización explícita.

## Fuentes

El inventario debe registrar fuentes como identificadores lógicos de comandos definidos en `policies/command-allowlist.md`, por ejemplo `disk_usage`, `memory_usage` o `docker_ps`.

No debe registrar:

- comando shell arbitrario completo cuando incluya datos sensibles;
- stdout/stderr crudo;
- fragmentos de logs;
- fragmentos de configuración con secretos.

## Exclusiones De Seguridad

Quedan fuera del inventario por defecto:

- `.env` y ficheros equivalentes;
- variables de entorno de procesos;
- claves privadas;
- `/etc/shadow` y `/etc/gshadow`;
- historiales shell;
- logs crudos;
- backups y dumps;
- `authorized_keys`;
- argumentos completos de procesos;
- consultas lógicas a bases de datos de aplicación;
- volcados completos de firewall;
- `machine-id` sin redacción irreversible.
