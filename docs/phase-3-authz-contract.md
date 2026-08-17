# Fase 3.4 - Contrato Futuro De Autenticacion Y Autorizacion Web

## Estado Y Objetivo

Este documento define un contrato conceptual para una futura capa de
autenticacion y autorizacion del Web Control Center. No implementa identidad,
sesiones, usuarios, permisos activos ni conexion con el Core Operator.

El objetivo futuro es identificar de forma verificable a cada persona, limitar
lo que puede ver o solicitar segun su rol y conservar trazabilidad suficiente
para que ninguna accion eluda las politicas del sistema.

La UI actual permanece estatica, local, alimentada por datos mock y
exclusivamente read-only. La presencia de un rol o permiso en este documento no
concede ninguna capacidad actual.

## Principios Del Contrato

- Denegacion por defecto y privilegio minimo.
- Autenticacion no implica autorizacion.
- La UI nunca es la autoridad final para conceder acceso.
- Los controles ocultos o deshabilitados no sustituyen una validacion de
  servidor.
- Cada solicitud futura debe validar identidad, rol, permiso, contexto, riesgo
  y politica.
- Solicitar, aprobar y ejecutar son capacidades distintas.
- Toda operacion que requiera aprobacion debe tener solicitante y aprobador
  distintos. Solo puede existir una excepcion definida explicitamente por
  politica, registrada y auditada.
- Una aprobacion no ejecuta por si sola ninguna operacion.
- Los permisos se evaluan de nuevo en cada etapa de la cadena de control.
- Las decisiones relevantes deben producir auditoria metadata-only, sin
  exponer contenido sensible.

## Roles Previstos

### `ADMIN`

Administracion futura de identidades, asignaciones y politicas. Es el rol de
mayor alcance, pero no puede omitir PolicyEngine, Approval workflow,
ExecutionGate ni los bloqueos del ControlledExecutor.

### `OPERATOR`

Operacion controlada futura. Podra revisar estado, solicitar y, cuando exista
separacion de funciones, aprobar operaciones. Sus capacidades seguiran sujetas
a riesgo, politica y autorizacion por operacion.

### `DEVELOPER`

Acceso futuro a vistas tecnicas y solicitudes de bajo riesgo relacionadas con
diagnostico o desarrollo. No administra usuarios o politicas ni obtiene por
defecto autoridad de produccion.

### `VIEWER`

Consulta futura de superficies read-only expresamente autorizadas. No solicita,
aprueba ni ejecuta operaciones.

## Permisos Previstos

### Permisos De Visualizacion

- `VIEW_DASHBOARD`
- `VIEW_CORE_OPERATOR`
- `VIEW_POLICY`
- `VIEW_AUDIT_METADATA`
- `VIEW_INVENTORY_METADATA`

Estos permisos solo cubren datos minimizados y autorizados. No incluyen salidas
crudas, credenciales, copias de seguridad, consultas a bases de datos ni otros
datos sensibles.

### Permisos De Solicitud Y Aprobacion

- `REQUEST_APPROVAL`
- `APPROVE_OPERATION`

`APPROVE_OPERATION` debe exigir una decision humana explicita, identidad fuerte,
vigencia limitada, coincidencia exacta con el plan y separacion entre solicitante
y aprobador para toda operacion que requiera aprobacion. Una excepcion solo puede
aplicarse si una politica la define explicitamente y la decision queda registrada
y auditada.

### Permisos De Operacion Futura

- `RUN_READ_SAFE`
- `RUN_READ_SENSITIVE`
- `RUN_PRIVILEGED`
- `DEPLOY`
- `ROLLBACK`

Estos nombres describen autorizaciones futuras, no capacidades implementadas.
Ninguno esta activo en Fase 3.4. Tener un permiso no evita una decision
`approval_required` o `deny`, ni cambia el estado actual
`blocked_by_default` del ControlledExecutor.

### Permisos Administrativos

- `MANAGE_POLICIES`
- `MANAGE_USERS`

La asignacion de estos permisos debe auditarse y requerir controles reforzados.
No deben otorgar acceso directo al sistema operativo.

## Matriz Rol A Permisos

La siguiente matriz es una propuesta de maximos futuros. Cada marca significa
"puede ser evaluado para este permiso", no "puede ejecutar automaticamente".

| Permiso | VIEWER | DEVELOPER | OPERATOR | ADMIN |
| --- | --- | --- | --- | --- |
| `VIEW_DASHBOARD` | Si | Si | Si | Si |
| `VIEW_CORE_OPERATOR` | Si | Si | Si | Si |
| `VIEW_POLICY` | Si | Si | Si | Si |
| `VIEW_AUDIT_METADATA` | Si | Si | Si | Si |
| `VIEW_INVENTORY_METADATA` | Si | Si | Si | Si |
| `REQUEST_APPROVAL` | No | Si | Si | Si |
| `APPROVE_OPERATION` | No | No | Si | Si |
| `RUN_READ_SAFE` | No | Si | Si | Si |
| `RUN_READ_SENSITIVE` | No | No | Si | Si |
| `RUN_PRIVILEGED` | No | No | Si | Si |
| `MANAGE_POLICIES` | No | No | No | Si |
| `MANAGE_USERS` | No | No | No | Si |
| `DEPLOY` | No | No | Si | Si |
| `ROLLBACK` | No | No | Si | Si |

Restricciones adicionales obligatorias:

- `OPERATOR` y `ADMIN` no pueden autoaprobar ninguna operacion que requiera
  aprobacion. Una excepcion solo es valida si esta definida explicitamente por
  politica, registrada y auditada.
- `RUN_PRIVILEGED`, `DEPLOY` y `ROLLBACK` requieren controles adicionales
  aunque la matriz permita evaluar el permiso correspondiente.
- `FORBIDDEN` permanece denegado para todos los roles.
- El rol nunca reemplaza la clasificacion de riesgo ni la politica por recurso,
  proyecto o entorno.

## Visibilidad Futura En La UI

### `VIEWER`

Podra ver Dashboard, resumen del Core Operator, decisiones de politica,
auditoria metadata-only e inventario minimizado si todos los permisos de vista
aplican al recurso solicitado.

### `DEVELOPER`

Podra ver las mismas superficies y, en una fase futura, preparar solicitudes de
aprobacion o diagnosticos READ_SAFE. No vera controles administrativos ni
capacidades de produccion por defecto.

### `OPERATOR`

Podra ver las superficies operativas autorizadas y colas futuras de aprobacion.
Los controles de solicitud o aprobacion solo se mostraran cuando existan backend,
identidad, PolicyEngine y trazabilidad efectivos.

### `ADMIN`

Podra acceder en el futuro a gestion de usuarios, asignaciones y politicas. Las
operaciones sensibles conservaran el mismo flujo controlado y no dispondran de
un bypass administrativo.

La interfaz debe distinguir entre contenido no autorizado, no disponible y
bloqueado por politica sin filtrar la existencia de recursos sensibles.

## Capacidades No Disponibles Para Ningun Rol

En Fase 3.4 ningun rol puede:

- iniciar sesion o mantener una sesion real;
- consultar identidades o usuarios reales;
- solicitar o aprobar operaciones reales;
- ejecutar comandos desde la web;
- ejecutar `RUN_READ_SAFE`, `RUN_READ_SENSITIVE` o `RUN_PRIVILEGED`;
- desplegar, reiniciar, modificar o revertir servicios;
- administrar politicas o usuarios;
- leer secretos, salidas crudas, backups o bases de datos;
- conectar la UI con Core Operator;
- cambiar `blocked_by_default`.

## Relacion Futura Con PolicyEngine

La capa de autorizacion debe entregar a PolicyEngine una identidad autenticada,
roles, permisos efectivos, recurso, entorno, accion solicitada y contexto de
riesgo. PolicyEngine debe tomar una decision verificable entre `allow`,
`approval_required` y `deny`.

La validacion debe realizarse en servidor y repetirse cuando cambie el plan, el
recurso, el actor, la vigencia o el riesgo. La UI solo representa la decision;
no la crea ni la modifica.

La cadena futura debe conservarse completa:

```text
Identity
  -> Authorization
  -> Policy
  -> Approval
  -> ApprovedExecutionPlan
  -> DryRun
  -> ExecutionGate
  -> ControlledExecutor
```

## Relacion Futura Con Approval Workflow

Una solicitud de aprobacion debe vincular, como minimo:

- identidad y rol del solicitante;
- identidad y rol del aprobador;
- actor y rol efectivos evaluados en el momento de la aprobacion;
- `policy_version` aplicada a la decision;
- `effective_permissions` evaluados para el actor y el recurso;
- accion y recurso exactos;
- riesgo y decision de politica;
- identificador inmutable del plan;
- fecha de creacion, caducidad y decision;
- justificacion y resultado metadata-only.

Approval workflow debe rechazar autoaprobaciones para toda operacion que requiera
aprobacion, salvo una excepcion definida explicitamente por politica, registrada
y auditada. Tambien debe rechazar decisiones caducadas, cambios de actor, accion
o plan y cualquier permiso revocado. El registro debe conservar una instantanea
inmutable de `policy_version`, `effective_permissions`, actor y rol evaluados para
que la decision pueda reconstruirse aunque cambien posteriormente los roles o
las politicas. Una aprobacion valida solo permite avanzar a
`ApprovedExecutionPlan`; nunca dispara ejecucion automatica.

## Requisitos Antes De Implementar Login Real

- HTTPS obligatorio y configuracion TLS revisada.
- Sesiones seguras con expiracion, revocacion y regeneracion de identificador.
- Proteccion CSRF en toda operacion con estado.
- Rate limiting por identidad, origen y tipo de accion.
- 2FA obligatorio para roles y operaciones sensibles.
- Audit trail de autenticacion, autorizacion y cambios administrativos.
- Lockout temporal y alertas frente a intentos repetidos.
- Rotacion de secretos y almacenamiento fuera del codigo y de la UI.
- Gestion segura de cookies con atributos restrictivos y alcance minimo.
- Separacion tecnica entre permisos de lectura, solicitud, aprobacion y
  ejecucion.
- Recuperacion de cuenta y baja de acceso auditables.
- Pruebas de autorizacion negativas y proteccion frente a escalada horizontal y
  vertical.
- Politica de minimizacion, retencion y redaccion de datos.

## NO-GO Actual

- No activar login real.
- No activar ni anadir backend.
- No activar botones operativos.
- No conectar usuarios reales.
- No ejecutar acciones desde la UI.
- No leer ni exponer secretos.
- No exponer logs crudos, backups ni datos de bases de datos.
- No aceptar autorizacion basada solo en controles del navegador.
- No conectar la UI con Core Operator.

## GO Futuro Para Implementar Autenticacion Real

La implementacion solo podra comenzar cuando:

- exista una decision de arquitectura revisada para identidad y sesiones;
- haya modelo de amenazas y requisitos de privacidad documentados;
- roles, permisos, herencia y denegaciones esten aprobados;
- exista almacenamiento seguro de credenciales y secretos;
- HTTPS, CSRF, rate limiting, 2FA, lockout y auditoria tengan criterios de prueba;
- se hayan definido alta, baja, recuperacion y revocacion de usuarios;
- existan tests automatizados de autenticacion y autorizacion negativa;
- se mantenga un modo cerrado por defecto y reversible;
- una revision humana de seguridad autorice la fase.

## GO Futuro Para Conectar La UI Con Core Operator

La conexion solo podra plantearse cuando:

- autenticacion y autorizacion esten implementadas y verificadas;
- PolicyEngine reciba y valide identidad y permisos efectivos;
- Approval workflow valide solicitante, aprobador, vigencia y plan;
- exista un contrato de API cerrado, autenticado, autorizado y versionado;
- las respuestas esten minimizadas y redactadas;
- exista proteccion frente a repeticion e idempotencia donde aplique;
- auditoria persistente segura registre cada transicion;
- ExecutionGate vuelva a comprobar identidad, permiso y aprobacion;
- ControlledExecutor permanezca deshabilitado salvo habilitacion explicita;
- existan tests end-to-end de denegacion, caducidad, revocacion y manipulacion;
- haya validacion humana y plan de rollback de la integracion.

## Riesgos Pendientes

- No existe proveedor de identidad seleccionado.
- No existe modelo persistente de usuarios, roles o permisos.
- No estan definidos tenancy, alcance por proyecto ni delegacion temporal.
- La matriz propuesta requiere revision humana y analisis de segregacion de
  funciones.
- No existe mecanismo de revocacion inmediata ni gestion de sesiones.
- Approval workflow sigue siendo contractual y en memoria.
- No existe API web autorizada ni modelo de amenazas completo.
- No estan definidas retencion, proteccion y acceso a auditoria persistente.
- No existen pruebas de seguridad web, carga ni recuperacion de cuenta.
- La UI actual no debe interpretarse como una frontera de seguridad.

## Estado De Cierre De Fase 3.4

Esta fase entrega un contrato documental. No habilita autenticacion,
autorizacion, sesiones, usuarios, permisos activos, backend ni ejecucion. La UI
read-only y el ControlledExecutor conservan sus bloqueos actuales.
