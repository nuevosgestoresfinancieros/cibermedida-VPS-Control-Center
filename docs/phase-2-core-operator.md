# Fase 2 - Core Operator

## Objetivo

Fase 2 establece la base interna del operador seguro del Cibermedida VPS Control Center. Su objetivo no es ejecutar operaciones reales de administracion, sino construir los contratos, controles y estados necesarios para separar observacion, decision, autorizacion, simulacion y ejecucion futura.

Esta fase mantiene produccion protegida: no incorpora ejecucion real de comandos operativos, no usa `sudo`, no modifica servicios y no habilita despliegues, rollback ni cambios de infraestructura.

## Alcance Real Implementado

Fase 2 implementa una cadena no operativa y auditable que llega hasta un `ControlledExecutor` bloqueado por defecto.

Componentes implementados:

- `OperatorConfig`: configuracion segura por defecto. La persistencia, logs a disco, auditoria a disco, carga de `.env` y health checks de red quedan deshabilitados salvo configuracion explicita futura.
- `safe_logging`: logging estructurado en memoria con redaccion centralizada.
- `InMemoryAuditStore`: backend de auditoria por defecto, sin escritura a disco.
- `JsonlAuditStore`: persistencia JSONL opcional, deshabilitada por defecto, con validacion de ruta, bloqueo de archivos criticos y rechazo de contenido sensible o salidas crudas.
- `PolicyEngine`: evaluacion inicial de politica para `READ_SAFE`, `READ_SENSITIVE`, `READ_PRIVILEGED`, `FORBIDDEN` y acciones modificadoras.
- `ReadSafeExecutorAdapter`: adaptador policy-gated para el executor READ_SAFE de Fase 1, sin ampliar comandos y sin persistir stdout/stderr crudos.
- `Approval workflow`: modelo y store en memoria para solicitudes y decisiones de aprobacion.
- `ApprovedExecutionPlan`: contrato que convierte una aprobacion valida en un plan `ready_to_execute`, sin ejecutar.
- `ApprovedPlanDryRunner`: runner seco que consume planes aprobados y produce resultado de simulacion metadata-only.
- `ExecutionGate`: puerta posterior al dry-run que declara elegibilidad para una futura ejecucion controlada.
- `ControlledExecutor`: contrato final pre-ejecucion; acepta decisiones elegibles, pero devuelve `blocked_by_default` en esta fase.

## Cadena De Control

La cadena implementada queda asi:

```text
Policy
  -> Approval
  -> ApprovedExecutionPlan
  -> DryRun
  -> ExecutionGate
  -> ControlledExecutor
```

La propiedad importante de esta cadena es que cada etapa vuelve a validar su entrada y no confia ciegamente en la etapa anterior.

```text
PolicyEngine
  evalua accion, comando y riesgo

Approval workflow
  registra pending, approved, denied o expired

ApprovedExecutionPlanner
  exige approval approved y coincidencia de actor, action y command_id

ApprovedPlanDryRunner
  acepta solo ready_to_execute y simula sin executor

ExecutionGate
  acepta solo dry_run completed y declara eligible_for_controlled_execution

ControlledExecutor
  acepta solo eligible_for_controlled_execution pero bloquea por defecto
```

## Estados Principales

### Politica

- `allow`: accion permitida por politica actual.
- `approval_required`: accion no ejecutable automaticamente; requiere decision humana.
- `deny`: accion denegada.

### Approval Workflow

- `pending`: aprobacion pendiente.
- `approved`: aprobacion concedida.
- `denied`: aprobacion denegada.
- `expired`: estado contractual para aprobaciones caducadas.

### ApprovedExecutionPlan

- `ready_to_execute`: plan valido en contrato, aun sin ejecutar.
- `blocked`: plan bloqueado por estado, mismatch, riesgo o falta de aprobacion valida.
- `rejected`: plan rechazado por politica o comando prohibido.

### Dry Run

- `completed`: simulacion metadata-only completada.
- `blocked`: simulacion bloqueada.
- `rejected`: simulacion rechazada.

### Execution Gate

- `eligible_for_controlled_execution`: dry-run completado y decision elegible para futura capa de ejecucion.
- `blocked`: decision bloqueada por validaciones.
- `rejected`: decision rechazada por politica o accion prohibida.

### Controlled Executor

- `blocked_by_default`: estado normal de Fase 2; nada se ejecuta aunque la decision sea elegible.
- `rejected`: entrada no aceptable para ejecucion controlada.
- `not_configured`: estado reservado para configuracion futura no habilitada.

## Bloqueos Por Diseno

Fase 2 mantiene bloqueado por diseno:

- ejecucion real de comandos operativos;
- uso de `sudo`;
- acciones modificadoras;
- lectura de secretos;
- lectura de `.env`;
- lectura de logs crudos;
- lectura de backups o dumps;
- consultas a bases de datos;
- lecturas de firewall no autorizadas;
- persistencia automatica;
- creacion automatica de `INVENTORY.json`;
- despliegues;
- rollback real;
- reinicio o modificacion de servicios;
- ejecucion posterior automatica tras una aprobacion.

Una aprobacion humana en Fase 2 no ejecuta nada por si sola. Como mucho permite construir estados contractuales internos que siguen siendo bloqueados antes de cualquier ejecucion real.

## Garantias De Seguridad

Las garantias implementadas son:

- no existe shell libre en Core Operator;
- no se usa `shell=True`;
- no se usa `os.system`;
- no se usa `eval` ni `exec`;
- no se introduce `subprocess` en Core Operator;
- el executor real no se llama desde planner, dry-runner, gate ni controlled executor;
- los comandos READ_SAFE siguen limitados por Fase 1;
- `READ_SENSITIVE` y `READ_PRIVILEGED` requieren aprobacion y no escalan automaticamente;
- `FORBIDDEN` se deniega o rechaza;
- acciones modificadoras se deniegan o rechazan por defecto;
- la auditoria guarda metadatos, no stdout/stderr crudos;
- la persistencia JSONL esta deshabilitada por defecto;
- el contenido con patrones de secreto se rechaza antes de persistir auditoria;
- imports de modulos no ejecutan inventario ni acciones reales.

## Matriz De Decisiones

| Clase | Politica Fase 2 | Ejecucion automatica | Estado esperado |
| --- | --- | --- | --- |
| `READ_SAFE` | `allow` si el comando esta registrado | Solo a traves del adaptador seguro de Fase 1 | permitido para metadatos seguros |
| `READ_SENSITIVE` | `approval_required` | no | approval pending |
| `READ_PRIVILEGED` | `approval_required` | no | approval pending |
| `FORBIDDEN` | `deny` | no | denied/rejected |
| modifying actions | `deny` por defecto | no | denied/rejected |

## Relacion Con Fase 1

Fase 1 aporta el inventario READ_SAFE, el schema, la allowlist, la redaccion, el secret scan y el executor restringido. Fase 2 reutiliza esa base desde `ReadSafeExecutorAdapter`, pero no amplia por si misma el alcance de inventario ni permite comandos nuevos.

El cierre READ_SAFE basico de Fase 1 ejecuto de forma controlada un subconjunto minimo: disco, memoria, uptime, kernel, arquitectura, CPU y metadata Git acotada. Fase 2 no repite ni amplia esas ejecuciones.

## Riesgos Pendientes

- No existe todavia autenticacion web, roles reales ni sesiones.
- Las aprobaciones son en memoria; no hay persistencia formal de approval workflow.
- `approval_id` se valida como metadata, no contra un store persistente.
- No existe UI ni API para revisar o aprobar operaciones.
- No existe configuracion habilitante para ejecucion real.
- No existe post-execution validation.
- No existe rollback operativo.
- No existe motor de backups previos a cambios sensibles.
- No existe matriz completa de permisos por usuario/rol.
- No existe rotacion, retencion ni locking fuerte para auditoria persistente.

## GO / NO-GO Para Fase 3 Web Control Center

### GO Para Empezar Fase 3 Si

- La web inicial es read-only.
- No dispara comandos reales.
- No habilita ejecucion desde botones o chat.
- Muestra solo estados, documentacion, health interno, policy decisions y auditoria metadata-only.
- Usa datos mock o datos ya minimizados/autorizados.
- Declara visualmente que ejecucion real esta bloqueada.
- Mantiene autenticacion/autorizacion como requisito antes de cualquier UI operativa.

### NO-GO Para Fase 3 Si

- La UI pretende ejecutar acciones reales.
- La UI expone secretos, logs crudos, backups o datos de bases de datos.
- La UI permite `sudo`, shell libre o comandos arbitrarios.
- La UI crea `INVENTORY.json` automaticamente.
- La UI permite deploy, rollback o reinicio de servicios.
- No hay separacion clara entre visualizacion y accion.

## GO / NO-GO Para Ejecucion Real Controlada

### GO Futuro Solo Si

- Existe autorizacion humana explicita por operacion.
- Existe configuracion habilitante cerrada y deshabilitada por defecto.
- Existe backup/verificacion cuando aplique.
- Existe validacion previa y posterior.
- Existe rollback documentado y probado cuando aplique.
- Existe auditoria persistente con retencion y proteccion.
- Existe control de identidad, roles y permisos.
- Existe allowlist ejecutable cerrada por identificadores logicos.
- Existe secret scan antes de persistir cualquier evidencia.

### NO-GO Actual

Fase 2 no esta lista para ejecucion real. El estado correcto del `ControlledExecutor` es `blocked_by_default`.

## Informacion Que Puede Mostrar Una Futura UI Sin Ejecutar Acciones

Una primera UI web read-only podria mostrar:

- fase actual del proyecto;
- cadena de control y estados;
- lista de componentes Core Operator implementados;
- comandos READ_SAFE disponibles por identificador logico;
- resultados de health interno del Core Operator;
- policy decisions simuladas;
- approvals en memoria de prueba;
- auditoria metadata-only;
- estado de bloqueos por diseno;
- riesgos pendientes;
- criterios GO/NO-GO para avanzar.

No deberia mostrar secretos, logs crudos, backups, variables de entorno, argumentos completos de procesos, consultas de bases de datos ni salidas crudas de comandos.
