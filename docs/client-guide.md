# Guía para el cliente

## Qué es el Cibermedida VPS Control Center

Cibermedida VPS Control Center es una aplicación web para centralizar la
visibilidad, la revisión y el control seguro de un entorno VPS. Reúne en una
interfaz el estado general del sistema, las capacidades declaradas, los
proyectos, las políticas de seguridad, las aprobaciones y la auditoría basada
en metadatos.

Su objetivo es que el cliente pueda entender qué está disponible, qué se ha
validado y qué permanece protegido. La aplicación separa expresamente la
consulta de la autorización y de cualquier ejecución futura.

## Para qué sirve

La aplicación sirve para:

- consultar el estado general y la salud interna disponible;
- revisar monitorización e inventario únicamente cuando existe un proveedor
  READ_SAFE autorizado;
- consultar metadatos de proyectos y Git, como rama, estado y referencia;
- revisar la matriz de decisiones de la política;
- visualizar solicitudes, aprobaciones y planes sin exponer contenido sensible;
- comprobar dry-runs, gates de ejecución y eventos de auditoría metadata-only;
- documentar de forma clara qué capacidades están activas, planificadas o
  bloqueadas.

La interfaz no es un terminal remoto ni un panel de comandos arbitrarios.

## Cómo funciona

Cada solicitud relevante sigue una cadena de controles:

1. **Policy** clasifica la acción, el riesgo y el nivel de autorización.
2. **Approval** solicita una aprobación independiente cuando la política lo
   exige.
3. **ApprovedExecutionPlan** fija la identidad, el alcance, el comando
   permitido, la versión de la política y la caducidad.
4. **ApprovedPlanDryRunner** comprueba el plan sin ejecutar comandos reales.
5. **ExecutionGate** revalida el resultado del dry-run, el riesgo, la
   autorización y la integridad del plan.
6. **ControlledExecutor** representa la última frontera y permanece
   \`blocked_by_default\` mientras no exista una activación explícita y segura.

Esta cadena permite explicar por qué una operación se permite, se somete a
aprobación o se bloquea.

## Qué puede ver el cliente

| Área | Qué muestra |
| --- | --- |
| Panel | Resumen de estado, salud, proyectos y fases. |
| Capacidades | Estado actual de cada módulo y su proveedor. |
| Monitorización | Métricas READ_SAFE cuando existe un proveedor autorizado. |
| Inventario | Metadatos mínimos autorizados, nunca una salida operativa completa. |
| Proyectos y Git | Estado declarado, rama y referencia sin push, merge ni cambios. |
| Política | Decisión \`allow\`, \`approval_required\` o \`deny\`. |
| Aprobaciones | Solicitante, aprobador, alcance y estado de la solicitud. |
| Auditoría | Eventos y resultados sin stdout, stderr, credenciales ni secretos. |
| Seguridad | Límites activos y capacidades bloqueadas por diseño. |

## Cómo interpretar los estados

- **READ_SAFE**: consulta permitida y limitada a metadatos no sensibles.
- **READ_SENSITIVE** o **READ_PRIVILEGED**: requieren autorización y no se
  ejecutan automáticamente.
- **approval_required**: la solicitud necesita una aprobación independiente;
  no significa que vaya a ejecutarse.
- **deny**: la política rechaza la solicitud.
- **blocked_by_default**: el contrato está definido, pero la operación no está
  habilitada.
- **metadata-only**: se conserva información descriptiva, no contenido crudo
  de procesos, archivos, logs o comandos.

## Qué permanece bloqueado

La configuración segura mantiene bloqueados por diseño:

- ejecución real de comandos del operador;
- uso de \`sudo\` o acceso elevado;
- acciones modificadoras, despliegues y rollback;
- reinicio o modificación de servicios;
- exposición o lectura de secretos y credenciales;
- lectura de logs crudos, backups o bases de datos;
- consultas arbitrarias a sistemas externos;
- creación automática de \`INVENTORY.json\`;
- cambios de repositorios, push, merge o despliegue desde la web.

Estas restricciones forman parte del modelo de seguridad. No representan un
fallo de la interfaz.

## Beneficios para el cliente

El programa proporciona una vista única y ordenada del entorno, reduce la
ambigüedad sobre el estado de cada capacidad y deja una explicación auditable
de las decisiones. También permite avanzar por etapas: primero observación
segura, después autorización explícita y, solo si se cumplen las condiciones,
una eventual ejecución controlada.

## Alcance actual de producción

La instancia publicada puede exponer proveedores READ_SAFE habilitados para
monitorización, inventario o proyectos cuando han sido activados expresamente.
El estado exacto se muestra en el propio panel y en \`/api/status\`.

Aunque existan datos READ_SAFE reales, la ejecución modificadora y el
\`ControlledExecutor\` continúan bloqueados. La auditoría y las aprobaciones
deben conservar únicamente metadatos y respetar el almacenamiento configurado
por el responsable del sistema.

## Evolución futura

Para habilitar una operación que hoy aparece como bloqueada se necesitarían,
como mínimo, una lista cerrada de comandos, permisos mínimos, un manifiesto con
versión de política y caducidad, un solicitante y un aprobador distintos,
backup verificable, validación posterior, auditoría metadata-only y un plan de
rollback revisado.

La habilitación futura debe hacerse por fases y con revisión humana. Esta guía
no autoriza ninguna operación ni inicia cambios en el VPS.
