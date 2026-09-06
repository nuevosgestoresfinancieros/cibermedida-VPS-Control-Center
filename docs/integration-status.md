# Estado de integración frente al documento maestro

Este documento es la matriz operativa de la implementación actual. Distingue
entre código funcional en el perfil local de laboratorio, contratos
metadata-only y capacidades que requieren una autorización de producción
independiente.

## Actualización de integración vNext

La integración actual añade un `OperationManifest` común para representar
scope de servidor, proyecto, entorno, recurso y acción; comandos, archivos,
servicios afectados, dependencias, tests, backup, rollback, validaciones,
timestamps y hashes de operación/plan/aprobación/ejecución. El manifiesto se
propaga por approvals, dry-run, execution gate y controlled executor. Cualquier
cambio del snapshot vinculante invalida la continuación.

Los catálogos de inventario, knowledge, backups, deployments, monitoring,
incidents y audit conservan ahora fuente, confianza, fechas y relaciones
metadata-only cuando el contrato las admite. Estos campos describen evidencia
declarada o de laboratorio; no convierten una entrada en observación live.

La UI en castellano presenta un Control Center visual con navegación lateral,
búsqueda, paleta `Ctrl/Cmd + K`, salud simulada, métricas, topología declarada,
actividad y proyectos. La fuente sigue siendo `/api/status` o
`web/readonly-shell/data/status.json`, con fallback embebido. El badge de
ejecución continúa en `blocked_by_default`.

La arquitectura detallada, auditoría visual, brechas y plan se mantienen en
`docs/CURRENT_ARCHITECTURE.md`, `docs/UI_AUDIT.md`, `docs/GAP_ANALYSIS.md` y
`docs/IMPLEMENTATION_PLAN.md`.

## Matriz de fases

| Fase | Estado actual | Evidencia / límite |
| --- | --- | --- |
| 0. Diseño | Completa | Arquitectura, políticas, seguridad y modelos versionados. |
| 1. Inventario | Provider READ_SAFE explícito | Existe allowlist y pipeline; el adapter solo se activa con `--read-safe-inventory`, valida el schema y conserva el resultado en memoria por defecto. El estado JSON solo se activa con una ruta opt-in segura; nunca crea `INVENTORY.json`. |
| 2. Core Operator | Completa | Policy, auditoría, aprobaciones, dry-run, gate y executor controlado. |
| 3. Web Control Center | Funcional local | Shell en castellano, API local, autenticación, CSRF, roles, proyectos/Git READ_SAFE opt-in y fallback estático. |
| 4. Chat IA | Planificador local funcional; provider externo opt-in | Las respuestas son planes no ejecutables. El provider externo requiere endpoint HTTPS y clave introducida de forma interactiva. |
| 5. Integración Codex y builds | Providers sintéticos, Testing Agent, build declarado y Codex CLI read-only | La API registra métricas de tests/builds y análisis Codex metadata-only. El CLI solo acepta proyectos declarados y sandbox read-only; no convierte análisis en autorización ni permite cambios de repositorio. |
| 6. Backup Manager | Funcional en laboratorio | Provider de filesystem con raíces declaradas, checksum y restore test; no usa rutas operativas por defecto. |
| 7. Deployment Manager | Funcional en laboratorio | Preflight, backup verificado, aprobación independiente, release inmutable y post-validación; no reinicia servicios ni despliega sobre producción. |
| 8. Rollback Manager | Funcional en laboratorio | Cambia el puntero `CURRENT` de releases aisladas; no restaura servicios, bases de datos ni infraestructura. |
| 9. Monitoring | READ_SAFE funcional en laboratorio | Métricas acotadas de memoria, disco y carga; no consulta logs, puertos ni servicios. |
| 10. Incident Manager | Funcional metadata-only | Ciclo, análisis de hipótesis, resolución, referencia de rollback y persistencia opt-in; no lee logs ni aplica mitigaciones. |
| 11. Knowledge Engine | Funcional metadata-only | `V3InsightsService` registra gemelo digital, relaciones y servidores declarados; no descubre automáticamente el VPS. |
| 12. Impact Analysis | Funcional metadata-only | Impacto y correlación histórica calculan evidencia aportada; no validan dependencias reales. |
| 13. Security Center | Política y contratos | La denegación, permisos y límites están implementados; no modifica firewall, SSH, usuarios o servicios. |
| 14. Anomaly Detection | Funcional sobre snapshots/READ_SAFE | Calcula anomalías y tendencias predictivas sobre datos aportados o del adapter acotado; no genera alertas operativas externas. |
| 15. Autonomía progresiva | Perfil metadata-only | Registra niveles 0-5 por proyecto, pero toda ejecución y recuperación permanece `blocked_by_default`. |

## Perfil integrado de laboratorio

El perfil habilita, en una raíz externa al repositorio:

- identidad persistente con hashes PBKDF2;
- bootstrap de cuentas con TOTP inyectado en memoria, sin persistir semillas;
- auditoría JSONL y aprobaciones metadata-only;
- estados persistentes de conversación redacted, operaciones, ejecución
  metadata-only, backup, deployment, rollback, monitorización, incidentes,
  validación, `tests.json`, `builds.json` y `codex.json` para ejecuciones metadata-only de
  Testing Agent y análisis Codex, además de
  `v3-insights.json` para los contratos V3;
- el ciclo de incidentes permite registrar transición, resolución y referencia
  de rollback sin convertirlas en una orden operativa;
- escrituras JSON/JSONL atómicas con locks de fichero por proceso para evitar
  intercalado de registros durante reinicios o workers concurrentes;
- auditoría JSONL con segmentos acotados, rotación por tamaño y retención
  configurable (`--audit-max-bytes` y `--audit-retention-files`); la recarga
  valida todos los segmentos conservados y descarta automáticamente los más
  antiguos al superar la retención;
- provider de backup de filesystem sobre fixtures declarados;
- provider de release/rollback mediante `CURRENT`;
- provider de inventario READ_SAFE sintético para validar la integración sin
  ejecutar comandos del host;
- provider sintético de proyectos/Git para validar rama, estado y HEAD sin
  consultar el host ni mutar repositorios;
- provider sintético de Testing Agent para validar el endpoint de tests en
  laboratorio; fuera de laboratorio, el provider in-process solo acepta el
  target fijo `repository`, limita los casos y descarta stdout/stderr;
- provider de build sintético en laboratorio y `DeclaredCommandBuildProvider`
  fuera del laboratorio; los perfiles argv se declaran al arranque y no usan
  shell;
- provider sintético de Codex para validar análisis declarados sin CLI, lectura
  de repositorio ni cambios;
- monitorización y ejecución READ_SAFE sintéticas, sin consultar el host ni
  invocar el executor;
- usuarios adicionales provisionados con `--bootstrap-user USUARIO[:ROL]`.

La composición completa queda cubierta por
`tests/test_integrated_lab_workflow.py`: el test recorre autenticación
persistentemente almacenada, auditoría JSONL, aprobación independiente, chat
local, snapshot de monitorización, backup con checksum y restore-test,
release/rollback aislados, ciclo de incidente y la cadena READ_SAFE hasta un
proveedor de ejecución simulado. La prueba usa únicamente raíces temporales y
no llama al executor del sistema.

Además, `tests/test_v2_acceptance_http.py` recorre esos mismos flujos a través
del servidor HTTP y verifica que la matriz dinámica de capacidades llega a la
interfaz/API como `provider_enabled`, sin exponer `stdout` ni `stderr` en la
auditoría.

El flujo de tests y builds queda separado de la evaluación de checks aportados por el
cliente: `POST /api/tests/run` registra ejecuciones del provider explícito y
`GET /api/tests/runs` devuelve únicamente métricas metadata-only. El target no
es configurable como comando, ruta o módulo arbitrario.

`POST /api/builds/run` y `GET /api/builds/runs` usan la misma frontera. Un build
live requiere `--build-root`, uno o varios `--build-profile TARGET=ARGV`, el
provider `declared-build` en el manifiesto y `RUN_BUILDS`. La salida del proceso
se descarta y solo se conserva código de retorno, duración y resultado.

La integración Codex se expone mediante `POST /api/codex/analyze` y conserva
solo hallazgos y contadores acotados. `codex-synthetic` es exclusivo del
laboratorio. Fuera de él, `CodexCliProvider` se activa con uno o varios
`--codex-project NOMBRE=/ruta`, invoca el CLI con sandbox `read-only` y
`--ask-for-approval never`, y exige `codex-provider` y `VIEW_PROJECTS` en el
manifiesto antes de alcanzar readiness. Si el CLI devuelve contenido ambiguo,
salida insegura o archivos modificados, la ejecución se rechaza.

La superficie V3 también está integrada en el API y la web en castellano:

- `POST /api/digital-twin/register` registra nodos y relaciones declaradas.
- `POST /api/history/correlate` vincula etiquetas históricas aportadas por el usuario.
- `POST /api/predictive/analyze` calcula tendencias acotadas sobre snapshots.
- `POST /api/autonomy/profile` registra el nivel 0-5 de un proyecto sin habilitar ejecución.
- `POST /api/servers/register` mantiene un catálogo multi-servidor sin abrir conexiones.
- `POST /api/recovery/plan` prepara recuperación vinculada a un incidente y exige aprobación independiente.

Todas estas rutas requieren sesión y CSRF, producen auditoría metadata-only y
rechazan secretos o salida cruda. No sustituyen adapters de infraestructura ni
conceden autonomía operacional.

Cuando se usa `--state-root`, el servicio V3 recarga y guarda los gemelos,
correlaciones, predicciones, perfiles de autonomía, servidores y planes de
recuperación en `v3-insights.json`. El almacén es opt-in, JSON metadata-only,
validado, acotado y escrito atómicamente; la recarga no habilita conexiones,
ejecución, autonomía ni recuperación real.

El arranque no crea usuarios implícitos ni acepta contraseñas en argumentos.
El ejemplo siguiente permite separar solicitante y aprobador:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8770 \
  --lab-mode \
  --lab-root /tmp/cibermedida-control-center-lab \
  --bootstrap-username admin --bootstrap-role ADMIN \
  --bootstrap-user operador:OPERATOR
```

La contraseña se solicita por terminal para cada cuenta. El perfil no lee
secretos, `.env`, logs, backups existentes, bases de datos ni servicios; solo
crea fixtures inocuos dentro de la raíz indicada.

El inventario se expone por separado: `GET /api/inventory/summary` solo muestra
el estado de la habilitación, `GET /api/inventory` requiere permiso de
metadatos y `POST /api/inventory/collect` requiere CSRF y `RUN_READ_SAFE`. El
perfil de laboratorio usa un fixture sintético; la colección del host real
solo se habilita con `--read-safe-inventory`, se valida contra
`schemas/inventory.schema.json` y queda en memoria por defecto. Una ruta
`--inventory-state` habilita de forma explícita un estado JSON seguro; el perfil
de laboratorio usa `state/inventory-workflow.json`. Ninguna modalidad crea
`INVENTORY.json`.

La preparación de producción se consulta mediante `GET /api/readiness`,
protegido por `VIEW_CORE_OPERATOR`. El informe es metadata-only y devuelve
`NO_GO` mientras no estén demostrados el almacén de identidad, 2FA, HTTPS,
persistencia de auditoría/workflows, providers revisados y autorización humana
explícita. Consultarlo no activa ninguna capacidad.

El check de validación también exige un `validation_state_store` persistente;
tener únicamente el servicio en memoria no permite alcanzar `GO` de producción.

La evidencia de autorización se puede aportar de forma explícita mediante
`--activation-manifest /ruta/activation.json`. El contrato exige decisión
`approved`, solicitante y aprobador distintos, `policy_version`,
`effective_permissions`, alcance, providers declarados y fechas con zona
horaria; la vigencia máxima es de 24 horas. El loader solo lee esa ruta exacta,
rechaza rutas bajo `.env`, `.git`, `logs`, `backups` o nombres protegidos y
bloquea contenido con secretos o `stdout`/`stderr` crudos. Un manifiesto
caducado mantiene `human_authorization` en `NO_GO` y bloquea las peticiones a
providers live. La evidencia no selecciona providers, cambia permisos ni inicia
servicios, pero un manifiesto activo también funciona como gate por petición:
cualquier provider live debe tener su identidad declarada en `provider_ids` y
cada uso vuelve a comprobar la vigencia, el scope y el permiso de la petición
contra `effective_permissions`; readiness también devuelve `NO_GO` si el
manifiesto activo no cubre esos providers o permisos. La opción
`--state-root` permite agrupar la persistencia JSON/JSONL de identidad,
auditoría y workflows en una raíz externa existente. La evidencia de TLS se
declara aparte mediante `--https-terminated` y no configura el proxy.

## Proyectos y Git READ_SAFE

Los proyectos se exponen por separado mediante GET /api/projects y POST
/api/projects/collect. Sin provider, el catálogo es mock. Con provider, solo
se devuelven registros estructurados ya validados. La colección requiere CSRF
y RUN_READ_SAFE; fuera del laboratorio se activa con --read-safe-projects.
El adapter solo usa la allowlist Git de Fase 1 y nunca devuelve stdout/stderr,
crea ramas, hace push, hace merge o ejecuta Codex CLI. projects.json solo se
usa con un --state-root explícito o el perfil de laboratorio.

## Requisitos para producción

Antes de conectar el Control Center a un VPS real todavía se necesita una
revisión separada que aporte, como mínimo:

1. Proveedor de identidad externo o almacén de producción con gestión de
   cuentas, 2FA, revocación y rotación de sesiones.
2. Terminación HTTPS, cabeceras, cookies `Secure`, política de red y control
   de acceso al proceso.
3. Adapters revisados para inventario, monitorización, logs, servicios,
   backups, despliegues y rollback, cada uno con allowlist, límites de tiempo,
   validación posterior y recuperación probada.
4. Cifrado, locking distribuido, recuperación externa y una política de
   retención aprobada para la auditoría y el estado de workflows. La rotación
   local JSONL y el locking local de fichero ya están implementados como
   protección acotada, pero no sustituyen esos controles.
5. Autorización humana explícita para activar cualquier acción modificadora o
   privilegiada, con backup verificado y rollback probado.

Mientras esos requisitos no estén satisfechos, el estado correcto de la
aplicación es local/laboratorio y `blocked_by_default` para producción.
