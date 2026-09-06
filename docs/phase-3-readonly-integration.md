# Fase 3.6 - Control Center local integrado

## Alcance

La shell web del Control Center queda conectada a un servidor Python sin
dependencias externas. El servidor combina:

- estado y documentación mock versionados;
- health interno del Core Operator sin sondas de red;
- autenticación por sesión HttpOnly, CSRF y roles en memoria;
- planner conversacional determinista y provider IA compatible opt-in;
- planes de operaciones, aprobaciones separadas y auditoría de metadatos;
- contratos y providers declarados para backups, releases/rollback,
  monitorización READ_SAFE e incidentes metadata-only.
- un provider de inventario READ_SAFE explícito que reutiliza el pipeline de
  Fase 1, valida el schema en la frontera de aplicación y mantiene el último
  resultado en memoria por defecto; el estado JSON solo se activa con una ruta
  opt-in segura.
- un provider de proyectos/Git READ_SAFE explícito que solo conserva nombre,
  rama, estado limpio/sucio y HEAD validado; el estado JSON de proyectos es
  opt-in y nunca incluye stdout, stderr, rutas sensibles ni mutaciones Git.
- un registro de capacidades en `GET /api/capabilities`, que diferencia
  persistencia, contratos simulados, proveedores configurados y bloqueos por
  defecto.
- una frontera `ControlledExecutionService` que solo acepta decisiones ya
  elegibles del `ExecutionGate`; el proveedor está ausente y deshabilitado por
  defecto, por lo que cualquier solicitud termina en `blocked_by_default`.

Por defecto los servicios no leen el VPS, `.env`, secretos, logs, backups ni
bases de datos. Los providers explícitos de filesystem y READ_SAFE solo
pueden leer o escribir las raíces declaradas y validadas al arrancar; nunca
descubren rutas operativas. Por defecto no escriben estado de aplicación a
disco; la identidad y auditoría JSON/JSONL son opt-in y guardan únicamente
hashes o metadatos. No existe una cuenta predeterminada.

## Arranque local

Desde la raíz del repositorio:

```text
python3 -m api.readonly_server --host 127.0.0.1 --port 8766
```

Abrir `http://127.0.0.1:8766/`. Para usarlo desde otro equipo, crear un
túnel SSH local; el servidor continúa escuchando solo en loopback del VPS.

Para probar autenticación en esa ejecución, provisiona una cuenta temporal
explícitamente. La contraseña se solicita de forma interactiva y solo vive en
memoria hasta detener el proceso:

```text
python3 -m api.readonly_server --host 127.0.0.1 --port 8766 --bootstrap-username admin --bootstrap-role ADMIN
```

Esto no es todavía un almacén de identidades de producción. Antes de exponer
el servicio fuera de loopback hace falta integrar un proveedor persistente,
HTTPS, gestión de 2FA y rotación de sesiones bajo revisión de seguridad.

Existe una persistencia local opt-in para laboratorio. Guarda únicamente
hashes PBKDF2 y salt, nunca contraseñas:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8766 \
  --auth-state /ruta/segura/users.json \
  --audit-path /ruta/segura/audit.jsonl \
  --approval-state /ruta/segura/approvals.json \
  --bootstrap-username admin --bootstrap-role ADMIN
```

El directorio padre debe existir y las rutas no pueden apuntar a `.env`,
`.git`, `AGENTS.md` o `INVENTORY.json`. La persistencia no se activa por
defecto. `--approval-state` guarda únicamente solicitudes y decisiones de
aprobación, con escritura atómica y permisos `0600`; no guarda contraseñas,
comandos ejecutados ni salida de procesos. Requiere una revisión de permisos,
backups, retención y recuperación antes de considerarse producción.

## Perfil integrado de laboratorio

La aplicación incluye un perfil opt-in para recorrer las capacidades seguras
en una sola ejecución. Requiere una raíz absoluta externa al repositorio y un
nombre de usuario para provisionar de forma interactiva:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8768 \
  --lab-mode --lab-root /tmp/cibermedida-control-center-lab \
  --bootstrap-username admin --bootstrap-role ADMIN
```

El arranque admite usuarios adicionales con `--bootstrap-user
USUARIO[:ROL]`. La opción puede repetirse, solicita cada contraseña de forma
interactiva y usa `VIEWER` si no se indica el rol. Para probar la separación
entre solicitante y aprobador, por ejemplo, añade
`--bootstrap-user operador:OPERATOR`; ninguna contraseña se escribe en los
argumentos ni se crea una cuenta implícita.

El perfil crea solo fixtures públicos dentro de la raíz declarada, habilita
providers READ_SAFE sintéticos de monitorización y ejecución, sin consultar el
host ni invocar el executor, y conecta los providers de
backup y release/rollback de filesystem. Las rutas de estado explícitas no se
combinan con este perfil para conservar el aislamiento; el propio perfil crea
`state/users.json`, `state/audit.jsonl` y `state/approvals.json` dentro de la
raíz de laboratorio. El historial conversacional redacted, los snapshots de
monitorización, incidentes, planes de operación, registros de ejecución y
planes de backup, deployment y rollback se conservan en JSON metadata-only
adicional dentro de `state/`, con escrituras atómicas.
La ejecución sigue
requiriendo aprobación independiente y solo acepta la allowlist READ_SAFE;
deploy y rollback solo cambian fixtures de laboratorio o un puntero `CURRENT`.

También habilita un provider de inventario sintético para comprobar la UI y el
contrato HTTP sin ejecutar comandos del host. Para una colección READ_SAFE del
host, fuera del perfil de laboratorio, se debe arrancar explícitamente con:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8766 \
  --read-safe-inventory \
  --auth-state /ruta/segura/users.json \
  --audit-path /ruta/segura/audit.jsonl \
  --approval-state /ruta/segura/approvals.json \
  --bootstrap-username admin --bootstrap-role ADMIN
```

La colección requiere una sesión con `RUN_READ_SAFE`, usa únicamente la
allowlist existente de Fase 1, valida y escanea el inventario antes de
exponerlo, y no escribe `INVENTORY.json`. La autorización para usar este flag
en un VPS real es independiente de la implementación y debe documentarse
antes de ejecutarlo.

El perfil también habilita un provider sintético de proyectos/Git. Para
recoger explícitamente metadatos Git READ_SAFE del proyecto declarado, fuera
del perfil de laboratorio, se debe añadir `--read-safe-projects`. El adapter
reutiliza únicamente `git.status` y `git.head_commit` de la allowlist de Fase
1, valida la rama, el estado y el hash, y descarta cualquier salida cruda.
No crea ramas, no hace push, no hace merge y no invoca Codex CLI. La colección
requiere `RUN_READ_SAFE`; consultar el catálogo requiere `VIEW_PROJECTS`.

El perfil rechaza la raíz del proyecto y sus directorios padre o hijos. No
descubre ni lee rutas existentes del VPS, secretos, `.env`, logs, backups,
bases de datos o servicios, y no inicia ni detiene ningún proceso operativo.
Es una superficie reproducible para pruebas de integración, no una
autorización para producción.

## API pública y flujos autenticados metadata-only

- `GET /api/health`: salud interna del Core Operator, sin red ni servicios.
- `GET /api/status`: estado mock completo para la interfaz.
- `GET /api/policy`: matriz de decisiones y bloqueo por defecto.
- `GET /api/audit-preview`: ejemplo de auditoría metadata-only.
- `GET /api/inventory/summary`: muestra si el provider READ_SAFE está
  habilitado y si ya existe una colección en memoria o en estado seguro opt-in,
  sin devolver el inventario.
- `GET /api/inventory`: devuelve el último inventario validado y sus metadatos;
  requiere `VIEW_INVENTORY_METADATA`.
- `GET /api/readiness`: devuelve la matriz metadata-only de requisitos de
  producción; requiere `VIEW_CORE_OPERATOR` y no habilita ningún provider.
- `GET /api/server/status`, `/api/projects`, `/api/projects/:id/status` y
  `/api/services`: catálogos mock cuando no hay provider; con el provider de
  proyectos explícito, `/api/projects` devuelve solo registros Git
  metadata-only ya validados y exige sesión.
- `GET /api/services/:id/logs`: responde bloqueo explícito; no se leen logs
  reales.
- `GET /api/views`: catálogo de áreas de la especificación.
- `GET /api/execution`: estado y registros metadata-only de la frontera de
  ejecución; requiere sesión con permiso de Core Operator y solo muestra un
  provider READ_SAFE si se habilitó explícitamente.
- `POST /api/execution/evaluate`: conecta planner, dry-run, gate y executor
  controlado para una aprobación existente; con la configuración incluida el
  resultado es `blocked_by_default`.
- `GET /api/capabilities`: estado explícito de autenticación, chat, auditoría,
  backups, despliegues, rollback, monitorización, testing, builds, Codex y
  ejecución controlada.

## API autenticada

El login devuelve una cookie `HttpOnly` y un token CSRF que se conserva solo
en memoria del navegador. Las operaciones POST requieren `X-CSRF-Token`.

- `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`.
- `POST /api/chat`: clasifica una petición y devuelve un plan sin ejecución.
- El proceso incluido usa el planificador local determinista por defecto. Puede
  habilitarse `OpenAICompatibleChatProvider` con `--chat-endpoint` y
  `--chat-api-key-prompt`; la clave solo se solicita en terminal y las
  respuestas deben ser JSON estructurado no ejecutable.
- `POST /api/diagnostics`: registra una solicitud de diagnóstico metadata-only
  y la deja bloqueada; no lanza sondas.
- `POST /api/tests` y `/api/validation/evaluate`: evalúan checks booleanos
  aportados por el cliente, sin ejecutar tests.
- `POST /api/tests/run`: ejecuta únicamente el target fijo `repository` cuando
  se habilita un provider explícito. El provider in-process descubre la suite
  `tests/test_*.py` con un límite acotado, descarta toda la salida de unittest
  y conserva solo estado, resultado, número de casos, fallos y duración.
  Requiere CSRF, `RUN_TESTS` y, para un provider live, el manifiesto activo con
  `repository-tests` y `RUN_TESTS`.
- `GET /api/tests/runs`: devuelve las ejecuciones metadata-only autorizadas;
  nunca expone stdout, stderr, trazas ni comandos.
- `POST /api/builds/run`: ejecuta únicamente un target de un perfil argv
  declarado al arrancar con `--build-root` y `--build-profile`; requiere CSRF,
  `RUN_BUILDS` y el provider `declared-build` cuando el perfil es live. La
  petición nunca puede enviar el ejecutable, la ruta o el comando. Solo se
  conservan estado, código de retorno, duración y resultado; stdout/stderr se
  descartan.
- `GET /api/builds/runs`: devuelve ejecuciones de build metadata-only sin
  salida cruda, comandos ni rutas.
- `POST /api/codex/analyze`: prepara un análisis Codex metadata-only sobre un
  proyecto declarado. En laboratorio usa un provider sintético; fuera de él
  usa `CodexCliProvider` únicamente si se declara `--codex-project`, el CLI
  está instalado y el manifiesto activo contiene `codex-provider`. Fuerza
  sandbox `read-only`, no acepta comandos ni rutas arbitrarias y rechaza
  archivos modificados, secretos o respuestas ambiguas.
- `GET /api/codex/runs`: muestra solo el estado, tipo de solicitud, hallazgos
  acotados y métricas del provider; no muestra contenido de repositorio ni
  salida de CLI.
- `POST /api/monitoring/snapshot`: registra un snapshot numérico aportado por
  el cliente y calcula anomalías en memoria; no recoge métricas del VPS.
- `POST /api/monitoring/collect`: prueba la frontera de recolección; sin un
  `MonitoringProvider` inyectado responde `blocked_by_default`. Si una
  colección READ_SAFE aceptada contiene anomalías, crea un incidente
  metadata-only vinculado a `read-safe-monitoring`; no lee logs ni ejecuta
  mitigaciones.
- `POST /api/inventory/collect`: solicita una colección explícita READ_SAFE;
  requiere CSRF y `RUN_READ_SAFE`, no acepta comandos arbitrarios, no persiste
  el resultado por defecto y termina bloqueado si no existe provider. La
  persistencia requiere la ruta JSON opt-in `--inventory-state` o el estado
  aislado del perfil de laboratorio.
- `POST /api/projects/collect`: solicita rama, estado limpio/sucio y HEAD Git
  validados; requiere CSRF y `RUN_READ_SAFE`, no acepta comandos ni rutas del
  cliente y conserva el registro solo si se habilita el estado JSON opt-in.
- `/api/operations/*`: planifica, aprueba, prepara backup y solicita ejecución;
  las acciones modificadoras siguen bloqueadas.
- `/api/backups/*`: prepara, verifica y prueba restore; por defecto es memoria,
  o usa el provider de filesystem solo con raíces declaradas.
- `/api/deployments/*`: ejecuta preflight sobre checks aportados por el
  cliente, registra aprobación y puede usar el release provider de filesystem
  explícitamente declarado; cuando el provider expone un post-validator, también exige
  evidencia verificada del artefacto y del puntero `CURRENT`. Sin provider o
  sin validación posterior permanece bloqueado o fallido de forma cerrada.
- `/api/rollbacks/*`: registra aprobación independiente y puede cambiar el
  puntero `CURRENT` del release provider de filesystem declarado; sin él
  permanece bloqueado.
- `/api/incidents/*`: mantiene un ciclo de incidentes en memoria; `--lab-mode`
  puede conservar su metadata en JSON. `analyze` solo registra una hipótesis
  y etiquetas aportadas por el usuario.
- `/api/validation/evaluate`, `/api/knowledge/register`, `/api/impact/analyze`,
  `/api/drift/compare`, `/api/agents/plan` y `/api/changes/propose` aceptan
  únicamente metadatos explícitos y producen contratos auditados sin ejecutar
  sondas, tests, agentes ni cambios.
- `GET /api/audit`, `/api/approvals`, `/api/operations`, `/api/backups`,
  `/api/deployments`, `/api/rollbacks`, `/api/incidents`, `/api/monitoring` y
  `/api/chat/messages`, `/api/validation`, `/api/knowledge`, `/api/impact`,
  `/api/drift`, `/api/agents` y `/api/changes` requieren permisos.
- `GET /api/execution` requiere permiso de Core Operator y muestra únicamente
  el estado de la frontera `ControlledExecutionService`. No existe un POST
  público para fabricar una decisión elegible desde el navegador.

La interfaz web añade un banco de trabajo autenticado para preparar el ciclo
de backup, registrar snapshots, abrir incidentes, preparar el
preflight de despliegue, preparar rollback y recorrer la cadena de aprobación.
La vista de aprobaciones permite crear una solicitud, aprobarla o denegarla
con una cuenta independiente y evaluar el pipeline READ_SAFE completo. Las
vistas de despliegue y rollback permiten recorrer sus transiciones
contractuales; los providers de laboratorio solo se activan con flags de raíces
declaradas, aprobación independiente y backup verificado. Sin esos providers,
la evaluación termina en `blocked_by_default`; no son botones de ejecución de
producción.

La vista **Proyectos** permite consultar el catálogo y solicitar la colección
READ_SAFE. Solo presenta campos estructurados; nunca muestra la salida de Git
ni ofrece controles de rama, push, merge o despliegue.

## Garantías

- Bind por defecto en `127.0.0.1`.
- Solo biblioteca estándar de Python y código del repositorio.
- Sin shell, `os.system`, `eval`, `exec` ni `sudo`; los únicos adapters que
  invocan procesos son los providers explícitos de tests, builds y Codex, con
  argv declarado, `shell=False`, límites de tiempo y salida descartada.
- No se leen secretos, `.env`, logs, backups, bases de datos ni servicios.
- No se escribe estado de aplicación ni auditoría a disco por defecto; las
  rutas persistentes requieren opt-in explícito y validación segura.
- En el arranque por defecto `liveData` permanece en `false` y la ejecución
  real permanece `blocked_by_default`. `--lab-mode` habilita únicamente
  fixtures y recolección sintética; `--read-safe-inventory` habilita aparte la
  allowlist de Fase 1 para una colección READ_SAFE explícita. Ninguna opción
  convierte el perfil de laboratorio en producción.
- El API no acepta una decisión `eligible_for_controlled_execution` enviada por
  el cliente. Esa decisión debe proceder del `ExecutionGate` en memoria; la
  frontera pública solo expone su estado y registros.
- El endpoint de ejecución recibe únicamente una referencia de aprobación y
  reconstruye la decisión internamente; no acepta decisiones serializadas del
  navegador.
- Solicitudes sensibles requieren aprobación independiente del solicitante.
- La interfaz mantiene fallback al JSON estático si la API no está disponible.
- Los datos de auditoría se rechazan si contienen secretos o `stdout`/`stderr`
  crudos.

## Pendiente antes de producción

1. Revisión de seguridad del almacén persistente de identidades, gestión de
   roles y 2FA real.
2. HTTPS terminado correctamente, cookies Secure y protección de cabeceras.
3. Retención y recuperación operativa del workflow completo; el perfil de
   laboratorio ya conserva identidad, auditoría JSONL, aprobaciones, snapshots,
   incidentes y planes de backup/deployment/rollback en JSON opt-in con límites,
   pero aún no constituye una base de datos transaccional.

`GET /api/readiness` centraliza estos criterios y solo puede devolver `GO` si
todos están presentes. El endpoint no concede permisos ni cambia la
configuración. La autorización humana puede documentarse con el argumento
opt-in `--activation-manifest /ruta/activation.json`. Ese manifiesto JSON
versionado es metadata-only y debe conservar la instantánea de
`policy_version`, `effective_permissions`, actor/roles, alcance, providers,
solicitante, aprobador y caducidad. El loader exige solicitante y aprobador
distintos, decisión `approved`, timestamps con zona horaria y una vigencia
máxima de 24 horas. No acepta secretos, `stdout`/`stderr`, rutas de logs o
backups, ni enlaces simbólicos. Un documento válido no selecciona providers,
permisos ni servicios, pero el servidor lo usa como gate por petición: fuera de
laboratorio, todo provider live requiere un manifiesto activo, su identidad en
`provider_ids`, el permiso de la operación en `effective_permissions` y una
comprobación de vigencia/scope en cada request. Los flags
de providers live también se validan al arrancar y requieren que cada
identificador solicitado aparezca en `provider_ids`; readiness además verifica
que el manifiesto cubra todos los permisos requeridos por el grafo live.
La persistencia completa de workflows se puede agrupar con
`--state-root /ruta/externa/estado`, una raíz absoluta existente fuera del
repositorio y de rutas protegidas. El transporte HTTPS se valida por separado:
`--https-terminated` solo registra una terminación externa revisada y
`--secure-cookies` marca las cookies; el proceso no configura TLS.

Para habilitar únicamente monitorización READ_SAFE durante una prueba
controlada, se puede añadir `--read-safe-monitoring`. Ese adapter usa la
allowlist de Fase 1 para memoria y disco y calcula carga de forma local; no
lee logs, procesos, puertos, secretos o servicios, y no modifica el sistema.
Sin flags adicionales, la opción no habilita backups, despliegues, rollback ni
ejecución controlada.

### Inventario READ_SAFE explícito

El flag `--read-safe-inventory` conecta `ReadSafeInventoryProvider` con
`collect_read_safe_inventory`. El provider solo acepta los identificadores de
la allowlist READ_SAFE, descarta salida no aprobada mediante los normalizadores
de Fase 1, valida `schemas/inventory.schema.json` y ejecuta el escaneo de
secretos. `InventoryService` vuelve a validar la forma y el escaneo, registra
solo metadatos de la solicitud y conserva el objeto en memoria. No hay
persistencia automática ni creación de `INVENTORY.json`; los datos sensibles,
logs, backups, bases de datos y servicios siguen fuera del alcance. Por defecto
el resultado solo vive en memoria; `--inventory-state` permite conservar el
último resultado validado mediante `JsonMetadataStore`, con validación de ruta,
escritura atómica y permisos restrictivos. El perfil de laboratorio usa
`state/inventory-workflow.json`. Esto no es `INVENTORY.json` ni una persistencia
operativa de producción.

### Backup de filesystem con raíz declarada

El servidor puede recibir un proveedor de backup de filesystem únicamente si
se indican simultáneamente `--backup-source-root` y
`--backup-destination-root`. Son raíces absolutas, existentes, separadas y
declaradas por quien arranca el proceso. El proveedor:

- crea archivos `.tar.gz` sin sobrescribir destinos existentes;
- recorre solo archivos regulares UTF-8 bajo la raíz de origen;
- limita el número y tamaño de archivos y el tamaño total;
- rechaza symlinks, traversal, `.env`, `.git`, `AGENTS.md`, `INVENTORY.json`,
  logs, backups y contenido con aspecto de secreto o salida cruda;
- calcula checksum, verifica el archivo y realiza una prueba de restauración
  dentro de un directorio temporal sin modificar el origen.

Esta opción es un adapter acotado. No descubre rutas, no lee backups
existentes automáticamente y no convierte el servidor en un sistema de
backup de producción. La retención, cifrado externo, almacenamiento remoto,
rotación y recuperación operativa requieren otra revisión y un proveedor
específico.

La autenticación incluye un verificador TOTP RFC 6238 inyectable en memoria.
La semilla se entrega desde un gestor de identidad externo al construir la
aplicación, nunca desde el repositorio, `.env`, logs o argumentos del proceso.
La API ya acepta el campo `otp` en login. Para una cuenta de laboratorio con
2FA se usa `--bootstrap-2fa-user USUARIO[:ROL]`: el arranque solicita la
contraseña y la semilla TOTP por prompts ocultos, inyecta la semilla solo en
memoria y nunca la guarda en argumentos, estado, logs ni repositorio. Si la
cuenta ya existe con 2FA, la semilla debe volver a inyectarse en cada arranque;
si existe sin 2FA, el arranque falla cerrado y no cambia silenciosamente su
política de autenticación.

El chat IA compatible se habilita con `--chat-endpoint` y
`--chat-api-key-prompt`. El provider exige HTTPS para endpoints remotos,
limita el tamaño de respuesta, no registra la clave y rechaza respuestas que
no sean planes JSON estructurados o que contengan secretos/salida cruda. La
respuesta nunca puede marcarse como ejecutable; las solicitudes de riesgo alto
siguen requiriendo aprobación independiente.

### Releases y rollback de filesystem en laboratorio

La opción `--release-artifact-root` junto con `--release-root` habilita el
proveedor `declared-filesystem-release`. Sus límites son deliberados:

- cada `commit` identifica un directorio de artefacto ya preparado;
- cada release se copia una sola vez bajo el proyecto declarado;
- solo se aceptan archivos regulares UTF-8 acotados y sin contenido sensible;
- el estado activo se representa por un archivo `CURRENT` dentro de la raíz
  de releases;
- el rollback aprobado solo cambia `CURRENT` a una release existente;
- el deployment de laboratorio puede exigir un post-check que confirma el
  artefacto y el puntero `CURRENT` antes de marcarlo `VERIFIED`;
- no se inicia ni detiene ningún servicio y no se modifica Apache, PM2,
  systemd, Docker ni bases de datos.

La API puede ejecutar estos providers únicamente después de preflight,
aprobación independiente y validación de evidencia. Las raíces declaradas
permiten una ejecución acotada fuera del perfil de laboratorio, pero no
sustituyen un pipeline de despliegue, health checks externos, locking
distribuido, retención de releases ni un rollback de infraestructura. No hay
ninguna integración con gestores de servicios ni con la infraestructura del
VPS.

La ejecución acotada READ_SAFE se puede habilitar por separado con
`--read-safe-execution`. Requiere crear una aprobación mediante
`POST /api/approvals/request`, aprobarla con otro usuario mediante
`POST /api/approvals/approve` y después evaluar
`POST /api/execution/evaluate`. Solo acepta `action=read` y comandos de la
allowlist READ_SAFE; no admite `sudo`, secretos ni acciones modificadoras.
La sesión que evalúa una orden READ_SAFE necesita `RUN_READ_SAFE`; las clases
READ_SENSITIVE y READ_PRIVILEGED nunca heredan ese permiso y se resuelven con
sus permisos específicos antes de quedar bloqueadas por el contrato actual.
Las acciones modificadoras mantienen la exigencia de `DEPLOY`, pero la policy
y el gate las rechazan y no llegan al proveedor.
4. Adaptadores reales para observabilidad y despliegue de servicios, cada uno
   con allowlist, sandbox, límites de tiempo, validación posterior y rollback.
   Los adapters actuales cubren únicamente métricas READ_SAFE y raíces de
   filesystem declaradas; no controlan servicios ni infraestructura.
5. Revisión humana de seguridad antes de activar cualquier ejecución.

## Estado frente al documento maestro

Esta entrega hace operativa la V2 en modo local simulado: permite iniciar una
sesión temporal, consultar la shell, planificar conversaciones y operaciones,
registrar aprobaciones, preparar catálogos de backup, prevalidar despliegues,
registrar rollback, mantener incidentes, evaluar checks y consultar auditoría
metadata-only. Los workflows permanecen en memoria por defecto; identidad,
auditoría y aprobaciones pueden persistirse mediante las rutas opt-in
documentadas. Los contratos V3 también pueden persistirse en
`v3-insights.json` dentro de la raíz `--state-root`, con carga validada y
escrituras atómicas. Los informes de validación se conservan en
`validation.json` con la misma frontera metadata-only.

No equivale todavía a una instalación operativa sobre el VPS. Siguen fuera de
alcance la provisión externa de semillas 2FA, el inventario real, la lectura de
servicios/logs, los adaptadores de deploy/rollback sobre servicios y la
ejecución modificadora; los providers de chat, monitorización READ_SAFE,
backup, builds, Codex y releases solo cubren los alcances explícitos
documentados. La
persistencia del workflow implementada en laboratorio es atómica pero no
ofrece todavía locking distribuido, retención ni recuperación de producción;
esto incluye `v3-insights.json`. Persistir un contrato V3 no cambia sus
estados ni habilita autonomía, conexiones o recuperación real.
Activar cualquiera de ellos exige una fase separada con revisión de seguridad,
allowlist, backup y restore probados, validación posterior, rollback y
autorización explícita.

La implementación actual hace funcional la aplicación local y sus contratos,
pero no afirma que el VPS esté inventariado, monitorizado o desplegado desde
la web. Las capacidades con proveedores solo se consideran activables cuando
el adapter se inyecta explícitamente, pasa validación de evidencia y existe
una revisión independiente de seguridad, permisos, backup, restore, validación
posterior y rollback.
