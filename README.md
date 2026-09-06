# Cibermedida VPS Control Center

Cibermedida VPS Control Center es el proyecto para construir una plataforma inteligente de administracion, desarrollo, seguridad y operaciones DevOps para el VPS de Cibermedida.

La especificacion funcional maestra es [Cibermedida VPS Control Center.md](./Cibermedida%20VPS%20Control%20Center.md). Este repositorio debe evolucionar por fases y con produccion protegida.

## Estado

- Arquitectura funcional: definida en la especificacion maestra.
- Fase 1 READ_SAFE: completada para el subconjunto minimo autorizado.
- Fase 2 Core Operator: completada; el `ControlledExecutor` permanece bloqueado por defecto.
- Fase 3.6: web en castellano integrada con una API local segura y servicios de
  planificación, autorización y auditoría en memoria.
- V3 metadata-only: gemelo digital, correlación histórica, análisis predictivo,
  autonomía por proyecto, catálogo multi-servidor y planes de recuperación.
  Con `--state-root`, esos registros se conservan en `v3-insights.json`,
  siempre como metadata-only y de forma opt-in.
- Inventario READ_SAFE: disponible solo con `--read-safe-inventory`; no se
  ejecuta por defecto, no acepta comandos arbitrarios y no crea `INVENTORY.json`.
- Cambios sobre produccion: ninguno.

La opción --read-safe-projects habilita únicamente la colección READ_SAFE de
rama, estado limpio/sucio y HEAD Git del proyecto declarado. Requiere
RUN_READ_SAFE, no devuelve stdout/stderr, no crea ramas y no hace push, merge
ni llamadas a Codex CLI. El catálogo requiere VIEW_PROJECTS cuando existe un
provider explícito; sin él permanece mock y bloqueado por defecto.

## Principios

- Autonomia controlada.
- Trazabilidad completa.
- Produccion protegida.
- Separacion entre planificar, autorizar, ejecutar y validar.
- Git obligatorio para nuevas funcionalidades.
- Backups verificados antes de cambios sensibles.
- Ninguna operacion tecnicamente posible se considera automaticamente autorizada.

## Estructura documental inicial

- [AGENTS.md](./AGENTS.md): reglas para agentes que trabajen en este repositorio.
- [docs/architecture.md](./docs/architecture.md): arquitectura conceptual.
- [docs/security-model.md](./docs/security-model.md): modelo de seguridad.
- [docs/policies.md](./docs/policies.md): politicas de ejecucion y aprobacion.
- [docs/data-model.md](./docs/data-model.md): entidades logicas previstas.
- [docs/agents.md](./docs/agents.md): agentes previstos y responsabilidades.
- [docs/phase-0.md](./docs/phase-0.md): alcance de Fase 0.
- [docs/phase-1-inventory.md](./docs/phase-1-inventory.md): preparacion documental de inventario.
- [policies/command-allowlist.md](./policies/command-allowlist.md): allowlist inicial conceptual.
- [policies/risk-levels.md](./policies/risk-levels.md): niveles de riesgo.
- [schemas/inventory.schema.json](./schemas/inventory.schema.json): contrato documental para inventario futuro.
- [docs/phase-2-core-operator.md](./docs/phase-2-core-operator.md): cierre real de Fase 2.
- [docs/phase-3-authz-contract.md](./docs/phase-3-authz-contract.md): contrato futuro de autenticacion y autorizacion.
- [docs/phase-3-readonly-integration.md](./docs/phase-3-readonly-integration.md): API local y web read-only integrada.
- [docs/integration-status.md](./docs/integration-status.md): matriz de fases, laboratorio y requisitos de produccion.
- [docs/production-activation-runbook.md](./docs/production-activation-runbook.md): precondiciones y composición explícita para producción.
- [docs/CURRENT_ARCHITECTURE.md](./docs/CURRENT_ARCHITECTURE.md): arquitectura real de la integración vNext.
- [docs/UI_AUDIT.md](./docs/UI_AUDIT.md): auditoría visual, accesibilidad y límites de la UI.
- [docs/GAP_ANALYSIS.md](./docs/GAP_ANALYSIS.md): brechas frente a la mejora funcional.
- [docs/IMPLEMENTATION_PLAN.md](./docs/IMPLEMENTATION_PLAN.md): plan de evolución y criterios de salida.

## Ejecutar la web integrada

Desde la raiz del repositorio:

```text
python3 -m api.readonly_server --host 127.0.0.1 --port 8766
```

Abre `http://127.0.0.1:8766/`. El servidor expone datos mock y contratos de
seguridad; por defecto no ejecuta inventario, comandos, despliegues ni acciones
sobre servicios. Si la API no esta disponible, la web conserva un fallback
estatico.
Para laboratorio se pueden añadir `--auth-state /ruta/users.json`,
`--audit-path /ruta/audit.jsonl` y `--approval-state /ruta/approvals.json`;
las rutas son opt-in y solo almacenan hashes o metadata auditada de identidad,
auditoría y aprobaciones.
La auditoría JSONL rota al alcanzar `--audit-max-bytes` (16 MiB por defecto) y
conserva tres segmentos rotados por defecto; ambos límites se pueden ajustar
con `--audit-max-bytes` y `--audit-retention-files`. Los segmentos siguen
siendo metadata-only, se validan al recargar y se escriben con permisos
restrictivos.
Para una composición no-lab con persistencia completa de workflows se puede
usar `--state-root /ruta/externa/estado`; debe ser un directorio absoluto ya
existente, fuera del repositorio, `.git`, `.env`, `logs` y `backups`. El proceso
crea allí únicamente los JSON/JSONL metadata-only de identidad, auditoría,
aprobaciones, conversación, inventario, tests, builds, Codex, validación, workflows y
contratos V3.
La aplicación acepta además un `TotpVerifier` inyectado por código para
usuarios marcados con 2FA; las semillas TOTP permanecen fuera del repositorio
y no se leen desde `.env`, logs ni argumentos del proceso.
La opción `--read-safe-monitoring` habilita solo métricas READ_SAFE acotadas
de memoria, disco y carga; no habilita ejecución ni cambios de producción.
La opción `--read-safe-execution` añade únicamente la frontera de ejecución
aprobada para comandos READ_SAFE; las acciones modificadoras siguen bloqueadas.
La opción `--read-safe-inventory` habilita la colección explícita del pipeline
READ_SAFE de Fase 1, valida el resultado contra el schema y lo conserva solo
en memoria. No se persiste `INVENTORY.json` y la colección requiere una cuenta
con `RUN_READ_SAFE`.
La opción `--run-repository-tests` habilita el Testing Agent acotado para el
target fijo `repository`. Descubre la suite local de `tests/test_*.py` en
proceso, aplica un límite de casos, descarta stdout/stderr y conserva solo
métricas metadata-only. Fuera de laboratorio requiere el manifiesto activo con
`repository-tests` y `RUN_TESTS`; no acepta comandos, rutas ni módulos del
cliente. El endpoint `POST /api/builds/run` usa perfiles de argv declarados al
arranque mediante `--build-root` y `--build-profile "TARGET=EXECUTABLE [ARG ...]"`;
requiere `declared-build` y `RUN_BUILDS` en el manifiesto, y nunca acepta el
comando desde la petición.
En `--lab-mode`, la interfaz también expone el provider `codex-synthetic` para
probar el contrato de análisis de Codex sin lanzar Codex CLI, leer contenidos ni
modificar repositorios. Fuera del laboratorio se puede usar el provider
`codex-provider` con `--codex-project NOMBRE=/ruta`; invoca Codex en sandbox
`read-only`, exige autorización explícita y conserva solo hallazgos acotados.
La preparación de producción puede recibir un manifiesto de autorización
humana explícito con `--activation-manifest /ruta/activation.json`. El fichero
debe ser JSON metadata-only con solicitante y aprobador distintos,
`policy_version`, `effective_permissions`, `scope`, `provider_ids`, decisión
`approved` y una ventana de vigencia máxima de 24 horas. El servidor valida el
documento y exige que sus `provider_ids` coincidan con los adapters live
solicitados. No activa providers por sí solo, no concede permisos y no ejecuta
operaciones. El manifiesto no se combina con
`--lab-mode`, no puede vivir bajo `.env`, `.git`, `logs` o `backups`, y se
rechaza si contiene secretos o `stdout`/`stderr` crudos.
Cuando un proxy externo ya termina HTTPS, `--https-terminated` permite
registrar esa evidencia en readiness; el proceso no configura TLS. Debe usarse
junto con `--secure-cookies` y solo después de revisar el proxy.
Para habilitar el chat IA con un endpoint compatible se usan
`--chat-endpoint https://...` y `--chat-api-key-prompt`; la clave se solicita
por terminal, se mantiene solo en memoria y las respuestas se reducen a planes
JSON no ejecutables. Sin esas opciones funciona el planificador local.
Para probar backups de archivos en un laboratorio aislado se pueden indicar
`--backup-source-root /ruta/origen` y `--backup-destination-root /ruta/destino`.
Ambas rutas deben ser absolutas, existentes, separadas y declaradas
explícitamente. El adaptador solo acepta archivos UTF-8 acotados, excluye
secretos, `.env`, `.git`, logs, backups e `INVENTORY.json`, no sobrescribe
archivos y prueba la restauración en un directorio temporal. No debe apuntarse
a una raíz operativa del VPS sin una revisión independiente.
Para una prueba de releases sin servicios se pueden indicar también
`--release-artifact-root /ruta/artefactos` y `--release-root /ruta/releases`.
El proveedor copia artefactos versionados seguros y actualiza únicamente un
puntero `CURRENT`; el rollback vuelve a apuntar a una release existente. No
reinicia procesos, no modifica Apache/PM2/systemd y no representa un deploy
productivo.

### Perfil integrado de laboratorio

Para probar el conjunto de capacidades en una sola ejecución, usa una raíz
externa al repositorio y una cuenta provisionada explícitamente:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8768 \
  --lab-mode --lab-root /tmp/cibermedida-control-center-lab \
  --bootstrap-username admin --bootstrap-role ADMIN
```

Para recorrer aprobaciones con dos identidades en el laboratorio, añade uno o
varios usuarios explícitos. La contraseña se solicita para cada cuenta y no se
incluye en la línea de comandos; los usuarios adicionales son `VIEWER` por
defecto:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8768 \
  --lab-mode --lab-root /tmp/cibermedida-control-center-lab \
  --bootstrap-username admin --bootstrap-role ADMIN \
  --bootstrap-user operador:OPERATOR \
  --bootstrap-user desarrollador:DEVELOPER
```

Para exigir 2FA a una cuenta de laboratorio, usa `--bootstrap-2fa-user
USUARIO[:ROL]`. El proceso solicitará la contraseña y la semilla TOTP mediante
prompts ocultos; la semilla no aparece en argumentos, no se escribe en el
estado JSON y solo permanece en memoria mientras el proceso está activo. En
arranques posteriores con un usuario ya existente hay que volver a inyectar su
semilla con la misma opción. No se puede convertir silenciosamente una cuenta
existente sin 2FA en una cuenta 2FA durante el arranque.

Ejemplo de laboratorio con administrador protegido por TOTP:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8770 \
  --lab-mode --lab-root /tmp/cibermedida-control-center-lab-2fa \
  --bootstrap-2fa-user admin:ADMIN \
  --bootstrap-user operador:OPERATOR
```

El proceso solicita la contraseña sin mostrarla y crea únicamente fixtures
inocuos bajo la raíz indicada: backup de filesystem, artefacto de release y
raíces separadas para releases. También crea dentro de `state/` los hashes de
identidad, la auditoría JSONL y las aprobaciones metadata-only, y habilita
monitorización y ejecución READ_SAFE sintéticas, sin consultar el host ni
invocar el executor. `--lab-mode` rechaza rutas explícitas de estado
o providers para evitar que se apunten por accidente a este repositorio o al
VPS. También conserva snapshots de monitorización, incidentes y planes de
backup, deployment y rollback en ficheros JSON metadata-only dentro de
`state/`, además de `builds.json`, `validation.json` y `v3-insights.json`, con escrituras atómicas. El último inventario sintético validado se
conserva en `state/inventory-workflow.json` dentro de la raíz aislada del
laboratorio; no se crea `INVENTORY.json`. No inicia servicios, no lee logs, no
consulta bases de datos y no ejecuta acciones modificadoras. El proveedor de chat sigue siendo el planificador local salvo
que se configure aparte un endpoint compatible y revisado.

## Flujo de trabajo Git

No se desarrollan nuevas funcionalidades directamente sobre `main`.

Flujo previsto:

```text
main
  -> agent/<funcionalidad>
  -> desarrollo
  -> tests
  -> build
  -> revision
  -> integracion
```

## Estado del bloque integrado

La integración local cubre autenticación temporal u opt-in persistente, TOTP
inyectable, chat determinista o un provider compatible con chat completions,
políticas, aprobaciones, auditoría, catálogos simulados, diagnósticos,
validación por checks aportados, Testing Agent, builds declarados, análisis
Codex read-only, ciclo de incidentes, monitorización READ_SAFE,
inventario READ_SAFE opt-in,
backups con checksum y restore test en raíces declaradas, y releases/rollback
por puntero `CURRENT` en laboratorio. La interfaz permite probar esos flujos
después de iniciar sesión. No ejecuta inventario salvo la opción READ_SAFE
explícita, no lee logs o servicios,
no reinicia procesos y no habilita cambios de producción. No hay cuenta por
defecto. Consulta
[docs/phase-3-readonly-integration.md](./docs/phase-3-readonly-integration.md)
antes de exponer el API fuera de loopback.

La sección **Inteligencia V3** de la web permite registrar esos contratos con
autenticación y CSRF. Solo acepta evidencia declarada, no descubre el VPS, no
abre conexiones y mantiene la autonomía y la recuperación en
`blocked_by_default`.
