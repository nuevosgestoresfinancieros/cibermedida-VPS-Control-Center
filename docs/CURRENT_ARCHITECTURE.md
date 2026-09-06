# Arquitectura actual del Control Center

Estado de referencia: integración local `agent/control-center-vnext`. Este
documento describe lo que existe en el repositorio; no concede permiso para
conectar el sistema a producción.

## Flujo implementado

```text
Web en castellano
    |
    v
API local / Supervisor de aplicación
    |
    +--> Auth + CSRF + roles
    +--> Knowledge / proyectos / inventario READ_SAFE
    +--> Policy + Risk + Operation Manifest
    |        |
    |        +--> Approval independiente
    |        +--> Dry-run metadata-only
    |        +--> Execution Gate
    |        +--> ControlledExecutor (blocked_by_default)
    |
    +--> Backup / Deployment / Rollback contracts
    +--> Monitoring / Incident / Audit metadata-only
    +--> Testing / Builds / Codex con providers explícitos
    |
    v
Estado en memoria o persistencia JSON/JSONL opt-in
```

La interfaz usa `GET /api/status` cuando la API local está disponible y cae
de forma segura a `web/readonly-shell/data/status.json`. La interfaz no llama
a servicios del sistema. Las acciones POST existentes exigen sesión, CSRF,
permiso, validación de entrada y el gate correspondiente; no son un shell
arbitrario.

## Componentes y responsabilidades

| Componente | Estado real | Límite actual |
| --- | --- | --- |
| Web Control Center | Integrada | UI en castellano, dashboard, navegación, búsqueda y datos mock/API local. |
| AuthService | Funcional en laboratorio | Estado en memoria u opt-in; falta proveedor de identidad de producción. |
| Policy/Risk | Funcional | Denegación por defecto para acciones modificadoras y privilegios. |
| OperationManifest | Funcional | Scope, estados, comandos declarados y hashes de integridad; no ejecuta. |
| Approval workflow | Funcional | Solicitante y aprobador distintos; estados y snapshot de autorización. |
| Dry-run / Execution Gate | Funcional | Reevalúa plan, riesgo, aprobación e integridad; solo metadata. |
| ControlledExecutor | Contrato funcional | Acepta únicamente elegibilidad válida y devuelve `blocked_by_default`. |
| Inventory | Provider READ_SAFE | Provider explícito; resultado validado y no crea `INVENTORY.json`. |
| Knowledge Engine | Metadata-only | Registra relaciones declaradas y gemelo digital; no descubre infraestructura. |
| Backup/Deployment/Rollback | Laboratorio | Fixtures y contratos seguros; no tocan servicios ni datos reales. |
| Monitoring/Incident | Snapshot/metadata-only | Evalúan evidencia aportada; no leen logs ni aplican mitigaciones. |
| Audit | En memoria o JSONL opt-in | Redacción, rotación y límites locales; falta operación distribuida de producción. |

## Manifiesto común de operación

Toda operación debe poder representarse con `OperationManifest`. Incluye
`operation_id`, proyecto, servidor, entorno, recurso, acción, solicitante,
agente, riesgo, estado, comandos y archivos declarados, servicios afectados,
dependencias, tests, backup, aprobación, rama, commit, rollback, resultado
esperado, validaciones, timestamps y hashes de operación, plan, aprobación y
ejecución.

Los hashes se recalculan cuando cambia el estado. Una aprobación o un plan no
pueden reutilizarse si cambia el snapshot vinculante. La API transporta estos
metadatos, pero no conserva stdout, stderr, secretos ni comandos construidos a
partir de texto libre.

## Providers

Los providers de inventario, monitorización, proyectos, tests, builds, Codex,
filesystem backup y releases se inyectan explícitamente al arrancar. La
configuración por defecto no abre red, no lee `.env`, no accede a logs,
backups, bases de datos o servicios y no persiste automáticamente.

El perfil `--lab-mode` usa fixtures externos al repositorio y permite recorrer
la integración sin consultar el VPS. Un provider live requiere además
permisos, manifiesto de activación humana, alcance compatible, HTTPS y
persistencia revisada; readiness permanece `NO_GO` hasta que esas condiciones
estén demostradas.

## Estado de despliegue

La aplicación está preparada para ejecución local o laboratorio, no para
exposición productiva. El servidor de ejemplo escucha en loopback y la UI se
puede abrir con:

```text
python3 -m api.readonly_server --host 127.0.0.1 --port 8770 --lab-mode --lab-root /tmp/cibermedida-control-center-lab --bootstrap-username admin --bootstrap-role ADMIN
```

La contraseña se solicita interactivamente. No se incluyen credenciales en el
repositorio ni en los argumentos.
