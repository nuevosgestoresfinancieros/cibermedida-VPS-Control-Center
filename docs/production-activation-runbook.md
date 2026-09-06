# Runbook De Activacion De Produccion

Este runbook describe la activacion futura del grafo completo. No es una
autorizacion para ejecutarlo ahora. Requiere revision humana independiente,
terminacion HTTPS ya operativa, una identidad de produccion revisada y
providers aprobados para las rutas concretas.

## Precondiciones

- El directorio de estado existe fuera del repositorio y tiene permisos
  restrictivos.
- El proxy HTTPS externo esta configurado y probado antes de arrancar el
  proceso.
- El proveedor de chat tiene endpoint HTTPS revisado; su clave se introduce
  mediante prompt y nunca se escribe en argumentos, estado o logs.
- La identidad que solicita y la que aprueba la activacion son distintas.
- El manifiesto contiene una instantanea de politica, permisos efectivos,
  alcance, providers y caducidad de 24 horas como maximo.
- Los roots de backup y releases han sido declarados y revisados de forma
  independiente.

El adapter Codex live no se considera disponible por el mero hecho de que la
UI o el provider sintético funcionen. Si se solicita en producción, debe
identificarse como `codex-provider` en el manifiesto y someterse a una revisión
separada de aislamiento, límites de repositorio, auditoría y autorización. La
composición usa `--codex-project NOMBRE=/ruta` y fuerza sandbox read-only.

## Manifiesto De Activacion

El fichero es JSON metadata-only. Los `provider_ids` deben coincidir con todos
los adapters live que se soliciten al arrancar:

```json
{
  "version": 1,
  "manifest_id": "activation-2026-09-01-001",
  "decision": "approved",
  "requester": "operador-declarado",
  "requester_role": "OPERATOR",
  "approver": "responsable-declarado",
  "approver_role": "ADMIN",
  "policy_version": "policy-2026-09",
  "effective_permissions": [
    "VIEW_CORE_OPERATOR",
    "VIEW_DASHBOARD",
    "VIEW_MONITORING",
    "VIEW_INVENTORY_METADATA",
    "VIEW_BACKUPS",
    "VIEW_PROJECTS",
    "RUN_READ_SAFE",
    "RUN_DIAGNOSTICS",
    "RUN_TESTS",
    "RUN_BUILDS",
    "CREATE_BACKUP",
    "APPROVE_OPERATION",
    "DEPLOY",
    "ROLLBACK"
  ],
  "scope": ["production-readiness", "declared-project"],
  "provider_ids": [
    "phase1-read-safe-monitoring",
    "phase1-read-safe-execution",
    "phase1-read-safe-inventory",
    "repository-tests",
    "declared-build",
    "codex-provider",
    "openai-compatible-chat",
    "declared-filesystem-backup",
    "declared-filesystem-release"
  ],
  "approved_at": "2026-09-05T10:00:00+00:00",
  "expires_at": "2026-09-05T18:00:00+00:00"
}
```

No se deben añadir claves de API, contrasenas, tokens, claves SSH, salidas de
comandos ni `stdout`/`stderr`. El loader rechaza esos valores, autoaprobaciones,
timestamps sin zona horaria, enlaces simbolicos y rutas dentro de `.env`,
`.git`, `logs` o `backups`.

## Composicion Explícita

El siguiente ejemplo es una plantilla operativa. Los paths son placeholders y
deben revisarse antes de usarse:

```text
python3 -m api.readonly_server \
  --host 127.0.0.1 --port 8766 \
  --secure-cookies --https-terminated \
  --state-root /srv/cibermedida/control-center-state \
  --audit-max-bytes 16777216 \
  --audit-retention-files 3 \
  --activation-manifest /srv/cibermedida/control-center-state/activation.json \
  --bootstrap-2fa-user admin:ADMIN \
  --bootstrap-2fa-user operador:OPERATOR \
  --chat-endpoint https://chat-provider.example/v1/chat/completions \
  --chat-api-key-prompt \
  --read-safe-monitoring \
  --read-safe-execution \
  --read-safe-inventory \
  --run-repository-tests \
  --build-root /srv/cibermedida/declared-project \
  --build-profile "production=python3 -m py_compile app.py" \
  --codex-project control-center=/srv/cibermedida/declared-project \
  --backup-source-root /srv/cibermedida/declared-source \
  --backup-destination-root /srv/cibermedida/declared-backups \
  --release-artifact-root /srv/cibermedida/release-artifacts \
  --release-root /srv/cibermedida/releases
```

El proceso no configura el proxy, no reinicia servicios, no descubre roots y
no ejecuta este comando durante una revisión de código. La auditoría rota por
tamaño dentro de la ruta declarada y conserva el número acotado de segmentos
indicado; la retención definitiva, cifrado y copia de recuperación deben
quedar cubiertos por la infraestructura operativa aprobada. Cada provider se
habilita solo porque su flag fue solicitado y porque el manifiesto activo lo
enumera. Cada request a un provider live vuelve a comprobar que el manifiesto
no haya caducado y que el provider siga dentro de `provider_ids`; al caducar o
retirarse el scope, la API responde bloqueada. `--state-root` crea únicamente
estados JSON/JSONL metadata-only; no crea `INVENTORY.json`.

Cada opción `--bootstrap-2fa-user` solicita la contraseña y la semilla TOTP de
forma interactiva. No se deben introducir credenciales, semillas ni claves en
los argumentos del proceso, en el manifiesto o en archivos de estado.

## Verificacion

Después del arranque, una identidad autorizada consulta `GET /api/readiness`.
El resultado debe ser `GO` y no debe contener checks bloqueantes. Un `NO_GO`
obliga a detener la activacion y corregir la causa; no se debe compensar con
un flag adicional ni con controles de la UI.

El check `activation_scope` debe pasar además de `human_authorization`: el
manifiesto debe declarar todos los `provider_ids` live solicitados y los
permisos efectivos necesarios para sus rutas. Si falta uno, las peticiones
correspondientes quedan bloqueadas aunque el manifiesto todavía no haya
caducado.

La consulta de readiness no ejecuta comandos ni concede permisos. Incluso con
`GO`, toda operación sensible conserva PolicyEngine, aprobación independiente,
backup verificado, validación posterior y rollback. El ControlledExecutor no
debe recibir una habilitación implícita por el mero hecho de consultar el
endpoint.

## Reversion

La activacion se revierte deteniendo el proceso mediante el procedimiento
operativo aprobado y retirando el manifiesto o dejando que caduque. La
configuracion de systemd, Apache/Nginx, firewall, base de datos y secretos
queda fuera de este repositorio y requiere un cambio operativo separado.
