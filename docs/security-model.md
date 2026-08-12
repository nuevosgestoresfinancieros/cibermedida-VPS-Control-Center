# Modelo de Seguridad

## Objetivo

La seguridad del Control Center se basa en autonomia controlada, privilegio minimo, trazabilidad y autorizacion explicita para operaciones sensibles.

## Principios

- Ninguna IA tendra mas privilegios que los necesarios.
- Chat no ejecuta shell directo.
- El Supervisor no modifica infraestructura.
- El Executor Controlado es el unico componente cercano al sistema operativo.
- El Policy Engine debe aplicar reglas verificables, no solo instrucciones en lenguaje natural.
- Produccion requiere controles adicionales.
- Las operaciones sensibles requieren backup, validacion y autorizacion segun riesgo.

## Capas

```text
Frontend Web
  -> Backend Control Center
  -> Supervisor / Planner
  -> Policy Engine
  -> Operator Service
  -> Restricted Executor
  -> VPS
```

## Seguridad web prevista

- HTTPS.
- Autenticacion.
- Sesiones seguras.
- 2FA.
- Roles.
- Permisos.
- Proteccion CSRF.
- Cookies seguras.
- Rate limiting.
- Auditoria.

## Roles iniciales

- `ADMIN`
- `OPERATOR`
- `DEVELOPER`
- `VIEWER`

## Permisos conceptuales

- `VIEW_SERVER`
- `VIEW_LOGS`
- `RUN_DIAGNOSTICS`
- `RUN_TESTS`
- `CREATE_BRANCH`
- `MODIFY_CODE`
- `CREATE_BACKUP`
- `DEPLOY`
- `ROLLBACK`
- `MANAGE_SECURITY`
- `MANAGE_USERS`
- `MANAGE_POLICIES`

## Gestion de secretos

Los secretos no deben exponerse al modelo ni a logs salvo necesidad estricta y con minimizacion.

Incluye:

- `.env`;
- API keys;
- tokens;
- passwords;
- claves privadas;
- credenciales de bases de datos.

## Operaciones nunca automaticas

- Borrar bases de datos.
- Eliminar backups.
- Modificar claves SSH.
- Cambiar usuarios privilegiados.
- Modificar firewall de forma destructiva.
- Formatear discos.
- Ejecutar acciones irreversibles.
