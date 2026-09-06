# Plan de implementación escalonado

Este plan organiza el trabajo restante sin convertir el Control Center en un
ejecutor remoto por defecto. Cada etapa debe nacer en una rama `agent/...`,
mantener pruebas y cerrar con revisión humana. Mientras tanto, la frontera de
ejecución permanece `blocked_by_default`.

## Tramo completado

1. **Fases 0–2:** diseño, inventario READ_SAFE, Core Operator, policy,
   aprobación, persistencia opt-in, plan aprobado, dry-run, gate y contrato
   de executor bloqueado.
2. **Fases 3.0–3.6:** shell web, datos mock, navegación, accesibilidad,
   integración API local, autenticación de laboratorio y workflows
   metadata-only.
3. **Integración vNext:** manifiesto común de operación, scope obligatorio,
   hashes, catálogos estructurados, dashboard visual y documentación de
   brechas.

## Próximos incrementos

### 1. Endurecimiento de laboratorio

- Pruebas de contrato HTTP para cada flujo y cada estado de rechazo.
- Comprobación visual automatizada en escritorio y móvil cuando el runner esté
  disponible.
- Validación de tipos, límites y redacción de todos los catálogos.
- Documentar fixtures y limpiar estado temporal al finalizar las pruebas.

### 2. Identidad y autorización de producción

- Integrar un proveedor de identidad revisado, 2FA, revocación y rotación.
- Terminar HTTPS en un proxy revisado; cookies seguras, cabeceras y rate limit.
- Mantener separación solicitante/aprobador y snapshots inmutables.
- Verificar `policy_version`, `effective_permissions`, scope y hashes en cada
  uso de una aprobación.

### 3. Persistencia operativa segura

- Elegir almacenamiento durable para audit, approval, operation y métricas.
- Añadir locking distribuido, retención, exportación, cifrado y recuperación.
- Probar restauración y detectar corrupción sin cargar datos sensibles.

### 4. Providers READ_SAFE seleccionados

- Incorporar solo inventario, proyectos y monitorización que tengan allowlist,
  timeout, cuenta mínima y revisión humana.
- Separar fuente `declared`, `discovered` y `observed`, con confianza y fecha.
- Nunca devolver stdout/stderr crudos ni crear `INVENTORY.json` automático.

### 5. Ejecución controlada futura

Solo se puede abrir esta etapa si existe un GO de producción que demuestre
identidad, HTTPS, auditoría recuperable, backup verificado, rollback probado,
scope explícito y autorización humana vigente. El primer provider debe:

- aceptar operaciones tipadas, no shell libre;
- requerir un `OperationManifest` inmutable y aprobación independiente;
- revalidar policy, riesgo, hashes, actor, branch, commit, backup e impacto;
- ejecutar en sandbox con allowlist, timeout y límites de recursos;
- validar postcondiciones y cerrar con auditoría metadata-only;
- quedar deshabilitado por defecto y tener rollback verificable.

## Criterios de salida

Una fase se considera terminada solo cuando el código, los tests, la
documentación, la evidencia de seguridad y el estado Git coinciden. Un
dashboard atractivo no es evidencia de que un provider live sea seguro.
