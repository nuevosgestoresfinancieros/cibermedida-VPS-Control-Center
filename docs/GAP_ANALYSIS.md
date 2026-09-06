# Análisis de brechas frente a las mejoras del Control Center

La siguiente matriz evita confundir contratos de laboratorio con capacidades
operativas de producción. El estado de seguridad por defecto es
`blocked_by_default` hasta que exista una activación humana verificable.

| Área del documento | Implementación actual | Brecha / condición de cierre |
| --- | --- | --- |
| Supervisor y arquitectura por capas | API y servicios separados por responsabilidad | Falta un despliegue productivo con límites de red y proceso. |
| Operation manifest | Implementado con scope, estados y hashes | Persistencia distribuida, locking y recuperación externa pendientes. |
| Planificación y dry-run | Policy, aprobación, plan, dry-run y gate conectados | Falta una ejecución real controlada, que debe ser un proyecto separado. |
| Aprobación | Snapshot de actor, rol, policy, permisos, plan y expiración | Falta proveedor de identidad/2FA y operación de aprobación persistente de producción. |
| Inventario | READ_SAFE explícito, schema y clasificación de fuente/confianza | Revisión independiente antes de leer cualquier host real. |
| Knowledge/Digital Twin | Registros declarados, relaciones y análisis V3 metadata-only | Falta descubrimiento autorizado y reconciliación con evidencia live. |
| Impact analysis | Impacto, dependencias, downtime y riesgo se transportan en el plan | Falta validar dependencias reales y ejecutar una revisión humana de impacto. |
| Backups | Contrato, checksum, verify y restore test en filesystem de laboratorio | Falta almacenamiento, cifrado, retención, locking y restore probado en producción. |
| Deployments | Preflight, release aislada y estados de pipeline | Falta proveedor de producción, health checks externos y rollback operacional autorizado. |
| Rollback | Cambio de puntero `CURRENT` en fixtures | No restaura servicios, DB ni infraestructura reales. |
| Monitoring | Snapshots, histórico y anomalías acotadas | Falta agente READ_SAFE revisado, almacenamiento histórico y alertas controladas. |
| Incidents | Estados, relaciones, hipótesis y resolución metadata-only | Falta correlación live, notificación y playbooks aprobados. |
| Audit | Eventos redactados, JSONL opt-in, rotación y campos del manifiesto | Falta almacén durable, retención aprobada, exportación y control de acceso operativo. |
| Chat IA | Planificador local y provider externo opt-in | Falta revisión de proveedor, minimización de contexto y contrato de disponibilidad. |
| Codex / Testing / Builds | Providers declarados, argv acotado y salida descartada | Falta firma de artefactos, runners aislados y política de consumo en producción. |
| Web Control Center | UI en castellano, dashboard visual, auth/CSRF y fallback seguro | Falta SSO/2FA, HTTPS, autorización de proxy y datos live seleccionados. |
| Seguridad de infraestructura | Bloqueos por defecto y no acceso a servicios | No existe integración con firewall, SSH, systemd, Docker, DB o logs. |

## Riesgos abiertos prioritarios

1. Activar por accidente un provider live sin evidencia humana, alcance y
   persistencia adecuados.
2. Tratar datos mock de salud, proyectos o monitorización como datos reales.
3. Reutilizar un approval o plan después de cambiar policy, actor, comando,
   branch, backup o impacto.
4. Exponer el servidor local sin HTTPS, cookies seguras, 2FA, rate limiting y
   control de red.
5. Perder la trazabilidad por no rotar, bloquear o recuperar el estado de
   auditoría.

## Criterio de prioridad

No se debe cerrar una brecha de producción añadiendo un bypass en la UI. Cada
capacidad live debe entrar por provider explícito, allowlist, límites de
tiempo, validación posterior, auditoría y rollback probado.
