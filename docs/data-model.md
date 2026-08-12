# Modelo de Datos

Este documento define entidades logicas previstas. No contiene datos reales del VPS.

## Estado logico

El sistema mantendra informacion estructurada sobre:

- server;
- projects;
- services;
- deployments;
- backups;
- incidents;
- changes;
- agents;
- policies;
- metrics;
- audit.

## Entidades previstas

- `users`
- `roles`
- `permissions`
- `projects`
- `services`
- `servers`
- `deployments`
- `backups`
- `incidents`
- `changes`
- `audit_logs`
- `metrics`
- `alerts`
- `agents`
- `agent_runs`
- `policies`
- `approvals`
- `conversations`
- `messages`

## Proyecto

Campos previstos para cada proyecto:

- `id`
- `name`
- `path`
- `repository`
- `branch`
- `production_branch`
- `frontend`
- `backend`
- `framework`
- `runtime`
- `database`
- `service`
- `domain`
- `health_endpoint`
- `backup_policy`
- `deployment_method`
- `autonomy_level`

## Backup

Campos previstos:

- `id`
- `project`
- `timestamp`
- `type`
- `source`
- `destination`
- `size`
- `checksum`
- `verified`
- `restore_tested`
- `retention`
- `created_by`

## Incidente

Campos previstos:

- `id`
- `timestamp`
- `project`
- `service`
- `severity`
- `symptom`
- `detected_by`
- `last_deployment`
- `suspected_cause`
- `diagnostic_steps`
- `actions`
- `resolution`
- `rollback`
- `closed_at`

## Auditoria

Campos previstos:

- `timestamp`
- `user`
- `agent`
- `project`
- `action`
- `risk`
- `command`
- `authorization`
- `backup`
- `commit`
- `result`
- `duration`

## Inventario

El inventario real se generara en Fase 1, en modo solo lectura. El contrato inicial esta definido en [../schemas/inventory.schema.json](../schemas/inventory.schema.json).
