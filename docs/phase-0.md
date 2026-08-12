# Fase 0 - Diseno

## Objetivo

Crear la estructura documental minima del proyecto a partir de la especificacion maestra.

## Alcance incluido

- README del proyecto.
- Reglas para agentes.
- Arquitectura conceptual.
- Modelo de seguridad.
- Politicas iniciales.
- Modelo de datos logico.
- Definicion de agentes.
- Preparacion documental de Fase 1.
- Allowlist conceptual de comandos.
- Niveles de riesgo.
- Esquema JSON del inventario futuro.

## Alcance excluido

- Inventario real del VPS.
- Codigo ejecutable.
- Automatizaciones.
- Directorios operativos de runtime, estado, logs o auditoria.
- Instalacion de paquetes.
- Modificacion de servicios de produccion.
- Despliegues.
- Commits, push o integracion en `main` sin instruccion posterior.

## Criterios de aceptacion

- Los documentos existen en las rutas definidas.
- La especificacion maestra no se modifica.
- No se crean datos reales del VPS.
- No se crea `inventory/INVENTORY.json`.
- No se crean `src/`, `scripts/`, `runtime/`, `state/`, `audit/` ni `logs/`.
- El trabajo queda en rama `agent/fase0`.

## Resultado

Fase 0 deja una base documental suficiente para iniciar Fase 1 en modo exclusivamente lectura.
