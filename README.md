# Cibermedida VPS Control Center

Cibermedida VPS Control Center es el proyecto para construir una plataforma inteligente de administracion, desarrollo, seguridad y operaciones DevOps para el VPS de Cibermedida.

La especificacion funcional maestra es [Cibermedida VPS Control Center.md](./Cibermedida%20VPS%20Control%20Center.md). Este repositorio debe evolucionar por fases y con produccion protegida.

## Estado

- Arquitectura funcional: definida en la especificacion maestra.
- Implementacion: pendiente.
- Fase actual documentada: Fase 0 - Diseno.
- Inventario real del VPS: pendiente.
- Cambios sobre produccion: ninguno en esta fase.

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

## Restricciones de esta fase

Fase 0 no crea automatizaciones, inventario real, datos operativos, codigo ejecutable ni capacidad de modificacion sobre el VPS.
