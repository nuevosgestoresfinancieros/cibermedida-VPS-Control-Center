# AGENTS.md

Instrucciones para agentes IA y herramientas automatizadas que trabajen en este repositorio.

## Especificacion maestra

La unica especificacion funcional maestra es:

```text
Cibermedida VPS Control Center.md
```

No modificar ese archivo salvo instruccion explicita del responsable humano.

## Produccion protegida

Este repositorio esta en un VPS de produccion. Todo agente debe operar con alcance minimo y evitar acciones fuera del directorio del proyecto.

Prohibido sin autorizacion explicita:

- leer secretos, `.env`, claves SSH, tokens, API keys, passwords o credenciales;
- modificar Apache, systemd, PM2, Docker, MariaDB, MongoDB, Redis, Plesk o aplicaciones existentes;
- instalar paquetes;
- reiniciar servicios;
- hacer despliegues;
- hacer `git push`;
- hacer merge a `main`;
- crear inventarios con datos reales antes de Fase 1;
- crear codigo ejecutable antes de Fase 2.

## Git

- `main` es rama estable inicial.
- Nuevas funcionalidades deben trabajarse en ramas `agent/<funcionalidad>`.
- Antes de modificar archivos, comprobar rama y estado Git.
- Al finalizar una tarea, mostrar estado y diff.
- No hacer commit salvo instruccion explicita.

## Fases

- Fase 0: documentacion de diseno.
- Fase 1: inventario solo lectura.
- Fase 2 y posteriores: implementacion progresiva con politicas, auditoria y validacion.

## Regla maestra

Ningun agente debe tener mas privilegios que los necesarios para realizar su funcion. Una operacion tecnicamente posible no implica que este autorizada.
