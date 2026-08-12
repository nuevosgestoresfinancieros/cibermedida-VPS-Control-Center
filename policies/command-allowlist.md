# Command Allowlist

Allowlist conceptual inicial para operaciones de bajo riesgo. La implementacion futura debera convertir esto en reglas verificables y contextualizadas.

## Normalmente permitidos en modo lectura

- `git status`
- `git diff`
- `git log`
- `df`
- `free`
- `uptime`
- `systemctl status`
- `journalctl`, solo de forma acotada a unidad o servicio especifico, intervalo temporal limitado y numero de lineas limitado
- `docker ps`
- `pm2 status`
- consultas de metricas y health checks seguros

`journalctl` no debe usarse para leer indiscriminadamente el journal completo. Sus resultados deben minimizar o redactar secretos, tokens, credenciales, cookies y otros datos sensibles antes de exponerse a un modelo IA.

## Permitidos bajo condiciones controladas

- crear ramas Git;
- modificar codigo dentro del repositorio autorizado;
- crear archivos documentales o de codigo dentro del proyecto autorizado;
- ejecutar tests;
- ejecutar lint;
- ejecutar builds;
- instalar dependencias del proyecto cuando exista autorizacion y analisis de impacto.

## Requieren autorizacion

- reiniciar servicios;
- modificar Apache;
- modificar Docker;
- migrar bases de datos;
- modificar configuracion de produccion;
- desplegar;
- rollback;
- cambios de seguridad.

## Bloqueados para ejecucion automatica

- borrar bases de datos;
- eliminar backups;
- modificar claves SSH;
- cambiar usuarios privilegiados;
- modificar firewall de forma destructiva;
- formatear discos;
- acciones irreversibles.

## Nota

Esta allowlist no concede permisos por si misma. Es documentacion inicial para el futuro Policy Engine y Executor Controlado.
