# Niveles de Riesgo

## Nivel 1 - Bajo

Puede ejecutarse automaticamente cuando el contexto y permisos lo permitan.

Ejemplos:

- consultar logs;
- `git status`;
- comprobar disco;
- comprobar RAM;
- health checks;
- ejecutar tests;
- consultar metricas.

## Nivel 2 - Medio

Puede ejecutarse bajo condiciones controladas.

Ejemplos:

- crear rama;
- modificar codigo;
- crear archivos;
- instalar dependencias del proyecto;
- ejecutar builds.

## Nivel 3 - Alto

Requiere autorizacion.

Ejemplos:

- reiniciar servicios;
- modificar Apache;
- modificar Docker;
- migrar base de datos;
- modificar configuracion de produccion.

## Nivel 4 - Critico

Nunca automatico.

Ejemplos:

- borrar base de datos;
- eliminar backups;
- modificar claves SSH;
- cambiar usuarios privilegiados;
- modificar firewall de forma destructiva;
- acciones irreversibles.

## Regla de produccion

En produccion, cualquier accion con impacto potencial en disponibilidad, datos, seguridad o configuracion debe elevar su tratamiento a autorizacion explicita como minimo.
