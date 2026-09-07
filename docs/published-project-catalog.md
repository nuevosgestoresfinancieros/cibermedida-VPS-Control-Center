# Catálogo READ_SAFE de aplicaciones publicadas

El Control Center puede mostrar los proyectos o aplicaciones publicados bajo `/var/www` mediante un provider explícito y de solo lectura.

## Qué muestra

La colección enumera únicamente los directorios directos de la raíz autorizada. Para cada directorio devuelve nombre, ruta relativa, tipo aproximado, presencia de Git, marcadores tecnológicos de una lista cerrada y estado `detected`.

No se recorren subdirectorios, no se abren archivos, no se siguen enlaces simbólicos y no se devuelve contenido de aplicaciones. Directorios ocultos y nombres reservados como `logs`, `backups`, `cache`, `tmp` y `node_modules` se omiten.

## API

`GET /api/projects/published` devuelve un resultado metadata-only. Requiere una sesión con `VIEW_PROJECTS`. Si el provider está desactivado, el resultado permanece `blocked_by_default`.

La respuesta incluye `root`, `scope`, `projects`, `skipped_entries`, `provider`, `live_data`, `state` y `reason`. La operación se registra con el evento `published_project_catalog_read` sin contenido de archivos ni salida de procesos.

## Activación explícita

La API se puede iniciar con:

```text
--read-safe-published-projects-root /var/www
```

La activación live añade el provider `phase3-read-safe-published-projects` al alcance requerido. El manifiesto activo debe declarar ese provider y el permiso `VIEW_PROJECTS`; de lo contrario, readiness y el endpoint fallan cerrado.

La opción no se incorpora automáticamente al servicio systemd. El cambio de servicio y de manifiesto requiere una revisión y autorización de despliegue independientes.

## Interfaz

La vista `Proyectos` conserva el catálogo Git existente y añade una tabla `Directorios publicados en /var/www`. La tabla muestra el estado seguro incluido mientras no exista activación live y sustituye ese estado por metadatos del endpoint cuando el usuario actualiza con una sesión autorizada.

## Límites

Esta capacidad no habilita despliegues, rollback, ejecución de comandos, lectura de secretos, logs, backups o bases de datos, ni crea `INVENTORY.json`.
