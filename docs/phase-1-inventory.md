# Fase 1 - Inventario

## Objetivo

Descubrir el estado real del VPS en modo exclusivamente lectura y producir un inventario estructurado.

## Restriccion principal

Fase 1 no debe modificar el VPS. No debe reiniciar servicios, cambiar configuraciones, instalar paquetes ni escribir datos operativos fuera de las ubicaciones aprobadas del proyecto.

## Areas a descubrir

- Ubuntu.
- CPU.
- RAM.
- Almacenamiento.
- Usuarios.
- Servicios.
- Apache.
- PM2.
- Docker.
- Certificados.
- Proyectos.
- Repositorios.
- Bases de datos.
- Backups.
- Dominios.
- Puertos.

## Resultado previsto

El resultado previsto por la especificacion es:

```text
INVENTORY.json
```

En esta Fase 0 no se crea ese archivo. Solo se define su contrato inicial en `schemas/inventory.schema.json`.

## Reglas para la futura ejecucion

- Leer solo metadatos necesarios.
- No leer secretos ni contenidos sensibles.
- No inventar datos desconocidos.
- Marcar campos no descubiertos como `unknown`, `null` o listas vacias segun el esquema.
- Registrar origen y fecha de captura cuando se implemente el inventario.
- Separar observacion de diagnostico y de ejecucion.
