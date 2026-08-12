# Agentes

## Principio

Los agentes especializados ayudan a observar, diagnosticar, planificar y ejecutar tareas bajo control del Supervisor, Policy Engine y Executor Controlado.

## Supervisor IA

Responsabilidades:

- interpretar solicitudes;
- identificar contexto;
- determinar proyecto;
- seleccionar agentes;
- crear plan;
- establecer riesgo inicial;
- enviar el plan al Policy Engine;
- coordinar resultados;
- resumir al usuario.

No modifica directamente infraestructura.

## Agent Manager

Coordina agentes especializados y evita modificaciones concurrentes sobre el mismo proyecto mediante mecanismos futuros de jobs, locks u ownership.

## Agentes previstos

- Infrastructure Agent: Ubuntu, systemd, recursos, procesos, puertos, red, logs y filesystem.
- Apache Agent: VirtualHosts, proxy inverso, HTTPS, certificados, logs y errores HTTP.
- PM2 Agent: procesos Node, estado, memoria, logs, ecosystem y crash loops.
- Docker Agent: contenedores, imagenes, redes, volumenes, Compose, logs y recursos.
- Development Agent: proyectos, estructura, dependencias, tests, builds y Codex CLI.
- Git Agent: estado, ramas, commits, diferencias y convencion `agent/<funcionalidad>`.
- Testing Agent: tests, lint, build, smoke tests y reportes.
- Backup Agent: creacion, verificacion, checksum, catalogo y restore test.
- Deploy Agent: pre-deploy, autorizacion, deploy, post-deploy y validaciones.
- Security Agent: SSH, usuarios, sudo, puertos, firewall, permisos, servicios, actualizaciones y exposicion accidental.
- Monitoring Agent: metricas, certificados, almacenamiento, servicios, endpoints y anomalias.
- Incident Agent: investigacion, correlacion, timeline, RCA y cierre.
- Database Agent: bases de datos, diagnostico y cambios sujetos a autorizacion.
- Network Agent: conectividad, puertos, dominios y exposicion.

## Codex CLI

Codex CLI sera motor de desarrollo y analisis de codigo, regulado por:

```text
Supervisor
  -> Policy Engine
  -> Executor
```

Codex no tendra autoridad absoluta sobre produccion.
