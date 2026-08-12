# Cibermedida VPS Control Center
## Operador Inteligente Conversacional para Administración, Desarrollo, Seguridad y Operaciones DevOps

**Versión del diseño:** V2/V3  
**Estado:** Arquitectura y especificación funcional  
**Objetivo:** Construcción progresiva  
**Entorno inicial:** VPS Ubuntu de Cibermedida  
**Motor de desarrollo IA:** Codex CLI  
**Interfaz principal:** Web + Chat conversacional + CLI  
**Principio fundamental:** autonomía controlada, trazabilidad completa y producción protegida.

---

# 1. Visión general

Cibermedida VPS Control Center será una plataforma inteligente para gestionar de forma centralizada un VPS, sus aplicaciones, servicios, repositorios, infraestructura, despliegues, backups, seguridad e incidencias.

El sistema combinará:

- inteligencia artificial;
- Codex CLI;
- administración Linux;
- DevOps;
- Git;
- testing;
- monitorización;
- seguridad;
- observabilidad;
- backups;
- despliegues;
- rollback;
- gestión de incidentes;
- interfaz web;
- conversación en lenguaje natural;
- automatización controlada;
- auditoría;
- análisis de impacto;
- detección de anomalías;
- conocimiento estructurado del servidor.

El operador no será simplemente una interfaz web que ejecute comandos SSH.

Será una capa inteligente situada entre el usuario y la infraestructura.

Su ciclo general será:

```text
OBSERVAR
   ↓
COMPRENDER
   ↓
DIAGNOSTICAR
   ↓
PLANIFICAR
   ↓
ANALIZAR IMPACTO
   ↓
EVALUAR RIESGO
   ↓
VALIDAR POLÍTICAS
   ↓
SOLICITAR AUTORIZACIÓN
   ↓
EJECUTAR
   ↓
VALIDAR
   ↓
MONITORIZAR
   ↓
REGISTRAR
```

---

# 2. Objetivos principales

El sistema deberá permitir:

1. conocer el estado real del VPS;
2. conversar con el servidor en lenguaje natural;
3. administrar múltiples proyectos;
4. diagnosticar problemas;
5. analizar logs;
6. analizar infraestructura;
7. utilizar Codex CLI para trabajar sobre código;
8. crear ramas Git automáticamente;
9. ejecutar tests;
10. ejecutar builds;
11. analizar cambios;
12. crear backups;
13. verificar backups;
14. probar restauraciones;
15. desplegar aplicaciones;
16. validar despliegues;
17. realizar rollback;
18. monitorizar servicios;
19. detectar anomalías;
20. gestionar incidentes;
21. controlar certificados;
22. controlar seguridad;
23. mantener auditoría;
24. controlar permisos;
25. impedir operaciones peligrosas;
26. gestionar niveles de autonomía;
27. mantener un mapa de dependencias del VPS;
28. analizar impacto antes de modificar infraestructura.

---

# 3. Principios de diseño

## 3.1 Producción protegida

Ninguna operación importante deberá ejecutarse directamente por una petición conversacional.

Una petición como:

```text
Actualiza Ikas-Txiki.
```

no significará:

```text
ejecutar actualización
```

Sino:

```text
interpretar
↓
analizar
↓
preparar plan
↓
comprobar requisitos
↓
evaluar riesgo
↓
solicitar autorización cuando corresponda
↓
ejecutar
```

---

## 3.2 Separación entre pensar y ejecutar

El componente que analiza una operación no será el responsable último de autorizarla.

Arquitectura conceptual:

```text
AI Planner
     ↓
Policy Engine
     ↓
Executor
     ↓
Validator
```

Esto reduce la posibilidad de que una interpretación incorrecta se convierta inmediatamente en una modificación del servidor.

---

## 3.3 Todo cambio deberá ser trazable

Cada operación deberá registrar:

- fecha;
- usuario;
- agente;
- proyecto;
- acción;
- nivel de riesgo;
- comandos autorizados;
- archivos modificados;
- rama;
- commit;
- backup;
- resultado;
- validaciones;
- rollback, si se produce.

---

## 3.4 Git como elemento obligatorio

Las nuevas funcionalidades no se desarrollarán directamente sobre `main`.

Flujo:

```text
main
  ↓
agent/nueva-funcionalidad
  ↓
desarrollo
  ↓
tests
  ↓
build
  ↓
revisión
  ↓
integración
```

---

## 3.5 Backup antes de cambios sensibles

Los cambios relevantes deberán seguir:

```text
Backup
↓
Verificación
↓
Checksum
↓
Registro
↓
Operación
```

Cuando sea necesario:

```text
Restore test
```

antes de producción.

---

# 4. Arquitectura general

```text
                         USUARIO
                           │
                           ▼
              ┌─────────────────────────┐
              │   WEB CONTROL CENTER    │
              │                         │
              │ Dashboard               │
              │ Chat IA                 │
              │ Proyectos               │
              │ Servicios               │
              │ Incidentes              │
              │ Backups                 │
              │ Deployments             │
              │ Seguridad               │
              │ Monitorización          │
              │ Auditoría               │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │      API GATEWAY        │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │      SUPERVISOR IA      │
              │      ORCHESTRATOR       │
              └────────────┬────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
 KNOWLEDGE ENGINE      AI PLANNER       INCIDENT ENGINE
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
              ┌─────────────────────────┐
              │      POLICY ENGINE      │
              └────────────┬────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │      AGENT MANAGER      │
              └────────────┬────────────┘
                           │
      ┌─────────┬──────────┼──────────┬─────────┐
      ▼         ▼          ▼          ▼         ▼
    Linux     Code      Security    Backup    Testing
    Agent     Agent       Agent      Agent     Agent

      ┌─────────┬──────────┼──────────┬─────────┐
      ▼         ▼          ▼          ▼         ▼
    Git      Docker      Database    Deploy   Network
   Agent      Agent       Agent       Agent    Agent

                           │
                           ▼
                    ┌────────────┐
                    │ CODEX CLI  │
                    └─────┬──────┘
                          │
                          ▼
                  ┌───────────────┐
                  │   EXECUTOR    │
                  │   CONTROLADO  │
                  └───────┬───────┘
                          │
                          ▼
                         VPS
                          │
                          ▼
                    ┌───────────┐
                    │ VALIDATOR │
                    └─────┬─────┘
                          │
                ┌─────────┴─────────┐
                ▼                   ▼
               OK                 ERROR
                │                   │
                ▼                   ▼
           MONITORING          RECOVERY
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                      ROLLBACK            INCIDENT
```

---

# 5. Interfaz Web

La aplicación web será la principal interfaz del sistema.

## Menú previsto

```text
Dashboard
Conversación
Servidor
Proyectos
Servicios
Git
Testing
Deployments
Backups
Incidentes
Monitorización
Seguridad
Agentes
Auditoría
Configuración
```

---

# 6. Dashboard

El Dashboard deberá mostrar exclusivamente información operativa relevante.

## Servidor

- CPU;
- RAM;
- swap;
- disco;
- carga;
- uptime;
- tráfico;
- procesos relevantes.

## Servicios

- Apache;
- systemd;
- PM2;
- Docker;
- SSH;
- otros servicios detectados.

## Aplicaciones

Estado de cada proyecto:

```text
Ikas-Txiki              ONLINE
Chatbot IA              ONLINE
Cibermedida             ONLINE
```

## Backups

- último backup;
- antigüedad;
- estado;
- verificación;
- última prueba de restauración.

## Seguridad

- críticos;
- altos;
- medios;
- advertencias.

## Incidentes

- abiertos;
- investigando;
- resueltos.

---

# 7. Centro conversacional

La plataforma dispondrá de un chat conectado al Supervisor IA.

Ejemplos:

```text
¿Cómo está el VPS?
```

```text
¿Por qué Ikas-Txiki está lento?
```

```text
¿Qué ha cambiado desde ayer?
```

```text
Analiza los errores de Apache.
```

```text
Comprueba los últimos despliegues.
```

```text
¿Tengo un backup válido de Ikas-Txiki?
```

```text
Prepara el despliegue de la nueva versión.
```

```text
No ejecutes nada. Solo analiza.
```

El contexto conversacional podrá incluir:

- proyecto activo;
- incidente activo;
- despliegue;
- servicio;
- backup;
- rama;
- commit;
- logs relacionados.

---

# 8. Supervisor IA

Será el coordinador central.

No deberá modificar directamente la infraestructura.

Responsabilidades:

- interpretar solicitudes;
- identificar contexto;
- determinar proyecto;
- identificar agentes necesarios;
- solicitar datos;
- crear plan;
- establecer nivel de riesgo;
- enviar el plan al Policy Engine;
- coordinar agentes;
- resumir resultados.

Ejemplo:

```text
Petición:
"Ikas-Txiki devuelve error 500"

Supervisor:

Área:
Backend

Agentes:
Infrastructure Agent
Application Agent
Log Agent
Testing Agent

Nivel inicial:
Solo lectura

Riesgo:
Bajo
```

---

# 9. AI Planner

Transformará una intención en un plan técnico.

Ejemplo:

```text
Objetivo:
Actualizar aplicación

Plan:

1. comprobar repositorio
2. comprobar rama
3. comprobar cambios pendientes
4. recuperar actualizaciones
5. ejecutar tests
6. ejecutar build
7. analizar dependencias
8. realizar backup
9. verificar backup
10. solicitar autorización
11. desplegar
12. validar
13. observar logs
```

---

# 10. Policy Engine

Será una de las capas de seguridad más importantes.

Las políticas no dependerán exclusivamente de instrucciones escritas para el modelo.

Deberán convertirse en reglas verificables.

Ejemplo:

```text
IF environment == production
AND action == deploy
THEN approval_required = true
```

```text
IF tests != passed
THEN deploy = blocked
```

```text
IF backup != verified
THEN deploy = blocked
```

```text
IF action == delete_database
THEN automatic_execution = false
```

---

# 11. Clasificación de riesgo

## Nivel 1 — Bajo

Puede ejecutarse automáticamente.

Ejemplos:

- consultar logs;
- `git status`;
- comprobar disco;
- comprobar RAM;
- health checks;
- ejecutar tests;
- consultar métricas.

---

## Nivel 2 — Medio

Puede ejecutarse bajo condiciones controladas.

Ejemplos:

- crear rama;
- modificar código;
- crear archivos;
- instalar dependencias del proyecto;
- ejecutar builds.

---

## Nivel 3 — Alto

Requiere autorización.

Ejemplos:

- reiniciar servicios;
- modificar Apache;
- modificar Docker;
- migrar base de datos;
- modificar configuración de producción.

---

## Nivel 4 — Crítico

Nunca automático.

Ejemplos:

- borrar base de datos;
- eliminar backups;
- modificar claves SSH;
- cambiar usuarios privilegiados;
- modificar firewall de forma destructiva;
- acciones irreversibles.

---

# 12. Agent Manager

Gestionará agentes especializados.

El Supervisor no tendrá que conocer los detalles de ejecución de todas las tecnologías.

---

# 13. Infrastructure Agent

Especialista en:

- Ubuntu;
- systemd;
- CPU;
- RAM;
- swap;
- disco;
- procesos;
- puertos;
- red;
- logs;
- filesystem.

---

# 14. Apache Agent

Especialista en:

- VirtualHosts;
- proxy inverso;
- HTTPS;
- certificados;
- configuración;
- logs;
- errores 4xx/5xx;
- configuración de dominios.

---

# 15. PM2 Agent

Especialista en:

- procesos Node;
- reinicios;
- estado;
- memoria;
- logs;
- ecosystem;
- crash loops.

---

# 16. Docker Agent

Especialista en:

- contenedores;
- imágenes;
- redes;
- volúmenes;
- Docker Compose;
- logs;
- recursos.

---

# 17. Development Agent

Especialista en proyectos.

Podrá identificar:

- frontend;
- backend;
- Node;
- React;
- Python;
- APIs;
- dependencias;
- estructura;
- tests.

Este agente utilizará Codex CLI.

---

# 18. Codex CLI

Codex será el motor principal para tareas de desarrollo y análisis de código.

Funciones:

- explorar repositorios;
- analizar código;
- detectar errores;
- implementar funcionalidades;
- refactorizar;
- crear archivos;
- modificar archivos;
- ejecutar tests;
- ejecutar builds;
- trabajar con Git;
- analizar diferencias.

Codex no deberá disponer por sí mismo de autoridad absoluta sobre producción.

Su acceso estará regulado por:

```text
Supervisor
↓
Policy Engine
↓
Executor
```

---

# 19. Git Agent

Responsabilidades:

- comprobar estado;
- comprobar rama;
- analizar commits;
- crear ramas;
- preparar commits;
- comparar ramas;
- analizar diferencias;
- detectar cambios sin commit.

Convención:

```text
agent/<funcionalidad>
```

Nunca desarrollar nuevas funcionalidades directamente sobre `main`.

---

# 20. Testing Agent

Después de modificaciones:

```text
Unit Tests
↓
Integration Tests
↓
Lint
↓
Build
↓
Smoke Tests
↓
Health Check
```

Resultado:

```text
TEST REPORT

Backend:
PASS

Frontend:
PASS

Lint:
PASS

Build:
PASS

Smoke:
PASS

STATUS:
READY
```

---

# 21. Backup Agent

Tipos de backup:

- código;
- configuración;
- base de datos;
- aplicación completa;
- pre-deploy;
- manual;
- programado.

Flujo:

```text
CREATE
↓
VERIFY
↓
CHECKSUM
↓
CATALOG
↓
RESTORE TEST
```

---

# 22. Catálogo de backups

Cada backup deberá registrar:

```text
id
project
timestamp
type
source
destination
size
checksum
verified
restore_tested
retention
created_by
```

---

# 23. Políticas de retención

Se estudiará una combinación de:

```text
diarios
semanales
mensuales
pre-deploy
manuales protegidos
```

Los backups vinculados a operaciones sensibles no deberán eliminarse automáticamente hasta que su política de retención permita hacerlo.

---

# 24. Deploy Agent

Flujo:

```text
PRE-DEPLOY

Git                PASS
Branch             PASS
Tests              PASS
Build              PASS
Dependencies       PASS
Disk               PASS
Backup             PASS
Backup verification PASS

↓

AUTHORIZATION

↓

DEPLOY

↓

POST-DEPLOY

Service            PASS
HTTP               PASS
API                PASS
Database           PASS
Logs               PASS
Health             PASS
```

---

# 25. Rollback

Tipos:

## Git rollback

Restauración del código.

## File rollback

Restauración de archivos.

## Configuration rollback

Restauración de configuración.

## Database rollback

Restauración de datos.

## Full deployment rollback

Restauración completa del estado previo al despliegue.

El tipo deberá elegirse según el cambio realizado.

---

# 26. Validator

Después de cualquier acción relevante, un componente independiente verificará el resultado.

Ejemplo:

```text
Objetivo:
Reiniciar backend

Executor:
restart realizado

Validator:
¿Servicio activo?
¿Health endpoint responde?
¿Errores nuevos?
¿HTTP correcto?
```

Solo entonces:

```text
SUCCESS
```

---

# 27. Knowledge Engine

Mantendrá conocimiento estructurado del VPS.

No será únicamente documentación estática.

Ejemplo:

```text
SERVER
│
├── PROJECTS
│
├── SERVICES
│
├── DOMAINS
│
├── DATABASES
│
├── REPOSITORIES
│
├── CERTIFICATES
│
├── CONTAINERS
│
├── PORTS
│
└── BACKUPS
```

---

# 28. Inventario de proyectos

Cada proyecto tendrá:

```text
id
name
path
repository
branch
production_branch
frontend
backend
framework
runtime
database
service
domain
health_endpoint
backup_policy
deployment_method
autonomy_level
```

---

# 29. Gemelo digital del VPS

El Knowledge Engine mantendrá relaciones.

Ejemplo:

```text
Internet
   │
 HTTPS
   │
 Apache
   │
 Proxy
   │
 Backend
   │
 Database
```

Otro ejemplo:

```text
chatbot.cibermedida.es
     │
   Apache
     │
    PM2
     │
   Node.js
     │
    API
    ├── OpenAI
    └── otros servicios
```

---

# 30. Impact Analysis

Antes de operaciones sensibles:

```text
CHANGE
  ↓
DEPENDENCIES
  ↓
PROJECTS AFFECTED
  ↓
SERVICES AFFECTED
  ↓
DOWNTIME RISK
  ↓
DATA RISK
  ↓
ROLLBACK AVAILABLE
```

Resultado:

```text
IMPACT ANALYSIS

Operation:
Apache configuration change

Projects affected:
3

Services affected:
Apache
Chatbot
Ikas-Txiki

Risk:
HIGH

Backup required:
YES

Approval required:
YES
```

---

# 31. Configuration Drift Detection

El operador mantendrá una referencia de configuración conocida.

Comparará:

```text
BASELINE
vs
CURRENT
```

Podrá detectar:

- cambios Apache;
- nuevos servicios;
- puertos inesperados;
- procesos inesperados;
- configuraciones modificadas;
- modificaciones fuera de despliegues registrados.

---

# 32. Detección de anomalías

Se analizarán:

- CPU;
- RAM;
- disco;
- errores HTTP;
- tiempos de respuesta;
- reinicios;
- uso de procesos;
- logs;
- crecimiento del almacenamiento;
- consumo de aplicaciones.

Ejemplo:

```text
PM2 restarts baseline:
0-2/day

Current:
15/day

ANOMALY DETECTED
```

---

# 33. Monitoring Engine

Monitorización:

```text
CPU
RAM
SWAP
DISK
LOAD
NETWORK
HTTP
HTTPS
LATENCY
ERROR RATE
SERVICES
PM2
DOCKER
APACHE
CERTIFICATES
BACKUPS
APPLICATION HEALTH
```

---

# 34. Histórico

Las métricas deberán conservar histórico suficiente para detectar tendencias.

Ejemplo:

```text
RAM normal:
40-50 %

Últimas 24h:
72-83 %

Último deploy:
hace 6 horas

Correlación:
posible
```

---

# 35. Incident Manager

Cuando se detecte un problema:

```text
INCIDENT
```

Estados:

```text
OPEN
INVESTIGATING
IDENTIFIED
MITIGATING
MONITORING
RESOLVED
```

---

# 36. Modelo de incidente

```text
id
timestamp
project
service
severity
symptom
detected_by
last_deployment
suspected_cause
diagnostic_steps
actions
resolution
rollback
closed_at
```

---

# 37. Investigación automática

Ejemplo:

```text
HTTP 502
   ↓
Apache
   ↓
Proxy
   ↓
Backend
   ↓
PM2
   ↓
Logs
   ↓
Port
   ↓
Dependencies
```

El sistema deberá investigar antes de reiniciar componentes indiscriminadamente.

---

# 38. Root Cause Analysis

Los incidentes cerrados podrán generar:

```text
ROOT CAUSE
IMPACT
TIMELINE
RESOLUTION
PREVENTION
```

Esto ayudará a evitar problemas repetidos.

---

# 39. Change Manager

Cada modificación significativa tendrá un expediente.

Estados:

```text
PLANNED
IMPLEMENTED
TESTED
REVIEWED
BACKED_UP
APPROVED
DEPLOYED
VERIFIED
CLOSED
```

---

# 40. Audit Engine

Cada acción quedará registrada.

Modelo:

```text
timestamp
user
agent
project
action
risk
command
authorization
backup
commit
result
duration
```

---

# 41. Seguridad de la aplicación web

La interfaz deberá disponer de:

- HTTPS;
- autenticación;
- sesiones seguras;
- 2FA;
- roles;
- permisos;
- CSRF;
- protección de cookies;
- rate limiting;
- auditoría.

---

# 42. Roles

Inicialmente:

```text
ADMIN
OPERATOR
DEVELOPER
VIEWER
```

---

# 43. Permisos

Ejemplos:

```text
VIEW_SERVER
VIEW_LOGS
RUN_DIAGNOSTICS
RUN_TESTS
CREATE_BRANCH
MODIFY_CODE
CREATE_BACKUP
DEPLOY
ROLLBACK
MANAGE_SECURITY
MANAGE_USERS
MANAGE_POLICIES
```

---

# 44. Gestión de secretos

Los secretos no deberán mostrarse innecesariamente al modelo.

Incluye:

- `.env`;
- API keys;
- tokens;
- passwords;
- claves privadas;
- credenciales de bases de datos.

El sistema deberá intentar proporcionar únicamente la información mínima necesaria.

---

# 45. Command Executor

Será el único componente autorizado para ejecutar comandos sensibles.

Nunca:

```text
Chat → shell directo
```

Siempre:

```text
Chat
↓
Supervisor
↓
Planner
↓
Policy Engine
↓
Executor
↓
VPS
```

---

# 46. Allowlist y Blocklist

Se implementarán controles adicionales.

Ejemplo de comandos normalmente permitidos:

```text
git status
git diff
df
free
systemctl status
journalctl
docker ps
pm2 status
```

Operaciones peligrosas deberán quedar bloqueadas o requerir un procedimiento explícito.

---

# 47. Autonomía graduada

Cada proyecto podrá tener su propio nivel.

## Nivel 0

Observación.

## Nivel 1

Diagnóstico.

## Nivel 2

Propuesta de acciones.

## Nivel 3

Acciones automáticas de bajo riesgo.

## Nivel 4

Despliegues con autorización.

## Nivel 5

Recuperación automática limitada.

---

# 48. Autonomía por acción

Ejemplo:

```text
health_check       AUTO
logs               AUTO
testing            AUTO
backup             AUTO
code_changes       CONTROLLED
deploy             APPROVAL
database_change    APPROVAL
security_change    APPROVAL
delete_data        NEVER_AUTO
```

---

# 49. Zona de laboratorio

El sistema deberá disponer de una separación conceptual y, cuando sea posible, técnica:

```text
LAB
│
├── pruebas
├── experimentos
├── desarrollo IA
└── validación

PRODUCTION
│
├── aplicaciones
├── datos
└── servicios protegidos
```

Codex deberá trabajar preferentemente en la zona de desarrollo/laboratorio.

---

# 50. Staging

Cuando un proyecto lo permita:

```text
Development
↓
Testing
↓
Staging
↓
Production
```

Esto reducirá el riesgo de probar directamente sobre producción.

---

# 51. Estado persistente

Se mantendrá información estructurada del operador.

Posible estructura:

```text
/opt/vps-operator/
│
├── config/
├── policies/
├── agents/
├── state/
├── scripts/
├── backups/
├── logs/
├── audit/
├── incidents/
└── runtime/
```

---

# 52. Estado lógico

Información aproximada:

```text
server
projects
services
deployments
backups
incidents
changes
agents
policies
metrics
audit
```

La implementación definitiva podrá utilizar base de datos en vez de archivos JSON.

---

# 53. Base de datos del Control Center

Entidades previstas:

```text
users
roles
permissions
projects
services
servers
deployments
backups
incidents
changes
audit_logs
metrics
alerts
agents
agent_runs
policies
approvals
conversations
messages
```

---

# 54. API interna

Ejemplos conceptuales:

```text
GET  /api/server/status
GET  /api/projects
GET  /api/projects/:id/status

GET  /api/services
GET  /api/services/:id/logs

POST /api/diagnostics
POST /api/tests

GET  /api/backups
POST /api/backups
POST /api/backups/:id/verify

GET  /api/deployments
POST /api/deployments/prepare
POST /api/deployments/:id/approve
POST /api/deployments/:id/execute

POST /api/rollback/prepare
POST /api/rollback/:id/approve

GET  /api/incidents
POST /api/incidents/:id/analyze

GET  /api/audit
POST /api/chat
```

Estos endpoints son una especificación conceptual y deberán revisarse durante la implementación.

---

# 55. WebSockets / eventos

Para operaciones largas:

```text
backup
tests
build
deploy
diagnostics
```

la interfaz deberá recibir actualizaciones en tiempo real.

Ejemplo:

```text
PREPARING
BACKING_UP
VERIFYING
DEPLOYING
TESTING
VALIDATING
SUCCESS
```

---

# 56. Notificaciones

El sistema podrá generar alertas por:

- aplicación caída;
- disco;
- memoria;
- certificado;
- backup fallido;
- deployment fallido;
- servicio detenido;
- anomalía;
- incidente crítico.

La integración concreta con email u otros canales se definirá posteriormente.

---

# 57. Experiencia conversacional

El chat deberá diferenciar claramente:

```text
INFORMACIÓN
```

```text
DIAGNÓSTICO
```

```text
PLAN PROPUESTO
```

```text
ACCIÓN PREPARADA
```

```text
AUTORIZACIÓN REQUERIDA
```

```text
OPERACIÓN EN CURSO
```

```text
OPERACIÓN FINALIZADA
```

---

# 58. Botones de autorización

Las operaciones sensibles no deberían depender únicamente de escribir:

```text
sí
```

La interfaz podrá ofrecer acciones explícitas:

```text
AUTORIZAR DEPLOY
RECHAZAR
REVISAR PLAN
AUTORIZAR ROLLBACK
```

---

# 59. Modo explicación

Cada operación mostrará:

## Acción técnica

```text
systemctl restart ...
```

## Explicación

```text
Se necesita reiniciar el servicio para cargar la nueva versión.
```

## Riesgo

```text
MEDIO
```

## Impacto

```text
Interrupción potencial de pocos segundos.
```

---

# 60. README y AGENTS.md por proyecto

Cada proyecto podrá incluir:

```text
AGENTS.md
```

con información específica:

- arquitectura;
- comandos;
- tests;
- build;
- restricciones;
- deploy;
- backup;
- servicios;
- reglas particulares.

Estas instrucciones complementarán, pero no reemplazarán, al Policy Engine.

---

# 61. Protocolo de diagnóstico

Por defecto:

```text
1. observar
2. recopilar información
3. correlacionar
4. identificar hipótesis
5. validar hipótesis
6. proponer solución
```

No:

```text
1. reiniciar cosas
2. esperar
```

---

# 62. Protocolo de desarrollo

```text
git status
↓
identificar main
↓
crear agent/*
↓
analizar
↓
modificar
↓
tests
↓
lint
↓
build
↓
diff
↓
informe
```

---

# 63. Protocolo de producción

```text
Change Request
↓
Impact Analysis
↓
Risk Assessment
↓
Tests
↓
Build
↓
Backup
↓
Backup Verify
↓
Authorization
↓
Deploy
↓
Validator
↓
Health Check
↓
Logs
↓
Monitoring
↓
Close Change
```

---

# 64. Protocolo de fallo

```text
FAILURE
↓
STOP
↓
COLLECT EVIDENCE
↓
DETERMINE IMPACT
↓
ROLLBACK ANALYSIS
↓
AUTHORIZATION
↓
ROLLBACK
↓
VALIDATION
```

El agente no deberá realizar una cadena indefinida de cambios para intentar arreglar un despliegue fallido.

---

# 65. Protección de main

Regla:

```text
Nunca desarrollar directamente sobre main.
```

`main` deberá representar una rama estable o vinculada a producción según la configuración de cada proyecto.

---

# 66. Health Checks

Cada proyecto podrá definir uno o varios:

```text
HTTP
API
database
authentication
service
critical workflow
```

---

# 67. Smoke Tests de producción

Tras un despliegue se comprobarán únicamente operaciones seguras y representativas.

Por ejemplo:

```text
home
login endpoint
health
dashboard
API esencial
```

No deberán modificar datos reales salvo que exista un entorno específico de prueba.

---

# 68. Certificados

El sistema monitorizará:

```text
domain
issuer
expiration
days_remaining
status
```

Generará alertas preventivas.

---

# 69. Disco

Monitorización:

- uso total;
- crecimiento;
- logs;
- Docker;
- backups;
- proyectos;
- bases de datos.

Esto permitirá responder:

```text
¿Qué está ocupando espacio?
```

---

# 70. Seguridad

El Security Agent analizará:

- SSH;
- usuarios;
- sudo;
- puertos;
- firewall;
- permisos;
- servicios;
- actualizaciones;
- certificados;
- configuración;
- procesos sospechosos;
- exposición accidental.

---

# 71. Baseline

El operador podrá mantener una referencia de:

```text
servicios esperados
puertos esperados
usuarios esperados
proyectos
dominios
contenedores
configuraciones
```

Un cambio inesperado podrá generar alerta.

---

# 72. Historial de despliegues

Cada deployment registrará:

```text
project
branch
commit
timestamp
user
backup
tests
build
result
duration
health
rollback
```

---

# 73. Comparación entre versiones

La interfaz podrá responder:

```text
¿Qué ha cambiado desde la versión anterior?
```

utilizando Git y los registros del sistema.

---

# 74. Conversación sobre incidentes

Un incidente tendrá su propio contexto.

Ejemplos:

```text
¿Qué ocurrió?
```

```text
¿Qué cambió justo antes?
```

```text
¿Hay backup?
```

```text
¿Qué solución propones?
```

```text
Prepara rollback.
```

---

# 75. Tareas del Supervisor

El Supervisor deberá poder dividir una petición compleja.

Ejemplo:

```text
Revisa completamente Ikas-Txiki.
```

Podrá delegar:

```text
Git Agent
Testing Agent
Infrastructure Agent
Security Agent
Database Agent
Monitoring Agent
```

Y consolidar un único informe.

---

# 76. Evitar modificaciones concurrentes

Dos agentes no deberán modificar simultáneamente el mismo proyecto sin coordinación.

Se implementará algún mecanismo de:

```text
locks
jobs
operation ownership
```

---

# 77. Jobs

Toda operación relevante será un Job.

Estados:

```text
QUEUED
RUNNING
WAITING_APPROVAL
SUCCESS
FAILED
CANCELLED
```

---

# 78. Auditoría de conversaciones

Las conversaciones vinculadas a acciones podrán conservar:

```text
request
plan
approval
execution
result
```

para reconstruir por qué se tomó una decisión.

---

# 79. Objetivo de seguridad

Una instrucción conversacional nunca deberá ser suficiente para saltarse:

- permisos;
- políticas;
- backup;
- pruebas;
- autorización;
- validación.

---

# 80. Arquitectura de permisos de sistema

El proceso web no deberá funcionar innecesariamente como `root`.

Se diseñará una cuenta específica del operador.

Los privilegios elevados deberán limitarse mediante reglas concretas.

---

# 81. Objetivo de aislamiento

Idealmente:

```text
Frontend Web
↓
Backend Control Center
↓
Operator Service
↓
Restricted Executor
```

El Executor será el único componente cercano al sistema operativo.

---

# 82. Alta disponibilidad futura

No será requisito de la primera versión.

La arquitectura deberá evitar impedir posteriormente:

- segundo VPS;
- múltiples servidores;
- agentes remotos;
- workers;
- bases de datos externas.

---

# 83. Multi-servidor futuro

La V3 podrá evolucionar:

```text
Control Center
     │
 ┌───┼────┐
 ▼   ▼    ▼
VPS1 VPS2 VPS3
```

Cada servidor dispondría de un agente ejecutor controlado.

---

# 84. Posible evolución hacia agentes remotos

En lugar de ejecutar todo dentro del servidor principal:

```text
Central Control Center
↓
Secure Agent API
↓
Remote VPS
```

Esto permitiría administrar múltiples máquinas.

---

# 85. Fases de implementación

## FASE 0 — Diseño

- README;
- arquitectura;
- políticas;
- modelo de seguridad;
- modelo de datos;
- definición de agentes.

---

## FASE 1 — Inventario

Solo lectura.

Descubrir:

- Ubuntu;
- CPU;
- RAM;
- almacenamiento;
- usuarios;
- servicios;
- Apache;
- PM2;
- Docker;
- certificados;
- proyectos;
- repositorios;
- bases de datos;
- backups;
- dominios;
- puertos.

Resultado:

```text
INVENTORY.json
```

o almacenamiento equivalente.

---

## FASE 2 — Core Operator

Crear:

- estructura del proyecto;
- configuración;
- logging;
- auditoría;
- executor seguro;
- Policy Engine inicial;
- health checks.

---

## FASE 3 — Web Control Center

Crear:

- autenticación;
- Dashboard;
- proyectos;
- servicios;
- logs;
- backups;
- auditoría.

---

## FASE 4 — Chat IA

Incorporar:

- Supervisor;
- conversación;
- contexto;
- diagnóstico;
- planes.

Inicialmente:

```text
READ ONLY
```

---

## FASE 5 — Codex Integration

Incorporar:

- Codex CLI;
- repositorios;
- ramas;
- análisis;
- modificaciones;
- testing;
- builds.

Producción seguirá bloqueada.

---

## FASE 6 — Backup Manager

Implementar:

- creación;
- checksum;
- catálogo;
- validación;
- políticas;
- restore test.

---

## FASE 7 — Deployment Manager

Implementar:

- pre-deploy;
- autorización;
- deploy;
- health checks;
- post-deploy;
- historial.

---

## FASE 8 — Rollback Manager

Implementar:

- rollback Git;
- archivos;
- configuración;
- datos;
- full deployment.

---

## FASE 9 — Monitoring

Añadir:

- métricas;
- histórico;
- servicios;
- endpoints;
- certificados;
- almacenamiento;
- alertas.

---

## FASE 10 — Incident Manager

Añadir:

- incidentes;
- timeline;
- diagnóstico;
- correlación;
- RCA.

---

## FASE 11 — Knowledge Engine

Crear:

- mapa VPS;
- dependencias;
- servicios;
- proyectos;
- relaciones;
- Digital Twin.

---

## FASE 12 — Impact Analysis

Incorporar análisis previo de:

- proyectos;
- servicios;
- dependencias;
- datos;
- disponibilidad;
- rollback.

---

## FASE 13 — Security Center

Añadir:

- análisis de permisos;
- SSH;
- firewall;
- servicios;
- puertos;
- actualizaciones;
- baseline.

---

## FASE 14 — Anomaly Detection

Añadir:

- baseline;
- tendencias;
- detección de desviaciones;
- correlación con cambios.

---

## FASE 15 — Autonomía progresiva

Activar por fases:

```text
0 → observación
1 → diagnóstico
2 → propuestas
3 → bajo riesgo
4 → deploy autorizado
5 → recuperación limitada
```

---

# 86. Criterios antes de producción

La plataforma completa no deberá recibir capacidad de modificación de producción hasta validar:

```text
authentication
authorization
policies
audit
backup
restore
testing
executor restrictions
approval workflow
rollback
```

---

# 87. Criterios de aceptación V2

La V2 estará funcional cuando sea posible:

- entrar por web;
- autenticarse;
- consultar estado;
- conversar con el VPS;
- diagnosticar;
- visualizar proyectos;
- analizar Git;
- utilizar Codex;
- ejecutar tests;
- crear backups;
- verificar backups;
- preparar deployments;
- autorizar deployments;
- validar deployments;
- realizar rollback;
- consultar auditoría.

---

# 88. Criterios de aceptación V3

La V3 añadirá:

- Knowledge Engine avanzado;
- Digital Twin;
- análisis de impacto;
- correlación histórica;
- detección de anomalías;
- configuración drift;
- autonomía por proyecto;
- recuperación controlada;
- multi-servidor;
- análisis predictivo prudente;
- gestión avanzada de incidentes.

---

# 89. Elementos explícitamente fuera de autonomía total

Aunque exista autonomía avanzada, determinadas operaciones permanecerán protegidas.

Ejemplos:

```text
DELETE DATABASE
DELETE BACKUPS
SSH KEY CHANGES
PRIVILEGED USERS
DESTRUCTIVE FIREWALL CHANGES
FULL SYSTEM UPGRADE
DISK FORMATTING
```

Estas acciones deberán disponer siempre de controles especiales.

---

# 90. Filosofía del proyecto

El objetivo no es que la IA tenga control absoluto sobre el servidor.

El objetivo es que la IA pueda:

```text
entender
diagnosticar
ayudar
desarrollar
automatizar
vigilar
proteger
recuperar
```

manteniendo siempre:

```text
control
seguridad
trazabilidad
reversibilidad
```

---

# 91. Nombre del proyecto

Nombre de trabajo:

```text
Cibermedida VPS Control Center
```

Nombre corto:

```text
VPS Control
```

Posible nombre técnico:

```text
Cibermedida Operator
```

---

# 92. Resultado final esperado

Cuando el sistema esté completo deberá ser posible escribir:

```text
¿Cómo está todo?
```

y recibir una visión consolidada del VPS.

También:

```text
Investiga por qué Ikas-Txiki está lento.
```

El sistema investigará sin modificar nada.

También:

```text
Corrige el problema y deja los cambios preparados.
```

El sistema podrá utilizar Codex, crear una rama, modificar, probar y preparar el cambio.

Finalmente:

```text
Prepara el despliegue.
```

El sistema comprobará:

```text
Git
Tests
Build
Impact
Backup
Verification
Risk
```

y solicitará autorización.

Solo entonces podrá modificar producción.

---

# 93. Regla maestra

> Ninguna capacidad de inteligencia artificial deberá tener más privilegios que los necesarios para realizar su función.

Y:

> Una operación técnicamente posible no implica que esté autorizada.

---

# 94. Flujo maestro definitivo

```text
USUARIO
   ↓
CONVERSACIÓN / WEB
   ↓
SUPERVISOR
   ↓
KNOWLEDGE ENGINE
   ↓
PLANNER
   ↓
IMPACT ANALYSIS
   ↓
RISK ASSESSMENT
   ↓
POLICY ENGINE
   ↓
AGENT MANAGER
   ↓
CODEX / AGENTES
   ↓
TESTING
   ↓
BACKUP
   ↓
AUTORIZACIÓN
   ↓
EXECUTOR
   ↓
VPS
   ↓
VALIDATOR
   ↓
MONITORING
   ↓
AUDIT
   ↓
SUCCESS

Si falla:

VALIDATOR
   ↓
INCIDENT MANAGER
   ↓
ROLLBACK ANALYSIS
   ↓
AUTORIZACIÓN
   ↓
RECOVERY
   ↓
VALIDATION
```

---

# 95. Estado actual del proyecto

```text
Arquitectura: DEFINIDA
Modelo V2: DEFINIDO
Modelo V3: DEFINIDO
Implementación: PENDIENTE
Inventario real VPS: PENDIENTE
Cambios en producción: NINGUNO
```

La implementación deberá comenzar por el inventario en modo exclusivamente lectura antes de crear automatizaciones con capacidad de modificación.

---

# 96. Principio de implementación

Cada fase deberá cumplir:

```text
DESARROLLAR
↓
PROBAR
↓
VALIDAR
↓
DOCUMENTAR
↓
COMMIT
↓
SIGUIENTE FASE
```

Las nuevas funcionalidades deberán mantenerse en ramas independientes hasta completar sus pruebas.

La integración con producción requerirá:

```text
TESTS
BUILD
BACKUP VERIFICADO
AUTORIZACIÓN
DEPLOY
VALIDACIÓN
LOGS
```

---

# 97. Objetivo final

Construir un operador inteligente que convierta la administración del VPS en una experiencia:

- centralizada;
- visual;
- conversacional;
- segura;
- verificable;
- reversible;
- automatizable;
- comprensible.

No será simplemente un panel de administración.

No será simplemente Codex CLI.

No será simplemente un chatbot.

Será una plataforma de operaciones inteligentes para gestionar infraestructura, software y servicios desde una única capa de control.

**Cibermedida VPS Control Center será el punto central de administración, desarrollo, supervisión y recuperación del ecosistema alojado en el VPS.**