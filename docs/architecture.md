# Arquitectura

Este documento resume la arquitectura conceptual definida por la especificacion maestra.

## Vision

Cibermedida VPS Control Center sera una capa inteligente entre el usuario y la infraestructura del VPS. No sera un shell remoto ni un chatbot con acceso directo a produccion.

Flujo maestro:

```text
USUARIO
  -> WEB / CHAT / CLI
  -> SUPERVISOR IA
  -> KNOWLEDGE ENGINE
  -> AI PLANNER
  -> IMPACT ANALYSIS
  -> RISK ASSESSMENT
  -> POLICY ENGINE
  -> AGENT MANAGER
  -> AGENTES / CODEX CLI
  -> EXECUTOR CONTROLADO
  -> VALIDATOR
  -> MONITORING
  -> AUDIT
```

## Separacion de responsabilidades

- Web Control Center: interfaz visual, dashboard, chat, auditoria y autorizaciones.
- API Gateway: entrada controlada a las capacidades internas.
- Supervisor IA: interpreta solicitudes, identifica contexto y coordina agentes.
- Knowledge Engine: mantiene conocimiento estructurado del VPS.
- AI Planner: transforma intenciones en planes tecnicos.
- Impact Analysis: estima dependencias, servicios afectados, riesgo de datos y rollback.
- Policy Engine: aplica reglas verificables de seguridad y autorizacion.
- Agent Manager: delega en agentes especializados.
- Executor Controlado: unico componente autorizado para ejecutar comandos sensibles.
- Validator: verifica de forma independiente el resultado de acciones relevantes.
- Monitoring: observa estado, metricas, servicios, certificados y anomalias.
- Audit Engine: registra acciones, autorizaciones, comandos, resultados y evidencias.

## Principio operativo

Las peticiones conversacionales deben producir analisis, planes y autorizaciones cuando corresponda. No deben convertirse directamente en comandos sobre produccion.

## Evolucion prevista

La arquitectura debe permitir evolucion futura hacia:

- interfaz web completa;
- chat IA en modo inicialmente solo lectura;
- integracion con Codex CLI;
- backups verificados;
- despliegues autorizados;
- rollback;
- monitorizacion;
- gestion de incidentes;
- Knowledge Engine avanzado;
- Digital Twin;
- analisis de impacto;
- deteccion de drift y anomalias;
- operacion multi-servidor.
