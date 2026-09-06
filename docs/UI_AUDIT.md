# Auditoría de la interfaz Control Center

## Estado actual

La web de `web/readonly-shell` es una interfaz de operación visual, en
castellano y orientada a lectura. La composición actual contiene:

- cabecera de producto, entorno, estado de ejecución y modo de datos;
- búsqueda de secciones y paleta de navegación con `Ctrl/Cmd + K`;
- navegación lateral en escritorio y navegación desplazable en móvil;
- dashboard con puntuación de salud, métricas, topología declarada,
  actividad reciente y proyectos;
- evolución de fases y estado de capacidades;
- cadena Policy -> Approval -> ApprovedExecutionPlan -> DryRun ->
  ExecutionGate -> ControlledExecutor;
- matriz de policy, vista de auditoría metadata-only y límites de seguridad;
- vistas operativas de conversación, aprobaciones, servidor, proyectos,
  testing, builds, deployments, rollback, backups, incidentes, monitorización,
  seguridad, agentes y conocimiento V3.

## Fuente de datos

La pantalla intenta `GET /api/status`, después `./data/status.json` y por
último usa un objeto incluido en `app.js`. El dashboard visual no inventa
datos del host: sus valores provienen del bloque `dashboard` del status mock o
de una respuesta de API con el mismo contrato.

La etiqueta de ejecución permanece visible como `Ejecución real bloqueada` y
los estados del dashboard distinguen `metadata-only`, provider deshabilitado,
datos estáticos y entorno de laboratorio.

## Accesibilidad y responsive

- `lang="es"`, skip link y `main` enfocable.
- navegación con `aria-current` y foco visible.
- diálogo de paleta etiquetado y cierre con Escape.
- estados vacíos seguros para listas, tablas, métricas, topología y actividad.
- `role="progressbar"` para salud y cobertura de proyectos.
- `prefers-reduced-motion` conservado.
- layout de sidebar a navegación horizontal en pantallas estrechas.
- contraste oscuro con verde, cian, ámbar y rojo para estados, sin depender
  solo del color.

## Seguridad de la UI

La búsqueda y la paleta solo navegan por anchors internos. No construyen URLs
externas, no guardan información en el navegador y no convierten texto de
chat en comandos. Los formularios de workflow, cuando están disponibles,
llaman a endpoints autenticados con CSRF y siguen sujetos a policy, aprobación,
dry-run, integridad y `blocked_by_default`.

La UI no debe interpretarse como una consola de producción hasta completar el
runbook de activación. En particular, ningún badge de salud del dashboard
representa una métrica live mientras `live_data` sea falso.

## Verificación recomendada

```text
jq empty web/readonly-shell/data/status.json
node --check web/readonly-shell/app.js
git diff --check
```

La comprobación visual manual debe cubrir escritorio, móvil, teclado, diálogo
de búsqueda, fallback sin API y ausencia de solapamientos. La auditoría WCAG
automática todavía no está incorporada al repositorio.
