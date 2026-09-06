const fallbackStatus = {
  "product": {
    "name": "Cibermedida VPS Control Center",
    "phase": "Fase 3.6 Integración read-only",
    "context": "Producción protegida",
    "executionStatus": "Ejecución real bloqueada"
  },
  "navigation": [
    {
      "label": "Panel",
      "target": "dashboard"
    },
    {
      "label": "Capacidades",
      "target": "capabilities"
    },
    {
      "label": "Core Operator",
      "target": "core-operator"
    },
    {
      "label": "Política",
      "target": "policy"
    },
    {
      "label": "Vista de auditoría",
      "target": "audit-preview"
    },
    {
      "label": "Límites de seguridad",
      "target": "safety-boundaries"
    },
    {
      "label": "Inteligencia V3",
      "target": "v3-intelligence"
    },
    {
      "label": "Fuente de datos",
      "target": "data-source"
    }
  ],
  "phases": [
    {
      "label": "Fase 1",
      "title": "READ_SAFE básico completado",
      "state": "complete",
      "summary": "Los metadatos mínimos autorizados de inventario se validaron sin persistir salida de inventario."
    },
    {
      "label": "Fase 2",
      "title": "Core Operator cerrado",
      "state": "complete",
      "summary": "Los contratos de política, aprobaciones, dry-run, execution gate y controlled executor están implementados."
    },
    {
      "label": "Fase 3.5",
      "title": "Interfaz solo lectura en castellano",
      "state": "complete",
      "summary": "La navegación por teclado, los estados vacíos seguros y la presentación responsive se mantienen sin acciones operativas."
    },
    {
      "label": "Fase 3.6",
      "title": "Integración read-only",
      "state": "current",
      "summary": "La web puede consumir una API local segura con datos simulados y mantiene fallback estático."
    }
  ],
  "securityChain": [
    {
      "name": "Policy",
      "state": "evalúa"
    },
    {
      "name": "Approval",
      "state": "con aprobación"
    },
    {
      "name": "ApprovedExecutionPlan",
      "state": "contrato"
    },
    {
      "name": "DryRun",
      "state": "solo metadatos"
    },
    {
      "name": "ExecutionGate",
      "state": "comprueba elegibilidad"
    },
    {
      "name": "ControlledExecutor",
      "state": "blocked_by_default"
    }
  ],
  "components": [
    "OperatorConfig",
    "safe logging",
    "audit",
    "PolicyEngine",
    "ReadSafeExecutorAdapter",
    "Approval workflow",
    "ApprovedExecutionPlan",
    "ApprovedPlanDryRunner",
    "ExecutionGate",
    "ControlledExecutor"
  ],
  "blockedByDesign": [
    "Sin ejecución real",
    "Sin privilegios elevados",
    "Sin exposición de credenciales",
    "Sin registros operativos crudos",
    "Sin acceso a backups ni bases de datos",
    "Sin modificación de servicios",
    "Sin inventario automático"
  ],
  "policyMatrix": [
    {
      "className": "READ_SAFE",
      "decision": "allow",
      "execution": "Solo metadatos",
      "uiTreatment": "Visible como estado solo lectura"
    },
    {
      "className": "READ_SENSITIVE",
      "decision": "approval_required",
      "execution": "No automática",
      "uiTreatment": "Mostrado como sujeto a aprobación"
    },
    {
      "className": "READ_PRIVILEGED",
      "decision": "approval_required",
      "execution": "No automática",
      "uiTreatment": "Mostrado como sujeto a aprobación"
    },
    {
      "className": "FORBIDDEN",
      "decision": "deny",
      "execution": "Bloqueada",
      "uiTreatment": "Mostrado como rechazado"
    },
    {
      "className": "acciones modificadoras",
      "decision": "deny",
      "execution": "Bloqueada",
      "uiTreatment": "Mostrado como rechazado"
    }
  ],
  "uiCapabilities": [
    "Ver estado",
    "Ver resumen documental",
    "Ver estados de política",
    "Ver ejemplos de auditoría solo metadatos",
    "Navegación por secciones accesible con teclado",
    "Ver fuente de datos simulados estática",
    "Solicitar validaciones, builds y análisis read-only con sesión autorizada",
    "Sin despliegues ni acciones modificadoras"
  ],
  "auditPreview": {
    "acción": "execution_gate_evaluated",
    "riesgo": "BAJO",
    "resultado": "blocked_by_default",
    "contenido": "solo metadatos"
  },
  "dataSource": {
    "mode": "datos simulados estáticos",
    "path": "web/readonly-shell/data/status.json",
    "liveData": false,
    "backend": false
  },
  "dashboard": {
    "healthScore": 92,
    "healthLabel": "Estable",
    "environment": "Laboratorio controlado",
    "refreshed": "06 sep 2026 · 09:30",
    "mode": "Metadata-only",
    "authorization": "Requerida",
    "provider": "Deshabilitado",
    "review": "Fase 3.6",
    "metrics": [
      { "label": "Proyectos catalogados", "value": "04", "detail": "declarados", "trend": "estable", "state": "stable" },
      { "label": "Operaciones en espera", "value": "00", "detail": "sin ejecución", "trend": "controlado", "state": "stable" },
      { "label": "Controles de seguridad", "value": "18", "detail": "activos", "trend": "100%", "state": "good" },
      { "label": "Incidentes abiertos", "value": "00", "detail": "metadata-only", "trend": "estable", "state": "stable" }
    ],
    "infrastructure": [
      { "label": "VPS / laboratorio", "type": "Servidor", "state": "declarado", "detail": "sin conexión operativa" },
      { "label": "Control Center", "type": "Aplicación", "state": "activo", "detail": "API local + UI" },
      { "label": "Knowledge Engine", "type": "Catálogo", "state": "metadata-only", "detail": "relaciones declaradas" }
    ],
    "activity": [
      { "time": "09:30", "title": "Estado de seguridad evaluado", "detail": "execution_gate_evaluated · bloqueado por defecto", "kind": "security" },
      { "time": "09:12", "title": "Contrato de operación actualizado", "detail": "manifiesto y hashes de integridad verificados", "kind": "change" },
      { "time": "08:45", "title": "Catálogo de proyectos sincronizado", "detail": "datos declarados · sin stdout/stderr", "kind": "catalog" }
    ],
    "projects": [
      { "name": "Control Center", "branch": "main", "status": "estable", "coverage": 100, "detail": "UI, API y contratos" },
      { "name": "Core Operator", "branch": "main", "status": "protegido", "coverage": 100, "detail": "policy, approval y gate" },
      { "name": "Documentación", "branch": "main", "status": "actualizada", "coverage": 86, "detail": "fases y autorización" },
      { "name": "Laboratorio", "branch": "lab", "status": "aislado", "coverage": 72, "detail": "fixtures metadata-only" }
    ]
  }
};

fallbackStatus.views = [
  {
    "id": "conversation",
    "label": "Conversación",
    "eyebrow": "Centro conversacional",
    "title": "Planificador conversacional seguro",
    "state": "read_only",
    "summary": "La API local puede clasificar solicitudes y preparar planes metadata-only después de iniciar sesión.",
    "items": [
      "Requiere sesión y protección CSRF.",
      "No hay proveedor IA externo conectado.",
      "No se ejecutan diagnósticos ni operaciones desde el chat."
    ]
  },
  {
    "id": "approval-workflow",
    "label": "Aprobaciones",
    "eyebrow": "Autorización independiente",
    "title": "Solicitudes y decisiones de aprobación",
    "state": "read_only",
    "summary": "La API permite recorrer el contrato de aprobación y evaluar una cadena READ_SAFE sin exponer salida operativa.",
    "items": [
      "El solicitante y el aprobador deben ser cuentas distintas.",
      "La decisión queda registrada como metadatos.",
      "La evaluación termina bloqueada si no hay proveedor explícito."
    ]
  },
  {
    "id": "server",
    "label": "Servidor",
    "eyebrow": "Estado del servidor",
    "title": "Superficie segura del servidor",
    "state": "read_only",
    "summary": "La API local puede mostrar contratos y salud interna, pero no consulta el VPS real.",
    "items": [
      "Datos operativos reales: no conectados.",
      "Health del Core Operator: disponible sin sondas de red.",
      "Ejecución real: bloqueada por diseño."
    ]
  },
  {
    "id": "projects",
    "label": "Proyectos",
    "eyebrow": "Inventario de proyectos",
    "title": "Proyectos y Git declarados",
    "state": "read_only",
    "summary": "La API puede recoger únicamente rama, estado y HEAD mediante un proveedor READ_SAFE explícito.",
    "items": [
      "La colección no devuelve stdout ni stderr crudos.",
      "No se crean ramas, no se hace push y no se ejecuta merge.",
      "Sin proveedor habilitado, el estado permanece blocked_by_default."
    ]
  },
  {
    "id": "services",
    "label": "Servicios",
    "eyebrow": "Servicios del VPS",
    "title": "Servicios no consultados",
    "state": "blocked",
    "summary": "La UI no ejecuta systemd, PM2, Docker, Apache ni SSH y no lee sus estados reales.",
    "items": [
      "Sin reinicios ni modificaciones.",
      "Sin lectura de logs o procesos.",
      "Sin llamadas a servicios del sistema."
    ]
  },
  {
    "id": "git",
    "label": "Git",
    "eyebrow": "Control de cambios",
    "title": "Git disponible como contrato",
    "state": "read_only",
    "summary": "La política exige ramas y revisión, pero esta UI no crea ramas ni modifica repositorios.",
    "items": [
      "Main protegida por flujo de ramas.",
      "Sin merge ni push desde la web.",
      "Los cambios deben pasar por revisión y pruebas."
    ]
  },
  {
    "id": "testing",
    "label": "Testing",
    "eyebrow": "Validación",
    "title": "Validación y tests acotados",
    "state": "read_only",
    "summary": "El Validator evalúa checks declarados y puede solicitar el target repository con un provider explícito.",
    "items": [
      "Los checks los aporta una capa autorizada.",
      "El runner solo acepta el target repository y descarta la salida.",
      "Sin provider explícito, la ejecución permanece blocked_by_default."
    ]
  },
  {
    "id": "builds",
    "label": "Builds",
    "eyebrow": "Construcción declarada",
    "title": "Builds acotados por perfil",
    "state": "read_only",
    "summary": "La API puede ejecutar únicamente un perfil argv declarado al arrancar y conserva métricas sin salida cruda.",
    "items": [
      "El target selecciona un perfil de configuración, no un comando de la petición.",
      "El provider requiere RUN_BUILDS y una sesión autorizada.",
      "No se modifican servicios, repositorios ni archivos fuera del proyecto declarado."
    ]
  },
  {
    "id": "deployments",
    "label": "Deployments",
    "eyebrow": "Despliegues",
    "title": "Preflight de despliegue sin ejecución",
    "state": "blocked",
    "summary": "La API puede registrar checks, backup y aprobación independiente, pero no despliega.",
    "items": [
      "Requiere autenticación, CSRF y autorización.",
      "Requiere tests, build, impacto y backup verificado.",
      "El ControlledExecutor permanece bloqueado."
    ]
  },
  {
    "id": "rollbacks",
    "label": "Rollback",
    "eyebrow": "Recuperación controlada",
    "title": "Plan de rollback sin ejecución",
    "state": "blocked",
    "summary": "La API registra preparación y aprobación independiente, pero el proveedor de rollback permanece deshabilitado.",
    "items": [
      "Se exige una cuenta aprobadora distinta.",
      "No se restauran código, archivos ni datos.",
      "La solicitud de ejecución queda bloqueada por defecto."
    ]
  },
  {
    "id": "backups",
    "label": "Backups",
    "eyebrow": "Protección de datos",
    "title": "Catálogo de backup simulado",
    "state": "blocked",
    "summary": "La API mantiene el ciclo prepare, verify y restore test únicamente en memoria.",
    "items": [
      "No hay acceso a rutas ni contenido de backup.",
      "No hay persistencia automática.",
      "El restore test es solo contractual."
    ]
  },
  {
    "id": "incidents",
    "label": "Incidentes",
    "eyebrow": "Gestión de incidentes",
    "title": "Ciclo de incidentes en memoria",
    "state": "read_only",
    "summary": "La API registra estado, notas de investigación y resolución sin leer logs ni ejecutar mitigaciones.",
    "items": [
      "No se analizan logs reales.",
      "No se correlacionan cambios de producción automáticamente.",
      "No se ejecutan recuperaciones automáticas."
    ]
  },
  {
    "id": "monitoring",
    "label": "Monitorización",
    "eyebrow": "Observabilidad",
    "title": "Monitorización de metadatos",
    "state": "blocked",
    "summary": "El servicio puede evaluar snapshots aportados, pero no recoge métricas reales ni genera alertas externas.",
    "items": [
      "Health checks de red: deshabilitados.",
      "Métricas: datos reales no disponibles.",
      "Alertas: no se generan desde esta aplicación."
    ]
  },
  {
    "id": "security",
    "label": "Seguridad",
    "eyebrow": "Centro de seguridad",
    "title": "Límites de seguridad activos",
    "state": "read_only",
    "summary": "La UI muestra políticas y límites, pero no modifica firewall, SSH, usuarios ni servicios.",
    "items": [
      "Denegación por defecto.",
      "Aprobación separada para operaciones sensibles.",
      "Sin exposición de secretos ni credenciales."
    ]
  },
  {
    "id": "agents",
    "label": "Agentes",
    "eyebrow": "Agent Manager",
    "title": "Agent Manager de planificación",
    "state": "read_only",
    "summary": "Los agentes están catalogados; Codex puede preparar análisis metadata-only en laboratorio, siempre sin modificar repositorios.",
    "items": [
      "Supervisor, Planner y Validator: contratos locales.",
      "Codex: provider sintético de análisis, sin CLI ni cambios de código.",
      "Deploy y Backup: sin adapters de producción.",
      "Sin ejecución concurrente de agentes."
    ]
  },
  {
    "id": "configuration",
    "label": "Configuración",
    "eyebrow": "Configuración segura",
    "title": "Configuración por defecto cerrada",
    "state": "read_only",
    "summary": "La configuración del Core Operator mantiene persistencia, red y ejecución real deshabilitadas.",
    "items": [
      "Sin carga de .env.",
      "Sin logs ni auditoría a disco por defecto.",
      "Sin configuración habilitante para producción."
    ]
  },
  {
    "id": "v3-intelligence",
    "label": "Inteligencia V3",
    "eyebrow": "Knowledge Engine y recuperación",
    "title": "Contratos V3 metadata-only",
    "state": "read_only",
    "summary": "Permite registrar gemelo digital, tendencias, servidores y planes de recuperación declarados sin conectar con el VPS.",
    "items": [
      "No descubre hosts ni relaciones automáticamente.",
      "Las predicciones solo calculan tendencias sobre snapshots aportados.",
      "La autonomía y la recuperación permanecen bloqueadas por defecto."
    ]
  }
];

fallbackStatus.capabilities = [
  {
    "capability_id": "authentication",
    "label": "Autenticación y roles",
    "phase": "Fase 3",
    "state": "provision_required",
    "live_data": false,
    "provider": null,
    "description": "Sesiones, CSRF y roles disponibles; la cuenta debe provisionarse explícitamente."
  },
  {
    "capability_id": "chat",
    "label": "Chat y planificación",
    "phase": "Fase 4",
    "state": "local_planner",
    "live_data": false,
    "provider": null,
    "description": "Planificador local determinista; no hay proveedor IA externo conectado."
  },
  {
    "capability_id": "audit",
    "label": "Auditoría metadata-only",
    "phase": "Fase 2/3",
    "state": "in_memory",
    "live_data": false,
    "provider": null,
    "description": "Registros en memoria sin secretos, stdout ni stderr crudos."
  },
  {
    "capability_id": "backups",
    "label": "Backups y restore test",
    "phase": "Fase 6",
    "state": "contract_only",
    "live_data": false,
    "provider": null,
    "description": "Ciclo contractual sin acceso a rutas ni contenido de backup."
  },
  {
    "capability_id": "deployments",
    "label": "Despliegues",
    "phase": "Fase 7",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": null,
    "description": "Preflight y aprobación disponibles; despliegue real deshabilitado."
  },
  {
    "capability_id": "rollback",
    "label": "Rollback",
    "phase": "Fase 8",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": null,
    "description": "Contrato preparado; no restaura código, archivos ni datos reales."
  },
  {
    "capability_id": "monitoring",
    "label": "Monitorización y anomalías",
    "phase": "Fase 9/14",
    "state": "snapshot_only",
    "live_data": false,
    "provider": null,
    "description": "Evalúa snapshots aportados; no recoge métricas del VPS."
  },
  {
    "capability_id": "controlled_execution",
    "label": "Ejecución controlada",
    "phase": "Fase 2/15",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": null,
    "description": "La UI puede evaluar la cadena aprobada; el proveedor de ejecución permanece bloqueado por defecto."
  },
  {
    "capability_id": "inventory",
    "label": "Inventario READ_SAFE",
    "phase": "Fase 1/3",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": null,
    "description": "La colección READ_SAFE requiere una habilitación explícita y conserva el resultado solo en memoria."
  },
  {
    "capability_id": "testing",
    "label": "Testing Agent",
    "phase": "Fase 5",
    "state": "contract_only",
    "live_data": false,
    "provider": null,
    "description": "El target repository y las métricas metadata-only están definidos; la ejecución requiere un provider explícito."
  },
  {
    "capability_id": "builds",
    "label": "Builds declarados",
    "phase": "Fase 5/7",
    "state": "contract_only",
    "live_data": false,
    "provider": null,
    "description": "Los perfiles argv se declaran al arrancar; la ejecución conserva solo estado, retorno y duración."
  },
  {
    "capability_id": "codex",
    "label": "Integración Codex",
    "phase": "Fase 5",
    "state": "contract_only",
    "live_data": false,
    "provider": null,
    "description": "El análisis Codex queda limitado a proyectos declarados, sandbox read-only y metadata acotada."
  },
  {
    "capability_id": "knowledge_engine",
    "label": "Knowledge Engine y gemelo digital",
    "phase": "Fase 11",
    "state": "metadata_only",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Registra relaciones declaradas sin descubrir automáticamente el VPS."
  },
  {
    "capability_id": "impact_analysis",
    "label": "Análisis de impacto e histórico",
    "phase": "Fase 12",
    "state": "metadata_only",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Calcula correlaciones y requisitos sobre evidencia aportada."
  },
  {
    "capability_id": "predictive_analysis",
    "label": "Análisis predictivo prudente",
    "phase": "Fase 14",
    "state": "metadata_only",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Calcula tendencias acotadas sin activar alertas operativas."
  },
  {
    "capability_id": "project_autonomy",
    "label": "Autonomía por proyecto",
    "phase": "Fase 15",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Registra el nivel solicitado y mantiene la ejecución bloqueada."
  },
  {
    "capability_id": "multi_server",
    "label": "Catálogo multi-servidor",
    "phase": "V3",
    "state": "metadata_only",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Registra servidores declarados sin abrir conexiones."
  },
  {
    "capability_id": "controlled_recovery",
    "label": "Recuperación controlada",
    "phase": "V3",
    "state": "blocked_by_default",
    "live_data": false,
    "provider": "V3InsightsService",
    "description": "Prepara planes vinculados a incidentes y exige aprobación independiente."
  }
];

fallbackStatus.navigation = [
  ...fallbackStatus.navigation.filter(
    (item) => item.target !== "data-source" && !fallbackStatus.views.some((view) => view.id === item.target)
  ),
  ...fallbackStatus.views.map((view) => ({ label: view.label, target: view.id })),
  { label: "Fuente de datos", target: "data-source" }
];

const navigationGroups = [
  {
    label: "Resumen",
    title: "Resumen general",
    description: "Estado global, alertas y actividad reciente.",
    targets: ["dashboard", "capabilities"],
  },
  {
    label: "Infraestructura",
    title: "Infraestructura",
    description: "Servidores, servicios y monitorización segura.",
    targets: ["server", "services", "monitoring"],
  },
  {
    label: "Operaciones",
    title: "Operaciones",
    description: "Proyectos, validaciones, cambios y recuperación.",
    targets: ["projects", "git", "testing", "builds", "deployments", "rollbacks", "backups", "incidents"],
  },
  {
    label: "Control",
    title: "Gobierno y control",
    description: "Políticas, aprobaciones, auditoría y seguridad.",
    targets: [
      "conversation", "approval-workflow", "core-operator", "policy", "audit-preview",
      "safety-boundaries", "security", "agents", "configuration", "v3-intelligence", "data-source",
    ],
  },
];

const navigationIcons = {
  dashboard: "RE",
  capabilities: "CA",
  server: "SV",
  services: "SE",
  monitoring: "MO",
  projects: "PR",
  git: "GT",
  testing: "TS",
  builds: "BL",
  deployments: "DP",
  rollbacks: "RB",
  backups: "BK",
  incidents: "IN",
  conversation: "IA",
  "approval-workflow": "AP",
  "core-operator": "CO",
  policy: "PO",
  "audit-preview": "AU",
  "safety-boundaries": "LS",
  security: "SG",
  agents: "AG",
  configuration: "CF",
  "v3-intelligence": "V3",
  "data-source": "DT",
};

const text = (value) => document.createTextNode(String(value));

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function appendList(container, items, className) {
  clear(container);
  if (!Array.isArray(items) || items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.appendChild(text("No hay elementos simulados disponibles."));
    container.appendChild(empty);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    if (className) {
      li.className = className;
    }
    li.appendChild(text(item));
    container.appendChild(li);
  });
}

function navigationGroupFor(target) {
  return navigationGroups.find((group) => group.targets.includes(target)) || navigationGroups[3];
}

function updateCurrentNavigation() {
  const requestedTarget = window.location.hash.slice(1) || "dashboard";
  const availableSections = [...document.querySelectorAll(".page-section")];
  const currentSection = availableSections.find((section) => section.id === requestedTarget)
    || availableSections.find((section) => section.id === "dashboard");
  const currentTarget = currentSection?.id || "dashboard";
  availableSections.forEach((section) => {
    section.hidden = section.id !== currentTarget;
  });
  document.querySelectorAll("[data-navigation] a").forEach((link) => {
    if (link.getAttribute("href") === `#${currentTarget}`) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
  const activeLink = document.querySelector(`[data-navigation] a[href="#${CSS.escape(currentTarget)}"]`);
  const group = navigationGroupFor(currentTarget);
  const groupNode = document.querySelector("[data-current-group]");
  const pageNode = document.querySelector("[data-current-page]");
  const contextTitle = document.querySelector("[data-sidebar-context-title]");
  const contextCopy = document.querySelector("[data-sidebar-context-copy]");
  if (groupNode) groupNode.textContent = group.label;
  if (pageNode) pageNode.textContent = activeLink?.dataset.label || activeLink?.textContent.trim() || "Panel";
  if (contextTitle) contextTitle.textContent = group.title;
  if (contextCopy) contextCopy.textContent = group.description;
  if (requestedTarget !== currentTarget) {
    window.history.replaceState(null, "", `#${currentTarget}`);
  }
}

function renderNavigation(items) {
  const container = document.querySelector("[data-navigation]");
  clear(container);
  if (!Array.isArray(items) || items.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.appendChild(text("La navegación de secciones no está disponible."));
    container.appendChild(empty);
    return;
  }
  navigationGroups.forEach((groupDefinition) => {
    const groupItems = items.filter((item) => groupDefinition.targets.includes(item.target));
    if (groupItems.length === 0) return;
    const group = document.createElement("section");
    group.className = "nav-group";
    group.dataset.navGroup = groupDefinition.label;
    const heading = document.createElement("h2");
    heading.className = "nav-group-title";
    heading.appendChild(text(groupDefinition.label));
    const list = document.createElement("ul");
    groupItems.forEach((item) => {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = `#${item.target}`;
      link.dataset.label = item.label;
      link.setAttribute("aria-label", item.label);
      const icon = document.createElement("span");
      icon.className = "nav-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.appendChild(text(navigationIcons[item.target] || "·"));
      const label = document.createElement("span");
      label.className = "nav-label";
      label.appendChild(text(item.label));
      link.append(icon, label);
      li.appendChild(link);
      list.appendChild(li);
    });
    group.append(heading, list);
    container.appendChild(group);
  });
}

function renderPhases(phases) {
  const container = document.querySelector("[data-phases]");
  clear(container);
  if (!Array.isArray(phases) || phases.length === 0) {
    const empty = document.createElement("article");
    empty.className = "phase-card empty-state";
    empty.appendChild(text("No hay estado simulado de fases disponible."));
    container.appendChild(empty);
    return;
  }
  phases.forEach((phase) => {
    const article = document.createElement("article");
    article.className = `phase-card ${phase.state === "current" ? "current" : "complete"}`;
    const label = document.createElement("span");
    label.className = "phase-index";
    label.appendChild(text(phase.label));
    const title = document.createElement("h2");
    title.appendChild(text(phase.title));
    const summary = document.createElement("p");
    summary.appendChild(text(phase.summary));
    article.append(label, title, summary);
    container.appendChild(article);
  });
}

function renderChain(chain) {
  const container = document.querySelector("[data-chain]");
  clear(container);
  if (!Array.isArray(chain) || chain.length === 0) {
    appendList(container, [], "empty-state");
    return;
  }
  chain.forEach((step) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.appendChild(text(step.name));
    const state = document.createElement("strong");
    state.appendChild(text(step.state));
    li.append(name, state);
    container.appendChild(li);
  });
}

function renderPolicy(rows) {
  const tbody = document.querySelector("[data-policy-matrix]");
  clear(tbody);
  if (!Array.isArray(rows) || rows.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "empty-state";
    td.appendChild(text("No hay decisiones simuladas de política disponibles."));
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const classCell = document.createElement("td");
    classCell.appendChild(text(row.className));
    const decisionCell = document.createElement("td");
    const decision = document.createElement("span");
    decision.className = `decision ${row.decision === "allow" ? "allow" : row.decision === "deny" ? "deny" : "pending"}`;
    decision.appendChild(text(row.decision));
    decisionCell.appendChild(decision);
    const executionCell = document.createElement("td");
    executionCell.appendChild(text(row.execution));
    const treatmentCell = document.createElement("td");
    treatmentCell.appendChild(text(row.uiTreatment));
    tr.append(classCell, decisionCell, executionCell, treatmentCell);
    tbody.appendChild(tr);
  });
}

function renderAudit(audit) {
  const container = document.querySelector("[data-audit-preview]");
  clear(container);
  if (!audit || Object.keys(audit).length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.appendChild(text("No hay metadatos simulados de auditoría disponibles."));
    container.appendChild(empty);
    return;
  }
  Object.entries(audit).forEach(([key, value]) => {
    const item = document.createElement("div");
    const dt = document.createElement("dt");
    dt.appendChild(text(key));
    const dd = document.createElement("dd");
    dd.appendChild(text(value));
    item.append(dt, dd);
    container.appendChild(item);
  });
}

function renderDataSource(source) {
  const dataSource = source || fallbackStatus.dataSource;
  document.querySelector("[data-source-mode]").textContent = dataSource.mode;
  document.querySelector("[data-source-path]").textContent = dataSource.path;
  document.querySelector("[data-source-live]").textContent = dataSource.liveData ? "sí" : "no";
  document.querySelector("[data-source-backend]").textContent = dataSource.backend ? "sí, solo lectura" : "no";
}

function renderCapabilities(capabilities) {
  const container = document.querySelector("[data-capability-grid]");
  clear(container);
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    const empty = document.createElement("article");
    empty.className = "capability-card empty-state";
    empty.appendChild(text("No hay estado de capacidades disponible."));
    container.appendChild(empty);
    return;
  }
  const stateLabels = {
    persistent: "Persistente",
    provision_required: "Requiere provisionar",
    local_planner: "Planificador local",
    provider_ready: "Proveedor preparado",
    in_memory: "En memoria",
    contract_only: "Solo contrato",
    blocked_by_default: "Bloqueado por defecto",
    snapshot_only: "Solo snapshots",
    provider_enabled: "Proveedor habilitado"
  };
  capabilities.forEach((capability) => {
    const card = document.createElement("article");
    card.className = `capability-card ${capability.state === "blocked_by_default" ? "blocked" : ""}`;
    const heading = document.createElement("div");
    heading.className = "capability-card-heading";
    const title = document.createElement("h3");
    title.appendChild(text(capability.label));
    const state = document.createElement("span");
    state.className = "capability-state";
    state.appendChild(text(stateLabels[capability.state] || capability.state));
    heading.append(title, state);
    const phase = document.createElement("p");
    phase.className = "capability-phase";
    phase.appendChild(text(capability.phase));
    const description = document.createElement("p");
    description.className = "capability-description";
    description.appendChild(text(capability.description));
    const provider = document.createElement("p");
    provider.className = "capability-provider";
    provider.appendChild(text(capability.provider ? `Proveedor: ${capability.provider}` : "Sin proveedor externo"));
    card.append(heading, phase, description, provider);
    container.appendChild(card);
  });
}

function renderDashboardVisuals(dashboard) {
  const data = dashboard || {};
  const score = Math.max(0, Math.min(100, Number(data.healthScore) || 0));
  const scoreNode = document.querySelector("[data-health-score]");
  const labelNode = document.querySelector("[data-health-label]");
  const environmentNode = document.querySelector("[data-health-environment]");
  const refreshedNode = document.querySelector("[data-health-refreshed]");
  const meter = document.querySelector("[data-health-meter]");
  if (scoreNode) scoreNode.textContent = String(score);
  if (labelNode) labelNode.textContent = data.healthLabel || "Sin datos";
  if (environmentNode) environmentNode.textContent = data.environment || "Entorno no declarado";
  if (refreshedNode) refreshedNode.textContent = formatDashboardTimestamp(data.refreshed);
  if (meter) {
    meter.setAttribute("aria-valuenow", String(score));
    const fill = meter.querySelector("span");
    if (fill) fill.style.width = `${score}%`;
  }

  const summaryValues = {
    "[data-dashboard-mode]": data.mode || "Metadata-only",
    "[data-dashboard-authorization]": data.authorization || "Requerida",
    "[data-dashboard-provider]": data.provider || "Deshabilitado",
    "[data-dashboard-review]": data.review || "Sin revisión",
  };
  Object.entries(summaryValues).forEach(([selector, value]) => {
    const node = document.querySelector(selector);
    if (node) node.textContent = value;
  });

  const metrics = document.querySelector("[data-dashboard-metrics]");
  if (metrics) clear(metrics);
  if (!metrics || !Array.isArray(data.metrics) || data.metrics.length === 0) {
    if (metrics) metrics.appendChild(emptyDashboardItem("No hay métricas simuladas disponibles."));
  } else {
    data.metrics.forEach((metric) => {
      const card = document.createElement("article");
      card.className = `metric-card ${metric.state === "good" ? "good" : "stable"}`;
      const label = document.createElement("span");
      label.className = "metric-label";
      label.appendChild(text(metric.label || "Métrica"));
      const value = document.createElement("strong");
      value.className = "metric-value";
      value.appendChild(text(metric.value || "--"));
      const detail = document.createElement("span");
      detail.className = "metric-detail";
      detail.appendChild(text(metric.detail || "sin detalle"));
      const trend = document.createElement("span");
      trend.className = "metric-trend";
      trend.appendChild(text(metric.trend || "sin variación"));
      card.append(label, value, detail, trend);
      metrics.appendChild(card);
    });
  }

  const infrastructure = document.querySelector("[data-infrastructure-map]");
  if (infrastructure) clear(infrastructure);
  if (!infrastructure || !Array.isArray(data.infrastructure) || data.infrastructure.length === 0) {
    if (infrastructure) infrastructure.appendChild(emptyDashboardItem("No hay topología declarada."));
  } else {
    const table = createCompactTable("Infraestructura declarada", ["Elemento", "Tipo", "Estado", "Detalle", ""]);
    const body = table.querySelector("tbody");
    data.infrastructure.forEach((nodeData) => {
      const row = document.createElement("tr");
      appendTableCell(row, nodeData.label || "Sin nombre", "table-primary");
      appendTableCell(row, nodeData.type || "Nodo");
      appendTableCell(row, nodeData.state || "declarado", "status-cell");
      appendTableCell(row, nodeData.detail || "metadata-only", "table-muted");
      const actionCell = document.createElement("td");
      actionCell.appendChild(detailButton("Ver detalles", "Infraestructura", nodeData.label || "Sin nombre", nodeData));
      row.appendChild(actionCell);
      body.appendChild(row);
    });
    infrastructure.appendChild(table);
  }

  const activity = document.querySelector("[data-activity-feed]");
  if (activity) clear(activity);
  if (!activity || !Array.isArray(data.activity) || data.activity.length === 0) {
    if (activity) {
      const empty = document.createElement("li");
      empty.className = "empty-state dashboard-empty";
      empty.appendChild(text("No hay actividad simulada."));
      activity.appendChild(empty);
    }
  } else {
    data.activity.forEach((entry) => {
      const item = document.createElement("li");
      item.className = `activity-item ${entry.kind || "system"}`;
      const time = document.createElement("time");
      time.appendChild(text(entry.time || "--:--"));
      const marker = document.createElement("span");
      marker.className = "activity-marker";
      marker.setAttribute("aria-hidden", "true");
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      title.appendChild(text(entry.title || "Evento"));
      const detail = document.createElement("span");
      detail.appendChild(text(entry.detail || "metadata-only"));
      copy.append(title, detail);
      item.append(time, marker, copy);
      activity.appendChild(item);
    });
  }

  const projects = document.querySelector("[data-project-cards]");
  if (projects) clear(projects);
  if (!projects || !Array.isArray(data.projects) || data.projects.length === 0) {
    if (projects) projects.appendChild(emptyDashboardItem("No hay proyectos declarados."));
  } else {
    const table = createCompactTable("Proyectos declarados", ["Proyecto", "Rama", "Estado", "Cobertura", ""]);
    const body = table.querySelector("tbody");
    data.projects.forEach((project) => {
      const row = document.createElement("tr");
      appendTableCell(row, project.name || "Proyecto", "table-primary");
      appendTableCell(row, project.branch || "no declarada", "code-cell");
      appendTableCell(row, project.status || "declarado", "status-cell");
      const coverage = Math.max(0, Math.min(100, Number(project.coverage) || 0));
      const coverageCell = document.createElement("td");
      const coverageWrap = document.createElement("div");
      coverageWrap.className = "table-progress-wrap";
      const coverageValue = document.createElement("span");
      coverageValue.appendChild(text(`${coverage}%`));
      const bar = document.createElement("div");
      bar.className = "project-progress";
      bar.setAttribute("role", "progressbar");
      bar.setAttribute("aria-label", `Cobertura de ${project.name || "proyecto"}`);
      bar.setAttribute("aria-valuenow", String(coverage));
      bar.setAttribute("aria-valuemin", "0");
      bar.setAttribute("aria-valuemax", "100");
      const fill = document.createElement("span");
      fill.style.width = `${coverage}%`;
      bar.appendChild(fill);
      coverageWrap.append(coverageValue, bar);
      coverageCell.appendChild(coverageWrap);
      row.appendChild(coverageCell);
      const actionCell = document.createElement("td");
      actionCell.appendChild(detailButton("Ver detalles", "Proyecto", project.name || "Proyecto", project));
      row.appendChild(actionCell);
      body.appendChild(row);
    });
    projects.appendChild(table);
  }
}

function createCompactTable(captionText, columns) {
  const table = document.createElement("table");
  table.className = "compact-table";
  const caption = document.createElement("caption");
  caption.className = "visually-hidden";
  caption.appendChild(text(captionText));
  const head = document.createElement("thead");
  const headRow = document.createElement("tr");
  columns.forEach((column) => {
    const heading = document.createElement("th");
    heading.scope = "col";
    heading.appendChild(text(column));
    headRow.appendChild(heading);
  });
  head.appendChild(headRow);
  table.append(caption, head, document.createElement("tbody"));
  return table;
}

function appendTableCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.appendChild(text(value));
  row.appendChild(cell);
}

function detailButton(label, eyebrow, titleText, details) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "table-detail-button";
  button.appendChild(text(label));
  button.addEventListener("click", () => openDetailDrawer(eyebrow, titleText, details));
  return button;
}

function openDetailDrawer(eyebrowText, titleText, details) {
  const drawer = document.querySelector("[data-detail-drawer]");
  const eyebrow = document.querySelector("[data-detail-eyebrow]");
  const titleNode = document.querySelector("[data-detail-title]");
  const body = document.querySelector("[data-detail-body]");
  if (!drawer || !eyebrow || !titleNode || !body) return;
  eyebrow.textContent = eyebrowText;
  titleNode.textContent = titleText;
  clear(body);
  const list = document.createElement("dl");
  list.className = "detail-list";
  Object.entries(details || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    term.appendChild(text(key));
    const description = document.createElement("dd");
    description.appendChild(text(value));
    row.append(term, description);
    list.appendChild(row);
  });
  body.appendChild(list);
  if (typeof drawer.showModal === "function") drawer.showModal();
  else drawer.setAttribute("open", "");
}

function emptyDashboardItem(message) {
  const empty = document.createElement("p");
  empty.className = "empty-state dashboard-empty";
  empty.appendChild(text(message));
  return empty;
}

function formatDashboardTimestamp(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value || "Sin actualización registrada";
  return new Intl.DateTimeFormat("es-ES", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed).replace(",", " ·");
}

function navigationEntries() {
  return [...document.querySelectorAll("[data-navigation] a")].map((link) => ({
    label: link.textContent.trim(),
    target: link.getAttribute("href").slice(1),
  }));
}

function renderCommandResults(query = "") {
  const container = document.querySelector("[data-command-results]");
  if (!container) return;
  clear(container);
  const normalized = query.trim().toLocaleLowerCase("es");
  const entries = navigationEntries().filter((entry) => entry.label.toLocaleLowerCase("es").includes(normalized));
  if (entries.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.appendChild(text("No hay secciones que coincidan."));
    container.appendChild(empty);
    return;
  }
  entries.slice(0, 12).forEach((entry) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "command-result";
    button.dataset.target = entry.target;
    button.appendChild(text(entry.label));
    item.appendChild(button);
    container.appendChild(item);
  });
}

function bindNavigationTools() {
  const palette = document.querySelector("[data-command-palette]");
  const drawer = document.querySelector("[data-detail-drawer]");
  const openButton = document.querySelector("[data-command-open]");
  const closeButton = document.querySelector("[data-command-close]");
  const drawerClose = document.querySelector("[data-detail-close]");
  const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
  const commandSearch = document.querySelector("[data-command-search]");
  const globalSearch = document.querySelector("[data-global-search]");
  const openPalette = () => {
    renderCommandResults(commandSearch?.value || "");
    if (typeof palette?.showModal === "function") {
      palette.showModal();
    } else if (palette) {
      palette.setAttribute("open", "");
    }
    commandSearch?.focus();
  };
  const closePalette = () => {
    if (typeof palette?.close === "function") {
      palette.close();
    } else {
      palette?.removeAttribute("open");
    }
  };
  openButton?.addEventListener("click", openPalette);
  closeButton?.addEventListener("click", closePalette);
  drawerClose?.addEventListener("click", () => drawer?.close());
  drawer?.addEventListener("click", (event) => {
    if (event.target === drawer) drawer.close();
  });
  sidebarToggle?.addEventListener("click", () => {
    const collapsed = document.body.classList.toggle("sidebar-collapsed");
    sidebarToggle.setAttribute("aria-expanded", String(!collapsed));
    sidebarToggle.setAttribute("aria-label", collapsed ? "Expandir menú lateral" : "Contraer menú lateral");
    sidebarToggle.title = collapsed ? "Expandir menú lateral" : "Contraer menú lateral";
    sidebarToggle.querySelector("span").textContent = collapsed ? "»" : "«";
  });
  commandSearch?.addEventListener("input", () => renderCommandResults(commandSearch.value));
  document.querySelector("[data-command-results]")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-target]");
    if (!button) return;
    closePalette();
    window.location.hash = button.dataset.target;
  });
  palette?.addEventListener("click", (event) => {
    if (event.target === palette) closePalette();
  });
  globalSearch?.addEventListener("input", () => {
    const query = globalSearch.value.trim().toLocaleLowerCase("es");
    document.querySelectorAll("[data-navigation] li").forEach((item) => {
      item.hidden = Boolean(query) && !item.textContent.toLocaleLowerCase("es").includes(query);
    });
    document.querySelectorAll("[data-nav-group]").forEach((group) => {
      group.hidden = ![...group.querySelectorAll("li")].some((item) => !item.hidden);
    });
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === "k") {
      event.preventDefault();
      openPalette();
    }
    if (event.key === "Escape" && palette?.open) closePalette();
  });
}

function renderOperationalSections(views) {
  const container = document.querySelector("[data-operational-sections]");
  clear(container);
  if (!Array.isArray(views) || views.length === 0) {
    return;
  }
  views.forEach((view) => {
    const section = document.createElement("section");
    section.id = view.id;
    section.className = "page-section";
    section.setAttribute("aria-labelledby", `${view.id}-title`);

    const intro = document.createElement("div");
    intro.className = "section-intro";
    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.appendChild(text(view.eyebrow));
    const title = document.createElement("h2");
    title.id = `${view.id}-title`;
    title.appendChild(text(view.title));
    intro.append(eyebrow, title);

    const panel = document.createElement("article");
    panel.className = "panel view-panel";
    const state = document.createElement("span");
    state.className = `view-state ${view.state}`;
    const stateLabels = {
      read_only: "Solo lectura",
      planned: "Pendiente de integración",
      blocked: "Bloqueado por diseño"
    };
    state.appendChild(text(stateLabels[view.state] || "Estado controlado"));
    const summary = document.createElement("p");
    summary.className = "view-summary";
    summary.appendChild(text(view.summary));
    const list = document.createElement("ul");
    list.className = "view-list";
    appendList(list, view.items);
    panel.append(state, summary, list);
    if (view.id === "conversation") {
      appendConversationPanel(panel);
    } else if (view.id === "approval-workflow") {
      appendApprovalPanel(panel);
    } else if (view.id === "backups") {
      appendBackupPanel(panel);
    } else if (view.id === "rollbacks") {
      appendRollbackPanel(panel);
    } else if (view.id === "deployments") {
      appendDeploymentPanel(panel);
    } else if (view.id === "monitoring") {
      appendMonitoringPanel(panel);
    } else if (view.id === "testing") {
      appendValidationPanel(panel);
    } else if (view.id === "builds") {
      appendBuildPanel(panel);
    } else if (view.id === "server") {
      appendInventoryPanel(panel);
    } else if (view.id === "projects") {
      appendProjectsPanel(panel);
    } else if (view.id === "incidents") {
      appendIncidentPanel(panel);
    } else if (view.id === "audit-preview") {
      appendAuditPanel(panel);
    } else if (view.id === "agents") {
      appendCodexPanel(panel);
    } else if (view.id === "v3-intelligence") {
      appendV3Panel(panel);
    }
    section.append(intro, panel);
    container.appendChild(section);
  });
}

const workflowState = {
  backupId: null,
  incidentId: null,
  approvalId: null,
  deploymentId: null,
  rollbackId: null,
};

function field(labelText, name, type = "text", value = "", required = true) {
  const wrapper = document.createElement("label");
  wrapper.className = "workflow-field";
  wrapper.appendChild(text(labelText));
  const input = document.createElement("input");
  input.name = name;
  input.type = type;
  input.value = value;
  input.required = required;
  if (type === "number") {
    input.min = "0";
    input.step = "any";
  }
  wrapper.appendChild(input);
  return wrapper;
}

function textareaField(labelText, name, value = "", required = true) {
  const wrapper = document.createElement("label");
  wrapper.className = "workflow-field workflow-field-wide";
  wrapper.appendChild(text(labelText));
  const input = document.createElement("textarea");
  input.name = name;
  input.rows = 5;
  input.value = value;
  input.required = required;
  wrapper.appendChild(input);
  return wrapper;
}

function selectField(labelText, name, options) {
  const wrapper = document.createElement("label");
  wrapper.className = "workflow-field";
  wrapper.appendChild(text(labelText));
  const select = document.createElement("select");
  select.name = name;
  select.required = true;
  options.forEach(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.appendChild(text(label));
    select.appendChild(option);
  });
  wrapper.appendChild(select);
  return wrapper;
}

function workflowForm(titleText) {
  const heading = document.createElement("h3");
  heading.className = "subsection-title";
  heading.appendChild(text(titleText));
  const form = document.createElement("form");
  form.className = "workflow-form";
  const result = document.createElement("p");
  result.className = "workflow-result";
  result.setAttribute("role", "status");
  result.setAttribute("aria-live", "polite");
  return { heading, form, result };
}

function workflowButton(labelText) {
  const button = document.createElement("button");
  button.type = "submit";
  button.appendChild(text(labelText));
  return button;
}

async function safePost(path, payload) {
  if (!authState.authenticated || !authState.csrfToken) {
    throw new Error("Inicia sesión para usar este flujo.");
  }
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": authState.csrfToken },
    body: JSON.stringify({ ...payload, csrfToken: authState.csrfToken }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "La solicitud no fue aceptada");
  }
  return data;
}

function showWorkflowResult(node, message) {
  node.textContent = message;
}

function actionButton(labelText, type = "button") {
  const button = document.createElement("button");
  button.type = type;
  button.appendChild(text(labelText));
  return button;
}

function renderApprovalRequests(container, requests) {
  clear(container);
  if (!Array.isArray(requests) || requests.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.appendChild(text("No hay solicitudes de aprobación disponibles."));
    container.appendChild(empty);
    return;
  }
  requests.forEach((request) => {
    const item = document.createElement("li");
    item.className = "approval-item";
    const identity = document.createElement("strong");
    identity.appendChild(text(`${request.id} · ${request.status}`));
    const details = document.createElement("span");
    details.appendChild(text(`${request.actor} · ${request.action} · ${request.command_id || "sin comando"}`));
    item.append(identity, details);
    container.appendChild(item);
  });
}

function appendApprovalPanel(panel) {
  const { heading, form, result } = workflowForm("Solicitar aprobación");
  form.append(
    selectField("Acción", "action", [
      ["read", "Lectura READ_SAFE"],
      ["read_sensitive", "Lectura READ_SENSITIVE"],
      ["read_privileged", "Lectura READ_PRIVILEGED"],
      ["deploy", "Despliegue (rechazado)"]
    ]),
    selectField("Comando declarado", "command_id", [
      ["system.memory", "Memoria"],
      ["system.disk_usage", "Disco"],
      ["system.uptime", "Uptime"],
      ["system.ports", "Puertos sensibles"],
      ["privileged.firewall_summary", "Firewall privilegiado"],
      ["forbidden.docker_inspect", "Comando prohibido"]
    ]),
    workflowButton("Solicitar aprobación")
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Evaluando policy y creando solicitud...");
    try {
      const request = await safePost("/api/approvals/request", Object.fromEntries(data.entries()));
      workflowState.approvalId = request.id;
      showWorkflowResult(result, `Solicitud ${request.id}: ${request.status}. Riesgo ${request.risk_level}.`);
      const requestInput = panel.querySelector("[data-approval-request-id]");
      if (requestInput) requestInput.value = request.id;
      const evaluateInput = panel.querySelector("[data-approval-evaluate-id]");
      if (evaluateInput) evaluateInput.value = request.id;
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, form, result);

  const decisionHeading = document.createElement("h3");
  decisionHeading.className = "subsection-title";
  decisionHeading.appendChild(text("Decisión independiente"));
  const decisionForm = document.createElement("form");
  decisionForm.className = "workflow-form";
  const requestIdField = field("ID de solicitud", "request_id", "text", "");
  const requestIdInput = requestIdField.querySelector("input");
  requestIdInput.setAttribute("data-approval-request-id", "");
  decisionForm.append(requestIdField);
  const decisionActions = document.createElement("div");
  decisionActions.className = "workflow-actions";
  const approve = actionButton("Aprobar");
  const deny = actionButton("Denegar");
  decisionActions.append(approve, deny);
  decisionForm.append(decisionActions);
  const decisionResult = document.createElement("p");
  decisionResult.className = "workflow-result";
  decisionResult.setAttribute("role", "status");
  decisionResult.setAttribute("aria-live", "polite");

  async function decide(path, label) {
    const requestId = requestIdInput.value.trim() || workflowState.approvalId;
    if (!requestId) {
      showWorkflowResult(decisionResult, "Indica un ID de solicitud.");
      return;
    }
    showWorkflowResult(decisionResult, `${label} solicitud...`);
    try {
      const decision = await safePost(path, { request_id: requestId });
      showWorkflowResult(decisionResult, `Solicitud ${decision.id}: ${decision.status}.`);
    } catch (error) {
      showWorkflowResult(decisionResult, error.message);
    }
  }
  approve.addEventListener("click", () => decide("/api/approvals/approve", "Aprobando"));
  deny.addEventListener("click", () => decide("/api/approvals/deny", "Denegando"));
  panel.append(decisionHeading, decisionForm, decisionResult);

  const listHeading = document.createElement("h3");
  listHeading.className = "subsection-title";
  listHeading.appendChild(text("Solicitudes registradas"));
  const refreshForm = document.createElement("form");
  refreshForm.className = "workflow-actions";
  const refresh = actionButton("Actualizar solicitudes", "submit");
  refreshForm.appendChild(refresh);
  const requestList = document.createElement("ul");
  requestList.className = "approval-list";
  const listResult = document.createElement("p");
  listResult.className = "workflow-result";
  listResult.setAttribute("role", "status");
  listResult.setAttribute("aria-live", "polite");
  refreshForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    showWorkflowResult(listResult, "Consultando solicitudes metadata-only...");
    try {
      const response = await fetch("/api/approvals", { credentials: "same-origin", cache: "no-store" });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || "La lista requiere una sesión autorizada.");
      renderApprovalRequests(requestList, payload.requests);
      showWorkflowResult(listResult, `${payload.requests.length} solicitudes disponibles.`);
    } catch (error) {
      showWorkflowResult(listResult, error.message);
    }
  });
  panel.append(listHeading, refreshForm, requestList, listResult);

  const evaluateHeading = document.createElement("h3");
  evaluateHeading.className = "subsection-title";
  evaluateHeading.appendChild(text("Evaluar cadena controlada"));
  const evaluateForm = document.createElement("form");
  evaluateForm.className = "workflow-form";
  const evaluateApprovalField = field("ID de aprobación", "approval_id", "text", "");
  const evaluateApprovalInput = evaluateApprovalField.querySelector("input");
  evaluateApprovalInput.setAttribute("data-approval-evaluate-id", "");
  evaluateForm.append(
    evaluateApprovalField,
    selectField("Acción", "action", [["read", "Lectura READ_SAFE"]]),
    selectField("Comando", "command_id", [["system.memory", "Memoria"], ["system.disk_usage", "Disco"]]),
    workflowButton("Evaluar sin ejecutar")
  );
  const evaluateResult = document.createElement("p");
  evaluateResult.className = "workflow-result";
  evaluateResult.setAttribute("role", "status");
  evaluateResult.setAttribute("aria-live", "polite");
  evaluateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(evaluateForm);
    const approvalId = data.get("approval_id") || workflowState.approvalId;
    showWorkflowResult(evaluateResult, "Reevaluando policy, dry-run y execution gate...");
    try {
      const response = await safePost("/api/execution/evaluate", {
        action: data.get("action"),
        command_id: data.get("command_id"),
        approval_id: approvalId,
      });
      const controlled = response.controlled_execution;
      const controlledState = controlled ? controlled.state : "sin solicitud al executor";
      showWorkflowResult(
        evaluateResult,
        `Plan: ${response.plan.state}. Dry-run: ${response.dry_run.state}. Gate: ${response.gate.state}. Executor: ${controlledState}. No se ejecutó ningún comando.`
      );
    } catch (error) {
      showWorkflowResult(evaluateResult, error.message);
    }
  });
  panel.append(evaluateHeading, evaluateForm, evaluateResult);
}

function appendBackupPanel(panel) {
  const { heading, form, result } = workflowForm("Ciclo seguro de backup");
  form.append(
    field("Proyecto", "project", "text", "control-center"),
    selectField("Tipo", "backup_type", [["pre_deploy", "Pre-deploy"], ["code", "Código"], ["configuration", "Configuración"], ["manual", "Manual"]]),
    field("Origen lógico", "source_label", "text", "fuente declarada"),
    field("Destino lógico", "destination_label", "text", "destino declarado"),
    workflowButton("Preparar backup")
  );
  const actions = document.createElement("div");
  actions.className = "workflow-actions";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Registrando ciclo en memoria...");
    try {
      const backup = await safePost("/api/backups/prepare", Object.fromEntries(data.entries()));
      workflowState.backupId = backup.backup_id;
      showWorkflowResult(result, `Preparado: ${backup.backup_id}. No se ha escrito ningún archivo.`);
      clear(actions);
      const verify = document.createElement("button");
      verify.type = "button";
      verify.appendChild(text("Verificar checksum simulado"));
      verify.addEventListener("click", async () => {
        try {
          const verified = await safePost("/api/backups/verify", { backup_id: workflowState.backupId });
          showWorkflowResult(result, `Estado: ${verified.state}. El proveedor real sigue deshabilitado.`);
          if (verified.state === "verified") {
            const restore = document.createElement("button");
            restore.type = "button";
            restore.appendChild(text("Probar restauración contractual"));
            restore.addEventListener("click", async () => {
              try {
                const tested = await safePost("/api/backups/restore-test", { backup_id: workflowState.backupId });
                showWorkflowResult(result, `Restore test: ${tested.state}. No se restauraron datos reales.`);
              } catch (error) {
                showWorkflowResult(result, error.message);
              }
            });
            actions.appendChild(restore);
          }
        } catch (error) {
          showWorkflowResult(result, error.message);
        }
      });
      actions.appendChild(verify);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, form, actions, result);
}

function appendDeploymentPanel(panel) {
  const { heading, form, result } = workflowForm("Preparar preflight");
  const checks = ["git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification"];
  form.append(field("Proyecto", "project", "text", "control-center"), field("Commit", "commit", "text", "commit-declarado"), field("ID de backup verificado", "backup_id"));
  const checkGroup = document.createElement("fieldset");
  checkGroup.className = "workflow-checks";
  const legend = document.createElement("legend");
  legend.appendChild(text("Checks declarados"));
  checkGroup.appendChild(legend);
  checks.forEach((name) => {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = `check_${name}`;
    input.value = "true";
    label.append(input, text(name));
    checkGroup.appendChild(label);
  });
  form.append(checkGroup, workflowButton("Preparar despliegue"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const payload = {
      project: data.get("project"),
      commit: data.get("commit"),
      backup_id: data.get("backup_id") || null,
      checks: Object.fromEntries(checks.map((name) => [name, data.get(`check_${name}`) === "true"])),
    };
    showWorkflowResult(result, "Evaluando preflight...");
    try {
      const deployment = await safePost("/api/deployments/prepare", payload);
      workflowState.deploymentId = deployment.deployment_id;
      showWorkflowResult(result, `Preflight: ${deployment.state}. La ejecución real permanece bloqueada.`);
      clear(actions);
      const approve = actionButton("Aprobar con otra cuenta");
      const execute = actionButton("Solicitar ejecución");
      approve.addEventListener("click", async () => {
        try {
          const updated = await safePost("/api/deployments/approve", { deployment_id: workflowState.deploymentId });
          showWorkflowResult(result, `Despliegue ${updated.deployment_id}: ${updated.state}.`);
        } catch (error) {
          showWorkflowResult(result, error.message);
        }
      });
      execute.addEventListener("click", async () => {
        try {
          const updated = await safePost("/api/deployments/execute", { deployment_id: workflowState.deploymentId });
          showWorkflowResult(result, `Despliegue ${updated.deployment_id}: ${updated.state}. No se ejecutó ningún cambio real.`);
        } catch (error) {
          showWorkflowResult(result, error.message);
        }
      });
      actions.append(approve, execute);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  const actions = document.createElement("div");
  actions.className = "workflow-actions";
  panel.append(heading, form, actions, result);
}

function appendRollbackPanel(panel) {
  const { heading, form, result } = workflowForm("Preparar rollback");
  form.append(
    field("Proyecto", "project", "text", "control-center"),
    selectField("Tipo", "rollback_type", [
      ["git", "Git"],
      ["file", "Archivo"],
      ["configuration", "Configuración"],
      ["full", "Despliegue completo"]
    ]),
    field("Objetivo declarado", "target", "text", "commit-o-version-declarada"),
    workflowButton("Preparar rollback")
  );
  const actions = document.createElement("div");
  actions.className = "workflow-actions";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Registrando plan de rollback...");
    try {
      const rollback = await safePost("/api/rollbacks/prepare", Object.fromEntries(data.entries()));
      workflowState.rollbackId = rollback.rollback_id;
      showWorkflowResult(result, `Rollback ${rollback.rollback_id}: ${rollback.state}.`);
      clear(actions);
      const approve = actionButton("Aprobar con otra cuenta");
      const execute = actionButton("Solicitar rollback");
      approve.addEventListener("click", async () => {
        try {
          const updated = await safePost("/api/rollbacks/approve", { rollback_id: workflowState.rollbackId });
          showWorkflowResult(result, `Rollback ${updated.rollback_id}: ${updated.state}.`);
        } catch (error) {
          showWorkflowResult(result, error.message);
        }
      });
      execute.addEventListener("click", async () => {
        try {
          const updated = await safePost("/api/rollbacks/execute", { rollback_id: workflowState.rollbackId });
          showWorkflowResult(result, `Rollback ${updated.rollback_id}: ${updated.state}. No se restauró ningún dato real.`);
        } catch (error) {
          showWorkflowResult(result, error.message);
        }
      });
      actions.append(approve, execute);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, form, actions, result);
}

function appendMonitoringPanel(panel) {
  const { heading, form, result } = workflowForm("Registrar snapshot de métricas");
  form.append(
    field("CPU %", "cpu_percent", "number", "12"),
    field("Memoria %", "memory_percent", "number", "30"),
    field("Disco %", "disk_percent", "number", "40"),
    field("Carga 1m", "load_1m", "number", "0.5"),
    field("Tasa de error HTTP", "http_error_rate", "number", "0"),
    field("Reinicios", "service_restarts", "number", "0"),
    workflowButton("Registrar snapshot")
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const payload = Object.fromEntries(data.entries());
    ["cpu_percent", "memory_percent", "disk_percent", "load_1m", "http_error_rate", "service_restarts"].forEach((key) => {
      payload[key] = Number(payload[key]);
    });
    showWorkflowResult(result, "Evaluando snapshot metadata-only...");
    try {
      const snapshot = await safePost("/api/monitoring/snapshot", payload);
      showWorkflowResult(result, `Snapshot registrado. Anomalías: ${snapshot.anomalies.length ? snapshot.anomalies.join(", ") : "ninguna"}.`);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  const collectForm = document.createElement("form");
  collectForm.className = "workflow-actions";
  const collectButton = actionButton("Recoger métricas READ_SAFE", "submit");
  collectForm.appendChild(collectButton);
  collectForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    showWorkflowResult(result, "Solicitando colección acotada...");
    try {
      const collected = await safePost("/api/monitoring/collect", {});
      const incident = collected.incident ? ` Incidente creado: ${collected.incident.incident_id}.` : "";
      showWorkflowResult(result, `Colección: ${collected.state}. Anomalías: ${collected.anomalies.length ? collected.anomalies.join(", ") : "ninguna"}.${incident}`);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, form, collectForm, result);
}

function appendInventoryPanel(panel) {
  const { heading, form, result } = workflowForm("Inventario READ_SAFE");
  const details = document.createElement("dl");
  details.className = "workflow-summary";
  const note = document.createElement("p");
  note.className = "workflow-note";
  note.appendChild(text("La colección solo está disponible con un proveedor habilitado explícitamente. El resultado se valida en memoria y no crea INVENTORY.json."));
  form.append(workflowButton("Recopilar inventario READ_SAFE"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showWorkflowResult(result, "Validando autorización y solicitando inventario READ_SAFE...");
    try {
      const collected = await safePost("/api/inventory/collect", {});
      const provider = collected.provider || "sin proveedor";
      const dataMode = collected.live_data ? "datos READ_SAFE" : "fixture de laboratorio";
      showWorkflowResult(
        result,
        `Inventario: ${collected.state}. Proveedor: ${provider}. Fuente: ${dataMode}. Persistido: ${collected.persisted ? "sí" : "no"}. ${collected.reason}`
      );
      clear(details);
      if (collected.inventory) {
        const server = collected.inventory.server || {};
        const os = server.os || {};
        const cpu = server.cpu || {};
        const memory = server.memory || {};
        [
          ["Schema", collected.inventory.schema_version],
          ["Sistema operativo", os.name || "no disponible"],
          ["Versión", os.version || "no disponible"],
          ["Arquitectura", os.architecture || "no disponible"],
          ["CPU lógicas", cpu.logical_cpus ?? "no disponible"],
          ["Memoria total", memory.total_bytes ?? "no disponible"],
          ["Volúmenes", Array.isArray(server.storage) ? server.storage.length : 0],
          ["Uptime", server.uptime || "no disponible"],
          ["Repositorios", Array.isArray(collected.inventory.repositories) ? collected.inventory.repositories.length : 0],
          ["Persistencia", collected.persisted ? "habilitada" : "deshabilitada"],
        ].forEach(([label, value]) => {
          const term = document.createElement("dt");
          term.appendChild(text(label));
          const description = document.createElement("dd");
          description.appendChild(text(value));
          details.append(term, description);
        });
      }
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, note, form, result, details);
}

function appendProjectsPanel(panel) {
  const { heading, form, result } = workflowForm("Proyectos y Git READ_SAFE");
  const note = document.createElement("p");
  note.className = "workflow-note";
  note.appendChild(
    text(
      "Solo se pueden recoger rama, estado limpio/sucio y HEAD validado mediante el proveedor READ_SAFE explícito. No se muestran salidas Git ni se modifican repositorios."
    )
  );
  form.append(workflowButton("Recopilar metadatos Git READ_SAFE"));

  const refreshForm = document.createElement("form");
  refreshForm.className = "workflow-actions";
  const refresh = actionButton("Actualizar proyectos", "submit");
  refreshForm.appendChild(refresh);

  const list = document.createElement("div");
  list.className = "workflow-projects";
  const listResult = document.createElement("p");
  listResult.className = "workflow-result";
  listResult.setAttribute("role", "status");
  listResult.setAttribute("aria-live", "polite");

  function renderProjects(projects) {
    clear(list);
    if (!Array.isArray(projects) || projects.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.appendChild(text("No hay metadatos de proyectos recopilados."));
      list.appendChild(empty);
      return;
    }
    projects.forEach((project) => {
      const card = document.createElement("article");
      card.className = "workflow-project";
      const title = document.createElement("h4");
      title.appendChild(text(project.name || project.project_id || "Proyecto declarado"));
      const details = document.createElement("dl");
      details.className = "workflow-summary";
      [
        ["Estado", project.state || "no disponible"],
        ["Repositorio lógico", project.repository || "no disponible"],
        ["Rama", project.branch || "no disponible"],
        ["HEAD validado", project.commit || "no disponible"],
        ["Estado Git", project.dirty ? "con cambios" : "limpio"],
        ["Proveedor", project.provider || "no disponible"],
        ["Datos live", project.live_data ? "sí, con autorización" : "no"],
      ].forEach(([label, value]) => {
        const term = document.createElement("dt");
        term.appendChild(text(label));
        const description = document.createElement("dd");
        description.appendChild(text(value));
        details.append(term, description);
      });
      card.append(title, details);
      list.appendChild(card);
    });
  }

  async function refreshProjects() {
    showWorkflowResult(listResult, "Consultando catálogo de proyectos metadata-only...");
    try {
      const response = await fetch("/api/projects", { credentials: "same-origin", cache: "no-store" });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || "El catálogo requiere una sesión autorizada.");
      renderProjects(payload.projects);
      showWorkflowResult(
        listResult,
        (Array.isArray(payload.projects) ? payload.projects.length : 0) + " proyectos disponibles."
      );
    } catch (error) {
      showWorkflowResult(listResult, error.message);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showWorkflowResult(result, "Validando autorización y recopilando metadatos Git READ_SAFE...");
    try {
      const project = await safePost("/api/projects/collect", {});
      showWorkflowResult(
        result,
        "Proyecto: " + project.state + ". Rama: " + project.branch + ". HEAD: " + project.commit + ". No se modificó el repositorio."
      );
      await refreshProjects();
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  refreshForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await refreshProjects();
  });
  panel.append(heading, note, form, result, refreshForm, list, listResult);
}

function appendIncidentPanel(panel) {
  const { heading, form, result } = workflowForm("Registrar incidente");
  const management = workflowForm("Gestionar incidente");
  management.heading.hidden = true;
  management.form.hidden = true;
  const incidentIdField = field("ID del incidente", "incident_id", "text", "", false);
  const statusField = selectField("Estado", "status", [
    ["OPEN", "Abierto"],
    ["INVESTIGATING", "Investigando"],
    ["IDENTIFIED", "Causa identificada"],
    ["MITIGATING", "Mitigando"],
    ["MONITORING", "En observación"],
    ["RESOLVED", "Resuelto"],
  ]);
  management.form.append(
    incidentIdField,
    statusField,
    textareaField("Nota de transición", "note", "", false),
    textareaField("Resolución", "resolution", "", false),
    textareaField("Referencia de rollback", "rollback", "", false),
    workflowButton("Actualizar incidente")
  );
  form.append(
    field("Proyecto", "project", "text", "control-center"),
    field("Servicio", "service", "text", "web-shell"),
    selectField("Severidad", "severity", [["LOW", "Baja"], ["MEDIUM", "Media"], ["HIGH", "Alta"], ["CRITICAL", "Crítica"]]),
    field("Síntoma", "symptom", "text", "observación declarada"),
    workflowButton("Abrir incidente")
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Registrando incidente metadata-only...");
    try {
      const incident = await safePost("/api/incidents/create", Object.fromEntries(data.entries()));
      workflowState.incidentId = incident.incident_id;
      incidentIdField.querySelector("input").value = incident.incident_id;
      management.heading.hidden = false;
      management.form.hidden = false;
      showWorkflowResult(result, `Incidente ${incident.incident_id} abierto. No se han leído logs.`);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  management.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(management.form);
    showWorkflowResult(management.result, "Actualizando incidente metadata-only...");
    try {
      const updated = await safePost("/api/incidents/transition", Object.fromEntries(data.entries()));
      showWorkflowResult(
        management.result,
        `Incidente ${updated.incident_id}: ${updated.status}. No se han ejecutado acciones operativas.`
      );
    } catch (error) {
      showWorkflowResult(management.result, error.message);
    }
  });
  panel.append(heading, form, result, management.heading, management.form, management.result);
}

function appendValidationPanel(panel) {
  const { heading, form, result } = workflowForm("Evaluar checks declarados");
  form.append(
    field("Objetivo", "target", "text", "release-a"),
    textareaField("Checks (JSON)", "checks", JSON.stringify({ syntax: true, tests: true, build: false }, null, 2)),
    workflowButton("Evaluar sin ejecutar")
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    let checks;
    try {
      checks = JSON.parse(String(data.get("checks") || "{}"));
    } catch (_error) {
      showWorkflowResult(result, "Los checks deben ser JSON válido.");
      return;
    }
    if (!checks || Array.isArray(checks) || typeof checks !== "object") {
      showWorkflowResult(result, "Los checks deben ser un objeto JSON.");
      return;
    }
    showWorkflowResult(result, "Evaluando metadata-only sin lanzar procesos...");
    try {
      const report = await safePost("/api/tests", {
        target: data.get("target"),
        checks,
      });
      showWorkflowResult(result, `Informe ${report.validation_id}: ${report.state}. No se ejecutaron tests reales.`);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });

  const run = workflowForm("Ejecutar tests autorizados");
  const runNote = document.createElement("p");
  runNote.className = "workflow-note";
  runNote.appendChild(
    text(
      "Solo se admite el target repository y el provider debe estar habilitado explícitamente. La salida de los tests se descarta y solo se muestran métricas."
    )
  );
  run.form.append(field("Target fijo", "target", "text", "repository"), workflowButton("Solicitar ejecución de tests"));
  run.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(run.form);
    showWorkflowResult(run.result, "Comprobando provider, autorización y límites del runner...");
    try {
      const executed = await safePost("/api/tests/run", { target: data.get("target") });
      showWorkflowResult(
        run.result,
        "Tests: " + executed.state + ". Pasaron: " + (executed.passed ? "sí" : "no") +
          ". Casos: " + executed.tests_run + ". Fallos: " + executed.failures +
          ". No se expuso salida de tests."
      );
    } catch (error) {
      showWorkflowResult(run.result, error.message);
    }
  });
  panel.append(heading, form, result, run.heading, runNote, run.form, run.result);
}

function appendBuildPanel(panel) {
  const { heading, form, result } = workflowForm("Ejecutar build declarado");
  const note = document.createElement("p");
  note.className = "workflow-note";
  note.appendChild(
    text(
      "Solo se puede seleccionar un target declarado al iniciar la API. El provider descarta stdout/stderr y devuelve estado, código de retorno y duración."
    )
  );
  form.append(field("Target declarado", "target", "text", "production"), workflowButton("Solicitar build"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Comprobando provider, autorización y perfil declarado...");
    try {
      const run = await safePost("/api/builds/run", { target: data.get("target") });
      showWorkflowResult(
        result,
        `Build: ${run.state}. Pasó: ${run.passed ? "sí" : "no"}. Código: ${run.return_code}. Duración: ${run.duration_ms} ms. No se expuso salida.`
      );
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, note, form, result);
}

function appendCodexPanel(panel) {
  const { heading, form, result } = workflowForm("Análisis Codex metadata-only");
  const note = document.createElement("p");
  note.className = "workflow-note";
  note.appendChild(
    text(
      "El provider de laboratorio prepara hallazgos sin leer ni modificar el repositorio. Fuera del laboratorio, Codex CLI solo se habilita para proyectos declarados, en sandbox read-only y con autorización explícita.")
  );
  form.append(
    field("Proyecto declarado", "project", "text", "control-center"),
    selectField("Tipo de solicitud", "request_kind", [
      ["repository", "Revisión de repositorio"],
      ["diagnosis", "Diagnóstico"],
      ["impact", "Análisis de impacto"],
    ]),
    workflowButton("Solicitar análisis")
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    showWorkflowResult(result, "Comprobando provider Codex y límites de seguridad...");
    try {
      const run = await safePost("/api/codex/analyze", {
        project: data.get("project"),
        request_kind: data.get("request_kind"),
      });
      showWorkflowResult(
        result,
        "Análisis: " + run.state + ". Hallazgos: " + (run.findings || []).join(", ") +
          ". Archivos examinados: " + run.files_examined + ". No se modificó el repositorio."
      );
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, note, form, result);
}

function appendAuditPanel(panel) {
  const { heading, form, result } = workflowForm("Auditoría");
  const button = workflowButton("Actualizar auditoría");
  form.append(button);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showWorkflowResult(result, "Consultando metadatos...");
    try {
      const response = await fetch("/api/audit", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error("La auditoría requiere una sesión autorizada.");
      const payload = await response.json();
      showWorkflowResult(result, `${payload.records.length} eventos metadata-only disponibles.`);
    } catch (error) {
      showWorkflowResult(result, error.message);
    }
  });
  panel.append(heading, form, result);
}

function appendV3Panel(panel) {
  const twin = workflowForm("Registrar gemelo digital");
  twin.form.append(
    field("Proyecto", "project", "text", "control-center"),
    textareaField("Nodos declarados (JSON)", "nodes", JSON.stringify([
      { node_id: "repo", kind: "repository", label: "Repositorio", metadata: { source: "declared" } },
      { node_id: "web", kind: "service", label: "Web", metadata: {} },
    ], null, 2)),
    textareaField("Relaciones declaradas (JSON)", "relations", JSON.stringify([
      { source_id: "repo", relation: "deploys", target_id: "web" },
    ], null, 2)),
    workflowButton("Registrar gemelo")
  );
  twin.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(twin.form);
    try {
      const response = await safePost("/api/digital-twin/register", {
        project: data.get("project"),
        nodes: JSON.parse(data.get("nodes")),
        relations: JSON.parse(data.get("relations")),
      });
      showWorkflowResult(twin.result, `Gemelo ${response.twin_id} registrado. No se descubrieron relaciones reales.`);
    } catch (error) {
      showWorkflowResult(twin.result, `No se pudo registrar: ${error.message}`);
    }
  });
  panel.append(twin.heading, twin.form, twin.result);

  const predictive = workflowForm("Analizar tendencia prudente");
  predictive.form.append(
    field("Proyecto", "project", "text", "control-center"),
    field("Horizonte (horas)", "horizon_hours", "number", "6"),
    textareaField("Snapshots aportados (JSON)", "snapshots", JSON.stringify([
      { timestamp: "2026-09-05T00:00:00+00:00", cpu_percent: 30, memory_percent: 40, disk_percent: 50, load_1m: 0.4 },
      { timestamp: "2026-09-05T01:00:00+00:00", cpu_percent: 45, memory_percent: 42, disk_percent: 50, load_1m: 0.5 },
    ], null, 2)),
    workflowButton("Calcular tendencia")
  );
  predictive.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(predictive.form);
    try {
      const response = await safePost("/api/predictive/analyze", {
        project: data.get("project"),
        horizon_hours: Number(data.get("horizon_hours")),
        snapshots: JSON.parse(data.get("snapshots")),
      });
      showWorkflowResult(predictive.result, `Informe ${response.report_id}: ${response.findings.length ? response.findings.join(", ") : "sin hallazgos"}. No genera alertas automáticas.`);
    } catch (error) {
      showWorkflowResult(predictive.result, `No se pudo analizar: ${error.message}`);
    }
  });
  panel.append(predictive.heading, predictive.form, predictive.result);

  const autonomy = workflowForm("Registrar autonomía por proyecto");
  autonomy.form.append(
    field("Proyecto", "project", "text", "control-center"),
    field("Nivel 0-5", "level", "number", "2"),
    workflowButton("Registrar nivel")
  );
  autonomy.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(autonomy.form);
    try {
      const response = await safePost("/api/autonomy/profile", {
        project: data.get("project"),
        level: Number(data.get("level")),
      });
      showWorkflowResult(autonomy.result, `Nivel ${response.level}: ${response.allowed_mode}. Ejecución: ${response.execution}.`);
    } catch (error) {
      showWorkflowResult(autonomy.result, `No se pudo registrar: ${error.message}`);
    }
  });
  panel.append(autonomy.heading, autonomy.form, autonomy.result);

  const server = workflowForm("Registrar servidor declarado");
  server.form.append(
    field("ID", "server_id", "text", "lab-01"),
    field("Etiqueta", "label", "text", "Laboratorio 01"),
    field("Entorno", "environment", "text", "lab"),
    workflowButton("Registrar servidor")
  );
  server.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const response = await safePost("/api/servers/register", Object.fromEntries(new FormData(server.form).entries()));
      showWorkflowResult(server.result, `Servidor ${response.server_id} registrado como ${response.connection_state}. Sin conexión real.`);
    } catch (error) {
      showWorkflowResult(server.result, `No se pudo registrar: ${error.message}`);
    }
  });
  panel.append(server.heading, server.form, server.result);

  const recovery = workflowForm("Preparar recuperación controlada");
  recovery.form.append(
    field("ID de incidente", "incident_id", "text", "incident-declared"),
    field("Proyecto", "project", "text", "control-center"),
    field("Objetivo", "target", "text", "release-a"),
    field("Estrategia", "strategy", "text", "restore_verified_release"),
    field("ID de backup (opcional)", "backup_id", "text", "backup-declared", false),
    workflowButton("Preparar recuperación")
  );
  recovery.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const response = await safePost("/api/recovery/plan", Object.fromEntries(new FormData(recovery.form).entries()));
      showWorkflowResult(recovery.result, `Plan ${response.recovery_id}: ${response.state}. Requiere aprobación independiente.`);
    } catch (error) {
      showWorkflowResult(recovery.result, `No se pudo preparar: ${error.message}`);
    }
  });
  panel.append(recovery.heading, recovery.form, recovery.result);
}

function appendConversationPanel(panel) {
  const heading = document.createElement("h3");
  heading.className = "subsection-title";
  heading.appendChild(text("Solicitar un plan seguro"));
  const form = document.createElement("form");
  form.className = "chat-form";
  form.setAttribute("data-chat-form", "");
  const label = document.createElement("label");
  label.setAttribute("for", "chat-message");
  label.appendChild(text("Mensaje"));
  const input = document.createElement("textarea");
  input.id = "chat-message";
  input.name = "message";
  input.rows = 3;
  input.maxLength = 4000;
  input.required = true;
  input.placeholder = "Ejemplo: muestra el estado seguro del sistema";
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.appendChild(text("Preparar plan"));
  const result = document.createElement("p");
  result.className = "chat-result";
  result.setAttribute("role", "status");
  result.setAttribute("aria-live", "polite");
  result.setAttribute("data-chat-result", "");
  form.append(label, input, submit);
  panel.append(heading, form, result);
  form.addEventListener("submit", handleChatSubmit);
}

function appendReadinessPanel(panel) {
  const result = panel.querySelector("[data-readiness-result]");
  const refresh = panel.querySelector("[data-readiness-refresh]");
  const checks = panel.querySelector("[data-readiness-checks]");
  if (!result || !refresh || !checks) return;

  const renderReadiness = async () => {
    result.textContent = "Consultando requisitos metadata-only...";
    clear(checks);
    try {
      const response = await fetch("/api/readiness", { credentials: "same-origin", cache: "no-store" });
      if (response.status === 401 || response.status === 403) {
        throw new Error("Inicia sesión con permiso de Core Operator para consultar la preparación.");
      }
      if (!response.ok) throw new Error("La matriz de preparación no está disponible.");
      const report = await response.json();
      result.textContent = `Resultado: ${report.state}. Esta consulta no activa ninguna capacidad.`;
      (report.checks || []).forEach((check) => {
        const item = document.createElement("li");
        item.className = check.passed ? "readiness-pass" : "readiness-blocked";
        item.textContent = `${check.passed ? "OK" : "BLOQUEADO"} · ${check.label}: ${check.evidence}`;
        checks.appendChild(item);
      });
    } catch (error) {
      result.textContent = error.message;
    }
  };

  refresh.addEventListener("click", renderReadiness);
}

function render(status, source) {
  document.title = `${status.product.name} - ${status.product.phase}`;
  document.querySelector("[data-product-name]").textContent = status.product.name;
  document.querySelector("[data-product-phase]").textContent = status.product.phase;
  document.querySelector("[data-product-context]").textContent = status.product.context;
  const executionStatus = status.product.executionStatus === "Ejecución READ_SAFE sintética de laboratorio"
    ? "Ejecución real bloqueada · provider sintético de laboratorio"
    : status.product.executionStatus;
  document.querySelector("[data-execution-status]").textContent = executionStatus;
  renderNavigation(status.navigation);
  renderPhases(status.phases);
  renderChain(status.securityChain);
  appendList(document.querySelector("[data-components]"), status.components);
  appendList(document.querySelector("[data-blocked]"), status.blockedByDesign);
  renderPolicy(status.policyMatrix);
  appendList(document.querySelector("[data-capabilities]"), status.uiCapabilities);
  renderAudit(status.auditPreview);
  renderDataSource(status.dataSource);
  renderCapabilities(status.capabilities);
  renderDashboardVisuals(status.dashboard);
  renderOperationalSections(status.views);
  updateCurrentNavigation();
  const readinessPanel = document.querySelector("[data-readiness-panel]");
  if (readinessPanel && !readinessPanel.dataset.bound) {
    readinessPanel.dataset.bound = "true";
    appendReadinessPanel(readinessPanel);
  }
  const auditPanel = document.querySelector("#audit-preview .audit-panel");
  if (auditPanel && !auditPanel.querySelector(".workflow-form")) {
    appendAuditPanel(auditPanel);
  }
  const dataMode = document.querySelector("[data-data-mode]");
  if (source === "api") {
    const inventoryEnabled = status.runtime && status.runtime.inventory === "provider_enabled";
    const monitoringEnabled = status.runtime && status.runtime.monitoring === "provider_enabled";
    dataMode.textContent = inventoryEnabled || monitoringEnabled
      ? "API local solo lectura · Provider READ_SAFE habilitado · Sin acciones operativas"
      : "API local solo lectura · Datos simulados · Sin datos reales";
  } else if (source === "static") {
    dataMode.textContent = "Datos simulados estáticos · Sin backend · Sin datos reales";
  } else {
    dataMode.textContent = "Datos seguros incluidos · Sin conexión · Sin datos reales";
  }
  const notice = document.querySelector("[data-load-notice]");
  notice.hidden = source !== "fallback";
  notice.textContent = source === "fallback" ? "La API y el JSON estático no están disponibles. Se muestran datos seguros incluidos en la página; no se intentó ninguna conexión real." : "";
}

async function loadJson(path) {
  const response = await fetch(path, { cache: "no-store", credentials: "same-origin" });
  if (!response.ok) {
    throw new Error("datos no disponibles");
  }
  return response.json();
}

async function loadStatus() {
  try {
    return { status: await loadJson("/api/status"), source: "api" };
  } catch {
    try {
      return { status: await loadJson("./data/status.json"), source: "static" };
    } catch {
      return { status: fallbackStatus, source: "fallback" };
    }
  }
}

const authState = {
  csrfToken: null,
  authenticated: false,
};

function setAuthMessage(message) {
  const node = document.querySelector("[data-auth-message]");
  if (node) {
    node.textContent = message || "";
  }
}

function renderAuth(payload) {
  const state = document.querySelector("[data-auth-state]");
  const summary = document.querySelector("[data-auth-summary]");
  const form = document.querySelector("[data-login-form]");
  const logout = document.querySelector("[data-logout]");
  authState.authenticated = Boolean(payload && payload.authenticated);
  authState.csrfToken = payload && payload.csrfToken ? payload.csrfToken : null;
  if (authState.authenticated && payload.user) {
    state.textContent = `Sesión: ${payload.user.username} · ${payload.user.role}`;
    if (summary) summary.textContent = payload.user.username;
    form.hidden = true;
    logout.hidden = false;
  } else {
    state.textContent = "Sesión no iniciada";
    if (summary) summary.textContent = "Acceso";
    form.hidden = false;
    logout.hidden = true;
  }
}

async function refreshAuth() {
  try {
    const response = await fetch("/api/auth/me", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) {
      throw new Error("sin sesión");
    }
    renderAuth(await response.json());
  } catch {
    renderAuth(null);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setAuthMessage("Comprobando sesión...");
  try {
    const payload = { username: data.get("username"), password: data.get("password") };
    const otp = String(data.get("otp") || "").trim();
    if (otp) {
      payload.otp = otp;
    }
    const response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error("No se pudo iniciar sesión");
    }
    renderAuth(await response.json());
    form.reset();
    setAuthMessage("Sesión iniciada. Las acciones siguen sujetas a policy y aprobación.");
  } catch {
    renderAuth(null);
    setAuthMessage("No se pudo iniciar sesión. Provisiona un usuario explícitamente en el servidor local.");
  }
}

async function handleLogout() {
  try {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": authState.csrfToken || "" },
      body: JSON.stringify({ csrfToken: authState.csrfToken }),
    });
    if (!response.ok) {
      throw new Error("logout failed");
    }
    renderAuth(null);
    setAuthMessage("Sesión cerrada.");
  } catch {
    setAuthMessage("No se pudo cerrar la sesión.");
  }
}

async function handleChatSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const result = form.parentElement.querySelector("[data-chat-result]");
  if (!authState.authenticated || !authState.csrfToken) {
    result.textContent = "Inicia sesión para preparar un plan seguro.";
    return;
  }
  const message = new FormData(form).get("message");
  result.textContent = "Preparando respuesta metadata-only...";
  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": authState.csrfToken },
      body: JSON.stringify({ message, csrfToken: authState.csrfToken }),
    });
    if (!response.ok) {
      throw new Error("chat failed");
    }
    const payload = await response.json();
    result.textContent = `${payload.response} Riesgo: ${payload.risk}. Aprobación: ${payload.requires_approval ? "sí" : "no"}.`;
    form.reset();
  } catch {
    result.textContent = "No se pudo conectar con el planificador local; no se ejecutó ninguna acción.";
  }
}

function bindAuthControls() {
  document.querySelector("[data-login-form]")?.addEventListener("submit", handleLogin);
  document.querySelector("[data-logout]")?.addEventListener("click", handleLogout);
  refreshAuth();
}

window.addEventListener("hashchange", updateCurrentNavigation);
bindAuthControls();
bindNavigationTools();
loadStatus().then(({ status, source }) => {
  render(status, source);
  if (source !== "api") {
    renderCapabilities(status.capabilities);
    return;
  }
  loadJson("/api/capabilities")
    .then((payload) => renderCapabilities(payload.capabilities))
    .catch(() => renderCapabilities(status.capabilities));
});
