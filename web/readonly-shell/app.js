const fallbackStatus = {
  "product": {
    "name": "Cibermedida VPS Control Center",
    "phase": "Fase 3.5 Interfaz solo lectura en castellano",
    "context": "Producción protegida",
    "executionStatus": "Ejecución real bloqueada"
  },
  "navigation": [
    {
      "label": "Panel",
      "target": "dashboard"
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
      "state": "current",
      "summary": "La navegación por teclado, los estados vacíos seguros y la presentación responsive se mantienen sin acciones operativas."
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
    "Sin controles de ejecución habilitados"
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
  }
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

function updateCurrentNavigation() {
  const currentTarget = window.location.hash.slice(1) || "dashboard";
  document.querySelectorAll("[data-navigation] a").forEach((link) => {
    if (link.getAttribute("href") === `#${currentTarget}`) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
}

function renderNavigation(items) {
  const container = document.querySelector("[data-navigation]");
  clear(container);
  if (!Array.isArray(items) || items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.appendChild(text("La navegación de secciones no está disponible."));
    container.appendChild(empty);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    const link = document.createElement("a");
    link.href = `#${item.target}`;
    link.appendChild(text(item.label));
    li.appendChild(link);
    container.appendChild(li);
  });
  updateCurrentNavigation();
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
  document.querySelector("[data-source-mode]").textContent = source.mode;
  document.querySelector("[data-source-path]").textContent = source.path;
  document.querySelector("[data-source-live]").textContent = source.liveData ? "sí" : "no";
  document.querySelector("[data-source-backend]").textContent = source.backend ? "sí" : "no";
}

function render(status, usedFallback) {
  document.title = `${status.product.name} - ${status.product.phase}`;
  document.querySelector("[data-product-name]").textContent = status.product.name;
  document.querySelector("[data-product-phase]").textContent = status.product.phase;
  document.querySelector("[data-product-context]").textContent = status.product.context;
  document.querySelector("[data-execution-status]").textContent = status.product.executionStatus;
  renderNavigation(status.navigation);
  renderPhases(status.phases);
  renderChain(status.securityChain);
  appendList(document.querySelector("[data-components]"), status.components);
  appendList(document.querySelector("[data-blocked]"), status.blockedByDesign);
  renderPolicy(status.policyMatrix);
  appendList(document.querySelector("[data-capabilities]"), status.uiCapabilities);
  renderAudit(status.auditPreview);
  renderDataSource(status.dataSource);
  const notice = document.querySelector("[data-load-notice]");
  notice.hidden = !usedFallback;
  notice.textContent = usedFallback ? "El JSON estático no está disponible. Se muestran datos seguros incluidos en la página; no se intentó ninguna conexión real." : "";
}

async function loadStatus() {
  try {
    const response = await fetch("./data/status.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error("datos estáticos no disponibles");
    }
    return { status: await response.json(), usedFallback: false };
  } catch {
    return { status: fallbackStatus, usedFallback: true };
  }
}

window.addEventListener("hashchange", updateCurrentNavigation);
loadStatus().then(({ status, usedFallback }) => render(status, usedFallback));
