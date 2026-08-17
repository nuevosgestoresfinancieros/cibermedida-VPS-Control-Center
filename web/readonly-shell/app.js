const fallbackStatus = {
  product: {
    name: "Cibermedida VPS Control Center",
    phase: "Phase 3.3 Read-only accessibility and visual checks",
    context: "Production protected",
    executionStatus: "Real execution blocked"
  },
  navigation: [
    { label: "Dashboard", target: "dashboard" },
    { label: "Core Operator", target: "core-operator" },
    { label: "Policy", target: "policy" },
    { label: "Audit Preview", target: "audit-preview" },
    { label: "Safety Boundaries", target: "safety-boundaries" },
    { label: "Data Source", target: "data-source" }
  ],
  phases: [
    { label: "Phase 1", title: "READ_SAFE basic completed", state: "complete", summary: "Minimal authorized inventory metadata was validated without persisted inventory output." },
    { label: "Phase 2", title: "Core Operator closed", state: "complete", summary: "Policy, approvals, dry-run, execution gate, and controlled executor contracts are in place." },
    { label: "Phase 3.3", title: "Accessible read-only shell", state: "current", summary: "Keyboard navigation, safe empty states, and responsive presentation are enabled without operational actions." }
  ],
  securityChain: [
    { name: "Policy", state: "evaluates" },
    { name: "Approval", state: "gated" },
    { name: "ApprovedExecutionPlan", state: "contract" },
    { name: "DryRun", state: "metadata-only" },
    { name: "ExecutionGate", state: "eligible check" },
    { name: "ControlledExecutor", state: "blocked_by_default" }
  ],
  components: ["OperatorConfig", "safe logging", "audit", "PolicyEngine", "ReadSafeExecutorAdapter", "Approval workflow", "ApprovedExecutionPlan", "ApprovedPlanDryRunner", "ExecutionGate", "ControlledExecutor"],
  blockedByDesign: ["No real execution", "No elevated shell access", "No credential exposure", "No raw operational records", "No backup or database access", "No service modification", "No automatic inventory file"],
  policyMatrix: [
    { className: "READ_SAFE", decision: "allow", execution: "Metadata only", uiTreatment: "Visible as read-only status" },
    { className: "READ_SENSITIVE", decision: "approval_required", execution: "Not automatic", uiTreatment: "Shown as gated" },
    { className: "READ_PRIVILEGED", decision: "approval_required", execution: "Not automatic", uiTreatment: "Shown as gated" },
    { className: "FORBIDDEN", decision: "deny", execution: "Blocked", uiTreatment: "Shown as rejected" },
    { className: "modifying actions", decision: "deny", execution: "Blocked", uiTreatment: "Shown as rejected" }
  ],
  uiCapabilities: ["View status", "View documentation summary", "View policy states", "View metadata-only audit examples", "Keyboard-accessible section navigation", "View static mock data source", "No execution controls enabled"],
  auditPreview: { action: "execution_gate_evaluated", risk: "LOW", result: "blocked_by_default", content: "metadata only" },
  dataSource: { mode: "static mock", path: "web/readonly-shell/data/status.json", liveData: false, backend: false }
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
    empty.appendChild(text("No mock items available."));
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
    empty.appendChild(text("Section navigation unavailable."));
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
    empty.appendChild(text("No mock phase status available."));
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
    td.appendChild(text("No mock policy decisions available."));
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
    empty.appendChild(text("No mock audit metadata available."));
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
  document.querySelector("[data-source-live]").textContent = source.liveData ? "yes" : "no";
  document.querySelector("[data-source-backend]").textContent = source.backend ? "yes" : "no";
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
  notice.textContent = usedFallback ? "Static JSON was unavailable. Safe bundled fallback data is being shown; no live connection was attempted." : "";
}

async function loadStatus() {
  try {
    const response = await fetch("./data/status.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error("static data unavailable");
    }
    return { status: await response.json(), usedFallback: false };
  } catch {
    return { status: fallbackStatus, usedFallback: true };
  }
}

window.addEventListener("hashchange", updateCurrentNavigation);
loadStatus().then(({ status, usedFallback }) => render(status, usedFallback));
