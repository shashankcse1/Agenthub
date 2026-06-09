function normalizeApiBaseAlias(rawBase) {
  const trimmed = String(rawBase || "").trim();
  if (!trimmed) return "";
  const normalized = trimmed.replace(/\/$/, "").toLowerCase();
  if (normalized === "https://api.agenthub.internal" || normalized === "https://stage-api.agenthub.internal") {
    return "http://127.0.0.1:8000";
  }
  return trimmed;
}

const state = {
  apiBase: normalizeApiBaseAlias(localStorage.getItem("apiBase")) || "http://127.0.0.1:8000",
  actorRole: localStorage.getItem("actorRole") || "Master Admin",
  actorId: localStorage.getItem("actorId") || "ui-operator",
  accessToken: localStorage.getItem("accessToken") || "",
  environmentProfile: localStorage.getItem("environmentProfile") || "local",
  mfaVerified: parseBooleanFlag(localStorage.getItem("mfaVerified"), true),
  theme: localStorage.getItem("theme") || (window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark"),
};

const ENVIRONMENT_PROFILES = {
  local: {
    apiBase: "http://127.0.0.1:8000",
    actorRole: "Master Admin",
    actorId: "ui-operator",
  },
  stage: {
    apiBase: "http://127.0.0.1:8000",
    actorRole: "Release Manager",
    actorId: "stage-operator",
  },
  prod: {
    apiBase: "http://127.0.0.1:8000",
    actorRole: "Security Approver",
    actorId: "prod-operator",
  },
};

const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const DIRECTORY_DESCRIPTION_MAX_LENGTH = 500;
const SESSION_POLICY_DESCRIPTION_MAX_LENGTH = 500;
const TABLE_PAGINATION_DEFAULT_PAGE_SIZE = 10;
const TABLE_PAGINATION_PAGE_SIZE_OPTIONS = [10, 25, 50];
const PROD_GUARD_EXEMPT_MUTATIONS = new Set([
  "POST:/auth/directory/groups",
]);
const tablePaginationState = new WeakMap();

function isSuperAdminRole(roleName) {
  return String(roleName || "").trim().toLowerCase() === "super admin";
}

function isProdGuardExemptMutation(method, path) {
  const normalizedMethod = String(method || "GET").toUpperCase();
  const normalizedPath = String(path || "").split("?")[0].replace(/\/+$/, "") || "/";
  if (PROD_GUARD_EXEMPT_MUTATIONS.has(`${normalizedMethod}:${normalizedPath}`)) return true;
  return normalizedMethod === "POST" && normalizedPath.startsWith("/auth/directory/groups");
}
const UI_FEATURE_VIEWS = ["overview", "agents", "playground", "benchmark-scan", "routing-gateway", "runtime-config", "providers", "modules", "agentic", "discovery", "cost", "audit", "compliance", "observability", "security"];
const UI_FEATURE_FLAG_PREFIX = "ui.feature.";
const RUNTIME_CONFIG_PRESETS = [
  {
    config_key: "gateway.default_global_timeout_ms",
    config_value: "4500",
    description: "Default global timeout for gateway fallback execution",
  },
  {
    config_key: "gateway.default_max_fallback_hops",
    config_value: "2",
    description: "Default maximum number of fallback hops for gateway execution",
  },
  {
    config_key: "cost.model_token_rates_json",
    config_value:
      '{"default":{"input_cents_per_1k":1.0,"output_cents_per_1k":2.0},"models":{"gpt-4o-mini":{"input_cents_per_1k":0.15,"output_cents_per_1k":0.6},"gpt-4o":{"input_cents_per_1k":2.5,"output_cents_per_1k":10.0}}}',
    description: "JSON object defining default and per-model token pricing in cents per 1K input/output tokens",
  },
  {
    config_key: "cost.cloud_component_multipliers_json",
    config_value:
      '{"provider_type":{"aws":1.0,"azure":1.05,"gcp":1.0,"openai":1.0,"anthropic":1.1},"endpoint_family":{"responses":1.0,"chat":0.95,"embeddings":0.4}}',
    description: "JSON object defining provider-type and endpoint-family multipliers applied to model token pricing",
  },
  {
    config_key: "cost.provider_discounts_json",
    config_value:
      '{"provider_type":{"aws":0.0,"azure":3.0,"gcp":0.0,"openai":0.0,"anthropic":4.5},"models":{"gpt-4o-mini":2.0}}',
    description: "JSON object defining provider/model discount percentages (0-95) applied after multipliers",
  },
  {
    config_key: "workload_identity.default_expires_in_seconds",
    config_value: "3600",
    description: "Default expiry used when workload identity token exchange does not specify one",
  },
  {
    config_key: "workload_identity.default_http_timeout_seconds",
    config_value: "3.0",
    description: "Default HTTP timeout for native provider exchanges",
  },
  {
    config_key: "rate_limit.rules_refresh_seconds",
    config_value: "30",
    description: "How often middleware refreshes DB-backed rate-limit rules",
  },
  {
    config_key: "rate_limit.rules_exact_json",
    config_value:
      '[{"method":"POST","path":"/auth/sessions","max_requests":20,"window_seconds":60}]',
    description: "JSON list of exact rate-limit rules with method/path/max_requests/window_seconds",
  },
  {
    config_key: "rate_limit.rules_wildcard_json",
    config_value:
      '[{"method":"POST","path_prefix":"/auth/basic/config/","max_requests":10,"window_seconds":300}]',
    description: "JSON list of wildcard rate-limit rules with method/path_prefix/max_requests/window_seconds",
  },
  {
    config_key: "auth.policy.revisions_default_limit",
    config_value: "50",
    description: "Default page size for /auth/policies/session/revisions when no limit query param is provided",
  },
  {
    config_key: "compliance.control_catalog_json",
    config_value:
      '{"CTRL-AUDIT-IMMUTABLE":"Immutable audit trail coverage","CTRL-AUTHZ-ROLE":"Role-based authorization enforcement"}',
    description: "JSON object control_id -> title used by compliance control catalog",
  },
  {
    config_key: "compliance.default_control_mappings_json",
    config_value:
      '{"CTRL-AUDIT-IMMUTABLE":{"control_family":"audit_governance","requirement_text":"Immutable audit logs with trace lineage.","applicable_components":"[\\"audit\\", \\"observability\\"]","required_evidence_types":"[\\"audit_events\\", \\"trace_events\\"]","automation_status":"automated","owner_team":"platform-security","review_frequency":"monthly"}}',
    description: "JSON object for default compliance control mappings seeded into the DB",
  },
  {
    config_key: "observability.logs.default_limit",
    config_value: "50",
    description: "Default page size for /observability/logs when limit query parameter is omitted",
  },
  {
    config_key: "observability.schema.default_sample_size",
    config_value: "200",
    description: "Default sample_size for /observability/logs/schema-status when omitted",
  },
  {
    config_key: "ui.feature.discovery.enabled.prod",
    config_value: "false",
    description: "Environment-scoped UI flag: disable Discovery view in prod profile",
  },
  {
    config_key: "ui.feature.security.enabled",
    config_value: "true",
    description: "Global UI flag: enable or disable Security view in all profiles",
  },
];

const qs = (sel) => document.querySelector(sel);
const qsa = (sel) => Array.from(document.querySelectorAll(sel));

let runtimeValidationRules = [];
const runtimeRuleValidationState = new Map();
const RUNTIME_RULE_STATUS_STORAGE_KEY = "runtimeRuleValidationState.v1";
let lastSpendRangeSelection = "1d";
let tenantCatalogRows = [];
const TENANT_TYPE_VALUES = ["enterprise", "regulated", "sandbox", "shared-services", "internal"];
let playgroundAttachments = [];
let playgroundJudgeRows = [];
let playgroundRuns = [];
let selectedPlaygroundRunId = "";
let playgroundStreamTimer = null;
let playgroundMicRecorder = null;
let playgroundMicStream = null;
let playgroundMicChunks = [];
let routePolicyRows = [];
let gatewayEntitlementRows = [];
let gatewayNhiInventoryRows = [];
let gatewayNhiHygieneSummary = null;
let gatewayAccessReviewCampaign = null;
let gatewayAccessReviewItems = [];
let gatewayLeastPrivilegeRows = [];
let gatewayGovernanceEvidenceRows = [];
let gatewayGovernanceEvidenceSummaryRows = [];
let gatewayOpenAiResponseRows = [];
let gatewayOpenAiFileRows = [];
let selectedGatewayOpenAiResponseId = "";
let selectedGatewayOpenAiFileId = "";
const selectedGatewayOpenAiResponseIds = new Set();
const selectedGatewayOpenAiFileIds = new Set();
let keyRows = [];
let discoverySourceRows = [];
let discoveryConflictRows = [];
let discoveryAlertRows = [];
let discoveryPromoteQueueRows = [];
let complianceControlRows = [];
let complianceMappingRows = [];
let complianceFreshnessRows = [];
let complianceRetentionRows = [];
let complianceLegalHoldRows = [];
let selectedComplianceControlId = "";
let costBudgetRows = [];
let latestCostLimitRows = [];
let latestPolicyRevisions = [];
let routeDraftRows = [];
let routeDraftHistoryRows = [];
let selectedRouteDraftId = "";
let selectedKeyId = "";
let keyRotationScheduleRows = [];
let moduleRows = [];
let agenticCertificationRows = [];
let agenticLoadTestRows = [];
let agenticCheckpointRows = [];
let policyScheduleRows = [];
let policyScheduleHistoryRows = [];
let latestBenchmarkRun = null;
let latestScanRun = null;
let benchmarkHistoryRows = [];
let scanHistoryRows = [];
let gatewayCachePolicyRows = [];
let gatewayMcpServerRows = [];
let gatewayMcpToolRows = [];
let gatewayExternalCallbackRows = [];
const gatewayMcpUiState = {
  selectedServer: "",
  toolCount: 0,
  lastTrace: "",
  status: "idle",
};
let directoryUserRows = [];
let directoryGroupRows = [];
let directoryTeamRows = [];

const VIEW_TITLES = {
  overview: "Overview",
  agents: "Agents",
  playground: "Playground",
  "benchmark-scan": "Benchmark & Scan",
  "routing-gateway": "Routing & Gateway",
  "runtime-config": "Runtime Config",
  providers: "Providers",
  modules: "Modules",
  agentic: "Agentic",
  discovery: "Discovery",
  cost: "Cost",
  audit: "Audit",
  compliance: "Compliance",
  observability: "Observability",
  security: "Security",
};

function runtimeRuleStatusStorageKey() {
  const api = encodeURIComponent(String(state.apiBase || "unknown"));
  const profile = encodeURIComponent(String(state.environmentProfile || "default"));
  return `${RUNTIME_RULE_STATUS_STORAGE_KEY}:${api}:${profile}`;
}

function renderRuntimeValidationContext() {
  const target = qs("#runtimeValidationContext");
  if (!target) return;
  target.textContent = `Status scope: ${safeText(state.environmentProfile)} @ ${safeText(state.apiBase)}`;
}

function safeText(value) {
  if (value === null || value === undefined || value === "") return "--";
  return String(value);
}

function setTableMessage(tbody, colSpan, message) {
  tbody.textContent = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = colSpan;
  td.className = "mono";
  td.textContent = message;
  tr.appendChild(td);
  tbody.appendChild(tr);
}

function isFormSubmitEventFor(evt, formId) {
  const form = evt?.target;
  return Boolean(form && form.tagName === "FORM" && form.id === formId);
}

function isClickEventFor(evt, elementId) {
  const target = evt?.target;
  return Boolean(target && typeof target.closest === "function" && target.closest(`#${elementId}`));
}

function setKeyFeedback(selector, message, tone = "neutral") {
  const el = qs(selector);
  if (!el) return;
  el.classList.remove("feedback-success", "feedback-error");
  if (tone === "success") el.classList.add("feedback-success");
  if (tone === "error") el.classList.add("feedback-error");
  el.textContent = message;
}

function isPaginationMessageRow(row) {
  if (!row || row.children.length !== 1) return false;
  const cell = row.firstElementChild;
  return Boolean(cell && Number(cell.colSpan || 0) > 1);
}

function getPaginationState(tbody) {
  const existing = tablePaginationState.get(tbody);
  if (existing) return existing;
  const state = {
    page: 1,
    pageSize: TABLE_PAGINATION_DEFAULT_PAGE_SIZE,
    controls: null,
    observer: null,
    refreshQueued: false,
  };
  tablePaginationState.set(tbody, state);
  return state;
}

function ensurePaginationControls(tbody) {
  const table = tbody.closest("table");
  if (!table) return null;
  const container = table.closest(".table-wrap") || table.parentElement || table;
  if (!container) return null;

  const state = getPaginationState(tbody);
  if (state.controls) return state.controls;

  const controls = document.createElement("div");
  controls.className = "table-pagination";

  const summary = document.createElement("span");
  summary.className = "table-pagination-summary mono";

  const pageSizeLabel = document.createElement("label");
  pageSizeLabel.className = "table-pagination-page-size";
  pageSizeLabel.textContent = "Rows";
  const pageSizeSelect = document.createElement("select");
  TABLE_PAGINATION_PAGE_SIZE_OPTIONS.forEach((size) => {
    const option = document.createElement("option");
    option.value = String(size);
    option.textContent = String(size);
    if (size === state.pageSize) option.selected = true;
    pageSizeSelect.appendChild(option);
  });
  pageSizeSelect.addEventListener("change", () => {
    state.pageSize = Number(pageSizeSelect.value) || TABLE_PAGINATION_DEFAULT_PAGE_SIZE;
    state.page = 1;
    refreshTablePagination(tbody);
  });
  pageSizeLabel.appendChild(pageSizeSelect);

  const buttons = document.createElement("div");
  buttons.className = "table-pagination-buttons";
  const prevBtn = document.createElement("button");
  prevBtn.type = "button";
  prevBtn.className = "ghost";
  prevBtn.textContent = "Prev";
  prevBtn.addEventListener("click", () => {
    state.page = Math.max(1, state.page - 1);
    refreshTablePagination(tbody);
  });
  const nextBtn = document.createElement("button");
  nextBtn.type = "button";
  nextBtn.className = "ghost";
  nextBtn.textContent = "Next";
  nextBtn.addEventListener("click", () => {
    state.page = state.page + 1;
    refreshTablePagination(tbody);
  });
  buttons.append(prevBtn, nextBtn);

  controls.append(summary, pageSizeLabel, buttons);

  const existingControls = container.parentElement?.querySelector(`.table-pagination[data-for="${tbody.id || ""}"]`);
  if (existingControls) existingControls.remove();
  controls.dataset.for = tbody.id || "";
  container.insertAdjacentElement("afterend", controls);

  state.controls = controls;
  state.summary = summary;
  state.pageSizeSelect = pageSizeSelect;
  state.prevBtn = prevBtn;
  state.nextBtn = nextBtn;
  return controls;
}

function refreshTablePagination(tbody) {
  if (!tbody) return;
  const rows = Array.from(tbody.children);
  const state = getPaginationState(tbody);

  if (!rows.length) {
    if (state.controls) state.controls.hidden = true;
    return;
  }

  if (rows.length === 1 && isPaginationMessageRow(rows[0])) {
    rows[0].hidden = false;
    if (state.controls) state.controls.hidden = true;
    return;
  }

  const totalRows = rows.length;
  const pageSize = Math.max(1, Number(state.pageSize) || TABLE_PAGINATION_DEFAULT_PAGE_SIZE);
  const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
  state.page = Math.min(Math.max(1, Number(state.page) || 1), totalPages);
  const startIndex = (state.page - 1) * pageSize;
  const endIndex = startIndex + pageSize;

  rows.forEach((row, index) => {
    row.hidden = index < startIndex || index >= endIndex;
  });

  const controls = ensurePaginationControls(tbody);
  if (controls) {
    controls.hidden = totalRows <= pageSize;
    if (state.summary) {
      const startLabel = totalRows ? startIndex + 1 : 0;
      const endLabel = Math.min(endIndex, totalRows);
      state.summary.textContent = totalRows <= pageSize
        ? `Showing all ${totalRows} rows`
        : `Showing ${startLabel}-${endLabel} of ${totalRows}`;
    }
    if (state.pageSizeSelect) {
      state.pageSizeSelect.value = String(pageSize);
    }
    if (state.prevBtn) {
      state.prevBtn.disabled = state.page <= 1;
    }
    if (state.nextBtn) {
      state.nextBtn.disabled = state.page >= totalPages;
    }
  }
}

function scheduleTablePaginationRefresh(tbody) {
  if (!tbody) return;
  const state = getPaginationState(tbody);
  if (state.refreshQueued) return;
  state.refreshQueued = true;
  window.requestAnimationFrame(() => {
    state.refreshQueued = false;
    refreshTablePagination(tbody);
  });
}

function initTablePagination() {
  if (window.__agenthubTablePaginationPatched) return;
  window.__agenthubTablePaginationPatched = true;

  const tableSectionProto = window.HTMLTableSectionElement?.prototype;
  if (tableSectionProto && !tableSectionProto.__agenthubPaginationPatched) {
    const originalAppendChild = tableSectionProto.appendChild;
    tableSectionProto.appendChild = function patchedAppendChild(child) {
      const result = originalAppendChild.call(this, child);
      if (this?.tagName === "TBODY" && child?.tagName === "TR") {
        refreshTablePagination(this);
      }
      return result;
    };
    tableSectionProto.__agenthubPaginationPatched = true;
  }

  const attach = (tbody) => {
    if (!tbody || tbody.dataset.paginationObserved === "true") return;
    tbody.dataset.paginationObserved = "true";
    const observer = new MutationObserver(() => scheduleTablePaginationRefresh(tbody));
    observer.observe(tbody, { childList: true });
    getPaginationState(tbody).observer = observer;
    tbody.dataset.paginationObserver = "attached";
    scheduleTablePaginationRefresh(tbody);
  };

  document.querySelectorAll(".table-wrap tbody").forEach(attach);
  const bodyObserver = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.matches("tbody")) attach(node);
        node.querySelectorAll?.("tbody").forEach(attach);
      });
    });
  });
  bodyObserver.observe(document.body, { childList: true, subtree: true });
}

function appendTableRow(tbody, values) {
  const tr = document.createElement("tr");
  values.forEach((value) => {
    const td = document.createElement("td");
    td.textContent = safeText(value);
    tr.appendChild(td);
  });
  tbody.appendChild(tr);
}

function buildApiUrl(path) {
  const base = parseApiBaseOrThrow(state.apiBase);
  return new URL(path, base).toString();
}

function fillSummaryCard(target, title, values) {
  if (!target) return;
  target.textContent = "";
  const heading = document.createElement("div");
  heading.className = "observability-summary-heading";
  heading.textContent = title;
  target.appendChild(heading);

  values.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "observability-summary-row";
    const labelEl = document.createElement("span");
    labelEl.className = "observability-summary-label";
    labelEl.textContent = label;
    const valueEl = document.createElement("span");
    valueEl.className = "observability-summary-value";
    valueEl.textContent = safeText(value);
    row.append(labelEl, valueEl);
    target.appendChild(row);
  });
}

function parseApiBaseOrThrow(rawBase) {
  const normalizedInput = normalizeApiBaseAlias(rawBase);
  let parsed;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    throw new Error("API Base URL must be a valid URL.");
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    throw new Error("API Base URL must use http or https.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("API Base URL must not include credentials.");
  }
  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/$/, "");
}

function incidentRef() {
  const epoch = Date.now().toString(36).toUpperCase();
  return `INC-${epoch}`;
}

function setGlobalError(message) {
  const banner = qs("#globalErrorBanner");
  const target = qs("#globalErrorMessage");
  const footer = qs(".public-footer");
  if (!banner || !target) return;
  target.textContent = `${safeText(message)} (Ref: ${incidentRef()})`;
  banner.hidden = false;
  if (footer) footer.classList.add("is-alert");
}

function clearGlobalError() {
  const banner = qs("#globalErrorBanner");
  const footer = qs(".public-footer");
  if (banner) banner.hidden = true;
  if (footer) footer.classList.remove("is-alert");
}

function renderStatusBadge(label, isHealthy = false) {
  const badge = qs("#statusBadge");
  if (!badge) return;
  const action = qs("#statusAction");
  const normalized = String(label || "").trim().toLowerCase();
  badge.textContent = `Status: ${label}`;
  badge.classList.remove("status-ok", "status-degraded", "status-incident");

  if (normalized === "incident") {
    badge.classList.add("status-incident");
    if (action) action.textContent = "Expected action: Open Incident Guidance, verify backend health and endpoint reachability, then escalate to Platform Ops if unresolved.";
    return;
  }

  if (normalized === "degraded") {
    badge.classList.add("status-degraded");
    if (action) action.textContent = "Expected action: Continue monitoring, review failed telemetry endpoints, and refresh after correcting profile or credentials.";
    return;
  }

  if (Boolean(isHealthy) || normalized === "healthy" || normalized === "monitoring") {
    badge.classList.add("status-ok");
    if (action) action.textContent = "Expected action: Monitor only. No intervention required.";
    return;
  }

  if (action) action.textContent = "Expected action: Validate backend and profile context, then refresh.";
}

function runtimeConfigPrettyValue(value) {
  if (value === null || value === undefined) return "--";
  const text = String(value);
  if (text.length > 80) return `${text.slice(0, 77)}...`;
  return text;
}

function parseBooleanFlag(value, fallback = true) {
  if (value === null || value === undefined || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on", "enabled"].includes(normalized)) return true;
  if (["0", "false", "no", "off", "disabled"].includes(normalized)) return false;
  return fallback;
}

function applyViewFeatureFlag(viewName, enabled) {
  const navBtn = qsa(".nav-item").find((btn) => btn.dataset.view === viewName);
  const section = qs(`#${viewName}`);
  if (navBtn) navBtn.hidden = !enabled;
  if (section) section.hidden = !enabled;
}

function findRuntimeValidationRule(configKey) {
  if (!configKey) return null;
  const key = String(configKey).trim();
  for (const rule of runtimeValidationRules) {
    if (rule.key && rule.key === key) return rule;
    if (rule.key_pattern) {
      try {
        const re = new RegExp(rule.key_pattern);
        if (re.test(key)) return rule;
      } catch {
        continue;
      }
    }
  }
  return null;
}

function ruleToHint(rule) {
  if (!rule) return "No key-specific server rule found. Generic non-empty string validation still applies.";
  if (rule.type === "int") return `Validation: integer between ${rule.min} and ${rule.max}.`;
  if (rule.type === "float") return `Validation: number between ${rule.min} and ${rule.max}.`;
  if (rule.type === "json_list") return `Validation: JSON list with fields ${rule.required_fields.join(", ")}.`;
  if (rule.key === "cost.model_token_rates_json") {
    return "Validation: JSON object with a default block and optional per-model input/output cents-per-1K rates.";
  }
  if (rule.key === "cost.cloud_component_multipliers_json") {
    return "Validation: JSON object with provider_type and endpoint_family multiplier maps using values greater than zero.";
  }
  if (rule.key === "cost.provider_discounts_json") {
    return "Validation: JSON object with provider_type and models discount maps using percentage values between 0 and 95.";
  }
  if (rule.type === "json_object") return "Validation: JSON object with required value shape.";
  if (rule.type === "boolean_like") return "Validation: boolean-like value (true/false/1/0).";
  return "Validation: server-side rule enforced.";
}

function updateRuntimeValidationHint(configKey) {
  const hint = qs("#runtimeConfigValidationHint");
  if (!hint) return;
  const rule = findRuntimeValidationRule(configKey);
  hint.textContent = ruleToHint(rule);
}

function uniqueSorted(values) {
  return Array.from(new Set(values.map((item) => String(item || "").trim().toLowerCase()).filter(Boolean))).sort();
}

function setSelectOptions(select, values, { placeholder = "Select an option", selectedValue = "" } = {}) {
  if (!select) return;
  const currentValue = selectedValue || select.value;
  select.textContent = "";

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = placeholder;
  placeholderOption.disabled = true;
  placeholderOption.hidden = true;
  select.appendChild(placeholderOption);

  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });

  if (values.includes(currentValue)) {
    select.value = currentValue;
  } else if (values.length) {
    select.value = values[0];
  } else {
    select.value = "";
  }
}

function setLabeledSelectOptions(select, options, { placeholder = "Select an option", selectedValue = "" } = {}) {
  if (!select) return;
  const currentValue = selectedValue || select.value;
  select.textContent = "";

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = placeholder;
  placeholderOption.disabled = true;
  placeholderOption.hidden = true;
  select.appendChild(placeholderOption);

  options.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.value;
    option.textContent = item.label;
    select.appendChild(option);
  });

  const values = options.map((item) => item.value);
  if (values.includes(currentValue)) {
    select.value = currentValue;
  } else if (values.length) {
    select.value = values[0];
  } else {
    select.value = "";
  }
}

function setTenantTypeDisplay(select, value = "") {
  if (!select) return;
  select.textContent = "";

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = value ? "Tenant type" : "Choose tenant first";
  select.appendChild(placeholderOption);

  TENANT_TYPE_VALUES.forEach((tenantType) => {
    const option = document.createElement("option");
    option.value = tenantType;
    option.textContent = tenantType;
    select.appendChild(option);
  });

  select.value = TENANT_TYPE_VALUES.includes(String(value || "").trim().toLowerCase()) ? String(value).trim().toLowerCase() : "";
}

function activeTenantRows() {
  return tenantCatalogRows.filter((row) => String(row.status || "").trim().toLowerCase() === "active");
}

function applyTenantOptionsToSelect(select, { includeBlank = false, selectedValue = "" } = {}) {
  if (!select) return;
  const options = activeTenantRows().map((row) => ({
    value: row.tenant_id,
    label: `${row.tenant_name} (${row.tenant_id})`,
  }));
  setLabeledSelectOptions(select, options, {
    placeholder: includeBlank ? "All tenants" : "Choose tenant",
    selectedValue,
  });
  if (includeBlank) {
    select.querySelector('option[value=""]')?.removeAttribute("disabled");
    select.querySelector('option[value=""]')?.removeAttribute("hidden");
  }
}

function syncTenantMetadataFields(form) {
  if (!form) return;
  const tenantId = String(form.elements.tenant_id?.value || "").trim();
  const tenant = activeTenantRows().find((row) => row.tenant_id === tenantId) || tenantCatalogRows.find((row) => row.tenant_id === tenantId) || null;

  if (form.elements.tenant_name_display) {
    form.elements.tenant_name_display.value = tenant?.tenant_name || "";
  }
  if (form.elements.tenant_description_display) {
    form.elements.tenant_description_display.value = tenant?.description || "";
  }
  if (form.elements.tenant_type_display) {
    setTenantTypeDisplay(form.elements.tenant_type_display, tenant?.tenant_type || "");
  }
}

function refreshTenantBoundForms() {
  const workloadCreate = qs("#createWorkloadIdentityProviderForm");
  const secretCreate = qs("#createSecretProviderForm");
  const workloadTokenExchange = qs("#workloadTokenExchangeForm");
  const workloadTrustForm = qs("#workloadIdentityTrustForm");
  const workloadHealthForm = qs("#workloadIdentityHealthForm");
  const workloadFilter = qs("#workloadIdentityProviderFilters");
  const secretFilter = qs("#secretProviderFilters");
  const supportedModelFilter = qs("#supportedModelFilters");
  const agentConfigForm = qs("#agentConfigForm");
  const entitlementForm = qs("#tenantModelEntitlementForm");
  const entitlementFilter = qs("#tenantModelEntitlementFilters");

  applyTenantOptionsToSelect(workloadCreate?.elements?.tenant_id, { selectedValue: workloadCreate?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(secretCreate?.elements?.tenant_id, { selectedValue: secretCreate?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(workloadTokenExchange?.elements?.tenant_id, {
    selectedValue: workloadTokenExchange?.elements?.tenant_id?.value || "",
  });
  applyTenantOptionsToSelect(workloadTrustForm?.elements?.tenant_id, {
    selectedValue: workloadTrustForm?.elements?.tenant_id?.value || "",
  });
  applyTenantOptionsToSelect(workloadHealthForm?.elements?.tenant_id, {
    selectedValue: workloadHealthForm?.elements?.tenant_id?.value || "",
  });
  applyTenantOptionsToSelect(workloadFilter?.elements?.tenant_id, { includeBlank: true, selectedValue: workloadFilter?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(secretFilter?.elements?.tenant_id, { includeBlank: true, selectedValue: secretFilter?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(supportedModelFilter?.elements?.tenant_id, { includeBlank: true, selectedValue: supportedModelFilter?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(agentConfigForm?.elements?.tenant_scope_id, {
    includeBlank: true,
    selectedValue: agentConfigForm?.elements?.tenant_scope_id?.value || "",
  });
  applyTenantOptionsToSelect(entitlementForm?.elements?.tenant_id, { selectedValue: entitlementForm?.elements?.tenant_id?.value || "" });
  applyTenantOptionsToSelect(entitlementFilter?.elements?.tenant_id, { includeBlank: true, selectedValue: entitlementFilter?.elements?.tenant_id?.value || "" });

  syncTenantMetadataFields(workloadCreate);
  syncTenantMetadataFields(secretCreate);
}

async function loadTenantCatalog() {
  const tbody = qs("#tenantCatalogTable");
  const result = qs("#tenantCatalogResult");
  if (tbody) setTableMessage(tbody, 7, "Loading...");

  try {
    const rows = await api("/providers/tenants?limit=500", { headers: { "X-Actor-Role": "Auditor" } });
    tenantCatalogRows = Array.isArray(rows) ? rows : [];
    refreshTenantBoundForms();

    if (result) result.textContent = `Loaded ${tenantCatalogRows.length} tenants.`;
    if (!tbody) return;
    if (!tenantCatalogRows.length) {
      setTableMessage(tbody, 7, "No tenant records found.");
      return;
    }

    tbody.textContent = "";
    tenantCatalogRows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.tenant_id);
      appendTableCell(tr, row.tenant_name);
      appendTableCell(tr, row.tenant_type);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.description);
      appendTableCell(tr, row.updated_at);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "ghost";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", () => populateTenantCatalogForm(row));
      actionsCell.appendChild(editBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

function resetTenantCatalogForm(message = "") {
  const form = qs("#tenantCatalogForm");
  const result = qs("#tenantCatalogResult");
  if (!form) return;
  form.reset();
  form.elements.existing_tenant_id.value = "";
  form.elements.tenant_id.readOnly = false;
  form.elements.tenant_type.value = "enterprise";
  form.elements.status.value = "active";
  if (result) result.textContent = message;
}

function populateTenantCatalogForm(row) {
  const form = qs("#tenantCatalogForm");
  const result = qs("#tenantCatalogResult");
  if (!form || !row) return;
  form.elements.existing_tenant_id.value = row.tenant_id || "";
  form.elements.tenant_id.value = row.tenant_id || "";
  form.elements.tenant_id.readOnly = true;
  form.elements.tenant_name.value = row.tenant_name || "";
  form.elements.tenant_type.value = row.tenant_type || "enterprise";
  form.elements.status.value = row.status || "active";
  form.elements.description.value = row.description || "";
  if (result) result.textContent = `Editing ${row.tenant_name}`;
}

async function saveTenantCatalogEntry(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#tenantCatalogResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const existingTenantId = String(raw.existing_tenant_id || "").trim();
  const payload = {
    tenant_id: String(raw.tenant_id || "").trim(),
    tenant_name: String(raw.tenant_name || "").trim(),
    tenant_type: String(raw.tenant_type || "enterprise").trim().toLowerCase(),
    description: String(raw.description || "").trim(),
    status: String(raw.status || "active").trim().toLowerCase(),
  };

  try {
    const path = existingTenantId ? `/providers/tenants/${encodeURIComponent(existingTenantId)}` : "/providers/tenants";
    const method = existingTenantId ? "PUT" : "POST";
    await api(path, {
      method,
      body: JSON.stringify(payload),
      headers: { "X-MFA-Verified": "true" },
    });
    resetTenantCatalogForm(`Saved tenant ${payload.tenant_name}.`);
    await loadTenantCatalog();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadProviderTypeOptions() {
  const agentProviderSelect = qs('#agentConfigForm select[name="provider"]');
  const providerTypeSelects = qsa('select[data-provider-type-select]');

  if (agentProviderSelect) {
    setSelectOptions(agentProviderSelect, [], { placeholder: "Loading provider types..." });
  }
  providerTypeSelects.forEach((select) => {
    const isFilter = select.closest("form")?.id?.includes("Filters");
    setSelectOptions(select, [], { placeholder: isFilter ? "All provider types" : "Loading provider types..." });
    if (isFilter) {
      select.querySelector('option[value=""]')?.removeAttribute("disabled");
      select.querySelector('option[value=""]')?.removeAttribute("hidden");
    }
  });

  try {
    const [workloadRows, secretRows] = await Promise.all([
      api("/auth/workload-identity/providers?limit=500", { headers: { "X-Actor-Role": "Auditor" } }),
      api("/secrets/providers?limit=500", { headers: { "X-Actor-Role": "Auditor" } }),
    ]);

    const providerTypes = uniqueSorted([
      ...(Array.isArray(workloadRows) ? workloadRows.map((row) => row.provider_type) : []),
      ...(Array.isArray(secretRows) ? secretRows.map((row) => row.provider_type) : []),
      "aws",
      "aws-secrets-manager",
      "azure",
      "azure-key-vault",
      "cohere",
      "fireworks",
      "google-cloud",
      "google",
      "nvidia-nim",
      "nvidia",
      "openai",
      "anthropic",
      "mistral",
      "groq",
      "perplexity",
      "together",
      "vault",
      "xai",
    ]);

    if (agentProviderSelect) {
      setSelectOptions(agentProviderSelect, providerTypes, { placeholder: "Choose provider type" });
    }
    providerTypeSelects.forEach((select) => {
      const isFilter = select.closest("form")?.id?.includes("Filters");
      setSelectOptions(select, providerTypes, { placeholder: isFilter ? "All provider types" : "Choose provider type" });
      if (isFilter) {
        select.querySelector('option[value=""]')?.removeAttribute("disabled");
        select.querySelector('option[value=""]')?.removeAttribute("hidden");
      }
    });
  } catch {
    const fallback = [
      "aws",
      "aws-secrets-manager",
      "azure",
      "azure-key-vault",
      "cohere",
      "fireworks",
      "google",
      "google-cloud",
      "groq",
      "mistral",
      "nvidia",
      "nvidia-nim",
      "openai",
      "anthropic",
      "perplexity",
      "together",
      "vault",
      "xai",
    ];
    if (agentProviderSelect) {
      setSelectOptions(agentProviderSelect, fallback, {
        placeholder: "Choose provider type",
      });
    }
    providerTypeSelects.forEach((select) => {
      const isFilter = select.closest("form")?.id?.includes("Filters");
      setSelectOptions(select, fallback, {
        placeholder: isFilter ? "All provider types" : "Choose provider type",
      });
      if (isFilter) {
        select.querySelector('option[value=""]')?.removeAttribute("disabled");
        select.querySelector('option[value=""]')?.removeAttribute("hidden");
      }
    });
  }
}

async function loadSupportedModelOptions(providerType = "", selectedValue = "", tenantId = "") {
  const select = qs('#agentConfigForm select[name="model"]');
  if (!select) return;

  const normalizedProvider = String(providerType || qs('#agentConfigForm select[name="provider"]')?.value || "").trim().toLowerCase();
  const normalizedTenantId = String(tenantId || qs('#agentConfigForm select[name="tenant_scope_id"]')?.value || "").trim();
  setLabeledSelectOptions(select, [], { placeholder: "Loading supported models...", selectedValue });

  try {
    const query = buildQueryString({
      tenant_id: normalizedTenantId || undefined,
      provider_type: normalizedProvider || undefined,
      status: "active",
      limit: 500,
    });
    const rows = await api(`/providers/models${query}`, { headers: { "X-Actor-Role": "Auditor" } });
    const options = (Array.isArray(rows) ? rows : []).map((row) => ({
      value: row.model_name,
      label: `${row.display_name} (${row.model_name})`,
    }));
    if (!options.length && selectedValue) {
      options.push({ value: selectedValue, label: selectedValue });
    }
    setLabeledSelectOptions(select, options, {
      placeholder: options.length ? "Choose supported model" : "No supported models found",
      selectedValue,
    });
  } catch {
    const fallbackOptions = selectedValue ? [{ value: selectedValue, label: selectedValue }] : [];
    setLabeledSelectOptions(select, fallbackOptions, {
      placeholder: fallbackOptions.length ? "Choose supported model" : "Unable to load supported models",
      selectedValue,
    });
  }
}

function normalizeAgentTypeFromProvider(providerType) {
  const normalized = String(providerType || "").trim().toLowerCase();
  if (["aws", "bedrock", "aws-secrets-manager"].includes(normalized)) return "aws";
  if (["azure", "azure-openai", "azure-key-vault"].includes(normalized)) return "azure";
  if (["google", "gcp", "vertex", "gcp-secret-manager"].includes(normalized)) return "gcp";
  if (["onprem", "self-hosted", "vmware", "kubernetes"].includes(normalized)) return "onprem";
  return "other";
}

function labelForAgentType(agentType) {
  const key = String(agentType || "").trim().toLowerCase();
  const labels = {
    aws: "AWS",
    azure: "Azure",
    gcp: "GCP",
    onprem: "On-Prem",
    hybrid: "Hybrid",
    other: "Other",
  };
  return labels[key] || "Other";
}

function setAgentTypeOptions(select, values, selectedValue = "") {
  if (!select) return;
  const current = selectedValue || select.value;
  select.textContent = "";
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = labelForAgentType(value);
    select.appendChild(option);
  });
  if (values.includes(current)) {
    select.value = current;
  } else if (values.length) {
    select.value = values[0];
  }
}

async function loadRegisterAgentTypeOptions() {
  const select = qs('#registerAgentForm select[name="agent_type"]');
  if (!select) return;

  setSelectOptions(select, [], { placeholder: "Loading enabled agent types..." });

  try {
    const [workloadRows, secretRows] = await Promise.all([
      api("/auth/workload-identity/providers?status=active&limit=500", { headers: { "X-Actor-Role": "Auditor" } }),
      api("/secrets/providers?status=active&limit=500", { headers: { "X-Actor-Role": "Auditor" } }),
    ]);

    const mapped = uniqueSorted([
      ...(Array.isArray(workloadRows) ? workloadRows.map((row) => normalizeAgentTypeFromProvider(row.provider_type)) : []),
      ...(Array.isArray(secretRows) ? secretRows.map((row) => normalizeAgentTypeFromProvider(row.provider_type)) : []),
    ]);

    const core = mapped.filter((item) => ["aws", "azure", "gcp", "onprem"].includes(item));
    const options = [...core];
    if (core.length >= 2) options.push("hybrid");
    if (mapped.includes("other") || !options.length) options.push("other");

    setAgentTypeOptions(select, uniqueSorted(options), "other");
  } catch {
    setAgentTypeOptions(select, ["other"], "other");
  }
}

async function loadRuntimeValidationRules() {
  try {
    const resp = await api("/runtime-config/validation-rules");
    runtimeValidationRules = Array.isArray(resp?.rules) ? resp.rules : [];
  } catch {
    runtimeValidationRules = [];
  }
}

function ruleTargetText(rule) {
  if (rule?.key) return rule.key;
  if (rule?.key_pattern) return `pattern: ${rule.key_pattern}`;
  return "--";
}

function ruleConstraintText(rule) {
  if (!rule) return "--";
  if (rule.type === "int" || rule.type === "float") {
    return `min=${safeText(rule.min)}, max=${safeText(rule.max)}`;
  }
  if (rule.type === "json_list") {
    return `required fields: ${Array.isArray(rule.required_fields) ? rule.required_fields.join(", ") : "--"}`;
  }
  if (rule.type === "json_object") {
    return `value type: ${safeText(rule.value_type || "object")}`;
  }
  if (rule.type === "boolean_like") {
    return "accepted: true/false/1/0";
  }
  return "--";
}

function ruleExampleValue(rule) {
  if (!rule) return "--";
  if (rule.key) {
    const preset = RUNTIME_CONFIG_PRESETS.find((item) => item.config_key === rule.key);
    if (preset) return String(preset.config_value);
  }
  if (rule.type === "boolean_like") return "true";
  if (rule.type === "json_list") return '[{"method":"POST","path":"/example","max_requests":10,"window_seconds":60}]';
  if (rule.type === "json_object") return '{"key":"value"}';
  if (rule.type === "int") return String(rule.min ?? 1);
  if (rule.type === "float") return String(rule.min ?? 0.1);
  return "--";
}

function ruleExampleText(rule) {
  return runtimeConfigPrettyValue(ruleExampleValue(rule));
}

function ruleFormKey(rule) {
  if (rule?.key) return rule.key;
  if (rule?.key_pattern && String(rule.key_pattern).includes("ui\\.feature")) {
    return "ui.feature.discovery.enabled.prod";
  }
  return "";
}

function runtimeRuleId(rule) {
  if (rule?.key) return `key:${rule.key}`;
  if (rule?.key_pattern) return `pattern:${rule.key_pattern}`;
  return `type:${safeText(rule?.type)}`;
}

function runtimeRuleStatusText(rule) {
  const status = runtimeRuleValidationState.get(runtimeRuleId(rule));
  if (!status) return "Not validated";
  const stamp = new Date(status.checked_at).toLocaleTimeString();
  if (status.valid) return `PASS at ${stamp}`;
  return `FAIL at ${stamp}: ${safeText(status.error || "Invalid value")}`;
}

function runtimeRuleStatusClass(rule) {
  const status = runtimeRuleValidationState.get(runtimeRuleId(rule));
  if (!status) return "rule-status";
  return status.valid ? "rule-status rule-status-pass" : "rule-status rule-status-fail";
}

function persistRuntimeRuleValidationState() {
  try {
    const serializable = Object.fromEntries(runtimeRuleValidationState.entries());
    sessionStorage.setItem(runtimeRuleStatusStorageKey(), JSON.stringify(serializable));
  } catch {
    // Best effort only; UI continues without persistence.
  }
}

function restoreRuntimeRuleValidationState() {
  try {
    const raw = sessionStorage.getItem(runtimeRuleStatusStorageKey());
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return;
    runtimeRuleValidationState.clear();
    Object.entries(parsed).forEach(([key, value]) => {
      if (!value || typeof value !== "object") return;
      runtimeRuleValidationState.set(key, {
        valid: Boolean(value.valid),
        error: value.error ? String(value.error) : null,
        checked_at: String(value.checked_at || new Date().toISOString()),
      });
    });
  } catch {
    runtimeRuleValidationState.clear();
  }
}

function switchRuntimeRuleValidationContext(message = "") {
  runtimeRuleValidationState.clear();
  restoreRuntimeRuleValidationState();
  renderRuntimeValidationContext();
  renderRuntimeValidationRulesTable();
  if (message) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = message;
  }
}

function setRuntimeRuleValidationStatus(ruleId, status) {
  runtimeRuleValidationState.set(ruleId, status);
  persistRuntimeRuleValidationState();
}

function clearRuntimeRuleValidationState(message = "") {
  runtimeRuleValidationState.clear();
  persistRuntimeRuleValidationState();
  renderRuntimeValidationRulesTable();
  if (message) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = message;
  }
}

function applyValidationRuleToForm(rule) {
  const form = qs("#runtimeConfigForm");
  if (!form) return;

  const key = ruleFormKey(rule);
  const value = ruleExampleValue(rule);
  if (key) form.elements.config_key.value = key;
  if (value && value !== "--") form.elements.config_value.value = value;
  if (!String(form.elements.description.value || "").trim()) {
    form.elements.description.value = "Seeded from validation rules explorer";
  }

  updateRuntimeValidationHint(form.elements.config_key.value || "");
  const result = qs("#runtimeConfigResult");
  if (result) {
    result.textContent = key
      ? `Seeded form from rule ${key}. Adjust values as needed and save.`
      : "Rule has no concrete key. Enter a target key that matches the pattern and then save.";
  }
}

async function copyTextToClipboard(text) {
  const value = String(text || "");
  if (!value) return false;
  if (navigator?.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return true;
  }

  const helper = document.createElement("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "readonly");
  helper.style.position = "absolute";
  helper.style.left = "-9999px";
  document.body.appendChild(helper);
  helper.select();
  const copied = document.execCommand("copy");
  document.body.removeChild(helper);
  return Boolean(copied);
}

async function copyValidationRuleTemplate(rule) {
  const result = qs("#runtimeConfigResult");
  const value = ruleExampleValue(rule);
  if (!value || value === "--") {
    if (result) result.textContent = "No template available for this rule.";
    return;
  }

  try {
    const copied = await copyTextToClipboard(value);
    if (result) {
      result.textContent = copied
        ? `Template copied for ${ruleTargetText(rule)}. Paste into Config Value.`
        : "Unable to copy template automatically. Copy from the Example column.";
    }
  } catch {
    if (result) result.textContent = "Clipboard write failed. Copy from the Example column.";
  }
}

async function validateValidationRuleTemplate(rule) {
  const result = qs("#runtimeConfigResult");
  const key = ruleFormKey(rule);
  const value = ruleExampleValue(rule);
  const ruleId = runtimeRuleId(rule);

  if (!key) {
    setRuntimeRuleValidationStatus(ruleId, {
      valid: false,
      error: "Pattern-only rule requires a concrete key",
      checked_at: new Date().toISOString(),
    });
    renderRuntimeValidationRulesTable();
    if (result) result.textContent = "Cannot validate pattern-only rule template. Use a concrete key first.";
    return;
  }
  if (!value || value === "--") {
    setRuntimeRuleValidationStatus(ruleId, {
      valid: false,
      error: "No template value available",
      checked_at: new Date().toISOString(),
    });
    renderRuntimeValidationRulesTable();
    if (result) result.textContent = `No template value available for ${key}.`;
    return;
  }

  try {
    const validation = await api("/runtime-config/validate", {
      method: "POST",
      body: JSON.stringify({
        config_key: key,
        config_value: value,
      }),
    });
    setRuntimeRuleValidationStatus(ruleId, {
      valid: Boolean(validation?.valid),
      error: validation?.error || null,
      checked_at: new Date().toISOString(),
    });
    renderRuntimeValidationRulesTable();
    if (result) {
      result.textContent = validation?.valid
        ? `Template validation passed for ${key}.`
        : `Template validation failed for ${key}: ${safeText(validation?.error || "Invalid value")}`;
    }
  } catch (err) {
    setRuntimeRuleValidationStatus(ruleId, {
      valid: false,
      error: safeText(err.message),
      checked_at: new Date().toISOString(),
    });
    renderRuntimeValidationRulesTable();
    if (result) result.textContent = `Validation request failed: ${safeText(err.message)}`;
  }
}

function renderRuntimeValidationRulesTable() {
  const tbody = qs("#runtimeValidationRulesTable");
  if (!tbody) return;

  const searchRaw = String(qs("#runtimeValidationSearch")?.value || "").trim().toLowerCase();
  const rows = runtimeValidationRules.filter((rule) => {
    if (!searchRaw) return true;
    const haystack = [rule.key, rule.key_pattern, rule.type, ruleConstraintText(rule)].join(" ").toLowerCase();
    return haystack.includes(searchRaw);
  });

  if (!rows.length) {
    setTableMessage(tbody, 6, searchRaw ? "No rules match the current filter." : "No runtime validation rules available.");
    return;
  }

  tbody.textContent = "";
  rows.forEach((rule) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, ruleTargetText(rule));
    appendTableCell(tr, safeText(rule.type));
    appendTableCell(tr, ruleConstraintText(rule));
    appendTableCell(tr, ruleExampleText(rule));

    const actionsCell = document.createElement("td");
    actionsCell.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use Rule";
    useBtn.addEventListener("click", () => applyValidationRuleToForm(rule));
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "ghost";
    copyBtn.textContent = "Copy Template";
    copyBtn.addEventListener("click", async () => copyValidationRuleTemplate(rule));
    const validateBtn = document.createElement("button");
    validateBtn.type = "button";
    validateBtn.className = "ghost";
    validateBtn.textContent = "Validate Template";
    validateBtn.addEventListener("click", async () => validateValidationRuleTemplate(rule));
    actionsCell.appendChild(useBtn);
    actionsCell.appendChild(copyBtn);
    actionsCell.appendChild(validateBtn);
    tr.appendChild(actionsCell);

    const statusCell = document.createElement("td");
    const statusPill = document.createElement("span");
    statusPill.className = runtimeRuleStatusClass(rule);
    statusPill.textContent = runtimeRuleStatusText(rule);
    statusCell.appendChild(statusPill);
    tr.appendChild(statusCell);

    tbody.appendChild(tr);
  });
}

function normalizeProfileForFeatureFlags(profile) {
  if (["local", "stage", "prod"].includes(profile)) return profile;
  return "default";
}

function resolveViewFeatureEnabled(viewName, runtimeRows, environmentProfile) {
  const profile = normalizeProfileForFeatureFlags(environmentProfile);
  const byKey = new Map((runtimeRows || []).map((row) => [String(row.config_key || ""), row.config_value]));
  const profileKey = `${UI_FEATURE_FLAG_PREFIX}${viewName}.enabled.${profile}`;
  const globalKey = `${UI_FEATURE_FLAG_PREFIX}${viewName}.enabled`;

  if (byKey.has(profileKey)) return parseBooleanFlag(byKey.get(profileKey), true);
  if (byKey.has(globalKey)) return parseBooleanFlag(byKey.get(globalKey), true);
  return true;
}

function applyUiFeatureFlags(runtimeRows) {
  UI_FEATURE_VIEWS.forEach((viewName) => {
    const enabled = resolveViewFeatureEnabled(viewName, runtimeRows, state.environmentProfile);
    applyViewFeatureFlag(viewName, enabled);
  });

  const active = qsa(".nav-item").find((btn) => btn.classList.contains("active") && !btn.hidden);
  if (!active) {
    const fallback = qsa(".nav-item").find((btn) => !btn.hidden);
    if (fallback) switchView(fallback.dataset.view);
  }
}

async function refreshUiFeatureFlags() {
  try {
    const rows = await api("/runtime-config");
    applyUiFeatureFlags(rows);
  } catch {
    applyUiFeatureFlags([]);
  }
}

function currency(cents) {
  if (typeof cents !== "number") return "--";
  return `$${(cents / 100).toFixed(2)}`;
}

function toNumber(value, fallback) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function parsePriorityList(raw) {
  const value = String(raw || "").trim();
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function stringifyPriorityList(items) {
  if (!Array.isArray(items)) return "";
  return items.filter(Boolean).join(",");
}

function cloudFamily(provider) {
  const normalized = String(provider || "").trim().toLowerCase();
  if (["aws", "bedrock"].includes(normalized)) return "aws";
  if (["azure", "azure-openai"].includes(normalized)) return "azure";
  if (["google", "gcp", "vertex"].includes(normalized)) return "google";
  if (["nvidia"].includes(normalized)) return "nvidia";
  if (["openai", "anthropic", "cohere", "mistral", "groq", "together", "fireworks", "perplexity", "xai"].includes(normalized)) {
    return "ai-vendor";
  }
  return "unknown";
}

function weakChecksum(input) {
  const text = String(input || "");
  let hash = 0;
  for (let idx = 0; idx < text.length; idx += 1) {
    hash = (hash * 31 + text.charCodeAt(idx)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function createConfigId() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `cfg-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

async function loadAgentConfigsFromStorage() {
  try {
    const rows = await api("/agent-configs");
    return rows.map((row) => normalizeAgentConfig(row, row.config_id));
  } catch {
    return [];
  }
}

async function saveAgentConfigsToStorage(configs) {
  const rows = Array.isArray(configs) ? configs : [];
  await Promise.all(
    rows
      .filter((config) => config?.agent_key)
      .map((config) =>
        api(`/agent-configs/${encodeURIComponent(config.agent_key)}`, {
          method: "PUT",
          body: JSON.stringify(config),
        }),
      ),
  );
}

function normalizeAgentConfig(payload, existingConfigId = "") {
  const now = new Date().toISOString();
  return {
    config_id: existingConfigId || createConfigId(),
    agent_key: String(payload.agent_key || "").trim(),
    display_name: String(payload.display_name || "").trim(),
    provider: String(payload.provider || "aws").trim().toLowerCase(),
    model: String(payload.model || "").trim(),
    provider_priority: parsePriorityList(payload.provider_priority || payload.provider),
    temperature: toNumber(payload.temperature, 0.3),
    max_tokens: Math.max(1, Math.round(toNumber(payload.max_tokens, 1024))),
    timeout_ms: Math.max(100, Math.round(toNumber(payload.timeout_ms, 4500))),
    fallback_enabled: String(payload.fallback_enabled ?? "true") === "true",
    max_fallback_hops: Math.max(0, Math.round(toNumber(payload.max_fallback_hops, 2))),
    global_timeout_ms: Math.max(100, Math.round(toNumber(payload.global_timeout_ms, 4500))),
    retry_budget: Math.max(0, Math.round(toNumber(payload.retry_budget, 1))),
    failure_threshold_percent: Math.min(100, Math.max(1, Math.round(toNumber(payload.failure_threshold_percent, 40)))),
    cooldown_seconds: Math.max(5, Math.round(toNumber(payload.cooldown_seconds, 60))),
    environment: String(payload.environment || "dev").trim().toLowerCase(),
    enabled: String(payload.enabled) === "true",
    notes: String(payload.notes || "").trim(),
    updated_at: now,
  };
}

async function renderAgentConfigTable() {
  const tbody = qs("#agentConfigTable");
  if (!tbody) return;

  const rows = (await loadAgentConfigsFromStorage()).sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
  if (!rows.length) {
    setTableMessage(tbody, 9, "No agent configurations saved yet.");
    return;
  }

  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.agent_key);
    appendTableCell(tr, row.display_name);
    appendTableCell(tr, `${row.provider} / ${row.model}`);
    appendTableCell(tr, `T=${row.temperature}, max=${row.max_tokens}, t/o=${row.timeout_ms}ms`);
    appendTableCell(
      tr,
      `${row.fallback_enabled ? "on" : "off"}; prio=${stringifyPriorityList(row.provider_priority)}; hops=${row.max_fallback_hops}; global=${row.global_timeout_ms}ms; retries=${row.retry_budget}; cb>${row.failure_threshold_percent}%/${row.cooldown_seconds}s`,
    );
    appendTableCell(tr, row.environment);
    appendTableCell(tr, row.enabled ? "enabled" : "disabled");
    appendTableCell(tr, row.updated_at);

    const actionsCell = document.createElement("td");
    actionsCell.className = "cell-actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "ghost";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => populateAgentConfigForm(row.config_id));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteAgentConfig(row.config_id));

    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(deleteBtn);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  });
}

function appendTableCell(tr, value) {
  const td = document.createElement("td");
  td.textContent = safeText(value);
  tr.appendChild(td);
}

function formatViewTitle(viewName) {
  return VIEW_TITLES[viewName] || String(viewName || "").replace(/-/g, " ");
}

function parseListInput(raw) {
  const text = String(raw || "").trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.map((item) => String(item).trim()).filter(Boolean);
  } catch {
    // fall back to line/comma splitting
  }
  return text
    .split(/[\n,]/)
    .map((item) => String(item).trim())
    .filter(Boolean);
}

function parseJsonOrFallback(raw, fallback) {
  const text = String(raw || "").trim();
  if (!text) return fallback;
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

function bytesToSize(bytes) {
  const size = Number(bytes || 0);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let unitIndex = 0;
  let value = size;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function attachmentKind(file) {
  const mime = String(file?.type || "");
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "voice";
  return "file";
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}

async function capturePlaygroundAttachments(fileList, kind) {
  const files = Array.from(fileList || []);
  const items = [];
  for (const file of files) {
    const previewUrl = await readFileAsDataUrl(file);
    items.push({
      kind,
      name: file.name,
      size: file.size,
      mime: file.type || "application/octet-stream",
      previewUrl,
    });
  }
  return items;
}

function renderPlaygroundAttachments() {
  const tbody = qs("#playgroundAttachmentTable");
  if (!tbody) return;
  if (!playgroundAttachments.length) {
    setTableMessage(tbody, 5, "No attachments selected.");
    return;
  }
  tbody.textContent = "";
  playgroundAttachments.forEach((attachment) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, attachment.kind);
    appendTableCell(tr, attachment.name);
    appendTableCell(tr, bytesToSize(attachment.size));
    appendTableCell(tr, attachment.mime);
    const previewCell = document.createElement("td");
    if (attachment.kind === "video") {
      const video = document.createElement("video");
      video.controls = true;
      video.src = attachment.previewUrl;
      video.style.maxWidth = "220px";
      previewCell.appendChild(video);
    } else if (attachment.kind === "voice") {
      const audio = document.createElement("audio");
      audio.controls = true;
      audio.src = attachment.previewUrl;
      previewCell.appendChild(audio);
    } else {
      previewCell.textContent = "Preview unavailable";
    }
    tr.appendChild(previewCell);
    tbody.appendChild(tr);
  });
}

function buildPlaygroundPromptPackage(promptText, liveStreamMode) {
  const attachmentLines = playgroundAttachments.length
    ? playgroundAttachments.map((attachment) => `- ${attachment.kind}: ${attachment.name} (${attachment.mime}, ${bytesToSize(attachment.size)})`).join("\n")
    : "- none";
  return [
    "## Multimodal Prompt Package",
    `- live_stream_mode: ${liveStreamMode}`,
    `- attachment_count: ${playgroundAttachments.length}`,
    "- attachments:",
    attachmentLines,
    "",
    "## Prompt",
    String(promptText || "").trim(),
  ]
    .join("\n")
    .trim();
}

function updatePlaygroundStreamLog(lines) {
  const target = qs("#playgroundLiveStreamLog");
  if (!target) return;
  target.textContent = Array.isArray(lines) ? lines.join("\n") : String(lines || "");
}

function updatePlaygroundMicStatus(message) {
  const target = qs("#playgroundMicStatus");
  if (target) target.textContent = String(message || "");
}

function appendTranscriptToPrompt(transcript) {
  const form = qs("#playgroundRunForm");
  if (!form || !transcript) return;
  const current = String(form.elements.prompt_text.value || "").trim();
  const transcriptBlock = `\n\nVoice transcript:\n${String(transcript || "").trim()}`;
  if (!current.includes("Voice transcript:")) {
    form.elements.prompt_text.value = `${current}${transcriptBlock}`.trim();
  }
}

async function stopPlaygroundMicRecording() {
  if (playgroundMicRecorder && playgroundMicRecorder.state !== "inactive") {
    playgroundMicRecorder.stop();
  }
  if (playgroundMicStream) {
    playgroundMicStream.getTracks().forEach((track) => track.stop());
    playgroundMicStream = null;
  }
}

async function togglePlaygroundMic() {
  const button = qs("#togglePlaygroundMic");
  const status = qs("#playgroundMicStatus");
  const promptForm = qs("#playgroundRunForm");
  if (!button || !status || !promptForm) return;

  if (playgroundMicRecorder && playgroundMicRecorder.state === "recording") {
    await stopPlaygroundMicRecording();
    button.textContent = "Turn On Mike";
    updatePlaygroundMicStatus("Microphone off.");
    return;
  }

  if (!navigator.mediaDevices?.getUserMedia) {
    updatePlaygroundMicStatus("Microphone access is not supported in this browser.");
    return;
  }

  try {
    playgroundMicStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    playgroundMicChunks = [];
    const recorder = new MediaRecorder(playgroundMicStream);
    playgroundMicRecorder = recorder;
    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) playgroundMicChunks.push(event.data);
    };
    recorder.onstop = () => {
      const mimeType = recorder.mimeType || "audio/webm";
      const blob = new Blob(playgroundMicChunks, { type: mimeType });
      const previewUrl = URL.createObjectURL(blob);
      playgroundAttachments = [
        ...playgroundAttachments.filter((item) => item.kind !== "voice"),
        {
          kind: "voice",
          name: `voice-note-${new Date().toISOString().replace(/[:.]/g, "-")}.webm`,
          size: blob.size,
          mime: blob.type || mimeType,
          previewUrl,
          blob,
        },
      ];
      renderPlaygroundAttachments();
      if (playgroundMicTranscriptBuffer.trim()) {
        appendTranscriptToPrompt(playgroundMicTranscriptBuffer.trim());
        playgroundMicTranscriptBuffer = "";
      }
      button.textContent = "Turn On Mike";
      updatePlaygroundMicStatus("Microphone saved as a voice attachment.");
      playgroundMicRecorder = null;
    };
    recorder.start();
    button.textContent = "Turn Off Mike";
    updatePlaygroundMicStatus("Microphone on. Speak to capture a voice attachment.");
  } catch (err) {
    updatePlaygroundMicStatus(`Microphone error: ${safeText(err.message)}`);
    button.textContent = "Turn On Mike";
  }
}

let playgroundMicTranscriptBuffer = "";

function stopPlaygroundStream() {
  if (playgroundStreamTimer) {
    window.clearInterval(playgroundStreamTimer);
    playgroundStreamTimer = null;
  }
}

function startPlaygroundStreamPreview(promptPackage) {
  stopPlaygroundStream();
  const lines = ["[stream] preparing multimodal prompt...", `[stream] attachment count: ${playgroundAttachments.length}`];
  const words = promptPackage.split(/\s+/).filter(Boolean);
  let index = 0;
  updatePlaygroundStreamLog(lines);
  playgroundStreamTimer = window.setInterval(() => {
    if (index >= words.length) {
      lines.push("[stream] completed");
      updatePlaygroundStreamLog(lines);
      stopPlaygroundStream();
      return;
    }
    lines.push(`[stream] ${words.slice(index, index + 10).join(" ")}`);
    index += 10;
    updatePlaygroundStreamLog(lines);
  }, 220);
}

function renderPlaygroundJudgeRows(rows) {
  const tbody = qs("#playgroundJudgeTable");
  const summary = qs("#playgroundJudgeSummary");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 5, "No judge results.");
    if (summary) summary.textContent = "No judge results available.";
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.model_name);
    appendTableCell(tr, `${row.estimated_latency_ms} ms`);
    appendTableCell(tr, `$${(Number(row.estimated_cost_cents || 0) / 100).toFixed(2)}`);
    appendTableCell(tr, row.quality_score);
    const actions = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.textContent = "Apply";
    button.addEventListener("click", () => applyPlaygroundWinner(row));
    actions.appendChild(button);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
  if (summary) {
    summary.textContent = `Best model: ${rows[0].model_name} with ${rows[0].quality_score} quality.`;
  }
}

function applyPlaygroundWinner(row = playgroundJudgeRows[0]) {
  const form = qs("#playgroundRunForm");
  if (!form || !row) return;
  form.elements.selected_model.value = row.model_name;
  const result = qs("#playgroundResult");
  if (result) result.textContent = `Applied winner ${row.model_name} to the prompt form.`;
}

function renderPlaygroundRuns() {
  const tbody = qs("#playgroundRunTable");
  if (!tbody) return;
  if (!playgroundRuns.length) {
    setTableMessage(tbody, 7, "No runs yet.");
    return;
  }
  tbody.textContent = "";
  playgroundRuns.forEach((run) => {
    const tr = document.createElement("tr");
    if (run.run_id === selectedPlaygroundRunId) {
      tr.classList.add("selected-row");
    }
    appendTableCell(tr, run.run_id);
    appendTableCell(tr, run.selected_model);
    appendTableCell(tr, run.status);
    appendTableCell(tr, run.policy_decision);
    appendTableCell(tr, `$${(Number(run.estimated_cost_cents || 0) / 100).toFixed(2)}`);
    appendTableCell(tr, run.created_at);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const openBtn = document.createElement("button");
    openBtn.type = "button";
    openBtn.className = "ghost";
    openBtn.textContent = "Open";
    openBtn.addEventListener("click", () => loadPlaygroundRunDetails(run.run_id));
    const retryBtn = document.createElement("button");
    retryBtn.type = "button";
    retryBtn.className = "ghost";
    retryBtn.textContent = "Retry";
    retryBtn.addEventListener("click", () => retryPlaygroundPrompt(run));
    const draftBtn = document.createElement("button");
    draftBtn.type = "button";
    draftBtn.className = "ghost";
    draftBtn.textContent = "Draft";
    draftBtn.addEventListener("click", () => createRouteDraftFromPlaygroundRun(run));
    actions.append(openBtn, retryBtn, draftBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

async function loadPlaygroundRuns(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#playgroundRunHistoryFilters");
  const result = qs("#playgroundRunHistoryResult");
  const tbody = qs("#playgroundRunTable");
  if (!form || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const runId = String(raw.run_id || "").trim();
  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = runId
      ? [await api(`/playground/runs/${encodeURIComponent(runId)}`)]
      : await api(`/playground/runs${buildQueryString({ limit: raw.limit, offset: raw.offset })}`);
    playgroundRuns = Array.isArray(rows) ? rows : [];
    selectedPlaygroundRunId = playgroundRuns[0]?.run_id || "";
    renderPlaygroundRuns();
    if (result) {
      result.textContent = playgroundRuns.length
        ? `Loaded ${playgroundRuns.length} playground runs${runId ? ` for ${runId}` : ""}.`
        : "No playground runs found.";
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadPlaygroundRunDetails(runId) {
  const form = qs("#playgroundRunHistoryFilters");
  const result = qs("#playgroundRunHistoryResult");
  const trimmedRunId = String(runId || form?.elements.run_id?.value || selectedPlaygroundRunId || "").trim();
  if (!trimmedRunId) {
    if (result) result.textContent = "Select a playground run first.";
    return;
  }
  try {
    const row = await api(`/playground/runs/${encodeURIComponent(trimmedRunId)}`);
    playgroundRuns = [row];
    selectedPlaygroundRunId = row.run_id;
    if (form?.elements?.run_id) form.elements.run_id.value = row.run_id;
    renderPlaygroundRuns();
    if (result) {
      result.textContent = `Opened run ${row.run_id} for ${row.selected_model} with status ${row.status}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function buildRetryPrompt(promptText) {
  const winner = playgroundJudgeRows[0];
  if (!winner) return String(promptText || "").trim();
  return `${String(promptText || "").trim()}\n\nRetry guidance: prefer ${winner.model_name} because it ranked highest in the last judge pass.`.trim();
}

function humanizeRoutePolicy(row) {
  return row?.route_name || row?.route_policy_id || "route-policy";
}

function routeGroupCount(row) {
  try {
    const fallbackPolicy = parseJsonSafe(row?.fallback_policy, {});
    const groups = Array.isArray(fallbackPolicy?.routing_groups) ? fallbackPolicy.routing_groups : [];
    return groups.length;
  } catch {
    return 0;
  }
}

function renderRoutePolicyRows() {
  const tbody = qs("#routePoliciesTable");
  if (!tbody) return;
  if (!routePolicyRows.length) {
    setTableMessage(tbody, 6, "No route policies found.");
    return;
  }
  tbody.textContent = "";
  routePolicyRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.route_policy_id);
    appendTableCell(tr, row.route_name);
    appendTableCell(tr, row.load_balancing_strategy);
    appendTableCell(tr, routeGroupCount(row));
    appendTableCell(tr, row.status);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => populateRoutingForms(row));
    const optimizeBtn = document.createElement("button");
    optimizeBtn.type = "button";
    optimizeBtn.className = "ghost";
    optimizeBtn.textContent = "Optimize";
    optimizeBtn.addEventListener("click", () => optimizeRoutePolicy(row.route_policy_id));
    const priorityBtn = document.createElement("button");
    priorityBtn.type = "button";
    priorityBtn.className = "ghost";
    priorityBtn.textContent = "Priority";
    priorityBtn.addEventListener("click", () => loadRoutePriorityReadback(row.route_policy_id));
    actions.append(useBtn, optimizeBtn, priorityBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function summarizeEntitlementScope(row) {
  const scopeParts = [];
  if (row?.tenant_id) scopeParts.push(`tenant:${row.tenant_id}`);
  if (row?.environment) scopeParts.push(`env:${row.environment}`);
  if (row?.route_policy_id) scopeParts.push(`route:${row.route_policy_id}`);
  if (row?.request_tag) scopeParts.push(`tag:${row.request_tag}`);
  if (row?.model_name) scopeParts.push(`model:${row.model_name}`);
  if (row?.tool_name) scopeParts.push(`tool:${row.tool_name}`);
  return scopeParts.length ? scopeParts.join(" | ") : "global";
}

function renderGatewayEntitlementRows() {
  const tbody = qs("#gatewayEntitlementTable");
  if (!tbody) return;
  if (!gatewayEntitlementRows.length) {
    setTableMessage(tbody, 7, "No entitlements found.");
    return;
  }

  tbody.textContent = "";
  gatewayEntitlementRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.entitlement_id);
    appendTableCell(tr, row.action);
    appendTableCell(tr, summarizeEntitlementScope(row));
    appendTableCell(tr, row.allowed_roles || "[]");
    appendTableCell(tr, String(Boolean(row.enabled)));
    appendTableCell(tr, formatComplianceDate(row.updated_at));

    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "ghost";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => populateGatewayEntitlementForm(row));
    actions.append(editBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderGatewayNhiHygieneSummary(data) {
  const tbody = qs("#gatewayNhiHygieneTable");
  if (!tbody) return;
  const rows = [
    ["Max Credential Age Days", safeText(data?.max_credential_age_days)],
    ["Total Identities", safeText(data?.total_identities)],
    ["Stale Credentials", safeText(data?.stale_credentials)],
    ["Missing Owner", safeText(data?.missing_owner)],
    ["Inactive Identities", safeText(data?.inactive_identities)],
    ["High-Risk Identities", safeText(data?.high_risk_identities)],
    [
      "Source Distribution",
      Array.isArray(data?.source_distribution) && data.source_distribution.length
        ? data.source_distribution.map((row) => `${safeText(row.key)} (${safeText(row.count)})`).join(", ")
        : "--",
    ],
    [
      "Findings Distribution",
      Array.isArray(data?.findings_distribution) && data.findings_distribution.length
        ? data.findings_distribution.map((row) => `${safeText(row.key)} (${safeText(row.count)})`).join(", ")
        : "--",
    ],
  ];
  tbody.textContent = "";
  rows.forEach((row) => appendTableRow(tbody, row));
}

function renderGatewayNhiInventoryRows() {
  const tbody = qs("#gatewayNhiInventoryTable");
  if (!tbody) return;
  if (!gatewayNhiInventoryRows.length) {
    setTableMessage(tbody, 9, "No NHI records found.");
    return;
  }

  tbody.textContent = "";
  gatewayNhiInventoryRows.forEach((row) => {
    appendTableRow(tbody, [
      row.nhi_record_id,
      `${safeText(row.source_type)}:${safeText(row.source_id)}`,
      row.tenant_id,
      row.environment,
      row.provider_type,
      row.owner_scope_id ? `${safeText(row.owner_scope_type || "scope")}:${safeText(row.owner_scope_id)}` : "--",
      row.credential_age_days ?? "--",
      row.findings || "[]",
      row.status,
    ]);
  });
}

function renderGatewayAccessReviewCampaign(data) {
  const summaryTbody = qs("#gatewayAccessReviewCampaignSummaryTable");
  const itemsTbody = qs("#gatewayAccessReviewItemsTable");
  if (!summaryTbody || !itemsTbody) return;

  if (!data) {
    setTableMessage(summaryTbody, 2, "No campaign loaded.");
    setTableMessage(itemsTbody, 6, "No review items.");
    return;
  }

  const summaryRows = [
    ["Campaign ID", safeText(data.campaign_id)],
    ["Campaign Name", safeText(data.campaign_name)],
    ["Tenant", safeText(data.tenant_id || "--")],
    ["Environment", safeText(data.environment)],
    ["Status", safeText(data.status)],
    ["Reviewer Role", safeText(data.reviewer_role)],
    ["Created By", safeText(data.created_by)],
    ["Total Items", safeText(data.total_items)],
    ["Pending", safeText(data.pending_items)],
    ["Approved", safeText(data.approved_items)],
    ["Revoked", safeText(data.revoked_items)],
  ];
  summaryTbody.textContent = "";
  summaryRows.forEach((row) => appendTableRow(summaryTbody, row));

  gatewayAccessReviewItems = Array.isArray(data.items) ? data.items : [];
  if (!gatewayAccessReviewItems.length) {
    setTableMessage(itemsTbody, 6, "No review items.");
    return;
  }
  itemsTbody.textContent = "";
  gatewayAccessReviewItems.forEach((item) => {
    appendTableRow(itemsTbody, [
      item.review_item_id,
      item.entitlement_id,
      item.decision,
      item.decision_reason || "--",
      item.decided_by || "--",
      formatComplianceDate(item.decided_at),
    ]);
  });
}

function renderGatewayLeastPrivilegeRows() {
  const tbody = qs("#gatewayLeastPrivilegeTable");
  if (!tbody) return;
  if (!gatewayLeastPrivilegeRows.length) {
    setTableMessage(tbody, 9, "No least-privilege recommendations found.");
    return;
  }

  tbody.textContent = "";
  gatewayLeastPrivilegeRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.recommendation_id);
    appendTableCell(tr, row.entitlement_id);
    appendTableCell(tr, row.recommendation_type);
    appendTableCell(tr, Number(row.confidence_score || 0).toFixed(2));
    appendTableCell(tr, row.current_allowed_roles || "[]");
    appendTableCell(tr, row.proposed_allowed_roles || "[]");
    appendTableCell(tr, row.proposed_enabled === null || row.proposed_enabled === undefined ? "--" : String(Boolean(row.proposed_enabled)));
    appendTableCell(tr, row.status);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const applyBtn = document.createElement("button");
    applyBtn.type = "button";
    applyBtn.className = "ghost";
    applyBtn.textContent = "Apply";
    applyBtn.disabled = String(row.status || "") !== "pending";
    applyBtn.addEventListener("click", () => applyGatewayLeastPrivilegeRecommendation(row.recommendation_id));
    actions.append(applyBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderGatewayGovernanceEvidenceSummary(rows) {
  const tbody = qs("#gatewayGovernanceEvidenceTable");
  if (!tbody) return;
  if (!Array.isArray(rows) || !rows.length) {
    setTableMessage(tbody, 4, "No governance evidence events loaded.");
    return;
  }

  tbody.textContent = "";
  rows
    .slice()
    .sort((a, b) => String(a.action_type || "").localeCompare(String(b.action_type || "")))
    .forEach((entry) => {
      appendTableRow(tbody, [
        String(entry.action_type || "unknown"),
        Number(entry.event_count || 0),
        formatComplianceDate(entry.latest_timestamp || ""),
        String(entry.latest_trace_id || "--"),
      ]);
    });
}

function formatGatewayRecordDate(value) {
  if (value === null || value === undefined || value === "") return "--";
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    const millis = numeric < 1e11 ? numeric * 1000 : numeric;
    const date = new Date(millis);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString();
  }
  return formatComplianceDate(value);
}

function parseGatewayJsonInput(raw, fieldLabel) {
  const text = String(raw || "").trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${fieldLabel} must be valid JSON.`);
  }
}

function getGatewayDualApprovalHeaders(formSelector) {
  const form = qs(formSelector);
  if (!form) return {};
  const raw = Object.fromEntries(new FormData(form).entries());
  const role = String(raw.approver_role || "").trim();
  const id = String(raw.approver_id || "").trim();
  if (role && id) {
    return {
      "X-Approver-Role": role,
      "X-Approver-Id": id,
    };
  }
  return {};
}

function getGatewayOpenAiResponseFilterSpec() {
  const form = qs("#gatewayOpenAiResponsesOpsForm");
  if (!form) return { modelContains: "", outputContains: "", riskTier: "" };
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    modelContains: String(raw.model_contains || "").trim().toLowerCase(),
    outputContains: String(raw.output_contains || "").trim().toLowerCase(),
    riskTier: String(raw.risk_tier || "").trim().toLowerCase(),
  };
}

function getGatewayOpenAiFileFilterSpec() {
  const form = qs("#gatewayOpenAiFilesOpsForm");
  if (!form) return { filenameContains: "", purpose: "", status: "" };
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    filenameContains: String(raw.filename_contains || "").trim().toLowerCase(),
    purpose: String(raw.purpose || "").trim().toLowerCase(),
    status: String(raw.status || "").trim().toLowerCase(),
  };
}

function getFilteredGatewayOpenAiResponseRows() {
  const spec = getGatewayOpenAiResponseFilterSpec();
  return gatewayOpenAiResponseRows.filter((row) => {
    const model = String(row.model || "").toLowerCase();
    const output = String(row.output_text || "").toLowerCase();
    const riskTier = String(row.risk_tier || "").toLowerCase();
    if (spec.modelContains && !model.includes(spec.modelContains)) return false;
    if (spec.outputContains && !output.includes(spec.outputContains)) return false;
    if (spec.riskTier && riskTier !== spec.riskTier) return false;
    return true;
  });
}

function getFilteredGatewayOpenAiFileRows() {
  const spec = getGatewayOpenAiFileFilterSpec();
  return gatewayOpenAiFileRows.filter((row) => {
    const filename = String(row.filename || "").toLowerCase();
    const purpose = String(row.purpose || "").toLowerCase();
    const status = String(row.status || "").toLowerCase();
    if (spec.filenameContains && !filename.includes(spec.filenameContains)) return false;
    if (spec.purpose && purpose !== spec.purpose) return false;
    if (spec.status && status !== spec.status) return false;
    return true;
  });
}

function syncGatewayOpenAiResponseSelection() {
  const validIds = new Set(gatewayOpenAiResponseRows.map((row) => String(row.id || "")).filter(Boolean));
  Array.from(selectedGatewayOpenAiResponseIds).forEach((id) => {
    if (!validIds.has(id)) selectedGatewayOpenAiResponseIds.delete(id);
  });
}

function syncGatewayOpenAiFileSelection() {
  const validIds = new Set(gatewayOpenAiFileRows.map((row) => String(row.id || "")).filter(Boolean));
  Array.from(selectedGatewayOpenAiFileIds).forEach((id) => {
    if (!validIds.has(id)) selectedGatewayOpenAiFileIds.delete(id);
  });
}

function updateGatewayOpenAiSelectionSummary() {
  const responseSummary = qs("#gatewayOpenAiResponsesSelection");
  if (responseSummary) {
    responseSummary.textContent = `${selectedGatewayOpenAiResponseIds.size} selected`;
  }
  const fileSummary = qs("#gatewayOpenAiFilesSelection");
  if (fileSummary) {
    fileSummary.textContent = `${selectedGatewayOpenAiFileIds.size} selected`;
  }
}

function renderGatewayOpenAiResponsesRows() {
  const tbody = qs("#gatewayOpenAiResponsesTable");
  if (!tbody) return;
  const rows = getFilteredGatewayOpenAiResponseRows();
  if (!rows.length) {
    setTableMessage(tbody, 8, "No response records found.");
    updateGatewayOpenAiSelectionSummary();
    return;
  }

  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    if (row.id === selectedGatewayOpenAiResponseId) tr.classList.add("selected-row");
    const selectCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedGatewayOpenAiResponseIds.has(String(row.id || ""));
    checkbox.addEventListener("change", () => {
      const id = String(row.id || "");
      if (!id) return;
      if (checkbox.checked) selectedGatewayOpenAiResponseIds.add(id);
      else selectedGatewayOpenAiResponseIds.delete(id);
      updateGatewayOpenAiSelectionSummary();
    });
    selectCell.appendChild(checkbox);
    tr.appendChild(selectCell);
    appendTableCell(tr, row.id || "--");
    appendTableCell(tr, row.model || "--");
    appendTableCell(tr, formatGatewayRecordDate(row.created_at));
    appendTableCell(tr, safeText(String(row.output_text || "").slice(0, 140) || "--"));
    appendTableCell(tr, row.usage?.total_tokens ?? "--");

    const riskCell = document.createElement("td");
    const tier = String(row.risk_tier || "").trim().toLowerCase();
    if (["low", "medium", "high"].includes(tier)) {
      const badge = document.createElement("span");
      badge.className = `risk-badge ${tier}`;
      badge.textContent = tier;
      const reasons = Array.isArray(row.risk_reasons)
        ? row.risk_reasons.map((item) => String(item || "").trim()).filter(Boolean)
        : [];
      if (reasons.length) badge.title = reasons.join(", ");
      riskCell.appendChild(badge);
    } else {
      riskCell.textContent = "--";
    }
    tr.appendChild(riskCell);

    const actions = document.createElement("td");
    actions.className = "cell-actions";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      selectedGatewayOpenAiResponseId = row.id;
      const ops = qs("#gatewayOpenAiResponsesOpsForm");
      if (ops?.elements?.response_id) ops.elements.response_id.value = row.id || "";
      renderGatewayOpenAiResponsesRows();
    });

    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "ghost";
    viewBtn.textContent = "Get";
    viewBtn.addEventListener("click", () => loadGatewayOpenAiResponseById(row.id));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteGatewayOpenAiResponseById(row.id));

    actions.append(useBtn, viewBtn, deleteBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
  updateGatewayOpenAiSelectionSummary();
}

function renderGatewayOpenAiFilesRows() {
  const tbody = qs("#gatewayOpenAiFilesTable");
  if (!tbody) return;
  const rows = getFilteredGatewayOpenAiFileRows();
  if (!rows.length) {
    setTableMessage(tbody, 8, "No file records found.");
    updateGatewayOpenAiSelectionSummary();
    return;
  }

  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    if (row.id === selectedGatewayOpenAiFileId) tr.classList.add("selected-row");
    const selectCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedGatewayOpenAiFileIds.has(String(row.id || ""));
    checkbox.addEventListener("change", () => {
      const id = String(row.id || "");
      if (!id) return;
      if (checkbox.checked) selectedGatewayOpenAiFileIds.add(id);
      else selectedGatewayOpenAiFileIds.delete(id);
      updateGatewayOpenAiSelectionSummary();
    });
    selectCell.appendChild(checkbox);
    tr.appendChild(selectCell);
    appendTableCell(tr, row.id || "--");
    appendTableCell(tr, row.filename || "--");
    appendTableCell(tr, row.purpose || "--");
    appendTableCell(tr, row.bytes ?? "--");
    appendTableCell(tr, row.status || "--");
    appendTableCell(tr, formatGatewayRecordDate(row.created_at));

    const actions = document.createElement("td");
    actions.className = "cell-actions";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      selectedGatewayOpenAiFileId = row.id;
      const ops = qs("#gatewayOpenAiFilesOpsForm");
      if (ops?.elements?.file_id) ops.elements.file_id.value = row.id || "";
      renderGatewayOpenAiFilesRows();
    });

    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "ghost";
    viewBtn.textContent = "Get";
    viewBtn.addEventListener("click", () => loadGatewayOpenAiFileById(row.id));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteGatewayOpenAiFileById(row.id));

    actions.append(useBtn, viewBtn, deleteBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
  updateGatewayOpenAiSelectionSummary();
}

function renderKeyRows() {
  const tbody = qs("#keysTable");
  if (!tbody) return;
  if (!keyRows.length) {
    setTableMessage(tbody, 8, "No keys found.");
    return;
  }
  tbody.textContent = "";
  keyRows.forEach((row) => {
    const tr = document.createElement("tr");
    if (row.key_id === selectedKeyId) {
      tr.classList.add("selected-row");
    }
    appendTableCell(tr, row.key_id);
    appendTableCell(tr, row.owner_scope_type);
    appendTableCell(tr, row.owner_scope_id);
    appendTableCell(tr, row.allowed_endpoint_families);
    appendTableCell(tr, row.allowed_models);
    appendTableCell(tr, summarizeKeyGuardrails(row.guardrail_policy));
    appendTableCell(tr, row.status);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Edit";
    useBtn.addEventListener("click", () => populateKeyForm(row));
    const usageBtn = document.createElement("button");
    usageBtn.type = "button";
    usageBtn.className = "ghost";
    usageBtn.textContent = "Usage";
    usageBtn.addEventListener("click", () => loadKeyUsage(row.key_id));
    const rotateBtn = document.createElement("button");
    rotateBtn.type = "button";
    rotateBtn.className = "ghost";
    rotateBtn.textContent = "Rotate";
    rotateBtn.addEventListener("click", () => rotateKey(row.key_id));
    const toggleStatusBtn = document.createElement("button");
    toggleStatusBtn.type = "button";
    toggleStatusBtn.className = "ghost";
    const shouldUnblock = String(row.status || "").trim().toLowerCase() === "blocked";
    toggleStatusBtn.textContent = shouldUnblock ? "Unblock" : "Block";
    toggleStatusBtn.addEventListener("click", () => setKeyLifecycleStatus(row.key_id, shouldUnblock ? "unblock" : "block"));
    const guardrailBtn = document.createElement("button");
    guardrailBtn.type = "button";
    guardrailBtn.className = "ghost";
    guardrailBtn.textContent = "Guardrails";
    guardrailBtn.addEventListener("click", () => populateKeyGuardrailForm(row.key_id));
    const budgetBtn = document.createElement("button");
    budgetBtn.type = "button";
    budgetBtn.className = "ghost";
    budgetBtn.textContent = "Budget";
    budgetBtn.addEventListener("click", () => populateKeyBudgetIncreaseForm(row.key_id));
    const schedulesBtn = document.createElement("button");
    schedulesBtn.type = "button";
    schedulesBtn.className = "ghost";
    schedulesBtn.textContent = "Schedules";
    schedulesBtn.addEventListener("click", () => {
      populateKeyRotationScheduleForm(row.key_id);
      loadKeyRotationSchedules(null, row.key_id);
    });
    actions.append(useBtn, usageBtn, rotateBtn, toggleStatusBtn, guardrailBtn, budgetBtn, schedulesBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderKeyRotationSchedules() {
  const tbody = qs("#keyRotationSchedulesTable");
  if (!tbody) return;
  if (!keyRotationScheduleRows.length) {
    setTableMessage(tbody, 7, "No rotation schedules found.");
    return;
  }

  tbody.textContent = "";
  keyRotationScheduleRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.schedule_id);
    appendTableCell(tr, row.environment);
    appendTableCell(tr, row.interval_hours);
    appendTableCell(tr, row.enabled ? "true" : "false");
    appendTableCell(tr, row.next_run_at || "--");
    appendTableCell(tr, row.last_run_at || "--");
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const runBtn = document.createElement("button");
    runBtn.type = "button";
    runBtn.className = "ghost";
    runBtn.textContent = "Run";
    runBtn.addEventListener("click", () => executeKeyRotationSchedule(row.schedule_id, row.key_id));
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "ghost";
    toggleBtn.textContent = row.enabled ? "Disable" : "Enable";
    toggleBtn.addEventListener("click", () => updateKeyRotationSchedule(row.schedule_id, row.key_id, { enabled: !row.enabled }));
    actions.append(runBtn, toggleBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function summarizeKeyGuardrails(rawPolicy) {
  try {
    const policy = JSON.parse(String(rawPolicy || "{}"));
    const parts = [];
    if (Array.isArray(policy.allowed_environments) && policy.allowed_environments.length) {
      parts.push(`env:${policy.allowed_environments.join("/")}`);
    }
    if (Number.isInteger(policy.max_requests_per_minute)) {
      parts.push(`rpm<=${policy.max_requests_per_minute}`);
    }
    if (Number.isInteger(policy.max_input_tokens)) {
      parts.push(`in<=${policy.max_input_tokens}`);
    }
    if (Number.isInteger(policy.max_output_tokens)) {
      parts.push(`out<=${policy.max_output_tokens}`);
    }
    if (policy.require_mfa_for_prod === true) {
      parts.push("mfa:prod");
    }
    return parts.length ? parts.join(" | ") : "none";
  } catch {
    return "invalid";
  }
}

function parseEnabledFilter(rawValue) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return null;
}

function populateGatewayEntitlementForm(row) {
  const form = qs("#gatewayEntitlementForm");
  if (!form || !row) return;
  form.elements.entitlement_id.value = row.entitlement_id || "";
  form.elements.action.value = row.action || "";
  form.elements.tenant_id.value = row.tenant_id || "";
  form.elements.environment.value = row.environment || "dev";
  form.elements.route_policy_id.value = row.route_policy_id || "";
  form.elements.request_tag.value = row.request_tag || "";
  form.elements.model_name.value = row.model_name || "";
  form.elements.tool_name.value = row.tool_name || "";
  form.elements.allowed_roles.value = row.allowed_roles || "[]";
  form.elements.enabled.value = String(Boolean(row.enabled));
}

async function loadGatewayEntitlements(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const filterForm = qs("#gatewayEntitlementFiltersForm");
  const result = qs("#gatewayEntitlementResult");
  const tbody = qs("#gatewayEntitlementTable");
  if (!filterForm || !result || !tbody) return;

  const raw = Object.fromEntries(new FormData(filterForm).entries());
  const query = buildQueryString({
    action: String(raw.action || "").trim() || null,
    tenant_id: String(raw.tenant_id || "").trim() || null,
    environment: String(raw.environment || "").trim() || null,
    route_policy_id: String(raw.route_policy_id || "").trim() || null,
    request_tag: String(raw.request_tag || "").trim() || null,
    enabled: parseEnabledFilter(raw.enabled),
    limit: 100,
    offset: 0,
  });

  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api(`/gateway/entitlements${query}`);
    gatewayEntitlementRows = Array.isArray(rows) ? rows : [];
    renderGatewayEntitlementRows();
    result.textContent = gatewayEntitlementRows.length
      ? `Loaded ${gatewayEntitlementRows.length} gateway entitlements.`
      : "No gateway entitlements found.";
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function saveGatewayEntitlement(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayEntitlementForm");
  const result = qs("#gatewayEntitlementResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const entitlementId = String(raw.entitlement_id || "").trim();
  if (!entitlementId) {
    result.textContent = "Entitlement ID is required.";
    return;
  }

  try {
    const data = await api(`/gateway/entitlements/${encodeURIComponent(entitlementId)}`, {
      method: "PUT",
      body: JSON.stringify({
        action: String(raw.action || "").trim(),
        tenant_id: String(raw.tenant_id || "").trim() || null,
        environment: String(raw.environment || "dev").trim(),
        route_policy_id: String(raw.route_policy_id || "").trim() || null,
        request_tag: String(raw.request_tag || "").trim() || null,
        model_name: String(raw.model_name || "").trim() || null,
        tool_name: String(raw.tool_name || "").trim() || null,
        allowed_roles: String(raw.allowed_roles || "[]").trim(),
        enabled: String(raw.enabled || "true") === "true",
      }),
    });
    result.textContent = `Saved gateway entitlement ${data.entitlement_id}.`;
    populateGatewayEntitlementForm(data);
    await loadGatewayEntitlements();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function parseBooleanSelect(rawValue, defaultValue = false) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return defaultValue;
}

function getGatewayNhiFilters() {
  const form = qs("#gatewayNhiFiltersForm");
  if (!form) return null;
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    tenant_id: String(raw.tenant_id || "").trim() || null,
    environment: String(raw.environment || "").trim() || null,
    source_type: String(raw.source_type || "").trim() || null,
    provider_type: String(raw.provider_type || "").trim() || null,
    identity_type: String(raw.identity_type || "").trim() || null,
    status: String(raw.status || "").trim() || null,
    max_credential_age_days: Number(raw.max_credential_age_days || 90),
    stale_only: parseBooleanSelect(raw.stale_only, false),
    missing_owner_only: parseBooleanSelect(raw.missing_owner_only, false),
  };
}

async function loadGatewayNhiInventory(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayNhiResult");
  const tbody = qs("#gatewayNhiInventoryTable");
  if (!result || !tbody) return;
  const filters = getGatewayNhiFilters();
  if (!filters) return;

  const query = buildQueryString({
    tenant_id: filters.tenant_id,
    environment: filters.environment,
    source_type: filters.source_type,
    provider_type: filters.provider_type,
    identity_type: filters.identity_type,
    status: filters.status,
    max_credential_age_days: filters.max_credential_age_days,
    stale_only: filters.stale_only,
    missing_owner_only: filters.missing_owner_only,
    limit: 100,
    offset: 0,
  });

  setTableMessage(tbody, 9, "Loading...");
  try {
    const rows = await api(`/gateway/nhi/inventory${query}`);
    gatewayNhiInventoryRows = Array.isArray(rows) ? rows : [];
    renderGatewayNhiInventoryRows();
    result.textContent = gatewayNhiInventoryRows.length
      ? `Loaded ${gatewayNhiInventoryRows.length} NHI records.`
      : "No NHI records found.";
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 9, `Error: ${safeText(err.message)}`);
  }
}

async function loadGatewayNhiHygiene(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayNhiResult");
  const filters = getGatewayNhiFilters();
  if (!result || !filters) return;

  const query = buildQueryString({
    tenant_id: filters.tenant_id,
    environment: filters.environment,
    max_credential_age_days: filters.max_credential_age_days,
  });

  try {
    gatewayNhiHygieneSummary = await api(`/gateway/nhi/hygiene${query}`);
    renderGatewayNhiHygieneSummary(gatewayNhiHygieneSummary);
    result.textContent = `Loaded NHI hygiene summary: ${safeText(gatewayNhiHygieneSummary.total_identities)} identities, ${safeText(gatewayNhiHygieneSummary.high_risk_identities)} high risk.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    const hygieneTbody = qs("#gatewayNhiHygieneTable");
    if (hygieneTbody) setTableMessage(hygieneTbody, 2, `Error: ${safeText(err.message)}`);
  }
}

async function createGatewayAccessReviewCampaign(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayAccessReviewCampaignForm");
  const result = qs("#gatewayAccessReviewResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/gateway/access-reviews/campaigns", {
      method: "POST",
      body: JSON.stringify({
        campaign_name: String(raw.campaign_name || "").trim(),
        tenant_id: String(raw.tenant_id || "").trim() || null,
        environment: String(raw.environment || "dev").trim(),
        include_disabled: parseBooleanSelect(raw.include_disabled, false),
        reviewer_role: String(raw.reviewer_role || "Security Approver").trim(),
      }),
    });
    gatewayAccessReviewCampaign = data;
    form.elements.campaign_id.value = data.campaign_id;
    renderGatewayAccessReviewCampaign(data);
    result.textContent = `Created campaign ${data.campaign_id} with ${safeText(data.total_items)} review items.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayAccessReviewCampaign(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayAccessReviewCampaignForm");
  const result = qs("#gatewayAccessReviewResult");
  if (!form || !result) return;
  const campaignId = String(form.elements.campaign_id.value || "").trim();
  if (!campaignId) {
    result.textContent = "Campaign ID is required to load a campaign.";
    return;
  }

  try {
    const data = await api(`/gateway/access-reviews/campaigns/${encodeURIComponent(campaignId)}`);
    gatewayAccessReviewCampaign = data;
    renderGatewayAccessReviewCampaign(data);
    result.textContent = `Loaded campaign ${campaignId}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function createGatewayJitRequest(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayJitRequestForm");
  const result = qs("#gatewayJitResult");
  const accessResult = qs("#gatewayAccessReviewResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/gateway/jit-requests", {
      method: "POST",
      body: JSON.stringify({
        entitlement_id: String(raw.entitlement_id || "").trim(),
        environment: String(raw.environment || "dev").trim(),
        justification: String(raw.justification || "").trim(),
        requested_duration_minutes: Number(raw.requested_duration_minutes || 60),
      }),
    });
    const approveForm = qs("#gatewayJitApproveForm");
    if (approveForm?.elements?.request_id) approveForm.elements.request_id.value = data.request_id;
    result.textContent = JSON.stringify(data, null, 2);
    if (accessResult) accessResult.textContent = `Created JIT request ${data.request_id}.`;
  } catch (err) {
    if (accessResult) accessResult.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function approveGatewayJitRequest(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayJitApproveForm");
  const result = qs("#gatewayJitResult");
  const accessResult = qs("#gatewayAccessReviewResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const requestId = String(raw.request_id || "").trim();
  if (!requestId) {
    if (accessResult) accessResult.textContent = "Request ID is required.";
    return;
  }

  try {
    const data = await api(`/gateway/jit-requests/${encodeURIComponent(requestId)}/approve`, {
      method: "POST",
      body: JSON.stringify({
        decision: String(raw.decision || "approve").trim(),
        decision_reason: String(raw.decision_reason || "").trim() || null,
      }),
    });
    result.textContent = JSON.stringify(data, null, 2);
    if (accessResult) accessResult.textContent = `JIT request ${requestId} marked ${safeText(data.status)}.`;
  } catch (err) {
    if (accessResult) accessResult.textContent = `Error: ${safeText(err.message)}`;
  }
}

function getGatewayLeastPrivilegeFilters() {
  const form = qs("#gatewayLeastPrivilegeFiltersForm");
  if (!form) return null;
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    tenant_id: String(raw.tenant_id || "").trim() || null,
    environment: String(raw.environment || "").trim() || null,
    entitlement_id: String(raw.entitlement_id || "").trim() || null,
    recommendation_type: String(raw.recommendation_type || "").trim() || null,
    status: String(raw.status || "").trim() || null,
    decision_reason: String(raw.decision_reason || "").trim() || null,
  };
}

async function loadGatewayLeastPrivilegeRecommendations(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayLeastPrivilegeResult");
  const tbody = qs("#gatewayLeastPrivilegeTable");
  const filters = getGatewayLeastPrivilegeFilters();
  if (!result || !tbody || !filters) return;

  const query = buildQueryString({
    tenant_id: filters.tenant_id,
    environment: filters.environment,
    entitlement_id: filters.entitlement_id,
    recommendation_type: filters.recommendation_type,
    status: filters.status,
    limit: 100,
    offset: 0,
  });

  setTableMessage(tbody, 9, "Loading...");
  try {
    const rows = await api(`/gateway/least-privilege/recommendations${query}`);
    gatewayLeastPrivilegeRows = Array.isArray(rows) ? rows : [];
    renderGatewayLeastPrivilegeRows();
    result.textContent = gatewayLeastPrivilegeRows.length
      ? `Loaded ${gatewayLeastPrivilegeRows.length} recommendations.`
      : "No least-privilege recommendations found.";
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 9, `Error: ${safeText(err.message)}`);
  }
}

async function applyGatewayLeastPrivilegeRecommendation(recommendationId) {
  const result = qs("#gatewayLeastPrivilegeResult");
  const filters = getGatewayLeastPrivilegeFilters();
  if (!result) return;
  const reason = String(filters?.decision_reason || "").trim();
  if (reason.length < 8) {
    result.textContent = "Decision reason must be at least 8 characters before applying a recommendation.";
    return;
  }
  try {
    const data = await api(`/gateway/least-privilege/recommendations/${encodeURIComponent(recommendationId)}/apply`, {
      method: "POST",
      body: JSON.stringify({
        decision_reason: reason,
      }),
    });
    result.textContent = `Applied recommendation ${data.recommendation_id} for entitlement ${data.entitlement_id}.`;
    await Promise.all([loadGatewayLeastPrivilegeRecommendations(), loadGatewayEntitlements()]);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function getGatewayGovernanceEvidenceFilters() {
  const form = qs("#gatewayGovernanceEvidenceForm");
  if (!form) return null;
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    limit: Number(raw.limit || 100),
    decision_outcome: String(raw.decision_outcome || "").trim() || null,
    bundle_label: String(raw.bundle_label || "gateway-governance-evidence").trim() || "gateway-governance-evidence",
  };
}

async function loadGatewayGovernanceEvidence(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayGovernanceEvidenceResult");
  const tbody = qs("#gatewayGovernanceEvidenceTable");
  const filters = getGatewayGovernanceEvidenceFilters();
  if (!result || !tbody || !filters) return;

  setTableMessage(tbody, 4, "Loading...");
  try {
    const data = await api("/gateway/governance/evidence/export", {
      method: "POST",
      body: JSON.stringify({
        decision_outcome: filters.decision_outcome,
        limit_per_action: filters.limit,
        bundle_label: filters.bundle_label,
      }),
    });

    gatewayGovernanceEvidenceRows = (Array.isArray(data?.events) ? data.events : []).sort((a, b) =>
      String(b.timestamp || "").localeCompare(String(a.timestamp || ""))
    );
    gatewayGovernanceEvidenceSummaryRows = Array.isArray(data?.action_summaries) ? data.action_summaries : [];

    renderGatewayGovernanceEvidenceSummary(gatewayGovernanceEvidenceSummaryRows);
    result.textContent = gatewayGovernanceEvidenceRows.length
      ? `Loaded ${gatewayGovernanceEvidenceRows.length} governance evidence events.`
      : "No governance evidence events found for selected filters.";
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 4, `Error: ${safeText(err.message)}`);
  }
}

async function exportGatewayGovernanceEvidence(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayGovernanceEvidenceResult");
  const filters = getGatewayGovernanceEvidenceFilters();
  if (!result || !filters) return;

  let data = null;
  try {
    data = await api("/gateway/governance/evidence/export", {
      method: "POST",
      body: JSON.stringify({
        decision_outcome: filters.decision_outcome,
        limit_per_action: filters.limit,
        bundle_label: filters.bundle_label,
      }),
    });
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    return;
  }

  gatewayGovernanceEvidenceRows = Array.isArray(data?.events) ? data.events : [];
  gatewayGovernanceEvidenceSummaryRows = Array.isArray(data?.action_summaries) ? data.action_summaries : [];
  renderGatewayGovernanceEvidenceSummary(gatewayGovernanceEvidenceSummaryRows);

  if (!gatewayGovernanceEvidenceRows.length) {
    result.textContent = "No events available to export.";
    return;
  }

  const payload = {
    bundle_type: "gateway_governance_evidence",
    export_id: data.export_id,
    export_uri: data.export_uri,
    exported_at: data.exported_at,
    bundle_label: data.bundle_label || filters.bundle_label,
    generated_at: new Date().toISOString(),
    reviewer_context: {
      actor_id: state.actorId,
      actor_role: state.actorRole,
      environment_profile: state.environmentProfile,
      api_base: state.apiBase,
    },
    filter_context: {
      decision_outcome: filters.decision_outcome,
      limit_per_action: filters.limit,
    },
    action_summaries: gatewayGovernanceEvidenceSummaryRows,
    included_action_types: Array.from(new Set(gatewayGovernanceEvidenceRows.map((row) => row.action_type))).sort(),
    event_count: gatewayGovernanceEvidenceRows.length,
    events: gatewayGovernanceEvidenceRows,
  };
  payload.integrity_checksum = weakChecksum(JSON.stringify(payload));

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  const safeLabel = filters.bundle_label.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "gateway-governance-evidence";
  anchor.download = `${safeLabel}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);

  result.textContent = `Exported governance evidence bundle (${payload.event_count} events).`;
}

async function runGatewayOpenAiChatCompletion(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayOpenAiChatForm");
  const result = qs("#gatewayOpenAiChatResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  let messages = null;
  try {
    messages = parseGatewayJsonInput(raw.messages_json, "Messages JSON");
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    return;
  }
  if (!Array.isArray(messages) || !messages.length) {
    result.textContent = "Error: Messages JSON must be a non-empty array.";
    return;
  }

  const stops = parseListInput(raw.stop_csv);
  const payload = {
    model: String(raw.model || "").trim(),
    messages,
    stream: false,
    environment: String(raw.environment || "dev").trim() || "dev",
    tenant_id: String(raw.tenant_id || "").trim() || null,
    request_tag: String(raw.request_tag || "").trim() || null,
    max_tokens: Number(raw.max_tokens || 64),
    response_format: { type: String(raw.response_format_type || "text").trim() || "text" },
    stop: stops.length === 0 ? null : (stops.length === 1 ? stops[0] : stops),
  };

  try {
    const data = await api("/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderGatewayOpenAiRiskSummary(data, "chat.create");
    result.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    renderGatewayOpenAiRiskSummary(null, "chat.create.error");
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderGatewayOpenAiRiskSummary(payload, sourceLabel = "--") {
  const tierEl = qs("#gatewayOpenAiRiskTier");
  const reasonsEl = qs("#gatewayOpenAiRiskReasons");
  const sourceEl = qs("#gatewayOpenAiRiskSource");
  const summaryEl = qs("#gatewayOpenAiRiskSummary");
  if (!tierEl || !reasonsEl || !sourceEl || !summaryEl) return;

  const reset = () => {
    tierEl.className = "status-pill idle";
    tierEl.textContent = "risk: --";
    reasonsEl.textContent = "--";
    sourceEl.textContent = sourceLabel || "--";
    summaryEl.textContent = "No risk metadata found in payload.";
  };

  if (!payload || typeof payload !== "object") {
    reset();
    return;
  }

  const order = { high: 3, medium: 2, low: 1 };
  const riskEntries = [];

  const maybeAdd = (row) => {
    if (!row || typeof row !== "object") return;
    const tier = String(row.risk_tier || "").trim().toLowerCase();
    if (!tier) return;
    const reasons = Array.isArray(row.risk_reasons)
      ? row.risk_reasons.map((item) => String(item || "").trim()).filter(Boolean)
      : [];
    riskEntries.push({ tier, reasons });
  };

  maybeAdd(payload);
  if (Array.isArray(payload.data)) payload.data.forEach(maybeAdd);

  if (!riskEntries.length) {
    reset();
    return;
  }

  let selected = riskEntries[0];
  riskEntries.forEach((entry) => {
    if ((order[entry.tier] || 0) > (order[selected.tier] || 0)) selected = entry;
  });

  const tier = ["low", "medium", "high"].includes(selected.tier) ? selected.tier : "low";
  const uniqueReasons = Array.from(
    new Set(riskEntries.flatMap((entry) => entry.reasons).filter((item) => item.length > 0))
  );

  tierEl.className = `status-pill ${tier}`;
  tierEl.textContent = `risk: ${tier}`;
  reasonsEl.textContent = uniqueReasons.length ? uniqueReasons.join(", ") : "baseline_policy_controls";
  sourceEl.textContent = sourceLabel || "--";
  summaryEl.textContent =
    `Highest tier from payload: ${tier}.` +
    (Array.isArray(payload.data)
      ? ` Aggregated over ${payload.data.length} listed responses.`
      : "");
}

async function createGatewayOpenAiResponse(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayOpenAiResponsesCreateForm");
  const result = qs("#gatewayOpenAiResponsesResult");
  const payloadTarget = qs("#gatewayOpenAiResponsesPayload");
  if (!form || !result || !payloadTarget) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  let tools = null;
  try {
    tools = parseGatewayJsonInput(raw.tools_json, "Tools JSON");
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    return;
  }

  const toolChoice = String(raw.tool_choice || "none").trim() || "none";
  const payload = {
    model: String(raw.model || "").trim(),
    input: String(raw.input || "").trim(),
    instructions: String(raw.instructions || "").trim() || null,
    stream: false,
    environment: String(raw.environment || "dev").trim() || "dev",
    tenant_id: String(raw.tenant_id || "").trim() || null,
    request_tag: String(raw.request_tag || "").trim() || null,
    max_output_tokens: Number(raw.max_output_tokens || 64),
    response_format: { type: String(raw.response_format_type || "text").trim() || "text" },
    tool_choice: toolChoice,
  };
  if (toolChoice !== "none") {
    if (!Array.isArray(tools) || !tools.length) {
      result.textContent = "Error: Tools JSON must be a non-empty array when tool choice is auto or required.";
      return;
    }
    payload.tools = tools;
  }

  try {
    const data = await api("/v1/responses", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderGatewayOpenAiRiskSummary(data, "responses.create");
    selectedGatewayOpenAiResponseId = data.id || "";
    const opsForm = qs("#gatewayOpenAiResponsesOpsForm");
    if (opsForm?.elements?.response_id) opsForm.elements.response_id.value = selectedGatewayOpenAiResponseId;
    result.textContent = `Created response ${safeText(selectedGatewayOpenAiResponseId)}.`;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    await loadGatewayOpenAiResponses();
  } catch (err) {
    renderGatewayOpenAiRiskSummary(null, "responses.create.error");
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayOpenAiResponses(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayOpenAiResponsesOpsForm");
  const result = qs("#gatewayOpenAiResponsesResult");
  const payloadTarget = qs("#gatewayOpenAiResponsesPayload");
  const tbody = qs("#gatewayOpenAiResponsesTable");
  if (!form || !result || !payloadTarget || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());

  setTableMessage(tbody, 7, "Loading...");
  try {
    const query = buildQueryString({
      limit: Number(raw.limit || 20),
      offset: Number(raw.offset || 0),
      model_contains: String(raw.model_contains || "").trim() || null,
      output_contains: String(raw.output_contains || "").trim() || null,
    });
    const data = await api(`/v1/responses${query}`);
    renderGatewayOpenAiRiskSummary(data, "responses.list");
    gatewayOpenAiResponseRows = Array.isArray(data?.data) ? data.data : [];
    syncGatewayOpenAiResponseSelection();
    if (!selectedGatewayOpenAiResponseId && gatewayOpenAiResponseRows.length) {
      selectedGatewayOpenAiResponseId = gatewayOpenAiResponseRows[0].id || "";
      form.elements.response_id.value = selectedGatewayOpenAiResponseId;
    }
    renderGatewayOpenAiResponsesRows();
    result.textContent = `Loaded ${gatewayOpenAiResponseRows.length} response records.`;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    renderGatewayOpenAiRiskSummary(null, "responses.list.error");
    gatewayOpenAiResponseRows = [];
    selectedGatewayOpenAiResponseIds.clear();
    renderGatewayOpenAiResponsesRows();
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayOpenAiResponseById(responseId) {
  const form = qs("#gatewayOpenAiResponsesOpsForm");
  const result = qs("#gatewayOpenAiResponsesResult");
  const payloadTarget = qs("#gatewayOpenAiResponsesPayload");
  if (!form || !result || !payloadTarget) return;

  const id = String(responseId || form.elements.response_id.value || selectedGatewayOpenAiResponseId || "").trim();
  if (!id) {
    result.textContent = "Response ID is required.";
    return;
  }

  try {
    const data = await api(`/v1/responses/${encodeURIComponent(id)}`);
    renderGatewayOpenAiRiskSummary(data, "responses.get");
    selectedGatewayOpenAiResponseId = data.id || id;
    form.elements.response_id.value = selectedGatewayOpenAiResponseId;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    result.textContent = `Loaded response ${safeText(selectedGatewayOpenAiResponseId)}.`;
    renderGatewayOpenAiResponsesRows();
  } catch (err) {
    renderGatewayOpenAiRiskSummary(null, "responses.get.error");
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deleteGatewayOpenAiResponseById(responseId, options = {}) {
  const form = qs("#gatewayOpenAiResponsesOpsForm");
  const result = qs("#gatewayOpenAiResponsesResult");
  const payloadTarget = qs("#gatewayOpenAiResponsesPayload");
  if (!form || !result || !payloadTarget) return;

  const id = String(responseId || form.elements.response_id.value || selectedGatewayOpenAiResponseId || "").trim();
  if (!id) {
    result.textContent = "Response ID is required.";
    return;
  }

  const shouldReload = options.reload !== false;
  const suppressMessage = options.suppressMessage === true;

  try {
    const data = await api(`/v1/responses/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: getGatewayDualApprovalHeaders("#gatewayOpenAiResponsesOpsForm"),
    });
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    if (!suppressMessage) result.textContent = `Deleted response ${safeText(id)}.`;
    selectedGatewayOpenAiResponseIds.delete(id);
    if (selectedGatewayOpenAiResponseId === id) selectedGatewayOpenAiResponseId = "";
    if (shouldReload) await loadGatewayOpenAiResponses();
    return { ok: true, id, data };
  } catch (err) {
    if (!suppressMessage) result.textContent = `Error: ${safeText(err.message)}`;
    return { ok: false, id, error: String(err.message || err) };
  }
}

async function createGatewayOpenAiFile(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayOpenAiFilesCreateForm");
  const result = qs("#gatewayOpenAiFilesResult");
  const payloadTarget = qs("#gatewayOpenAiFilesPayload");
  if (!form || !result || !payloadTarget) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  let metadata = null;
  try {
    metadata = parseGatewayJsonInput(raw.metadata_json, "Metadata JSON");
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    return;
  }

  const payload = {
    filename: String(raw.filename || "").trim(),
    purpose: String(raw.purpose || "assistants").trim() || "assistants",
    bytes: Number(raw.bytes || 1),
    content_type: String(raw.content_type || "application/octet-stream").trim() || "application/octet-stream",
    metadata: metadata && typeof metadata === "object" ? metadata : {},
    environment: String(raw.environment || "dev").trim() || "dev",
  };

  try {
    const data = await api("/v1/files", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    selectedGatewayOpenAiFileId = data.id || "";
    const opsForm = qs("#gatewayOpenAiFilesOpsForm");
    if (opsForm?.elements?.file_id) opsForm.elements.file_id.value = selectedGatewayOpenAiFileId;
    result.textContent = `Created file record ${safeText(selectedGatewayOpenAiFileId)}.`;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    await loadGatewayOpenAiFiles();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayOpenAiFiles(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayOpenAiFilesOpsForm");
  const result = qs("#gatewayOpenAiFilesResult");
  const payloadTarget = qs("#gatewayOpenAiFilesPayload");
  const tbody = qs("#gatewayOpenAiFilesTable");
  if (!form || !result || !payloadTarget || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());

  setTableMessage(tbody, 8, "Loading...");
  try {
    const query = buildQueryString({
      limit: Number(raw.limit || 20),
      offset: Number(raw.offset || 0),
      filename_contains: String(raw.filename_contains || "").trim() || null,
      purpose: String(raw.purpose || "").trim() || null,
      status: String(raw.status || "").trim() || null,
    });
    const data = await api(`/v1/files${query}`);
    gatewayOpenAiFileRows = Array.isArray(data?.data) ? data.data : [];
    syncGatewayOpenAiFileSelection();
    if (!selectedGatewayOpenAiFileId && gatewayOpenAiFileRows.length) {
      selectedGatewayOpenAiFileId = gatewayOpenAiFileRows[0].id || "";
      form.elements.file_id.value = selectedGatewayOpenAiFileId;
    }
    renderGatewayOpenAiFilesRows();
    result.textContent = `Loaded ${gatewayOpenAiFileRows.length} file records.`;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    gatewayOpenAiFileRows = [];
    selectedGatewayOpenAiFileIds.clear();
    renderGatewayOpenAiFilesRows();
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayOpenAiFileById(fileId) {
  const form = qs("#gatewayOpenAiFilesOpsForm");
  const result = qs("#gatewayOpenAiFilesResult");
  const payloadTarget = qs("#gatewayOpenAiFilesPayload");
  if (!form || !result || !payloadTarget) return;

  const id = String(fileId || form.elements.file_id.value || selectedGatewayOpenAiFileId || "").trim();
  if (!id) {
    result.textContent = "File ID is required.";
    return;
  }

  try {
    const data = await api(`/v1/files/${encodeURIComponent(id)}`);
    selectedGatewayOpenAiFileId = data.id || id;
    form.elements.file_id.value = selectedGatewayOpenAiFileId;
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    result.textContent = `Loaded file ${safeText(selectedGatewayOpenAiFileId)}.`;
    renderGatewayOpenAiFilesRows();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deleteGatewayOpenAiFileById(fileId, options = {}) {
  const form = qs("#gatewayOpenAiFilesOpsForm");
  const result = qs("#gatewayOpenAiFilesResult");
  const payloadTarget = qs("#gatewayOpenAiFilesPayload");
  if (!form || !result || !payloadTarget) return;

  const id = String(fileId || form.elements.file_id.value || selectedGatewayOpenAiFileId || "").trim();
  if (!id) {
    result.textContent = "File ID is required.";
    return;
  }

  const shouldReload = options.reload !== false;
  const suppressMessage = options.suppressMessage === true;

  try {
    const data = await api(`/v1/files/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: getGatewayDualApprovalHeaders("#gatewayOpenAiFilesOpsForm"),
    });
    payloadTarget.textContent = JSON.stringify(data, null, 2);
    if (!suppressMessage) result.textContent = `Deleted file ${safeText(id)}.`;
    selectedGatewayOpenAiFileIds.delete(id);
    if (selectedGatewayOpenAiFileId === id) selectedGatewayOpenAiFileId = "";
    if (shouldReload) await loadGatewayOpenAiFiles();
    return { ok: true, id, data };
  } catch (err) {
    if (!suppressMessage) result.textContent = `Error: ${safeText(err.message)}`;
    return { ok: false, id, error: String(err.message || err) };
  }
}

function selectAllGatewayOpenAiResponses() {
  getFilteredGatewayOpenAiResponseRows().forEach((row) => {
    const id = String(row.id || "");
    if (id) selectedGatewayOpenAiResponseIds.add(id);
  });
  renderGatewayOpenAiResponsesRows();
}

function clearGatewayOpenAiResponsesSelection() {
  selectedGatewayOpenAiResponseIds.clear();
  renderGatewayOpenAiResponsesRows();
}

async function bulkDeleteGatewayOpenAiResponses() {
  const result = qs("#gatewayOpenAiResponsesResult");
  const ids = Array.from(selectedGatewayOpenAiResponseIds);
  if (!result) return;
  if (!ids.length) {
    result.textContent = "Select at least one response record for bulk delete.";
    return;
  }

  let success = 0;
  const failures = [];
  for (const id of ids) {
    const outcome = await deleteGatewayOpenAiResponseById(id, { reload: false, suppressMessage: true });
    if (outcome.ok) success += 1;
    else failures.push(`${id}: ${outcome.error}`);
  }

  await loadGatewayOpenAiResponses();
  result.textContent = failures.length
    ? `Bulk delete completed: ${success} deleted, ${failures.length} failed. ${failures.join(" | ")}`
    : `Bulk delete completed: ${success} deleted.`;
}

function exportFilteredGatewayOpenAiResponses() {
  const result = qs("#gatewayOpenAiResponsesResult");
  if (!result) return;

  const rows = getFilteredGatewayOpenAiResponseRows();
  if (!rows.length) {
    result.textContent = "No filtered response records available to export.";
    return;
  }

  const filterSpec = getGatewayOpenAiResponseFilterSpec();
  const payload = {
    exported_at: new Date().toISOString(),
    export_scope: "gateway_openai_responses_filtered",
    filter_spec: filterSpec,
    selected_count: selectedGatewayOpenAiResponseIds.size,
    exported_count: rows.length,
    risk_counts: rows.reduce(
      (acc, row) => {
        const tier = String(row.risk_tier || "").trim().toLowerCase();
        if (tier === "high" || tier === "medium" || tier === "low") {
          acc[tier] = (acc[tier] || 0) + 1;
        } else {
          acc.unknown = (acc.unknown || 0) + 1;
        }
        return acc;
      },
      { high: 0, medium: 0, low: 0, unknown: 0 }
    ),
    records: rows,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `gateway-openai-responses-risk-export-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  result.textContent = `Exported ${rows.length} filtered response records with risk metadata.`;
}

function exportSelectedGatewayOpenAiResponses() {
  const result = qs("#gatewayOpenAiResponsesResult");
  if (!result) return;

  const selectedIds = new Set(Array.from(selectedGatewayOpenAiResponseIds));
  const rows = gatewayOpenAiResponseRows.filter((row) => selectedIds.has(String(row.id || "")));
  if (!rows.length) {
    result.textContent = "No selected response records available to export.";
    return;
  }

  const filterSpec = getGatewayOpenAiResponseFilterSpec();
  const payload = {
    exported_at: new Date().toISOString(),
    export_scope: "gateway_openai_responses_selected",
    filter_spec: filterSpec,
    selected_ids: Array.from(selectedIds),
    exported_count: rows.length,
    risk_counts: rows.reduce(
      (acc, row) => {
        const tier = String(row.risk_tier || "").trim().toLowerCase();
        if (tier === "high" || tier === "medium" || tier === "low") {
          acc[tier] = (acc[tier] || 0) + 1;
        } else {
          acc.unknown = (acc.unknown || 0) + 1;
        }
        return acc;
      },
      { high: 0, medium: 0, low: 0, unknown: 0 }
    ),
    records: rows,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `gateway-openai-responses-selected-export-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  result.textContent = `Exported ${rows.length} selected response records with risk metadata.`;
}

function selectAllGatewayOpenAiFiles() {
  getFilteredGatewayOpenAiFileRows().forEach((row) => {
    const id = String(row.id || "");
    if (id) selectedGatewayOpenAiFileIds.add(id);
  });
  renderGatewayOpenAiFilesRows();
}

function clearGatewayOpenAiFilesSelection() {
  selectedGatewayOpenAiFileIds.clear();
  renderGatewayOpenAiFilesRows();
}

async function bulkDeleteGatewayOpenAiFiles() {
  const result = qs("#gatewayOpenAiFilesResult");
  const ids = Array.from(selectedGatewayOpenAiFileIds);
  if (!result) return;
  if (!ids.length) {
    result.textContent = "Select at least one file record for bulk delete.";
    return;
  }

  let success = 0;
  const failures = [];
  for (const id of ids) {
    const outcome = await deleteGatewayOpenAiFileById(id, { reload: false, suppressMessage: true });
    if (outcome.ok) success += 1;
    else failures.push(`${id}: ${outcome.error}`);
  }

  await loadGatewayOpenAiFiles();
  result.textContent = failures.length
    ? `Bulk delete completed: ${success} deleted, ${failures.length} failed. ${failures.join(" | ")}`
    : `Bulk delete completed: ${success} deleted.`;
}

function renderKeyGuardrailPolicySummary(rawPolicy) {
  const target = qs("#keyGuardrailPolicySummary");
  if (!target) return;
  try {
    const policy = JSON.parse(String(rawPolicy || "{}"));
    const summaries = [];
    if (Array.isArray(policy.allowed_environments) && policy.allowed_environments.length) {
      summaries.push(`environments: ${policy.allowed_environments.join(", ")}`);
    }
    if (Number.isInteger(policy.max_requests_per_minute)) {
      summaries.push(`rpm cap: ${policy.max_requests_per_minute}`);
    }
    if (Number.isInteger(policy.max_input_tokens)) {
      summaries.push(`input cap: ${policy.max_input_tokens}`);
    }
    if (Number.isInteger(policy.max_output_tokens)) {
      summaries.push(`output cap: ${policy.max_output_tokens}`);
    }
    if (policy.require_mfa_for_prod === true) {
      summaries.push("prod requires MFA");
    }
    if (Array.isArray(policy.blocked_owner_scope_ids) && policy.blocked_owner_scope_ids.length) {
      summaries.push(`blocked scopes: ${policy.blocked_owner_scope_ids.join(", ")}`);
    }
    if (policy.deny_on_weekends === true) {
      summaries.push("weekend traffic denied");
    }
    target.textContent = summaries.length ? `Guardrail summary: ${summaries.join(" | ")}` : "Guardrail summary: no active rules.";
  } catch {
    target.textContent = "Guardrail summary: invalid JSON policy.";
  }
}

function applyGuardrailTemplate(templateName) {
  const form = qs("#keyLifecycleForm");
  const result = qs("#keyLifecycleResult");
  if (!form) return;

  const templates = {
    balanced: {
      allowed_environments: ["dev", "stage"],
      max_requests_per_minute: 120,
      max_input_tokens: 8000,
      max_output_tokens: 4000,
    },
    strict_prod: {
      allowed_environments: ["prod"],
      max_requests_per_minute: 60,
      max_input_tokens: 6000,
      max_output_tokens: 3000,
      require_mfa_for_prod: true,
      deny_on_weekends: true,
    },
    dev_sandbox: {
      allowed_environments: ["dev"],
      max_requests_per_minute: 30,
      max_input_tokens: 2000,
      max_output_tokens: 1000,
      blocked_owner_scope_ids: ["prod-core"],
    },
  };

  const policy = templates[templateName];
  if (!policy) return;
  form.elements.guardrail_policy.value = JSON.stringify(policy, null, 2);
  renderKeyGuardrailPolicySummary(form.elements.guardrail_policy.value);
  if (result) result.textContent = `Applied ${templateName.replace("_", " ")} guardrail template.`;
}

function populateKeyForm(row) {
  const form = qs("#keyLifecycleForm");
  const result = qs("#keyLifecycleResult");
  if (!form || !row) return;
  selectedKeyId = row.key_id;
  form.elements.key_id.value = row.key_id || "";
  form.elements.owner_scope_type.value = row.owner_scope_type || "";
  form.elements.owner_scope_id.value = row.owner_scope_id || "";
  form.elements.allowed_endpoint_families.value = row.allowed_endpoint_families || "[]";
  form.elements.allowed_models.value = row.allowed_models || "[]";
  form.elements.guardrail_policy.value = row.guardrail_policy || "{}";
  renderKeyGuardrailPolicySummary(form.elements.guardrail_policy.value);
  form.elements.status.value = row.status || "active";
  syncScopeIdPicker("#keyLifecycleForm", "owner_scope_type", "owner_scope_id", "keyOwnerScopeIdList");
  if (result) result.textContent = `Loaded key ${row.key_id} into the editor.`;
}

function populateKeyGuardrailForm(keyId) {
  const form = qs("#keyGuardrailEvalForm");
  if (!form) return;
  form.elements.key_id.value = keyId || "";
  selectedKeyId = keyId || selectedKeyId;
  populateKeyBudgetIncreaseForm(keyId);
  populateKeyRotationScheduleForm(keyId);
}

function populateKeyBudgetIncreaseForm(keyId) {
  const form = qs("#keyBudgetIncreaseForm");
  if (!form) return;
  const resolved = String(keyId || selectedKeyId || qs("#keyLifecycleForm")?.elements?.key_id?.value || "").trim();
  form.elements.key_id.value = resolved;
}

function populateKeyRotationScheduleForm(keyId) {
  const form = qs("#keyRotationScheduleForm");
  if (!form) return;
  const resolved = String(keyId || selectedKeyId || qs("#keyLifecycleForm")?.elements?.key_id?.value || "").trim();
  form.elements.key_id.value = resolved;
}

async function loadKeys(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const tbody = qs("#keysTable");
  if (!tbody) return;
  setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api("/keys?limit=50&offset=0");
    keyRows = Array.isArray(rows) ? rows : [];
    selectedKeyId = keyRows[0]?.key_id || selectedKeyId;
    renderKeyRows();
    if (selectedKeyId) {
      populateKeyBudgetIncreaseForm(selectedKeyId);
      populateKeyRotationScheduleForm(selectedKeyId);
    }
    setKeyFeedback("#keyLifecycleResult", keyRows.length ? `Loaded ${keyRows.length} keys.` : "No keys found.", "success");
  } catch (err) {
    setKeyFeedback("#keyLifecycleResult", `Error: ${safeText(err.message)}`, "error");
    setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function saveKey(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const raw = Object.fromEntries(new FormData(form).entries());
  const keyId = String(raw.key_id || "").trim();
  const payload = {
    owner_scope_type: String(raw.owner_scope_type || "").trim().toLowerCase(),
    owner_scope_id: String(raw.owner_scope_id || "").trim(),
    allowed_endpoint_families: String(raw.allowed_endpoint_families || "[]").trim(),
    allowed_models: String(raw.allowed_models || "[]").trim(),
    guardrail_policy: String(raw.guardrail_policy || "{}").trim(),
  };
  try {
    const parsedPolicy = JSON.parse(payload.guardrail_policy || "{}");
    if (!parsedPolicy || typeof parsedPolicy !== "object" || Array.isArray(parsedPolicy)) {
      throw new Error("Guardrail policy must be a JSON object.");
    }
    payload.guardrail_policy = JSON.stringify(parsedPolicy);
    renderKeyGuardrailPolicySummary(payload.guardrail_policy);
  } catch (err) {
    setKeyFeedback("#keyLifecycleResult", `Error: ${safeText(err.message || "Invalid guardrail policy JSON.")}`, "error");
    return;
  }
  try {
    let data;
    if (keyId) {
      data = await api(`/keys/${encodeURIComponent(keyId)}`, {
        method: "PATCH",
        body: JSON.stringify({
          allowed_endpoint_families: payload.allowed_endpoint_families,
          allowed_models: payload.allowed_models,
          guardrail_policy: payload.guardrail_policy,
          status: String(raw.status || "active").trim(),
        }),
      });
      setKeyFeedback("#keyLifecycleResult", `Updated key ${data.key_id}.`, "success");
    } else {
      data = await api("/keys", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setKeyFeedback("#keyLifecycleResult", `Created key ${data.key_id}.`, "success");
    }
    selectedKeyId = data.key_id;
    await loadKeys();
    populateKeyForm(data);
  } catch (err) {
    setKeyFeedback("#keyLifecycleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function evaluateKeyGuardrails(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#keyGuardrailEvalResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const keyId = String(raw.key_id || selectedKeyId || qs("#keyLifecycleForm")?.elements?.key_id?.value || "").trim();
  if (!keyId) {
    if (result) result.textContent = "Select a key first.";
    return;
  }

  const payload = {
    environment: String(raw.environment || "dev").trim().toLowerCase(),
    requests_last_minute: Number.parseInt(String(raw.requests_last_minute || "0"), 10) || 0,
    input_tokens: Number.parseInt(String(raw.input_tokens || "0"), 10) || 0,
    output_tokens: Number.parseInt(String(raw.output_tokens || "0"), 10) || 0,
    owner_scope_id: String(raw.owner_scope_id || "").trim() || null,
    mfa_verified: String(raw.mfa_verified || "false").trim().toLowerCase() === "true",
  };

  try {
    const data = await api(`/keys/${encodeURIComponent(keyId)}/guardrails/evaluate`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const reasons = Array.isArray(data.reasons) && data.reasons.length ? data.reasons.join("; ") : "none";
    const applied = Array.isArray(data.applied_guardrails) && data.applied_guardrails.length ? data.applied_guardrails.join(", ") : "none";
    if (result) {
      result.classList.remove("feedback-success", "feedback-error");
      result.classList.add(data.decision === "allow" ? "feedback-success" : "feedback-error");
      result.textContent = `Guardrail decision for ${data.key_id}: ${data.decision}. Applied: ${applied}. Reasons: ${reasons}.`;
    }
  } catch (err) {
    if (result) {
      result.classList.remove("feedback-success");
      result.classList.add("feedback-error");
      result.textContent = `Error: ${safeText(err.message)}`;
    }
  }
}

async function rotateKey(keyId) {
  const form = qs("#keyLifecycleForm");
  const trimmedKeyId = String(keyId || form?.elements.key_id?.value || selectedKeyId || "").trim();
  if (!trimmedKeyId) {
    setKeyFeedback("#keyLifecycleResult", "Select a key first.", "error");
    return;
  }
  const environment = String(form?.elements.rotate_environment?.value || "dev").trim();
  try {
    const data = await api(`/keys/${encodeURIComponent(trimmedKeyId)}/rotate?environment=${encodeURIComponent(environment)}`, {
      method: "POST",
    });
    setKeyFeedback("#keyLifecycleResult", `Rotated ${data.key_id} in ${environment}.`, "success");
    await loadKeys();
  } catch (err) {
    setKeyFeedback("#keyLifecycleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function setKeyLifecycleStatus(keyId, action) {
  const trimmedKeyId = String(keyId || selectedKeyId || qs("#keyLifecycleForm")?.elements.key_id?.value || "").trim();
  const normalizedAction = String(action || "").trim().toLowerCase();
  if (!trimmedKeyId) {
    setKeyFeedback("#keyLifecycleResult", "Select a key first.", "error");
    return;
  }
  if (!["block", "unblock"].includes(normalizedAction)) {
    setKeyFeedback("#keyLifecycleResult", "Unsupported key lifecycle action.", "error");
    return;
  }
  try {
    const data = await api(`/keys/${encodeURIComponent(trimmedKeyId)}/${normalizedAction}`, {
      method: "POST",
    });
    setKeyFeedback("#keyLifecycleResult", `${safeText(data.action)} key ${safeText(data.key_id)}.`, "success");
    await loadKeys();
  } catch (err) {
    setKeyFeedback("#keyLifecycleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function loadKeyUsage(keyId) {
  const trimmedKeyId = String(keyId || selectedKeyId || qs("#keyLifecycleForm")?.elements.key_id?.value || "").trim();
  if (!trimmedKeyId) {
    setKeyFeedback("#keyUsageResult", "Select a key first.", "error");
    return;
  }
  try {
    const data = await api(`/keys/${encodeURIComponent(trimmedKeyId)}/usage`);
    selectedKeyId = trimmedKeyId;
    setKeyFeedback("#keyUsageResult", `Usage for ${data.key_id}: ${data.requests_last_24h} requests in the last 24h, status ${data.status}.`, "success");
  } catch (err) {
    setKeyFeedback("#keyUsageResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function applyTemporaryKeyBudgetIncrease(evt) {
  evt.preventDefault();
  const form = evt?.currentTarget?.tagName === "FORM" ? evt.currentTarget : (evt?.target?.tagName === "FORM" ? evt.target : null);
  if (!form) {
    setKeyFeedback("#keyBudgetIncreaseResult", "Form context unavailable.", "error");
    return;
  }
  const raw = Object.fromEntries(new FormData(form).entries());
  const keyId = String(raw.key_id || selectedKeyId || "").trim();
  if (!keyId) {
    setKeyFeedback("#keyBudgetIncreaseResult", "Select a key first.", "error");
    return;
  }

  try {
    const data = await api(`/keys/${encodeURIComponent(keyId)}/budget/increase-temporary`, {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "dev").trim(),
        increase_cents: Number(raw.increase_cents || 0),
        duration_minutes: Number(raw.duration_minutes || 0),
        reason: String(raw.reason || "operator-request").trim(),
      }),
    });
    setKeyFeedback(
      "#keyBudgetIncreaseResult",
      `Applied temporary increase +${safeText(data.increase_cents)} cents for ${safeText(data.duration_minutes)} minutes (active=${safeText(data.active)}).`,
      "success",
    );
  } catch (err) {
    setKeyFeedback("#keyBudgetIncreaseResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function loadKeyRotationSchedules(evt, keyIdArg) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#keyRotationScheduleForm");
  const keyId = String(keyIdArg || form?.elements?.key_id?.value || selectedKeyId || "").trim();
  if (!keyId) {
    setKeyFeedback("#keyRotationScheduleResult", "Select a key first.", "error");
    return;
  }
  const tbody = qs("#keyRotationSchedulesTable");
  if (tbody) setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api(`/keys/${encodeURIComponent(keyId)}/rotation-schedules`);
    keyRotationScheduleRows = Array.isArray(rows) ? rows : [];
    renderKeyRotationSchedules();
    setKeyFeedback("#keyRotationScheduleResult", `Loaded ${keyRotationScheduleRows.length} rotation schedules.`, "success");
  } catch (err) {
    setKeyFeedback("#keyRotationScheduleResult", `Error: ${safeText(err.message)}`, "error");
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function saveKeyRotationSchedule(evt) {
  evt.preventDefault();
  const form = evt?.currentTarget?.tagName === "FORM" ? evt.currentTarget : (evt?.target?.tagName === "FORM" ? evt.target : null);
  if (!form) {
    setKeyFeedback("#keyRotationScheduleResult", "Form context unavailable.", "error");
    return;
  }
  const raw = Object.fromEntries(new FormData(form).entries());
  const keyId = String(raw.key_id || selectedKeyId || "").trim();
  if (!keyId) {
    setKeyFeedback("#keyRotationScheduleResult", "Select a key first.", "error");
    return;
  }

  try {
    const data = await api(`/keys/${encodeURIComponent(keyId)}/rotation-schedules`, {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "dev").trim(),
        interval_hours: Number(raw.interval_hours || 24),
        enabled: String(raw.enabled || "true") === "true",
        reason: String(raw.reason || "scheduled-rotation").trim(),
      }),
    });
    setKeyFeedback("#keyRotationScheduleResult", `Saved schedule ${safeText(data.schedule_id)} for ${safeText(data.environment)}.`, "success");
    await loadKeyRotationSchedules(null, keyId);
  } catch (err) {
    setKeyFeedback("#keyRotationScheduleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function updateKeyRotationSchedule(scheduleId, keyId, changes) {
  const trimmedScheduleId = String(scheduleId || "").trim();
  const trimmedKeyId = String(keyId || selectedKeyId || "").trim();
  if (!trimmedScheduleId || !trimmedKeyId) {
    setKeyFeedback("#keyRotationScheduleResult", "Schedule or key context missing.", "error");
    return;
  }
  try {
    await api(`/keys/${encodeURIComponent(trimmedKeyId)}/rotation-schedules/${encodeURIComponent(trimmedScheduleId)}`, {
      method: "PATCH",
      body: JSON.stringify(changes || {}),
    });
    await loadKeyRotationSchedules(null, trimmedKeyId);
  } catch (err) {
    setKeyFeedback("#keyRotationScheduleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

async function executeKeyRotationSchedule(scheduleId, keyId) {
  const trimmedScheduleId = String(scheduleId || "").trim();
  const trimmedKeyId = String(keyId || selectedKeyId || "").trim();
  if (!trimmedScheduleId || !trimmedKeyId) {
    setKeyFeedback("#keyRotationScheduleResult", "Schedule or key context missing.", "error");
    return;
  }
  try {
    const data = await api(
      `/keys/${encodeURIComponent(trimmedKeyId)}/rotation-schedules/${encodeURIComponent(trimmedScheduleId)}/execute-now`,
      { method: "POST" },
    );
    setKeyFeedback(
      "#keyRotationScheduleResult",
      `Executed schedule ${safeText(data.schedule_id)}: ${safeText(data.rotation_status)} (next ${safeText(data.next_run_at)}).`,
      "success",
    );
    await loadKeyRotationSchedules(null, trimmedKeyId);
    await loadKeys();
  } catch (err) {
    setKeyFeedback("#keyRotationScheduleResult", `Error: ${safeText(err.message)}`, "error");
  }
}

function renderRouteDraftRows() {
  const tbody = qs("#routeDraftsTable");
  if (!tbody) return;
  if (!routeDraftRows.length) {
    setTableMessage(tbody, 7, "No route drafts found.");
    return;
  }
  tbody.textContent = "";
  routeDraftRows.forEach((row) => {
    const tr = document.createElement("tr");
    if (row.draft_id === selectedRouteDraftId) {
      tr.classList.add("selected-row");
    }
    appendTableCell(tr, row.draft_id);
    appendTableCell(tr, row.agent_id);
    appendTableCell(tr, row.environment);
    appendTableCell(tr, row.status);
    appendTableCell(tr, row.approved_security ? "yes" : "no");
    appendTableCell(tr, row.approved_ai_ops ? "yes" : "no");
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => populateRouteDraftActionForm(row));
    actions.appendChild(useBtn);
    const historyBtn = document.createElement("button");
    historyBtn.type = "button";
    historyBtn.className = "ghost";
    historyBtn.textContent = "History";
    historyBtn.addEventListener("click", () => loadRouteDraftHistory(row.draft_id));
    actions.appendChild(historyBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderRouteDraftHistoryRows() {
  const tbody = qs("#routeDraftHistoryTable");
  if (!tbody) return;
  if (!routeDraftHistoryRows.length) {
    setTableMessage(tbody, 7, "No approval history loaded.");
    return;
  }
  tbody.textContent = "";
  routeDraftHistoryRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.occurred_at || row.created_at);
    appendTableCell(tr, row.action);
    appendTableCell(tr, row.state_from);
    appendTableCell(tr, row.state_to);
    appendTableCell(tr, row.actor_id);
    appendTableCell(tr, row.decision);
    appendTableCell(tr, row.reason_code || "");
    tbody.appendChild(tr);
  });
}

async function loadRouteDrafts(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeDraftFilters");
  const result = qs("#routeDraftsResult");
  const tbody = qs("#routeDraftsTable");
  if (!form || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const draftId = String(raw.draft_id || "").trim();
  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api(`/route-drafts${buildQueryString({ limit: raw.limit, offset: raw.offset })}`);
    routeDraftRows = Array.isArray(rows) ? rows : [];
    if (draftId) {
      routeDraftRows = routeDraftRows.filter((row) => row.draft_id.includes(draftId));
    }
    selectedRouteDraftId = routeDraftRows[0]?.draft_id || "";
    renderRouteDraftRows();
    if (routeDraftRows.length) {
      await loadRouteDraftHistory(selectedRouteDraftId);
      if (result) result.textContent = `Loaded ${routeDraftRows.length} route drafts.`;
    } else {
      routeDraftHistoryRows = [];
      renderRouteDraftHistoryRows();
      if (result) result.textContent = "No route drafts found.";
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadRouteDraftHistory(draftId) {
  const result = qs("#routeDraftsResult");
  const tbody = qs("#routeDraftHistoryTable");
  const trimmedDraftId = String(draftId || selectedRouteDraftId || qs("#routeDraftFilters")?.elements.draft_id?.value || "").trim();
  if (!trimmedDraftId) {
    if (result) result.textContent = "Select a route draft first.";
    return;
  }
  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api(`/route-drafts/${encodeURIComponent(trimmedDraftId)}/approval-history`);
    routeDraftHistoryRows = Array.isArray(rows) ? rows : [];
    selectedRouteDraftId = trimmedDraftId;
    renderRouteDraftRows();
    renderRouteDraftHistoryRows();
    if (result) {
      result.textContent = routeDraftHistoryRows.length
        ? `Loaded ${routeDraftHistoryRows.length} history events for ${trimmedDraftId}.`
        : `No approval history found for ${trimmedDraftId}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

function populateRouteDraftActionForm(row) {
  const form = qs("#routeDraftActionForm");
  if (!form || !row) return;
  form.elements.draft_id.value = row.draft_id || "";
  form.elements.agent_id.value = row.agent_id || "";
  form.elements.environment.value = row.environment || "dev";
  form.elements.expected_state_version.value = String(row.state_version || 1);
}

function parseRouteDraftEvidenceRefs(raw) {
  const parsed = parseJsonOrFallback(raw, []);
  return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [];
}

async function runRouteDraftAction(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#routeDraftsResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const draftId = String(raw.draft_id || "").trim();
  const action = String(raw.action || "").trim();
  if (!draftId || !action) {
    if (result) result.textContent = "Draft ID and action are required.";
    return;
  }

  const payload = {};
  if (action === "submit") {
    payload.agent_id = String(raw.agent_id || "").trim();
    payload.route_policy_snapshot_id = String(raw.route_policy_snapshot_id || "snapshot-default").trim();
    payload.environment = String(raw.environment || "dev").trim();
  } else if (action === "approve") {
    payload.reason_code = String(raw.reason_code || "").trim() || null;
    payload.evidence_refs = parseRouteDraftEvidenceRefs(raw.evidence_refs);
    payload.risk_ticket_ref = String(raw.risk_ticket_ref || "").trim() || null;
  } else if (action === "reject") {
    payload.reason_code = String(raw.reason_code || "").trim();
  } else if (action === "approve-change-window") {
    payload.reason_code = String(raw.reason_code || "").trim() || null;
    payload.change_window_id = String(raw.change_window_id || "").trim() || null;
    payload.evidence_refs = parseRouteDraftEvidenceRefs(raw.evidence_refs);
    payload.risk_ticket_ref = String(raw.risk_ticket_ref || "").trim() || null;
  } else if (action === "promote") {
    payload.target_environment = String(raw.target_environment || "prod").trim();
    payload.expected_state_version = Number(raw.expected_state_version || 1);
  } else if (action === "rollback-to-draft") {
    payload.reason_code = String(raw.reason_code || "").trim();
  } else if (action === "rollback-last-good") {
    payload.reason_code = String(raw.reason_code || "").trim();
    payload.expected_state_version = Number(raw.expected_state_version || 1);
  }

  try {
    const data = await api(`/route-drafts/${encodeURIComponent(draftId)}/${encodeURIComponent(action)}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (result) result.textContent = `Route draft ${safeText(draftId)} ${safeText(action)} completed: ${safeText(data.status || "ok")}.`;
    selectedRouteDraftId = draftId;
    await loadRouteDrafts();
    await loadRouteDraftHistory(draftId);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function populateRoutingForms(row) {
  const routePolicyForm = qs("#routePolicyForm");
  const routePriorityForm = qs("#routePriorityForm");
  const routeProviderHealthForm = qs("#routeProviderHealthForm");
  const routePreCallFiltersForm = qs("#routePreCallFiltersForm");
  const routeTrafficMirroringForm = qs("#routeTrafficMirroringForm");
  const routeTrafficMirroringAnalyticsForm = qs("#routeTrafficMirroringAnalyticsForm");
  const gatewayEntitlementFiltersForm = qs("#gatewayEntitlementFiltersForm");
  const gatewayEntitlementForm = qs("#gatewayEntitlementForm");
  const routeFallbackForm = qs("#routeFallbackForm");
  const routeOptimizeForm = qs("#routeOptimizeForm");
  if (routePolicyForm) {
    routePolicyForm.elements.route_name.value = row.route_name || "";
    routePolicyForm.elements.candidate_deployments.value = row.candidate_deployments || "[]";
    routePolicyForm.elements.load_balancing_strategy.value = row.load_balancing_strategy || "weighted";
    routePolicyForm.elements.retry_policy.value = row.retry_policy || "{}";
    routePolicyForm.elements.fallback_policy.value = row.fallback_policy || "{}";
    routePolicyForm.elements.timeout_policy.value = row.timeout_policy || "{}";
  }
  if (routePriorityForm) routePriorityForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (routeProviderHealthForm) routeProviderHealthForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (routePreCallFiltersForm) routePreCallFiltersForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (routeTrafficMirroringForm) routeTrafficMirroringForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (routeTrafficMirroringAnalyticsForm) routeTrafficMirroringAnalyticsForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (gatewayEntitlementFiltersForm) gatewayEntitlementFiltersForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (gatewayEntitlementForm) gatewayEntitlementForm.elements.route_policy_id.value = row.route_policy_id || "";
  if (routeFallbackForm) {
    routeFallbackForm.elements.route_policy_id.value = row.route_policy_id || "";
    routeFallbackForm.elements.tenant_id.value = row?.tenant_id || routeFallbackForm.elements.tenant_id.value || "tenant-platform";
  }
  if (routeOptimizeForm) routeOptimizeForm.elements.route_policy_id.value = row.route_policy_id || "";
}

function renderBenchmarkTable(rows) {
  const tbody = qs("#benchmarkTable");
  if (!tbody) return;
  const list = Array.isArray(rows) ? rows : (rows ? [rows] : []);
  if (!list.length) {
    setTableMessage(tbody, 6, "No benchmark runs yet.");
    return;
  }
  tbody.textContent = "";
  list.forEach((run) => {
    appendTableRow(tbody, [run.benchmark_run_id, run.agent_id, run.benchmark_suite, run.environment, run.score, run.summary]);
  });
}

function renderScanTable(rows) {
  const tbody = qs("#scanTable");
  if (!tbody) return;
  const list = Array.isArray(rows) ? rows : (rows ? [rows] : []);
  if (!list.length) {
    setTableMessage(tbody, 7, "No scan runs yet.");
    return;
  }
  tbody.textContent = "";
  list.forEach((run) => {
    appendTableRow(tbody, [run.scan_run_id, run.agent_id, run.scan_type, run.environment, run.findings_count, run.severity_high_count, run.summary]);
  });
}

function renderBenchmarkTrendSummary(rows) {
  const target = qs("#benchmarkTrendSummary");
  if (!target) return;
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    target.textContent = "";
    return;
  }
  const totalRuns = list.length;
  const avgScore = Math.round(list.reduce((sum, row) => sum + Number(row.score || 0), 0) / totalRuns);
  const environments = Array.from(new Set(list.map((row) => String(row.environment || "").trim()).filter(Boolean))).join(", ");
  target.textContent = `Benchmark trend: ${totalRuns} runs, avg score ${avgScore}, environments: ${environments || "n/a"}.`;
}

function renderScanTrendSummary(rows) {
  const target = qs("#scanTrendSummary");
  if (!target) return;
  const list = Array.isArray(rows) ? rows : [];
  if (!list.length) {
    target.textContent = "";
    return;
  }
  const totalRuns = list.length;
  const totalFindings = list.reduce((sum, row) => sum + Number(row.findings_count || 0), 0);
  const totalHigh = list.reduce((sum, row) => sum + Number(row.severity_high_count || 0), 0);
  target.textContent = `Scan trend: ${totalRuns} runs, findings ${totalFindings}, high severity ${totalHigh}.`;
}

function bindRuntimePresetButtons() {
  const target = qs("#runtimeConfigPresets");
  if (!target || target.childElementCount > 0) return;

  RUNTIME_CONFIG_PRESETS.forEach((preset) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.textContent = preset.config_key;
    button.addEventListener("click", () => populateRuntimeConfigForm(preset));
    target.appendChild(button);
  });
}

function openRuntimeConfigPreset(configKey) {
  const preset = RUNTIME_CONFIG_PRESETS.find((item) => item.config_key === configKey);
  switchView("runtime-config");
  if (preset) {
    populateRuntimeConfigForm(preset);
    return;
  }
  populateRuntimeConfigForm({ config_key: configKey, config_value: "", description: "" });
}

function bindCostingConfigActions() {
  const openBtn = qs("#openRuntimeConfigPricing");
  if (openBtn && !openBtn.dataset.bound) {
    openBtn.dataset.bound = "true";
    openBtn.addEventListener("click", () => switchView("runtime-config"));
  }

  qsa(".cost-config-shortcut").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "true";
    button.addEventListener("click", () => {
      const configKey = String(button.dataset.configKey || "").trim();
      if (!configKey) return;
      openRuntimeConfigPreset(configKey);
    });
  });
}

async function loadRuntimeConfigs() {
  try {
    return await api("/runtime-config");
  } catch (err) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    return [];
  }
}

async function renderRuntimeConfigTable() {
  const tbody = qs("#runtimeConfigTable");
  if (!tbody) return;
  setTableMessage(tbody, 6, "Loading...");

  const rows = await loadRuntimeConfigs();
  if (!rows?.length) {
    setTableMessage(tbody, 6, "No runtime configs saved yet.");
    return;
  }

  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.config_key);
    appendTableCell(tr, runtimeConfigPrettyValue(row.config_value));
    appendTableCell(tr, row.description);
    appendTableCell(tr, row.updated_by);
    appendTableCell(tr, row.updated_at);

    const actionsCell = document.createElement("td");
    actionsCell.className = "cell-actions";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "ghost";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => populateRuntimeConfigForm(row));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteRuntimeConfig(row.config_key));

    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(deleteBtn);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  });
}

function resetRuntimeConfigForm(message = "") {
  const form = qs("#runtimeConfigForm");
  if (!form) return;
  form.reset();
  updateRuntimeValidationHint("");
  const result = qs("#runtimeConfigResult");
  if (result) result.textContent = message;
}

function populateRuntimeConfigForm(row) {
  const form = qs("#runtimeConfigForm");
  if (!form || !row) return;

  form.elements.config_key.value = row.config_key || "";
  form.elements.config_value.value = row.config_value || "";
  form.elements.description.value = row.description || "";
  updateRuntimeValidationHint(row.config_key || "");
  const result = qs("#runtimeConfigResult");
  if (result) result.textContent = `Editing ${row.config_key}`;
}

async function saveRuntimeConfig(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const raw = Object.fromEntries(new FormData(form).entries());
  const configKey = String(raw.config_key || "").trim();
  const configValue = String(raw.config_value || "").trim();

  if (!configKey || !configValue) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = "Config key and config value are required.";
    return;
  }

  try {
    const validation = await api("/runtime-config/validate", {
      method: "POST",
      body: JSON.stringify({
        config_key: configKey,
        config_value: configValue,
      }),
    });
    if (!validation?.valid) {
      const result = qs("#runtimeConfigResult");
      if (result) result.textContent = `Validation failed: ${safeText(validation?.error || "Invalid value")}`;
      return;
    }

    await api(`/runtime-config/${encodeURIComponent(configKey)}`, {
      method: "PUT",
      body: JSON.stringify({
        config_value: configValue,
        description: String(raw.description || "").trim(),
      }),
    });
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = `Saved ${configKey}.`;
    await renderRuntimeConfigTable();
    if (configKey.startsWith(UI_FEATURE_FLAG_PREFIX)) {
      await refreshUiFeatureFlags();
    }
  } catch (err) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deleteRuntimeConfig(configKey) {
  try {
    await api(`/runtime-config/${encodeURIComponent(configKey)}`, { method: "DELETE" });
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = `Deleted ${configKey}.`;
    await renderRuntimeConfigTable();
    if (String(configKey || "").startsWith(UI_FEATURE_FLAG_PREFIX)) {
      await refreshUiFeatureFlags();
    }
  } catch (err) {
    const result = qs("#runtimeConfigResult");
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function evaluateSingleConfigRisk(config) {
  const findings = [];
  const priority = Array.isArray(config.provider_priority) ? config.provider_priority : [];
  const familySet = new Set(priority.map((item) => cloudFamily(item)));
  const isProd = String(config.environment || "").toLowerCase() === "prod";
  const usesAws = cloudFamily(config.provider) === "aws" || priority.some((item) => cloudFamily(item) === "aws");

  if (isProd && !config.fallback_enabled) {
    findings.push({ severity: "high", message: `${config.agent_key}: production fallback is disabled.` });
  }
  if (isProd && priority.length < 2) {
    findings.push({ severity: "high", message: `${config.agent_key}: production priority list should include at least 2 providers.` });
  }
  if (isProd && familySet.size < 2) {
    findings.push({ severity: "medium", message: `${config.agent_key}: production config is not multi-cloud resilient.` });
  }
  if (config.max_fallback_hops > 3) {
    findings.push({ severity: "medium", message: `${config.agent_key}: max fallback hops exceeds recommended threshold (3).` });
  }
  if (config.global_timeout_ms > 8000) {
    findings.push({ severity: "medium", message: `${config.agent_key}: global timeout is high and may affect availability SLOs.` });
  }
  if (config.retry_budget > 2) {
    findings.push({ severity: "medium", message: `${config.agent_key}: retry budget above 2 may amplify outages.` });
  }
  if (config.failure_threshold_percent > 50) {
    findings.push({ severity: "medium", message: `${config.agent_key}: circuit threshold above 50 percent may delay protection.` });
  }
  if (config.cooldown_seconds < 30) {
    findings.push({ severity: "low", message: `${config.agent_key}: circuit cooldown below 30 seconds can cause flapping.` });
  }
  if (usesAws && config.timeout_ms > 10000) {
    findings.push({ severity: "medium", message: `${config.agent_key}: AWS path timeout exceeds recommended 10000ms.` });
  }
  if (usesAws && config.max_tokens > 4096) {
    findings.push({ severity: "low", message: `${config.agent_key}: AWS config max tokens is high; review cost guardrails.` });
  }
  if (!priority.includes(config.provider)) {
    findings.push({ severity: "low", message: `${config.agent_key}: primary provider is missing from priority order.` });
  }

  return findings;
}

function renderSecurityFindings(findings) {
  const summary = qs("#agentConfigSecuritySummary");
  const list = qs("#agentConfigSecurityFindings");
  if (!summary || !list) return;

  list.textContent = "";
  const counts = { high: 0, medium: 0, low: 0 };
  findings.forEach((item) => {
    counts[item.severity] += 1;
    const li = document.createElement("li");
    li.textContent = `${item.severity.toUpperCase()}: ${item.message}`;
    li.className = `sev-${item.severity}`;
    list.appendChild(li);
  });

  const total = findings.length;
  summary.textContent = `Security findings: total=${total}, high=${counts.high}, medium=${counts.medium}, low=${counts.low}`;

  if (!total) {
    const li = document.createElement("li");
    li.textContent = "No findings. Configuration posture aligns with baseline CISO guardrails.";
    li.className = "sev-low";
    list.appendChild(li);
  }
}

async function runConfigSecurityReview() {
  const configs = await loadAgentConfigsFromStorage();
  const findings = configs.flatMap((config) => evaluateSingleConfigRisk(config));
  renderSecurityFindings(findings);
  return findings;
}

async function exportCisoAuditBundle() {
  const configs = await loadAgentConfigsFromStorage();
  const findings = await runConfigSecurityReview();
  const payload = {
    bundle_type: "agent_config_security_audit",
    generated_at: new Date().toISOString(),
    reviewer_context: {
      actor_id: state.actorId,
      actor_role: state.actorRole,
      environment_profile: state.environmentProfile,
      api_base: state.apiBase,
    },
    controls_reference: [
      "CISO-CLOUD-001 multi-cloud fallback",
      "CISO-AWS-002 AWS timeout and token-cost posture",
      "CISO-RESILIENCE-003 retry and circuit thresholds",
      "AUDIT-EVIDENCE-004 serialized change evidence",
    ],
    findings,
    config_count: configs.length,
    configs,
  };
  payload.integrity_checksum = weakChecksum(JSON.stringify(payload));

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `ciso-audit-bundle-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function resetAgentConfigForm(message = "") {
  const form = qs("#agentConfigForm");
  if (!form) return;
  form.reset();
  form.elements.config_id.value = "";
  form.elements.provider_priority.value = "aws,azure,google";
  form.elements.temperature.value = "0.3";
  form.elements.max_tokens.value = "1024";
  form.elements.timeout_ms.value = "4500";
  form.elements.fallback_enabled.value = "true";
  form.elements.max_fallback_hops.value = "2";
  form.elements.global_timeout_ms.value = "4500";
  form.elements.retry_budget.value = "1";
  form.elements.failure_threshold_percent.value = "40";
  form.elements.cooldown_seconds.value = "60";
  form.elements.enabled.value = "true";
  loadSupportedModelOptions(form.elements.provider.value || "", "gpt-4o-mini");
  const result = qs("#agentConfigResult");
  if (result) result.textContent = message;
}

async function populateAgentConfigForm(configId) {
  const form = qs("#agentConfigForm");
  if (!form) return;
  const config = (await loadAgentConfigsFromStorage()).find((item) => item.config_id === configId);
  if (!config) return;

  form.elements.config_id.value = config.config_id;
  form.elements.agent_key.value = config.agent_key;
  form.elements.display_name.value = config.display_name;
  form.elements.provider.value = config.provider;
  await loadSupportedModelOptions(config.provider, config.model);
  form.elements.provider_priority.value = stringifyPriorityList(config.provider_priority || [config.provider]);
  form.elements.temperature.value = String(config.temperature);
  form.elements.max_tokens.value = String(config.max_tokens);
  form.elements.timeout_ms.value = String(config.timeout_ms);
  form.elements.fallback_enabled.value = String(Boolean(config.fallback_enabled ?? true));
  form.elements.max_fallback_hops.value = String(config.max_fallback_hops ?? 2);
  form.elements.global_timeout_ms.value = String(config.global_timeout_ms ?? config.timeout_ms ?? 4500);
  form.elements.retry_budget.value = String(config.retry_budget ?? 1);
  form.elements.failure_threshold_percent.value = String(config.failure_threshold_percent ?? 40);
  form.elements.cooldown_seconds.value = String(config.cooldown_seconds ?? 60);
  form.elements.environment.value = config.environment;
  form.elements.enabled.value = String(Boolean(config.enabled));
  form.elements.notes.value = config.notes || "";
  const result = qs("#agentConfigResult");
  if (result) result.textContent = `Editing ${config.agent_key}`;
}

async function deleteAgentConfig(configId) {
  const current = await loadAgentConfigsFromStorage();
  const target = current.find((item) => item.config_id === configId);
  if (!target?.agent_key) return;
  await api(`/agent-configs/${encodeURIComponent(target.agent_key)}`, { method: "DELETE" });
  await renderAgentConfigTable();
  await runConfigSecurityReview();
  const result = qs("#agentConfigResult");
  if (result) result.textContent = "Configuration deleted.";
}

async function exportAgentConfigs() {
  const rows = await loadAgentConfigsFromStorage();
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `agent-configs-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function importAgentConfigs(evt) {
  const file = evt.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new Error("Expected a JSON array.");

    const normalized = parsed
      .map((item) => normalizeAgentConfig(item, item.config_id || createConfigId()))
      .filter((item) => item.agent_key && item.display_name && item.model);

    await saveAgentConfigsToStorage(normalized);
    await renderAgentConfigTable();
    await runConfigSecurityReview();
    const result = qs("#agentConfigResult");
    if (result) result.textContent = `Imported ${normalized.length} configurations.`;
  } catch (err) {
    const result = qs("#agentConfigResult");
    if (result) result.textContent = `Import failed: ${safeText(err.message)}`;
  } finally {
    evt.target.value = "";
  }
}

async function saveAgentConfig(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const raw = Object.fromEntries(new FormData(form).entries());
  const existingId = String(raw.config_id || "").trim();
  const nextConfig = normalizeAgentConfig(raw, existingId);

  if (!nextConfig.agent_key || !nextConfig.display_name || !nextConfig.model) {
    qs("#agentConfigResult").textContent = "Agent key, display name, and model are required.";
    return;
  }

  await saveAgentConfigsToStorage([nextConfig]);
  await renderAgentConfigTable();
  await runConfigSecurityReview();
  resetAgentConfigForm(`Saved configuration for ${nextConfig.agent_key}.`);
}

function updateContextInputs() {
  qs("#apiBase").value = state.apiBase;
  qs("#actorRole").value = state.actorRole;
  qs("#actorId").value = state.actorId;
  if (qs("#loginUsername")) {
    qs("#loginUsername").value = state.actorId;
  }
  qs("#mfaVerified").value = String(Boolean(state.mfaVerified));
  qs("#environmentProfile").value = state.environmentProfile;
  renderActiveProfile();
  renderLoggedInUserDetails();
}

function detectProfileFromBaseUrl(baseUrl) {
  const normalized = (baseUrl || "").trim().toLowerCase();
  const matches = Object.entries(ENVIRONMENT_PROFILES)
    .filter(([, profile]) => profile.apiBase.toLowerCase() === normalized)
    .map(([name]) => name);
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) {
    if (matches.includes(state.environmentProfile)) return state.environmentProfile;
    return matches[0];
  }
  return "custom";
}

function renderActiveProfile() {
  const target = qs("#activeProfileText");
  target.textContent = `Profile: ${state.environmentProfile.toUpperCase()}`;
  renderProdGuardBanner();
}

function toTitleCaseToken(token) {
  const raw = String(token || "").trim();
  if (!raw) return "";
  return raw.charAt(0).toUpperCase() + raw.slice(1).toLowerCase();
}

function normalizeActorId(actorId) {
  return String(actorId || "").trim().toLowerCase();
}

function resolveActorRole(actorId, fallbackRole) {
  return String(fallbackRole || "Master Admin");
}

function normalizeActorRoleForBackend(roleName) {
  const role = String(roleName || "").trim();
  return role || "Master Admin";
}

function enforceKnownActorRole() {
  state.actorRole = resolveActorRole(state.actorId, state.actorRole);
}

function redirectToLoginPage() {
  if (window.location.pathname.endsWith("/login.html")) return;
  window.location.href = "./login.html";
}

function deriveUserNameFromActorId(actorId) {
  const parts = String(actorId || "")
    .split(/[-_.\s]+/)
    .map((part) => toTitleCaseToken(part))
    .filter(Boolean);
  const firstName = parts[0] || "First";
  const lastName = parts[1] || "User";
  return {
    firstName,
    lastName,
    initials: `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase(),
  };
}

function renderLoggedInUserDetails() {
  const target = qs("#loggedInUserDetails");
  const avatar = qs("#loggedInUserAvatar");
  const name = qs("#loggedInUserName");
  const overviewName = qs("#overviewLoggedInUser");
  const overviewContext = qs("#overviewLoggedInContext");
  const headerAvatar = qs("#headerLoggedInAvatar");
  const headerName = qs("#headerLoggedInUser");
  const headerRole = qs("#headerLoggedInRole");
  const headerEnv = qs("#headerLoggedInEnv");
  const headerSignOut = qs("#headerSignOut");
  const loginControls = qs("#loginControls");
  const loginResult = qs("#loginResult");
  const signOutButton = qs("#signOutSession");
  const parsed = deriveUserNameFromActorId(state.actorId);

  if (avatar) {
    avatar.textContent = parsed.initials;
    avatar.setAttribute("aria-label", `Logged in user ${parsed.firstName} ${parsed.lastName}`);
  }
  if (name) {
    name.textContent = `${parsed.firstName} ${parsed.lastName}`;
  }
  if (overviewName) {
    overviewName.textContent = `${parsed.firstName} ${parsed.lastName}`;
  }
  if (overviewContext) {
    overviewContext.textContent = `${safeText(state.actorRole)} @ ${safeText(state.environmentProfile).toUpperCase()}`;
  }
  if (headerAvatar) {
    headerAvatar.setAttribute("aria-label", `${parsed.firstName} ${parsed.lastName}`);
  }
  if (headerName) {
    headerName.textContent = `${parsed.firstName} ${parsed.lastName}`;
  }
  if (headerRole) {
    headerRole.textContent = safeText(state.actorRole);
  }
  if (headerEnv) {
    headerEnv.textContent = safeText(state.environmentProfile).toUpperCase();
  }
  if (headerSignOut) {
    headerSignOut.hidden = !state.accessToken;
  }

  if (!target) return;
  target.textContent = [
    `actor_id: ${safeText(state.actorId)}`,
    `actor_role: ${safeText(state.actorRole)}`,
    `environment: ${safeText(state.environmentProfile)}`,
    `api_base: ${safeText(state.apiBase)}`,
    `context_source: local operator session`,
  ].join("\n");

  if (loginControls) {
    loginControls.hidden = Boolean(state.accessToken);
  }
  if (signOutButton) {
    signOutButton.hidden = !state.accessToken;
  }
  if (loginResult) {
    loginResult.textContent = state.accessToken
      ? `Signed in as ${safeText(state.actorId)} (${safeText(state.actorRole)}).`
      : "Sign in with a directory user to issue a session token and hide these controls.";
  }
}

function renderThemeToggle() {
  const toggle = qs("#themeToggle");
  if (!toggle) return;
  const nextTheme = state.theme === "dark" ? "light" : "dark";
  const label = nextTheme === "light" ? "Switch to light theme" : "Switch to dark theme";
  toggle.setAttribute("aria-label", label);
  toggle.setAttribute("title", label);
  while (toggle.firstChild) toggle.removeChild(toggle.firstChild);
  const svgNs = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS(svgNs, "path");
  path.setAttribute(
    "d",
    nextTheme === "light"
      ? "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm0-6h1v3h-1V2zm0 17h1v3h-1v-3zM2 11h3v1H2v-1zm17 0h3v1h-3v-1zM4.22 5.64l.71-.71 2.12 2.12-.71.71-2.12-2.12zm12.95 12.95.71-.71 2.12 2.12-.71.71-2.12-2.12zM4.93 19.29l-.71-.71 2.12-2.12.71.71-2.12 2.12zm12.24-12.24-.71-.71 2.12-2.12.71.71-2.12 2.12z"
      : "M21.64 13a9 9 0 1 1-10.63-10.63 7 7 0 1 0 10.63 10.63z"
  );
  path.setAttribute("fill", "currentColor");
  svg.appendChild(path);
  toggle.appendChild(svg);
}

function applyTheme(theme) {
  state.theme = theme === "light" ? "light" : "dark";
  document.body.dataset.theme = state.theme;
  localStorage.setItem("theme", state.theme);
  renderThemeToggle();
}

function renderProdGuardBanner() {
  const banner = qs("#prodGuardBanner");
  banner.hidden = state.environmentProfile !== "prod";
}

function applySelectedProfile() {
  const selected = qs("#environmentProfile").value;
  if (selected === "custom") {
    state.environmentProfile = detectProfileFromBaseUrl(state.apiBase);
    updateContextInputs();
    return;
  }

  const profile = ENVIRONMENT_PROFILES[selected];
  if (!profile) return;

  state.environmentProfile = selected;
  state.apiBase = profile.apiBase;
  state.actorId = profile.actorId;
  state.actorRole = resolveActorRole(profile.actorId, profile.actorRole);
  updateContextInputs();
}

function saveContext() {
  state.apiBase = parseApiBaseOrThrow(qs("#apiBase").value.trim());
  state.actorId = qs("#actorId").value.trim();
  state.actorRole = resolveActorRole(state.actorId, qs("#actorRole").value);
  state.accessToken = "";
  state.environmentProfile = detectProfileFromBaseUrl(state.apiBase);
  state.mfaVerified = parseBooleanFlag(qs("#mfaVerified")?.value, true);
  localStorage.setItem("apiBase", state.apiBase);
  localStorage.setItem("actorRole", state.actorRole);
  localStorage.setItem("actorId", state.actorId);
  localStorage.removeItem("accessToken");
  localStorage.setItem("environmentProfile", state.environmentProfile);
  localStorage.setItem("mfaVerified", String(state.mfaVerified));
  updateContextInputs();
}

function signOutSession() {
  state.accessToken = "";
  localStorage.removeItem("accessToken");
  renderLoggedInUserDetails();
  const result = qs("#loginResult");
  if (result) result.textContent = "Signed out. Enter credentials to sign in again.";
  redirectToLoginPage();
}

async function signInWithPrompt() {
  const usernameInput = qs("#loginUsername");
  const passwordInput = qs("#loginPassword");
  const result = qs("#loginResult");

  const username = String(usernameInput?.value || "").trim();
  const password = String(passwordInput?.value || "");
  if (!username || !password) {
    if (result) result.textContent = "Username and password are required.";
    return;
  }

  state.mfaVerified = parseBooleanFlag(qs("#mfaVerified")?.value, true);
  const payload = {
    username,
    password,
    ttl_minutes: 60,
    idle_timeout_minutes: 30,
  };

  const issued = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  state.actorId = String(issued?.actor_id || username);
  state.actorRole = resolveActorRole(state.actorId, issued?.actor_role || qs("#actorRole")?.value || "Master Admin");

  state.accessToken = String(issued?.access_token || "");
  if (!state.accessToken) {
    throw new Error("Session token was not issued.");
  }
  localStorage.setItem("actorId", state.actorId);
  localStorage.setItem("actorRole", state.actorRole);
  localStorage.setItem("accessToken", state.accessToken);
  localStorage.setItem("mfaVerified", String(state.mfaVerified));
  updateContextInputs();

  if (passwordInput) passwordInput.value = "";
  if (result) result.textContent = `Signed in as ${safeText(state.actorId)} (${safeText(state.actorRole)}).`;
  await loadOverview();
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const guardExempt = isProdGuardExemptMutation(method, path);
  const isSuperAdmin = isSuperAdminRole(normalizeActorRoleForBackend(state.actorRole));
  if (state.environmentProfile === "prod" && !SAFE_HTTP_METHODS.has(method) && !guardExempt && !isSuperAdmin) {
    const approved = window.confirm(
      `Production guard: confirm ${method} ${path} with actor ${state.actorId} (${state.actorRole}).`,
    );
    if (!approved) {
      throw new Error("Action canceled by operator.");
    }
  }

  const optionHeaders = {
    ...(options.headers || {}),
  };
  if (optionHeaders["X-Actor-Role"]) {
    optionHeaders["X-Actor-Role"] = normalizeActorRoleForBackend(optionHeaders["X-Actor-Role"]);
  }

  const headers = {
    "Content-Type": "application/json",
    "X-Actor-Role": normalizeActorRoleForBackend(state.actorRole),
    "X-Actor-Id": state.actorId,
    "X-MFA-Verified": String(Boolean(state.mfaVerified)),
    ...(state.accessToken ? { Authorization: `Bearer ${state.accessToken}` } : {}),
    ...optionHeaders,
  };

  const requestUrl = `${state.apiBase}${path}`;
  let resp = await fetch(requestUrl, {
    ...options,
    headers,
  });

  const forcedRole = options?.headers?.["X-Actor-Role"];
  const effectiveRole = normalizeActorRoleForBackend(state.actorRole);
  if ((resp.status === 401 || resp.status === 403) && forcedRole && normalizeActorRoleForBackend(forcedRole) !== effectiveRole) {
    const retryHeaders = {
      ...headers,
      "X-Actor-Role": effectiveRole,
      "X-Actor-Id": state.actorId,
    };
    resp = await fetch(requestUrl, {
      ...options,
      headers: retryHeaders,
    });
  }

  let data = null;
  try {
    data = await resp.json();
  } catch {
    data = null;
  }

  if (!resp.ok) {
    const detail = data?.detail;
    let message = detail?.message || detail || `Request failed (${resp.status})`;
    if (detail && typeof detail === "object") {
      const requiredRole = String(detail.required_role || "").trim();
      const traceId = String(detail.decision_trace_id || "").trim();
      if (requiredRole) {
        message = `${message} Required role: ${requiredRole}.`;
      }
      if (traceId) {
        message = `${message} Trace: ${traceId}.`;
      }
    }
    if (resp.status >= 500) {
      setGlobalError("The service is currently unavailable");
    }
    throw new Error(String(message));
  }
  return data;
}

function setProfileHealthStatus(profileName, text) {
  const row = qs(`#profileHealthList [data-profile="${profileName}"]`);
  if (!row) return;
  row.textContent = `${profileName[0].toUpperCase() + profileName.slice(1)}: ${text}`;
}

async function fetchHealthForProfile(profileName, timeoutMs = 2500) {
  const profile = ENVIRONMENT_PROFILES[profileName];
  if (!profile) return;

  setProfileHealthStatus(profileName, "probing...");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(`${profile.apiBase}/health`, {
      method: "GET",
      headers: {
        "X-Actor-Role": profile.actorRole,
        "X-Actor-Id": profile.actorId,
      },
      signal: controller.signal,
    });
    if (!resp.ok) {
      setProfileHealthStatus(profileName, `http ${resp.status}`);
      return;
    }
    const data = await resp.json().catch(() => ({}));
    const label = data?.status ? `ok (${data.status})` : "ok";
    setProfileHealthStatus(profileName, label);
  } catch (err) {
    if (err && err.name === "AbortError") {
      setProfileHealthStatus(profileName, "timeout");
      return;
    }
    setProfileHealthStatus(profileName, "unreachable");
  } finally {
    clearTimeout(timeout);
  }
}

async function probeProfiles(profileNames = [state.environmentProfile || "local"]) {
  const uniqueNames = Array.from(new Set(profileNames)).filter((name) => Boolean(ENVIRONMENT_PROFILES[name]));
  if (!uniqueNames.length) return;
  await Promise.all(uniqueNames.map((name) => fetchHealthForProfile(name)));
}

function switchView(viewName) {
  const targetBtn = qsa(".nav-item").find((btn) => btn.dataset.view === viewName);
  if (!targetBtn || targetBtn.hidden) return;

  qsa(".nav-item").forEach((btn) => {
    const isActive = btn.dataset.view === viewName;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-current", isActive ? "page" : "false");
  });
  qsa(".view").forEach((section) => {
    section.classList.toggle("active", section.id === viewName);
  });
  qs("#viewTitle").textContent = formatViewTitle(viewName);
}

function buildQueryString(raw) {
  const params = new URLSearchParams();
  Object.entries(raw || {}).forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    const text = String(value).trim();
    if (!text) return;
    params.set(key, text);
  });
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

async function loadOverview() {
  const [healthResult, costResult, discoveryResult, auditResult] = await Promise.allSettled([
    api("/health", { headers: {} }),
    api("/cost/live"),
    api("/discovery/agents"),
    api("/audit/events?limit=50", { headers: { "X-Actor-Role": "Auditor" } }),
  ]);

  if (healthResult.status === "fulfilled") {
    const health = healthResult.value;
    qs("#healthStatus").textContent = `Backend: ${health?.status || "unknown"}`;
  } else {
    qs("#healthStatus").textContent = `Error: ${safeText(healthResult.reason?.message || "Failed to fetch")}`;
  }

  if (costResult.status === "fulfilled") {
    qs("#spendDay").textContent = currency(costResult.value?.spend_last_day_cents);
    qs("#spendHour").textContent = currency(costResult.value?.spend_last_hour_cents);
  } else {
    qs("#spendDay").textContent = "--";
    qs("#spendHour").textContent = "--";
  }

  if (discoveryResult.status === "fulfilled") {
    qs("#discoveryCount").textContent = String(Array.isArray(discoveryResult.value) ? discoveryResult.value.length : 0);
  } else {
    qs("#discoveryCount").textContent = "--";
  }

  if (auditResult.status === "fulfilled") {
    qs("#auditCount").textContent = String(Array.isArray(auditResult.value) ? auditResult.value.length : 0);
  } else {
    qs("#auditCount").textContent = "--";
  }

  if (healthResult.status === "fulfilled") {
    const degraded = [costResult, discoveryResult, auditResult].some((item) => item.status === "rejected");
    renderStatusBadge(degraded ? "Degraded" : "Healthy", !degraded);
    clearGlobalError();
  } else {
    let localFallbackStatus = null;
    try {
      const localProfile = ENVIRONMENT_PROFILES.local;
      const localResp = await fetch(`${localProfile.apiBase}/health`, {
        method: "GET",
        headers: {
          "X-Actor-Role": localProfile.actorRole,
          "X-Actor-Id": localProfile.actorId,
        },
      });
      if (localResp.ok) {
        const localData = await localResp.json().catch(() => ({}));
        localFallbackStatus = localData?.status || "ok";
      }
    } catch {
      localFallbackStatus = null;
    }

    if (localFallbackStatus) {
      qs("#healthStatus").textContent = `Selected backend unreachable. Local backend: ${localFallbackStatus}`;
      renderStatusBadge("Degraded", false);
      setGlobalError("Selected profile is unreachable. Switch Environment Profile to Local to use live local data.");
    } else {
      renderStatusBadge("Incident", false);
      setGlobalError("Unable to reach backend health endpoint");
    }
  }

  await loadSpendBreakdown();
}

async function loadDiscovery() {
  const tbody = qs("#discoveryTable");
  setTableMessage(tbody, 4, "Loading...");
  try {
    const rows = await api("/discovery/agents");
    if (!rows?.length) {
      setTableMessage(tbody, 4, "No discovery records.");
      return;
    }

    tbody.textContent = "";
    rows.slice(0, 20).forEach((row) => {
      appendTableRow(tbody, [
        row.canonical_agent_key,
        row.source_system,
        row.discovery_confidence,
        row.discovery_status,
      ]);
    });
  } catch (err) {
    setTableMessage(tbody, 4, `Error: ${safeText(err.message)}`);
  }
}

function renderDiscoverySources() {
  const tbody = qs("#discoverySourcesTable");
  if (!tbody) return;
  if (!discoverySourceRows.length) {
    setTableMessage(tbody, 6, "No discovery sources.");
    return;
  }
  tbody.textContent = "";
  discoverySourceRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.source_id);
    appendTableCell(tr, row.status);
    appendTableCell(tr, row.last_sync_at || "");
    appendTableCell(tr, row.sync_lag_minutes ?? "--");
    appendTableCell(tr, row.discovered_count ?? 0);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const syncBtn = document.createElement("button");
    syncBtn.type = "button";
    syncBtn.className = "ghost";
    syncBtn.textContent = "Sync";
    syncBtn.addEventListener("click", () => syncDiscoverySource(row.source_id));
    actions.appendChild(syncBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderDiscoveryConflicts() {
  const tbody = qs("#discoveryConflictsTable");
  if (!tbody) return;
  if (!discoveryConflictRows.length) {
    setTableMessage(tbody, 6, "No discovery conflicts.");
    return;
  }
  tbody.textContent = "";
  discoveryConflictRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.discovered_agent_id);
    appendTableCell(tr, row.canonical_agent_key);
    appendTableCell(tr, row.source_system);
    appendTableCell(tr, row.discovery_confidence);
    appendTableCell(tr, row.review_priority);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const approveBtn = document.createElement("button");
    approveBtn.type = "button";
    approveBtn.className = "ghost";
    approveBtn.textContent = "Approve";
    approveBtn.addEventListener("click", () => resolveDiscoveryRecord(row.discovered_agent_id, "approve"));
    const rejectBtn = document.createElement("button");
    rejectBtn.type = "button";
    rejectBtn.className = "ghost";
    rejectBtn.textContent = "Reject";
    rejectBtn.addEventListener("click", () => resolveDiscoveryRecord(row.discovered_agent_id, "reject"));
    actions.append(approveBtn, rejectBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderDiscoveryAlerts() {
  const tbody = qs("#discoveryAlertsTable");
  if (!tbody) return;
  if (!discoveryAlertRows.length) {
    setTableMessage(tbody, 7, "No discovery alerts.");
    return;
  }
  tbody.textContent = "";
  discoveryAlertRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.alert_id);
    appendTableCell(tr, row.discovered_agent_id);
    appendTableCell(tr, row.source_system);
    appendTableCell(tr, row.discovery_confidence);
    appendTableCell(tr, row.severity);
    appendTableCell(tr, row.alert_type);
    appendTableCell(tr, row.message);
    tbody.appendChild(tr);
  });
}

function renderDiscoveryPromoteQueue() {
  const tbody = qs("#discoveryPromoteQueueTable");
  if (!tbody) return;
  if (!discoveryPromoteQueueRows.length) {
    setTableMessage(tbody, 6, "No discovered agents ready for promotion.");
    return;
  }
  tbody.textContent = "";
  discoveryPromoteQueueRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.discovered_agent_id);
    appendTableCell(tr, row.canonical_agent_key);
    appendTableCell(tr, row.source_system);
    appendTableCell(tr, row.discovery_confidence);
    appendTableCell(tr, row.queue_reason);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const promoteBtn = document.createElement("button");
    promoteBtn.type = "button";
    promoteBtn.className = "ghost";
    promoteBtn.textContent = "Promote";
    promoteBtn.addEventListener("click", () => promoteDiscoveryAgent(row.discovered_agent_id));
    actions.appendChild(promoteBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

async function loadDiscoverySources() {
  const result = qs("#discoverySourceResult");
  const tbody = qs("#discoverySourcesTable");
  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api("/discovery/sources");
    discoverySourceRows = Array.isArray(rows) ? rows : [];
    renderDiscoverySources();
    if (result) result.textContent = discoverySourceRows.length ? `Loaded ${discoverySourceRows.length} discovery sources.` : "No discovery sources.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

async function syncDiscoverySource(sourceId) {
  const result = qs("#discoverySourceResult");
  try {
    const data = await api(`/discovery/sources/${encodeURIComponent(sourceId)}/sync`, { method: "POST" });
    if (result) result.textContent = `Synced ${data.source_id}.`;
    await loadDiscoverySources();
    await Promise.all([loadDiscovery(), loadDiscoveryConflicts(), loadDiscoveryAlerts(), loadDiscoveryPromoteQueue()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadDiscoveryConflicts() {
  const result = qs("#discoveryTriageResult");
  const tbody = qs("#discoveryConflictsTable");
  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api("/discovery/conflicts");
    discoveryConflictRows = Array.isArray(rows) ? rows : [];
    renderDiscoveryConflicts();
    if (result) result.textContent = discoveryConflictRows.length ? `Loaded ${discoveryConflictRows.length} discovery conflicts.` : "No discovery conflicts.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

async function loadDiscoveryAlerts() {
  const result = qs("#discoveryTriageResult");
  const tbody = qs("#discoveryAlertsTable");
  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/discovery/alerts");
    discoveryAlertRows = Array.isArray(rows) ? rows : [];
    renderDiscoveryAlerts();
    if (result) result.textContent = discoveryAlertRows.length ? `Loaded ${discoveryAlertRows.length} discovery alerts.` : "No discovery alerts.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadDiscoveryPromoteQueue() {
  const result = qs("#discoveryTriageResult");
  const tbody = qs("#discoveryPromoteQueueTable");
  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api("/discovery/promote-queue");
    discoveryPromoteQueueRows = Array.isArray(rows) ? rows : [];
    renderDiscoveryPromoteQueue();
    if (result) result.textContent = discoveryPromoteQueueRows.length ? `Loaded ${discoveryPromoteQueueRows.length} promotion candidates.` : "No promotion candidates.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

async function resolveDiscoveryRecord(discoveredAgentId, decision) {
  const result = qs("#discoveryTriageResult");
  try {
    const data = await api("/discovery/resolve", {
      method: "POST",
      body: JSON.stringify({ discovered_agent_id: discoveredAgentId, decision }),
    });
    if (result) result.textContent = `Resolved ${data.discovered_agent_id} as ${data.status}.`;
    await Promise.all([loadDiscoveryConflicts(), loadDiscoveryAlerts(), loadDiscoveryPromoteQueue(), loadDiscovery()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function promoteDiscoveryAgent(discoveredAgentId) {
  const result = qs("#discoveryTriageResult");
  try {
    const data = await api(`/discovery/promote/${encodeURIComponent(discoveredAgentId)}`, { method: "POST" });
    if (result) result.textContent = `Promoted to agent ${data.agent_id} (${data.status}).`;
    await Promise.all([loadDiscoveryPromoteQueue(), loadDiscovery(), loadDiscoverySources()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadWorkloadIdentityProviders(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#workloadIdentityProviderFilters");
  const tbody = qs("#workloadIdentityProvidersTable");
  const result = qs("#workloadIdentityProvidersResult");
  if (!form || !tbody) return;

  const payload = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    tenant_id: payload.tenant_id,
    provider_type: payload.provider_type,
    status: payload.status,
    limit: payload.limit,
    offset: payload.offset,
  });

  setTableMessage(tbody, 11, "Loading...");
  try {
    const rows = await api(`/auth/workload-identity/providers${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (result) result.textContent = `Loaded ${rows.length} providers.`;
    if (!rows?.length) {
      setTableMessage(tbody, 11, "No workload identity providers found.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.workload_identity_profile_id);
      appendTableCell(tr, row.tenant_id);
      appendTableCell(tr, row.tenant_name);
      appendTableCell(tr, row.tenant_type);
      appendTableCell(tr, row.tenant_description);
      appendTableCell(tr, row.provider_type);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.audience);
      appendTableCell(tr, row.session_duration_seconds);
      appendTableCell(tr, row.last_token_exchange_at);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const testBtn = document.createElement("button");
      testBtn.type = "button";
      testBtn.className = "ghost";
      testBtn.textContent = "Test";
      testBtn.addEventListener("click", () => testWorkloadIdentityProvider(row.workload_identity_profile_id, row.tenant_id));
      const trustBtn = document.createElement("button");
      trustBtn.type = "button";
      trustBtn.className = "ghost";
      trustBtn.textContent = "Trust";
      trustBtn.addEventListener("click", () => populateWorkloadTrustForms(row));
      const healthBtn = document.createElement("button");
      healthBtn.type = "button";
      healthBtn.className = "ghost";
      healthBtn.textContent = "Health";
      healthBtn.addEventListener("click", () => loadWorkloadIdentityHealth(row.workload_identity_profile_id, row.tenant_id));
      actionsCell.append(testBtn, trustBtn, healthBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 11, `Error: ${safeText(err.message)}`);
  }
}

async function testWorkloadIdentityProvider(providerId, tenantId) {
  const result = qs("#workloadIdentityProvidersResult");
  if (!providerId || !tenantId) return;
  try {
    const query = buildQueryString({ tenant_id: tenantId });
    const payload = await api(`/auth/workload-identity/providers/${encodeURIComponent(providerId)}/test${query}`, {
      method: "POST",
    });
    if (result) {
      result.textContent = `Test ${safeText(providerId)}: ${safeText(payload.test_status)} (${safeText(payload.detail)})`;
    }
    await loadWorkloadIdentityProviders();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function exchangeWorkloadIdentityToken(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#workloadTokenExchangeResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const payload = await api("/auth/workload-identity/token-exchange", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        workload_identity_profile_id: String(raw.workload_identity_profile_id || "").trim(),
        subject: String(raw.subject || "svc:connectivity-test").trim(),
      }),
    });
    if (result) {
      result.textContent = `Exchange completed via ${safeText(payload.token_source)} with ttl ${safeText(payload.expires_in)}s and ref ${safeText(payload.token_reference)}.`;
    }
    await loadWorkloadIdentityProviders();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function populateWorkloadTrustForms(row) {
  const trustForm = qs("#workloadIdentityTrustForm");
  const healthForm = qs("#workloadIdentityHealthForm");
  if (trustForm) {
    trustForm.elements.provider_id.value = row.workload_identity_profile_id || "";
    trustForm.elements.tenant_id.value = row.tenant_id || "";
    trustForm.elements.expected_audience.value = row.audience || "";
  }
  if (healthForm) {
    healthForm.elements.provider_id.value = row.workload_identity_profile_id || "";
    healthForm.elements.tenant_id.value = row.tenant_id || "";
  }
}

function renderWorkloadTrustDetails(payload) {
  const details = qs("#workloadIdentityTrustDetails");
  if (!details) return;
  details.textContent = payload ? JSON.stringify(payload, null, 2) : "";
}

async function loadWorkloadTrustEvidence(providerId) {
  const result = qs("#workloadIdentityTrustResult");
  const table = qs("#workloadTrustEvidenceTable");
  const resolvedProviderId = String(providerId || qs("#workloadIdentityTrustForm")?.elements?.provider_id?.value || "").trim();
  if (!resolvedProviderId) {
    if (result) result.textContent = "Provider ID is required.";
    return;
  }
  if (table) setTableMessage(table, 6, "Loading...");
  try {
    const query = buildQueryString({
      action_type: "workload_identity.trust.validate",
      resource_type: "workload_identity_profile",
      resource_id: resolvedProviderId,
      since_hours: 168,
      limit: 50,
      offset: 0,
    });
    const rows = await api(`/audit/events${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (!table) return;
    if (!rows?.length) {
      setTableMessage(table, 6, "No trust evidence found for this provider.");
      if (result) result.textContent = `No trust evidence found for ${safeText(resolvedProviderId)}.`;
      return;
    }
    table.textContent = "";
    rows.forEach((row) => {
      appendTableRow(table, [
        formatComplianceDate(row.timestamp),
        row.actor_id,
        row.action_type,
        row.resource_id,
        row.decision_outcome,
        row.trace_id,
      ]);
    });
    if (result) result.textContent = `Loaded ${rows.length} trust evidence events for ${safeText(resolvedProviderId)}.`;
  } catch (err) {
    if (table) setTableMessage(table, 6, `Error: ${safeText(err.message)}`);
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function validateWorkloadIdentityTrust(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#workloadIdentityTrustResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const providerId = String(raw.provider_id || "").trim();
  if (!providerId) {
    if (result) result.textContent = "Provider ID is required.";
    return;
  }
  try {
    const data = await api(`/auth/workload-identity/providers/${encodeURIComponent(providerId)}/validate-trust`, {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        check_type: String(raw.check_type || "trust_policy").trim(),
        expected_audience: String(raw.expected_audience || "").trim() || null,
        simulate_pass: parseBooleanFlag(raw.simulate_pass, true),
      }),
    });
    renderWorkloadTrustDetails(data);
    if (result) result.textContent = `Trust ${safeText(data.status)} (${safeText(data.details)}) for ${safeText(data.workload_identity_profile_id)}.`;
    await Promise.all([loadWorkloadIdentityProviders(), loadWorkloadTrustEvidence(providerId)]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadWorkloadIdentityHealth(providerId, tenantId) {
  const result = qs("#workloadIdentityTrustResult");
  const resolvedProviderId = String(providerId || qs("#workloadIdentityHealthForm")?.elements?.provider_id?.value || "").trim();
  const resolvedTenantId = String(tenantId || qs("#workloadIdentityHealthForm")?.elements?.tenant_id?.value || "").trim();
  if (!resolvedProviderId || !resolvedTenantId) {
    if (result) result.textContent = "Provider ID and tenant are required.";
    return;
  }
  try {
    const query = buildQueryString({ tenant_id: resolvedTenantId });
    const data = await api(`/auth/workload-identity/providers/${encodeURIComponent(resolvedProviderId)}/health${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    renderWorkloadTrustDetails(data);
    if (result) {
      result.textContent = `Health ${safeText(data.status)} for ${safeText(data.workload_identity_profile_id)}; stale ${safeText(data.token_exchange_stale_minutes)} minutes.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function submitWorkloadIdentityHealthForm(evt) {
  evt.preventDefault();
  await loadWorkloadIdentityHealth();
}

async function handleLoadWorkloadTrustEvidenceClick() {
  await loadWorkloadTrustEvidence();
}

async function createWorkloadIdentityProvider(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#createWorkloadIdentityProviderResult");
  const raw = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/auth/workload-identity/providers", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        provider_type: String(raw.provider_type || "").trim().toLowerCase(),
        audience: String(raw.audience || "").trim(),
        role_arn_or_equivalent: String(raw.role_arn_or_equivalent || "").trim(),
        bootstrap_token: String(raw.bootstrap_token || "").trim(),
        session_duration_seconds: Number(raw.session_duration_seconds || 3600),
        allowed_subject_patterns: String(raw.allowed_subject_patterns || "[]").trim(),
      }),
    });
    if (result) result.textContent = `Created workload identity provider ${safeText(data?.workload_identity_profile_id)}.`;
    form.reset();
    refreshTenantBoundForms();
    await Promise.all([loadWorkloadIdentityProviders(), loadProviderTypeOptions(), loadRegisterAgentTypeOptions()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadSecretProviders(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#secretProviderFilters");
  const tbody = qs("#secretProvidersTable");
  const result = qs("#secretProvidersResult");
  if (!form || !tbody) return;

  const payload = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    tenant_id: payload.tenant_id,
    provider_type: payload.provider_type,
    status: payload.status,
    auto_renew_enabled: payload.auto_renew_enabled,
    limit: payload.limit,
    offset: payload.offset,
  });

  setTableMessage(tbody, 13, "Loading...");
  try {
    const rows = await api(`/secrets/providers${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (result) result.textContent = `Loaded ${rows.length} secret providers.`;
    if (!rows?.length) {
      setTableMessage(tbody, 13, "No secret providers found.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.secret_provider_id);
      appendTableCell(tr, row.tenant_id);
      appendTableCell(tr, row.tenant_name);
      appendTableCell(tr, row.tenant_type);
      appendTableCell(tr, row.tenant_description);
      appendTableCell(tr, row.provider_type);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.auth_method);
      appendTableCell(tr, row.role_or_mount);
      appendTableCell(tr, row.lease_ttl_seconds);
      appendTableCell(tr, row.auto_renew_enabled);
      appendTableCell(tr, row.last_health_check_at);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const testBtn = document.createElement("button");
      testBtn.type = "button";
      testBtn.className = "ghost";
      testBtn.textContent = "Test";
      testBtn.addEventListener("click", () => testSecretProvider(row.secret_provider_id));
      const leaseBtn = document.createElement("button");
      leaseBtn.type = "button";
      leaseBtn.className = "ghost";
      leaseBtn.textContent = "Leases";
      leaseBtn.addEventListener("click", () => {
        populateSecretLeaseForm(row);
        loadSecretProviderLeases(row.secret_provider_id);
      });
      const healthBtn = document.createElement("button");
      healthBtn.type = "button";
      healthBtn.className = "ghost";
      healthBtn.textContent = "Health";
      healthBtn.addEventListener("click", () => loadSecretProviderHealth(row.secret_provider_id));
      actionsCell.append(testBtn, leaseBtn, healthBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 13, `Error: ${safeText(err.message)}`);
  }
}

async function testSecretProvider(providerId) {
  const result = qs("#secretProvidersResult");
  if (!providerId) return;
  try {
    const payload = await api(`/secrets/providers/${encodeURIComponent(providerId)}/test`, { method: "POST" });
    if (result) {
      result.textContent = `Test ${safeText(providerId)}: ${safeText(payload.test_status)} (${safeText(payload.detail)})`;
    }
    await loadSecretProviders();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function populateSecretLeaseForm(row) {
  const leaseForm = qs("#secretProviderLeaseRenewForm");
  const healthForm = qs("#secretProviderHealthForm");
  if (leaseForm) leaseForm.elements.provider_id.value = row.secret_provider_id || "";
  if (healthForm) healthForm.elements.provider_id.value = row.secret_provider_id || "";
}

async function loadSecretProviderLeases(providerId) {
  const result = qs("#secretProviderLeaseResult");
  const table = qs("#secretProviderLeasesTable");
  const resolvedProviderId = String(providerId || qs("#secretProviderHealthForm")?.elements?.provider_id?.value || "").trim();
  if (!resolvedProviderId) {
    if (result) result.textContent = "Provider ID is required.";
    return;
  }
  if (table) setTableMessage(table, 7, "Loading...");
  try {
    const data = await api(`/secrets/providers/${encodeURIComponent(resolvedProviderId)}/leases`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    const rows = Array.isArray(data?.leases) ? data.leases : [];
    if (!table) return;
    if (!rows.length) {
      setTableMessage(table, 7, "No active leases found.");
      if (result) result.textContent = `No active leases found for ${safeText(resolvedProviderId)}.`;
      return;
    }
    table.textContent = "";
    rows.forEach((row) => {
      appendTableRow(table, [
        row.lease_id,
        row.secret_ref,
        row.lease_ttl_seconds,
        formatComplianceDate(row.issued_at),
        formatComplianceDate(row.renewed_at),
        formatComplianceDate(row.expires_at),
        row.status,
      ]);
    });
    if (result) result.textContent = `Loaded ${rows.length} active leases for ${safeText(resolvedProviderId)}.`;
  } catch (err) {
    if (table) setTableMessage(table, 7, `Error: ${safeText(err.message)}`);
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function renewSecretProviderLease(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#secretProviderLeaseResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const providerId = String(raw.provider_id || "").trim();
  if (!providerId) {
    if (result) result.textContent = "Provider ID is required.";
    return;
  }
  try {
    const data = await api(`/secrets/providers/${encodeURIComponent(providerId)}/leases/renew`, {
      method: "POST",
      body: JSON.stringify({
        secret_ref: String(raw.secret_ref || "").trim(),
        requested_ttl_seconds: Number(raw.requested_ttl_seconds || 3600),
      }),
    });
    if (result) {
      result.textContent = `Lease ${safeText(data.lease_id)} renewed for ${safeText(data.secret_provider_id)}; expires ${safeText(data.expires_at)}.`;
    }
    await Promise.all([loadSecretProviders(), loadSecretProviderLeases(providerId)]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadSecretProviderHealth(providerId) {
  const result = qs("#secretProviderLeaseResult");
  const resolvedProviderId = String(providerId || qs("#secretProviderHealthForm")?.elements?.provider_id?.value || "").trim();
  if (!resolvedProviderId) {
    if (result) result.textContent = "Provider ID is required.";
    return;
  }
  try {
    const data = await api(`/secrets/providers/${encodeURIComponent(resolvedProviderId)}/health`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (result) {
      result.textContent = `Secret provider ${safeText(data.secret_provider_id)} health ${safeText(data.status)}; active leases ${safeText(data.lease_count_active)}, expiring soon ${safeText(data.leases_expiring_5m)}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function submitSecretProviderHealthForm(evt) {
  evt.preventDefault();
  await loadSecretProviderHealth();
}

async function handleSecretProviderLeasesClick() {
  await loadSecretProviderLeases();
}

async function rotateKeyViaSecretProvider(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#rotateViaSecretProviderResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const keyId = String(raw.key_id || "").trim();
  const environment = String(raw.environment || "dev").trim();
  if (!keyId) {
    if (result) result.textContent = "Key ID is required.";
    return;
  }
  try {
    const payload = await api(`/keys/${encodeURIComponent(keyId)}/rotate-via-secret-provider?environment=${encodeURIComponent(environment)}`, {
      method: "POST",
    });
    if (result) {
      result.textContent = `Rotation delegated for ${safeText(payload.key_id)} in ${safeText(payload.environment)} (${safeText(payload.rotation_status)}).`;
    }
    await loadKeys();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function createSecretProvider(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#createSecretProviderResult");
  const raw = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/secrets/providers", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        provider_type: String(raw.provider_type || "").trim().toLowerCase(),
        provider_address: String(raw.provider_address || "").trim(),
        auth_method: String(raw.auth_method || "").trim(),
        role_or_mount: String(raw.role_or_mount || "").trim(),
        bootstrap_token: String(raw.bootstrap_token || "").trim(),
        secret_path_prefixes: String(raw.secret_path_prefixes || "[]").trim(),
        lease_ttl_seconds: Number(raw.lease_ttl_seconds || 3600),
        auto_renew_enabled: parseBooleanFlag(raw.auto_renew_enabled, true),
      }),
    });
    if (result) result.textContent = `Created secret provider ${safeText(data?.secret_provider_id)}.`;
    form.reset();
    refreshTenantBoundForms();
    await Promise.all([loadSecretProviders(), loadProviderTypeOptions(), loadRegisterAgentTypeOptions()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadSupportedModels(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#supportedModelFilters");
  const tbody = qs("#supportedModelsTable");
  const result = qs("#supportedModelsResult");
  if (!form || !tbody) return;

  const payload = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    tenant_id: payload.tenant_id,
    provider_type: payload.provider_type,
    status: payload.status,
    limit: payload.limit,
    offset: payload.offset,
  });

  setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api(`/providers/models${query}`, { headers: { "X-Actor-Role": "Auditor" } });
    if (result) result.textContent = `Loaded ${rows.length} supported models.`;
    if (!rows?.length) {
      setTableMessage(tbody, 8, "No supported models found.");
      return;
    }

    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.provider_type);
      appendTableCell(tr, row.model_name);
      appendTableCell(tr, row.display_name);
      appendTableCell(tr, row.context_window_tokens);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.description);
      appendTableCell(tr, row.updated_at);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "ghost";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", () => populateSupportedModelForm(row));
      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "ghost";
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", () => deleteSupportedModel(row.supported_model_id));
      actionsCell.append(editBtn, deleteBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

function resetSupportedModelForm(message = "") {
  const form = qs("#supportedModelForm");
  if (!form) return;
  form.reset();
  form.elements.supported_model_id.value = "";
  form.elements.context_window_tokens.value = "128000";
  form.elements.status.value = "active";
  const result = qs("#supportedModelsResult");
  if (result) result.textContent = message;
}

function populateSupportedModelForm(row) {
  const form = qs("#supportedModelForm");
  if (!form || !row) return;

  form.elements.supported_model_id.value = row.supported_model_id || "";
  form.elements.provider_type.value = row.provider_type || "";
  form.elements.model_name.value = row.model_name || "";
  form.elements.display_name.value = row.display_name || "";
  form.elements.context_window_tokens.value = String(row.context_window_tokens || 128000);
  form.elements.status.value = row.status || "active";
  form.elements.description.value = row.description || "";
  const result = qs("#supportedModelsResult");
  if (result) result.textContent = `Editing ${row.model_name}`;
}

async function saveSupportedModel(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#supportedModelsResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const supportedModelId = String(raw.supported_model_id || "").trim();
  const payload = {
    provider_type: String(raw.provider_type || "").trim().toLowerCase(),
    model_name: String(raw.model_name || "").trim(),
    display_name: String(raw.display_name || "").trim(),
    context_window_tokens: Number(raw.context_window_tokens || 128000),
    status: String(raw.status || "active").trim().toLowerCase(),
    description: String(raw.description || "").trim(),
  };

  try {
    const path = supportedModelId ? `/providers/models/${encodeURIComponent(supportedModelId)}` : "/providers/models";
    const method = supportedModelId ? "PUT" : "POST";
    await api(path, { method, body: JSON.stringify(payload) });
    resetSupportedModelForm(`Saved supported model ${payload.model_name}.`);
    await Promise.all([loadSupportedModels(), loadSupportedModelOptions(payload.provider_type, payload.model_name)]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deleteSupportedModel(supportedModelId) {
  const result = qs("#supportedModelsResult");
  if (!supportedModelId) return;
  try {
    await api(`/providers/models/${encodeURIComponent(supportedModelId)}`, { method: "DELETE" });
    if (result) result.textContent = "Supported model deleted.";
    await Promise.all([loadSupportedModels(), loadSupportedModelOptions()]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadTenantModelEntitlements(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#tenantModelEntitlementFilters");
  const tbody = qs("#tenantModelEntitlementsTable");
  const result = qs("#tenantModelEntitlementsResult");
  if (!form || !tbody) return;

  const payload = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    tenant_id: payload.tenant_id,
    provider_type: payload.provider_type,
    status: payload.status,
    limit: payload.limit,
    offset: payload.offset,
  });

  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api(`/providers/tenant-model-entitlements${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (result) result.textContent = `Loaded ${rows.length} entitlements.`;
    if (!rows?.length) {
      setTableMessage(tbody, 6, "No tenant model entitlements found.");
      return;
    }

    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.tenant_id);
      appendTableCell(tr, row.provider_type);
      appendTableCell(tr, row.model_name);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.updated_at);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "ghost";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", () => populateTenantModelEntitlementForm(row));

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "ghost";
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", () => deleteTenantModelEntitlement(row.tenant_model_entitlement_id));

      actionsCell.append(editBtn, deleteBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

function resetTenantModelEntitlementForm(message = "") {
  const form = qs("#tenantModelEntitlementForm");
  const result = qs("#tenantModelEntitlementsResult");
  if (!form) return;
  form.reset();
  form.elements.tenant_model_entitlement_id.value = "";
  form.elements.status.value = "active";
  if (result) result.textContent = message;
}

function populateTenantModelEntitlementForm(row) {
  const form = qs("#tenantModelEntitlementForm");
  const result = qs("#tenantModelEntitlementsResult");
  if (!form || !row) return;

  form.elements.tenant_model_entitlement_id.value = row.tenant_model_entitlement_id || "";
  form.elements.tenant_id.value = row.tenant_id || "";
  form.elements.provider_type.value = row.provider_type || "";
  form.elements.model_name.value = row.model_name || "";
  form.elements.status.value = row.status || "active";
  if (result) result.textContent = `Editing entitlement ${row.tenant_id} / ${row.model_name}`;
}

async function saveTenantModelEntitlement(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#tenantModelEntitlementsResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const entitlementId = String(raw.tenant_model_entitlement_id || "").trim();

  const payload = {
    tenant_id: String(raw.tenant_id || "").trim(),
    provider_type: String(raw.provider_type || "").trim().toLowerCase(),
    model_name: String(raw.model_name || "").trim(),
    status: String(raw.status || "active").trim().toLowerCase(),
  };

  try {
    const path = entitlementId
      ? `/providers/tenant-model-entitlements/${encodeURIComponent(entitlementId)}`
      : "/providers/tenant-model-entitlements";
    const method = entitlementId ? "PUT" : "POST";
    await api(path, { method, body: JSON.stringify(payload) });
    resetTenantModelEntitlementForm(`Saved entitlement ${payload.tenant_id} / ${payload.model_name}.`);
    await Promise.all([
      loadTenantModelEntitlements(),
      loadSupportedModels(),
      loadSupportedModelOptions(payload.provider_type, payload.model_name),
    ]);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deleteTenantModelEntitlement(entitlementId) {
  const result = qs("#tenantModelEntitlementsResult");
  if (!entitlementId) return;
  try {
    await api(`/providers/tenant-model-entitlements/${encodeURIComponent(entitlementId)}`, { method: "DELETE" });
    if (result) result.textContent = "Tenant model entitlement deleted.";
    await loadTenantModelEntitlements();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadProviderConsole() {
  await loadTenantCatalog();
  await Promise.all([
    loadProviderTypeOptions(),
    loadRegisterAgentTypeOptions(),
    loadWorkloadIdentityProviders(),
    loadSecretProviders(),
    loadSupportedModels(),
    loadTenantModelEntitlements(),
  ]);
}

function populateModuleForms(row) {
  const versionsForm = qs("#moduleVersionsForm");
  const validateForm = qs("#moduleValidateForm");
  const planForm = qs("#moduleUpgradePlanForm");
  const deprecateForm = qs("#moduleDeprecateForm");
  if (versionsForm) versionsForm.elements.module_id.value = row.module_id || "";
  if (validateForm) {
    validateForm.elements.module_id.value = row.module_id || "";
    validateForm.elements.pinned_version.value = row.version || "";
  }
  if (planForm) {
    planForm.elements.module_id.value = row.module_id || "";
    planForm.elements.pinned_version.value = row.version || "";
  }
  if (deprecateForm) deprecateForm.elements.module_id.value = row.module_id || "";
}

function renderModuleRows() {
  const tbody = qs("#modulesTable");
  if (!tbody) return;
  if (!moduleRows.length) {
    setTableMessage(tbody, 7, "No modules found.");
    return;
  }
  tbody.textContent = "";
  moduleRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.module_id);
    appendTableCell(tr, row.module_name);
    appendTableCell(tr, row.module_type);
    appendTableCell(tr, row.version);
    appendTableCell(tr, row.status);
    appendTableCell(tr, row.owner_team);

    const actionsCell = document.createElement("td");
    actionsCell.className = "cell-actions";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => populateModuleForms(row));

    const versionsBtn = document.createElement("button");
    versionsBtn.type = "button";
    versionsBtn.className = "ghost";
    versionsBtn.textContent = "Versions";
    versionsBtn.addEventListener("click", () => loadModuleVersions(row.module_id));

    actionsCell.append(useBtn, versionsBtn);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  });
}

async function loadModules(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#moduleRegisterResult");
  const tbody = qs("#modulesTable");
  if (tbody) setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/modules", { headers: { "X-Actor-Role": "Auditor" } });
    moduleRows = Array.isArray(rows) ? rows : [];
    renderModuleRows();
    if (result) result.textContent = `Loaded ${moduleRows.length} modules.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function registerModule(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#moduleRegisterResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {
    module_name: String(raw.module_name || "").trim(),
    module_type: String(raw.module_type || "").trim().toLowerCase(),
    version: String(raw.version || "").trim(),
    contract_version: String(raw.contract_version || "").trim(),
    owner_team: String(raw.owner_team || "").trim(),
    compatibility_range: String(raw.compatibility_range || "*").trim() || "*",
    required_permissions: String(raw.required_permissions || "[]").trim(),
    artifact_signature: String(raw.artifact_signature || "").trim(),
    provenance_ref: String(raw.provenance_ref || "").trim(),
    security_review_ticket: String(raw.security_review_ticket || "").trim(),
  };
  try {
    const module = await api("/modules/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (result) result.textContent = `Registered module ${safeText(module.module_id)} (${safeText(module.module_name)}).`;
    await loadModules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadModuleVersions(moduleId) {
  const result = qs("#moduleVersionsResult");
  const resolvedId = String(moduleId || qs("#moduleVersionsForm")?.elements?.module_id?.value || "").trim();
  if (!resolvedId) {
    if (result) result.textContent = "Module ID is required.";
    return;
  }
  try {
    const data = await api(`/modules/${encodeURIComponent(resolvedId)}/versions`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    const versions = Array.isArray(data.versions) ? data.versions.join(", ") : "--";
    if (result) result.textContent = `Versions for ${safeText(resolvedId)}: ${safeText(versions)}`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function submitModuleVersionsForm(evt) {
  evt.preventDefault();
  await loadModuleVersions();
}

function moduleActionPayloadFromForm(form) {
  const raw = Object.fromEntries(new FormData(form).entries());
  return {
    agent_id: String(raw.agent_id || "").trim(),
    body: {
      module_id: String(raw.module_id || "").trim(),
      pinned_version: String(raw.pinned_version || "").trim(),
      config_hash: String(raw.config_hash || "").trim(),
    },
  };
}

async function validateModuleForAgent(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#moduleValidateResult");
  const payload = moduleActionPayloadFromForm(form);
  if (!payload.agent_id || !payload.body.module_id || !payload.body.pinned_version || !payload.body.config_hash) {
    if (result) result.textContent = "Agent ID, module ID, pinned version, and config hash are required.";
    return;
  }
  try {
    const data = await api(`/agents/${encodeURIComponent(payload.agent_id)}/modules/validate`, {
      method: "POST",
      body: JSON.stringify(payload.body),
    });
    if (result) result.textContent = `Validation ${safeText(data.validation_status)} for agent ${safeText(data.agent_id)}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function planModuleUpgrade(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#moduleUpgradePlanResult");
  const payload = moduleActionPayloadFromForm(form);
  if (!payload.agent_id || !payload.body.module_id || !payload.body.pinned_version || !payload.body.config_hash) {
    if (result) result.textContent = "Agent ID, module ID, pinned version, and config hash are required.";
    return;
  }
  try {
    const data = await api(`/agents/${encodeURIComponent(payload.agent_id)}/modules/upgrade-plan`, {
      method: "POST",
      body: JSON.stringify(payload.body),
    });
    if (result) {
      result.textContent = `Upgrade plan ${safeText(data.plan_status)}: ${safeText(data.from_version)} -> ${safeText(data.to_version)}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function deprecateModule(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#moduleDeprecateResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const moduleId = String(raw.module_id || "").trim();
  if (!moduleId) {
    if (result) result.textContent = "Module ID is required.";
    return;
  }
  const payload = {
    migration_guidance: String(raw.migration_guidance || "").trim(),
    deprecation_timeline: String(raw.deprecation_timeline || "").trim(),
    replacement_module_id: String(raw.replacement_module_id || "").trim() || null,
  };
  try {
    const data = await api(`/modules/${encodeURIComponent(moduleId)}/deprecate`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (result) result.textContent = `Deprecated module ${safeText(data.module_id)}.`;
    await loadModules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadModulesConsole() {
  await loadModules();
}

function renderAgenticCertificationRows() {
  const tbody = qs("#agenticCertificationsTable");
  if (!tbody) return;
  if (!agenticCertificationRows.length) {
    setTableMessage(tbody, 7, "No certifications found.");
    return;
  }
  tbody.textContent = "";
  agenticCertificationRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.certification_id);
    appendTableCell(tr, row.target_capacity);
    appendTableCell(tr, row.readiness_score);
    appendTableCell(tr, row.certified ? "yes" : "no");
    appendTableCell(tr, row.executed_by);
    appendTableCell(tr, row.created_at);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const actionForm = qs("#agenticCertificationActionForm");
      if (actionForm) actionForm.elements.certification_id.value = row.certification_id || "";
    });
    const exportBtn = document.createElement("button");
    exportBtn.type = "button";
    exportBtn.className = "ghost";
    exportBtn.textContent = "Export";
    exportBtn.addEventListener("click", () => runAgenticCertificationAction("export", row.certification_id));
    actions.append(useBtn, exportBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderAgenticLoadTestRows() {
  const tbody = qs("#agenticLoadTestsTable");
  if (!tbody) return;
  if (!agenticLoadTestRows.length) {
    setTableMessage(tbody, 8, "No load test runs found.");
    return;
  }
  tbody.textContent = "";
  agenticLoadTestRows.forEach((row) => {
    appendTableRow(tbody, [
      row.load_test_run_id,
      row.tier,
      row.target_capacity,
      row.observed_peak_concurrency,
      row.observed_peak_rps,
      row.passed ? "yes" : "no",
      row.executed_by,
      formatComplianceDate(row.created_at),
    ]);
  });
}

function renderAgenticCheckpointRows() {
  const tbody = qs("#agenticCheckpointsTable");
  if (!tbody) return;
  if (!agenticCheckpointRows.length) {
    setTableMessage(tbody, 8, "No checkpoints found.");
    return;
  }
  tbody.textContent = "";
  agenticCheckpointRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.checkpoint_id);
    appendTableCell(tr, row.session_id);
    appendTableCell(tr, row.agent_id);
    appendTableCell(tr, row.stage_name);
    appendTableCell(tr, row.status);
    appendTableCell(tr, row.resume_count);
    appendTableCell(tr, row.created_by);
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const form = qs("#agenticCheckpointActionForm");
      if (!form) return;
      form.elements.session_id.value = row.session_id || "";
      form.elements.checkpoint_id.value = row.checkpoint_id || "";
    });
    const resumeBtn = document.createElement("button");
    resumeBtn.type = "button";
    resumeBtn.className = "ghost";
    resumeBtn.textContent = "Resume";
    resumeBtn.addEventListener("click", () => resumeAgenticCheckpoint(row.checkpoint_id));
    actions.append(useBtn, resumeBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderPolicyScheduleRows() {
  const tbody = qs("#policySchedulesTable");
  if (!tbody) return;
  if (!policyScheduleRows.length) {
    setTableMessage(tbody, 7, "No policy schedules found.");
    return;
  }
  tbody.textContent = "";
  policyScheduleRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.job_id);
    appendTableCell(tr, row.name);
    appendTableCell(tr, row.environment);
    appendTableCell(tr, row.optimize_for);
    appendTableCell(tr, row.enabled ? "yes" : "no");
    appendTableCell(tr, row.last_run_at || "--");
    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const actionForm = qs("#policyScheduleActionForm");
      if (actionForm) actionForm.elements.job_id.value = row.job_id || "";
      const updateForm = qs("#policyScheduleUpdateForm");
      if (updateForm) updateForm.elements.job_id.value = row.job_id || "";
    });
    const detailBtn = document.createElement("button");
    detailBtn.type = "button";
    detailBtn.className = "ghost";
    detailBtn.textContent = "Detail";
    detailBtn.addEventListener("click", () => loadPolicyScheduleDetail(row.job_id));
    const historyBtn = document.createElement("button");
    historyBtn.type = "button";
    historyBtn.className = "ghost";
    historyBtn.textContent = "History";
    historyBtn.addEventListener("click", () => loadPolicyScheduleHistory(row.job_id));
    actions.append(useBtn, detailBtn, historyBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderPolicyScheduleHistoryRows() {
  const tbody = qs("#policyScheduleHistoryTable");
  if (!tbody) return;
  if (!policyScheduleHistoryRows.length) {
    setTableMessage(tbody, 5, "No schedule history loaded.");
    return;
  }
  tbody.textContent = "";
  policyScheduleHistoryRows.forEach((row) => {
    appendTableRow(tbody, [row.timestamp, row.action_type, row.actor_id, row.decision_outcome, row.trace_id]);
  });
}

async function loadAgenticReadinessReport(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#agenticReadinessResult");
  try {
    const data = await api("/agentic/readiness/report", { headers: { "X-Actor-Role": "Auditor" } });
    if (result) {
      result.textContent = `Score ${safeText(data.readiness_score)} | controls ${safeText(data.controls_status)} | certified ${data.scale_tier3_certified ? "yes" : "no"} | recommendation: ${safeText(data.recommendation)}`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function validateAgenticContract(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agenticContractValidateResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/contracts/validate", {
      method: "POST",
      body: JSON.stringify({
        agent_id: String(raw.agent_id || "").trim(),
        route_policy_snapshot_id: String(raw.route_policy_snapshot_id || "").trim(),
        module_ids: parseListInput(raw.module_ids),
        required_capabilities: parseListInput(raw.required_capabilities),
      }),
    });
    if (result) result.textContent = `Contract validation ${safeText(data.status)}: ${safeText(data.checks_passed)} passed, ${safeText(data.checks_failed)} failed.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runAgenticCertification(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agenticRunCertificationResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/readiness/certifications/run", {
      method: "POST",
      body: JSON.stringify({
        target_capacity: Number(raw.target_capacity || 100000),
        require_multi_region: parseBooleanFlag(raw.require_multi_region, true),
        cost_freshness_slo_seconds: Number(raw.cost_freshness_slo_seconds || 60),
      }),
    });
    if (result) result.textContent = `Certification ${safeText(data.certification_id)}: certified=${data.certified ? "yes" : "no"}, score=${safeText(data.readiness_score)}.`;
    await loadAgenticCertifications();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadAgenticCertifications(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#agenticRunCertificationResult");
  const tbody = qs("#agenticCertificationsTable");
  if (tbody) setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/agentic/readiness/certifications?limit=20", { headers: { "X-Actor-Role": "Auditor" } });
    agenticCertificationRows = Array.isArray(rows) ? rows : [];
    renderAgenticCertificationRows();
    if (result) result.textContent = `Loaded ${agenticCertificationRows.length} certifications.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadLatestAgenticCertification() {
  const result = qs("#agenticRunCertificationResult");
  try {
    const row = await api("/agentic/readiness/certifications/latest", { headers: { "X-Actor-Role": "Auditor" } });
    agenticCertificationRows = row ? [row] : [];
    renderAgenticCertificationRows();
    if (result) result.textContent = row ? `Loaded latest certification ${safeText(row.certification_id)}.` : "No latest certification.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runAgenticCertificationAction(actionArg, certificationIdArg) {
  const form = qs("#agenticCertificationActionForm");
  const result = qs("#agenticCertificationActionResult");
  const details = qs("#agenticCertificationActionDetails");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const action = String(actionArg || raw.action || "export").trim();
  const certificationId = String(certificationIdArg || raw.certification_id || "").trim();
  if (!certificationId) {
    result.textContent = "Certification ID is required.";
    return;
  }
  try {
    if (action === "override") {
      const data = await api(`/agentic/readiness/certifications/${encodeURIComponent(certificationId)}/override`, {
        method: "POST",
        body: JSON.stringify({ reason_code: String(raw.reason_code || "operator override").trim() }),
      });
      if (details) details.textContent = JSON.stringify(data, null, 2);
      result.textContent = `Override applied to ${safeText(data.certification_id)} by ${safeText(data.override_by)}.`;
      await loadAgenticCertifications();
      return;
    }
    const data = await api(`/agentic/readiness/certifications/${encodeURIComponent(certificationId)}/export`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (details) details.textContent = JSON.stringify(data, null, 2);
    result.textContent = `Export generated ${safeText(data.export_id)} with ${safeText(data.audit_event_count)} evidence events.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function submitAgenticCertificationActionForm(evt) {
  evt.preventDefault();
  await runAgenticCertificationAction();
}

async function runAgenticLoadTest(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agenticLoadTestResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/readiness/load-tests/run", {
      method: "POST",
      body: JSON.stringify({
        tier: String(raw.tier || "tier3").trim(),
        target_capacity: Number(raw.target_capacity || 100000),
        expected_concurrency: Number(raw.expected_concurrency || 1200),
        expected_rps: Number(raw.expected_rps || 4200),
        observed_peak_concurrency: Number(raw.observed_peak_concurrency || 0),
        observed_peak_rps: Number(raw.observed_peak_rps || 0),
        degradation_test_pass: parseBooleanFlag(raw.degradation_test_pass, true),
        recovery_test_pass: parseBooleanFlag(raw.recovery_test_pass, true),
        compliance_continuity_pass: parseBooleanFlag(raw.compliance_continuity_pass, true),
      }),
    });
    agenticLoadTestRows = [data, ...agenticLoadTestRows.filter((row) => row.load_test_run_id !== data.load_test_run_id)].slice(0, 25);
    renderAgenticLoadTestRows();
    if (result) result.textContent = `Load test ${safeText(data.load_test_run_id)} ${data.passed ? "passed" : "warn"}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadLatestAgenticLoadTest() {
  const form = qs("#agenticLoadTestRunForm");
  const result = qs("#agenticLoadTestResult");
  const tier = String(new FormData(form).get("tier") || "").trim();
  const query = buildQueryString({ tier });
  try {
    const data = await api(`/agentic/readiness/load-tests/latest${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    agenticLoadTestRows = data ? [data] : [];
    renderAgenticLoadTestRows();
    if (result) result.textContent = data ? `Loaded latest load test ${safeText(data.load_test_run_id)}.` : "No load test found.";
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function createAgenticCheckpoint(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agenticCheckpointResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/checkpoints", {
      method: "POST",
      body: JSON.stringify({
        session_id: String(raw.session_id || "").trim(),
        agent_id: String(raw.agent_id || "").trim(),
        stage_name: String(raw.stage_name || "").trim(),
        state_payload: String(raw.state_payload || "{}").trim(),
      }),
    });
    if (result) result.textContent = `Created checkpoint ${safeText(data.checkpoint_id)}.`;
    const actionForm = qs("#agenticCheckpointActionForm");
    if (actionForm) {
      actionForm.elements.session_id.value = data.session_id || "";
      actionForm.elements.checkpoint_id.value = data.checkpoint_id || "";
    }
    await loadAgenticCheckpoints(data.session_id);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadAgenticCheckpoints(sessionIdArg) {
  const form = qs("#agenticCheckpointActionForm");
  const result = qs("#agenticCheckpointResult");
  const sessionId = String(sessionIdArg || new FormData(form).get("session_id") || "").trim();
  const table = qs("#agenticCheckpointsTable");
  if (!sessionId) {
    if (result) result.textContent = "Session ID is required.";
    return;
  }
  if (table) setTableMessage(table, 8, "Loading...");
  try {
    const rows = await api(`/agentic/checkpoints/${encodeURIComponent(sessionId)}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    agenticCheckpointRows = Array.isArray(rows) ? rows : [];
    renderAgenticCheckpointRows();
    if (result) result.textContent = `Loaded ${agenticCheckpointRows.length} checkpoints for ${safeText(sessionId)}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (table) setTableMessage(table, 8, `Error: ${safeText(err.message)}`);
  }
}

async function resumeAgenticCheckpoint(checkpointIdArg) {
  const form = qs("#agenticCheckpointActionForm");
  const result = qs("#agenticCheckpointResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const checkpointId = String(checkpointIdArg || raw.checkpoint_id || "").trim();
  if (!checkpointId) {
    result.textContent = "Checkpoint ID is required.";
    return;
  }
  try {
    const data = await api(`/agentic/checkpoints/${encodeURIComponent(checkpointId)}/resume`, {
      method: "POST",
      body: JSON.stringify({ reason_code: String(raw.reason_code || "operator resume").trim() }),
    });
    result.textContent = `Resumed checkpoint ${safeText(data.checkpoint_id)} (count ${safeText(data.resume_count)}).`;
    await loadAgenticCheckpoints(data.session_id);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runAgenticPolicyAutoTune(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agenticPolicyAutoTuneResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/policy/auto-tune", {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "prod").trim(),
        optimize_for: String(raw.optimize_for || "balanced").trim(),
        max_routes: Number(raw.max_routes || 10),
        dry_run: parseBooleanFlag(raw.dry_run, true),
      }),
    });
    if (result) {
      result.textContent = `Auto tune ${data.dry_run ? "dry-run" : "apply"}: evaluated ${safeText(data.total_routes_evaluated)}, changed ${safeText(data.total_routes_changed)}, controls ${safeText(data.controls_status)}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function createPolicySchedule(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#policySchedulesResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/policy/schedules", {
      method: "POST",
      body: JSON.stringify({
        name: String(raw.name || "").trim(),
        environment: String(raw.environment || "prod").trim(),
        optimize_for: String(raw.optimize_for || "balanced").trim(),
        max_routes: Number(raw.max_routes || 10),
        window_start_hour_utc: Number(raw.window_start_hour_utc || 0),
        window_end_hour_utc: Number(raw.window_end_hour_utc || 0),
        max_changes_without_approval: Number(raw.max_changes_without_approval || 3),
        enabled: parseBooleanFlag(raw.enabled, true),
      }),
    });
    if (result) result.textContent = `Created schedule ${safeText(data.job_id)}.`;
    await loadPolicySchedules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runPolicyScheduledOptimize(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#policySchedulesResult");
  const detail = qs("#policyScheduleDetailResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/agentic/policy/scheduled-optimize", {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "prod").trim(),
        optimize_for: String(raw.optimize_for || "balanced").trim(),
        max_routes: Number(raw.max_routes || 10),
        window_start_hour_utc: Number(raw.window_start_hour_utc || 0),
        window_end_hour_utc: Number(raw.window_end_hour_utc || 0),
        max_changes_without_approval: Number(raw.max_changes_without_approval || 3),
        approval_token: String(raw.approval_token || "").trim() || null,
        dry_run: parseBooleanFlag(raw.dry_run, true),
      }),
    });
    if (result) {
      result.textContent = `Scheduled optimize ${safeText(data.execution_status)}: proposed ${safeText(data.proposed_changes)}, applied ${safeText(data.applied_changes)}.`;
    }
    if (detail) detail.textContent = JSON.stringify(data, null, 2);
    await loadPolicySchedules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadPolicyScheduleSummary(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#policyScheduleSummaryFilters");
  const result = qs("#policyScheduleSummaryResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Loading schedule summary...";
  try {
    const query = buildQueryString({
      environment: raw.environment,
      optimize_for: raw.optimize_for,
      enabled: raw.enabled,
      dual_approval_ready: raw.dual_approval_ready,
    });
    const data = await api(`/agentic/policy/schedules/summary${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    result.textContent = `Summary: total ${safeText(data.total_schedules)}, enabled ${safeText(data.enabled_schedules)}, disabled ${safeText(data.disabled_schedules)}, dual-ready ${safeText(data.dual_approval_ready_schedules)}, pending-dual ${safeText(data.pending_dual_approval_schedules)}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadPolicyScheduleDetail(jobId) {
  const resolvedJobId = String(jobId || qs("#policyScheduleUpdateForm")?.elements?.job_id?.value || "").trim();
  const result = qs("#policySchedulesResult");
  const detail = qs("#policyScheduleDetailResult");
  if (!resolvedJobId) {
    if (result) result.textContent = "Job ID is required.";
    return;
  }
  try {
    const data = await api(`/agentic/policy/schedules/${encodeURIComponent(resolvedJobId)}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    const updateForm = qs("#policyScheduleUpdateForm");
    if (updateForm) {
      updateForm.elements.job_id.value = data.job_id || "";
      updateForm.elements.name.value = data.name || "";
      updateForm.elements.environment.value = data.environment || "";
      updateForm.elements.optimize_for.value = data.optimize_for || "";
      updateForm.elements.max_routes.value = Number(data.max_routes || 10);
      updateForm.elements.window_start_hour_utc.value = Number(data.window_start_hour_utc || 0);
      updateForm.elements.window_end_hour_utc.value = Number(data.window_end_hour_utc || 0);
      updateForm.elements.max_changes_without_approval.value = Number(data.max_changes_without_approval || 3);
      updateForm.elements.enabled.value = String(Boolean(data.enabled));
    }
    if (detail) detail.textContent = JSON.stringify(data, null, 2);
    if (result) result.textContent = `Loaded detail for ${safeText(resolvedJobId)}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function updatePolicySchedule(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#policySchedulesResult");
  const detail = qs("#policyScheduleDetailResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const jobId = String(raw.job_id || "").trim();
  if (!jobId) {
    if (result) result.textContent = "Job ID is required.";
    return;
  }

  const payload = {};
  ["name", "environment", "optimize_for"].forEach((key) => {
    const value = String(raw[key] || "").trim();
    if (value) payload[key] = value;
  });
  ["max_routes", "window_start_hour_utc", "window_end_hour_utc", "max_changes_without_approval"].forEach((key) => {
    const value = String(raw[key] || "").trim();
    if (value !== "") payload[key] = Number(value);
  });
  const enabledText = String(raw.enabled || "").trim();
  if (enabledText) payload.enabled = parseBooleanFlag(enabledText, true);

  if (!Object.keys(payload).length) {
    if (result) result.textContent = "Provide at least one field to update.";
    return;
  }

  try {
    const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    if (result) result.textContent = `Updated schedule ${safeText(data.job_id)}.`;
    if (detail) detail.textContent = JSON.stringify(data, null, 2);
    await loadPolicySchedules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadPolicySchedules(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#policySchedulesResult");
  const tbody = qs("#policySchedulesTable");
  if (tbody) setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/agentic/policy/schedules?limit=100", { headers: { "X-Actor-Role": "Auditor" } });
    policyScheduleRows = Array.isArray(rows) ? rows : [];
    renderPolicyScheduleRows();
    if (result) result.textContent = `Loaded ${policyScheduleRows.length} policy schedules.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadPolicyScheduleHistory(jobId) {
  const result = qs("#policySchedulesResult");
  const tbody = qs("#policyScheduleHistoryTable");
  const resolvedJobId = String(jobId || qs("#policyScheduleActionForm")?.elements?.job_id?.value || "").trim();
  if (!resolvedJobId) {
    if (result) result.textContent = "Job ID is required.";
    return;
  }
  if (tbody) setTableMessage(tbody, 5, "Loading...");
  try {
    const rows = await api(`/agentic/policy/schedules/${encodeURIComponent(resolvedJobId)}/history?limit=50`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    policyScheduleHistoryRows = Array.isArray(rows) ? rows : [];
    renderPolicyScheduleHistoryRows();
    if (result) result.textContent = `Loaded ${policyScheduleHistoryRows.length} history events for ${safeText(resolvedJobId)}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
  }
}

async function runPolicyScheduleAction(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#policySchedulesResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const jobId = String(raw.job_id || "").trim();
  const action = String(raw.action || "status").trim();
  if (!jobId) {
    if (result) result.textContent = "Job ID is required.";
    return;
  }

  try {
    if (action === "status") {
      const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}/status`, {
        headers: { "X-Actor-Role": "Auditor" },
      });
      if (result) {
        result.textContent = `Status for ${safeText(jobId)}: enabled=${data.enabled ? "yes" : "no"}, dual_ready=${data.dual_approval_ready ? "yes" : "no"}, pending_dual=${data.pending_dual_approval ? "yes" : "no"}.`;
      }
    } else if (action === "history") {
      await loadPolicyScheduleHistory(jobId);
      return;
    } else if (action === "approve") {
      const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}/approve`, {
        method: "POST",
        body: JSON.stringify({ reason_code: String(raw.reason_code || "").trim() || null }),
      });
      if (result) result.textContent = `Approval recorded: ${safeText(data.approval_action)} by ${safeText(data.approved_by)}.`;
    } else if (action === "execute-now") {
      const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}/execute-now`, {
        method: "POST",
        body: JSON.stringify({
          dry_run: parseBooleanFlag(raw.dry_run, false),
          approval_token: String(raw.approval_token || "").trim() || null,
        }),
      });
      if (result) result.textContent = `Execute-now ${safeText(data.execution_status)}; proposed=${safeText(data.proposed_changes)}, applied=${safeText(data.applied_changes)}.`;
    } else if (action === "enable" || action === "disable") {
      const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}/${action}`, { method: "POST" });
      if (result) result.textContent = `Schedule ${safeText(data.job_id)} ${action}d.`;
    } else if (action === "delete") {
      const query = buildQueryString({ idempotent: raw.idempotent });
      const data = await api(`/agentic/policy/schedules/${encodeURIComponent(jobId)}${query}`, { method: "DELETE" });
      if (result) result.textContent = `Delete action completed for ${safeText(data.job_id)}: deleted=${data.deleted ? "true" : "false"}.`;
    }
    await loadPolicySchedules();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadAgenticConsole() {
  await Promise.all([loadAgenticReadinessReport(), loadAgenticCertifications(), loadPolicySchedules(), loadPolicyScheduleSummary()]);
}

function normalizeSpendBreakdownDimension(value) {
  const normalized = String(value || "all").trim().toLowerCase();
  if (["all", "user", "group", "team", "request_tag"].includes(normalized)) return normalized;
  return "all";
}

function normalizeSpendRange(value) {
  const normalized = String(value || "1d").trim().toLowerCase();
  if (["1d", "1w", "1m", "1y", "custom"].includes(normalized)) return normalized;
  return "1d";
}

function isoDateToday() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function isoDateMinusDays(days) {
  const ts = new Date();
  ts.setDate(ts.getDate() - Math.max(0, Number(days) || 0));
  const year = ts.getFullYear();
  const month = String(ts.getMonth() + 1).padStart(2, "0");
  const day = String(ts.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function compactDateLabel(rawIso) {
  const ts = new Date(rawIso);
  if (Number.isNaN(ts.getTime())) return "--";
  const month = String(ts.getMonth() + 1).padStart(2, "0");
  const day = String(ts.getDate()).padStart(2, "0");
  return `${month}/${day}`;
}

function shortBucketLabel(rawIso, bucketCount) {
  if (bucketCount > 72) return compactDateLabel(rawIso);
  return shortHourLabel(rawIso);
}

function collapseTimeseriesPoints(points, maxBars = 96) {
  const rows = Array.isArray(points) ? points : [];
  if (rows.length <= maxBars) return rows;

  const step = Math.ceil(rows.length / maxBars);
  const collapsed = [];

  for (let idx = 0; idx < rows.length; idx += step) {
    const chunk = rows.slice(idx, idx + step);
    if (!chunk.length) continue;
    collapsed.push({
      hour_start: chunk[0].hour_start,
      spend_cents: chunk.reduce((sum, item) => sum + Number(item?.spend_cents || 0), 0),
      event_count: chunk.reduce((sum, item) => sum + Number(item?.event_count || 0), 0),
    });
  }

  return collapsed;
}

function updateSpendFilterControls() {
  const dimensionSelector = qs("#spendBreakdownDimension");
  const rangeSelector = qs("#spendBreakdownRange");
  const scopeInput = qs("#spendBreakdownScopeFilter");
  const scopeLabel = qs("#spendBreakdownScopeLabel");
  const customRange = qs("#spendBreakdownCustomRange");
  const startDate = qs("#spendBreakdownStartDate");
  const endDate = qs("#spendBreakdownEndDate");
  const startTime = qs("#spendBreakdownStartTime");
  const endTime = qs("#spendBreakdownEndTime");
  if (!dimensionSelector || !rangeSelector || !scopeInput || !scopeLabel || !customRange || !startDate || !endDate || !startTime || !endTime) return;

  const dimension = normalizeSpendBreakdownDimension(dimensionSelector.value);
  const range = normalizeSpendRange(rangeSelector.value);
  const switchedToCustom = range === "custom" && lastSpendRangeSelection !== "custom";

  const scopeMap = {
    all: { label: "Filter", placeholder: "Not used for All", disabled: true },
    user: { label: "Username", placeholder: "Filter by username", disabled: false },
    team: { label: "Team Name", placeholder: "Filter by team name", disabled: false },
    group: { label: "Group Name", placeholder: "Filter by group name", disabled: false },
    request_tag: { label: "Request Tag", placeholder: "Filter by request tag", disabled: false },
  };
  const scopeSettings = scopeMap[dimension] || scopeMap.all;
  scopeLabel.textContent = scopeSettings.label;
  scopeInput.placeholder = scopeSettings.placeholder;
  scopeInput.disabled = scopeSettings.disabled;
  if (scopeSettings.disabled) scopeInput.value = "";

  customRange.hidden = range !== "custom";
  const today = isoDateToday();
  if (!endDate.value) endDate.value = today;
  if (!startDate.value) startDate.value = isoDateMinusDays(6);
  if (!startTime.value) startTime.value = "00:00";
  if (!endTime.value) endTime.value = "23:59";

  if (switchedToCustom) {
    const end = new Date();
    const start = new Date(end.getTime() - 60 * 60 * 1000);
    const formatDate = (ts) => {
      const year = ts.getFullYear();
      const month = String(ts.getMonth() + 1).padStart(2, "0");
      const day = String(ts.getDate()).padStart(2, "0");
      return `${year}-${month}-${day}`;
    };
    const formatTime = (ts) => {
      const hour = String(ts.getHours()).padStart(2, "0");
      const minute = String(ts.getMinutes()).padStart(2, "0");
      return `${hour}:${minute}`;
    };

    startDate.value = formatDate(start);
    endDate.value = formatDate(end);
    startTime.value = formatTime(start);
    endTime.value = formatTime(end);
  }

  if (startDate.value > endDate.value) {
    startDate.value = endDate.value;
  }

  lastSpendRangeSelection = range;
}

function spendRangeLabel(range, startDate, endDate) {
  if (range === "1d") return "1 day";
  if (range === "1w") return "1 week";
  if (range === "1m") return "1 month";
  if (range === "1y") return "1 year";
  return `${startDate} to ${endDate}`;
}

function shortHourLabel(rawIso) {
  const ts = new Date(rawIso);
  if (Number.isNaN(ts.getTime())) return "--";
  const hour = ts.getHours();
  return `${String(hour).padStart(2, "0")}:00`;
}

function setSpendInsights(lines) {
  const target = qs("#spendBreakdownInsights");
  if (!target) return;
  target.textContent = "";
  (lines || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    target.appendChild(li);
  });
}

function buildSpendInsights(response) {
  const points = Array.isArray(response?.points) ? response.points : [];
  if (!points.length) {
    return ["No spend activity in the selected window."];
  }

  const total = Number(response?.total_spend_cents || 0);
  const events = Number(response?.total_event_count || 0);
  const sortedBySpend = [...points].sort((a, b) => Number(b.spend_cents || 0) - Number(a.spend_cents || 0));
  const peak = sortedBySpend[0];
  const peakShare = total > 0 ? (Number(peak?.spend_cents || 0) / total) * 100 : 0;

  const last = points[points.length - 1] || { spend_cents: 0, hour_start: "--" };
  const prev = points[points.length - 2] || { spend_cents: 0, hour_start: "--" };
  const delta = Number(last.spend_cents || 0) - Number(prev.spend_cents || 0);
  const trend = delta > 0 ? "up" : delta < 0 ? "down" : "flat";

  const avgPerEvent = events > 0 ? total / events : 0;

  return [
    `Peak spend hour: ${shortHourLabel(peak?.hour_start)} at ${currency(Number(peak?.spend_cents || 0))} (${peakShare.toFixed(1)}% of window spend).`,
    `Recent hourly trend is ${trend} (${delta >= 0 ? "+" : ""}${currency(delta)} vs previous hour).`,
    `Average spend per event is ${currency(avgPerEvent)} across ${events} events.`,
  ];
}

function renderSpendBreakdownChart(payload) {
  const target = qs("#spendBreakdownChart");
  if (!target) return;
  target.textContent = "";

  const points = Array.isArray(payload?.points) ? payload.points : [];
  if (!points.length) {
    const empty = document.createElement("p");
    empty.className = "spend-breakdown-empty";
    empty.textContent = "No hourly spend data available for the selected view.";
    target.appendChild(empty);
    setSpendInsights(["No spend activity in the selected window."]);
    return;
  }

  const pointsToRender = collapseTimeseriesPoints(points, 96);
  const maxSpend = Math.max(...pointsToRender.map((item) => Number(item?.spend_cents || 0)), 1);

  const width = 920;
  const height = 280;
  const margin = { top: 16, right: 16, bottom: 52, left: 58 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const step = plotWidth / Math.max(pointsToRender.length, 1);
  const barWidth = Math.max(8, step * 0.62);

  const svgNs = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("class", "spend-breakdown-svg");

  const defs = document.createElementNS(svgNs, "defs");
  const gradient = document.createElementNS(svgNs, "linearGradient");
  gradient.setAttribute("id", "spendBreakdownGradient");
  gradient.setAttribute("x1", "0%");
  gradient.setAttribute("y1", "0%");
  gradient.setAttribute("x2", "0%");
  gradient.setAttribute("y2", "100%");
  const stopTop = document.createElementNS(svgNs, "stop");
  stopTop.setAttribute("offset", "0%");
  stopTop.setAttribute("stop-color", "#6ef3d6");
  const stopBottom = document.createElementNS(svgNs, "stop");
  stopBottom.setAttribute("offset", "100%");
  stopBottom.setAttribute("stop-color", "#4d8dff");
  gradient.append(stopTop, stopBottom);
  defs.appendChild(gradient);
  svg.appendChild(defs);

  const axisX = document.createElementNS(svgNs, "line");
  axisX.setAttribute("x1", String(margin.left));
  axisX.setAttribute("y1", String(height - margin.bottom));
  axisX.setAttribute("x2", String(width - margin.right));
  axisX.setAttribute("y2", String(height - margin.bottom));
  axisX.setAttribute("class", "spend-breakdown-axis");
  svg.appendChild(axisX);

  const axisY = document.createElementNS(svgNs, "line");
  axisY.setAttribute("x1", String(margin.left));
  axisY.setAttribute("y1", String(margin.top));
  axisY.setAttribute("x2", String(margin.left));
  axisY.setAttribute("y2", String(height - margin.bottom));
  axisY.setAttribute("class", "spend-breakdown-axis");
  svg.appendChild(axisY);

  const ticks = 4;
  for (let idx = 0; idx <= ticks; idx += 1) {
    const y = margin.top + (plotHeight * idx) / ticks;
    const valueCents = Math.round(maxSpend * (1 - idx / ticks));

    const grid = document.createElementNS(svgNs, "line");
    grid.setAttribute("x1", String(margin.left));
    grid.setAttribute("y1", String(y));
    grid.setAttribute("x2", String(width - margin.right));
    grid.setAttribute("y2", String(y));
    grid.setAttribute("class", "spend-breakdown-grid");
    svg.appendChild(grid);

    const label = document.createElementNS(svgNs, "text");
    label.setAttribute("x", String(margin.left - 8));
    label.setAttribute("y", String(y + 4));
    label.setAttribute("text-anchor", "end");
    label.setAttribute("class", "spend-breakdown-y-label");
    label.textContent = currency(valueCents);
    svg.appendChild(label);
  }

  const labelStep = Math.max(1, Math.ceil(pointsToRender.length / 8));
  pointsToRender.forEach((point, idx) => {
    const spend = Number(point?.spend_cents || 0);
    const xCenter = margin.left + step * idx + step / 2;
    const barHeight = (spend / maxSpend) * plotHeight;
    const barY = height - margin.bottom - barHeight;

    const rect = document.createElementNS(svgNs, "rect");
    rect.setAttribute("x", String(xCenter - barWidth / 2));
    rect.setAttribute("y", String(barY));
    rect.setAttribute("width", String(barWidth));
    rect.setAttribute("height", String(Math.max(1, barHeight)));
    rect.setAttribute("rx", "2");
    rect.setAttribute("class", "spend-breakdown-bar");
    svg.appendChild(rect);

    if (idx % labelStep === 0 || idx === pointsToRender.length - 1) {
      const xLabel = document.createElementNS(svgNs, "text");
      xLabel.setAttribute("x", String(xCenter));
      xLabel.setAttribute("y", String(height - margin.bottom + 16));
      xLabel.setAttribute("text-anchor", "middle");
      xLabel.setAttribute("class", "spend-breakdown-x-label");
      xLabel.textContent = shortBucketLabel(point?.hour_start, pointsToRender.length);
      svg.appendChild(xLabel);
    }
  });

  target.appendChild(svg);
  setSpendInsights(buildSpendInsights(payload));
}

async function loadSpendBreakdown() {
  const selector = qs("#spendBreakdownDimension");
  const rangeSelector = qs("#spendBreakdownRange");
  const scopeInput = qs("#spendBreakdownScopeFilter");
  const startDateInput = qs("#spendBreakdownStartDate");
  const endDateInput = qs("#spendBreakdownEndDate");
  const startTimeInput = qs("#spendBreakdownStartTime");
  const endTimeInput = qs("#spendBreakdownEndTime");
  const summary = qs("#spendBreakdownSummary");
  if (!selector || !rangeSelector || !scopeInput || !summary) return;

  const dimension = normalizeSpendBreakdownDimension(selector.value);
  const range = normalizeSpendRange(rangeSelector.value);
  const hoursMap = { "1d": 24, "1w": 24 * 7, "1m": 24 * 30, "1y": 24 * 365 };
  const scopeFilter = String(scopeInput.value || "").trim();

  const query = {
    dimension,
  };

  if (range === "custom") {
    const startDate = String(startDateInput?.value || "").trim();
    const endDate = String(endDateInput?.value || "").trim();
    const startTime = String(startTimeInput?.value || "").trim();
    const endTime = String(endTimeInput?.value || "").trim();
    if (!startDate || !endDate || !startTime || !endTime) {
      summary.textContent = "Choose start/end date and time for custom range.";
      renderSpendBreakdownChart({ points: [] });
      setSpendInsights(["Pick a full date range to calculate spend insights."]);
      return;
    }
    const startDateTime = `${startDate}T${startTime}:00`;
    const endDateTime = `${endDate}T${endTime}:59`;
    if (startDateTime > endDateTime) {
      summary.textContent = "Start date/time must be earlier than end date/time.";
      renderSpendBreakdownChart({ points: [] });
      setSpendInsights(["Fix date order to load hourly spend insights."]);
      return;
    }
    query.start_datetime = startDateTime;
    query.end_datetime = endDateTime;
  } else {
    query.window_hours = String(hoursMap[range] || 24);
  }

  if (dimension !== "all" && scopeFilter) {
    query.scope_filter = scopeFilter;
  }

  summary.textContent = "Loading spend vs hours...";

  try {
    const response = await api(`/cost/timeseries${buildQueryString(query)}`);
    renderSpendBreakdownChart(response);
    const startDate = String(startDateInput?.value || "").trim();
    const endDate = String(endDateInput?.value || "").trim();
    const startTime = String(startTimeInput?.value || "").trim();
    const endTime = String(endTimeInput?.value || "").trim();
    const rangeText = range === "custom" ? `${startDate} ${startTime} to ${endDate} ${endTime}` : spendRangeLabel(range, startDate, endDate);
    const scopeText =
      dimension === "all"
        ? "all"
        : `${safeText(response?.dimension || dimension)}${scopeFilter ? ` (${safeText(scopeFilter)})` : ""}`;
    summary.textContent = `${rangeText} spend vs hours for ${scopeText}. Total: ${currency(response?.total_spend_cents)} across ${safeText(response?.total_event_count)} events.`;
  } catch (err) {
    renderSpendBreakdownChart({ points: [] });
    setSpendInsights(["Unable to compute spend insights until timeseries data is available."]);
    summary.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadCost() {
  try {
    const cost = await api("/cost/live");
    qs("#costHour").textContent = currency(cost?.spend_last_hour_cents);
    qs("#costDay").textContent = currency(cost?.spend_last_day_cents);
    qs("#costEvents").textContent = String(cost?.event_count_last_day ?? "--");
  } catch (err) {
    qs("#costHour").textContent = "--";
    qs("#costDay").textContent = "--";
    qs("#costEvents").textContent = "--";
  }
}

async function loadGatewayAnalytics(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayAnalyticsFilters");
  const result = qs("#gatewayAnalyticsResult");
  const topModels = qs("#gatewayTopModelsTable");
  const topEndpoints = qs("#gatewayTopEndpointTable");
  if (!form || !result || !topModels || !topEndpoints) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    environment: raw.environment,
    hours: raw.hours,
  });

  setTableMessage(topModels, 3, "Loading...");
  setTableMessage(topEndpoints, 3, "Loading...");

  try {
    const data = await api(`/gateway/analytics/summary${query}`);
    qs("#gatewayEvents").textContent = safeText(data?.total_events);
    qs("#gatewayRequests").textContent = safeText(data?.distinct_requests);
    qs("#gatewayCost").textContent = currency(Number(data?.total_estimated_cost_cents || 0));
    qs("#gatewayAvgInput").textContent = Number(data?.avg_input_tokens || 0).toFixed(1);
    qs("#gatewayAvgOutput").textContent = Number(data?.avg_output_tokens || 0).toFixed(1);
    qs("#gatewayWindowHours").textContent = safeText(data?.hours);
    result.textContent = `Loaded gateway analytics for ${safeText(data?.environment || "all environments")} in ${safeText(data?.hours)}h window.`;

    const modelRows = Array.isArray(data?.top_models) ? data.top_models : [];
    if (!modelRows.length) {
      setTableMessage(topModels, 3, "No model analytics found.");
    } else {
      topModels.textContent = "";
      modelRows.forEach((row) => appendTableRow(topModels, [row.model_name, row.events, row.cost_cents]));
    }

    const endpointRows = Array.isArray(data?.top_endpoint_families) ? data.top_endpoint_families : [];
    if (!endpointRows.length) {
      setTableMessage(topEndpoints, 3, "No endpoint analytics found.");
    } else {
      topEndpoints.textContent = "";
      endpointRows.forEach((row) => appendTableRow(topEndpoints, [row.endpoint_family, row.events, row.cost_cents]));
    }
  } catch (err) {
    qs("#gatewayEvents").textContent = "--";
    qs("#gatewayRequests").textContent = "--";
    qs("#gatewayCost").textContent = "--";
    qs("#gatewayAvgInput").textContent = "--";
    qs("#gatewayAvgOutput").textContent = "--";
    qs("#gatewayWindowHours").textContent = "--";
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(topModels, 3, `Error: ${safeText(err.message)}`);
    setTableMessage(topEndpoints, 3, `Error: ${safeText(err.message)}`);
  }
}

function renderCostBudgetRows() {
  const tbody = qs("#costBudgetTable");
  if (!tbody) return;
  if (!costBudgetRows.length) {
    setTableMessage(tbody, 8, "No budget policies found.");
    return;
  }
  tbody.textContent = "";
  costBudgetRows.forEach((row) => {
    const tr = document.createElement("tr");
    const effectiveBudget = Number(row.effective_budget_cents || row.budget_amount_cents || 0);
    const temporaryIncrease = Number(row.temporary_increase_cents || 0);
    const resetTimezone = String(row.reset_timezone || "UTC");
    const resetHour = Number(row.reset_hour_local ?? 0);
    const controlsSummary = [
      `reset ${resetTimezone}@${String(resetHour).padStart(2, "0")}:00`,
      temporaryIncrease > 0 ? `temp +${temporaryIncrease}c` : "temp none",
      row.soft_alert_enabled ? "soft alert on" : "soft alert off",
      row.rate_limit_tpm ? `tpm ${row.rate_limit_tpm}` : "tpm --",
      row.rate_limit_rpm ? `rpm ${row.rate_limit_rpm}` : "rpm --",
      row.session_iteration_cap ? `iter ${row.session_iteration_cap}` : "iter --",
      row.session_budget_cents ? `session ${row.session_budget_cents}c` : "session --",
    ].join("; ");
    [
      row.budget_policy_id,
      `${row.scope_type}:${row.scope_id}`,
      `${row.budget_amount_cents}c`,
      row.window_type,
      `${row.soft_limit_percent}% / ${row.hard_limit_percent}% (effective ${effectiveBudget}c)`,
      controlsSummary,
      row.status,
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });

    const actions = document.createElement("td");
    actions.className = "cell-actions";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const form = qs("#costBudgetForm");
      const result = qs("#costBudgetResult");
      if (!form) return;
      form.elements.budget_policy_id.value = row.budget_policy_id || "";
      form.elements.scope_type.value = row.scope_type || "actor";
      form.elements.scope_id.value = row.scope_id || "";
      form.elements.budget_amount_cents.value = Number(row.budget_amount_cents || 0);
      form.elements.window_type.value = row.window_type || "daily";
      form.elements.soft_limit_percent.value = Number(row.soft_limit_percent || 75);
      form.elements.hard_limit_percent.value = Number(row.hard_limit_percent || 95);
      form.elements.action_on_soft_limit.value = row.action_on_soft_limit || "notify";
      form.elements.action_on_hard_limit.value = row.action_on_hard_limit || "block";
      form.elements.reset_timezone.value = String(row.reset_timezone || "UTC");
      form.elements.reset_hour_local.value = Number(row.reset_hour_local ?? 0);
      form.elements.temporary_increase_cents.value = Number(row.temporary_increase_cents || 0);
      form.elements.temporary_increase_expires_at.value = toDatetimeLocalValue(row.temporary_increase_expires_at);
      form.elements.soft_alert_enabled.value = row.soft_alert_enabled ? "true" : "false";
      form.elements.rate_limit_tpm.value = row.rate_limit_tpm ?? "";
      form.elements.rate_limit_rpm.value = row.rate_limit_rpm ?? "";
      form.elements.session_iteration_cap.value = row.session_iteration_cap ?? "";
      form.elements.session_budget_cents.value = row.session_budget_cents ?? "";
      if (result) result.textContent = `Loaded budget policy ${row.budget_policy_id} into form.`;
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "ghost";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", async () => {
      const result = qs("#costBudgetResult");
      const approved = window.confirm(`Delete budget policy ${row.budget_policy_id}?`);
      if (!approved) return;
      if (result) result.textContent = `Deleting budget policy ${row.budget_policy_id}...`;
      try {
        await api(`/cost/budgets/${encodeURIComponent(row.budget_policy_id)}`, { method: "DELETE" });
        await loadCostBudgetPolicies();
        if (result) result.textContent = `Deleted budget policy ${row.budget_policy_id}.`;
      } catch (err) {
        if (result) result.textContent = `Error: ${safeText(err.message)}`;
      }
    });

    actions.append(useBtn, deleteBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function resetCostBudgetForm(message) {
  const form = qs("#costBudgetForm");
  const result = qs("#costBudgetResult");
  if (!form) return;
  form.reset();
  form.elements.budget_policy_id.value = "";
  form.elements.scope_type.value = "actor";
  form.elements.scope_id.value = state.actorId || "ui-operator";
  form.elements.budget_amount_cents.value = 5000;
  form.elements.window_type.value = "daily";
  form.elements.soft_limit_percent.value = 75;
  form.elements.hard_limit_percent.value = 95;
  form.elements.action_on_soft_limit.value = "notify";
  form.elements.action_on_hard_limit.value = "block";
  form.elements.reset_timezone.value = "UTC";
  form.elements.reset_hour_local.value = 0;
  form.elements.temporary_increase_cents.value = 0;
  form.elements.temporary_increase_expires_at.value = "";
  form.elements.soft_alert_enabled.value = "true";
  form.elements.rate_limit_tpm.value = "";
  form.elements.rate_limit_rpm.value = "";
  form.elements.session_iteration_cap.value = "";
  form.elements.session_budget_cents.value = "";
  syncScopeIdPicker("#costBudgetForm", "scope_type", "scope_id", "costBudgetScopeIdList");
  if (result && message) result.textContent = message;
}

function toDatetimeLocalValue(rawValue) {
  if (!rawValue) return "";
  const parsed = new Date(rawValue);
  if (Number.isNaN(parsed.getTime())) return "";
  const localMs = parsed.getTime() - parsed.getTimezoneOffset() * 60 * 1000;
  return new Date(localMs).toISOString().slice(0, 16);
}

function parseOptionalInteger(rawValue) {
  const text = String(rawValue ?? "").trim();
  if (!text) return null;
  const value = Number(text);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.round(value);
}

function parseOptionalDateTime(rawValue) {
  const text = String(rawValue ?? "").trim();
  if (!text) return null;
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function parseOptionalFloat(rawValue) {
  const text = String(rawValue ?? "").trim();
  if (!text) return null;
  const value = Number(text);
  if (!Number.isFinite(value) || value < 0) return null;
  return value;
}

async function loadCostPricingCatalog() {
  const result = qs("#costPricingCatalogResult");
  if (!result) return;
  result.textContent = "Loading pricing catalog...";
  try {
    const data = await api("/cost/pricing/catalog");
    const providerCount = Object.keys(data?.provider_multipliers || {}).length;
    const modelCount = Object.keys(data?.model_rates || {}).length;
    const discountCount = Object.keys(data?.provider_discounts || {}).length;
    result.textContent = `Loaded pricing catalog: ${providerCount} provider multipliers, ${modelCount} model rate entries, ${discountCount} provider discount entries.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function calculateCostPricing(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#costPricingCalculatorForm");
  const result = qs("#costPricingCalculatorResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Calculating...";
  try {
    const data = await api("/cost/pricing/calculate", {
      method: "POST",
      body: JSON.stringify({
        provider_type: String(raw.provider_type || "").trim(),
        model_name: String(raw.model_name || "").trim(),
        endpoint_family: String(raw.endpoint_family || "responses").trim(),
        input_tokens: Number(raw.input_tokens || 0),
        output_tokens: Number(raw.output_tokens || 0),
        custom_input_cents_per_1k: parseOptionalFloat(raw.custom_input_cents_per_1k),
        custom_output_cents_per_1k: parseOptionalFloat(raw.custom_output_cents_per_1k),
        custom_provider_discount_percent: parseOptionalFloat(raw.custom_provider_discount_percent),
      }),
    });
    result.textContent = `Estimated ${data.estimated_cost_cents} cents (base ${data.base_cost_cents} cents). Rates in/out: ${data.input_cents_per_1k}/${data.output_cents_per_1k} c/1k. Multipliers provider/endpoint: ${data.provider_multiplier}/${data.endpoint_multiplier}. Applied discount: ${data.applied_discount_percent}%.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function trackSpendEvent(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#costSpendTrackForm");
  const result = qs("#costSpendTrackResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Tracking spend event...";
  try {
    const data = await api("/cost/events", {
      method: "POST",
      body: JSON.stringify({
        request_id: String(raw.request_id || "").trim(),
        trace_id: String(raw.trace_id || "").trim() || null,
        request_tag: String(raw.request_tag || "").trim() || null,
        session_id: String(raw.session_id || "").trim(),
        agent_id: String(raw.agent_id || "").trim(),
        scope_type: String(raw.scope_type || "actor").trim(),
        scope_id: String(raw.scope_id || "").trim(),
        environment: String(raw.environment || "dev").trim(),
        model_name: String(raw.model_name || "").trim(),
        endpoint_family: String(raw.endpoint_family || "responses").trim(),
        input_tokens: Number(raw.input_tokens || 0),
        output_tokens: Number(raw.output_tokens || 0),
        estimated_cost_cents: Number(raw.estimated_cost_cents || 0),
        currency: String(raw.currency || "USD").trim(),
      }),
    });
    result.textContent = `Tracked cost event ${data.cost_event_id} (${data.estimated_cost_cents} cents).`;
    await loadCost();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadCostBudgetPolicies() {
  const tbody = qs("#costBudgetTable");
  const result = qs("#costBudgetResult");
  if (!tbody) return;
  setTableMessage(tbody, 8, "Loading...");
  if (result) result.textContent = "Loading budget policies...";
  try {
    const rows = await api("/cost/budgets?status=active&limit=100&offset=0");
    costBudgetRows = Array.isArray(rows) ? rows : [];
    renderCostBudgetRows();
    if (result) result.textContent = `Loaded ${costBudgetRows.length} active budget policies.`;
  } catch (err) {
    costBudgetRows = [];
    setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveCostBudgetPolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#costBudgetForm");
  const result = qs("#costBudgetResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const policyId = String(raw.budget_policy_id || "").trim();
  const method = policyId ? "PUT" : "POST";
  const path = policyId ? `/cost/budgets/${encodeURIComponent(policyId)}` : "/cost/budgets";
  result.textContent = `${policyId ? "Updating" : "Saving"} budget policy...`;
  try {
    const row = await api(path, {
      method,
      body: JSON.stringify({
        scope_type: String(raw.scope_type || "actor").trim(),
        scope_id: String(raw.scope_id || "").trim(),
        budget_amount_cents: Number(raw.budget_amount_cents || 0),
        window_type: String(raw.window_type || "daily").trim(),
        soft_limit_percent: Number(raw.soft_limit_percent || 75),
        hard_limit_percent: Number(raw.hard_limit_percent || 95),
        action_on_soft_limit: String(raw.action_on_soft_limit || "notify").trim(),
        action_on_hard_limit: String(raw.action_on_hard_limit || "block").trim(),
        reset_timezone: String(raw.reset_timezone || "UTC").trim() || "UTC",
        reset_hour_local: Number(raw.reset_hour_local || 0),
        temporary_increase_cents: Number(raw.temporary_increase_cents || 0),
        temporary_increase_expires_at: parseOptionalDateTime(raw.temporary_increase_expires_at),
        soft_alert_enabled: String(raw.soft_alert_enabled || "true").trim().toLowerCase() !== "false",
        rate_limit_tpm: parseOptionalInteger(raw.rate_limit_tpm),
        rate_limit_rpm: parseOptionalInteger(raw.rate_limit_rpm),
        session_iteration_cap: parseOptionalInteger(raw.session_iteration_cap),
        session_budget_cents: parseOptionalInteger(raw.session_budget_cents),
      }),
    });
    await loadCostBudgetPolicies();
    result.textContent = `${policyId ? "Updated" : "Saved"} budget policy ${row.budget_policy_id}.`;
    resetCostBudgetForm();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function evaluateCostPolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#costPolicyEvalForm");
  const result = qs("#costPolicyEvalResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Evaluating policy...";
  try {
    const data = await api("/cost/policies/evaluate", {
      method: "POST",
      body: JSON.stringify({
        scope_type: String(raw.scope_type || "actor").trim(),
        scope_id: String(raw.scope_id || "").trim(),
        window_type: String(raw.window_type || "daily").trim(),
      }),
    });
    const softAlertText = data.soft_limit_alert ? " Soft alert triggered." : "";
    result.textContent = `Decision ${data.decision}. Utilization ${data.utilization_percent}% (${data.spend_cents}/${data.effective_budget_cents || data.budget_cents} cents effective, base ${data.budget_cents} cents). Recommended action: ${data.recommended_action}.${softAlertText}`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderCostLimitRows() {
  const tbody = qs("#costLimitTable");
  if (!tbody) return;
  if (!latestCostLimitRows.length) {
    setTableMessage(tbody, 9, "No limit evaluation results yet.");
    return;
  }
  tbody.textContent = "";
  latestCostLimitRows.forEach((row) => {
    appendTableRow(tbody, [
      `${row.scope_type}:${row.scope_id}`,
      row.policy_id || "--",
      row.spend_cents,
      row.budget_cents,
      row.effective_budget_cents,
      row.utilization_percent,
      row.decision,
      row.recommended_action,
      row.soft_limit_alert ? "yes" : "no",
    ]);
  });
}

async function evaluateCostLimits(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#costLimitEvalForm");
  const result = qs("#costLimitEvalResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Evaluating aggregated limits...";
  try {
    const data = await api("/cost/limits/evaluate", {
      method: "POST",
      body: JSON.stringify({
        actor_id: String(raw.actor_id || "").trim() || undefined,
        team_ids: parseListInput(raw.team_ids),
        group_ids: parseListInput(raw.group_ids),
        agent_ids: parseListInput(raw.agent_ids),
        window_type: String(raw.window_type || "daily").trim(),
        projected_additional_cost_cents: Number(raw.projected_additional_cost_cents || 0),
      }),
    });
    latestCostLimitRows = Array.isArray(data?.scopes_evaluated) ? data.scopes_evaluated : [];
    renderCostLimitRows();
    const softAlerts = Array.isArray(data.soft_alert_scopes) && data.soft_alert_scopes.length ? data.soft_alert_scopes.join(", ") : "none";
    result.textContent = `Aggregated decision: ${data.aggregated_decision}. Blocking scopes: ${Array.isArray(data.blocking_scopes) && data.blocking_scopes.length ? data.blocking_scopes.join(", ") : "none"}. Soft-alert scopes: ${softAlerts}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadCostAnomalies() {
  const tbody = qs("#costAnomaliesTable");
  if (!tbody) return;
  setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/cost/anomalies");
    if (!rows?.length) {
      setTableMessage(tbody, 7, "No anomalies detected.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      appendTableRow(tbody, [
        row.anomaly_id,
        row.anomaly_type,
        row.severity,
        `${row.scope_type}:${row.scope_id}`,
        row.observed_cost_cents,
        row.threshold_cents,
        formatComplianceDate(row.detected_at),
      ]);
    });
  } catch (err) {
    setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function loadCostDrilldown(kind) {
  const form = qs("#costDrilldownForm");
  const result = qs("#costDrilldownResult");
  const tbody = qs("#costDrilldownTable");
  if (!form || !result || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const sessionId = String(raw.session_id || "").trim();
  const agentId = String(raw.agent_id || "").trim();
  const path = kind === "session"
    ? `/cost/sessions/${encodeURIComponent(sessionId)}`
    : `/cost/agents/${encodeURIComponent(agentId)}`;
  const targetText = kind === "session" ? sessionId : agentId;
  if (!targetText) {
    result.textContent = `${kind === "session" ? "Session" : "Agent"} ID is required.`;
    return;
  }

  result.textContent = `Loading ${kind} cost events for ${targetText}...`;
  setTableMessage(tbody, 9, "Loading...");
  try {
    const rows = await api(path);
    if (!rows?.length) {
      setTableMessage(tbody, 9, "No cost events found.");
      result.textContent = `No cost events found for ${targetText}.`;
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      appendTableRow(tbody, [
        formatComplianceDate(row.timestamp),
        row.request_id,
        row.request_tag || "--",
        row.trace_id,
        row.model_name,
        row.endpoint_family,
        row.input_tokens,
        row.output_tokens,
        row.estimated_cost_cents,
      ]);
    });
    result.textContent = `Loaded ${rows.length} ${kind} cost events for ${targetText}.`;
  } catch (err) {
    setTableMessage(tbody, 9, `Error: ${safeText(err.message)}`);
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderRoutePriorityReadback(data) {
  const table = qs("#routePriorityTable");
  if (!table) return;
  const order = parseJsonOrFallback(data?.priority_order, []);
  if (!Array.isArray(order) || !order.length) {
    setTableMessage(table, 3, "No provider priority entries configured.");
    return;
  }
  table.textContent = "";
  order.forEach((row) => {
    appendTableRow(table, [row.provider_id, row.model_name || "--", row.priority]);
  });
}

function renderRouteProviderHealth(data) {
  const table = qs("#routeProviderHealthTable");
  if (!table) return;
  const rows = Array.isArray(data?.entries) ? data.entries : [];
  if (!rows.length) {
    setTableMessage(table, 5, "No provider health entries configured.");
    return;
  }
  table.textContent = "";
  rows.forEach((row) => {
    appendTableRow(table, [
      row.provider_id || "--",
      row.status || "healthy",
      row.latency_ms ?? "--",
      row.error_rate_percent ?? "--",
      row.checked_at || "--",
    ]);
  });
}

function updateRoutePriorityScopeLabel(requestTag) {
  const target = qs("#routePriorityScope");
  if (!target) return;
  const normalized = String(requestTag || "").trim();
  target.textContent = normalized ? `request_tag:${normalized}` : "default";
}

function renderRoutePriorityTimeline(data) {
  const table = qs("#routePriorityTimelineTable");
  if (!table) return;
  const events = Array.isArray(data?.events) ? data.events : [];
  if (!events.length) {
    setTableMessage(table, 6, "No timeline events found.");
    return;
  }
  table.textContent = "";
  events.forEach((event) => {
    appendTableRow(table, [
      formatComplianceDate(event.timestamp),
      event.actor_id,
      event.action_type,
      event.decision_outcome,
      event.policy_version,
      event.trace_id,
    ]);
  });
}

async function loadRoutePriorityTimeline(evt, routePolicyId) {
  if (evt?.preventDefault) evt.preventDefault();
  const priorityForm = qs("#routePriorityForm");
  const timelineForm = qs("#routePriorityTimelineForm");
  const result = qs("#routePriorityResult");
  const table = qs("#routePriorityTimelineTable");
  if (!priorityForm || !timelineForm || !result || !table) return;

  const priorityRaw = Object.fromEntries(new FormData(priorityForm).entries());
  const timelineRaw = Object.fromEntries(new FormData(timelineForm).entries());
  const id = String(routePolicyId || priorityRaw.route_policy_id || "").trim();
  if (!id) {
    result.textContent = "Route policy ID is required to load timeline.";
    return;
  }

  const limit = String(timelineRaw.limit || "25").trim();
  const offset = String(timelineRaw.offset || "0").trim();
  setTableMessage(table, 6, "Loading...");
  try {
    const query = buildQueryString({ limit, offset });
    const data = await api(`/gateway/routes/${encodeURIComponent(id)}/providers/priority/timeline${query}`);
    renderRoutePriorityTimeline(data);
    result.textContent = `Loaded priority timeline for ${id} (${Array.isArray(data?.events) ? data.events.length : 0} events).`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(table, 6, `Error: ${safeText(err.message)}`);
  }
}

async function loadRoutePriorityReadback(routePolicyId) {
  const form = qs("#routePriorityForm");
  const result = qs("#routePriorityResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const id = String(routePolicyId || raw.route_policy_id || "").trim();
  const requestTag = String(raw.request_tag || "").trim();
  if (!id) {
    result.textContent = "Route policy ID is required to load priority.";
    return;
  }

  result.textContent = `Loading priority for ${id}...`;
  try {
    const query = buildQueryString({ request_tag: requestTag || null });
    const data = await api(`/gateway/routes/${encodeURIComponent(id)}/providers/priority${query}`);
    form.elements.route_policy_id.value = id;
    form.elements.tenant_id.value = data.tenant_id || "";
    form.elements.environment.value = data.environment || "prod";
    form.elements.request_tag.value = data.request_tag || requestTag || "";
    form.elements.priority_order.value = data.priority_order || "[]";
    form.elements.global_timeout_ms.value = data.global_timeout_ms ?? 4500;
    form.elements.max_fallback_hops.value = data.max_fallback_hops ?? 2;
    if (form.elements.budget_limit_cents) form.elements.budget_limit_cents.value = data.budget_limit_cents ?? "";
    if (form.elements.health_check_enabled) form.elements.health_check_enabled.value = String(Boolean(data.health_check_enabled));
    updateRoutePriorityScopeLabel(data.request_tag || requestTag || "");
    renderRoutePriorityReadback(data);
    await loadRoutePriorityTimeline(null, id);
    result.textContent = `Loaded provider priority for ${id}.`;
  } catch (err) {
    updateRoutePriorityScopeLabel("");
    result.textContent = `Error: ${safeText(err.message)}`;
    const table = qs("#routePriorityTable");
    if (table) setTableMessage(table, 3, `Error: ${safeText(err.message)}`);
  }
}

async function loadRouteProviderHealth() {
  const form = qs("#routeProviderHealthForm");
  const result = qs("#routeProviderHealthResult");
  const table = qs("#routeProviderHealthTable");
  if (!form || !result || !table) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required to load provider health.";
    return;
  }

  setTableMessage(table, 5, "Loading...");
  result.textContent = `Loading provider health for ${routePolicyId}...`;
  try {
    const query = buildQueryString({ request_tag: String(raw.request_tag || "").trim() || null });
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/providers/health${query}`);
    renderRouteProviderHealth(data);
    result.textContent = `Loaded ${Array.isArray(data?.entries) ? data.entries.length : 0} provider health rows.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(table, 5, `Error: ${safeText(err.message)}`);
  }
}

async function saveRouteProviderHealth(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#routeProviderHealthResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    if (result) result.textContent = "Route policy ID is required.";
    return;
  }

  const entries = parseJsonOrFallback(String(raw.entries || "[]"), []);
  if (!Array.isArray(entries)) {
    if (result) result.textContent = "Entries must be a JSON array.";
    return;
  }

  try {
    await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/providers/health`, {
      method: "PUT",
      body: JSON.stringify({
        request_tag: String(raw.request_tag || "").trim() || null,
        entries,
      }),
    });
    if (result) result.textContent = `Saved provider health for ${routePolicyId}.`;
    await loadRouteProviderHealth();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayCacheStats() {
  const result = qs("#gatewayCacheStatsResult");
  if (!result) return;
  result.textContent = "Loading cache stats...";
  try {
    const data = await api("/gateway/cache/stats");
    result.textContent = `Cache hit ratio ${safeText(data.hit_ratio)} across ${safeText(data.eligible_requests)} eligible requests.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayCacheHealth() {
  const result = qs("#gatewayCacheHealthResult");
  if (!result) return;
  result.textContent = "Loading cache health...";
  try {
    const data = await api("/gateway/cache/health");
    result.textContent = `Cache ${safeText(data.status)} on ${safeText(data.cache_backend)} backend; ${safeText(data.active_policies)} active policies, ${safeText(data.invalidation_requests_last_24h)} invalidation requests in the last 24h.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderGatewayCachePolicies() {
  const table = qs("#gatewayCachePoliciesTable");
  if (!table) return;
  if (!gatewayCachePolicyRows.length) {
    setTableMessage(table, 8, "No cache policies found.");
    return;
  }

  table.textContent = "";
  gatewayCachePolicyRows.forEach((row) => {
    const tr = document.createElement("tr");
    [
      row.cache_policy_id,
      row.scope,
      row.ttl_seconds,
      row.key_strategy,
      row.invalidation_strategy,
      row.privacy_mode,
      row.status,
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });

    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const form = qs("#gatewayCachePolicyForm");
      if (!form) return;
      form.elements.scope.value = row.scope || "";
      form.elements.ttl_seconds.value = Number(row.ttl_seconds || 300);
      form.elements.key_strategy.value = row.key_strategy || "";
      form.elements.invalidation_strategy.value = row.invalidation_strategy || "";
      form.elements.privacy_mode.value = row.privacy_mode || "";
      const result = qs("#gatewayCachePolicyResult");
      if (result) result.textContent = `Loaded cache policy ${row.cache_policy_id} into form.`;
    });
    actions.appendChild(useBtn);
    tr.appendChild(actions);
    table.appendChild(tr);
  });
}

async function loadGatewayCachePolicies(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayCachePolicyFilters");
  const result = qs("#gatewayCachePolicyResult");
  const table = qs("#gatewayCachePoliciesTable");
  if (!form || !table) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const query = buildQueryString({
    scope: raw.scope,
    status: raw.status,
    limit: raw.limit,
    offset: raw.offset,
  });

  setTableMessage(table, 8, "Loading...");
  if (result) result.textContent = "Loading cache policies...";
  try {
    const rows = await api(`/gateway/cache/policies${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    gatewayCachePolicyRows = Array.isArray(rows) ? rows : [];
    renderGatewayCachePolicies();
    if (result) result.textContent = `Loaded ${gatewayCachePolicyRows.length} cache policies.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(table, 8, `Error: ${safeText(err.message)}`);
  }
}

async function saveGatewayCachePolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayCachePolicyForm");
  const result = qs("#gatewayCachePolicyResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Creating cache policy...";
  try {
    const data = await api("/gateway/cache/policies", {
      method: "POST",
      body: JSON.stringify({
        scope: String(raw.scope || "").trim(),
        ttl_seconds: Number(raw.ttl_seconds || 300),
        key_strategy: String(raw.key_strategy || "default").trim(),
        invalidation_strategy: String(raw.invalidation_strategy || "ttl").trim(),
        privacy_mode: String(raw.privacy_mode || "standard").trim(),
      }),
    });
    result.textContent = `Created cache policy ${safeText(data.cache_policy_id)}.`;
    await loadGatewayCachePolicies();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function invalidateGatewayCache(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayCacheInvalidateForm");
  const result = qs("#gatewayCachePolicyResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  let cacheKeys = [];
  try {
    const parsed = JSON.parse(String(raw.cache_keys || "[]"));
    if (!Array.isArray(parsed)) {
      throw new Error("Cache Keys JSON must be an array.");
    }
    cacheKeys = parsed.map((item) => String(item || "").trim()).filter(Boolean);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message || "Invalid cache keys JSON.")}`;
    return;
  }
  result.textContent = "Submitting cache invalidation...";
  try {
    const data = await api("/gateway/cache/delete", {
      method: "POST",
      body: JSON.stringify({
        scope: String(raw.scope || "").trim() || null,
        cache_keys: cacheKeys,
        reason: String(raw.reason || "").trim() || null,
        active_only: parseBooleanFlag(raw.active_only, true),
      }),
    });
    result.textContent = `Cache invalidation ${safeText(data.status)}; matched ${safeText(data.matching_policies)} policies and ${safeText(data.requested_keys)} explicit keys.`;
    await loadGatewayCacheHealth();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadEndpointCompatibility() {
  const result = qs("#endpointCompatibilityResult");
  if (!result) return;
  result.textContent = "Loading endpoint compatibility...";
  try {
    const data = await api("/gateway/endpoints/compatibility");
    const families = Array.isArray(data?.supported_families) ? data.supported_families.join(", ") : "--";
    result.textContent = `Compatibility ${safeText(data.status)}. Families: ${families}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runGatewayTransformDebug(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayTransformForm");
  const target = qs("#gatewayTransformResult");
  if (!form || !target) return;
  const payloadJson = String(new FormData(form).get("payload_json") || "{}").trim();
  const payload = parseJsonOrFallback(payloadJson, {});
  target.textContent = "Running transform debug...";
  try {
    const data = await api("/gateway/debug/transform-request", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    target.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    target.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderGatewayMcpSummary() {
  const selected = qs("#gatewayMcpSelectedServer");
  const toolCount = qs("#gatewayMcpToolCount");
  const trace = qs("#gatewayMcpLastTrace");
  const status = qs("#gatewayMcpStatus");
  if (selected) selected.textContent = gatewayMcpUiState.selectedServer || "--";
  if (toolCount) toolCount.textContent = String(gatewayMcpUiState.toolCount || 0);
  if (trace) trace.textContent = gatewayMcpUiState.lastTrace || "--";
  if (status) {
    status.className = `status-pill ${gatewayMcpUiState.status || "idle"}`;
    status.textContent = gatewayMcpUiState.status || "idle";
  }
}

function setGatewayMcpStatus(nextStatus) {
  gatewayMcpUiState.status = String(nextStatus || "idle").toLowerCase();
  renderGatewayMcpSummary();
}

function tryParseJson(text, label) {
  const raw = String(text || "").trim();
  if (!raw) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch (err) {
    return { ok: false, error: `${label} must be valid JSON: ${safeText(err.message)}` };
  }
}

function renderGatewayMcpServers() {
  const tbody = qs("#gatewayMcpServersTable");
  if (!tbody) return;
  if (!gatewayMcpServerRows.length) {
    setTableMessage(tbody, 6, "No MCP servers configured.");
    return;
  }

  tbody.textContent = "";
  gatewayMcpServerRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.server_id);
    appendTableCell(tr, row.base_url);
    appendTableCell(tr, row.transport);
    appendTableCell(tr, row.enabled ? "enabled" : "disabled");
    appendTableCell(tr, Array.isArray(row.allowed_tools) && row.allowed_tools.length ? row.allowed_tools.join(", ") : "all");

    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const toolsForm = qs("#gatewayMcpToolsForm");
      const callForm = qs("#gatewayMcpCallForm");
      if (toolsForm) toolsForm.elements.server_id.value = row.server_id || "";
      if (callForm) callForm.elements.server_id.value = row.server_id || "";
      gatewayMcpUiState.selectedServer = String(row.server_id || "");
      renderGatewayMcpSummary();
      const result = qs("#gatewayMcpResult");
      if (result) result.textContent = `Selected MCP server ${safeText(row.server_id)}.`;
    });
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "ghost";
    copyBtn.textContent = "Copy URL";
    copyBtn.addEventListener("click", async () => {
      const copied = await copyTextToClipboard(row.base_url || "");
      const result = qs("#gatewayMcpResult");
      if (result) {
        result.textContent = copied
          ? `Copied MCP URL for ${safeText(row.server_id)}.`
          : `Unable to copy MCP URL for ${safeText(row.server_id)}.`;
      }
    });
    actions.appendChild(useBtn);
    actions.appendChild(copyBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

function renderGatewayMcpTools() {
  const tbody = qs("#gatewayMcpToolsTable");
  if (!tbody) return;
  if (!gatewayMcpToolRows.length) {
    setTableMessage(tbody, 4, "No MCP tools found for selected server.");
    return;
  }

  tbody.textContent = "";
  gatewayMcpToolRows.forEach((tool) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, tool.name);
    appendTableCell(tr, tool.description || "--");

    const schemaCell = document.createElement("td");
    schemaCell.className = "mono";
    const details = document.createElement("details");
    details.className = "schema-preview";
    const summary = document.createElement("summary");
    summary.textContent = "View schema";
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(tool.inputSchema || tool.input_schema || {}, null, 2);
    details.appendChild(summary);
    details.appendChild(pre);
    schemaCell.appendChild(details);
    tr.appendChild(schemaCell);

    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const callForm = qs("#gatewayMcpCallForm");
      if (!callForm) return;
      callForm.elements.tool_name.value = tool.name || "";
      gatewayMcpUiState.toolCount = Array.isArray(gatewayMcpToolRows) ? gatewayMcpToolRows.length : 0;
      renderGatewayMcpSummary();
      const result = qs("#gatewayMcpResult");
      if (result) result.textContent = `Prepared tool ${safeText(tool.name)} for execution.`;
    });
    actions.appendChild(useBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

async function loadGatewayMcpServers() {
  const result = qs("#gatewayMcpResult");
  const tbody = qs("#gatewayMcpServersTable");
  const btn = qs("#loadGatewayMcpServers");
  if (!tbody) return;
  if (btn) btn.disabled = true;
  setGatewayMcpStatus("loading");
  if (result) result.textContent = "Loading MCP servers...";
  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api("/gateway/mcp/servers");
    gatewayMcpServerRows = Array.isArray(rows) ? rows : [];
    gatewayMcpUiState.selectedServer = gatewayMcpUiState.selectedServer || gatewayMcpServerRows[0]?.server_id || "";
    renderGatewayMcpServers();
    setGatewayMcpStatus("success");
    if (result) result.textContent = `Loaded ${gatewayMcpServerRows.length} MCP servers.`;
  } catch (err) {
    setGatewayMcpStatus("error");
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  } finally {
    if (btn) btn.disabled = false;
    renderGatewayMcpSummary();
  }
}

async function loadGatewayMcpTools(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayMcpToolsForm");
  const result = qs("#gatewayMcpResult");
  const tbody = qs("#gatewayMcpToolsTable");
  const submitBtn = form?.querySelector('button[type="submit"]');
  if (!form || !tbody) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const serverId = String(raw.server_id || "").trim();
  if (!serverId) {
    if (result) result.textContent = "Server ID is required to load tools.";
    return;
  }

  if (submitBtn) submitBtn.disabled = true;
  setGatewayMcpStatus("loading");
  setTableMessage(tbody, 4, "Loading...");
  if (result) result.textContent = `Loading tools for ${safeText(serverId)}...`;
  try {
    const data = await api(`/gateway/mcp/servers/${encodeURIComponent(serverId)}/tools/list`, {
      method: "POST",
      body: JSON.stringify({ environment: String(raw.environment || "dev").trim() || "dev" }),
    });
    gatewayMcpToolRows = Array.isArray(data?.tools) ? data.tools : [];
    gatewayMcpUiState.selectedServer = serverId;
    gatewayMcpUiState.toolCount = gatewayMcpToolRows.length;
    renderGatewayMcpTools();
    setGatewayMcpStatus("success");
    if (result) result.textContent = `Loaded ${gatewayMcpToolRows.length} MCP tools for ${safeText(serverId)}.`;
  } catch (err) {
    setGatewayMcpStatus("error");
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 4, `Error: ${safeText(err.message)}`);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
    renderGatewayMcpSummary();
  }
}

async function callGatewayMcpTool(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayMcpCallForm");
  const result = qs("#gatewayMcpCallResult");
  const status = qs("#gatewayMcpResult");
  const submitBtn = form?.querySelector('button[type="submit"]');
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const serverId = String(raw.server_id || "").trim();
  const toolName = String(raw.tool_name || "").trim();
  if (!serverId || !toolName) {
    result.textContent = "Server ID and Tool Name are required.";
    return;
  }

  const parsedArgs = tryParseJson(raw.arguments_json, "Tool Arguments JSON");
  if (!parsedArgs.ok) {
    setGatewayMcpStatus("error");
    result.textContent = parsedArgs.error;
    if (status) status.textContent = parsedArgs.error;
    return;
  }

  if (submitBtn) submitBtn.disabled = true;
  setGatewayMcpStatus("loading");
  result.textContent = "Calling MCP tool...";
  if (status) status.textContent = `Calling ${safeText(toolName)} on ${safeText(serverId)}...`;
  try {
    const data = await api(`/gateway/mcp/servers/${encodeURIComponent(serverId)}/tools/call`, {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "dev").trim() || "dev",
        tool_name: toolName,
        arguments: parsedArgs.value,
      }),
    });
    result.textContent = JSON.stringify(data, null, 2);
    gatewayMcpUiState.selectedServer = serverId;
    gatewayMcpUiState.lastTrace = String(data?.trace_id || "").trim();
    setGatewayMcpStatus("success");
    if (status) status.textContent = `MCP tool ${safeText(toolName)} completed on ${safeText(serverId)}.`;
  } catch (err) {
    setGatewayMcpStatus("error");
    result.textContent = `Error: ${safeText(err.message)}`;
    if (status) status.textContent = `Error: ${safeText(err.message)}`;
  } finally {
    if (submitBtn) submitBtn.disabled = false;
    renderGatewayMcpSummary();
  }
}

function formatGatewayMcpArgsJson() {
  const form = qs("#gatewayMcpCallForm");
  const status = qs("#gatewayMcpResult");
  if (!form) return;
  const current = String(form.elements.arguments_json?.value || "{}");
  const parsed = tryParseJson(current, "Tool Arguments JSON");
  if (!parsed.ok) {
    if (status) status.textContent = parsed.error;
    setGatewayMcpStatus("error");
    return;
  }
  form.elements.arguments_json.value = JSON.stringify(parsed.value, null, 2);
  if (status) status.textContent = "Formatted tool arguments JSON.";
  setGatewayMcpStatus("success");
}

async function copyGatewayMcpResult() {
  const result = qs("#gatewayMcpCallResult");
  const status = qs("#gatewayMcpResult");
  const value = String(result?.textContent || "").trim();
  if (!value) {
    if (status) status.textContent = "No MCP result available to copy yet.";
    return;
  }
  const copied = await copyTextToClipboard(value);
  if (status) status.textContent = copied ? "Copied MCP result to clipboard." : "Unable to copy MCP result.";
}

function clearGatewayMcpState() {
  gatewayMcpToolRows = [];
  gatewayMcpUiState.selectedServer = "";
  gatewayMcpUiState.toolCount = 0;
  gatewayMcpUiState.lastTrace = "";
  setGatewayMcpStatus("idle");
  const result = qs("#gatewayMcpResult");
  const call = qs("#gatewayMcpCallResult");
  const toolsTable = qs("#gatewayMcpToolsTable");
  if (result) result.textContent = "Cleared MCP state.";
  if (call) call.textContent = "";
  if (toolsTable) setTableMessage(toolsTable, 4, "Load tools to inspect server capabilities.");
  renderGatewayMcpSummary();
}

function parseCsvList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderGatewayExternalCallbacks() {
  const tbody = qs("#gatewayExternalCallbacksTable");
  if (!tbody) return;
  if (!gatewayExternalCallbackRows.length) {
    setTableMessage(tbody, 7, "No external callbacks configured.");
    return;
  }

  tbody.textContent = "";
  gatewayExternalCallbackRows.forEach((row) => {
    const tr = document.createElement("tr");
    appendTableCell(tr, row.callback_id || "--");
    appendTableCell(tr, row.callback_url || "--");
    appendTableCell(tr, Array.isArray(row.event_types) ? row.event_types.join(", ") : "--");
    appendTableCell(tr, row.environment || "dev");
    appendTableCell(tr, row.enabled ? "true" : "false");
    appendTableCell(tr, row.redact_sensitive ? "true" : "false");

    const actions = document.createElement("td");
    actions.className = "cell-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "ghost";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      const testForm = qs("#gatewayExternalCallbackTestForm");
      if (!testForm) return;
      testForm.elements.callback_id.value = String(row.callback_id || "");
      testForm.elements.environment.value = String(row.environment || "dev");
      const result = qs("#gatewayExternalCallbackResult");
      if (result) result.textContent = `Selected callback ${safeText(row.callback_id)} for test delivery.`;
    });

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "ghost";
    toggleBtn.textContent = row.enabled ? "Disable" : "Enable";
    toggleBtn.addEventListener("click", async () => {
      const result = qs("#gatewayExternalCallbackResult");
      try {
        await api(`/gateway/external-callbacks/${encodeURIComponent(String(row.callback_id || ""))}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: !row.enabled }),
        });
        await loadGatewayExternalCallbacks();
        if (result) result.textContent = `${row.enabled ? "Disabled" : "Enabled"} callback ${safeText(row.callback_id)}.`;
      } catch (err) {
        if (result) result.textContent = `Error: ${safeText(err.message)}`;
      }
    });

    actions.append(useBtn, toggleBtn);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

async function loadGatewayExternalCallbacks(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const result = qs("#gatewayExternalCallbackResult");
  const tbody = qs("#gatewayExternalCallbacksTable");
  if (tbody) setTableMessage(tbody, 7, "Loading...");
  try {
    const rows = await api("/gateway/external-callbacks");
    gatewayExternalCallbackRows = Array.isArray(rows) ? rows : [];
    renderGatewayExternalCallbacks();
    if (result) result.textContent = `Loaded ${gatewayExternalCallbackRows.length} external callbacks.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (tbody) setTableMessage(tbody, 7, `Error: ${safeText(err.message)}`);
  }
}

async function saveGatewayExternalCallback(evt) {
  evt.preventDefault();
  const form = qs("#gatewayExternalCallbackForm");
  const result = qs("#gatewayExternalCallbackResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/gateway/external-callbacks", {
      method: "POST",
      body: JSON.stringify({
        callback_url: String(raw.callback_url || "").trim(),
        event_types: parseCsvList(raw.event_types_csv),
        environment: String(raw.environment || "dev").trim(),
        redact_sensitive: String(raw.redact_sensitive || "true") === "true",
        enabled: String(raw.enabled || "true") === "true",
        description: String(raw.description || "").trim() || null,
      }),
    });
    await loadGatewayExternalCallbacks();
    if (result) result.textContent = `Saved callback ${safeText(data.callback_id)}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function testGatewayExternalCallback(evt) {
  evt.preventDefault();
  const form = qs("#gatewayExternalCallbackTestForm");
  const result = qs("#gatewayExternalCallbackResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const callbackId = String(raw.callback_id || "").trim();
  if (!callbackId) {
    if (result) result.textContent = "Callback ID is required.";
    return;
  }
  const samplePayload = parseJsonOrFallback(raw.sample_payload_json, {});
  try {
    const data = await api(`/gateway/external-callbacks/${encodeURIComponent(callbackId)}/test-delivery`, {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "dev").trim(),
        sample_payload: samplePayload,
      }),
    });
    if (result) {
      result.textContent = `Test delivery ${safeText(data.delivery_status)} for ${safeText(data.callback_id)} (trace ${safeText(data.trace_id)}).`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function exportGatewayExternalCallbackEvidence(evt) {
  evt.preventDefault();
  const form = qs("#gatewayExternalCallbackExportForm");
  const result = qs("#gatewayExternalCallbackResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/gateway/external-callbacks/export", {
      method: "POST",
      body: JSON.stringify({
        environment: String(raw.environment || "").trim() || null,
        limit: Number(raw.limit || 50),
      }),
    });
    if (result) {
      result.textContent = `Exported ${safeText(data.event_count)} events across ${safeText(data.callback_count)} callbacks (${safeText(data.export_id)}).`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadAudit() {
  const tbody = qs("#auditTable");
  setTableMessage(tbody, 5, "Loading...");
  try {
    const rows = await api("/audit/events?limit=30", { headers: { "X-Actor-Role": "Auditor" } });
    if (!rows?.length) {
      setTableMessage(tbody, 5, "No audit events.");
      return;
    }

    tbody.textContent = "";
    rows.forEach((row) => {
      appendTableRow(tbody, [
        row.timestamp,
        row.actor_id,
        row.action_type,
        row.resource_type,
        row.decision_outcome,
      ]);
    });
  } catch (err) {
    setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
  }
}

async function loadPlaygroundTestSets() {
  const result = qs("#playgroundResult");
  const tbody = qs("#playgroundTestSetsTable");
  if (!tbody) return;
  setTableMessage(tbody, 3, "Loading...");
  try {
    const rows = await api("/playground/test-sets");
    if (!rows?.length) {
      setTableMessage(tbody, 3, "No test sets found.");
      if (result) result.textContent = "No playground test sets found.";
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => appendTableRow(tbody, [row.test_set_id, row.name, row.case_count]));
    if (result) result.textContent = `Loaded ${rows.length} playground test sets.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 3, `Error: ${safeText(err.message)}`);
  }
}

async function judgePlaygroundPrompt(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#playgroundRunForm");
  const result = qs("#playgroundResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const promptText = String(raw.prompt_text || "").trim();
  const candidateModels = parseListInput(raw.candidate_models);
  if (!promptText || !candidateModels.length) {
    if (result) result.textContent = "Prompt text and at least one candidate model are required for judging.";
    return;
  }
  try {
    const data = await api("/playground/compare", {
      method: "POST",
      body: JSON.stringify({ prompt_text: promptText, candidate_models: candidateModels }),
    });
    playgroundJudgeRows = Array.isArray(data?.results) ? data.results : [];
    renderPlaygroundJudgeRows(playgroundJudgeRows);
    if (result) {
      result.textContent = playgroundJudgeRows.length
        ? `Judged ${playgroundJudgeRows.length} models. Best model: ${playgroundJudgeRows[0].model_name}.`
        : "No judge results returned.";
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function retryPlaygroundPrompt(targetRun) {
  const form = qs("#playgroundRunForm");
  const result = qs("#playgroundResult");
  if (!form) return;
  const chosenRun = targetRun || playgroundRuns[0] || null;
  if (!chosenRun && !playgroundJudgeRows.length) {
    if (result) result.textContent = "Judge a prompt before retrying so the console can reuse the best model.";
    return;
  }
  const nextModel = playgroundJudgeRows[0]?.model_name || chosenRun?.selected_model || form.elements.selected_model.value;
  form.elements.selected_model.value = nextModel;
  form.elements.prompt_text.value = buildRetryPrompt(form.elements.prompt_text.value);
  if (result) result.textContent = `Retry prepared with ${nextModel}. Re-run the prompt to execute it.`;
}

async function runPlaygroundPrompt(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#playgroundRunForm");
  const result = qs("#playgroundResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const promptText = String(raw.prompt_text || "").trim();
  const selectedModel = String(raw.selected_model || "").trim();
  const liveStream = String(raw.live_stream || "true") !== "false";
  const candidateModels = parseListInput(raw.candidate_models);
  if (!promptText || !selectedModel) {
    if (result) result.textContent = "Prompt text and selected model are required.";
    return;
  }

  const packagedPrompt = buildPlaygroundPromptPackage(promptText, liveStream ? "preview" : "off");
  if (liveStream) startPlaygroundStreamPreview(packagedPrompt);

  try {
    const data = await api("/playground/runs", {
      method: "POST",
      body: JSON.stringify({
        prompt_text: packagedPrompt,
        candidate_models: JSON.stringify(candidateModels),
        selected_model: selectedModel,
        team_ids: parseListInput(raw.team_ids),
        group_ids: parseListInput(raw.group_ids),
        projected_additional_cost_cents: Number(raw.projected_additional_cost_cents || 0),
      }),
    });
    playgroundRuns = [data, ...playgroundRuns.filter((run) => run.run_id !== data.run_id)].slice(0, 25);
    selectedPlaygroundRunId = data.run_id;
    latestBenchmarkRun = latestBenchmarkRun;
    latestScanRun = latestScanRun;
    renderPlaygroundRuns();
    applyPlaygroundWinner();
    if (result) result.textContent = `Created playground run ${data.run_id} using ${data.selected_model}.`;
    await Promise.all([loadAudit(), loadOverview()]);
  } catch (err) {
    stopPlaygroundStream();
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function createRouteDraftFromPlaygroundRun(run) {
  const result = qs("#playgroundResult");
  if (!run?.run_id) return;
  api(`/playground/runs/${encodeURIComponent(run.run_id)}/route-draft`, { method: "POST" })
    .then(async (data) => {
      if (result) result.textContent = `Created route draft ${data.draft_id} from run ${data.run_id}.`;
      await loadRouteDrafts();
      await loadRouteDraftHistory(data.draft_id);
    })
    .catch((err) => {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
    });
}

function updatePlaygroundMicStatus(message) {
  const target = qs("#playgroundMicStatus");
  if (target) target.textContent = String(message || "");
}

async function runBenchmark(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#agentQualityForm");
  const result = qs("#benchmarkResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/benchmarks/run", {
      method: "POST",
      body: JSON.stringify({
        agent_id: String(raw.agent_id || "").trim(),
        benchmark_suite: String(raw.benchmark_suite || "reliability-core").trim(),
        environment: String(raw.environment || "dev").trim(),
      }),
    });
    latestBenchmarkRun = data;
    await loadBenchmarkHistory();
    if (result) result.textContent = `Benchmark completed for ${data.agent_id} with score ${data.score}.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runScan(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#agentQualityForm");
  const result = qs("#scanResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/scans/run", {
      method: "POST",
      body: JSON.stringify({
        agent_id: String(raw.agent_id || "").trim(),
        scan_type: String(raw.scan_type || "security").trim(),
        environment: String(raw.environment || "dev").trim(),
      }),
    });
    latestScanRun = data;
    await loadScanHistory();
    if (result) result.textContent = `Scan completed for ${data.agent_id} with ${data.findings_count} findings.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadBenchmarkHistory() {
  const result = qs("#benchmarkResult");
  const form = qs("#agentQualityForm");
  const raw = form ? Object.fromEntries(new FormData(form).entries()) : {};
  const agentId = String(raw.agent_id || "").trim();
  const environment = String(raw.environment || "").trim().toLowerCase();
  const params = new URLSearchParams({ limit: "25", offset: "0" });
  if (agentId) params.set("agent_id", agentId);
  if (environment) params.set("environment", environment);
  try {
    const rows = await api(`/benchmarks/runs?${params.toString()}`);
    benchmarkHistoryRows = Array.isArray(rows) ? rows : [];
    renderBenchmarkTable(benchmarkHistoryRows);
    renderBenchmarkTrendSummary(benchmarkHistoryRows);
    if (result) result.textContent = `Loaded ${benchmarkHistoryRows.length} benchmark runs.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    renderBenchmarkTable([]);
    renderBenchmarkTrendSummary([]);
  }
}

async function loadScanHistory() {
  const result = qs("#scanResult");
  const form = qs("#agentQualityForm");
  const raw = form ? Object.fromEntries(new FormData(form).entries()) : {};
  const agentId = String(raw.agent_id || "").trim();
  const environment = String(raw.environment || "").trim().toLowerCase();
  const params = new URLSearchParams({ limit: "25", offset: "0" });
  if (agentId) params.set("agent_id", agentId);
  if (environment) params.set("environment", environment);
  try {
    const rows = await api(`/scans/runs?${params.toString()}`);
    scanHistoryRows = Array.isArray(rows) ? rows : [];
    renderScanTable(scanHistoryRows);
    renderScanTrendSummary(scanHistoryRows);
    if (result) result.textContent = `Loaded ${scanHistoryRows.length} scan runs.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    renderScanTable([]);
    renderScanTrendSummary([]);
  }
}

async function loadRoutePolicies() {
  const result = qs("#routePolicyResult");
  const tbody = qs("#routePoliciesTable");
  if (!tbody) return;
  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api("/gateway/routes");
    routePolicyRows = Array.isArray(rows) ? rows : [];
    if (!routePolicyRows.length) {
      setTableMessage(tbody, 6, "No route policies found.");
      if (result) result.textContent = "No route policies found.";
      return;
    }
    renderRoutePolicyRows();
    if (result) result.textContent = `Loaded ${routePolicyRows.length} route policies.`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

async function saveRoutePolicy(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#routePolicyResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api("/gateway/routes", {
      method: "POST",
      body: JSON.stringify({
        route_name: String(raw.route_name || "").trim(),
        candidate_deployments: String(raw.candidate_deployments || "[]").trim(),
        load_balancing_strategy: String(raw.load_balancing_strategy || "weighted").trim(),
        retry_policy: String(raw.retry_policy || "{}").trim(),
        fallback_policy: String(raw.fallback_policy || "{}").trim(),
        timeout_policy: String(raw.timeout_policy || "{}").trim(),
      }),
    });
    if (result) result.textContent = `Created route policy ${data.route_policy_id}.`;
    await loadRoutePolicies();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveRoutePriority(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#routePriorityResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(String(raw.route_policy_id || "").trim())}/providers/priority`, {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        environment: String(raw.environment || "prod").trim(),
        request_tag: String(raw.request_tag || "").trim() || null,
        priority_order: String(raw.priority_order || "[]").trim(),
        global_timeout_ms: Number(raw.global_timeout_ms || 4500),
        max_fallback_hops: Number(raw.max_fallback_hops || 2),
        budget_limit_cents: String(raw.budget_limit_cents || "").trim() ? Number(raw.budget_limit_cents) : null,
        health_check_enabled: String(raw.health_check_enabled || "false") === "true",
      }),
    });
    updateRoutePriorityScopeLabel(data.request_tag || raw.request_tag || "");
    if (result) result.textContent = `Saved priority for ${data.route_policy_id}.`;
    await loadRoutePriorityTimeline(null, data.route_policy_id);
    await loadRoutePolicies();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function simulateRouteFallback(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeFallbackForm");
  const result = qs("#routeFallbackResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(String(raw.route_policy_id || "").trim())}/simulate-fallback`, {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        environment: String(raw.environment || "prod").trim(),
        request_tag: String(raw.request_tag || "").trim() || null,
        requested_region: String(raw.requested_region || "").trim() || null,
        simulate_fail_provider_ids: String(raw.simulate_fail_provider_ids || "[]").trim(),
      }),
    });
    if (result) {
      const selectedGroup = String(data.selected_group_id || "").trim();
      result.textContent = selectedGroup
        ? `Simulated ${data.provider_attempts} providers, selected ${safeText(data.selected_provider_id)} in group ${safeText(selectedGroup)}.`
        : `Simulated ${data.provider_attempts} providers, selected ${safeText(data.selected_provider_id)}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function executeRouteFallback(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeFallbackForm");
  const result = qs("#routeFallbackResult");
  if (!form) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(String(raw.route_policy_id || "").trim())}/execute-fallback`, {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        environment: String(raw.environment || "prod").trim(),
        agent_id: String(raw.agent_id || "agent-ui").trim(),
        request_tag: String(raw.request_tag || "").trim() || null,
        requested_region: String(raw.requested_region || "").trim() || null,
        request_priority: String(raw.request_priority || "normal").trim(),
        model_name: String(raw.model_name || "").trim() || null,
        session_id: String(raw.session_id || "gateway-session").trim(),
        owner_scope: composeOwnerScope(raw) || "team:platform",
        endpoint_family: String(raw.endpoint_family || "responses").trim(),
        input_tokens: Number(raw.input_tokens || 100),
        output_tokens: Number(raw.output_tokens || 50),
        currency: String(raw.currency || "USD").trim(),
        simulate_fail_provider_ids: String(raw.simulate_fail_provider_ids || "[]").trim(),
      }),
    });
    if (result) {
      const selectedGroup = String(data.selected_group_id || "").trim();
      result.textContent = selectedGroup
        ? `Executed fallback: ${safeText(data.final_outcome)} via ${safeText(data.selected_provider_id)} in group ${safeText(selectedGroup)}.`
        : `Executed fallback: ${safeText(data.final_outcome)} via ${safeText(data.selected_provider_id)}.`;
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadRoutePreCallFilters(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routePreCallFiltersForm");
  const result = qs("#routePreCallFiltersResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required to load pre-call filters.";
    return;
  }

  try {
    const query = buildQueryString({ request_tag: String(raw.request_tag || "").trim() || null });
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/pre-call-filters${query}`);
    form.elements.route_policy_id.value = routePolicyId;
    form.elements.tenant_id.value = data.tenant_id || "";
    form.elements.environment.value = data.environment || "dev";
    form.elements.request_tag.value = data.request_tag || String(raw.request_tag || "").trim();
    form.elements.allowed_regions.value = data.allowed_regions || "[]";
    form.elements.min_context_window_tokens.value = data.min_context_window_tokens ?? "";
    form.elements.max_context_window_tokens.value = data.max_context_window_tokens ?? "";
    form.elements.enforce.value = String(Boolean(data.enforce));
    result.textContent = `Loaded pre-call filters for ${routePolicyId}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveRoutePreCallFilters(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routePreCallFiltersForm");
  const result = qs("#routePreCallFiltersResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required.";
    return;
  }

  const allowedRegions = parseJsonOrFallback(raw.allowed_regions, []);
  if (!Array.isArray(allowedRegions)) {
    result.textContent = "Allowed Regions must be a JSON array.";
    return;
  }

  try {
    await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/pre-call-filters`, {
      method: "PUT",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        environment: String(raw.environment || "dev").trim(),
        request_tag: String(raw.request_tag || "").trim() || null,
        allowed_regions: JSON.stringify(allowedRegions),
        min_context_window_tokens: String(raw.min_context_window_tokens || "").trim() ? Number(raw.min_context_window_tokens) : null,
        max_context_window_tokens: String(raw.max_context_window_tokens || "").trim() ? Number(raw.max_context_window_tokens) : null,
        enforce: String(raw.enforce || "true") === "true",
      }),
    });
    result.textContent = `Saved pre-call filters for ${routePolicyId}.`;
    await loadRoutePreCallFilters();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadRouteTrafficMirroring(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeTrafficMirroringForm");
  const result = qs("#routeTrafficMirroringResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required to load traffic mirroring.";
    return;
  }

  try {
    const query = buildQueryString({ request_tag: String(raw.request_tag || "").trim() || null });
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/traffic-mirroring${query}`);
    form.elements.route_policy_id.value = routePolicyId;
    form.elements.tenant_id.value = data.tenant_id || "";
    form.elements.environment.value = data.environment || "dev";
    form.elements.request_tag.value = data.request_tag || String(raw.request_tag || "").trim();
    form.elements.enabled.value = String(Boolean(data.enabled));
    form.elements.mirror_targets.value = data.mirror_targets || "[]";
    result.textContent = `Loaded traffic mirroring for ${routePolicyId}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveRouteTrafficMirroring(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeTrafficMirroringForm");
  const result = qs("#routeTrafficMirroringResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required.";
    return;
  }

  const mirrorTargets = parseJsonOrFallback(raw.mirror_targets, []);
  if (!Array.isArray(mirrorTargets)) {
    result.textContent = "Mirror Targets must be a JSON array.";
    return;
  }

  try {
    await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/traffic-mirroring`, {
      method: "PUT",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        environment: String(raw.environment || "dev").trim(),
        request_tag: String(raw.request_tag || "").trim() || null,
        enabled: String(raw.enabled || "true") === "true",
        mirror_targets: JSON.stringify(mirrorTargets),
      }),
    });
    result.textContent = `Saved traffic mirroring for ${routePolicyId}.`;
    await loadRouteTrafficMirroring();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function explainGatewayAuthorization(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayAuthzExplainForm");
  const result = qs("#gatewayAuthzExplainResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/gateway/authz/explain", {
      method: "POST",
      body: JSON.stringify({
        actor_role: String(raw.actor_role || "").trim(),
        actor_id: String(raw.actor_id || "explain-actor").trim() || "explain-actor",
        action: String(raw.action || "").trim(),
        environment: String(raw.environment || "dev").trim(),
        resource_type: String(raw.resource_type || "gateway_action").trim() || "gateway_action",
        resource_id: String(raw.resource_id || "").trim() || null,
        approver_role: String(raw.approver_role || "").trim() || null,
        approver_id: String(raw.approver_id || "").trim() || null,
      }),
    });
    result.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGatewayDecisionTrace(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#gatewayDecisionTraceForm");
  const result = qs("#gatewayDecisionTraceResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const traceId = String(raw.trace_id || "").trim();
  const limit = Number.parseInt(String(raw.limit || "200"), 10);
  if (!traceId) {
    result.textContent = "Trace ID is required.";
    return;
  }

  const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, 1000) : 200;

  try {
    const data = await api(
      `/gateway/decision-traces/${encodeURIComponent(traceId)}?limit=${encodeURIComponent(String(normalizedLimit))}`
    );
    result.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function renderTrafficMirroringSummary(data) {
  const tbody = qs("#routeTrafficMirroringSummaryTable");
  if (!tbody) return;

  const rows = [
    ["Total Mirror Events", safeText(data?.total_mirror_events)],
    ["Mirrored Request Count", safeText(data?.mirrored_request_count)],
    [
      "Top Mirror Providers",
      Array.isArray(data?.top_mirror_providers) && data.top_mirror_providers.length
        ? data.top_mirror_providers.map((row) => `${safeText(row.key)} (${safeText(row.events)})`).join(", ")
        : "--",
    ],
    [
      "Primary Provider Distribution",
      Array.isArray(data?.primary_provider_distribution) && data.primary_provider_distribution.length
        ? data.primary_provider_distribution.map((row) => `${safeText(row.key)} (${safeText(row.events)})`).join(", ")
        : "--",
    ],
    [
      "Mirror Mode Distribution",
      Array.isArray(data?.mirror_mode_distribution) && data.mirror_mode_distribution.length
        ? data.mirror_mode_distribution.map((row) => `${safeText(row.key)} (${safeText(row.events)})`).join(", ")
        : "--",
    ],
    [
      "Region Distribution",
      Array.isArray(data?.region_distribution) && data.region_distribution.length
        ? data.region_distribution.map((row) => `${safeText(row.key)} (${safeText(row.events)})`).join(", ")
        : "--",
    ],
    [
      "Outcome Comparison",
      Array.isArray(data?.outcome_comparison) && data.outcome_comparison.length
        ? data.outcome_comparison
            .map((row) => `${safeText(row.primary_outcome)} -> ${safeText(row.mirror_outcome)} (${safeText(row.events)})`)
            .join(", ")
        : "--",
    ],
  ];

  tbody.textContent = "";
  rows.forEach((row) => appendTableRow(tbody, row));
}

async function loadRouteTrafficMirroringAnalytics(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeTrafficMirroringAnalyticsForm");
  const result = qs("#routeTrafficMirroringAnalyticsResult");
  const reportTable = qs("#routeTrafficMirroringReportTable");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required.";
    return;
  }

  const query = buildQueryString({
    request_tag: String(raw.request_tag || "").trim() || null,
    environment: String(raw.environment || "").trim() || null,
    hours: Number(raw.hours || 24),
  });
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/traffic-mirroring/analytics-summary${query}`);
    renderTrafficMirroringSummary(data);
    result.textContent = `Loaded mirroring summary for ${routePolicyId}: ${safeText(data.total_mirror_events)} mirror events across ${safeText(data.mirrored_request_count)} requests.`;
    if (reportTable && !reportTable.children.length) {
      setTableMessage(reportTable, 9, "Load report to inspect event-level comparisons.");
    }
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    const summaryTable = qs("#routeTrafficMirroringSummaryTable");
    if (summaryTable) setTableMessage(summaryTable, 2, `Error: ${safeText(err.message)}`);
  }
}

async function loadRouteTrafficMirroringReport(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#routeTrafficMirroringAnalyticsForm");
  const result = qs("#routeTrafficMirroringAnalyticsResult");
  const tbody = qs("#routeTrafficMirroringReportTable");
  if (!form || !result || !tbody) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const routePolicyId = String(raw.route_policy_id || "").trim();
  if (!routePolicyId) {
    result.textContent = "Route policy ID is required.";
    return;
  }

  const query = buildQueryString({
    request_tag: String(raw.request_tag || "").trim() || null,
    environment: String(raw.environment || "").trim() || null,
    hours: Number(raw.hours || 24),
    limit: Number(raw.limit || 25),
    offset: Number(raw.offset || 0),
  });

  setTableMessage(tbody, 9, "Loading...");
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/traffic-mirroring/experiment-report${query}`);
    const rows = Array.isArray(data?.rows) ? data.rows : [];
    if (!rows.length) {
      setTableMessage(tbody, 9, "No mirror experiment events found for selected filters.");
    } else {
      tbody.textContent = "";
      rows.forEach((row) => {
        appendTableRow(tbody, [
          formatComplianceDate(row.timestamp),
          row.request_id,
          row.primary_provider_id,
          row.primary_outcome,
          row.mirror_provider_id,
          row.mirror_mode,
          row.mirror_outcome,
          row.requested_region || "--",
          row.request_tag || "--",
        ]);
      });
    }
    result.textContent = `Loaded experiment report for ${routePolicyId}: ${safeText(data.total_rows)} rows (limit ${safeText(data.limit)}, offset ${safeText(data.offset)}).`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 9, `Error: ${safeText(err.message)}`);
  }
}

async function optimizeRoutePolicy(evtOrRouteId) {
  const form = qs("#routeOptimizeForm");
  const result = qs("#routeOptimizeResult");
  const routePolicyId = typeof evtOrRouteId === "string" ? evtOrRouteId : String(new FormData(form).get("route_policy_id") || "").trim();
  const raw = form ? Object.fromEntries(new FormData(form).entries()) : {};
  if (!routePolicyId) {
    if (result) result.textContent = "Route policy ID is required.";
    return;
  }
  try {
    const data = await api(`/gateway/routes/${encodeURIComponent(routePolicyId)}/optimize`, {
      method: "POST",
      body: JSON.stringify({
        optimize_for: String(raw.optimize_for || "balanced").trim(),
        environment: String(raw.environment || "prod").trim(),
      }),
    });
    if (result) result.textContent = `Optimization recommendation: ${data.recommended_strategy} (${data.optimize_for}).`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function formatComplianceDate(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return safeText(value);
  return date.toLocaleString();
}

function setComplianceText(selector, message) {
  const target = qs(selector);
  if (target) {
    target.textContent = message;
  }
}

function setComplianceEvidenceBundle(bundle) {
  const target = qs("#complianceEvidenceBundleResult");
  if (!target) return;
  if (!bundle) {
    target.textContent = "";
    return;
  }
  target.textContent = JSON.stringify(bundle, null, 2);
}

function updateComplianceControlOptions(rows) {
  const select = qs("#complianceEvidenceControlId");
  if (!select) return;
  select.textContent = "";
  const controls = Array.isArray(rows) ? rows : [];
  controls.forEach((row) => {
    const option = document.createElement("option");
    option.value = row.control_id;
    option.textContent = `${row.control_id} - ${safeText(row.title)}`;
    select.appendChild(option);
  });
  if (controls.length) {
    const preferred = controls.some((row) => row.control_id === selectedComplianceControlId)
      ? selectedComplianceControlId
      : controls[0].control_id;
    select.value = preferred;
    selectedComplianceControlId = preferred;
  } else {
    selectedComplianceControlId = "";
  }
}

function renderComplianceControlsTable(rows) {
  const tbody = qs("#complianceControlsTable");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 5, "No compliance controls found.");
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const selectButton = document.createElement("button");
    selectButton.type = "button";
    selectButton.className = "ghost";
    selectButton.textContent = "Select";
    selectButton.addEventListener("click", () => {
      const select = qs("#complianceEvidenceControlId");
      if (select) {
        select.value = row.control_id;
        selectedComplianceControlId = row.control_id;
      }
      setComplianceText("#complianceEvidenceResult", `Selected ${row.control_id} for evidence actions.`);
    });

    const evidenceButton = document.createElement("button");
    evidenceButton.type = "button";
    evidenceButton.className = "ghost";
    evidenceButton.textContent = "Generate";
    evidenceButton.addEventListener("click", async () => {
      const select = qs("#complianceEvidenceControlId");
      if (select) {
        select.value = row.control_id;
        selectedComplianceControlId = row.control_id;
      }
      await generateComplianceEvidence();
    });

    [row.control_id, row.title, row.status, row.evidence_count].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.append(selectButton, evidenceButton);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function renderComplianceFreshnessTable(rows) {
  const tbody = qs("#complianceFreshnessTable");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 5, "No freshness data found.");
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    [row.control_id, row.status, row.evidence_count, formatComplianceDate(row.last_evidence_at), row.age_hours ?? "--"].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function renderComplianceMappingsTable(rows) {
  const tbody = qs("#complianceMappingsTable");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 8, "No compliance mappings found.");
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const editButton = document.createElement("button");
    editButton.type = "button";
    editButton.className = "ghost";
    editButton.textContent = "Edit";
    editButton.addEventListener("click", () => {
      const form = qs("#complianceMappingForm");
      if (!form) return;
      form.elements.control_id.value = row.control_id;
      form.elements.control_family.value = row.control_family || "";
      form.elements.requirement_text.value = row.requirement_text || "";
      form.elements.applicable_components.value = row.applicable_components || "[]";
      form.elements.required_evidence_types.value = row.required_evidence_types || "[]";
      form.elements.automation_status.value = row.automation_status || "manual";
      form.elements.owner_team.value = row.owner_team || "";
      form.elements.review_frequency.value = row.review_frequency || "quarterly";
      setComplianceText("#complianceMappingResult", `Loaded ${row.control_id} into the mapping form.`);
    });

    [
      row.control_id,
      row.control_family,
      row.requirement_text,
      row.required_evidence_types,
      row.automation_status,
      row.owner_team,
      row.review_frequency,
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.append(editButton);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function renderRetentionPoliciesTable(rows) {
  const tbody = qs("#retentionPoliciesTable");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 8, "No retention policies found.");
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const editButton = document.createElement("button");
    editButton.type = "button";
    editButton.className = "ghost";
    editButton.textContent = "Edit";
    editButton.addEventListener("click", () => {
      const form = qs("#retentionPolicyForm");
      if (!form) return;
      form.elements.data_class.value = row.data_class || "";
      form.elements.jurisdiction.value = row.jurisdiction || "";
      form.elements.retention_days.value = row.retention_days ?? "";
      form.elements.deletion_mode.value = row.deletion_mode || "soft_delete";
      form.elements.legal_hold_supported.value = String(Boolean(row.legal_hold_supported));
      setComplianceText("#retentionPolicyResult", `Loaded ${row.data_class} / ${row.jurisdiction} into the form.`);
    });

    [
      row.data_class,
      row.jurisdiction,
      row.retention_days,
      row.deletion_mode,
      row.legal_hold_supported,
      row.status,
      formatComplianceDate(row.updated_at),
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.append(editButton);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

function renderLegalHoldsTable(rows) {
  const tbody = qs("#legalHoldsTable");
  if (!tbody) return;
  if (!rows.length) {
    setTableMessage(tbody, 8, "No legal holds found.");
    return;
  }
  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    const releaseButton = document.createElement("button");
    releaseButton.type = "button";
    releaseButton.className = "ghost";
    releaseButton.textContent = "Release";
    releaseButton.disabled = row.status !== "active";
    releaseButton.addEventListener("click", async () => {
      await releaseLegalHold(row.hold_id);
    });

    [
      row.hold_id,
      row.data_class,
      row.jurisdiction,
      row.reason,
      row.scope_ref,
      row.status,
      formatComplianceDate(row.placed_at),
    ].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = safeText(value);
      tr.appendChild(td);
    });
    const actionCell = document.createElement("td");
    actionCell.append(releaseButton);
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  });
}

async function loadComplianceControls() {
  const tbody = qs("#complianceControlsTable");
  if (tbody) setTableMessage(tbody, 5, "Loading...");
  try {
    const rows = await api("/compliance/controls");
    complianceControlRows = Array.isArray(rows) ? rows : [];
    updateComplianceControlOptions(complianceControlRows);
    qs("#complianceControlCount").textContent = safeText(complianceControlRows.length);
    renderComplianceControlsTable(complianceControlRows);
  } catch (err) {
    complianceControlRows = [];
    updateComplianceControlOptions([]);
    if (tbody) setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
    qs("#complianceControlCount").textContent = "--";
  }
}

async function loadComplianceCoverage() {
  const summary = qs("#complianceSummary");
  const paths = qs("#complianceCoveragePaths");
  if (summary) summary.textContent = "Loading compliance coverage...";
  if (paths) paths.textContent = "";
  try {
    const data = await api("/compliance/controls/coverage");
    const total = Number(data?.total_routes || 0);
    const covered = Number(data?.covered_routes || 0);
    const uncovered = Number(data?.uncovered_routes || 0);
    if (summary) {
      summary.textContent = `Coverage generated ${formatComplianceDate(data?.generated_at)}. ${covered}/${total} routes covered, ${uncovered} uncovered.`;
    }
    if (paths) {
      paths.textContent = "";
      const uncoveredPaths = Array.isArray(data?.uncovered_paths) ? data.uncovered_paths : [];
      if (!uncoveredPaths.length) {
        const li = document.createElement("li");
        li.textContent = "No uncovered routes reported.";
        paths.appendChild(li);
      } else {
        uncoveredPaths.slice(0, 12).forEach((path) => {
          const li = document.createElement("li");
          li.textContent = safeText(path);
          paths.appendChild(li);
        });
      }
    }
  } catch (err) {
    if (summary) summary.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadComplianceFreshness() {
  const summary = qs("#complianceSummary");
  const tbody = qs("#complianceFreshnessTable");
  if (summary && summary.textContent === "") {
    summary.textContent = "Loading compliance freshness...";
  }
  if (tbody) setTableMessage(tbody, 5, "Loading...");
  try {
    const data = await api("/compliance/controls/evidence-freshness?freshness_slo_hours=24");
    complianceFreshnessRows = Array.isArray(data?.items) ? data.items : [];
    qs("#complianceControlCount").textContent = safeText(data?.total_controls ?? complianceControlRows.length);
    qs("#compliancePassingCount").textContent = safeText(data?.controls_passing);
    qs("#complianceStaleCount").textContent = safeText(data?.controls_stale);
    qs("#complianceMissingCount").textContent = safeText(data?.controls_missing);
    renderComplianceFreshnessTable(complianceFreshnessRows);
  } catch (err) {
    complianceFreshnessRows = [];
    if (tbody) setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
    qs("#compliancePassingCount").textContent = "--";
    qs("#complianceStaleCount").textContent = "--";
    qs("#complianceMissingCount").textContent = "--";
  }
}

async function loadComplianceMappings() {
  const tbody = qs("#complianceMappingsTable");
  if (tbody) setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api("/compliance/controls/mappings");
    complianceMappingRows = Array.isArray(rows) ? rows : [];
    renderComplianceMappingsTable(complianceMappingRows);
  } catch (err) {
    complianceMappingRows = [];
    if (tbody) setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function saveComplianceMapping(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#complianceMappingForm");
  const result = qs("#complianceMappingResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const controlId = String(raw.control_id || "").trim();
  if (!controlId) {
    result.textContent = "Control ID is required.";
    return;
  }

  result.textContent = `Saving mapping for ${controlId}...`;
  try {
    await api(`/compliance/controls/mappings/${encodeURIComponent(controlId)}`, {
      method: "PUT",
      body: JSON.stringify({
        control_family: String(raw.control_family || "").trim(),
        requirement_text: String(raw.requirement_text || "").trim(),
        applicable_components: String(raw.applicable_components || "[]").trim(),
        required_evidence_types: String(raw.required_evidence_types || "[]").trim(),
        automation_status: String(raw.automation_status || "manual").trim(),
        owner_team: String(raw.owner_team || "").trim(),
        review_frequency: String(raw.review_frequency || "quarterly").trim(),
      }),
    });
    result.textContent = `Saved mapping for ${controlId}.`;
    await Promise.all([loadComplianceMappings(), loadComplianceCoverage()]);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadComplianceEvidence() {
  const form = qs("#complianceEvidenceForm");
  const result = qs("#complianceEvidenceResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const controlId = String(raw.control_id || selectedComplianceControlId || "").trim();
  if (!controlId) {
    result.textContent = "Select a control before loading evidence.";
    return;
  }

  result.textContent = `Loading evidence for ${controlId}...`;
  try {
    const data = await api(`/compliance/evidence/${encodeURIComponent(controlId)}`);
    result.textContent = `${data?.control_id || controlId} generated ${formatComplianceDate(data?.generated_at)} with ${Array.isArray(data?.evidence_items) ? data.evidence_items.length : 0} evidence items.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadComplianceEvidenceBundle() {
  const form = qs("#complianceEvidenceForm");
  const result = qs("#complianceEvidenceResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const controlId = String(raw.control_id || selectedComplianceControlId || "").trim();
  if (!controlId) {
    result.textContent = "Select a control before loading a bundle.";
    return;
  }

  result.textContent = `Loading bundle for ${controlId}...`;
  try {
    const data = await api(`/compliance/evidence/${encodeURIComponent(controlId)}/bundle`);
    setComplianceEvidenceBundle(data);
    result.textContent = `${data?.control_id || controlId} bundle generated ${formatComplianceDate(data?.generated_at)}.`;
  } catch (err) {
    setComplianceEvidenceBundle(null);
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function generateComplianceEvidence() {
  const form = qs("#complianceEvidenceForm");
  const result = qs("#complianceEvidenceResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const controlId = String(raw.control_id || selectedComplianceControlId || "").trim();
  if (!controlId) {
    result.textContent = "Select a control before generating evidence.";
    return;
  }

  result.textContent = `Generating evidence for ${controlId}...`;
  try {
    await api(`/compliance/evidence/${encodeURIComponent(controlId)}/generate`, {
      method: "POST",
      body: JSON.stringify({
        source_type: String(raw.source_type || "audit_events").trim(),
        source_id: String(raw.source_id || "latest").trim(),
      }),
    });
    result.textContent = `Generated evidence for ${controlId}.`;
    await Promise.all([loadComplianceControls(), loadComplianceFreshness()]);
    await loadComplianceEvidenceBundle();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadRetentionPolicies() {
  const tbody = qs("#retentionPoliciesTable");
  if (tbody) setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api("/compliance/retention/policies");
    complianceRetentionRows = Array.isArray(rows) ? rows : [];
    renderRetentionPoliciesTable(complianceRetentionRows);
  } catch (err) {
    complianceRetentionRows = [];
    if (tbody) setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function saveRetentionPolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#retentionPolicyForm");
  const result = qs("#retentionPolicyResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const dataClass = String(raw.data_class || "").trim();
  const jurisdiction = String(raw.jurisdiction || "").trim();
  if (!dataClass || !jurisdiction) {
    result.textContent = "Data class and jurisdiction are required.";
    return;
  }

  result.textContent = `Saving retention policy for ${dataClass}/${jurisdiction}...`;
  try {
    await api("/compliance/retention/policies", {
      method: "POST",
      body: JSON.stringify({
        data_class: dataClass,
        jurisdiction,
        retention_days: Number(raw.retention_days || 365),
        deletion_mode: String(raw.deletion_mode || "soft_delete").trim(),
        legal_hold_supported: String(raw.legal_hold_supported || "true") === "true",
      }),
    });
    result.textContent = `Saved retention policy for ${dataClass}/${jurisdiction}.`;
    await loadRetentionPolicies();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadLegalHolds() {
  const tbody = qs("#legalHoldsTable");
  if (tbody) setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api("/compliance/legal-holds?status=active");
    complianceLegalHoldRows = Array.isArray(rows) ? rows : [];
    renderLegalHoldsTable(complianceLegalHoldRows);
  } catch (err) {
    complianceLegalHoldRows = [];
    if (tbody) setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function placeLegalHold(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#legalHoldForm");
  const result = qs("#legalHoldResult");
  if (!form || !result) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const dataClass = String(raw.data_class || "").trim();
  const jurisdiction = String(raw.jurisdiction || "").trim();
  const reason = String(raw.reason || "").trim();
  const scopeRef = String(raw.scope_ref || "").trim();
  if (!dataClass || !jurisdiction || !reason || !scopeRef) {
    result.textContent = "All legal hold fields are required.";
    return;
  }

  result.textContent = `Placing legal hold for ${scopeRef}...`;
  try {
    await api("/compliance/legal-holds", {
      method: "POST",
      body: JSON.stringify({
        data_class: dataClass,
        jurisdiction,
        reason,
        scope_ref: scopeRef,
      }),
    });
    result.textContent = `Placed legal hold for ${scopeRef}.`;
    await loadLegalHolds();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function releaseLegalHold(holdId) {
  const result = qs("#legalHoldResult");
  if (result) result.textContent = `Releasing hold ${holdId}...`;
  try {
    await api(`/compliance/legal-holds/${encodeURIComponent(holdId)}/release`, {
      method: "POST",
      body: JSON.stringify({ reason_code: "operator_release" }),
    });
    if (result) result.textContent = `Released hold ${holdId}.`;
    await loadLegalHolds();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadComplianceWorkspace() {
  await loadComplianceControls();
  await Promise.allSettled([
    loadComplianceCoverage(),
    loadComplianceFreshness(),
    loadComplianceMappings(),
    loadRetentionPolicies(),
    loadLegalHolds(),
  ]);
}

async function loadObservability() {
  const tbody = qs("#observabilityRequestMapTable");
  if (!tbody) return;

  const rows = [
    {
      method: "GET",
      endpoint: "/observability/traces/{trace_id}",
      purpose: "Fetch a single trace by trace ID for request-level investigation.",
      link: buildApiUrl("/observability/traces/{trace_id}"),
    },
    {
      method: "GET",
      endpoint: "/observability/logs",
      purpose: "List recent observability logs with the current default limit.",
      link: buildApiUrl("/observability/logs?limit=50"),
    },
    {
      method: "GET",
      endpoint: "/observability/logs/schema-status",
      purpose: "Check observability log schema health and sample coverage.",
      link: buildApiUrl("/observability/logs/schema-status?sample_size=200"),
    },
  ];

  tbody.textContent = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    [row.method, row.endpoint, row.purpose].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.appendChild(td);
    });

    const linkTd = document.createElement("td");
    const link = document.createElement("a");
    link.href = row.link;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = "Open";
    linkTd.appendChild(link);
    tr.appendChild(linkTd);
    tbody.appendChild(tr);
  });

  await Promise.all([loadObservabilityLogs(), loadObservabilitySchema()]);
}

async function loadObservabilityTrace(evt) {
  if (evt) evt.preventDefault();
  const form = qs("#observabilityTraceForm");
  const result = qs("#observabilityTraceResult");
  const summary = qs("#observabilityTraceSummary");
  const table = qs("#observabilityTraceTable");
  const status = qs("#observabilityTraceStatus");
  const traceId = String(new FormData(form).get("trace_id") || "").trim();

  if (!traceId) {
    if (result) result.textContent = "Trace ID is required.";
    return;
  }

  setTableMessage(table, 2, "Loading...");
  if (status) status.textContent = "Loading";

  try {
    const data = await api(`/observability/traces/${encodeURIComponent(traceId)}`, {
      headers: { "X-Actor-Role": state.actorRole },
    });
    if (result) result.textContent = `Trace ${data.trace_id} loaded successfully.`;
    if (status) status.textContent = `Found ${data.event_count}`;
    fillSummaryCard(summary, "Trace Summary", [
      ["Events", data.event_count],
      ["Cost events", data.cost_event_count],
      ["First seen", data.first_seen],
      ["Last seen", data.last_seen],
    ]);
    table.textContent = "";
    [
      ["Trace ID", data.trace_id],
      ["Event Count", data.event_count],
      ["Cost Event Count", data.cost_event_count],
      ["First Seen", data.first_seen],
      ["Last Seen", data.last_seen],
    ].forEach(([field, value]) => appendTableRow(table, [field, value]));
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (status) status.textContent = "Error";
    setTableMessage(table, 2, `Error: ${safeText(err.message)}`);
  }
}

async function loadObservabilityTraceById(traceId) {
  const form = qs("#observabilityTraceForm");
  if (!form) return;
  const input = form.querySelector('input[name="trace_id"]');
  if (input) input.value = traceId;
  await loadObservabilityTrace();
}

async function loadObservabilityLogs(evt) {
  if (evt) evt.preventDefault();
  const form = qs("#observabilityLogsForm");
  const result = qs("#observabilityLogsResult");
  const table = qs("#observabilityLogsTable");
  const status = qs("#observabilityLogsStatus");
  const raw = Object.fromEntries(new FormData(form).entries());
  const limit = String(raw.limit || "25").trim();
  const offset = String(raw.offset || "0").trim();
  const sinceHours = String(raw.since_hours || "24").trim();
  const redact = String(raw.redact_sensitive || "false").trim();
  const actorId = String(raw.actor_id || "").trim();
  const traceId = String(raw.trace_id || "").trim();
  const actionType = String(raw.action_type || "").trim();
  const resourceType = String(raw.resource_type || "").trim();
  const resourceId = String(raw.resource_id || "").trim();
  const decisionOutcome = String(raw.decision_outcome || "").trim();
  const search = String(raw.search || "").trim();

  setTableMessage(table, 8, "Loading...");
  if (status) status.textContent = `Loading ${limit}`;

  try {
    const query = buildQueryString({
      limit,
      offset,
      since_hours: sinceHours,
      redact_sensitive: redact,
      actor_id: actorId || undefined,
      trace_id: traceId || undefined,
      action_type: actionType || undefined,
      resource_type: resourceType || undefined,
      resource_id: resourceId || undefined,
      decision_outcome: decisionOutcome || undefined,
      search: search || undefined,
    });
    const rows = await api(`/observability/logs${query}`, {
      headers: { "X-Actor-Role": state.actorRole },
    });
    if (result) result.textContent = `Loaded ${rows.length} log entries (offset ${offset}, last ${sinceHours}h).`;
    if (status) status.textContent = `${rows.length} rows`;
    if (!rows?.length) {
      setTableMessage(table, 8, "No logs found.");
      return;
    }
    table.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      [
        row.timestamp,
        row.actor_id,
        row.action_type,
        row.resource_type,
        row.resource_id,
        row.decision_outcome,
        row.trace_id,
      ].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = safeText(value);
        tr.appendChild(td);
      });
      const actionsTd = document.createElement("td");
      const viewTrace = document.createElement("button");
      viewTrace.type = "button";
      viewTrace.className = "ghost";
      viewTrace.textContent = "Open Trace";
      viewTrace.addEventListener("click", () => loadObservabilityTraceById(String(row.trace_id || "")));
      actionsTd.appendChild(viewTrace);
      tr.appendChild(actionsTd);
      table.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (status) status.textContent = "Error";
    setTableMessage(table, 8, `Error: ${safeText(err.message)}`);
  }
}

async function loadObservabilitySchema(evt) {
  if (evt) evt.preventDefault();
  const result = qs("#observabilitySchemaResult");
  const table = qs("#observabilitySchemaTable");
  const summary = qs("#observabilitySchemaSummary");
  const status = qs("#observabilitySchemaStatus");

  setTableMessage(table, 2, "Loading...");
  if (status) status.textContent = "Loading";

  try {
    const data = await api(`/observability/logs/schema-status?sample_size=200`, {
      headers: { "X-Actor-Role": state.actorRole },
    });
    if (result) result.textContent = `Sampled ${data.sampled_count} log records.`;
    if (status) status.textContent = `${data.conformance_percent}%`;
    fillSummaryCard(summary, "Schema Health Summary", [
      ["Sampled", data.sampled_count],
      ["Valid", data.valid_count],
      ["Invalid", data.invalid_count],
      ["Conformance", `${data.conformance_percent}%`],
    ]);
    table.textContent = "";
    Object.entries(data.missing_field_counts || {}).forEach(([field, missingCount]) => {
      appendTableRow(table, [field, missingCount]);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    if (status) status.textContent = "Error";
    setTableMessage(table, 2, `Error: ${safeText(err.message)}`);
  }
}

function switchSecurityConsole(consoleName = "users") {
  const normalized = ["users", "groups", "teams"].includes(String(consoleName || "").toLowerCase())
    ? String(consoleName || "users").toLowerCase()
    : "users";
  qsa("[data-security-console]").forEach((button) => {
    button.classList.toggle("active", button.dataset.securityConsole === normalized);
  });
  qsa(".security-console").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `securityConsole${toTitleCaseToken(normalized)}`);
  });
}

function filterDirectoryRows(rows, searchTerm, fields) {
  const query = String(searchTerm || "").trim().toLowerCase();
  if (!query) return Array.isArray(rows) ? rows : [];
  return (Array.isArray(rows) ? rows : []).filter((row) =>
    fields.some((field) => String(row?.[field] || "").toLowerCase().includes(query))
  );
}

async function ensureDirectoryScopeCatalogLoaded() {
  if (directoryGroupRows.length && directoryTeamRows.length) return;
  try {
    const [groupsResult, teamsResult] = await Promise.allSettled([
      api("/auth/directory/groups?limit=500"),
      api("/auth/directory/teams?limit=500"),
    ]);
    if (groupsResult.status === "fulfilled") {
      directoryGroupRows = Array.isArray(groupsResult.value) ? groupsResult.value : [];
    }
    if (teamsResult.status === "fulfilled") {
      directoryTeamRows = Array.isArray(teamsResult.value) ? teamsResult.value : [];
    }
  } catch {
    // Scope pickers degrade to manual entry when directory APIs are unavailable.
  }
}

function getDirectoryScopeCandidates(scopeType) {
  const normalized = String(scopeType || "").trim().toLowerCase();
  const rows = normalized === "group" ? directoryGroupRows : normalized === "team" ? directoryTeamRows : [];
  const idField = normalized === "group" ? "group_id" : "team_id";
  const seen = new Set();
  return rows
    .map((row) => String(row?.[idField] || "").trim())
    .filter((value) => value && !seen.has(value) && seen.add(value))
    .sort((a, b) => a.localeCompare(b));
}

async function syncScopeIdPicker(formSelector, scopeTypeField, scopeIdField, datalistId) {
  const form = typeof formSelector === "string" ? qs(formSelector) : formSelector;
  if (!form?.elements) return;

  const datalist = qs(`#${datalistId}`);
  if (!datalist) return;

  const selectedType = String(form.elements?.[scopeTypeField]?.value || "").trim().toLowerCase();
  datalist.textContent = "";

  if (!["team", "group"].includes(selectedType)) return;

  await ensureDirectoryScopeCatalogLoaded();
  const candidates = getDirectoryScopeCandidates(selectedType);
  candidates.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    datalist.appendChild(option);
  });

  const input = form.elements?.[scopeIdField];
  if (!String(input?.value || "").trim() && candidates.length) {
    input.value = candidates[0];
  }
}

function composeOwnerScope(raw) {
  const explicit = String(raw.owner_scope || "").trim();
  if (explicit) return explicit;
  const scopeType = String(raw.owner_scope_type || "").trim().toLowerCase();
  const scopeId = String(raw.owner_scope_id || "").trim();
  if (!scopeType || !scopeId) return "";
  return `${scopeType}:${scopeId}`;
}

async function loadDirectoryAuditForResource(resourceId, targetBodyId) {
  const tbody = qs(targetBodyId);
  if (!tbody) return;
  setTableMessage(tbody, 5, "Loading...");
  try {
    const rows = await api("/audit/events?limit=500", { headers: { "X-Actor-Role": "Auditor" } });
    const filtered = (Array.isArray(rows) ? rows : []).filter((row) => String(row?.resource_id || "") === String(resourceId || ""));
    if (!filtered.length) {
      setTableMessage(tbody, 5, `No audit events found for ${safeText(resourceId)}.`);
      return;
    }
    tbody.textContent = "";
    filtered.slice(0, 50).forEach((row) => {
      appendTableRow(tbody, [
        row.timestamp,
        row.action_type,
        row.actor_id,
        row.decision_outcome,
        row.trace_id,
      ]);
    });
  } catch (err) {
    setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
  }
}

async function upsertDirectoryUser(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#directoryUserResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {
    user_id: String(raw.user_id || "").trim(),
    display_name: String(raw.display_name || "").trim(),
    email: String(raw.email || "").trim(),
    role_name: String(raw.role_name || "").trim(),
    status: String(raw.status || "active").trim().toLowerCase(),
    password: String(raw.password || ""),
  };
  if (!payload.user_id || !payload.display_name || !payload.email) {
    if (result) result.textContent = "User ID, display name, and email are required.";
    return;
  }
  if (!payload.password) {
    delete payload.password;
  }

  try {
    await api("/auth/directory/users", { method: "POST", body: JSON.stringify(payload) });
    if (result) result.textContent = `Created user ${payload.user_id}.`;
  } catch (err) {
    if (String(err.message || "").includes("already exists")) {
      await api(`/auth/directory/users/${encodeURIComponent(payload.user_id)}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      if (result) result.textContent = `Updated user ${payload.user_id}.`;
    } else {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
      return;
    }
  }
  await loadDirectoryUsers();
}

async function loadDirectoryUsers(searchOverride) {
  const tbody = qs("#directoryUsersTable");
  if (!tbody) return;
  setTableMessage(tbody, 8, "Loading...");
  try {
    directoryUserRows = await api("/auth/directory/users?limit=500");
    const searchTerm = typeof searchOverride === "string" ? searchOverride : qs("#directoryUserSearch")?.value;
    const rows = filterDirectoryRows(directoryUserRows, searchTerm, ["user_id", "display_name", "email", "role_name", "status"]);
    if (!rows?.length) {
      setTableMessage(tbody, 8, "No users found.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.user_id);
      appendTableCell(tr, row.display_name);
      appendTableCell(tr, row.email);
      appendTableCell(tr, row.role_name);
      appendTableCell(tr, row.status);
      const lockedUntil = row.locked_until ? String(row.locked_until) : "";
      const failedAttempts = Number(row.failed_login_attempts || 0);
      const lockStatusLabel = row.status === "inactive"
        ? `Disabled (${failedAttempts} failed)`
        : lockedUntil
          ? `Locked until ${lockedUntil} (${failedAttempts} failed)`
          : `Open (${failedAttempts} failed)`;
      appendTableCell(tr, lockStatusLabel);

      const lockControls = document.createElement("td");
      lockControls.className = "cell-actions";
      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "ghost";
      lockBtn.textContent = "Lock";
      lockBtn.addEventListener("click", async () => {
        const result = qs("#directoryUserResult");
        try {
          await api(`/auth/directory/users/${encodeURIComponent(row.user_id)}/lock`, { method: "POST" });
          if (result) result.textContent = `Locked user ${row.user_id}.`;
          await loadDirectoryUsers(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      lockControls.appendChild(lockBtn);

      const unlockBtn = document.createElement("button");
      unlockBtn.type = "button";
      unlockBtn.className = "ghost";
      unlockBtn.textContent = "Unlock";
      unlockBtn.addEventListener("click", async () => {
        const result = qs("#directoryUserResult");
        try {
          await api(`/auth/directory/users/${encodeURIComponent(row.user_id)}/unlock`, { method: "POST" });
          if (result) result.textContent = `Unlocked user ${row.user_id}.`;
          await loadDirectoryUsers(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      lockControls.appendChild(unlockBtn);

      tr.appendChild(lockControls);

      const actions = document.createElement("td");
      actions.className = "cell-actions";

      const disableBtn = document.createElement("button");
      disableBtn.type = "button";
      disableBtn.className = "ghost";
      disableBtn.textContent = "Disable";
      disableBtn.addEventListener("click", async () => {
        const result = qs("#directoryUserResult");
        try {
          await api(`/auth/directory/users/${encodeURIComponent(row.user_id)}/disable`, { method: "POST" });
          if (result) result.textContent = `Disabled user ${row.user_id}.`;
          await loadDirectoryUsers(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(disableBtn);

      const auditBtn = document.createElement("button");
      auditBtn.type = "button";
      auditBtn.className = "ghost";
      auditBtn.textContent = "Audit";
      auditBtn.addEventListener("click", async () => {
        const result = qs("#directoryUserResult");
        if (result) result.textContent = `Loaded audit events for ${row.user_id}.`;
        await loadDirectoryAuditForResource(row.user_id, "#directoryUserAuditTable");
      });
      actions.appendChild(auditBtn);

      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "ghost";
      removeBtn.textContent = "Delete";
      removeBtn.addEventListener("click", async () => {
        const result = qs("#directoryUserResult");
        try {
          await api(`/auth/directory/users/${encodeURIComponent(row.user_id)}`, { method: "DELETE" });
          if (result) result.textContent = `Deleted user ${row.user_id}.`;
          setTableMessage(qs("#directoryUserAuditTable"), 5, `Deleted ${safeText(row.user_id)}. Reload audit to inspect event history.`);
          await loadDirectoryUsers(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(removeBtn);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  } catch (err) {
    setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function upsertDirectoryGroup(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#directoryGroupResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {
    group_id: String(raw.group_id || "").trim(),
    display_name: String(raw.display_name || "").trim(),
    description: String(raw.description || "").trim(),
    status: String(raw.status || "active").trim().toLowerCase(),
  };
  if (!payload.group_id || !payload.display_name) {
    if (result) result.textContent = "Group ID and name are required.";
    return;
  }
  if (payload.description.length > DIRECTORY_DESCRIPTION_MAX_LENGTH) {
    if (result) result.textContent = `Group description must be ${DIRECTORY_DESCRIPTION_MAX_LENGTH} characters or less.`;
    return;
  }

  try {
    await api("/auth/directory/groups", { method: "POST", body: JSON.stringify(payload) });
    if (result) result.textContent = `Created group ${payload.group_id}.`;
  } catch (err) {
    if (String(err.message || "").includes("already exists")) {
      await api(`/auth/directory/groups/${encodeURIComponent(payload.group_id)}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      if (result) result.textContent = `Updated group ${payload.group_id}.`;
    } else {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
      return;
    }
  }
  await loadDirectoryGroups();
}

async function loadDirectoryGroups(searchOverride) {
  const tbody = qs("#directoryGroupsTable");
  if (!tbody) return;
  setTableMessage(tbody, 5, "Loading...");
  try {
    directoryGroupRows = await api("/auth/directory/groups?limit=500");
    const searchTerm = typeof searchOverride === "string" ? searchOverride : qs("#directoryGroupSearch")?.value;
    const rows = filterDirectoryRows(directoryGroupRows, searchTerm, ["group_id", "display_name", "description", "status"]);
    if (!rows?.length) {
      setTableMessage(tbody, 5, "No groups found.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.group_id);
      appendTableCell(tr, row.display_name);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.description);

      const actions = document.createElement("td");
      actions.className = "cell-actions";
      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "ghost";
      lockBtn.textContent = row.status === "inactive" ? "Unlock" : "Lock";
      lockBtn.addEventListener("click", async () => {
        const result = qs("#directoryGroupResult");
        try {
          await api(`/auth/directory/groups/${encodeURIComponent(row.group_id)}`, {
            method: "PUT",
            body: JSON.stringify({
              group_id: row.group_id,
              display_name: row.display_name,
              description: row.description,
              status: row.status === "inactive" ? "active" : "inactive",
            }),
          });
          if (result) result.textContent = `${row.status === "inactive" ? "Unlocked" : "Locked"} group ${row.group_id}.`;
          await loadDirectoryGroups(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(lockBtn);

      const auditBtn = document.createElement("button");
      auditBtn.type = "button";
      auditBtn.className = "ghost";
      auditBtn.textContent = "Audit";
      auditBtn.addEventListener("click", async () => {
        const result = qs("#directoryGroupResult");
        if (result) result.textContent = `Loaded audit events for group ${row.group_id}.`;
        await loadDirectoryAuditForResource(row.group_id, "#directoryGroupAuditTable");
      });
      actions.appendChild(auditBtn);

      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "ghost";
      removeBtn.textContent = "Delete";
      removeBtn.addEventListener("click", async () => {
        const result = qs("#directoryGroupResult");
        try {
          await api(`/auth/directory/groups/${encodeURIComponent(row.group_id)}`, { method: "DELETE" });
          if (result) result.textContent = `Deleted group ${row.group_id}.`;
          await loadDirectoryGroups(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(removeBtn);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  } catch (err) {
    setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
  }
}

async function upsertDirectoryTeam(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#directoryTeamResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {
    team_id: String(raw.team_id || "").trim(),
    display_name: String(raw.display_name || "").trim(),
    description: String(raw.description || "").trim(),
    status: String(raw.status || "active").trim().toLowerCase(),
  };
  if (!payload.team_id || !payload.display_name) {
    if (result) result.textContent = "Team ID and name are required.";
    return;
  }
  if (payload.description.length > DIRECTORY_DESCRIPTION_MAX_LENGTH) {
    if (result) result.textContent = `Team description must be ${DIRECTORY_DESCRIPTION_MAX_LENGTH} characters or less.`;
    return;
  }

  try {
    await api("/auth/directory/teams", { method: "POST", body: JSON.stringify(payload) });
    if (result) result.textContent = `Created team ${payload.team_id}.`;
  } catch (err) {
    if (String(err.message || "").includes("already exists")) {
      await api(`/auth/directory/teams/${encodeURIComponent(payload.team_id)}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      if (result) result.textContent = `Updated team ${payload.team_id}.`;
    } else {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
      return;
    }
  }
  await loadDirectoryTeams();
}

async function loadDirectoryTeams(searchOverride) {
  const tbody = qs("#directoryTeamsTable");
  if (!tbody) return;
  setTableMessage(tbody, 5, "Loading...");
  try {
    directoryTeamRows = await api("/auth/directory/teams?limit=500");
    const searchTerm = typeof searchOverride === "string" ? searchOverride : qs("#directoryTeamSearch")?.value;
    const rows = filterDirectoryRows(directoryTeamRows, searchTerm, ["team_id", "display_name", "description", "status"]);
    if (!rows?.length) {
      setTableMessage(tbody, 5, "No teams found.");
      return;
    }
    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.team_id);
      appendTableCell(tr, row.display_name);
      appendTableCell(tr, row.status);
      appendTableCell(tr, row.description);

      const actions = document.createElement("td");
      actions.className = "cell-actions";
      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "ghost";
      lockBtn.textContent = row.status === "inactive" ? "Unlock" : "Lock";
      lockBtn.addEventListener("click", async () => {
        const result = qs("#directoryTeamResult");
        try {
          await api(`/auth/directory/teams/${encodeURIComponent(row.team_id)}`, {
            method: "PUT",
            body: JSON.stringify({
              team_id: row.team_id,
              display_name: row.display_name,
              description: row.description,
              status: row.status === "inactive" ? "active" : "inactive",
            }),
          });
          if (result) result.textContent = `${row.status === "inactive" ? "Unlocked" : "Locked"} team ${row.team_id}.`;
          await loadDirectoryTeams(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(lockBtn);

      const auditBtn = document.createElement("button");
      auditBtn.type = "button";
      auditBtn.className = "ghost";
      auditBtn.textContent = "Audit";
      auditBtn.addEventListener("click", async () => {
        const result = qs("#directoryTeamResult");
        if (result) result.textContent = `Loaded audit events for team ${row.team_id}.`;
        await loadDirectoryAuditForResource(row.team_id, "#directoryTeamAuditTable");
      });
      actions.appendChild(auditBtn);

      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "ghost";
      removeBtn.textContent = "Delete";
      removeBtn.addEventListener("click", async () => {
        const result = qs("#directoryTeamResult");
        try {
          await api(`/auth/directory/teams/${encodeURIComponent(row.team_id)}`, { method: "DELETE" });
          if (result) result.textContent = `Deleted team ${row.team_id}.`;
          await loadDirectoryTeams(searchTerm);
        } catch (err) {
          if (result) result.textContent = `Error: ${safeText(err.message)}`;
        }
      });
      actions.appendChild(removeBtn);
      tr.appendChild(actions);
      tbody.appendChild(tr);
    });
  } catch (err) {
    setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
  }
}

async function addMembership(target) {
  const form = qs("#directoryMembershipForm");
  const result = qs("#directoryMembershipResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const userId = String(raw.user_id || "").trim();
  const groupId = String(raw.group_id || "").trim();
  const teamId = String(raw.team_id || "").trim();
  if (!userId) {
    if (result) result.textContent = "User ID is required.";
    return;
  }

  try {
    if (target === "group") {
      if (!groupId) throw new Error("Group ID is required.");
      await api(`/auth/directory/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, { method: "POST" });
      if (result) result.textContent = `Added ${userId} to group ${groupId}.`;
    } else {
      if (!teamId) throw new Error("Team ID is required.");
      await api(`/auth/directory/teams/${encodeURIComponent(teamId)}/members/${encodeURIComponent(userId)}`, { method: "POST" });
      if (result) result.textContent = `Added ${userId} to team ${teamId}.`;
    }
    await loadDirectoryMemberships();
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadDirectoryMemberships() {
  const form = qs("#directoryMembershipForm");
  const result = qs("#directoryMembershipResult");
  const raw = Object.fromEntries(new FormData(form).entries());
  const groupId = String(raw.group_id || "").trim();
  const teamId = String(raw.team_id || "").trim();
  const groupTable = qs("#directoryGroupMembershipsTable");
  const teamTable = qs("#directoryTeamMembershipsTable");

  setTableMessage(groupTable, 5, "Provide Group ID and click Load Memberships.");
  setTableMessage(teamTable, 5, "Provide Team ID and click Load Memberships.");

  try {
    if (groupId) {
      const rows = await api(`/auth/directory/groups/${encodeURIComponent(groupId)}/members`);
      if (!rows?.length) {
        setTableMessage(groupTable, 5, "No group members.");
      } else {
        groupTable.textContent = "";
        rows.forEach((row) => {
          const tr = document.createElement("tr");
          appendTableCell(tr, row.group_id);
          appendTableCell(tr, row.user_id);
          appendTableCell(tr, row.created_by);
          appendTableCell(tr, row.created_at);
          const actions = document.createElement("td");
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "ghost";
          btn.textContent = "Remove";
          btn.addEventListener("click", async () => {
            await api(`/auth/directory/groups/${encodeURIComponent(row.group_id)}/members/${encodeURIComponent(row.user_id)}`, {
              method: "DELETE",
            });
            await loadDirectoryMemberships();
          });
          actions.appendChild(btn);
          tr.appendChild(actions);
          groupTable.appendChild(tr);
        });
      }
    }

    if (teamId) {
      const rows = await api(`/auth/directory/teams/${encodeURIComponent(teamId)}/members`);
      if (!rows?.length) {
        setTableMessage(teamTable, 5, "No team members.");
      } else {
        teamTable.textContent = "";
        rows.forEach((row) => {
          const tr = document.createElement("tr");
          appendTableCell(tr, row.team_id);
          appendTableCell(tr, row.user_id);
          appendTableCell(tr, row.created_by);
          appendTableCell(tr, row.created_at);
          const actions = document.createElement("td");
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "ghost";
          btn.textContent = "Remove";
          btn.addEventListener("click", async () => {
            await api(`/auth/directory/teams/${encodeURIComponent(row.team_id)}/members/${encodeURIComponent(row.user_id)}`, {
              method: "DELETE",
            });
            await loadDirectoryMemberships();
          });
          actions.appendChild(btn);
          tr.appendChild(actions);
          teamTable.appendChild(tr);
        });
      }
    }
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function applySessionPolicyToForm(policy) {
  const form = qs("#sessionPolicyForm");
  if (!form || !policy) return;
  form.elements.description.value = policy.description || "";
  updateSessionPolicyDescriptionCounter();
  form.elements.session_read_roles.value = (policy.session_read_roles || []).join(",");
  form.elements.session_issuer_roles.value = (policy.session_issuer_roles || []).join(",");
  form.elements.issuable_session_roles.value = (policy.issuable_session_roles || []).join(",");
  form.elements.cross_actor_dual_approval_roles.value = (policy.cross_actor_dual_approval_roles || []).join(",");
  form.elements.dual_approval_required_approver_role.value = policy.dual_approval_required_approver_role || "";
  form.elements.privileged_mfa_reauth_minutes.value = Number(policy.privileged_mfa_reauth_minutes || 30);
}

function updateSessionPolicyDescriptionCounter() {
  const form = qs("#sessionPolicyForm");
  const counter = qs("#sessionPolicyDescriptionCount");
  if (!form || !counter) return;
  const length = String(form.elements.description?.value || "").length;
  counter.textContent = `${length} / ${SESSION_POLICY_DESCRIPTION_MAX_LENGTH}`;
}

function updateDirectoryDescriptionCounter(formSelector, counterSelector) {
  const form = qs(formSelector);
  const counter = qs(counterSelector);
  if (!form || !counter) return;
  const length = String(form.elements.description?.value || "").length;
  counter.textContent = `${length} / ${DIRECTORY_DESCRIPTION_MAX_LENGTH}`;
}

async function loadSessionPolicy() {
  const result = qs("#sessionPolicyResult");
  if (result) result.textContent = "Loading session policy...";
  try {
    const data = await api("/auth/policies/session");
    applySessionPolicyToForm(data);
    if (result) result.textContent = `Loaded session policy (${data.source}).`;
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveSessionPolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#sessionPolicyForm");
  const result = qs("#sessionPolicyResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const description = String(raw.description || "").trim();
  if (description.length > SESSION_POLICY_DESCRIPTION_MAX_LENGTH) {
    result.textContent = `Description must be ${SESSION_POLICY_DESCRIPTION_MAX_LENGTH} characters or less.`;
    return;
  }
  result.textContent = "Saving session policy...";
  try {
    const data = await api("/auth/policies/session", {
      method: "PATCH",
      body: JSON.stringify({
        description,
        session_read_roles: parseListInput(raw.session_read_roles),
        session_issuer_roles: parseListInput(raw.session_issuer_roles),
        issuable_session_roles: parseListInput(raw.issuable_session_roles),
        cross_actor_dual_approval_roles: parseListInput(raw.cross_actor_dual_approval_roles),
        dual_approval_required_approver_role: String(raw.dual_approval_required_approver_role || "").trim(),
        privileged_mfa_reauth_minutes: Number(raw.privileged_mfa_reauth_minutes || 30),
      }),
    });
    applySessionPolicyToForm(data);
    result.textContent = "Saved session policy.";
    await loadSessionPolicyRevisions();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadSessionPolicyRevisions() {
  const table = qs("#sessionPolicyRevisionsTable");
  const result = qs("#sessionPolicyResult");
  if (!table) return;
  setTableMessage(table, 6, "Loading...");
  try {
    const rows = await api("/auth/policies/session/revisions?limit=50");
    latestPolicyRevisions = Array.isArray(rows) ? rows : [];
    if (!latestPolicyRevisions.length) {
      setTableMessage(table, 6, "No policy revisions found.");
      return;
    }
    table.textContent = "";
    latestPolicyRevisions.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.revision_id);
      appendTableCell(tr, row.description || "");
      appendTableCell(tr, row.changed_by);
      appendTableCell(tr, row.change_reason);
      appendTableCell(tr, formatComplianceDate(row.created_at));
      const actions = document.createElement("td");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ghost";
      button.textContent = "Use";
      button.addEventListener("click", () => {
        const rollbackForm = qs("#sessionPolicyRollbackForm");
        const revisionInput = rollbackForm?.querySelector('input[name="revision_id"]');
        if (revisionInput) {
          revisionInput.value = row.revision_id;
          revisionInput.focus();
        }
        // Load selected revision values into the main form so operators can review before rollback.
        applySessionPolicyToForm({
          description: row.description,
          session_read_roles: row.session_read_roles,
          session_issuer_roles: row.session_issuer_roles,
          issuable_session_roles: row.issuable_session_roles,
          cross_actor_dual_approval_roles: row.cross_actor_dual_approval_roles,
          dual_approval_required_approver_role: row.dual_approval_required_approver_role,
          privileged_mfa_reauth_minutes: row.privileged_mfa_reauth_minutes,
        });
        if (result) result.textContent = `Loaded ${row.revision_id}. Click "Rollback to Revision" to apply.`;
      });
      actions.appendChild(button);
      tr.appendChild(actions);
      table.appendChild(tr);
    });
  } catch (err) {
    setTableMessage(table, 6, `Error: ${safeText(err.message)}`);
  }
}

async function rollbackSessionPolicy(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#sessionPolicyRollbackForm");
  const result = qs("#sessionPolicyResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const revisionId = String(raw.revision_id || "").trim();
  if (!revisionId) {
    result.textContent = "Revision ID is required for rollback.";
    return;
  }
  result.textContent = `Rolling back to ${revisionId}...`;
  try {
    const data = await api("/auth/policies/session/rollback", {
      method: "POST",
      body: JSON.stringify({
        revision_id: revisionId,
        change_reason: String(raw.change_reason || "rollback").trim(),
      }),
    });
    applySessionPolicyToForm(data);
    result.textContent = `Rolled back to ${revisionId}.`;
    await loadSessionPolicyRevisions();
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function createSsoProvider(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#ssoProviderCreateForm");
  const result = qs("#ssoProviderResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Creating SSO provider...";
  try {
    const data = await api("/auth/sso/providers", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: String(raw.tenant_id || "").trim(),
        protocol_type: String(raw.protocol_type || "OIDC").trim(),
        issuer_or_entity_id: String(raw.issuer_or_entity_id || "").trim(),
        jwks_or_metadata_url: String(raw.jwks_or_metadata_url || "").trim(),
        scim_base_url: String(raw.scim_base_url || "").trim(),
        role_mapping_rules: String(raw.role_mapping_rules || "{}").trim(),
        mfa_required_roles: String(raw.mfa_required_roles || "[]").trim(),
        session_policy_id: String(raw.session_policy_id || "default").trim(),
      }),
    });
    const updateForm = qs("#ssoProviderUpdateForm");
    if (updateForm) updateForm.elements.provider_id.value = data.provider_id;
    result.textContent = `Created SSO provider ${data.provider_id}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function updateSsoProvider(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#ssoProviderUpdateForm");
  const result = qs("#ssoProviderResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const providerId = String(raw.provider_id || "").trim();
  if (!providerId) {
    result.textContent = "Provider ID is required to update.";
    return;
  }
  const payload = {};
  ["jwks_or_metadata_url", "scim_base_url", "role_mapping_rules", "mfa_required_roles", "session_policy_id", "status"].forEach((key) => {
    const value = String(raw[key] || "").trim();
    if (value) payload[key] = value;
  });
  result.textContent = `Updating ${providerId}...`;
  try {
    await api(`/auth/sso/providers/${encodeURIComponent(providerId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    result.textContent = `Updated SSO provider ${providerId}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function testSsoProvider() {
  const form = qs("#ssoProviderUpdateForm");
  const result = qs("#ssoProviderResult");
  if (!form || !result) return;
  const providerId = String(new FormData(form).get("provider_id") || "").trim();
  if (!providerId) {
    result.textContent = "Provider ID is required to test.";
    return;
  }
  try {
    const data = await api(`/auth/sso/providers/${encodeURIComponent(providerId)}/test`, { method: "POST" });
    result.textContent = `SSO provider ${providerId} test status: ${data.test_status}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function syncScimProvider() {
  const form = qs("#ssoProviderUpdateForm");
  const result = qs("#ssoProviderResult");
  if (!form || !result) return;
  const providerId = String(new FormData(form).get("provider_id") || "").trim();
  if (!providerId) {
    result.textContent = "Provider ID is required for SCIM sync.";
    return;
  }
  try {
    const data = await api(`/auth/sso/providers/${encodeURIComponent(providerId)}/scim/sync`, { method: "POST" });
    result.textContent = `SCIM sync completed for ${providerId}: ${data.synced_users} users, ${data.synced_groups} groups.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function validateRoleBinding(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#roleBindingValidateForm");
  const result = qs("#roleBindingValidateResult");
  const details = qs("#roleBindingExplainDetails");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const payload = {
    role_name: String(raw.role_name || "").trim(),
    resource_pattern: String(raw.resource_pattern || "").trim(),
    action: String(raw.action || "").trim(),
  };
  try {
    const data = await api("/auth/roles/bindings/validate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (details) {
      details.textContent = JSON.stringify({
        request: payload,
        response: data,
        interpretation: data.valid
          ? "Role/action combination is currently accepted by policy validation."
          : "Role/action combination is currently rejected by policy validation.",
      }, null, 2);
    }
    result.textContent = `Role binding validation for ${safeText(data.role)}: ${data.valid ? "valid" : "invalid"}.`;
    await loadRoleBindingEvidence(payload.role_name);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function runRoleBindingExplainability(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#roleBindingExplainForm");
  const result = qs("#roleBindingValidateResult");
  const details = qs("#roleBindingExplainDetails");
  const table = qs("#roleBindingExplainTable");
  if (!form || !result || !table) return;

  const raw = Object.fromEntries(new FormData(form).entries());
  const roleName = String(raw.role_name || "").trim();
  const actions = parseListInput(raw.actions_csv);
  const resources = parseListInput(raw.resource_patterns_csv);
  if (!roleName || !actions.length || !resources.length) {
    result.textContent = "Role, actions CSV, and resource patterns CSV are required.";
    return;
  }

  setTableMessage(table, 5, "Running explainability matrix...");
  result.textContent = "Running role-binding explainability matrix...";

  const combinations = [];
  actions.forEach((action) => {
    resources.forEach((resourcePattern) => {
      combinations.push({ role_name: roleName, action, resource_pattern: resourcePattern });
    });
  });

  try {
    const responses = await Promise.all(combinations.map((payload) => api("/auth/roles/bindings/validate", {
      method: "POST",
      body: JSON.stringify(payload),
    }).then((data) => ({ payload, data, error: null })).catch((error) => ({ payload, data: null, error }))));

    table.textContent = "";
    let validCount = 0;
    let invalidCount = 0;
    responses.forEach((entry) => {
      const decision = entry.data?.valid === true ? "valid" : "invalid";
      if (entry.data?.valid === true) validCount += 1;
      else invalidCount += 1;
      appendTableRow(table, [
        entry.payload.role_name,
        entry.payload.action,
        entry.payload.resource_pattern,
        decision,
        entry.error ? safeText(entry.error.message) : "policy validation",
      ]);
    });

    if (details) {
      details.textContent = JSON.stringify({
        role_name: roleName,
        combinations_tested: responses.length,
        valid_count: validCount,
        invalid_count: invalidCount,
      }, null, 2);
    }
    result.textContent = `Explainability matrix complete for ${safeText(roleName)}: ${validCount} valid, ${invalidCount} invalid.`;
    await loadRoleBindingEvidence(roleName);
  } catch (err) {
    setTableMessage(table, 5, `Error: ${safeText(err.message)}`);
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadRoleBindingEvidence(roleNameArg) {
  const result = qs("#roleBindingValidateResult");
  const evidenceTable = qs("#roleBindingEvidenceTable");
  const roleName = String(
    roleNameArg
      || qs("#roleBindingValidateForm")?.elements?.role_name?.value
      || qs("#roleBindingExplainForm")?.elements?.role_name?.value
      || ""
  ).trim();
  if (!evidenceTable) return;
  if (!roleName) {
    if (result) result.textContent = "Role is required to load evidence.";
    return;
  }

  setTableMessage(evidenceTable, 5, "Loading...");
  try {
    const query = buildQueryString({
      action_type: "auth.role_binding.validate",
      resource_type: "role_binding",
      resource_id: roleName,
      since_hours: 168,
      limit: 50,
      offset: 0,
    });
    const rows = await api(`/audit/events${query}`, {
      headers: { "X-Actor-Role": "Auditor" },
    });
    if (!rows?.length) {
      setTableMessage(evidenceTable, 5, `No evidence events found for ${safeText(roleName)}.`);
      return;
    }
    evidenceTable.textContent = "";
    rows.forEach((row) => {
      appendTableRow(evidenceTable, [
        formatComplianceDate(row.timestamp),
        row.actor_id,
        row.resource_id,
        row.decision_outcome,
        row.trace_id,
      ]);
    });
  } catch (err) {
    setTableMessage(evidenceTable, 5, `Error: ${safeText(err.message)}`);
  }
}

async function handleLoadRoleBindingEvidenceClick() {
  await loadRoleBindingEvidence();
}

async function issueGovernedSession(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#issueSessionForm");
  const result = qs("#sessionGovernanceResult");
  const details = qs("#sessionGovernanceDetails");
  if (!form || !result || !details) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  result.textContent = "Issuing session...";
  try {
    const data = await api("/auth/sessions", {
      method: "POST",
      body: JSON.stringify({
        actor_id: String(raw.actor_id || "").trim(),
        actor_role: String(raw.actor_role || "").trim(),
        ttl_minutes: Number(raw.ttl_minutes || 60),
        idle_timeout_minutes: Number(raw.idle_timeout_minutes || 30),
        mfa_verified: String(raw.mfa_verified || "true") === "true",
      }),
    });
    const lookupForm = qs("#sessionLookupForm");
    if (lookupForm) lookupForm.elements.session_id.value = data.session_id;
    result.textContent = `Issued session ${data.session_id}.`;
    details.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function loadGovernedSession() {
  const form = qs("#sessionLookupForm");
  const result = qs("#sessionGovernanceResult");
  const details = qs("#sessionGovernanceDetails");
  if (!form || !result || !details) return;
  const sessionId = String(new FormData(form).get("session_id") || "").trim();
  if (!sessionId) {
    result.textContent = "Session ID is required.";
    return;
  }
  result.textContent = `Loading session ${sessionId}...`;
  try {
    const data = await api(`/auth/sessions/${encodeURIComponent(sessionId)}`);
    result.textContent = `Loaded session ${sessionId}.`;
    details.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function reauthGovernedSession() {
  const form = qs("#sessionLookupForm");
  const result = qs("#sessionGovernanceResult");
  const details = qs("#sessionGovernanceDetails");
  if (!form || !result || !details) return;
  const sessionId = String(new FormData(form).get("session_id") || "").trim();
  if (!sessionId) {
    result.textContent = "Session ID is required.";
    return;
  }
  result.textContent = `Reauthenticating session ${sessionId}...`;
  try {
    const data = await api(`/auth/sessions/${encodeURIComponent(sessionId)}/reauth`, { method: "POST" });
    result.textContent = `Session ${sessionId} reauthenticated.`;
    details.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function saveBasicAuthConfig(evt) {
  if (evt?.preventDefault) evt.preventDefault();
  const form = qs("#basicAuthConfigForm");
  const result = qs("#basicAuthResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const configId = String(raw.config_id || "").trim();
  const payload = {
    tenant_id: String(raw.tenant_id || "").trim(),
    environment: String(raw.environment || "").trim(),
    allowed_user_groups: String(raw.allowed_user_groups || "[]").trim(),
    ip_allowlist: String(raw.ip_allowlist || "[]").trim(),
    max_enable_duration_minutes: Number(raw.max_enable_duration_minutes || 60),
  };
  try {
    if (configId) {
      await api(`/auth/basic/config/${encodeURIComponent(configId)}`, {
        method: "PATCH",
        body: JSON.stringify({
          allowed_user_groups: payload.allowed_user_groups,
          ip_allowlist: payload.ip_allowlist,
          max_enable_duration_minutes: payload.max_enable_duration_minutes,
        }),
      });
      result.textContent = `Updated basic-auth config ${configId}.`;
    } else {
      const data = await api("/auth/basic/config", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      form.elements.config_id.value = data.basic_auth_config_id;
      const toggleForm = qs("#basicAuthToggleForm");
      if (toggleForm) toggleForm.elements.config_id.value = data.basic_auth_config_id;
      result.textContent = `Created basic-auth config ${data.basic_auth_config_id}.`;
    }
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function enableBasicAuthTemporary() {
  const form = qs("#basicAuthToggleForm");
  const result = qs("#basicAuthResult");
  if (!form || !result) return;
  const raw = Object.fromEntries(new FormData(form).entries());
  const configId = String(raw.config_id || "").trim();
  if (!configId) {
    result.textContent = "Config ID is required to enable break-glass auth.";
    return;
  }
  result.textContent = `Enabling temporary basic auth for ${configId}...`;
  try {
    const data = await api(`/auth/basic/config/${encodeURIComponent(configId)}/enable-temporary`, {
      method: "POST",
      body: JSON.stringify({
        break_glass_reason: String(raw.break_glass_reason || "emergency").trim(),
        duration_minutes: Number(raw.duration_minutes || 30),
      }),
    });
    result.textContent = `Enabled basic auth for ${configId} until ${formatComplianceDate(data.expires_at)}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function disableBasicAuthTemporary() {
  const form = qs("#basicAuthToggleForm");
  const result = qs("#basicAuthResult");
  if (!form || !result) return;
  const configId = String(new FormData(form).get("config_id") || "").trim();
  if (!configId) {
    result.textContent = "Config ID is required to disable break-glass auth.";
    return;
  }
  result.textContent = `Disabling basic auth for ${configId}...`;
  try {
    await api(`/auth/basic/config/${encodeURIComponent(configId)}/disable`, { method: "POST" });
    result.textContent = `Disabled basic auth for ${configId}.`;
  } catch (err) {
    result.textContent = `Error: ${safeText(err.message)}`;
  }
}

async function registerAgent(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const result = qs("#agentRegisterResult");
  const payload = Object.fromEntries(new FormData(form).entries());

  try {
    const data = await api("/agents/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    result.textContent = `Registered: ${data.agent_id}`;

    const current = await loadAgentConfigsFromStorage();
    const exists = current.some((item) => item.agent_key === data.agent_id);
    if (!exists) {
      const normalizedType = String(payload.agent_type || "other").trim().toLowerCase();
      const providerMap = {
        aws: "aws",
        azure: "azure",
        gcp: "google",
      };
      const configuredProviderFallback = String(qs('#agentConfigForm select[name="provider"]')?.value || "").trim().toLowerCase();
      const providerFromType = providerMap[normalizedType] || configuredProviderFallback || "aws";
      current.push(
        normalizeAgentConfig({
          agent_key: data.agent_id,
          display_name: payload.name,
          provider: providerFromType,
          model: "gpt-4o-mini",
          provider_priority: "aws,azure,google",
          temperature: 0.3,
          max_tokens: 1024,
          timeout_ms: 4500,
          fallback_enabled: true,
          max_fallback_hops: 2,
          global_timeout_ms: 4500,
          retry_budget: 1,
          failure_threshold_percent: 40,
          cooldown_seconds: 60,
          environment: state.environmentProfile === "custom" ? "dev" : state.environmentProfile,
          enabled: true,
          notes: `Bootstrap config created from register action for owner ${payload.owner_id}`,
        }),
      );
      await saveAgentConfigsToStorage(current);
      await renderAgentConfigTable();
      await runConfigSecurityReview();
    }

    await Promise.all([loadOverview(), loadAudit()]);
  } catch (err) {
    result.textContent = `Error: ${err.message}`;
  }
}

async function loadOwnerAgents(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const ownerId = String(new FormData(form).get("owner_id") || "").trim();
  const result = qs("#ownerAgentsResult");
  const tbody = qs("#ownerAgentsTable");

  if (!ownerId) {
    if (result) result.textContent = "Owner ID is required.";
    return;
  }

  setTableMessage(tbody, 8, "Loading...");
  try {
    const rows = await api(`/owners/${encodeURIComponent(ownerId)}/agents`);
    if (result) result.textContent = `Loaded ${rows.length} agents for ${ownerId}.`;
    if (!rows.length) {
      setTableMessage(tbody, 8, "No agents found for this owner.");
      return;
    }

    tbody.textContent = "";
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      appendTableCell(tr, row.agent_id);
      appendTableCell(tr, row.name);
      appendTableCell(tr, row.agent_type);
      appendTableCell(tr, row.description);
      appendTableCell(tr, row.owner_id);
      appendTableCell(tr, row.owner_team);
      appendTableCell(tr, row.status);

      const actionsCell = document.createElement("td");
      actionsCell.className = "cell-actions";
      const historyBtn = document.createElement("button");
      historyBtn.type = "button";
      historyBtn.className = "ghost";
      historyBtn.textContent = "History";
      historyBtn.addEventListener("click", () => loadOwnershipHistoryById(row.agent_id));
      actionsCell.appendChild(historyBtn);
      tr.appendChild(actionsCell);
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 8, `Error: ${safeText(err.message)}`);
  }
}

async function loadOwnershipHistoryById(agentId) {
  const result = qs("#ownershipHistoryResult");
  const tbody = qs("#ownershipHistoryTable");
  const form = qs("#ownershipHistoryForm");
  if (form) form.elements.agent_id.value = agentId;

  setTableMessage(tbody, 6, "Loading...");
  try {
    const rows = await api(`/agents/${encodeURIComponent(agentId)}/ownership-history`);
    if (result) result.textContent = `Loaded ${rows.length} history events for ${agentId}.`;
    if (!rows.length) {
      setTableMessage(tbody, 6, "No ownership history for this agent.");
      return;
    }

    tbody.textContent = "";
    rows.forEach((row) => {
      appendTableRow(tbody, [
        row.changed_at,
        row.old_owner_id,
        row.new_owner_id,
        row.changed_by,
        row.reason,
        row.ticket_ref,
      ]);
    });
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
    setTableMessage(tbody, 6, `Error: ${safeText(err.message)}`);
  }
}

async function loadOwnershipHistory(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const agentId = String(new FormData(form).get("agent_id") || "").trim();
  if (!agentId) {
    const result = qs("#ownershipHistoryResult");
    if (result) result.textContent = "Agent ID is required.";
    return;
  }
  await loadOwnershipHistoryById(agentId);
}

async function transferOwner(evt) {
  evt.preventDefault();
  const form = evt.currentTarget;
  const raw = Object.fromEntries(new FormData(form).entries());
  const agentId = String(raw.agent_id || "").trim();
  const result = qs("#transferOwnerResult");

  if (!agentId) {
    if (result) result.textContent = "Agent ID is required.";
    return;
  }

  try {
    const updated = await api(`/agents/${encodeURIComponent(agentId)}/owner`, {
      method: "PATCH",
      body: JSON.stringify({
        new_owner_id: String(raw.new_owner_id || "").trim(),
        new_owner_name: String(raw.new_owner_name || "").trim(),
        new_owner_team: String(raw.new_owner_team || "").trim(),
        reason: String(raw.reason || "").trim(),
        ticket_ref: String(raw.ticket_ref || "").trim(),
      }),
    });
    if (result) result.textContent = `Transferred ${agentId} to ${updated.owner_id}.`;
    await loadOwnershipHistoryById(agentId);
  } catch (err) {
    if (result) result.textContent = `Error: ${safeText(err.message)}`;
  }
}

function bindEvents() {
  qsa(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  const themeToggle = qs("#themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      applyTheme(state.theme === "dark" ? "light" : "dark");
    });
  }

  qs("#saveContext").addEventListener("click", async () => {
    const statusTarget = qs("#healthStatus");
    try {
      saveContext();
      switchRuntimeRuleValidationContext("Loaded validation status for the current context.");
      await refreshUiFeatureFlags();
      await loadOverview();
    } catch (err) {
      statusTarget.textContent = `Error: ${safeText(err.message)}`;
    }
  });

  if (qs("#loginSession")) {
    qs("#loginSession").addEventListener("click", async () => {
      const statusTarget = qs("#healthStatus");
      try {
        await signInWithPrompt();
      } catch (err) {
        if (statusTarget) statusTarget.textContent = `Error: ${safeText(err.message)}`;
      }
    });
  }

  if (qs("#signOutSession")) {
    qs("#signOutSession").addEventListener("click", () => {
      signOutSession();
    });
  }

  if (qs("#headerSignOut")) {
    qs("#headerSignOut").addEventListener("click", () => {
      signOutSession();
    });
  }

  qs("#applyProfile").addEventListener("click", async () => {
    const statusTarget = qs("#healthStatus");
    try {
      applySelectedProfile();
      saveContext();
      switchRuntimeRuleValidationContext("Loaded validation status for the selected profile.");
      await refreshUiFeatureFlags();
      await loadOverview();
    } catch (err) {
      statusTarget.textContent = `Error: ${safeText(err.message)}`;
    }
  });

  qs("#probeProfiles").addEventListener("click", probeProfiles);

  qs("#refreshAll").addEventListener("click", async () => {
    await Promise.all([
      loadOverview(),
      renderRuntimeConfigTable(),
      loadProviderConsole(),
      loadModulesConsole(),
      loadAgenticConsole(),
      loadDiscovery(),
      loadComplianceWorkspace(),
      loadCost(),
      loadGatewayAnalytics(),
      loadCostAnomalies(),
      loadAudit(),
      loadSessionPolicy(),
      loadSessionPolicyRevisions(),
      loadObservability(),
    ]);
  });

  qs("#loadRuntimeConfigs").addEventListener("click", renderRuntimeConfigTable);
  qs("#runtimeConfigForm").addEventListener("submit", saveRuntimeConfig);
  qs("#runtimeConfigForm").elements.config_key.addEventListener("input", (evt) => {
    updateRuntimeValidationHint(evt.target.value);
  });
  qs("#runtimeValidationSearch").addEventListener("input", () => renderRuntimeValidationRulesTable());
  qs("#refreshRuntimeValidationRules").addEventListener("click", async () => {
    await loadRuntimeValidationRules();
    clearRuntimeRuleValidationState("Validation status cleared after reloading rules.");
  });
  qs("#clearRuntimeValidationStatus").addEventListener("click", () => {
    clearRuntimeRuleValidationState("Validation status cleared.");
  });
  qs("#resetRuntimeConfigForm").addEventListener("click", () => resetRuntimeConfigForm("Form reset."));
  qs("#loadDiscovery").addEventListener("click", loadDiscovery);
  qs("#loadDiscoverySources").addEventListener("click", loadDiscoverySources);
  qs("#syncRuntimeInventory").addEventListener("click", () => syncDiscoverySource("runtime_inventory"));
  qs("#syncCodeMetadata").addEventListener("click", () => syncDiscoverySource("code_metadata"));
  qs("#syncGatewayTelemetry").addEventListener("click", () => syncDiscoverySource("gateway_telemetry"));
  qs("#loadDiscoveryConflicts").addEventListener("click", loadDiscoveryConflicts);
  qs("#loadDiscoveryAlerts").addEventListener("click", loadDiscoveryAlerts);
  qs("#loadDiscoveryPromoteQueue").addEventListener("click", loadDiscoveryPromoteQueue);
  qs("#loadTenantCatalog").addEventListener("click", loadTenantCatalog);
  qs("#loadWorkloadIdentityProviders").addEventListener("click", loadWorkloadIdentityProviders);
  qs("#loadSecretProviders").addEventListener("click", loadSecretProviders);
  qs("#loadModules").addEventListener("click", loadModules);
  qs("#moduleRegisterForm").addEventListener("submit", registerModule);
  qs("#moduleVersionsForm").addEventListener("submit", submitModuleVersionsForm);
  qs("#moduleValidateForm").addEventListener("submit", validateModuleForAgent);
  qs("#moduleUpgradePlanForm").addEventListener("submit", planModuleUpgrade);
  qs("#moduleDeprecateForm").addEventListener("submit", deprecateModule);
  qs("#loadAgenticReadinessReport").addEventListener("click", loadAgenticReadinessReport);
  qs("#agenticContractValidateForm").addEventListener("submit", validateAgenticContract);
  qs("#agenticRunCertificationForm").addEventListener("submit", runAgenticCertification);
  qs("#agenticCertificationActionForm").addEventListener("submit", submitAgenticCertificationActionForm);
  qs("#loadAgenticCertifications").addEventListener("click", loadAgenticCertifications);
  qs("#loadLatestAgenticCertification").addEventListener("click", loadLatestAgenticCertification);
  qs("#agenticLoadTestRunForm").addEventListener("submit", runAgenticLoadTest);
  qs("#loadLatestAgenticLoadTest").addEventListener("click", loadLatestAgenticLoadTest);
  qs("#agenticCheckpointCreateForm").addEventListener("submit", createAgenticCheckpoint);
  qs("#loadAgenticCheckpoints").addEventListener("click", () => loadAgenticCheckpoints());
  qs("#resumeAgenticCheckpoint").addEventListener("click", () => resumeAgenticCheckpoint());
  qs("#agenticPolicyAutoTuneForm").addEventListener("submit", runAgenticPolicyAutoTune);
  qs("#policyScheduleCreateForm").addEventListener("submit", createPolicySchedule);
  qs("#policyScheduledOptimizeForm").addEventListener("submit", runPolicyScheduledOptimize);
  qs("#policyScheduleSummaryFilters").addEventListener("submit", loadPolicyScheduleSummary);
  qs("#policyScheduleUpdateForm").addEventListener("submit", updatePolicySchedule);
  qs("#loadPolicySchedules").addEventListener("click", loadPolicySchedules);
  qs("#loadPolicyScheduleSummary").addEventListener("click", loadPolicyScheduleSummary);
  qs("#loadPolicyScheduleDetail").addEventListener("click", () => loadPolicyScheduleDetail());
  qs("#policyScheduleActionForm").addEventListener("submit", runPolicyScheduleAction);
  qs("#tenantCatalogForm").addEventListener("submit", saveTenantCatalogEntry);
  qs("#resetTenantCatalogForm").addEventListener("click", () => resetTenantCatalogForm("Form reset."));
  qs("#workloadIdentityProviderFilters").addEventListener("submit", loadWorkloadIdentityProviders);
  qs("#workloadTokenExchangeForm").addEventListener("submit", exchangeWorkloadIdentityToken);
  qs("#workloadIdentityTrustForm").addEventListener("submit", validateWorkloadIdentityTrust);
  qs("#workloadIdentityHealthForm").addEventListener("submit", submitWorkloadIdentityHealthForm);
  qs("#loadWorkloadTrustEvidence").addEventListener("click", handleLoadWorkloadTrustEvidenceClick);
  qs("#secretProviderFilters").addEventListener("submit", loadSecretProviders);
  qs("#secretProviderLeaseRenewForm").addEventListener("submit", renewSecretProviderLease);
  qs("#secretProviderHealthForm").addEventListener("submit", submitSecretProviderHealthForm);
  qs("#loadSecretProviderLeases").addEventListener("click", handleSecretProviderLeasesClick);
  qs("#createWorkloadIdentityProviderForm").addEventListener("submit", createWorkloadIdentityProvider);
  qs("#createSecretProviderForm").addEventListener("submit", createSecretProvider);
  qs("#rotateViaSecretProviderForm").addEventListener("submit", rotateKeyViaSecretProvider);
  qs("#createWorkloadIdentityProviderForm").elements.tenant_id.addEventListener("change", () => {
    syncTenantMetadataFields(qs("#createWorkloadIdentityProviderForm"));
  });
  qs("#createSecretProviderForm").elements.tenant_id.addEventListener("change", () => {
    syncTenantMetadataFields(qs("#createSecretProviderForm"));
  });
  qs("#supportedModelForm").addEventListener("submit", saveSupportedModel);
  qs("#supportedModelFilters").addEventListener("submit", loadSupportedModels);
  qs("#resetSupportedModelForm").addEventListener("click", () => resetSupportedModelForm("Form reset."));
  qs("#tenantModelEntitlementForm").addEventListener("submit", saveTenantModelEntitlement);
  qs("#tenantModelEntitlementFilters").addEventListener("submit", loadTenantModelEntitlements);
  qs("#resetTenantModelEntitlementForm").addEventListener("click", () =>
    resetTenantModelEntitlementForm("Form reset.")
  );
  qs("#loadCost").addEventListener("click", loadCost);
  qs("#loadCostPricingCatalog").addEventListener("click", loadCostPricingCatalog);
  qs("#costPricingCalculatorForm").addEventListener("submit", calculateCostPricing);
  qs("#costSpendTrackForm").addEventListener("submit", trackSpendEvent);
  qs("#loadGatewayAnalytics").addEventListener("click", loadGatewayAnalytics);
  qs("#gatewayAnalyticsFilters").addEventListener("submit", loadGatewayAnalytics);
  qs("#costBudgetForm").addEventListener("submit", saveCostBudgetPolicy);
  qs('#costBudgetForm select[name="scope_type"]').addEventListener("change", () => {
    syncScopeIdPicker("#costBudgetForm", "scope_type", "scope_id", "costBudgetScopeIdList");
  });
  qs('#costBudgetForm input[name="scope_id"]').addEventListener("focus", () => {
    syncScopeIdPicker("#costBudgetForm", "scope_type", "scope_id", "costBudgetScopeIdList");
  });
  qs("#loadCostBudgets").addEventListener("click", loadCostBudgetPolicies);
  qs("#resetCostBudgetForm").addEventListener("click", () => resetCostBudgetForm("Budget form reset."));
  qs("#costPolicyEvalForm").addEventListener("submit", evaluateCostPolicy);
  qs('#costPolicyEvalForm select[name="scope_type"]').addEventListener("change", () => {
    syncScopeIdPicker("#costPolicyEvalForm", "scope_type", "scope_id", "costPolicyEvalScopeIdList");
  });
  qs('#costPolicyEvalForm input[name="scope_id"]').addEventListener("focus", () => {
    syncScopeIdPicker("#costPolicyEvalForm", "scope_type", "scope_id", "costPolicyEvalScopeIdList");
  });
  qs("#costLimitEvalForm").addEventListener("submit", evaluateCostLimits);
  qs("#loadCostAnomalies").addEventListener("click", loadCostAnomalies);
  qs("#loadCostSessionDrilldown").addEventListener("click", () => loadCostDrilldown("session"));
  qs("#loadCostAgentDrilldown").addEventListener("click", () => loadCostDrilldown("agent"));
  qs("#loadSpendBreakdown").addEventListener("click", loadSpendBreakdown);
  qs("#spendBreakdownDimension").addEventListener("change", loadSpendBreakdown);
  qs("#spendBreakdownDimension").addEventListener("change", updateSpendFilterControls);
  qs("#spendBreakdownRange").addEventListener("change", () => {
    updateSpendFilterControls();
    loadSpendBreakdown();
  });
  qs("#spendBreakdownStartDate").addEventListener("change", loadSpendBreakdown);
  qs("#spendBreakdownEndDate").addEventListener("change", loadSpendBreakdown);
  qs("#spendBreakdownStartTime").addEventListener("change", loadSpendBreakdown);
  qs("#spendBreakdownEndTime").addEventListener("change", loadSpendBreakdown);
  qs("#spendBreakdownScopeFilter").addEventListener("change", loadSpendBreakdown);
  qs("#loadAudit").addEventListener("click", loadAudit);
  qs("#loadComplianceControls").addEventListener("click", loadComplianceControls);
  qs("#loadComplianceCoverage").addEventListener("click", loadComplianceCoverage);
  qs("#loadComplianceFreshness").addEventListener("click", loadComplianceFreshness);
  qs("#loadComplianceMappings").addEventListener("click", loadComplianceMappings);
  qs("#loadComplianceEvidence").addEventListener("click", loadComplianceEvidence);
  qs("#loadComplianceEvidenceBundle").addEventListener("click", loadComplianceEvidenceBundle);
  qs("#refreshComplianceEvidence").addEventListener("click", loadComplianceEvidence);
  qs("#complianceMappingForm").addEventListener("submit", saveComplianceMapping);
  qs("#resetComplianceMappingForm").addEventListener("click", () => {
    const form = qs("#complianceMappingForm");
    if (form) form.reset();
    setComplianceText("#complianceMappingResult", "Compliance mapping form reset.");
  });
  qs("#complianceEvidenceForm").addEventListener("submit", generateComplianceEvidence);
  qs("#loadRetentionPolicies").addEventListener("click", loadRetentionPolicies);
  qs("#retentionPolicyForm").addEventListener("submit", saveRetentionPolicy);
  qs("#resetRetentionPolicyForm").addEventListener("click", () => {
    const form = qs("#retentionPolicyForm");
    if (form) form.reset();
    setComplianceText("#retentionPolicyResult", "Retention policy form reset.");
  });
  qs("#loadLegalHolds").addEventListener("click", loadLegalHolds);
  qs("#legalHoldForm").addEventListener("submit", placeLegalHold);
  qs("#resetLegalHoldForm").addEventListener("click", () => {
    const form = qs("#legalHoldForm");
    if (form) form.reset();
    setComplianceText("#legalHoldResult", "Legal hold form reset.");
  });
  qs("#playgroundRunForm").addEventListener("submit", runPlaygroundPrompt);
  qs("#runPlaygroundPrompt").addEventListener("click", runPlaygroundPrompt);
  qs("#judgePlaygroundPrompt").addEventListener("click", judgePlaygroundPrompt);
  qs("#retryPlaygroundPrompt").addEventListener("click", () => retryPlaygroundPrompt());
  qs("#applyPlaygroundWinner").addEventListener("click", () => applyPlaygroundWinner());
  qs("#playgroundRunHistoryFilters").addEventListener("submit", loadPlaygroundRuns);
  qs("#loadPlaygroundRuns").addEventListener("click", loadPlaygroundRuns);
  qs("#loadSelectedPlaygroundRun").addEventListener("click", () => loadPlaygroundRunDetails());
  qs("#loadPlaygroundTestSets").addEventListener("click", loadPlaygroundTestSets);
  qs("#clearPlaygroundStream").addEventListener("click", () => {
    stopPlaygroundStream();
    updatePlaygroundStreamLog("");
  });
  qs("#playgroundVideoInput").addEventListener("change", async (evt) => {
    const selected = await capturePlaygroundAttachments(evt.target.files, "video");
    playgroundAttachments = [
      ...playgroundAttachments.filter((item) => item.kind !== "video"),
      ...selected,
    ];
    renderPlaygroundAttachments();
  });
  qs("#playgroundVoiceInput").addEventListener("change", async (evt) => {
    const selected = await capturePlaygroundAttachments(evt.target.files, "voice");
    playgroundAttachments = [
      ...playgroundAttachments.filter((item) => item.kind !== "voice"),
      ...selected,
    ];
    renderPlaygroundAttachments();
  });
  qs("#togglePlaygroundMic").addEventListener("click", togglePlaygroundMic);
  qs("#runBenchmark").addEventListener("click", runBenchmark);
  qs("#runScan").addEventListener("click", runScan);
  qs("#loadBenchmarkHistory").addEventListener("click", loadBenchmarkHistory);
  qs("#loadScanHistory").addEventListener("click", loadScanHistory);
  qs("#agentQualityForm").addEventListener("submit", (evt) => evt.preventDefault());
  qs("#routePolicyForm").addEventListener("submit", saveRoutePolicy);
  qs("#loadRoutePolicies").addEventListener("click", loadRoutePolicies);
  qs("#loadKeys").addEventListener("click", loadKeys);
  qs("#keyLifecycleForm").addEventListener("submit", saveKey);
  qs("#keyGuardrailEvalForm").addEventListener("submit", evaluateKeyGuardrails);

  document.addEventListener("submit", (evt) => {
    if (isFormSubmitEventFor(evt, "keyBudgetIncreaseForm")) {
      applyTemporaryKeyBudgetIncrease(evt);
      return;
    }
    if (isFormSubmitEventFor(evt, "keyRotationScheduleForm")) {
      saveKeyRotationSchedule(evt);
    }
  });
  document.addEventListener("click", (evt) => {
    if (isClickEventFor(evt, "loadKeyRotationSchedules")) {
      loadKeyRotationSchedules(evt);
    }
  });
  qs("#guardrailTemplateBalanced").addEventListener("click", () => applyGuardrailTemplate("balanced"));
  qs("#guardrailTemplateStrictProd").addEventListener("click", () => applyGuardrailTemplate("strict_prod"));
  qs("#guardrailTemplateDevSandbox").addEventListener("click", () => applyGuardrailTemplate("dev_sandbox"));
  qs('#keyLifecycleForm textarea[name="guardrail_policy"]').addEventListener("input", (evt) => {
    renderKeyGuardrailPolicySummary(evt.currentTarget.value);
  });
  qs('#keyLifecycleForm select[name="owner_scope_type"]').addEventListener("change", () => {
    syncScopeIdPicker("#keyLifecycleForm", "owner_scope_type", "owner_scope_id", "keyOwnerScopeIdList");
  });
  qs('#keyLifecycleForm input[name="owner_scope_id"]').addEventListener("focus", () => {
    syncScopeIdPicker("#keyLifecycleForm", "owner_scope_type", "owner_scope_id", "keyOwnerScopeIdList");
  });
  qs("#routePriorityForm").addEventListener("submit", saveRoutePriority);
  qs("#loadRoutePriority").addEventListener("click", () => loadRoutePriorityReadback());
  qs("#routePriorityTimelineForm").addEventListener("submit", loadRoutePriorityTimeline);
  qs("#routeProviderHealthForm").addEventListener("submit", saveRouteProviderHealth);
  qs("#loadRouteProviderHealth").addEventListener("click", loadRouteProviderHealth);
  qs("#routePreCallFiltersForm").addEventListener("submit", saveRoutePreCallFilters);
  qs("#loadRoutePreCallFilters").addEventListener("click", loadRoutePreCallFilters);
  qs("#routeTrafficMirroringForm").addEventListener("submit", saveRouteTrafficMirroring);
  qs("#loadRouteTrafficMirroring").addEventListener("click", loadRouteTrafficMirroring);
  qs("#routeTrafficMirroringAnalyticsForm").addEventListener("submit", loadRouteTrafficMirroringAnalytics);
  qs("#loadRouteTrafficMirroringAnalytics").addEventListener("click", loadRouteTrafficMirroringAnalytics);
  qs("#loadRouteTrafficMirroringReport").addEventListener("click", loadRouteTrafficMirroringReport);
  qs("#gatewayEntitlementFiltersForm").addEventListener("submit", loadGatewayEntitlements);
  qs("#gatewayEntitlementForm").addEventListener("submit", saveGatewayEntitlement);
  qs("#loadGatewayEntitlements").addEventListener("click", loadGatewayEntitlements);
  qs("#gatewayNhiFiltersForm").addEventListener("submit", loadGatewayNhiInventory);
  qs("#loadGatewayNhiInventory").addEventListener("click", loadGatewayNhiInventory);
  qs("#loadGatewayNhiHygiene").addEventListener("click", loadGatewayNhiHygiene);
  qs("#createGatewayAccessReviewCampaign").addEventListener("click", createGatewayAccessReviewCampaign);
  qs("#loadGatewayAccessReviewCampaign").addEventListener("click", loadGatewayAccessReviewCampaign);
  qs("#gatewayJitRequestForm").addEventListener("submit", createGatewayJitRequest);
  qs("#gatewayJitApproveForm").addEventListener("submit", approveGatewayJitRequest);
  qs("#gatewayLeastPrivilegeFiltersForm").addEventListener("submit", loadGatewayLeastPrivilegeRecommendations);
  qs("#loadGatewayLeastPrivilegeRecommendations").addEventListener("click", loadGatewayLeastPrivilegeRecommendations);
  qs("#gatewayGovernanceEvidenceForm").addEventListener("submit", loadGatewayGovernanceEvidence);
  qs("#loadGatewayGovernanceEvidence").addEventListener("click", loadGatewayGovernanceEvidence);
  qs("#exportGatewayGovernanceEvidence").addEventListener("click", exportGatewayGovernanceEvidence);
  qs("#gatewayOpenAiChatForm").addEventListener("submit", runGatewayOpenAiChatCompletion);
  qs("#runGatewayOpenAiChat").addEventListener("click", runGatewayOpenAiChatCompletion);
  qs("#gatewayOpenAiResponsesCreateForm").addEventListener("submit", createGatewayOpenAiResponse);
  qs("#createGatewayOpenAiResponse").addEventListener("click", createGatewayOpenAiResponse);
  qs("#loadGatewayOpenAiResponses").addEventListener("click", loadGatewayOpenAiResponses);
  qs("#getGatewayOpenAiResponse").addEventListener("click", () => loadGatewayOpenAiResponseById());
  qs("#deleteGatewayOpenAiResponse").addEventListener("click", () => deleteGatewayOpenAiResponseById());
  qs("#selectAllGatewayOpenAiResponses").addEventListener("click", selectAllGatewayOpenAiResponses);
  qs("#clearGatewayOpenAiResponsesSelection").addEventListener("click", clearGatewayOpenAiResponsesSelection);
  qs("#bulkDeleteGatewayOpenAiResponses").addEventListener("click", bulkDeleteGatewayOpenAiResponses);
  qs("#exportGatewayOpenAiResponses").addEventListener("click", exportFilteredGatewayOpenAiResponses);
  qs("#exportSelectedGatewayOpenAiResponses").addEventListener("click", exportSelectedGatewayOpenAiResponses);
  qs("#applyGatewayOpenAiResponsesFilter").addEventListener("click", renderGatewayOpenAiResponsesRows);
  qs("#gatewayOpenAiFilesCreateForm").addEventListener("submit", createGatewayOpenAiFile);
  qs("#createGatewayOpenAiFile").addEventListener("click", createGatewayOpenAiFile);
  qs("#loadGatewayOpenAiFiles").addEventListener("click", loadGatewayOpenAiFiles);
  qs("#getGatewayOpenAiFile").addEventListener("click", () => loadGatewayOpenAiFileById());
  qs("#deleteGatewayOpenAiFile").addEventListener("click", () => deleteGatewayOpenAiFileById());
  qs("#selectAllGatewayOpenAiFiles").addEventListener("click", selectAllGatewayOpenAiFiles);
  qs("#clearGatewayOpenAiFilesSelection").addEventListener("click", clearGatewayOpenAiFilesSelection);
  qs("#bulkDeleteGatewayOpenAiFiles").addEventListener("click", bulkDeleteGatewayOpenAiFiles);
  qs("#applyGatewayOpenAiFilesFilter").addEventListener("click", renderGatewayOpenAiFilesRows);
  qs("#routeFallbackForm").addEventListener("submit", (evt) => evt.preventDefault());
  qs('#routeFallbackForm select[name="owner_scope_type"]').addEventListener("change", () => {
    syncScopeIdPicker("#routeFallbackForm", "owner_scope_type", "owner_scope_id", "routeFallbackOwnerScopeIdList");
  });
  qs('#routeFallbackForm input[name="owner_scope_id"]').addEventListener("focus", () => {
    syncScopeIdPicker("#routeFallbackForm", "owner_scope_type", "owner_scope_id", "routeFallbackOwnerScopeIdList");
  });
  qs("#routeOptimizeForm").addEventListener("submit", optimizeRoutePolicy);
  qs("#loadGatewayCacheStats").addEventListener("click", loadGatewayCacheStats);
  qs("#loadGatewayCacheHealth").addEventListener("click", loadGatewayCacheHealth);
  qs("#gatewayCachePolicyForm").addEventListener("submit", saveGatewayCachePolicy);
  qs("#gatewayCachePolicyFilters").addEventListener("submit", loadGatewayCachePolicies);
  qs("#gatewayCacheInvalidateForm").addEventListener("submit", invalidateGatewayCache);
  qs("#loadGatewayCachePolicies").addEventListener("click", loadGatewayCachePolicies);
  qs("#loadEndpointCompatibility").addEventListener("click", loadEndpointCompatibility);
  qs("#gatewayTransformForm").addEventListener("submit", runGatewayTransformDebug);
  qs("#gatewayAuthzExplainForm").addEventListener("submit", explainGatewayAuthorization);
  qs("#gatewayDecisionTraceForm").addEventListener("submit", loadGatewayDecisionTrace);
  qs("#loadGatewayMcpServers").addEventListener("click", loadGatewayMcpServers);
  qs("#gatewayMcpToolsForm").addEventListener("submit", loadGatewayMcpTools);
  qs("#gatewayMcpCallForm").addEventListener("submit", callGatewayMcpTool);
  qs("#formatGatewayMcpArgs").addEventListener("click", formatGatewayMcpArgsJson);
  qs("#copyGatewayMcpResult").addEventListener("click", copyGatewayMcpResult);
  qs("#clearGatewayMcpState").addEventListener("click", clearGatewayMcpState);
  qs("#loadGatewayExternalCallbacks").addEventListener("click", loadGatewayExternalCallbacks);
  qs("#gatewayExternalCallbackForm").addEventListener("submit", saveGatewayExternalCallback);
  qs("#gatewayExternalCallbackTestForm").addEventListener("submit", testGatewayExternalCallback);
  qs("#gatewayExternalCallbackExportForm").addEventListener("submit", exportGatewayExternalCallbackEvidence);
  qs("#routeDraftFilters").addEventListener("submit", loadRouteDrafts);
  qs("#routeDraftActionForm").addEventListener("submit", runRouteDraftAction);
  qs("#loadRouteDrafts").addEventListener("click", loadRouteDrafts);
  qs("#simulateRouteFallback").addEventListener("click", simulateRouteFallback);
  qs("#executeRouteFallback").addEventListener("click", executeRouteFallback);
  qs("#loadDirectoryUsers").addEventListener("click", loadDirectoryUsers);
  qs("#loadDirectoryGroups").addEventListener("click", loadDirectoryGroups);
  qs("#loadDirectoryTeams").addEventListener("click", loadDirectoryTeams);
  qs("#searchDirectoryUsers").addEventListener("click", () => loadDirectoryUsers(qs("#directoryUserSearch")?.value || ""));
  qs("#searchDirectoryGroups").addEventListener("click", () => loadDirectoryGroups(qs("#directoryGroupSearch")?.value || ""));
  qs("#searchDirectoryTeams").addEventListener("click", () => loadDirectoryTeams(qs("#directoryTeamSearch")?.value || ""));
  qsa("[data-security-console]").forEach((button) => {
    button.addEventListener("click", () => switchSecurityConsole(button.dataset.securityConsole));
  });
  qs("#loadDirectoryMemberships").addEventListener("click", loadDirectoryMemberships);
  qs("#directoryUserForm").addEventListener("submit", upsertDirectoryUser);
  qs("#directoryGroupForm").addEventListener("submit", upsertDirectoryGroup);
  qs("#directoryTeamForm").addEventListener("submit", upsertDirectoryTeam);
  qs('#directoryGroupForm input[name="description"]').addEventListener("input", () => {
    updateDirectoryDescriptionCounter("#directoryGroupForm", "#directoryGroupDescriptionCount");
  });
  qs('#directoryTeamForm input[name="description"]').addEventListener("input", () => {
    updateDirectoryDescriptionCounter("#directoryTeamForm", "#directoryTeamDescriptionCount");
  });
  qs("#addGroupMembership").addEventListener("click", () => addMembership("group"));
  qs("#addTeamMembership").addEventListener("click", () => addMembership("team"));
  qs("#loadSessionPolicy").addEventListener("click", loadSessionPolicy);
  qs("#sessionPolicyForm").addEventListener("submit", saveSessionPolicy);
  qs('#sessionPolicyForm input[name="description"]').addEventListener("input", updateSessionPolicyDescriptionCounter);
  qs("#loadSessionPolicyRevisions").addEventListener("click", loadSessionPolicyRevisions);
  qs("#sessionPolicyRollbackForm").addEventListener("submit", rollbackSessionPolicy);
  qs("#ssoProviderCreateForm").addEventListener("submit", createSsoProvider);
  qs("#ssoProviderUpdateForm").addEventListener("submit", updateSsoProvider);
  qs("#roleBindingValidateForm").addEventListener("submit", validateRoleBinding);
  qs("#roleBindingExplainForm").addEventListener("submit", runRoleBindingExplainability);
  qs("#loadRoleBindingEvidence").addEventListener("click", handleLoadRoleBindingEvidenceClick);
  qs("#testSsoProvider").addEventListener("click", testSsoProvider);
  qs("#syncScimProvider").addEventListener("click", syncScimProvider);
  qs("#issueSessionForm").addEventListener("submit", issueGovernedSession);
  qs("#loadGovernedSession").addEventListener("click", loadGovernedSession);
  qs("#reauthGovernedSession").addEventListener("click", reauthGovernedSession);
  qs("#basicAuthConfigForm").addEventListener("submit", saveBasicAuthConfig);
  qs("#enableBasicAuthTemporary").addEventListener("click", enableBasicAuthTemporary);
  qs("#disableBasicAuthTemporary").addEventListener("click", disableBasicAuthTemporary);
  qs("#refreshObservability").addEventListener("click", loadObservability);
  qs("#loadObservabilityTrace").addEventListener("click", loadObservabilityTrace);
  qs("#loadObservabilityLogs").addEventListener("click", loadObservabilityLogs);
  qs("#loadObservabilitySchema").addEventListener("click", loadObservabilitySchema);
  qs("#observabilityTraceForm").addEventListener("submit", loadObservabilityTrace);
  qs("#observabilityLogsForm").addEventListener("submit", loadObservabilityLogs);
  qs("#registerAgentForm").addEventListener("submit", registerAgent);
  qs("#ownerAgentsForm").addEventListener("submit", loadOwnerAgents);
  qs("#transferOwnerForm").addEventListener("submit", transferOwner);
  qs("#ownershipHistoryForm").addEventListener("submit", loadOwnershipHistory);
  qs("#agentConfigForm").addEventListener("submit", saveAgentConfig);
  qs('#agentConfigForm select[name="provider"]').addEventListener("change", (evt) => {
    loadSupportedModelOptions(evt.target.value, "");
  });
  qs('#agentConfigForm select[name="tenant_scope_id"]').addEventListener("change", () => {
    const provider = qs('#agentConfigForm select[name="provider"]')?.value || "";
    loadSupportedModelOptions(provider, "");
  });
  qs("#resetConfigForm").addEventListener("click", () => resetAgentConfigForm("Form reset."));
  qs("#loadAgentConfigs").addEventListener("click", renderAgentConfigTable);
  qs("#exportAgentConfigs").addEventListener("click", exportAgentConfigs);
  qs("#importAgentConfigs").addEventListener("change", importAgentConfigs);
  qs("#runConfigSecurityReview").addEventListener("click", runConfigSecurityReview);
  qs("#exportCisoAuditBundle").addEventListener("click", exportCisoAuditBundle);
  switchSecurityConsole("users");
  syncScopeIdPicker("#keyLifecycleForm", "owner_scope_type", "owner_scope_id", "keyOwnerScopeIdList");
  renderKeyGuardrailPolicySummary(qs('#keyLifecycleForm textarea[name="guardrail_policy"]').value);
  syncScopeIdPicker("#routeFallbackForm", "owner_scope_type", "owner_scope_id", "routeFallbackOwnerScopeIdList");
  syncScopeIdPicker("#costBudgetForm", "scope_type", "scope_id", "costBudgetScopeIdList");
  syncScopeIdPicker("#costPolicyEvalForm", "scope_type", "scope_id", "costPolicyEvalScopeIdList");
  const incidentGuidanceLink = qs("#incidentGuidanceLink");
  if (incidentGuidanceLink) {
    incidentGuidanceLink.addEventListener("click", (event) => {
      event.preventDefault();
      window.location.assign("./500.html");
    });
  }

  window.addEventListener("error", (event) => {
    const message = String(event?.message || event?.error?.message || "");
    if (message.includes("frame-ancestors") || message.includes("Content Security Policy")) {
      return;
    }
    // Keep browser/runtime noise from surfacing a stale incident banner.
  });

  window.addEventListener("unhandledrejection", (event) => {
    const message = String(event?.reason?.message || event?.reason || "");
    if (message.includes("frame-ancestors") || message.includes("Content Security Policy")) {
      return;
    }
    // Keep browser/runtime noise from surfacing a stale incident banner.
  });
}

async function init() {
  try {
    state.apiBase = parseApiBaseOrThrow(state.apiBase);
    localStorage.setItem("apiBase", state.apiBase);
  } catch {
    state.apiBase = ENVIRONMENT_PROFILES.local.apiBase;
    localStorage.setItem("apiBase", state.apiBase);
  }
  state.environmentProfile = detectProfileFromBaseUrl(state.apiBase);
  localStorage.setItem("environmentProfile", state.environmentProfile);
  enforceKnownActorRole();
  localStorage.setItem("actorRole", state.actorRole);
  if (!state.accessToken) {
    redirectToLoginPage();
    return;
  }
  applyTheme(state.theme);
  updateContextInputs();
  clearGlobalError();
  restoreRuntimeRuleValidationState();
  renderRuntimeValidationContext();
  bindEvents();
  initTablePagination();
  renderGatewayMcpSummary();
  updateSpendFilterControls();
  bindRuntimePresetButtons();
  bindCostingConfigActions();
  await loadRuntimeValidationRules();
  renderRuntimeValidationRulesTable();
  updateRuntimeValidationHint("");
  await refreshUiFeatureFlags();
  await renderRuntimeConfigTable();
  await loadProviderConsole();
  await loadModulesConsole();
  await loadAgenticConsole();
  await renderAgentConfigTable();
  await runConfigSecurityReview();
  resetAgentConfigForm();
  resetRuntimeConfigForm();
  await probeProfiles([state.environmentProfile || "local"]);
  await loadOverview();
  await loadCost();
  await loadCostPricingCatalog();
  await loadGatewayAnalytics();
  await loadCostBudgetPolicies();
  resetCostBudgetForm();
  renderCostLimitRows();
  await loadCostAnomalies();
  renderPlaygroundAttachments();
  renderPlaygroundRuns();
  renderGatewayAccessReviewCampaign(null);
  renderGatewayGovernanceEvidenceSummary([]);
  renderGatewayOpenAiResponsesRows();
  renderGatewayOpenAiFilesRows();
  renderBenchmarkTable(latestBenchmarkRun);
  renderScanTable(latestScanRun);
  await loadBenchmarkHistory();
  await loadScanHistory();
  updatePlaygroundMicStatus("Microphone off.");
  await loadPlaygroundTestSets();
  await loadPlaygroundRuns();
  await loadRoutePolicies();
  await loadGatewayEntitlements();
  await loadGatewayNhiInventory();
  await loadGatewayNhiHygiene();
  await loadGatewayLeastPrivilegeRecommendations();
  await loadGatewayOpenAiResponses();
  await loadGatewayOpenAiFiles();
  await loadGatewayExternalCallbacks();
  await loadGatewayCachePolicies();
  await loadKeys();
  await loadRouteDrafts();
  await loadDiscoverySources();
  await loadDiscoveryConflicts();
  await loadDiscoveryAlerts();
  await loadDiscoveryPromoteQueue();
  updateDirectoryDescriptionCounter("#directoryGroupForm", "#directoryGroupDescriptionCount");
  updateDirectoryDescriptionCounter("#directoryTeamForm", "#directoryTeamDescriptionCount");
  await loadSessionPolicy();
  updateSessionPolicyDescriptionCounter();
  await loadSessionPolicyRevisions();
  await loadComplianceWorkspace();
  await loadObservability();
}

init();
