(function initUiCoverage(global) {
  const { ACTOR_ROLES, API_LIMITS, UI_COVERAGE } = global.AppConstants;

  let inventory = null;

  function qs(selector) {
    return document.querySelector(selector);
  }

  function safeText(value) {
    if (value === null || value === undefined || value === "") return "--";
    return String(value);
  }

  function formatComplianceDate(value) {
    if (!value) return "--";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return safeText(value);
    return parsed.toLocaleString();
  }

  function setTableMessage(tbody, colSpan, message) {
    if (!tbody) return;
    tbody.textContent = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colSpan;
    td.className = "mono";
    td.textContent = message;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  function normalizeApiPath(path) {
    const rawPath = String(path || "").split("?")[0].trim() || "/";
    const normalized = rawPath.replace(/\/+$/, "") || "/";
    return normalized.startsWith("/") ? normalized : `/${normalized}`;
  }

  function routeTemplateMatches(livePath, templatePath) {
    const liveSegments = livePath.split("/").filter(Boolean);
    const templateSegments = String(templatePath || "").split("/").filter(Boolean);
    if (liveSegments.length !== templateSegments.length) return false;
    return templateSegments.every((segment, index) => {
      if (segment.startsWith("{") && segment.endsWith("}")) return true;
      return segment === liveSegments[index];
    });
  }

  function findInventoryEntry(method, path) {
    if (!Array.isArray(inventory) || !inventory.length) return null;
    const normalizedMethod = String(method || "GET").toUpperCase();
    const normalizedPath = normalizeApiPath(path);
    const exactMatch = inventory.find(
      (item) => String(item?.method || "").toUpperCase() === normalizedMethod
        && normalizeApiPath(item?.route) === normalizedPath,
    );
    if (exactMatch) return exactMatch;
    return inventory.find(
      (item) => String(item?.method || "").toUpperCase() === normalizedMethod
        && routeTemplateMatches(normalizedPath, item?.route),
    ) || null;
  }

  function isGateExemptPath(path) {
    const normalizedPath = normalizeApiPath(path);
    return UI_COVERAGE.GATE_EXEMPT_PREFIXES.some(
      (prefix) => normalizedPath === prefix.replace(/\/$/, "") || normalizedPath.startsWith(prefix),
    );
  }

  function assertFrontendAvailable(method, path) {
    if (isGateExemptPath(path)) return;
    const entry = findInventoryEntry(method, path);
    if (!entry || entry.ui_coverage !== UI_COVERAGE.STATUSES.GAP) return;
    throw new Error(
      `UI not available for ${String(method || "GET").toUpperCase()} ${normalizeApiPath(path)}. `
      + "Backend API exists but no operator workflow is exposed yet.",
    );
  }

  async function loadInventory(apiFn) {
    try {
      const data = await apiFn(UI_COVERAGE.INVENTORY_PATH, {
        headers: { "X-Actor-Role": ACTOR_ROLES.AUDITOR },
      });
      inventory = Array.isArray(data?.items) ? data.items : [];
    } catch {
      inventory = null;
    }
    return inventory;
  }

  function collectGapRows(report) {
    const rows = [];
    const appendRows = (items, fallbackCoverage) => {
      if (!Array.isArray(items)) return;
      items.forEach((item) => {
        rows.push({
          method: item?.method,
          route: item?.route,
          ui_coverage: item?.ui_coverage || fallbackCoverage,
          frontend_available: Boolean(item?.frontend_available),
          notes: item?.notes || "",
        });
      });
    };
    appendRows(report?.gap_items, UI_COVERAGE.STATUSES.GAP);
    appendRows(report?.partial_items, UI_COVERAGE.STATUSES.PARTIAL);
    appendRows(report?.undocumented_items, UI_COVERAGE.STATUSES.UNDOCUMENTED);
    return rows;
  }

  function renderGapsTable(rows) {
    const tbody = qs("#uiCoverageGapsTable");
    if (!tbody) return;
    if (!rows.length) {
      setTableMessage(tbody, 5, "No backend-only or partial UI coverage gaps reported.");
      return;
    }
    tbody.textContent = "";
    rows.slice(0, API_LIMITS.UI_COVERAGE_TABLE_MAX).forEach((row) => {
      const tr = document.createElement("tr");
      [
        row.method,
        row.route,
        row.ui_coverage,
        row.frontend_available ? "yes" : "no",
        row.notes,
      ].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = safeText(value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  function renderOverviewGaps(rows) {
    const list = qs("#overviewUiCoverageGaps");
    if (!list) return;
    list.textContent = "";
    if (!rows.length) {
      const li = document.createElement("li");
      li.textContent = "No backend-only or partial UI coverage gaps reported.";
      list.appendChild(li);
      return;
    }
    rows.slice(0, API_LIMITS.OVERVIEW_GAPS_MAX).forEach((row) => {
      const li = document.createElement("li");
      li.textContent = `${safeText(row.method)} ${safeText(row.route)} (${safeText(row.ui_coverage)})`;
      list.appendChild(li);
    });
  }

  function updateSummaryElements(report, rows) {
    const generatedAt = formatComplianceDate(report?.generated_at);
    const summaryText = `Coverage generated ${generatedAt}. `
      + `${report?.frontend_unavailable_endpoints ?? 0} endpoint(s) lack full UI workflows; `
      + `${report?.undocumented_backend_routes ?? 0} live route(s) are undocumented.`;
    const overviewSummary = qs("#overviewUiCoverageSummary");
    if (overviewSummary) overviewSummary.textContent = summaryText;
    const complianceSummary = qs("#uiCoverageSummary");
    if (complianceSummary) complianceSummary.textContent = summaryText;
    const counts = {
      "#overviewUiCoverageInventoryCount": report?.total_inventory_endpoints,
      "#overviewUiCoverageFullCount": report?.full_coverage_endpoints,
      "#overviewUiCoveragePartialCount": report?.partial_coverage_endpoints,
      "#overviewUiCoverageGapCount": report?.gap_coverage_endpoints,
      "#overviewUiCoverageUndocumentedCount": report?.undocumented_backend_routes,
      "#uiCoverageInventoryCount": report?.total_inventory_endpoints,
      "#uiCoverageFullCount": report?.full_coverage_endpoints,
      "#uiCoveragePartialCount": report?.partial_coverage_endpoints,
      "#uiCoverageGapCount": report?.gap_coverage_endpoints,
      "#uiCoverageUndocumentedCount": report?.undocumented_backend_routes,
    };
    Object.entries(counts).forEach(([selector, value]) => {
      const node = qs(selector);
      if (node) node.textContent = safeText(value ?? "--");
    });
    renderOverviewGaps(rows);
    renderGapsTable(rows);
  }

  async function loadGaps(apiFn) {
    const summary = qs("#uiCoverageSummary");
    const tbody = qs("#uiCoverageGapsTable");
    if (summary) summary.textContent = "Loading UI coverage gaps...";
    if (tbody) setTableMessage(tbody, 5, "Loading...");
    try {
      const data = await apiFn(UI_COVERAGE.REPORT_PATH, {
        headers: { "X-Actor-Role": ACTOR_ROLES.AUDITOR },
      });
      const rows = collectGapRows(data);
      updateSummaryElements(data, rows);
    } catch (err) {
      if (summary) summary.textContent = `Error: ${safeText(err.message)}`;
      if (tbody) setTableMessage(tbody, 5, `Error: ${safeText(err.message)}`);
    }
  }

  async function loadOverviewReport(apiFn) {
    const summary = qs("#overviewUiCoverageSummary");
    if (summary) summary.textContent = "Loading UI coverage summary...";
    try {
      const data = await apiFn(UI_COVERAGE.REPORT_PATH, {
        headers: { "X-Actor-Role": ACTOR_ROLES.AUDITOR },
      });
      const rows = collectGapRows(data);
      updateSummaryElements(data, rows);
    } catch (err) {
      if (summary) summary.textContent = `Error: ${safeText(err.message)}`;
    }
  }

  global.UiCoverage = {
    assertFrontendAvailable,
    collectGapRows,
    getInventory: () => inventory,
    isGateExemptPath,
    loadGaps,
    loadInventory,
    loadOverviewReport,
    renderGapsTable,
    renderOverviewGaps,
    updateSummaryElements,
  };
})(window);
