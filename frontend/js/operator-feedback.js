(function initOperatorFeedback(global) {
  const CONTEXT = {
    clientLatencyMs: null,
    operationalStatus: null,
    contextAction: "",
  };

  let submitFeedback = null;
  let loadAnalytics = null;
  let applyFeedbackAction = null;
  let getCurrentView = () => "overview";
  let getIncidentRef = () => "";
  let getActorRole = () => "Auditor";

  function qs(selector) {
    return document.querySelector(selector);
  }

  function safeText(value) {
    return String(value ?? "").trim();
  }

  function setContext(partial = {}) {
    Object.assign(CONTEXT, partial);
  }

  function openPanel() {
    const panel = qs("#operatorFeedbackPanel");
    if (!panel) return;
    panel.hidden = false;
    const viewInput = panel.querySelector('[name="context_view"]');
    const latencyInput = panel.querySelector('[name="client_latency_ms"]');
    const actionInput = panel.querySelector('[name="context_action"]');
    if (viewInput) viewInput.value = getCurrentView();
    if (latencyInput && CONTEXT.clientLatencyMs != null) latencyInput.value = String(CONTEXT.clientLatencyMs);
    if (actionInput && CONTEXT.contextAction) actionInput.value = CONTEXT.contextAction;
  }

  function closePanel() {
    const panel = qs("#operatorFeedbackPanel");
    if (panel) panel.hidden = true;
  }

  function renderAnalytics(data) {
    const summary = qs("#operatorFeedbackAnalyticsSummary");
    const actions = qs("#operatorFeedbackActionBreakdown");
    const tbody = qs("#operatorFeedbackReportTable");
    if (summary) {
      summary.textContent = data
        ? `${data.total_count} report(s) in last ${data.since_hours}h · ${data.open_count} open`
        : "Load analytics to review operator feedback trends.";
    }
    if (actions) {
      actions.textContent = "";
      if (!data?.by_context_action?.length) return;
      data.by_context_action.slice(0, 8).forEach((row) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "chip";
        chip.textContent = `${row.label} (${row.count})`;
        chip.addEventListener("click", () => {
          const filter = qs("#operatorFeedbackActionFilter");
          if (filter) filter.value = row.label;
          void loadFeedbackReports();
        });
        actions.appendChild(chip);
      });
    }
    if (!tbody) return;
    tbody.textContent = "";
    if (!data?.by_category?.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 3;
      td.textContent = "No analytics loaded.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    data.by_category.forEach((row) => {
      const tr = document.createElement("tr");
      ["label", "count"].forEach((key) => {
        const td = document.createElement("td");
        td.textContent = String(row[key] ?? "");
        tr.appendChild(td);
      });
      const actionCell = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ghost";
      btn.textContent = "Filter";
      btn.addEventListener("click", () => {
        const categoryFilter = qs("#operatorFeedbackCategoryFilter");
        if (categoryFilter) categoryFilter.value = row.label;
        void loadFeedbackReports();
      });
      actionCell.appendChild(btn);
      tr.appendChild(actionCell);
      tbody.appendChild(tr);
    });
  }

  async function loadFeedbackAnalytics() {
    if (!loadAnalytics) return null;
    try {
      const data = await loadAnalytics();
      renderAnalytics(data);
      return data;
    } catch (err) {
      renderAnalytics(null);
      const summary = qs("#operatorFeedbackAnalyticsSummary");
      if (summary) summary.textContent = `Error: ${safeText(err.message)}`;
      return null;
    }
  }

  async function loadFeedbackReports() {
    const tbody = qs("#operatorFeedbackItemsTable");
    const result = qs("#operatorFeedbackReportResult");
    if (!tbody || !submitFeedback) return;
    tbody.textContent = "";
    if (result) result.textContent = "Loading feedback reports...";
    try {
      const category = safeText(qs("#operatorFeedbackCategoryFilter")?.value);
      const action = safeText(qs("#operatorFeedbackActionFilter")?.value);
      const rows = await submitFeedback.list({ category, context_action: action });
      if (!rows.length) {
        if (result) result.textContent = "No feedback reports match the current filters.";
        return;
      }
      rows.forEach((row) => {
        const tr = document.createElement("tr");
        [row.created_at, row.category, row.severity, row.context_view, row.context_action, row.status, row.comment].forEach((value) => {
          const td = document.createElement("td");
          td.textContent = safeText(value);
          tr.appendChild(td);
        });
        const actions = document.createElement("td");
        if (row.status === "open" && applyFeedbackAction) {
          const ack = document.createElement("button");
          ack.type = "button";
          ack.className = "ghost";
          ack.textContent = "Ack";
          ack.addEventListener("click", () => {
            void applyFeedbackAction(row.feedback_id, "acknowledge", "Acknowledged from overview report");
          });
          actions.appendChild(ack);
        }
        tr.appendChild(actions);
        tbody.appendChild(tr);
      });
      if (result) result.textContent = `Showing ${rows.length} feedback report(s).`;
    } catch (err) {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
    }
  }

  async function handleSubmit(form) {
    const result = qs("#operatorFeedbackResult");
    if (!submitFeedback) return;
    const payload = {
      category: form.elements.category.value,
      severity: form.elements.severity.value,
      comment: safeText(form.elements.comment.value),
      context_view: safeText(form.elements.context_view.value) || getCurrentView(),
      context_action: safeText(form.elements.context_action.value),
      client_latency_ms: Number(form.elements.client_latency_ms.value) || CONTEXT.clientLatencyMs || null,
      incident_ref: getIncidentRef() || null,
      metadata_json: {
        operational_status: CONTEXT.operationalStatus || null,
        user_agent: navigator.userAgent.slice(0, 180),
      },
    };
    try {
      await submitFeedback.create(payload);
      if (result) result.textContent = "Feedback submitted. Thank you.";
      form.elements.comment.value = "";
      closePanel();
      void loadFeedbackAnalytics();
    } catch (err) {
      if (result) result.textContent = `Error: ${safeText(err.message)}`;
    }
  }

  function bindUi() {
    qs("#operatorFeedbackFab")?.addEventListener("click", openPanel);
    qs("#operatorFeedbackClose")?.addEventListener("click", closePanel);
    qs("#operatorFeedbackCapturePerf")?.addEventListener("click", () => {
      setContext({ contextAction: "slow_performance_banner" });
      openPanel();
      const form = qs("#operatorFeedbackForm");
      if (form) {
        form.elements.category.value = "performance";
        form.elements.context_action.value = "slow_performance_banner";
      }
    });
    qs("#operatorFeedbackForm")?.addEventListener("submit", (evt) => {
      evt.preventDefault();
      void handleSubmit(evt.target);
    });
    qs("#loadOperatorFeedbackAnalytics")?.addEventListener("click", () => { void loadFeedbackAnalytics(); });
    qs("#loadOperatorFeedbackReports")?.addEventListener("click", () => { void loadFeedbackReports(); });
  }

  function configure(options = {}) {
    submitFeedback = options.submitFeedback || submitFeedback;
    loadAnalytics = options.loadAnalytics || loadAnalytics;
    applyFeedbackAction = options.applyFeedbackAction || applyFeedbackAction;
    if (typeof options.getCurrentView === "function") getCurrentView = options.getCurrentView;
    if (typeof options.getIncidentRef === "function") getIncidentRef = options.getIncidentRef;
    if (typeof options.getActorRole === "function") getActorRole = options.getActorRole;
  }

  function init(options = {}) {
    configure(options);
    bindUi();
  }

  global.OperatorFeedback = Object.freeze({
    init,
    configure,
    setContext,
    openPanel,
    closePanel,
    loadFeedbackAnalytics,
    loadFeedbackReports,
  });
})(window);
