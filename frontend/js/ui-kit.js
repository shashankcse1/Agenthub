(function initUiKit(global) {
  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderOperatorResult(target, options = {}) {
    if (!target) return;
    const status = String(options.status || "info").trim().toLowerCase();
    const title = String(options.title || "").trim();
    const message = String(options.message || "").trim();
    const payload = options.payload;
    const source = String(options.source || "").trim();
    const details = String(options.details || "").trim();

    const payloadBlock =
      payload === undefined || payload === null || payload === ""
        ? ""
        : `<details class="result-raw-json"><summary>View raw JSON</summary><pre class="mono">${escapeHtml(
            typeof payload === "string" ? payload : JSON.stringify(payload, null, 2),
          )}</pre></details>`;

    target.innerHTML = `
      <article class="operator-result operator-result-${escapeHtml(status)}" role="status" aria-live="polite">
        <div class="operator-result-head">
          <span class="status-pill ${status === "success" ? "success" : status === "error" ? "error" : "idle"}">${escapeHtml(status)}</span>
          ${title ? `<strong class="operator-result-title">${escapeHtml(title)}</strong>` : ""}
          ${source ? `<span class="operator-result-source mono">${escapeHtml(source)}</span>` : ""}
        </div>
        ${message ? `<p class="operator-result-message">${escapeHtml(message)}</p>` : ""}
        ${details ? `<p class="operator-result-details mono">${escapeHtml(details)}</p>` : ""}
        ${payloadBlock}
      </article>
    `;
  }

  function renderOperatorResultError(target, message, source = "") {
    renderOperatorResult(target, { status: "error", title: "Request failed", message, source });
  }

  function renderOperatorResultSuccess(target, title, message, payload, source = "") {
    renderOperatorResult(target, { status: "success", title, message, payload, source });
  }

  function showToast(message, type = "info", timeoutMs = 3200) {
    let host = document.getElementById("toastHost");
    if (!host) {
      host = document.createElement("div");
      host.id = "toastHost";
      host.className = "toast-host";
      host.setAttribute("aria-live", "polite");
      document.body.appendChild(host);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = String(message || "");
    host.appendChild(toast);
    window.setTimeout(() => {
      toast.classList.add("toast-hide");
      window.setTimeout(() => toast.remove(), 220);
    }, timeoutMs);
  }

  function bindTabGroup(root, { tabSelector, panelSelector, activeClass = "active", onChange, suppressInitialChange = false } = {}) {
    if (!root) return;
    const tabs = Array.from(root.querySelectorAll(tabSelector));
    const panels = Array.from(root.querySelectorAll(panelSelector));
    if (!tabs.length || !panels.length) return;

    const tabNameFor = (tab) =>
      tab.dataset.consoleTab ||
      tab.dataset.modulesConsoleTab ||
      tab.dataset.providersConsoleTab ||
      tab.dataset.runtimeConsoleTab ||
      tab.dataset.gatewayConsoleTab ||
      tab.dataset.gatewayOpsTab ||
      tab.dataset.browserSecurityConsoleTab ||
      "";
    const panelNameFor = (panel) =>
      panel.dataset.consolePanel ||
      panel.dataset.modulesConsolePanel ||
      panel.dataset.providersConsolePanel ||
      panel.dataset.runtimeConsolePanel ||
      panel.dataset.gatewayConsolePanel ||
      panel.dataset.gatewayOpsPanel ||
      panel.dataset.browserSecurityConsolePanel ||
      "";

    const activate = (name) => {
      tabs.forEach((tab) => {
        const isActive = tabNameFor(tab) === name;
        tab.classList.toggle(activeClass, isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });
      panels.forEach((panel) => {
        const isActive = panelNameFor(panel) === name;
        panel.classList.toggle(activeClass, isActive);
        panel.hidden = !isActive;
      });
      if (typeof onChange === "function") onChange(name);
    };

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const name = tabNameFor(tab);
        if (!name) return;
        activate(name);
      });
    });

    const initial =
      tabNameFor(tabs.find((tab) => tab.classList.contains(activeClass)) || tabs[0] || {}) || "";
    if (initial) {
      tabs.forEach((tab) => {
        const isActive = tabNameFor(tab) === initial;
        tab.classList.toggle(activeClass, isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });
      panels.forEach((panel) => {
        const isActive = panelNameFor(panel) === initial;
        panel.classList.toggle(activeClass, isActive);
        panel.hidden = !isActive;
      });
      if (!suppressInitialChange) onChange?.(initial);
    }
    return { activate };
  }

  function collapseCardHelp(root = document) {
    root.querySelectorAll("[data-help-text]").forEach((node) => {
      const text = String(node.getAttribute("data-help-text") || "").trim();
      if (!text) return;
      const details = document.createElement("details");
      details.className = "help-details";
      details.innerHTML = `<summary>Help</summary><p class="profile-note">${escapeHtml(text)}</p>`;
      node.replaceWith(details);
    });
  }

  global.UiKit = {
    renderOperatorResult,
    renderOperatorResultError,
    renderOperatorResultSuccess,
    showToast,
    bindTabGroup,
    collapseCardHelp,
    escapeHtml,
  };
})(window);
