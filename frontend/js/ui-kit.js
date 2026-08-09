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

  function ensureToastHost() {
    let host = document.getElementById("toastHost");
    if (!host) {
      host = document.createElement("div");
      host.id = "toastHost";
      host.className = "toast-host";
      host.setAttribute("aria-live", "polite");
      host.setAttribute("aria-relevant", "additions");
      document.body.appendChild(host);
    }
    return host;
  }

  function showToast(message, type = "info", timeoutMs = 3200) {
    const host = ensureToastHost();
    const toast = document.createElement("div");
    const tone = String(type || "info").toLowerCase();
    toast.className = `toast toast-${tone}`;
    toast.setAttribute("role", tone === "error" ? "alert" : "status");

    const text = document.createElement("span");
    text.className = "toast-message";
    text.textContent = String(message || "");
    toast.appendChild(text);

    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "toast-dismiss";
    dismiss.setAttribute("aria-label", "Dismiss notification");
    dismiss.textContent = "×";
    const removeToast = () => {
      toast.classList.add("toast-hide");
      window.setTimeout(() => toast.remove(), 220);
    };
    dismiss.addEventListener("click", removeToast);
    toast.appendChild(dismiss);

    host.appendChild(toast);
    while (host.children.length > 4) {
      host.firstElementChild?.remove();
    }
    window.setTimeout(removeToast, Math.max(1200, Number(timeoutMs) || 3200));
    return toast;
  }

  function announce(message, politeness = "polite") {
    let region = document.getElementById("uiKitLiveRegion");
    if (!region) {
      region = document.createElement("div");
      region.id = "uiKitLiveRegion";
      region.className = "sr-only";
      region.setAttribute("aria-live", politeness === "assertive" ? "assertive" : "polite");
      region.setAttribute("aria-atomic", "true");
      document.body.appendChild(region);
    }
    region.setAttribute("aria-live", politeness === "assertive" ? "assertive" : "polite");
    region.textContent = "";
    window.requestAnimationFrame(() => {
      region.textContent = String(message || "");
    });
  }

  let shellProgressDepth = 0;

  function setShellProgress(active) {
    const el = document.getElementById("shellProgress");
    if (!el) return;
    if (active) {
      shellProgressDepth += 1;
      el.hidden = false;
      el.setAttribute("aria-hidden", "false");
      el.classList.add("is-active");
      return;
    }
    shellProgressDepth = Math.max(0, shellProgressDepth - 1);
    if (shellProgressDepth === 0) {
      el.classList.remove("is-active");
      el.hidden = true;
      el.setAttribute("aria-hidden", "true");
    }
  }

  async function withShellProgress(work) {
    setShellProgress(true);
    try {
      return await work();
    } finally {
      setShellProgress(false);
    }
  }

  function bindConnectivityBanner() {
    const banner = document.getElementById("connectivityBanner");
    if (!banner) return;
    const sync = () => {
      const offline = !navigator.onLine;
      banner.hidden = !offline;
      if (offline) {
        announce("Connection lost. Working offline.", "assertive");
      } else if (!banner.dataset.wasOffline) {
        return;
      } else {
        announce("Connection restored.");
        showToast("Back online", "success", 1800);
      }
      banner.dataset.wasOffline = offline ? "1" : "";
    };
    window.addEventListener("online", sync);
    window.addEventListener("offline", sync);
    sync();
  }

  function trapFocus(container, event) {
    if (!container || event.key !== "Tab") return;
    const focusable = Array.from(
      container.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => !el.hidden && el.getAttribute("aria-hidden") !== "true");
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  let confirmResolver = null;

  function confirm(message, options = {}) {
    const overlay = document.getElementById("confirmOverlay");
    const titleEl = document.getElementById("confirmTitle");
    const messageEl = document.getElementById("confirmMessage");
    const okBtn = document.getElementById("confirmOk");
    const cancelBtn = document.getElementById("confirmCancel");
    if (!overlay || !messageEl || !okBtn || !cancelBtn) {
      return Promise.resolve(window.confirm(String(message || "Continue?")));
    }

    if (confirmResolver) {
      confirmResolver(false);
      confirmResolver = null;
    }

    const title = String(options.title || "Confirm action").trim();
    const okLabel = String(options.okLabel || "Confirm").trim();
    const cancelLabel = String(options.cancelLabel || "Cancel").trim();
    const danger = Boolean(options.danger);

    if (titleEl) titleEl.textContent = title;
    messageEl.textContent = String(message || "Continue?");
    okBtn.textContent = okLabel;
    cancelBtn.textContent = cancelLabel;
    okBtn.classList.toggle("danger", danger);
    okBtn.classList.toggle("primary", !danger);
    overlay.hidden = false;
    overlay.dataset.open = "1";
    (danger ? cancelBtn : okBtn).focus();

    return new Promise((resolve) => {
      confirmResolver = resolve;
    });
  }

  function closeConfirm(result) {
    const overlay = document.getElementById("confirmOverlay");
    if (overlay) {
      overlay.hidden = true;
      delete overlay.dataset.open;
    }
    const okBtn = document.getElementById("confirmOk");
    if (okBtn) {
      okBtn.classList.remove("danger");
      okBtn.classList.add("primary");
    }
    if (confirmResolver) {
      const resolve = confirmResolver;
      confirmResolver = null;
      resolve(Boolean(result));
    }
  }

  function bindConfirmDialog() {
    const overlay = document.getElementById("confirmOverlay");
    if (!overlay || overlay.dataset.bound === "1") return;
    overlay.dataset.bound = "1";
    document.getElementById("confirmOk")?.addEventListener("click", () => closeConfirm(true));
    document.getElementById("confirmCancel")?.addEventListener("click", () => closeConfirm(false));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) closeConfirm(false);
    });
    document.addEventListener("keydown", (event) => {
      if (overlay.hidden) return;
      trapFocus(overlay, event);
      if (event.key === "Escape") {
        event.preventDefault();
        closeConfirm(false);
      }
    });
  }

  async function copyText(value, successMessage = "Copied") {
    const text = String(value || "");
    if (!text) return false;
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.left = "-9999px";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      showToast(successMessage, "success", 1600);
      announce(successMessage);
      return true;
    } catch {
      showToast("Copy failed", "error", 1800);
      return false;
    }
  }

  function enhanceCopyableResults(root = document) {
    root.querySelectorAll(".operator-result, .mono[id$='Result'], .mono[id$='Feedback'], .key-feedback").forEach((node) => {
      if (node.dataset.copyEnhanced === "true") return;
      const text = String(node.textContent || "").trim();
      if (!text || text.length < 8) return;
      if (/^(ready|idle|—|-)$/i.test(text)) return;
      node.dataset.copyEnhanced = "true";
      if (getComputedStyle(node).position === "static") {
        node.classList.add("copyable-result");
      }
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ghost copy-result-btn";
      btn.setAttribute("aria-label", "Copy result");
      btn.title = "Copy";
      btn.textContent = "Copy";
      btn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const payload = Array.from(node.childNodes)
          .filter((child) => !(child.nodeType === 1 && child.classList?.contains("copy-result-btn")))
          .map((child) => child.textContent || "")
          .join("")
          .trim();
        void copyText(payload, "Result copied");
      });
      node.appendChild(btn);
    });
  }

  function setControlBusy(control, busy, busyLabel = "Working…") {
    if (!control) return;
    const isBusy = Boolean(busy);
    if (isBusy) {
      if (!control.dataset.busyLabelRestore) {
        control.dataset.busyLabelRestore = control.getAttribute("aria-label") || "";
        control.dataset.busyTextRestore = control.tagName === "BUTTON" ? control.textContent : "";
      }
      control.classList.add("is-busy");
      control.setAttribute("aria-busy", "true");
      control.disabled = true;
      if (busyLabel && control.tagName === "BUTTON" && !control.classList.contains("icon-button")) {
        control.textContent = busyLabel;
      }
      if (busyLabel) control.setAttribute("aria-label", busyLabel);
      return;
    }
    control.classList.remove("is-busy");
    control.removeAttribute("aria-busy");
    control.disabled = false;
    if (control.dataset.busyTextRestore !== undefined && control.tagName === "BUTTON" && !control.classList.contains("icon-button")) {
      control.textContent = control.dataset.busyTextRestore;
    }
    if (control.dataset.busyLabelRestore) {
      control.setAttribute("aria-label", control.dataset.busyLabelRestore);
    } else {
      control.removeAttribute("aria-label");
    }
    delete control.dataset.busyLabelRestore;
    delete control.dataset.busyTextRestore;
  }

  async function withBusy(control, work, busyLabel = "Working…") {
    setControlBusy(control, true, busyLabel);
    try {
      return await work();
    } finally {
      setControlBusy(control, false);
    }
  }

  function renderEmptyState({ title = "Ledger empty", message = "", actionLabel = "", actionAttrs = "" } = {}) {
    const action = actionLabel
      ? `<button type="button" class="ghost empty-state-action" ${actionAttrs}>${escapeHtml(actionLabel)}</button>`
      : "";
    return `<div class="empty-state" role="status">
      <strong>${escapeHtml(title)}</strong>
      ${message ? `<p>${escapeHtml(message)}</p>` : ""}
      ${action}
    </div>`;
  }

  function renderTableEmptyRow(colSpan, title, message = "") {
    const span = Math.max(1, Number(colSpan) || 1);
    return `<tr class="table-empty-row"><td colspan="${span}">${renderEmptyState({ title, message })}</td></tr>`;
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

    const tablist =
      tabs[0]?.closest('[role="tablist"]') ||
      root.querySelector('[role="tablist"]') ||
      root;
    if (tablist && !tablist.getAttribute("role")) {
      tablist.setAttribute("role", "tablist");
    }

    const activate = (name, { focusTab = false } = {}) => {
      let activeTab = null;
      tabs.forEach((tab) => {
        const isActive = tabNameFor(tab) === name;
        tab.classList.toggle(activeClass, isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
        tab.setAttribute("tabindex", isActive ? "0" : "-1");
        if (isActive) activeTab = tab;
      });
      panels.forEach((panel) => {
        const isActive = panelNameFor(panel) === name;
        panel.classList.toggle(activeClass, isActive);
        panel.hidden = !isActive;
        if (isActive) {
          panel.setAttribute("tabindex", "-1");
        }
      });
      if (focusTab && activeTab) activeTab.focus();
      if (typeof onChange === "function") onChange(name);
    };

    tabs.forEach((tab, index) => {
      const name = tabNameFor(tab);
      if (!tab.getAttribute("role")) tab.setAttribute("role", "tab");
      if (name) {
        const panel = panels.find((p) => panelNameFor(p) === name);
        if (panel) {
          if (!panel.id) panel.id = `${name}-panel-${index}`;
          if (!tab.id) tab.id = `${name}-tab-${index}`;
          tab.setAttribute("aria-controls", panel.id);
          panel.setAttribute("role", "tabpanel");
          panel.setAttribute("aria-labelledby", tab.id);
        }
      }
      tab.addEventListener("click", () => {
        if (!name) return;
        activate(name);
      });
      tab.addEventListener("keydown", (event) => {
        const key = event.key;
        if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(key)) return;
        event.preventDefault();
        const currentIndex = tabs.indexOf(tab);
        if (currentIndex < 0) return;
        let nextIndex = currentIndex;
        if (key === "Home") nextIndex = 0;
        else if (key === "End") nextIndex = tabs.length - 1;
        else if (key === "ArrowLeft" || key === "ArrowUp") {
          nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        } else if (key === "ArrowRight" || key === "ArrowDown") {
          nextIndex = (currentIndex + 1) % tabs.length;
        }
        const nextName = tabNameFor(tabs[nextIndex]);
        if (!nextName) return;
        activate(nextName, { focusTab: true });
      });
    });

    const initial =
      tabNameFor(tabs.find((tab) => tab.classList.contains(activeClass)) || tabs[0] || {}) || "";
    if (initial) {
      tabs.forEach((tab) => {
        const isActive = tabNameFor(tab) === initial;
        tab.classList.toggle(activeClass, isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
        tab.setAttribute("tabindex", isActive ? "0" : "-1");
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

  function buildInfoTip(text, label = "More information") {
    const tip = document.createElement("details");
    tip.className = "info-tip";
    const summary = document.createElement("summary");
    summary.setAttribute("aria-label", label);
    summary.textContent = "i";
    summary.addEventListener("click", (event) => {
      // Keep parent <details> drawers from toggling when opening the tip.
      event.stopPropagation();
    });
    const panel = document.createElement("div");
    panel.className = "info-tip-panel";
    panel.setAttribute("role", "tooltip");
    panel.textContent = text;
    tip.appendChild(summary);
    tip.appendChild(panel);
    tip.addEventListener("toggle", () => {
      if (!tip.open) return;
      const closer = (event) => {
        if (tip.contains(event.target)) return;
        tip.open = false;
        document.removeEventListener("pointerdown", closer, true);
      };
      document.addEventListener("pointerdown", closer, true);
    });
    return tip;
  }

  function collapseCardHelp(root = document) {
    root.querySelectorAll("[data-help-text]").forEach((node) => {
      if (node.matches?.("details.ops-pack-drawer")) return;
      const text = String(node.getAttribute("data-help-text") || "").trim();
      if (!text || node.dataset.infoTipBound === "true") return;
      const tip = buildInfoTip(text, String(node.getAttribute("data-help-label") || "More information"));
      node.dataset.infoTipBound = "true";
      node.replaceWith(tip);
    });
  }

  function attachDrawerInfoTips(root = document) {
    root.querySelectorAll("details.ops-pack-drawer[data-help-text]").forEach((drawer) => {
      if (drawer.dataset.infoTipBound === "true") return;
      const text = String(drawer.getAttribute("data-help-text") || "").trim();
      const summary = drawer.querySelector(":scope > summary");
      if (!text || !summary) return;
      drawer.dataset.infoTipBound = "true";
      summary.appendChild(
        buildInfoTip(text, String(drawer.getAttribute("data-help-label") || "More information")),
      );
    });
  }

  function attachInfoTips(root = document) {
    attachDrawerInfoTips(root);

    // Long card leads → i icon beside the nearest heading; keep short leads visible.
    root.querySelectorAll("article.card > .card-lead, .card > .card-lead, .card-head + .card-lead").forEach((lead) => {
      if (lead.dataset.infoTipBound === "true" || lead.closest(".info-tip, .operator-guide")) return;
      if (lead.closest(".runtime-config-hero, .gateway-console-hero, .flow-studio-hero, .overview-hero")) return;
      const text = String(lead.textContent || "").replace(/\s+/g, " ").trim();
      if (text.length < 72) return;
      lead.dataset.infoTipBound = "true";
      const head =
        lead.previousElementSibling?.matches?.(".card-head")
          ? lead.previousElementSibling
          : lead.closest("article.card, .card")?.querySelector(".card-head h4, .card-head h3, h4, h3");
      const title = head?.querySelector?.("h4, h3") || (head?.matches?.("h3, h4") ? head : null);
      if (title) {
        if (!title.classList.contains("heading-with-info")) title.classList.add("heading-with-info");
        title.appendChild(buildInfoTip(text, `About ${String(title.textContent || "section").trim()}`));
        lead.hidden = true;
        lead.setAttribute("data-empty", "true");
      } else {
        const tip = buildInfoTip(text);
        lead.replaceWith(tip);
      }
    });

    // Explicit help paragraphs: <p class="help-copy"> or data-info-copy
    root.querySelectorAll("p.help-copy, p[data-info-copy], .mono.help-copy").forEach((node) => {
      if (node.dataset.infoTipBound === "true") return;
      const text = String(node.textContent || "").replace(/\s+/g, " ").trim();
      if (!text) return;
      node.dataset.infoTipBound = "true";
      const tip = buildInfoTip(text, String(node.getAttribute("data-help-label") || "More information"));
      const head = node.previousElementSibling?.matches?.(".card-head")
        ? node.previousElementSibling
        : node.closest("article.card, .card")?.querySelector(".card-head");
      const title = head?.querySelector?.("h4, h3");
      if (title) {
        if (!title.classList.contains("heading-with-info")) title.classList.add("heading-with-info");
        title.appendChild(tip);
        node.remove();
      } else {
        node.replaceWith(tip);
      }
    });
  }

  function enhanceFormValidation(root = document) {
    root.querySelectorAll("form").forEach((form) => {
      if (form.dataset.uiKitValidationBound === "true") return;
      form.dataset.uiKitValidationBound = "true";
      form.addEventListener(
        "invalid",
        (event) => {
          const control = event.target;
          if (!control || !control.setAttribute) return;
          control.setAttribute("aria-invalid", "true");
          control.classList.add("is-invalid");
        },
        true,
      );
      form.addEventListener("input", (event) => {
        const control = event.target;
        if (!control || !control.classList) return;
        if (typeof control.checkValidity === "function" && control.checkValidity()) {
          control.removeAttribute("aria-invalid");
          control.classList.remove("is-invalid");
        }
      });
      form.addEventListener("change", (event) => {
        const control = event.target;
        if (!control || !control.classList) return;
        if (typeof control.checkValidity === "function" && control.checkValidity()) {
          control.removeAttribute("aria-invalid");
          control.classList.remove("is-invalid");
        }
      });
    });
  }

  function collapseOperatorGuides(root = document) {
    root.querySelectorAll(".sig-trust-ledger-console").forEach((ledger) => {
      if (ledger.dataset.guideBound === "true" || ledger.closest("details.operator-guide")) return;
      ledger.dataset.guideBound = "true";
      const details = document.createElement("details");
      details.className = "operator-guide operator-guide-posture";
      const summary = document.createElement("summary");
      const labels = Array.from(ledger.querySelectorAll(".sig-trust-label"))
        .map((el) => String(el.textContent || "").trim())
        .filter(Boolean);
      summary.innerHTML = `<span class="operator-guide-label">Posture</span><span class="operator-guide-preview">${escapeHtml(
        labels.join(" · ") || "Signals",
      )}</span>`;
      details.appendChild(summary);
      ledger.parentNode?.insertBefore(details, ledger);
      details.appendChild(ledger);
    });

    root.querySelectorAll(".runtime-workflow-steps, .gateway-workflow-steps").forEach((steps) => {
      if (steps.dataset.guideBound === "true" || steps.closest("details.operator-guide")) return;
      steps.dataset.guideBound = "true";
      steps.classList.add("workflow-steps-compact");
      const titles = Array.from(
        steps.querySelectorAll(".runtime-workflow-step > strong, .gateway-workflow-step > strong"),
      )
        .map((el) => String(el.textContent || "").trim())
        .filter(Boolean);
      const details = document.createElement("details");
      details.className = "operator-guide operator-guide-workflow";
      const summary = document.createElement("summary");
      let label = "How to operate";
      const prev = steps.previousElementSibling;
      if (prev?.matches?.(".card-head") && /sequence|workflow|guide|how|exam|attestation|laboratory/i.test(prev.textContent || "")) {
        label = String(prev.querySelector("h4, h3")?.textContent || label).trim() || label;
        prev.hidden = true;
      }
      summary.innerHTML = `<span class="operator-guide-label">${escapeHtml(label)}</span><span class="operator-guide-preview">${escapeHtml(
        titles.join(" → ") || "Steps",
      )}</span>`;
      details.appendChild(summary);
      steps.parentNode?.insertBefore(details, steps);
      details.appendChild(steps);
    });

    root.querySelectorAll("article.card > .card-lead, .card > .card-lead, article.card > .overview-intro").forEach((lead) => {
      if (lead.dataset.guideBound === "true" || lead.closest("details.operator-guide")) return;
      if (lead.closest(".runtime-config-hero, .gateway-console-hero, .flow-studio-hero, .security-hero, .discovery-hero, .observability-hero, .cost-console-hero")) {
        return;
      }
      const text = String(lead.textContent || "").trim();
      if (text.length < 88) return;
      lead.dataset.guideBound = "true";
      const details = document.createElement("details");
      details.className = "operator-guide operator-guide-note";
      const summary = document.createElement("summary");
      summary.innerHTML = `<span class="operator-guide-label">Details</span><span class="operator-guide-preview">${escapeHtml(
        text.slice(0, 72).replace(/\s+/g, " ") + (text.length > 72 ? "…" : ""),
      )}</span>`;
      details.appendChild(summary);
      lead.parentNode?.insertBefore(details, lead);
      details.appendChild(lead);
    });
  }

  function enhancePageSurfaces(root = document) {
    root.querySelectorAll(".card-head").forEach((head) => {
      if (!head.style.display) {
        head.classList.add("page-card-head");
      }
    });
    root.querySelectorAll(".mono, [id$='Result'], [id$='Feedback'], .key-feedback, .feedback").forEach((node) => {
      if (node.classList.contains("runtime-feedback")) return;
      if (!String(node.textContent || "").trim() && !node.querySelector("*")) {
        node.setAttribute("data-empty", "true");
      } else {
        node.removeAttribute("data-empty");
      }
    });
    // Keep status lines quiet until they have content (:empty CSS hides them).
    root.querySelectorAll(".runtime-feedback").forEach((node) => {
      const idle = /^(loading|checking|idle|appears here|loads with|n\/a|\.|…|\.\.\.)/i;
      const text = String(node.textContent || "").trim();
      if (!text || idle.test(text) || /appear here|checking…|loading…/i.test(text)) {
        if (!node.dataset.preserveIdle) node.textContent = "";
      }
    });
    enhanceCopyableResults(root);
    collapseCardHelp(root);
    attachInfoTips(root);
    collapseOperatorGuides(root);
  }

  function bindRefreshBusy(root = document) {
    if (root.dataset?.uiKitRefreshBusy === "true") return;
    const target = root === document ? document : root;
    if (target.dataset) target.dataset.uiKitRefreshBusy = "true";
    target.addEventListener(
      "click",
      (event) => {
        const btn = event.target?.closest?.("button[id^='refresh']");
        if (!btn || btn.id === "refreshAll") return;
        if (!/Console$/i.test(btn.id) && btn.id !== "probeProfiles") return;
        if (btn.classList.contains("is-busy")) return;
        setControlBusy(btn, true, "Refreshing…");
        window.setTimeout(() => {
          setControlBusy(btn, false);
          showToast("Console refreshed", "success", 1600);
          if (typeof markViewRefreshed === "function") markViewRefreshed("Refreshed");
          else {
            const target = document.getElementById("viewLastRefreshed");
            if (target) {
              const stamp = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
              target.textContent = `Refreshed · ${stamp}`;
            }
          }
        }, 850);
      },
      true,
    );
  }

  global.UiKit = {
    renderOperatorResult,
    renderOperatorResultError,
    renderOperatorResultSuccess,
    showToast,
    announce,
    setShellProgress,
    withShellProgress,
    bindConnectivityBanner,
    trapFocus,
    confirm,
    closeConfirm,
    bindConfirmDialog,
    copyText,
    enhanceCopyableResults,
    collapseOperatorGuides,
    setControlBusy,
    withBusy,
    renderEmptyState,
    renderTableEmptyRow,
    bindTabGroup,
    collapseCardHelp,
    attachInfoTips,
    buildInfoTip,
    enhanceFormValidation,
    enhancePageSurfaces,
    bindRefreshBusy,
    escapeHtml,
  };
})(window);
