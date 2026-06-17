(function initViewSearch(global) {
  const viewSearchHooks = {};

  function isPlaceholderRow(tr) {
    return Boolean(tr.querySelector("td[colspan]"));
  }

  function applyViewPageSearch(viewId, query) {
    const view = document.getElementById(viewId);
    if (!view) return { visibleRows: 0, visibleCards: 0 };

    const q = String(query || "").trim().toLowerCase();
    let visibleRows = 0;
    let visibleCards = 0;

    view.querySelectorAll("table tbody").forEach((tbody) => {
      Array.from(tbody.querySelectorAll("tr")).forEach((tr) => {
        if (isPlaceholderRow(tr)) {
          tr.hidden = Boolean(q);
          return;
        }
        const text = String(tr.textContent || "").toLowerCase();
        const visible = !q || text.includes(q);
        tr.hidden = !visible;
        if (visible) visibleRows += 1;
      });
    });

    view.querySelectorAll("article.card").forEach((card) => {
      if (card.matches(".view-page-search-toolbar, [data-view-search-toolbar]")) return;

      const heading = String(card.querySelector("h3,h4")?.textContent || "").toLowerCase();
      const cardText = String(card.textContent || "").toLowerCase();
      const visibleDataRows = Array.from(card.querySelectorAll("tbody tr")).filter(
        (tr) => !isPlaceholderRow(tr) && !tr.hidden,
      ).length;
      const formMatches =
        q &&
        Array.from(card.querySelectorAll("label, .card-lead, .overview-intro, p.mono")).some((node) =>
          String(node.textContent || "")
            .toLowerCase()
            .includes(q),
        );

      const matches = !q || heading.includes(q) || cardText.includes(q) || formMatches || visibleDataRows > 0;
      card.hidden = !matches;
      if (matches) visibleCards += 1;
    });

    return { visibleRows, visibleCards };
  }

  function updateViewSearchStatus(statusEl, query, stats) {
    if (!statusEl) return;
    const q = String(query || "").trim();
    if (!q) {
      statusEl.textContent = "";
      return;
    }
    if (stats.visibleRows || stats.visibleCards) {
      statusEl.textContent = `Matches found: ${stats.visibleRows} table row(s), ${stats.visibleCards} section(s).`;
      return;
    }
    statusEl.textContent = `No matches for "${q}" on this page.`;
  }

  function runViewSearch(view) {
    const viewId = view.id;
    const toolbar = view.querySelector("[data-view-search-toolbar], .view-page-search-toolbar");
    const input = toolbar?.querySelector("[data-view-search-input], .view-page-search-input");
    const statusEl = toolbar?.querySelector(".view-page-search-status");
    const query = input?.value || "";
    const hooks = viewSearchHooks[viewId];

    let stats = { visibleRows: 0, visibleCards: 0 };
    if (hooks?.onSearch) {
      stats = hooks.onSearch(query) || stats;
    } else {
      stats = applyViewPageSearch(viewId, query);
    }
    updateViewSearchStatus(statusEl, query, stats);
  }

  function clearViewSearch(view) {
    const viewId = view.id;
    const toolbar = view.querySelector("[data-view-search-toolbar], .view-page-search-toolbar");
    const input = toolbar?.querySelector("[data-view-search-input], .view-page-search-input");
    const statusEl = toolbar?.querySelector(".view-page-search-status");
    if (input) input.value = "";

    const hooks = viewSearchHooks[viewId];
    if (hooks?.onClear) {
      hooks.onClear();
    } else {
      applyViewPageSearch(viewId, "");
    }
    if (statusEl) statusEl.textContent = "";
  }

  function bindViewSearchToolbar(view) {
    const toolbar = view.querySelector("[data-view-search-toolbar], .view-page-search-toolbar");
    if (!toolbar || toolbar.dataset.viewSearchBound === "true") return;
    toolbar.dataset.viewSearchBound = "true";

    const searchBtn = toolbar.querySelector(".view-page-search-btn");
    const clearBtn = toolbar.querySelector(".view-page-search-clear-btn");
    const input = toolbar.querySelector("[data-view-search-input], .view-page-search-input");

    searchBtn?.addEventListener("click", () => runViewSearch(view));
    clearBtn?.addEventListener("click", () => clearViewSearch(view));
    input?.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter") {
        evt.preventDefault();
        runViewSearch(view);
      }
      if (evt.key === "Escape") {
        clearViewSearch(view);
      }
    });
  }

  function createViewSearchToolbar() {
    const article = document.createElement("article");
    article.className = "card view-page-search-toolbar";
    article.dataset.viewSearchToolbar = "true";
    article.innerHTML = `
      <div class="view-page-search-row">
        <label class="view-page-search-label">
          Search this page
          <input type="search" class="view-page-search-input" data-view-search-input placeholder="Filter tables and sections on this page" autocomplete="off" />
        </label>
        <div class="view-page-search-actions">
          <button type="button" class="primary view-page-search-btn">Search</button>
          <button type="button" class="ghost view-page-search-clear-btn">Clear</button>
        </div>
      </div>
      <p class="view-page-search-status mono" aria-live="polite"></p>
    `;
    return article;
  }

  function initViewPageSearchToolbars() {
    document.querySelectorAll("#viewsRoot .view").forEach((view) => {
      if (!view.id) return;
      if (!view.querySelector("[data-view-search-toolbar], .view-page-search-toolbar")) {
        view.insertBefore(createViewSearchToolbar(), view.firstChild);
      }
      bindViewSearchToolbar(view);
    });
  }

  function registerViewSearchHook(viewId, hooks = {}) {
    if (!viewId) return;
    viewSearchHooks[viewId] = hooks;
  }

  global.ViewSearch = {
    init: initViewPageSearchToolbars,
    apply: applyViewPageSearch,
    registerHook: registerViewSearchHook,
    runForView(viewId) {
      const view = document.getElementById(viewId);
      if (view) runViewSearch(view);
    },
    clearForView(viewId) {
      const view = document.getElementById(viewId);
      if (view) clearViewSearch(view);
    },
  };
})(window);
