(function initTableSearch(global) {
  function isPlaceholderRow(tr) {
    return Boolean(tr?.querySelector("td[colspan]"));
  }

  function hasExistingTableSearch(tableWrap) {
    if (!tableWrap) return true;
    if (tableWrap.dataset.tableSearchSkip === "true") return true;

    let prev = tableWrap.previousElementSibling;
    for (let i = 0; i < 4 && prev; i += 1) {
      if (
        prev.matches(
          ".table-search-toolbar, .view-page-search-row, .modules-table-search, .providers-tenant-table-search, .directory-search-row",
        )
      ) {
        return true;
      }
      if (prev.matches(".view-page-search-status")) {
        prev = prev.previousElementSibling;
        continue;
      }
      prev = prev.previousElementSibling;
    }

    const card = tableWrap.closest("article.card, .runtime-console-panel");
    if (card?.querySelector(":scope > .card-head .view-page-search-input, :scope > .card-head #runtimeValidationSearch")) {
      return true;
    }
    if (card?.querySelector("#discoveryTriageSearch")) {
      const tbody = tableWrap.querySelector("tbody");
      if (tbody?.id === "discoveryUnifiedTriageTable") return true;
    }
    return false;
  }

  function getTableLabel(tableWrap) {
    const caption = tableWrap.querySelector("caption");
    if (caption?.textContent?.trim()) {
      return `Search ${caption.textContent.trim()}`;
    }
    const cardHeading = tableWrap.closest("article.card")?.querySelector("h3,h4")?.textContent?.trim();
    if (cardHeading) return `Search ${cardHeading}`;
    const tbodyId = tableWrap.querySelector("tbody")?.id || "";
    if (tbodyId) {
      const label = tbodyId
        .replace(/Table$/, "")
        .replace(/([A-Z])/g, " $1")
        .trim();
      if (label) return `Search ${label}`;
    }
    return "Search table";
  }

  function refreshPagination(tbody) {
    if (typeof global.refreshTablePagination === "function") {
      global.refreshTablePagination(tbody);
      return;
    }
    global.dispatchEvent(new CustomEvent("agenthub:table-search-applied", { detail: { tbody } }));
  }

  function applyTableSearch(tbody, query) {
    if (!tbody) return 0;
    const q = String(query || "").trim().toLowerCase();
    tbody.dataset.tableSearchQuery = String(query || "").trim();
    let visible = 0;

    Array.from(tbody.querySelectorAll("tr")).forEach((tr) => {
      if (isPlaceholderRow(tr)) {
        tr.dataset.tableSearchHidden = q ? "true" : "false";
        tr.hidden = Boolean(q);
        return;
      }
      const text = String(tr.textContent || "").toLowerCase();
      const match = !q || text.includes(q);
      tr.dataset.tableSearchHidden = match ? "false" : "true";
      if (!match) {
        tr.hidden = true;
        return;
      }
      visible += 1;
    });

    refreshPagination(tbody);
    return visible;
  }

  function updateStatus(statusEl, query, visibleCount, totalCount) {
    if (!statusEl) return;
    const q = String(query || "").trim();
    if (!q) {
      statusEl.textContent = totalCount ? `Showing ${totalCount} row(s).` : "";
      return;
    }
    if (!visibleCount) {
      statusEl.textContent = `No matches for "${q}".`;
      return;
    }
    statusEl.textContent = `Showing ${visibleCount} of ${totalCount} row(s) matching "${q}".`;
  }

  function countDataRows(tbody) {
    return Array.from(tbody.querySelectorAll("tr")).filter((tr) => !isPlaceholderRow(tr)).length;
  }

  function bindToolbar(tbody, toolbar, statusEl) {
    const input = toolbar.querySelector(".table-search-input");
    const searchBtn = toolbar.querySelector(".table-search-btn");
    const clearBtn = toolbar.querySelector(".table-search-clear-btn");

    const runSearch = () => {
      const query = input?.value || "";
      const total = countDataRows(tbody);
      const visible = applyTableSearch(tbody, query);
      updateStatus(statusEl, query, visible, total);
    };

    searchBtn?.addEventListener("click", runSearch);
    clearBtn?.addEventListener("click", () => {
      if (input) input.value = "";
      const total = countDataRows(tbody);
      applyTableSearch(tbody, "");
      updateStatus(statusEl, "", total, total);
    });
    input?.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter") {
        evt.preventDefault();
        runSearch();
      }
      if (evt.key === "Escape") {
        if (input) input.value = "";
        applyTableSearch(tbody, "");
        updateStatus(statusEl, "", countDataRows(tbody), countDataRows(tbody));
      }
    });
  }

  function createToolbar(tbody, label) {
    const toolbar = document.createElement("div");
    toolbar.className = "table-search-toolbar view-page-search-row";
    toolbar.dataset.tableSearchFor = tbody.id || "";
    toolbar.innerHTML = `
      <label class="view-page-search-label">
        ${label}
        <input type="search" class="view-page-search-input table-search-input" placeholder="Filter rows in this table" autocomplete="off" />
      </label>
      <div class="view-page-search-actions">
        <button type="button" class="primary view-page-search-btn table-search-btn">Search</button>
        <button type="button" class="ghost view-page-search-clear-btn table-search-clear-btn">Clear</button>
      </div>
    `;
    const statusEl = document.createElement("p");
    statusEl.className = "view-page-search-status mono table-search-status";
    statusEl.setAttribute("aria-live", "polite");
    return { toolbar, statusEl };
  }

  function initTableSearchToolbars(root = document) {
    root.querySelectorAll(".table-wrap").forEach((tableWrap) => {
      const tbody = tableWrap.querySelector("tbody");
      if (!tbody || tbody.dataset.tableSearchBound === "true" || tbody.dataset.tableSearchSkip === "true") return;
      if (hasExistingTableSearch(tableWrap)) return;

      const label = getTableLabel(tableWrap);
      const { toolbar, statusEl } = createToolbar(tbody, label);
      tableWrap.insertAdjacentElement("beforebegin", statusEl);
      tableWrap.insertAdjacentElement("beforebegin", toolbar);
      bindToolbar(tbody, toolbar, statusEl);
      tbody.dataset.tableSearchBound = "true";
    });
  }

  global.TableSearch = {
    init: initTableSearchToolbars,
    apply: applyTableSearch,
    refresh: (tbody) => applyTableSearch(tbody, tbody?.dataset?.tableSearchQuery || ""),
  };
})(window);
