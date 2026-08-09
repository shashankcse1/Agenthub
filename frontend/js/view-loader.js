(function initViewLoader(global) {
  const VIEW_IDS = [
    "overview",
    "agents",
    "playground",
    "benchmark-scan",
    "orchestration",
    "routing-gateway",
    "runtime-config",
    "providers",
    "modules",
    "agentic",
    "discovery",
    "cost",
    "audit",
    "security",
    "compliance",
    "observability",
    "browser-security",
  ];

  const loadedViews = new Set();
  const loadingViews = new Map();
  let bootstrapPromise = null;

  function formatViewLabel(viewId) {
    return String(viewId || "")
      .split("-")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
  }

  function ensureSkeleton(viewId) {
    const root = document.getElementById("viewsRoot");
    if (!root) return null;
    const existing = document.getElementById(`view-skeleton-${viewId}`);
    // Never steal .active from another real view (e.g. overview prefetch of Flow Studio).
    // Only show a skeleton when the viewport has nothing else active.
    const hasActiveView = Boolean(
      [...root.querySelectorAll(".view.active")].find(
        (section) =>
          !section.classList.contains("view-boot-skeleton") &&
          !String(section.id || "").startsWith("view-error-"),
      ),
    );
    if (existing) {
      if (!hasActiveView) existing.classList.add("active");
      return existing;
    }

    const skeleton = document.createElement("section");
    skeleton.id = `view-skeleton-${viewId}`;
    skeleton.className = "view view-boot-skeleton";
    if (!hasActiveView) skeleton.classList.add("active");
    skeleton.setAttribute("aria-busy", "true");
    skeleton.setAttribute("aria-live", "polite");
    skeleton.innerHTML = `
      <p class="view-boot-skeleton-meta">Loading ${formatViewLabel(viewId)}…</p>
      <div class="ui-skeleton hero" aria-hidden="true"></div>
      <div class="ui-skeleton line" aria-hidden="true"></div>
      <div class="ui-skeleton line-short" aria-hidden="true"></div>
      <div class="ui-skeleton line" aria-hidden="true"></div>
    `;
    root.appendChild(skeleton);
    return skeleton;
  }

  function clearSkeleton(viewId) {
    const skeleton = document.getElementById(`view-skeleton-${viewId}`);
    if (skeleton) skeleton.remove();
  }

  async function fetchView(viewId) {
    const response = await fetch(`./views/${viewId}.html`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Failed to load view "${viewId}" (${response.status})`);
    }
    return response.text();
  }

  function mountView(viewId, html) {
    const root = document.getElementById("viewsRoot");
    if (!root) throw new Error("Missing #viewsRoot mount point");

    const wrapper = document.createElement("div");
    wrapper.innerHTML = html.trim();
    const section = wrapper.firstElementChild;
    if (!section || section.tagName !== "SECTION") {
      throw new Error(`View "${viewId}" must render a <section> root element`);
    }

    clearSkeleton(viewId);
    const existing = document.getElementById(viewId);
    if (existing) existing.remove();
    root.appendChild(section);
    loadedViews.add(viewId);
    return section;
  }

  async function loadView(viewId) {
    if (loadedViews.has(viewId)) {
      return document.getElementById(viewId);
    }
    if (loadingViews.has(viewId)) {
      return loadingViews.get(viewId);
    }

    ensureSkeleton(viewId);
    if (typeof global.UiKit !== "undefined" && typeof global.UiKit.setShellProgress === "function") {
      global.UiKit.setShellProgress(true);
    }
    const promise = fetchView(viewId)
      .then((html) => mountView(viewId, html))
      .catch((err) => {
        clearSkeleton(viewId);
        const root = document.getElementById("viewsRoot");
        if (root) {
          const failure = document.createElement("section");
          failure.className = "view active";
          failure.id = `view-error-${viewId}`;
          failure.innerHTML = `<article class="card empty-state" role="alert">
            <strong>Could not load ${formatViewLabel(viewId)}</strong>
            <p>${String(err?.message || err)}</p>
            <button type="button" class="ghost empty-state-action" data-retry-view="${viewId}">Retry</button>
          </article>`;
          root.appendChild(failure);
          failure.querySelector("[data-retry-view]")?.addEventListener("click", () => {
            failure.remove();
            loadedViews.delete(viewId);
            void loadView(viewId).then(() => setActiveView(viewId));
          });
        }
        throw err;
      })
      .finally(() => {
        loadingViews.delete(viewId);
        if (typeof global.UiKit !== "undefined" && typeof global.UiKit.setShellProgress === "function") {
          global.UiKit.setShellProgress(false);
        }
      });
    loadingViews.set(viewId, promise);
    return promise;
  }

  async function bootstrap(initialView = "overview") {
    if (!bootstrapPromise) {
      bootstrapPromise = loadView(initialView).then(() => {
        setActiveView(initialView);
      });
    }
    return bootstrapPromise;
  }

  function setActiveView(viewId) {
    document.querySelectorAll("#viewsRoot .view").forEach((section) => {
      const isTarget = section.id === viewId;
      const isSkeleton = section.id === `view-skeleton-${viewId}`;
      section.classList.toggle("active", isTarget || isSkeleton);
    });
  }

  async function prefetchView(viewId) {
    if (!VIEW_IDS.includes(viewId)) return null;
    if (loadedViews.has(viewId) || loadingViews.has(viewId)) {
      return document.getElementById(viewId);
    }
    const promise = fetchView(viewId)
      .then((html) => mountView(viewId, html))
      .catch(() => null)
      .finally(() => {
        loadingViews.delete(viewId);
      });
    loadingViews.set(viewId, promise);
    return promise;
  }

  async function ensureView(viewId) {
    return loadView(viewId);
  }

  function unloadView(viewId) {
    if (viewId === "overview") return;
    const section = document.getElementById(viewId);
    if (!section) return;
    section.remove();
    loadedViews.delete(viewId);
    delete section.dataset.consoleBound;
    clearSkeleton(viewId);
  }

  global.ViewLoader = {
    VIEW_IDS,
    bootstrap,
    ensureView,
    prefetchView,
    loadView,
    unloadView,
    setActiveView,
    isLoaded(viewId) {
      return loadedViews.has(viewId);
    },
  };
})(window);
