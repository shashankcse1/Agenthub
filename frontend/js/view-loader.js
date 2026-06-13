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
    const promise = fetchView(viewId)
      .then((html) => mountView(viewId, html))
      .finally(() => {
        loadingViews.delete(viewId);
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
      section.classList.toggle("active", section.id === viewId);
    });
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
  }

  global.ViewLoader = {
    VIEW_IDS,
    bootstrap,
    ensureView,
    loadView,
    unloadView,
    setActiveView,
    isLoaded(viewId) {
      return loadedViews.has(viewId);
    },
  };
})(window);
