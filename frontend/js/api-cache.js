(function initApiCache(global) {
  const inFlight = new Map();
  let getApiBase = () => "";

  function configure(options = {}) {
    if (typeof options.getApiBase === "function") {
      getApiBase = options.getApiBase;
    }
  }

  function normalizePath(path) {
    return String(path || "").split("?")[0].replace(/\/+$/, "") || "/";
  }

  function cacheKey(method, path, headers = {}) {
    const role = String(headers["X-Actor-Role"] || "").trim();
    return `${getApiBase()}|${String(method || "GET").toUpperCase()}|${normalizePath(path)}|${role}`;
  }

  function shouldDedupe(method, path) {
    const normalizedMethod = String(method || "GET").toUpperCase();
    if (normalizedMethod !== "GET") return false;
    const normalizedPath = normalizePath(path);
    const bootPaths = global.AppConstants?.BOOT_DEDUPE_PATHS || [];
    return bootPaths.some((exactPath) => normalizedPath === exactPath);
  }

  async function dedupe(method, path, headers, fetchFn) {
    if (!shouldDedupe(method, path)) {
      return fetchFn();
    }
    const key = cacheKey(method, path, headers);
    if (inFlight.has(key)) {
      return inFlight.get(key);
    }
    const promise = Promise.resolve().then(fetchFn).finally(() => {
      inFlight.delete(key);
    });
    inFlight.set(key, promise);
    return promise;
  }

  global.ApiCache = {
    configure,
    cacheKey,
    dedupe,
    shouldDedupe,
  };
})(window);
