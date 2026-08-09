function normalizeApiBaseAlias(rawBase) {
  const trimmed = String(rawBase || "").trim();
  if (!trimmed) return "";
  const normalized = trimmed.replace(/\/$/, "").toLowerCase();
  if (normalized === "https://api.agenthub.internal" || normalized === "https://stage-api.agenthub.internal") {
    return "http://127.0.0.1:8000";
  }
  return trimmed.replace(/\/$/, "");
}

function resolveActorRole(_actorId, fallbackRole) {
  return String(fallbackRole || "Master Admin");
}

function parseBooleanFlag(rawValue, fallback = false) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;
  return Boolean(fallback);
}

function isLoopbackApiBase(rawBase) {
  try {
    const host = new URL(String(rawBase || "")).hostname;
    return host === "127.0.0.1" || host === "localhost" || host === "::1";
  } catch {
    return false;
  }
}

function setStatus(message, isError = false) {
  const target = document.querySelector("#loginStatus");
  if (!target) return;
  target.textContent = message;
  target.classList.toggle("error", isError);
}

function formatLoginError(payload, status) {
  const detail = payload?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (detail && typeof detail === "object") {
    if (typeof detail.message === "string" && detail.message.trim()) {
      const code = detail.error_code ? ` (${detail.error_code})` : "";
      const hint = detail.remediation_hint ? ` ${detail.remediation_hint}` : "";
      return `${detail.message}${code}.${hint}`.trim();
    }
    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object") {
            return item.msg || item.message || JSON.stringify(item);
          }
          return String(item);
        })
        .join("; ");
    }
    try {
      return JSON.stringify(detail);
    } catch {
      /* fall through */
    }
  }
  if (typeof payload?.message === "string" && payload.message.trim()) return payload.message;
  return `Login failed with status ${status || "unknown"}`;
}

function sameOriginApiBase() {
  try {
    return window.location.origin.replace(/\/$/, "");
  } catch {
    return "";
  }
}

function defaultLocalApiBase() {
  // Prefer same-origin UI proxy so gb_session/gb_csrf stay on the console host.
  return sameOriginApiBase() || "http://127.0.0.1:8000";
}

function setApiForProfile(profile) {
  const apiBaseInput = document.querySelector("#apiBase");
  if (!apiBaseInput) return;
  if (profile === "local" || profile === "stage" || profile === "prod") {
    // Day-0 defaults keep profiles on loopback; operators can still override the URL field.
    if (!apiBaseInput.dataset.userEdited) {
      apiBaseInput.value = defaultLocalApiBase();
    }
  }
}

async function signIn(event) {
  event.preventDefault();
  const environmentSelect = document.querySelector("#environmentProfile");
  const apiBaseInput = document.querySelector("#apiBase");
  const environmentProfile = String(environmentSelect?.value || "local").trim() || "local";
  const apiBase = normalizeApiBaseAlias(apiBaseInput?.value) || defaultLocalApiBase();
  const username = String(document.querySelector("#username")?.value || "").trim();
  const password = String(document.querySelector("#password")?.value || "");
  const mfaVerified = parseBooleanFlag(document.querySelector("#mfaVerified")?.value, true);

  if (environmentSelect) environmentSelect.value = environmentProfile;
  if (apiBaseInput) apiBaseInput.value = apiBase;

  if (!username || !password) {
    setStatus("Username and password are required.", true);
    return;
  }
  const localConsole =
    isLoopbackApiBase(apiBase) || apiBase === sameOriginApiBase();
  if (localConsole && username !== "admin") {
    setStatus('Local Day-0 login requires username "admin" (not prod-operator).', true);
    return;
  }

  setStatus(`Signing in to ${apiBase}…`);
  const submitBtn = document.querySelector("#loginForm button[type='submit']");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add("is-busy");
    submitBtn.dataset.labelRestore = submitBtn.textContent;
    submitBtn.textContent = "Signing in…";
  }

  try {
    let response;
    try {
      response = await fetch(`${apiBase}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          ttl_minutes: 60,
          idle_timeout_minutes: 30,
        }),
      });
    } catch {
      throw new Error(
        `Cannot reach backend at ${apiBase}. Start the stack, then hard-refresh this page (Cmd+Shift+R).`,
      );
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      let detail = formatLoginError(payload, response.status);
      if (response.status === 401) {
        detail += " Check username and password, then try again.";
      }
      throw new Error(detail);
    }

    const actorId = String(payload?.actor_id || username);
    const actorRole = resolveActorRole(actorId, payload?.actor_role || "Master Admin");
    if (!payload?.session_id && !payload?.actor_id) {
      throw new Error("Session was not issued by the backend.");
    }

    localStorage.setItem("apiBase", apiBase);
    localStorage.setItem("environmentProfile", environmentProfile);
    localStorage.setItem("actorId", actorId);
    localStorage.setItem("actorRole", actorRole);
    // Never persist bearer tokens in localStorage. Keep a tab-scoped copy in sessionStorage
    // so index.html can authorize across the login→app navigation (httpOnly cookie remains primary).
    localStorage.removeItem("accessToken");
    localStorage.setItem("sessionActive", "1");
    localStorage.setItem("mfaVerified", String(mfaVerified));
    const accessToken = String(payload?.access_token || "").trim();
    const csrfToken = String(payload?.csrf_token || "").trim();
    try {
      if (accessToken) sessionStorage.setItem("sessionBearer", accessToken);
      else sessionStorage.removeItem("sessionBearer");
      if (csrfToken) sessionStorage.setItem("csrfToken", csrfToken);
    } catch {
      /* ignore quota / private-mode */
    }
    setStatus("Signed in — opening governance plane…");
    // Defer navigation so the login Enter key cannot activate Sign Out on the next page.
    window.setTimeout(() => {
      window.location.replace("./");
    }, 150);
    return;
  } catch (err) {
    setStatus(String(err?.message || err || "Login failed."), true);
  } finally {
    if (submitBtn && !localStorage.getItem("sessionActive")) {
      submitBtn.disabled = false;
      submitBtn.classList.remove("is-busy");
      if (submitBtn.dataset.labelRestore) {
        submitBtn.textContent = submitBtn.dataset.labelRestore;
        delete submitBtn.dataset.labelRestore;
      }
    }
  }
}

async function probeBackend(apiBase) {
  try {
    const response = await fetch(`${apiBase}/health`, { method: "GET" });
    if (!response.ok) {
      setStatus(`Backend reachable but /health returned ${response.status}.`, true);
      return;
    }
    setStatus("Ready to sign in.");
  } catch {
    setStatus("Backend offline. Start the local stack, then reload.", true);
  }
}

function init() {
  const params = new URLSearchParams(window.location.search || "");
  const bounceReason = String(params.get("reason") || "").trim();
  const bounced = Boolean(bounceReason);
  if (
    bounceReason === "session_idle" ||
    bounceReason === "session_expired" ||
    bounceReason === "auth_required" ||
    bounceReason === "signed_out" ||
    bounceReason === "missing_session"
  ) {
    localStorage.removeItem("sessionActive");
    localStorage.removeItem("accessToken");
    try {
      sessionStorage.removeItem("sessionBearer");
      sessionStorage.removeItem("sessionActive");
    } catch {
      /* ignore */
    }
  }
  // Resume only when we were not explicitly bounced from the app shell.
  if (
    !bounced &&
    localStorage.getItem("sessionActive") === "1" &&
    sessionStorage.getItem("sessionBearer")
  ) {
    window.location.replace("./");
    return;
  }
  const savedProfile = String(localStorage.getItem("environmentProfile") || "local").trim() || "local";
  let savedApiBase = normalizeApiBaseAlias(localStorage.getItem("apiBase")) || defaultLocalApiBase();
  // Migrate stale cross-origin local API base to same-origin proxy.
  if (savedApiBase === "http://127.0.0.1:8000" || savedApiBase === "http://localhost:8000") {
    savedApiBase = defaultLocalApiBase();
    localStorage.setItem("apiBase", savedApiBase);
  }
  localStorage.removeItem("accessToken");

  const environmentSelect = document.querySelector("#environmentProfile");
  if (environmentSelect) {
    environmentSelect.value = ["local", "stage", "prod"].includes(savedProfile) ? savedProfile : "local";
    environmentSelect.addEventListener("change", (event) => {
      setApiForProfile(String(event.target?.value || "local"));
      const nextBase = normalizeApiBaseAlias(document.querySelector("#apiBase")?.value) || defaultLocalApiBase();
      void probeBackend(nextBase);
    });
  }

  const apiBaseInput = document.querySelector("#apiBase");
  if (apiBaseInput) {
    apiBaseInput.value = savedApiBase;
    apiBaseInput.addEventListener("input", () => {
      apiBaseInput.dataset.userEdited = "true";
    });
    apiBaseInput.addEventListener("change", () => {
      const nextBase = normalizeApiBaseAlias(apiBaseInput.value) || defaultLocalApiBase();
      apiBaseInput.value = nextBase;
      void probeBackend(nextBase);
    });
  }

  document.querySelector("#loginForm")?.addEventListener("submit", signIn);
  void probeBackend(savedApiBase).then(() => {
    if (bounceReason === "session_idle") {
      setStatus("Session timed out due to idle. Sign in again.", true);
    } else if (bounceReason === "session_expired") {
      setStatus("Session expired. Sign in again.", true);
    } else if (bounceReason === "signed_out") {
      setStatus("Signed out. Sign in to continue.");
    }
  });
}

init();
