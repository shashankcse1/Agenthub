(function initApiClient(global) {
  const { ACTOR_ROLES } = global.AppConstants;

  function normalizeActorRole(roleName) {
    const role = String(roleName || "").trim();
    return role || ACTOR_ROLES.MASTER_ADMIN;
  }

  function readCsrfToken() {
    try {
      const stored = String(sessionStorage.getItem("csrfToken") || "").trim();
      if (stored) return stored;
    } catch {
      /* ignore */
    }
    try {
      // Same-origin cookie path (when UI is proxied through the API host).
      const match = String(document.cookie || "").match(/(?:^|; )gb_csrf=([^;]*)/);
      return match ? decodeURIComponent(match[1]) : "";
    } catch {
      return "";
    }
  }

  function setCsrfToken(token) {
    const value = String(token || "").trim();
    try {
      if (value) sessionStorage.setItem("csrfToken", value);
      else sessionStorage.removeItem("csrfToken");
    } catch {
      /* ignore */
    }
    return value;
  }

  function buildHeaders(state, options = {}) {
    const optionHeaders = {
      ...(options.headers || {}),
    };
    if (optionHeaders["X-Actor-Role"]) {
      optionHeaders["X-Actor-Role"] = normalizeActorRole(optionHeaders["X-Actor-Role"]);
    }

    const headers = {
      "Content-Type": "application/json",
      "X-Actor-Role": normalizeActorRole(state?.actorRole),
      "X-Actor-Id": state?.actorId || "",
      "X-MFA-Verified": String(Boolean(state?.mfaVerified)),
      // Optional in-memory Bearer only; browser auth prefers httpOnly gb_session cookie.
      ...(state?.accessToken ? { Authorization: `Bearer ${state.accessToken}` } : {}),
      ...optionHeaders,
    };
    const csrf = readCsrfToken();
    if (csrf && !headers["X-CSRF-Token"]) {
      headers["X-CSRF-Token"] = csrf;
    }
    const approverId = String(headers["X-Approver-Id"] || "").trim();
    if (
      state?.approverAccessToken &&
      !headers["X-Approver-Authorization"] &&
      approverId &&
      state?.approverCosignUser === approverId
    ) {
      headers["X-Approver-Authorization"] = `Bearer ${state.approverAccessToken}`;
    }
    return headers;
  }

  function roleHeader(roleName) {
    return { "X-Actor-Role": normalizeActorRole(roleName) };
  }

  function auditorHeaders() {
    return roleHeader(ACTOR_ROLES.AUDITOR);
  }

  global.ApiClient = {
    normalizeActorRole,
    buildHeaders,
    readCsrfToken,
    setCsrfToken,
    roleHeader,
    auditorHeaders,
  };
})(window);
