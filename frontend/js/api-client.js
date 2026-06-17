(function initApiClient(global) {
  const { ACTOR_ROLES } = global.AppConstants;

  function normalizeActorRole(roleName) {
    const role = String(roleName || "").trim();
    return role || ACTOR_ROLES.MASTER_ADMIN;
  }

  function buildHeaders(state, options = {}) {
    const optionHeaders = {
      ...(options.headers || {}),
    };
    if (optionHeaders["X-Actor-Role"]) {
      optionHeaders["X-Actor-Role"] = normalizeActorRole(optionHeaders["X-Actor-Role"]);
    }

    return {
      "Content-Type": "application/json",
      "X-Actor-Role": normalizeActorRole(state?.actorRole),
      "X-Actor-Id": state?.actorId || "",
      "X-MFA-Verified": String(Boolean(state?.mfaVerified)),
      ...(state?.accessToken ? { Authorization: `Bearer ${state.accessToken}` } : {}),
      ...optionHeaders,
    };
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
    roleHeader,
    auditorHeaders,
  };
})(window);
