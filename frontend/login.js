function normalizeApiBaseAlias(rawBase) {
  const trimmed = String(rawBase || "").trim();
  if (!trimmed) return "";
  const normalized = trimmed.replace(/\/$/, "").toLowerCase();
  if (normalized === "https://api.agenthub.internal" || normalized === "https://stage-api.agenthub.internal") {
    return "http://127.0.0.1:8000";
  }
  return trimmed;
}

function normalizeActorId(actorId) {
  return String(actorId || "").trim().toLowerCase();
}

function resolveActorRole(actorId, fallbackRole) {
  return String(fallbackRole || "Master Admin");
}

function parseBooleanFlag(rawValue, fallback = false) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;
  return Boolean(fallback);
}

function setStatus(message, isError = false) {
  const target = document.querySelector("#loginStatus");
  if (!target) return;
  target.textContent = message;
  target.classList.toggle("error", isError);
}

function setApiForProfile(profile) {
  const apiBaseInput = document.querySelector("#apiBase");
  if (!apiBaseInput) return;
  if (profile === "local" || profile === "stage" || profile === "prod") {
    apiBaseInput.value = "http://127.0.0.1:8000";
  }
}

async function signIn(event) {
  event.preventDefault();
  const environmentProfile = String(document.querySelector("#environmentProfile")?.value || "local");
  const apiBaseRaw = String(document.querySelector("#apiBase")?.value || "").trim();
  const apiBase = normalizeApiBaseAlias(apiBaseRaw).replace(/\/$/, "");
  const username = String(document.querySelector("#username")?.value || "").trim();
  const password = String(document.querySelector("#password")?.value || "");
  const mfaVerified = parseBooleanFlag(document.querySelector("#mfaVerified")?.value, true);

  if (!apiBase || !username || !password) {
    setStatus("API base URL, username, and password are required.", true);
    return;
  }

  setStatus("Signing in...");

  try {
    const response = await fetch(`${apiBase}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        password,
        ttl_minutes: 60,
        idle_timeout_minutes: 30,
      }),
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = String(payload?.detail || payload?.message || `Login failed with status ${response.status}`);
      throw new Error(detail);
    }

    const actorId = String(payload?.actor_id || username);
    const actorRole = resolveActorRole(actorId, payload?.actor_role || "Master Admin");
    const accessToken = String(payload?.access_token || "");

    if (!accessToken) {
      throw new Error("Session token was not issued by the backend.");
    }

    localStorage.setItem("apiBase", apiBase);
    localStorage.setItem("environmentProfile", environmentProfile);
    localStorage.setItem("actorId", actorId);
    localStorage.setItem("actorRole", actorRole);
    localStorage.setItem("accessToken", accessToken);
    localStorage.setItem("mfaVerified", String(mfaVerified));

    window.location.href = "./index.html";
  } catch (err) {
    setStatus(String(err?.message || err || "Login failed."), true);
  }
}

function init() {
  const environmentProfile = localStorage.getItem("environmentProfile") || "local";
  const apiBase = normalizeApiBaseAlias(localStorage.getItem("apiBase") || "http://127.0.0.1:8000");
  const actorId = localStorage.getItem("actorId") || "prod-operator";

  const environmentSelect = document.querySelector("#environmentProfile");
  if (environmentSelect) {
    environmentSelect.value = ["local", "stage", "prod"].includes(environmentProfile) ? environmentProfile : "local";
    environmentSelect.addEventListener("change", (event) => {
      setApiForProfile(String(event.target?.value || "local"));
    });
  }

  const apiBaseInput = document.querySelector("#apiBase");
  if (apiBaseInput) {
    apiBaseInput.value = apiBase;
  }

  const usernameInput = document.querySelector("#username");
  if (usernameInput) {
    usernameInput.value = actorId;
  }

  document.querySelector("#loginForm")?.addEventListener("submit", signIn);
}

init();
