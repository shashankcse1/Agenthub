(function initPlatformStatus(global) {
  const POLL_INTERVAL_MS = 60000;
  const LATENCY_SAMPLES_MAX = 5;

  let pollTimer = null;
  let operationalStatus = null;
  let lastHealthLatencyMs = null;
  let latencySamples = [];
  let getApiBase = () => "";
  let getCurrentView = () => "overview";
  let onDowntime = null;

  function qs(selector) {
    return document.querySelector(selector);
  }

  function averageLatency() {
    if (!latencySamples.length) return null;
    const total = latencySamples.reduce((sum, value) => sum + value, 0);
    return Math.round(total / latencySamples.length);
  }

  function recordLatency(ms) {
    if (!Number.isFinite(ms) || ms < 0) return;
    lastHealthLatencyMs = ms;
    latencySamples.push(ms);
    if (latencySamples.length > LATENCY_SAMPLES_MAX) latencySamples.shift();
  }

  function renderMaintenanceBanner(status) {
    const banner = qs("#platformMaintenanceBanner");
    if (!banner) return;
    const maintenance = status?.maintenance || {};
    if (!maintenance.active) {
      banner.hidden = true;
      banner.textContent = "";
      return;
    }
    banner.hidden = false;
    banner.textContent = maintenance.message
      || "Planned maintenance is in progress. Some console actions may be unavailable.";
  }

  function renderSlowPerformanceBanner(status, latencyMs) {
    const banner = qs("#platformSlowPerformanceBanner");
    const label = banner?.querySelector(".platform-perf-banner-text");
    if (!banner) return;
    const threshold = Number(status?.performance?.slow_response_threshold_ms) || 2000;
    const avg = averageLatency();
    const observed = Math.max(Number(latencyMs) || 0, Number(avg) || 0);
    if (!observed || observed < threshold) {
      banner.hidden = true;
      if (label) label.textContent = "";
      return;
    }
    banner.hidden = false;
    const target = label || banner;
    target.textContent = `Slow response detected (${observed} ms avg). Console may feel sluggish — consider refreshing or submitting feedback.`;
  }

  function renderDowntimeBanner(status, healthOk) {
    const banner = qs("#platformDowntimeBanner");
    if (!banner) return;
    const degraded = status?.status === "degraded" || status?.runtime_config_cache?.degraded;
    if (healthOk && status?.status !== "maintenance" && !degraded) {
      banner.hidden = true;
      banner.textContent = "";
      return;
    }
    if (status?.status === "maintenance") {
      banner.hidden = true;
      return;
    }
    banner.hidden = false;
    banner.textContent = healthOk
      ? "Platform is degraded. Some dependencies may be unavailable."
      : "Platform connectivity issue detected. Retry shortly or switch environment profile.";
    if (!healthOk && typeof onDowntime === "function") onDowntime();
  }

  function renderControlPlaneBanner(status) {
    const banner = qs("#platformControlPlaneBanner");
    if (!banner) return;
    const cp = status?.control_plane || {};
    const advisory = cp.advisory;
    if (!advisory) {
      banner.hidden = true;
      banner.textContent = "";
      banner.classList.remove("warn");
      return;
    }
    banner.hidden = false;
    banner.classList.toggle("warn", Boolean(cp.control_readonly) || cp.ready === false);
    banner.textContent = String(advisory);
  }

  async function fetchOperationalStatus() {
    const base = String(getApiBase() || "").replace(/\/$/, "");
    const started = performance.now();
    const response = await fetch(`${base}/platform/operational-status`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    recordLatency(Math.round(performance.now() - started));
    if (!response.ok) throw new Error(`operational-status ${response.status}`);
    return response.json();
  }

  let lastHealthPayload = null;

  function renderLeadershipPostureChips(health) {
    const root = qs("#leadershipPostureChips");
    if (!root) return;
    if (!health || typeof health !== "object") {
      root.hidden = true;
      return;
    }
    root.hidden = false;
    const mfa = health.mfa_optional || {};
    const token = health.token_exposure || {};
    const rotation = health.session_signing_rotation || {};
    const rate = health.rate_limit || {};
    const setText = (id, value) => {
      const el = qs(id);
      if (el) el.textContent = value;
    };
    setText("#postureMfaOptional", mfa.effective ? "ON (local-only)" : "off");
    setText("#postureTokenExposure", token.effective ? "ON (local-only)" : "off");
    if (rotation.rotation_age_exceeded) {
      setText("#postureSessionSigning", "rotation overdue");
    } else if (rotation.key_ring_configured) {
      setText("#postureSessionSigning", rotation.monitoring_enabled ? "monitored" : "configured");
    } else {
      setText("#postureSessionSigning", "default");
    }
    setText(
      "#postureRateLimit",
      rate.degraded ? "degraded" : String(rate.active_backend || rate.status || "ok")
    );
    const transport = health.transport || {};
    setText(
      "#postureTransport",
      transport.expect_https ? "HTTPS expected · HSTS on" : "HSTS on (local)"
    );
    const exceptions = health.exception_posture || {};
    const activeBg = Number(exceptions.active_break_glass || 0);
    const expired = Number(exceptions.expired_still_marked_enabled || 0);
    setText(
      "#postureExceptions",
      expired > 0 ? `${expired} expired (auto-disable)` : activeBg > 0 ? `${activeBg} active` : "none"
    );
  }

  async function probeHealthLatency() {
    const base = String(getApiBase() || "").replace(/\/$/, "");
    const started = performance.now();
    const response = await fetch(`${base}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    recordLatency(Math.round(performance.now() - started));
    if (response.ok) {
      try {
        lastHealthPayload = await response.json();
      } catch {
        lastHealthPayload = null;
      }
    } else {
      lastHealthPayload = null;
    }
    return response.ok;
  }

  async function refresh(options = {}) {
    let healthOk = true;
    try {
      healthOk = await probeHealthLatency();
    } catch {
      healthOk = false;
      lastHealthPayload = null;
    }
    try {
      operationalStatus = await fetchOperationalStatus();
    } catch {
      operationalStatus = operationalStatus || {
        status: healthOk ? "degraded" : "incident",
        maintenance: { active: false, message: "" },
        performance: { slow_response_threshold_ms: 2000 },
      };
    }
    renderLeadershipPostureChips(lastHealthPayload);
    renderMaintenanceBanner(operationalStatus);
    renderSlowPerformanceBanner(operationalStatus, lastHealthLatencyMs);
    renderDowntimeBanner(operationalStatus, healthOk);
    renderControlPlaneBanner(operationalStatus);
    if (options.notifyFeedback && global.OperatorFeedback) {
      global.OperatorFeedback.setContext({
        clientLatencyMs: lastHealthLatencyMs,
        operationalStatus: operationalStatus?.status,
      });
    }
    return { healthOk, operationalStatus, lastHealthLatencyMs };
  }

  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      void refresh({ notifyFeedback: true });
    }, POLL_INTERVAL_MS);
  }

  function stopPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
  }

  function getStatus() {
    return {
      operationalStatus,
      lastHealthLatencyMs,
      averageLatencyMs: averageLatency(),
      currentView: getCurrentView(),
      lastHealthPayload,
    };
  }

  function configure(options = {}) {
    if (typeof options.getApiBase === "function") getApiBase = options.getApiBase;
    if (typeof options.getCurrentView === "function") getCurrentView = options.getCurrentView;
    if (typeof options.onDowntime === "function") onDowntime = options.onDowntime;
  }

  async function init(options = {}) {
    configure(options);
    await refresh({ notifyFeedback: true });
    startPolling();
  }

  global.PlatformStatus = Object.freeze({
    init,
    configure,
    refresh,
    startPolling,
    stopPolling,
    getStatus,
    getOperationalStatus: () => operationalStatus,
    getLastLatencyMs: () => lastHealthLatencyMs,
  });
})(window);
