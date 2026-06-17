/* GuardBridge shared constants and privacy helpers */

const GuardBridgeConfig = {
  extensionName: "GuardBridge",
  apiBase: "http://127.0.0.1:8000",
  policyPath: "/browser/extensions/policies",
  eventsPath: "/browser/extensions/events",
  sessionPath: "/browser/extensions/sessions",
  supportedBrowsers: [
    "chrome",
    "edge",
    "firefox",
    "safari",
    "opera",
    "brave",
    "arc",
    "vivaldi",
    "samsung",
    "other",
  ],
};

function toETldPlusOne(hostname) {
  if (!hostname || typeof hostname !== "string") {
    return "";
  }
  const clean = hostname.trim().toLowerCase().replace(/^www\./, "");
  const parts = clean.split(".").filter(Boolean);
  if (parts.length < 2) {
    return clean;
  }
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

function sanitizeEventPayload(payload) {
  const safe = {
    trace_id: payload.trace_id || "",
    actor_id: payload.actor_id || "",
    environment: payload.environment || "dev",
    action_type: payload.action_type || "other",
    destination_domain: toETldPlusOne(payload.destination_domain || ""),
    destination_app: payload.destination_app || "",
    page_url_host: toETldPlusOne(payload.page_url_host || ""),
    decision_outcome: payload.decision_outcome || "allow",
    policy_rule_id: payload.policy_rule_id || null,
    risk_signals: Array.isArray(payload.risk_signals) ? payload.risk_signals.slice(0, 20) : [],
    content_fingerprint: payload.content_fingerprint || "",
    data_class: payload.data_class || "standard",
    browser_name: payload.browser_name || "unknown",
    browser_version: payload.browser_version || "",
    os_name: payload.os_name || "unknown",
    device_type: payload.device_type || "unknown",
    geo_country: payload.geo_country || "",
    geo_region: payload.geo_region || "",
  };
  return safe;
}

if (typeof module !== "undefined") {
  module.exports = { GuardBridgeConfig, sanitizeEventPayload, toETldPlusOne };
}
