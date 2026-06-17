/* global browser, chrome */

const runtimeApi = typeof browser !== "undefined" ? browser : chrome;

async function readConfig() {
  return {
    apiBase: "http://127.0.0.1:8000",
    actorId: "extension-user",
    environment: "dev",
  };
}

async function fetchPolicy() {
  const cfg = await readConfig();
  const res = await fetch(`${cfg.apiBase}/browser/extensions/policies?environment=${encodeURIComponent(cfg.environment)}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "X-Actor-Role": "Security Approver",
      "X-Actor-Id": "guardbridge-extension",
    },
  });
  if (!res.ok) {
    throw new Error(`Policy fetch failed: ${res.status}`);
  }
  return res.json();
}

async function postEvent(eventPayload) {
  const cfg = await readConfig();
  const res = await fetch(`${cfg.apiBase}/browser/extensions/events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Actor-Role": "Security Approver",
      "X-Actor-Id": "guardbridge-extension",
    },
    body: JSON.stringify({
      trace_id: eventPayload.trace_id,
      actor_id: cfg.actorId,
      environment: cfg.environment,
      action_type: eventPayload.action_type || "other",
      destination_domain: eventPayload.destination_domain || "",
      destination_app: eventPayload.destination_app || "",
      page_url_host: eventPayload.page_url_host || "",
      decision_outcome: eventPayload.decision_outcome || "allow",
      policy_rule_id: eventPayload.policy_rule_id || null,
      risk_signals: Array.isArray(eventPayload.risk_signals) ? eventPayload.risk_signals : [],
      content_fingerprint: eventPayload.content_fingerprint || "",
      data_class: eventPayload.data_class || "standard",
      browser_name: eventPayload.browser_name || "unknown",
      browser_version: eventPayload.browser_version || "",
      os_name: eventPayload.os_name || "unknown",
      device_type: eventPayload.device_type || "unknown",
      geo_country: eventPayload.geo_country || "",
      geo_region: eventPayload.geo_region || "",
    }),
  });
  if (!res.ok) {
    throw new Error(`Event ingest failed: ${res.status}`);
  }
  return res.json();
}

runtimeApi.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.type) {
    sendResponse({ ok: false, error: "missing message type" });
    return;
  }

  if (message.type === "guardbridge.fetchPolicy") {
    fetchPolicy()
      .then((policy) => sendResponse({ ok: true, policy }))
      .catch((err) => sendResponse({ ok: false, error: String(err.message || err) }));
    return true;
  }

  if (message.type === "guardbridge.emitEvent") {
    postEvent(message.payload || {})
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: String(err.message || err) }));
    return true;
  }

  sendResponse({ ok: false, error: "unknown message type" });
});
