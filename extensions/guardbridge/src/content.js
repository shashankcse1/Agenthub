/* global browser, chrome */

const runtimeApi = typeof browser !== "undefined" ? browser : chrome;

function currentHost() {
  try {
    return window.location.hostname || "";
  } catch {
    return "";
  }
}

function makeTraceId() {
  const rand = Math.random().toString(16).slice(2);
  return `gb-trace-${Date.now()}-${rand}`;
}

function sendAction(actionType, decisionOutcome) {
  runtimeApi.runtime.sendMessage({
    type: "guardbridge.emitEvent",
    payload: {
      trace_id: makeTraceId(),
      action_type: actionType,
      decision_outcome: decisionOutcome,
      destination_domain: currentHost(),
      destination_app: currentHost(),
      page_url_host: currentHost(),
      risk_signals: [],
      data_class: "standard",
      browser_name: "unknown",
      browser_version: "",
      os_name: "unknown",
      device_type: "desktop",
      geo_country: "",
      geo_region: "",
    },
  });
}

document.addEventListener("submit", () => {
  sendAction("form_submit", "allow");
}, true);

document.addEventListener("paste", () => {
  sendAction("paste", "allow");
}, true);

document.addEventListener("copy", () => {
  sendAction("copy", "allow");
}, true);
