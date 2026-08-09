/**
 * AgentHub Gateway SDK — first-party turnkey instrumentation.
 *
 * Wraps OpenAI-compatible /v1/chat/completions and optionally posts
 * spend events to POST /cost/events so Cost + Observability consoles
 * stay populated without a separate auto-instrumentation agent.
 * No runtime dependency on Helicone, Portkey, n8n, or other gateway SaaS.
 */

function randomId(prefix = "req") {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function estimateTokens(text) {
  const value = String(text || "");
  if (!value) return 0;
  return Math.max(1, Math.ceil(value.length / 4));
}

function asPlainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

export class AgentHubGateway {
  /**
   * @param {object} options
   * @param {string} options.baseUrl - Gateway API base, e.g. https://gateway.example.com
   * @param {string} [options.apiKey] - Virtual key / bearer token
   * @param {string} [options.actorRole="AI Ops Approver"]
   * @param {string} [options.actorId="sdk-client"]
   * @param {string} [options.environment="dev"]
   * @param {string} [options.agentId="sdk-agent"]
   * @param {string} [options.scopeType="agent"]
   * @param {string} [options.scopeId] - defaults to agentId
   * @param {boolean} [options.trackCost=true] - POST /cost/events after completions
   * @param {typeof fetch} [options.fetchImpl]
   * @param {string} [options.sessionId] - Gateway-native session header (auto-instrumented)
   * @param {string} [options.user] - Gateway-native user header (auto-instrumented)
   * @param {Record<string, unknown>} [options.properties] - Gateway-native property headers
   */
  constructor(options = {}) {
    if (!options.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = String(options.baseUrl).replace(/\/+$/, "");
    this.apiKey = options.apiKey || "";
    this.actorRole = options.actorRole || "AI Ops Approver";
    this.actorId = options.actorId || "sdk-client";
    this.environment = options.environment || "dev";
    this.agentId = options.agentId || "sdk-agent";
    this.scopeType = options.scopeType || "agent";
    this.scopeId = options.scopeId || this.agentId;
    this.trackCost = options.trackCost !== false;
    this.virtualKeyId = options.virtualKeyId || "";
    this.sessionId = options.sessionId ? String(options.sessionId) : "";
    this.user = options.user ? String(options.user) : "";
    this.properties =
      options.properties && typeof options.properties === "object" && !Array.isArray(options.properties)
        ? options.properties
        : {};
    const baseFetch = options.fetchImpl || globalThis.fetch;
    const wantsInstrument =
      Boolean(this.sessionId || this.user || Object.keys(this.properties).length) && !options.fetchImpl;
    this.fetchImpl = wantsInstrument
      ? createGatewayFetchInstrumenter({
          sessionId: this.sessionId,
          user: this.user,
          properties: this.properties,
          fetchImpl: baseFetch,
        })
      : baseFetch;
    if (typeof this.fetchImpl !== "function") {
      throw new Error("fetch is required (Node 18+ or provide fetchImpl)");
    }
  }

  _headers(extra = {}) {
    const headers = {
      "Content-Type": "application/json",
      "X-Actor-Role": this.actorRole,
      "X-Actor-Id": this.actorId,
      ...extra,
    };
    if (this.apiKey) {
      headers.Authorization = `Bearer ${this.apiKey}`;
    }
    if (this.sessionId) headers["x-session-id"] = this.sessionId;
    if (this.user) headers["x-user"] = this.user;
    for (const [key, value] of Object.entries(this.properties || {})) {
      if (!key) continue;
      headers[`x-property-${String(key).slice(0, 64)}`] = String(value).slice(0, 256);
    }
    return headers;
  }

  /**
   * OpenAI-compatible chat completion with automatic cost instrumentation.
   * @param {object} body - OpenAI chat.completions payload
   * @param {object} [opts]
   * @param {string} [opts.traceId]
   * @param {string} [opts.sessionId]
   * @param {string} [opts.requestTag]
   * @param {object} [opts.userProperties]
   * @param {object} [opts.properties]
   * @param {string} [opts.user]
   * @param {string} [opts.virtualKeyId]
   * @param {string} [opts.promptId]
   * @param {string} [opts.configId]
   * @param {string} [opts.routePolicyId]
   * @param {object} [opts.variables]
   * @param {string} [opts.sessionPath]
   * @param {string} [opts.sessionName]
   * @param {object} [opts.metadata]
   * @param {"inherit"|"bypass"|"force"} [opts.cacheMode]
   */
  /**
   * Classify prompt complexity and select a catalog model (Pack 7 SDK helper).
   * @param {string} promptText
   * @param {object} [opts]
   * @param {"balanced"|"cost"|"quality"} [opts.strategy="balanced"]
   * @param {boolean} [opts.preferLiveOnly=true]
   * @param {boolean} [opts.refineWithJudge=true]
   * @param {boolean} [opts.useTelemetryRanking=true]
   */
  async autoRouteClassify(promptText, opts = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/best-practices/auto-route`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({
        prompt_text: String(promptText || ""),
        strategy: opts.strategy || "balanced",
        prefer_live_only: opts.preferLiveOnly !== false,
        refine_with_judge: opts.refineWithJudge !== false,
        use_telemetry_ranking: opts.useTelemetryRanking !== false,
      }),
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`Gateway auto-route failed (${response.status}): ${detail}`);
    }
    return response.json();
  }

  async chatCompletions(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "gpt-4o-mini");
    const mergedProps = {
      ...asPlainObject(opts.properties),
      ...asPlainObject(body.properties),
      ...asPlainObject(opts.userProperties),
      ...asPlainObject(body.user_properties),
    };
    const requestBody = {
      ...body,
      session_id: body.session_id || sessionId,
    };
    if (opts.autoRoute || body.auto_route === true) {
      requestBody.auto_route = true;
      requestBody.auto_route_strategy = String(opts.autoRouteStrategy || body.auto_route_strategy || "balanced");
      const currentModel = String(requestBody.model || "").trim().toLowerCase();
      if (!currentModel || currentModel === "auto" || currentModel === "gateway/auto") {
        requestBody.model = "auto";
      }
    }
    if (Object.keys(mergedProps).length) {
      requestBody.user_properties = mergedProps;
      requestBody.properties = mergedProps;
    }
    const endUser = String(opts.user || body.user || "").trim();
    if (endUser) requestBody.user = endUser;
    const vk = String(
      opts.virtualKeyId || opts.guardrailId || body.virtual_key_id || body.guardrail_id || this.virtualKeyId || "",
    ).trim();
    if (vk) {
      requestBody.virtual_key_id = vk;
      requestBody.guardrail_id = vk;
    }
    const promptId = String(
      opts.promptId || opts.promptRegistryId || body.prompt_id || body.prompt_registry_id || "",
    ).trim();
    if (promptId) {
      requestBody.prompt_id = promptId;
      requestBody.prompt_registry_id = promptId;
    }
    const configId = String(
      opts.configId || opts.routePolicyId || body.config_id || body.route_policy_id || "",
    ).trim();
    if (configId) {
      requestBody.config_id = configId;
      requestBody.route_policy_id = configId;
    }
    const variables = asPlainObject(opts.variables) || asPlainObject(body.variables);
    if (variables) {
      requestBody.variables = Object.fromEntries(
        Object.entries(variables)
          .slice(0, 64)
          .filter(([key]) => String(key || "").trim())
          .map(([key, value]) => [String(key).slice(0, 64), String(value).slice(0, 4000)]),
      );
    }
    const sessionPath = String(opts.sessionPath || body.session_path || "").trim();
    if (sessionPath) requestBody.session_path = sessionPath.slice(0, 256);
    const sessionName = String(opts.sessionName || body.session_name || "").trim();
    if (sessionName) requestBody.session_name = sessionName.slice(0, 128);
    const metadata = asPlainObject(opts.metadata) || asPlainObject(body.metadata);
    if (metadata) {
      requestBody.metadata = Object.fromEntries(
        Object.entries(metadata)
          .slice(0, 32)
          .filter(([key]) => String(key || "").trim())
          .map(([key, value]) => {
            const safe =
              typeof value === "string" ||
              typeof value === "number" ||
              typeof value === "boolean" ||
              value == null
                ? value
                : String(value).slice(0, 256);
            return [String(key).slice(0, 64), safe];
          }),
      );
    }
    const cacheMode = String(opts.cacheMode || body.cache_mode || "").trim().toLowerCase();
    if (["inherit", "bypass", "force"].includes(cacheMode)) {
      requestBody.cache_mode = cacheMode;
    }

    const headers = this._headers({
      "X-Request-Id": requestId,
      "X-Trace-Id": traceId,
    });
    if (vk) headers["X-Virtual-Key-Id"] = vk;

    const response = await this.fetchImpl(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway chat completion failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }

    const usage = payload?.usage || {};
    const inputTokens =
      Number(usage.prompt_tokens || usage.input_tokens || 0) ||
      estimateTokens((body.messages || []).map((m) => m.content).join("\n"));
    const outputTokens =
      Number(usage.completion_tokens || usage.output_tokens || 0) ||
      estimateTokens(payload?.choices?.[0]?.message?.content || "");

    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "chat.completions",
        inputTokens,
        outputTokens,
      }).catch(() => 0);
      const costProps = { ...mergedProps };
      if (sessionPath) costProps.session_path = sessionPath.slice(0, 256);
      if (sessionName) costProps.session_name = sessionName.slice(0, 128);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "chat.completions",
        inputTokens,
        outputTokens,
        estimatedCostCents,
        userProperties: Object.keys(costProps).length ? costProps : undefined,
        cacheHit: Boolean(payload?.cache_short_circuit),
      }).catch((error) => ({ error: String(error?.message || error) }));
    }

    return {
      ...payload,
      agenthub: {
        requestId,
        traceId,
        sessionId,
        costEvent,
        observabilityUrl: `${this.baseUrl}/observability/traces/${encodeURIComponent(traceId)}`,
      },
    };
  }

  /**
   * OpenAI-compatible Responses API via the gateway.
   * Helicone props use user/properties/session_*; OpenAI metadata is upstream-only.
   *
   * @param {object} body
   * @param {object} [opts]
   * @param {string} [opts.traceId]
   * @param {string} [opts.sessionId]
   * @param {string} [opts.requestTag]
   * @param {string} [opts.user]
   * @param {object} [opts.properties]
   * @param {object} [opts.userProperties]
   * @param {string} [opts.virtualKeyId]
   * @param {string} [opts.promptId]
   * @param {string} [opts.promptRegistryId]
   * @param {string} [opts.configId]
   * @param {string} [opts.routePolicyId]
   * @param {object} [opts.variables]
   * @param {string} [opts.sessionPath]
   * @param {string} [opts.sessionName]
   * @param {object} [opts.metadata]
   * @param {"inherit"|"bypass"|"force"} [opts.cacheMode]
   */
  async responses(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "gpt-4o-mini");
    const mergedProps = {
      ...asPlainObject(opts.properties),
      ...asPlainObject(body.properties),
      ...asPlainObject(opts.userProperties),
      ...asPlainObject(body.user_properties),
    };
    const requestBody = {
      ...body,
      session_id: body.session_id || sessionId,
    };
    if (Object.keys(mergedProps).length) {
      requestBody.user_properties = mergedProps;
      requestBody.properties = mergedProps;
    }
    const endUser = String(opts.user || body.user || "").trim();
    if (endUser) requestBody.user = endUser;
    const vk = String(
      opts.virtualKeyId || opts.guardrailId || body.virtual_key_id || body.guardrail_id || this.virtualKeyId || "",
    ).trim();
    if (vk) {
      requestBody.virtual_key_id = vk;
      requestBody.guardrail_id = vk;
    }
    const promptId = String(
      opts.promptId || opts.promptRegistryId || body.prompt_id || body.prompt_registry_id || "",
    ).trim();
    if (promptId) {
      requestBody.prompt_id = promptId;
      requestBody.prompt_registry_id = promptId;
    }
    const configId = String(
      opts.configId || opts.routePolicyId || body.config_id || body.route_policy_id || "",
    ).trim();
    if (configId) {
      requestBody.config_id = configId;
      requestBody.route_policy_id = configId;
    }
    const variables = asPlainObject(opts.variables) || asPlainObject(body.variables);
    if (variables) {
      requestBody.variables = Object.fromEntries(
        Object.entries(variables)
          .slice(0, 64)
          .filter(([key]) => String(key || "").trim())
          .map(([key, value]) => [String(key).slice(0, 64), String(value).slice(0, 4000)]),
      );
    }
    const sessionPath = String(opts.sessionPath || body.session_path || "").trim();
    if (sessionPath) requestBody.session_path = sessionPath.slice(0, 256);
    const sessionName = String(opts.sessionName || body.session_name || "").trim();
    if (sessionName) requestBody.session_name = sessionName.slice(0, 128);
    const metadata = asPlainObject(opts.metadata) || asPlainObject(body.metadata);
    if (metadata) {
      requestBody.metadata = Object.fromEntries(
        Object.entries(metadata)
          .slice(0, 32)
          .filter(([key]) => String(key || "").trim())
          .map(([key, value]) => {
            const safe =
              typeof value === "string" ||
              typeof value === "number" ||
              typeof value === "boolean" ||
              value == null
                ? value
                : String(value).slice(0, 256);
            return [String(key).slice(0, 64), safe];
          }),
      );
    }
    const cacheMode = String(opts.cacheMode || body.cache_mode || "").trim().toLowerCase();
    if (["inherit", "bypass", "force"].includes(cacheMode)) {
      requestBody.cache_mode = cacheMode;
    }

    const headers = this._headers({
      "X-Request-Id": requestId,
      "X-Trace-Id": traceId,
    });
    if (vk) headers["X-Virtual-Key-Id"] = vk;

    const response = await this.fetchImpl(`${this.baseUrl}/v1/responses`, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway responses failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }

    const usage = payload?.usage || {};
    const inputTokens =
      Number(usage.input_tokens || usage.prompt_tokens || 0) ||
      estimateTokens(String(body.input || ""));
    const outputTokens =
      Number(usage.output_tokens || usage.completion_tokens || 0) ||
      estimateTokens(String(payload?.output_text || ""));

    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "responses",
        inputTokens,
        outputTokens,
      }).catch(() => 0);
      const costProps = { ...mergedProps };
      if (sessionPath) costProps.session_path = sessionPath.slice(0, 256);
      if (sessionName) costProps.session_name = sessionName.slice(0, 128);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "responses",
        inputTokens,
        outputTokens,
        estimatedCostCents,
        userProperties: Object.keys(costProps).length ? costProps : undefined,
        cacheHit: Boolean(payload?.cache_short_circuit),
      }).catch((error) => ({ error: String(error?.message || error) }));
    }

    return {
      ...payload,
      agenthub: {
        requestId,
        traceId,
        sessionId,
        costEvent,
        observabilityUrl: `${this.baseUrl}/observability/traces/${encodeURIComponent(traceId)}`,
      },
    };
  }

  /** OpenAI/Portkey-style responses list (`GET /v1/responses`). */
  async listResponses({ limit = 20, offset = 0, modelContains, outputContains } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (modelContains) params.set("model_contains", String(modelContains).trim());
    if (outputContains) params.set("output_contains", String(outputContains).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/responses?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Responses list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style response get (`GET /v1/responses/{id}`). */
  async getResponse(responseId) {
    const id = String(responseId || "").trim();
    if (!id) throw new Error("responseId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/responses/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Response get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style response delete (`DELETE /v1/responses/{id}`). */
  async deleteResponse(responseId) {
    const id = String(responseId || "").trim();
    if (!id) throw new Error("responseId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/responses/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Response delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /**
   * Post a spend event for Helicone-style cost dashboards.
   */
  async trackSpend({
    requestId,
    traceId,
    sessionId,
    requestTag,
    modelName,
    endpointFamily = "chat.completions",
    inputTokens = 0,
    outputTokens = 0,
    estimatedCostCents = 0,
    userProperties,
    cacheHit = false,
  }) {
    const response = await this.fetchImpl(`${this.baseUrl}/cost/events`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({
        request_id: requestId || randomId("sdk"),
        trace_id: traceId || randomId("trace"),
        request_tag: requestTag || "gateway-sdk",
        session_id: sessionId || randomId("session"),
        agent_id: this.agentId,
        scope_type: this.scopeType,
        scope_id: this.scopeId,
        environment: this.environment,
        model_name: modelName,
        endpoint_family: endpointFamily,
        input_tokens: Math.max(0, Number(inputTokens) || 0),
        output_tokens: Math.max(0, Number(outputTokens) || 0),
        estimated_cost_cents: Math.max(0, Number(estimatedCostCents) || 0),
        currency: "USD",
        cache_hit: Boolean(cacheHit),
        user_properties: userProperties && typeof userProperties === "object" ? userProperties : undefined,
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Cost event failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /**
   * Helicone-style feedback attached to cost events by request_id.
   */
  async submitFeedback({ requestId, rating, scores, comment, traceId } = {}) {
    const body = { request_id: String(requestId || "").trim() };
    if (rating != null) body.rating = Number(rating);
    if (scores && typeof scores === "object") body.scores = scores;
    if (comment != null && String(comment).trim()) body.comment = String(comment).trim().slice(0, 2048);
    if (traceId) body.trace_id = String(traceId).trim();
    const response = await this.fetchImpl(`${this.baseUrl}/v1/feedback`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Feedback submit failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Read previously attached feedback for a request. */
  async getFeedback({ requestId, traceId } = {}) {
    const params = new URLSearchParams({ request_id: String(requestId || "").trim() });
    if (traceId) params.set("trace_id", String(traceId).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/feedback?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Feedback lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style virtual key inventory (`GET /v1/virtual-keys`). */
  async listVirtualKeys({ limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/v1/virtual-keys?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Virtual key list failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.data)) return payload.data;
    return [];
  }

  /** Portkey-style virtual key get (`GET /v1/virtual-keys/{id}`). */
  async getVirtualKey(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/virtual-keys/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Virtual key lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style virtual key usage (`GET /v1/virtual-keys/{id}/usage`). */
  async getVirtualKeyUsage(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/virtual-keys/${encodeURIComponent(id)}/usage`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Virtual key usage failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style virtual key create (`POST /keys`; never returns secret material). */
  async createVirtualKey({
    ownerScopeType,
    ownerScopeId,
    allowedEndpointFamilies = "[]",
    allowedModels = "[]",
    guardrailPolicy = "{}",
    budgetPolicyId = "default",
    rateLimitPolicyId = "default",
    expiresAt,
    authnMethod = "token",
  } = {}) {
    const body = {
      owner_scope_type: String(ownerScopeType || "").trim(),
      owner_scope_id: String(ownerScopeId || "").trim(),
      allowed_endpoint_families: String(allowedEndpointFamilies || "[]"),
      allowed_models: String(allowedModels || "[]"),
      guardrail_policy: String(guardrailPolicy || "{}"),
      budget_policy_id: String(budgetPolicyId || "default").trim() || "default",
      rate_limit_policy_id: String(rateLimitPolicyId || "default").trim() || "default",
      authn_method: String(authnMethod || "token").trim() || "token",
    };
    if (expiresAt != null) body.expires_at = String(expiresAt).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/keys`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key update (`PATCH /keys/{id}`; never returns secret material). */
  async updateVirtualKey(
    keyId,
    {
      allowedEndpointFamilies,
      allowedModels,
      guardrailPolicy,
      status,
      budgetPolicyId,
      rateLimitPolicyId,
      expiresAt,
      authnMethod,
    } = {},
  ) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const body = {};
    if (allowedEndpointFamilies != null) body.allowed_endpoint_families = String(allowedEndpointFamilies);
    if (allowedModels != null) body.allowed_models = String(allowedModels);
    if (guardrailPolicy != null) body.guardrail_policy = String(guardrailPolicy);
    if (status != null) body.status = String(status).trim();
    if (budgetPolicyId != null) body.budget_policy_id = String(budgetPolicyId).trim() || "default";
    if (rateLimitPolicyId != null) body.rate_limit_policy_id = String(rateLimitPolicyId).trim() || "default";
    if (expiresAt != null) body.expires_at = String(expiresAt).trim() || null;
    if (authnMethod != null) body.authn_method = String(authnMethod).trim() || "token";
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key guardrail evaluate (`POST /keys/{id}/guardrails/evaluate`). */
  async evaluateKeyGuardrails(
    keyId,
    {
      environment = "dev",
      stage = "input",
      policyMode = "block",
      requestsLastMinute = 0,
      inputTokens = 0,
      outputTokens = 0,
      ownerScopeId,
      mfaVerified = false,
    } = {},
  ) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const body = {
      environment: String(environment || "dev").trim() || "dev",
      stage: String(stage || "input").trim() || "input",
      policy_mode: String(policyMode || "block").trim() || "block",
      requests_last_minute: Math.max(0, Number(requestsLastMinute) || 0),
      input_tokens: Math.max(0, Number(inputTokens) || 0),
      output_tokens: Math.max(0, Number(outputTokens) || 0),
      mfa_verified: Boolean(mfaVerified),
    };
    if (ownerScopeId != null) body.owner_scope_id = String(ownerScopeId).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}/guardrails/evaluate`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key guardrail evaluate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key rotation schedule create (`POST /keys/{id}/rotation-schedules`). */
  async createKeyRotationSchedule(
    keyId,
    { environment = "dev", intervalHours = 24, enabled = true, reason = "scheduled-rotation" } = {},
  ) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const body = {
      environment: String(environment || "dev").trim() || "dev",
      interval_hours: Math.max(1, Math.min(Number(intervalHours) || 24, 720)),
      enabled: Boolean(enabled),
      reason: String(reason || "scheduled-rotation").trim() || "scheduled-rotation",
    };
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}/rotation-schedules`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key rotation schedule create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key rotation schedule list (`GET /keys/{id}/rotation-schedules`). */
  async listKeyRotationSchedules(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}/rotation-schedules`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key rotation schedule list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style virtual key rotation schedule update (`PATCH /keys/{id}/rotation-schedules/{scheduleId}`). */
  async updateKeyRotationSchedule(keyId, scheduleId, { intervalHours, enabled, reason } = {}) {
    const id = String(keyId || "").trim();
    const sid = String(scheduleId || "").trim();
    if (!id) throw new Error("keyId is required");
    if (!sid) throw new Error("scheduleId is required");
    const body = {};
    if (intervalHours != null) body.interval_hours = Math.max(1, Math.min(Number(intervalHours) || 24, 720));
    if (enabled != null) body.enabled = Boolean(enabled);
    if (reason != null) body.reason = String(reason).trim() || "scheduled-rotation";
    const response = await this.fetchImpl(
      `${this.baseUrl}/keys/${encodeURIComponent(id)}/rotation-schedules/${encodeURIComponent(sid)}`,
      {
        method: "PATCH",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key rotation schedule update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key rotation execute-now (`POST .../execute-now`). */
  async executeKeyRotationScheduleNow(keyId, scheduleId) {
    const id = String(keyId || "").trim();
    const sid = String(scheduleId || "").trim();
    if (!id) throw new Error("keyId is required");
    if (!sid) throw new Error("scheduleId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/keys/${encodeURIComponent(id)}/rotation-schedules/${encodeURIComponent(sid)}/execute-now`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify({}),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key rotation schedule execute failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Advance due virtual-key rotation schedules (`POST /keys/rotation-schedules/tick`). */
  async tickKeyRotationSchedules({ includeProd = false } = {}) {
    const query = new URLSearchParams({ include_prod: includeProd ? "true" : "false" });
    const response = await this.fetchImpl(`${this.baseUrl}/keys/rotation-schedules/tick?${query}`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key rotation schedule tick failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key block (`POST /keys/{id}/block`). */
  async blockVirtualKey(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}/block`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key block failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key unblock (`POST /keys/{id}/unblock`). */
  async unblockVirtualKey(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/keys/${encodeURIComponent(id)}/unblock`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key unblock failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style virtual key rotate (`POST /keys/{id}/rotate`). */
  async rotateVirtualKey(keyId, { environment = "dev" } = {}) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const params = new URLSearchParams({
      environment: String(environment || "dev").trim() || "dev",
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/keys/${encodeURIComponent(id)}/rotate?${params.toString()}`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify({}),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Virtual key rotate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style temporary key budget increase (`POST /keys/{id}/budget/increase-temporary`). */
  async increaseKeyBudgetTemporary(
    keyId,
    { increaseCents, environment = "dev", durationMinutes = 60, reason = "operator-request" } = {},
  ) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const body = {
      environment: String(environment || "dev").trim() || "dev",
      increase_cents: Math.max(1, Number(increaseCents) || 0),
      duration_minutes: Math.max(1, Math.min(Number(durationMinutes) || 60, 10080)),
      reason: String(reason || "operator-request").trim() || "operator-request",
    };
    const response = await this.fetchImpl(
      `${this.baseUrl}/keys/${encodeURIComponent(id)}/budget/increase-temporary`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key budget temporary increase failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style temporary key budget increase get (`GET /keys/{id}/budget/increase-temporary`). */
  async getKeyBudgetIncreaseTemporary(keyId) {
    const id = String(keyId || "").trim();
    if (!id) throw new Error("keyId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/keys/${encodeURIComponent(id)}/budget/increase-temporary`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Key budget temporary increase get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style analytics summary (`GET /v1/analytics`). */
  async getAnalytics({ hours = 24, environment } = {}) {
    const params = new URLSearchParams({
      hours: String(Math.max(1, Math.min(Number(hours) || 24, 168))),
    });
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/analytics?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Analytics failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style guardrail inventory (`GET /v1/guardrails`). */
  async listGuardrails({ limit = 50, offset = 0, hasPolicy } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (hasPolicy === true) params.set("has_policy", "true");
    if (hasPolicy === false) params.set("has_policy", "false");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/guardrails?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Guardrail list failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.data)) return payload.data;
    return [];
  }

  /** Portkey-style guardrail get (`GET /v1/guardrails/{id}`). */
  async getGuardrail(guardrailId) {
    const id = String(guardrailId || "").trim();
    if (!id) throw new Error("guardrailId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/guardrails/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Guardrail lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style route/config inventory (`GET /v1/configs`). */
  async listConfigs({ limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/v1/configs?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Config list failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.data)) return payload.data;
    return [];
  }

  /** Portkey-style route/config get (`GET /v1/configs/{id}`). */
  async getConfig(configId) {
    const id = String(configId || "").trim();
    if (!id) throw new Error("configId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/configs/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Config lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey/OpenAI-style model catalog (`GET /v1/models`). */
  async listModels({ limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/v1/models?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Model list failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.items)) return payload.items;
    return [];
  }

  /** Portkey/OpenAI-style model get (`GET /v1/models/{id}`). */
  async getModel(modelId) {
    const id = String(modelId || "").trim();
    if (!id) throw new Error("modelId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/models/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Model lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style prompt registry list (`GET /v1/prompts`). */
  async listPrompts({ limit = 50, offset = 0, q } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const search = String(q || "").trim();
    if (search) params.set("q", search.slice(0, 128));
    const response = await this.fetchImpl(`${this.baseUrl}/v1/prompts?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Prompt list failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.data)) return payload.data;
    return [];
  }

  /** Portkey-style prompt registry get (`GET /v1/prompts/{id}`). */
  async getPrompt(promptId) {
    const id = String(promptId || "").trim();
    if (!id) throw new Error("promptId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/prompts/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Prompt lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style prompt version history (`GET /v1/prompts/{id}/versions`). */
  async listPromptVersions(promptId) {
    const id = String(promptId || "").trim();
    if (!id) throw new Error("promptId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/prompts/${encodeURIComponent(id)}/versions`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Prompt versions failed (${response.status}): ${detail}`);
    }
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.data)) return payload.data;
    return [];
  }

  /** Portkey-style prompt version get (`GET /v1/prompts/{id}/versions/{version}`). */
  async getPromptVersion(promptId, version) {
    const id = String(promptId || "").trim();
    if (!id) throw new Error("promptId is required");
    const versionNumber = Number(version);
    if (!Number.isInteger(versionNumber) || versionNumber < 1) {
      throw new Error("version must be an integer >= 1");
    }
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/prompts/${encodeURIComponent(id)}/versions/${versionNumber}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Prompt version lookup failed (${response.status}): ${detail}`);
    }
    return payload;
  }

  /** Portkey-style prompt render/preview (`POST /v1/prompts/{id}/render`). */
  async renderPrompt(promptId, { variables = {}, version, requireAllVariables = true } = {}) {
    const id = String(promptId || "").trim();
    if (!id) throw new Error("promptId is required");
    const body = {
      variables: variables && typeof variables === "object" ? variables : {},
      require_all_variables: Boolean(requireAllVariables),
    };
    if (version != null) body.version = Number(version);
    const response = await this.fetchImpl(`${this.baseUrl}/v1/prompts/${encodeURIComponent(id)}/render`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Prompt render failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** Portkey-style prompt promote (`POST /v1/prompts/{id}/promote`). */
  async promotePrompt(
    promptId,
    {
      targetEnvironment = "dev",
      reason = "promote",
      approvalTicket,
      requireRenderValidation = true,
      renderVariables = {},
      previewOnly = false,
    } = {},
  ) {
    const id = String(promptId || "").trim();
    if (!id) throw new Error("promptId is required");
    const body = {
      target_environment: String(targetEnvironment || "dev").trim() || "dev",
      reason: String(reason || "promote").trim() || "promote",
      require_render_validation: Boolean(requireRenderValidation),
      render_variables: renderVariables && typeof renderVariables === "object" ? renderVariables : {},
      preview_only: Boolean(previewOnly),
    };
    const ticket = String(approvalTicket || "").trim();
    if (ticket) body.approval_ticket = ticket;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/prompts/${encodeURIComponent(id)}/promote`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Prompt promote failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style request logs (`GET /v1/logs`; metadata-only). */
  async listLogs({
    windowHours = 24,
    userId,
    model,
    propertyKey,
    propertyValue,
    cacheHit,
    hasFeedback,
    limit = 50,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    if (userId) params.set("user_id", String(userId).trim());
    if (model) params.set("model", String(model).trim());
    if (propertyKey) params.set("property_key", String(propertyKey).trim());
    if (propertyValue) params.set("property_value", String(propertyValue).trim());
    if (cacheHit === true || cacheHit === false) params.set("cache_hit", cacheHit ? "true" : "false");
    if (hasFeedback === true || hasFeedback === false) {
      params.set("has_feedback", hasFeedback ? "true" : "false");
    }
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Logs list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** Portkey-style single request log (`GET /v1/logs/{request_id}`). */
  async getLog(requestId) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Log get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** Portkey-style log export job create (`POST /v1/logs/exports`). */
  async createLogExport({ filters = {}, requestedData = [], description, workspaceId } = {}) {
    const body = {
      filters: filters && typeof filters === "object" ? filters : {},
      requested_data: Array.isArray(requestedData) ? requestedData : [],
    };
    if (description != null) body.description = String(description);
    if (workspaceId != null) body.workspace_id = String(workspaceId);
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style log export job list (`GET /v1/logs/exports`). */
  async listLogExports({ limit = 20, offset = 0, status } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log exports list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style log export job get (`GET /v1/logs/exports/{id}`). */
  async getLogExport(exportId) {
    const id = String(exportId || "").trim();
    if (!id) throw new Error("exportId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style log export start (`POST /v1/logs/exports/{id}/start`). */
  async startLogExport(exportId) {
    const id = String(exportId || "").trim();
    if (!id) throw new Error("exportId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports/${encodeURIComponent(id)}/start`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export start failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style log export download (`GET /v1/logs/exports/{id}/download`). */
  async downloadLogExport(exportId) {
    const id = String(exportId || "").trim();
    if (!id) throw new Error("exportId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/logs/exports/${encodeURIComponent(id)}/download`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export download failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style log export cancel (`POST /v1/logs/exports/{id}/cancel`). */
  async cancelLogExport(exportId) {
    const id = String(exportId || "").trim();
    if (!id) throw new Error("exportId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export cancel failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style log export delete (`DELETE /v1/logs/exports/{id}`). */
  async deleteLogExport(exportId) {
    const id = String(exportId || "").trim();
    if (!id) throw new Error("exportId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/exports/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Log export delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style file create (`POST /v1/files`; registry metadata only). */
  async createFile({
    filename,
    purpose = "assistants",
    bytes,
    contentType = "application/octet-stream",
    metadata,
    environment = "dev",
  } = {}) {
    const body = {
      filename: String(filename || "").trim(),
      purpose: String(purpose || "assistants").trim() || "assistants",
      bytes: Number(bytes),
      content_type: String(contentType || "application/octet-stream").trim() || "application/octet-stream",
      environment: String(environment || "dev").trim() || "dev",
    };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/files`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`File create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** OpenAI/Portkey-style file list (`GET /v1/files`). */
  async listFiles({ limit = 20, offset = 0, purpose, status, filenameContains } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (purpose) params.set("purpose", String(purpose).trim());
    if (status) params.set("status", String(status).trim());
    if (filenameContains) params.set("filename_contains", String(filenameContains).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/files?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Files list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style file get (`GET /v1/files/{id}`). */
  async getFile(fileId) {
    const id = String(fileId || "").trim();
    if (!id) throw new Error("fileId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/files/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`File get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** OpenAI/Portkey-style file content (`GET /v1/files/{id}/content`; metadata-only). */
  async getFileContent(fileId) {
    const id = String(fileId || "").trim();
    if (!id) throw new Error("fileId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/files/${encodeURIComponent(id)}/content`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `File content failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style file delete (`DELETE /v1/files/{id}`). */
  async deleteFile(fileId) {
    const id = String(fileId || "").trim();
    if (!id) throw new Error("fileId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/files/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `File delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style assistant create (`POST /v1/assistants`). */
  async createAssistant({ name, model, instructions = "", metadata, environment = "dev" } = {}) {
    const body = {
      name: String(name || "").trim(),
      model: String(model || "").trim(),
      instructions: String(instructions || ""),
      environment: String(environment || "dev").trim() || "dev",
    };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/assistants`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Assistant create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style assistant list (`GET /v1/assistants`). */
  async listAssistants({ limit = 20, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/v1/assistants?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Assistants list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style assistant get (`GET /v1/assistants/{id}`). */
  async getAssistant(assistantId) {
    const id = String(assistantId || "").trim();
    if (!id) throw new Error("assistantId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/assistants/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Assistant get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style assistant delete (`DELETE /v1/assistants/{id}`). */
  async deleteAssistant(assistantId) {
    const id = String(assistantId || "").trim();
    if (!id) throw new Error("assistantId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/assistants/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Assistant delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style thread create (`POST /v1/threads`). */
  async createThread({ metadata, environment = "dev" } = {}) {
    const body = { environment: String(environment || "dev").trim() || "dev" };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/threads`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style thread get (`GET /v1/threads/{id}`). */
  async getThread(threadId) {
    const id = String(threadId || "").trim();
    if (!id) throw new Error("threadId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/threads/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style thread message create (`POST /v1/threads/{id}/messages`). */
  async createThreadMessage(threadId, { content, role = "user", metadata } = {}) {
    const id = String(threadId || "").trim();
    if (!id) throw new Error("threadId is required");
    const body = { role: String(role || "user").trim() || "user", content: String(content || "") };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/threads/${encodeURIComponent(id)}/messages`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread message create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style thread message list (`GET /v1/threads/{id}/messages`). */
  async listThreadMessages(threadId, { limit = 20, offset = 0 } = {}) {
    const id = String(threadId || "").trim();
    if (!id) throw new Error("threadId is required");
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/threads/${encodeURIComponent(id)}/messages?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread messages list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style thread run create (`POST /v1/threads/{id}/runs`). */
  async createThreadRun(
    threadId,
    { assistantId, model, additionalInstructions = "", environment = "dev", stream = false } = {},
  ) {
    const id = String(threadId || "").trim();
    const aid = String(assistantId || "").trim();
    if (!id) throw new Error("threadId is required");
    if (!aid) throw new Error("assistantId is required");
    const body = {
      assistant_id: aid,
      additional_instructions: String(additionalInstructions || ""),
      environment: String(environment || "dev").trim() || "dev",
      stream: Boolean(stream),
    };
    if (model != null) body.model = String(model);
    const response = await this.fetchImpl(`${this.baseUrl}/v1/threads/${encodeURIComponent(id)}/runs`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread run create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style thread run get (`GET /v1/threads/{id}/runs/{runId}`). */
  async getThreadRun(threadId, runId) {
    const tid = String(threadId || "").trim();
    const rid = String(runId || "").trim();
    if (!tid) throw new Error("threadId is required");
    if (!rid) throw new Error("runId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/threads/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Thread run get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style fine-tuning job create (`POST /v1/fine_tuning/jobs`). */
  async createFineTuningJob({ model, trainingFileId, metadata, environment = "dev" } = {}) {
    const body = {
      model: String(model || "").trim(),
      training_file_id: String(trainingFileId || "").trim(),
      environment: String(environment || "dev").trim() || "dev",
    };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/fine_tuning/jobs`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Fine-tuning job create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style fine-tuning job list (`GET /v1/fine_tuning/jobs`). */
  async listFineTuningJobs({ limit = 20, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/v1/fine_tuning/jobs?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Fine-tuning jobs list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style fine-tuning job get (`GET /v1/fine_tuning/jobs/{id}`). */
  async getFineTuningJob(jobId) {
    const id = String(jobId || "").trim();
    if (!id) throw new Error("jobId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/fine_tuning/jobs/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Fine-tuning job get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style fine-tuning job cancel (`POST /v1/fine_tuning/jobs/{id}/cancel`). */
  async cancelFineTuningJob(jobId) {
    const id = String(jobId || "").trim();
    if (!id) throw new Error("jobId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/fine_tuning/jobs/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Fine-tuning job cancel failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch create (`POST /v1/batches`). */
  async createBatch({ requests = [], endpointFamily = "responses", metadata, environment = "dev" } = {}) {
    const body = {
      endpoint_family: String(endpointFamily || "responses").trim() || "responses",
      requests: Array.isArray(requests) ? requests : [],
      environment: String(environment || "dev").trim() || "dev",
    };
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Batch create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch list (`GET /v1/batches`). */
  async listBatches({ limit = 20, offset = 0, status } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Batches list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style batch get (`GET /v1/batches/{id}`). */
  async getBatch(batchId) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Batch get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`);
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch results (`GET /v1/batches/{id}/results`; metadata-only). */
  async getBatchResults(batchId) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}/results`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Batch results failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch cancel (`POST /v1/batches/{id}/cancel`). */
  async cancelBatch(batchId) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Batch cancel failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch complete (`POST /v1/batches/{id}/complete`). */
  async completeBatch(batchId, { completedCount, failedCount, status = "completed" } = {}) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const body = { status: String(status || "completed").trim() || "completed" };
    if (completedCount != null) body.completed_count = Number(completedCount);
    if (failedCount != null) body.failed_count = Number(failedCount);
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}/complete`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Batch complete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch expire (`POST /v1/batches/{id}/expire`). */
  async expireBatch(batchId) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}/expire`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Batch expire failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style batch delete (`DELETE /v1/batches/{id}`). */
  async deleteBatch(batchId) {
    const id = String(batchId || "").trim();
    if (!id) throw new Error("batchId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/batches/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Batch delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style logs CSV export (`GET /v1/logs/export`; metadata-only). */
  async exportLogs({
    windowHours = 24,
    userId,
    model,
    propertyKey,
    propertyValue,
    cacheHit,
    hasFeedback,
    limit = 1000,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      limit: String(Math.max(1, Math.min(Number(limit) || 1000, 5000))),
    });
    if (userId) params.set("user_id", String(userId).trim());
    if (model) params.set("model", String(model).trim());
    if (propertyKey) params.set("property_key", String(propertyKey).trim());
    if (propertyValue) params.set("property_value", String(propertyValue).trim());
    if (cacheHit === true || cacheHit === false) params.set("cache_hit", cacheHit ? "true" : "false");
    if (hasFeedback === true || hasFeedback === false) {
      params.set("has_feedback", hasFeedback ? "true" : "false");
    }
    const response = await this.fetchImpl(`${this.baseUrl}/v1/logs/export?${params.toString()}`, {
      headers: this._headers(),
    });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`Logs export failed (${response.status}): ${text.slice(0, 500)}`);
    }
    return text;
  }





  /** Portkey-style observability log schema status (`GET /observability/logs/schema-status`). */
  async getObservabilityLogSchemaStatus({ sampleSize } = {}) {
    const params = new URLSearchParams();
    if (sampleSize != null) {
      params.set("sample_size", String(Math.max(1, Math.min(Number(sampleSize) || 200, 1000))));
    }
    const suffix = params.toString() ? `?${params.toString()}` : "";
    const response = await this.fetchImpl(`${this.baseUrl}/observability/logs/schema-status${suffix}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Observability log schema status failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style SIEM alert rule catalog (`GET /observability/siem-rules`). */
  async listSiemRules() {
    const response = await this.fetchImpl(`${this.baseUrl}/observability/siem-rules`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `SIEM rules list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style SIEM alert rule export (`POST /observability/siem-rules/export`). */
  async exportSiemRules() {
    const response = await this.fetchImpl(`${this.baseUrl}/observability/siem-rules/export`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `SIEM rules export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style SIEM rule evaluation (`GET /observability/siem-rules/evaluate`). */
  async evaluateSiemRules({
    limit = 100,
    sinceHours = 24,
    actionTypePrefix,
    decisionOutcome,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      since_hours: String(Math.max(1, Math.min(Number(sinceHours) || 24, 720))),
    });
    if (actionTypePrefix) params.set("action_type_prefix", String(actionTypePrefix).trim());
    if (decisionOutcome) params.set("decision_outcome", String(decisionOutcome).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/siem-rules/evaluate?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `SIEM rules evaluate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style observability log list (`GET /observability/logs`). */
  async listObservabilityLogs({
    sinceHours = 24,
    limit = 50,
    offset = 0,
    traceId,
    actionType,
    resourceType,
    resourceId,
    actorId,
    decisionOutcome,
    search,
    redactSensitive = false,
  } = {}) {
    const params = new URLSearchParams({
      since_hours: String(Math.max(1, Math.min(Number(sinceHours) || 24, 720))),
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
      redact_sensitive: redactSensitive ? "true" : "false",
    });
    if (traceId) params.set("trace_id", String(traceId).trim());
    if (actionType) params.set("action_type", String(actionType).trim());
    if (resourceType) params.set("resource_type", String(resourceType).trim());
    if (resourceId) params.set("resource_id", String(resourceId).trim());
    if (actorId) params.set("actor_id", String(actorId).trim());
    if (decisionOutcome) params.set("decision_outcome", String(decisionOutcome).trim());
    if (search) params.set("search", String(search).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/logs?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Observability logs list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload;
    if (payload && typeof payload === "object") {
      const items = payload.items || payload.data || payload.logs || [];
      return Array.isArray(items) ? items : [];
    }
    return [];
  }

  /** Portkey-style observability log export (`GET /observability/logs/export`). */
  async exportObservabilityLogs({
    format = "csv",
    sinceHours = 24,
    limit = 500,
    offset = 0,
    traceId,
    actionType,
    resourceType,
    resourceId,
    actorId,
    decisionOutcome,
    search,
    redactSensitive = false,
  } = {}) {
    const normalizedFormat = String(format || "csv").trim().toLowerCase() || "csv";
    if (!["csv", "json"].includes(normalizedFormat)) {
      throw new Error("format must be csv or json");
    }
    const params = new URLSearchParams({
      format: normalizedFormat,
      since_hours: String(Math.max(1, Math.min(Number(sinceHours) || 24, 720))),
      limit: String(Math.max(1, Math.min(Number(limit) || 500, 2000))),
      offset: String(Math.max(0, Number(offset) || 0)),
      redact_sensitive: redactSensitive ? "true" : "false",
    });
    if (traceId) params.set("trace_id", String(traceId).trim());
    if (actionType) params.set("action_type", String(actionType).trim());
    if (resourceType) params.set("resource_type", String(resourceType).trim());
    if (resourceId) params.set("resource_id", String(resourceId).trim());
    if (actorId) params.set("actor_id", String(actorId).trim());
    if (decisionOutcome) params.set("decision_outcome", String(decisionOutcome).trim());
    if (search) params.set("search", String(search).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/logs/export?${params.toString()}`,
      { headers: this._headers() },
    );
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      let detail = text || response.statusText;
      try {
        const payload = JSON.parse(text || "{}");
        detail = payload?.detail || payload?.message || detail;
      } catch {
        /* keep text */
      }
      throw new Error(
        `Observability logs export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return text;
  }

  /** Portkey/Helicone-style observability summary (`GET /observability/summary`). */
  async getObservabilitySummary({ sinceHours = 24 } = {}) {
    const params = new URLSearchParams({
      since_hours: String(Math.max(1, Math.min(Number(sinceHours) || 24, 168))),
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/summary?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Observability summary failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style trace event timeline (`GET /observability/traces/{id}/events`). */
  async getTraceEvents(traceId) {
    const id = String(traceId || "").trim();
    if (!id) throw new Error("traceId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/traces/${encodeURIComponent(id)}/events`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Trace events failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Fetch observability trace for a prior SDK call. */
  async getTrace(traceId) {
    const response = await this.fetchImpl(
      `${this.baseUrl}/observability/traces/${encodeURIComponent(traceId)}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(`Trace lookup failed (${response.status})`);
    }
    return payload;
  }

  /** OpenAI-compatible embeddings with optional cost instrumentation. */
  async embeddings(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "text-embedding-3-small");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/embeddings`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway embeddings failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const usage = payload?.usage || {};
    const inputTokens =
      Number(usage.prompt_tokens || usage.total_tokens || 0) ||
      estimateTokens(Array.isArray(body.input) ? body.input.join("\n") : body.input);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "embeddings",
        inputTokens,
        outputTokens: 0,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "embeddings",
        inputTokens,
        outputTokens: 0,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** OpenAI/Portkey-style image generation with optional cost instrumentation. */
  async images(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "gpt-image-1");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/images`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway images failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const inputTokens = estimateTokens(body.prompt);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "images",
        inputTokens,
        outputTokens: 0,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "images",
        inputTokens,
        outputTokens: 0,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** OpenAI/Portkey-style audio transcription with optional cost instrumentation. */
  async audioTranscriptions(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "whisper-1");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/audio/transcriptions`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway audio transcriptions failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const inputTokens = estimateTokens(body.input_text || body.prompt);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "audio.transcriptions",
        inputTokens,
        outputTokens: 0,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "audio.transcriptions",
        inputTokens,
        outputTokens: 0,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** OpenAI/Portkey-style audio translation with optional cost instrumentation. */
  async audioTranslations(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "whisper-1");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/audio/translations`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway audio translations failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const inputTokens = estimateTokens(body.input_text || body.prompt);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "audio.translations",
        inputTokens,
        outputTokens: 0,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "audio.translations",
        inputTokens,
        outputTokens: 0,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** OpenAI/Portkey-style rerank with optional cost instrumentation. */
  async rerank(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "rerank-english-v3.0");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/rerank`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway rerank failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const usage = payload?.usage || {};
    const docs = Array.isArray(body.documents) ? body.documents.join("\n") : String(body.documents || "");
    const inputTokens =
      Number(usage.prompt_tokens || usage.total_tokens || 0) || estimateTokens(`${body.query || ""}\n${docs}`);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "rerank",
        inputTokens,
        outputTokens: 0,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "rerank",
        inputTokens,
        outputTokens: 0,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** OpenAI/Portkey-style messages with optional cost instrumentation. */
  async messages(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || randomId("session");
    const model = String(body.model || "gpt-4o-mini");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway messages failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const inputTokens = estimateTokens(body.input);
    const outputTokens = estimateTokens(payload?.content);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "messages",
        inputTokens,
        outputTokens,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "messages",
        inputTokens,
        outputTokens,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** Agent-to-agent messages (`POST /v1/a2a/messages`) with optional cost instrumentation. */
  async a2aMessages(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const sessionId = opts.sessionId || String(body.session_id || "").trim() || randomId("session");
    const model = String(body.model || "gpt-4o-mini");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/a2a/messages`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      const err = new Error(`Gateway a2a messages failed (${response.status}): ${detail}`);
      err.status = response.status;
      err.payload = payload;
      err.traceId = traceId;
      throw err;
    }
    const inputTokens = estimateTokens(body.message);
    const outputTokens = estimateTokens(payload?.content || payload?.message);
    let costEvent = null;
    if (this.trackCost) {
      const estimatedCostCents = await this.estimateCostCents({
        modelName: model,
        endpointFamily: "a2a",
        inputTokens,
        outputTokens,
      }).catch(() => 0);
      costEvent = await this.trackSpend({
        requestId,
        traceId,
        sessionId,
        requestTag: opts.requestTag,
        modelName: model,
        endpointFamily: "a2a",
        inputTokens,
        outputTokens,
        estimatedCostCents,
      }).catch((error) => ({ error: String(error?.message || error) }));
    }
    return {
      ...payload,
      agenthub: { requestId, traceId, sessionId, costEvent },
    };
  }

  /** Portkey-style provider passthrough (`POST /v1/passthrough`). */
  async passthrough({ providerId, path, method = "POST", headers, body, environment = "dev" } = {}) {
    const pid = String(providerId || "").trim();
    const pth = String(path || "").trim();
    if (!pid) throw new Error("providerId is required");
    if (!pth) throw new Error("path is required");
    const payloadBody = {
      provider_id: pid,
      path: pth,
      method: String(method || "POST").trim().toUpperCase() || "POST",
      environment: String(environment || "dev").trim() || "dev",
    };
    if (headers && typeof headers === "object") payloadBody.headers = headers;
    if (body && typeof body === "object") payloadBody.body = body;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/passthrough`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(payloadBody),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Passthrough failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style realtime session create (`POST /v1/realtime`). */
  async createRealtimeSession(body = {}, opts = {}) {
    const requestId = randomId("sdk");
    const traceId = opts.traceId || randomId("trace");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime`, {
      method: "POST",
      headers: this._headers({
        "X-Request-Id": requestId,
        "X-Trace-Id": traceId,
      }),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Realtime session create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return {
      ...payload,
      agenthub: { ...(payload?.agenthub || {}), requestId, traceId },
    };
  }

  /** OpenAI/Portkey-style realtime session list (`GET /v1/realtime/sessions`). */
  async listRealtimeSessions({ limit = 20, offset = 0, status } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 20, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime/sessions?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Realtime sessions list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style realtime session get (`GET /v1/realtime/sessions/{id}`). */
  async getRealtimeSession(sessionId) {
    const id = String(sessionId || "").trim();
    if (!id) throw new Error("sessionId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime/sessions/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Realtime session get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style realtime event create (`POST /v1/realtime/sessions/{id}/events`). */
  async createRealtimeSessionEvent(
    sessionId,
    { eventType, payload, binaryMode = "metadata_only", eventBytes = 0 } = {},
  ) {
    const id = String(sessionId || "").trim();
    if (!id) throw new Error("sessionId is required");
    const body = {
      event_type: String(eventType || "").trim(),
      binary_mode: String(binaryMode || "metadata_only").trim() || "metadata_only",
      event_bytes: Math.max(0, Number(eventBytes) || 0),
    };
    if (payload && typeof payload === "object") body.payload = payload;
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime/sessions/${encodeURIComponent(id)}/events`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = result?.detail || result?.message || response.statusText;
      throw new Error(
        `Realtime event create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return result;
  }

  /** OpenAI/Portkey-style realtime event list (`GET /v1/realtime/sessions/{id}/events`). */
  async listRealtimeSessionEvents(sessionId) {
    const id = String(sessionId || "").trim();
    if (!id) throw new Error("sessionId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime/sessions/${encodeURIComponent(id)}/events`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Realtime events list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style realtime session close (`POST /v1/realtime/sessions/{id}/close`). */
  async closeRealtimeSession(sessionId) {
    const id = String(sessionId || "").trim();
    if (!id) throw new Error("sessionId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/realtime/sessions/${encodeURIComponent(id)}/close`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Realtime session close failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** OpenAI/Portkey-style vector store list (`GET /v1/vector_stores`). */
  async listVectorStores() {
    const response = await this.fetchImpl(`${this.baseUrl}/v1/vector_stores`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Vector stores list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** OpenAI/Portkey-style vector store get (`GET /v1/vector_stores/{id}`). */
  async getVectorStore(storeId) {
    const id = String(storeId || "").trim();
    if (!id) throw new Error("storeId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/v1/vector_stores/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Vector store get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style RAG ingest (`POST /rag/ingest`). */
  async ragIngest({ storeId, documents, metadata } = {}) {
    const id = String(storeId || "").trim();
    if (!id) throw new Error("storeId is required");
    if (!Array.isArray(documents) || !documents.length) throw new Error("documents is required");
    const body = {
      store_id: id,
      documents: documents.filter((doc) => doc && typeof doc === "object"),
    };
    if (!body.documents.length) throw new Error("documents must contain at least one object");
    if (metadata && typeof metadata === "object") body.metadata = metadata;
    const response = await this.fetchImpl(`${this.baseUrl}/rag/ingest`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `RAG ingest failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style RAG query (`POST /rag/query`). */
  async ragQuery({ storeId, query, topK } = {}) {
    const id = String(storeId || "").trim();
    const q = String(query || "").trim();
    if (!id) throw new Error("storeId is required");
    if (!q) throw new Error("query is required");
    const body = { store_id: id, query: q };
    if (topK != null) body.top_k = Math.max(1, Math.min(Number(topK) || 1, 100));
    const response = await this.fetchImpl(`${this.baseUrl}/rag/query`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `RAG query failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style memory create (`POST /gateway/memory/records`). */
  async createMemoryRecord({
    memoryTier,
    scopeType,
    scopeId,
    content,
    label = "",
    metadataJson,
    environment = "dev",
  } = {}) {
    const body = {
      memory_tier: String(memoryTier || "").trim(),
      scope_type: String(scopeType || "").trim(),
      scope_id: String(scopeId || "").trim(),
      content: String(content || ""),
      label: String(label || "").slice(0, 256),
      environment: String(environment || "dev").trim() || "dev",
    };
    if (metadataJson != null) body.metadata_json = String(metadataJson);
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/records`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style memory list (`GET /gateway/memory/records`). */
  async listMemoryRecords({ memoryTier, scopeType, scopeId, limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (memoryTier) params.set("memory_tier", String(memoryTier).trim());
    if (scopeType) params.set("scope_type", String(scopeType).trim());
    if (scopeId) params.set("scope_id", String(scopeId).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/records?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style memory get (`GET /gateway/memory/records/{id}`). */
  async getMemoryRecord(memoryId) {
    const id = String(memoryId || "").trim();
    if (!id) throw new Error("memoryId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/records/${encodeURIComponent(id)}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style memory delete (`DELETE /gateway/memory/records/{id}`). */
  async deleteMemoryRecord(memoryId) {
    const id = String(memoryId || "").trim();
    if (!id) throw new Error("memoryId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/records/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style memory overview (`GET /gateway/memory/overview`). */
  async getMemoryOverview() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/overview`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory overview failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style memory platform config (`GET /gateway/memory/config`). */
  async getMemoryConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/memory/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Memory config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style MCP server registry (`GET /gateway/mcp/servers`). */
  async listMcpServers() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/mcp/servers`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `MCP servers list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style endpoint family compatibility (`GET /gateway/endpoints/compatibility`). */
  async getEndpointsCompatibility() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/endpoints/compatibility`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Endpoints compatibility failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style notification channel registry (`GET /gateway/notification-channels`). */
  async listNotificationChannels() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/notification-channels`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Notification channels list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style gateway vector store registry (`GET /gateway/vector-stores`). */
  async listGatewayVectorStores() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/vector-stores`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Gateway vector stores list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style entitlement list (`GET /gateway/entitlements`). */
  async listEntitlements({
    entitlementId,
    action,
    tenantId,
    environment,
    enabled,
    limit = 100,
    offset = 0,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (entitlementId) params.set("entitlement_id", String(entitlementId).trim());
    if (action) params.set("action", String(action).trim());
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    if (enabled != null) params.set("enabled", enabled ? "true" : "false");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/entitlements?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Entitlements list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style entitlement upsert (`PUT /gateway/entitlements/{entitlementId}`). */
  async upsertEntitlement({
    entitlementId,
    action,
    tenantId,
    environment = "dev",
    routePolicyId,
    requestTag,
    modelName,
    toolName,
    allowedRoles = "[]",
    enabled = true,
  } = {}) {
    const eid = String(entitlementId || "").trim();
    if (!eid) throw new Error("entitlementId is required");
    const body = {
      action: String(action || "").trim(),
      environment: String(environment || "dev").trim() || "dev",
      allowed_roles: String(allowedRoles == null ? "[]" : allowedRoles),
      enabled: Boolean(enabled),
    };
    if (tenantId != null) body.tenant_id = String(tenantId).trim() || null;
    if (routePolicyId != null) body.route_policy_id = String(routePolicyId).trim() || null;
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (modelName != null) body.model_name = String(modelName).trim() || null;
    if (toolName != null) body.tool_name = String(toolName).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/entitlements/${encodeURIComponent(eid)}`, {
      method: "PUT",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Entitlement upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style NHI hygiene summary (`GET /gateway/nhi/hygiene`). */
  async getNhiHygiene({ maxCredentialAgeDays = 90, tenantId, environment } = {}) {
    const params = new URLSearchParams({
      max_credential_age_days: String(Math.max(1, Math.min(Number(maxCredentialAgeDays) || 90, 3650))),
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/hygiene?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI hygiene failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style NHI inventory (`GET /gateway/nhi/inventory`). */
  async listNhiInventory({
    tenantId,
    environment,
    sourceType,
    status,
    staleOnly = false,
    maxCredentialAgeDays = 90,
    limit = 100,
    offset = 0,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
      max_credential_age_days: String(Math.max(1, Math.min(Number(maxCredentialAgeDays) || 90, 3650))),
      stale_only: staleOnly ? "true" : "false",
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    if (sourceType) params.set("source_type", String(sourceType).trim());
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/inventory?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI inventory list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Export gateway NHI inventory for IGA correlation (`POST /gateway/nhi/export`). */
  async exportNhiInventory({
    tenantId,
    environment,
    profile = "iga_correlation",
    targetSystem = "generic",
    staleOnly = false,
    missingOwnerOnly = false,
    maxCredentialAgeDays = 90,
    limit = 100,
    includeHygieneSummary = true,
    deliverWebhook = false,
    dryRunDelivery = true,
    headers = {},
  } = {}) {
    const body = {
      profile: String(profile || "iga_correlation").trim(),
      target_system: String(targetSystem || "generic").trim(),
      stale_only: Boolean(staleOnly),
      missing_owner_only: Boolean(missingOwnerOnly),
      max_credential_age_days: Math.max(1, Math.min(Number(maxCredentialAgeDays || 90), 3650)),
      limit: Math.max(1, Math.min(Number(limit || 100), 500)),
      include_hygiene_summary: Boolean(includeHygieneSummary),
      deliver_webhook: Boolean(deliverWebhook),
      dry_run_delivery: Boolean(dryRunDelivery),
    };
    if (tenantId) body.tenant_id = String(tenantId).trim();
    if (environment) body.environment = String(environment).trim();
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/export`, {
      method: "POST",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Gateway NHI Insights risk ranking (`GET /gateway/nhi/insights`). */
  async getNhiInsights({ tenantId, environment, maxCredentialAgeDays = 90, limit = 50 } = {}) {
    const params = new URLSearchParams({
      max_credential_age_days: String(Math.max(1, Math.min(Number(maxCredentialAgeDays) || 90, 3650))),
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 100))),
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/insights?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI insights failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Gateway-plane NHI access map (`GET /gateway/nhi/{id}/access-map`). */
  async getNhiAccessMap(nhiRecordId) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/access-map`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI access map failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** NHI activity timeline (`GET /gateway/nhi/{id}/timeline`). */
  async getNhiTimeline(nhiRecordId, { limit = 50 } = {}) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/timeline?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI timeline failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Assign NHI owner (`PUT /gateway/nhi/{id}/owner`; dual-approval). */
  async updateNhiOwner(nhiRecordId, { ownerScopeType, ownerScopeId, purpose, headers = {} } = {}) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const body = {
      owner_scope_type: String(ownerScopeType || "").trim(),
      owner_scope_id: String(ownerScopeId || "").trim(),
    };
    if (purpose !== undefined) body.purpose = String(purpose || "").trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/owner`, {
      method: "PUT",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI owner update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** NHI lifecycle suspend/reactivate/retire (`POST /gateway/nhi/{id}/lifecycle`). For VKs mirrors Key Lifecycle block/unblock. */
  async updateNhiLifecycle(nhiRecordId, { action, reason = "", headers = {} } = {}) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/lifecycle`, {
      method: "POST",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify({
        action: String(action || "").trim(),
        reason: String(reason || "").trim(),
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI lifecycle failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Set approved intents for an NHI (`PUT /gateway/nhi/{id}/intents`). */
  async updateNhiIntents(nhiRecordId, { approvedIntents = [], purpose, headers = {} } = {}) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const body = { approved_intents: Array.isArray(approvedIntents) ? approvedIntents : [] };
    if (purpose !== undefined) body.purpose = String(purpose || "").trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/intents`, {
      method: "PUT",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI intents update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Read NHI intent_mode config (`GET /gateway/nhi/governance/config`). */
  async getNhiGovernanceConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/governance/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI governance config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Save NHI intent_mode (`PUT /gateway/nhi/governance/config`; dual-approval). */
  async updateNhiGovernanceConfig({ intentMode = "off", headers = {} } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/governance/config`, {
      method: "PUT",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify({ intent_mode: String(intentMode || "off").trim() || "off" }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI governance config update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Evaluate declared intent vs approved intents (`POST /gateway/nhi/intent-check`). */
  async checkNhiIntent({ declaredIntent, nhiRecordId, virtualKeyId, action } = {}) {
    const body = { declared_intent: String(declaredIntent || "").trim() };
    if (nhiRecordId) body.nhi_record_id = String(nhiRecordId).trim();
    if (virtualKeyId) body.virtual_key_id = String(virtualKeyId).trim();
    if (action) body.action = String(action).trim();
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/intent-check`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI intent-check failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Read NHI IGA export webhook config (`GET /gateway/nhi/iga-export/config`). */
  async getNhiIgaExportConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/iga-export/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI IGA export config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Read NHI IGA deny-signal config (`GET /gateway/nhi/iga-deny/config`). */
  async getNhiIgaDenyConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/iga-deny/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI IGA deny config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** IGA deny event history (`GET /gateway/nhi/iga-deny/events`). */
  async listNhiIgaDenyEvents({ limit = 50 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/iga-deny/events?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI IGA deny events failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Missing-owner orphan queue (`GET /gateway/nhi/orphans`). */
  async listNhiOrphans({ tenantId, environment, maxCredentialAgeDays = 90, limit = 100 } = {}) {
    const params = new URLSearchParams({
      max_credential_age_days: String(Math.max(1, Math.min(Number(maxCredentialAgeDays) || 90, 3650))),
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 200))),
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/orphans?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI orphans failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Bulk orphan owner assign (`POST /gateway/nhi/orphans/assign`; dual-approval). */
  async assignNhiOrphans({ nhiRecordIds = [], ownerScopeType, ownerScopeId, purpose, headers = {} } = {}) {
    const body = {
      nhi_record_ids: Array.isArray(nhiRecordIds) ? nhiRecordIds : [],
      owner_scope_type: String(ownerScopeType || "").trim(),
      owner_scope_id: String(ownerScopeId || "").trim(),
    };
    if (purpose !== undefined) body.purpose = String(purpose || "").trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/orphans/assign`, {
      method: "POST",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI orphans assign failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Set IGA correlation ids (`PUT /gateway/nhi/{id}/correlation`). */
  async updateNhiCorrelation(nhiRecordId, { externalRef, igaAgentId, sourceSystem, headers = {} } = {}) {
    const rid = String(nhiRecordId || "").trim();
    if (!rid) throw new Error("nhiRecordId is required");
    const body = {};
    if (externalRef !== undefined) body.external_ref = String(externalRef || "").trim() || null;
    if (igaAgentId !== undefined) body.iga_agent_id = String(igaAgentId || "").trim() || null;
    if (sourceSystem !== undefined) body.source_system = String(sourceSystem || "").trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/${encodeURIComponent(rid)}/correlation`, {
      method: "PUT",
      headers: { ...this._headers(), ...headers },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI correlation update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Evaluate whether an IGA deny matches (`POST /gateway/nhi/iga-deny/evaluate`). */
  async evaluateNhiIgaDeny(body = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/nhi/iga-deny/evaluate`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify(body || {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `NHI IGA deny evaluate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style OpenAI-compatible tunnel config (`GET /gateway/tunnel/config`). */
  async getTunnelConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/tunnel/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Tunnel config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style gateway system instructions (`GET /gateway/system-instructions`). */
  async getSystemInstructions() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/system-instructions`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `System instructions failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style gateway system instructions update (`PUT /gateway/system-instructions`). */
  async updateSystemInstructions({ instructions = "" } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/system-instructions`, {
      method: "PUT",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ instructions: String(instructions || "") }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `System instructions update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style gateway system rules (`GET /gateway/system-rules`). */
  async getSystemRules() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/system-rules`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `System rules failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style gateway system rules update (`PUT /gateway/system-rules`). */
  async updateSystemRules({ rules = [] } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/system-rules`, {
      method: "PUT",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ rules: Array.isArray(rules) ? rules : [] }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `System rules update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style external callback registry (`GET /gateway/external-callbacks`). */
  async listExternalCallbacks() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/external-callbacks`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `External callbacks list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style external callback create (`POST /gateway/external-callbacks`). */
  async createExternalCallback({
    callbackUrl,
    eventTypes = ["gateway.route.execute_fallback"],
    environment = "dev",
    sinkType = "generic_webhook",
    sinkRouteKey,
    correlationPreset = "trace_resource",
    redactSensitive = true,
    enabled = true,
    description,
  } = {}) {
    const body = {
      callback_url: String(callbackUrl || "").trim(),
      event_types: Array.isArray(eventTypes) ? eventTypes : ["gateway.route.execute_fallback"],
      environment: String(environment || "dev").trim() || "dev",
      sink_type: String(sinkType || "generic_webhook").trim() || "generic_webhook",
      correlation_preset: String(correlationPreset || "trace_resource").trim() || "trace_resource",
      redact_sensitive: Boolean(redactSensitive),
      enabled: Boolean(enabled),
    };
    if (sinkRouteKey != null) body.sink_route_key = String(sinkRouteKey).trim() || null;
    if (description != null) body.description = String(description).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/external-callbacks`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `External callback create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style external callback update (`PATCH /gateway/external-callbacks/{callbackId}`). */
  async updateExternalCallback(
    callbackId,
    {
      callbackUrl,
      eventTypes,
      environment,
      sinkType,
      sinkRouteKey,
      correlationPreset,
      redactSensitive,
      enabled,
      description,
    } = {},
  ) {
    const id = String(callbackId || "").trim();
    if (!id) throw new Error("callbackId is required");
    const body = {};
    if (callbackUrl != null) body.callback_url = String(callbackUrl).trim();
    if (eventTypes != null) body.event_types = Array.isArray(eventTypes) ? eventTypes : [];
    if (environment != null) body.environment = String(environment).trim();
    if (sinkType != null) body.sink_type = String(sinkType).trim();
    if (sinkRouteKey != null) body.sink_route_key = String(sinkRouteKey).trim() || null;
    if (correlationPreset != null) body.correlation_preset = String(correlationPreset).trim();
    if (redactSensitive != null) body.redact_sensitive = Boolean(redactSensitive);
    if (enabled != null) body.enabled = Boolean(enabled);
    if (description != null) body.description = String(description).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/external-callbacks/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `External callback update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style external callback test delivery (`POST .../test-delivery`). */
  async testExternalCallbackDelivery(callbackId, { environment = "dev", samplePayload = {} } = {}) {
    const id = String(callbackId || "").trim();
    if (!id) throw new Error("callbackId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/external-callbacks/${encodeURIComponent(id)}/test-delivery`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify({
          environment: String(environment || "dev").trim() || "dev",
          sample_payload: samplePayload && typeof samplePayload === "object" ? samplePayload : {},
        }),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `External callback test delivery failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style external callback evidence export (`POST /gateway/external-callbacks/export`). */
  async exportExternalCallbacks({ environment, limit = 50 } = {}) {
    const body = {
      limit: Math.max(1, Math.min(Number(limit) || 50, 500)),
    };
    if (environment != null) body.environment = String(environment).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/external-callbacks/export`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `External callbacks export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style gateway governance evidence export (`POST /gateway/governance/evidence/export`). */
  async exportGatewayGovernanceEvidence({
    decisionOutcome,
    limitPerAction = 100,
    bundleLabel = "gateway-governance-evidence",
    dataClassification = "confidential",
    retentionDays = 90,
    approvedSharingChannels = ["security-ops", "compliance-review"],
    redactActorLogin = false,
  } = {}) {
    const body = {
      limit_per_action: Math.max(10, Math.min(Number(limitPerAction) || 100, 500)),
      bundle_label: String(bundleLabel || "gateway-governance-evidence").trim() || "gateway-governance-evidence",
      data_classification: String(dataClassification || "confidential").trim() || "confidential",
      retention_days: Math.max(7, Math.min(Number(retentionDays) || 90, 2555)),
      approved_sharing_channels: Array.isArray(approvedSharingChannels)
        ? approvedSharingChannels
        : ["security-ops", "compliance-review"],
      redact_actor_login: Boolean(redactActorLogin),
    };
    if (decisionOutcome != null) body.decision_outcome = String(decisionOutcome).trim() || null;
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/governance/evidence/export`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Gateway governance evidence export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style Cursor secret binding posture (`GET /gateway/cursor-secret-binding`; no raw secrets). */
  async getCursorSecretBinding() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cursor-secret-binding`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cursor secret binding failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style Cursor secret binding update (`PUT /gateway/cursor-secret-binding`; no raw secrets returned). */
  async updateCursorSecretBinding({ secretProviderId, secretRef } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cursor-secret-binding`, {
      method: "PUT",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify({
        secret_provider_id: String(secretProviderId || "").trim(),
        secret_ref: String(secretRef || "").trim(),
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cursor secret binding update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style Cursor secret binding clear (`DELETE /gateway/cursor-secret-binding`). */
  async clearCursorSecretBinding() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cursor-secret-binding`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cursor secret binding clear failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style least-privilege recommendations (`GET /gateway/least-privilege/recommendations`). */
  async listLeastPrivilegeRecommendations({
    tenantId,
    environment,
    entitlementId,
    recommendationType,
    status = "pending",
    limit = 100,
    offset = 0,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (environment) params.set("environment", String(environment).trim());
    if (entitlementId) params.set("entitlement_id", String(entitlementId).trim());
    if (recommendationType) params.set("recommendation_type", String(recommendationType).trim());
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/least-privilege/recommendations?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Least-privilege recommendations failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style decision trace (`GET /gateway/decision-traces/{traceId}`). */
  async getDecisionTrace(traceId, { limit = 200 } = {}) {
    const id = String(traceId || "").trim();
    if (!id) throw new Error("traceId is required");
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 200, 1000))),
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/decision-traces/${encodeURIComponent(id)}?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Decision trace failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style access review campaign (`GET /gateway/access-reviews/campaigns/{campaignId}`). */
  /** Portkey-style access review create (`POST /gateway/access-reviews/campaigns`). */
  async createAccessReviewCampaign({
    campaignName,
    tenantId,
    environment = "dev",
    includeDisabled = false,
    reviewerRole = "Security Approver",
  } = {}) {
    const name = String(campaignName || "").trim();
    if (!name) throw new Error("campaignName is required");
    const body = {
      campaign_name: name,
      environment: String(environment || "dev").trim() || "dev",
      include_disabled: Boolean(includeDisabled),
      reviewer_role: String(reviewerRole || "Security Approver").trim() || "Security Approver",
    };
    if (tenantId) body.tenant_id = String(tenantId).trim();
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/access-reviews/campaigns`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Access review campaign create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style JIT access request (`POST /gateway/jit-requests`). */
  async createJitAccessRequest({
    entitlementId,
    justification,
    environment = "dev",
    requestedDurationMinutes = 60,
    ownerScopeType,
    ownerScopeId,
    mintVirtualKey,
  } = {}) {
    const eid = String(entitlementId || "").trim();
    if (!eid) throw new Error("entitlementId is required");
    const reason = String(justification || "").trim();
    if (reason.length < 8) throw new Error("justification must be at least 8 characters");
    const body = {
      entitlement_id: eid,
      justification: reason,
      environment: String(environment || "dev").trim() || "dev",
      requested_duration_minutes: Math.max(5, Math.min(Number(requestedDurationMinutes) || 60, 1440)),
    };
    if (ownerScopeType != null && String(ownerScopeType).trim()) {
      body.owner_scope_type = String(ownerScopeType).trim().toLowerCase();
    }
    if (ownerScopeId != null && String(ownerScopeId).trim()) {
      body.owner_scope_id = String(ownerScopeId).trim();
    }
    if (mintVirtualKey != null) body.mint_virtual_key = Boolean(mintVirtualKey);
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-requests`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT access request create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style JIT approve/deny (`POST /gateway/jit-requests/{requestId}/approve`). */
  async approveJitAccessRequest(
    requestId,
    { decision = "approve", decisionReason, mintVirtualKey } = {},
  ) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const choice = String(decision || "approve").trim().toLowerCase() || "approve";
    if (!["approve", "deny"].includes(choice)) {
      throw new Error("decision must be one of: approve, deny");
    }
    const body = { decision: choice };
    if (decisionReason != null) body.decision_reason = String(decisionReason);
    if (mintVirtualKey != null) body.mint_virtual_key = Boolean(mintVirtualKey);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/approve`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT access request approve failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** List gateway JIT requests (`GET /gateway/jit-requests`). */
  async listJitAccessRequests({
    status,
    environment,
    entitlementId,
    requesterId,
    activeOnly = false,
    limit = 50,
    offset = 0,
  } = {}) {
    const params = new URLSearchParams();
    params.set("limit", String(Math.max(1, Math.min(Number(limit) || 50, 200))));
    params.set("offset", String(Math.max(0, Number(offset) || 0)));
    if (status) params.set("status", String(status).trim().toLowerCase());
    if (environment) params.set("environment", String(environment).trim().toLowerCase());
    if (entitlementId) params.set("entitlement_id", String(entitlementId).trim());
    if (requesterId) params.set("requester_id", String(requesterId).trim());
    if (activeOnly) params.set("active_only", "true");
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-requests?${params.toString()}`, {
      method: "GET",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT access request list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Get one gateway JIT request (`GET /gateway/jit-requests/{requestId}`). */
  async getJitAccessRequest(requestId) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}`,
      { method: "GET", headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT access request get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Revoke a gateway JIT grant (`POST /gateway/jit-requests/{requestId}/revoke`). */
  async revokeJitAccessRequest(requestId, { reason } = {}) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const body = {};
    if (reason != null) body.reason = String(reason);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/revoke`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT access request revoke failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Expire stale approved JIT grants (`POST /gateway/jit-requests/expire-tick`). */
  async expireJitAccessGrants({ limit = 200 } = {}) {
    const params = new URLSearchParams();
    params.set("limit", String(Math.max(1, Math.min(Number(limit) || 200, 1000))));
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-requests/expire-tick?${params.toString()}`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: "{}",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT expire tick failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Get JIT email/external REST decision notify config (`GET /gateway/jit-decision-notify/config`). */
  async getJitDecisionNotifyConfig() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-decision-notify/config`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT decision notify config failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Update JIT decision notify config (`PUT /gateway/jit-decision-notify/config`, dual-approval headers required). */
  async updateJitDecisionNotifyConfig(config = {}, { approverRole, approverId } = {}) {
    const headers = { ...this._headers(), "Content-Type": "application/json" };
    if (approverRole) headers["X-Approver-Role"] = String(approverRole);
    if (approverId) headers["X-Approver-Id"] = String(approverId);
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-decision-notify/config`, {
      method: "PUT",
      headers,
      body: JSON.stringify(config || {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT decision notify config update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Test JIT decision notify delivery (`POST /gateway/jit-decision-notify/test-delivery`). */
  async testJitDecisionNotifyDelivery() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-decision-notify/test-delivery`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: "{}",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT decision notify test failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Notify reviewers/webhooks for a JIT request (`POST /gateway/jit-requests/{id}/notify`). */
  async notifyJitAccessRequest(requestId, { reminder = false, force = false, escalate = false } = {}) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const params = new URLSearchParams();
    if (reminder) params.set("reminder", "true");
    if (escalate) params.set("escalate", "true");
    if (force) params.set("force", "true");
    const qs = params.toString() ? `?${params.toString()}` : "";
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/notify${qs}`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: "{}",
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT notify failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Run SLA reminder/escalation/retry tick (`POST /gateway/jit-requests/notify-tick`). */
  async runJitNotifyTick({ limit = 100 } = {}) {
    const params = new URLSearchParams();
    params.set("limit", String(Math.max(1, Math.min(Number(limit) || 100, 500))));
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-requests/notify-tick?${params.toString()}`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: "{}",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT notify tick failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Pending notify SLA summary (`GET /gateway/jit-decision-notify/pending-summary`). */
  async getJitPendingNotifySummary() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/jit-decision-notify/pending-summary`, {
      method: "GET",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT pending notify summary failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Retry failed webhook deliveries (`POST /gateway/jit-requests/{id}/notify-retry`). */
  async retryJitNotifyWebhooks(requestId) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/notify-retry`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: "{}",
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT notify retry failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Read notify delivery history (`GET /gateway/jit-requests/{id}/notify-history`). */
  async getJitNotifyHistory(requestId) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/notify-history`,
      {
        method: "GET",
        headers: this._headers(),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT notify history failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Preview signed email action links (`POST /gateway/jit-requests/{id}/preview-action-links`). */
  async previewJitActionLinks(requestId, { reviewerEmail = "preview@example.com" } = {}) {
    const id = String(requestId || "").trim();
    if (!id) throw new Error("requestId is required");
    const params = new URLSearchParams();
    params.set("reviewer_email", String(reviewerEmail || "preview@example.com").trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/jit-requests/${encodeURIComponent(id)}/preview-action-links?${params.toString()}`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: "{}",
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `JIT preview links failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style LPR apply (`POST /gateway/least-privilege/recommendations/{recommendationId}/apply`). */
  async applyLeastPrivilegeRecommendation(
    recommendationId,
    { decisionReason, changeTicketId, reviewEvidenceUri } = {},
  ) {
    const id = String(recommendationId || "").trim();
    if (!id) throw new Error("recommendationId is required");
    const body = {};
    if (decisionReason != null) body.decision_reason = String(decisionReason);
    if (changeTicketId != null) body.change_ticket_id = String(changeTicketId).trim();
    if (reviewEvidenceUri != null) body.review_evidence_uri = String(reviewEvidenceUri).trim();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/least-privilege/recommendations/${encodeURIComponent(id)}/apply`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Least-privilege apply failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  async getAccessReviewCampaign(campaignId) {
    const id = String(campaignId || "").trim();
    if (!id) throw new Error("campaignId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/access-reviews/campaigns/${encodeURIComponent(id)}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Access review campaign failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style MCP tool list (`POST /gateway/mcp/servers/{serverId}/tools/list`). */
  async listMcpTools(serverId, { environment = "dev" } = {}) {
    const id = String(serverId || "").trim();
    if (!id) throw new Error("serverId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/mcp/servers/${encodeURIComponent(id)}/tools/list`,
      {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify({ environment: String(environment || "dev").trim() || "dev" }),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `MCP tools list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style MCP tool call (`POST /gateway/mcp/servers/{serverId}/tools/call`). */
  async callMcpTool(serverId, toolName, { arguments: args = {}, environment = "dev" } = {}) {
    const id = String(serverId || "").trim();
    const name = String(toolName || "").trim();
    if (!id) throw new Error("serverId is required");
    if (!name) throw new Error("toolName is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/mcp/servers/${encodeURIComponent(id)}/tools/call`,
      {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify({
          environment: String(environment || "dev").trim() || "dev",
          tool_name: name,
          arguments: args && typeof args === "object" && !Array.isArray(args) ? args : {},
        }),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `MCP tool call failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route policy inventory (`GET /gateway/routes`). */
  async listRoutes({ limit = 50, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/routes?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Routes list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.items || payload?.data || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey-style route policy get (`GET /gateway/routes/{routePolicyId}`). */
  async getRoute(routePolicyId) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route get failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route policy create (`POST /gateway/routes`). */
  async createRoute({
    routeName,
    candidateDeployments = "[]",
    loadBalancingStrategy = "weighted",
    retryPolicy = "{}",
    fallbackPolicy = "{}",
    timeoutPolicy = "{}",
  } = {}) {
    const body = {
      route_name: String(routeName || "").trim(),
      candidate_deployments: String(candidateDeployments || "[]"),
      load_balancing_strategy: String(loadBalancingStrategy || "weighted").trim() || "weighted",
      retry_policy: String(retryPolicy || "{}"),
      fallback_policy: String(fallbackPolicy || "{}"),
      timeout_policy: String(timeoutPolicy || "{}"),
    };
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/routes`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Portkey/Helicone-style cost anomaly list (`GET /cost/anomalies`). */
  async listCostAnomalies() {
    const response = await this.fetchImpl(`${this.baseUrl}/cost/anomalies`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ([]));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost anomalies list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload;
    if (payload && typeof payload === "object") {
      const items = payload.items || payload.data || payload.anomalies || [];
      return Array.isArray(items) ? items : [];
    }
    return [];
  }

  /** Portkey-style preflight cost limit evaluation (`POST /cost/limits/evaluate`). */
  async evaluateCostLimits({
    actorId,
    teamIds = [],
    groupIds = [],
    agentIds = [],
    windowType = "daily",
    projectedAdditionalCostCents = 0,
  } = {}) {
    const body = {
      window_type: String(windowType || "daily").trim() || "daily",
      projected_additional_cost_cents: Math.max(0, Number(projectedAdditionalCostCents) || 0),
      team_ids: (Array.isArray(teamIds) ? teamIds : []).map((x) => String(x || "").trim()).filter(Boolean),
      group_ids: (Array.isArray(groupIds) ? groupIds : []).map((x) => String(x || "").trim()).filter(Boolean),
      agent_ids: (Array.isArray(agentIds) ? agentIds : []).map((x) => String(x || "").trim()).filter(Boolean),
    };
    if (actorId) body.actor_id = String(actorId).trim();
    const response = await this.fetchImpl(`${this.baseUrl}/cost/limits/evaluate`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost limits evaluate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }



  /** Helicone-style request search (`GET /cost/requests`; metadata + spend only). */
  async listCostRequests({
    windowHours = 24,
    userId,
    model,
    propertyKey,
    propertyValue,
    cacheHit,
    hasFeedback,
    limit = 50,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    if (userId) params.set("user_id", String(userId).trim());
    if (model) params.set("model", String(model).trim());
    if (propertyKey) params.set("property_key", String(propertyKey).trim());
    if (propertyValue) params.set("property_value", String(propertyValue).trim());
    if (cacheHit != null) params.set("cache_hit", cacheHit ? "true" : "false");
    if (hasFeedback != null) params.set("has_feedback", hasFeedback ? "true" : "false");
    const response = await this.fetchImpl(`${this.baseUrl}/cost/requests?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost requests list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style session path tree (`GET /cost/sessions/tree`). */
  async getCostSessionTree({
    windowHours = 24,
    pathPrefix,
    maxDepth = 4,
    limit = 50,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      max_depth: String(Math.max(1, Math.min(Number(maxDepth) || 4, 16))),
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    if (pathPrefix) params.set("path_prefix", String(pathPrefix).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/sessions/tree?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost session tree failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style rollout burn timeseries (`GET /cost/rollouts/timeseries`). */
  async getCostRolloutTimeseries({
    windowHours = 24,
    rolloutFilter,
    topRollouts = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_rollouts: String(Math.max(1, Math.min(Number(topRollouts) || 8, 20))),
    });
    if (rolloutFilter) params.set("rollout_filter", String(rolloutFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/rollouts/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost rollout timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style route burn timeseries (`GET /cost/routes/timeseries`). */
  async getCostRouteTimeseries({
    windowHours = 24,
    routeFilter,
    topRoutes = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_routes: String(Math.max(1, Math.min(Number(topRoutes) || 8, 20))),
    });
    if (routeFilter) params.set("route_filter", String(routeFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/routes/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost route timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style batch burn timeseries (`GET /cost/batches/timeseries`). */
  async getCostBatchTimeseries({
    windowHours = 24,
    batchFilter,
    topBatches = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_batches: String(Math.max(1, Math.min(Number(topBatches) || 8, 20))),
    });
    if (batchFilter) params.set("batch_filter", String(batchFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/batches/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost batch timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style job burn timeseries (`GET /cost/jobs/timeseries`). */
  async getCostJobTimeseries({
    windowHours = 24,
    jobFilter,
    topJobs = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_jobs: String(Math.max(1, Math.min(Number(topJobs) || 8, 20))),
    });
    if (jobFilter) params.set("job_filter", String(jobFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/jobs/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost job timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style queue burn timeseries (`GET /cost/queues/timeseries`). */
  async getCostQueueTimeseries({
    windowHours = 24,
    queueFilter,
    topQueues = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_queues: String(Math.max(1, Math.min(Number(topQueues) || 8, 20))),
    });
    if (queueFilter) params.set("queue_filter", String(queueFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/queues/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost queue timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style topic burn timeseries (`GET /cost/topics/timeseries`). */
  async getCostTopicTimeseries({
    windowHours = 24,
    topicFilter,
    topTopics = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_topics: String(Math.max(1, Math.min(Number(topTopics) || 8, 20))),
    });
    if (topicFilter) params.set("topic_filter", String(topicFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/topics/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost topic timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style pipeline burn timeseries (`GET /cost/pipelines/timeseries`). */
  async getCostPipelineTimeseries({
    windowHours = 24,
    pipelineFilter,
    topPipelines = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_pipelines: String(Math.max(1, Math.min(Number(topPipelines) || 8, 20))),
    });
    if (pipelineFilter) params.set("pipeline_filter", String(pipelineFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/pipelines/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost pipeline timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style run burn timeseries (`GET /cost/runs/timeseries`). */
  async getCostRunTimeseries({
    windowHours = 24,
    runFilter,
    topRuns = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_runs: String(Math.max(1, Math.min(Number(topRuns) || 8, 20))),
    });
    if (runFilter) params.set("run_filter", String(runFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/runs/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost run timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style worker burn timeseries (`GET /cost/workers/timeseries`). */
  async getCostWorkerTimeseries({
    windowHours = 24,
    workerFilter,
    topWorkers = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_workers: String(Math.max(1, Math.min(Number(topWorkers) || 8, 20))),
    });
    if (workerFilter) params.set("worker_filter", String(workerFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/workers/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost worker timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style slot burn timeseries (`GET /cost/slots/timeseries`). */
  async getCostSlotTimeseries({
    windowHours = 24,
    slotFilter,
    topSlots = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_slots: String(Math.max(1, Math.min(Number(topSlots) || 8, 20))),
    });
    if (slotFilter) params.set("slot_filter", String(slotFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/slots/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost slot timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style task burn timeseries (`GET /cost/tasks/timeseries`). */
  async getCostTaskTimeseries({
    windowHours = 24,
    taskFilter,
    topTasks = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_tasks: String(Math.max(1, Math.min(Number(topTasks) || 8, 20))),
    });
    if (taskFilter) params.set("task_filter", String(taskFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/tasks/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost task timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style step burn timeseries (`GET /cost/steps/timeseries`). */
  async getCostStepTimeseries({
    windowHours = 24,
    stepFilter,
    topSteps = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_steps: String(Math.max(1, Math.min(Number(topSteps) || 8, 20))),
    });
    if (stepFilter) params.set("step_filter", String(stepFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/steps/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost step timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style replica burn timeseries (`GET /cost/replicas/timeseries`). */
  async getCostReplicaTimeseries({
    windowHours = 24,
    replicaFilter,
    topReplicas = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_replicas: String(Math.max(1, Math.min(Number(topReplicas) || 8, 20))),
    });
    if (replicaFilter) params.set("replica_filter", String(replicaFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/replicas/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost replica timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style shard burn timeseries (`GET /cost/shards/timeseries`). */
  async getCostShardTimeseries({
    windowHours = 24,
    shardFilter,
    topShards = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_shards: String(Math.max(1, Math.min(Number(topShards) || 8, 20))),
    });
    if (shardFilter) params.set("shard_filter", String(shardFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/shards/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost shard timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style partition burn timeseries (`GET /cost/partitions/timeseries`). */
  async getCostPartitionTimeseries({
    windowHours = 24,
    partitionFilter,
    topPartitions = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_partitions: String(Math.max(1, Math.min(Number(topPartitions) || 8, 20))),
    });
    if (partitionFilter) params.set("partition_filter", String(partitionFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/partitions/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost partition timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style consumer burn timeseries (`GET /cost/consumers/timeseries`). */
  async getCostConsumerTimeseries({
    windowHours = 24,
    consumerFilter,
    topConsumers = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_consumers: String(Math.max(1, Math.min(Number(topConsumers) || 8, 20))),
    });
    if (consumerFilter) params.set("consumer_filter", String(consumerFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/consumers/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost consumer timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style producer burn timeseries (`GET /cost/producers/timeseries`). */
  async getCostProducerTimeseries({
    windowHours = 24,
    producerFilter,
    topProducers = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_producers: String(Math.max(1, Math.min(Number(topProducers) || 8, 20))),
    });
    if (producerFilter) params.set("producer_filter", String(producerFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/producers/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost producer timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style gpu burn timeseries (`GET /cost/gpus/timeseries`). */
  async getCostGpuTimeseries({
    windowHours = 24,
    gpuFilter,
    topGpus = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_gpus: String(Math.max(1, Math.min(Number(topGpus) || 8, 20))),
    });
    if (gpuFilter) params.set("gpu_filter", String(gpuFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/gpus/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost gpu timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style accelerator burn timeseries (`GET /cost/accelerators/timeseries`). */
  async getCostAcceleratorTimeseries({
    windowHours = 24,
    acceleratorFilter,
    topAccelerators = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_accelerators: String(Math.max(1, Math.min(Number(topAccelerators) || 8, 20))),
    });
    if (acceleratorFilter) params.set("accelerator_filter", String(acceleratorFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/accelerators/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost accelerator timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style cell burn timeseries (`GET /cost/cells/timeseries`). */
  async getCostCellTimeseries({
    windowHours = 24,
    cellFilter,
    topCells = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_cells: String(Math.max(1, Math.min(Number(topCells) || 8, 20))),
    });
    if (cellFilter) params.set("cell_filter", String(cellFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/cells/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost cell timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style zone burn timeseries (`GET /cost/zones/timeseries`). */
  async getCostZoneTimeseries({
    windowHours = 24,
    zoneFilter,
    topZones = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_zones: String(Math.max(1, Math.min(Number(topZones) || 8, 20))),
    });
    if (zoneFilter) params.set("zone_filter", String(zoneFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/zones/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost zone timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style rack burn timeseries (`GET /cost/racks/timeseries`). */
  async getCostRackTimeseries({
    windowHours = 24,
    rackFilter,
    topRacks = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_racks: String(Math.max(1, Math.min(Number(topRacks) || 8, 20))),
    });
    if (rackFilter) params.set("rack_filter", String(rackFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/racks/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost rack timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style pool burn timeseries (`GET /cost/pools/timeseries`). */
  async getCostPoolTimeseries({
    windowHours = 24,
    poolFilter,
    topPools = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_pools: String(Math.max(1, Math.min(Number(topPools) || 8, 20))),
    });
    if (poolFilter) params.set("pool_filter", String(poolFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/pools/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost pool timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style fleet burn timeseries (`GET /cost/fleets/timeseries`). */
  async getCostFleetTimeseries({
    windowHours = 24,
    fleetFilter,
    topFleets = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_fleets: String(Math.max(1, Math.min(Number(topFleets) || 8, 20))),
    });
    if (fleetFilter) params.set("fleet_filter", String(fleetFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/fleets/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost fleet timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style lease burn timeseries (`GET /cost/leases/timeseries`). */
  async getCostLeaseTimeseries({
    windowHours = 24,
    leaseFilter,
    topLeases = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_leases: String(Math.max(1, Math.min(Number(topLeases) || 8, 20))),
    });
    if (leaseFilter) params.set("lease_filter", String(leaseFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/leases/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost lease timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }


  /** Helicone-style quota burn timeseries (`GET /cost/quotas/timeseries`). */
  async getCostQuotaTimeseries({
    windowHours = 24,
    quotaFilter,
    topQuotas = 8,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      top_quotas: String(Math.max(1, Math.min(Number(topQuotas) || 8, 20))),
    });
    if (quotaFilter) params.set("quota_filter", String(quotaFilter).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/quotas/timeseries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost quota timeseries failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style live burn snapshot (`GET /cost/live`). */
  async getCostLive() {
    const response = await this.fetchImpl(`${this.baseUrl}/cost/live`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost live failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style cost breakdown (`GET /cost/breakdown`). */
  async getCostBreakdown({ dimension = "all", windowHours = 24, limit = 8 } = {}) {
    const params = new URLSearchParams({
      dimension: String(dimension || "all").trim() || "all",
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      limit: String(Math.max(1, Math.min(Number(limit) || 8, 50))),
    });
    const response = await this.fetchImpl(`${this.baseUrl}/cost/breakdown?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cost breakdown failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style cost events CSV export (`GET /cost/export`). */
  async exportCost({
    windowHours = 24,
    dimension = "all",
    scopeFilter,
    propertyKey,
    propertyValue,
    limit = 1000,
  } = {}) {
    const params = new URLSearchParams({
      window_hours: String(Math.max(1, Math.min(Number(windowHours) || 24, 24 * 30))),
      dimension: String(dimension || "all").trim() || "all",
      limit: String(Math.max(1, Math.min(Number(limit) || 1000, 5000))),
    });
    if (scopeFilter) params.set("scope_filter", String(scopeFilter).trim());
    if (propertyKey) params.set("property_key", String(propertyKey).trim());
    if (propertyValue) params.set("property_value", String(propertyValue).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/export?${params.toString()}`, {
      headers: this._headers(),
    });
    const text = await response.text().catch(() => "");
    if (!response.ok) {
      let detail = text || response.statusText;
      try {
        const payload = JSON.parse(text || "{}");
        detail = payload?.detail || payload?.message || detail;
      } catch {
        /* keep text detail */
      }
      throw new Error(
        `Cost export failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return text;
  }

  /**
   * Gateway analytics summary (`GET /gateway/analytics/summary`).
   * Includes Leader Readiness on-plane fields: `on_plane_coverage_percent`,
   * `on_plane_events`, `off_plane_detected`, nested `on_plane_coverage`.
   */
  async getGatewayAnalyticsSummary({ hours = 24, environment } = {}) {
    const params = new URLSearchParams({
      hours: String(Math.max(1, Math.min(Number(hours) || 24, 168))),
    });
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/analytics/summary?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Gateway analytics summary failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /**
   * Leader Readiness numbers-first QBR pack (`GET /gateway/governance/qbr-snapshot`).
   * Does not authorize market-leadership claims.
   */
  async getLeadershipQbrSnapshot({ hours = 2160, environment } = {}) {
    const params = new URLSearchParams({
      hours: String(Math.max(1, Math.min(Number(hours) || 2160, 4320))),
    });
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/governance/qbr-snapshot?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Leadership QBR snapshot failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** List dated Clock/RT drill attestations (`GET /gateway/governance/drill-runs`). */
  async listLeadershipDrillRuns({ drillId, limit = 50 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 50, 200))),
    });
    if (drillId) params.set("drill_id", String(drillId).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/governance/drill-runs?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Leadership drill runs failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Record a dated drill after a real exercise (`POST /gateway/governance/drill-runs`). */
  async recordLeadershipDrillRun(body = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/governance/drill-runs`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Record leadership drill failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route provider health (`GET /gateway/routes/{routePolicyId}/providers/health`). */
  async getRouteProviderHealth(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/providers/health${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route provider health failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route provider priority (`GET /gateway/routes/{routePolicyId}/providers/priority`). */
  async getRouteProviderPriority(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/providers/priority${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route provider priority failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style provider priority upsert (`POST /gateway/routes/{routePolicyId}/providers/priority`). */
  async upsertRouteProviderPriority(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      priorityOrder = "[]",
      globalTimeoutMs = 4500,
      maxFallbackHops = 2,
      healthCheckEnabled = false,
      budgetLimitCents,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      priority_order: String(priorityOrder == null ? "[]" : priorityOrder),
      global_timeout_ms: Math.max(100, Math.min(Number(globalTimeoutMs) || 4500, 120000)),
      max_fallback_hops: Math.max(0, Math.min(Number(maxFallbackHops) || 0, 10)),
      health_check_enabled: Boolean(healthCheckEnabled),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (budgetLimitCents != null) body.budget_limit_cents = Number(budgetLimitCents);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/providers/priority`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route provider priority upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style provider health upsert (`PUT /gateway/routes/{routePolicyId}/providers/health`). */
  async upsertRouteProviderHealth(routePolicyId, { entries = [], requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = { entries: Array.isArray(entries) ? entries : [] };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/providers/health`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route provider health upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style provider priority timeline (`GET /gateway/routes/{routePolicyId}/providers/priority/timeline`). */
  async getRouteProviderPriorityTimeline(routePolicyId, { limit = 25, offset = 0 } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 25, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/providers/priority/timeline?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route provider priority timeline failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style traffic mirroring analytics (`GET /gateway/routes/{routePolicyId}/traffic-mirroring/analytics-summary`). */
  async getRouteTrafficMirroringAnalyticsSummary(
    routePolicyId,
    { hours = 24, requestTag, environment } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams({
      hours: String(Math.max(1, Math.min(Number(hours) || 24, 168))),
    });
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/traffic-mirroring/analytics-summary?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route traffic mirroring analytics failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style traffic mirroring experiment report (`GET /gateway/routes/{routePolicyId}/traffic-mirroring/experiment-report`). */
  async getRouteTrafficMirroringExperimentReport(
    routePolicyId,
    { hours = 24, requestTag, environment, limit = 25, offset = 0 } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams({
      hours: String(Math.max(1, Math.min(Number(hours) || 24, 168))),
      limit: String(Math.max(1, Math.min(Number(limit) || 25, 200))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    if (environment) params.set("environment", String(environment).trim());
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/traffic-mirroring/experiment-report?${params.toString()}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route traffic mirroring experiment report failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style dry-run fallback simulation (`POST /gateway/routes/{routePolicyId}/simulate-fallback`). */
  async simulateRouteFallback(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      requestedRegion,
      simulateFailProviderIds = "[]",
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const tid = String(tenantId || "").trim();
    if (!tid) throw new Error("tenantId is required");
    const body = {
      tenant_id: tid,
      environment: String(environment || "prod").trim() || "prod",
      simulate_fail_provider_ids: String(simulateFailProviderIds || "[]"),
    };
    if (requestTag) body.request_tag = String(requestTag).trim();
    if (requestedRegion) body.requested_region = String(requestedRegion).trim();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/simulate-fallback`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route fallback simulation failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style traffic mirroring policy (`GET /gateway/routes/{routePolicyId}/traffic-mirroring`). */
  async getRouteTrafficMirroring(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/traffic-mirroring${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route traffic mirroring failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style traffic mirroring upsert (`PUT /gateway/routes/{routePolicyId}/traffic-mirroring`). */
  async upsertRouteTrafficMirroring(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      mirrorTargets = "[]",
      enabled = true,
      maxLiveAttempts = 1,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      mirror_targets: String(mirrorTargets == null ? "[]" : mirrorTargets),
      enabled: Boolean(enabled),
      max_live_attempts: Math.max(0, Math.min(Number(maxLiveAttempts) || 0, 3)),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/traffic-mirroring`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route traffic mirroring upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style canary rollout policy (`GET /gateway/routes/{routePolicyId}/canary-rollout`). */
  async getRouteCanaryRollout(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/canary-rollout${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route canary rollout failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style canary rollout upsert (`PUT /gateway/routes/{routePolicyId}/canary-rollout`). */
  async upsertRouteCanaryRollout(
    routePolicyId,
    {
      tenantId,
      baselineProviderId,
      environment = "prod",
      requestTag,
      canaryTargets = "[]",
      cohortRequestTags = "[]",
      cohortOwnerScopes = "[]",
      gateMinRequests,
      gateMaxFailureRate,
      gateMinSuccessRate,
      enabled = true,
      notes,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      baseline_provider_id: String(baselineProviderId || "").trim(),
      canary_targets: String(canaryTargets == null ? "[]" : canaryTargets),
      cohort_request_tags: String(cohortRequestTags == null ? "[]" : cohortRequestTags),
      cohort_owner_scopes: String(cohortOwnerScopes == null ? "[]" : cohortOwnerScopes),
      enabled: Boolean(enabled),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (gateMinRequests != null) body.gate_min_requests = Number(gateMinRequests);
    if (gateMaxFailureRate != null) body.gate_max_failure_rate = Number(gateMaxFailureRate);
    if (gateMinSuccessRate != null) body.gate_min_success_rate = Number(gateMinSuccessRate);
    if (notes != null) body.notes = String(notes);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/canary-rollout`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route canary rollout upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style canary stop (`POST /gateway/routes/{routePolicyId}/canary-rollout/stop`). */
  async stopRouteCanaryRollout(routePolicyId, { requestTag, notes } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const body = {};
    if (notes != null) body.notes = String(notes);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/canary-rollout/stop${query ? `?${query}` : ""}`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route canary stop failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style canary promote (`POST /gateway/routes/{routePolicyId}/canary-rollout/promote`). */
  async promoteRouteCanaryRollout(routePolicyId, { requestTag, notes } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const body = {};
    if (notes != null) body.notes = String(notes);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/canary-rollout/promote${query ? `?${query}` : ""}`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route canary promote failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route optimize (`POST /gateway/routes/{routePolicyId}/optimize`). */
  async optimizeRoute(routePolicyId, { optimizeFor = "balanced", environment = "prod" } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const goal = String(optimizeFor || "balanced").trim().toLowerCase() || "balanced";
    if (!["balanced", "cost", "latency"].includes(goal)) {
      throw new Error("optimizeFor must be one of: balanced, cost, latency");
    }
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/optimize`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify({
          optimize_for: goal,
          environment: String(environment || "prod").trim() || "prod",
        }),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route optimize failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style governed fallback execute (`POST /gateway/routes/{routePolicyId}/execute-fallback`). */
  async executeRouteFallback(
    routePolicyId,
    {
      tenantId,
      agentId,
      environment = "prod",
      requestTag,
      requestedRegion,
      requestPriority = "normal",
      modelName,
      sessionId = "gateway-session",
      ownerScope,
      ownerScopeType,
      ownerScopeId,
      endpointFamily = "responses",
      inputTokens = 100,
      outputTokens = 50,
      simulatedInputText,
      simulatedOutputText,
      currency = "USD",
      simulateFailProviderIds = "[]",
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const tid = String(tenantId || "").trim();
    if (!tid) throw new Error("tenantId is required");
    const aid = String(agentId || "").trim();
    if (!aid) throw new Error("agentId is required");
    const body = {
      tenant_id: tid,
      agent_id: aid,
      environment: String(environment || "prod").trim() || "prod",
      request_priority: String(requestPriority || "normal").trim() || "normal",
      session_id: String(sessionId || "gateway-session").trim() || "gateway-session",
      endpoint_family: String(endpointFamily || "responses").trim() || "responses",
      input_tokens: Math.max(0, Number(inputTokens) || 0),
      output_tokens: Math.max(0, Number(outputTokens) || 0),
      currency: String(currency || "USD").trim() || "USD",
      simulate_fail_provider_ids: String(simulateFailProviderIds || "[]"),
    };
    if (requestTag) body.request_tag = String(requestTag).trim();
    if (requestedRegion) body.requested_region = String(requestedRegion).trim();
    if (modelName) body.model_name = String(modelName).trim();
    if (ownerScope) body.owner_scope = String(ownerScope).trim();
    if (ownerScopeType) body.owner_scope_type = String(ownerScopeType).trim();
    if (ownerScopeId) body.owner_scope_id = String(ownerScopeId).trim();
    if (simulatedInputText != null) body.simulated_input_text = String(simulatedInputText);
    if (simulatedOutputText != null) body.simulated_output_text = String(simulatedOutputText);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/execute-fallback`,
      {
        method: "POST",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route fallback execute failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route fallbacks (`GET /gateway/routes/{routePolicyId}/fallbacks`). */
  async getRouteFallbacks(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/fallbacks${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route fallbacks failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style route fallbacks upsert (`PUT /gateway/routes/{routePolicyId}/fallbacks`). */
  async upsertRouteFallbacks(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      priorityOrder = "[]",
      globalTimeoutMs = 4500,
      maxFallbackHops = 2,
      healthCheckEnabled = false,
      budgetLimitCents,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      priority_order: String(priorityOrder == null ? "[]" : priorityOrder),
      global_timeout_ms: Math.max(100, Math.min(Number(globalTimeoutMs) || 4500, 120000)),
      max_fallback_hops: Math.max(0, Math.min(Number(maxFallbackHops) || 0, 10)),
      health_check_enabled: Boolean(healthCheckEnabled),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (budgetLimitCents != null) body.budget_limit_cents = Number(budgetLimitCents);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/fallbacks`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route fallbacks upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style pre-call filters (`GET /gateway/routes/{routePolicyId}/pre-call-filters`). */
  async getRoutePreCallFilters(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/pre-call-filters${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route pre-call filters failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style pre-call filters upsert (`PUT /gateway/routes/{routePolicyId}/pre-call-filters`). */
  async upsertRoutePreCallFilters(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      allowedRegions = "[]",
      minContextWindowTokens,
      maxContextWindowTokens,
      enforce = true,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      allowed_regions: String(allowedRegions == null ? "[]" : allowedRegions),
      enforce: Boolean(enforce),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (minContextWindowTokens != null) body.min_context_window_tokens = Number(minContextWindowTokens);
    if (maxContextWindowTokens != null) body.max_context_window_tokens = Number(maxContextWindowTokens);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/pre-call-filters`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route pre-call filters upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style input data policy (`GET /gateway/routes/{routePolicyId}/input-data-policy`). */
  async getRouteInputDataPolicy(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/input-data-policy${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route input data policy failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style input data policy upsert (`PUT /gateway/routes/{routePolicyId}/input-data-policy`). */
  async upsertRouteInputDataPolicy(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      policyMode = "warn",
      dataClasses = "[]",
      blockPatterns = "[]",
      maskToken = "[REDACTED]",
      enforce = true,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      policy_mode: String(policyMode || "warn").trim() || "warn",
      data_classes: String(dataClasses == null ? "[]" : dataClasses),
      block_patterns: String(blockPatterns == null ? "[]" : blockPatterns),
      mask_token: String(maskToken || "[REDACTED]"),
      enforce: Boolean(enforce),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/input-data-policy`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route input data policy upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style output guardrails (`GET /gateway/routes/{routePolicyId}/output-guardrails`). */
  async getRouteOutputGuardrails(routePolicyId, { requestTag } = {}) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const params = new URLSearchParams();
    if (requestTag) params.set("request_tag", String(requestTag).trim());
    const query = params.toString();
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/output-guardrails${query ? `?${query}` : ""}`,
      { headers: this._headers() },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route output guardrails failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey-style output guardrails upsert (`PUT /gateway/routes/{routePolicyId}/output-guardrails`). */
  async upsertRouteOutputGuardrails(
    routePolicyId,
    {
      tenantId,
      environment = "prod",
      requestTag,
      policyMode = "warn",
      blockedPhrases = "[]",
      redactPhrases = "[]",
      maxOutputTokens,
      enforce = true,
    } = {},
  ) {
    const id = String(routePolicyId || "").trim();
    if (!id) throw new Error("routePolicyId is required");
    const body = {
      tenant_id: String(tenantId || "").trim(),
      environment: String(environment || "prod").trim() || "prod",
      policy_mode: String(policyMode || "warn").trim() || "warn",
      blocked_phrases: String(blockedPhrases == null ? "[]" : blockedPhrases),
      redact_phrases: String(redactPhrases == null ? "[]" : redactPhrases),
      enforce: Boolean(enforce),
    };
    if (requestTag != null) body.request_tag = String(requestTag).trim() || null;
    if (maxOutputTokens != null) body.max_output_tokens = Number(maxOutputTokens);
    const response = await this.fetchImpl(
      `${this.baseUrl}/gateway/routes/${encodeURIComponent(id)}/output-guardrails`,
      {
        method: "PUT",
        headers: { ...this._headers(), "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
    );
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Route output guardrails upsert failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style cache policy list (`GET /gateway/cache/policies`). */
  async listCachePolicies({ scope, status, limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (scope) params.set("scope", String(scope).trim());
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/policies?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache policies list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey/Helicone-style cache policy create (`POST /gateway/cache/policies`). */
  async createCachePolicy({
    scope,
    ttlSeconds = 60,
    keyStrategy = "default",
    invalidationStrategy = "ttl",
    privacyMode = "standard",
    privacyScope = "tenant",
    nonCacheDataClasses = "[]",
    cacheMode = "exact",
    similarityThreshold = 0.9,
  } = {}) {
    const body = {
      scope: String(scope || "").trim(),
      ttl_seconds: Math.max(1, Math.min(Number(ttlSeconds) || 60, 86400)),
      key_strategy: String(keyStrategy || "default").trim() || "default",
      invalidation_strategy: String(invalidationStrategy || "ttl").trim() || "ttl",
      privacy_mode: String(privacyMode || "standard").trim() || "standard",
      privacy_scope: String(privacyScope || "tenant").trim() || "tenant",
      non_cache_data_classes: String(nonCacheDataClasses == null ? "[]" : nonCacheDataClasses),
      cache_mode: String(cacheMode || "exact").trim() || "exact",
      similarity_threshold: Math.max(0, Math.min(Number(similarityThreshold) || 0, 1)),
    };
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/policies`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache policy create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style cache invalidate (`POST /gateway/cache/delete`). */
  async invalidateCache({ scope, cacheKeys = [], reason, activeOnly = true } = {}) {
    const body = {
      cache_keys: (Array.isArray(cacheKeys) ? cacheKeys : [])
        .map((item) => String(item || "").trim())
        .filter(Boolean),
      active_only: Boolean(activeOnly),
    };
    if (scope != null) body.scope = String(scope).trim() || null;
    if (reason != null) body.reason = String(reason);
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/delete`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache invalidate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style budget policy list (`GET /cost/budgets`). */
  async listBudgetPolicies({ status = "active", scopeType, scopeId, limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (status != null) params.set("status", String(status).trim());
    if (scopeType) params.set("scope_type", String(scopeType).trim());
    if (scopeId) params.set("scope_id", String(scopeId).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/cost/budgets?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Budget policies list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Helicone-style budget policy create (`POST /cost/budgets`). */
  async createBudgetPolicy({
    scopeType,
    scopeId,
    budgetAmountCents,
    windowType = "daily",
    softLimitPercent = 80,
    hardLimitPercent = 100,
    actionOnSoftLimit = "warn",
    actionOnHardLimit = "block",
    resetTimezone = "UTC",
    resetHourLocal = 0,
    temporaryIncreaseCents = 0,
    softAlertEnabled = true,
    rateLimitTpm,
    rateLimitRpm,
    sessionIterationCap,
    sessionBudgetCents,
  } = {}) {
    const body = {
      scope_type: String(scopeType || "").trim(),
      scope_id: String(scopeId || "").trim(),
      budget_amount_cents: Math.max(0, Number(budgetAmountCents) || 0),
      window_type: String(windowType || "daily").trim() || "daily",
      soft_limit_percent: Math.max(1, Math.min(Number(softLimitPercent) || 80, 100)),
      hard_limit_percent: Math.max(1, Math.min(Number(hardLimitPercent) || 100, 100)),
      action_on_soft_limit: String(actionOnSoftLimit || "warn").trim() || "warn",
      action_on_hard_limit: String(actionOnHardLimit || "block").trim() || "block",
      reset_timezone: String(resetTimezone || "UTC").trim() || "UTC",
      reset_hour_local: Math.max(0, Math.min(Number(resetHourLocal) || 0, 23)),
      temporary_increase_cents: Math.max(0, Number(temporaryIncreaseCents) || 0),
      soft_alert_enabled: Boolean(softAlertEnabled),
    };
    if (rateLimitTpm != null) body.rate_limit_tpm = Number(rateLimitTpm);
    if (rateLimitRpm != null) body.rate_limit_rpm = Number(rateLimitRpm);
    if (sessionIterationCap != null) body.session_iteration_cap = Number(sessionIterationCap);
    if (sessionBudgetCents != null) body.session_budget_cents = Number(sessionBudgetCents);
    const response = await this.fetchImpl(`${this.baseUrl}/cost/budgets`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Budget policy create failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style budget policy update (`PUT /cost/budgets/{budgetPolicyId}`). */
  async updateBudgetPolicy(
    budgetPolicyId,
    {
      scopeType,
      scopeId,
      budgetAmountCents,
      windowType = "daily",
      softLimitPercent = 80,
      hardLimitPercent = 100,
      actionOnSoftLimit = "warn",
      actionOnHardLimit = "block",
      resetTimezone = "UTC",
      resetHourLocal = 0,
      temporaryIncreaseCents = 0,
      softAlertEnabled = true,
      rateLimitTpm,
      rateLimitRpm,
      sessionIterationCap,
      sessionBudgetCents,
    } = {},
  ) {
    const id = String(budgetPolicyId || "").trim();
    if (!id) throw new Error("budgetPolicyId is required");
    const body = {
      scope_type: String(scopeType || "").trim(),
      scope_id: String(scopeId || "").trim(),
      budget_amount_cents: Math.max(0, Number(budgetAmountCents) || 0),
      window_type: String(windowType || "daily").trim() || "daily",
      soft_limit_percent: Math.max(1, Math.min(Number(softLimitPercent) || 80, 100)),
      hard_limit_percent: Math.max(1, Math.min(Number(hardLimitPercent) || 100, 100)),
      action_on_soft_limit: String(actionOnSoftLimit || "warn").trim() || "warn",
      action_on_hard_limit: String(actionOnHardLimit || "block").trim() || "block",
      reset_timezone: String(resetTimezone || "UTC").trim() || "UTC",
      reset_hour_local: Math.max(0, Math.min(Number(resetHourLocal) || 0, 23)),
      temporary_increase_cents: Math.max(0, Number(temporaryIncreaseCents) || 0),
      soft_alert_enabled: Boolean(softAlertEnabled),
    };
    if (rateLimitTpm != null) body.rate_limit_tpm = Number(rateLimitTpm);
    if (rateLimitRpm != null) body.rate_limit_rpm = Number(rateLimitRpm);
    if (sessionIterationCap != null) body.session_iteration_cap = Number(sessionIterationCap);
    if (sessionBudgetCents != null) body.session_budget_cents = Number(sessionBudgetCents);
    const response = await this.fetchImpl(`${this.baseUrl}/cost/budgets/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Budget policy update failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style budget policy delete (`DELETE /cost/budgets/{budgetPolicyId}`). */
  async deleteBudgetPolicy(budgetPolicyId) {
    const id = String(budgetPolicyId || "").trim();
    if (!id) throw new Error("budgetPolicyId is required");
    const response = await this.fetchImpl(`${this.baseUrl}/cost/budgets/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Budget policy delete failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Helicone-style budget policy evaluate (`POST /cost/policies/evaluate`). */
  async evaluateBudgetPolicy({ scopeType, scopeId, windowType = "daily" } = {}) {
    const body = {
      scope_type: String(scopeType || "").trim(),
      scope_id: String(scopeId || "").trim(),
      window_type: String(windowType || "daily").trim() || "daily",
    };
    const response = await this.fetchImpl(`${this.baseUrl}/cost/policies/evaluate`, {
      method: "POST",
      headers: { ...this._headers(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Budget policy evaluate failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style cache stats (`GET /gateway/cache/stats`). */
  async getCacheStats() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/stats`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache stats failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style cache health (`GET /gateway/cache/health`). */
  async getCacheHealth() {
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/health`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache health failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    return payload;
  }

  /** Portkey/Helicone-style cache entry metadata (`GET /gateway/cache/entries`; no bodies). */
  async listCacheEntries({ tenantId, cachePolicyId, status = "active", limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (cachePolicyId) params.set("cache_policy_id", String(cachePolicyId).trim());
    if (status) params.set("status", String(status).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/entries?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache entries list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Portkey/Helicone-style cache decisions (`GET /gateway/cache/decisions`). */
  async listCacheDecisions({ decision, tenantId, traceId, cachePolicyId, limit = 100, offset = 0 } = {}) {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(Number(limit) || 100, 500))),
      offset: String(Math.max(0, Number(offset) || 0)),
    });
    if (decision) params.set("decision", String(decision).trim());
    if (tenantId) params.set("tenant_id", String(tenantId).trim());
    if (traceId) params.set("trace_id", String(traceId).trim());
    if (cachePolicyId) params.set("cache_policy_id", String(cachePolicyId).trim());
    const response = await this.fetchImpl(`${this.baseUrl}/gateway/cache/decisions?${params.toString()}`, {
      headers: this._headers(),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(
        `Cache decisions list failed (${response.status}): ${typeof detail === "string" ? detail : JSON.stringify(detail)}`,
      );
    }
    if (Array.isArray(payload)) return payload.filter((item) => item && typeof item === "object");
    const items = payload?.data || payload?.items || [];
    return Array.isArray(items) ? items.filter((item) => item && typeof item === "object") : [];
  }

  /** Price a token volume via gateway catalog (Helicone-class cost accuracy). */
  async estimateCostCents({
    modelName,
    endpointFamily = "chat.completions",
    inputTokens = 0,
    outputTokens = 0,
    providerType = "openai",
  }) {
    const response = await this.fetchImpl(`${this.baseUrl}/cost/pricing/calculate`, {
      method: "POST",
      headers: this._headers(),
      body: JSON.stringify({
        model_name: modelName,
        provider_type: providerType,
        endpoint_family: endpointFamily,
        input_tokens: Math.max(0, Number(inputTokens) || 0),
        output_tokens: Math.max(0, Number(outputTokens) || 0),
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) return 0;
    return Math.max(0, Number(payload.estimated_cost_cents || 0));
  }
}

/**
 * Gateway-native lightweight instrumenter: stamps session/user/property headers
 * onto outbound fetch calls without a separate proxy agent or external SaaS.
 *
 * @param {object} [options]
 * @param {string} [options.sessionId]
 * @param {string} [options.user]
 * @param {Record<string, unknown>} [options.properties]
 * @param {typeof fetch} [options.fetchImpl]
 * @returns {typeof fetch}
 */
export function createGatewayFetchInstrumenter(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is required (Node 18+ or provide fetchImpl)");
  }
  const sessionId = options.sessionId ? String(options.sessionId) : "";
  const user = options.user ? String(options.user) : "";
  const properties =
    options.properties && typeof options.properties === "object" && !Array.isArray(options.properties)
      ? options.properties
      : {};

  return async function instrumentedFetch(input, init = {}) {
    const headers = new Headers((init && init.headers) || {});
    if (sessionId) headers.set("x-session-id", sessionId);
    if (user) headers.set("x-user", user);
    for (const [key, value] of Object.entries(properties)) {
      if (!key) continue;
      headers.set(`x-property-${String(key).slice(0, 64)}`, String(value).slice(0, 256));
    }
    return fetchImpl(input, { ...init, headers });
  };
}

export default AgentHubGateway;
