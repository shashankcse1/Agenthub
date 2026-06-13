/**
 * Flow Orchestration catalog — single place to register node types, labels, and studio UX metadata.
 * Add new widgets here; Studio UI picks them up automatically from the API catalog + this registry.
 */
(function initOrchestrationRegistry(global) {
  const FLOW_START_ID = "__flow_start__";
  const FLOW_END_ID = "__flow_end__";

  const TRIGGER_VISUAL = {
    manual: { icon: "▶", color: "#10b981", label: "Manual run", hint: "Run on demand from Run now" },
    schedule: { icon: "⏱", color: "#14b8a6", label: "On a schedule", hint: "Runs automatically on a cron" },
    webhook: { icon: "⚡", color: "#0ea5e9", label: "Webhook event", hint: "Starts when an HTTP webhook fires" },
  };

  const NODE_VISUAL = {
    llm_chat: {
      icon: "AI",
      color: "#6366f1",
      category: "ai",
      label: "Ask AI",
      help: "Send a prompt to a gateway model and use the response in later steps.",
      keywords: ["llm", "chat", "model", "gpt", "ai"],
    },
    mcp_tool: {
      icon: "⚙",
      color: "#8b5cf6",
      category: "ai",
      label: "Tool call",
      help: "Invoke a registered MCP tool from the gateway.",
      keywords: ["mcp", "tool", "agent"],
    },
    http_request: {
      icon: "↗",
      color: "#0ea5e9",
      category: "integration",
      label: "HTTP",
      help: "Call an external API on an allowlisted host. Auth uses credential bindings — never paste tokens in headers.",
      keywords: ["http", "api", "rest", "webhook", "email"],
    },
    condition: {
      icon: "?",
      color: "#f59e0b",
      category: "logic",
      label: "If / else",
      help: "Branch using a JSON path from a prior HTTP, LLM, or MCP step output.",
      keywords: ["if", "branch", "logic", "condition", "json", "path"],
    },
    schedule_trigger: {
      icon: "⏱",
      color: "#10b981",
      category: "trigger",
      label: "Schedule",
      help: "Use Start → On a schedule instead of this widget.",
      keywords: ["cron", "schedule"],
    },
    webhook_trigger: {
      icon: "⚡",
      color: "#14b8a6",
      category: "trigger",
      label: "Webhook",
      help: "Use Start → Webhook event instead of this widget.",
      keywords: ["webhook", "event"],
    },
    memory_read: {
      icon: "↓",
      color: "#64748b",
      category: "data",
      label: "Read memory",
      help: "Load stored context for this scope before the next step.",
      keywords: ["memory", "read", "context"],
    },
    memory_write: {
      icon: "↑",
      color: "#64748b",
      category: "data",
      label: "Save memory",
      help: "Persist output or context for later runs.",
      keywords: ["memory", "write", "store"],
    },
    vector_query: {
      icon: "🔍",
      color: "#8b5cf6",
      category: "data",
      label: "Vector search",
      help: "Semantic search against a vector database from the gateway registry.",
      keywords: ["vector", "rag", "search", "embedding", "qdrant", "pinecone", "pgvector"],
    },
    vector_ingest: {
      icon: "📥",
      color: "#8b5cf6",
      category: "data",
      label: "Vector ingest",
      help: "Add documents to a vector database configured in Routing & Gateway.",
      keywords: ["vector", "rag", "ingest", "embed", "index"],
    },
    embedding_create: {
      icon: "⊞",
      color: "#6366f1",
      category: "ai",
      label: "Create embedding",
      help: "Generate embeddings via gateway embedding API for downstream RAG or search steps.",
      keywords: ["embedding", "vector", "embed", "openai", "litellm"],
    },
    rag_query: {
      icon: "📚",
      color: "#8b5cf6",
      category: "data",
      label: "RAG query",
      help: "Retrieval-augmented query against a gateway vector store with governed bindings.",
      keywords: ["rag", "retrieval", "vector", "search", "qdrant", "pinecone"],
    },
    wait_delay: {
      icon: "⏸",
      color: "#06b6d4",
      category: "control",
      label: "Wait / delay",
      help: "Pause the flow for a configured number of seconds before continuing.",
      keywords: ["wait", "delay", "sleep", "pause", "timer"],
    },
    guardrail_evaluate: {
      icon: "🛡",
      color: "#ef4444",
      category: "governance",
      label: "Guardrail check",
      help: "Evaluate gateway guardrail policy against step output before proceeding.",
      keywords: ["guardrail", "policy", "safety", "compliance", "key"],
    },
    email_send: {
      icon: "✉",
      color: "#f97316",
      category: "notify",
      label: "Send email",
      help: "Send email via a notification channel from the gateway registry (Phase 1 simulated).",
      keywords: ["email", "notify", "sendgrid", "smtp", "alert", "mail"],
    },
    sms_send: {
      icon: "📱",
      color: "#f97316",
      category: "notify",
      label: "Send SMS",
      help: "Send SMS via a notification channel from the gateway registry (Phase 1 simulated).",
      keywords: ["sms", "text", "twilio", "notify", "alert", "phone"],
    },
    human_approval: {
      icon: "✓",
      color: "#ef4444",
      category: "governance",
      label: "Approval",
      help: "Pause until a human approver signs off — role can be static or read from prior step JSON.",
      keywords: ["approval", "human", "review", "ciso", "approver"],
    },
    parallel_fork: {
      icon: "⑂",
      color: "#06b6d4",
      category: "control",
      label: "Parallel fork",
      help: "Split into branches that run at the same time.",
      keywords: ["parallel", "fork", "split", "branch"],
    },
    parallel_join: {
      icon: "⑃",
      color: "#06b6d4",
      category: "control",
      label: "Parallel join",
      help: "Merge parallel branches before continuing.",
      keywords: ["parallel", "join", "merge"],
    },
  };

  const PALETTE_CATEGORIES = [
    { id: "all", label: "All", hint: "Every available widget" },
    { id: "ai", label: "AI", hint: "Models and tools" },
    { id: "integration", label: "Connect", hint: "External APIs" },
    { id: "data", label: "Memory & vectors", hint: "Memory, RAG, and vector DB" },
    { id: "notify", label: "Notify", hint: "Email and SMS alerts" },
    { id: "logic", label: "Logic", hint: "Branch and decide" },
    { id: "governance", label: "Governance", hint: "Human review gates" },
    { id: "control", label: "Control", hint: "Parallel fork/join and timing" },
  ];

  const CATEGORY_BADGE_LABELS = {
    ai: "AI",
    integration: "Connect",
    data: "Data",
    notify: "Notify",
    logic: "Logic",
    governance: "Gov",
    control: "Control",
    trigger: "Trigger",
  };

  /** Declarative inspector field groups — extend when adding node types. */
  const INSPECTOR_FIELD_SCHEMA = {
    llm_chat: {
      groups: [
        {
          legend: "Model & prompt",
          fields: [
            "model_id",
            "prompt_template",
            "binding_id",
            "temperature",
            "route_id",
            "prompt_registry_id",
            "max_tokens",
            "response_format",
            "cache_mode",
          ],
          required: ["model_id", "prompt_template"],
        },
      ],
    },
    mcp_tool: {
      groups: [{ legend: "Tool invocation", fields: ["server_id", "tool_name", "arguments_json", "binding_id"], required: ["server_id", "tool_name"] }],
    },
    http_request: {
      groups: [
        { legend: "Request", fields: ["url", "method", "headers_json", "body_template"], required: ["url", "method"] },
        { legend: "Authentication", custom: "http_auth" },
      ],
    },
    condition: {
      groups: [{ legend: "Response condition", custom: "condition_builder" }],
    },
    human_approval: {
      groups: [
        { legend: "Approval gate", fields: ["approval_title", "instructions"], required: ["approval_title"] },
        { legend: "Approver selection", custom: "approver_picker" },
      ],
    },
    vector_query: {
      groups: [{ legend: "Vector search", custom: "vector_store", required: ["store_id", "query"] }],
    },
    vector_ingest: {
      groups: [{ legend: "Vector ingest", custom: "vector_store", required: ["store_id", "content_template"] }],
    },
    embedding_create: {
      groups: [{ legend: "Embedding", fields: ["model_id", "input_template", "binding_id"], required: ["model_id", "input_template"] }],
    },
    rag_query: {
      groups: [{ legend: "RAG query", custom: "vector_store", required: ["store_id", "query_template"] }],
    },
    wait_delay: {
      groups: [{ legend: "Timing", fields: ["delay_seconds"], required: ["delay_seconds"] }],
    },
    guardrail_evaluate: {
      groups: [{ legend: "Guardrail", fields: ["key_id", "input_template", "guardrail_policy_id"], required: ["key_id", "input_template"] }],
    },
    email_send: {
      groups: [{ legend: "Email notification", custom: "notification_channel", required: ["channel_id", "to_template", "subject_template", "body_template"] }],
    },
    sms_send: {
      groups: [{ legend: "SMS notification", custom: "notification_channel", required: ["channel_id", "to_template", "body_template"] }],
    },
    memory_read: {
      groups: [{ legend: "Memory read", fields: ["scope_type", "scope_id", "memory_tier", "label_filter"], required: ["scope_type", "scope_id", "memory_tier"] }],
    },
    memory_write: {
      groups: [{ legend: "Memory write", fields: ["scope_type", "scope_id", "memory_tier", "content_template", "label"], required: ["scope_type", "scope_id", "memory_tier", "content_template"] }],
    },
  };

  const JSON_PATH_PRESETS = [
    { path: "$.status", label: "HTTP status", sample: '{"status":"ok"}' },
    { path: "$.data.approved", label: "Nested boolean", sample: '{"data":{"approved":true}}' },
    { path: "$.choices[0].message.content", label: "LLM content", sample: '{"choices":[{"message":{"content":"hello"}}]}' },
    { path: "$.reviewer.user_id", label: "Reviewer ID", sample: '{"reviewer":{"user_id":"user-42","role":"Security Approver"}}' },
    { path: "$.error.code", label: "Error code", sample: '{"error":{"code":"rate_limited"}}' },
  ];

  const CONFIG_FIELDS = {
    model_id: { label: "Model", placeholder: "e.g. gpt-4o-mini", wide: false },
    prompt_template: { label: "Prompt", placeholder: "Describe what the model should do…", wide: true, multiline: true },
    binding_id: { label: "Credential binding", placeholder: "Optional secret binding ID" },
    temperature: { label: "Temperature", placeholder: "0.0 – 1.0" },
    route_id: { label: "Gateway route", placeholder: "Optional route policy ID" },
    prompt_registry_id: { label: "Prompt registry", placeholder: "Governed prompt registry ID" },
    max_tokens: { label: "Max tokens", placeholder: "e.g. 1024" },
    response_format: { label: "Response format", placeholder: "text or json_object" },
    cache_mode: { label: "Cache mode", placeholder: "inherit, bypass, or force" },
    input_template: { label: "Input template", placeholder: "Text to embed or evaluate…", wide: true, multiline: true },
    query_template: { label: "Query template", placeholder: "RAG question or keywords…", wide: true, multiline: true },
    delay_seconds: { label: "Delay (seconds)", placeholder: "1 – 3600" },
    key_id: { label: "Gateway key", placeholder: "Key ID for guardrail evaluation" },
    guardrail_policy_id: { label: "Guardrail policy", placeholder: "Optional policy ID override" },
    server_id: { label: "MCP server", placeholder: "Gateway MCP server ID" },
    tool_name: { label: "Tool name", placeholder: "Tool to invoke" },
    arguments_json: { label: "Tool arguments (JSON)", placeholder: "{}", wide: true, multiline: true },
    url: { label: "URL", placeholder: "https://api.example.com/…", wide: true },
    method: { label: "HTTP method", placeholder: "GET, POST, …" },
    auth_type: { label: "Authentication", placeholder: "none, bearer, basic, …" },
    auth_binding_id: { label: "Auth credential binding", placeholder: "Select a platform credential binding" },
    auth_header_name: { label: "API key header name", placeholder: "e.g. X-API-Key or Authorization" },
    headers_json: { label: "Headers (JSON)", placeholder: "{}", wide: true, multiline: true },
    body_template: { label: "Body template", placeholder: "Request body…", wide: true, multiline: true },
    expression: { label: "Condition expression", placeholder: "Auto-built from JSON path or enter manually", wide: true, multiline: true },
    source_node_id: { label: "Source step", placeholder: "Prior step node id" },
    json_path: { label: "JSON path", placeholder: "e.g. $.status or $.data.approver_id" },
    operator: { label: "Operator", placeholder: "==, !=, >, <, contains, exists" },
    compare_value: { label: "Compare value", placeholder: "Expected value (omit for exists)" },
    true_branch: { label: "When true", placeholder: "Next step hint" },
    false_branch: { label: "When false", placeholder: "Alternate path hint" },
    scope_type: { label: "Scope type", placeholder: "session, conversation, agent, or global" },
    scope_id: { label: "Scope ID", placeholder: "Session id, agent id, or global key" },
    memory_tier: { label: "Memory tier", placeholder: "short_term or long_term" },
    label_filter: { label: "Label filter", placeholder: "Optional label" },
    content_template: { label: "Content to save", placeholder: "Text or template…", wide: true, multiline: true },
    label: { label: "Memory label", placeholder: "Optional label" },
    store_id: { label: "Vector store", placeholder: "Select from gateway registry" },
    query: { label: "Search query", placeholder: "Question or keywords…", wide: true, multiline: true },
    top_k: { label: "Top K results", placeholder: "8" },
    document_id: { label: "Document ID", placeholder: "Optional — auto-generated if empty" },
    channel_id: { label: "Notification channel", placeholder: "Select from gateway registry" },
    to_template: { label: "Recipient (template)", placeholder: "ops@example.com or {{steps['prior'].output.email}}", wide: true },
    subject_template: { label: "Subject (template)", placeholder: "Alert: workflow complete", wide: true },
    from_override: { label: "From override (optional)", placeholder: "Override channel default sender" },
    approval_title: { label: "Approval title", placeholder: "What needs review?", wide: true },
    required_role: { label: "Required role (static)", placeholder: "e.g. Security Approver" },
    instructions: { label: "Instructions for approver", placeholder: "Context for the reviewer…", wide: true, multiline: true },
    approver_source: { label: "Approver source", placeholder: "static or json_path" },
    approver_role_json_path: { label: "Approver role JSON path", placeholder: "e.g. $.reviewer.role" },
    approver_id_json_path: { label: "Approver ID JSON path", placeholder: "e.g. $.reviewer.user_id" },
  };

  const STUDIO_PHASES = [
    { id: "create", label: "Create", action: "Pick a template or blank flow" },
    { id: "build", label: "Build", action: "Add widgets or parallel branches between Start and End" },
    { id: "save", label: "Save", action: "Name your flow and save" },
    { id: "validate", label: "Check", action: "Validate policy and schema" },
    { id: "run", label: "Run", action: "Test or run in target environment" },
  ];

  const ORCHESTRATION_MAX_PARALLEL_BRANCHES = 5;
  const ORCHESTRATION_MIN_PARALLEL_BRANCHES = 2;

  /** How prior-step data is referenced in templates, conditions, and approvals. */
  const DATA_MAPPING_FORMAT = {
    template: {
      label: "Template fields",
      description: "Use in prompt, body, email, memory, RAG, and HTTP body templates.",
      syntax: "{{steps['NODE_ID'].output.FIELD}}",
      nested: "{{steps['NODE_ID'].output.data.email}}",
      example: "{{steps['node-abc123'].output.message}}",
    },
    jsonPath: {
      label: "If / else conditions",
      description: "Built automatically in the condition widget, or edit in Advanced JSON.",
      syntax: "jsonPath(steps['NODE_ID'].output, '$.path')",
      example: "jsonPath(steps['node-http1'].output, '$.status') == 'ok'",
    },
    approver: {
      label: "Human approval (JSON path)",
      description: "Pick a prior step, then set approver_role_json_path / approver_id_json_path.",
      syntax: "$.reviewer.user_id",
      example: "Source step → $.data.approver_id",
    },
    audit: {
      label: "Audit & trace",
      description: "Each run stores step_results_json with node_id, output, and trace_id for Observability.",
      syntax: "steps['NODE_ID'].output",
      example: "Recent runs → Detail → step_results_json",
    },
  };

  /** Example output shapes per node type (Phase 1 stub / Phase 2 live contract). */
  const NODE_OUTPUT_EXAMPLES = {
    llm_chat: {
      simulated: true,
      model_id: "gpt-4o-mini",
      message: "Assistant reply text…",
      choices: [{ message: { content: "Hello" } }],
    },
    http_request: {
      simulated: true,
      status: 200,
      data: { approved: true, email: "ops@example.com" },
    },
    mcp_tool: { simulated: true, server_id: "mcp-1", tool_name: "search", result: {} },
    condition: { simulated: true, matched: true, expression: "…" },
    memory_read: { simulated: true, scope_type: "session", records: [] },
    memory_write: { simulated: true, scope_type: "session", written: true },
    vector_query: { simulated: true, store_id: "vs-1", hits: [{ score: 0.92, text: "…" }] },
    vector_ingest: { simulated: true, store_id: "vs-1", document_id: "doc-1" },
    rag_query: { simulated: true, source: "rag_query", store_id: "vs-1", chunks: [] },
    embedding_create: { simulated: true, embedding_dims: 1536, model_id: "text-embedding-3-small" },
    email_send: { simulated: true, to: "…", subject: "…", sent: true },
    sms_send: { simulated: true, to: "+1…", sent: true },
    human_approval: { simulated: true, approved: true, approver_id: "user-42" },
    guardrail_evaluate: { simulated: true, passed: true, violations: [] },
    wait_delay: { simulated: true, delay_seconds: 5, waited: true },
  };

  const TEMPLATE_FIELD_HINTS = {
    llm_chat: ["prompt_template"],
    http_request: ["body_template"],
    memory_write: ["content_template"],
    vector_ingest: ["content_template"],
    vector_query: ["query"],
    rag_query: ["query_template"],
    embedding_create: ["input_template"],
    guardrail_evaluate: ["input_template"],
    email_send: ["to_template", "subject_template", "body_template"],
    sms_send: ["to_template", "body_template"],
  };

  function getDataMappingFormat() {
    return { ...DATA_MAPPING_FORMAT };
  }

  function getNodeOutputExample(nodeType) {
    const key = String(nodeType || "").trim();
    return NODE_OUTPUT_EXAMPLES[key] ? { ...NODE_OUTPUT_EXAMPLES[key] } : { output: "See run step_results_json" };
  }

  function getTemplateFieldsForNodeType(nodeType) {
    return TEMPLATE_FIELD_HINTS[String(nodeType || "")] || [];
  }

  const FLOW_TEMPLATES = [
    {
      id: "support",
      name: "Support triage",
      description: "AI review → human approval",
      trigger: "manual",
      steps: ["llm_chat", "human_approval"],
    },
    {
      id: "daily",
      name: "Daily report",
      description: "Scheduled AI summary → HTTP post",
      trigger: "schedule",
      steps: ["llm_chat", "http_request"],
    },
    {
      id: "webhook",
      name: "Webhook handler",
      description: "Branch on payload → AI response",
      trigger: "webhook",
      steps: ["condition", "llm_chat"],
    },
    {
      id: "rag",
      name: "RAG answer",
      description: "Retrieve context → AI response",
      trigger: "manual",
      steps: ["rag_query", "llm_chat"],
    },
  ];

  const ENV_LABELS = { dev: "Development", staging: "Staging", prod: "Production" };
  const TRIGGER_LABELS = { manual: "Manual run", schedule: "On a schedule", webhook: "Webhook" };
  const APPROVAL_LABELS = { pending: "Needs approval", approved: "Approved", rejected: "Rejected" };

  const TRIGGER_CONFIG_EXAMPLES = {
    manual: "{}",
    schedule: '{\n  "cron_expression": "0 9 * * *"\n}',
    webhook: '{\n  "webhook_path_ref": "your-webhook-path-ref"\n}',
  };

  function getNodeVisual(type) {
    return (
      NODE_VISUAL[type] || {
        icon: "?",
        color: "#64748b",
        category: "logic",
        label: type,
        help: "Configure this step in the panel on the right.",
        keywords: [],
      }
    );
  }

  function getConfigFieldMeta(field) {
    const meta = CONFIG_FIELDS[field];
    if (meta) return meta;
    const label = String(field || "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return { label, placeholder: field, wide: false, multiline: false };
  }

  function getInspectorSchema(nodeType) {
    return INSPECTOR_FIELD_SCHEMA[nodeType] || null;
  }

  function getCategoryBadgeLabel(category) {
    return CATEGORY_BADGE_LABELS[category] || category || "";
  }

  function getFallbackNodeTypes() {
    return Object.entries(NODE_VISUAL)
      .filter(([, visual]) => visual.category !== "trigger" && visual.category !== "control")
      .map(([type, visual]) => ({
        type,
        label: visual.label,
        description: visual.help || `Add a ${visual.label.toLowerCase()} step.`,
      }));
  }

  global.OrchestrationRegistry = {
    FLOW_START_ID,
    FLOW_END_ID,
    TRIGGER_VISUAL,
    NODE_VISUAL,
    PALETTE_CATEGORIES,
    CONFIG_FIELDS,
    STUDIO_PHASES,
    FLOW_TEMPLATES,
    ENV_LABELS,
    TRIGGER_LABELS,
    APPROVAL_LABELS,
    TRIGGER_CONFIG_EXAMPLES,
    ORCHESTRATION_MAX_PARALLEL_BRANCHES,
    ORCHESTRATION_MIN_PARALLEL_BRANCHES,
    CATEGORY_BADGE_LABELS,
    INSPECTOR_FIELD_SCHEMA,
    JSON_PATH_PRESETS,
    getNodeVisual,
    getConfigFieldMeta,
    getInspectorSchema,
    getCategoryBadgeLabel,
    getFallbackNodeTypes,
    DATA_MAPPING_FORMAT,
    NODE_OUTPUT_EXAMPLES,
    getDataMappingFormat,
    getNodeOutputExample,
    getTemplateFieldsForNodeType,
  };
})(window);
