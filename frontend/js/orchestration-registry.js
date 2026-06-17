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
      help: "Send email via a notification channel from the gateway registry (live delivery when executor enabled).",
      keywords: ["email", "notify", "sendgrid", "smtp", "alert", "mail"],
    },
    sms_send: {
      icon: "📱",
      color: "#f97316",
      category: "notify",
      label: "Send SMS",
      help: "Send SMS via a notification channel from the gateway registry (live delivery when executor enabled).",
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
    prompt_template: {
      label: "Prompt template",
      placeholder: "Summarize ticket {{steps['fetch-step'].output.ticket_id}} for the approver…",
      wide: true,
      multiline: true,
      helperText: "Input sent to the model. Reference prior steps with {{steps['NODE_ID'].output.field}}.",
      mappingCategory: "input",
    },
    binding_id: { label: "Credential binding", placeholder: "Optional secret binding ID" },
    temperature: { label: "Temperature", placeholder: "0.0 – 1.0" },
    route_id: { label: "Gateway route", placeholder: "Optional route policy ID" },
    prompt_registry_id: { label: "Prompt registry", placeholder: "Governed prompt registry ID" },
    max_tokens: { label: "Max tokens", placeholder: "e.g. 1024", inputType: "number" },
    response_format: {
      label: "Response format",
      type: "select",
      default: "",
      options: [
        { value: "", label: "Default (text)" },
        { value: "text", label: "Text" },
        { value: "json_object", label: "JSON object" },
      ],
      helperText: "Structured JSON output when set to JSON object.",
    },
    cache_mode: {
      label: "Cache mode",
      type: "select",
      default: "inherit",
      options: [
        { value: "inherit", label: "Inherit — follow gateway cache policy" },
        { value: "bypass", label: "Bypass — never read or write cache" },
        { value: "force", label: "Force — always attempt cache lookup" },
      ],
      helperText: "Controls semantic/exact cache for this LLM step (gateway policy applies when inherit).",
    },
    input_template: {
      label: "Input template",
      placeholder: "{{steps['prior'].output.message}}",
      wide: true,
      multiline: true,
      helperText: "Text passed into this step. Use {{steps['NODE_ID'].output.field}} from prior steps.",
      mappingCategory: "input",
    },
    query_template: {
      label: "Query template",
      placeholder: "What is the policy for {{steps['context'].output.topic}}?",
      wide: true,
      multiline: true,
      helperText: "RAG search query with optional template values from prior step output.",
      mappingCategory: "input",
    },
    delay_seconds: { label: "Delay (seconds)", placeholder: "1 – 3600" },
    key_id: { label: "Gateway key", placeholder: "Key ID for guardrail evaluation" },
    guardrail_policy_id: { label: "Guardrail policy", placeholder: "Optional policy ID override" },
    server_id: { label: "MCP server", placeholder: "Gateway MCP server ID" },
    tool_name: { label: "Tool name", placeholder: "Tool to invoke" },
    arguments_json: {
      label: "Tool arguments (JSON)",
      placeholder: '{"query":"{{steps[\'prior\'].output.search_term}}"}',
      wide: true,
      multiline: true,
      helperText: "JSON arguments for the MCP tool. String values may use step output templates.",
      mappingCategory: "json",
    },
    url: {
      label: "Request URL",
      placeholder: "https://api.example.com/users/{{steps['prior-step'].output.user_id}}",
      wide: true,
      helperText: "Path and query segments can include {{steps['NODE_ID'].output.field}} from prior steps.",
      mappingCategory: "url",
    },
    method: { label: "HTTP method", placeholder: "GET, POST, PUT, PATCH, DELETE" },
    auth_type: { label: "Authentication", placeholder: "none, bearer, basic, …" },
    auth_binding_id: { label: "Auth credential binding", placeholder: "Select a platform credential binding" },
    auth_header_name: { label: "API key header name", placeholder: "e.g. X-API-Key or Authorization" },
    headers_json: {
      label: "Headers (JSON)",
      placeholder: '{"Content-Type":"application/json","X-Request-Id":"{{steps[\'prior\'].output.trace_id}}"}',
      wide: true,
      multiline: true,
      helperText: "Valid JSON object. String values may use {{steps['NODE_ID'].output.field}} templates.",
      mappingCategory: "json",
    },
    body_template: {
      label: "Request body (JSON template)",
      placeholder: '{"ticket_id":"{{steps[\'llm-step\'].output.ticket_id}}","status":"open"}',
      wide: true,
      multiline: true,
      helperText: "Body content with {{steps['NODE_ID'].output.field}} placeholders — JSON for HTTP/MCP, plain text for email/SMS.",
      mappingCategory: "json",
    },
    expression: { label: "Condition expression", placeholder: "Auto-built from JSON path or enter manually", wide: true, multiline: true },
    source_node_id: { label: "Source step", placeholder: "Prior step node id" },
    json_path: { label: "JSON path", placeholder: "e.g. $.status or $.data.approver_id" },
    operator: { label: "Operator", placeholder: "==, !=, >, <, contains, exists" },
    compare_value: { label: "Compare value", placeholder: "Expected value (omit for exists)" },
    true_branch: { label: "When true", placeholder: "Next step hint" },
    false_branch: { label: "When false", placeholder: "Alternate path hint" },
    scope_type: { label: "Scope type", placeholder: "session, conversation, agent, or global" },
    scope_id: {
      label: "Scope ID",
      placeholder: "Run trace (auto), platform, {{input}}, or {{steps['NODE_ID'].output.field}}",
      helperText: "Memory partition key. Empty on write uses run trace_id; templates resolve from prior steps or run input.",
      mappingCategory: "scope",
    },
    memory_tier: { label: "Memory tier", placeholder: "short_term or long_term" },
    label_filter: { label: "Label filter", placeholder: "Optional label" },
    content_template: {
      label: "Content template",
      placeholder: "{{steps['llm-step'].output.message}}",
      wide: true,
      multiline: true,
      helperText: "Text or JSON to store. Templates resolve from prior step output at run time.",
      mappingCategory: "input",
    },
    label: { label: "Memory label", placeholder: "Optional label" },
    store_id: { label: "Vector store", placeholder: "Select from gateway registry" },
    query: {
      label: "Search query",
      placeholder: "{{steps['prior'].output.question}}",
      wide: true,
      multiline: true,
      helperText: "Vector search text. May include {{steps['NODE_ID'].output.field}} templates.",
      mappingCategory: "input",
    },
    top_k: { label: "Top K results", placeholder: "8" },
    document_id: { label: "Document ID", placeholder: "Optional — auto-generated if empty" },
    channel_id: { label: "Notification channel", placeholder: "Select from gateway registry" },
    to_template: {
      label: "Recipient (template)",
      placeholder: "{{steps['http-step'].output.data.email}}",
      wide: true,
      helperText: "Email or phone from a static value or prior step output template.",
      mappingCategory: "input",
    },
    subject_template: {
      label: "Subject (template)",
      placeholder: "Alert: ticket {{steps['prior'].output.ticket_id}}",
      wide: true,
      helperText: "Subject line with optional {{steps['NODE_ID'].output.field}} placeholders.",
      mappingCategory: "input",
    },
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
    url: {
      id: "url",
      label: "URL mapping",
      description: "Embed prior-step values in the request URL path or query string.",
      syntax: "https://api.example.com/resource/{{steps['NODE_ID'].output.id}}?status={{steps['NODE_ID'].output.status}}",
      example: "https://api.example.com/tickets/{{steps['fetch-ticket'].output.ticket_id}}?env=prod",
      where: "HTTP widget → Request URL field",
    },
    jsonBody: {
      id: "jsonBody",
      label: "JSON mapping",
      description: "Build JSON request bodies, headers, and MCP tool arguments with template placeholders.",
      syntax: '{"field":"{{steps[\'NODE_ID\'].output.field}}"}',
      nested: '{"user":{"email":"{{steps[\'http1\'].output.data.email}}"}}',
      example: '{"ticket_id":"{{steps[\'llm-step\'].output.ticket_id}}","priority":"high"}',
      where: "HTTP body, Headers JSON, MCP arguments, email/SMS body templates",
    },
    inputParams: {
      id: "inputParams",
      label: "Input parameters",
      description: "Values sent into this step — prompts, queries, recipients, memory content, embeddings.",
      syntax: "{{steps['NODE_ID'].output.FIELD}} or {{input}}",
      nested: "{{steps['NODE_ID'].output.choices[0].message.content}}",
      example: "Summarize: {{steps['fetch-step'].output.message}}",
      where: "Prompt, query, input/content/recipient/subject template fields; also {{input}} for run text",
    },
    outputParams: {
      id: "outputParams",
      label: "Output parameters",
      description: "After a step runs, downstream steps read these fields from steps['NODE_ID'].output.",
      syntax: "steps['NODE_ID'].output.FIELD",
      example: "jsonPath(steps['http1'].output, '$.data.approved')",
      where: "If/else conditions, approval JSON paths, later template fields",
    },
    scopeId: {
      id: "scopeId",
      label: "Scope ID mapping",
      description: "Gateway memory partition key — static value, run input, prior step output, or auto trace on write.",
      syntax: "{{steps['NODE_ID'].output.conversation_id}} or {{input}} or platform",
      example: "{{steps['webhook'].output.data.session_id}}",
      where: "Memory read / Memory write → Scope ID field",
    },
    jsonPath: {
      id: "jsonPath",
      label: "JSON path conditions",
      description: "Branch or pick approvers by reading a field from prior step JSON output.",
      syntax: "jsonPath(steps['NODE_ID'].output, '$.path')",
      example: "jsonPath(steps['http1'].output, '$.status') == 200",
      where: "If / else and Human approval widgets",
    },
    audit: {
      id: "audit",
      label: "Audit & trace",
      description: "Each run stores step_results_json with node_id, output, and trace_id for Observability.",
      syntax: "steps['NODE_ID'].output",
      example: "History → run detail → step_results_json",
      where: "History tab, Audit tab, Observability trace pivot",
    },
  };

  /** Inspector field groupings for variable mapping clarity. */
  const MAPPING_SECTIONS = {
    url: {
      legend: "URL mapping",
      intro: "Build the outbound URL with static segments and dynamic values from prior steps.",
      fields: ["url"],
    },
    json: {
      legend: "JSON mapping",
      intro: "Request bodies and JSON headers use template syntax inside valid JSON strings.",
      fields: ["body_template", "headers_json", "arguments_json"],
    },
    input: {
      legend: "Input parameters",
      intro: "These fields define what this step receives — map prior step output into prompts, queries, or recipients.",
      fields: [
        "prompt_template",
        "input_template",
        "query",
        "query_template",
        "content_template",
        "to_template",
        "subject_template",
      ],
    },
    scope: {
      legend: "Scope mapping",
      intro: "Gateway memory partition key — static value, run input, prior step output, or auto trace on write.",
      fields: ["scope_id"],
    },
  };

  /** Fields rendered by specialized inspectors (not generic mapping sections). */
  const INSPECTOR_CUSTOM_FIELDS = {
    condition: ["source_node_id", "json_path", "operator", "compare_value", "expression"],
    human_approval: [
      "approval_title",
      "instructions",
      "required_role",
      "approver_source",
      "source_node_id",
      "approver_role_json_path",
      "approver_id_json_path",
    ],
    http_request: ["auth_type", "auth_binding_id", "auth_header_name", "url", "method", "headers_json", "body_template"],
    vector_query: ["store_id", "query", "top_k"],
    vector_ingest: ["store_id", "content_template", "document_id"],
    rag_query: ["store_id", "query_template", "top_k"],
    memory_read: ["scope_type", "scope_id", "memory_tier", "label_filter"],
    memory_write: ["scope_type", "scope_id", "memory_tier", "content_template", "label"],
    email_send: ["channel_id", "to_template", "subject_template", "body_template", "from_override"],
    sms_send: ["channel_id", "to_template", "body_template", "from_override"],
  };

  /** Node types with a dedicated inspector renderer (skip generic mapping duplicate). */
  const SPECIALIZED_INSPECTOR_TYPES = new Set([
    "condition",
    "human_approval",
    "http_request",
    "vector_query",
    "vector_ingest",
    "rag_query",
    "memory_read",
    "memory_write",
    "email_send",
    "sms_send",
  ]);

  /** Human-readable output field hints per node type. */
  const OUTPUT_PARAM_HINTS = {
    llm_chat: [
      { path: "message", description: "Primary assistant reply text" },
      { path: "choices[0].message.content", description: "OpenAI-style content path" },
      { path: "model_id", description: "Model used for the completion" },
    ],
    http_request: [
      { path: "status_code", description: "HTTP status code (live runs)" },
      { path: "status", description: "Same as status_code — use in conditions and templates" },
      { path: "data", description: "Parsed JSON response body object" },
      { path: "body_preview", description: "Raw response text preview (first 2 KB)" },
      { path: "data.approved", description: "Example nested field for conditions" },
      { path: "data.email", description: "Example nested recipient field" },
    ],
    mcp_tool: [
      { path: "result", description: "Tool invocation result object" },
      { path: "tool_name", description: "Tool that was called" },
    ],
    condition: [
      { path: "matched", description: "Whether the expression evaluated true" },
      { path: "expression", description: "Resolved condition expression" },
    ],
    memory_read: [{ path: "records", description: "Array of memory records read" }],
    memory_write: [
      { path: "memory_id", description: "Created memory record ID (live runs)" },
      { path: "scope_id", description: "Resolved scope partition key" },
      { path: "content", description: "Stored content preview" },
    ],
    vector_query: [
      { path: "hits", description: "Search hits with score and text" },
      { path: "matches", description: "Alias for hits in live runs" },
      { path: "match_count", description: "Number of hits returned" },
    ],
    vector_ingest: [{ path: "document_id", description: "Ingested document identifier" }],
    rag_query: [
      { path: "matches", description: "Retrieved context matches (live runs)" },
      { path: "chunks", description: "Context chunks for downstream LLM" },
      { path: "match_count", description: "Number of matches returned" },
    ],
    embedding_create: [{ path: "embedding_dims", description: "Vector dimensions produced" }],
    email_send: [
      { path: "sent", description: "Delivery success flag" },
      { path: "to", description: "Resolved recipient" },
    ],
    sms_send: [{ path: "sent", description: "Delivery success flag" }],
    human_approval: [
      { path: "approved", description: "Approval decision" },
      { path: "approver_id", description: "User who approved or rejected" },
    ],
    guardrail_evaluate: [
      { path: "passed", description: "Whether content passed guardrails" },
      { path: "violations", description: "Policy violations if any" },
    ],
    wait_delay: [{ path: "waited", description: "Whether delay completed" }],
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
      status_code: 200,
      status: 200,
      data: { approved: true, email: "ops@example.com" },
      body_preview: '{"approved":true}',
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

  /** Run-scoped tokens available in any template field. */
  const RUN_CONTEXT_VARIABLES = [{ value: "{{input}}", label: "Run input", hint: "Text supplied when the flow is run manually" }];

  function getRunContextVariables() {
    return RUN_CONTEXT_VARIABLES.map((item) => ({ ...item }));
  }

  /** Quick-set presets for memory scope_id — resolved at run time where noted. */
  const SCOPE_ID_PRESETS = [
    {
      value: "",
      label: "Run trace ID (auto)",
      hint: "Leave empty on write to use the run trace_id; set explicitly for reads",
    },
    { value: "{{input}}", label: "Run input", hint: "Use manual run input text as the scope key" },
    { value: "platform", label: "Platform", hint: "Shared platform scope — pair with global scope type" },
  ];

  /** Starter snippets per widget field — {{PRIOR}} is replaced with the nearest prior step id in the UI. */
  const TEMPLATE_STARTERS = {
    llm_chat: {
      prompt_template: [
        {
          label: "Summarize prior output",
          value: "Summarize the following clearly for an operator:\n\n{{steps['{{PRIOR}}'].output.message}}",
        },
        {
          label: "Classify intent",
          value:
            "Classify the intent of the following text as support, sales, or other:\n\n{{steps['{{PRIOR}}'].output.message}}",
        },
        {
          label: "Draft customer reply",
          value: "Draft a concise customer reply based on:\n\n{{steps['{{PRIOR}}'].output.message}}",
        },
      ],
    },
    http_request: {
      url: [
        {
          label: "Resource from prior step",
          value: "https://api.example.com/tickets/{{steps['{{PRIOR}}'].output.data.id}}",
        },
        {
          label: "Session scoped URL",
          value: "https://api.example.com/sessions/{{steps['{{PRIOR}}'].output.data.session_id}}",
        },
      ],
      headers_json: [
        {
          label: "JSON headers with trace",
          value: '{"Content-Type":"application/json","X-Trace-Id":"{{steps[\'{{PRIOR}}\'].output.trace_id}}"}',
        },
      ],
      body_template: [
        {
          label: "Forward prior output",
          value: '{"source":"orchestration","payload":"{{steps[\'{{PRIOR}}\'].output.message}}"}',
        },
        {
          label: "Ticket status update",
          value: '{"ticket_id":"{{steps[\'{{PRIOR}}\'].output.ticket_id}}","status":"reviewed"}',
        },
      ],
    },
    mcp_tool: {
      arguments_json: [
        {
          label: "Search from prior step",
          value: '{"query":"{{steps[\'{{PRIOR}}\'].output.message}}"}',
        },
        {
          label: "Forward prior data field",
          value: '{"payload":"{{steps[\'{{PRIOR}}\'].output.data}}"}',
        },
      ],
    },
    memory_write: {
      content_template: [
        { label: "Save prior message", value: "{{steps['{{PRIOR}}'].output.message}}" },
        { label: "Save HTTP response body", value: "{{steps['{{PRIOR}}'].output.data}}" },
      ],
    },
    rag_query: {
      query_template: [
        { label: "Question from prior step", value: "{{steps['{{PRIOR}}'].output.message}}" },
        { label: "Topic lookup", value: "What is the policy for {{steps['{{PRIOR}}'].output.topic}}?" },
      ],
    },
    vector_ingest: {
      content_template: [{ label: "Ingest prior text", value: "{{steps['{{PRIOR}}'].output.message}}" }],
    },
    vector_query: {
      query: [{ label: "Search prior text", value: "{{steps['{{PRIOR}}'].output.message}}" }],
    },
    embedding_create: {
      input_template: [{ label: "Embed prior output", value: "{{steps['{{PRIOR}}'].output.message}}" }],
    },
    guardrail_evaluate: {
      input_template: [{ label: "Check prior LLM output", value: "{{steps['{{PRIOR}}'].output.message}}" }],
    },
    email_send: {
      to_template: [{ label: "Email from HTTP data", value: "{{steps['{{PRIOR}}'].output.data.email}}" }],
      subject_template: [
        { label: "Alert with ticket id", value: "Alert: ticket {{steps['{{PRIOR}}'].output.ticket_id}}" },
      ],
      body_template: [{ label: "Summary body", value: "Review needed:\n\n{{steps['{{PRIOR}}'].output.message}}" }],
    },
    sms_send: {
      to_template: [{ label: "Phone from prior step", value: "{{steps['{{PRIOR}}'].output.data.phone}}" }],
      body_template: [{ label: "Short alert", value: "Alert: {{steps['{{PRIOR}}'].output.message}}" }],
    },
  };

  function getScopeIdPresets() {
    return SCOPE_ID_PRESETS.map((item) => ({ ...item }));
  }

  function getTemplateStarters(nodeType, fieldName) {
    const byType = TEMPLATE_STARTERS[String(nodeType || "")];
    if (!byType) return [];
    const starters = byType[String(fieldName || "")];
    return starters ? starters.map((item) => ({ ...item })) : [];
  }

  function getAllMappingFields() {
    const fields = new Set();
    Object.values(MAPPING_SECTIONS).forEach((section) => {
      section.fields.forEach((field) => fields.add(field));
    });
    return [...fields];
  }

  function isMappingField(fieldName) {
    return getAllMappingFields().includes(String(fieldName || ""));
  }

  function getCustomInspectorFields(nodeType) {
    const key = String(nodeType || "").trim();
    return INSPECTOR_CUSTOM_FIELDS[key] ? [...INSPECTOR_CUSTOM_FIELDS[key]] : [];
  }

  function hasSpecializedInspector(nodeType) {
    return SPECIALIZED_INSPECTOR_TYPES.has(String(nodeType || ""));
  }

  function getDataMappingFormat() {
    return { ...DATA_MAPPING_FORMAT };
  }

  function getMappingSections() {
    return { ...MAPPING_SECTIONS };
  }

  function getOutputParamHints(nodeType) {
    const key = String(nodeType || "").trim();
    return OUTPUT_PARAM_HINTS[key] ? [...OUTPUT_PARAM_HINTS[key]] : [];
  }

  const DEFAULT_OUTPUT_FIELD_PATHS = ["status", "body", "response", "output", "message", "data", "result"];

  /** Output field paths for variable pickers — registry hints plus sensible defaults. */
  function getOutputFieldPaths(nodeType) {
    const seen = new Set();
    const paths = [];
    getOutputParamHints(nodeType).forEach((item) => {
      if (!seen.has(item.path)) {
        seen.add(item.path);
        paths.push(item.path);
      }
    });
    DEFAULT_OUTPUT_FIELD_PATHS.forEach((path) => {
      if (!seen.has(path)) {
        seen.add(path);
        paths.push(path);
      }
    });
    return paths;
  }

  function getMappingCategoryForField(field) {
    const meta = CONFIG_FIELDS[field];
    return meta?.mappingCategory || null;
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
    MAPPING_SECTIONS,
    OUTPUT_PARAM_HINTS,
    NODE_OUTPUT_EXAMPLES,
    getDataMappingFormat,
    getMappingSections,
    getOutputParamHints,
    getOutputFieldPaths,
    DEFAULT_OUTPUT_FIELD_PATHS,
    getMappingCategoryForField,
    getNodeOutputExample,
    getTemplateFieldsForNodeType,
    getScopeIdPresets,
    getTemplateStarters,
    getRunContextVariables,
    getAllMappingFields,
    isMappingField,
    getCustomInspectorFields,
    hasSpecializedInspector,
    INSPECTOR_CUSTOM_FIELDS,
    SPECIALIZED_INSPECTOR_TYPES,
    SCOPE_ID_PRESETS,
    TEMPLATE_STARTERS,
    RUN_CONTEXT_VARIABLES,
  };
})(window);
