(function initAppConstants(global) {
  const ACTOR_ROLES = Object.freeze({
    AUDITOR: "Auditor",
    PLATFORM_ADMIN: "Platform Admin",
    MASTER_ADMIN: "Master Admin",
    SUPER_ADMIN: "Super Admin",
    SECURITY_APPROVER: "Security Approver",
    RELEASE_MANAGER: "Release Manager",
    AGENT_OWNER: "Agent Owner",
    AI_OPS_APPROVER: "AI Ops Approver",
  });

  global.AppConstants = Object.freeze({
    ACTOR_ROLES,
    API_LIMITS: Object.freeze({
      DEFAULT_LIST: 500,
      AUDIT_EVENTS: 50,
      UI_COVERAGE_TABLE_MAX: 100,
      OVERVIEW_GAPS_MAX: 8,
    }),
    VIEW_NAMES: Object.freeze([
      "overview",
      "agents",
      "playground",
    "benchmark-scan",
    "orchestration",
    "routing-gateway",
      "runtime-config",
      "providers",
      "modules",
      "agentic",
      "discovery",
      "cost",
      "audit",
      "compliance",
      "observability",
      "security",
    ]),
    UI_COVERAGE: Object.freeze({
      STATUSES: Object.freeze({
        FULL: "Full",
        PARTIAL: "Partial",
        GAP: "Gap",
        UNDOCUMENTED: "Undocumented",
      }),
      GATE_EXEMPT_PREFIXES: Object.freeze(["/health", "/platform/operational-status", "/governance/", "/auth/login"]),
      INVENTORY_PATH: "/governance/ui-coverage/inventory",
      REPORT_PATH: "/governance/ui-coverage",
    }),
    SAFE_HTTP_METHODS: Object.freeze(["GET", "HEAD", "OPTIONS"]),
    BOOT_DEDUPE_PATHS: Object.freeze(["/runtime-config", "/governance/ui-coverage/inventory"]),
    TABLE_PAGINATION: Object.freeze({
      DEFAULT_PAGE_SIZE: 10,
      PAGE_SIZE_OPTIONS: Object.freeze([10, 25, 50]),
    }),
  });
})(window);
