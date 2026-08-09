from __future__ import annotations

ROLE_PLATFORM_ADMIN = "Platform Admin"
ROLE_MASTER_ADMIN = "Master Admin"
ROLE_SUPER_ADMIN = "Super Admin"
ROLE_AGENT_OWNER = "Agent Owner"
ROLE_SECURITY_APPROVER = "Security Approver"
ROLE_AI_OPS_APPROVER = "AI Ops Approver"
ROLE_RELEASE_MANAGER = "Release Manager"
ROLE_AUDITOR = "Auditor"

SUPPORTED_ACTOR_ROLES = {
	ROLE_MASTER_ADMIN,
	ROLE_SUPER_ADMIN,
	ROLE_PLATFORM_ADMIN,
	ROLE_AGENT_OWNER,
	ROLE_SECURITY_APPROVER,
	ROLE_AI_OPS_APPROVER,
	ROLE_RELEASE_MANAGER,
	ROLE_AUDITOR,
}

AUTH_SESSION_READ_ROLES_DEFAULT = {
	ROLE_MASTER_ADMIN,
	ROLE_PLATFORM_ADMIN,
	ROLE_SECURITY_APPROVER,
	ROLE_AUDITOR,
}

AUTH_SESSION_ISSUER_ROLES_DEFAULT = {
	ROLE_MASTER_ADMIN,
	ROLE_PLATFORM_ADMIN,
	ROLE_RELEASE_MANAGER,
}

ISSUABLE_SESSION_ROLES_DEFAULT = set(SUPPORTED_ACTOR_ROLES)

CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT = {
	ROLE_MASTER_ADMIN,
	ROLE_PLATFORM_ADMIN,
	ROLE_SECURITY_APPROVER,
	ROLE_RELEASE_MANAGER,
}

DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT = ROLE_SECURITY_APPROVER

PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT = 15

DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES = 60
DEFAULT_BASIC_AUTH_ENABLE_DURATION_MINUTES = 30
# Leader Readiness Gates: exceptions ≤ 90 days (hard cap for break-glass duration).
MAX_BASIC_AUTH_ENABLE_DURATION_MINUTES = 90 * 24 * 60

DEFAULT_SESSION_TTL_MINUTES = 60
DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES = 30

MIN_SESSION_TTL_MINUTES = 1
MAX_SESSION_TTL_MINUTES = 1440

MIN_SESSION_IDLE_TIMEOUT_MINUTES = 1
MAX_SESSION_IDLE_TIMEOUT_MINUTES = 720

# ── Browser Security ───────────────────────────────────────────────────────────
# Canonical browser type identifiers used across sessions, events, and analytics.
SUPPORTED_BROWSER_TYPES = {
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
    "unknown",
}

# Geo collection detail levels. City-level requires explicit operator policy.
BROWSER_GEO_DETAIL_LEVEL_COUNTRY = "country"   # default, GDPR-safe
BROWSER_GEO_DETAIL_LEVEL_REGION  = "region"    # country + region
BROWSER_GEO_DETAIL_LEVEL_CITY    = "city"      # requires operator opt-in
SUPPORTED_GEO_DETAIL_LEVELS = {
    BROWSER_GEO_DETAIL_LEVEL_COUNTRY,
    BROWSER_GEO_DETAIL_LEVEL_REGION,
    BROWSER_GEO_DETAIL_LEVEL_CITY,
}

BROWSER_DECISION_MODES = {"allow", "warn", "challenge", "deny", "mask"}

BROWSER_ACTION_TYPES = {
    "prompt_send",
    "file_upload",
    "file_download",
    "paste",
    "copy",
    "screenshot",
    "extension_install",
    "extension_update",
    "navigation",
    "form_submit",
    "api_call",
    "other",
}

# ── GuardBridge data minimization manifest ────────────────────────────────────
# This is the canonical list of what GuardBridge collects and what it NEVER collects.
# Any extension SDK release must not transmit fields outside this manifest.
GUARDBRIDGE_EXTENSION_NAME = "GuardBridge"

GUARDBRIDGE_COLLECTED_FIELDS = {
    "browser_name",        # canonical slug (chrome|firefox|safari|edge|opera|brave|arc|vivaldi|samsung)
    "browser_version",     # major.minor string
    "extension_version",   # semver string
    "os_name",             # coarse class (windows|macos|linux|ios|android|other)
    "os_version",          # version string
    "device_type",         # desktop|mobile|tablet|unknown
    "device_managed",      # boolean from MDM/policy
    "user_agent_digest",   # SHA-256 of raw UA — raw UA never transmitted
    "ip_hash",             # HMAC-SHA256 of client IP — raw IP never stored
    "geo_country",         # ISO 3166-1 alpha-2 country code (default: enabled)
    "geo_region",          # state/province (opt-in, requires policy)
    # geo_city is intentionally ABSENT — stripped server-side always
    "action_type",         # canonical action class from BROWSER_ACTION_TYPES
    "destination_domain",  # eTLD+1 only (e.g. chatgpt.com)
    "destination_app",     # human-readable app name
    "page_url_host",       # eTLD+1 of page origin — full URL never collected
    "decision_outcome",    # allow|warn|challenge|deny|mask
    "policy_rule_id",      # matched policy id
    "risk_signals",        # list of signal labels
    "content_fingerprint", # hash of content — raw prompt/file content never collected
    "data_class",          # standard|pii|credentials|regulated
}

GUARDBRIDGE_NEVER_COLLECTED = {
    "raw_user_agent",      # full navigator.userAgent string
    "raw_ip_address",      # client IP in any form
    "full_url",            # pathname, query string, fragment
    "raw_prompt_text",     # prompt or message content
    "raw_file_content",    # uploaded or downloaded file bytes
    "geo_city",            # city — always stripped server-side
    "geo_postal_code",     # postal code
    "geo_lat_lon",         # coordinates
    "hardware_model",      # device hardware identifier
    "imei_or_serial",      # device serial/IMEI
    "cookies",             # browser cookies
    "local_storage_keys",  # localStorage or sessionStorage
    "screen_capture_data", # screenshot bytes — only action_type=screenshot is logged
}

AUTH_POLICY_DEFAULT_ID = "default"

COST_SCOPE_USER = "user"
COST_SCOPE_TEAM = "team"
COST_SCOPE_GROUP = "group"
COST_SCOPE_OWNER = "owner"
COST_SCOPE_ACTOR = "actor"
COST_SCOPE_AGENT = "agent"
COST_SCOPE_ENVIRONMENT = "environment"

SUPPORTED_BUDGET_SCOPE_TYPES = {
	COST_SCOPE_USER,
	COST_SCOPE_TEAM,
	COST_SCOPE_GROUP,
	COST_SCOPE_OWNER,
	COST_SCOPE_ACTOR,
	COST_SCOPE_AGENT,
	COST_SCOPE_ENVIRONMENT,
}

COST_POLICY_DECISION_ALLOW = "allow"
COST_POLICY_DECISION_WARN = "warn"
COST_POLICY_DECISION_DENY = "deny"
