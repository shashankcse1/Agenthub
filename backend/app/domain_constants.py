"""Domain-level defaults for discovery, observability, and audit analytics.

Operator-tunable overrides belong in runtime-config (see runtime_constants.py).
These values are code defaults used when no runtime-config row exists.
"""

# Discovery confidence posture
DISCOVERY_CONFIDENCE_CONFLICT_MIN = 50
DISCOVERY_CONFIDENCE_PROMOTE_MIN = 85
DISCOVERY_CONFLICT_REASON_MEDIUM = "medium_confidence_conflict"

DISCOVERY_QUERY_LIMIT_CONFLICTS = 2000
DISCOVERY_QUERY_LIMIT_PROMOTE = 2000
DISCOVERY_QUERY_LIMIT_SUMMARY_SCAN = 5000
DISCOVERY_QUERY_LIMIT_DUPLICATES = 5000
DISCOVERY_QUERY_LIMIT_AGENTS = 500

DISCOVERY_CONFIDENCE_BUCKETS: tuple[tuple[str, int, int], ...] = (
    ("0-49", 0, 49),
    ("50-74", 50, 74),
    ("75-84", 75, 84),
    ("85-94", 85, 94),
    ("95-100", 95, 100),
)

# Observability analytics
OBSERVABILITY_SUMMARY_MAX_EVENTS_DEFAULT = 5000
OBSERVABILITY_SUMMARY_SCHEMA_SAMPLE_SIZE = 200
OBSERVABILITY_SUMMARY_RECENT_TRACES_LIMIT = 10
OBSERVABILITY_BREAKDOWN_TOP_ACTIONS = 12
OBSERVABILITY_BREAKDOWN_TOP_ACTORS = 8
OBSERVABILITY_UNKNOWN_ACTOR = "unknown"
OBSERVABILITY_UNKNOWN_ACTION = "unknown"
OBSERVABILITY_DEFAULT_OUTCOME = "allow"

REQUIRED_OBSERVABILITY_LOG_FIELDS: tuple[str, ...] = (
    "timestamp",
    "request_id",
    "actor_id",
    "action_type",
    "resource_type",
    "resource_id",
    "trace_id",
    "span_id",
    "session_id",
    "agent_id",
    "owner_scope",
    "environment",
    "policy_version",
    "decision_outcome",
)

# Platform operator experience
PLATFORM_FEEDBACK_CATEGORIES: frozenset[str] = frozenset(
    {"performance", "ux", "bug", "feature", "incident", "other"}
)
PLATFORM_FEEDBACK_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high"})
PLATFORM_FEEDBACK_STATUSES: frozenset[str] = frozenset(
    {"open", "acknowledged", "resolved", "dismissed"}
)
PLATFORM_FEEDBACK_ACTIONS: frozenset[str] = frozenset(
    {"acknowledge", "resolve", "dismiss", "escalate"}
)
PLATFORM_SLOW_RESPONSE_THRESHOLD_MS_DEFAULT = 2000
PLATFORM_FEEDBACK_QUERY_LIMIT_DEFAULT = 200
PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT = 168
