from enum import Enum


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    CHALLENGE = "CHALLENGE"
    DENY = "DENY"
