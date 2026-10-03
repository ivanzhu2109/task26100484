"""EDR 离线行为链检测库。"""

from .engine import detect
from .types import (
    MAX_GAP_MS,
    MAX_TOTAL_SPAN_MS,
    MIN_GAP_MS,
    Alert,
    Event,
    Rule,
    Stage,
    load_rule,
    load_rule_json,
)

__all__ = [
    "Alert",
    "Event",
    "Rule",
    "Stage",
    "detect",
    "load_rule",
    "load_rule_json",
    "MAX_GAP_MS",
    "MAX_TOTAL_SPAN_MS",
    "MIN_GAP_MS",
]
