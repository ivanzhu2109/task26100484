"""EDR 离线行为链检测库。"""
from .engine import detect
from .models import Alert, TelemetryEvent
from .rule import MAX_TOTAL_SPAN_MS, Rule, Stage, load_rule

__all__ = [
    "Alert",
    "MAX_TOTAL_SPAN_MS",
    "Rule",
    "Stage",
    "TelemetryEvent",
    "detect",
    "load_rule",
]
