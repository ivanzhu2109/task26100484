"""规则模型与 JSON 载入。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union

#: 整条链首末时间差的全局上限（毫秒）。
MAX_TOTAL_SPAN_MS = 600000
#: 相邻阶段最大允许间隔的上限（毫秒）。
MAX_ADJACENT_INTERVAL_MS = 600000


@dataclass(frozen=True)
class Stage:
    """一个顺序阶段：事件类型 + 若干属性等值条件。"""

    event_type: str
    attributes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Rule:
    """检测规则：多个顺序阶段 + 相邻阶段最大间隔。

    max_intervals_ms[i] 是第 i 阶段与第 i+1 阶段之间允许的最大间隔，
    取值 1..600000，包含边界。
    max_total_span_ms 为整条链首末时间差上限，默认且不得超过 600000。
    """

    name: str
    stages: Tuple[Stage, ...]
    max_intervals_ms: Tuple[int, ...]
    max_total_span_ms: int = MAX_TOTAL_SPAN_MS


def _parse_stage(raw: Any, index: int) -> Stage:
    if not isinstance(raw, dict):
        raise ValueError(f"stage {index}: must be an object")
    event_type = raw.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise ValueError(f"stage {index}: 'event_type' must be a non-empty string")
    raw_attrs = raw.get("attributes", {})
    if not isinstance(raw_attrs, dict):
        raise ValueError(f"stage {index}: 'attributes' must be an object")
    attrs = []
    for key, value in raw_attrs.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"stage {index}: attribute keys and values must be strings")
        attrs.append((key, value))
    return Stage(event_type=event_type, attributes=tuple(attrs))


def load_rule(source: Union[str, Dict[str, Any]]) -> Rule:
    """从 JSON 字符串或已解析的字典载入规则并校验。

    规则格式::

        {
          "name": "rule-name",
          "stages": [
            {"event_type": "process_create", "attributes": {"image": "cmd.exe"}},
            {"event_type": "network_connect"}
          ],
          "max_intervals_ms": [5000],
          "max_total_span_ms": 600000
        }

    ``max_total_span_ms`` 可省略，默认 600000。
    非法规则抛出 ``ValueError``。
    """
    if isinstance(source, str):
        try:
            data = json.loads(source)
        except json.JSONDecodeError as exc:
            raise ValueError(f"rule is not valid JSON: {exc}") from exc
    elif isinstance(source, dict):
        data = source
    else:
        raise ValueError("rule source must be a JSON string or a dict")

    name = data.get("name", "")
    if not isinstance(name, str):
        raise ValueError("'name' must be a string")

    raw_stages = data.get("stages")
    if not isinstance(raw_stages, list) or len(raw_stages) < 2:
        raise ValueError("'stages' must be a list with at least 2 stages")
    stages = tuple(_parse_stage(raw, i) for i, raw in enumerate(raw_stages))

    raw_intervals = data.get("max_intervals_ms")
    if not isinstance(raw_intervals, list) or len(raw_intervals) != len(stages) - 1:
        raise ValueError(
            "'max_intervals_ms' must be a list with exactly len(stages) - 1 entries"
        )
    intervals = []
    for i, value in enumerate(raw_intervals):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"max_intervals_ms[{i}] must be an integer")
        if not 1 <= value <= MAX_ADJACENT_INTERVAL_MS:
            raise ValueError(
                f"max_intervals_ms[{i}] must be within 1..{MAX_ADJACENT_INTERVAL_MS}"
            )
        intervals.append(value)

    total_span = data.get("max_total_span_ms", MAX_TOTAL_SPAN_MS)
    if not isinstance(total_span, int) or isinstance(total_span, bool):
        raise ValueError("'max_total_span_ms' must be an integer")
    if not 1 <= total_span <= MAX_TOTAL_SPAN_MS:
        raise ValueError(f"'max_total_span_ms' must be within 1..{MAX_TOTAL_SPAN_MS}")

    return Rule(
        name=name,
        stages=stages,
        max_intervals_ms=tuple(intervals),
        max_total_span_ms=total_span,
    )
