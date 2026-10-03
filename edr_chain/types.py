"""数据类型定义：遥测事件、规则、告警。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: 相邻阶段最大允许间隔的合法范围（毫秒，含边界）
MIN_GAP_MS = 1
MAX_GAP_MS = 600_000
#: 整条链首末时间差上限（毫秒，含边界）
MAX_TOTAL_SPAN_MS = 600_000


@dataclass(frozen=True)
class Event:
    """一条遥测事件。

    event_id 全局唯一且为 ASCII 字符串；ts_ms 为整数毫秒时间戳。
    """

    event_id: str
    ts_ms: int
    endpoint_id: str
    process_instance_id: str
    event_type: str
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Stage:
    """规则中的一个阶段：事件类型 + 若干属性等值条件。

    max_gap_to_next_ms 表示本阶段与下一阶段之间允许的最大间隔，
    最后一个阶段该字段为 None。
    """

    event_type: str
    conditions: dict[str, str] = field(default_factory=dict)
    max_gap_to_next_ms: int | None = None

    def matches(self, event: Event) -> bool:
        """事件类型相同且所有条件属性存在并等值；缺少属性则不匹配。"""
        if event.event_type != self.event_type:
            return False
        for key, value in self.conditions.items():
            if event.attributes.get(key) != value:
                return False
        return True


@dataclass(frozen=True)
class Rule:
    """一条检测规则：按顺序的多个阶段。"""

    name: str
    stages: tuple[Stage, ...]
    max_total_span_ms: int = MAX_TOTAL_SPAN_MS


@dataclass(frozen=True)
class Alert:
    """一条告警：末阶段事件 + 规范证据链（首到末的事件 ID）。"""

    rule_name: str
    final_event_id: str
    evidence_event_ids: tuple[str, ...]


def load_rule(data: dict[str, Any]) -> Rule:
    """从 JSON 字典载入规则并校验。"""
    if not isinstance(data, dict):
        raise ValueError("规则必须是 JSON 对象")
    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("规则缺少有效的 name 字段")

    max_total_span_ms = data.get("max_total_span_ms", MAX_TOTAL_SPAN_MS)
    if (
        not isinstance(max_total_span_ms, int)
        or isinstance(max_total_span_ms, bool)
        or not MIN_GAP_MS <= max_total_span_ms <= MAX_TOTAL_SPAN_MS
    ):
        raise ValueError(
            f"max_total_span_ms 必须是 [{MIN_GAP_MS}, {MAX_TOTAL_SPAN_MS}] 内的整数"
        )

    raw_stages = data.get("stages")
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ValueError("规则必须包含非空的 stages 列表")

    stages: list[Stage] = []
    for index, raw in enumerate(raw_stages):
        if not isinstance(raw, dict):
            raise ValueError(f"阶段 {index} 必须是 JSON 对象")
        event_type = raw.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            raise ValueError(f"阶段 {index} 缺少有效的 event_type")
        conditions = raw.get("conditions", {})
        if not isinstance(conditions, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in conditions.items()
        ):
            raise ValueError(f"阶段 {index} 的 conditions 必须是字符串到字符串的映射")

        is_last = index == len(raw_stages) - 1
        gap = raw.get("max_gap_to_next_ms")
        if is_last:
            if gap is not None:
                raise ValueError(f"最后一个阶段 {index} 不应配置 max_gap_to_next_ms")
        else:
            if (
                not isinstance(gap, int)
                or isinstance(gap, bool)
                or not MIN_GAP_MS <= gap <= MAX_GAP_MS
            ):
                raise ValueError(
                    f"阶段 {index} 的 max_gap_to_next_ms 必须是 "
                    f"[{MIN_GAP_MS}, {MAX_GAP_MS}] 内的整数"
                )
        stages.append(
            Stage(
                event_type=event_type,
                conditions=dict(conditions),
                max_gap_to_next_ms=gap,
            )
        )

    return Rule(
        name=name, stages=tuple(stages), max_total_span_ms=max_total_span_ms
    )


def load_rule_json(text: str) -> Rule:
    """从 JSON 字符串载入规则并校验。"""
    return load_rule(json.loads(text))
