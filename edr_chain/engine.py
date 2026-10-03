"""行为链检测引擎：单次计算使用一条规则，数据仅存内存。"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .models import Alert, TelemetryEvent
from .rule import Rule

# 一条候选链：按阶段顺序排列的事件元组。
_Chain = Tuple[TelemetryEvent, ...]


def _coerce_event(raw: Union[TelemetryEvent, Dict[str, Any]]) -> TelemetryEvent:
    """把调用方提供的事件（字典或 TelemetryEvent）规整为 TelemetryEvent 并校验。"""
    if isinstance(raw, TelemetryEvent):
        event = raw
    elif isinstance(raw, dict):
        try:
            event = TelemetryEvent(
                event_id=raw["event_id"],
                timestamp_ms=raw["timestamp_ms"],
                endpoint_id=raw["endpoint_id"],
                process_instance_id=raw["process_instance_id"],
                event_type=raw["event_type"],
                attributes=dict(raw.get("attributes", {})),
            )
        except KeyError as exc:
            raise ValueError(f"event is missing required field: {exc}") from exc
    else:
        raise ValueError("event must be a TelemetryEvent or a dict")

    if not isinstance(event.event_id, str) or not event.event_id.isascii():
        raise ValueError("event_id must be an ASCII string")
    if not isinstance(event.timestamp_ms, int) or isinstance(event.timestamp_ms, bool):
        raise ValueError("timestamp_ms must be an integer")
    for field_name in ("endpoint_id", "process_instance_id", "event_type"):
        if not isinstance(getattr(event, field_name), str):
            raise ValueError(f"{field_name} must be a string")
    for key, value in event.attributes.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("event attributes must map strings to strings")
    return event


def _matches(event: TelemetryEvent, event_type: str, attributes: Tuple[Tuple[str, str], ...]) -> bool:
    """事件类型相同且全部属性等值条件满足；缺少所需属性则不匹配。"""
    if event.event_type != event_type:
        return False
    return all(event.attributes.get(key) == value for key, value in attributes)


def _chain_key(chain: _Chain) -> Tuple[int, Tuple[Tuple[int, str], ...]]:
    """规范链比较键：先首末时间差，再从首到末按 (时间戳, ID) 逐项字典序。"""
    span = chain[-1].timestamp_ms - chain[0].timestamp_ms
    return (span, tuple(event.order_key for event in chain))


def _detect_group(events: List[TelemetryEvent], rule: Rule) -> List[Alert]:
    """在同一终端同一进程实例的事件组内检测（事件已按排序键升序）。"""
    # prev 保存上一阶段每个匹配事件的最优（规范）链。
    prev: List[Tuple[TelemetryEvent, _Chain]] = []
    first_stage = rule.stages[0]
    for event in events:
        if _matches(event, first_stage.event_type, first_stage.attributes):
            prev.append((event, (event,)))

    for stage_index in range(1, len(rule.stages)):
        stage = rule.stages[stage_index]
        max_interval = rule.max_intervals_ms[stage_index - 1]
        current: List[Tuple[TelemetryEvent, _Chain]] = []
        for event in events:
            if not _matches(event, stage.event_type, stage.attributes):
                continue
            best: Optional[_Chain] = None
            best_key: Optional[Tuple[int, Tuple[Tuple[int, str], ...]]] = None
            for prev_event, prev_chain in prev:
                # 链内按 (时间戳, ID) 严格递增。
                if prev_event.order_key >= event.order_key:
                    continue
                # 相邻阶段间隔上限（含边界）。
                if event.timestamp_ms - prev_event.timestamp_ms > max_interval:
                    continue
                # 整条链首末时间差上限（含边界）。
                if event.timestamp_ms - prev_chain[0].timestamp_ms > rule.max_total_span_ms:
                    continue
                candidate = prev_chain + (event,)
                candidate_key = _chain_key(candidate)
                if best_key is None or candidate_key < best_key:
                    best = candidate
                    best_key = candidate_key
            if best is not None:
                current.append((event, best))
        prev = current
        if not prev:
            return []

    alerts = []
    for last_event, chain in prev:
        alerts.append(
            Alert(
                rule_name=rule.name,
                endpoint_id=last_event.endpoint_id,
                process_instance_id=last_event.process_instance_id,
                last_event_id=last_event.event_id,
                evidence_event_ids=tuple(e.event_id for e in chain),
                start_timestamp_ms=chain[0].timestamp_ms,
                end_timestamp_ms=last_event.timestamp_ms,
            )
        )
    return alerts


def detect(events: Iterable[Union[TelemetryEvent, Dict[str, Any]]], rule: Rule) -> List[Alert]:
    """对一批遥测执行单规则检测，返回告警列表。

    - 输入顺序任意；同一批遥测以不同顺序提供时结果完全一致。
    - 每个能作为合法链末阶段的事件产生且只产生一条告警，
      附带唯一规范证据链（首末时间差最小，其次按 (时间戳, ID) 字典序最小）。
    - 返回的告警按末阶段事件的 (时间戳, ID) 排序，保证确定性。
    """
    if len(rule.stages) < 2:
        raise ValueError("rule must have at least 2 stages")
    if len(rule.max_intervals_ms) != len(rule.stages) - 1:
        raise ValueError("rule.max_intervals_ms must have exactly len(stages) - 1 entries")

    groups: Dict[Tuple[str, str], List[TelemetryEvent]] = {}
    seen_ids = set()
    for raw in events:
        event = _coerce_event(raw)
        if event.event_id in seen_ids:
            raise ValueError(f"duplicate event_id: {event.event_id!r}")
        seen_ids.add(event.event_id)
        key = (event.endpoint_id, event.process_instance_id)
        groups.setdefault(key, []).append(event)

    alerts: List[Alert] = []
    for group in groups.values():
        group.sort(key=lambda e: e.order_key)
        alerts.extend(_detect_group(group, rule))

    alerts.sort(key=lambda a: (a.end_timestamp_ms, a.last_event_id))
    return alerts
