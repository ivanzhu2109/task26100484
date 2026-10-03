"""数据模型：遥测事件与告警。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass(frozen=True)
class TelemetryEvent:
    """一条遥测事件。

    event_id: 全局唯一 ASCII 事件 ID。
    timestamp_ms: 整数毫秒时间戳。
    endpoint_id: 终端 ID。
    process_instance_id: 进程实例 ID（由调用方保证唯一，非可复用 PID）。
    event_type: 事件类型。
    attributes: 字符串属性字典。
    """

    event_id: str
    timestamp_ms: int
    endpoint_id: str
    process_instance_id: str
    event_type: str
    attributes: Dict[str, str] = field(default_factory=dict)

    @property
    def order_key(self) -> Tuple[int, str]:
        """链内排序键：先时间戳，再按 ASCII 字典序比较事件 ID。"""
        return (self.timestamp_ms, self.event_id)


@dataclass(frozen=True)
class Alert:
    """一条告警：末阶段事件 + 完整规范证据链。"""

    rule_name: str
    endpoint_id: str
    process_instance_id: str
    last_event_id: str
    evidence_event_ids: Tuple[str, ...]
    start_timestamp_ms: int
    end_timestamp_ms: int

    @property
    def span_ms(self) -> int:
        return self.end_timestamp_ms - self.start_timestamp_ms
