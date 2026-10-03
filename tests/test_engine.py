"""行为链检测引擎测试。"""

from __future__ import annotations

import random

from edr_chain import Alert, Event, Rule, Stage, detect

EP = "endpoint-1"
PI = "proc-inst-1"


def ev(event_id, ts, event_type, endpoint=EP, pi=PI, attrs=None):
    return Event(
        event_id=event_id,
        ts_ms=ts,
        endpoint_id=endpoint,
        process_instance_id=pi,
        event_type=event_type,
        attributes=attrs or {},
    )


def test_incomplete_prefix_and_canonical_chain_selection():
    """场景一：
    - 最近的中间候选 B1 无法补齐前缀，较早的 B2 才能形成完整链；
    - 同一末阶段存在不同跨度的多条链时选跨度最小者；
    - 跨度相同时按 (时间戳, ID) 逐项字典序选最小完整链；
    - 每个可作为末阶段的事件产生且只产生一条告警。
    """
    rule = Rule(
        name="three-stage",
        stages=(
            Stage("A", max_gap_to_next_ms=100),
            Stage("B", max_gap_to_next_ms=1000),
            Stage("C"),
        ),
    )
    events = [
        # C1 的合法链只有 (A1, B2, C1)：B1 距 C1 更近但 100ms 内没有 A 前缀
        ev("A1", 0, "A"),
        ev("B2", 50, "B"),
        ev("B1", 500, "B"),
        ev("C1", 600, "C"),
        # C2 有两条链：(A2,B3,C2) 跨度 500，(A3,B3,C2) 跨度 200，选后者
        ev("A2", 1000, "A"),
        ev("A3", 1300, "A"),
        ev("B3", 1400, "B"),
        ev("C2", 1500, "C"),
        # C3 有多条同跨度链：首事件同时间戳按 ID 选 A4，中间同时间戳按 ID 选 B4
        ev("A5", 2000, "A"),
        ev("A4", 2000, "A"),
        ev("B5", 2100, "B"),
        ev("B4", 2100, "B"),
        ev("C3", 2200, "C"),
        # C4 之前没有任何 B，不能作为末阶段，不产生告警
        ev("C4", 5000, "C"),
    ]

    alerts = detect(events, rule)

    assert alerts == [
        Alert("three-stage", "C1", ("A1", "B2", "C1")),
        Alert("three-stage", "C2", ("A3", "B3", "C2")),
        Alert("three-stage", "C3", ("A4", "B4", "C3")),
    ]


def _overlap_rule(gap):
    """两个阶段条件完全重叠的规则（同一事件类型与属性条件）。"""
    proc = {"name": "cmd.exe"}
    return Rule(
        name="overlap",
        stages=(
            Stage("proc", proc, max_gap_to_next_ms=gap),
            Stage("proc", dict(proc)),
        ),
    )


def _scenario2_events():
    """场景二数据：条件重叠、同时间戳、间隔边界、混入其他实例。"""
    proc = {"name": "cmd.exe"}
    return [
        # 相邻间隔恰好等于上限 300：P1 -> P2
        ev("P1", 1000, "proc", attrs=proc),
        ev("P2", 1300, "proc", attrs=proc),
        # 相同时间戳的事件依照 ID 顺序组成链：P3 -> P4（间隔 0）
        ev("P4", 2000, "proc", attrs=proc),
        ev("P3", 2000, "proc", attrs=proc),
        # 缺少条件所需属性，不匹配任何阶段
        ev("P9", 2500, "proc", attrs={"other": "x"}),
        # 其他终端的完整链：X1 -> X4，不得与 P 链混用
        ev("X1", 1100, "proc", endpoint="endpoint-2", attrs=proc),
        ev("X4", 1150, "proc", endpoint="endpoint-2", attrs=proc),
        # 其他进程实例的孤立事件：若误跨实例可与 P1 成链，必须被隔离
        ev("Y1", 1250, "proc", pi="proc-inst-2", attrs=proc),
        # 不相关事件类型的干扰
        ev("D1", 1150, "dns", attrs=proc),
    ]


def test_overlapping_conditions_and_instance_isolation():
    """场景二：阶段条件重叠、同时间戳、相邻间隔边界、实例隔离。"""
    alerts = detect(_scenario2_events(), _overlap_rule(gap=300))

    assert alerts == [
        # endpoint-2 内部独立成链
        Alert("overlap", "X4", ("X1", "X4")),
        # P1->P2 间隔恰好 300；不得跨实例使用 X1/Y1
        Alert("overlap", "P2", ("P1", "P2")),
        # 相同时间戳按 ID 顺序：P3 -> P4；P3 之前 300ms 内无首阶段事件，无告警
        Alert("overlap", "P4", ("P3", "P4")),
    ]


def test_gap_and_total_span_upper_bounds_inclusive():
    """相邻间隔与总跨度上限均含边界 600000，超出 1ms 即排除。"""
    proc = {"name": "cmd.exe"}
    events = [
        ev("Q1", 0, "proc", attrs=proc),
        ev("Q2", 1, "proc", attrs=proc),
        # Q2 -> Q4 间隔与跨度均恰好 600000；Q1 -> Q4 跨度 600001 超限
        ev("Q4", 600001, "proc", attrs=proc),
    ]
    alerts = detect(events, _overlap_rule(gap=600_000))

    assert alerts == [
        Alert("overlap", "Q2", ("Q1", "Q2")),
        # Q2 被多条告警复用；Q4 的规范链首事件是 Q2 而非 Q1
        Alert("overlap", "Q4", ("Q2", "Q4")),
    ]


def test_input_order_does_not_change_results():
    """同一批遥测任意打乱顺序，告警集合与规范证据链完全一致。"""
    events = _scenario2_events() + [
        ev("Q1", 0, "proc", attrs={"name": "cmd.exe"}),
        ev("Q2", 1, "proc", attrs={"name": "cmd.exe"}),
        ev("Q4", 600001, "proc", attrs={"name": "cmd.exe"}),
    ]
    for gap in (300, 600_000):
        rule = _overlap_rule(gap)
        baseline = detect(events, rule)
        for seed in range(10):
            shuffled = list(events)
            random.Random(seed).shuffle(shuffled)
            assert detect(shuffled, rule) == baseline
