"""行为链检测引擎：单次计算使用一条规则与一批遥测，全部在内存中完成。"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict

from .types import Alert, Event, Rule


def _key(event: Event) -> tuple[int, str]:
    """链内排序键：先时间戳，再按 ASCII 字典序的事件 ID。"""
    return (event.ts_ms, event.event_id)


def detect(events: list[Event], rule: Rule) -> list[Alert]:
    """对一批遥测应用一条规则，返回告警列表。

    每个能作为合法链末阶段的事件产生且只产生一条告警；
    告警按末阶段事件的 (时间戳, 事件ID) 升序返回，保证结果与输入顺序无关。
    """
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        groups[(event.endpoint_id, event.process_instance_id)].append(event)

    found: list[tuple[tuple[int, str], Alert]] = []
    for group_events in groups.values():
        group_events.sort(key=_key)
        for final_event, chain in _detect_in_group(group_events, rule):
            found.append(
                (
                    _key(final_event),
                    Alert(
                        rule_name=rule.name,
                        final_event_id=final_event.event_id,
                        evidence_event_ids=tuple(e.event_id for e in chain),
                    ),
                )
            )
    found.sort(key=lambda item: item[0])
    return [alert for _, alert in found]


def _detect_in_group(
    sorted_events: list[Event], rule: Rule
) -> list[tuple[Event, list[Event]]]:
    """在同一终端同一进程实例的有序事件内查找合法链。

    返回 (末阶段事件, 规范证据链) 列表，按末阶段事件排序键升序。
    """
    stages = rule.stages
    n_stages = len(stages)

    # 每个阶段匹配的事件（保持有序）
    matched: list[list[Event]] = [
        [e for e in sorted_events if stage.matches(e)] for stage in stages
    ]
    if not matched[-1]:
        return []

    # 前向 DP：max_start[i][e] = 以 e 为第 i 阶段事件的合法前缀链中，
    # 首阶段事件时间戳的最大值（用于总跨度上限判断）。
    max_start: list[dict[str, int]] = [{} for _ in range(n_stages)]
    max_start[0] = {e.event_id: e.ts_ms for e in matched[0]}
    for i in range(1, n_stages):
        gap = stages[i - 1].max_gap_to_next_ms
        assert gap is not None
        prevs = matched[i - 1]
        prev_keys = [_key(e) for e in prevs]
        for event in matched[i]:
            lo = bisect_left(prev_keys, (event.ts_ms - gap, ""))
            hi = bisect_left(prev_keys, _key(event))
            best: int | None = None
            for prev in prevs[lo:hi]:
                value = max_start[i - 1].get(prev.event_id)
                if value is not None and (best is None or value > best):
                    best = value
            if best is not None:
                max_start[i][event.event_id] = best

    results: list[tuple[Event, list[Event]]] = []
    for final in matched[-1]:
        if final.event_id not in max_start[-1]:
            continue
        earliest_start = final.ts_ms - rule.max_total_span_ms

        # 反向可达：ok[i] = 能作为第 i 阶段并最终到达 final 的事件集合
        ok: list[set[str]] = [set() for _ in range(n_stages)]
        ok[-1] = {final.event_id}
        for i in range(n_stages - 2, -1, -1):
            gap = stages[i].max_gap_to_next_ms
            assert gap is not None
            next_events = [e for e in matched[i + 1] if e.event_id in ok[i + 1]]
            next_keys = [_key(e) for e in next_events]
            for event in matched[i]:
                start = max_start[i].get(event.event_id)
                if start is None or start < earliest_start:
                    continue
                idx = bisect_right(next_keys, _key(event))
                if idx < len(next_events) and next_events[idx].ts_ms - event.ts_ms <= gap:
                    ok[i].add(event.event_id)
        if not ok[0]:
            continue

        # 规范链选择：首末时间差最小（即首阶段时间戳最大），
        # 并列时完整链按 (时间戳, ID) 逐项字典序最小。
        first: Event | None = None
        for event in matched[0]:
            if event.event_id not in ok[0] or event.ts_ms < earliest_start:
                continue
            if first is None or event.ts_ms > first.ts_ms:
                first = event  # 同时间戳时先出现者 ID 更小
        assert first is not None

        chain = [first]
        for i in range(1, n_stages):
            gap = stages[i - 1].max_gap_to_next_ms
            assert gap is not None
            prev = chain[-1]
            keys = [_key(e) for e in matched[i]]
            idx = bisect_right(keys, _key(prev))
            chosen: Event | None = None
            while idx < len(matched[i]):
                candidate = matched[i][idx]
                if candidate.ts_ms - prev.ts_ms > gap:
                    break
                if candidate.event_id in ok[i]:
                    chosen = candidate
                    break
                idx += 1
            assert chosen is not None
            chain.append(chosen)
        results.append((final, chain))
    return results
