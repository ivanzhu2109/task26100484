"""EDR 行为链检测库的自动化测试。"""
import itertools
import json

import pytest

from edr_chain import Alert, TelemetryEvent, detect, load_rule


def ev(event_id, ts, etype, endpoint="h1", instance="p1", attrs=None):
    return {
        "event_id": event_id,
        "timestamp_ms": ts,
        "endpoint_id": endpoint,
        "process_instance_id": instance,
        "event_type": etype,
        "attributes": attrs or {},
    }


def alert_map(alerts):
    """末阶段事件 ID -> 规范证据链，便于断言。"""
    return {a.last_event_id: a.evidence_event_ids for a in alerts}


# ---------------------------------------------------------------------------
# 场景一：最近的中间候选无法补齐前缀，较早候选才能形成完整链；
#         同时存在不同跨度与相同跨度的多条链。
# ---------------------------------------------------------------------------

def test_earlier_intermediate_completes_chain_not_nearest():
    rule = load_rule({
        "name": "three-stage",
        "stages": [
            {"event_type": "a"},
            {"event_type": "b"},
            {"event_type": "c"},
        ],
        "max_intervals_ms": [500, 1000],
    })
    events = [
        ev("a1", 0, "a"),
        ev("b1", 100, "b"),   # 较早的 b：能接上 a1
        ev("b2", 900, "b"),   # 最近的 b：距 a1 为 900 > 500，无法补齐前缀
        ev("c1", 1000, "c"),  # 末阶段：只能经 b1 成链
    ]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"c1": ("a1", "b1", "c1")}


def test_multiple_last_events_each_produce_one_alert():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [1000],
    })
    events = [
        ev("a1", 0, "a"),
        ev("b1", 100, "b"),
        ev("b2", 200, "b"),
        ev("b3", 5000, "b"),  # 间隔超限，不能作为末阶段
    ]
    alerts = detect(events, rule)
    # b1、b2 各产生且只产生一条告警；b3 无告警。
    assert alert_map(alerts) == {"b1": ("a1", "b1"), "b2": ("a1", "b2")}


def test_min_span_wins_over_lexicographic():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [1000],
    })
    events = [
        ev("a1", 0, "a"),     # 链跨度 500
        ev("a9", 400, "a"),   # 链跨度 100，ID 虽大但跨度最小
        ev("b1", 500, "b"),
    ]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"b1": ("a9", "b1")}


def test_equal_span_tie_breaks_by_timestamp_then_id():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [1000],
    })
    events = [
        ev("a2", 0, "a"),     # 与 a1 同跨度 500，字典序更大
        ev("a1", 0, "a"),
        ev("b1", 500, "b"),
    ]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"b1": ("a1", "b1")}


def test_tie_break_compares_full_chain_elementwise():
    # 三阶段：首事件相同，比较第二阶段的 (时间戳, ID)。
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}, {"event_type": "c"}],
        "max_intervals_ms": [1000, 1000],
    })
    events = [
        ev("a1", 0, "a"),
        ev("b2", 100, "b"),   # 与 b1 同时间戳，ID 更大
        ev("b1", 100, "b"),
        ev("c1", 200, "c"),
    ]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"c1": ("a1", "b1", "c1")}


# ---------------------------------------------------------------------------
# 场景二：阶段条件重叠、相同时间戳、边界间隔、混入其他终端/进程实例。
# ---------------------------------------------------------------------------

def test_overlapping_stage_conditions_need_distinct_events():
    rule = load_rule({
        "name": "overlap",
        "stages": [
            {"event_type": "ev", "attributes": {"k": "1"}},
            {"event_type": "ev", "attributes": {"k": "1"}},
        ],
        "max_intervals_ms": [100],
    })
    # 单个事件不能同时充当两个阶段（链内须严格递增）。
    assert detect([ev("e1", 0, "ev", attrs={"k": "1"})], rule) == []
    events = [
        ev("e1", 0, "ev", attrs={"k": "1"}),
        ev("e2", 10, "ev", attrs={"k": "1"}),
        ev("e3", 20, "ev", attrs={"k": "2"}),  # 属性不满足，不匹配
    ]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"e2": ("e1", "e2")}


def test_missing_attribute_does_not_match():
    rule = load_rule({
        "name": "r",
        "stages": [
            {"event_type": "a", "attributes": {"need": "x"}},
            {"event_type": "b"},
        ],
        "max_intervals_ms": [100],
    })
    events = [
        ev("a1", 0, "a"),                       # 缺少所需属性
        ev("a2", 10, "a", attrs={"need": "y"}),  # 值不等
        ev("b1", 20, "b"),
    ]
    assert detect(events, rule) == []


def test_same_timestamp_chains_by_id_order():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [100],
    })
    # 相同时间戳，ID 字典序递增 => 合法链。
    events = [ev("e2", 100, "b"), ev("e1", 100, "a")]
    alerts = detect(events, rule)
    assert alert_map(alerts) == {"e2": ("e1", "e2")}
    # 相同时间戳，ID 顺序不符 => 不能成链。
    events2 = [ev("e1", 100, "b"), ev("e2", 100, "a")]
    assert detect(events2, rule) == []


def test_adjacent_interval_boundary_inclusive():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [600000],
    })
    ok = [ev("a1", 0, "a"), ev("b1", 600000, "b")]
    assert alert_map(detect(ok, rule)) == {"b1": ("a1", "b1")}
    too_far = [ev("a1", 0, "a"), ev("b1", 600001, "b")]
    assert detect(too_far, rule) == []


def test_total_span_boundary_inclusive():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}, {"event_type": "c"}],
        "max_intervals_ms": [600000, 600000],
    })
    ok = [ev("a1", 0, "a"), ev("b1", 300000, "b"), ev("c1", 600000, "c")]
    alerts = detect(ok, rule)
    assert alert_map(alerts) == {"c1": ("a1", "b1", "c1")}
    assert alerts[0].span_ms == 600000
    # 相邻间隔各自合法，但总跨度 600001 超限。
    too_long = [ev("a1", 0, "a"), ev("b1", 300000, "b"), ev("c1", 600001, "c")]
    assert detect(too_long, rule) == []


def test_other_endpoint_and_instance_not_used_as_evidence():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [1000],
    })
    events = [
        ev("a1", 0, "a"),                                  # p1 的 a
        ev("a2", 490, "a", instance="p2"),                 # 其他进程实例的 a（更近）
        ev("a3", 495, "a", endpoint="h2"),                 # 其他终端的 a（更近）
        ev("b1", 500, "b"),                                # p1 的末阶段
        ev("b2", 600, "b", instance="p2"),                 # p2 自己的末阶段
    ]
    alerts = detect(events, rule)
    result = alert_map(alerts)
    # p1 的链不得误用 p2 / h2 的事件；p2 的链只能用 p2 的事件。
    assert result["b1"] == ("a1", "b1")
    assert result["b2"] == ("a2", "b2")
    assert len(alerts) == 2
    for alert in alerts:
        assert alert.endpoint_id == "h1"
        assert alert.process_instance_id in {"p1", "p2"}


def test_input_order_does_not_change_results():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}, {"event_type": "c"}],
        "max_intervals_ms": [500, 1000],
    })
    base = [
        ev("a1", 0, "a"),
        ev("a2", 50, "a"),
        ev("b1", 100, "b"),
        ev("b2", 900, "b"),
        ev("c1", 1000, "c"),
        ev("c2", 1100, "c"),
        ev("x1", 60, "a", instance="p2"),
        ev("x2", 120, "b", instance="p2"),
        ev("y1", 70, "a", endpoint="h2"),
        ev("y2", 130, "b", endpoint="h2"),
    ]
    expected = detect(base, rule)
    assert expected  # 确保用例本身有告警
    # 反序与若干确定性打乱顺序，结果必须完全一致。
    variants = [list(reversed(base))]
    for seed in (1, 7, 42):
        shuffled = sorted(base, key=lambda e: hash((seed, e["event_id"])))
        variants.append(shuffled)
    for variant in variants:
        assert detect(variant, rule) == expected


def test_shared_events_reused_across_alerts():
    rule = load_rule({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [1000],
    })
    events = [ev("a1", 0, "a"), ev("b1", 100, "b"), ev("b2", 200, "b")]
    alerts = detect(events, rule)
    # 同一事件 a1 被不同告警复用。
    assert alert_map(alerts) == {"b1": ("a1", "b1"), "b2": ("a1", "b2")}


# ---------------------------------------------------------------------------
# 输入与规则校验。
# ---------------------------------------------------------------------------

def test_accepts_telemetry_event_objects_and_json_rule_string():
    rule_json = json.dumps({
        "name": "r",
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [100],
    })
    events = [
        TelemetryEvent("a1", 0, "h1", "p1", "a", {}),
        TelemetryEvent("b1", 50, "h1", "p1", "b", {}),
    ]
    alerts = detect(events, load_rule(rule_json))
    assert alert_map(alerts) == {"b1": ("a1", "b1")}
    assert alerts[0].rule_name == "r"


def test_duplicate_event_id_rejected():
    rule = load_rule({
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [100],
    })
    events = [ev("e1", 0, "a"), ev("e1", 1, "b")]
    with pytest.raises(ValueError):
        detect(events, rule)


@pytest.mark.parametrize("bad_rule", [
    {},                                                     # 缺 stages
    {"stages": [{"event_type": "a"}], "max_intervals_ms": []},  # 阶段数不足
    {"stages": [{"event_type": "a"}, {"event_type": "b"}],
     "max_intervals_ms": []},                               # 间隔数量不符
    {"stages": [{"event_type": "a"}, {"event_type": "b"}],
     "max_intervals_ms": [0]},                              # 间隔小于 1
    {"stages": [{"event_type": "a"}, {"event_type": "b"}],
     "max_intervals_ms": [600001]},                         # 间隔超过上限
    {"stages": [{"event_type": "a"}, {"event_type": "b"}],
     "max_intervals_ms": [100], "max_total_span_ms": 600001},  # 总跨度超过上限
    {"stages": [{"attributes": {}}, {"event_type": "b"}],
     "max_intervals_ms": [100]},                            # 缺 event_type
])
def test_invalid_rules_rejected(bad_rule):
    with pytest.raises(ValueError):
        load_rule(bad_rule)


def test_default_total_span_is_600000():
    rule = load_rule({
        "stages": [{"event_type": "a"}, {"event_type": "b"}],
        "max_intervals_ms": [600000],
    })
    assert rule.max_total_span_ms == 600000
