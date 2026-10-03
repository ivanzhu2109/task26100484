"""规则 JSON 载入与校验测试。"""

from __future__ import annotations

import pytest

from edr_chain import Event, detect, load_rule, load_rule_json

RULE_JSON = """
{
  "name": "cmd-then-net",
  "stages": [
    {
      "event_type": "process_create",
      "conditions": {"Image": "cmd.exe"},
      "max_gap_to_next_ms": 5000
    },
    {
      "event_type": "network_connect",
      "conditions": {"DestPort": "443"}
    }
  ]
}
"""


def test_load_rule_json_and_detect():
    rule = load_rule_json(RULE_JSON)
    assert rule.name == "cmd-then-net"
    assert len(rule.stages) == 2
    assert rule.stages[0].max_gap_to_next_ms == 5000
    assert rule.max_total_span_ms == 600_000

    events = [
        Event("E2", 2000, "ep", "pi", "network_connect", {"DestPort": "443"}),
        Event("E1", 1000, "ep", "pi", "process_create", {"Image": "cmd.exe"}),
    ]
    alerts = detect(events, rule)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "cmd-then-net"
    assert alerts[0].evidence_event_ids == ("E1", "E2")


def test_load_rule_rejects_invalid_rules():
    bad_rules = [
        {},  # 缺 name / stages
        {"name": "r", "stages": []},  # 空阶段
        {"name": "r", "stages": [{"event_type": "a"}, {"event_type": "b"}]},  # 缺间隔
        {  # 间隔超出上限
            "name": "r",
            "stages": [
                {"event_type": "a", "max_gap_to_next_ms": 600001},
                {"event_type": "b"},
            ],
        },
        {  # 末阶段多配间隔
            "name": "r",
            "stages": [
                {"event_type": "a", "max_gap_to_next_ms": 1},
                {"event_type": "b", "max_gap_to_next_ms": 1},
            ],
        },
        {  # 条件值不是字符串
            "name": "r",
            "stages": [{"event_type": "a", "conditions": {"k": 1}}],
        },
        {  # 总跨度超限
            "name": "r",
            "stages": [{"event_type": "a"}],
            "max_total_span_ms": 600001,
        },
    ]
    for data in bad_rules:
        with pytest.raises(ValueError):
            load_rule(data)
