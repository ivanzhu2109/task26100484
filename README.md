# edr_chain — EDR 离线行为链检测库

纯 Python、零依赖的离线行为链检测库。调用方提供 JSON 规则与遥测事件，
库在内存中完成计算并返回告警，不读写磁盘、不依赖任何外部服务。

## 快速开始

```python
from edr_chain import Event, detect, load_rule_json

rule = load_rule_json("""
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
""")

events = [
    Event("EV-2", 2000, "host-1", "proc-inst-9", "network_connect", {"DestPort": "443"}),
    Event("EV-1", 1000, "host-1", "proc-inst-9", "process_create", {"Image": "cmd.exe"}),
]

for alert in detect(events, rule):
    print(alert.final_event_id, alert.evidence_event_ids)
# EV-2 ('EV-1', 'EV-2')
```

输入顺序任意：同一批遥测以任何顺序提供，告警集合与每条规范证据链完全一致。

## 数据模型

### 遥测事件 `Event`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | `str` | 全局唯一 ASCII 事件 ID |
| `ts_ms` | `int` | 整数毫秒时间戳 |
| `endpoint_id` | `str` | 终端 ID |
| `process_instance_id` | `str` | 进程实例 ID（由调用方提供，非可复用的 PID） |
| `event_type` | `str` | 事件类型 |
| `attributes` | `dict[str, str]` | 字符串属性 |

### 规则（JSON）

```json
{
  "name": "规则名",
  "max_total_span_ms": 600000,
  "stages": [
    {
      "event_type": "事件类型",
      "conditions": {"属性名": "期望值"},
      "max_gap_to_next_ms": 5000
    }
  ]
}
```

- `stages`：按顺序的多个阶段。每阶段由事件类型与若干属性等值条件组成，
  全部满足才算匹配；事件缺少所需属性则不匹配。不同阶段的条件可以重叠。
- `max_gap_to_next_ms`：本阶段与下一阶段的最大允许间隔，取值 1–600000，
  最后一个阶段不配置。
- `max_total_span_ms`：整条链首末时间差上限，默认 600000。
  两类上限均包含边界。

用 `load_rule(dict)` 或 `load_rule_json(str)` 载入；非法规则抛出 `ValueError`。

### 告警 `Alert`

| 字段 | 说明 |
| --- | --- |
| `rule_name` | 规则名 |
| `final_event_id` | 末阶段事件 ID |
| `evidence_event_ids` | 规范证据链，首到末的完整事件 ID 序列 |

## 检测语义

- 合法链来自同一终端的同一进程实例，每阶段恰好选取一条匹配事件。
- 链内按 (时间戳, 事件 ID) 严格递增；ID 按 ASCII 字典序比较，
  相同时间戳的事件可依 ID 顺序组成链。
- 同一事件可被不同告警复用；不同终端/进程实例的事件绝不混用。
- 每个能作为合法链末阶段的事件产生且只产生一条告警。
- 同一末阶段事件有多条合法链时，先选首末时间差最小者；
  仍并列时按 (时间戳, ID) 逐项比较，选字典序最小的完整链。
- 告警按末阶段事件的 (时间戳, 事件 ID) 升序返回。

## 运行测试

```bash
python3 -m pytest tests -q
```
