# edr_chain — EDR 离线行为链检测库

由上层直接调用的纯内存 Python 库：载入一条 JSON 规则，对调用方提供的一批
遥测事件计算告警。无外部服务依赖，不监听端口，不做任何持久化。

## 概念

- **遥测事件**：全局唯一 ASCII 事件 ID、整数毫秒时间戳、终端 ID、
  进程实例 ID（调用方保证唯一，不用可复用 PID）、事件类型、字符串属性。
- **规则**：多个顺序阶段，每阶段由事件类型 + 若干属性等值条件组成；
  每对相邻阶段配置 1..600000 毫秒的最大允许间隔；
  整条链首末时间差不超过 600000 毫秒（两类上限均含边界）。
- **合法链**：同一终端同一进程实例内，每阶段恰好一条匹配事件，
  链内按 (时间戳, 事件 ID) 严格递增（ID 按 ASCII 字典序，
  相同时间戳可依照 ID 顺序成链）。同一事件可被不同告警复用。
- **告警**：每个能作为合法链末阶段的事件产生且只产生一条告警。
  同一末阶段事件有多条合法链时，先选首末时间差最小的链；
  仍并列时，将各链从首到末按 (时间戳, ID) 逐项比较，取字典序最小者。
  告警与输入顺序无关。

## 安装与测试

无第三方运行时依赖（Python 3.9+）。测试依赖 pytest：

```bash
python3 -m pytest tests/ -q
```

## 使用

```python
from edr_chain import detect, load_rule

rule = load_rule('''{
  "name": "suspicious-chain",
  "stages": [
    {"event_type": "process_create", "attributes": {"image": "cmd.exe"}},
    {"event_type": "file_write",     "attributes": {"path": "/tmp/x"}},
    {"event_type": "network_connect"}
  ],
  "max_intervals_ms": [5000, 60000]
}''')
# max_total_span_ms 可省略，默认且上限为 600000。

events = [
    {
        "event_id": "e1", "timestamp_ms": 1000,
        "endpoint_id": "host-1", "process_instance_id": "pi-9",
        "event_type": "process_create", "attributes": {"image": "cmd.exe"},
    },
    {
        "event_id": "e2", "timestamp_ms": 3000,
        "endpoint_id": "host-1", "process_instance_id": "pi-9",
        "event_type": "file_write", "attributes": {"path": "/tmp/x"},
    },
    {
        "event_id": "e3", "timestamp_ms": 8000,
        "endpoint_id": "host-1", "process_instance_id": "pi-9",
        "event_type": "network_connect", "attributes": {},
    },
]

alerts = detect(events, rule)
for alert in alerts:
    print(alert.last_event_id, alert.evidence_event_ids, alert.span_ms)
# e3 ('e1', 'e2', 'e3') 7000
```

事件也可以是 `TelemetryEvent` 实例；`load_rule` 同样接受已解析的 dict。

## API

- `load_rule(source) -> Rule`：从 JSON 字符串或 dict 载入并校验规则，
  非法规则抛 `ValueError`。
- `detect(events, rule) -> list[Alert]`：执行单次检测。
  输入顺序任意；重复事件 ID 或字段类型非法抛 `ValueError`。
  返回告警按末阶段事件的 (时间戳, ID) 排序，结果确定。
- `Alert` 字段：`rule_name`、`endpoint_id`、`process_instance_id`、
  `last_event_id`、`evidence_event_ids`（首到末完整证据链）、
  `start_timestamp_ms`、`end_timestamp_ms`、`span_ms`。

## 项目结构

- `edr_chain/models.py` — `TelemetryEvent` / `Alert` 数据模型
- `edr_chain/rule.py` — 规则模型与 JSON 载入校验
- `edr_chain/engine.py` — 分组 + 按阶段动态规划的检测引擎
- `tests/test_engine.py` — 场景化自动化测试
