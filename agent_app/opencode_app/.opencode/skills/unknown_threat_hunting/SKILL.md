---
name: unknown_threat_hunting
description: 当用户希望基于 OpenCTI 关联图谱，从威胁组织、恶意软件或 IOC 假设出发执行未知威胁猎杀，并输出事实与推断分离的调查报告时触发。
---

# Trigger & Context (触发条件与上下文)

当用户提出下列意图之一时触发本技能：

- 以某个 `intrusion-set` 为起点，查询其相关恶意软件、IOC、基础设施和潜在共用关系。
- 基于图谱关联，寻找“尚未被直接告警但值得进一步调查”的威胁线索。
- 输出面向猎杀工程师的结构化报告，明确区分直接事实（Fact）与图谱推断（Inference）。

本技能当前只依赖 `opencti` 这一 `sourceId` 作为最小闭环数据源；其他车辆域数据源不作为本场景的前置依赖。

# Prerequisites (槽位/前置依赖提取)

执行前必须从用户输入中提取或确认以下槽位：

- `hunt_seed_type`：优先支持 `intrusion-set`；若用户给的是恶意软件、基础设施或 IOC，先归一化为可查询的猎杀种子。
- `hunt_seed_value`：例如 `APT29`、`WellMess`、某个域名、某个 IP 或某个文件哈希。
- `max_first_hop`：第一阶段图谱展开上限，默认建议 `25`。
- `max_second_hop`：第二阶段共享线索回溯上限，默认建议 `25`。
- `time_window`：如用户要求限定 `first_seen` / `last_seen` 时间窗时使用；否则不强加时间过滤。

如果缺少 `hunt_seed_value`，必须先向用户请求补充。若 `catalog` 或 `schema` 步骤确认 `opencti` 不存在或缺失关键对象类型，则停止查询并输出结构化空结果。

# SOP Action Steps (标准作业步骤)

## Step 1. Catalog

先验证目标数据源是否可用，严格使用唯一工具 `ai4x_query`：

```json
{
  "command": "catalog"
}
```

判定规则：

- 必须在返回结果中确认存在 `sourceId=opencti`。
- 若不存在，直接输出空结果：`status=empty`、`missing_source=["opencti"]`，禁止继续猜测或编造。

## Step 2. Schema

在任何真实查询前，读取 `opencti` 的 Schema：

```json
{
  "command": "schema",
  "sourceId": "opencti"
}
```

必须从 Schema 中确认以下对象类型或字段可用后再构造 Cypher：

- `intrusion-set`
- `malware`
- `indicator`
- `infrastructure`
- `relationship`（至少含 `source_ref`、`target_ref`、`relationship_type`）
- 如需落地 IOC 实体，优先确认 `domain-name`、`ipv4-addr`、`file`
- 如需环境命中证据，确认 `sighting`、`observed-data`

如果 Schema 未暴露某类对象或字段，只能降级流程或在输出中标记 `data_gap`，禁止擅自假设字段存在。

## Step 3. Query Phase A - 发现直接关联事实

以 `intrusion-set` 为主路径，先获取第一层和第二层事实实体，形成“组织 -> 恶意软件/基础设施/指标 -> IOC 候选”的证据图。查询前再次确认 Cypher 只使用 Schema 已暴露的对象类型和字段。

建议查询示例：

```json
{
  "command": "query",
  "sourceId": "opencti",
  "cypher": "MATCH (seed:`intrusion-set`) WHERE seed.name = $hunt_seed_value OR $hunt_seed_value IN coalesce(seed.aliases, []) MATCH (rel1:relationship) WHERE rel1.source_ref = seed.id OR rel1.target_ref = seed.id MATCH (neighbor) WHERE ((rel1.source_ref = seed.id AND rel1.target_ref = neighbor.id) OR (rel1.target_ref = seed.id AND rel1.source_ref = neighbor.id)) AND any(label IN labels(neighbor) WHERE label IN ['malware', 'indicator', 'infrastructure', 'tool', 'campaign']) OPTIONAL MATCH (rel2:relationship) WHERE rel2.source_ref = neighbor.id OR rel2.target_ref = neighbor.id OPTIONAL MATCH (pivot) WHERE ((rel2.source_ref = neighbor.id AND rel2.target_ref = pivot.id) OR (rel2.target_ref = neighbor.id AND rel2.source_ref = pivot.id)) AND any(label IN labels(pivot) WHERE label IN ['indicator', 'infrastructure', 'domain-name', 'ipv4-addr', 'file']) RETURN seed.id AS seed_id, seed.name AS seed_name, collect(DISTINCT {relationship_type: rel1.relationship_type, entity_id: neighbor.id, entity_labels: labels(neighbor), entity_name: coalesce(neighbor.name, neighbor.value, neighbor.pattern, 'unknown')})[..$max_first_hop] AS first_hop_facts, collect(DISTINCT {via_entity_id: neighbor.id, relationship_type: rel2.relationship_type, pivot_id: pivot.id, pivot_labels: labels(pivot), pivot_value: coalesce(pivot.name, pivot.value, pivot.pattern, 'unknown')})[..$max_first_hop] AS pivot_candidates"
}
```

执行要求：

- 如果用户提供的种子不是 `intrusion-set`，仅在 Schema 已确认相应对象类型可用时改写 `MATCH` 起点。
- 第一阶段输出只能记录直接查询命中的实体与关系，不做归因结论。
- 若 `first_hop_facts` 与 `pivot_candidates` 全为空，返回结构化空结果并结束流程。

## Step 4. Query Phase B - 共享线索与潜在线索回溯

对 Phase A 产出的 `pivot_candidates` 做第二次只读回溯，寻找与这些 IOC/基础设施共享的其他组织、恶意软件或基础设施，形成“未知威胁猎杀”的候选线索。

建议查询示例：

```json
{
  "command": "query",
  "sourceId": "opencti",
  "cypher": "UNWIND $pivot_ids AS pivot_id MATCH (pivot) WHERE pivot.id = pivot_id MATCH (rel:relationship) WHERE rel.source_ref = pivot.id OR rel.target_ref = pivot.id MATCH (other) WHERE ((rel.source_ref = pivot.id AND rel.target_ref = other.id) OR (rel.target_ref = pivot.id AND rel.source_ref = other.id)) AND any(label IN labels(other) WHERE label IN ['intrusion-set', 'malware', 'infrastructure', 'indicator']) WITH pivot, rel, other WHERE NOT ('intrusion-set' IN labels(other) AND other.name = $hunt_seed_value) RETURN collect(DISTINCT {pivot_id: pivot.id, pivot_labels: labels(pivot), pivot_value: coalesce(pivot.name, pivot.value, pivot.pattern, 'unknown'), relationship_type: rel.relationship_type, related_id: other.id, related_labels: labels(other), related_value: coalesce(other.name, other.value, other.pattern, 'unknown')})[..$max_second_hop] AS shared_leads"
}
```

执行要求：

- 只把 `shared_leads` 作为候选线索，不直接宣称“同一组织共用基础设施”已经被证实。
- 仅当关系链条完整且来自查询结果时，才允许在 `Inference` 中描述“可能共用基础设施”“可能存在共同投递链”之类的推断。

## Step 5. Optional Query Phase C - 环境命中验证

如果 `schema(opencti)` 明确包含 `sighting` 与 `observed-data`，可对高价值 `indicator` 或 `infrastructure` 追加一次验证查询，用于区分“纯情报线索”和“已在环境中被观测的线索”。

建议查询示例：

```json
{
  "command": "query",
  "sourceId": "opencti",
  "cypher": "UNWIND $candidate_indicator_ids AS indicator_id MATCH (indicator:indicator {id: indicator_id}) MATCH (s:sighting {sighting_of_ref: indicator.id}) OPTIONAL MATCH (obs:`observed-data`) WHERE any(ref IN coalesce(s.observed_data_refs, []) WHERE ref = obs.id) RETURN collect(DISTINCT {indicator_id: indicator.id, sighting_id: s.id, first_seen: s.first_seen, last_seen: s.last_seen, observed_data_id: obs.id, observed_first_seen: obs.first_observed, observed_last_seen: obs.last_observed}) AS environment_hits"
}
```

如果 Schema 未暴露 `observed_data_refs` 或相关对象，则跳过本步骤，并在结果中明确写入 `environment_validation: not_available`。

## Step 6. 事实与推断分离

整理输出时必须遵守：

- `Fact` 只包含查询直接返回的对象、字段、关系链和计数。
- `Inference` 只包含基于 Fact 的图谱推断，并注明触发该推断的证据路径。
- 若任何阶段未命中，则返回结构化空结果，禁止用模型常识补足缺失数据。

# Data Enhancement Suggestions (数据扩充建议)

当前数据源不能完美支撑该技能，建议如下：

1. 在 `opencti` 数据源中补充 `indicator` 到 `domain-name` / `ipv4-addr` / `file` 的显式规范化关联字段或对象引用，避免只能从 `pattern` 文本中间接解析 IOC。
2. 在 `opencti` 数据源中确保 `sighting`、`observed-data`、`where_sighted_refs`、`observed_data_refs` 等命中证据字段稳定可查询，以支撑“情报关联”到“环境命中”的闭环。
3. 若目标是判断“我方环境是否存在相关痕迹”，建议未来新增一个内部遥测数据源（如网络流量、EDR、DNS、代理日志），并与 `opencti` 的 IOC 做统一关联；仅靠当前公开 Schema 仍偏向情报图谱分析，而非环境落地验证。
4. 若需要把猎杀线索直接映射到车端资产影响，建议未来增加 `opencti` 与 `vehicle_iobe` / `vehicle_func` 的跨源关联键，例如域名、IP、组件标识或软件版本映射字段。

# Output Format (输出规范)

统一返回 Markdown + JSON 双层结构，且必须显式分离 `Fact` 与 `Inference`。

必需字段清单：`request_id`、`hunt_seed`、`evidence_paths`、`derived_leads`、`confidence_statement`、`recommended_actions`。

Markdown 结构：

```markdown
## Hunt Summary
- Hunt Seed: <hunt_seed_value>
- Status: success | empty | partial

## Fact
- Direct entities: ...
- Direct relationships: ...
- Evidence paths: ...

## Inference
- Derived leads: ...
- Confidence statement: ...

## Gaps
- Missing sources / fields / schema limits: ...

## Recommended Actions
- Next investigation steps: ...
```

JSON 结构：

```json
{
  "request_id": "string",
  "hunt_seed": {
    "type": "intrusion-set",
    "value": "APT29"
  },
  "status": "success",
  "facts": {
    "direct_entities": [],
    "direct_relationships": [],
    "evidence_paths": []
  },
  "inference": {
    "derived_leads": [],
    "confidence_statement": "string"
  },
  "environment_validation": {
    "status": "available_or_not_available",
    "hits": []
  },
  "data_gaps": [],
  "recommended_actions": []
}
```

空结果时必须返回：

- `status: "empty"`
- `facts.direct_entities: []`
- `facts.direct_relationships: []`
- `inference.derived_leads: []`
- `recommended_actions` 仅包含后续补充数据或调整猎杀假设的建议