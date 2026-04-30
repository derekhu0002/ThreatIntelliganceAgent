---
name: unknown-threat-hunting
description: 当用户提供已知威胁实体、报告标题、IOC、攻击模式或漏洞编号，并希望基于关联图谱扩展发现潜在同源团伙、共享基础设施、可疑攻击链或未知威胁候选时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 从已知 threat-actor、intrusion-set、恶意软件、工具、基础设施或报告出发，扩展发现未知威胁候选。
- 希望识别共享基础设施、共享 indicator、共享 attack-pattern、共享 malware 或共享 campaign 的潜在关联。
- 希望获得“哪些对象值得继续追查、哪些对象证据不足应暂时排除”的猎杀结果。

本技能只使用 `opencti` 数据源进行只读分析，不跨入车辆侧组件、TARA 风险或 SES 需求分析。

# Prerequisites (槽位/前置依赖提取)

优先从用户输入提取以下槽位：

- `entry_type`: 允许值为 `report_title`、`actor_name`、`intrusion_set_name`、`malware_name`、`tool_name`、`indicator_or_infrastructure`、`attack_pattern_name`、`cve`。
- `entry_value`: 与入口类型对应的实际值。
- `time_range`: 可选增强条件。若用户提供，则用于缩小查询范围；否则不是硬性前置条件。
- `hunting_goal`: 默认值为 `expand_unknown_candidates`。

提取与追问规则：

- 所有入口等价，不设固定优先级。
- 若无法从输入中提取任何可查询入口，必须先追问用户补充一个具体对象名、报告标题、IOC 或漏洞编号。
- 如果用户只给出模糊描述，停止真实查询，仅返回需要补充的最小入口字段。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

在执行查询前，先声明以下规则：

- 仅允许使用 `ai4x_query`。
- 任何真实查询都必须遵循 `catalog -> schema -> query` 三步查询范式。
- 所有输出必须严格区分 `Facts` 与 `Inferences`。
- 本技能不做自动归因，只允许输出“候选关联”或“可能同源”。
- 空结果和排除项必须结构化输出，不能用模型补全未命中事实。

## Step 1. 确认 opencti 数据源存在

先调用：

```text
ai4x_query(command="catalog")
```

检查目录中是否存在 `sourceId="opencti"`。

如果不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不得编造替代数据源。

## Step 2. 获取 opencti Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

重点确认是否可消费以下对象：

- `report`
- `intrusion-set`
- `threat-actor`
- `campaign`
- `malware`
- `tool`
- `indicator`
- `infrastructure`
- `attack-pattern`
- `vulnerability`
- `identity`
- `relationship`

如果 Schema 中缺失某条计划中的对象链路，则在 `Gaps` 中注明并跳过相关扩展分支。

## Step 3. 以用户入口定位初始事实锚点

所有入口等价，按 `entry_type` 选择对应分支。先定位直接命中的对象，再从该对象向外扩展。

### 3A. 报告标题入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(coalesce(r.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (r)-[rel]-(m) RETURN r, rel, m"
)
```

### 3B. actor / intrusion-set 入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE n.type IN ['intrusion-set','threat-actor'] AND toLower(coalesce(n.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (n)-[rel]-(m) RETURN n, rel, m"
)
```

### 3C. malware / tool / attack-pattern / indicator / infrastructure 入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE n.type IN ['malware','tool','attack-pattern','indicator','infrastructure'] AND toLower(coalesce(n.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (n)-[rel]-(m) RETURN n, rel, m"
)
```

### 3D. vulnerability / CVE 入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (v {type: 'vulnerability'}) WHERE toLower(coalesce(v.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (v)-[rel]-(m) RETURN v, rel, m"
)
```

入口判定规则：

- 若命中 `report`，优先围绕其邻接对象扩展。
- 若命中其他对象，则保留该对象为事实锚点，并尝试找到与之相邻的 `report`、`intrusion-set` 或 `campaign`。
- 若完全未命中，返回结构化空结果。

## Step 4. 构建主猎杀链

本技能的主查询链为：

- `report -> related objects -> shared infrastructure / attack-pattern`

先围绕入口对象扩展以下事实对象：

- `infrastructure`
- `indicator`
- `attack-pattern`
- `malware`
- `tool`
- `campaign`
- `intrusion-set`
- `threat-actor`
- `identity`
- `vulnerability`

推荐主链查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE toLower(coalesce(seed.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH path1=(seed)-[*1..2]-(infra {type: 'infrastructure'}) OPTIONAL MATCH path2=(seed)-[*1..2]-(ap {type: 'attack-pattern'}) OPTIONAL MATCH path3=(seed)-[*1..2]-(mw) WHERE mw.type IN ['malware','tool'] OPTIONAL MATCH path4=(seed)-[*1..2]-(grp) WHERE grp.type IN ['intrusion-set','threat-actor','campaign'] RETURN seed, path1, infra, path2, ap, path3, mw, path4, grp"
)
```

事实抽取要求：

- 记录直接命中的对象、对象类型、关系类型和来源 `sourceId=opencti`。
- 对于 `path` 中未显式暴露的关系含义，只能原样引用底层返回结果，不得自行升格为确定归因语言。

## Step 5. 搜索未知候选对象

目标是寻找与已知入口共享关键对象的其他组织类候选。候选对象类型允许为：

- `intrusion-set`
- `threat-actor`
- `campaign`

搜索策略：

1. 从已命中的共享对象出发，优先寻找共享 `infrastructure` 或共享 `indicator` 的其他候选。
2. 再检查这些候选是否同时具备第二条辅助证据。

允许作为第二条辅助证据的对象或关系：

- 共享 `attack-pattern`
- 共享 `malware` / `tool`
- 共享 `indicator`
- 共享 `report` 邻接关系
- 共享 `vulnerability`
- 共享 `identity` / `campaign`

候选搜索查询示例：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE toLower(coalesce(seed.name, '')) CONTAINS toLower($entry_value) MATCH (seed)-[*1..2]-(shared) WHERE shared.type IN ['infrastructure','indicator'] MATCH (candidate)-[*1..2]-(shared) WHERE candidate.type IN ['intrusion-set','threat-actor','campaign'] AND candidate.id <> seed.id OPTIONAL MATCH (seed)-[*1..2]-(aux) WHERE aux.type IN ['attack-pattern','malware','tool','indicator','vulnerability','identity','campaign','report'] OPTIONAL MATCH (candidate)-[*1..2]-(aux) RETURN seed, shared, candidate, collect(DISTINCT aux) AS shared_auxiliary_evidence"
)
```

候选输出门槛：

- 至少共享 1 条 `infrastructure` 或 1 个 `indicator`。
- 并且存在第二条辅助证据。
- 不满足门槛的对象不得进入 `Unknown Candidates`，而应进入 `Exclusions`。

## Step 6. 形成候选结论与排除项

### 6A. Facts

只保留以下内容：

- 入口对象。
- 与入口对象直接或近邻相关的 `report`、`infrastructure`、`indicator`、`attack-pattern`、`malware`、`tool`、`campaign`、`intrusion-set`、`threat-actor`、`identity`、`vulnerability`。
- 命中的共享对象及其关联候选。

### 6B. Inferences

只允许输出以下类型的推断：

- 某候选对象与入口对象“可能同源”或“值得进一步追查”。
- 某条共享对象链可能说明基础设施复用、行动模式复用或组织协同。

禁止输出：

- “确定属于同一组织”
- “已经完成归因”
- “确认是同一攻击者”

### 6C. Exclusions

必须列出搜索过但未达到候选门槛的对象，并说明原因，例如：

- 仅共享单一对象，缺少辅助证据。
- 与入口对象的路径过长或语义不稳定。
- 仅存在报告邻接，但无共享基础设施或 indicator。

## Step 7. 生成后续验证建议

建议必须聚焦于进一步验证未知候选，而不是直接给出确定结论。可包含：

- 继续检查共享基础设施是否仍在活跃。
- 针对共享 indicator 搜索更多 sighting 或报告邻接对象。
- 对共享 malware / tool 的版本、投递方式、目标集进行二次比对。
- 对排除项说明还缺哪类证据才值得重新纳入猎杀范围。

# Data Enhancement Suggestions (数据扩充建议)

当前 `opencti` 聚合 Schema 可支撑基本的图谱关联猎杀，但若要更稳定地做未知威胁发现，建议增强如下：

1. 为 `attack-pattern` 增加更稳定的外部标识和 kill chain phase 字段，以便区别“共享对象”与“共享阶段语义”。
2. 为 `indicator` 与 `infrastructure` 增加统一的时效字段和状态字段，避免历史失效对象对当前猎杀造成误导。
3. 为 `report` 与 `campaign` 增加更规范的引用来源、时间范围和置信度字段，支持按时间窗和证据新鲜度筛选候选。
4. 若需要更可靠的候选组织聚类，建议补充同源证据标签或人工验证状态对象，避免所有关联都只能停留在推断层。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Entry Anchor:
  - sourceId: opencti
  - object: [入口对象]
- Shared Evidence:
  - [对象A(type)] --[relationship]--> [共享对象(type)]
- Candidate Links:
  - [共享对象(type)] --[relationship]--> [候选对象(type)]

## Unknown Candidates
- [候选对象名称]
  - confidence: high|medium|low
  - supporting_facts:
    - [共享基础设施或 indicator]
    - [第二条辅助证据]
  - inference: [只允许写“可能同源”或“值得进一步追查”]
  - review_required: yes

## Exclusions
- [对象名称]
  - reason: [为什么未达到候选门槛]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Unresolved Links:
  - [路径不稳定、语义不清或未命中的链路]

## Recommendations
- Next Validation Steps:
  - [进一步验证建议]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [若有已命中事实则列出，否则为空数组]
- empty_segments:
  - [未命中的入口或扩展链路]
- next_questions:
  - [建议用户补充的对象名、报告标题、IOC 或时间范围]
```

输出约束：

- 置信度仅允许使用 `high`、`medium`、`low` 三档，依据证据覆盖度给出。
- `Unknown Candidates` 仅包含满足门槛的候选。
- `Exclusions` 必须存在，只要检索过程中出现证据不足的对象就要列出。
- 不得把关联候选写成确定归因结论。---
name: unknown-threat-hunting
description: 当用户希望基于 OpenCTI 关联图谱，从威胁组织或相关 IOC 假设出发，执行未知威胁猎杀、识别共用基础设施或输出结构化猎杀报告时触发。
---

# Trigger & Context (触发条件与上下文)

当用户提出下列意图之一时触发本技能：

- 以某个 `intrusion-set` 为起点，查询其相关恶意软件、IOC、基础设施和潜在共用关系。
- 基于图谱关联，寻找“尚未被直接告警但值得进一步调查”的威胁线索。
- 验证某个 IOC 或基础设施是否同时关联多个威胁实体，从而形成新的猎杀方向。
- 输出面向威胁狩猎工程师的结构化报告，明确区分直接事实（Fact）与图谱推断（Inference）。

本技能当前只依赖 `opencti` 这一 `sourceId` 作为最小闭环数据源；其他车辆域数据源不作为本场景的前置依赖。

# Prerequisites (槽位/前置依赖提取)

执行前必须从用户输入中提取或确认以下槽位：

- `hunt_seed_type`：优先支持 `intrusion-set`；若用户给的是恶意软件、基础设施或 IOC，先归一化为可查询的猎杀种子。
- `hunt_seed_value`：例如 `APT29`、`WellMess`、某个域名、某个 IP 或某个文件哈希。
- `max_first_hop`：第一阶段图谱展开上限，默认建议 `25`。
- `max_second_hop`：第二阶段共享线索回溯上限，默认建议 `25`。
- `time_window`：如用户要求限定 `first_seen` / `last_seen` 时间窗时使用；否则不强加时间过滤。
- `report_goal`：例如“发现共享基础设施”“找到可落地排查的 IOC”“形成猎杀报告”。

如果缺少 `hunt_seed_value`，必须先向用户请求补充。若 `catalog` 或 `schema` 步骤确认 `opencti` 不存在或缺失关键对象类型，则停止查询并输出结构化空结果。若 `hunt_seed_type` 未明确，则默认优先按 `intrusion-set` 解释，并在输出中说明归一化假设。

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

Schema 审核要求：

- 若 Schema 只能确认对象类型，但无法确认某条关系的标签方向，则查询应退化为基于 `relationship.source_ref` / `relationship.target_ref` 的显式连接方式。
- 不得假设存在 OpenCTI 图数据库内部的派生边名称；一律以 Schema 已知的 STIX 对象和 `relationship` 字段为准。

如果 Schema 未暴露某类对象或字段，只能降级流程或在输出中标记 `data_gap`，禁止擅自假设字段存在。

## Step 3. Query Phase A - 发现直接关联事实

以 `intrusion-set` 为主路径，先获取第一层和第二层事实实体，形成“组织 -> 恶意软件/基础设施/指标 -> IOC 候选”的证据图。查询前再次确认 Cypher 只使用 Schema 已暴露的对象类型和字段。

建议查询示例：

```json
{
  "command": "query",
  "sourceId": "opencti",
  "cypher": "MATCH (seed:`intrusion-set`) WHERE seed.name = $hunt_seed_value OR $hunt_seed_value IN coalesce(seed.aliases, []) MATCH (rel1:relationship) WHERE rel1.source_ref = seed.id OR rel1.target_ref = seed.id MATCH (neighbor) WHERE ((rel1.source_ref = seed.id AND rel1.target_ref = neighbor.id) OR (rel1.target_ref = seed.id AND rel1.source_ref = neighbor.id)) AND any(label IN labels(neighbor) WHERE label IN ['malware', 'indicator', 'infrastructure', 'campaign', 'tool']) OPTIONAL MATCH (rel2:relationship) WHERE rel2.source_ref = neighbor.id OR rel2.target_ref = neighbor.id OPTIONAL MATCH (pivot) WHERE ((rel2.source_ref = neighbor.id AND rel2.target_ref = pivot.id) OR (rel2.target_ref = neighbor.id AND rel2.source_ref = pivot.id)) AND any(label IN labels(pivot) WHERE label IN ['indicator', 'infrastructure', 'domain-name', 'ipv4-addr', 'file']) RETURN seed.id AS seed_id, seed.name AS seed_name, collect(DISTINCT {relationship_type: rel1.relationship_type, entity_id: neighbor.id, entity_labels: labels(neighbor), entity_name: coalesce(neighbor.name, neighbor.value, neighbor.pattern, 'unknown')})[..$max_first_hop] AS first_hop_facts, collect(DISTINCT {via_entity_id: neighbor.id, relationship_type: rel2.relationship_type, pivot_id: pivot.id, pivot_labels: labels(pivot), pivot_value: coalesce(pivot.name, pivot.value, pivot.pattern, 'unknown')})[..$max_first_hop] AS pivot_candidates"
}
```

执行要求：

- 如果用户提供的种子不是 `intrusion-set`，仅在 Schema 已确认相应对象类型可用时改写 `MATCH` 起点。
- 第一阶段输出只能记录直接查询命中的实体与关系，不做归因结论。
- 如果查询命中 `indicator.pattern` 但没有显式 observable 对象，不要把模式文本解析结果写成事实实体；只能标记为“可进一步解析的 IOC 模式”。
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

建议证据路径表达：

- `intrusion-set(APT29) -> relationship -> malware(WellMess) -> relationship -> indicator(...)`
- `intrusion-set(APT29) -> relationship -> infrastructure(shared-domain) <- relationship <- intrusion-set(DarkHotel)`

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
- 若查询结果只支持“共享某个 pivot 对象”，则推断措辞必须使用“可能”“需进一步验证”，不得升级为确定性归因。

# Output Format (输出规范)

统一返回 Markdown + JSON 双层结构，且必须显式分离 `Fact` 与 `Inference`。

必需字段清单：`request_id`、`hunt_seed`、`evidence_paths`、`derived_leads`、`confidence_statement`、`recommended_actions`。

Markdown 结构：

```markdown
## Hunt Summary
- Hunt Seed: <hunt_seed_value>
- Status: success | empty | partial
- Report Goal: <report_goal>

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
  "report_goal": "identify shared infrastructure",
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