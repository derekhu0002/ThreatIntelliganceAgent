---
name: unknown-threat-hunt-graph-hypothesis
description: 当用户提供 intrusion-set、malware、indicator、domain、ip 或 infrastructure 作为狩猎种子，并希望基于图谱假设扩展发现新的待验证线索、共享基础设施或次级候选时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 从 `intrusion-set`、`malware`、`indicator`、`domain`、`ip`、`infrastructure` 出发，寻找新的高价值待验证线索。
- 希望识别共享基础设施、共享 IOC、共用恶意软件、次级团伙或值得继续追查的关系簇。
- 希望获得下一轮狩猎方向、证据路径和调查建议，而不是最终归因结论。

本技能默认以 `opencti` 为主数据源做只读分析；只有 `catalog` 明确存在 `vehicle_iobe` 且用户要求补充环境相关性时，才允许在同样的渐进式查询范式内做增强解释。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `seed.type`: 允许值为 `intrusion-set`、`malware`、`indicator`、`domain`、`ip`、`infrastructure`、`other`。
- `seed.value`: 狩猎起点实际值。
- `hunt_hypothesis`: 用户要验证的狩猎目标或线索方向。
- `focus_dimension`: 可选，允许关注 `infrastructure`、`indicator`、`intrusion-set`、`malware`、`environment-relevance`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `max_lead_count`: 可选，默认 `5`。

提取与追问规则：

- 如果无法提取任何有效种子对象，则先追问用户补充一个具体组织、恶意软件、域名、IP、IOC 或基础设施对象。
- 如果用户目标在“发现新线索”和“做最终归因”之间不清晰，先追问一次，不直接进入深度扩图。
- 如果用户没有说明输出深度或线索上限，可使用默认值，但必须在输出中显式说明。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。对 `opencti` 的 query 默认采用平台 `auto` 策略，优先提交更容易被 GraphQL 支持的最小只读查询，由平台在不支持时自动回落 replica。
- 必须严格区分 `Direct Facts` 与 `Inferred Assessments`。
- 本技能只输出候选线索和下一轮狩猎建议，不给出最终归因结论。
- 空结果和排除项必须结构化输出，不能用模型补全未命中事实。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_ai4x_query(command="catalog")
```

最少检查：

- `opencti` 是否存在。
- 如果用户要求环境相关性解释，`vehicle_iobe` 是否存在。

如果 `opencti` 不存在：

- 在 `Boundary Notes` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_ai4x_query(command="schema", sourceId="opencti")
ai4x_ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship-type|relationship-schema", typeName="...")
```

重点确认以下对象是否可消费：

- `intrusion-set`
- `threat-actor`
- `malware`
- `indicator`
- `infrastructure`
- `relationship`
- `report`
- `campaign`
- `domain-name`
- `ipv4-addr`
- `url`
- `file`
- `sighting`
- `observed-data`

如用户要求环境相关性增强，再检查：

```text
ai4x_ai4x_query(command="schema", sourceId="vehicle_iobe")
```

重点确认：

- `x-exposure-surface`
- `x-external-peer`
- `network-traffic`
- `relationship`

如果 Schema 未覆盖计划使用的对象或关系，必须在 `Pending Confirmations` 中说明并缩减后续查询链。

## Step 3. 建立初始事实锚点

根据 `seed.type` 优先定位最接近的事实锚点。

### 3A. intrusion-set / threat-actor 入口

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE seed.type IN ['intrusion-set','threat-actor'] AND toLower(coalesce(seed.name, '')) CONTAINS toLower($seed_value) OPTIONAL MATCH (seed)-[rel]-(adj) RETURN seed, rel, adj"
)
```

### 3B. malware / indicator / infrastructure 入口

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE seed.type IN ['malware','indicator','infrastructure'] AND (toLower(coalesce(seed.name, '')) CONTAINS toLower($seed_value) OR toLower(coalesce(seed.pattern, '')) CONTAINS toLower($seed_value)) OPTIONAL MATCH (seed)-[rel]-(adj) RETURN seed, rel, adj"
)
```

### 3C. domain / ip / other observable 入口

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE (seed.type IN ['domain-name','ipv4-addr','url','file'] AND toLower(coalesce(seed.value, coalesce(seed.name, ''))) CONTAINS toLower($seed_value)) OR (seed.type = 'indicator' AND toLower(coalesce(seed.pattern, '')) CONTAINS toLower($seed_value)) OPTIONAL MATCH (seed)-[rel]-(adj) RETURN seed, rel, adj"
)
```

入口判定规则：

- 若命中多个种子对象，优先选择与用户输入类型最一致的对象作为主锚点。
- 若仅命中弱匹配对象，保留结果但在 `Pending Confirmations` 中说明匹配不稳定。
- 若完全未命中，则返回结构化空结果。

## Step 4. 执行一跳事实查询

围绕主锚点，查询第一轮直接事实，目标是找出：

- 直接相邻的 `indicator`、`infrastructure`、`malware`、`report`、`campaign`。
- 与线索直接相邻的时间字段、置信度字段和来源引用。
- 可以继续落地到 `domain-name`、`ipv4-addr`、`url`、`file` 的 observable。

事实抽取要求：

- 只记录直接命中的对象、关系和来源数据源。
- 不在这一轮写入任何最终狩猎结论。

## Step 5. 执行二跳扩展查询

主扩展链为：

- `seed -> malware / indicator / infrastructure -> intrusion-set / threat-actor / campaign`
- `seed -> report -> related objects -> candidate groups`

推荐查询模板：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE id(seed) = $seed_id OPTIONAL MATCH path1=(seed)-[*1..2]-(shared1) WHERE shared1.type IN ['infrastructure','indicator'] OPTIONAL MATCH path2=(seed)-[*1..2]-(shared2) WHERE shared2.type IN ['malware','report','campaign'] OPTIONAL MATCH path3=(shared1)-[*1..2]-(candidate1) WHERE candidate1.type IN ['intrusion-set','threat-actor','campaign'] OPTIONAL MATCH path4=(shared2)-[*1..2]-(candidate2) WHERE candidate2.type IN ['intrusion-set','threat-actor','campaign'] RETURN seed, path1, shared1, path2, shared2, path3, candidate1, path4, candidate2"
)
```

真实执行时，`query` 调用必须保持 `ai4x_ai4x_query(command="query", sourceId="opencti", cypher="...")` 的显式数据源约束。

扩展要求：

- 优先寻找共享 `infrastructure` 或共享 `indicator` 的其他候选对象。
- 若候选只有单一共享对象，没有第二条辅助证据，则不得进入 `Ranked Leads`。
- 对高扩展度结果进行裁剪、去重和聚类，不得把全部子图原样带入后续评分。

## Step 6. 评估候选线索优先级

候选对象允许类型：

- `domain`
- `ip`
- `indicator`
- `infrastructure`
- `intrusion-set`
- `threat-actor`
- `campaign`

评估规则：

- 至少存在一条从 `seed` 到候选对象的可回溯路径。
- 共享基础设施或共享 IOC 加辅助证据的对象优先级更高。
- 时间新鲜度、来源多样性、环境相关性可提升优先级。
- 仅有单一路径、过期情报、单条弱关系或无环境相关性时，应降级为 `medium` 或 `low`。

优先级建议：

- `high`: 至少两条独立证据路径，且包含共享基础设施或共享 IOC。
- `medium`: 一条稳定路径，或两条但都依赖同类桥接对象。
- `low`: 只有弱共现、单点命中或待补充验证的路径。

## Step 7. 生成建议、待确认项与边界说明

### 7A. Recommended Actions

建议应聚焦于继续验证猎杀线索，例如：

- 检查共享基础设施是否仍然活跃。
- 对共享 IOC 扩展历史解析、关联 IP、URL 或样本。
- 若命中 `vehicle_iobe`，补充与我方暴露面的相关性解释。
- 若用户目标升级为最终归因，明确转交 `威胁溯源分析`。

### 7B. Pending Confirmations

必须列出仍需人工确认的内容，例如：

- 共享关系是否足以支撑组织级结论。
- 当前是否缺少 `sighting` 或 `observed-data`。
- 排除项还缺哪类证据才值得重新纳入。

### 7C. Boundary Notes

必须显式写明：

- 结果用于指导下一轮狩猎，不等同于最终归因。
- 当前结果不代表系统已执行任何阻断或响应动作。
- 未注册数据源不能被写成平台原生已验证事实。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Hunt Hypothesis Summary
- intent_id: biz.unknown-threat-hunting
- seed:
  - type: [intrusion-set|malware|indicator|domain|ip|infrastructure|other]
  - value: [seed.value]
- report_depth: [brief|standard|deep]
- max_lead_count: [number]

## Direct Facts
- [直接命中的对象、关系、来源、时间或置信度字段]

## Ranked Leads
- [lead_value]
  - lead_type: [domain|ip|indicator|infrastructure|intrusion-set|threat-actor|campaign]
  - priority: [high|medium|low]
  - why_it_matters: [为何值得继续调查]
  - recommended_next_step: [下一步动作]

## Evidence Paths
- [path_id]
  - path_summary: [Seed -> Bridge -> Candidate]
  - nodes:
    - [节点列表]

## Inferred Assessments
- [只能写基于事实链形成的候选性判断]

## Recommended Actions
- [后续调查与验证建议]

## Pending Confirmations
- [待人工确认的弱关系、缺失观测或边界条件]

## Boundary Notes
- [事实与推断边界、平台能力边界、未注册数据源边界]

## Empty Result Contract
- status: no_viable_leads | partial_hit
- reason: [未命中的原因或仅形成部分路径的说明]
```

# Structured Response Contract (结构化响应契约)

如需输出结构化 JSON，至少包含以下字段：

- `request_id`
- `intent_id`
- `seed`
- `summary`
- `direct_facts`
- `inferred_assessments`
- `ranked_leads`
- `evidence_paths`
- `recommended_actions`
- `pending_confirmations`
- `boundary_notes`

其中：

- `ranked_leads` 必须显式区分 `priority` 和 `recommended_next_step`。
- `evidence_paths` 必须能够回溯到种子对象。
- `pending_confirmations` 必须说明哪些内容还不能升格为最终结论。