---
name: peer-group-report-linkage
description: 当用户提供攻击事件报告标题、事件摘要文本或相关实体名，并希望从报告出发识别直接相关群组和同级候选群组、共享证据链及后续验证建议时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供报告标题，希望查询与该报告直接相关的攻击者群组。
- 希望从报告、恶意软件、攻击模式或组织入口扩展出同级候选群组。
- 希望得到报告事实摘要、共享证据链、候选关系、排除项和验证建议。

本技能仅使用 `opencti` 数据源做只读分析，不扩展到车辆侧对象、TARA 风险或 SES 需求。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `entry_type`: 允许值为 `report_title`、`report_summary_text`、`actor_name`、`malware_or_tool_name`、`campaign_name`。
- `entry_value`: 用户提供的标题、文本或实体值。
- `time_range`: 可选增强条件。若用户提供，则用于缩小报告范围；否则不是硬性前置条件。
- `analysis_goal`: 默认值为 `peer_group_linkage_from_report`。

提取与追问规则：

- 若用户提供的是事件摘要文本，先抽取可能的报告标题、组织名、恶意软件名或攻击模式，再进入同一查询 SOP。
- 若无法从文本中抽取任何可查询对象，必须先追问用户补充报告标题或实体名。
- 报告标题、组织名、恶意软件或 campaign 入口都可用，但如果已命中 `report`，优先围绕 `report` 扩展。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行查询前先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 必须严格区分 `Facts` 与 `Inferences`。
- 不能自动归因，只能输出直接相关群组和证据驱动的同级候选群组。
- 必须输出结构化排除项和空结果。

## Step 1. 确认 opencti 数据源存在

先调用：

```text
ai4x_query(command="catalog")
```

确认目录中存在 `sourceId="opencti"`。

若不存在：

- 在 `Gaps` 中记录缺失数据源。
- 停止后续查询。
- 不得编造替代数据源。

## Step 2. 获取 opencti Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

重点确认以下对象是否可消费：

- `report`
- `intrusion-set`
- `threat-actor`
- `campaign`
- `malware`
- `tool`
- `infrastructure`
- `attack-pattern`
- `relationship`

如果 Schema 缺失计划使用的对象链路，必须在 `Gaps` 中说明并缩减后续查询范围。

## Step 3. 定位报告事实锚点

### 3A. report 标题入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(coalesce(r.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (r)-[rel]-(m) RETURN r, rel, m"
)
```

### 3B. actor / malware / campaign 入口

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE n.type IN ['intrusion-set','threat-actor','malware','tool','campaign'] AND toLower(coalesce(n.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (n)-[rel]-(m) RETURN n, rel, m"
)
```

入口判定规则：

- 若命中 `report`，以 `report` 作为主事实锚点。
- 若只命中组织、恶意软件、工具或 `campaign`，保留该对象为事实锚点，并尝试回溯到相邻 `report`。
- 若完全未命中，则返回结构化空结果。

## Step 4. 生成报告事实摘要

围绕已命中的 `report` 或其近邻对象，抽取报告事实摘要。摘要必须只包含查询命中的事实，例如：

- 报告标题
- 报告描述
- 报告相邻的已知 `intrusion-set` / `threat-actor`
- 报告相邻的 `malware` / `tool`
- 报告相邻的 `infrastructure`
- 报告相邻的 `attack-pattern`

推荐摘要查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(coalesce(r.name, '')) CONTAINS toLower($report_name) OPTIONAL MATCH path1=(r)-[*1..2]-(grp) WHERE grp.type IN ['intrusion-set','threat-actor'] OPTIONAL MATCH path2=(r)-[*1..2]-(mw) WHERE mw.type IN ['malware','tool'] OPTIONAL MATCH path3=(r)-[*1..2]-(infra {type: 'infrastructure'}) OPTIONAL MATCH path4=(r)-[*1..2]-(ap {type: 'attack-pattern'}) RETURN r, path1, grp, path2, mw, path3, infra, path4, ap"
)
```

## Step 5. 判定直接相关群组

`Directly Related Groups` 只允许收录以下类型：

- `intrusion-set`
- `threat-actor`

进入主输出的门槛：

- 该群组必须与报告之间存在可回溯的事实链。
- 事实链可以经过 `malware`、`tool`、`infrastructure` 或 `attack-pattern`，也可以直接与 `report` 邻接。
- 仅凭语义相似或弱共现，不得进入 `Directly Related Groups`。

## Step 6. 搜索同级候选群组

主查询链固定为：

- `report -> intrusion-set / threat-actor -> shared infrastructure / malware / attack-pattern -> peer groups`

候选群组允许类型：

- `intrusion-set`
- `threat-actor`
- `campaign`

候选门槛：

- 与报告中的已知群组共享至少一类关键对象。
- 并且存在第二条辅助证据。

允许作为第二条辅助证据的对象：

- 共享 `infrastructure`
- 共享 `malware` / `tool`
- 共享 `attack-pattern`
- 共享 `campaign`

候选搜索查询示例：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(coalesce(r.name, '')) CONTAINS toLower($report_name) MATCH (r)-[*1..2]-(known_group) WHERE known_group.type IN ['intrusion-set','threat-actor'] MATCH (known_group)-[*1..2]-(shared) WHERE shared.type IN ['infrastructure','malware','tool','attack-pattern','campaign'] MATCH (candidate)-[*1..2]-(shared) WHERE candidate.type IN ['intrusion-set','threat-actor','campaign'] AND candidate.id <> known_group.id OPTIONAL MATCH (known_group)-[*1..2]-(aux) WHERE aux.type IN ['infrastructure','malware','tool','attack-pattern','campaign'] OPTIONAL MATCH (candidate)-[*1..2]-(aux) RETURN r, known_group, shared, candidate, collect(DISTINCT aux) AS auxiliary_evidence"
)
```

判定规则：

- 满足门槛的对象进入 `Peer Group Candidates`。
- 只共享一类对象、没有第二条辅助证据的对象进入 `Exclusions`。

## Step 7. 形成排除项和建议

### 7A. Exclusions

必须列出搜索过但证据不足的群组或路径，例如：

- 仅共享单一基础设施，没有第二条辅助证据。
- 仅与已知群组存在弱连接路径，无法形成稳定事实链。
- 与报告只存在间接邻接，但不能回溯到已知群组链路。

### 7B. Recommendations

后续建议应聚焦于进一步验证候选群组，而不是宣称确定同源。例如：

- 继续检查共享基础设施是否仍与候选群组相邻。
- 对共享恶意软件或攻击模式补查更多报告邻接对象。
- 对排除项说明还缺哪类证据才值得重新纳入分析。

# Data Enhancement Suggestions (数据扩充建议)

当前 `opencti` 聚合 Schema 可支撑基础的报告到同级群组关联分析，但若要更稳定地做同级群组识别，建议补充如下：

1. 为 `report` 增加更明确的主题、来源和验证状态字段，便于区分强事实报告和弱引用报告。
2. 为 `intrusion-set`、`threat-actor` 与 `campaign` 增加更清晰的层级或同级关系标识，降低仅凭共享对象推断“同级”的歧义。
3. 为 `attack-pattern`、`malware`、`infrastructure` 增加时效字段，便于判断共享证据是否仍具备当前相关性。
4. 若希望自动化生成更稳定的报告事实摘要，建议新增报告归一化中间对象或结构化摘要字段。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Report Facts Summary
- Report:
  - [报告标题]
  - [报告描述]
- Direct Evidence Objects:
  - [报告相邻的组织、恶意软件、基础设施、攻击模式]

## Directly Related Groups
- [群组名称]
  - type: intrusion-set|threat-actor
  - confidence: high|medium|low
  - supporting_facts:
    - [报告到群组的可回溯事实链]

## Peer Group Candidates
- [候选名称]
  - type: intrusion-set|threat-actor|campaign
  - confidence: high|medium|low
  - supporting_facts:
    - [共享关键对象]
    - [第二条辅助证据]
  - inference: [只能写候选性结论]
  - review_required: yes

## Exclusions
- [对象名称]
  - reason: [证据不足原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Unresolved Links:
  - [未命中的链路或语义不稳定路径]

## Recommendations
- Next Validation Steps:
  - [进一步验证建议]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [若有部分命中事实则列出，否则为空数组]
- empty_segments:
  - [未命中的 report 或扩展链路]
- next_questions:
  - [建议用户补充的报告标题、组织名或相关实体]
```

输出约束：

- 必须显式区分 `Directly Related Groups` 与 `Peer Group Candidates`。
- 置信度仅允许使用 `high`、`medium`、`low` 三档，依据证据覆盖度给出。
- 不得把候选群组写成确定归因结论。
- 必须包含报告事实摘要和排除项。