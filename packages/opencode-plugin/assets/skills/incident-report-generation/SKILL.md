---
name: incident-report-generation
description: 当用户提供已确认事件摘要、恶意软件、IOC、攻击技术或相关活动实体，并希望生成可复核的攻击事件报告、同类群组关联和后续关注建议时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供已确认事件摘要，希望生成可流转的结构化事件报告。
- 希望围绕恶意软件、IOC、攻击技术或活动入口补齐威胁行为体、Campaign 和报告引用。
- 希望得到同类风险对象或同级群组候选，同时要求事实、推断和边界说明分层表达。

本技能首版仅使用 `opencti` 数据源做只读分析，不扩展到自动响应编排、整体态势评分或完整归因画像。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `event_type`: 允许值为 `ransomware_incident`、`malware_incident`、`phishing_incident`、`confirmed_security_incident` 等已确认事件类型。
- `event_summary`: 用户给出的事件摘要或标题。
- `core_entities`: 事件核心实体，优先包括 `malware`、`indicator`、`attack_pattern`、`campaign_hint`、`victim_identity`。
- `report_depth`: 可选值为 `brief`、`standard`、`deep`。
- `target_audience`: 可选读者角色。
- `need_peer_grouping`: 默认 `true`。
- `need_follow_up_recommendation`: 默认 `true`。

提取与追问规则：

- 若输入仍是未确认告警或单条 IOC 分诊请求，必须先提示切换到更合适的业务场景，不直接生成事件报告。
- 若无法从文本中抽取任何可查询核心实体，必须先追问用户补充恶意软件、IOC、攻击技术、报告标题或活动入口。
- 若用户未给出报告深度和读者角色，可使用默认值 `standard`，但需要在输出中保持简洁并显式记录假设。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行查询前先声明：

- 所有外部数据交互只能通过 `ai4x_ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。对 `opencti` 的 query 默认采用平台 `auto` 策略，优先提交更容易被 GraphQL 支持的最小只读查询，由平台在不支持时自动回落 replica。
- 必须严格区分 `Core Facts` 与 `Inferred Assessments`。
- 不能自动处置、自动通知或自动归因，只能输出结构化事件报告和待复核关联发现。
- 必须输出结构化边界说明和空结果片段。

## Step 1. 确认 opencti 数据源存在

先调用：

```text
ai4x_ai4x_query(command="catalog")
```

确认目录中存在 `sourceId="opencti"`。

若不存在：

- 在 `Boundary Notes` 中记录缺失数据源。
- 停止后续查询。
- 不得编造替代数据源。

## Step 2. 读取 opencti 最小目录并按需下钻 Detail

在构造任何 Cypher 前，必须调用：

```text
ai4x_ai4x_query(command="schema", sourceId="opencti")
ai4x_ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship-type|relationship-schema", typeName="...")
```

重点确认以下对象是否可消费：

- `malware`
- `intrusion-set`
- `campaign`
- `attack-pattern`
- `indicator`
- `relationship`
- `report`
- `grouping`
- `identity`

如果 Schema 缺失计划使用的对象链路，必须在 `Boundary Notes` 中说明并缩减后续查询范围。

## Step 3. 定位事件事实锚点

优先围绕核心实体命中事件主线，建议先从恶意软件、IOC 或攻击技术入口建立一跳事实层：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE n.type IN ['malware','indicator','attack-pattern','campaign','report','identity'] AND toLower(coalesce(n.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (n)-[rel]-(m) RETURN n, rel, m"
)
```

入口判定规则：

- 若命中 `report`，保留 `report` 作为报告事实锚点。
- 若命中 `malware`、`indicator`、`attack-pattern` 或 `campaign`，保留该对象为事实锚点，并尝试回溯到相邻 `report`、`intrusion-set`、`campaign`、`grouping` 与 `identity`。
- 若完全未命中，则返回结构化空结果。

## Step 4. 生成核心事实层

围绕已命中的事实锚点，整理事件报告所需最小闭环，只允许包含直接命中的事实，例如：

- 事件摘要与主要对象类型
- 恶意软件、IOC、攻击技术和活动对象
- 直接相邻的 `intrusion-set`、`campaign`、`report`、`grouping` 和 `identity`
- 关键 `relationship` 与 `report.object_refs`

推荐事实层查询模板：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE seed.type IN ['malware','indicator','attack-pattern','campaign','report','identity'] AND seed.id IN $seed_ids OPTIONAL MATCH path1=(seed)-[*1..2]-(actor) WHERE actor.type IN ['intrusion-set','campaign'] OPTIONAL MATCH path2=(seed)-[*1..2]-(rep {type: 'report'}) OPTIONAL MATCH path3=(seed)-[*1..2]-(grp {type: 'grouping'}) OPTIONAL MATCH path4=(seed)-[*1..2]-(idn {type: 'identity'}) RETURN seed, path1, actor, path2, rep, path3, grp, path4, idn"
)
```

## Step 5. 扩展威胁行为体、活动和同类群组候选

扩展链路固定为：

- `core entity -> intrusion-set / campaign / report -> grouping / relationship / identity -> peer associations`

候选门槛：

- 必须存在至少一条可回溯事实链。
- 若进入 `Peer Associations`，至少要有一类共享关键对象，加上一条辅助证据。

允许作为辅助证据的对象：

- 共享 `relationship`
- 共享 `report.object_refs`
- 共享 `grouping`
- 共享 `identity.sectors`
- 共享 `malware`、`indicator`、`attack-pattern` 或 `campaign`

候选搜索查询示例：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE seed.id IN $seed_ids MATCH (seed)-[*1..2]-(known) WHERE known.type IN ['intrusion-set','campaign','report'] MATCH (known)-[*1..2]-(shared) WHERE shared.type IN ['grouping','identity','relationship','malware','indicator','attack-pattern','campaign','report'] MATCH (candidate)-[*1..2]-(shared) WHERE candidate.type IN ['intrusion-set','campaign','identity','grouping'] AND candidate.id <> known.id OPTIONAL MATCH (known)-[*1..2]-(aux) WHERE aux.type IN ['grouping','identity','relationship','malware','indicator','attack-pattern','campaign','report'] OPTIONAL MATCH (candidate)-[*1..2]-(aux) RETURN known, shared, candidate, collect(DISTINCT aux) AS auxiliary_evidence"
)
```

判定规则：

- 满足门槛的对象进入 `Peer Associations`。
- 只共享单一弱对象、无法回溯到事实锚点或缺少辅助证据的对象进入 `Boundary Notes`。

## Step 6. 评估边界与后续建议

### 6A. Boundary Notes

必须列出证据不足或需要人工复核的对象与路径，例如：

- 仅共享单一 IOC 或单条弱关系。
- 仅由过期 `report`、稀疏 `relationship` 或模糊 `identity.sectors` 支撑。
- 缺少 `grouping` 或 `report.object_refs` 交叉证据，无法稳定表达同类群组关联。

### 6B. Follow-up Recommendations

后续建议应聚焦于进一步验证或补充报告，而不是宣称系统已经执行。例如：

- 追加检查共享对象是否在更新的 `report` 或 `grouping` 中继续出现。
- 对候选群组补查更多 `report.object_refs`、`identity.sectors` 或共享 `relationship`。
- 当事件主问题转向响应编排或归因时，建议切换到相邻业务能力。

# Data Enhancement Suggestions (数据扩充建议)

当前 `opencti` 聚合 Schema 可支撑首版事件报告生成，但若要更稳定地做自动化攻击事件报告，建议补充如下：

1. 为 `report` 增加更明确的验证状态、对象聚合质量或摘要字段，降低草率复用弱报告的风险。
2. 为 `grouping` 增加更稳定的上下文类型与时间边界，便于区分同类群组与普通对象集合。
3. 为 `identity` 增加更完整的行业、地域或角色维度，便于同类目标的有限边界解释。
4. 为共享对象链路补充时效字段，避免过期证据在自动报告中被误写成当前相关结论。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Event Overview
- Event Type:
  - [事件类型]
- Headline:
  - [报告标题或事件概述]
- Audience:
  - [主要读者]

## Core Facts
- Core Entities:
  - [恶意软件、IOC、攻击技术、活动对象]
- Evidence References:
  - [report、relationship、grouping、identity]

## Threat Actor & Campaign Linkage
- [对象名称]
  - type: intrusion-set|campaign
  - confidence: high|medium|low
  - supporting_facts:
    - [可回溯事实链]

## Peer Associations
- [候选名称]
  - type: intrusion-set|campaign|identity|grouping
  - confidence: high|medium|low
  - supporting_facts:
    - [共享关键对象]
    - [辅助证据]
  - inference: [只能写候选性结论]
  - review_required: yes|no

## Inferred Assessments
- [明确标记为推断的解释性判断]

## Follow-up Recommendations
- [进一步验证、补查或转交建议]

## Boundary Notes
- [证据不足、字段缺口、范围假设或待复核项]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [若有部分命中事实则列出，否则为空数组]
- empty_segments:
  - [未命中的实体或扩展链路]
- next_questions:
  - [建议用户补充的事件摘要、实体名或报告标题]
```

输出约束：

- 必须显式区分 `Core Facts` 与 `Inferred Assessments`。
- `Peer Associations` 只能表达候选性关联，不得写成确定归因或已确认同源结论。
- 必须包含 `Follow-up Recommendations`、`Boundary Notes` 和 `Empty Result Contract`。