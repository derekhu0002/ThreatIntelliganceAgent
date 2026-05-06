---
name: ioc-triage-indicator-priority
description: 当用户希望从 IOC 或简短告警摘要出发，快速判断是否值得升级处置并生成结构化分诊结论时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供域名、IP、URL、HASH、Indicator 或简短告警摘要，希望判断是否值得优先处置。
- 希望获得高、中、低优先级或等价的快速分诊结果。
- 希望生成适合 SOC 一线消费的结构化结论、建议动作和待确认项。

本技能默认采用“先收敛入口，再确认平台能力，再建立 IOC 主事实，最后补一跳语境”的分析顺序：

- `opencti` 负责提供 `indicator`、`relationship`、`report` 和关联威胁对象。
- 平台外告警内容只承担输入上下文角色，不应被误写为平台原生事实源。
- 来源可靠性、误报风险和优先级属于派生判断，必须建立在已命中的直接事实之上。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `target_type`: 至少识别为 `domain`、`ip`、`url`、`hash`、`indicator_id`、`alert_event` 之一。
- `target_value`: 至少识别一个可用于查询的入口值。
- `alert_context`: 可选，允许包含 `source_system`、`alert_name`、`occurred_at`、`rule_name`、`host`、`deadline` 等。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `need_source_reasoning`: 可选，默认 `true`。
- `need_relation_context`: 可选，默认 `true`。

提取与追问规则：

- 如果缺少 `target_type` 或 `target_value`，先追问补齐，不直接查询。
- 如果用户给的是告警摘要而不是稳定 IOC，先抽取出可查询 IOC 再进入正式链路。
- 如果用户目标在“快速分诊”和“归因/响应编排”之间不清晰，先追问一次，不直接进入关系扩展。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。
- 必须严格区分 `Direct Facts` 与 `Inferred Assessments`。
- 平台外的 SIEM、EDR、CMDB 或工单系统只能作为外部补充上下文，而不是平台原生事实源。
- 当缺少关键上下文、现场反馈或来源支撑时，允许输出“待人工确认”的结构化报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_query(command="catalog")
```

最少检查：

- `opencti` 是否存在。
- 是否存在其他可选增强源，但不得假定其一定存在。

如果 `opencti` 不存在：

- 在 `Boundary Notes` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何查询前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

若需要确认具体字段，再调用：

```text
ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship", typeName="indicator|relationship|report|malware|infrastructure|intrusion-set|attack-pattern")
```

重点确认以下对象是否可消费：

- `indicator`
- `relationship`
- `report`
- `malware`
- `infrastructure`
- `intrusion-set`
- `attack-pattern`
- `domain-name`
- `ipv4-addr`
- `url`
- `file`

如果 Schema 未覆盖计划使用的字段或对象，必须在 `Boundary Notes` 中说明并缩减后续查询链。

## Step 3. 提取 IOC 主事实

根据输入类型选择第一轮 IOC 查询：

- 当输入是域名、IP、URL、HASH 或 Indicator 标识时，优先拉取命中的 `indicator` 主对象。
- 当输入是告警摘要时，先标准化出一个或多个可查询 IOC，再进入正式查询链路。

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE toLower(coalesce(n.name, n.value, n.pattern, '')) CONTAINS toLower($target_value) RETURN n LIMIT $limit"
)
```

要求：

- 提取 `confidence`、`valid_from`、`valid_until`、`labels`、`pattern`、`pattern_type` 等排序主输入。
- 只把直接命中的对象和字段作为事实层。
- 不在这一阶段输出最终优先级。

## Step 4. 扩展一跳威胁语境

围绕第一轮命中的 `indicator` 在 `opencti` 中扩展：

- `relationship`
- `report`
- `malware`
- `infrastructure`
- `intrusion-set`
- `attack-pattern`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (indicator)-[rel]-(peer) WHERE toLower(coalesce(indicator.name, indicator.value, indicator.pattern, '')) CONTAINS toLower($target_value) RETURN indicator, rel, peer LIMIT $limit"
)
```

扩展要求：

- 结合 `created_by_ref`、`external_references` 和标签形成来源侧代理信号。
- 识别 `likely_false_positive`、过期情报、关系稀薄和来源冲突等降权因素。
- 若结果不足以支持稳定高优先级判断，必须保留“继续观察”或“待补证据”结论。

## Step 5. 评估优先级

每个 IOC 至少考虑以下因素：

- `confidence`。
- 有效期窗口。
- 标签中的误报或例外语义。
- 来源侧代理信号。
- 关系与报告支撑强度。
- 数据完整性。

排序规则：

- 不能只按单一 `confidence` 排序。
- 同时具备较高置信度、有效期内且有稳定关系支撑的 IOC 可提升为 `high`。
- 存在误报标签、证据稀薄或已过期的对象应降级为 `medium` 或 `low`。
- 当来源冲突或字段缺失较大时，必须显式降低结论置信度。

## Step 6. 生成结构化报告

输出时必须包含：

- IOC 摘要。
- 优先级。
- 主要证据。
- 加权与降权因素。
- 建议动作。
- 待人工确认项。
- 平台边界说明。

建议动作聚焦于：

- 继续观察。
- 提升监控。
- 补充来源或上下文证据。
- 当风险已转向响应编排时，移交到对应业务意图。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Summary
- [一句话总结 IOC 当前是否值得优先处置]

## Direct Facts
- Target:
  - target_type: [domain|ip|url|hash|indicator_id|alert_event]
  - target_value: [value]
- IOC Facts:
  - [indicator 主对象、confidence、valid_from、valid_until、labels]
- Related Context:
  - [relationship、report、malware、infrastructure、intrusion-set、attack-pattern]

## Priority
- level: high|medium|low
- reason: [优先级依据]

## Inferred Assessments
- [基于事实形成的判断]

## Recommended Actions
- [建议动作 1]
- [建议动作 2]

## Pending Confirmations
- [需要人工确认的项]

## Boundary Notes
- [平台能力边界、外部补充信号、来源派生属性说明]

## Empty Result Contract
- [当未命中 IOC 或证据不足时的标准化空结果说明]
```

结构要求：

- 必须显式区分 `Direct Facts` 与 `Inferred Assessments`。
- 必须显式说明误报标签、有效期或来源冲突等关键降权因素。
- 不得把来源派生判断写成平台原生字段事实。
- 不得把建议动作写成系统已执行结果。

# Empty Result Contract (空结果契约)

当 `opencti` 未命中稳定 IOC 主事实，或只命中无法支持排序的弱线索时，输出应至少包含：

- `Summary`: 未形成稳定 IOC 分诊结论。
- `Direct Facts`: 已检索的数据源和对象范围。
- `Priority`: `low` 或 `undetermined` 的保守表达，且说明原因。
- `Pending Confirmations`: 需要补充的 IOC、上下文或来源信息。
- `Boundary Notes`: 当前结果不等同于无风险，只代表平台内证据不足。