---
name: alert-priority-ranking
description: 当用户提供多个 IOC 或告警对象，并希望结合 OpenCTI 中的 confidence、valid_from、valid_until 以及相关组织和报告上下文，对告警进行优先级排序时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供多个 IOC，希望按威胁情报证据对其排序。
- 提供告警对象列表，希望结合 OpenCTI 的 indicator 置信度和有效期评估优先级。
- 希望输出高优先级告警清单、排序理由、上下文证据和未命中项。

本技能仅使用 `opencti` 数据源做只读分析，不扩展到车辆侧对象、TARA 风险或 SES 需求。

# Prerequisites (槽位/前置依赖提取)

支持以下两类输入格式：

- 纯 IOC 字符串数组，例如 `['shared-c2.example', '198.51.100.24']`
- 告警对象数组，每条至少包含 `id`、`ioc`、`type` 中的一项或多项

执行前优先提取以下槽位：

- `alerts`: 原始输入列表
- `ioc_value`: 每条告警对应的 IOC 值
- `ioc_type`: 允许值为 `domain-name`、`ipv4-addr`、`url`、`file-hash`、`email-addr`、`unknown`
- `analysis_time`: 默认使用当前分析时间作为有效期比较基准
- `ranking_goal`: 默认值为 `priority_ranking_from_opencti_context`

提取与追问规则：

- 如果用户未提供可迭代处理的 IOC 或告警列表，必须先追问补充。
- 若 IOC 类型缺失但可从值形态推断，可先做弱识别；若仍无法判定，则标记为 `unknown` 并在 `Gaps` 中说明。
- 允许用户不提供时间范围；有效期判断默认基于当前分析时间。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行查询前先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 不能编造 `confidence`、`valid_from`、`valid_until`。
- 排序必须区分事实依据和解释性推断。
- 若字段缺失，只能降低确定性并写入缺口，不能由模型补全。

## Step 1. 确认 opencti 数据源存在

先调用：

```text
ai4x_query(command="catalog")
```

确认目录中存在 `sourceId="opencti"`。

若不存在：

- 在 `Gaps` 中列出缺失数据源。
- 停止排序流程。
- 不得编造替代数据源或虚构排序结果。

## Step 2. 获取 opencti Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

重点确认以下对象或字段是否可消费：

- `indicator`
- `domain-name`
- `ipv4-addr`
- `url`
- `file`
- `email-addr`
- `report`
- `intrusion-set`
- `threat-actor`
- `infrastructure`
- `malware`
- `relationship`
- `confidence`
- `valid_from`
- `valid_until`

若 Schema 未体现 `confidence` 或有效期字段：

- 不得假定这些字段存在。
- 在 `Gaps` 中记录字段缺口。
- 排序仍可继续，但必须降低该条目的解释确定性。

## Step 3. 逐条 IOC 定位 indicator 或 observable

对输入列表中的每条 IOC 依次处理。

### 3A. 优先查询 indicator

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (i {type: 'indicator'}) WHERE toLower(coalesce(i.name, '')) CONTAINS toLower($ioc_value) OR toLower(coalesce(i.pattern, '')) CONTAINS toLower($ioc_value) RETURN i"
)
```

### 3B. 再查询 observable

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (o) WHERE o.type IN ['domain-name','ipv4-addr','url','file','email-addr'] AND toLower(coalesce(o.name, coalesce(o.value, ''))) CONTAINS toLower($ioc_value) OPTIONAL MATCH (o)-[rel]-(m) RETURN o, rel, m"
)
```

判定规则：

- 若命中 `indicator`，优先使用 `indicator` 的 `confidence`、`valid_from`、`valid_until` 作为排序事实依据。
- 若仅命中 observable，但没有相邻 indicator，则该条只能保留为低确定性结果，不能伪造置信度。
- 若完全未命中，则该条进入 `Exclusions` 或 `Empty Result Contract`。

## Step 4. 拉取排序所需上下文

主排序链固定为：

- `alert/ioc -> indicator -> confidence + valid_from/valid_until -> actor/report context`

补充上下文对象：

- `report`
- `intrusion-set`
- `threat-actor`
- `malware`
- `infrastructure`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE (seed.type = 'indicator' AND (toLower(coalesce(seed.name, '')) CONTAINS toLower($ioc_value) OR toLower(coalesce(seed.pattern, '')) CONTAINS toLower($ioc_value))) OR (seed.type IN ['domain-name','ipv4-addr','url','file','email-addr'] AND toLower(coalesce(seed.name, coalesce(seed.value, ''))) CONTAINS toLower($ioc_value)) OPTIONAL MATCH path1=(seed)-[*1..2]-(rep {type: 'report'}) OPTIONAL MATCH path2=(seed)-[*1..2]-(actor) WHERE actor.type IN ['intrusion-set','threat-actor'] OPTIONAL MATCH path3=(seed)-[*1..2]-(mw {type: 'malware'}) OPTIONAL MATCH path4=(seed)-[*1..2]-(infra {type: 'infrastructure'}) RETURN seed, path1, rep, path2, actor, path3, mw, path4, infra"
)
```

上下文抽取要求：

- 记录命中的 `confidence`、`valid_from`、`valid_until`。
- 若命中 `report` 或组织对象，必须把它们作为排序解释项输出。
- 若命中 `malware` 或 `infrastructure`，可以作为补充佐证，但不能取代置信度和有效期字段。

## Step 5. 按规则计算优先级

主判定顺序固定为：

1. 先判断 indicator 在当前分析时间是否仍有效。
2. 在有效状态相同的前提下，再比较 `confidence`。
3. 若前两项不足以区分，再参考已命中的组织和报告上下文强度。

有效期判定规则：

- 若存在 `valid_from` 和 `valid_until`，以当前分析时间判断是否处于有效窗口。
- 若仅有 `valid_from`，可判断“已开始生效”，但不能判断是否过期。
- 若仅有 `valid_until`，可判断是否已过期。
- 若两者都缺失，必须在该条的 `Gaps` 中注明“有效期字段缺失”。

缺失字段处理：

- 允许该条保留在排序结果中。
- 但必须降低优先级解释确定性，并在排序理由中明确字段缺口。
- 不得推断一个不存在的时间窗或置信度值。

## Step 6. 输出排序分组

最终结果必须同时包含：

- 总排序列表
- `high priority`
- `medium priority`
- `low priority`

建议分组逻辑：

- `high priority`: 当前仍有效，且 confidence 较高，并具有组织或报告上下文支撑。
- `medium priority`: 当前仍有效但 confidence 中等，或有效期存在部分缺失但上下文较强。
- `low priority`: 已过期、confidence 较低、字段缺口明显，或仅命中弱上下文。

说明：

- 若底层 confidence 不是统一数值体系，只能原样引用并做相对解释，不得强行数值归一化。
- 上下文只能作为第三优先级解释项，不能覆盖有效期和 confidence 的事实缺口。

## Step 7. 形成排除项和空结果

### 7A. Exclusions

以下情况必须进入 `Exclusions`：

- IOC 完全未命中 indicator 和 observable。
- 只命中弱共现对象，无法形成最小排序解释链。
- 字段缺口严重到无法解释其排序位置。

### 7B. Empty Result Contract

若输入 IOC 列表全部未命中任何 indicator 或 observable：

- 返回结构化空结果。
- 列出未命中的 IOC 列表。
- 建议用户补充其他 IOC、indicator 名称或时间范围。

## Step 8. 生成处置建议

建议必须基于排序结果和事实证据，不得冒充系统已执行动作。可包括：

- 对高优先级条目优先开展人工复核或关联情报扩展。
- 对即将过期但当前仍有效的 indicator 尽快验证其关联组织和报告上下文。
- 对低优先级或过期条目建议保留观察，不应强行升级为高风险。

# Data Enhancement Suggestions (数据扩充建议)

当前 `opencti` 聚合 Schema 可支撑基础的排序逻辑，但仍建议补充以下能力以实现更稳定的告警优先级判断：

1. 统一 `confidence` 字段的取值规范和解释映射，避免不同对象类型采用不兼容的置信度表达。
2. 明确 `indicator` 的 `valid_from`、`valid_until` 可用性和缺省语义，减少“无字段时无法判断”的歧义。
3. 为 observables 到 indicator 的映射补充更稳定的标准关系，避免 IOC 只命中 observable 时上下文不足。
4. 若希望纳入更精细的优先级权重，建议新增独立字段承载人工验证状态、最近观测时间或处置状态。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Input Alerts:
  - [原始输入条目]
- Matched Indicators:
  - [IOC] -> [indicator/observable] (confidence=?, valid_from=?, valid_until=?)
- Context Objects:
  - [indicator] -> [report / intrusion-set / threat-actor / malware / infrastructure]

## Ranked Alerts
- [rank]. [IOC 或告警ID]
  - priority: high|medium|low
  - confidence: [原始字段值或 missing]
  - validity_status: active|expired|unknown
  - context:
    - [命中的组织]
    - [命中的报告]
  - rationale:
    - [排序理由]

## Priority Groups
- High Priority:
  - [条目列表]
- Medium Priority:
  - [条目列表]
- Low Priority:
  - [条目列表]

## Exclusions
- [IOC 或告警ID]
  - reason: [未命中或字段缺口原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Missing Fields:
  - [缺失 confidence / valid_from / valid_until 的条目]
- Unresolved Links:
  - [弱连接或无法形成解释链的路径]

## Recommendations
- Next Steps:
  - [高优先级复核建议]
  - [低优先级观察建议]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [若有部分命中则列出，否则为空数组]
- empty_segments:
  - [未命中的 IOC 列表]
- next_questions:
  - [建议补充的 IOC、indicator 名称或时间范围]
```

输出约束：

- 置信度、有效期字段必须原样来自查询结果，不得脑补。
- 必须保留总排序和三档优先级分组。
- 若命中组织或报告上下文，必须体现在排序理由中。
- 字段缺失不能阻止输出，但必须降低解释确定性并写入 `Gaps`。