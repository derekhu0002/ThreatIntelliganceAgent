---
name: threat-attribution-ip-trace
description: 当用户提供 IP、域名、文件哈希、恶意软件、TTP 或相关 IOC 线索，并希望追溯背后的攻击组织、历史活动、技术、工具和证据路径时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供 `IP`、域名、哈希、恶意软件、TTP 或其他 IOC，希望识别背后的 `intrusion-set`、`threat-actor`、历史活动或相关技术。
- 希望获得从线索到组织、再到技术和工具的完整证据链。
- 希望输出可解释、可回溯的威胁溯源分析报告，而不是只看单个对象详情。

本技能默认以 `opencti` 为主数据源做只读分析；只有在 `catalog` 明确显示存在其他授权来源且确有必要时，才可在同样的三步查询范式内扩展。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `target_type`: 允许值为 `ip`、`domain`、`hash`、`malware`、`ttp`、`other`。
- `target_value`: 线索实际值。
- `time_range`: 可选增强条件。若用户提供，则限制分析窗口；否则不是硬性必需。
- `focus_dimension`: 可选，允许关注 `intrusion-set`、`attack-pattern`、`malware`、`tool`、`timeline`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。

提取与追问规则：

- 如果无法提取任何有效线索值，则先追问用户补充具体对象。
- 如果用户同时给出多个线索，先确认是要分别归因还是合并做同案分析。
- 若线索值形态可识别但类型未显式给出，可先推断 `target_type`，并在输出中说明。
- 如果用户目标在“快速研判”和“深度归因”之间不清晰，先追问一次，不直接进入深度扩图。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 必须严格区分 `Facts` 与 `Inferences`。
- 候选组织必须绑定可回溯的证据路径。
- 当没有足够证据时，允许输出“未形成稳定归因”的空结论报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_query(command="catalog")
```

最少检查：

- `opencti` 是否存在。
- 是否存在其他被当前运行环境授权的数据源。

如果 `opencti` 不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

重点确认以下对象是否可消费：

- `indicator`
- `ipv4-addr`
- `domain-name`
- `file`
- `malware`
- `tool`
- `infrastructure`
- `attack-pattern`
- `intrusion-set`
- `threat-actor`
- `campaign`
- `report`
- `relationship`

同时确认是否存在可用于时间或证据判断的字段，例如：

- `confidence`
- `valid_from`
- `valid_until`
- `created`
- `first_seen`
- `last_seen`

如果 Schema 未覆盖计划使用的对象或关系，必须在 `Gaps` 中说明并缩减后续查询链。

## Step 3. 建立初始事实锚点

根据 `target_type` 优先查找与输入对象最接近的事实锚点。

### 3A. IP / Domain / Hash 入口

优先查 `indicator`，再查 observable：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE (seed.type = 'indicator' AND (toLower(coalesce(seed.name, '')) CONTAINS toLower($target_value) OR toLower(coalesce(seed.pattern, '')) CONTAINS toLower($target_value))) OR (seed.type IN ['ipv4-addr','domain-name','file'] AND toLower(coalesce(seed.name, coalesce(seed.value, ''))) CONTAINS toLower($target_value)) OPTIONAL MATCH (seed)-[rel]-(adj) RETURN seed, rel, adj"
)
```

### 3B. Malware / TTP 入口

若入口本身是 `malware` 或 `attack-pattern`，直接以该对象为锚点：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE seed.type IN ['malware','attack-pattern'] AND toLower(coalesce(seed.name, '')) CONTAINS toLower($target_value) OPTIONAL MATCH (seed)-[rel]-(adj) RETURN seed, rel, adj"
)
```

入口判定规则：

- 若命中多个种子对象，优先选择与用户输入类型最一致的对象作为主锚点。
- 若仅命中弱匹配对象，保留结果但在 `Gaps` 中说明匹配不稳定。
- 若完全未命中，则返回结构化空结果。

## Step 4. 执行一跳事实查询

围绕主锚点，查询第一轮直接事实，目标是找出：

- 被哪些 `indicator`、`observable`、`report`、`infrastructure` 或 `campaign` 引用。
- 直接相邻的 `malware`、`tool`、`attack-pattern`。
- 与线索直接相邻的时间字段或置信度字段。

事实抽取要求：

- 只记录直接命中的对象、关系和来源数据源。
- 不在这一轮写入任何归因结论。

## Step 5. 执行二跳扩展查询

主扩展链为：

- `seed -> malware/tool/attack-pattern -> intrusion-set/threat-actor`
- `seed -> report/infrastructure/campaign -> intrusion-set/threat-actor`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE id(seed) = $seed_id OPTIONAL MATCH path1=(seed)-[*1..2]-(bridge1) WHERE bridge1.type IN ['malware','tool','attack-pattern'] OPTIONAL MATCH path2=(seed)-[*1..2]-(bridge2) WHERE bridge2.type IN ['report','infrastructure','campaign'] OPTIONAL MATCH path3=(bridge1)-[*1..2]-(actor1) WHERE actor1.type IN ['intrusion-set','threat-actor'] OPTIONAL MATCH path4=(bridge2)-[*1..2]-(actor2) WHERE actor2.type IN ['intrusion-set','threat-actor'] RETURN seed, path1, bridge1, path2, bridge2, path3, actor1, path4, actor2"
)
```

扩展要求：

- 聚合候选组织的历史活动、桥接对象、相关技术和工具。
- 记录每条证据路径的节点和摘要。
- 如果中间结果过长，只在当前会话内压缩为稳定中间结论，不发明未注册的辅助 Skill。

## Step 6. 评估候选组织可信度

候选组织允许类型：

- `intrusion-set`
- `threat-actor`

评估规则：

- 至少存在一条从 `target` 到候选组织的可回溯路径。
- 多条独立路径或多类桥接对象可提升可信度。
- 仅有单一路径、单一桥接对象或长链弱连接时，应降级为 `medium` 或 `low`。
- 只共享单一 `report` 或名称相似的对象，不能直接进入主要候选列表。

证据强度建议：

- `high`: 至少两条独立证据路径，且桥接对象不止一种。
- `medium`: 一条稳定路径，或两条但都依赖同类桥接对象。
- `low`: 只有弱共现、单点命中或待补充验证的路径。

## Step 7. 形成排除项与建议

### 7A. Exclusions

必须列出搜索过但证据不足的对象或路径，例如：

- 仅共享同一 `report`，没有第二条证据。
- 只能通过较长或语义不稳定的路径命中。
- 路径存在中间对象缺失，无法回溯到原始线索。

### 7B. Recommendations

建议应聚焦于继续验证归因链，例如：

- 检查近 30 天内与该线索相关的新增报告、基础设施或观测数据。
- 对已命中的 `malware`、`tool` 和 `attack-pattern` 继续扩展相邻组织。
- 对低可信候选补查是否存在共享基础设施、共享活动时间窗或重复出现的中间对象。
- 若命中内部资产或处置门槛，再转交后续应急响应流程。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Target:
  - type: [ip|domain|hash|malware|ttp|other]
  - value: [target_value]
  - sourceId: [opencti or other approved source]
- Direct Facts:
  - [直接命中的对象、关系、时间或置信度字段]

## Candidate Intrusion Sets
- [组织名称]
  - type: intrusion-set|threat-actor
  - confidence: high|medium|low
  - supporting_facts:
    - [桥接对象和直接事实]
  - review_required: yes|no

## Evidence Paths
- [path_id]
  - path_summary: [Target -> Bridge -> Actor]
  - nodes:
    - [节点列表]

## Related TTPs / Tools
- Attack Patterns:
  - [TTP 或 attack-pattern]
- Tools and Malware:
  - [tool / malware]

## Inferred Assessments
- [只能写基于证据路径得出的候选性结论]

## Exclusions
- [对象名称]
  - reason: [证据不足原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Missing Schema or Links:
  - [缺少的对象、字段、关系或未稳定命中的路径]

## Recommendations
- [后续调查与验证建议]

## Empty Result Contract
- status: no_stable_attribution | partial_hit
- reason: [未命中的原因或仅形成部分路径的说明]
```

# Acceptance Notes (验收说明)

执行本技能时，至少满足以下验收条件：

1. 查询前已完成必要槽位提取与必要澄清。
2. 所有真实查询遵循 `catalog -> schema -> query`。
3. 输出明确分离 `Facts` 与 `Inferred Assessments`。
4. 每个候选组织都可映射到至少一条 `Evidence Paths`。
5. 当证据不足时，输出空结论或部分命中报告，而不是强行归因。