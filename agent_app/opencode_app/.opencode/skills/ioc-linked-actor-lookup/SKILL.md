---
name: ioc-linked-actor-lookup
description: 当用户提供域名、IP、URL、文件哈希、邮箱等 IOC，并希望反查关联的攻击者组织、相关恶意软件、基础设施、报告和候选组织时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供 IOC，希望反查关联的 `intrusion-set`、`threat-actor` 或其他组织类对象。
- 希望查看 IOC 关联的恶意软件、工具、基础设施、报告和证据链。
- 希望在直接命中的组织之外，识别证据不足但值得继续验证的候选组织。

本技能仅使用 `opencti` 数据源做只读分析，不扩展到车辆侧对象或 TARA 风险图谱。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `ioc_type`: 允许值为 `domain-name`、`ipv4-addr`、`url`、`file-hash`、`email-addr`、`other`。
- `ioc_value`: IOC 实际值。
- `time_range`: 可选增强条件。若用户提供，则用于限制报告时间窗；否则不是硬性必需。
- `lookup_goal`: 默认值为 `actor_lookup_from_ioc`。

提取与追问规则：

- 如果无法提取任何 IOC 值，则先追问用户补充具体 IOC。
- 如果用户提供多个 IOC，可逐个处理，并在输出中分开列示。
- 若 IOC 类型不明确，但值形态可识别，先按可识别类型查询；仍不确定时标记为 `other` 并在 `Gaps` 中说明。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 必须严格区分 `Facts` 与 `Inferences`。
- 不能自动归因，只能输出直接命中组织和证据驱动的候选组织。
- 必须输出结构化空结果和排除项。

## Step 1. 确认 opencti 数据源存在

先调用：

```text
ai4x_query(command="catalog")
```

检查 `sourceId="opencti"` 是否存在。

如果不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 opencti Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
```

重点确认以下对象是否可消费：

- `indicator`
- `domain-name`
- `ipv4-addr`
- `url`
- `file`
- `email-addr`
- `malware`
- `tool`
- `infrastructure`
- `report`
- `intrusion-set`
- `threat-actor`
- `campaign`
- `relationship`

如果 Schema 未覆盖计划使用的对象或关系，必须在 `Gaps` 中说明并缩减后续查询链。

## Step 3. 以 IOC 定位初始事实锚点

IOC 查询优先策略：

- 优先查 `indicator`。
- 同时兼容 `domain-name`、`ipv4-addr`、`url`、`file`、`email-addr` 等 observable。

### 3A. 先查 indicator

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (i {type: 'indicator'}) WHERE toLower(coalesce(i.name, '')) CONTAINS toLower($ioc_value) OR toLower(coalesce(i.pattern, '')) CONTAINS toLower($ioc_value) OPTIONAL MATCH (i)-[rel]-(m) RETURN i, rel, m"
)
```

### 3B. 再查 observable

根据 `ioc_type` 选择对应对象类型，例如：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (o) WHERE o.type IN ['domain-name','ipv4-addr','url','file','email-addr'] AND toLower(coalesce(o.name, coalesce(o.value, ''))) CONTAINS toLower($ioc_value) OPTIONAL MATCH (o)-[rel]-(m) RETURN o, rel, m"
)
```

入口判定规则：

- 若命中 `indicator`，优先以该对象为主事实锚点。
- 若只命中 observable，也可以作为主事实锚点继续扩展。
- 若两者都未命中，则返回结构化空结果。

## Step 4. 构建主反查链

本技能主查询链为：

- `indicator / observable -> malware / tool -> intrusion-set / threat-actor`

补充链可包括：

- `indicator / observable -> report -> intrusion-set / threat-actor`
- `indicator / observable -> infrastructure -> intrusion-set / threat-actor`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE (seed.type = 'indicator' AND (toLower(coalesce(seed.name, '')) CONTAINS toLower($ioc_value) OR toLower(coalesce(seed.pattern, '')) CONTAINS toLower($ioc_value))) OR (seed.type IN ['domain-name','ipv4-addr','url','file','email-addr'] AND toLower(coalesce(seed.name, coalesce(seed.value, ''))) CONTAINS toLower($ioc_value)) OPTIONAL MATCH path1=(seed)-[*1..2]-(mt) WHERE mt.type IN ['malware','tool'] OPTIONAL MATCH path2=(seed)-[*1..2]-(rep {type: 'report'}) OPTIONAL MATCH path3=(seed)-[*1..2]-(infra {type: 'infrastructure'}) OPTIONAL MATCH path4=(mt)-[*1..2]-(actor) WHERE actor.type IN ['intrusion-set','threat-actor'] OPTIONAL MATCH path5=(rep)-[*1..2]-(actor2) WHERE actor2.type IN ['intrusion-set','threat-actor'] OPTIONAL MATCH path6=(infra)-[*1..2]-(actor3) WHERE actor3.type IN ['intrusion-set','threat-actor'] RETURN seed, path1, mt, path2, rep, path3, infra, path4, actor, path5, actor2, path6, actor3"
)
```

事实抽取要求：

- 记录 IOC 入口对象、相邻 malware/tool、report、infrastructure 以及组织类对象。
- 只保留可回溯的事实链，不接受“同报告出现但路径不明”的组织进入主输出。

## Step 5. 判定直接命中的组织

主输出中的组织类对象允许为：

- `intrusion-set`
- `threat-actor`

进入主输出的门槛：

- IOC 与组织之间必须存在至少一条可回溯事实链。
- 该事实链可以经过 `malware`、`tool`、`report` 或 `infrastructure`。
- 如果只有松散共现、没有清晰路径，则不得进入 `Direct Actor Hits`。

## Step 6. 搜索候选组织

除直接命中的组织外，还允许输出候选组织，但必须与直接事实分开。

候选组织允许类型：

- `intrusion-set`
- `threat-actor`
- `campaign`

候选门槛：

- 与 IOC 共享同一 `malware` / `tool` 或同一 `report`。
- 并且存在第二条辅助证据。

允许作为第二条辅助证据的对象：

- 共享 `report` 邻接关系
- 共享 `malware` / `tool`
- 共享 `infrastructure`

候选搜索查询示例：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (seed) WHERE (seed.type = 'indicator' AND (toLower(coalesce(seed.name, '')) CONTAINS toLower($ioc_value) OR toLower(coalesce(seed.pattern, '')) CONTAINS toLower($ioc_value))) OR (seed.type IN ['domain-name','ipv4-addr','url','file','email-addr'] AND toLower(coalesce(seed.name, coalesce(seed.value, ''))) CONTAINS toLower($ioc_value)) MATCH (seed)-[*1..2]-(bridge) WHERE bridge.type IN ['malware','tool','report'] MATCH (candidate)-[*1..2]-(bridge) WHERE candidate.type IN ['intrusion-set','threat-actor','campaign'] OPTIONAL MATCH (seed)-[*1..2]-(aux {type: 'infrastructure'}) OPTIONAL MATCH (candidate)-[*1..2]-(aux) RETURN seed, bridge, candidate, collect(DISTINCT aux) AS auxiliary_evidence"
)
```

判定规则：

- 满足门槛的对象进入 `Candidate Organizations`。
- 只共享单一桥接对象、没有第二条辅助证据的对象进入 `Exclusions`。

## Step 7. 形成排除项与建议

### 7A. Exclusions

必须列出搜索过但证据不足的组织或路径，例如：

- 仅与 IOC 共享同一报告，但无 malware/tool/infrastructure 辅助证据。
- 仅通过路径较长的弱连接命中，证据不稳定。
- 可回溯链条中缺少关键中间对象。

### 7B. Recommendations

后续建议应聚焦于继续验证 IOC 与组织关联，而不是宣布确定归因。例如：

- 继续检查 IOC 是否出现在更多报告或观测数据中。
- 对已命中的 malware/tool 搜索更多相邻的组织和基础设施。
- 对候选组织补查是否存在共享基础设施或重复出现的报告邻接关系。

# Data Enhancement Suggestions (数据扩充建议)

当前 `opencti` 聚合 Schema 可以支撑 IOC 到组织的基本反查，但仍有以下改进空间：

1. 为 `indicator` 增加更统一的 `pattern_type`、`valid_from`、`valid_until`、置信度字段，便于后续做时效性和优先级筛选。
2. 为 observables 提供更稳定的字段规范，例如统一的值字段映射，减少 `name` 与 `value` 并存带来的查询歧义。
3. 为 `report` 和组织类对象补充更明确的证据来源标识和验证状态，帮助区分“直接证据链”与“弱共现”。
4. 若需要对文件哈希、URL 和邮箱做更强的 IOC 归一化，建议补充标准化中间对象或字段映射规范。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- IOC Anchor:
  - sourceId: opencti
  - object: [indicator 或 observable]
- Evidence Chain:
  - [IOC(type)] --[relationship]--> [malware/tool/report/infrastructure(type)] --[relationship]--> [organization(type)]

## Direct Actor Hits
- [组织名称]
  - type: intrusion-set|threat-actor
  - confidence: high|medium|low
  - supporting_facts:
    - [可回溯事实链]

## Candidate Organizations
- [候选名称]
  - type: intrusion-set|threat-actor|campaign
  - confidence: high|medium|low
  - supporting_facts:
    - [桥接对象]
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
  - [未命中的链路或语义不稳定的路径]

## Recommendations
- Next Steps:
  - [进一步验证建议]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [若有已命中事实则列出，否则为空数组]
- empty_segments:
  - [未命中的入口或扩展链路]
- next_questions:
  - [建议用户补充的 IOC、时间范围或相关报告]
```

输出约束：

- 置信度只允许使用 `high`、`medium`、`low`。
- `Direct Actor Hits` 只收录可回溯事实链支持的组织。
- `Candidate Organizations` 必须与直接事实分开。
- 不得把候选组织写成确定归因结论。