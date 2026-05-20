# 自动化攻击事件报告 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `自动化攻击事件报告` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能自动写一份报告”，而是“有限的上下文窗口应优先留给哪些高价值事件归纳与关联判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛事件边界、核心实体和输出对象，避免在未定稿的事件材料上做大规模无效扩查。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制同一批事件证据、实体关系和报告草稿上下文。
3. 当证据列表、关联对象或报告草稿逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续归纳推理时，才创建附属 AGENT 隔离长上下文。

本设计与场景文档 [scenarios/威胁情报分析/自动化攻击事件报告与同级群组关联.md](../../scenarios/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5%E5%88%86%E6%9E%90/%E8%87%AA%E5%8A%A8%E5%8C%96%E6%94%BB%E5%87%BB%E4%BA%8B%E4%BB%B6%E6%8A%A5%E5%91%8A%E4%B8%8E%E5%90%8C%E7%BA%A7%E7%BE%A4%E7%BB%84%E5%85%B3%E8%81%94.md) 对齐。场景名使用“自动化攻击事件报告与同级群组关联”，能力名使用“自动化攻击事件报告”，本文统一将其视为同一业务能力在不同抽象层的表达。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.automated-incident-reporting`
- `intent_name`: `自动化攻击事件报告`
- `intent_level`: `L1`
- `parent_capability`: `自动化攻击事件报告`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一起已经完成基础调查或已被确认的安全事件出发，提取事件核心实体，查询其在威胁情报图谱中的关联组织、活动、TTP、目标行业和同类风险对象，生成一份可复核、可分发、可追溯的结构化事件报告，并给出有限边界内的后续关注建议。

这里的“自动化攻击事件报告”默认关注“事件复盘报告和同类关联对象提示”，而不是完整的事件检测平台、案件管理系统、最终归因平台或自动化响应编排平台。

### 2.3 典型触发者

- 安全事件响应工程师
- 应急响应团队负责人
- IT安全经理

### 2.4 典型触发表达

- 这起勒索软件事件已经基本确认，帮我生成最终调查报告。
- 把这次事件涉及的恶意软件、组织和同类活动整理成一份可以流转的报告。
- 看看这次事件里的 IOC 是否还关联到其他攻击活动或行业对象。
- 给我一份适合发给应急响应负责人和安全经理复核的事件摘要。
- 不要自动处置，只需要给出报告和后续关注建议。

### 2.5 业务边界

本意图负责：

1. 从已确认事件中提取恶意软件、IOC、TTP、目标对象和时间边界等核心事实。
2. 查询图谱中与本次事件直接相关的组织、活动、攻击技术、行业对象和可复用证据包。
3. 基于共享 IOC、共享活动、共享行业或共享对象集合，识别可供继续研判的同类风险对象。
4. 输出结构化事件报告、证据引用、同类关联发现和后续关注建议。

本意图不直接负责：

1. 自动触发隔离、阻断、通知或工单编排。
2. 替代完整的攻击组织归因分析。
3. 对海量告警做一线分诊或优先级排序。
4. 持续输出态势看板或跨事件总体风险评分。

如果请求目标已经变成“这条告警现在要不要升级处置”，应转交 `IOC 快速核查与告警分诊`；如果目标变成“这个组织的历史活动、画像和归属证据是什么”，应转交 `威胁溯源分析`；如果目标变成“根据报告结果自动执行响应动作”，应转交 `应急响应编排`；如果目标变成“输出整体态势结论”，应转交 `安全态势感知`。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_target | `op.identify-target` | 识别事件边界、报告目标和核心实体输入 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认事件报告所需对象、关系和字段边界 | 是 |
| query_fact | `op.query-fact` | 拉取事件实体的一跳直接事实与报告基础对象 | 是 |
| expand_relation | `op.expand-relation` | 扩展到组织、活动、行业对象和同类风险对象 | 是 |
| assess_confidence | `op.assess-confidence` | 评估关联发现和报告结论的证据强度与适用边界 | 是 |
| compose_report | `op.compose-report` | 生成结构化事件报告与后续关注建议 | 是 |

### 3.2 操作顺序

`identify_target -> discover_source -> inspect_schema -> query_fact -> expand_relation -> assess_confidence -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定某个实体、字段或关系在当前平台中一定存在，也不允许把“图上有关联”直接写成“报告结论已确认”。

### 3.3 每个操作意图的职责

#### identify_target

输入是自然语言或结构化事件报告请求；输出是标准化事件摘要范围。

最少要完成：

1. 识别 `event_type`，例如 `ransomware_incident`、`malware_incident`、`phishing_incident`、`confirmed_security_incident`。
2. 提取 `core_entities`，例如 `malware`、`indicator`、`attack-pattern`、`campaign_hint`、`victim_identity`。
3. 提取 `report_depth`、`target_audience`、`need_peer_grouping` 和 `need_follow_up_recommendation`。
4. 识别用户要的是“事件复盘报告”“关联补充报告”还是“可分发摘要”。
5. 若事件尚未确认、核心实体不足或输出对象不明确，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 确认当前平台是否已注册可用于补充环境对象或行业对象解释的数据源。
3. 识别 `report`、`grouping`、`identity`、`campaign`、`intrusion-set`、`indicator` 等对象是否已由当前公开 Schema 对外暴露。
4. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `malware`、`intrusion-set`、`campaign`、`attack-pattern`、`indicator`、`relationship`、`report`、`grouping`、`identity` 的关键字段。
2. 明确“同级群组关联”在当前公开 Schema 下优先通过 `grouping`、`report.object_refs`、共享 `relationship` 和 `identity.sectors` 组合表达，而不是假定存在单一固定字段。
3. 确认哪些字段属于直接事实，哪些只能作为报告中的推断或后续关注建议依据。
4. 若某类 IOC 缺少标准对象类型，明确其需通过 `indicator.pattern` 或扩展对象间接表示。

#### query_fact

最少要完成：

1. 查询事件核心实体本体及其一跳直接关系。
2. 拉取恶意软件、组织、活动、TTP、IOC 和已有报告对象的基础事实层。
3. 优先取回报告所需最小闭环，不得一开始就拉取无边界的全量多跳图谱。
4. 返回第一轮事实结果，不直接输出最终定性结论。

#### expand_relation

最少要完成：

1. 沿 `relationship` 扩展到关联 `intrusion-set`、`campaign`、`attack-pattern`、`identity`、`grouping` 和 `report`。
2. 识别共享 IOC、共享恶意软件、共享活动目标或共享对象集合所形成的同类风险对象。
3. 对可复用关系做裁剪、去重和聚类，不得把整个子图原样塞进最终报告。
4. 当缺少直接关系时，必须把结果标记为“候选关联”或“待人工复核”，而不是输出确定性同级结论。

#### assess_confidence

最少要完成：

1. 对报告摘要、组织归属、活动关联和同类对象提示分别评估证据强度。
2. 将来源多样性、关系直接性、时间新鲜度、共享对象密度和字段完整性纳入评分。
3. 区分“已确认事实”“高可信关联”“待复核候选关联”。
4. 当某个结论仅依赖单条弱关系、过期报告或单一 IOC 复用时，必须显式降级并说明边界。

#### compose_report

最少要完成：

1. 输出事件概述、核心实体、威胁行为体、活动与技术、关联发现、后续关注建议和边界说明。
2. 明确哪些章节是直接事实，哪些章节是基于图谱关系的解释性推断。
3. 输出适合前端展示、复核流转和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260507-incident-report-001",
  "intent_id": "biz.automated-incident-reporting",
  "scenario_id": "incident-reporting.confirmed-incident-summary",
  "event": {
    "type": "ransomware_incident",
    "summary": "Ryuk infection confirmed on critical business host"
  },
  "core_entities": {
    "malware": ["Ryuk"],
    "indicator": ["btc-wallet-observed-in-case-01"],
    "attack_pattern": ["T1486"]
  },
  "analyst_id": "ir-engineer-001",
  "requested_at": "2026-05-07T10:15:00Z",
  "slots": {
    "report_depth": "standard",
    "target_audience": ["incident_commander", "security_manager"],
    "need_peer_grouping": true,
    "need_follow_up_recommendation": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "require_traceable_object_refs": true,
    "mark_candidate_association_explicitly": true
  },
  "role_policy": {
    "initiator_role": "IncidentReportConsumer",
    "execution_role": "IncidentReportingAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "incident_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| event | 是 | 事件类型与摘要 |
| core_entities | 是 | 报告起点实体 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| report_depth | 否 | `brief` / `standard` / `deep` |
| target_audience | 否 | 报告目标读者，如响应负责人或安全经理 |
| need_peer_grouping | 否 | 是否输出同类风险对象或群组关联 |
| need_follow_up_recommendation | 否 | 是否输出有限边界内的后续关注建议 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模图谱扩展，而应先做定向澄清：

1. 当前事件是否已经完成基本确认，还是仍停留在告警研判阶段。
2. 核心实体是否足够稳定到可以形成报告主线。
3. 用户要的是可分发报告，还是只要补充几条关联线索。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| IncidentReportingAgent | 默认唯一执行 AGENT，负责识别业务意图、执行关联查询、整理事件证据并生成报告 | 是 |
| IncidentReportConsumer | 人类使用者或外部消费角色，负责提交事件摘要、消费报告并决定是否触发后续联动 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `IncidentReportConsumer`，允许其提交 `biz.automated-incident-reporting` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_fact`、`expand_relation` 或 `assess_confidence`。
2. 若 `identify_target` 阶段发现输入仍是未确认 IOC 或初始告警，应先转交 `IOC 快速核查与告警分诊`，而不是直接生成事件报告。
3. 若用户要求“自动通知、自动封禁、自动处置”，应转交 `应急响应编排`。
4. 若用户要求完整攻击组织画像、组织级归因证据树或长期活动回顾，应转交 `威胁溯源分析`。
5. 默认路由器始终将该业务意图交给单一执行 AGENT `IncidentReportingAgent`。
6. 当事件证据包、对象引用集或长报告草稿开始明显挤占后续推理窗口时，`IncidentReportingAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部整理任务下放给临时附属 AGENT。

### 5.3 与相邻业务意图的路由判定

1. 当主问题是“把已经确认的事件整理成一份可复核、可分发的结构化报告”时，应路由到 `biz.automated-incident-reporting`。
2. 当主问题是“这个 IOC 现在要不要升级、处置或分诊”时，应路由到 `biz.ioc-triage`。
3. 当主问题是“这次事件最终归属哪个组织、历史上还有哪些活动和画像”时，应路由到 `biz.threat-attribution`。
4. 当主问题是“根据调查结果自动做什么响应动作”时，应转交 `应急响应编排`。
5. 当主问题是“这类事件对当前整体安全状态意味着什么”时，应转交 `安全态势感知`。

### 5.4 路由伪代码

```text
if intent_id == biz.automated-incident-reporting:
    if current_role == IncidentReportConsumer:
        delegate_to(IncidentReportingAgent)
    else:
        if need_clarification():
            ask_high_value_questions()
        else:
            execute_pipeline()
```

## 6. Tool 设计与调用边界

### 6.1 正式工具入口

本业务意图访问外部数据的正式入口应为统一查询工具，例如：

- `ai4x_query.catalog`
- `ai4x_query.schema`
- `ai4x_query.query`

如果后续存在专门的报告模板渲染器、上下文压缩器或对象聚类工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层图库已完全开放。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_target | 无需外部工具或仅轻量解析工具 | 不得把未确认告警直接当成已确认事件 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段或关系类型 |
| query_fact | `ai4x_query.query` | 不得一开始就拉取无边界多跳全图 |
| expand_relation | `ai4x_query.query` | 不得把“存在关系”直接写成“结论已证实” |
| assess_confidence | 内部评分逻辑 | 不得忽略时间边界、对象缺口和来源稀疏性 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略证据边界、对象引用和待复核项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 获取事件核心实体及一跳直接事实
4. 第二轮 `query` 扩展到组织、活动、TTP、行业对象和对象集合
5. 必要时在当前 session 内做聚类、裁剪和上下文治理
6. 内部证据强度评估与报告章节装配
7. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 当前公开注册的数据源为准，而不是按抽象“事件调查平台”假设任意扩写。根据当前仓库已知信息，本场景首版成立的最小闭环是 `opencti`。若后续需要补充“与我方环境相关性”的解释，再由相邻业务意图或增强数据源补入。

#### `opencti`（外部威胁情报源）

用途：提供恶意软件、组织、活动、IOC、报告和对象集合，是当前场景的核心事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `malware` | `id`、`name`、`aliases`、`description`、`malware_types` | 作为事件主体恶意软件 | 形成报告主线 |
| `intrusion-set` | `id`、`name`、`aliases`、`description`、`goals` | 表示与事件相关的攻击组织 | 支撑威胁行为体章节 |
| `campaign` | `id`、`name`、`description`、`first_seen`、`last_seen` | 表示具体攻击活动 | 支撑历史活动与关联发现 |
| `attack-pattern` | `id`、`name`、`description`、`kill_chain_phases` | 表示攻击技术 | 支撑 TTP 章节 |
| `indicator` | `id`、`name`、`pattern`、`valid_from`、`valid_until` | 承载 IOC 或检测线索 | 支撑证据和横向关联 |
| `relationship` | `id`、`relationship_type`、`source_ref`、`target_ref` | 串起对象关系 | 构造证据路径 |
| `report` | `id`、`name`、`published`、`object_refs` | 表示已有情报报告对象 | 引用来源与复用证据包 |
| `grouping` | `id`、`name`、`context`、`object_refs` | 表示一组上下文相关对象 | 承载同级群组关联 |
| `identity` | `id`、`name`、`identity_class`、`sectors` | 表示受害组织或行业对象 | 支撑同类目标或行业关联 |

#### “同级群组关联”的实现约束

在当前公开 Schema 下，“同级群组关联”应优先理解为以下几类可追溯关系：

1. 与本次事件共享 IOC、恶意软件或 Campaign 的其他对象。
2. 与本次事件目标处于同一 `sector` 的 `identity` 对象。
3. 被同一 `grouping` 或 `report.object_refs` 共同引用的一组相关对象。

因此，本设计不允许把“同级群组关联”写成未定义的组织层级推理，也不允许把单个行业标签直接扩大成确定受害结论。

## 7. 输出契约

### 7.1 输出结构

```json
{
  "report_id": "incident-report-20260507-001",
  "intent_id": "biz.automated-incident-reporting",
  "summary": {
    "event_type": "ransomware_incident",
    "headline": "Ryuk infection linked to Wizard Spider-related activity",
    "confidence": 0.78
  },
  "core_facts": {
    "malware": ["Ryuk"],
    "intrusion_set": ["Wizard Spider"],
    "campaign": ["Operation Ghost"],
    "attack_patterns": ["T1486"],
    "indicators": ["btc-wallet-observed-in-case-01"]
  },
  "peer_associations": [
    {
      "type": "campaign_overlap",
      "object": "Operation Ghost",
      "confidence": 0.71,
      "status": "high_confidence_association"
    }
  ],
  "follow_up_recommendations": [
    "Assess whether peer assets in the same sector require targeted hunting"
  ],
  "evidence_refs": [
    "report--xxx",
    "relationship--yyy"
  ],
  "uncertainties": [
    "The wallet IOC is represented through indicator.pattern rather than a dedicated standard object"
  ]
}
```

### 7.2 报告章节要求

至少包含以下章节：

1. 事件概述。
2. 核心实体与证据摘要。
3. 威胁行为体与活动关联。
4. 攻击技术与影响语境。
5. 同类风险对象或群组关联发现。
6. 后续关注建议。
7. 边界说明与待复核项。

### 7.3 事实与推断分离规则

1. 直接来自对象字段或直接关系的内容，标记为事实。
2. 基于多条关系归纳出的组织、活动或群组关联，标记为高可信关联或候选关联。
3. 面向后续行动的建议，只能写成“建议关注”“建议追加排查”“建议转交某能力”，不得写成已自动执行。

## 8. 验收标准

### 8.1 设计验收

满足以下条件时，视为本意图设计完成：

1. 能从一个已确认事件请求中稳定识别事件边界、核心实体和目标读者。
2. 能说明当前首版最小依赖数据源是 `opencti`，并给出主要对象类型与字段边界。
3. 能明确区分“事件报告生成”与“IOC 分诊”“组织归因”“响应编排”“态势感知”之间的能力边界。
4. 能把“同级群组关联”约束为当前公开 Schema 下可追溯的 `grouping`、`report.object_refs`、共享 `relationship` 和 `identity.sectors` 组合，而不是抽象空话。
5. 能输出结构化报告契约，并显式要求事实与推断分离。

### 8.2 行为验收

对于场景文档中的 Ryuk 示例，请求执行后至少应满足：

1. 能把 `Ryuk` 识别为 `malware`，把 `T1486` 识别为 `attack-pattern`。
2. 若图谱中存在 `Wizard Spider` 和 `Operation Ghost` 的相关关系，应在报告中分别落到威胁行为体和关联活动章节。
3. 若“比特币地址”类 IOC 缺少标准对象类型，应明确说明其通过 `indicator.pattern` 或扩展对象表示，而不是伪造标准对象。
4. 输出中必须包含至少一条“后续关注建议”，但不得越权写成自动响应动作。
5. 输出中必须包含至少一条边界说明或待复核项。

## 9. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/automated-incident-report/manifest.json](../../sample/automated-incident-report/manifest.json)。

### 9.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于提供 `Ryuk -> Wizard Spider -> Operation Ghost -> T1486 -> healthcare grouping` 的事件报告证据链。

### 9.2 推荐验证请求

1. 直接使用 [sample/automated-incident-report/manifest.json](../../sample/automated-incident-report/manifest.json) 中的 `request_fixture`。
2. 核心输入为已确认的 `ransomware_incident`，包含 `Ryuk`、`btc-wallet-observed-in-case-01` 和 `T1486`。

### 9.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
IR 已确认一起 Ryuk 勒索软件感染事件，已知恶意软件是 Ryuk，IOC 是 btc-wallet-observed-in-case-01，TTP 是 T1486。请生成最终调查报告，包含主要威胁行为体、关联活动、医疗行业同类对象关联和后续关注建议，并明确哪些结论只是候选关联。
```

### 9.4 预期验证点

1. 能形成高置信路径 `btc-wallet-observed-in-case-01 -> Ryuk -> Operation Ghost -> Wizard Spider`。
2. 报告中应包含 `T1486`、医疗行业相关目标对象和 `grouping` / `report.object_refs` 支撑的同级关联。
3. 能显式说明比特币地址 IOC 在当前测试数据中通过 `indicator.pattern` 表达，而不是独立标准对象。
4. 能给出“追加排查同医疗行业对象”的后续关注建议，但不越权写成自动响应动作。

## 10. 最终 AGENT 实现建议

### 9.1 Agent 命名建议

- `IncidentReportingAgent`

### 9.2 System Prompt 关注点

主系统提示词应重点固定以下规则：

1. 默认只处理已确认或基本收敛的事件报告请求。
2. 所有报告结论必须可追溯到对象字段、关系或报告引用。
3. 事实、关联判断和建议动作必须分层表达。
4. 不得把后续编排、态势更新或完整归因工作混入当前报告能力。

### 9.3 Skill 分层建议

首版建议保持单主 SKILL，不提前拆成多个平行报告 SKILL：

1. 主 SKILL：`incident_report_generation`
2. 可选上下文治理类 SKILL：`incident_evidence_compaction`
3. 仅当未来出现稳定分化时，再考虑拆出 `executive_summary_report` 或 `peer_association_report` 等扩展 SKILL。

### 9.4 与图谱能力的实现映射

本意图在实现层应映射到以下最小链路：

1. 前端入口：`CHROME_EXTENSION`
2. 业务执行：`AI AGENT`
3. 数据接入：`ai4x_platform`
4. 威胁事实源：`OPENCTI_PLATFORM`

这条链路与 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的 Application Layer 关系保持一致，不额外假设新的实现组件。