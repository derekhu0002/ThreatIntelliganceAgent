# IOC 快速核查与告警分诊 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `IOC 快速核查与告警分诊` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能查到某个 IOC 的情报”，而是“有限的上下文窗口应优先留给哪些高价值分诊判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛 IOC 类型、告警上下文和输出目标，避免在错误的对象上扩查。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制同一批 Indicator、标签、关系和来源上下文。
3. 当候选 IOC、关联对象或告警列表逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.ioc-triage`
- `intent_name`: `IOC 快速核查与告警分诊`
- `intent_level`: `L1`
- `parent_capability`: `IOC 快速核查与告警分诊`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个外部安全告警、人工上报 IOC、可疑域名、IP、URL、文件 HASH 或简单告警摘要出发，结合 OpenCTI 中的 Indicator、置信度、有效期、标签、来源侧证据和关联对象，对该 IOC 当前是否值得优先处置做快速判断，并输出结构化的优先级结论、研判理由、建议动作和待确认边界。

这里的“IOC 快速核查与告警分诊”默认是围绕“这个 IOC 当前值不值得投入更高处置成本”展开的分析能力，而不是完整的 SIEM 平台、自动封禁编排引擎或归因分析系统。

### 2.3 典型触发者

- 安全运营中心分析师
- 安全值班人员
- 安全事件分析师
- 情报分析专员

### 2.4 典型触发表达

- 这个域名出现在告警里，先帮我看值不值得升级处置。
- 这个 IP 是不是高风险 IOC，应该立刻拉高优先级吗。
- 这个 HASH 有没有可靠情报支撑，还是更像噪声。
- 帮我给这条告警做快速分诊，告诉我是高优先级还是继续观察。
- 给我一个适合 SOC 一线使用的简版结论和建议动作。

### 2.5 业务边界

本意图负责：

1. 从 IOC 或外部告警对象出发识别可用情报事实。
2. 快速汇总 `confidence`、有效期、标签、来源侧代理信号和关联威胁上下文。
3. 输出高、中、低优先级或等价的分诊结果，并给出处置建议。
4. 标记证据边界、待人工确认项和不适合直接下结论的情况。

本意图不直接负责：

1. 自动执行封禁、隔离、回滚、应急响应或工单流转。
2. 输出完整的攻击组织归因、长时间线调查或事件根因分析。
3. 替代安全态势感知、威胁溯源分析或应急响应编排等后续深度业务意图。

如果研判结果已经进入“这个 IOC 背后是谁、关联哪些活动和组织”的问题，应转交 `威胁溯源分析`；如果问题升级为“这个事件要不要立刻执行响应动作”，应转交 `应急响应编排`；如果需要汇总整体风险水平或趋势，则应转交 `安全态势感知`。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_target | `op.identify-target` | 识别 IOC 类型、告警上下文和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认 Indicator、关系、标签和公共字段边界 | 是 |
| query_fact | `op.query-fact` | 拉取 IOC 一跳事实和排序主输入 | 是 |
| expand_relation | `op.expand-relation` | 扩展关联对象、来源侧线索和威胁上下文 | 是 |
| assess_confidence | `op.assess-confidence` | 计算分诊优先级并评估结论置信度 | 是 |
| compose_report | `op.compose-report` | 生成结构化分诊结果和建议动作 | 是 |

### 3.2 操作顺序

`identify_target -> discover_source -> inspect_schema -> query_fact -> expand_relation -> assess_confidence -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定某个 IOC 一定在平台中存在，也不允许直接把模糊告警描述当成稳定情报事实。

### 3.3 每个操作意图的职责

#### identify_target

输入是自然语言或结构化 IOC 分诊请求；输出是标准化核查范围。

最少要完成：

1. 识别 `target_type`，例如 `domain`、`ip`、`url`、`hash`、`indicator_id`、`alert_event`。
2. 解析 `target_value`。
3. 提取可用的 `alert_context`，例如告警来源、触发时间、命中规则、宿主或处置时限。
4. 识别用户是否要求补充 `report_depth`、`need_source_reasoning`、`need_relation_context`。
5. 若 IOC 对象、告警目标或输出目标存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 确认当前平台是否已注册其他能直接支持分诊的数据源；若未注册，不得擅自假定其存在。
3. 记录本次允许访问的数据源列表和缺失源。
4. 把用户直接提供的告警字段与平台查询字段区分开。

#### inspect_schema

最少要完成：

1. 确认 `indicator` 的请求字段与响应字段边界。
2. 确认 `common/core` 层中的 `confidence`、`labels`、`external_references`、`created_by_ref` 等公共字段可用性。
3. 确认 `relationship` 以及相关联的 `malware`、`infrastructure`、`intrusion-set`、`attack-pattern`、`report` 等对象边界。
4. 明确哪些字段属于直接事实，哪些只能作为派生评分输入。

#### query_fact

最少要完成：

1. 当输入是域名、IP、URL、HASH 或 Indicator 标识时，优先拉取命中的 `indicator` 主对象。
2. 提取 `confidence`、`valid_from`、`valid_until`、`labels`、`pattern`、`pattern_type` 等排序主输入。
3. 若输入是告警摘要，则先标准化出可查询 IOC，再进入正式查询链路。
4. 返回第一轮 IOC 事实结果，不直接输出最终优先级结论。

#### expand_relation

最少要完成：

1. 通过 `relationship` 补充该 IOC 关联的 `malware`、`infrastructure`、`intrusion-set`、`attack-pattern`、`report` 等上下文对象。
2. 结合 `created_by_ref`、`external_references` 和标签规则形成来源侧代理信号。
3. 识别 `likely_false_positive`、过期情报、关系稀薄或来源冲突等降权因素。
4. 若当前结果不足以支持稳定高优先级判断，必须保留“继续观察”或“待补证据”结论，而不是强行上结论。

#### assess_confidence

最少要完成：

1. 对每个 IOC 计算综合分诊分数，而不是只按单一 `confidence` 排序。
2. 将置信度、有效期窗口、来源侧代理信号、上下文关联强度、误报标签和数据完整性纳入评分。
3. 识别高优先级处置对象、持续观察对象和待确认对象。
4. 当来源冲突、情报过期或证据稀薄时，必须显式降低结论置信度。

#### compose_report

最少要完成：

1. 输出摘要、优先级、主要证据、建议动作和待确认项。
2. 说明分析边界、评分依据、缺失数据和例外标签。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260506-ioc-triage-001",
  "intent_id": "biz.ioc-triage",
  "scenario_id": "ioc-triage.alert-priority",
  "target": {
    "type": "domain",
    "value": "evil.example"
  },
  "alert_context": {
    "source_system": "external-siem",
    "alert_name": "Suspicious DNS Query",
    "occurred_at": "2026-05-06T10:00:00Z"
  },
  "analyst_id": "soc-analyst-001",
  "requested_at": "2026-05-06T10:03:00Z",
  "slots": {
    "report_depth": "brief",
    "need_source_reasoning": true,
    "need_relation_context": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "mark_false_positive_signal_explicitly": true,
    "min_confidence_threshold": 0.6
  },
  "role_policy": {
    "initiator_role": "IOCTriageConsumer",
    "execution_role": "IOCTriageAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "ioc_triage_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| target | 是 | IOC 对象类型和值 |
| alert_context | 否 | 告警上下文 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_source_reasoning | 否 | 是否展示来源侧代理信号和降权原因 |
| need_relation_context | 否 | 是否展示一跳关联上下文 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模查询或长链路扩展，而应先做定向澄清：

1. 用户要的是一线快速分诊、标准核查结论，还是深度情报说明。
2. 输入对象到底是单个 IOC，还是一整条告警摘要，需要先抽取 IOC。
3. 当前输出目标是优先级排序，还是要继续进入溯源分析或响应编排。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| IOCTriageAgent | 默认唯一执行 AGENT，负责识别业务意图、执行查询、完成优先级评估并生成分诊结果 | 是 |
| IOCTriageConsumer | 人类使用者或外部消费角色，负责提交 IOC 或告警线索，消费结果并决定是否升级处置 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `IOCTriageConsumer`，允许其提交 `biz.ioc-triage` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_fact`、`expand_relation` 或 `assess_confidence`。
2. 若 `identify_target` 阶段发现 IOC 对象、告警上下文或输出目标存在明显分叉，默认先进入澄清分支，而不是立即进入关系扩展分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `IOCTriageAgent`。
4. 当关联对象、候选 IOC 或批量告警结果开始挤占后续推理窗口时，`IOCTriageAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 当请求目标从“快速判断处置优先级”转变成“分析攻击组织、关联活动和溯源链条”时，应转交 `威胁溯源分析`。
6. 当请求目标从“给出建议动作”升级为“触发标准化响应流程”，应转交 `应急响应编排`。

### 5.3 与相邻业务意图的路由判定

1. 当主输入对象是域名、IP、URL、HASH、Indicator 或简单告警摘要，且问题是“值不值得优先处置、是否应继续观察”时，应路由到 `biz.ioc-triage`。
2. 当主输入对象是攻击事件、完整事件上下文或待处置工单，且问题是“下一步要执行哪些响应动作”时，应路由到 `应急响应编排`。
3. 当主输入对象需要做组织归因、活动归并或长链溯源时，应路由到 `威胁溯源分析`。
4. 当主输入对象变成多条告警整体的风险水平、趋势和态势摘要时，应路由到 `安全态势感知`。

### 5.4 路由伪代码

```text
if intent_id == biz.ioc-triage:
    if current_role == IOCTriageConsumer:
        delegate_to(IOCTriageAgent)
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

如果后续存在专门的 IOC 分诊策略工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层平台能力已经存在。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_target | 无需外部工具或仅轻量解析工具 | 不得臆造 IOC、标签或来源信息 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| query_fact | `ai4x_query.query` | 不得把模糊告警摘要直接当成平台事实 |
| expand_relation | `ai4x_query.query` | 不得绕过平台直连底层库 |
| assess_confidence | 内部评分逻辑 | 不得忽略误报标签、过期窗口或来源冲突 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略边界、不确定性和待确认项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 获取 IOC 对应 `indicator` 的主事实
4. 第二轮 `query` 扩展 `relationship`、`report` 和关联威胁对象
5. 内部优先级评分与置信度评估
6. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 当前公开注册的数据源为准，而不是按抽象情报平台假设任意扩写。根据当前仓库已知信息，本场景首版成立的最小闭环是 `外部告警输入 + opencti`。也就是说，AGENT 不能假定 SIEM、EDR、资产 CMDB、工单平台或阻断系统已经作为 `ai4x_platform` 原生数据源存在；这些内容若未注册为 `source_id`，只能作为用户输入上下文或外部补充信号处理。

#### 平台已注册数据源与 IOC 分诊信号映射

对本场景而言，当前真正构成最小闭环的是 `opencti`。用户或外部系统提供的告警内容只承担输入上下文角色，不应被误写为平台可查询源。

#### `opencti`（外部威胁情报源）

用途：提供 IOC 分诊所需的 Indicator 主对象、置信度、有效期、标签、来源引用和关联关系，是当前场景的核心事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `indicator`（指标） | `id`、`name`、`pattern`、`pattern_type`、`indicator_types`、`valid_from`、`valid_until` | 表示 IOC 的检测规则与有效期窗口 | 这是快速分诊的主对象 |
| `common/core` 公共字段 | `confidence`、`labels`、`external_references`、`created_by_ref` | 作为分诊排序、来源代理推断和误报降权输入 | 当前最稳定的评分事实来自这些字段 |
| `relationship`（关系） | `id`、`relationship_type`、`source_ref`、`target_ref`、`start_time`、`stop_time` | 串联 Indicator 与威胁上下文对象 | 用于增强解释性，而不是替代主评分 |
| `report`（报告） | `id`、`name`、`published`、`object_refs` | 提供关联报告与发布时间线索 | 用于判断情报是否仍具业务价值 |
| `malware`（恶意软件）、`infrastructure`（基础设施）、`intrusion-set`（入侵组织）、`attack-pattern`（攻击模式） | `id`、`name`、`description` | 为高优先级结果补充一跳威胁语境 | 用于说明为什么需要升级关注 |

#### 与 IOC 落地直接相关的 observable 类型

由于外部告警通常落在域名、URL、IP、HASH 等 IOC 上，当前场景还依赖以下可观测对象或表达方式：

| Observable/表达方式 | 关键字段 | 在本场景中的作用 |
| --- | --- | --- |
| `domain-name`（域名） | `id`、`value`、`resolves_to_refs` | 适用于可疑域名类告警 |
| `ipv4-addr`（IPv4 地址） | `id`、`value`、`resolves_to_refs`、`belongs_to_refs` | 适用于恶意 IP、C2 IP 或外联目的地址类告警 |
| `url`（URL 地址） | `id`、`value` | 适用于钓鱼链接或恶意下载地址类告警 |
| `file`（文件） | `id`、`hashes`、`name` | 适用于文件 HASH 类告警 |
| `indicator.pattern`（指标模式） | `pattern`、`pattern_type` | 用于把上述 observable 统一抽象为可匹配的检测规则 |

#### 当前 SCHEMA 对“来源可靠性（派生属性）”的支持边界

文档中的“来源可靠性”维度很重要，但需要注意：

1. 当前公开 STIX 2.1 Schema 中没有名为 `reliability` 的标准一级字段。
2. 若业务上需要“来源可靠性”，当前更稳妥的建模方式是组合使用：`created_by_ref`、`external_references`、`labels`，以及与来源实体相关的 `relationship`。
3. 因此它更适合被实现为派生评分维度，而不是依赖某个固定的原生字段。

#### 本场景最小数据闭环

按当前对外 Schema，这个场景至少需要具备以下数据链路：

1. 外部系统或分析师给出一个 IOC，例如域名、URL、IP 或文件 HASH。
2. OpenCTI 中存在一个能够命中该 IOC 的 `indicator`。
3. 该 `indicator` 至少具备 `confidence`、`valid_from`，最好还具备 `valid_until`、`labels`。
4. 如需提高解释性，可进一步通过 `relationship` 补齐该 Indicator 指向的 `malware`、`infrastructure`、`intrusion-set` 或 `report`。
5. `IOCTriageAgent` 基于 `confidence`、有效期窗口、标签和来源侧代理信息输出高、中、低优先级结论。

#### 平台外补充数据源的边界说明

当前仓库没有把 SIEM、EDR、资产重要度、工单系统或封禁平台声明为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入分诊链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `query_fact` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与当前平台能力一致的分析逻辑：

1. 先通过 `schema/catalog` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `opencti` 提取 `indicator` 主事实，形成 IOC 分诊主事实层。
3. 再用 `relationship`、`report` 和关联对象补齐解释性上下文，而不是在一开始就扩写长链关系。
4. 对尚未注册到平台的告警系统、工单系统或资产系统，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面受当前平台能力边界约束，另一方面也符合仓库现有设计思路：优先跑通“IOC 事实核查 + 规则评分 + 分诊建议”的最小闭环，而不是在首版就假定事件处置自动化能力已经齐备。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `IOC 快速核查与告警分诊` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.ioc-triage.indicator-priority`
- `skill_name`: `IOC 快速分诊与优先级判断`
- `bind_intent_id`: `biz.ioc-triage`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为域名、IP、URL、HASH、Indicator 或简短告警摘要。
2. 请求目标是识别高、中、低优先级或给出处置建议。
3. 用户要求生成适合一线 SOC 快速消费的结构化结论。

在第一阶段，即便用户只给出一个 IOC 字符串而未补充告警上下文，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别 IOC 对象类型、对象值和可用告警上下文。
2. 若对象、上下文或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对 IOC 执行第一轮事实查询。
7. 提取 `confidence`、有效期、标签和来源侧代理输入。
8. 必要时用 `relationship`、`report` 和关联对象补充一跳威胁语境。
9. 若中间结果已形成长对象列表、长报告列表或大批候选 IOC，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
10. 对 IOC 进行加权排序并输出结构化分诊报告，同时明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. IOC 摘要。
2. 分诊优先级。
3. 主要证据。
4. 降权或加权因素。
5. 待人工确认项。
6. 建议动作。
7. 置信度说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.ioc-triage.indicator-priority` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.ioc-triage.alert-extract` | 针对原始告警摘要先做 IOC 抽取和标准化 | 否 |
| 输出目的特化 SKILL | `skill.ioc-triage.shift-handover-brief` | 针对值班交接生成更短的结论模板 | 否 |
| 高负载辅助 SKILL | `skill.ioc-triage.batch-condense` | 压缩批量 IOC 或告警列表 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.ioc-triage`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当输入对象、数据入口、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.ioc-triage.indicator-priority`，跑通默认 IOC 分诊链路。
2. 第二阶段：当单个 IOC 与告警摘要两类输入的处理方式稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当值班交接摘要、标准分诊结果和批量告警排序三类输出稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当批量 IOC 成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260506-ioc-triage-001",
  "intent_id": "biz.ioc-triage",
  "target": {
    "type": "domain",
    "value": "evil.example"
  },
  "summary": "该 IOC 当前具备较高置信度且仍在有效期内，但存在误报风险标签，需要维持监控并暂不升级为最高优先级处置。",
  "direct_facts": [
    "opencti 中存在命中 evil.example 的 indicator",
    "该 indicator 的 confidence 为 85",
    "valid_from 为 2026-05-03T00:00:00Z，valid_until 为 2026-05-20T00:00:00Z",
    "labels 中包含 likely_false_positive"
  ],
  "inferred_assessments": [
    "虽然情报活跃且置信度较高，但误报标签显著降低即时处置优先级",
    "该 IOC 更适合列为持续观察对象，而非立即升级应急响应"
  ],
  "ranked_triage": [
    {
      "object_type": "indicator",
      "object_name": "evil.example",
      "risk_score": 0.58,
      "priority": "medium",
      "recommended_disposition": "monitor",
      "needs_manual_confirmation": true
    }
  ],
  "recommended_actions": [
    "维持监控并观察后续命中频率",
    "若后续出现新的高可信来源或误报标签被移除，再重新评估优先级",
    "若该 IOC 与内部高价值事件链路重合，再升级到应急响应链路"
  ],
  "pending_confirmations": [
    "当前来源可靠性属于派生判断，不是原生字段",
    "未接入外部资产重要度和现场处置反馈，无法单凭平台数据做最终封禁决策"
  ],
  "confidence": 0.71,
  "boundary_notes": [
    "该结果用于快速核查与告警分诊，不等同于攻击归因结论",
    "该结果为处置优先级建议，不代表系统已执行阻断或响应动作"
  ]
}
```

### 8.2 验收标准

一次合格的 `IOC 快速核查与告警分诊` 输出至少应满足：

1. 明确 IOC 对象和优先级，不得只输出笼统风险描述。
2. 区分直接事实与推断结论，不得把来源派生判断写成原生字段事实。
3. 至少给出优先级、证据、建议动作和待确认项四类核心结果。
4. 显式说明误报标签、有效期或来源冲突等关键降权因素。
5. 明确当前平台能力边界，不能把未注册数据源写成已验证事实。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.ioc-triage`。
2. 决定具体场景，例如 `alert-priority`、`ioc-quick-check`。
3. 在方向不清时优先发起高价值澄清，收敛 IOC 对象、上下文和输出深度。
4. 生成或补齐 Intent Envelope。
5. 决定是否可以由单 AGENT 直接完成，还是需要在高上下文负载场景下创建临时附属 AGENT。

### 9.3 Skill Orchestrator 责任

1. 加载对应 Skill。
2. 按顺序触发 L2 操作意图。
3. 在中间结果过长时优先调用上下文治理类 SKILL。
4. 收集中间结果并传递给下一步。
5. 汇总最终报告。

在默认情况下，全部中间状态都由主 AGENT 自己维护。

### 9.4 Tool Policy Guard 责任

1. 限制只有主执行 AGENT 或其经授权的临时附属 AGENT 才能执行查询型操作意图。
2. 限制工具调用顺序为 `catalog -> schema -> query`。
3. 拒绝未授权的直连访问。
4. 校验输出中是否分离事实与推断，并显式标记误报信号、过期窗口和来源派生属性。

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当 IOC、告警上下文或输出目标不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本关系扩展。
3. 处理 `biz.ioc-triage` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及优先级判断时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 当输入已经进入归因、溯源或响应编排问题域时，必须转交相邻业务意图，而不是继续停留在快速分诊链路。
8. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.ioc-triage":
        route_elsewhere()

    if need_clarification(envelope):
        return ask_for_clarification(
            topics=["target", "alert_context", "report_depth"]
        )

    if should_route_to_attribution(envelope):
        return route_to("威胁溯源分析")

    if should_route_to_incident_response(envelope):
        return route_to("应急响应编排")

    skill = skill_orchestrator.load("skill.ioc-triage.indicator-priority", envelope)

    tool_policy_guard.authorize("IOCTriageAgent", envelope)

    target = run_identify_target(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    facts = run_query_fact(skill, envelope, schema)
    context = run_expand_relation(skill, envelope, facts)

    if should_compact_in_current_session(context):
        context = run_context_governance_skill(
            "skill.ioc-triage.batch-condense",
            context
        )

    scores = run_assess_confidence(skill, envelope, facts, context)
    report = run_compose_report(skill, envelope, facts, context, scores)

    return report
```

## 10. 验收建议

### 10.1 业务意图验收

1. 能把域名、IP、URL、HASH、Indicator 或简短告警请求稳定识别为 `biz.ioc-triage`。
2. 缺少 `target` 或关键告警上下文时不进入高成本扩展流程。
3. 能输出结构化分诊结果，而不是单段散文。

### 10.2 操作意图验收

1. `discover_source` 前不得直接执行查询。
2. `inspect_schema` 后才能发起正式查询。
3. `assess_confidence` 必须综合多个评分维度，而不是只看 `confidence`。
4. `compose_report` 必须产出优先级、建议动作、待确认项和边界说明。
5. 当问题域已经转向溯源分析或响应编排时，必须转交相邻业务意图。

### 10.3 角色验收

1. `IOCTriageConsumer` 不得直接调用查询工具。
2. 单一主 AGENT `IOCTriageAgent` 能完成全链路执行。
3. 只有在高上下文负载任务中，系统才允许创建附属 AGENT。
4. 附属 AGENT 的输出必须回流到主 AGENT，由主 AGENT 负责最终结论。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/ioc-triage/manifest.json](../../sample/ioc-triage/manifest.json)。

### 11.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于提供 `evil.example` 的 `indicator`、有效期、标签和关联 `report`。

### 11.2 推荐验证请求

1. 直接使用 [sample/ioc-triage/manifest.json](../../sample/ioc-triage/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `domain = evil.example`，告警上下文为“一线告警命中可疑域名，判断是否需要升级处置”。

### 11.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
SOC 一线告警命中可疑域名 evil.example，请快速核查它现在是否值得升级处置。请结合置信度、有效期、标签、关联报告和误报信号，给我一个适合一线使用的分诊结论和建议动作。
```

### 11.4 预期验证点

1. 能命中 `indicator` 主事实，而不是只返回模糊 IOC 文本。
2. 能识别 `confidence = 85`、有效期仍然有效、`labels` 含 `likely_false_positive`。
3. 能输出 `medium` 或观察态结论，并显式说明降权原因。

## 12. 与当前模型文件的关系

本文档对应 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中：

1. L1 业务意图：`IOC 快速核查与告警分诊`
2. 当前能力元素：`IOC 快速核查与告警分诊`

当前模型文件已经表达了顶层能力位置，但还没有表达：

1. 操作意图的执行顺序。
2. 角色与工具权限约束。
3. Intent Envelope、输入槽位和输出契约。
4. 数据源、对象、字段与分诊评分逻辑之间的映射关系。

这四部分由本文档补齐，后续再决定是否继续回写到 JSON 模型中。