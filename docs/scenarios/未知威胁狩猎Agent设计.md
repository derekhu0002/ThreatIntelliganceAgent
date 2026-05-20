# 未知威胁狩猎 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `未知威胁狩猎` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能扩出更多关系”，而是“有限的上下文窗口应优先留给哪些高价值新线索判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛狩猎假设、种子对象和输出目标，避免在错误图谱区域上盲目扩展。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制同一批子图、候选线索和证据路径上下文。
3. 当中间结果逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始子图、治理过程与后续研判时，才创建附属 AGENT 隔离长上下文。

本设计与场景文档 [scenarios/威胁情报分析/基于“关联图谱”的未知威胁猎杀.md](../../scenarios/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5%E5%88%86%E6%9E%90/%E5%9F%BA%E4%BA%8E%E2%80%9C%E5%85%B3%E8%81%94%E5%9B%BE%E8%B0%B1%E2%80%9D%E7%9A%84%E6%9C%AA%E7%9F%A5%E5%A8%81%E8%83%81%E7%8C%8E%E6%9D%80.md) 对齐。场景名使用“未知威胁猎杀”，能力名使用“未知威胁狩猎”，本文统一将其视为同一业务能力在不同抽象层的表达。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.unknown-threat-hunting`
- `intent_name`: `未知威胁狩猎`
- `intent_level`: `L1`
- `parent_capability`: `未知威胁狩猎`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个明确的狩猎假设、攻击组织、恶意软件家族、关键 IOC、基础设施对象或异常关系出发，沿威胁图谱做受控扩展，发现当前尚未被直接告警或尚未进入处置队列的高价值调查线索，并输出可解释的候选线索列表、证据路径、优先调查建议和待验证边界。

这里的“未知威胁狩猎”默认关注“发现新的高价值待验证线索”，而不是完整的攻击组织归因、批量 IOC 分诊、事件根因报告或自动化响应流程。

### 2.3 典型触发者

- 威胁狩猎工程师
- 安全事件分析师
- 安全运营中心分析师
- 情报分析专员

### 2.4 典型触发表达

- 以 APT29 为起点，帮我找图谱里还没被关注但值得追的线索。
- 这个恶意软件家族还能扩出哪些共用基础设施或关联组织。
- 从这个 C2 域名出发，找可能被忽略的关联对象。
- 基于当前图谱，帮我提出 3 个最值得继续验证的猎杀线索。
- 不要给我完整归因报告，我只需要下一轮狩猎方向和证据路径。

### 2.5 业务边界

本意图负责：

1. 从狩猎假设或种子对象出发查询和扩展图谱事实。
2. 识别共用基础设施、跨团伙复用、关系稀疏但值得跟进的异常连接和潜在线索。
3. 对候选线索做新颖性、证据强度和继续调查价值排序。
4. 输出结构化猎杀报告、后续调查建议和待验证项。

本意图不直接负责：

1. 给出最终攻击组织归因结论。
2. 对单个 IOC 做一线处置优先级分诊。
3. 生成完整事件时间线或同级群组关联报告。
4. 自动执行阻断、隔离、响应编排或工单流转。

如果请求目标已经变成“这个 IOC 是否应优先处置”，应转交 `IOC 快速核查与告警分诊`；如果目标变成“这个线索最终属于哪个组织、有哪些 TTP 和活动画像”，应转交 `威胁溯源分析`；如果目标升级为“要不要立刻触发响应动作”，应转交 `应急响应编排`。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_target | `op.identify-target` | 识别狩猎假设、种子对象、调查范围和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认图谱对象、关系和可观测字段边界 | 是 |
| query_fact | `op.query-fact` | 拉取种子对象的一跳直接事实与基础子图 | 是 |
| expand_relation | `op.expand-relation` | 沿组织、恶意软件、IOC、基础设施和观测关系做受控扩展 | 是 |
| assess_confidence | `op.assess-confidence` | 评估候选线索的新颖性、证据强度和调查优先级 | 是 |
| compose_report | `op.compose-report` | 生成结构化猎杀报告和建议动作 | 是 |

### 3.2 操作顺序

`identify_target -> discover_source -> inspect_schema -> query_fact -> expand_relation -> assess_confidence -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接大规模扩图，也不允许把“图上有关联”直接当成“值得调查的新线索”。

### 3.3 每个操作意图的职责

#### identify_target

输入是自然语言或结构化狩猎请求；输出是标准化狩猎范围。

最少要完成：

1. 识别 `seed_type`，例如 `intrusion-set`、`malware`、`indicator`、`infrastructure`、`domain`、`ip`、`hash`、`relationship-cluster`。
2. 解析 `seed_value` 或 `seed_object_id`。
3. 提取 `hunt_hypothesis`、`focus_dimension`、`report_depth` 和 `max_lead_count`。
4. 识别用户要的是“发现新线索”“验证共用基础设施”还是“给出下一轮调查方向”。
5. 若种子对象、狩猎目标或输出目标存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 确认当前平台是否已注册可补充“与我方环境相关性”解释的数据源，例如 `vehicle_iobe`。
3. 识别 `observed-data`、`sighting` 等环境命中事实是否已由当前 OpenCTI 数据对外暴露。
4. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `intrusion-set`、`malware`、`indicator`、`infrastructure`、`relationship`、`report` 的关键字段。
2. 确认 `domain-name`、`ipv4-addr`、`file`、`url` 等 observable 的可落地字段。
3. 若当前需要从“图谱关系”走向“环境命中”，确认 `observed-data`、`sighting` 的字段边界。
4. 明确哪些字段属于直接事实，哪些只能作为候选线索评分输入。

#### query_fact

最少要完成：

1. 查询种子对象本体及其一跳直接关系。
2. 提取基础事实层，例如组织、恶意软件、IOC、基础设施、标签、时间边界和来源引用。
3. 对图谱子图做第一轮裁剪，避免一开始就扩到所有二跳、三跳对象。
4. 返回第一轮事实结果，不直接输出最终狩猎结论。

#### expand_relation

最少要完成：

1. 沿 `relationship` 扩展到关联 `malware`、`infrastructure`、`indicator`、`report` 和候选 `intrusion-set`。
2. 识别“共用基础设施”“同一 IOC 被多个团伙或恶意软件复用”“从同一报告簇反复出现的对象”等值得继续跟进的线索模式。
3. 当可用时，利用 `sighting`、`observed-data` 或内部暴露面语境识别“与我方范围更相关”的候选线索。
4. 对高扩展度结果进行裁剪、去重和聚类，不得把全部子图原样带入后续评分。

#### assess_confidence

最少要完成：

1. 对每个候选线索计算综合猎杀优先级，而不是只按连接边数量排序。
2. 将证据强度、关系独特性、来源多样性、时间新鲜度、环境相关性和误报风险纳入评分。
3. 区分“强线索”“可跟进线索”“弱线索/观察项”。
4. 当线索仅来自单条弱关系、过期情报或无环境相关性时，必须显式降级。

#### compose_report

最少要完成：

1. 输出摘要、候选线索排序、证据路径、建议验证动作和待确认项。
2. 明确哪些是直接事实，哪些是为了指导下一轮狩猎的推断建议。
3. 输出适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260507-hunt-001",
  "intent_id": "biz.unknown-threat-hunting",
  "scenario_id": "unknown-threat-hunting.graph-hypothesis",
  "seed": {
    "type": "intrusion-set",
    "value": "APT29"
  },
  "hunt_hypothesis": "查找与 APT29 关联、但尚未进入现有处置队列的共用基础设施或次级团伙线索",
  "analyst_id": "hunter-001",
  "requested_at": "2026-05-07T09:30:00Z",
  "slots": {
    "focus_dimension": ["infrastructure", "indicator", "intrusion-set"],
    "report_depth": "standard",
    "max_lead_count": 5,
    "need_environment_relevance": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "require_traceable_evidence_path": true,
    "min_lead_confidence_threshold": 0.6
  },
  "role_policy": {
    "initiator_role": "ThreatHunterConsumer",
    "execution_role": "ThreatHunterAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "unknown_threat_hunt_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| seed | 是 | 狩猎起点对象类型和值 |
| hunt_hypothesis | 是 | 狩猎假设或目标 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| focus_dimension | 否 | 关注基础设施、IOC、团伙、恶意软件或环境命中 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| max_lead_count | 否 | 最大候选线索数 |
| need_environment_relevance | 否 | 是否补充与我方环境相关性的解释 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模扩图，而应先做定向澄清：

1. 用户到底要“发现新线索”还是“给出最终归因”。
2. 当前种子对象是稳定图谱对象，还是只是自然语言假设，需要先标准化。
3. 用户要的是下一轮狩猎方向，还是要生成管理层可消费的报告。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| ThreatHunterAgent | 默认唯一执行 AGENT，负责识别业务意图、执行图谱查询、提炼新线索并生成猎杀报告 | 是 |
| ThreatHunterConsumer | 人类使用者或外部消费角色，负责提交狩猎假设、消费结果并决定是否继续调查 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `ThreatHunterConsumer`，允许其提交 `biz.unknown-threat-hunting` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_fact`、`expand_relation` 或 `assess_confidence`。
2. 若 `identify_target` 阶段发现输入更像 IOC 分诊请求，则应转交 `IOC 快速核查与告警分诊`。
3. 若用户要求最终攻击组织排序、TTP 画像和归因报告，则应转交 `威胁溯源分析`。
4. 默认路由器始终将该业务意图交给单一执行 AGENT `ThreatHunterAgent`。
5. 当子图扩展结果、候选线索簇或证据路径开始明显挤占后续推理窗口时，`ThreatHunterAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部压缩任务下放给临时附属 AGENT。

### 5.3 与相邻业务意图的路由判定

1. 当主问题是“从某个组织、恶意软件或 IOC 出发还能挖出哪些高价值新线索”时，应路由到 `biz.unknown-threat-hunting`。
2. 当主问题是“某个 IOC 当前是否需要升级处置”时，应路由到 `biz.ioc-triage`。
3. 当主问题是“这个线索最终归属哪个组织、有哪些历史活动和 TTP”时，应路由到 `biz.threat-attribution`。
4. 当主问题是“如何据此触发标准化处置动作”时，应转交 `应急响应编排`。

### 5.4 路由伪代码

```text
if intent_id == biz.unknown-threat-hunting:
    if current_role == ThreatHunterConsumer:
        delegate_to(ThreatHunterAgent)
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

如果后续存在专门的图谱聚类或线索压缩工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层图库已完全开放。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_target | 无需外部工具或仅轻量解析工具 | 不得臆造狩猎假设已被事实验证 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段或关系类型 |
| query_fact | `ai4x_query.query` | 不得一开始就拉取全量多跳子图 |
| expand_relation | `ai4x_query.query` | 不得把“存在关联”直接当成“值得调查” |
| assess_confidence | 内部评分逻辑 | 不得忽略时间新鲜度、来源稀疏性和误报风险 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略证据路径、边界和待验证项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 获取种子对象与一跳直接事实
4. 第二轮 `query` 按狩猎假设扩展关系和候选线索
5. 必要时在当前 session 内做聚类、裁剪和上下文治理
6. 内部线索评分与优先级评估
7. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 当前公开注册的数据源为准，而不是按抽象威胁狩猎平台假设任意扩写。根据当前仓库已知信息，本场景首版成立的最小闭环仍然是 `opencti`；若要补充“与我方环境相关性”，则优先看 `opencti` 中是否已暴露 `sighting` / `observed-data`，其次再补 `vehicle_iobe` 这类内部边界语境数据。

#### 平台已注册数据源与未知威胁狩猎信号映射

对本场景而言，当前真正构成狩猎主链路的是 `opencti`。`vehicle_iobe` 只在需要解释“为什么这条线索更值得我们关注”时承担增强角色。

#### `opencti`（外部威胁情报源）

用途：提供组织、恶意软件、IOC、基础设施和关系图谱，是当前场景的核心事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `intrusion-set`（入侵组织） | `id`、`name`、`aliases`、`first_seen`、`last_seen` | 作为狩猎假设起点或候选关联对象 | 这是图谱猎杀常见入口 |
| `malware`（恶意软件） | `id`、`name`、`aliases`、`malware_types`、`first_seen`、`last_seen` | 作为从组织下钻到 IOC 与基础设施的中间层 | 用于形成更稳定的扩展骨架 |
| `indicator`（指标） | `id`、`name`、`pattern`、`pattern_type`、`valid_from`、`valid_until`、`confidence` | 作为可落地排查的 IOC 收敛层 | 用于把图谱线索落到可验证对象 |
| `infrastructure`（基础设施） | `id`、`name`、`infrastructure_types`、`first_seen`、`last_seen` | 识别共用 C2、投递或匿名化资源 | 这是“未知新线索”高频来源 |
| `relationship`（关系） | `id`、`relationship_type`、`source_ref`、`target_ref`、`start_time`、`stop_time` | 串联各类对象形成证据路径 | 没有关系边就无法做图谱狩猎 |
| `report`（报告） | `id`、`name`、`published`、`object_refs` | 识别多个对象的共同出处或时间窗口 | 用于判断线索是否有统一来源支撑 |

#### 与线索落地直接相关的 observable 类型

| Observable/表达方式 | 关键字段 | 在本场景中的作用 |
| --- | --- | --- |
| `domain-name`（域名） | `id`、`value`、`resolves_to_refs` | 识别共用域名或 C2 域名 |
| `ipv4-addr`（IPv4 地址） | `id`、`value`、`belongs_to_refs`、`resolves_to_refs` | 识别共用 IP、跳板节点或外联目标 |
| `file`（文件） | `id`、`hashes`、`name` | 把线索扩展到样本侧 |
| `url`（URL 地址） | `id`、`value` | 承接钓鱼或恶意下载入口 |
| `indicator.pattern`（指标模式） | `pattern`、`pattern_type` | 用于把 observable 统一抽象为检测线索 |

#### 环境相关性增强对象

如果当前 OpenCTI 对外 Schema 已包含以下对象，它们可以把“图谱线索”进一步提升为“值得我方关注的狩猎线索”：

| 对象类型 | 关键字段 | 在本场景中的作用 |
| --- | --- | --- |
| `sighting` | `sighting_of_ref`、`observed_data_refs`、`where_sighted_refs`、`first_seen`、`last_seen` | 判断某线索是否实际被看见过 |
| `observed-data` | `first_observed`、`last_observed`、`number_observed`、`object_refs` | 将图谱线索连接到事实观测 |

#### `vehicle_iobe`（内部暴露面与边界语境）

用途：不是狩猎主事实源，但在判断“该线索与我方边界是否相关”时有价值。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-exposure-surface`（暴露面） | `id`、`name`、`x_domain_tag` | 将外部线索映射到可能相关的暴露面 | 用于提升调查优先级解释 |
| `x-external-peer`、`network-traffic`、`relationship` | `name`、`protocols`、`src_ref`、`dst_ref` | 判断线索是否贴近内部连接边界 | 让猎杀结果更贴近内部调查价值 |

#### 本场景最小数据闭环

按当前对外 Schema，这个场景至少需要具备以下数据链路：

1. 分析师给出一个狩猎起点，例如 `APT29`、某个恶意软件家族、某个域名或 IP。
2. OpenCTI 中存在该对象及其一跳关系。
3. 可以沿 `relationship` 扩展到 `malware`、`indicator`、`infrastructure`、`report` 等对象。
4. 至少有一类 observable 可落到域名、IP、URL 或 HASH，形成下一步可验证线索。
5. `ThreatHunterAgent` 基于关系独特性、来源多样性、时间新鲜度和相关性输出候选线索排序。

#### 平台外补充数据源的边界说明

当前仓库没有把 SIEM、EDR、资产 CMDB、流量取证平台或沙箱平台声明为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入狩猎链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `query_fact` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与当前平台能力一致的分析逻辑：

1. 先通过 `schema/catalog` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `opencti` 提取种子对象和一跳事实，形成狩猎主事实层。
3. 再用 `relationship`、`report` 和 observable 逐层扩展，形成候选线索集合。
4. 对尚未注册到平台的日志、资产或事件系统，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面受当前平台能力边界约束，另一方面也符合仓库现有设计思路：优先跑通“图谱假设 -> 受控扩展 -> 线索排序 -> 建议验证”的最小闭环，而不是在首版就假定全量环境观测能力已经齐备。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `未知威胁狩猎` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.unknown-threat-hunting.graph-hypothesis`
- `skill_name`: `图谱假设驱动的未知线索狩猎`
- `bind_intent_id`: `biz.unknown-threat-hunting`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为 `intrusion-set`、`malware`、`indicator`、`domain`、`ip` 或 `infrastructure`。
2. 请求目标是发现新的待验证线索、共用基础设施或次级关联对象。
3. 用户要求生成下一轮猎杀方向，而不是最终归因报告。

在第一阶段，即便用户给出的只是自然语言狩猎假设，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别种子对象、狩猎假设和输出深度。
2. 若目标、边界或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对种子对象执行一跳事实查询。
7. 基于返回的关系、恶意软件、基础设施和 IOC 执行二跳扩展。
8. 对候选对象按“共用基础设施”“跨团伙复用”“新颖高相关线索”等模式做聚类。
9. 若中间结果已形成长对象列表、长证据路径或大关系簇，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
10. 对候选线索进行优先级评估并输出结构化猎杀报告，同时明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 狩猎假设摘要。
2. 候选线索列表。
3. 每条线索的证据路径。
4. 继续调查建议。
5. 待验证项。
6. 置信度说明。
7. 边界说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.unknown-threat-hunting.graph-hypothesis` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.unknown-threat-hunting.indicator-pivot` | 针对 IOC 作为种子对象时优化扩展路径 | 否 |
| 输出目的特化 SKILL | `skill.unknown-threat-hunting.hunter-brief` | 针对值班交接或晨会输出更短的猎杀简报 | 否 |
| 高负载辅助 SKILL | `skill.unknown-threat-hunting.cluster-condense` | 压缩大关系簇和候选线索列表 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.unknown-threat-hunting`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当输入对象、扩展模式、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.unknown-threat-hunting.graph-hypothesis`，跑通默认图谱狩猎链路。
2. 第二阶段：当 `intrusion-set`、`malware`、`indicator` 三类种子的扩展路径稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“猎杀工作台简报”和“标准调查建议报告”两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当大规模关系簇和多候选线索压缩成为常态时，再增加辅助 SKILL 处理高负载上下文治理。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260507-hunt-001",
  "intent_id": "biz.unknown-threat-hunting",
  "seed": {
    "type": "intrusion-set",
    "value": "APT29"
  },
  "summary": "基于 APT29 相关图谱扩展，发现 2 条值得继续验证的高价值线索，其中一条是与 DarkHotel 共享的可疑 C2 域名。",
  "direct_facts": [
    "APT29 关联 malware WellMess",
    "WellMess 关联到多个 indicator 和一个可疑域名簇",
    "其中一个域名同时出现在与 DarkHotel 相关的关系子图中"
  ],
  "inferred_assessments": [
    "共享 C2 域名可能意味着基础设施复用或关系交叉，值得继续验证",
    "当前证据足以支持把该域名列为下一轮重点狩猎线索，但不足以直接下组织归因结论"
  ],
  "ranked_leads": [
    {
      "lead_id": "lead-1",
      "lead_type": "domain",
      "lead_value": "shared-c2.example",
      "priority": "high",
      "novelty_score": 0.82,
      "confidence": 0.74,
      "recommended_next_step": "对该域名的历史解析、关联 IP 和环境命中做二次验证"
    },
    {
      "lead_id": "lead-2",
      "lead_type": "intrusion-set",
      "lead_value": "DarkHotel",
      "priority": "medium",
      "novelty_score": 0.61,
      "confidence": 0.56,
      "recommended_next_step": "检查是否存在额外报告或直接 IOC 证据支撑该交叉关联"
    }
  ],
  "evidence_paths": [
    {
      "path_id": "path-1",
      "nodes": ["APT29", "WellMess", "indicator--shared-c2", "shared-c2.example", "DarkHotel"],
      "path_summary": "APT29 -> WellMess -> Indicator -> shared-c2.example -> DarkHotel"
    }
  ],
  "recommended_actions": [
    "优先核查 shared-c2.example 是否在我方环境出现过",
    "对与该域名同簇的 IP/URL 做补充扩展",
    "如需最终归因，转交威胁溯源分析链路"
  ],
  "pending_confirmations": [
    "当前共享关系来自图谱关联，并不等同于确认同一组织操控",
    "如果缺少 sighting 或 observed-data，则无法证明该线索已在我方环境中出现"
  ],
  "boundary_notes": [
    "该结果用于指导下一轮猎杀，不等同于最终归因或事件结论",
    "当前结果不代表系统已执行任何阻断或响应动作"
  ]
}
```

### 8.2 验收标准

一次合格的 `未知威胁狩猎` 输出至少应满足：

1. 明确狩猎起点和狩猎假设，不得只输出模糊关联叙述。
2. 区分直接事实与推断建议，不得把图谱弱关联写成已证实结论。
3. 至少给出候选线索、证据路径、建议动作和待确认项四类核心结果。
4. 能显式解释为什么某条线索值得继续调查，而不是只按节点数量排序。
5. 明确当前平台能力边界，不能把未注册数据源写成已验证事实。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.unknown-threat-hunting`。
2. 决定具体场景，例如 `graph-hypothesis`、`shared-infrastructure-hunt`。
3. 在方向不清时优先发起高价值澄清，收敛种子对象、狩猎目标和输出深度。
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
4. 校验输出中是否分离事实与推断，并显式标记弱关系、过期情报和环境相关性缺口。

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当种子对象、狩猎假设或输出目标不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本扩图。
3. 处理 `biz.unknown-threat-hunting` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及候选线索排序时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 当输入已经进入 IOC 分诊、最终归因或响应编排问题域时，必须转交相邻业务意图，而不是继续停留在狩猎链路。
8. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.unknown-threat-hunting":
        route_elsewhere()

    if need_clarification(envelope):
        return ask_for_clarification(
            topics=["seed", "hunt_hypothesis", "report_depth"]
        )

    if should_route_to_ioc_triage(envelope):
        return route_to("IOC 快速核查与告警分诊")

    if should_route_to_attribution(envelope):
        return route_to("威胁溯源分析")

    skill = skill_orchestrator.load(
        "skill.unknown-threat-hunting.graph-hypothesis",
        envelope
    )

    tool_policy_guard.authorize("ThreatHunterAgent", envelope)

    target = run_identify_target(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    facts = run_query_fact(skill, envelope, schema)
    context = run_expand_relation(skill, envelope, facts)

    if should_compact_in_current_session(context):
        context = run_context_governance_skill(
            "skill.unknown-threat-hunting.cluster-condense",
            context
        )

    leads = run_assess_confidence(skill, envelope, facts, context)
    report = run_compose_report(skill, envelope, facts, context, leads)

    return report
```

## 10. 验收建议

### 10.1 业务意图验收

1. 能把以组织、恶意软件、IOC 或基础设施为起点的狩猎请求稳定识别为 `biz.unknown-threat-hunting`。
2. 缺少种子对象或狩猎目标时不进入高成本扩展流程。
3. 能输出结构化候选线索，而不是单段散文式总结。

### 10.2 操作意图验收

1. `discover_source` 前不得直接执行查询。
2. `inspect_schema` 后才能发起正式扩图。
3. `expand_relation` 必须受狩猎假设约束，不能无限扩展。
4. `assess_confidence` 必须综合多维度排序，而不是只看连接数量。
5. `compose_report` 必须产出候选线索、建议动作、待确认项和边界说明。

### 10.3 角色验收

1. `ThreatHunterConsumer` 不得直接调用查询工具。
2. 单一主 AGENT `ThreatHunterAgent` 能完成全链路执行。
3. 只有在高上下文负载任务中，系统才允许创建附属 AGENT。
4. 附属 AGENT 的输出必须回流到主 AGENT，由主 AGENT 负责最终候选线索结论。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/unknown-threat-hunting/manifest.json](../../sample/unknown-threat-hunting/manifest.json)。

### 11.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于恢复 `APT29 -> WellMess -> Northern Relay -> DarkHotel` 的共享基础设施候选线索链，并补 `Northern Relay Campaign` 报告上下文。
2. 若需要补“与我方环境相关性”的解释，可选导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)。

### 11.2 推荐验证请求

1. 直接使用 [sample/unknown-threat-hunting/manifest.json](../../sample/unknown-threat-hunting/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `seed = intrusion-set/APT29`，狩猎假设为“查找与 APT29 关联、但尚未进入现有处置队列的共用基础设施或次级团伙线索”。

### 11.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
以 intrusion-set APT29 为种子，帮我找与它关联但尚未进入现有处置队列的共用基础设施或次级团伙线索，最多给 5 条 ranked leads，并明确区分直接事实、证据路径和待验证候选线索。
```

### 11.4 预期验证点

1. 能从 `APT29` 稳定扩展到 `WellMess`、`Northern Relay`，并把共享基础设施识别为高优先级待验证线索。
2. 能把 `DarkHotel` 保留为通过 `Northern Relay -> DarkHotel Loader -> DarkHotel` 形成的次级候选对象，而不是直接输出为强归因结论。
3. 能显式拆分 `Direct Facts`、`Ranked Leads`、`Evidence Paths` 和 `Pending Confirmations`。
4. 能显式声明在缺少 `sighting` / `observed-data` 时，仍无法证明该线索已在我方环境中出现。

## 12. 场景映射与验证建议

本文档直接对应场景文档 [scenarios/威胁情报分析/基于“关联图谱”的未知威胁猎杀.md](../../scenarios/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5%E5%88%86%E6%9E%90/%E5%9F%BA%E4%BA%8E%E2%80%9C%E5%85%B3%E8%81%94%E5%9B%BE%E8%B0%B1%E2%80%9D%E7%9A%84%E6%9C%AA%E7%9F%A5%E5%A8%81%E8%83%81%E7%8C%8E%E6%9D%80.md) 中的 “APT29 -> WellMess -> 共享 C2 域名 -> DarkHotel” 示例链路。

在当前 sample 数据中，这条链路以“`APT29 -> WellMess -> Northern Relay -> DarkHotel Loader -> DarkHotel`”的共享基础设施形式落地，用于验证“发现高价值新线索”而非“给出最终组织归因”的输出边界。

## 13. 与当前模型文件的关系

本文档对应 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中：

1. L1 业务意图：`未知威胁狩猎`
2. 当前能力元素：`未知威胁狩猎`

当前模型文件已经表达了顶层能力位置，但还没有表达：

1. 操作意图的执行顺序。
2. 角色与工具权限约束。
3. Intent Envelope、输入槽位和输出契约。
4. 数据源、对象、字段与猎杀线索排序逻辑之间的映射关系。

这四部分由本文档补齐，后续再决定是否继续回写到 JSON 模型中。
