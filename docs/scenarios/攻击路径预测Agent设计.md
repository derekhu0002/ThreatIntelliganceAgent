# 攻击路径预测 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `攻击路径预测` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能算出一条路径”，而是“有限的上下文窗口应优先留给哪一段高价值推理”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛入口点、目标资产和分析范围，避免在错误的架构边界上扩图。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制拓扑上下文。
3. 当候选路径、候选跳板节点或控制建议逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始拓扑、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.attack-path-prediction`
- `intent_name`: `攻击路径预测`
- `intent_level`: `L1`
- `parent_capability`: `攻击路径预测`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个外部入口点或已知暴露面出发，结合系统架构、通信拓扑和威胁模型，推演攻击者可能如何进入系统、如何横向移动、最终可触达哪些关键资产，并输出一份可解释、可追溯、可用于防御布局的路径预测报告。

这里的“预测”默认是事前架构分析，而不是事后事件复盘。它回答的是“攻击者可能如何到达目标”，不是“攻击已经如何发生”。

### 2.3 典型触发者

- 安全架构师
- 渗透测试工程师
- 红队成员
- 防御策略规划人员

### 2.4 典型触发表达

- 如果攻击者从 T-Box 蜂窝接口进入，是否可能横向移动到网关 ECU。
- 从手机互联入口到信息娱乐系统有哪些高概率攻击路径。
- 给我看从 OTA 接口到动力域的最可能路径和关键阻断点。
- 哪些入口最容易触达制动 ECU。
- 帮我输出某个平台版本的攻击路径预测报告。

### 2.5 业务边界

本意图负责：

1. 从入口点和目标资产出发做架构可达性分析。
2. 结合 TARA 威胁模型匹配候选攻击路径。
3. 对候选路径做可行性和风险排序。
4. 输出跳板节点、关键阻断点和防御建议。

本意图不直接负责：

1. 证明某条路径已经在真实环境中被利用。
2. 自动执行阻断、隔离、策略下发或编排动作。
3. 替代事件调查或数字取证流程。

如果预测结果需要进一步落地为检测、响应或控制编排，应转交 `应急响应编排`、`合规性验证` 或其他后续业务意图。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_scope | `op.identify-scope` | 识别入口点、目标资产、分析范围和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认对象类型、字段和关系边界 | 是 |
| query_reachability | `op.query-reachability` | 查询入口、资产、拓扑和暴露面的一跳事实 | 是 |
| match_threat_model | `op.match-threat-model` | 匹配 TARA 攻击路径和威胁场景 | 是 |
| score_paths | `op.score-paths` | 对候选路径做加权排序并识别关键阻断点 | 是 |
| compose_report | `op.compose-report` | 生成结构化路径预测报告 | 是 |

### 3.2 操作顺序

`identify_scope -> discover_source -> inspect_schema -> query_reachability -> match_threat_model -> score_paths -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定对象、字段或边关系存在。

### 3.3 每个操作意图的职责

#### identify_scope

输入是自然语言或结构化路径预测请求；输出是标准化分析范围。

最少要完成：

1. 识别 `entry_surface`，例如 `cellular`、`wifi`、`bluetooth`、`usb`、`ota`、`mobile-app`、`diagnostic-port`。
2. 解析 `target_asset`，例如 `ECU`、`gateway`、`domain-controller`、`function-domain`。
3. 识别 `scope`，例如 `vehicle_platform`、`product_line`、`software_version`。
4. 提取用户是否要求补充 `path_budget`、`focus_dimension`、`report_depth`。
5. 若入口点、目标资产或分析范围存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `vehicle_iobe` 是否可用。
2. 确认 `tara` 是否可用。
3. 判断 `ai4x_platform` 当前已注册数据源中，是否还需要 `ses`、`opencti`、`vehicle_func`、`ecu_func`、`func_design_spec` 作为补充解释来源。
4. 若需要渗透验证结果、运行期日志或平台外安全扫描结果，必须标记为外部补充源，而不是假定其已作为原生 `source_id` 存在。
5. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship` 等对象结构。
2. 确认 `x-threat-scenario`、`x-damage-scenario`、`x-attack-path`、`x-attack-feasibility` 等对象结构。
3. 确认 `x-cybersecurity-requirement`、`attack-pattern`、`course-of-action` 的可用字段和边界。
4. 明确哪些字段属于直接事实，哪些只能作为推导依据。

#### query_reachability

最少要完成：

1. 查询入口点对应的暴露面、外部对端和起始节点。
2. 查询目标资产本体及其上下游通信关系。
3. 返回第一轮拓扑与暴露面事实结果，不混入路径结论。

#### match_threat_model

最少要完成：

1. 将入口点和候选节点映射到 `tara` 侧威胁场景和攻击路径模板。
2. 利用 `x-attack-path`、`x-threat-scenario` 和 `x-attack-feasibility` 生成候选路径集。
3. 在需要补充攻击技术语义时，引入 `opencti.attack-pattern` 和 `kill_chain_phases`。

#### score_paths

最少要完成：

1. 对每条候选路径计算加权分数，而不是只按 hop 数排序。
2. 将入口暴露强度、拓扑可达性、TARA 匹配度、攻击可行性和控制缺失程度纳入评分。
3. 识别路径中的关键跳板节点和关键阻断点。
4. 将高置信路径与待验证路径分层表达。

#### compose_report

最少要完成：

1. 输出摘要、候选路径、跳板节点、关键阻断点和建议。
2. 说明分析边界、评分依据、未证实部分和模型假设。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260503-attack-path-001",
  "intent_id": "biz.attack-path-prediction",
  "scenario_id": "attack-path.entry-to-target",
  "entry_surface": {
    "type": "cellular",
    "value": "tbox-4g"
  },
  "target_asset": {
    "type": "x-vehicle-ecu",
    "value": "GW-ECU-01"
  },
  "scope": {
    "vehicle_platform": "EV-Platform-A",
    "software_version": "2026.03"
  },
  "analyst_id": "arch-001",
  "requested_at": "2026-05-03T14:30:00Z",
  "slots": {
    "path_budget": 5,
    "focus_dimension": ["pivot-node", "choke-point", "mitigation"],
    "report_depth": "standard",
    "need_function_rollup": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "min_path_score_threshold": 0.6,
    "require_tara_match_for_high_confidence": true
  },
  "role_policy": {
    "initiator_role": "AttackPathOperator",
    "execution_role": "AttackPathAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "attack_path_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| entry_surface | 是 | 入口点类型和值 |
| target_asset | 是 | 目标资产类型和值 |
| scope | 是 | 平台、版本或产品范围 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与评分策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| path_budget | 否 | 返回的最大路径数 |
| focus_dimension | 否 | 关注跳板节点、阻断点、功能上卷或控制建议 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_function_rollup | 否 | 是否将 ECU 层结果上卷到功能域 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模拓扑搜索或深度扩图，而应先做定向澄清：

1. 用户要的是快速评审、标准报告还是深度路径推演。
2. 用户更关注入口风险、横向移动，还是关键阻断点。
3. 当前入口点、目标资产和范围是否已经足够明确到可以进入默认查询链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| AttackPathAgent | 默认唯一执行 AGENT，负责识别业务意图、执行查询、构建候选路径、做路径评分并生成报告 | 是 |
| AttackPathOperator | 人类使用者或外部消费角色，负责提交入口点、目标资产和范围，消费结果并发起后续评审或处置 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `AttackPathOperator`，允许其提交 `biz.attack-path-prediction` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_reachability`、`match_threat_model` 或 `score_paths`。
2. 若 `identify_scope` 阶段发现入口点、目标资产或分析范围存在明显分叉，默认先进入澄清分支，而不是立即进入扩图分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `AttackPathAgent`。
4. 当候选路径、控制建议或功能上卷结果开始挤占后续推理窗口时，`AttackPathAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 多路径冲突和评分复核，默认仍由 `AttackPathAgent` 在单次流程内完成，而不是自动升级为多 AGENT 协作。

### 5.3 路由伪代码

```text
if intent_id == biz.attack-path-prediction:
    if current_role == AttackPathOperator:
        delegate_to(AttackPathAgent)
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

如果后续存在专门的攻击路径分析工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或直接假定图数据库结构。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_scope | 无需外部工具或仅轻量解析工具 | 不得臆造入口点或目标资产 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| query_reachability | `ai4x_query.query` | 不得绕过平台直连底层库 |
| match_threat_model | `ai4x_query.query` | 不得把 TARA 模板直接当成已证实攻击事实 |
| score_paths | 内部评分逻辑 | 不得只按最短 hop 输出唯一结论 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略事实与推断边界说明 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 优先在 `ai4x_platform` 已注册数据源中查询入口点、资产、暴露面和拓扑事实
4. 第二轮 `query` 匹配 `tara` 攻击路径、威胁场景和风险对象
5. 第三轮 `query` 补充 `ses` 控制要求、`vehicle_func` / `ecu_func` 功能映射以及 `func_design_spec` 设计语境
6. 若需要通用攻击技术语义，再查询 `opencti`
7. 内部路径评分
8. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象攻击图平台假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `攻击路径预测` 不能假定渗透结果库、运行期日志、任意攻击图引擎或平台外扫描结果已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或后续待接入能力。

#### 平台已注册数据源与路径预测信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，真正构成路径预测主链路的是 `vehicle_iobe` 和 `tara`，其余数据源主要承担控制解释、功能上卷和语义补充作用。

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：提供内部架构和一跳可达性事实，是路径推演的第一事实来源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-vehicle-ecu`（车辆 ECU） | `id`、`name`、`x_ecu_type`、`x_software_version`、`x_domain_tag` | 标识起始 ECU、目标 ECU、候选跳板节点和域归属 | 路径预测的主节点粒度默认放在 ECU / 组件层 |
| `x-exposure-surface`（暴露面） | `id`、`name`、`description`、`x_domain_tag` | 把入口点映射到架构中的真实暴露面 | 没有入口暴露面就无法说明路径从哪里开始 |
| `x-external-peer`（外部对端） | `id`、`name`、`description`、`x_domain_tag` | 标识外部通信对端，如云端、手机 App、OTA 服务 | 用于界定哪些外部连接可能形成攻击入口 |
| `network-traffic`（网络流量） | `id`、`name`、`protocols`、`src_ref`、`dst_ref`、`x_domain_tag` | 恢复 ECU 之间或 ECU 与外部对端之间的通信路径 | 用于判断横向移动的技术可达性 |
| `relationship`（关系） | `source_ref`、`target_ref`、`relationship_type`、`x_name`、`x_domain_tag` | 串联暴露面、对端、流量和 ECU 节点 | 保持对图谱边语义的显式追踪 |

#### `tara`（威胁分析与风险评估数据源）

用途：提供预设攻击路径、威胁场景和可行性评分，是路径候选和风险校验的强先验来源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-threat-scenario`（威胁场景） | `threat_id`、`stride`、`attack_vector`、`cal`、`description` | 将入口点和目标资产映射到既有威胁场景 | 防止路径推演脱离已建模威胁语境 |
| `x-damage-scenario`（损害场景）、`x-impact-assessment`（影响评估） | `scenario`、影响评分相关字段 | 评估目标被触达后的潜在业务影响 | 用于解释为什么某条路径更值得优先防御 |
| `x-attack-path`（攻击路径） | `path`、`description`、`exposed_surface` 或等价字段 | 作为候选路径模板，与内部拓扑结果做匹配和约束校验 | 让 AGENT 不是只做最短路搜索，而是做受威胁模型约束的搜索 |
| `x-attack-feasibility`（攻击可行性）、`x-tara-risk`（TARA 风险） | 可行性、风险评级相关字段 | 对候选路径做额外加权 | 使路径排序更接近风险优先级而不是纯图距离 |

#### `ses`（网络安全需求数据源）

用途：提供内部安全要求和控制措施描述，用于从路径结果映射到防御动作。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-cybersecurity-requirement`（网络安全需求） | `keywords/labels`、`cybersecurity_goal`、`cybersecurity_measure`、`text`、`x_domain_tag` | 按入口点、攻击技术、目标域和控制类型检索相关要求 | 让输出不止有风险，还能落到企业已有控制语义 |

#### `vehicle_func`、`ecu_func`、`func_design_spec`（车辆功能、ECU 控制器与功能设计规格数据源）

用途：这三类数据源不是路径评分的直接主信号，但它们决定功能上卷、设计语境解释和评审输出是否成立。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `vehicle_func` | `function_id`、`function_name`、`related_ecus`、`x_domain_tag` | 将 ECU 层路径结果上卷到功能层 | 便于输出产品线或业务域视角的路径摘要 |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从 ECU 反查功能归属 | 避免报告只停留在底层技术对象 |
| `func_design_spec` | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 为关键跳板节点或阻断点补设计语境说明 | 让结果更适合设计评审和整改讨论 |

#### `opencti`（外部威胁情报源，可选增强）

用途：补充业界通用攻击技术和高层级防御语义，不作为 V1 的最小前置数据源。

根据 `INTRODUCTION`，`opencti` 不是固定字段表，而是一套 STIX 2.1 聚合目录；首版应先锁定少量代表类型，而不是假定 57 份 Schema 全量消费。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `attack-pattern`（攻击模式） | `name`、`description`、`kill_chain_phases` | 为候选路径贴上 MITRE ATT&CK 技术语义 | 让报告更容易被安全团队理解和复用 |
| `course-of-action`（缓解措施） | `name`、`description` | 为阻断点补充通用缓解动作 | 便于把内部要求和外部最佳实践并列展示 |
| `relationship`（关系） | `relationship_type`、`source_ref`、`target_ref` | 串联技术与缓解动作 | 用于构建可解释的建议链路 |

#### `cve2oss`（CVE 查询代理数据源）

用途：不是路径预测的主数据源，但当入口面、组件或设计版本明确关联已知 CVE 时，可作为漏洞代理补充源。

根据 `INTRODUCTION`，`cve2oss` 是独立代理接口，不应通过统一 Cypher 查询访问。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id` | 按明确的漏洞编号拉取代理结果 | 用于补充漏洞侧事实，不替代主路径推演链 |
| 成功响应 | `success`、`total`、`datalist` | 判断漏洞是否命中相关产品或版本 | 用于增强入口暴露或组件风险解释 |

#### 平台外补充数据源的边界说明

当前 `INTRODUCTION` 并没有把渗透结果库、运行期日志、资产扫描结果或独立攻击图引擎列为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入路径预测链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `query_reachability` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `vehicle_iobe` 确认入口暴露、拓扑可达性和目标资产，形成直接事实层。
3. 再用 `tara` 匹配预设攻击路径、威胁场景和风险对象，形成模型约束层。
4. 再用 `ses`、`vehicle_func`、`ecu_func`、`func_design_spec` 做控制解释、功能上卷和设计语境补强。
5. 若需要通用攻击技术语义，再用 `opencti` 做增强解释。
6. 对尚未注册到平台的日志、扫描或渗透结果，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面参考了三类常见业界实践，另一方面直接受 `ai4x_platform` 当前能力边界约束：

1. ISO/SAE 21434 与 TARA 实践强调先识别暴露面、资产和威胁场景，再讨论攻击可行性。
2. MITRE ATT&CK 实践强调用标准化攻击技术语义描述路径阶段，便于分析、对齐和复用。
3. Attack Graph / Reachability Analysis 实践强调路径排序不应只看最短 hop，还应综合 exploitability、reachability、impact 和 control coverage 等因素。
4. 统一查询虽暴露为 Cypher 接口，但对 MongoDB 和 OpenCTI 实际上是受限子集翻译，不能假定任意查询表达式都可用。
5. 当前平台已注册的数据源范围就是路径预测设计的最小事实边界，超出部分必须标记为待接入而不是默认存在。

因此，本场景不把 `x-attack-path` 当成唯一真相，也不把最短路径当成最终结论，而是输出一个带权重、带证据、带控制建议的候选路径集。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `攻击路径预测` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.attack-path.entry-to-target`
- `skill_name`: `入口到目标攻击路径预测`
- `bind_intent_id`: `biz.attack-path-prediction`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象包含明确入口点和目标资产。
2. 请求目标是识别横向移动路径、跳板节点或关键阻断点。
3. 用户要求生成可回溯的攻击路径预测报告。

在第一阶段，即便用户只给出入口点而未明确目标资产，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别入口点、目标资产和值域范围。
2. 若入口、目标或分析边界不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对入口点和目标资产执行一跳事实查询。
7. 基于返回的 ECU、暴露面、对端和网络流量执行二跳拓扑扩展。
8. 用 `tara` 中的威胁场景和攻击路径模板对候选路径做匹配和约束校验。
9. 若中间结果已形成长路径列表、长节点列表或大控制集，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
10. 对候选路径进行加权排序。
11. 输出结构化报告，并明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 入口点与目标资产摘要。
2. 候选攻击路径列表。
3. 每条路径的证据链。
4. 关键跳板节点和关键阻断点。
5. 相关攻击技术与控制建议。
6. 评分说明。
7. 防御和调查建议。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.attack-path.entry-to-target` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.attack-path.interface-sweep` | 针对某一类入口接口做批量入口风险扫描 | 否 |
| 输出目的特化 SKILL | `skill.attack-path.briefing` | 针对设计评审会输出简版阻断点摘要 | 否 |
| 高负载辅助 SKILL | `skill.attack-path.path-condense` | 压缩长路径列表和重复控制建议 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.attack-path-prediction`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当入口对象、搜索路径、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.attack-path.entry-to-target`，跑通默认路径预测链路。
2. 第二阶段：当按入口类型或平台类型的搜索链路稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“深度路径评审报告”和“快速设计评审摘要”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长路径集、海量节点或大控制库匹配成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260503-attack-path-001",
  "intent_id": "biz.attack-path-prediction",
  "entry_surface": {
    "type": "cellular",
    "value": "tbox-4g"
  },
  "target_asset": {
    "type": "x-vehicle-ecu",
    "value": "GW-ECU-01"
  },
  "summary": "从 T-Box 蜂窝入口到网关 ECU 存在两条主要候选路径，其中经 T-Box 到 CAN 网关的路径评分最高，且入口认证缺失与网关分段不足是主要风险点。",
  "direct_facts": [
    "T-Box ECU 暴露在蜂窝网络入口",
    "T-Box 与网关 ECU 存在可达网络流量关系",
    "TARA 中存在与该入口相匹配的 x-attack-path 模板"
  ],
  "inferred_assessments": [
    "经 T-Box 横向移动到网关 ECU 是当前最高优先级候选路径",
    "手机互联链路为次级路径，需要补充入口认证细节后进一步验证"
  ],
  "ranked_paths": [
    {
      "path_id": "path-1",
      "score": 0.84,
      "confidence": "high",
      "nodes": ["cellular-entry", "ECU-TBOX-001", "CAN-GW", "GW-ECU-01"],
      "path_summary": "蜂窝入口 -> T-Box -> CAN 网关 -> 网关 ECU",
      "pivot_nodes": ["ECU-TBOX-001", "CAN-GW"],
      "choke_points": ["T-Box entry authentication", "GW segmentation rule"]
    },
    {
      "path_id": "path-2",
      "score": 0.63,
      "confidence": "medium",
      "nodes": ["mobile-app", "ECU-TBOX-001", "IVI", "GW-ECU-01"],
      "path_summary": "手机互联 -> T-Box -> IVI -> 网关 ECU",
      "pivot_nodes": ["ECU-TBOX-001", "IVI"],
      "choke_points": ["mobile pairing control", "IVI service isolation"]
    }
  ],
  "supporting_attack_patterns": ["T1071.001", "T1570"],
  "recommended_controls": [
    "补强 T-Box 外部接口认证与会话保护",
    "在网关 ECU 前增加分段与消息过滤",
    "核查相关 x-cybersecurity-requirement 是否已在当前平台版本落地"
  ],
  "confidence_statement": "高置信路径同时满足内部拓扑可达性与 TARA 模板匹配；次级路径存在入口侧假设，不能视为已证实攻击链。",
  "generated_at": "2026-05-03T14:35:00Z"
}
```

### 8.2 输出规则

1. `direct_facts` 与 `inferred_assessments` 必须分开。
2. 每条候选路径必须附带 `score` 和 `confidence`。
3. 每条核心结论都必须能映射到至少一条路径证据。
4. 当没有足够证据时，允许输出“未形成稳定高置信路径”的空结论报告。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.attack-path-prediction`。
2. 决定具体场景，例如 `entry-to-target`、`interface-sweep`。
3. 在方向不清时优先发起高价值澄清，收敛入口点、目标资产和分析范围。
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
4. 校验输出中是否分离事实与推断。

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当入口点、目标资产或分析范围不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本扩图。
3. 处理 `biz.attack-path-prediction` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及路径预测时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.attack-path-prediction":
        route_elsewhere()

    if need_clarification(envelope):
        return ask_for_clarification(
            topics=["entry_surface", "target_asset", "scope"]
        )

    skill = skill_orchestrator.load("skill.attack-path.entry-to-target", envelope)

    tool_policy_guard.authorize("AttackPathAgent", envelope)

    scope = run_identify_scope(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    reachability = run_query_reachability(skill, envelope, schema)
    candidates = run_match_threat_model(skill, envelope, reachability)

    if should_compact_in_current_session(candidates):
        candidates = run_context_governance_skill(
            "skill.attack-path.path-condense",
            candidates
        )

    if should_spawn_support_agent(
        raw_material=candidates,
        future_reasoning_steps=["score_paths", "compose_report"],
        current_session_cannot_hold_all=true,
        can_reduce_to_stable_artifact=true
    ):
        condensed_candidates = spawn_support_agent_for_condense(candidates)
        candidates = merge_back(condensed_candidates)

    scores = run_score_paths(skill, envelope, reachability, candidates)
    report = run_compose_report(skill, envelope, reachability, candidates, scores)

    return report
```

## 10. 验收建议

### 10.1 业务意图验收

1. 能把入口点到目标资产的请求稳定识别为 `biz.attack-path-prediction`。
2. 缺少 `entry_surface` 或 `target_asset` 时不进入扩图流程。
3. 能输出结构化报告，而不是单段散文。

### 10.2 操作意图验收

1. `discover_source` 前不得直接执行查询。
2. `inspect_schema` 后才能发起正式查询。
3. `score_paths` 必须对多条候选路径做排序，而不是只返回 hop 最短的一条。
4. `compose_report` 必须产出路径证据、阻断点和评分说明。

### 10.3 角色验收

1. `AttackPathOperator` 不得直接调用查询工具。
2. 单一主 AGENT `AttackPathAgent` 能完成全链路执行。
3. 只有在高上下文负载任务中，系统才允许创建附属 AGENT。
4. 附属 AGENT 的输出必须回流到主 AGENT，由主 AGENT 负责最终结论。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/attack-path/manifest.json](../../sample/attack-path/manifest.json)。

### 11.1 需要导入的数据

1. `vehicle_iobe`：导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)，用于提供入口暴露面、内部可达性和目标 ECU。
2. `tara`：导入 [sample/shared/tara_bundle.json](../../sample/shared/tara_bundle.json)，用于提供 `x-attack-path` 模板与威胁场景约束。
3. `ses`、`ecu_func`、`vehicle_func`、`func_design_spec`：分别导入对应 shared bundle，用于补阻断点、ECU 职责、功能域上卷和设计语境。
4. 如需 ATT&CK 语义增强，可选导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)。

### 11.2 推荐验证请求

1. 直接使用 [sample/attack-path/manifest.json](../../sample/attack-path/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `entry_surface = tbox-4g`、`target_asset = GW-ECU-01`。

### 11.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
请以 tbox-4g 为攻击入口、GW-ECU-01 为目标资产，预测最可能的攻击路径并排序，说明主路径、次级路径、关键 pivot node 和 choke point，但不要把候选路径写成已发生的攻击事实。
```

### 11.4 预期验证点

1. 能产出主路径 `Cellular -> TBOX-ECU-01 -> GW-ECU-01` 和次级路径 `Mobile App -> TBOX-ECU-01 -> CDC-ECU-01 -> GW-ECU-01`。
2. 能识别关键 `pivot_nodes` 与 `choke_points`，尤其是入口认证和网关分段规则。
3. 能把候选路径表述为“带权重的预测结果”，而不是已发生的事件链。

## 12. 与当前模型文件的关系

本文档对应 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中：

1. L1 业务意图：`攻击路径预测`
2. 已有能力描述：`基于系统架构图和威胁模型，分析攻击者可能利用的攻击路径，预测潜在的攻击链条，提前部署防御措施。`

当前模型文件已经表达了顶层能力、通用操作原语层、攻击路径预测操作链和业务角色视图，但还没有表达：

1. 操作意图的执行顺序。
2. 角色与工具权限约束。
3. Intent Envelope、评分规则和输出契约。
3. 角色与工具权限约束。
4. Intent Envelope 与输出契约。
5. 数据源、对象、字段与路径评分逻辑之间的映射关系。

这五部分由本文档补齐，后续再决定是否继续回写到 JSON 模型中。