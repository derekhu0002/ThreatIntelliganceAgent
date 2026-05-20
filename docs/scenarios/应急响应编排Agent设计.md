# 应急响应编排 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `应急响应编排` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能输出一个处置清单”，而是“有限的上下文窗口应优先留给哪些高价值响应判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛事件范围、受影响对象和响应目标，避免在错误的事件边界上聚合无关上下文。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多个执行体复制同一批事件、资产和处置上下文。
3. 当事件列表、受影响对象、证据片段或候选动作逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.incident-response-orchestration`
- `intent_name`: `应急响应编排`
- `intent_level`: `L1`
- `parent_capability`: `应急响应编排`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个安全事件、告警摘要、IOC、资产异常或漏洞触发信息出发，结合威胁情报、系统暴露面、资产关系和控制要求，快速形成可执行的应急响应方案，包括事件级别、影响范围、优先处置对象、响应步骤、协同角色和后续观察项，输出一份可解释、可追溯、可直接转入人工处置流程的响应编排报告。

这里的“应急响应编排”默认是围绕“如何组织分析、遏制、排查、恢复和跟踪”的决策辅助能力，而不是完整的 SOAR 自动执行平台、工单系统或主机侧自动化处置引擎。

### 2.3 典型触发者

- 安全事件分析师
- 安全运营中心分析师
- 安全值班人员
- 安全事件响应工程师

### 2.4 典型触发表达

- 这个高危告警该怎么处置，先做什么。
- 帮我把这起事件整理成应急响应步骤。
- 某个 IOC 命中后，需要给出隔离、排查和恢复建议。
- 现在值班人员接到可疑外联告警，给一份标准处置方案。
- 给我一份适合事件响应群快速执行的行动清单。

### 2.5 业务边界

本意图负责：

1. 从事件入口出发归并可用事实、影响对象和威胁语境。
2. 对事件优先级、响应阶段和处置顺序做结构化判断。
3. 输出遏制、排查、恢复、通报和跟踪建议。
4. 显式说明分析边界、缺失证据和需要人工确认的动作。

本意图不直接负责：

1. 自动执行隔离、阻断、封禁、补丁下发或工单流转。
2. 替代主机取证、内存分析、日志深度检索等专业调查工作。
3. 假定 SIEM、EDR、SOAR、工单系统已经作为 `ai4x_platform` 原生数据源存在。

如果后续需要深挖攻击组织、攻击路径或合规整改闭环，应转交 `威胁溯源分析`、`攻击路径预测`、`合规性验证` 或其他后续业务意图。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_scope | `op.identify-scope` | 识别事件入口、影响范围、响应目标和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认事件、资产、暴露面、控制和情报对象边界 | 是 |
| collect_incident_context | `op.collect-incident-context` | 拉取事件相关的 IOC、资产、漏洞和威胁线索 | 是 |
| correlate_impact | `op.correlate-impact` | 将事件线索映射到内部对象、暴露面和功能影响 | 是 |
| assess_priority | `op.assess-priority` | 判断事件优先级、响应阶段和动作排序 | 是 |
| compose_report | `op.compose-report` | 生成结构化响应编排报告 | 是 |

### 3.2 操作顺序

`identify_scope -> discover_source -> inspect_schema -> collect_incident_context -> correlate_impact -> assess_priority -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定事件对象、资产关系或处置动作已经成立。

### 3.3 每个操作意图的职责

#### identify_scope

输入是自然语言或结构化应急响应请求；输出是标准化响应范围。

最少要完成：

1. 识别 `incident_type`，例如 `alert`、`ioc_hit`、`malware_activity`、`vulnerability_exposure`、`suspicious_connection`。
2. 解析 `incident_seed`，例如 IOC、资产名、事件编号、漏洞编号或摘要文本。
3. 识别 `scope`，例如 `organization`、`product_line`、`vehicle_platform`、`asset_group`。
4. 提取用户是否要求补充 `response_mode`、`report_depth`、`need_function_rollup`、`need_control_mapping`。
5. 若事件入口、范围或输出目标存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 确认 `vehicle_iobe` 是否可用于资产、暴露面和连接映射。
3. 判断 `tara`、`ses` 是否可用于风险解释和控制建议。
4. 判断 `vehicle_func`、`ecu_func`、`func_design_spec` 是否可用于功能上卷和设计语境补充。
5. 若事件线索直接关联 CVE，则确认 `cve2oss` 是否可用。
6. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `opencti` 中 IOC、恶意软件、攻击技术、关系和报告对象结构。
2. 确认 `vehicle_iobe` 中 ECU、暴露面、外部对端、网络关系等对象结构。
3. 确认 `tara`、`ses` 中风险语义和控制要求对象结构。
4. 明确哪些字段属于直接事实，哪些只能作为推导依据。

#### collect_incident_context

最少要完成：

1. 从用户输入或上游告警中抽取可查询的 IOC、资产名、漏洞编号或异常行为关键词。
2. 基于 `opencti` 拉取 IOC、恶意软件、攻击技术、活动报告等关联事实。
3. 当事件与漏洞相关时，通过 `cve2oss` 补充漏洞影响线索。
4. 返回第一轮事件上下文结果，不直接输出最终响应结论。

#### correlate_impact

最少要完成：

1. 将事件线索映射到 `vehicle_iobe` 中的 ECU、暴露面、外部对端和网络关系。
2. 通过 `ecu_func`、`vehicle_func` 将受影响对象上卷到功能域或产品域。
3. 结合 `tara` 判断相关威胁场景、攻击路径或攻击可行性语义。
4. 若缺少直接事件遥测、主机日志或版本事实，则必须把结果标记为“待人工确认”，而不是输出确定性影响判断。

#### assess_priority

最少要完成：

1. 对事件计算综合优先级，而不是只按单条告警级别排序。
2. 将外部威胁活跃度、内部暴露强度、关键功能影响、控制缺失程度和数据置信度纳入排序。
3. 将响应动作拆分为 `遏制`、`排查`、`恢复`、`通报`、`跟踪` 五类阶段。
4. 识别必须立即执行的动作、可并行动作和待确认动作。
5. 当缺少关键现场证据时，必须显式降低结论置信度。

#### compose_report

最少要完成：

1. 输出摘要、优先级、影响范围、响应步骤、协同角色和观察项。
2. 说明分析边界、评分依据、缺失数据和待人工确认项。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260506-ir-001",
  "intent_id": "biz.incident-response-orchestration",
  "scenario_id": "incident-response.alert-triage",
  "incident": {
    "type": "ioc_hit",
    "value": "185.130.5.253",
    "source": "manual-alert-summary"
  },
  "scope": {
    "vehicle_platform": "EV-Platform-A",
    "asset_group": "TBOX"
  },
  "analyst_id": "ir-duty-001",
  "requested_at": "2026-05-06T10:00:00Z",
  "slots": {
    "response_mode": "standard",
    "report_depth": "standard",
    "need_function_rollup": true,
    "need_control_mapping": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "mark_missing_telemetry_explicitly": true,
    "min_confidence_threshold": 0.65
  },
  "role_policy": {
    "initiator_role": "IncidentResponseConsumer",
    "execution_role": "IncidentResponseAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "incident_response_plan_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| incident | 是 | 事件入口类型和值 |
| scope | 是 | 平台、资产组或业务范围 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| response_mode | 否 | `fast` / `standard` / `deep` |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_function_rollup | 否 | 是否将受影响 ECU 上卷到功能域 |
| need_control_mapping | 否 | 是否补充控制要求映射 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模查询或长链路扩展，而应先做定向澄清：

1. 用户要的是值班快处建议、标准响应方案还是深度处置剧本。
2. 用户更关注遏制优先级、影响范围，还是恢复与跟踪动作。
3. 当前事件入口与范围是否已经足够明确到可以进入默认查询链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| IncidentResponseAgent | 默认唯一执行 AGENT，负责识别业务意图、汇总事件上下文、判断优先级并生成响应编排结果 | 是 |
| IncidentResponseConsumer | 人类使用者或外部消费角色，负责提交事件入口和范围，消费结果并推动人工响应动作 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `IncidentResponseConsumer`，允许其提交 `biz.incident-response-orchestration` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`collect_incident_context`、`correlate_impact` 或 `assess_priority`。
2. 若 `identify_scope` 阶段发现事件入口、范围或输出目标存在明显分叉，默认先进入澄清分支，而不是立即进入批量扩展分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `IncidentResponseAgent`。
4. 当事件上下文、受影响对象或候选动作列表开始挤占后续推理窗口时，`IncidentResponseAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 若用户的问题已经转向攻击组织归因、攻击路径推演或合规差距核查，应显式路由到对应业务意图，而不是让响应 AGENT 硬扛跨领域深度分析。

### 5.3 路由伪代码

```text
if intent_id == biz.incident-response-orchestration:
    if current_role == IncidentResponseConsumer:
        delegate_to(IncidentResponseAgent)
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

如果后续存在专门的事件响应编排工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层 SOAR 编排能力已经存在。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_scope | 无需外部工具或仅轻量解析工具 | 不得臆造事件事实或资产归属 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| collect_incident_context | `ai4x_query.query`、`POST /api/v1/cve2oss/query` | 不得把弱线索直接升级为确定事件事实 |
| correlate_impact | `ai4x_query.query` | 不得绕过平台直连底层库 |
| assess_priority | 内部评分逻辑 | 不得把低置信度线索输出成确定性高危结论 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略边界、不确定性和待确认项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 优先提取 IOC、漏洞、攻击技术和报告等事件主线索
4. 第二轮 `query` 映射 `vehicle_iobe` 中的 ECU、暴露面、外部对端和网络关系
5. 第三轮 `query` 补充 `vehicle_func`、`ecu_func` 的功能上卷，以及 `tara`、`ses` 的风险和控制增强
6. 若事件与 CVE 直接相关，再调用 `POST /api/v1/cve2oss/query`
7. 内部优先级评估与响应分阶段排序
8. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象 SOAR 或 SIEM 平台假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `应急响应编排` 不能假定 SIEM、EDR、SOAR、工单系统、主机取证平台或日志检索系统已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或人工输入。

#### 平台已注册数据源与应急响应信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，真正构成最小闭环的是 `opencti + vehicle_iobe + tara + ses`，其余数据源主要承担功能上卷、设计语境和漏洞增强解释作用。

#### `opencti`（外部威胁情报源）

用途：提供 IOC、恶意软件、攻击技术、组织活动和报告线索，是应急响应编排的外部威胁语境主事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `indicator`（指标）、`ipv4-addr`（IPv4 地址）、`domain-name`（域名）、`url`（URL 地址）、`file`（文件） | `name`、`pattern`、`value`、`confidence`、`valid_until` | 作为事件入口 IOC 或可疑对象事实 | 用于建立响应分析的第一跳事实层 |
| `malware`（恶意软件）、`attack-pattern`（攻击模式） | `name`、`description`、`kill_chain_phases` | 补充威胁行为和攻击技术语境 | 便于判断应优先排查什么 |
| `report`（报告）、`relationship`（关系）、`sighting`（观测） | `name`、`relationship_type`、`source_ref`、`target_ref`、时间字段 | 构建上下文出处和事件关联路径 | 让处置建议可追溯而不是凭空生成 |

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：提供内部资产、暴露面和网络关系，是把外部事件线索映射到我方系统影响面的主事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-vehicle-ecu`（车辆 ECU） | `name`、`description`、`x_ecu_type`、`x_domain_tag` | 标识可能受影响的 ECU 和关键对象 | 需要明确谁是优先处置目标 |
| `x-exposure-surface`（暴露面） | `name`、`description`、`x_domain_tag` | 识别蜂窝、Wi-Fi、蓝牙、USB、诊断口等暴露面 | 遏制动作必须考虑外部可触达性 |
| `x-external-peer`（外部对端） | `name`、`description`、`x_domain_tag` | 标识云端、手机、充电桩等外部依赖对象 | 用于判断是否需要外联侧排查或联动 |
| `network-traffic`（网络流量）、`relationship`（关系） | `protocols`、`src_ref`、`dst_ref`、`relationship_type` | 恢复对象间通信和依赖关系 | 支撑影响范围和横向扩散判断 |

#### `tara`（威胁分析与风险评估数据源）

用途：补充威胁场景、攻击路径和攻击可行性语义，用于解释为什么某起事件需要某种响应级别和响应顺序。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-threat-scenario`（威胁场景） | `threat_id`、`stride`、`attack_vector`、`description` | 将事件映射到既有威胁场景 | 便于快速匹配标准响应思路 |
| `x-attack-path`（攻击路径）、`x-attack-feasibility`（攻击可行性）、`x-tara-risk`（TARA 风险） | 路径、可行性、风险评级字段 | 判断事件是否具备较高扩散或利用可能性 | 支撑优先级排序和阶段划分 |

#### `ses`（网络安全需求数据源）

用途：提供网络安全需求与控制语义，用于把响应建议映射成更可执行的控制动作。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-cybersecurity-requirement`（网络安全需求） | `cybersecurity_goal`、`cybersecurity_measure`、`text`、`x_domain_tag` | 将事件和受影响对象关联到已有控制要求 | 便于将建议转换成内部响应语言 |

#### `vehicle_func`、`ecu_func` 与 `func_design_spec`（车辆功能、ECU 控制器与功能设计规格数据源）

用途：将技术对象上卷到功能域，并补充设计语境，便于值班和协调角色快速理解业务影响。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从命中的 ECU 反查功能列表 | 让响应建议不只停留在底层设备名 |
| `vehicle_func` | `function_id`、`function_name`、`related_ecus`、`x_domain_tag` | 将命中结果上卷到功能域 | 便于评估业务影响和通报对象 |
| `func_design_spec` | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 补充设计语境 | 便于解释为什么某对象重要 |

#### `cve2oss`（CVE 查询代理数据源）

用途：当事件直接与 CVE 或已知组件漏洞相关时，补充产品命中和版本线索，不作为事件响应的默认主入口。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id` | 按明确漏洞编号拉取产品命中线索 | 用于补充漏洞驱动型事件的影响判断 |
| 成功响应 | `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`HWPSIRTID` | 识别产品和版本线索 | 用于把事件和版本排查动作连接起来 |

#### 平台外补充数据源的边界说明

当前 `INTRODUCTION` 并没有把 SIEM 告警流、EDR 遥测、SOAR 编排、工单平台、日志检索或主机取证系统列为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号或人工输入上下文，不能被写成平台原生能力。
2. 若后续需要把这些能力正式纳入响应编排链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `collect_incident_context` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `opencti` 提取 IOC、攻击技术和报告等事件主事实层。
3. 再用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 将结果映射到内部对象、暴露面和功能域，形成影响范围层。
4. 若需要补风险语义和控制要求，再用 `tara`、`ses`、`func_design_spec` 做增强解释。
5. 对尚未注册到平台的日志、SOAR 或工单能力，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面受当前平台能力边界约束，另一方面也符合仓库现有设计思路：优先跑通“事件线索 + 内部影响映射 + 响应建议”的最小闭环，而不是在首版就假定全链路自动化处置系统已经齐备。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `应急响应编排` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.incident-response.alert-triage`
- `skill_name`: `安全事件响应编排`
- `bind_intent_id`: `biz.incident-response-orchestration`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为事件摘要、告警编号、IOC、资产异常或漏洞触发信息。
2. 请求目标是给出遏制、排查、恢复或协同处置方案。
3. 用户要求生成可回溯的响应步骤或应急行动清单。

在第一阶段，即便用户只给出简短告警摘要而缺少完整事件编号，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别事件入口类型、事件值和范围。
2. 若事件、范围或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对事件入口执行第一轮上下文查询。
7. 基于返回的 IOC、攻击技术、漏洞和报告线索执行内部影响映射。
8. 用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 恢复受影响对象、暴露面和功能域。
9. 若需要更强解释，再用 `tara`、`ses`、`func_design_spec` 补充风险语义、控制要求和设计语境。
10. 若中间结果已形成长对象列表、长动作集或大量待确认项，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
11. 对事件优先级和动作顺序做加权排序，并输出结构化响应报告，同时明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 事件摘要。
2. 影响对象和功能域列表。
3. 响应优先级和分阶段动作。
4. 协同角色建议。
5. 待人工确认项。
6. 控制或恢复建议。
7. 置信度说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.incident-response.alert-triage` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.incident-response.vuln-driven` | 针对漏洞驱动型事件优化输入和影响映射 | 否 |
| 输出目的特化 SKILL | `skill.incident-response.exec-briefing` | 针对值班快处或管理简报压缩输出 | 否 |
| 高负载辅助 SKILL | `skill.incident-response.action-condense` | 压缩长动作列表和待确认对象集 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.incident-response-orchestration`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当事件入口、数据入口、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.incident-response.alert-triage`，跑通默认响应编排链路。
2. 第二阶段：当告警驱动、漏洞驱动和 IOC 驱动这几类入口的查询链路稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“值班快处行动清单”和“标准响应报告”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长动作集、海量待确认对象或跨角色协同清单成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260506-ir-001",
  "intent_id": "biz.incident-response-orchestration",
  "incident": {
    "type": "ioc_hit",
    "value": "185.130.5.253"
  },
  "summary": "该事件当前命中 1 个高风险外联 IOC，并关联到具备蜂窝暴露面的 T-Box ECU。建议立即执行遏制与重点排查，同时保留 2 个待人工确认对象。",
  "direct_facts": [
    "opencti 中存在与该 IOC 相关的 indicator 和报告对象",
    "vehicle_iobe 中存在与 T-Box 相关的 ECU、外部暴露面和网络关系",
    "tara 中存在与远程连接相关的威胁场景"
  ],
  "inferred_assessments": [
    "该事件优先级应提升到 high，因为外部可触达性和功能影响面同时存在",
    "部分受影响对象仅存在间接关系，需人工确认是否真实命中"
  ],
  "priority": {
    "level": "high",
    "score": 0.82,
    "reason": "外部暴露面、关键功能影响和威胁语境同时成立"
  },
  "affected_objects": [
    {
      "object_type": "x-vehicle-ecu",
      "object_name": "TBOX-ECU-01",
      "exposure": ["cellular"],
      "needs_manual_confirmation": false
    },
    {
      "object_type": "x-vehicle-function",
      "object_name": "Remote Connectivity",
      "exposure": ["cellular", "cloud-peer"],
      "needs_manual_confirmation": true
    }
  ],
  "response_actions": {
    "containment": [
      "优先限制相关外联面或加强入口监控",
      "对命中的 T-Box ECU 建立重点观察和隔离准备"
    ],
    "investigation": [
      "核查该 IOC 在相关资产上的命中范围和时间窗口",
      "补充人工确认受影响 ECU 的软件版本和实际连接状态"
    ],
    "recovery": [
      "若确认命中，按版本和功能域制定恢复及补丁计划"
    ],
    "communication": [
      "通知安全事件响应工程师和相关产品/运维接口人进入协同处置"
    ],
    "tracking": [
      "将待确认对象加入观察项并记录下一次复核时间"
    ]
  },
  "recommended_roles": [
    "安全事件响应工程师",
    "安全值班人员",
    "安全事件分析师"
  ],
  "pending_confirmations": [
    "缺少终端或 ECU 侧遥测，无法确认实际执行痕迹",
    "部分功能域仅存在间接关系，需要人工验证"
  ],
  "confidence": 0.72,
  "boundary_notes": [
    "当前平台未注册 SIEM/EDR/SOAR 数据源，因此未包含日志侧直接证据",
    "该结果用于响应编排建议，不等同于自动执行处置"
  ]
}
```

### 8.2 验收标准

一次合格的 `应急响应编排` 输出至少应满足：

1. 明确事件入口、范围和优先级，不得只输出笼统建议。
2. 区分直接事实与推断结论，不得把缺少现场证据的判断伪装成确定事实。
3. 至少给出 `遏制`、`排查`、`恢复`、`通报`、`跟踪` 五类动作中的核心步骤。
4. 明确受影响对象或待排查对象，不能只输出抽象风险描述。
5. 显式说明缺失数据、待人工确认项和当前平台能力边界。

## 9. 最终 AGENT 实现建议

### 9.1 推荐实现形态

建议将 `应急响应编排` 实现为单一主 AGENT `IncidentResponseAgent`，在首版只承接“事件上下文聚合 + 影响映射 + 响应建议”这条主链路，不直接承接自动化执行。

### 9.2 推荐 Prompt 主线

主 Prompt 应长期固定以下约束：

1. 先识别事件入口和范围，再查询数据。
2. 所有事实必须来自用户输入或平台查询结果。
3. 响应建议必须按阶段组织，并显式标注待人工确认项。
4. 当用户要求自动执行动作时，必须说明当前设计只负责编排建议，不负责直接执行。

### 9.3 首版落地优先级

建议按以下顺序实施：

1. 先打通 `IncidentResponseAgent + skill.incident-response.alert-triage` 的默认链路。
2. 再补事件摘要到内部对象和功能域的映射逻辑。
3. 再补 `tara`、`ses` 带来的风险与控制增强解释。
4. 最后再考虑是否增加针对高负载场景的上下文治理辅助 SKILL。

## 10. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/incident-response/manifest.json](../../sample/incident-response/manifest.json)。

### 10.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于提供高风险 IOC、攻击技术和活动报告。
2. `vehicle_iobe`：导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)，用于恢复 TBOX、Gateway 与外联面的关系。
3. `tara`：导入 [sample/shared/tara_bundle.json](../../sample/shared/tara_bundle.json)，用于补远程连接和网关的威胁场景。
4. `ses`：导入 [sample/shared/ses_bundle.json](../../sample/shared/ses_bundle.json)，用于补控制要求。
5. `ecu_func`、`vehicle_func`：分别导入 [sample/shared/ecu_func_bundle.json](../../sample/shared/ecu_func_bundle.json) 和 [sample/shared/vehicle_func_bundle.json](../../sample/shared/vehicle_func_bundle.json)，用于把事件上卷到 ECU 职责与功能域。

### 10.2 推荐验证请求

1. 直接使用 [sample/incident-response/manifest.json](../../sample/incident-response/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `incident.type = ioc_hit`、`incident.value = 185.130.5.253`，范围为 `T-Box remote connectivity`。

### 10.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
我们在 T-Box remote connectivity 范围命中 IOC 185.130.5.253，请按 containment、investigation、recovery、communication、tracking 五个部分给出标准应急响应编排建议，但不要自动执行任何动作。
```

### 10.4 预期验证点

1. 能把 IOC 风险映射到 `TBOX-ECU-01`、`GW-ECU-01` 和远程连接功能域。
2. 能输出按 `containment`、`investigation`、`recovery`、`communication`、`tracking` 分段的响应建议。
3. 能明确当前结果是编排建议，而不是自动执行结果。