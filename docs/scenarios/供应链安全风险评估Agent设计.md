# 供应链安全风险评估 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `供应链安全风险评估` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能列出一个供应链风险清单”，而是“有限的上下文窗口应优先留给哪些高价值判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛评估对象、供应链层级和影响范围，避免在错误的供应商或组件边界上扩查。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制相同的组件、漏洞和架构上下文。
3. 当组件清单、命中对象、漏洞列表或合规要求逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.supply-chain-risk-assessment`
- `intent_name`: `供应链安全风险评估`
- `intent_level`: `L1`
- `parent_capability`: `供应链安全风险评估`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个第三方组件、开源库、供应商产品、供应商标识、采购对象或 SBOM/SCA 线索出发，结合依赖治理信息、已知风险信号、内部产品/ECU/功能映射、暴露面和现有控制要求，判断该外部依赖对我方系统的潜在影响范围、供应链暴露强度、治理优先级和待确认边界，输出一份可解释、可追溯、可用于治理决策的供应链风险评估报告。

这里的“供应链安全风险评估”默认是围绕“外部依赖是否对我方形成现实安全风险”的分析能力，而不是完整的 SBOM 解析平台、采购审批流或自动化整改编排。

### 2.3 典型触发者

- 安全架构师
- 开源治理专员
- 采购合规专员

### 2.4 典型触发表达

- 评估某个开源组件是否已经影响我们当前车型平台。
- 这个供应商 SDK 接入车端后，哪些 ECU 和功能域会受到供应链风险影响。
- 帮我判断某个第三方供应商产品的风险是否会扩散到车端暴露面。
- 看一下某个采购组件当前的已知风险、暴露面和治理优先级。
- 给我一份适合安全评审会使用的供应链风险摘要。

### 2.5 业务边界

本意图负责：

1. 从组件、供应商、采购对象或 SBOM/SCA 线索出发识别可用风险线索。
2. 将外部依赖的已知风险、供应商属性和治理状态映射到内部产品、ECU、功能域和暴露面。
3. 结合威胁语境、控制要求和依赖治理成熟度做风险排序与整改建议。
4. 输出影响范围、治理优先级、证据边界和待人工确认项。

本意图不直接负责：

1. 自动完成精确到每个软件包版本的 SBOM 级命中判定。
2. 自动执行采购阻断、补丁下发、隔离或应急编排动作。
3. 替代合规审计、漏洞影响评估或攻击路径预测等后续深度业务意图。

如果评估结果已经收敛成“某个已知漏洞到底影响哪些资产、风险多高、先修什么”的问题，应转交 `漏洞影响评估`；如果需要继续分析攻击路径或合规整改闭环，应转交 `攻击路径预测`、`合规性验证` 或其他后续业务意图。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_scope | `op.identify-scope` | 识别评估对象、供应链层级、治理范围和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认漏洞、组件、ECU、功能和控制对象边界 | 是 |
| collect_supply_chain_signals | `op.collect-supply-chain-signals` | 拉取组件、供应商、漏洞和命中线索 | 是 |
| map_internal_impact | `op.map-internal-impact` | 将外部线索映射到内部产品、ECU、功能域和暴露面 | 是 |
| assess_risk | `op.assess-risk` | 对风险做加权排序并识别整改优先级 | 是 |
| compose_report | `op.compose-report` | 生成结构化供应链风险报告 | 是 |

### 3.2 操作顺序

`identify_scope -> discover_source -> inspect_schema -> collect_supply_chain_signals -> map_internal_impact -> assess_risk -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定某个供应商、组件或字段已经在平台中存在。

### 3.3 每个操作意图的职责

#### identify_scope

输入是自然语言或结构化供应链风险评估请求；输出是标准化评估范围。

最少要完成：

1. 识别 `subject_type`，例如 `component`、`supplier`、`supplier_product`、`procurement_item`、`sbom_item`。
2. 解析 `subject_value`。
3. 识别 `scope`，例如 `vehicle_platform`、`product_line`、`organization_domain`。
4. 提取用户是否要求补充 `focus_dimension`、`report_depth`、`need_function_rollup`、`need_compliance_mapping`。
5. 若评估对象、范围或关注维度存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `vehicle_iobe` 是否可用。
2. 判断 `vehicle_func`、`ecu_func` 是否可用于功能上卷。
3. 判断 `opencti`、`tara`、`ses` 是否作为威胁语境、风险解释和控制要求增强源可用。
4. 当组件已知关联具体漏洞时，再确认 `cve2oss` 是否可作为补充增强源。
5. 记录本次允许访问的数据源列表和缺失源，并区分平台原生源与外部治理输入。

#### inspect_schema

最少要完成：

1. 确认组件、供应商、采购对象和 SBOM/SCA 输入的最小字段边界。
2. 确认 `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship` 等对象结构。
3. 确认 `x-vehicle-function`、`x-cybersecurity-requirement`、`x-threat-scenario` 等增强对象结构。
4. 当存在已知漏洞编号时，再确认 `cve2oss` 的请求字段与响应字段边界。
5. 明确哪些字段属于直接事实，哪些只能作为推导依据。

#### collect_supply_chain_signals

最少要完成：

1. 当输入为 `component`、`supplier`、`supplier_product`、`procurement_item` 或 `sbom_item` 时，先将其标准化为可映射的组件关键词、供应商标识、采购线索或依赖清单条目。
2. 优先汇总用户提供的组件清单、SBOM/SCA 结果、采购信息和供应商属性，形成供应链主事实层。
3. 当组件已知关联具体漏洞编号时，再通过 `cve2oss` 或 `opencti.vulnerability` 拉取补充风险线索。
4. 返回第一轮风险线索结果，不直接输出最终风险结论。

#### map_internal_impact

最少要完成：

1. 将命中的产品/版本线索映射到 `vehicle_iobe` 中的 ECU、外部对端、暴露面和网络关系。
2. 通过 `ecu_func`、`vehicle_func` 将结果上卷到功能域或产品域。
3. 识别哪些对象具备蜂窝、Wi-Fi、蓝牙、USB、诊断口等外部暴露面。
4. 若缺少直接组件版本事实，则必须把结果标记为“命中线索”或“待人工确认”，而不是输出确定性命中判断。

#### assess_risk

最少要完成：

1. 对每个命中对象计算综合风险分数，而不是只按单个漏洞严重度或命中数量排序。
2. 将供应商关键性、依赖普遍性、已知风险信号、内部暴露强度、功能影响面、控制缺失程度和数据置信度纳入评分。
3. 识别高优先级整改对象、次级观察对象和待确认对象。
4. 当缺少关键版本、供应商确认或 SBOM/SCA 事实时，必须显式降低结论置信度。

#### compose_report

最少要完成：

1. 输出摘要、命中对象、暴露面、功能上卷、优先级和整改建议。
2. 说明分析边界、评分依据、缺失数据和待人工确认项。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260506-supply-chain-001",
  "intent_id": "biz.supply-chain-risk-assessment",
  "scenario_id": "supply-chain.component-impact",
  "subject": {
    "type": "component",
    "value": "TSP-Connect SDK"
  },
  "scope": {
    "vehicle_platform": "EV-Platform-A",
    "product_line": "T-Box-Series"
  },
  "analyst_id": "oss-governance-001",
  "requested_at": "2026-05-06T09:00:00Z",
  "slots": {
    "focus_dimension": ["component", "supplier", "exposure", "control"],
    "report_depth": "standard",
    "need_function_rollup": true,
    "need_compliance_mapping": false
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "mark_version_uncertainty_explicitly": true,
    "min_confidence_threshold": 0.65
  },
  "role_policy": {
    "initiator_role": "SupplyChainRiskConsumer",
    "execution_role": "SupplyChainRiskAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "supply_chain_risk_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| subject | 是 | 评估对象类型和值 |
| scope | 是 | 平台、产品线或组织范围 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| focus_dimension | 否 | 关注漏洞、暴露面、功能影响、控制或合规 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_function_rollup | 否 | 是否将 ECU 层结果上卷到功能域 |
| need_compliance_mapping | 否 | 是否补充控制要求或合规映射 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模查询或长链路映射，而应先做定向澄清：

1. 用户要的是快速准入评审、标准治理报告还是深度供应链治理评审。
2. 用户更关注供应商可信度、内部影响范围，还是控制与合规缺口。
3. 当前评估对象与范围是否已经足够明确到可以进入默认查询链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| SupplyChainRiskAgent | 默认唯一执行 AGENT，负责识别业务意图、执行查询、构建影响映射、完成风险排序并生成报告 | 是 |
| SupplyChainRiskConsumer | 人类使用者或外部消费角色，负责提交评估对象和范围，消费结果并发起后续治理动作 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `SupplyChainRiskConsumer`，允许其提交 `biz.supply-chain-risk-assessment` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`collect_supply_chain_signals`、`map_internal_impact` 或 `assess_risk`。
2. 若 `identify_scope` 阶段发现评估对象、范围或输出目标存在明显分叉，默认先进入澄清分支，而不是立即进入批量映射分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `SupplyChainRiskAgent`。
4. 当命中组件列表、ECU 映射结果或控制要求开始挤占后续推理窗口时，`SupplyChainRiskAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 多个候选整改对象之间的排序复核，默认仍由 `SupplyChainRiskAgent` 在单次流程内完成，而不是自动升级为多 AGENT 协作。

### 5.4 与相邻业务意图的路由判定

1. 当主输入对象是 `supplier`、`component`、`supplier_product`、`procurement_item` 或 `sbom_item`，且问题是“这个外部依赖是否可信、风险在哪里、该怎么治理”时，应路由到 `biz.supply-chain-risk-assessment`。
2. 当主输入对象已经收敛为 `CVE`、漏洞公告或明确漏洞编号，且问题是“这个漏洞实际影响哪些资产、风险多高、先修什么”时，应路由到 `biz.vulnerability-impact-assessment`。
3. 当供应链评估过程中发现真正需要回答的是漏洞落地影响，而不是依赖治理边界时，主 AGENT 应停止继续扩写供应链结论，并转交 `漏洞影响评估`。
4. 当漏洞影响评估反向需要回答“这个组件/供应商是否应该继续准入、替换或收敛采购”时，再回路由到 `biz.supply-chain-risk-assessment`。

### 5.3 路由伪代码

```text
if intent_id == biz.supply-chain-risk-assessment:
    if current_role == SupplyChainRiskConsumer:
        delegate_to(SupplyChainRiskAgent)
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

如果后续存在专门的供应链组件查询工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层库结构。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_scope | 无需外部工具或仅轻量解析工具 | 不得臆造供应商、组件或版本事实 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| collect_supply_chain_signals | `ai4x_query.query`、外部 SBOM/SCA 输入、`POST /api/v1/cve2oss/query` | 不得把代理返回线索直接当成内部命中结论 |
| map_internal_impact | `ai4x_query.query` | 不得绕过平台直连底层库 |
| assess_risk | 内部评分逻辑 | 不得把不确定线索输出成高置信结论 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略边界、不确定性和待确认项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 或外部输入优先获取组件、供应商、采购对象或 SBOM/SCA 线索
4. 第二轮 `query` 映射 `vehicle_iobe` 中的 ECU、暴露面和网络关系
5. 第三轮 `query` 补充 `vehicle_func`、`ecu_func` 的功能上卷，以及 `tara`、`ses`、`opencti` 的风险和控制增强
6. 仅当已知组件明确关联漏洞编号时，再调用 `POST /api/v1/cve2oss/query` 做补充增强
7. 内部风险评分
8. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象供应链安全平台假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `供应链安全风险评估` 不能假定已有完整 SBOM、组件清单、供应商主数据或采购系统已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或后续待接入能力。

#### 平台已注册数据源与供应链风险信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，平台内真正构成可计算闭环的是 `vehicle_iobe + ecu_func + vehicle_func`，`opencti`、`tara`、`ses` 用于风险与控制增强；`cve2oss` 只在组件已知关联具体漏洞时承担补充作用。完整供应链治理闭环仍依赖外部 SBOM、SCA、采购和供应商数据。

#### `cve2oss`（CVE 查询代理数据源）

用途：当组件、供应商产品或采购对象已经关联到明确漏洞编号时，提供漏洞侧补充线索和内部跟踪标识；它不是供应链风险评估的默认主入口。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id`、`sub_id` | 按明确漏洞编号补充风险线索 | 用于验证某个外部依赖是否已存在公开漏洞信号 |
| 成功响应 | `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`LDY_NAME`、`HWPSIRTID` | 识别产品名、版本包标识、领域归属和内部跟踪标识 | 用于给组件或供应商风险补充漏洞侧证据 |

需要特别说明：当前公开 `cve2oss` Schema 不直接暴露完整组件名、供应商名、CPE、PURL、受影响版本区间和修复版本，因此它更适合作为“风险命中线索源”，而不是完整 SBOM 命中引擎。

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：提供内部产品、ECU、暴露面和通信关系，是把外部组件或漏洞线索映射到我方系统影响面的主事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-vehicle-ecu`（车辆 ECU） | `name`、`description`、`x_ecu_type`、`x_software_version`、`x_domain_tag` | 标识命中的 ECU、本体属性和软件版本线索 | 这是把风险落到具体控制器和系统边界的核心对象 |
| `x-exposure-surface`（暴露面） | `name`、`description`、`x_domain_tag` | 识别蜂窝、Wi-Fi、蓝牙、USB、诊断口等外部暴露面 | 风险优先级不能只看漏洞，还要看外部可触达性 |
| `x-external-peer`（外部对端） | `name`、`description`、`x_domain_tag` | 标识云端、手机、充电桩等外部依赖对象 | 用于判断供应链风险是否可沿外部连接进入系统 |
| `network-traffic`（网络流量） | `name`、`protocols`、`src_ref`、`dst_ref`、`x_domain_tag` | 恢复对象间通信关系 | 用于说明风险影响是否可能扩散 |
| `relationship`（关系） | `source_ref`、`target_ref`、`relationship_type`、`x_name`、`x_domain_tag` | 串联 ECU、暴露面、外部对端和连接关系 | 保持影响映射过程可追溯 |

#### `ecu_func` 与 `vehicle_func`（ECU 控制器与车辆功能数据源）

用途：将 ECU 层命中结果上卷到功能域和产品域，避免输出只停留在底层对象层面。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从命中的 ECU 反查关联功能列表 | 便于从“受影响 ECU”转成“受影响能力” |
| `vehicle_func` | `function_id`、`function_name`、`function_description`、`related_ecus`、`x_domain_tag` | 将命中结果上卷到车辆功能层 | 便于给治理和评审角色输出更可执行的摘要 |

#### `opencti`（外部威胁情报源）

用途：补充漏洞是否已被公开利用、是否关联恶意活动或威胁组织，不作为最小闭环必需源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `vulnerability`（漏洞） | `id`、`name`、`description` | 表示漏洞本体 | 用于补充漏洞侧公开情报 |
| `relationship`（关系）、`indicator`（指标）、`report`（报告） | `relationship_type`、`source_ref`、`target_ref`、时间相关字段 | 连接漏洞、活动、组织和报告 | 用于判断该风险是否已经具备更高威胁语境 |

#### `tara` 与 `ses`（威胁分析与风险评估、网络安全需求数据源）

用途：为供应链风险结果补风险语义和控制要求，不替代内部影响映射。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `tara` | `x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk` | 将命中对象映射到威胁场景和风险语义 | 用于解释为什么某个命中对象优先级更高 |
| `ses` | `x-cybersecurity-requirement` 相关字段 | 为整改建议补内部控制和要求映射 | 让结论更容易转成治理动作 |

#### `func_design_spec`（功能设计规格数据源）

用途：补充关键功能或子功能的设计说明，用于解释风险对象在架构中的语境，不是最小闭环必需源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| 设计说明对象（功能设计规格对象） | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 为高优先级对象补充设计语境 | 便于设计评审和整改沟通 |

#### 平台外补充数据源的边界说明

当前 `INTRODUCTION` 并没有把完整 SBOM、采购系统、供应商主数据、源码仓库依赖清单或 SCA 扫描结果列为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入供应链风险链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `collect_supply_chain_signals` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 先用外部 SBOM、SCA、采购或供应商清单形成供应链主事实层。
3. 再用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 将结果映射到内部产品、ECU、功能域和暴露面，形成影响范围层。
4. 若组件已知关联漏洞编号，再用 `cve2oss`、`opencti` 做漏洞和威胁语境增强。
5. 若需要补充控制要求或设计语境，再用 `tara`、`ses`、`func_design_spec` 做增强解释。
6. 对尚未注册到平台的 SBOM、采购或 SCA 数据，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面受当前平台能力边界约束，另一方面也符合仓库现有设计思路：优先跑通“风险线索 + 内部影响映射 + 治理建议”的最小闭环，而不是在首版就假定全量供应链元数据已经齐备。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `供应链安全风险评估` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.supply-chain.dependency-governance`
- `skill_name`: `供应链依赖治理评估`
- `bind_intent_id`: `biz.supply-chain-risk-assessment`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为组件名、供应商名、供应商产品、采购对象或 SBOM 条目。
2. 请求目标是识别受影响产品、ECU、功能域、暴露面或整改优先级。
3. 用户要求生成可回溯的供应链风险评估报告。

在第一阶段，即便用户只给出供应商名或组件名而未明确产品范围，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。若用户只给出漏洞编号，则默认应优先路由到 `漏洞影响评估`。

### 7.4 主 SKILL SOP

1. 识别评估对象类型、对象值和范围。
2. 若对象、范围或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对组件、供应商、采购对象或 SBOM 条目执行第一轮风险线索查询。
7. 基于返回的产品线索、版本线索和跟踪标识执行内部对象映射。
8. 用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 恢复影响对象、暴露面和功能域。
9. 若已知组件存在明确漏洞编号，再用 `cve2oss`、`opencti` 补充已知漏洞与威胁语境。
10. 若需要更强解释，再用 `tara`、`ses`、`func_design_spec` 补充控制和设计语境。
11. 若中间结果已形成长命中列表、长对象列表或大控制集，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
12. 对命中对象进行加权排序并输出结构化报告，同时明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 评估对象摘要。
2. 命中的产品/ECU/功能域列表。
3. 外部暴露面和影响范围说明。
4. 风险优先级和排序依据。
5. 待人工确认项。
6. 控制或整改建议。
7. 置信度说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.supply-chain.dependency-governance` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.supply-chain.supplier-brief` | 针对供应商级评估优化输入和汇总方式 | 否 |
| 输出目的特化 SKILL | `skill.supply-chain.governance-briefing` | 针对治理评审会输出简版摘要 | 否 |
| 高负载辅助 SKILL | `skill.supply-chain.hit-condense` | 压缩长命中列表和待确认对象集 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.supply-chain-risk-assessment`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当输入对象、数据入口、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.supply-chain.dependency-governance`，跑通默认风险评估链路。
2. 第二阶段：当组件级、供应商级和采购级输入的查询链路稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“深度治理报告”和“快速评审摘要”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长命中列表、海量待确认对象或大控制库匹配成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%85%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260506-supply-chain-001",
  "intent_id": "biz.supply-chain-risk-assessment",
  "subject": {
    "type": "component",
    "value": "TSP-Connect SDK"
  },
  "summary": "该第三方 SDK 当前被 T-Box 产品线使用，并与 2 个具备外部暴露面的 ECU 相关；供应商版本确认尚未完成，应列为高优先级治理对象，同时保留 1 个待确认功能域映射。",
  "direct_facts": [
    "用户提供的组件清单表明 TSP-Connect SDK 被 T-Box 产品线引用",
    "vehicle_iobe 中存在与该产品线相关的 T-Box ECU 和蜂窝暴露面",
    "ecu_func 将命中 ECU 上卷到远程连接功能域"
  ],
  "inferred_assessments": [
    "具备蜂窝外联能力的 T-Box ECU 为当前最高优先级治理对象",
    "某 IVI 相关功能域仅存在间接组件映射线索，需人工确认是否真正受影响"
  ],
  "ranked_impacts": [
    {
      "object_type": "x-vehicle-ecu",
      "object_name": "TBOX-ECU-01",
      "risk_score": 0.86,
      "priority": "high",
      "exposure": ["cellular"],
      "needs_manual_confirmation": false
    },
    {
      "object_type": "x-vehicle-function",
      "object_name": "Remote Connectivity",
      "risk_score": 0.68,
      "priority": "medium",
      "exposure": ["cellular", "cloud-peer"],
      "needs_manual_confirmation": true
    }
  ],
  "recommended_actions": [
    "优先确认供应商版本、补丁状态和组件准入范围",
    "补充 SBOM 或 SCA 事实以确认中风险对象是否真实命中",
    "检查相关 x-cybersecurity-requirement 是否已覆盖外部入口控制和第三方依赖治理"
  ],
  "confidence_statement": "高优先级对象同时具备组件使用线索和内部暴露面映射；仅有产品线索而缺少 SBOM、SCA 或供应商版本确认的对象被降级为待确认项。",
  "generated_at": "2026-05-06T09:05:00Z"
}
```

### 8.2 输出规则

1. `direct_facts` 与 `inferred_assessments` 必须分开。
2. 每个命中对象必须附带 `risk_score`、`priority` 和不确定性标记。
3. 每条核心结论都必须能映射到至少一组命中事实或影响链路。
4. 当没有足够证据时，允许输出“未形成稳定高置信命中”的空结论报告。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.supply-chain-risk-assessment`。
2. 决定具体场景，例如 `component-impact`、`supplier-brief`。
3. 在方向不清时优先发起高价值澄清，收敛评估对象、范围和输出深度。
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
4. 校验输出中是否分离事实与推断，并显式标记版本不确定性。

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当评估对象、范围或输出目标不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本批量查询。
3. 处理 `biz.supply-chain-risk-assessment` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及供应链风险判断时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 当输入已经收敛为明确漏洞编号且问题变成“影响哪些资产、先修什么”时，必须转交 `漏洞影响评估`，而不是继续输出供应链治理结论。
8. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.supply-chain-risk-assessment":
        route_elsewhere()

    if need_clarification(envelope):
        return ask_for_clarification(
            topics=["subject", "scope", "report_depth"]
        )

    if should_route_to_vulnerability_impact(envelope):
      return route_to("biz.vulnerability-impact-assessment")

    skill = skill_orchestrator.load("skill.supply-chain.dependency-governance", envelope)

    tool_policy_guard.authorize("SupplyChainRiskAgent", envelope)

    scope = run_identify_scope(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    signals = run_collect_supply_chain_signals(skill, envelope, schema)
    impacts = run_map_internal_impact(skill, envelope, signals)

    if should_compact_in_current_session(impacts):
        impacts = run_context_governance_skill(
            "skill.supply-chain.hit-condense",
            impacts
        )

    if should_spawn_support_agent(
        raw_material=impacts,
        future_reasoning_steps=["assess_risk", "compose_report"],
        current_session_cannot_hold_all=true,
        can_reduce_to_stable_artifact=true
    ):
        condensed_impacts = spawn_support_agent_for_condense(impacts)
        impacts = merge_back(condensed_impacts)

    scores = run_assess_risk(skill, envelope, signals, impacts)
    report = run_compose_report(skill, envelope, signals, impacts, scores)

    return report
```

## 10. 验收建议

### 10.1 业务意图验收

1. 能把组件、供应商、采购对象或 SBOM 请求稳定识别为 `biz.supply-chain-risk-assessment`。
2. 缺少 `subject` 或 `scope` 时不进入批量查询流程。
3. 能输出结构化报告，而不是单段散文。

### 10.2 操作意图验收

1. `discover_source` 前不得直接执行查询。
2. `inspect_schema` 后才能发起正式查询。
3. `assess_risk` 必须对多个命中对象做排序，而不是只输出一个对象。
4. `compose_report` 必须产出影响范围、优先级、待确认项和整改建议。
5. 当输入只剩明确漏洞编号时，必须转交 `漏洞影响评估`，而不是继续停留在供应链治理链路。

### 10.3 角色验收

1. `SupplyChainRiskConsumer` 不得直接调用查询工具。
2. 单一主 AGENT `SupplyChainRiskAgent` 能完成全链路执行。
3. 只有在高上下文负载任务中，系统才允许创建附属 AGENT。
4. 附属 AGENT 的输出必须回流到主 AGENT，由主 AGENT 负责最终结论。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/supply-chain-risk/manifest.json](../../sample/supply-chain-risk/manifest.json)。

### 11.1 需要导入的数据

1. `vehicle_iobe`、`ecu_func`、`vehicle_func`：分别导入对应 shared bundle，用于提供组件命中后的内部暴露面、ECU 和功能域映射。
2. `tara`、`ses`、`func_design_spec`：分别导入对应 shared bundle，用于补风险语义、控制要求和设计解释。
3. `opencti` 为可选增强源，可在组件已知关联漏洞时导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)。

### 11.2 外部输入夹具

1. `SBOM/SCA` 线索不作为平台原生导入源，而是使用 [sample/supply-chain-risk/manifest.json](../../sample/supply-chain-risk/manifest.json) 中的 `external_inputs.sbom_item`。
2. 若需要漏洞增强，继续按同一 manifest 中给出的 `known_cves` 补 `cve2oss` 查询夹具。

### 11.3 推荐验证请求

1. 直接使用 [sample/supply-chain-risk/manifest.json](../../sample/supply-chain-risk/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `component = TSP-Connect SDK`，范围为 `Telematics product line`。

### 11.4 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
请评估 TSP-Connect SDK 在 Telematics product line 中的供应链安全风险，结合组件使用位置、外部暴露面、已知 CVE 和控制要求，给我一份标准报告，并明确版本确认和 SBOM 完整性不足带来的不确定性。
```

### 11.5 预期验证点

1. 高优先级对象应优先落在 `TBOX-ECU-01` 与 `Remote Connectivity`。
2. 风险判断应由组件使用线索与外部暴露面共同驱动，而不是直接退化成漏洞影响评估。
3. 应显式保留供应商版本确认和 SBOM 完整性的边界说明。

## 12. 与当前模型文件的关系

本文档对应 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中：

1. L1 业务意图：`供应链安全风险评估`
2. 已有能力描述：`识别和评估第三方组件、开源库、供应商带来的安全风险，确保软件供应链的可信度。`

当前模型文件已经表达了顶层能力、业务角色视图和应用组件骨架，但还没有表达：

1. 操作意图的执行顺序。
2. 角色与工具权限约束。
3. Intent Envelope、输入槽位和输出契约。
4. 数据源、对象、字段与风险排序逻辑之间的映射关系。

这四部分由本文档补齐，后续再决定是否继续回写到 JSON 模型中。