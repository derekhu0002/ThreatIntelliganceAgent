# 漏洞影响评估 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `漏洞影响评估` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能给一个 CVE 风险等级”，而是“有限的上下文窗口应优先留给哪些高价值影响判断”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛漏洞对象、评估范围和输出目标，避免在错误的资产边界上扩查。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体复制同一批漏洞、资产和暴露面上下文。
3. 当产品命中列表、受影响 ECU、功能上卷结果或候选整改对象逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.vulnerability-impact-assessment`
- `intent_name`: `漏洞影响评估`
- `intent_level`: `L1`
- `parent_capability`: `漏洞影响评估`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个新披露的 CVE、漏洞公告、组件漏洞线索或漏洞相关产品信息出发，结合漏洞情报、内部产品/ECU/功能映射、暴露面和现有控制要求，判断该漏洞对我方系统的实际影响范围、风险等级、修复优先级和待确认边界，输出一份可解释、可追溯、可用于漏洞处置决策的影响评估报告。

这里的“漏洞影响评估”默认是围绕“某个漏洞是否已经对我方形成现实影响”展开的分析能力，而不是完整的漏洞扫描平台、补丁管理系统或自动化修复编排平台。

### 2.3 典型触发者

- 安全运营工程师
- 漏洞管理专员
- 运维工程师
- IT安全经理

### 2.4 典型触发表达

- 这个新披露的 CVE 会不会影响我们当前车型平台。
- 帮我判断某个漏洞命中了哪些 ECU 和功能域。
- 这个高危漏洞要不要立即升级为高优先级修复。
- 给我看一下某个漏洞对我们产品的实际影响范围。
- 生成一份适合漏洞例会使用的影响评估摘要。

### 2.5 业务边界

本意图负责：

1. 从漏洞对象出发识别可用事实和内部命中线索。
2. 将漏洞影响映射到内部产品、ECU、功能域和暴露面。
3. 结合威胁语境和控制要求做风险排序与修复优先级判断。
4. 输出影响范围、优先级、证据边界和待人工确认项。

本意图不直接负责：

1. 自动完成主机或代码层面的真实漏洞验证。
2. 自动执行补丁下发、回滚、隔离或应急编排动作。
3. 替代供应链风险评估、攻击路径预测或合规验证等后续深度业务意图。

如果评估结果需要继续分析攻击利用链、供应商责任边界或合规整改闭环，应转交 `供应链安全风险评估`、`攻击路径预测`、`合规性验证` 或其他后续业务意图。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_target | `op.identify-target` | 识别漏洞对象、评估范围和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认漏洞、资产、暴露面和控制对象边界 | 是 |
| query_fact | `op.query-fact` | 拉取漏洞本体、产品命中和一跳事实 | 是 |
| expand_relation | `op.expand-relation` | 将漏洞线索扩展到内部资产、功能域、暴露面和控制语境 | 是 |
| assess_confidence | `op.assess-confidence` | 对影响范围、风险等级和修复优先级做置信度评估 | 是 |
| compose_report | `op.compose-report` | 生成结构化漏洞影响评估报告 | 是 |

### 3.2 操作顺序

`identify_target -> discover_source -> inspect_schema -> query_fact -> expand_relation -> assess_confidence -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接假定某个漏洞、组件、资产或字段已经在平台中存在。

### 3.3 每个操作意图的职责

#### identify_target

输入是自然语言或结构化漏洞影响评估请求；输出是标准化评估范围。

最少要完成：

1. 识别 `target_type`，例如 `cve`、`vulnerability_notice`、`component_vuln`、`product_vuln`。
2. 解析 `target_value`。
3. 识别 `scope`，例如 `vehicle_platform`、`product_line`、`organization_domain`。
4. 提取用户是否要求补充 `focus_dimension`、`report_depth`、`need_function_rollup`、`need_control_mapping`。
5. 若漏洞对象、范围或输出目标存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `cve2oss` 是否可用。
2. 确认 `vehicle_iobe` 是否可用。
3. 判断 `vehicle_func`、`ecu_func` 是否可用于功能上卷。
4. 判断 `opencti`、`tara`、`ses`、`func_design_spec` 是否作为威胁语境、风险解释、控制要求和设计语境增强源可用。
5. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `cve2oss` 的请求字段与响应字段边界。
2. 确认 `vehicle_iobe` 中 `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship` 等对象结构。
3. 确认 `tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec` 的关键对象与字段边界。
4. 明确哪些字段属于直接事实，哪些只能作为推导依据。

#### query_fact

最少要完成：

1. 当输入为 `cve` 时，通过 `cve2oss` 拉取产品命中线索、版本标识、领域归属和内部跟踪标识。
2. 当输入为漏洞公告或组件漏洞线索时，先将其标准化为可查询的漏洞标识、产品关键词或版本线索。
3. 若需要威胁语境增强，补充 `opencti.vulnerability`、`report`、`relationship` 等对象的关联事实。
4. 返回第一轮漏洞事实结果，不直接输出最终风险结论。

#### expand_relation

最少要完成：

1. 将命中的产品/版本线索映射到 `vehicle_iobe` 中的 ECU、外部对端、暴露面和网络关系。
2. 通过 `ecu_func`、`vehicle_func` 将结果上卷到功能域或产品域。
3. 结合 `tara` 识别该漏洞涉及的威胁场景、攻击路径或攻击可行性语义。
4. 结合 `ses` 和 `func_design_spec` 补充控制要求和设计语境。
5. 若缺少直接版本事实，则必须把结果标记为“命中线索”或“待人工确认”，而不是输出确定性命中判断。

#### assess_confidence

最少要完成：

1. 对每个命中对象计算综合风险分数，而不是只按 CVE 严重度或命中数量排序。
2. 将漏洞严重度、外部威胁活跃度、内部暴露强度、功能影响面、控制缺失程度和数据置信度纳入评分。
3. 识别高优先级修复对象、次级观察对象和待确认对象。
4. 当缺少关键版本事实或现场验证证据时，必须显式降低结论置信度。

#### compose_report

最少要完成：

1. 输出摘要、命中对象、暴露面、功能上卷、风险等级和修复建议。
2. 说明分析边界、评分依据、缺失数据和待人工确认项。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260506-vuln-impact-001",
  "intent_id": "biz.vulnerability-impact-assessment",
  "scenario_id": "vuln-impact.cve-evaluation",
  "target": {
    "type": "cve",
    "value": "CVE-2026-12345"
  },
  "scope": {
    "vehicle_platform": "EV-Platform-A",
    "product_line": "T-Box-Series"
  },
  "analyst_id": "vuln-manager-001",
  "requested_at": "2026-05-06T11:00:00Z",
  "slots": {
    "focus_dimension": ["vulnerability", "impact", "exposure", "control"],
    "report_depth": "standard",
    "need_function_rollup": true,
    "need_control_mapping": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "mark_version_uncertainty_explicitly": true,
    "min_confidence_threshold": 0.65
  },
  "role_policy": {
    "initiator_role": "VulnerabilityImpactConsumer",
    "execution_role": "VulnerabilityImpactAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "vulnerability_impact_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| target | 是 | 漏洞对象类型和值 |
| scope | 是 | 平台、产品线或组织范围 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与不确定性策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| focus_dimension | 否 | 关注漏洞、影响范围、暴露面、控制或修复 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_function_rollup | 否 | 是否将 ECU 层结果上卷到功能域 |
| need_control_mapping | 否 | 是否补充控制要求或整改映射 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模查询或长链路映射，而应先做定向澄清：

1. 用户要的是快速排查、标准影响评估报告还是深度整改评审。
2. 用户更关注实际命中范围、修复优先级，还是控制缺口和暴露面。
3. 当前漏洞对象与范围是否已经足够明确到可以进入默认查询链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| VulnerabilityImpactAgent | 默认唯一执行 AGENT，负责识别业务意图、执行查询、构建影响映射、完成风险排序并生成报告 | 是 |
| VulnerabilityImpactConsumer | 人类使用者或外部消费角色，负责提交漏洞对象和范围，消费结果并推动后续修复动作 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `VulnerabilityImpactConsumer`，允许其提交 `biz.vulnerability-impact-assessment` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_fact`、`expand_relation` 或 `assess_confidence`。
2. 若 `identify_target` 阶段发现漏洞对象、范围或输出目标存在明显分叉，默认先进入澄清分支，而不是立即进入批量映射分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `VulnerabilityImpactAgent`。
4. 当命中对象、ECU 映射结果或整改建议开始挤占后续推理窗口时，`VulnerabilityImpactAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 若用户的问题已经转向供应链责任界定、攻击路径推演或合规差距核查，应显式路由到对应业务意图，而不是让漏洞影响 AGENT 硬扛跨领域深度分析。

### 5.4 与相邻业务意图的路由判定

1. 当主输入对象是 `CVE`、漏洞公告、漏洞编号或明确漏洞产品线索，且问题是“影响哪些资产、风险多高、先修什么”时，应路由到 `biz.vulnerability-impact-assessment`。
2. 当主输入对象是 `supplier`、`component`、`supplier_product`、`procurement_item` 或 `sbom_item`，且问题是“这个外部依赖是否可信、是否应该准入、替换或治理”时，应路由到 `biz.supply-chain-risk-assessment`。
3. 当漏洞影响评估过程中发现问题已经转向供应商责任边界、采购治理或 SBOM 依赖治理时，主 AGENT 应停止继续扩写漏洞影响结论，并转交 `供应链安全风险评估`。
4. 当供应链评估已经收敛成已知漏洞的落地影响问题时，则反向回路由到 `biz.vulnerability-impact-assessment`。

### 5.3 路由伪代码

```text
if intent_id == biz.vulnerability-impact-assessment:
    if current_role == VulnerabilityImpactConsumer:
        delegate_to(VulnerabilityImpactAgent)
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

如果后续存在专门的漏洞影响分析工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定底层漏洞平台能力已经存在。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_target | 无需外部工具或仅轻量解析工具 | 不得臆造漏洞编号、版本事实或资产归属 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| query_fact | `ai4x_query.query`、`POST /api/v1/cve2oss/query` | 不得把代理返回线索直接当成内部命中结论 |
| expand_relation | `ai4x_query.query` | 不得绕过平台直连底层库 |
| assess_confidence | 内部评分逻辑 | 不得把不确定线索输出成高置信命中结论 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略边界、不确定性和待确认项 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 或代理调用优先获取漏洞本体、产品命中线索和版本标识
4. 第二轮 `query` 映射 `vehicle_iobe` 中的 ECU、暴露面和网络关系
5. 第三轮 `query` 补充 `vehicle_func`、`ecu_func` 的功能上卷，以及 `tara`、`ses`、`func_design_spec` 的风险和控制增强
6. 内部风险评分与置信度评估
7. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象漏洞平台假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `漏洞影响评估` 不能假定漏洞扫描平台、资产 CMDB、运行期日志平台或主机验证系统已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或人工确认项。

#### 平台已注册数据源与漏洞影响信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，真正构成最小闭环的是 `cve2oss + vehicle_iobe + ecu_func + vehicle_func`，其余数据源主要承担威胁语境、风险解释、控制要求和设计语境增强作用。

#### `cve2oss`（CVE 查询代理数据源）

用途：提供以 CVE 为主入口的漏洞命中线索和内部跟踪标识，是漏洞影响评估的主入口。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id`、`sub_id` | 按明确的漏洞编号拉取命中线索 | 用于建立外部漏洞到内部产品线索的第一跳关联 |
| 成功响应 | `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`LDY_NAME`、`HWPSIRTID` | 识别产品名、版本包标识、领域归属和内部跟踪标识 | 当前公开 Schema 能稳定提供的漏洞影响主事实主要来自这里 |

需要特别说明：当前公开 `cve2oss` Schema 不直接暴露完整组件名、供应商名、CPE、PURL、受影响版本区间和修复版本，因此它更适合作为“漏洞命中线索源”，而不是精确的 SBOM 级验证引擎。

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：提供内部产品、ECU、暴露面和通信关系，是把漏洞线索映射到我方系统影响面的主事实源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-vehicle-ecu`（车辆 ECU） | `name`、`description`、`x_ecu_type`、`x_software_version`、`x_domain_tag` | 标识命中的 ECU、本体属性和软件版本线索 | 这是把漏洞影响落到具体控制器和系统边界的核心对象 |
| `x-exposure-surface`（暴露面） | `name`、`description`、`x_domain_tag` | 识别蜂窝、Wi-Fi、蓝牙、USB、诊断口等外部暴露面 | 风险优先级不能只看漏洞，还要看外部可触达性 |
| `x-external-peer`（外部对端） | `name`、`description`、`x_domain_tag` | 标识云端、手机、充电桩等外部依赖对象 | 用于判断漏洞影响是否可能沿外部连接扩大 |
| `network-traffic`（网络流量） | `name`、`protocols`、`src_ref`、`dst_ref`、`x_domain_tag` | 恢复对象间通信关系 | 用于说明影响范围是否可能扩散 |
| `relationship`（关系） | `source_ref`、`target_ref`、`relationship_type`、`x_name`、`x_domain_tag` | 串联 ECU、暴露面、外部对端和连接关系 | 保持影响映射过程可追溯 |

#### `ecu_func` 与 `vehicle_func`（ECU 控制器与车辆功能数据源）

用途：将 ECU 层命中结果上卷到功能域和产品域，避免输出只停留在底层对象层面。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从命中的 ECU 反查关联功能列表 | 便于从“受影响 ECU”转成“受影响能力” |
| `vehicle_func` | `function_id`、`function_name`、`function_description`、`related_ecus`、`x_domain_tag` | 将命中结果上卷到车辆功能层 | 便于给运营、运维和管理角色输出更可执行的摘要 |

#### `opencti`（外部威胁情报源）

用途：补充漏洞是否已被公开利用、是否关联恶意活动或威胁组织，不作为最小闭环必需源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `vulnerability`（漏洞） | `id`、`name`、`description` | 表示漏洞本体 | 用于补充漏洞侧公开情报 |
| `relationship`（关系）、`report`（报告）、`indicator`（指标） | `relationship_type`、`source_ref`、`target_ref`、时间相关字段 | 连接漏洞、活动和报告 | 用于判断该漏洞是否已经具备更高威胁语境 |

#### `tara` 与 `ses`（威胁分析与风险评估、网络安全需求数据源）

用途：为漏洞影响结果补风险语义和控制要求，不替代内部影响映射。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `tara` | `x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk` | 将命中对象映射到威胁场景和风险语义 | 用于解释为什么某个命中对象优先级更高 |
| `ses` | `x-cybersecurity-requirement` 相关字段 | 为整改建议补内部控制和要求映射 | 让结论更容易转成治理动作 |

#### `func_design_spec`（功能设计规格数据源）

用途：补充关键功能或子功能的设计说明，用于解释高优先级对象在架构中的语境，不是最小闭环必需源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| 设计说明对象（功能设计规格对象） | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 为高优先级对象补充设计语境 | 便于设计评审和修复沟通 |

#### 平台外补充数据源的边界说明

当前 `INTRODUCTION` 并没有把漏洞扫描、运行期日志、主机验证、补丁系统或资产 CMDB 列为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入漏洞影响链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `query_fact` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `cve2oss` 或等价漏洞入口提取命中线索，形成漏洞主事实层。
3. 再用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 将结果映射到内部产品、ECU、功能域和暴露面，形成影响范围层。
4. 若需要补充威胁语境、控制要求或设计语境，再用 `opencti`、`tara`、`ses`、`func_design_spec` 做增强解释。
5. 对尚未注册到平台的扫描、日志或验证数据，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑一方面受当前平台能力边界约束，另一方面也符合仓库现有设计思路：优先跑通“漏洞线索 + 内部影响映射 + 修复建议”的最小闭环，而不是在首版就假定全量验证和自动修复能力已经齐备。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `漏洞影响评估` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.vuln-impact.cve-evaluation`
- `skill_name`: `CVE 漏洞影响评估`
- `bind_intent_id`: `biz.vulnerability-impact-assessment`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为 `CVE`、漏洞公告、漏洞相关产品信息或组件漏洞线索。
2. 请求目标是识别受影响产品、ECU、功能域、暴露面或修复优先级。
3. 用户要求生成可回溯的漏洞影响评估报告。

在第一阶段，即便用户只给出漏洞编号而未明确产品范围，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别漏洞对象类型、对象值和范围。
2. 若对象、范围或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对漏洞对象执行第一轮事实查询。
7. 基于返回的产品线索、版本线索和跟踪标识执行内部对象映射。
8. 用 `vehicle_iobe`、`ecu_func`、`vehicle_func` 恢复影响对象、暴露面和功能域。
9. 若需要更强解释，再用 `opencti`、`tara`、`ses`、`func_design_spec` 补充威胁、控制和设计语境。
10. 若中间结果已形成长命中列表、长对象列表或大整改集，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
11. 对命中对象进行加权排序并输出结构化报告，同时明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 漏洞对象摘要。
2. 命中的产品/ECU/功能域列表。
3. 外部暴露面和影响范围说明。
4. 风险等级和排序依据。
5. 待人工确认项。
6. 修复或控制建议。
7. 置信度说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.vuln-impact.cve-evaluation` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.vuln-impact.notice-brief` | 针对公告或产品级漏洞线索优化输入和汇总方式 | 否 |
| 输出目的特化 SKILL | `skill.vuln-impact.fix-priority` | 针对修复排期输出简版优先级摘要 | 否 |
| 高负载辅助 SKILL | `skill.vuln-impact.hit-condense` | 压缩长命中列表和待确认对象集 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.vulnerability-impact-assessment`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当输入对象、数据入口、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.vuln-impact.cve-evaluation`，跑通默认漏洞影响评估链路。
2. 第二阶段：当 CVE 级、公告级和产品级输入的查询链路稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“标准影响报告”和“修复优先级简报”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长命中列表、海量待确认对象或大整改库匹配成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260506-vuln-impact-001",
  "intent_id": "biz.vulnerability-impact-assessment",
  "target": {
    "type": "cve",
    "value": "CVE-2026-12345"
  },
  "summary": "该漏洞当前命中了与 T-Box 产品线相关的版本线索，其中 2 个 ECU 具备外部暴露面，应列为高优先级排查对象；另有 1 个功能域存在间接命中线索，需补组件版本事实后确认。",
  "direct_facts": [
    "cve2oss 返回了与 T-Box 产品线相关的 PROD_CN_NAME 和 EDITION_CODE",
    "vehicle_iobe 中存在与该产品线相关的 T-Box ECU 和蜂窝暴露面",
    "ecu_func 将命中 ECU 上卷到远程连接功能域"
  ],
  "inferred_assessments": [
    "具备蜂窝外联能力的 T-Box ECU 为当前最高优先级排查对象",
    "某 IVI 相关功能域仅存在间接版本线索，需人工确认是否真正受影响"
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
    "优先排查具备外部暴露面的 T-Box ECU 和关联版本包",
    "补充组件版本或 SBOM 事实以确认中风险对象是否真实命中",
    "对高优先级对象关联的控制要求和修复窗口进行升级评审"
  ],
  "pending_confirmations": [
    "当前平台未提供精确到组件版本的完整 SBOM 事实",
    "部分功能域映射依赖间接产品线索，需人工复核"
  ],
  "confidence": 0.74,
  "boundary_notes": [
    "该结果用于影响评估和修复优先级排序，不等同于漏洞已在现场被利用",
    "未接入平台的扫描或日志系统应作为外部补充证据处理"
  ]
}
```

### 8.2 验收标准

一次合格的 `漏洞影响评估` 输出至少应满足：

1. 明确漏洞对象、范围和命中对象，不得只输出笼统风险描述。
2. 区分直接事实与推断结论，不得把缺少版本或验证证据的判断伪装成确定事实。
3. 至少给出影响范围、风险等级、优先级和建议动作四类核心结果。
4. 明确受影响对象或待排查对象，不能只停留在外部漏洞公告层。
5. 显式说明缺失数据、待人工确认项和当前平台能力边界。

## 9. 最终 AGENT 实现建议

### 9.1 推荐实现形态

建议将 `漏洞影响评估` 实现为单一主 AGENT `VulnerabilityImpactAgent`，在首版只承接“漏洞线索聚合 + 内部影响映射 + 风险排序”这条主链路，不直接承接自动修复或自动编排。

### 9.2 推荐 Prompt 主线

主 Prompt 应长期固定以下约束：

1. 先识别漏洞对象和范围，再查询数据。
2. 所有事实必须来自用户输入或平台查询结果。
3. 风险排序必须显式说明暴露面、功能影响和证据不确定性。
4. 当用户要求直接执行补丁或处置动作时，必须说明当前设计只负责编排建议，不负责自动执行。

### 9.3 首版落地优先级

建议按以下顺序实施：

1. 先打通 `VulnerabilityImpactAgent + skill.vuln-impact.cve-evaluation` 的默认链路。
2. 再补漏洞到内部对象和功能域的映射逻辑。
3. 再补 `opencti`、`tara`、`ses` 带来的威胁与控制增强解释。
4. 最后再考虑是否增加针对高负载场景的上下文治理辅助 SKILL。

## 10. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/vulnerability-impact/manifest.json](../../sample/vulnerability-impact/manifest.json)。

### 10.1 需要导入的数据

1. `vehicle_iobe`：导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)，用于提供 TBOX、Gateway 与外部暴露面。
2. `ecu_func`、`vehicle_func`：分别导入 [sample/shared/ecu_func_bundle.json](../../sample/shared/ecu_func_bundle.json) 和 [sample/shared/vehicle_func_bundle.json](../../sample/shared/vehicle_func_bundle.json)，用于恢复 ECU 到功能域的映射。
3. `opencti`、`tara`、`ses`、`func_design_spec` 为可选增强源，可按 [sample/vulnerability-impact/manifest.json](../../sample/vulnerability-impact/manifest.json) 的 `optional_imports` 继续导入。
4. `cve2oss` 不可导入，应按 manifest 中的 `non_importable_fixtures` 作为查询夹具使用。

### 10.2 推荐验证请求

1. 直接使用 [sample/vulnerability-impact/manifest.json](../../sample/vulnerability-impact/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `cve = CVE-2026-12345`，关注 `affected_objects`、`exposure` 和 `priority`。

### 10.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
我们收到 CVE-2026-12345 通报，请结合 T-Box / Remote Connectivity / OTA 相关资产评估影响范围，重点看受影响对象、暴露面和修复优先级，给我一份标准深度的漏洞影响评估结论，并明确哪些部分还需要人工确认。
```

### 10.4 预期验证点

1. 高优先级对象应至少包含 `TBOX-ECU-01`。
2. 结果应能上卷到 `Remote Connectivity` 和 `OTA Update`。
3. 在缺少 SBOM 或精确版本事实时，应显式保留“待人工确认”的边界说明。
