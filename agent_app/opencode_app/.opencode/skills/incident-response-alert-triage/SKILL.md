---
name: incident-response-alert-triage
description: 当用户希望从事件摘要、告警编号、IOC、资产异常或漏洞触发信息出发，生成分阶段响应步骤和行动清单时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供事件摘要、告警编号、IOC、资产异常或漏洞触发信息，希望生成可执行的响应步骤。
- 希望判断某起事件的优先级、影响范围和优先处置对象。
- 希望生成适合值班、响应群或人工处置流程消费的应急行动清单。

本技能默认采用“事件事实优先，内部影响落地，风险与控制按需增强”的分析顺序：

- `opencti` 负责建立 IOC、恶意软件、攻击技术和报告线索。
- `vehicle_iobe` 负责内部资产、暴露面和网络关系事实。
- `tara` 与 `ses` 负责风险语义和控制建议。
- `ecu_func`、`vehicle_func`、`func_design_spec` 只在需要时补充功能上卷和设计语境。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `incident_type`: 至少识别为 `alert`、`ioc_hit`、`malware_activity`、`vulnerability_exposure`、`suspicious_connection` 之一。
- `incident_seed`: 至少识别一个可用于查询的入口值。
- `scope`: 至少识别 `organization`、`product_line`、`vehicle_platform`、`asset_group` 中一个范围锚点。
- `response_mode`: 可选，允许值为 `fast`、`standard`、`deep`，默认 `standard`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `need_function_rollup`: 可选，默认 `true`。
- `need_control_mapping`: 可选，默认 `true`。

提取与追问规则：

- 如果缺少 `incident_type` 或 `incident_seed`，先追问补齐，不直接查询。
- 如果范围缺失但用户只要求快处建议，可继续执行，但必须在 `Gaps` 中说明结论可能覆盖多个对象或平台。
- 如果用户目标在“值班快处”和“深度处置剧本”之间不清晰，先追问一次，不直接进入大规模查询。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。
- 必须严格区分 `Facts` 与 `Inferred Assessments`。
- 平台外的 SIEM、EDR、SOAR 或日志系统只能作为外部补充上下文，而不是平台原生事实源。
- 当缺少关键遥测、主机日志或版本事实时，允许输出“待人工确认”的结构化报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_query(command="catalog")
```

最少检查：

- `opencti` 是否存在。
- `vehicle_iobe` 是否存在。
- `tara` 是否存在。
- `ses` 是否存在。
- 是否存在可选增强源 `vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`。

如果 `opencti` 或 `vehicle_iobe` 不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
ai4x_query(command="schema", sourceId="vehicle_iobe")
ai4x_query(command="schema", sourceId="tara")
ai4x_query(command="schema", sourceId="ses")
```

若需要功能或漏洞增强，再调用：

```text
ai4x_query(command="schema", sourceId="vehicle_func")
ai4x_query(command="schema", sourceId="ecu_func")
ai4x_query(command="schema", sourceId="func_design_spec")
ai4x_query(command="schema", sourceId="cve2oss")
```

重点确认以下对象是否可消费：

- `opencti`: `indicator`、`ipv4-addr`、`domain-name`、`url`、`file`、`malware`、`attack-pattern`、`report`、`relationship`、`sighting`
- `vehicle_iobe`: `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship`
- `tara`: `x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk`
- `ses`: `x-cybersecurity-requirement`
- `vehicle_func`: `function_name`、`related_ecus`
- `ecu_func`: `ecu_name`、`related_functions`

如果 Schema 未覆盖计划使用的字段或对象，必须在 `Gaps` 中说明并缩减后续查询链。

对 `opencti` 额外适用：`schema(opencti)` 只用于确认对象类型、关系类型和 detail 指针；若要确认具体字段，再调用：

```text
ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship-type|relationship-schema", typeName="...")
```

## Step 3. 提取事件主线索

根据输入类型选择第一轮事件上下文查询：

- 当 `incident_type` 是 `ioc_hit` 或 `suspicious_connection`，优先用 `opencti` 查询 indicator、相关 report 和 relationship。
- 当 `incident_type` 是 `malware_activity`，优先查询 malware、attack-pattern 和 relationship。
- 当事件与 CVE 明确相关时，可额外用 `cve2oss` 补充版本和产品线索。

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) OPTIONAL MATCH (n)-[rel]-(peer) WHERE toLower(coalesce(n.name, n.value, n.pattern, n.description, '')) CONTAINS toLower($incident_seed) RETURN n, rel, peer LIMIT $limit"
)
```

要求：

- 只把直接命中的 IOC、技术、恶意软件、报告和关系作为事实层。
- 不在这一阶段输出最终响应优先级。

## Step 4. 建立内部影响映射

围绕第一轮命中的 IOC、资产线索或漏洞线索，在 `vehicle_iobe` 中恢复内部影响对象：

- 命中的 `x-vehicle-ecu`
- 关联的 `x-exposure-surface`
- 外部对端 `x-external-peer`
- 相关 `network-traffic` 和 `relationship`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (node) OPTIONAL MATCH (node)-[rel]-(neighbor) WHERE toLower(coalesce(node.name, node.description, node.x_domain_tag, '')) CONTAINS toLower($keyword) RETURN node, rel, neighbor LIMIT $limit"
)
```

映射要求：

- 记录受影响对象、本体属性、暴露面和连接关系。
- 只把图中真实存在的对象和关系作为直接事实。
- 缺少日志、遥测或版本事实时，必须把结果标为“待人工确认”。

## Step 5. 执行功能上卷与语义增强

若 `need_function_rollup == true`，继续查询：

```text
ai4x_query(
  command="query",
  sourceId="ecu_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.ecu_name, '')) CONTAINS toLower($ecu_name) RETURN n LIMIT $limit"
)

ai4x_query(
  command="query",
  sourceId="vehicle_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.function_name, n.function_description, '')) CONTAINS toLower($function_keyword) RETURN n LIMIT $limit"
)
```

然后按需补充：

- `tara` 的威胁场景、攻击路径和攻击可行性。
- `ses` 的控制要求与恢复语义。
- `func_design_spec` 的设计语境。

要求：

- 功能上卷用于解释业务影响，不当作新增事件命中事实。
- `tara` 和 `ses` 用于解释为什么某些动作优先，不等于动作已执行。

## Step 6. 形成优先级与分阶段动作

每个事件至少考虑以下因素：

- 外部威胁活跃度或 IOC 线索强度。
- 内部暴露面强度。
- 关键功能影响面。
- 控制缺失程度。
- 数据置信度和现场证据完整性。

排序规则：

- 不能只按单条告警级别排序。
- 同时具备外部暴露面、关键功能影响和威胁语境的事件可提升为高优先级。
- 依赖弱关联或缺少现场证据的对象和动作应降级为 `medium` 或 `low`。

动作必须拆分为：

- `containment`
- `investigation`
- `recovery`
- `communication`
- `tracking`

并明确：

- 必须立即执行的动作
- 可并行动作
- 待人工确认动作

## Step 7. 输出排除项、缺口和建议

### 7A. Exclusions

必须列出搜索过但证据不足的对象或动作，例如：

- 仅存在 IOC 线索，没有内部映射支撑。
- 仅存在功能上卷，没有 ECU、暴露面或连接事实。
- 依赖未接入平台的日志或主机数据。

### 7B. Recommendations

建议应聚焦于响应与协同，例如：

- 优先对高置信对象执行入口监控加强、隔离准备或重点观察。
- 补充日志、遥测、版本和连接状态以确认中低置信对象。
- 通知响应工程师、值班人员和相关接口人进入协同处置。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Incident Scope:
  - incident_type: [incident_type]
  - incident_seed: [incident_seed]
  - scope: [scope]
- Direct Facts:
  - [opencti 命中的 IOC、恶意软件、报告和关系]
  - [vehicle_iobe 命中的 ECU、暴露面、对端和关系]
  - [tara / ses / ecu_func / vehicle_func 的直接事实]

## Priority
- level: high|medium|low
- reason: [优先级依据]

## Affected Objects
- [object_id]
  - object_type: [x-vehicle-ecu | x-vehicle-function | other]
  - object_name: [name]
  - exposure: [cellular | wifi | bluetooth | usb | diagnostic | none]
  - needs_manual_confirmation: true|false

## Response Actions
- containment:
  - [动作]
- investigation:
  - [动作]
- recovery:
  - [动作]
- communication:
  - [动作]
- tracking:
  - [动作]

## Inferred Assessments
- [基于事实层形成的优先级、影响和动作判断]

## Exclusions
- [对象或动作名称]
  - reason: [证据不足原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Missing Facts or Assumptions:
  - [缺失日志、遥测、版本、Schema 或外部补充数据]

## Recommendations
- [后续排查、协同和恢复建议]

## Empty Result Contract
- status: no_stable_incident_hit | partial_incident_signal_only
- reason: [未命中的原因或仅形成部分线索的说明]
```

# Acceptance Notes (验收说明)

执行本技能时，至少满足以下验收条件：

1. 查询前已完成事件入口、范围和输出目标的必要澄清。
2. 所有真实查询遵循渐进式查询顺序；若命中 `opencti`，需要时追加 `detail`。
3. 输出明确分离 `Facts` 与 `Inferred Assessments`。
4. 核心响应动作必须能映射到至少一条可回溯事实链。
5. 当缺少现场证据或平台数据源时，输出待确认或空结果报告，而不是强行给出高置信处置结论。