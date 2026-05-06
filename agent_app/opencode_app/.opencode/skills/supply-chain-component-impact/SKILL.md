---
name: supply-chain-component-impact
description: 当用户希望从 CVE、组件、供应商、产品或采购对象出发，识别受影响产品、ECU、功能域、暴露面和整改优先级时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供明确的 `CVE`、组件名、供应商名、产品名或采购对象，希望识别受影响产品、ECU、功能域或外部暴露面。
- 希望判断某个第三方依赖是否已经影响我方车辆平台、产品线或业务域。
- 希望生成可回溯、可解释、适合治理沟通的供应链风险评估报告。

本技能默认采用“外部风险线索优先，内部影响映射落地，语义增强按需补充”的分析顺序：

- `cve2oss` 负责建立漏洞或产品命中线索。
- `vehicle_iobe` 负责内部产品、ECU、暴露面和网络关系事实。
- `ecu_func` 与 `vehicle_func` 负责功能上卷。
- `opencti`、`tara`、`ses`、`func_design_spec` 只在需要时补充威胁、控制和设计语境。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `subject_type`: 至少识别为 `cve`、`component`、`supplier`、`product`、`procurement_item` 之一。
- `subject_value`: 至少识别一个可用于查询的对象值。
- `scope`: 至少识别 `vehicle_platform`、`product_line`、`organization_domain` 中一个范围锚点。
- `focus_dimension`: 可选，允许关注 `vulnerability`、`exposure`、`function`、`control`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `need_function_rollup`: 可选，默认 `true`。
- `need_compliance_mapping`: 可选，默认 `false`。

提取与追问规则：

- 如果缺少 `subject_type` 或 `subject_value`，先追问补齐，不直接查询。
- 如果范围缺失但用户只要求快速排查，可继续执行，但必须在 `Gaps` 中说明结论可能跨多个平台或版本。
- 如果用户目标在“快速排查”和“深度治理评审”之间不清晰，先追问一次，不直接进入大规模查询。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 必须严格区分 `Facts` 与 `Inferred Assessments`。
- `cve2oss` 命中结果是风险线索，不自动等于内部精确命中。
- 当缺少关键版本事实时，允许输出“命中线索”或“待人工确认”的结构化报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_query(command="catalog")
```

最少检查：

- `cve2oss` 是否存在。
- `vehicle_iobe` 是否存在。
- `ecu_func` 是否存在。
- `vehicle_func` 是否存在。
- 是否存在可选增强源 `opencti`、`tara`、`ses`、`func_design_spec`。

如果 `cve2oss` 或 `vehicle_iobe` 不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="cve2oss")
ai4x_query(command="schema", sourceId="vehicle_iobe")
ai4x_query(command="schema", sourceId="ecu_func")
ai4x_query(command="schema", sourceId="vehicle_func")
```

若需要控制或威胁语义增强，再调用：

```text
ai4x_query(command="schema", sourceId="opencti")
ai4x_query(command="schema", sourceId="tara")
ai4x_query(command="schema", sourceId="ses")
ai4x_query(command="schema", sourceId="func_design_spec")
```

重点确认以下对象是否可消费：

- `cve2oss`: `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`LDY_NAME`、`HWPSIRTID`
- `vehicle_iobe`: `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship`
- `ecu_func`: `ecu_name`、`related_functions`
- `vehicle_func`: `function_id`、`function_name`、`related_ecus`
- `ses`: `x-cybersecurity-requirement`
- `tara`: `x-threat-scenario`、`x-attack-path`、`x-tara-risk`

如果 Schema 未覆盖计划使用的字段或对象，必须在 `Gaps` 中说明并缩减后续查询链。

## Step 3. 识别供应链风险线索

根据输入类型选择第一轮风险线索查询：

- 当 `subject_type == cve`，优先使用 `cve2oss` 建立命中线索。
- 当输入是 `component`、`supplier`、`product` 或 `procurement_item`，先标准化为关键词，再通过 `cve2oss` 和相关数据源做名称或产品线索检索。

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="cve2oss",
  cypher="MATCH (n) WHERE toLower(coalesce(n.CVEID, n.PROD_CN_NAME, n.EDITION_CODE, n.LDY_NAME, n.HWPSIRTID, '')) CONTAINS toLower($subject_value) RETURN n LIMIT $limit"
)
```

要求：

- 只把直接命中的漏洞、产品和版本线索作为事实层。
- 不在这一阶段输出最终风险优先级。

## Step 4. 建立内部影响映射

围绕第一轮命中的产品、版本和领域线索，在 `vehicle_iobe` 中恢复内部影响对象：

- 命中的 `x-vehicle-ecu`
- 关联的 `x-exposure-surface`
- 外部对端 `x-external-peer`
- 相关 `network-traffic` 和 `relationship`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (ecu {type: 'x-vehicle-ecu'}) OPTIONAL MATCH (ecu)-[rel]-(neighbor) WHERE toLower(coalesce(ecu.name, ecu.description, ecu.x_software_version, ecu.x_domain_tag, '')) CONTAINS toLower($keyword) RETURN ecu, rel, neighbor LIMIT $limit"
)
```

映射要求：

- 记录 ECU、本体属性、暴露面和外部连接关系。
- 只把图中真实存在的对象和关系作为直接事实。
- 缺少版本事实时，必须把结果标为“命中线索”或“待人工确认”。

## Step 5. 执行功能上卷

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

要求：

- 从命中的 ECU 反查关联功能列表。
- 把 ECU 层结论上卷到功能域或产品域。
- 不把功能上卷当成新增命中证据，只能当作影响解释层。

## Step 6. 补充威胁与控制语义

如 `opencti`、`tara`、`ses` 或 `func_design_spec` 可用，再补充：

- 漏洞公开利用或攻击语境。
- 威胁场景、攻击路径或风险语义。
- 控制要求与整改解释。
- 关键功能的设计语境。

该阶段仅用于增强解释，不替代 `cve2oss + vehicle_iobe` 的最小闭环事实层。

## Step 7. 形成风险排序

每个命中对象至少考虑以下因素：

- 外部漏洞热度或命中强度。
- 内部暴露面强度。
- 功能影响面。
- 控制缺失程度。
- 数据置信度和版本不确定性。

排序规则：

- 不能只按 CVE 严重度或命中数量排序。
- 同时具备外部暴露面和明确内部映射的对象可提升为高优先级。
- 依赖名称相似性或缺失版本事实的对象应降级为 `medium` 或 `low`。

## Step 8. 输出排除项、缺口和建议

### 8A. Exclusions

必须列出搜索过但证据不足的对象，例如：

- 仅存在产品名称相似性，没有内部映射支撑。
- 仅存在功能上卷，没有 ECU 或暴露面事实。
- 依赖未接入平台的外部 SBOM 或采购数据。

### 8B. Recommendations

建议应聚焦于排查和治理，例如：

- 优先排查具备蜂窝、Wi-Fi、蓝牙、USB、诊断口等外部暴露面的命中 ECU。
- 补充组件版本、SBOM 或采购记录以确认中低置信对象是否真实命中。
- 对高优先级对象关联控制要求和设计语境，支撑评审和整改。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Request Scope:
  - subject_type: [subject_type]
  - subject_value: [subject_value]
  - scope: [scope]
- Direct Facts:
  - [cve2oss 命中的产品、版本、领域线索]
  - [vehicle_iobe 命中的 ECU、暴露面、对端和关系]
  - [ecu_func / vehicle_func 的功能上卷事实]

## Ranked Impacts
- [impact_id]
  - object_type: [x-vehicle-ecu | x-vehicle-function | other]
  - object_name: [name]
  - confidence: high|medium|low
  - priority: high|medium|low
  - exposure: [cellular | wifi | bluetooth | usb | diagnostic | none]
  - needs_manual_confirmation: true|false

## Inferred Assessments
- [基于事实层形成的影响判断、优先级解释和治理含义]

## Exclusions
- [对象名称]
  - reason: [证据不足原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Missing Facts or Assumptions:
  - [缺失版本、范围、Schema 或外部补充数据]

## Recommendations
- [后续排查、补证和治理建议]

## Empty Result Contract
- status: no_stable_supply_chain_hit | partial_signal_only
- reason: [未命中的原因或仅形成部分线索的说明]
```

# Acceptance Notes (验收说明)

执行本技能时，至少满足以下验收条件：

1. 查询前已完成评估对象、范围和输出目标的必要澄清。
2. 所有真实查询遵循 `catalog -> schema -> query`。
3. 输出明确分离 `Facts` 与 `Inferred Assessments`。
4. 高优先级对象必须能映射到至少一条可回溯事实链。
5. 当缺少版本事实或平台数据源时，输出待确认或空结果报告，而不是强行给出高置信命中结论。