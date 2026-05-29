---
name: supply-chain-dependency-governance
description: 当用户希望基于组件、供应商、采购对象或 SBOM/SCA 条目评估外部依赖对我方产品、ECU、功能域和暴露面的影响，并输出治理优先级与整改建议时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 希望评估某个组件、供应商、供应商产品、采购对象或 `SBOM/SCA` 条目是否已经影响我方平台或产品线。
- 希望识别受影响 ECU、功能域、暴露面和优先治理对象。
- 希望生成适合治理评审、准入评审或标准风险评估报告消费的供应链风险结果。

本技能默认采用“先收敛评估对象，再建立供应链主事实层，再做内部影响映射和增强解释”的分析顺序：

- 外部 `SBOM/SCA`、采购和供应商输入负责建立供应链主事实层。
- `vehicle_iobe` 负责 ECU、暴露面、外部对端和网络关系事实。
- `ecu_func` 与 `vehicle_func` 负责功能上卷。
- 仅当组件已知关联明确漏洞编号时，`cve2oss` 与 `opencti` 负责漏洞和威胁语境增强。
- `tara`、`ses`、`func_design_spec` 负责风险语义、控制解释和设计语境增强。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `subject_type`: 至少识别为 `component`、`supplier`、`supplier_product`、`procurement_item`、`sbom_item` 之一。
- `subject_value`: 至少识别一个可用于查询、映射或治理判断的入口值。
- `scope`: 至少识别 `vehicle_platform`、`product_line`、`organization_domain`、`asset_group` 中一个范围锚点。
- `focus_dimension`: 可选，允许值包括 `component`、`supplier`、`exposure`、`control`、`compliance`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `need_function_rollup`: 可选，默认 `true`。
- `need_compliance_mapping`: 可选，默认 `false`。

提取与追问规则：

- 如果缺少 `subject_type` 或 `subject_value`，先追问补齐，不直接查询。
- 如果范围缺失但用户只要求快速准入评审，可继续执行，但必须在 `Boundary Notes` 中说明可能覆盖多个平台或产品线。
- 如果用户目标在快速准入评审、标准治理报告和深度供应链治理之间不清晰，先追问一次，不直接进入大规模映射。
- 如果用户只提供明确漏洞编号，且主问题变成“影响哪些资产、风险多高、先修什么”，则不执行本技能，应转交 `biz.vulnerability-impact-assessment`。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。对 `opencti` 的 query 默认采用平台 `auto` 策略，优先提交更容易被 GraphQL 支持的最小只读查询，由平台在不支持时自动回落 replica。
- 必须严格区分 `Direct Facts` 与 `Inferred Assessments`。
- 平台外的 `SBOM/SCA`、采购或供应商主数据只能作为外部补充上下文，而不是平台原生事实源。
- 当缺少组件版本、供应商确认或暴露面事实时，允许输出“待人工确认”的结构化报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_ai4x_query(command="catalog")
```

最少检查：

- `vehicle_iobe` 是否存在。
- `ecu_func`、`vehicle_func` 是否存在。
- `opencti`、`tara`、`ses`、`func_design_spec` 是否作为增强源存在。
- 当组件已知关联具体漏洞编号时，再确认 `cve2oss` 是否存在。

如果 `vehicle_iobe` 不存在：

- 在 `Boundary Notes` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_ai4x_query(command="schema", sourceId="vehicle_iobe")
ai4x_ai4x_query(command="schema", sourceId="ecu_func")
ai4x_ai4x_query(command="schema", sourceId="vehicle_func")
```

若需要增强解释，再补充：

```text
ai4x_ai4x_query(command="schema", sourceId="opencti")
ai4x_ai4x_query(command="schema", sourceId="tara")
ai4x_ai4x_query(command="schema", sourceId="ses")
ai4x_ai4x_query(command="schema", sourceId="func_design_spec")
```

若组件已知关联漏洞编号，再补充：

```text
ai4x_ai4x_query(command="schema", sourceId="cve2oss")
```

对 `opencti` 额外适用：`schema(opencti)` 只用于确认对象类型、关系类型和 detail 指针；若要确认具体字段，再调用：

```text
ai4x_ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship-type|relationship-schema", typeName="...")
```

重点确认以下对象或字段是否可消费：

- 外部治理输入: 组件名、供应商标识、采购对象、`SBOM/SCA` 条目中的最小字段边界
- `vehicle_iobe`: `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship`
- `ecu_func`: `ecu_name`、`related_functions`
- `vehicle_func`: `function_name`、`related_ecus`
- `opencti`: `vulnerability`、`relationship`、`indicator`、`report`
- `tara`: `x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk`
- `ses`: `x-cybersecurity-requirement`
- `func_design_spec`: `function_model_name`、`description`
- `cve2oss`: `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`LDY_NAME`、`HWPSIRTID`

如果 Schema 未覆盖计划使用的字段或对象，必须在 `Boundary Notes` 中说明并缩减后续查询链。

## Step 3. 提取供应链主事实层

根据输入类型选择第一轮信号提取：

- 当 `subject_type` 是 `component`、`supplier`、`supplier_product`、`procurement_item` 或 `sbom_item` 时，先将其标准化为组件关键词、供应商标识、采购线索或依赖清单条目。
- 优先汇总用户提供的组件清单、`SBOM/SCA` 结果、采购信息和供应商属性，形成供应链主事实层。
- 当组件已知关联具体漏洞编号时，再通过 `cve2oss` 或 `opencti.vulnerability` 拉取补充风险线索。

推荐查询模板：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (node) OPTIONAL MATCH (node)-[rel]-(neighbor) WHERE toLower(coalesce(node.name, node.description, node.x_domain_tag, '')) CONTAINS toLower($subject_value) RETURN node, rel, neighbor LIMIT $limit"
)
```

若存在明确漏洞编号，可补充：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="cve2oss",
  cypher="MATCH (n) WHERE toLower(coalesce(n.CVEID, n.PROD_CN_NAME, n.EDITION_CODE, n.LDY_NAME, n.HWPSIRTID, '')) CONTAINS toLower($cve_id) RETURN n LIMIT $limit"
)
```

要求：

- 优先把外部治理输入和内部对象映射形成供应链主事实层。
- 只把命中的对象、字段和供应链输入作为线索层事实。
- 不在这一阶段输出最终风险结论。

## Step 4. 建立内部影响映射

围绕第一轮命中的组件、供应商、采购对象或版本线索，在 `vehicle_iobe` 中恢复内部影响对象：

- 命中的 `x-vehicle-ecu`
- 关联的 `x-exposure-surface`
- 外部对端 `x-external-peer`
- 相关 `network-traffic` 和 `relationship`

映射要求：

- 记录受影响对象、本体属性、暴露面和连接关系。
- 只把图中真实存在的对象和关系作为直接事实。
- 缺少版本、供应商确认或 `SBOM/SCA` 事实时，必须把结果标为“命中线索”或“待人工确认”。

## Step 5. 执行功能上卷与增强解释

若 `need_function_rollup == true`，继续查询：

```text
ai4x_ai4x_query(
  command="query",
  sourceId="ecu_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.ecu_name, '')) CONTAINS toLower($ecu_name) RETURN n LIMIT $limit"
)
```

```text
ai4x_ai4x_query(
  command="query",
  sourceId="vehicle_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.function_name, n.function_description, '')) CONTAINS toLower($function_keyword) RETURN n LIMIT $limit"
)
```

然后按需补充：

- 若存在明确漏洞编号，使用 `opencti` 与 `cve2oss` 补充漏洞公开利用语境和内部跟踪线索。
- `tara` 的威胁场景和风险语义。
- `ses` 的控制要求。
- `func_design_spec` 的设计说明。

要求：

- 功能上卷用于解释业务影响，不当作新增漏洞命中事实。
- 增强源只用于解释为什么某些对象优先级更高，不等于命中对象已被现实利用。

## Step 6. 形成风险优先级与建议

每个命中对象至少考虑以下因素：

- 供应商关键性。
- 依赖普遍性。
- 已知风险信号。
- 内部暴露面强度。
- 功能影响面。
- 控制缺失程度。
- 数据置信度以及版本、供应商确认或 `SBOM/SCA` 完整度。

排序规则：

- 不能只按单个漏洞严重度或命中数量排序。
- 同时具备外部暴露面、关键功能影响和高质量供应链线索的对象可提升为高优先级。
- 缺少版本、供应商确认或 `SBOM/SCA` 事实的对象应降级为 `medium` 或 `low`。

## Step 7. 输出排除项、缺口和空结果

### 7A. Boundary Notes

必须列出以下边界信息：

- 已搜索但平台未接入的 `SBOM`、采购、`SCA` 或供应商主数据。
- 因字段缺失无法纳入高置信排序的对象。
- 依赖弱关联、跨源映射或待补组件版本事实才能确认的对象。

### 7B. Empty Result Contract

若输入对象已明确，但主要数据源均未命中最小事实层：

- 返回结构化空结果。
- 列出未命中的对象值、范围锚点和缺失数据源。
- 建议用户补充更具体的组件、供应商、`SBOM/SCA` 条目或范围信息。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Summary
- [一句话评估摘要]

## Direct Facts
- [查询直接命中的组件、供应商、ECU、暴露面和功能事实]

## Inferred Assessments
- [基于事实形成的风险判断和优先级解释]

## Ranked Impacts
- [对象 1]
  - priority: high|medium|low
  - risk_score: [0-1 或定性说明]
  - exposure: [cellular | wifi | bluetooth | usb | diagnostic | cloud-peer | none]
  - needs_manual_confirmation: true|false

## Recommended Actions
- [建议动作]

## Confidence Statement
- [置信度说明]

## Boundary Notes
- [缺失数据、平台边界、版本不确定性]

## Empty Result Contract
- triggered: true|false
- reason: [未命中原因]
```

额外要求：

- 不得把 `Direct Facts` 与 `Inferred Assessments` 混写。
- 每个高优先级对象都必须有可追溯的命中事实或映射链路。
- 当缺少精确版本、供应商确认或 `SBOM/SCA` 事实时，必须显式标记不确定性。
- 若平台未接入 `SBOM` 或采购系统，必须在 `Boundary Notes` 中显式说明。