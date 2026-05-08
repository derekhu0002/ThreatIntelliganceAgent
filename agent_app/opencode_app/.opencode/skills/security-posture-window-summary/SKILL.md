---
name: security-posture-window-summary
description: 当用户希望在明确时间窗和范围内汇总整体安全态势、趋势变化、前三风险驱动项和重点观察对象时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 希望查看过去一段时间的整体安全态势、风险等级或趋势变化。
- 希望针对组织、产品线、业务域或其他明确范围生成值班快照、管理摘要或标准态势报告。
- 希望汇总威胁活跃度、漏洞暴露、资产暴露面和控制语义，并输出重点关注对象和建议动作。

本技能默认采用“先收敛范围，再建立事实层，再做解释增强”的分析顺序：

- `opencti` 负责外部威胁活跃度事实。
- `vehicle_iobe` 负责资产暴露面、范围映射和连接上下文事实。
- `tara` 与 `ses` 负责风险语义和控制解释。
- `vehicle_func`、`ecu_func`、`func_design_spec` 负责功能上卷和设计语境。
- `cve2oss` 仅在用户提供明确漏洞入口时补充漏洞代理结果。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `time_window`: 至少识别 `from` 和 `to`，或能稳定映射到最近 24 小时、本周等时间窗。
- `scope`: 至少识别 `organization`、`product_line`、`business_domain`、`asset_group` 中一个范围锚点。
- `focus_dimension`: 可选，允许值包括 `threat`、`vulnerability`、`exposure`、`incident`、`trend`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。
- `include_watchlist`: 可选，默认 `true`。
- `need_cve_enrichment`: 可选，默认 `false`，只有输入含明确 CVE 才置为 `true`。

提取与追问规则：

- 如果缺少 `time_window` 或 `scope`，先追问补齐，不直接查询。
- 如果用户目标在值班快照、管理摘要和标准分析报告之间不清晰，先追问一次，不直接进入大规模聚合。
- 如果 `focus_dimension` 未提供，可按默认链路继续，但必须在输出中说明当前聚合维度。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须先 `catalog`，再读取目标源 `schema`；若 `sourceId="opencti"`，只将 `schema` 作为最小目录，并在需要具体字段时追加 `detail`，之后再 `query`。
- 必须严格区分 `Direct Facts` 与 `Inferred Assessments`。
- 平台外的事件摘要、告警热度或资产台账只能作为外部补充上下文，而不是平台原生事实源。
- 当缺少关键字段、时间窗映射或范围锚点时，允许输出带边界说明的结构化报告。

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
- `vehicle_func`、`ecu_func`、`func_design_spec` 是否存在。
- 当 `need_cve_enrichment == true` 时，`cve2oss` 是否存在或是否可通过独立代理能力访问。

如果 `opencti` 或 `vehicle_iobe` 不存在：

- 在 `Boundary Notes` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="opencti")
ai4x_query(command="schema", sourceId="vehicle_iobe")
ai4x_query(command="schema", sourceId="tara")
ai4x_query(command="schema", sourceId="ses")
ai4x_query(command="schema", sourceId="vehicle_func")
ai4x_query(command="schema", sourceId="ecu_func")
ai4x_query(command="schema", sourceId="func_design_spec")
```

若用户明确提供 CVE，再补充：

```text
ai4x_query(command="schema", sourceId="cve2oss")
```

重点确认以下对象或字段是否可消费：

- `opencti`: `indicator`、`intrusion-set`、`threat-actor`、`malware`、`attack-pattern`、`vulnerability`、`report`
- `vehicle_iobe`: `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship`
- `tara`: `x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk`
- `ses`: `x-cybersecurity-requirement`
- `vehicle_func`: `function_name`、`related_ecus`
- `ecu_func`: `ecu_name`、`related_functions`
- `func_design_spec`: `function_model_name`、`description`

如果 Schema 未覆盖计划使用的字段或对象，必须在 `Boundary Notes` 中说明并缩减后续查询链。

对 `opencti` 额外适用：`schema(opencti)` 只用于确认对象类型、关系类型和 detail 指针；若要确认具体字段，再调用：

```text
ai4x_query(command="detail", sourceId="opencti", detailKind="object|relationship-type|relationship-schema", typeName="...")
```

## Step 3. 拉取态势主信号

围绕时间窗与范围，至少组织以下四类主信号：

- 威胁活跃度信号：来自 `opencti` 的 indicator、intrusion-set、threat-actor、report 或相关对象。
- 资产暴露信号：来自 `vehicle_iobe` 的 ECU、暴露面、对端和连接关系。
- 风险语义信号：来自 `tara` 的威胁场景、攻击路径、风险评级。
- 控制解释信号：来自 `ses` 的需求与控制语义。

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE toLower(coalesce(n.name, n.description, '')) CONTAINS toLower($scope_keyword) OPTIONAL MATCH (n)-[rel]-(peer) RETURN n, rel, peer LIMIT $limit"
)
```

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (node) WHERE toLower(coalesce(node.name, node.description, node.x_domain_tag, '')) CONTAINS toLower($scope_keyword) OPTIONAL MATCH (node)-[rel]-(neighbor) RETURN node, rel, neighbor LIMIT $limit"
)
```

要求：

- 只把直接命中的对象、字段和关系作为事实层。
- 不在这一阶段输出最终等级结论。
- 如果平台未接入事件热度源，只能把事件热度列入 `Boundary Notes`，不能伪装成已查询结果。

## Step 4. 执行功能上卷与漏洞补充

若需要管理层解释或功能上卷，继续查询：

```text
ai4x_query(
  command="query",
  sourceId="ecu_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.ecu_name, '')) CONTAINS toLower($ecu_name) RETURN n LIMIT $limit"
)
```

```text
ai4x_query(
  command="query",
  sourceId="vehicle_func",
  cypher="MATCH (n) WHERE toLower(coalesce(n.function_name, n.function_description, '')) CONTAINS toLower($function_keyword) RETURN n LIMIT $limit"
)
```

按需补充：

- `func_design_spec` 用于设计语境说明。
- `tara` 用于高风险路径和攻击可行性解释。
- 当 `need_cve_enrichment == true` 时，补充 `sourceId="cve2oss"` 的漏洞代理结果。

要求：

- 功能上卷用于解释业务影响，不当作新增外部威胁事实。
- `tara`、`ses` 和 `func_design_spec` 用于解释为何某些对象需要优先关注，不等于动作已执行。

## Step 5. 归一化并评估态势

归一化时至少完成：

- 去重重复对象和重复命中。
- 统一时间窗和聚合口径。
- 将长列表压缩为前三风险驱动项、重点观察对象和边界说明。
- 标记缺失数据、低置信度结果和待人工确认项。

总体态势评估至少考虑以下因素：

- 威胁活跃度。
- 漏洞暴露度。
- 资产暴露敏感度。
- 风险语义与控制覆盖解释。
- 数据置信度和字段完整性。

排序规则：

- 主信号优先于增强信号，不能让弱趋势或设计语境直接主导总体等级。
- 当总体等级发生变化时，必须输出显式驱动原因。
- 低置信度结果必须降级为 `Watchlist` 或 `Boundary Notes`，不能直接升级总体等级。

## Step 6. 形成报告

最终结果必须至少包含：

- `Summary`
- `Overall Posture`
- `Direct Facts`
- `Inferred Assessments`
- `Top Risk Drivers`
- `Watchlist`
- `Recommendations`
- `Boundary Notes`

## Step 7. 输出排除项、缺口和空结果

### 7A. Boundary Notes

必须列出以下边界信息：

- 已搜索但平台未接入的事件热度或告警汇总信号。
- 因字段缺失无法纳入评分的对象。
- 依赖弱关联、跨源映射或待补充遥测才能确认的对象。

### 7B. Empty Result Contract

若范围和时间窗已明确，但主要数据源均未命中最小事实层：

- 返回结构化空结果。
- 列出未命中的范围锚点、查询维度和缺失数据源。
- 建议用户补充更具体的范围、时间窗或已知风险入口。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Summary
- [一句话态势摘要]

## Overall Posture
- level: green|yellow|orange|red
- trend: up|flat|down
- confidence: [0-1 或 high|medium|low]
- scope: [scope]
- time_window: [time_window]

## Direct Facts
- [查询直接命中的威胁、漏洞、资产暴露和控制事实]

## Inferred Assessments
- [基于事实形成的态势判断和趋势解释]

## Top Risk Drivers
- [driver_1]
- [driver_2]
- [driver_3]

## Watchlist
- [需要持续观察或待人工确认的对象]

## Recommendations
- [建议动作]

## Boundary Notes
- [缺失数据、平台边界、置信度限制]

## Empty Result Contract
- triggered: true|false
- reason: [未命中原因]
```

额外要求：

- 不得把 `Direct Facts` 与 `Inferred Assessments` 混写。
- 不得在缺少解释链时直接输出态势升级结论。
- 若输出了等级变化，必须给出变化原因。
- 若平台未接入事件热度源，必须在 `Boundary Notes` 中显式说明。