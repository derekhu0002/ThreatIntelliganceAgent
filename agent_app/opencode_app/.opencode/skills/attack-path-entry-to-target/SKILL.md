---
name: attack-path-entry-to-target
description: 当用户提供入口点、目标资产或平台范围，并希望预测从入口到目标的候选攻击路径、关键跳板节点、关键阻断点和防御建议时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户有以下任一意图时触发本技能：

- 提供明确入口点和目标资产，希望识别横向移动路径、关键跳板节点或关键阻断点。
- 希望基于系统架构、通信拓扑和 TARA 模型输出攻击路径预测报告。
- 希望用结构化结果支撑设计评审、防御布局或架构风险沟通。

本技能默认采用“内部架构事实优先，威胁模型模板校验，控制语义与技术语义补强”的分析顺序：

- `vehicle_iobe` 负责入口暴露、节点和通信事实。
- `tara` 负责威胁场景、攻击路径模板和可行性约束。
- `ses` 负责控制要求与防御语义。
- `opencti` 仅作为可选增强，用于补充 `attack-pattern` 和 `course-of-action` 语义。

# Prerequisites (槽位/前置依赖提取)

优先提取以下槽位：

- `entry_surface`: 至少识别入口类型和值，例如 `cellular`、`wifi`、`bluetooth`、`usb`、`ota`、`mobile-app`、`diagnostic-port`。
- `target_asset`: 至少识别目标资产类型和值，例如 `x-vehicle-ecu`、`gateway`、`domain-controller`、`function-domain`。
- `scope`: 至少识别 `vehicle_platform`、`product_line` 或 `software_version` 中一个范围锚点。
- `path_budget`: 可选，默认 `5`。
- `focus_dimension`: 可选，允许关注 `pivot-node`、`choke-point`、`mitigation`、`function-rollup`。
- `report_depth`: 可选，允许值为 `brief`、`standard`、`deep`，默认 `standard`。

提取与追问规则：

- 如果缺少 `entry_surface` 或 `target_asset`，先追问补齐，不直接搜索路径。
- 如果用户只给出入口点，也允许承接，但必须先进入澄清分支补齐目标资产。
- 若范围过宽，例如只有平台名没有版本信息，可先继续，但在 `Gaps` 中说明结果可能覆盖多个版本差异。
- 如果用户目标在“快速评审”和“深度推演”之间不清晰，先追问一次，不直接进入大规模扩图。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明执行边界

执行任何查询前，先声明：

- 所有外部数据交互只能通过 `ai4x_query` 完成。
- 任何真实查询必须遵循 `catalog -> schema -> query` 三步查询范式。
- 必须严格区分 `Facts` 与 `Inferred Assessments`。
- `x-attack-path` 是威胁模型模板，不等于已证实攻击事实。
- 当没有足够证据时，允许输出“未形成稳定高置信路径”的空结论报告。

## Step 1. 确认可用数据源

先调用：

```text
ai4x_query(command="catalog")
```

最少检查：

- `vehicle_iobe` 是否存在。
- `tara` 是否存在。
- `ses` 是否存在。
- 是否存在可选增强源 `opencti`。

如果 `vehicle_iobe` 或 `tara` 不存在：

- 在 `Gaps` 中输出缺失数据源。
- 停止后续查询。
- 不编造替代数据源。

## Step 2. 获取 Schema

在构造任何 Cypher 前，必须调用：

```text
ai4x_query(command="schema", sourceId="vehicle_iobe")
ai4x_query(command="schema", sourceId="tara")
```

若需要控制或技术补强，再调用：

```text
ai4x_query(command="schema", sourceId="ses")
ai4x_query(command="schema", sourceId="opencti")
```

重点确认以下对象是否可消费：

- `vehicle_iobe`: `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`relationship`
- `tara`: `x-threat-scenario`、`x-damage-scenario`、`x-attack-path`、`x-attack-feasibility`
- `ses`: `x-cybersecurity-requirement`
- `opencti`: `attack-pattern`、`course-of-action`、`relationship`

如果 Schema 未覆盖计划使用的对象或关系，必须在 `Gaps` 中说明并缩减后续查询链。

## Step 3. 建立入口与目标事实锚点

先在 `vehicle_iobe` 中查询入口暴露面、外部对端和目标资产本体：

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (entry)-[r1]-(adj1) WHERE entry.type IN ['x-exposure-surface','x-external-peer'] AND toLower(coalesce(entry.name, entry.value, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (target)-[r2]-(adj2) WHERE target.type IN ['x-vehicle-ecu','x-domain-controller','x-function-domain'] AND toLower(coalesce(target.name, entry.value, '')) CONTAINS toLower($target_value) RETURN entry, r1, adj1, target, r2, adj2"
)
```

事实抽取要求：

- 记录入口暴露面、相关外部对端、起始 ECU 或组件。
- 记录目标资产及其直接上下游通信邻接。
- 此阶段只返回架构事实，不混入路径结论。

## Step 4. 执行一跳拓扑与可达性查询

围绕入口和目标，在 `vehicle_iobe` 中扩展：

- 入口相关的 `x-exposure-surface`、`x-external-peer`、`network-traffic`。
- 目标相关的 `x-vehicle-ecu`、相邻 ECU、域控制器、函数域。
- 能形成横向移动基础的直接通信或关系边。

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH path=(entry)-[*1..3]-(target) WHERE id(entry) = $entry_id AND id(target) = $target_id RETURN path LIMIT $path_budget"
)
```

要求：

- 只把图中真实存在的路径作为候选拓扑事实。
- 不因为最短路存在就直接认定为高风险路径。

## Step 5. 用 TARA 模板匹配候选路径

在 `tara` 中查询与入口、目标和中间节点相关的威胁场景、攻击路径模板和可行性：

```text
ai4x_query(
  command="query",
  sourceId="tara",
  cypher="MATCH (ap {type: 'x-attack-path'}) OPTIONAL MATCH (ap)-[r1]-(ts {type: 'x-threat-scenario'}) OPTIONAL MATCH (ap)-[r2]-(af {type: 'x-attack-feasibility'}) WHERE toLower(coalesce(ap.description, ap.name, '')) CONTAINS toLower($entry_value) OR toLower(coalesce(ap.description, ap.name, '')) CONTAINS toLower($target_value) RETURN ap, r1, ts, r2, af"
)
```

匹配要求：

- 用 `x-attack-path` 和 `x-threat-scenario` 校验拓扑候选路径是否符合已建模威胁语境。
- 用 `x-attack-feasibility` 为路径排序提供额外权重。
- 不把模板匹配直接写成“攻击已发生”。

## Step 6. 补充控制与攻击技术语义

如 `ses` 可用，查询与入口类型、目标域和候选路径相关的控制要求：

```text
ai4x_query(
  command="query",
  sourceId="ses",
  cypher="MATCH (req {type: 'x-cybersecurity-requirement'}) WHERE toLower(coalesce(req.text, req.name, '')) CONTAINS toLower($entry_value) OR toLower(coalesce(req.text, req.name, '')) CONTAINS toLower($target_value) RETURN req"
)
```

如 `opencti` 可用，再补充：

- `attack-pattern`
- `course-of-action`

用于解释：

- 路径相关的攻击技术语义。
- 候选阻断点可参考的通用缓解动作。

## Step 7. 对候选路径做加权排序

每条候选路径至少考虑以下因素：

- 入口暴露强度。
- 拓扑可达性。
- `tara` 模板匹配度。
- `x-attack-feasibility` 可行性。
- 控制缺失或控制薄弱程度。

排序规则：

- 不能只按 hop 数排序。
- 同时满足内部可达性和 TARA 模板匹配的路径可提升为高优先级。
- 依赖缺失配置、假设入口或弱模板匹配的路径应降级为 `medium` 或 `low`。

路径强度建议：

- `high`: 内部拓扑可达，且有明确 TARA 模板与可行性支撑。
- `medium`: 可达性明确，但模板或控制信息不完整。
- `low`: 路径存在较强假设、证据稀疏或控制信息缺失。

## Step 8. 形成排除项与建议

### 8A. Exclusions

必须列出搜索过但证据不足的路径或节点，例如：

- 只存在抽象模板，没有内部拓扑可达性支撑。
- 只存在通信边，但没有对应威胁场景或可行性支撑。
- 依赖未确认的配置前提或版本假设。

### 8B. Recommendations

建议应聚焦于阻断和验证，例如：

- 优先补强入口认证、会话保护和接口隔离。
- 对关键跳板节点增加分段、消息过滤或服务隔离。
- 核查相关 `x-cybersecurity-requirement` 是否在当前范围内落地。
- 对中低置信路径补查版本差异、配置细节和控制状态。

# Output Format (输出规范)

最终输出必须采用以下 Markdown 结构：

```markdown
## Facts
- Entry Surface:
  - type: [entry_surface.type]
  - value: [entry_surface.value]
  - sourceId: [vehicle_iobe]
- Target Asset:
  - type: [target_asset.type]
  - value: [target_asset.value]
- Direct Facts:
  - [入口暴露面、网络流量、目标邻接、TARA 模板等直接事实]

## Ranked Paths
- [path_id]
  - score: [0-1 or qualitative score backing]
  - confidence: high|medium|low
  - path_summary: [Entry -> Pivot -> Target]
  - nodes:
    - [节点列表]
  - pivot_nodes:
    - [关键跳板节点]
  - choke_points:
    - [关键阻断点]

## Supporting Attack Patterns / Controls
- Attack Patterns:
  - [attack-pattern 或 TARA 攻击语义]
- Controls:
  - [x-cybersecurity-requirement 或 course-of-action]

## Inferred Assessments
- [只能写基于事实层和模型层形成的候选路径判断]

## Exclusions
- [路径或节点名称]
  - reason: [证据不足原因]

## Gaps
- Missing Sources:
  - [缺失 sourceId，若无则写 none]
- Missing Schema or Assumptions:
  - [缺失对象、字段、关系、配置前提或范围信息]

## Recommendations
- [后续验证与阻断建议]

## Empty Result Contract
- status: no_stable_high_confidence_path | partial_path_hit
- reason: [未命中的原因或仅形成部分路径的说明]
```

# Acceptance Notes (验收说明)

执行本技能时，至少满足以下验收条件：

1. 查询前已完成入口点、目标资产和范围的必要澄清。
2. 所有真实查询遵循 `catalog -> schema -> query`。
3. 输出明确分离 `Facts` 与 `Inferred Assessments`。
4. 每条主要候选路径都可映射到至少一条路径证据。
5. 当证据不足时，输出空结论或部分命中报告，而不是强行给出高置信路径。