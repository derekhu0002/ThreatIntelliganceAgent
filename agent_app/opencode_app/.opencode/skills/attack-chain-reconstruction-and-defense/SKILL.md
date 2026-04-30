---
name: attack-chain-reconstruction-and-defense
description: 当用户提供安全事件标题、IOC、实体名或CVE，并希望自动还原攻击链、识别受影响车辆组件、评估风险并生成防御建议时触发此技能。
---

# Trigger & Context (触发条件与上下文)

当用户表达以下任一意图时触发本技能：

- 希望从公开安全事件、威胁情报报告或事件摘要中还原攻击链。
- 希望基于 STIX 2.1 可观测对象、attack-pattern、基础设施和车辆侧对象识别受影响组件。
- 希望将外部威胁事件与车辆 ECU、暴露面、组件、风险对象进行关联。
- 希望在事实证据基础上生成风险判断、缓解建议和后续检测思路。

本技能采用严格单 Skill 路由。命中该场景后，Agent 仅执行本 SOP，不跨 Skill 自由拼接未授权流程。

# Prerequisites (槽位/前置依赖提取)

优先从用户输入中提取以下槽位：

- `entry_type`: 入口类型，允许值为 `report_title`、`ioc`、`entity_name`、`cve`。
- `entry_value`: 与入口类型对应的实际查询值。
- `time_range`: 可选增强条件。若用户提供则用于缩小查询范围；若缺失且当前结果过宽或冲突，再追问。
- `analysis_goal`: 默认值为 `reconstruct_attack_chain_and_defense`。

补槽位规则：

- 如果无法提取任何入口信息，必须先追问用户补充事件标题、IOC、实体名或 CVE。
- 如果仅有模糊描述且无法形成可查询入口，停止真实查询，仅返回所需补充信息清单。
- 时间范围不是硬性必需槽位，由 Agent 根据查询命中范围自行判断是否需要追问。

# SOP Action Steps (标准作业步骤)

## Step 0. 声明边界

在执行任何查询前，先声明以下约束：

- 仅使用 `ai4x_query`。
- 严格遵守 `catalog -> schema -> query` 三步查询范式。
- 不编造字段、关系、对象或数据源。
- 输出必须明确区分 `Facts` 与 `Inferences`。
- 任一链路未命中时，保留已命中的事实，并对未命中部分返回结构化空结果。

## Step 1. 确认需要的数据源存在

必须先调用目录能力确认本场景依赖的数据源可用：

1. `ai4x_query(command="catalog")`
2. 在目录中检查以下 `sourceId` 是否存在：
   - `opencti`
   - `vehicle_iobe`
   - `tara`
3. 若任一关键数据源缺失：
   - 返回 `Gaps`：列出缺失的 `sourceId`。
   - 停止后续依赖该数据源的查询。
   - 不得用推断替代缺失事实。

## Step 2. 获取目标数据源 Schema

在构造任何 Cypher 前，必须获取并检查 Schema：

1. `ai4x_query(command="schema", sourceId="opencti")`
2. `ai4x_query(command="schema", sourceId="vehicle_iobe")`
3. `ai4x_query(command="schema", sourceId="tara")`

Schema 检查重点：

- `opencti` 中是否可消费 `report`、`attack-pattern`、`infrastructure`、`malware`、`indicator`、`relationship`。
- `vehicle_iobe` 中是否可消费 `x-vehicle-ecu`、`x-exposure-surface`、`x-external-peer`、`network-traffic`、`x-message`、`relationship`。
- `tara` 中是否可消费 `x-vehicle-component`、`x-vehicle-asset`、`x-threat-scenario`、`x-attack-path`、`x-attack-feasibility`、`x-tara-risk`、`relationship`。

若 Schema 未体现后续查询依赖的对象类型或关键字段，则在 `Gaps` 中明确列出，并跳过对应链路。

## Step 3. 在 opencti 中定位事件入口事实

根据入口类型选择查询策略，但必须先从 `opencti` 起步建立事实锚点。

### 3A. 入口为 report_title

先查询事件报告与其直接关联对象：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(r.name) CONTAINS toLower($entry_value) OPTIONAL MATCH (r)-[rel1]-(ap {type: 'attack-pattern'}) OPTIONAL MATCH (r)-[rel2]-(infra {type: 'infrastructure'}) OPTIONAL MATCH (r)-[rel3]-(mw {type: 'malware'}) RETURN r, rel1, ap, rel2, infra, rel3, mw"
)
```

### 3B. 入口为 ioc 或 entity_name

先尝试匹配 `indicator`、`infrastructure`、`malware`、`attack-pattern`、`report`：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (n) WHERE (n.type IN ['indicator','infrastructure','malware','attack-pattern','report']) AND toLower(coalesce(n.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (n)-[rel]-(m) RETURN n, rel, m"
)
```

### 3C. 入口为 cve

先尝试匹配 `vulnerability` 及其与 `report`、`attack-pattern` 的关系：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (v {type: 'vulnerability'}) WHERE toLower(coalesce(v.name, '')) CONTAINS toLower($entry_value) OPTIONAL MATCH (v)-[rel]-(m) RETURN v, rel, m"
)
```

判定规则：

- 如果 `report` 命中，则将其作为主事件事实锚点。
- 如果只命中 `indicator`、`infrastructure`、`malware` 或 `attack-pattern`，则继续向外扩展并寻找相关 `report`。
- 如果未命中任何对象，直接输出结构化空结果，不得编造事件上下文。

## Step 4. 还原 opencti 侧攻击链事实

在已命中的 `report` 或其近邻对象上，还原最小攻击链。主链优先级固定为：

- `report -> attack-pattern -> infrastructure`

若主链不完整，可补充：

- `report -> malware -> infrastructure`
- `report -> indicator -> infrastructure`

推荐查询模板：

```text
ai4x_query(
  command="query",
  sourceId="opencti",
  cypher="MATCH (r {type: 'report'}) WHERE toLower(r.name) CONTAINS toLower($entry_value) OPTIONAL MATCH path1=(r)-[*1..2]-(ap {type: 'attack-pattern'}) OPTIONAL MATCH path2=(ap)-[*1..2]-(infra {type: 'infrastructure'}) OPTIONAL MATCH path3=(r)-[*1..2]-(mw {type: 'malware'}) RETURN r, path1, path2, path3, mw, infra, ap"
)
```

事实抽取要求：

- 记录命中的关键对象名称、对象类型和来源 `sourceId=opencti`。
- 记录关系方向与关系类型。如果底层返回未显式提供标准关系含义，只能原样引用，不得自行改写为 ATT&CK 语义。
- 若命中 `attack-pattern`，可以在 `Facts` 中表述为“命中攻击模式对象”；将其映射为具体攻击阶段时，必须放入 `Inferences` 并标注待人工确认。

## Step 5. 将外部事件映射到 vehicle_iobe 暴露面与 ECU

目标：把 opencti 侧事件事实与车端暴露面、外部对端、通信对象和 ECU 进行只读映射。

### 5A. 先定位外部基础设施与暴露面接触点

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (peer {type: 'x-external-peer'})-[r1]-(traffic {type: 'network-traffic'})-[r2]-(surface {type: 'x-exposure-surface'}) WHERE toLower(coalesce(peer.name, '')) CONTAINS toLower($infra_or_ioc_name) RETURN peer, r1, traffic, r2, surface"
)
```

### 5B. 再定位与暴露面相关的 ECU 与消息对象

```text
ai4x_query(
  command="query",
  sourceId="vehicle_iobe",
  cypher="MATCH (surface {type: 'x-exposure-surface'})-[r1]-(ecu {type: 'x-vehicle-ecu'}) OPTIONAL MATCH (surface)-[r2]-(msg {type: 'x-message'}) WHERE toLower(coalesce(surface.name, '')) CONTAINS toLower($surface_name) RETURN surface, r1, ecu, r2, msg"
)
```

判定规则：

- `vehicle_iobe` 仅作为受影响面与通信链路事实来源。
- 如果 opencti 侧基础设施名称与 `x-external-peer.name` 存在直接命中，可视为一条事实映射线索。
- 如果只能通过相似语义人工理解，不能直接下结论，必须放入 `Gaps` 或 `Inferences`。

## Step 6. 使用 tara 验证受影响组件与风险事实

目标：只有在 `opencti` 侧事件事实与 `vehicle_iobe` 侧通信/暴露事实都存在时，才尝试在 `tara` 中下沉到组件、资产和风险层。

### 6A. 查询组件和资产

```text
ai4x_query(
  command="query",
  sourceId="tara",
  cypher="MATCH (component {type: 'x-vehicle-component'}) OPTIONAL MATCH (component)-[r1]-(asset {type: 'x-vehicle-asset'}) WHERE toLower(coalesce(component.name, '')) CONTAINS toLower($candidate_component_name) OR toLower(coalesce(asset.component_name, '')) CONTAINS toLower($candidate_component_name) RETURN component, r1, asset"
)
```

### 6B. 查询威胁场景、攻击路径、可行性与风险

```text
ai4x_query(
  command="query",
  sourceId="tara",
  cypher="MATCH (component {type: 'x-vehicle-component'})-[*1..3]-(threat {type: 'x-threat-scenario'}) OPTIONAL MATCH (threat)-[r1]-(path {type: 'x-attack-path'}) OPTIONAL MATCH (threat)-[r2]-(feasibility {type: 'x-attack-feasibility'}) OPTIONAL MATCH (threat)-[r3]-(risk {type: 'x-tara-risk'}) WHERE toLower(coalesce(component.name, '')) CONTAINS toLower($candidate_component_name) RETURN component, threat, path, feasibility, risk, r1, r2, r3"
)
```

判定规则：

- 受影响车辆组件的最终判定必须同时满足：
  - `opencti` 存在与事件相关的攻击事实锚点。
  - `vehicle_iobe` 存在与基础设施或暴露面相关的通信/暴露事实。
  - `tara` 存在与候选组件关联的威胁或风险事实。
- 若仅满足其中两项，不得在 `Facts` 中写成最终受影响组件，只能在 `Inferences` 中写为候选，并标记待人工确认。
- 风险等级优先引用 `tara` 中已有 `x-tara-risk`、`x-attack-feasibility`、`x-impact-assessment` 等事实；若未命中则明确返回“无法判定”。

## Step 7. 形成事实攻击链与推断性杀伤链

输出时严格分离：

- `Facts`：仅包含查询命中的对象、关系、来源数据源。
- `Inferences`：仅包含基于 `attack-pattern`、基础设施复用、车辆暴露面与 TARA 风险链路做出的推断。

攻击链构造规则：

- STIX 事实攻击链：按命中的 `report / attack-pattern / infrastructure / malware / x-external-peer / network-traffic / x-exposure-surface / x-vehicle-ecu / x-vehicle-component / x-tara-risk` 顺序组织。
- 推断性杀伤链：可依据命中的 `attack-pattern` 对应到“初始访问、执行、横向移动、影响”等阶段性描述，但必须明确写为推断，并标记“待人工确认”。

## Step 8. 生成缓解与检测建议

建议必须证据驱动，不能伪装成已验证事实。

### 8A. 研判动作

- 列出应优先复核的事件入口、基础设施、受影响暴露面和 ECU。
- 如果 `tara` 风险命中，建议优先检查对应组件的现有控制措施和适用范围。

### 8B. ECU / 组件级缓解建议

- 基于命中的 `x-exposure-surface`、`network-traffic`、`x-vehicle-ecu`、`x-vehicle-component` 输出针对性建议。
- 只能输出“建议检查/建议限制/建议验证/建议隔离”等动作，不能伪造系统已执行结果。

### 8C. TARA 风险降低建议

- 如果命中 `x-threat-scenario`、`x-attack-path`、`x-tara-risk`，引用这些对象作为风险降低建议的证据支撑。
- 若未命中 `tara` 风险对象，则明确写明“暂无可验证的 TARA 风险事实”。

### 8D. EQL / ECS 检测思路模板

- EQL 和 ECS 在当前已知数据源中不具备直接查询基础。
- 只能依据已命中的事实对象生成“检测思路模板”，例如围绕域名、网络连接、暴露面、异常消息流设计候选规则。
- 所有检测模板必须标记为“建议模板，待人工落地确认”。

# Data Enhancement Suggestions (数据扩充建议)

当前数据源可以支撑事件事实定位、车辆暴露面映射和部分 TARA 风险验证，但无法完美覆盖全部业务目标。建议补充如下：

1. 在 `opencti` 可消费对象映射中补充更稳定的 ATT&CK 语义字段，如 tactic、technique external id、kill chain phase，避免仅凭 `attack-pattern` 名称做阶段推断。
2. 在 `vehicle_iobe` 中增加更明确的基础设施到暴露面映射字段，例如域名、IP、URL 或协议端点标识，降低外部基础设施到 `x-external-peer` 的语义匹配歧义。
3. 在 `tara` 中增加组件与 ECU 或暴露面的标准化关联字段，减少跨数据源拼接时对名称匹配的依赖。
4. 若希望让检测建议可查询验证，建议新增独立数据源或对象模型承载 ECS 字段字典、可观测日志模式和 EQL 规则模板。
5. 若希望更稳定地把公开事件文本导入图谱，建议新增事件归一化中间对象，显式记录事件标题、时间、IOC、攻击模式和车辆对象映射证据。

# Output Format (输出规范)

最终输出必须使用以下 Markdown 模板：

```markdown
## Facts
- Event Anchor:
  - sourceId: opencti
  - objects: [事件报告或入口对象]
- Attack Chain Facts:
  - [对象A(type)] --[relationship]--> [对象B(type)] (sourceId=...)
- Vehicle Exposure Facts:
  - [外部对端/流量/暴露面/ECU 事实链]
- Component & Risk Facts:
  - [组件/资产/威胁场景/风险对象]

## Inferences
- [推断结论 1] (confidence: high|medium|low, review_required: yes/no)
- [推断结论 2] (confidence: high|medium|low, review_required: yes/no)

## Gaps
- Missing Sources:
  - [缺失的 sourceId]
- Unresolved Links:
  - [未命中的链路或无法验证的映射]

## Recommendations
- Triage Actions:
  - [证据驱动的研判动作]
- Mitigations:
  - [ECU/组件级缓解建议]
- Detection Templates:
  - [EQL/ECS 候选思路，必须标记待人工确认]

## Empty Result Contract
- query_status: empty|partial|complete
- retained_facts:
  - [保留的已命中事实，若无则为空数组]
- empty_segments:
  - [未命中的查询链路]
- next_questions:
  - [建议用户补充的信息]
```

输出约束：

- 置信度只允许使用 `high`、`medium`、`low` 的定性分级，依据证据覆盖度给出。
- 必须列出关键对象、关系和来源 `sourceId`。
- `attack-pattern` 到实际攻击阶段的映射、`tara` 风险继承判断、`EQL/ECS` 模板、跨源拼接得到的组件归属，必须标记待人工确认。
- 不得把查询未命中的部分写成事实。