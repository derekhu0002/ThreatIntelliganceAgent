# 角色设定
你是一位资深的 AI Agent 架构师和安全业务领域专家。你的任务是基于**“Agent + 多Skill + 泛型Tool”**的设计模式，结合给定的业务场景，生成核心的 Agent 配置文件和相应的业务 Skill SOP 文件。

---

# 背景上下文

## 1. 业务场景描述

 以下是本次需要构建的业务场景详细描述：
==================================================
 businesscases\威胁情报分析\基于“关联图谱”的未知威胁猎杀.md
==================================================

## 2. 当前可用数据资产及 SCHEMA 定义
系统当前通过统一的数据平台提供若干核心数据源。你在设计技能 SOP 的实际查询逻辑（如 Cypher 语句构建、字段映射）时，**必须且只能基于以下已知数据结构**进行组装。如果遇到结构不明确的地方，请参考对应的 SCHEMA 文件：

==================================================
### 各数据源 Schema 使用摘要

#### 1. `vehicle_iobe`

**定位**：车辆内外部边界与暴露面数据模型，适合描述 ECU、暴露面、外部对端、网络流量、消息及其关系。

**Schema 根结构**：STIX 2.1 `bundle`

**根字段**：

1. `type`，固定为 `bundle`
2. `id`，`bundle--UUID`
3. `objects`，对象数组

**当前对象类型**：

1. `x-vehicle-ecu`
2. `x-exposure-surface`
3. `x-external-peer`
4. `network-traffic`
5. `x-message`
6. `relationship`

**关键字段**：

1. ECU：`id`、`name`、`x_ecu_type`、`x_software_version`、`x_aliases`、`x_domain_tag`
2. 暴露面：`id`、`name`、`description`、`x_domain_tag`
3. 外部对端：`id`、`name`、`description`、`x_domain_tag`
4. 网络流量：`id`、`name`、`protocols`、`src_ref`、`dst_ref`、`x_domain_tag`
5. 消息：`id`、`name`、`description`、`x_domain_tag`
6. 关系：`source_ref`、`target_ref`、`relationship_type`、`x_name`、`x_domain_tag`

**已知关系类型枚举**：`exposes`、`via_channel`、`transmitted_by`、`connects_to`、`communicates_with`、`related-to`

- sourceId: vehicle_iobe
  Schema File Path: schema\schema_vehicle_iobe.json

#### 2. `tara`

**定位**：威胁分析与风险评估图数据模型，适合表达组件、资产、威胁场景、攻击路径、可行性、风险和安全需求之间的关系。

**Schema 根结构**：STIX 2.1 `bundle`

**根字段**：

1. `type`
2. `id`
3. `objects`

**当前对象类型**：

1. `x-vehicle-component`
2. `x-tara-report`
3. `x-vehicle-asset`
4. `x-damage-scenario`
5. `x-impact-assessment`
6. `x-threat-scenario`
7. `x-vulnerability`
8. `x-attack-path`
9. `x-attack-feasibility`
10. `x-tara-risk`
11. `x-security-objective`
12. `x-security-claim`
13. `x-security-requirement`
14. `relationship`

**关键字段示例**：

1. 组件：`name`、`item`、`description`、`x_domain_tag`
2. 报告：`report_id`、`name`、`standard`、`scope`、`x_domain_tag`
3. 资产：`asset_id`、`component_name`、`asset_item`、`function`、`architecture`、`level`
4. 损害场景：`scenario`、`confidentiality`、`integrity`、`availability`
5. 影响评估：`safety`、`property`、`operation`、`privacy`、`sum_score`、`rating`
6. 威胁场景：`threat_id`、`stride`、`attack_vector`、`cal`、`description`
7. 关系：`source_ref`、`target_ref`、`relationship_type`
- sourceId: tara
  Schema File Path: schema\schema_tara.json

#### 3. `ses`

**定位**：网络安全需求数据模型，适合表达安全目标、消减措施和原始需求文本。

**Schema 根结构**：STIX 2.1 `bundle`

**根字段**：

1. `type`
2. `id`
3. `objects`

**当前对象类型**：

1. `x-cybersecurity-requirement`

**关键字段**：

1. `id`
2. `keywords/labels`
3. `cybersecurity_goal`
4. `cybersecurity_measure`
5. `text`
6. `x_domain_tag`
- sourceId: ses
  Schema File Path: schema\schema_ses.json

#### 4. `vehicle_func`

**定位**：车辆功能数据模型，适合表达整车功能及其关联 ECU。

**Schema 根结构**：STIX 2.1 `bundle`

**当前对象类型**：

1. `x-vehicle-function`

**关键字段**：

1. `function_id`
2. `function_name`
3. `function_description`
4. `related_ecus`
5. `x_domain_tag`
- sourceId: vehicle_func
  Schema File Path: schema\schema_vehicle_func.json

#### 5. `ecu_func`

**定位**：ECU 控制器数据模型，适合表达 ECU 与功能的对应关系。

**Schema 根结构**：STIX 2.1 `bundle`

**当前对象类型**：

1. `x-ecu-controller`

**关键字段**：

1. `ecu_name`
2. `related_functions`
3. `x_domain_tag`
- sourceId: ecu_func
  Schema File Path: schema\schema_ecu_func.json


#### 6. `func_design_spec`

**定位**：功能设计规格数据模型，适合表达某类功能域、子功能域及其详细设计说明。

**Schema 根结构**：`bundle` 风格对象

**根字段**：

1. `id`
2. `type`
3. `x_domain_tag`
4. `objects`

**当前对象类型**：

1. `x-function-design-spec`

**关键字段**：

1. `function_model_name`
2. `sub_function_model_name`
3. `description`
4. `x_domain_tag`
- sourceId: func_design_spec
  Schema File Path: schema\schema_func_design_spec.json

#### 7. `opencti`

**定位**：外部 OpenCTI 威胁情报数据源的聚合 STIX Schema 目录。

**Schema 根结构**：聚合目录对象，而不是单个业务 Bundle。

**当前可消费的类型范围**：
1. `common`：基础公共类型，如 `bundle`、`identifier`、`timestamp`
2. `observables`：观测类对象，如 `artifact`、`domain-name`、`email-addr`、`file`、`ipv4-addr`、`network-traffic`、`software`、`url`
3. `sdos`：领域对象，如 `attack-pattern`、`campaign`、`course-of-action`、`identity`、`indicator`、`infrastructure`、`intrusion-set`、`malware`、`observed-data`、`report`、`threat-actor`、`tool`、`vulnerability`
4. `sros`：关系对象，如 `relationship`、`sighting`
- sourceId: opencti
  Schema File Path: schema\schema_stix_schema_aggregated.json
==================================================

---

# 核心架构约束（必须严格遵守）

1. **唯一的数据工具 (`ai4x_query`)**：
   - 所有的外部数据交互**只能**通过唯一泛型工具 `ai4x_query` 完成，绝对禁止编造其他工具（如 `query_neo4j` 或 `query_cve`）。
2. **三步查询范式 (The 3-Step Paradigm)**：
   - 技能的 SOP 中涉及任何实际查询前，必须强制遵循流水线：
     - **第一步 (Catalog)**：调用 `ai4x_query(command="catalog")` 确认该场景需要的数据源 (`sourceId`) 是否存在。
     - **第二步 (Schema)**：调用 `ai4x_query(command="schema", sourceId="xxx")` 获取目标数据源的具体字段和关系规范。
     - **第三步 (Query)**：根据刚获取到的 Schema 构造 Cypher 语句，调用 `ai4x_query(command="query", sourceId="xxx", cypher="...")` 发起真实查询。
3. **事实与推断分离**：
   - 查询返回的“直接事实（Fact）”与“图谱推断（Inference）”必须在输出给用户时明确分离；若未命中任何目标，必须返回结构化的“空结果”，禁止大模型幻觉编造数据。
4. **【重要】数据不足时的处理机制（Schema 建议）**：
   - 在梳理业务 SOP 时，请认真评估**“当前提供的可用数据源 SCHEMA”**是否能完全支撑该业务场景。
   - 如果发现关键数据缺失，你**不能去强行捏造不存在的字段或数据源**。
   - 你需要在该 Skill SOP 的末尾，新增一个 `Data Enhancement Suggestions` (数据扩充建议) 章节，明确指出：“要完美实现该技能，建议系统未来在某某现有数据源中新增 XXX 字段，或接入全新的 XXX 数据源”。

---

# 任务拆解与生成要求

请为我生成以下文件。所有输出请使用 Markdown 代码块包裹，并在文件顶部标注准确的文件路径。

## 任务 1：生成主 Agent 配置文件
**文件路径**：`agent_app/opencode_app/.opencode/agents/{{主AGENT文件名，如: ThreatIntelAnalyst}}.md`
Agent 的核心定义文件不需要写死具体的业务细节，而是要定义其**行为准则、调度逻辑和边界**。

一般需要包含以下内容：
1. **身份与人设 (Identity & Persona)**
   *   **描述**：你是谁？你的总体目标是什么？
   *   *示例*：“你是高级威胁情报分析师，负责安全事件的意图识别、证据收集与研判。”
2. **意图路由逻辑 (Intent Routing & Planning)**
   *   **描述**：当收到用户输入时，你的思考框架是什么？（比如 ReAct 框架：Thought -> Action -> Observation）。
   *   *示例*：“收到输入后，你必须先分析用户的意图，从可用的 Skill 列表中检索出最匹配的 Skill，然后严格按照该 Skill 的步骤执行。”
3. **能力与权限控制 (Permissions & Constraints)**
   *   **描述**：你能做什么，绝对不能做什么（防止幻觉和越权操作）。
   *   *示例*：“你只能使用被授权的工具；禁止猜测数据库字段名；涉及数据修改必须请求人工确认。”
4. **大模型配置 (LLM Configuration)**
   *   **描述**：选用的模型基座、Temperature（温度值，推理场景通常设为 0~0.2 以保证严谨性）、Top-P 等参数。

## 任务 2：生成业务 Skill SOP 文件
请在 `agent_app/opencode_app/.opencode/skills/` 路径下，**为以下每一个指定的业务场景先生成一个独立目录，然后在该目录下生成名为 `SKILL.md` 的文件**。
**强制约束：`SKILL.md` 中 YAML 头部的 `name` 字段，必须与它所在的目录名完全一致！**
Skill 的核心是将复杂的模糊任务转化为**可执行的标准作业程序 (SOP)**。每新增一个业务场景，只需新增一个 Skill，而不需要改动 Agent 的底层代码。

一个高质量的 Skill（如 `SKILL.md`）一般包含：
1. **元数据与触发条件 (Metadata & Triggers)**
   *   **描述**：Skill 的名称、功能摘要，以及“在什么情况下 Agent 应该选择这个 Skill”。这部分是写给 Agent 里的意图识别路由看的。
   *   *示例*：`name: ioc_quick_check`, `description: 当用户输入IP、域名或HASH并询问其安全性时触发此技能。`
2. **槽位与前置依赖 (Slots & Prerequisites)**
   *   **描述**：执行这个技能必须从用户输入中提取到哪些关键信息？如果没有，Agent 应该反问用户补充。
   *   *示例*：必须提取到 `target_ioc` 和 `ioc_type`。
3. **标准作业步骤 (SOP - Standard Operating Procedure)**
   *   **描述**：分步骤指导 Agent 如何思考以及如何调用工具。这是 Skill 的灵魂。
   *   *示例*：
       *   *Step 1: 先调用工具 A 获取数据源目录。*
       *   *Step 2: 调用工具 B 获取目标 IOC 的信誉分。*
       *   *Step 3: 如果分数 < 50，则结束并返回安全；如果 > 50，再调用工具 C 获取历史攻击上下文。*
4. **输出规范 (Output Format)**
   *   **描述**：最终交付给用户的内容结构。
   *   *示例*：“输出必须包含：1. 恶意定性；2. 置信度；3. 关联的APT组织；4. 处置建议，并使用 JSON 或指定的 Markdown 模板返回。”
 
 本次需要生成的技能列表如下：
==================================================

1. 目录名：unknown_threat_hunting (未知威胁猎杀)

==================================================

**每个 `SKILL.md` 文件的内部结构必须严格遵循以下模板：**

```yaml
---
name:[必须与所在目录名完全一致，不可包含特殊字符]
description: [触发此技能的具体场景和用户意图]
---
```
*(这里是正文)*
- **Trigger & Context (触发条件与上下文)**
- **Prerequisites (槽位/前置依赖提取)**
- **SOP Action Steps (标准作业步骤)**：明确指出依据哪几个具体的 sourceId、结合刚刚参考的 SCHEMA 规范，调用 `ai4x_query` 执行什么命令（严格遵循三步查询范式）。如果有具体的 Cypher 示例，请确保符合 Schema。
- **Data Enhancement Suggestions (数据扩充建议)**：(如果当前数据源能满足则填“无”，如果不能完全支撑业务，请在此提出 Schema 改进建议，指导人类开发完善数据源)。
- **Output Format (输出规范)**：定义统一的 Markdown/JSON 结构化输出版式。
---
请确认理解上述所有逻辑、架构约束与目录一致性要求。