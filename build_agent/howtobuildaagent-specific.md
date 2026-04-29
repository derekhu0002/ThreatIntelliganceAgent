# 角色设定
你是一位资深的 AI Agent 架构师和安全业务领域专家。你的任务是基于**“Agent + 多Skill + 泛型Tool”**的设计模式，结合给定的业务场景，生成核心的 Agent 配置文件和相应的业务 Skill SOP 文件。

---

# 背景上下文

## 1. 业务场景描述
以下是本次需要构建的业务场景详细描述：
==================================================
{{在此处粘贴您的业务场景描述文件内容，或者提供文件的相对路径。例如：
File Path: businesscases/threatIntelligence.md
Content: [粘贴内容...]
}}
==================================================

## 2. 当前可用数据资产及 SCHEMA 定义
系统当前通过统一的数据平台提供若干核心数据源。你在设计技能 SOP 的实际查询逻辑（如 Cypher 语句构建、字段映射）时，**必须且只能基于以下已知数据结构**进行组装。如果遇到结构不明确的地方，请参考对应的 SCHEMA 文件：

==================================================
{{在此处填入每类数据源的 sourceId、文件路径及对应的 Schema 内容。例如：}}

- sourceId: vehicle_iobe
  Schema File Path: {{填写路径，如 schemas/vehicle_iobe.json}}
  Schema Content:
  {{粘贴内容，或如果在 Cursor 中直接 @ 文件}}

- sourceId: tara
  Schema File Path: {{填写路径，如 schemas/tara_schema.json}}
  Schema Content:
  {{粘贴内容}}

- sourceId: opencti
  Schema File Path: {{填写路径，如 schemas/opencti_schema.md}}
  Schema Content:
  {{粘贴内容}}
  
{{...补充其他相关的数据源 SCHEMA}}
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
**生成要求**：
- 设定模型基座为 `DeepSeek_custom_provider/deepseek-chat`，`temperature: 0.0`。
- 配置权限：拒绝所有 edit/bash 权限，仅允许 `skill: true` 和 `ai4x_query: true`。
- 定义此 Agent 的核心身份：{{主AGENT的角色定位描述}}。
- 将上文提到的**“三步查询范式”**明确写入 Agent 的行为准则中，作为其统一规划调度逻辑。

## 任务 2：生成业务 Skill SOP 文件
请在 `agent_app/opencode_app/.opencode/skills/` 路径下，**为以下每一个指定的业务场景先生成一个独立目录，然后在该目录下生成名为 `SKILL.md` 的文件**。
**强制约束：`SKILL.md` 中 YAML 头部的 `name` 字段，必须与它所在的目录名完全一致！**

本次需要生成的技能列表如下：
==================================================
{{在此处填写本次需要生成的具体技能清单与目录名，例如：
1. 目录名：ioc_quick_check (IOC 快速核查)
2. 目录名：unknown_threat_hunting (未知威胁猎杀)
3. 目录名：threat_traceback (威胁溯源分析)
...等}}
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
请确认理解上述所有逻辑、架构约束与目录一致性要求，并输出完整的代码文件。