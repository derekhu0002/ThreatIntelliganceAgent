
# 角色设定
你是一位资深的 AI Agent 架构师和安全领域专家。你的任务是基于**“Agent + 多Skill + 泛型Tool”**的设计模式，为“威胁情报分析”系统生成核心的 Agent 配置文件和 6 个具体的业务 Skill SOP 文件。

---

# 核心架构约束（必须严格遵守）

1. **唯一的数据工具 (`ai4x_query`)**：
   - 所有的外部数据交互**只能**通过唯一泛型工具 `ai4x_query` 完成，禁止编造其他工具（如 `query_neo4j` 或 `query_cve`）。
   - 该工具通过 `command` 参数实现多态。
2. **三步查询范式 (The 3-Step Paradigm)**：
   - 在任何实际查询前，必须强制遵循以下流水线：
     - **第一步 (Catalog)**：调用 `ai4x_query(command="catalog")` 发现可用数据源 (`sourceId`)。
     - **第二步 (Schema)**：调用 `ai4x_query(command="schema", sourceId="xxx")` 获取对应数据源的字段规范和关联图谱。
     - **第三步 (Query)**：根据 Schema 构造 Cypher 或 paramsJson，调用 `ai4x_query(command="query", sourceId="xxx", cypher="...")` 发起真实查询。
3. **事实与推断分离**：
   - 查询返回的“直接事实（Fact）”与“图谱推断（Inference）”必须在上下文中明确分离；
   - 若未命中目标或无新增线索，必须返回结构化的“空结果”，禁止编造（幻觉）数据。

---

# 任务拆解与生成要求

请为我生成以下 7 个文件。所有输出请使用 Markdown 代码块包裹，并在文件顶部包含必要的 YAML Frontmatter 元数据。

## 任务 1：生成主 Agent 配置文件
**文件路径**：`agent_app/opencode_app/.opencode/agents/ThreatIntelAnalyst.md`
**生成要求**：
- 设定模型基座为 `DeepSeek_custom_provider/deepseek-chat`，`temperature: 0.0`。
- 配置权限（Permission）：拒绝所有 edit/bash 权限，仅允许 `skill: true` 和 `ai4x_query: true`。
- 定义 Agent 的核心身份（Canonical Threat Intelligence Analyst）。
- 将上文提到的**“三步查询范式”**明确写入 Agent 的核心行为准则（Core Behaviors）中，作为其意图路由和规划的基础。

## 任务 2：生成 6 个核心业务 Skill SOP 文件
请根据《AI辅助威胁情报大颗粒业务场景总览》的要求，在 `agent_app/opencode_app/.opencode/skills/` 目录下生成以下 6 个 `.md` 文件：

1. **`ioc_quick_check.md` (IOC 快速核查)**：
   - 提取槽位：目标 IOC、IOC 类型。
   - 流程要求：利用 `opencti` 等数据源，查询信誉、关联组织和历史活动。
2. **`unknown_threat_hunting.md` (未知威胁猎杀)**：
   - **特殊约束**：明确要求对 `sourceId=opencti` 先做一跳查询，再基于 IOC 做二次查询；严格区分直接事实与图谱拓展结果。
3. **`threat_traceback.md` (威胁溯源分析)**：
   - 流程要求：从 IP/样本出发，串联 Malware -> 攻击模式 -> 攻击组织 -> 历史活动，生成溯源链路。
4. **`attack_path_prediction.md` (攻击路径预测)**：
   - 流程要求：基于 `vehicle_iobe` 和 `tara` 数据源（暴露面和架构图），推演横向移动的可能性与跳板节点。
5. **`incident_analysis_report.md` (安全事件分析与自动化事件报告)**：
   - 流程要求：自动提取事件实体，结合外部上下文生成结构化调查报告（含动机、影响、处置建议）。
6. **`security_posture_awareness.md` (安全态势感知)**：
   - 流程要求：聚合活跃威胁、漏洞命中率，生成当前态势分数（红橙黄蓝）与趋势报告。

**每个 Skill 文件的内部结构必须包含：**
```yaml
---
name: [技能英文名]
description: [触发此技能的具体场景和用户意图]
---
```
**Markdown 正文必须包含：**
- **Trigger & Context (触发条件与上下文)**
- **Prerequisites (槽位/前置依赖提取)**
- **SOP Action Steps (标准作业步骤)**：明确指出哪一步该调用 `ai4x_query` 的哪个 `command`。
- **Output Format (输出规范)**：要求统一的 Markdown/JSON 结构化输出。

---

请确认理解上述要求，并按顺序输出这 7 个文件的完整内容。