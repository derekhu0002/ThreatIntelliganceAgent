# Agent 设计文档清单

## 目的

汇总仓库中已经具备独立设计文档的业务 Agent，便于快速查看每个 Agent 的职责边界、建议主 Agent 名称以及当前控制平面的落地文件。

信息来源：

- `design/KG/SystemArchitecture.json`
- `OVERALL_ARCHITECTURE.md`
- `agent_app/opencode_app/.opencode/ARCHITECTURE.md`
- `docs/scenarios/*Agent设计.md`
- `agent_app/opencode_app/.opencode/agents/*.md`

当前已确认有独立设计文档的业务 Agent 共 9 个。

## 总览

| 业务能力 | 简要总结 | 设计文档建议主 Agent | 当前控制平面 Agent 文件 | 备注 |
| --- | --- | --- | --- | --- |
| IOC 快速核查与告警分诊 | 面向 IOC 或外部告警做快速事实核查、优先级评估和建议动作输出，目标是判断是否值得升级处置。 | `IOCTriageAgent` | `agent_app/opencode_app/.opencode/agents/IOCTriageAgent.md` | 不负责自动响应、完整归因和整体态势汇总。 |
| 威胁溯源分析 | 从 IP、域名、HASH、恶意软件或 TTP 出发，扩展组织、活动、技术和工具关系，输出可追溯的归因报告。 | `ThreatIntelAgent` | `agent_app/opencode_app/.opencode/agents/ThreatIntelAttributionAnalyst.md` | 存在命名差异，设计文档与当前 Agent 文件名称未统一。 |
| 安全态势感知 | 按时间窗聚合威胁、漏洞、资产暴露面和事件摘要，形成总体风险等级、趋势和重点关注项。 | `SecurityPostureAgent` | `agent_app/opencode_app/.opencode/agents/SecuritySituationalAwarenessAgent.md` | 存在命名差异，设计文档与当前 Agent 文件名称未统一。 |
| 应急响应编排 | 从事件、IOC 或漏洞触发信息出发，生成遏制、排查、恢复和跟踪建议，服务人工响应流程。 | `IncidentResponseAgent` | `agent_app/opencode_app/.opencode/agents/IncidentResponseAgent.md` | 不负责自动执行隔离、阻断、补丁下发或工单流转。 |
| 供应链安全风险评估 | 围绕第三方组件、供应商、采购对象或 SBOM/SCA 线索，评估外部依赖对内部系统的实际风险和治理优先级。 | `SupplyChainRiskAgent` | `agent_app/opencode_app/.opencode/agents/SupplyChainRiskAgent.md` | 当问题收敛为明确漏洞影响时，应转交漏洞影响评估。 |
| 攻击路径预测 | 从外部入口点或暴露面出发，结合系统架构、通信拓扑和威胁模型推演高概率攻击链路。 | `AttackPathAgent` | `agent_app/opencode_app/.opencode/agents/AttackPathAgent.md` | 偏事前路径分析，不负责证明真实攻击已发生。 |
| 未知威胁狩猎 | 从狩猎假设、组织、恶意软件家族、IOC 或异常关系出发，扩展图谱并发现高价值待验证线索。 | `ThreatHunterAgent` | `agent_app/opencode_app/.opencode/agents/ThreatHunterAgent.md` | 不负责最终归因、一线 IOC 分诊或自动化响应。 |
| 漏洞影响评估 | 从 CVE、漏洞公告或组件漏洞线索出发，映射内部产品、ECU、功能域和暴露面，评估影响范围与修复优先级。 | `VulnerabilityImpactAgent` | `agent_app/opencode_app/.opencode/agents/VulnerabilityImpactAgent.md` | 不替代供应链风险评估、攻击路径预测或自动修复。 |
| 自动化攻击事件报告 | 从已确认事件中提取核心实体，整理关联组织、活动、TTP 和同类风险对象，生成结构化事件报告。 | `IncidentReportingAgent` | `agent_app/opencode_app/.opencode/agents/IncidentReportingAgent.md` | 不负责自动处置、一线分诊或跨事件态势评分。 |

## 命名差异

以下 2 处在“设计文档建议主 Agent 名称”与“当前控制平面 Agent 文件名称”之间存在差异，后续如果继续扩展 Prompt、Skill 或测试，建议优先统一命名：

1. `威胁溯源分析`
   - 设计文档：`ThreatIntelAgent`
   - 当前文件：`ThreatIntelAttributionAnalyst.md`
2. `安全态势感知`
   - 设计文档：`SecurityPostureAgent`
   - 当前文件：`SecuritySituationalAwarenessAgent.md`

## 建议使用方式

1. 新增 Skill 或测试时，先从本清单确认目标业务能力属于哪个主 Agent。
2. 需要查看完整设计约束时，再跳转对应的 `docs/scenarios/*Agent设计.md` 文档。
3. 需要修改实际 Prompt 时，以 `agent_app/opencode_app/.opencode/agents/*.md` 中现有 Agent 文件为落地点，并注意处理命名差异。