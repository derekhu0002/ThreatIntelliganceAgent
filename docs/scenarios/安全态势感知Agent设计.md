# 安全态势感知 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `安全态势感知` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能产出一个态势分数”，而是“有限的上下文窗口应优先留给哪些高价值解释”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛时间窗、分析范围和关注维度，避免在错误边界上聚合无关信号。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多个执行体复制聚合上下文。
3. 当原始信号列表、观察项列表或事件摘要逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.security-posture-awareness`
- `intent_name`: `安全态势感知`
- `intent_level`: `L1`
- `parent_capability`: `安全态势感知`
- `domain`: `threat_intelligence`

### 2.2 业务目标

按固定时间窗聚合威胁情报、漏洞暴露、资产暴露面和安全事件摘要，形成组织级或范围级安全态势结论，输出可解释的总体风险等级、趋势变化、主要驱动因素、重点关注对象和建议动作。

这里的“态势感知”默认是组织级风险汇总与解释能力，而不是单条告警调查、单个 IOC 深挖或自动化响应能力。

### 2.3 典型触发者

- 安全运营主管
- CISO/信息安全总监
- 安全值班人员
- 安全架构师

### 2.4 典型触发表达

- 给我看过去 24 小时的整体安全态势。
- 为什么今天的风险等级从黄色升到了橙色。
- 帮我汇总本周对某产品线影响最大的三个风险点。
- 当前哪些外部威胁和内部暴露面组合最值得优先关注。
- 给我一份适合晨会汇报的态势摘要。

### 2.5 业务边界

本意图负责：

1. 在给定时间窗和范围内聚合多源风险信号。
2. 形成总体风险等级、趋势判断和风险驱动项解释。
3. 输出重点关注对象、观察项和建议动作。
4. 对结果中的分析边界、缺失数据和待确认项做显式说明。

本意图不直接负责：

1. 深挖单条 IOC、单个攻击组织或单起事件的完整成因。
2. 自动执行阻断、隔离、封禁、工单或通知动作。
3. 替代应急响应编排、威胁溯源分析或自动化事件报告等后续业务意图。

如果某个风险驱动项需要继续深挖，应转交 `威胁溯源分析`、`自动化攻击事件报告` 或 `应急响应编排`。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_scope | `op.identify-scope` | 识别时间窗、分析范围、关注维度和输出深度 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认威胁、漏洞、资产、事件和趋势指标的对象边界 | 是 |
| collect_signals | `op.collect-signals` | 拉取时间窗内的原始态势信号 | 是 |
| normalize_signals | `op.normalize-signals` | 去重、对齐时间窗、统一口径并压缩长列表 | 是 |
| assess_posture | `op.assess-posture` | 计算态势等级、趋势变化和风险驱动项 | 是 |
| compose_report | `op.compose-report` | 生成结构化态势报告 | 是 |

### 3.2 操作顺序

`identify_scope -> discover_source -> inspect_schema -> collect_signals -> normalize_signals -> assess_posture -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接聚合大结果并输出态势结论。

### 3.3 每个操作意图的职责

#### identify_scope

输入是自然语言或结构化态势请求；输出是标准化分析范围。

最少要完成：

1. 识别 `time_window`。
2. 识别 `scope`，例如 `organization`、`product_line`、`business_domain`。
3. 提取 `focus_dimension` 和 `report_depth`。
4. 判断用户要的是值班快照、管理摘要还是标准分析报告。
5. 若时间窗、范围或关注维度存在明显分叉，则优先通过少量高价值问题向用户澄清。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 确认漏洞/风险数据源是否可用。
3. 确认内部资产暴露面或范围映射数据是否可用。
4. 确认安全事件或告警摘要数据是否可用。
5. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认威胁、漏洞、资产、事件等对象的关键字段。
2. 确认哪些字段可用于计数、聚合和时间窗过滤。
3. 明确哪些是直接事实，哪些只能作为推断依据。
4. 明确哪些字段可用于趋势比较和范围过滤。

#### collect_signals

最少要完成：

1. 拉取时间窗内的威胁活跃度信号。
2. 拉取时间窗内的漏洞暴露信号。
3. 拉取时间窗内的事件热度信号。
4. 拉取当前范围内的资产暴露敏感度信号。
5. 若可用，再补充行业外部趋势信号。

#### normalize_signals

最少要完成：

1. 去重重复对象和重复命中。
2. 统一时间窗和聚合口径。
3. 将长列表压缩为稳定中间产物，例如 Top 风险对象、变化摘要和观察项。
4. 标记缺失数据、低置信度结果和待人工确认项。

#### assess_posture

最少要完成：

1. 基于威胁活跃度、漏洞暴露度、事件热度和资产暴露敏感度计算总体态势分数。
2. 区分主信号和增强信号，避免行业趋势等弱信号直接主导总体等级。
3. 输出总体等级、趋势方向和前三风险驱动项。
4. 将低置信度结果降级为观察项或待确认项。
5. 当态势等级发生变化时，必须输出显式驱动原因。

#### compose_report

最少要完成：

1. 输出摘要、总体等级、趋势解释、风险驱动项和重点关注对象。
2. 输出观察项、建议动作和证据边界说明。
3. 生成为前端展示和后续系统消费都可使用的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260504-posture-001",
  "intent_id": "biz.security-posture-awareness",
  "scenario_id": "posture.window-summary",
  "time_window": {
    "from": "2026-05-03T00:00:00Z",
    "to": "2026-05-04T00:00:00Z"
  },
  "scope": {
    "type": "organization",
    "value": "enterprise-all"
  },
  "analyst_id": "soc-manager-001",
  "requested_at": "2026-05-04T08:00:00Z",
  "slots": {
    "focus_dimension": ["threat", "vulnerability", "incident", "trend"],
    "report_depth": "standard",
    "include_watchlist": true
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "min_posture_score_confidence": 0.7,
    "require_explanation_for_level_change": true
  },
  "role_policy": {
    "initiator_role": "SecurityPostureConsumer",
    "execution_role": "SecurityPostureAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "security_posture_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| time_window | 是 | 本次态势分析的时间窗 |
| scope | 是 | 组织、产品线或业务域范围 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与评分策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| focus_dimension | 否 | 关注威胁、漏洞、暴露、事件或趋势 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| include_watchlist | 否 | 是否显式输出观察项清单 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模信号聚合，而应先做定向澄清：

1. 用户要的是值班快照、管理摘要还是标准态势报告。
2. 用户更关注总体风险等级、趋势变化还是重点对象。
3. 当前时间窗和范围是否已经足够明确到可以进入默认链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| SecurityPostureAgent | 默认唯一执行 AGENT，负责聚合信号、评估态势、生成报告并控制输出边界 | 是 |
| SecurityPostureConsumer | 人类使用者或外部消费角色，负责提交范围和时间窗、消费结果并发起后续追问 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `SecurityPostureConsumer`，允许其提交 `biz.security-posture-awareness` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`collect_signals` 或 `assess_posture`。
2. 若 `identify_scope` 阶段发现时间窗、范围或输出目标存在明显分叉，默认先进入澄清分支，而不是立即进入聚合分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `SecurityPostureAgent`。
4. 当原始信号、事件摘要或观察项列表开始挤占后续推理窗口时，`SecurityPostureAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 若用户转向单 IOC、单事件或单攻击组织的深挖问题，应显式路由到对应业务意图，而不是让态势 AGENT 硬扛深度调查。

### 5.3 路由伪代码

```text
if intent_id == biz.security-posture-awareness:
    if current_role == SecurityPostureConsumer:
        delegate_to(SecurityPostureAgent)
    else:
        if need_clarification():
            ask_high_value_questions()
        else:
            execute_pipeline()
```

## 6. Tool 设计与调用边界

### 6.1 正式工具入口

本业务意图访问外部数据的正式入口应为统一查询工具，例如：

- `ai4x_query.catalog`
- `ai4x_query.schema`
- `ai4x_query.query`

如果后续存在专门的态势聚合工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求或假定任意指标接口存在。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_scope | 无需外部工具或仅轻量解析工具 | 不得臆造时间窗或范围 |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| collect_signals | `ai4x_query.query` | 不得绕过平台直连底层库 |
| normalize_signals | 内部整理逻辑或上下文治理类 SKILL | 不得把未经去重的长列表直接当最终事实 |
| assess_posture | 内部评分逻辑 | 不得输出无解释链的等级结论 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略边界与缺失数据说明 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 优先拉取 `ai4x_platform` 已注册数据源中的威胁、漏洞、暴露面、功能和需求信号
4. 第二轮 `query` 补充趋势比较、重点对象明细，以及必要的功能域或需求域映射
5. 若需要漏洞代理能力，单独调用 `POST /api/v1/cve2oss/query`
6. 若需要事件热度信号，读取外部事件摘要源或等待其注册为新的 `source_id`
7. 内部信号归一化
8. 内部态势评估
9. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象数据湖假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `安全态势感知` 不能假定“事件摘要源”“通用资产台账源”或任意指标接口已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或后续待接入能力。

#### 平台已注册数据源与态势信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，不是每个数据源都直接产出态势分数，但它们共同决定了“威胁活跃度、漏洞暴露度、资产暴露敏感度、控制覆盖解释”能否闭环。

#### `opencti`（外部威胁情报源）

用途：提供外部威胁活跃度和威胁对象语义，是态势中的威胁活跃信号主来源。

根据 `INTRODUCTION`，`opencti` 不是一个固定字段表，而是一套 STIX 2.1 聚合目录；首版不应假定 57 份 Schema 全量消费，而应先锁定少量代表类型。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `indicator`（指标） | `name`、`valid_from`、`valid_until`、`confidence` | 统计当前时间窗内仍有效且高可信的 IOC 信号 | 避免把低质量或过期情报直接拉高态势 |
| `intrusion-set`（入侵组织） / `threat-actor`（威胁行为体） | `name`、`confidence`、`last_seen` | 识别当前范围内高活跃组织或行为体 | 用于构成威胁活跃度主信号 |
| `malware`（恶意软件）、`attack-pattern`（攻击模式）、`vulnerability`（漏洞）、`report`（报告） | `name`、`description`、`kill_chain_phases` 或等价字段 | 为驱动项和重点对象补充解释语义 | 让态势报告可被运营和管理层消费 |

#### `cve2oss`（CVE 查询代理数据源）

用途：提供平台内置的漏洞代理能力，是态势中的漏洞暴露信号入口之一。

根据 `INTRODUCTION`，`cve2oss` 不是 STIX Bundle，而是一个接口型 Schema；调用时不能走统一 Cypher 查询，而应直接访问 `POST /api/v1/cve2oss/query`。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id` | 按漏洞编号拉取代理结果 | 这是平台当前明确提供的漏洞代理入口 |
| 成功响应 | `success`、`total`、`datalist` | 判断是否命中相关漏洞条目 | 用于构成漏洞事实层 |
| `datalist` 白名单字段 | `CVEID`、`PROD_CN_NAME`、`EDITION_CODE`、`LDY_NAME`、`HWPSIRTID` | 将 CVE 与产品、版本或厂内标识做映射 | 让漏洞信号能落到真实产品范围，而不是停留在外部公告层 |

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：提供车辆内外部边界与暴露面，是态势中的资产暴露敏感度主来源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-vehicle-ecu`（车辆 ECU） | `id`、`name`、`x_ecu_type`、`x_software_version`、`x_domain_tag` | 识别范围内关键 ECU、版本分布和域归属 | 让态势结果落到真实资产对象 |
| `x-exposure-surface`（暴露面） | `id`、`name`、`description`、`x_domain_tag` | 识别对外暴露入口和暴露变化 | 用于构成暴露敏感度信号 |
| `x-external-peer`（外部对端）、`network-traffic`（网络流量）、`relationship`（关系） | `name`、`protocols`、`src_ref`、`dst_ref`、`source_ref`、`target_ref` | 补充暴露链路和连接上下文 | 用于解释为什么某个范围当前更敏感 |

#### `tara`（威胁分析与风险评估数据源）

用途：提供威胁分析与风险评估对象，是态势中的风险语义增强源，而不是单独的事件热度源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-threat-scenario`（威胁场景） | `threat_id`、`stride`、`attack_vector`、`cal` | 用于解释当前风险驱动项属于哪类威胁场景 | 让态势结论与既有 TARA 模型对齐 |
| `x-attack-path`（攻击路径）、`x-attack-feasibility`（攻击可行性） | 路径描述、可行性相关字段 | 识别高风险路径或高可行性风险模式 | 为态势升降级提供模型侧解释 |
| `x-tara-risk`（TARA 风险）、`x-damage-scenario`（损害场景）、`x-impact-assessment`（影响评估） | `rating`、影响评分等字段 | 提供风险评级和潜在影响说明 | 防止态势只有热度没有风险语义 |

#### `ses`（网络安全需求数据源）

用途：提供网络安全需求，是态势中的控制覆盖与整改解释源。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-cybersecurity-requirement`（网络安全需求） | `keywords/labels`、`cybersecurity_goal`、`cybersecurity_measure`、`text`、`x_domain_tag` | 将高风险对象映射到已定义控制和整改语义 | 让建议动作可以落到内部要求而不是空泛建议 |

#### `vehicle_func`、`ecu_func`、`func_design_spec`（车辆功能、ECU 控制器与功能设计规格数据源）

用途：这三类数据源不是态势分数的直接主信号，但它们决定范围过滤、功能上卷和管理层解释是否成立。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `vehicle_func` | `function_id`、`function_name`、`related_ecus`、`x_domain_tag` | 将 ECU 或风险对象上卷到功能层 | 便于输出产品线或业务域态势摘要 |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从 ECU 反查功能归属 | 避免态势结果只停留在底层技术对象 |
| `func_design_spec` | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 为重点风险点补设计语境和说明文字 | 让管理摘要更可读、更贴近设计评审语境 |

#### 事件热度信号的边界说明

`INTRODUCTION` 中当前并没有把“事件摘要”或“告警汇总”列为已注册 `source_id`。因此本场景对事件热度的处理必须明确分成两种状态：

1. 若外部事件源尚未接入 `ai4x_platform`，则事件热度属于外部补充信号，不能被表述为平台原生数据能力。
2. 若后续把事件摘要注册为新的 `source_id`，则应先补 Schema，再把它纳入 `collect_signals` 的正式查询链路。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造字段。
2. 再用 `opencti`、`cve2oss`、`vehicle_iobe` 提取威胁、漏洞和暴露事实层。
3. 再用 `tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec` 做风险语义增强、功能上卷和控制解释。
4. 对尚未注册到平台的事件热度源，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑直接受 `ai4x_platform` 的三个实现边界约束：

1. 统一查询虽暴露为 Cypher 接口，但对 MongoDB 和 OpenCTI 实际上是受限子集翻译，不能假定任意查询表达式都可用。
2. `cve2oss` 是独立代理接口，不应被误写成统一图查询数据源。
3. 当前平台已注册的数据源范围就是态势设计的最小事实边界，超出部分必须标记为待接入而不是默认存在。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `安全态势感知` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.security-posture.window-summary`
- `skill_name`: `时间窗安全态势汇总`
- `bind_intent_id`: `biz.security-posture-awareness`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象包含明确时间窗和分析范围。
2. 请求目标是查看整体风险等级、趋势变化或重点风险项。
3. 用户要求生成值班快照、管理摘要或标准态势报告。

在第一阶段，即便用户只给出时间窗而未明确范围，也允许由主 SKILL 承接，但必须先进入澄清分支补齐最小槽位。

### 7.4 主 SKILL SOP

1. 识别时间窗、分析范围和输出目标。
2. 若时间窗、范围或关注维度不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 拉取时间窗内的威胁、漏洞、事件和资产暴露信号。
7. 对原始信号做去重、归一化和变化摘要压缩。
8. 若中间结果已形成长列表、长观察项或长事件摘要，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
9. 计算总体等级、趋势方向和驱动项排序。
10. 输出结构化报告，并明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 总体态势等级。
2. 趋势方向和变化原因。
3. 前三风险驱动项。
4. 重点关注对象或观察项。
5. 建议动作。
6. 缺失数据和边界说明。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.security-posture.window-summary` | 覆盖最稳定的默认链路 | 是 |
| 输入范围特化 SKILL | `skill.security-posture.product-line` | 针对某产品线或业务域优化聚合逻辑 | 否 |
| 输出目的特化 SKILL | `skill.security-posture.briefing` | 针对晨会或管理层汇报输出简版摘要 | 否 |
| 高负载辅助 SKILL | `skill.security-posture.signal-condense` | 压缩长观察项、长事件摘要和大对象列表 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.security-posture-awareness`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当分析范围、聚合口径、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.security-posture.window-summary`，跑通默认态势汇总链路。
2. 第二阶段：当不同范围的聚合口径稳定分化后，再按输入范围拆分扩展 SKILL。
3. 第三阶段：当“值班快照”和“管理层态势简报”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长观察项、海量对象或长时间序列比较成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260504-posture-001",
  "intent_id": "biz.security-posture-awareness",
  "time_window": {
    "from": "2026-05-03T00:00:00Z",
    "to": "2026-05-04T00:00:00Z"
  },
  "scope": {
    "type": "organization",
    "value": "enterprise-all"
  },
  "summary": "过去 24 小时整体态势由黄色升为橙色，主要由高危漏洞命中增加、关键暴露面扩大和高置信威胁组织活跃度上升共同驱动。",
  "overall_posture": {
    "level": "orange",
    "score": 78,
    "confidence": 0.81,
    "trend": "up"
  },
  "direct_facts": [
    "过去 24 小时新增 3 个高危漏洞命中关键资产",
    "对外暴露高敏资产数量较上一时间窗增加 2 个",
    "2 个高置信 intrusion-set 在当前关注行业内活跃度上升"
  ],
  "inferred_assessments": [
    "当前总体风险已从常规观察升级为重点关注",
    "漏洞暴露与外部威胁活跃度叠加是本次等级上升的主要原因"
  ],
  "top_risk_drivers": [
    {
      "name": "高危漏洞暴露扩大",
      "dimension": "vulnerability",
      "reason": "关键资产命中新高危漏洞且仍处于暴露状态"
    },
    {
      "name": "关键暴露面增加",
      "dimension": "exposure",
      "reason": "新增外网可达高敏接口"
    },
    {
      "name": "外部威胁活跃度上升",
      "dimension": "threat",
      "reason": "高置信攻击组织与当前行业相关活动增多"
    }
  ],
  "watch_items": [
    "观察某产品线的新增暴露面是否在下一个时间窗继续扩大",
    "跟踪两个高危漏洞的修复进度和资产确认状态"
  ],
  "recommended_actions": [
    "立即关注关键资产上的高危漏洞修复状态",
    "持续观察新增暴露面的变化和防护加固情况",
    "对与当前活跃组织相关的 IOC 命中进行定向复核"
  ],
  "analysis_boundary": "本次结论基于已接入的威胁情报、漏洞映射、资产暴露面和事件摘要；未接入的外部行业基准数据未纳入总体分数。",
  "generated_at": "2026-05-04T08:05:00Z"
}
```

### 8.2 输出规则

1. `direct_facts` 与 `inferred_assessments` 必须分开。
2. 总体等级必须同时附带 `score`、`confidence` 和 `trend`。
3. 每个等级变化都必须能映射到至少一个明确的风险驱动项。
4. 低置信度结果只能进入 `watch_items` 或边界说明，不能直接拉高总体等级。
5. 当没有足够证据时，允许输出“未形成稳定等级变化结论”的空变化报告。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.security-posture-awareness`。
2. 决定具体场景，例如 `posture.window-summary`、`posture.briefing`。
3. 在方向不清时优先发起高价值澄清，收敛时间窗、范围、关注维度和输出深度。
4. 生成或补齐 Intent Envelope。
5. 决定是否可以由单 AGENT 直接完成，还是需要在高上下文负载场景下创建临时附属 AGENT。

### 9.3 Skill Orchestrator 责任

1. 加载对应 Skill。
2. 按顺序触发 L2 操作意图。
3. 在中间结果过长时优先调用上下文治理类 SKILL。
4. 收集中间结果并传递给下一步。
5. 汇总最终报告。

在默认情况下，全部中间状态都由主 AGENT 自己维护。

### 9.4 Tool Policy Guard 责任

1. 限制只有主执行 AGENT 或其经授权的临时附属 AGENT 才能执行查询型操作意图。
2. 限制工具调用顺序为 `catalog -> schema -> query`。
3. 拒绝未授权的直连访问。
4. 校验输出中是否分离事实与推断。
5. 校验等级变化是否附带显式驱动原因。

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当时间窗、范围或输出目标不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本聚合。
3. 处理 `biz.security-posture-awareness` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及态势等级时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.security-posture-awareness":
        route_elsewhere()

    if need_clarification(envelope):
        return ask_for_clarification(
            topics=["time_window", "scope", "focus_dimension", "report_depth"]
        )

    skill = skill_orchestrator.load(
        "skill.security-posture.window-summary",
        envelope
    )

    tool_policy_guard.authorize("SecurityPostureAgent", envelope)

    scope = run_identify_scope(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    raw_signals = run_collect_signals(skill, envelope, schema)
    normalized_signals = run_normalize_signals(skill, envelope, raw_signals)

    if should_compact_in_current_session(normalized_signals):
        normalized_signals = run_context_governance_skill(
            "skill.security-posture.signal-condense",
            normalized_signals
        )

    posture = run_assess_posture(skill, envelope, normalized_signals)
    report = run_compose_report(skill, envelope, posture)
    return report
```

## 10. 验收标准

首版设计至少应满足以下验收标准：

1. 使用者能看懂为什么当前是这个风险等级。
2. 使用者能知道相比上一个时间窗为什么升降级。
3. 使用者能快速识别当前最值得关注的 3 个风险点。
4. 使用者能分辨哪些是直接事实，哪些仍需人工确认。
5. 系统在缺失部分数据源时，能显式说明分析边界而不是假装结论完整。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/security-posture/manifest.json](../../sample/security-posture/manifest.json)。

### 11.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于提供活跃威胁组织、IOC 和漏洞利用语境。
2. `vehicle_iobe`：导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)，用于提供对外暴露面和高敏 ECU。
3. `tara`、`ses`：分别导入 [sample/shared/tara_bundle.json](../../sample/shared/tara_bundle.json) 和 [sample/shared/ses_bundle.json](../../sample/shared/ses_bundle.json)，用于补风险语义与控制要求。
4. `vehicle_func`、`ecu_func`、`func_design_spec`：分别导入 [sample/shared/vehicle_func_bundle.json](../../sample/shared/vehicle_func_bundle.json)、[sample/shared/ecu_func_bundle.json](../../sample/shared/ecu_func_bundle.json)、[sample/shared/func_design_spec_bundle.json](../../sample/shared/func_design_spec_bundle.json)，用于补功能上卷、ECU 职责和设计语境。
5. `cve2oss` 不可导入，应按 [sample/security-posture/manifest.json](../../sample/security-posture/manifest.json) 中的 `non_importable_fixtures` 作为查询夹具使用。

### 11.2 推荐验证请求

1. 直接使用 [sample/security-posture/manifest.json](../../sample/security-posture/manifest.json) 中的 `request_fixture`。
2. 时间窗为 `2026-05-03T00:00:00Z` 到 `2026-05-04T00:00:00Z`，范围为 `enterprise-all`。

### 11.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
请基于 2026-05-03T00:00:00Z 到 2026-05-04T00:00:00Z 的时间窗，评估 enterprise-all 的整体安全态势，重点汇总 threat、exposure、vulnerability 三个维度，并给出适合管理层阅读的摘要结论。
```

### 11.4 预期验证点

1. 风险驱动至少覆盖 `threat`、`exposure`、`vulnerability` 三个维度。
2. 能把 `APT29 / Northern Relay Campaign`、`tbox-4g` 等暴露面、以及 `CVE-2026-12345` 归并到统一态势结论。
3. 能在结论中说明 `cve2oss` 和外部事件热度属于补充信号，而不是原生可导入事实。
