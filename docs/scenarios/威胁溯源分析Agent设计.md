# 威胁溯源分析 - 业务意图到 AGENT 实现设计

## 1. 设计目标

本文档将 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中的业务意图 `威胁溯源分析` 继续向下展开，形成一条可落地的设计链：

1. 业务意图定义。
2. 业务意图与操作意图映射。
3. Intent Envelope 统一请求契约。
4. Agent 角色分工与路由规则。
5. Skill / Tool 约束。
6. 输出契约与验收标准。
7. 最终 AGENT 实现建议。

本文档的目标不是描述某个具体代码实现细节，而是给后续 Prompt、Skill、Tool 和前端场景入口提供统一的设计基线。

本文档同时受通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 约束。对本场景而言，最重要的设计前提不是单纯“能不能完成溯源”，而是“有限的上下文窗口应优先留给哪一段推理”。因此，本场景设计默认遵循以下优先顺序：

1. 先通过必要澄清收敛分析目标，避免在错误方向上消耗 token。
2. 再由单一主 AGENT 执行默认链路，避免过早引入多执行体。
3. 当材料逐步变长时，优先在当前 session 内通过上下文治理类 SKILL 做压缩。
4. 只有当前 session 无法同时容纳原始材料、治理过程与后续推理时，才创建附属 AGENT 隔离长上下文。

## 2. 业务意图定义

### 2.1 意图标识

- `intent_id`: `biz.threat-attribution`
- `intent_name`: `威胁溯源分析`
- `intent_level`: `L1`
- `parent_capability`: `威胁溯源分析`
- `domain`: `threat_intelligence`

### 2.2 业务目标

从一个外部线索出发，例如 `IP`、`domain-name`、`file hash`、`malware` 或 `TTP`，追溯其背后的攻击组织、历史活动、惯用战术技术、攻击工具、目标行业和潜在风险，输出一份可解释、可追溯的溯源分析报告。

### 2.3 典型触发者

- 安全事件分析师
- 安全运营中心分析师
- 情报分析专员
- 威胁狩猎工程师

### 2.4 典型触发表达

- 这个 IP 背后是不是某个 APT 组织。
- 这个域名和哪些攻击组织有关。
- 帮我追溯这个 HASH 的历史活动。
- 这个 IOC 是否和已知攻击团伙有关。
- 给我一份从 IP 到组织再到 TTP 的完整链路。

### 2.5 业务边界

本意图负责：

1. 从线索出发做事实查询和图谱扩展。
2. 做组织归因候选排序。
3. 形成证据路径和风险结论。
4. 输出后续调查建议。

本意图不直接负责：

1. 在内部日志系统中进行全量检索。
2. 自动执行阻断、隔离、封禁。
3. 直接发起应急响应流程。

如果分析结果需要进一步处置，应转交 `应急响应编排` 或其他后续业务意图。

## 3. 业务意图与操作意图映射

### 3.1 L2 操作意图总览

| L2 操作意图 | operation_intent_id | 作用 | 是否必需 |
| --- | --- | --- | --- |
| identify_target | `op.identify-target` | 识别输入线索类型和值，补齐最小槽位 | 是 |
| discover_source | `op.discover-source` | 确认可用数据源与访问范围 | 是 |
| inspect_schema | `op.inspect-schema` | 确认对象类型、字段和关系边界 | 是 |
| query_fact | `op.query-fact` | 查询输入线索的一跳直接事实 | 是 |
| expand_relation | `op.expand-relation` | 从一跳事实向组织、技术、工具、活动扩展 | 是 |
| assess_confidence | `op.assess-confidence` | 对归因候选做证据强度与可信度评估 | 是 |
| compose_report | `op.compose-report` | 生成结构化溯源报告 | 是 |

### 3.2 操作顺序

`identify_target -> discover_source -> inspect_schema -> query_fact -> expand_relation -> assess_confidence -> compose_report`

该顺序是默认顺序，不允许跳过前三步直接臆造查询字段。

### 3.3 每个操作意图的职责

#### identify_target

输入是自然语言或结构化 IOC 请求；输出是标准化目标对象。

最少要完成：

1. 判断 `target_type` 是 `ip`、`domain`、`hash`、`malware` 还是 `ttp`。
2. 解析 `target_value`。
3. 提取用户是否要求补充 `time_range`、`focus_dimension`、`report_depth`。
4. 若分析目标、输出深度或关注维度存在明显分叉，则优先通过少量高价值问题向用户澄清。
5. 若关键槽位缺失，则要求前端或对话补齐。

#### discover_source

最少要完成：

1. 确认 `opencti` 是否可用。
2. 判断 `ai4x_platform` 当前已注册数据源中，是否还需要 `cve2oss`、`vehicle_iobe`、`tara`、`ses` 等源作为补充解释来源。
3. 若需要事件日志、沙箱结果或平台外商业情报 feed，必须标记为外部补充源，而不是假定其已作为原生 `source_id` 存在。
4. 记录本次允许访问的数据源列表和缺失源。

#### inspect_schema

最少要完成：

1. 确认 `ipv4-addr`、`domain-name`、`indicator`、`infrastructure`、`malware`、`attack-pattern`、`intrusion-set` 等对象结构。
2. 确认关系边，例如 `related-to`、`indicates`、`uses`、`targets`、`located-at`。
3. 明确哪些字段属于直接事实，哪些只能作为推导依据。

#### query_fact

最少要完成：

1. 查询输入对象本体。
2. 查询该对象被哪些 indicator、infrastructure 或 observed-data 引用。
3. 返回第一轮事实结果，不混入推断结论。

#### expand_relation

最少要完成：

1. 从输入线索扩展到关联 malware、attack-pattern、intrusion-set。
2. 聚合组织历史活动、目标行业、地域和工具使用记录。
3. 构建从输入线索到候选组织的证据路径。

#### assess_confidence

最少要完成：

1. 对每个候选组织计算证据强度。
2. 区分多源交叉验证与单点命中。
3. 将直接证据与间接推断分层表达。
4. 对低于阈值的结果降级为待验证线索。

#### compose_report

最少要完成：

1. 输出摘要、证据路径、组织候选、TTP、工具、时间线和建议。
2. 说明分析边界、置信度、未证实部分。
3. 生成适合前端展示和后续系统消费的结构化结果。

## 4. Intent Envelope 设计

### 4.1 请求结构

```json
{
  "request_id": "req-20260503-001",
  "intent_id": "biz.threat-attribution",
  "scenario_id": "threat-attribution.ip-trace",
  "target_type": "ip",
  "target_value": "185.130.5.253",
  "analyst_id": "soc-001",
  "requested_at": "2026-05-03T10:30:00Z",
  "time_range": {
    "from": null,
    "to": null
  },
  "slots": {
    "focus_dimension": ["intrusion-set", "attack-pattern", "malware"],
    "report_depth": "standard",
    "need_asset_impact": false
  },
  "evidence_policy": {
    "separate_fact_and_inference": true,
    "min_confidence_threshold": 0.65,
    "require_multi_source_for_attribution": true
  },
  "role_policy": {
    "initiator_role": "ThreatIntelSecOps",
    "execution_role": "ThreatIntelAgent",
    "support_agent_role": "ContextSupportAgent"
  },
  "output_profile": "trace_report_v1"
}
```

### 4.2 核心槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| request_id | 是 | 请求唯一标识 |
| intent_id | 是 | 顶层业务意图 |
| scenario_id | 是 | 具体入口场景 |
| target_type | 是 | 线索类型 |
| target_value | 是 | 线索值 |
| analyst_id | 是 | 发起人 |
| requested_at | 是 | 发起时间 |
| evidence_policy | 是 | 证据与推断策略 |
| role_policy | 是 | 角色约束 |
| output_profile | 是 | 输出模板 |

### 4.3 场景扩展槽位

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| time_range | 否 | 限制分析窗口 |
| focus_dimension | 否 | 关注组织、技术、工具或受害行业 |
| report_depth | 否 | `brief` / `standard` / `deep` |
| need_asset_impact | 否 | 是否继续映射内部资产影响 |

### 4.4 方向治理约束

当以下信息未明确时，主 AGENT 不应直接进入大规模查询或深度扩图，而应先做定向澄清：

1. 用户要的是快速研判、标准报告还是深度归因。
2. 用户更关注攻击组织、TTP、工具画像，还是内部资产影响。
3. 当前输入对象是否已经足够明确到可以进入默认查询链路。

这一约束对应通用原则中的“用户澄清优先原则”，其目的不是增加交互轮次，而是减少错误方向上的无效 token 消耗。

## 5. 角色与路由设计

### 5.1 角色职责

| 角色 | 职责 | 是否直接调用查询工具 |
| --- | --- | --- |
| ThreatIntelAgent | 默认唯一执行 AGENT，负责识别业务意图、执行查询、构建证据路径、生成报告并控制输出边界 | 是 |
| ThreatIntelSecOps | 人类使用者或外部消费角色，负责提交线索、消费结果、发起后续处置 | 否 |

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“单 AGENT 优先原则”和“附属 AGENT 创建原则”。

### 5.2 路由规则

1. 如果入口来自 `ThreatIntelSecOps`，允许其提交 `biz.threat-attribution` 请求，但不允许其直接执行 `discover_source`、`inspect_schema`、`query_fact`、`expand_relation`。
2. 若 `identify_target` 阶段发现目标、输出深度或关注维度存在明显分叉，默认先进入澄清分支，而不是立即进入查询分支。
3. 默认路由器始终将该业务意图交给单一执行 AGENT `ThreatIntelAgent`。
4. 当局部材料开始挤占后续推理窗口时，`ThreatIntelAgent` 应先尝试在当前 session 内调用上下文治理类 SKILL；只有仍无法承载后续推理时，才把局部任务下放给临时附属 AGENT。
5. 多组织归因冲突的复核，默认仍由 `ThreatIntelAgent` 在单次流程内完成，而不是自动升级为多 AGENT 协作。

### 5.3 路由伪代码

```text
if intent_id == biz.threat-attribution:
    if current_role == ThreatIntelSecOps:
    delegate_to(ThreatIntelAgent)
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

如果后续存在专门的威胁情报工具，也应服从相同的意图层约束，而不是让 Prompt 直接拼接任意 HTTP 请求。

### 6.2 Tool 与操作意图映射

| 操作意图 | 允许工具 | 禁止行为 |
| --- | --- | --- |
| identify_target | 无需外部工具或仅轻量解析工具 | 不得臆造 target_type |
| discover_source | `ai4x_query.catalog` | 不得跳过 catalog 假定数据源存在 |
| inspect_schema | `ai4x_query.schema` | 不得凭经验猜字段 |
| query_fact | `ai4x_query.query` | 不得绕过平台直连底层库 |
| expand_relation | `ai4x_query.query` | 不得把推导结果当直接事实返回 |
| assess_confidence | 内部评分逻辑 | 不得输出无证据支撑的高置信归因 |
| compose_report | 模板生成器或 Agent 内部生成逻辑 | 不得省略证据边界说明 |

### 6.3 默认查询节奏

1. `catalog`
2. `schema`
3. 第一轮 `query` 优先在 `ai4x_platform` 已注册数据源中查询输入线索事实
4. 第二轮 `query` 扩展关联组织、技术、工具和证据链
5. 若需要漏洞代理能力，单独调用 `POST /api/v1/cve2oss/query`
6. 若需要资产映射、暴露面或风险语义，则继续查询 `vehicle_iobe`、`tara`、`ses`
7. 内部置信度评估
8. 报告生成

### 6.4 数据源、对象与字段使用逻辑

本节必须以 `ai4x_platform` 的产品说明和当前已注册数据源为准，而不是按抽象威胁情报平台假设任意扩写。根据 `D:\Projects\AI4X-Platform\INTRODUCTION.md`，当前平台的最小接入路径是：

1. 调用 `GET /api/v1/api-center/schema/catalog` 或 `GET /api/v1/api-center/schema/summaries` 确认可用 `source_id`。
2. 调用 `GET /api/v1/api-center/schema/{source_id}` 获取完整 Schema。
3. 对对象型数据源调用 `POST /api/v1/api-center/query/universal` 发起只读查询。
4. 对漏洞代理能力单独调用 `POST /api/v1/cve2oss/query`。

这意味着 `威胁溯源分析` 不能假定 `mitre_attack`、任意商业情报 feed、沙箱平台或事件日志系统已经作为 `ai4x_platform` 原生数据源存在；首版必须围绕当前已注册的 8 个 `source_id` 组织分析逻辑，再把缺失信号声明为外部补充项或后续待接入能力。

#### 平台已注册数据源与溯源信号映射

`ai4x_platform` 当前已注册的数据源包括：`vehicle_iobe`、`tara`、`ses`、`vehicle_func`、`ecu_func`、`func_design_spec`、`cve2oss`、`opencti`。对本场景而言，真正构成溯源主链路的是 `opencti`，其余数据源主要承担资产语境、风险语义和整改解释的补充作用。

#### `opencti`（外部威胁情报源）

用途：提供外部威胁情报对象、关系和归因候选，是威胁溯源分析的主事实来源。

根据 `INTRODUCTION`，`opencti` 不是固定字段表，而是一套 STIX 2.1 聚合目录；首版应先锁定少量代表类型，而不是假定 57 份 Schema 全量消费。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `ipv4-addr`（IPv4 地址）、`domain-name`（域名）、`file`（文件）、`url`（URL 地址） | `value` 或等价标识字段 | 作为输入线索本体或一跳观测对象 | 这是溯源链的起点对象 |
| `indicator`（指标） | `name`、`pattern`、`valid_from`、`valid_until`、`confidence` | 判断 IOC 的有效性、可信度和被引用情况 | 避免把低质量或过期信号直接提升为高置信证据 |
| `infrastructure`（基础设施）、`malware`（恶意软件）、`attack-pattern`（攻击模式） | `name`、`description`、`kill_chain_phases` | 将 IOC 扩展到基础设施、恶意软件和攻击技术 | 用于构建从线索到行为模式的中间证据层 |
| `intrusion-set`（入侵组织） / `threat-actor`（威胁行为体） | `name`、`description`、`confidence`、`last_seen` | 形成候选归因对象 | 这是威胁溯源报告的核心候选结论 |
| `relationship`（关系）、`sighting`（观测）、`observed-data`（观测数据）、`report`（报告） | `relationship_type`、`source_ref`、`target_ref`、时间相关字段 | 构建证据路径、活动时间线和上下文出处 | 让归因结论可追溯而不是只剩静态标签 |

#### `vehicle_iobe`（车辆内外部边界与暴露面数据源）

用途：为 IOC 或基础设施补充内部资产暴露语境，不是归因主事实源，但在“是否影响我方范围”这一层很有价值。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-exposure-surface`（暴露面） | `id`、`name`、`description`、`x_domain_tag` | 将外部 IOC 映射到已知暴露面或入口语境 | 用于解释该 IOC 为什么值得优先关注 |
| `x-vehicle-ecu`（车辆 ECU）、`x-external-peer`（外部对端）、`network-traffic`（网络流量）、`relationship`（关系） | `name`、`protocols`、`src_ref`、`dst_ref`、`source_ref`、`target_ref` | 判断该 IOC 是否与内部连接边界或关键 ECU 相关 | 让溯源结果从“外部归因”延伸到“对我方的相关性” |

#### `tara`（威胁分析与风险评估数据源）

用途：提供威胁场景和风险语义，用于解释某个归因对象或技术链条在本域中的风险含义，而不是替代 OpenCTI 做归因。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-threat-scenario`（威胁场景） | `threat_id`、`stride`、`attack_vector`、`description` | 将已识别的攻击技术或基础设施映射到已建模威胁场景 | 用于补足业务风险解释 |
| `x-attack-path`（攻击路径）、`x-attack-feasibility`（攻击可行性）、`x-tara-risk`（TARA 风险） | 路径、可行性、风险评级相关字段 | 解释该归因对象为何对当前系统更具现实风险 | 让报告不只停留在外部情报层 |

#### `ses`（网络安全需求数据源）

用途：提供网络安全需求与控制语义，用于把溯源结果落到防御和整改建议。

| 对象类型 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `x-cybersecurity-requirement`（网络安全需求） | `keywords/labels`、`cybersecurity_goal`、`cybersecurity_measure`、`text`、`x_domain_tag` | 按攻击技术、风险对象或目标域检索相关控制要求 | 让输出建议可对应内部控制语言 |

#### `cve2oss`（CVE 查询代理数据源）

用途：不是主归因数据源，但当 IOC、恶意软件或报告中明确关联 CVE 时，可作为漏洞代理补充源。

根据 `INTRODUCTION`，`cve2oss` 是独立代理接口，不应通过统一 Cypher 查询访问。

| 接口或字段 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `POST /api/v1/cve2oss/query` | `cve_id` | 按明确的漏洞编号拉取代理结果 | 用于补充漏洞侧事实，不替代主溯源链 |
| 成功响应 | `success`、`total`、`datalist` | 判断 CVE 是否命中相关产品或版本 | 用于连接“外部归因线索”和“产品影响线索” |

#### `vehicle_func`、`ecu_func`、`func_design_spec`（车辆功能、ECU 控制器与功能设计规格数据源）

用途：这三类数据源不是溯源归因的主信号，但在需要把外部线索上卷到功能层、ECU 层或设计语境时非常有用。

| 数据源 | 关键字段 | 怎么使用 | 为什么要用 |
| --- | --- | --- | --- |
| `vehicle_func` | `function_id`、`function_name`、`related_ecus`、`x_domain_tag` | 将受影响 ECU 或暴露对象上卷到功能域 | 便于把威胁溯源结果转给业务方 |
| `ecu_func` | `ecu_name`、`related_functions`、`x_domain_tag` | 从 ECU 反查功能归属 | 避免报告只停留在底层技术对象 |
| `func_design_spec` | `function_model_name`、`sub_function_model_name`、`description`、`x_domain_tag` | 为重点对象补设计语境和说明文字 | 让报告更适合设计评审或整改讨论 |

#### 平台外补充数据源的边界说明

当前 `INTRODUCTION` 并没有把 `mitre_attack`、商业威胁 feed、沙箱分析结果、SOC 事件日志等列为已注册 `source_id`。因此本场景对这些数据源的处理必须明确分成两种状态：

1. 若尚未接入 `ai4x_platform`，则它们只能被表述为外部补充信号，不能被写成平台原生能力。
2. 若后续需要把这些数据正式纳入溯源链路，应先注册为新的 `source_id` 并补 Schema，再进入 `discover_source` 和 `query_fact` 的正式流程。

### 6.5 分析逻辑与平台约束参考

本场景默认遵循以下、与 `ai4x_platform` 当前能力一致的分析逻辑：

1. 先通过 `schema/summaries` 和 `schema/{source_id}` 确认可用数据源与字段，而不是由 Prompt 臆造 Schema。
2. 再用 `opencti` 提取线索本体、关联对象和证据路径，形成溯源主事实层。
3. 若需要补“是否影响我方范围”的语境，再用 `vehicle_iobe`、`vehicle_func`、`ecu_func`、`func_design_spec` 做内部映射。
4. 若需要补风险语义和控制建议，再用 `tara`、`ses`、`cve2oss` 做增强解释。
5. 对尚未注册到平台的外部 feed、日志或沙箱结果，统一按外部补充信号处理，并在输出边界中显式声明。

这一逻辑直接受 `ai4x_platform` 的三个实现边界约束：

1. 统一查询虽暴露为 Cypher 接口，但对 MongoDB 和 OpenCTI 实际上是受限子集翻译，不能假定任意查询表达式都可用。
2. `cve2oss` 是独立代理接口，不应被误写成统一图查询数据源。
3. 当前平台已注册的数据源范围就是溯源设计的最小事实边界，超出部分必须标记为待接入而不是默认存在。

## 7. Skill 设计

### 7.1 单业务意图下的 SKILL 分层原则

本场景遵循通用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的“SKILL 分层原则”。

对 `威胁溯源分析` 而言，当前仍采用一个主 SKILL 作为默认执行路径，并为后续扩展预留分层结构。

### 7.2 主 SKILL 标识

- `skill_id`: `skill.threat-attribution.ip-trace`
- `skill_name`: `IP 威胁溯源分析`
- `bind_intent_id`: `biz.threat-attribution`
- `skill_role`: `primary`
- `default_entry`: `true`

### 7.3 主 SKILL 触发条件

当用户输入满足以下任一条件时触发：

1. 输入对象为 `IP`、`域名`、`HASH`。
2. 请求目标是识别背后组织、历史活动或 TTP。
3. 用户要求生成可回溯的威胁画像或归因报告。

在第一阶段，即便入口对象是 `domain` 或 `hash`，也允许仍由主 SKILL 承接，只要实际执行路径与 IP 溯源的核心 SOP 仍然足够接近。

### 7.4 主 SKILL SOP

1. 识别目标类型和值。
2. 若目标、边界或输出目标不清，则先做少量高价值澄清。
3. 补齐最小槽位。
4. 调用 `catalog` 确认可用数据源。
5. 调用 `schema` 确认对象和字段。
6. 对目标对象执行一跳事实查询。
7. 基于返回的 indicator、infrastructure、malware 和 attack-pattern 执行二跳扩展。
8. 若中间结果已形成长列表、长时间线或大证据集，则优先尝试上下文治理类 SKILL 压缩为稳定中间结果。
9. 汇总候选 intrusion-set。
10. 对归因结果进行可信度分层。
11. 输出结构化报告，并明确事实与推断边界。

### 7.5 主 SKILL 输出要求

输出至少包含：

1. 目标线索摘要。
2. 候选攻击组织列表。
3. 证据路径。
4. 相关技术与工具。
5. 时间线或活动摘要。
6. 置信度说明。
7. 防御和调查建议。

### 7.6 预留的扩展 SKILL 层

当单一主 SKILL 不再适合覆盖全部请求时，可在同一业务意图下增加扩展 SKILL。建议的扩展层次如下：

| SKILL 类型 | 示例 | 作用 | 默认是否启用 |
| --- | --- | --- | --- |
| 主 SKILL | `skill.threat-attribution.ip-trace` | 覆盖最稳定的默认链路 | 是 |
| 输入对象特化 SKILL | `skill.threat-attribution.hash-trace` | 针对 HASH、样本、文件实体优化查询路径 | 否 |
| 输出目的特化 SKILL | `skill.threat-attribution.briefing` | 针对快速简报或管理层摘要压缩输出 | 否 |
| 高负载辅助 SKILL | `skill.threat-attribution.timeline-condense` | 压缩长时间线或大证据集 | 否 |

这些扩展 SKILL 都必须继续绑定同一个业务意图 `biz.threat-attribution`，不能因为新增 SKILL 就错误地新增顶层业务意图。

### 7.7 何时从一个主 SKILL 拆成多个 SKILL

新增 SKILL 的通用判定规则、上下文治理类 SKILL 的收益、以及何时应拆出辅助 SKILL，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

在本场景下，只有当输入对象、查询链路、输出目标或上下文治理方式出现稳定分化时，才应从主 SKILL 拆出扩展 SKILL。

### 7.8 不应该创建新 SKILL 的情况

本场景中，不建议创建新 SKILL 的通用情形同样引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 7.9 本业务意图的建议演进顺序

当前建议采用以下演进路线：

1. 第一阶段：只保留一个主 SKILL `skill.threat-attribution.ip-trace`，跑通默认分析链路。
2. 第二阶段：当 `domain`、`hash`、`malware`、`ttp` 的查询链路稳定分化后，再按输入对象拆分扩展 SKILL。
3. 第三阶段：当“深度归因报告”和“快速研判简报”这两类输出目标稳定分化后，再按输出目的拆分 SKILL。
4. 第四阶段：当长时间线、海量路径等高 token 场景成为常态时，再增加辅助 SKILL 处理高负载上下文压缩。

### 7.10 SKILL 设计检查清单

新建 SKILL 前应使用原则文档 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md) 中的检查清单进行评审。

## 8. 输出契约

### 8.1 结构化响应

```json
{
  "request_id": "req-20260503-001",
  "intent_id": "biz.threat-attribution",
  "target": {
    "type": "ip",
    "value": "185.130.5.253"
  },
  "summary": "该 IP 与两个候选攻击组织相关，其中 APT29 证据较强，DarkHotel 为次级待验证线索。",
  "direct_facts": [
    "该 IP 被 2 个 indicator 引用",
    "其中 1 条 indicator 与 malware WellMess 关联"
  ],
  "inferred_assessments": [
    "APT29 是当前最可能的关联组织",
    "DarkHotel 关联需要额外来源验证"
  ],
  "candidate_intrusion_sets": [
    {
      "name": "APT29",
      "confidence": 0.82,
      "evidence_strength": "high"
    },
    {
      "name": "DarkHotel",
      "confidence": 0.54,
      "evidence_strength": "medium"
    }
  ],
  "evidence_paths": [
    {
      "path_id": "path-1",
      "nodes": ["185.130.5.253", "indicator--1", "malware--WellMess", "intrusion-set--APT29"],
      "path_summary": "IP -> Indicator -> Malware -> APT29"
    }
  ],
  "related_ttps": ["T1071", "T1105"],
  "related_tools": ["WellMess"],
  "recommendations": [
    "检查近 30 天内与该 IP 的通信记录",
    "对关联域名与哈希继续扩展溯源",
    "若命中内部资产，转交应急响应编排"
  ],
  "confidence_statement": "已满足多源证据要求的组织为 APT29；DarkHotel 仅为间接推断，不应直接作为最终归因结论。",
  "generated_at": "2026-05-03T10:35:00Z"
}
```

### 8.2 输出规则

1. `direct_facts` 与 `inferred_assessments` 必须分开。
2. 每个候选组织必须附带 `confidence` 与 `evidence_strength`。
3. 每条核心结论都必须能映射到至少一条 `evidence_paths`。
4. 当没有足够证据时，允许输出“未形成稳定归因”的空结论报告。

## 9. AGENT 实现建议

### 9.1 推荐实现分层

建议先在单个 `AI AGENT` 内部细化出三个实现部件：

1. `Intent Router`
2. `Skill Orchestrator`
3. `Tool Policy Guard`

这三个部件是同一个主 AGENT 的内部职责，不代表三个独立 AGENT。

### 9.2 Intent Router 责任

1. 把用户输入归类到 `biz.threat-attribution`。
2. 决定具体场景，例如 `ip-trace`、`domain-trace`、`hash-trace`。
3. 在方向不清时优先发起高价值澄清，收敛分析目标、关注维度和输出深度。
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

本场景中的单 AGENT 规则、附属 AGENT 创建逻辑、以及上下文隔离的通用判断标准，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.5 Prompt 设计骨架

主 Agent Prompt 至少应包含：

1. 先识别业务意图，再选 Skill。
2. 当目标、边界或输出目标不明确时，先向用户发起少量高价值澄清，而不是立即展开高成本查询。
3. 处理 `biz.threat-attribution` 时必须遵守 `catalog -> schema -> query` 的操作顺序。
4. 涉及归因时必须区分直接事实和间接推断。
5. 默认由单个主 AGENT 完成全链路。
6. 当中间结果过长时，优先通过上下文治理类 SKILL 压缩，再决定是否需要创建临时附属 AGENT。
7. 提示词只保留本场景约束、边界和执行规则，动态字段、真实 Schema 和工具参数以运行时结果为准。

本场景中的通用提示词设计原则，统一引用 [design/KG/威胁情报AGENT设计原则.md](d:/projects/HIVS_CTI/design/KG/%E5%A8%81%E8%83%81%E6%83%85%E6%8A%A5AGENT%E8%AE%BE%E8%AE%A1%E5%8E%9F%E5%88%99.md)。

### 9.6 实现伪代码

```text
handle_request(user_input, current_role):
    envelope = intent_router.normalize(user_input)

    if envelope.intent_id != "biz.threat-attribution":
        route_elsewhere()

  if need_clarification(envelope):
    return ask_for_clarification(
      topics=["analysis_goal", "focus_dimension", "report_depth"]
    )

    skill = skill_orchestrator.load("skill.threat-attribution.ip-trace", envelope)

    tool_policy_guard.authorize("ThreatIntelAgent", envelope)

    target = run_identify_target(skill, envelope)
    sources = run_discover_source(skill, envelope)
    schema = run_inspect_schema(skill, envelope, sources)
    facts = run_query_fact(skill, envelope, schema)
    relations = run_expand_relation(skill, envelope, facts)

    if should_compact_in_current_session(relations):
      relations = run_context_governance_skill(
        "skill.threat-attribution.timeline-condense",
        relations
      )

    if should_spawn_support_agent(
        raw_material=relations,
        future_reasoning_steps=["assess_confidence", "compose_report"],
      current_session_cannot_hold_all=true,
        can_reduce_to_stable_artifact=true
    ):
        condensed_relations = spawn_support_agent_for_condense(relations)
        relations = merge_back(condensed_relations)

    confidence = run_assess_confidence(skill, envelope, facts, relations)
    report = run_compose_report(skill, envelope, facts, relations, confidence)

    return report
```

## 10. 验收建议

### 10.1 业务意图验收

1. 能把 IP、域名、HASH 请求稳定识别为 `biz.threat-attribution`。
2. 缺少 `target_value` 时不进入查询流程。
3. 能输出结构化报告，而不是单段散文。

### 10.2 操作意图验收

1. `discover_source` 前不得直接执行查询。
2. `inspect_schema` 后才能发起正式查询。
3. `assess_confidence` 必须对多组织归因做排序。
4. `compose_report` 必须产出证据路径和置信度说明。

### 10.3 角色验收

1. `ThreatIntelSecOps` 不得直接调用查询工具。
2. 单一主 AGENT `ThreatIntelAgent` 能完成全链路执行。
3. 只有在高上下文负载任务中，系统才允许创建附属 AGENT。
4. 附属 AGENT 的输出必须回流到主 AGENT，由主 AGENT 负责最终结论。

## 11. 基于 SAMPLE 的测试数据验证

本设计可以直接使用本次新增的 sample 数据做验证，入口清单见 [sample/threat-attribution/manifest.json](../../sample/threat-attribution/manifest.json)。

### 11.1 需要导入的数据

1. `opencti`：导入 [sample/shared/opencti_bundle.json](../../sample/shared/opencti_bundle.json)，用于提供 `185.130.5.253 -> indicator -> malware -> intrusion-set` 的证据路径。
2. 若需要补“是否影响我方范围”的解释，可选导入 [sample/shared/vehicle_iobe_bundle.json](../../sample/shared/vehicle_iobe_bundle.json)。

### 11.2 推荐验证请求

1. 直接使用 [sample/threat-attribution/manifest.json](../../sample/threat-attribution/manifest.json) 中的 `request_fixture`。
2. 核心输入为 `ip = 185.130.5.253`，关注维度为 `intrusion-set`、`malware`、`attack-pattern`。

### 11.3 用户触发提示词

可直接使用以下自然语言提示词触发与 sample 夹具等价的测试：

```text
请以 IP 185.130.5.253 为起点，分析它关联的攻击组织、恶意软件和攻击技术，区分高置信证据链与次级待验证线索，并给出一份适合研判复核的溯源结论。
```

### 11.4 预期验证点

1. 能形成高置信路径 `IP -> indicator -> WellMess -> APT29`。
2. 能保留 `DarkHotel` 为次级待验证组织，而不是直接并列输出强归因。
3. 能显式拆分 `Facts`、`Evidence Paths` 和 `Inferences`。

## 12. 与当前模型文件的关系

本文档对应 [design/KG/SystemArchitecture.json](design/KG/SystemArchitecture.json) 中：

1. L1 业务意图：`威胁溯源分析`
2. L2 操作意图：`identify_target`、`discover_source`、`inspect_schema`、`query_fact`、`expand_relation`、`assess_confidence`、`compose_report`

当前模型文件已经表达了顶层能力、通用操作原语层和威胁溯源分析操作链骨架，但还没有表达：

1. 操作意图的执行顺序。
2. 角色与工具权限约束。
3. Intent Envelope、输入槽位和输出契约。
4. Intent Envelope 与输出契约。

这四部分由本文档补齐，后续再决定是否继续回写到 JSON 模型中。