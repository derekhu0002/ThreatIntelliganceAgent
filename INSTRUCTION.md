# Threat Intelligence Agent V1 对外说明文档

## 快速结论

### 谁应该使用它

- 需要把 OPENCTI 或类似威胁事件推送，转换为结构化分析结果的内部安全平台团队
- 正在评估“Python listener + 远端多 Agent 分析 + 图数据库验证写回”闭环方案的集成团队
- 已经具备 OPENCODE Server、Docker、Neo4j、AI4X Platform 等运行条件，且愿意自行集成与运维的研发团队

### 谁不适合使用它

- 希望直接获得一个即装即用 SaaS 或通用开放平台的团队
- 需要稳定对外北向 API、正式 SLA、多租户治理、权限体系和生产级交付说明的外部客户
- 没有 Docker、Python、OPENCODE 运行环境，也不打算接管这些依赖的团队

### 最小接入路径是什么

最小接入路径是：准备 Python 环境和依赖后，用一个事件 JSON 文件调用 `services.python_listener`，并把远端 OPENCODE Server 地址指向 `http://127.0.0.1:8124` 或你自己的部署地址；如果只是验证闭环，可直接运行 `scripts/run_minimal_closed_loop.py`。

### 采用前最需要验证的 3 个风险点

1. 远端 OPENCODE Server 是否能稳定提供 `session` / `message` 协议能力，而不只是测试环境可用。
2. 真实运行时依赖是否齐全，包括 Docker、Neo4j、模型 Provider 配置、`DEEPSEEK_API_KEY`，以及可选的 AI4X Platform。
3. 你们是否接受当前主要以 Python CLI、脚本和工作区配置驱动集成，而不是现成的对外产品 API。

## 1. 产品概述

### 一句话定位

这是一个面向威胁情报分析的最小闭环集成工程，用于把威胁事件输入转换成结构化分析结果，并在验证场景下将结果写回 Neo4j 投影。

### 它解决什么问题

根据仓库中的实现，这个项目试图解决的问题不是“建设一个完整对外情报平台”，而是把以下链路串起来：

1. 接收或读取一个 OPENCTI PUSH 事件
2. 规范化事件内容并提取 STIX 元素
3. 将上下文转交给远端 OPENCODE 多 Agent 工作区进行分析
4. 由 Agent 借助 STIX 查询工具和可选的 AI4X Platform 查询能力补充证据
5. 输出结构化威胁分析结果
6. 在闭环验收中把结果写入 Neo4j 做验证性投影

### 适用对象

- 内部 SOC / Threat Intel 平台研发团队
- 需要验证多 Agent 威胁研判流程的 PoC / 集成团队
- 需要把图谱查询、STIX 证据检索、结构化输出串成自动化流程的研究型团队

### 典型场景

- 用样例或真实事件验证“威胁情报事件到结构化分析结果”的闭环链路
- 将 OPENCODE 作为远端 Agent 执行引擎，验证多角色协同分析流程
- 在真实 AI4X Platform 存在时，验证 Agent 通过 catalog/schema/query 三段式访问外部数据源的能力

### 当前更接近什么产品形态

基于仓库现状，这个项目**更接近一个内部集成样板、闭环验证工程和 Agent 工作区资产集合**，而不是一个已经包装完成的通用开放平台。

判断依据包括：

- 仓库主入口是 Python CLI、脚本和 Docker 编排，而不是稳定对外服务网关
- 仓库中未发现 `package.json`，也未体现以 Node 包或 VS Code 扩展产品形式发布的清晰证据
- README、测试和架构文件都围绕“最小闭环”“验收脚本”“mock 与真实环境切换”展开

## 2. 功能清单

### 2.1 事件接入与规范化

核心能力：

- 读取 OPENCTI PUSH 事件 JSON
- 规范化事件内容
- 提取 STIX entity、observables、labels、severity
- 生成远端请求上下文和运行上下文

业务价值：

- 把原始事件转成远端 Agent 能稳定消费的请求合同
- 为后续分析、审计和结果重放保留请求快照

基于现有代码可证实的入口：

- `services.python_listener.__main__`
- `services.python_listener.listener.ThreatIntelListener`

### 2.2 远端多 Agent 分析编排

核心能力：

- 默认主 Agent 为 `ThreatIntelPrimary`
- 支持 canonical role：`ThreatIntelPrimary`、`ThreatIntelAnalyst`、`ThreatIntelSecOps`
- 支持 legacy alias 到 canonical role 的兼容映射
- 将事件上下文提交给远端 OPENCODE Server 执行分析

业务价值：

- 把事件路由到具备职责分工的 Agent 工作区中执行
- 把多角色协作的结构化结果回传给 listener

需要明确的边界：

- 本仓库**消费**远端 OPENCODE Server 的能力，但不等同于在仓库内实现了一个完整自主的推理服务后端
- 远端协议由仓库消费，当前仓库面向外部的直接入口仍主要是 listener CLI 和闭环脚本

### 2.3 STIX 查询与语义辅助

核心能力：

- 提供 STIX CLI 工具
- 支持搜索、邻接关系、进阶过滤等能力
- 工具权限按 Agent 角色限制，重点向 `ThreatIntelAnalyst` 开放

业务价值：

- 让 Agent 在本地 STIX 样本上做语义查找和证据补充
- 为分析结论提供可追溯的查询依据

已证实的约束：

- 测试明确要求某些工具仅允许 `ThreatIntelAnalyst` 使用
- `ThreatIntelSecOps` 会收到“回交给 ThreatIntelAnalyst”的兼容性提示，而不是等价权限

### 2.4 AI4X Platform 数据消费

核心能力：

- 支持发现 AI4X Platform 可用数据源
- 支持读取指定 `source_id` 的 schema
- 支持通过统一查询 API 执行只读查询

业务价值：

- 让 Agent 在本地 STIX 之外，还能访问外部图数据或其他注册数据源
- 为威胁分析和证据整合提供外部知识支撑

已证实的实现路径：

1. Agent 侧 `ai4x_query.js`
2. 调用 Python CLI `agent_app/opencode_app/tools/ai4x_cli.py`
3. 再由 `services/ai4x_client.py` 访问 AI4X Platform API Center

### 2.5 结构化结果校验与 Neo4j 验证写回

核心能力：

- 输出结构化 JSON 分析结果
- 在闭环验收脚本中将结果写入 Neo4j 验证投影
- 验证参与角色数量、推荐动作数量、结论摘要等是否已持久化

业务价值：

- 不只验证“有结果文件”，还验证结果是否满足最小业务完整性
- 为验收与调试提供可检查的数据库落点

需要明确的边界：

- 这里的 Neo4j 写回更多是**验证性投影**，不是仓库中已经定义完整生产域模型和正式写库协议的充分证据

## 3. 接口与集成点

### 3.1 已证实存在的对外入口

#### Python CLI

1. `python -m services.python_listener`
   - 输入：事件 JSON 文件路径
   - 关键参数：`--event`、`--output`、`--remote-server-url`、`--main-agent`

2. `python scripts/run_minimal_closed_loop.py`
   - 用于跑最小闭环验收
   - 自动启动 Neo4j 验证容器
   - 可通过环境变量切换 mock remote server 或真实远端地址

3. `python -m tools.stix_cli`
   - 运行于 `agent_app/opencode_app/` 工作区上下文中
   - 用于本地 STIX 查询

#### Docker Compose

`agent_app/docker-compose.yml` 暴露了两个核心运行组件：

- `opencode`：容器内监听 `4096`，宿主机映射到 `8124`
- `neo4j`：宿主机暴露 `7498` 和 `7698`

#### 配置文件

1. `agent_app/opencode_app/.opencode/opencode.json`
   - 指定模型 provider
   - 指定默认主 Agent 为 `ThreatIntelPrimary`
   - 指定工作区指令文件 `AGENTS.md`

2. `agent_app/opencode_app/.opencode/AGENTS.md`
   - 定义 canonical workspace root 和 canonical roles

3. `design/KG/SystemArchitecture.json`
   - 记录架构元素、关系、验收用例和若干运行前置条件

#### 测试入口

可作为集成验证入口的测试包括：

- `tests/test_python_listener.py`
- `tests/test_minimal_closed_loop_script.py`
- `tests/test_opencode_workspace_config.py`
- `tests/test_ai4x_platform_integration.py`

### 3.2 已证实存在的外部依赖

- Python 3.11+，依赖见 `requirements.txt`
- Docker 与 Docker Compose
- 远端 OPENCODE Server
- Neo4j
- 可选的 AI4X Platform API Center
- 模型 provider 配置及 `DEEPSEEK_API_KEY`

### 3.3 仓库中未明确说明或不应过度外推的接口

- 仓库中**未明确说明**本项目自身对外暴露稳定 HTTP API 供第三方业务系统直接调用
- 仓库中**未明确说明**正式的 webhook 接收服务部署方式
- 仓库中**未明确说明**SLA、租户隔离、权限体系、审计合规策略、生产高可用方案
- 仓库中**未明确说明**版本化的对外 API 合同管理机制

因此，对外介绍时更稳妥的表述应是：

> 当前仓库已经实现可执行的 CLI、脚本、Docker 运行与远端 Agent 工作区集成能力，但尚不能仅凭现有仓库内容将其描述为“已成型的开放情报平台产品”。

## 4. 调用与使用方法

### 4.1 运行前置条件

最少需要准备：

1. Python 环境与 `requirements.txt` 依赖
2. Docker 与 Docker Compose
3. 可访问的远端 OPENCODE Server，默认地址为 `http://127.0.0.1:8124`

若要运行完整真实集成路径，还需要：

4. Neo4j，可通过 `agent_app/docker-compose.yml` 启动
5. `.env` 与模型 provider 配置，至少包括 `DEEPSEEK_API_KEY`
6. 可选的 AI4X Platform，默认基础地址为 `http://localhost:8000`

### 4.2 最小使用步骤

#### 路径 A：最小 listener 接入

适合外部系统先验证输入输出契约。

1. 准备一个事件 JSON 文件，例如 `data/mock_events/mock_opencti_push_event.json`
2. 确保远端 OPENCODE Server 可访问
3. 执行：

```powershell
.\.venv\Scripts\python.exe -m services.python_listener --event data/mock_events/mock_opencti_push_event.json --output artifacts/runtime/opencti-push-001-analysis.json --remote-server-url http://127.0.0.1:8124
```

成功后可获得：

- 结构化分析结果文件
- 远端请求上下文快照文件

#### 路径 B：最小闭环验收

适合外部团队快速判断仓库是否能“端到端跑通”。

```powershell
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

如需使用本地 mock remote server：

```powershell
$env:THREAT_INTEL_USE_MOCK_REMOTE_SERVER="1"
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

如需改用自定义远端地址：

```powershell
$env:THREAT_INTEL_REMOTE_SERVER_URL="http://127.0.0.1:9555"
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

#### 路径 C：启动真实 OPENCODE 工作区

```powershell
docker compose -f agent_app/docker-compose.yml up -d opencode neo4j
```

这条路径适合：

- 你需要验证真实 OPENCODE 工作区与 Agent 配置是否能加载
- 你需要让 listener 指向本地拉起的真实容器服务

### 4.3 外部系统可以如何集成

基于现有代码，外部系统最现实的集成方式有两种：

1. **文件驱动式集成**
   - 外部系统生成事件 JSON
   - 调用 `services.python_listener`
   - 读取产出的结构化结果文件

2. **把本仓库作为中间层/工作流组件接入**
   - 由外部系统负责事件接入与调度
   - 本仓库负责 listener、远端 Agent 调用、结果装配与验证

根据现有代码推断但仓库中未直接给出完整部署说明的是：

- 可以将 listener 进一步封装为长期运行服务或 webhook 接收端
- 但该封装与部署方式不属于当前仓库已充分文档化的既定产品能力

## 5. 评估采用时应关注的约束

### 5.1 运行环境约束

- Python、Docker、Neo4j、远端 OPENCODE Server 都是实质依赖
- 真实 AI4X 路径下，还需要外部 AI4X Platform 可用
- 容器到宿主机 AI4X 服务的访问依赖 `host.docker.internal` 映射

### 5.2 产品边界约束

- 仓库主要解决“最小闭环验证”和“工作区集成”问题，不是完整运营化产品
- 当前以脚本、CLI、测试和配置为主，缺少正式对外产品化包装
- 对外调用方若采用，通常需要自行承担部署、监控、认证、运维和二次封装工作

### 5.3 当前局限

- 真实调用可能因 provider、API key、上游模型服务或远端 OPENCODE 健康状况失败
- 闭环能力虽可通过测试验证，但这不等于生产级稳定性已经证明
- 写回 Neo4j 的逻辑当前更偏验证性，不宜直接等同于正式业务写库契约

### 5.4 更适合的集成方式

- 作为内部威胁分析自动化链路中的一个子系统
- 作为 Agent 工作区与外部数据查询能力的集成样板
- 作为研究、PoC、验证环境，而不是直接面对外部客户的成品平台

### 5.5 不适用场景

- 需要即开即用控制台和多租户权限体系
- 需要正式外部 API 文档、配额体系、稳定商业支持
- 不能接受依赖远端模型和多套外部运行组件的团队

## 6. 证据来源

以下结论均来自仓库中可直接核查的文件：

### 关于系统定位与运行链路

- `README.md`
- `services/python_listener/listener.py`
- `scripts/run_minimal_closed_loop.py`

### 关于 CLI 入口与参数

- `services/python_listener/__main__.py`
- `validation/README.md`

### 关于 Docker、端口和运行依赖

- `agent_app/docker-compose.yml`
- `requirements.txt`

### 关于 Agent 工作区、默认角色与兼容别名

- `agent_app/opencode_app/.opencode/opencode.json`
- `agent_app/opencode_app/.opencode/AGENTS.md`
- `tests/test_opencode_workspace_config.py`

### 关于 AI4X Platform 集成能力

- `services/ai4x_client.py`
- `tests/test_ai4x_platform_integration.py`
- `design/KG/SystemArchitecture.json`

### 关于验收与 Neo4j 验证写回

- `scripts/run_minimal_closed_loop.py`
- `services/neo4j_validation.py`
- `design/KG/SystemArchitecture.json`

### 关于“不是通用开放平台”的判断依据

- 仓库中未发现 `package.json`
- 当前已知入口均指向 Python CLI、脚本、Docker 运行与测试
- 仓库中未见面向第三方正式发布的 API 产品说明、SLA 或运营化对外能力定义

## 7. 对外沟通建议

如果需要把这个项目介绍给外部团队，建议使用以下表述口径：

> Threat Intelligence Agent V1 当前是一个面向威胁情报分析的最小闭环集成工程。它可以把 OPENCTI 风格的事件输入交给远端 OPENCODE 多 Agent 工作区分析，结合本地 STIX 查询和可选的 AI4X Platform 数据查询能力，生成结构化分析结果，并在验收路径中将结果写入 Neo4j 验证投影。当前仓库更适合内部集成、PoC 和工作流验证；若要作为正式对外产品采用，通常还需要补充稳定部署、认证授权、运维监控和对外 API 封装。
