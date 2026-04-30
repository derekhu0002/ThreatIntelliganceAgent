# Threat Intelligence Agent V1

## 1. 这个项目构建了什么系统

这是一个面向威胁情报分析的最小闭环系统，用来把一次 OPENCTI 推送事件转成结构化分析结果，并把结果验证性写回到 Neo4j 投影中。

系统包含四个核心部分：

1. **事件入口**：`services/python_listener/`
   - 接收一个 OPENCTI PUSH 事件 JSON
   - 做事件规范化和 STIX 元素提取
   - 组装远端分析请求并调用 OPENCODE SERVER

2. **多 Agent 分析工作区**：`agent_app/opencode_app/`
   - 运行在 OPENCODE SERVER 容器里
   - 默认主 Agent 是 `ThreatIntelPrimary`
   - 规范角色包括：`ThreatIntelPrimary`、`ThreatIntelAnalyst`、`ThreatIntelSecOps`
   - 由主 Agent 编排分析、证据提取和处置建议生成

3. **证据与工具层**
   - `agent_app/opencode_app/tools/stix_cli/`：本地 STIX 2.1 语义查询工具
   - `services/ai4x_client.py` + `agent_app/opencode_app/tools/ai4x_cli.py`：对接 AI4X Platform API Center 的真实查询客户端

4. **结果装配与验证层**：`services/result_assembler/` 与 `services/neo4j_validation.py`
   - 校验结构化 JSON 输出
   - 在闭环验收脚本里把结果写入 Neo4j 验证投影

一句话概括：

> 这是一个“OPENCTI 事件 -> Python listener -> 远端 OPENCODE 多 Agent 分析 -> 结构化情报结果 -> Neo4j 验证写回”的最小闭环威胁情报系统。

## 2. 系统运行时长什么样

### 2.1 最小闭环链路

1. 外部系统或测试脚本提供一个 OPENCTI PUSH 事件
2. `services.python_listener` 读取并规范化事件
3. listener 生成 remote request，并把主 Agent 名称一起发送到 OPENCODE SERVER
4. OPENCODE 工作区中的 Agent 执行分析
5. Agent 通过 STIX CLI 或 AI4X 查询证据
6. 远端返回结构化 JSON 结果
7. listener 落盘结果文件
8. 闭环脚本再把结果写入 Neo4j 做验证性投影

### 2.2 两种运行模式

#### 模式 A：本地 mock 闭环

适合快速验证协议链路，不依赖真实 OPENCODE 分析服务。

- 使用 `services/remote_opencode_server/mock_server.py`
- 使用仓库内的 STIX 样例数据
- 仍然会在闭环验收脚本中启用 Neo4j 验证投影

#### 模式 B：真实后端闭环

适合集成验证。

- 使用 `agent_app/docker-compose.yml` 启动真实 OPENCODE SERVER
- OPENCODE 容器挂载 `agent_app/opencode_app/` 作为工作区
- 可进一步访问真实 AI4X Platform API Center

## 3. 仓库结构速览

```text
agent_app/
  docker-compose.yml               # OPENCODE + Neo4j 本地容器编排
  Dockerfile                       # 为 OPENCODE 镜像补充 Python 运行时
  opencode_app/                    # Agent 工作区
    .opencode/                     # agents / skills / opencode config
    data/stix_samples/             # 本地 STIX 样例数据
    tools/                         # agent 侧工具，包括 ai4x_cli 和 stix_cli

services/
  ai4x_client.py                   # AI4X Platform API Center 客户端
  mock_opencti_adapter/            # OPENCTI 事件规范化
  neo4j_validation.py              # Neo4j 验证投影与写回
  python_listener/                 # listener CLI、主流程、remote client
  remote_opencode_server/          # 本地 mock remote server
  result_assembler/                # 结构化结果 schema 与校验

data/mock_events/                  # 输入事件样例
scripts/run_minimal_closed_loop.py # 最小闭环验收入口
tests/                             # pytest 用例
validation/README.md               # 验收与 STIX CLI 快速说明
artifacts/runtime/                 # 运行时输出目录
```

## 4. 依赖与环境准备

### 4.1 Python 依赖

仓库根目录已经提供 `requirements.txt`，当前依赖包括：

- `pydantic`
- `neo4j`
- `pytest`

建议使用 Python 3.11+。

### 4.2 本地安装

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS / Linux：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

### 4.3 Docker 依赖

如果你要运行以下任一能力，需要本机安装 Docker 与 Docker Compose：

- `scripts/run_minimal_closed_loop.py`
- `agent_app/docker-compose.yml` 中的真实 OPENCODE SERVER
- Neo4j 验证容器

### 4.4 可选环境变量

真实 OPENCODE / AI4X 模式下，常见变量包括：

- `DEEPSEEK_API_KEY`：OPENCODE 默认 provider 需要
- `THREAT_INTEL_REMOTE_SERVER_URL`：覆盖 listener 默认远端地址
- `THREAT_INTEL_USE_MOCK_REMOTE_SERVER=1`：强制闭环脚本走本地 mock server
- `THREAT_INTEL_AI4X_BASE_URL`：AI4X Platform 基础地址
- `THREAT_INTEL_AI4X_AUTH_MODE`：`none` / `apikey` / `jwt`
- `THREAT_INTEL_AI4X_API_KEY`：AI4X API Key
- `THREAT_INTEL_AI4X_JWT`：AI4X JWT

## 5. 如何使用这个系统

下面按“最容易上手”到“真实集成”给出三条路径。

### 5.1 路径一：直接运行 listener

这是理解系统输入输出边界的最短路径。

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m services.python_listener --event data/mock_events/mock_opencti_push_event.json --output artifacts/runtime/opencti-push-001-analysis.json --remote-server-url http://127.0.0.1:8124
```

说明：

- 输入是一个 OPENCTI PUSH 事件 JSON
- 输出是结构化分析结果 JSON
- 默认远端地址是 `http://127.0.0.1:8124`
- 默认主 Agent 来自 `agent_app/opencode_app/.opencode/opencode.json`
- 当前默认值是 `ThreatIntelPrimary`

如需覆盖主 Agent：

```powershell
.\.venv\Scripts\python.exe -m services.python_listener --event data/mock_events/mock_opencti_push_event.json --main-agent ThreatIntelAnalyst --remote-server-url http://127.0.0.1:8124
```

### 5.2 路径二：跑最小闭环验收

这是最推荐的外部演示入口，因为它会把“事件输入、远端调用、结果校验、Neo4j 写回验证”串成一条完整链路。

```powershell
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

默认行为：

- 自动通过 Docker 启动 Neo4j 验证容器
- 默认把远端地址指向 `http://127.0.0.1:8124`
- 输出分析结果到 `artifacts/runtime/opencti-push-001-analysis.json`
- 输出验收摘要到 `artifacts/runtime/opencti-push-001-acceptance-summary.json`

如果你还没有真实 OPENCODE SERVER，可切到本地 mock 模式：

```powershell
$env:THREAT_INTEL_USE_MOCK_REMOTE_SERVER="1"
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

如果你有真实后端，但地址不是默认端口：

```powershell
$env:THREAT_INTEL_REMOTE_SERVER_URL="http://127.0.0.1:9555"
.\.venv\Scripts\python.exe scripts/run_minimal_closed_loop.py
```

### 5.3 路径三：启动真实 OPENCODE SERVER 工作区

在仓库中，真实 OPENCODE 工作区位于 `agent_app/opencode_app/`，容器编排文件位于 `agent_app/docker-compose.yml`。

启动方式：

```powershell
docker compose -f agent_app/docker-compose.yml up -d opencode neo4j
```

关键事实：

- OPENCODE 容器端口是 `4096`
- 宿主机映射端口是 `8124`
- 因此 listener 默认访问地址是 `http://127.0.0.1:8124`
- 工作区内默认 `default_agent` 是 `ThreatIntelPrimary`
- 容器里会把 `agent_app/opencode_app/` 挂载到 `/root/project_tia`

如果你只想启动 OPENCODE：

```powershell
docker compose -f agent_app/docker-compose.yml up -d opencode
```

## 6. 输出内容是什么

listener 或闭环脚本成功后，会产出结构化 JSON。主要字段包括：

- `schema_version`
- `run_id`
- `generated_at`
- `event`
- `key_information_summary`
- `analysis_conclusion`
- `evidence_query_basis`
- `recommended_actions`
- `collaboration_trace`

常见输出文件：

```text
artifacts/runtime/opencti-push-001-analysis.json
artifacts/runtime/opencti-push-001-acceptance-summary.json
artifacts/runtime/opencti-push-001-remote-request.json
```

其中：

- `*-analysis.json` 是最终结构化分析结果
- `*-acceptance-summary.json` 是闭环验收摘要
- `*-remote-request.json` 是 listener 发送给远端 Agent 的请求上下文快照

## 7. STIX CLI 与 AI4X 能力

### 7.1 STIX CLI

STIX CLI 是 agent 侧本地知识查询工具，可以直接在工作区里试跑：

```powershell
cd agent_app/opencode_app
..\..\.venv\Scripts\python.exe -m tools.stix_cli --data data/stix_samples/threat_intel_bundle.json search --query APT28
```

### 7.2 AI4X Platform 集成

项目已经包含 AI4X Platform API Center 的真实客户端与测试：

- schema catalog 发现
- source schema 获取
- universal query 执行

如果没有可用的 AI4X 环境，相关真实集成调用会失败；这不是 listener 本身的逻辑错误，而是运行依赖未满足。

## 8. 测试

运行全部测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -rA
```

运行本仓库当前提供的定向测试任务：

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies tests/test_ai4x_platform_integration.py -q
```

如果你只想验证最小闭环相关能力，优先看这些测试：

- `tests/test_python_listener.py`
- `tests/test_minimal_closed_loop_script.py`
- `tests/test_opencode_workspace_config.py`
- `tests/test_ai4x_platform_integration.py`

## 9. 当前边界与注意事项

1. 这个仓库已经打通了 listener 到 OPENCODE `session/message` 协议的代码路径，但不等于当前机器上的真实服务一定可用。
2. 真实模式下最常见失败点不是 Python listener，而是外部依赖未准备好，例如：
   - OPENCODE 容器未启动
   - provider 或 API key 配置错误
   - AI4X Platform 不可达
   - Docker / Neo4j 没有正常拉起
3. `scripts/run_minimal_closed_loop.py` 即使在 mock remote server 模式下，也会启用 Neo4j 验证容器。
4. 仓库里的本地 mock server 主要用于协议验证和测试替身，不代表生产可用的分析后端。

## 10. 给外部读者的建议上手顺序

如果你第一次接触这个项目，建议按这个顺序：

1. 先读本 README 的第 1、2、5 节，理解系统边界和三条使用路径。
2. 先运行一次 `scripts/run_minimal_closed_loop.py` 的 mock 模式，看完整闭环输出。
3. 再启动 `agent_app/docker-compose.yml`，切到真实 OPENCODE 模式。
4. 最后再接入真实 AI4X Platform，验证真实知识查询链路。