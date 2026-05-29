# Threat Intelligence Agent V1

## 1. 这个项目构建了什么系统

这是一个面向威胁情报分析的最小闭环系统，用来把一次 OPENCTI 推送事件转成结构化分析结果，并把结果验证性写回到 Neo4j 投影中。

系统包含四个核心部分：

1. **多 Agent 分析工作区**：`agent_app/opencode_app/`
   - 运行在 OPENCODE SERVER 容器里
   - 默认主 Agent 是 `ThreatIntelPrimary`
   - 规范角色包括：`ThreatIntelPrimary`、`ThreatIntelAnalyst`、`ThreatIntelSecOps`
  - 由主 Agent 编排分析、证据提取和处置建议生成

2. **证据与工具层**
   - `agent_app/opencode_app/tools/stix_cli/`：本地 STIX 2.1 语义查询工具
  - `agent_app/opencode_app/services/ai4x_client.py` + `agent_app/opencode_app/tools/ai4x_cli.py`：对接 AI4X Platform API Center 的真实查询客户端

3. **配置与契约层**
  - `agent_app/opencode_app/.opencode/`：MCP 注册、Agent 定义、Skill 定义、插件源文件
  - `design/KG/SystemArchitecture.json`：意图架构基线
  - `OVERALL_ARCHITECTURE.md` 与本地 `ARCHITECTURE.md`：实现架构合同

4. **测试与发布层**
  - `tests/`：显式验收与工作区合同测试
  - `packages/opencode-plugin/`：可发布的 OPENCODE 插件包

一句话概括：

> 这是一个“AI4X 远端 MCP 边界 + OPENCODE 多 Agent 工作区 + 可发布插件包 + 显式验收测试”的威胁情报工作区仓库。

## 2. 系统运行时长什么样

### 2.1 当前运行链路

1. OPENCODE 载入 `agent_app/opencode_app/.opencode` 中的 MCP 注册、Agent 和 Skill 定义
2. 工作区中的 Agent 通过 `ai4x_query` 访问远端 AI4X MCP 边界
3. Agent 按 `catalog -> schema -> optional detail -> query` 的顺序完成证据获取
4. 测试通过工作区合同和远端 MCP 会话验证这一链路是否保持稳定

### 2.2 两种主要使用模式

#### 模式 A：真实 OPENCODE 工作区

适合集成验证和真实工作区加载。

- 使用 `agent_app/docker-compose.yml` 启动真实 OPENCODE SERVER
- OPENCODE 容器挂载 `agent_app/opencode_app/` 作为工作区
- 可进一步访问真实 AI4X Platform API Center

#### 模式 B：插件打包与分发

适合把当前工作区能力作为插件提供给外部 OPENCODE 环境。

- 使用 `packages/opencode-plugin/` 打包 npm 插件
- 从 `agent_app/opencode_app/.opencode` 同步 Agent、Skill 和插件资源
- 通过 `@ai4x/opencode-plugin` 安装和分发

## 3. 仓库结构速览

```text
agent_app/
  docker-compose.yml               # OPENCODE + Neo4j 本地容器编排
  Dockerfile                       # 为 OPENCODE 镜像补充 Python 运行时
  opencode_app/                    # Agent 工作区
    .opencode/                     # agents / skills / opencode config
    data/stix_samples/             # 本地 STIX 样例数据
    services/                      # 工作区本地 AI4X 客户端
    tools/                         # agent 侧工具，包括 ai4x_cli 和 stix_cli

design/
  KG/SystemArchitecture.json       # 意图架构基线

tests/                             # pytest 用例
packages/opencode-plugin/          # 可发布的 OPENCODE 插件包
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

- `agent_app/docker-compose.yml` 中的真实 OPENCODE SERVER
- OPENCODE 工作区集成验证

### 4.4 可选环境变量

真实 OPENCODE / AI4X 模式下，常见变量包括：

- `DEEPSEEK_API_KEY`：OPENCODE 默认 provider 需要
- `THREAT_INTEL_REMOTE_SERVER_URL`：覆盖 listener 默认远端地址
- `THREAT_INTEL_USE_MOCK_REMOTE_SERVER=1`：强制闭环脚本走本地 mock server
- `THREAT_INTEL_AI4X_BASE_URL`：AI4X Platform 基础地址
- `THREAT_INTEL_AI4X_AUTH_MODE`：`none` / `apikey` / `jwt`
- `THREAT_INTEL_AI4X_API_KEY`：AI4X API Key
- `THREAT_INTEL_AI4X_JWT`：AI4X JWT
- `THREAT_INTEL_AI4X_CA_CERT_FILE`：HTTPS 场景下用于校验证书链的 CA PEM 文件路径
- `THREAT_INTEL_AI4X_SKIP_SSL_VERIFY=1`：临时跳过 HTTPS 证书校验，仅建议排障时使用

### 4.5 稳定环境变量配置方案

仓库根目录现在支持把 AI4X 相关配置固定在 `.env` 中，供三类入口共享：

- 工作区本地 Python 代码，例如 `agent_app/opencode_app/services/ai4x_client.py`
- OPENCODE 隔离运行时，例如 `agent_app/opencode_app/tools/ai4x_cli.py`
- Docker Compose 中的 OPENCODE 容器，`agent_app/docker-compose.yml`

推荐做法：

1. 复制仓库根目录的 `.env.example` 为 `.env`
2. 把 `THREAT_INTEL_AI4X_BASE_URL` 改成你的真实 AI4X 地址
3. 如需鉴权，再补 `THREAT_INTEL_AI4X_AUTH_MODE` 和对应凭据

PowerShell：

```powershell
Copy-Item .env.example .env
```

最小示例：

```dotenv
THREAT_INTEL_AI4X_BASE_URL=http://your-ai4x-host:8000
THREAT_INTEL_AI4X_AUTH_MODE=none
```

如果 AI4X 地址是内网 HTTPS，例如 `https://ai4sec.xx.com/`，优先配置受信任 CA：

```dotenv
THREAT_INTEL_AI4X_BASE_URL=https://ai4sec.xx.com
THREAT_INTEL_AI4X_CA_CERT_FILE=C:/certs/ai4x-root-ca.pem
THREAT_INTEL_AI4X_AUTH_MODE=none
```

`THREAT_INTEL_AI4X_CA_CERT_FILE` 也可以使用相对路径；相对路径会按仓库根目录 `.env` 所在位置解析，例如：

```dotenv
THREAT_INTEL_AI4X_BASE_URL=https://ai4sec.xx.com
THREAT_INTEL_AI4X_CA_CERT_FILE=certs/ai4x-root-ca.pem
THREAT_INTEL_AI4X_AUTH_MODE=none
```

只有在临时排障、确认是证书链问题时，才建议短时间使用：

```dotenv
THREAT_INTEL_AI4X_BASE_URL=https://ai4sec.xx.com
THREAT_INTEL_AI4X_SKIP_SSL_VERIFY=1
THREAT_INTEL_AI4X_AUTH_MODE=none
```

优先级规则：

- 显式命令行参数最高，例如 `--base-url`
- 当前进程环境变量次之，例如 PowerShell 中的 `$env:THREAT_INTEL_AI4X_BASE_URL`
- 仓库根目录 `.env` 再次之
- 代码内默认值最后兜底

## 5. 如何使用这个系统

下面按“最容易上手”到“可分发集成”给出两条路径。

### 5.1 路径一：启动真实 OPENCODE SERVER 工作区

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

### 5.2 路径二：OPENCODE 插件包

当前 `.opencode` 工作区已经整理为可发布的 npm 插件包，位置为：

```text
packages/opencode-plugin
```

插件包名：`@ai4x/opencode-plugin`。

插件默认注入：

- `default_agent: "安全运营助手"`
- `mcp.ai4x: http://localhost:8000/mcp`
- 从 `agent_app/opencode_app/.opencode/agents` 同步打包的 Agent 定义
- 从 `agent_app/opencode_app/.opencode/skills` 同步打包的 Skill 定义
- 从 `agent_app/opencode_app/.opencode/plugins` 同步打包的插件源文件
- 从 `agent_app/opencode_app/.opencode/GLOBAL_INSTRUCTIONS.md` 同步打包的全局说明

为避免重复维护，`packages/opencode-plugin/assets` 不作为源码保存。`npm pack`、`npm publish` 和发布脚本会在打包前从 `agent_app/opencode_app/.opencode` 生成临时 `assets`，打包后自动删除。

用户安装后在自己的 `opencode.json` 中启用：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    "@ai4x/opencode-plugin"
  ]
}
```

如需覆盖 AI4X MCP 地址：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    ["@ai4x/opencode-plugin", {
      "ai4xMcpUrl": "http://your-ai4x-host:8000/mcp"
    }]
  ]
}
```

修改 opencode 配置后需要重启 opencode，运行中的会话不会热加载插件或配置变更。

插件本地验证：

```powershell
cd packages/opencode-plugin
npm test
```

一键发布新版本：

```powershell
cd packages/opencode-plugin
npm run release -- patch
```

发布脚本支持 `patch`、`minor`、`major` 或显式版本号，例如：

```powershell
npm run release -- 0.2.0
npm run release -- patch --otp 123456
npm run release -- 0.2.0 --tag beta
```

发布前预演：

```powershell
npm run release:dry-run -- patch
```

发布脚本会更新 `package.json` 和 `package-lock.json`，运行插件验证，从 `.opencode` 同步临时 `assets`，执行 `npm pack --dry-run`，最后执行 `npm publish --access public`。发布脚本结束后会清理临时 `assets`；`release:dry-run` 还会恢复版本文件。

## 6. 当前稳定输出面

当前仓库稳定维护的是工作区配置、插件打包结果和显式验收测试，而不是仓库根目录下的运行时输出目录。

主要稳定输出包括：

- `agent_app/opencode_app/.opencode/opencode.json`
- `agent_app/opencode_app/.opencode/workspace.contract.json`
- `packages/opencode-plugin` 打包产物
- `tests/test_opencode_workspace_config.py` 与 `tests/test_ai4x_platform_integration.py` 的显式验收结果

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
- progressive detail schema 获取（用于 `opencti`）
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

- `tests/test_opencode_workspace_config.py`
- `tests/test_ai4x_platform_integration.py`

## 9. 当前边界与注意事项

1. 这个仓库当前聚焦于 OPENCODE 工作区、AI4X MCP 边界和插件打包，不等于当前机器上的真实服务一定可用。
2. 真实模式下最常见失败点不是 Python listener，而是外部依赖未准备好，例如：
   - OPENCODE 容器未启动
   - provider 或 API key 配置错误
   - AI4X Platform 不可达
  - Docker 运行环境没有正常拉起
3. 插件打包与工作区合同测试不覆盖外部 AI4X 服务的可用性，真实集成仍需单独验证。

## 10. 给外部读者的建议上手顺序

如果你第一次接触这个项目，建议按这个顺序：

1. 先读本 README 的第 1、2、5 节，理解系统边界和三条使用路径。
2. 先启动 `agent_app/docker-compose.yml`，确认真实 OPENCODE 工作区能正常加载。
3. 再运行 `tests/test_opencode_workspace_config.py` 和 `tests/test_ai4x_platform_integration.py`。
4. 最后再接入真实 AI4X Platform，验证真实知识查询链路。

opencode serve --print-log --log-level DEBUG
