# Threat Intelligence Agent V1

## 1. 项目简介

本仓库实现的是 **Threat Intelligence Agent V1 的最小闭环**：

- 输入：一个 Mock OPENCTI PUSH 事件（当前样例为 `data/mock_events/mock_opencti_push_event.json`）
- Listener：Python 监听服务接收事件、提取事件中已有的 STIX elements、组装 prompt/request、指定 main agent、调用远端 OPENCODE SERVER
- Agent 侧：由远端 OPENCODE SERVER 负责主 agent 协作、语义查询、分析与结构化结果生成
- 输出：结构化 JSON 分析结果，落盘到 `artifacts/runtime/`

> 当前实现已经接入真实的 `session/message` 协议，但**不要把本仓库理解为“真实 server 已在当前环境稳定可用”**。代码路径已对接真实协议，实际 live 调用仍可能因 server/provider/api key 等环境问题失败。

## 2. 当前架构边界

### Python listener 的职责边界

`services/python_listener/` 只负责：

1. 接收/读取 PUSH 事件
2. 规范化事件内容
3. 从 PUSH 中提取已有的 STIX elements
4. 组装 remote request 与 prompt
5. 指定 main agent（默认读取 `agent_app/opencode_app/.opencode/opencode.json` 中的 `default_agent`）
6. 调用 remote OPENCODE SERVER：
   - `POST /session`
   - `POST /session/{sessionID}/message`
7. 校验并落盘结构化结果

### Remote OPENCODE SERVER 的职责边界

远端 OPENCODE SERVER 是主 agent 的执行边界，负责：

- 主 agent / specialist agent 协作
- 使用 agent-side tools / skills
- STIX 语义查询与证据整合
- 生成符合 JSON Schema 的结构化分析结果

### 不是 listener 本地依赖的内容

以下内容**属于 agent-side capabilities，不是 listener 的本地运行依赖**：

- `agent_app/opencode_app/.opencode/tools`
- `agent_app/opencode_app/tools/stix_cli`

它们当前保留在仓库内，主要用于：

- 远端 agent 工作区能力定义
- 本地测试/验证 stub
- 结果组装与最小闭环验证辅助

其中 `services/remote_opencode_server/mock_server.py` 是**协议兼容的本地 mock server**，用于测试和验证，不等同于真实可用的生产 server。

## 3. 主要目录说明

```text
agent_app/
  docker-compose.yml              # 启动 OPENCODE SERVER 的容器配置
  opencode_app/.opencode/         # agent、skills、opencode 配置

services/
  mock_opencti_adapter/           # Mock OPENCTI 事件适配与规范化
  python_listener/                # Python listener 入口与 remote client
  remote_opencode_server/         # 本地 mock remote server（测试/验证用）
  result_assembler/               # 结构化结果 schema 与校验/组装

agent_app/opencode_app/tools/stix_cli/ # STIX 2.1 语义查询 CLI（agent-side capability）
data/
  mock_events/                    # Mock OPENCTI PUSH 事件样例与 schema
  stix_samples/                   # 本地 STIX 样例数据
scripts/
  run_minimal_closed_loop.py      # 最小闭环验证脚本
tests/                            # pytest 测试
artifacts/runtime/                # 运行输出目录（结果文件）
validation/README.md              # 最小验证说明
```

## 4. 环境准备与依赖说明

### Python 侧

当前 listener/adapter/result assembler 代码使用的是 Python 标准库；仓库里**没有** `requirements.txt` / `pyproject.toml`。

建议环境：

- Python 3.11+ 或 3.12
- `pytest`（仅测试需要）

示例：

```bash
python3 --version
python3 -m pip install pytest
```

### OPENCODE SERVER / Agent 侧

- `agent_app/docker-compose.yml` 使用镜像：`ghcr.io/anomalyco/opencode`
- Compose 会先构建一个薄包装镜像，为 OPENCODE 补充 Python 3 运行时
- Agent 侧依赖已经内聚到 `agent_app/opencode_app/` 下，容器仅挂载该目录到 `/root/project_tia`
- `agent_app/opencode_app/` 内现在包含 agent-side `tools/stix_cli` 与 `data/stix_samples/` 运行依赖
- Compose 会读取仓库根目录的 `.env`
- 当前 `agent_app/opencode_app/.opencode/opencode.json` 中默认 provider 依赖：
  - `DEEPSEEK_API_KEY`

如果 provider、API key 或上游模型服务不可用，listener 虽然能发起真实协议请求，但 live 调用可能失败。

## 5. 如何启动 OPENCODE SERVER

参考 `agent_app/docker-compose.yml`：

```bash
docker compose -f agent_app/docker-compose.yml up
```

当前 compose 额外约束：

- 容器内提供 `python3` 和 `python` 两个可执行入口
- `THREAT_INTEL_REPO_ROOT=/root/project_tia`
- Python import 根路径指向 `agent_app/opencode_app` 自包含工作区，保证 `python -m tools.stix_cli` 可直接运行

或在 `agent_app/` 目录下运行：

```bash
docker compose up
```

当前映射关系：

- 容器内服务端口：`4096`
- 宿主机暴露端口：`8124`

因此默认 real server 地址为：

```text
http://127.0.0.1:8124
```

## 6. 如何运行 listener

直接运行模块入口：

```bash
python3 -m services.python_listener \
  --event data/mock_events/mock_opencti_push_event.json \
  --output artifacts/runtime/opencti-push-001-analysis.json \
  --remote-server-url http://127.0.0.1:8124
```

可选参数：

- `--main-agent`：覆盖默认 main agent
- `--remote-server-url`：覆盖默认 server 地址

默认 main agent 来自：

```text
agent_app/opencode_app/.opencode/opencode.json
```

当前默认值为：

```text
ThreatIntelliganceCommander
```

## 7. 如何运行最小闭环脚本

```bash
python3 scripts/run_minimal_closed_loop.py
```

脚本行为：

- 内部调用 `python -m services.python_listener`
- 默认远端地址：`http://127.0.0.1:8124`
- 输出验证摘要到标准输出
- 默认结果文件：`artifacts/runtime/validation-result.json`

也可以通过环境变量覆盖 server 地址：

```bash
THREAT_INTEL_REMOTE_SERVER_URL=http://127.0.0.1:9555 python3 scripts/run_minimal_closed_loop.py
```

## 8. 如何运行测试

运行全部测试：

```bash
pytest
```

或指定文件：

```bash
pytest tests/test_mock_opencti_adapter.py
pytest tests/test_python_listener.py
pytest tests/test_result_assembler.py
pytest tests/test_stix_cli.py
pytest tests/test_minimal_closed_loop_script.py
```

测试覆盖重点：

- Mock OPENCTI 事件契约与规范化
- Python listener 到 remote session/message 协议的派发
- 结构化结果 schema/校验
- STIX CLI 基础查询能力
- 最小闭环脚本行为

## 9. 当前已知问题 / 注意事项

1. 默认 real server 地址为：`http://127.0.0.1:8124`
2. 代码已经接到真实的 OPENCODE SERVER `session/message` 协议
3. 但在当前环境下，live 调用可能出现：
   - `POST /session` 返回 `502`
   - `POST /session/{sessionID}/message` 阶段超时
4. 这通常不是 listener 边界代码本身的问题，需优先检查：
   - OPENCODE SERVER 是否真正启动
   - provider 配置是否正确
   - API key 是否存在且有效
   - 上游模型服务是否可达
5. 仓库内有本地 mock remote server 用于测试协议路径，但它只是测试替身，不代表真实 server 健康可用

## 10. 输出结果样式与结果文件位置

listener 成功后会输出并落盘结构化 JSON，主要字段包括：

- `schema_version`
- `run_id`
- `generated_at`
- `event`
- `key_information_summary`
- `analysis_conclusion`
- `evidence_query_basis`
- `recommended_actions`
- `collaboration_trace`

默认结果位置：

- listener 默认：`artifacts/runtime/<event_id>-analysis.json`
- 最小闭环脚本默认：`artifacts/runtime/validation-result.json`

例如当前样例事件的常见输出文件名：

```text
artifacts/runtime/opencti-push-001-analysis.json
artifacts/runtime/validation-result.json
```
