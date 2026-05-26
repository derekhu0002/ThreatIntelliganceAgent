# ARCHITECTURE

## Scope

This contract freezes OPENCODE workspace runtime boundary behavior under `agent_app/opencode_app`.

## Stable Elements

1. `.opencode/opencode.json`
- Canonical runtime registration for remote MCP server usage and default primary agent.

2. `.opencode/workspace.contract.json`
- Read-only workspace architecture baseline for MCP transport, canonical tool names, fallback flags, and role aliases.

3. `tools/` and `services/`
- Local runtime dependencies that support execution but do not replace canonical remote MCP acceptance boundary.

4. `tests/test_runtime_architecture_contract.py`
- Frozen runtime architecture guard entrypoint.

## Interfaces

1. Control-plane interface
- Workspace config and contract files define MCP transport and role mapping.

2. Runtime dependency interface
- Isolated local Python and JS tool paths remain present for support-only use.

## Dependency Direction

1. Runtime guard tests may read workspace config/contract and explicit acceptance test source text.
2. Workspace runtime files must not force explicit acceptance tests to call local wrappers directly.

## Intent Mapping

1. Direct implementation
- Implements `ELM-INTENT-OPENCODE-WORKSPACE` through `.opencode/opencode.json` and `.opencode/workspace.contract.json`.

2. Indirect implementation chain
- `agent_app/opencode_app` runtime contracts -> `tests/test_opencode_workspace_config.py` entrypoint implements `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

## Frozen Guardrails

1. Canonical MCP tool name is `ai4x_query`.
2. Canonical default agent is `sec-copilot`.
3. Runtime contract continues to allow `fallback_http_api_allowed=true` while preserving remote MCP as canonical boundary.