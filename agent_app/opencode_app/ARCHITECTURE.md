# ARCHITECTURE

## Scope

This contract freezes the OPENCODE workspace control plane and runtime support boundary under `agent_app/opencode_app`.
It distinguishes the canonical remote MCP contract from workspace-local compatibility surfaces so Coding/Repair can evolve support assets without silently redefining acceptance boundaries.

## Stable Elements

1. `.opencode/opencode.json`
- Canonical remote MCP registration and default agent selection.

2. `.opencode/workspace.contract.json`
- Read-only workspace contract for transport, canonical tool names, fallback policy, and agent role mapping.

3. `tools/`
- Isolated Python-side support runtime dependencies required by the workspace dependency baseline.

4. `services/`
- Isolated service-side support dependencies mirrored into the OPENCODE runtime.

5. `data/`
- Workspace-local read-only sample data required by the workspace dependency baseline.

6. `tests/test_runtime_architecture_contract.py`
- Frozen critical non-explicit runtime guard.

## Interfaces

1. Control-plane interface
- `.opencode/opencode.json` and `.opencode/workspace.contract.json` define the canonical AI4X MCP registration, health probe, and tool naming contract.

2. Runtime support interface
- `agent_app/opencode_app/tools` and `agent_app/opencode_app/services` provide support-only local runtime files validated by the workspace dependency explicit testcase.
- `agent_app/opencode_app/data` provides workspace-local sample payloads used by the same dependency baseline.

3. Host runtime interface
- The canonical OPENCODE execution target for repository-driven validation is a host-side service at `http://127.0.0.1:4096`.
- Dockerized OPENCODE startup remains compatibility-only and is not the primary validation path for this repository.

## Dependency Direction

1. Runtime guard tests may read workspace config, workspace contract, and explicit AI4X acceptance test source text.
2. Workspace runtime files may depend on local `services`, `tools`, and `data` support modules under `agent_app/opencode_app`.
3. Explicit acceptance entrypoints must depend on remote MCP registration rather than direct calls to workspace-local compatibility wrappers.
4. Repository defaults and support scripts must target host-side OPENCODE at `http://127.0.0.1:4096` unless explicitly overridden by environment or test fixture.

## Intent Mapping

1. Direct implementation
- `.opencode/opencode.json` and `.opencode/workspace.contract.json` directly implement `ELM-INTENT-OPENCODE-WORKSPACE` and constrain `ELM-INTENT-AI4X-BOUNDARY`.

2. Indirect implementation chain
- `agent_app/opencode_app` runtime contracts -> `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies` implements `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

## Frozen Guardrails

1. Canonical MCP tool name remains `ai4x_query`.
2. Canonical default agent remains `安全运营助手`.
3. `fallback_http_api_allowed=true` remains permitted only as support for the remote MCP boundary, not as a replacement control path.
4. No repository-root runtime mirror is part of this stable element; runtime dependencies must stay inside `agent_app/opencode_app`.