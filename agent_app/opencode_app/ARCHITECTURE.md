# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers the isolated Python runtime under `agent_app/opencode_app`.
- It exists to keep OPENCODE compatibility flows independent from arbitrary repository imports while still exposing the minimum stable bridge into Python services during the MCP migration period.

## Stable Elements

- `tools/ai4x_cli.py`: transitional Python CLI bridge retained for compatibility harnesses and migration support.
- `services/ai4x_client.py`: transitional runtime-local AI4X HTTP client surface.
- `data/stix_samples/`: protected runtime fixture authority for local tool execution and acceptance harnesses.

## Public Interfaces

- Python module entry `tools.ai4x_cli`
- function surface exposed through `services.ai4x_client`
- runtime-local package markers `tools/__init__.py` and `services/__init__.py`

## Dependency Direction

- Upstream callers are compatibility wrappers or migration harnesses only.
- `tools/ai4x_cli.py` may depend on runtime-local `services/ai4x_client.py`.
- Runtime-local services may call external systems.
- For `source_id=opencti`, the runtime bridge must keep backend selection inside AI4X Platform's unified `query/universal` boundary: default `auto` mode prefers GraphQL and only falls back to replica when GraphQL cannot serve the requested read shape.
- This runtime must not depend on root tests, root `.opencode/agents`, or unrelated repository helpers.

## Implements Mapping

- This runtime bridge implements a transitional compatibility element declared in the root contract.
- Through that bridge, `tools/ai4x_cli.py` and `services/ai4x_client.py` indirectly support migration from the deprecated local path to the registered MCP boundary for `1739 / Tools`.

## Explicit Acceptance Baselines Mounted Here

- `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`

## Frozen Critical Non-Explicit Guards

- none

## Protected Fixtures And Baselines

- `.opencode/tools/ai4x_query_local.js`
- `tools/ai4x_cli.py`
- `services/ai4x_client.py`
- `data/stix_samples/threat_intel_bundle.json`

## Ordinary Supporting Tests

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_isolated_runtime_boundary_keeps_local_bridge_surface`
- future unit tests under `agent_app/opencode_app/tests/` that do not move or weaken the control-plane MCP contract