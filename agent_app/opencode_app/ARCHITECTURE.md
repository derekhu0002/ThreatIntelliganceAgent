# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers the isolated Python runtime under `agent_app/opencode_app`.
- It exists to keep OPENCODE tool execution independent from arbitrary repository imports while still exposing the minimum stable bridge into Python services.

## Stable Elements

- `tools/ai4x_cli.py`: stable Python CLI bridge for AI4X catalog, schema, detail, and query commands.
- `services/ai4x_client.py`: stable runtime-local AI4X HTTP client surface.
- `data/stix_samples/`: protected runtime fixture authority for local tool execution and acceptance harnesses.

## Public Interfaces

- Python module entry `tools.ai4x_cli`
- function surface exposed through `services.ai4x_client`
- runtime-local package markers `tools/__init__.py` and `services/__init__.py`

## Dependency Direction

- Upstream callers are `.opencode/tools/*.js` only.
- `tools/ai4x_cli.py` may depend on runtime-local `services/ai4x_client.py`.
- Runtime-local services may call external systems.
- This runtime must not depend on root tests, root `.opencode/agents`, or unrelated repository helpers.

## Implements Mapping

- This runtime bridge implements the isolated runtime bridge element declared in the root contract.
- Through that bridge, `tools/ai4x_cli.py` and `services/ai4x_client.py` indirectly carry the intention `1739 / Tools` capability.

## Explicit Acceptance Baselines Mounted Here

- `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_catalog_exposes_available_data_range`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_query_tool_returns_real_data_payload`

## Frozen Critical Non-Explicit Guards

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_isolated_runtime_boundary_keeps_local_bridge_surface`
- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_ai4x_query_tool_delegates_to_isolated_runtime_cli_module`

## Protected Fixtures And Baselines

- `.opencode/tools/ai4x_query.js`
- `tools/ai4x_cli.py`
- `services/ai4x_client.py`
- `data/stix_samples/threat_intel_bundle.json`

## Ordinary Supporting Tests

- future unit tests under `agent_app/opencode_app/tests/` that do not move or weaken the frozen guards