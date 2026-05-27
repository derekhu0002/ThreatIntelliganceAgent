# ARCHITECTURE

## Scope

This contract freezes explicit acceptance entrypoints and the repository-level test guard ownership under `tests`.
Implementation Design may add supporting tests, but Coding/Repair must treat the explicit entrypoints and frozen critical guards below as read-only acceptance and architecture baselines.

## Explicit Entrypoints (Read-Only Acceptance Baseline)

1. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_catalog_exposes_available_data_range`
- Control point: `tools/list` followed by `tools/call` on remote `ai4x_query` with `command=catalog`.
- Observation point: response includes non-empty databases and consistent `total_databases`.

2. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_query_tool_returns_real_data_payload`
- Control point: remote `ai4x_query` call with `command=query` and a selected `sourceId`.
- Observation point: `source_id` matches input and payload exposes valid `items` and `count` semantics.

3. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure`
- Control point: remote `ai4x_query` schema call followed by detail call using a returned pointer.
- Observation point: schema and detail payloads preserve progressive disclosure semantics.

4. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`
- Control point: execute the real OPENCODE flow with the registered AI4X MCP environment against the canonical host endpoint `http://127.0.0.1:4096`.
- Observation point: session activity shows completed `catalog`, `schema`, and `query` tool calls.

5. `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`
- Control point: read workspace config and contract, then inspect isolated runtime paths.
- Observation point: remote MCP declaration remains canonical and required support-only runtime files exist.

## Critical Non-Explicit Tests (Frozen In Implementation Design)

1. `tests/test_architecture_contract_baselines.py`
- Kind: explicit entrypoint correctness guard and key implementation traceability guard.
- Control point: read canonical explicit entrypoint files.
- Observation point: explicit function names and required architecture tags remain present at the canonical paths.

2. `agent_app/opencode_app/tests/test_runtime_architecture_contract.py`
- Kind: architecture boundary guard, dependency direction guard, and explicit entrypoint correctness guard.
- Control point: read workspace contract files and explicit AI4X acceptance source text.
- Observation point: remote MCP boundary remains canonical and explicit entrypoints do not execute local AI4X wrappers directly.

## Supporting Non-Explicit Tests (Evolvable In Coding/Repair)

1. Non-explicit tests in `tests/test_opencode_workspace_config.py` outside the single explicit testcase entrypoint remain support guards for the compatibility/runtime surface.
2. Agent-specific scenario tests that still read `.opencode/tools/ai4x_query_local.js` remain evolvable compatibility tests unless promoted into a future frozen contract.

## Dependency Direction

1. Tests may read contracts, runtime assets, and emitted artifacts.
2. Production runtime code must not depend on test modules.
3. Supporting tests may cover compatibility surfaces, but explicit entrypoints must keep remote MCP or contract-read control points only.
4. Host-side OPENCODE validation now assumes `http://127.0.0.1:4096` as the default endpoint; compatibility ports such as `8124` are support-only and must not remain the canonical expectation in new or refreshed tests.

## Intent Mapping

1. Direct implementation
- The five explicit pytest node ids directly implement testcase baselines mounted under `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE` and `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

2. Key traceability guard
- Architecture tags in frozen files remain bound to canonical entrypoints and requirement mapping.