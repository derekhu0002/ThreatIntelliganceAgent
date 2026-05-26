# ARCHITECTURE

## Scope

This contract freezes explicit acceptance test entrypoints and architecture guard test ownership under `tests`.

## Explicit Entrypoints (Read-Only Acceptance Baseline)

1. `tests/test_ai4x_platform_integration.py`
- `test_ai4x_platform_catalog_exposes_available_data_range`
- `test_ai4x_platform_query_tool_returns_real_data_payload`
- `test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure`
- `test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`

2. `tests/test_opencode_workspace_config.py`
- `test_opencode_app_contains_local_tool_runtime_dependencies`

## Critical Non-Explicit Tests (Frozen In Implementation Design)

1. `tests/test_architecture_contract_baselines.py`
- Guards canonical explicit entrypoint paths and architecture traceability tags.

2. `agent_app/opencode_app/tests/test_runtime_architecture_contract.py`
- Guards workspace runtime boundary, remote MCP contract, and explicit entrypoint call-pattern constraints.

## Supporting Non-Explicit Tests (Evolvable In Coding/Repair)

1. Non-explicit tests in this directory outside the two frozen guard files may evolve if they do not modify explicit acceptance entry boundaries.

## Control And Observation Discipline

1. Control point for explicit acceptance tests
- Invoke canonical remote MCP boundary or workspace contract read path only.

2. Observation point for explicit acceptance tests
- Assert externally observable payload semantics, tool-chain activity, contract values, and path-presence outcomes.

## Dependency Direction

1. Tests may read contracts and runtime artifacts.
2. Production runtime code must not depend on test modules.

## Intent Mapping

1. Direct implementation
- Explicit test entrypoints directly implement testcase baselines under `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE` and `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

2. Key traceability guard
- Architecture tags in frozen files remain bound to canonical entrypoints and requirement mapping.