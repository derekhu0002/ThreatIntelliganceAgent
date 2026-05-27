# OVERALL_ARCHITECTURE

## Scope

This contract is the root implementation architecture for the AI4X-only intent baseline in `design/KG/SystemArchitecture.json`.
It freezes stable layers, explicit testcase ownership, critical non-explicit guards, and the handoff surface that Coding/Repair must consume without redefining acceptance boundaries.

## Stable Layers

1. `services`
- Owns Python-side execution services, listener dispatch, schema catalog resolution, and result assembly.

2. `agent_app/opencode_app`
- Owns OPENCODE workspace control-plane contracts, isolated runtime dependencies, and workspace-local runtime guards.

3. `tests`
- Owns explicit acceptance entrypoints and repository-level architecture guardrails.

## Stable Contract Files

1. `OVERALL_ARCHITECTURE.md`
2. `services/ARCHITECTURE.md`
3. `agent_app/opencode_app/ARCHITECTURE.md`
4. `tests/ARCHITECTURE.md`

## Canonical Interfaces

1. Remote AI4X MCP boundary
- Frozen at `agent_app/opencode_app/.opencode/opencode.json` and `agent_app/opencode_app/.opencode/workspace.contract.json`.
- Canonical tool name is `ai4x_query`.
- Explicit acceptance tests must cross this remote MCP boundary, not call workspace-local wrappers directly.

2. Workspace runtime support boundary
- Support-only local runtime dependencies live under `agent_app/opencode_app/tools`, `agent_app/opencode_app/services`, and `agent_app/opencode_app/data`.
- Workspace-local `.opencode/tools/ai4x_query.js` and `.opencode/tools/ai4x_query_local.js` remain compatibility surfaces, not the canonical acceptance boundary.

3. Service execution boundary
- `services/python_listener`, `services/result_assembler`, and `services/stix_contracts` provide execution-time behavior consumed by explicit entrypoints.

## Explicit Acceptance Entrypoints

1. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_catalog_exposes_available_data_range`
- Control point: initialize remote MCP session, list tools, call `ai4x_query` with `command=catalog`.
- Observation point: response exposes non-empty `databases` and `total_databases == len(databases)`.

2. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_query_tool_returns_real_data_payload`
- Control point: call remote `ai4x_query` with `command=query` and selected `sourceId`.
- Observation point: `source_id` echoes request and payload exposes valid `items` and `count` semantics.

3. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure`
- Control point: call remote `ai4x_query` with `command=schema`, then `command=detail` using a returned detail pointer.
- Observation point: schema payload exposes detail pointers and detail payload matches requested kind/type.

4. `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`
- Control point: trigger the real OPENCODE flow against the registered MCP environment.
- Observation point: session activity contains completed `ai4x_query` `catalog`, `schema`, and `query` calls.

5. `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`
- Control point: read `opencode.json` and `workspace.contract.json`, then inspect isolated runtime paths.
- Observation point: remote MCP declarations and fallback constraints are present and required support-only local runtime files exist.

## Critical Non-Explicit Tests (Frozen)

1. `agent_app/opencode_app/tests/test_runtime_architecture_contract.py`
- Categories: architecture boundary guard, dependency direction guard, explicit entrypoint correctness guard.
- Control point: inspect workspace runtime files and explicit AI4X acceptance source text.
- Observation point: remote MCP contract remains canonical and explicit acceptance tests do not route through local wrappers.

2. `tests/test_architecture_contract_baselines.py`
- Categories: explicit entrypoint correctness guard, key implementation traceability guard.
- Control point: read canonical explicit entrypoint files.
- Observation point: explicit pytest entry names and required architecture trace tags remain bound to canonical files.

## Supporting Non-Explicit Tests (Evolvable)

1. Supporting workspace compatibility tests remain in `tests/test_opencode_workspace_config.py` outside the single explicit testcase entrypoint.
2. Agent-level scenario tests that still inspect `ai4x_query_local.js` are compatibility/support guards and may evolve in Coding/Repair unless promoted by a contract update.
3. Supporting tests may expand coverage, but they must not rename or weaken explicit acceptance entrypoints or frozen critical guard assertions.

## Dependency Direction

1. `tests` may read stable contracts and runtime artifacts.
2. `agent_app/opencode_app` may depend on `services` and workspace-local support modules.
3. `services` must not depend on `tests`.
4. Compatibility surfaces under `.opencode/tools` must not become mandatory control points for the explicit AI4X acceptance baseline.

## Intent Mapping

1. Direct implementation
- `agent_app/opencode_app/.opencode/opencode.json` and `agent_app/opencode_app/.opencode/workspace.contract.json` directly implement `ELM-INTENT-OPENCODE-WORKSPACE` and constrain `ELM-INTENT-AI4X-BOUNDARY`.
- The five explicit pytest node ids above directly implement the testcase baselines mounted under `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE` and `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

2. Indirect implementation chains
- `services/stix_contracts` -> `services/result_assembler` -> `services/python_listener` -> explicit pytest entrypoints indirectly carry `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE`.
- `agent_app/opencode_app/tools` and `agent_app/opencode_app/services` support `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE` as local runtime dependencies without replacing the canonical MCP boundary.

## Validation Commands

1. `npm run validate:system-architecture`
2. `npm run validate:handoff:intent`
3. `npm run validate:handoff:implementation`
