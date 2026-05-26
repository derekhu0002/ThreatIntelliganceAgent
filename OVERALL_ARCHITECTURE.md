# OVERALL_ARCHITECTURE

## Scope

This contract defines the implementation architecture baseline aligned to `design/KG/SystemArchitecture.json` and `design/KG/IntentToImplementationHandoff.json`.
Current scope is intentionally limited to the AI4X remote MCP boundary, explicit acceptance entrypoints, and implementation guardrails required for Coding/Repair handoff.

## Stable Architecture Layers

1. `services`
- Owns Python-side service contracts, listener dispatch boundaries, result assembly, and schema catalog validation.

2. `agent_app/opencode_app`
- Owns isolated OPENCODE runtime assets and workspace control-plane contracts.

3. `tests`
- Owns explicit acceptance entrypoints and architecture guardrails that enforce canonical paths and traceability tags.

## Stable Element Contracts

1. `services/ARCHITECTURE.md`
2. `agent_app/opencode_app/ARCHITECTURE.md`
3. `tests/ARCHITECTURE.md`

## Canonical AI4X Boundary

1. Canonical transport boundary is remote MCP registration in `agent_app/opencode_app/.opencode/opencode.json` and mirrored constraints in `agent_app/opencode_app/.opencode/workspace.contract.json`.
2. Canonical tool name is `ai4x_query`.
3. Local runtime wrappers are supporting runtime dependencies and do not replace the canonical remote MCP boundary.

## Explicit Acceptance Entrypoints

1. `tests/test_ai4x_platform_integration.py`
- test_ai4x_platform_catalog_exposes_available_data_range
- test_ai4x_platform_query_tool_returns_real_data_payload
- test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure
- test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service

2. `tests/test_opencode_workspace_config.py`
- test_opencode_app_contains_local_tool_runtime_dependencies

## Critical Non-Explicit Guards (Frozen)

1. `agent_app/opencode_app/tests/test_runtime_architecture_contract.py`
- Categories: architecture boundary guard, dependency direction guard, explicit entrypoint correctness guard.

2. `tests/test_architecture_contract_baselines.py`
- Categories: explicit entrypoint correctness guard, key implementation traceability guard.

## Supporting Non-Explicit Guardrails (Evolvable)

1. Non-explicit tests outside frozen guard files remain evolvable in Coding/Repair.
2. Evolvable tests must preserve explicit testcase entrypoint paths and assertion boundaries.

## Intent To Implementation Mapping

1. Direct mappings
- `agent_app/opencode_app/.opencode/opencode.json` and `agent_app/opencode_app/.opencode/workspace.contract.json` directly implement `ELM-INTENT-OPENCODE-WORKSPACE` and constrain `ELM-INTENT-AI4X-BOUNDARY`.
- Explicit entrypoints in `tests/test_ai4x_platform_integration.py` directly implement `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE`.
- Explicit entrypoint `test_opencode_app_contains_local_tool_runtime_dependencies` in `tests/test_opencode_workspace_config.py` directly implements `ELM-INTENT-WORKSPACE-DEPENDENCY-BASELINE`.

2. Indirect mappings
- `services/stix_contracts` and `services/result_assembler` indirectly carry `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE` through runtime dependencies required by explicit entrypoint execution.

## Validation Commands

1. npm run validate:system-architecture
2. npm run validate:handoff:intent
3. npm run validate:handoff:implementation
