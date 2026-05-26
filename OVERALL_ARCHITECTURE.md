# OVERALL_ARCHITECTURE

## Scope

This contract defines the minimal implementation architecture baseline aligned to the intent graph in design/KG/SystemArchitecture.json.
Current scope is intentionally limited to the AI4X runtime boundary and explicit acceptance entrypoints.

## Stable Architecture Elements

1. services
- Owns Python-side service contracts, listener dispatch boundaries, and result schema validation.

2. agent_app/opencode_app
- Owns isolated OPENCODE runtime assets and workspace control-plane contracts.

3. tests
- Owns explicit acceptance entrypoints and architecture guardrails that enforce canonical paths and traceability tags.

## Canonical AI4X Boundary

1. Canonical transport boundary is remote MCP registration in agent_app/opencode_app/.opencode/opencode.json and mirrored constraints in agent_app/opencode_app/.opencode/workspace.contract.json.
2. Canonical tool name is ai4x_query.
3. Local runtime wrappers are supporting runtime dependencies and do not replace the canonical remote MCP boundary.

## Explicit Acceptance Entrypoints

1. tests/test_ai4x_platform_integration.py
- test_ai4x_platform_catalog_exposes_available_data_range
- test_ai4x_platform_query_tool_returns_real_data_payload
- test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure
- test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service

2. tests/test_opencode_workspace_config.py
- test_opencode_app_contains_local_tool_runtime_dependencies

## Dependency Direction Guard

1. tests and runtime contracts may assert stable boundary behavior.
2. Implementation details are evolvable unless frozen by explicit acceptance entrypoints or workspace contract constraints.

## Validation Commands

1. npm run validate:system-architecture
2. npm run validate:handoff:intent
