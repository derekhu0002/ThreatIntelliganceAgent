# ARCHITECTURE

## Scope

This contract freezes the service-layer implementation boundary for listener orchestration, result assembly, and schema contract validation.

## Stable Elements

1. python_listener
- Owns remote OPENCODE invocation boundary and workspace-config-driven agent selection.

2. result_assembler
- Owns structured output contract validation and schema version invariants.

3. stix_contracts
- Owns canonical STIX schema catalog resolution and schema-derived typing contracts.

## Interfaces

1. Input boundary
- Receives normalized event payloads and runtime environment configuration.

2. Output boundary
- Emits validated structured analysis artifacts and failure signals consumable by test entrypoints.

## Dependency Direction

1. `services/python_listener` may depend on `services/result_assembler` and `services/stix_contracts`.
2. Service modules must not depend on acceptance tests.

## Intent Mapping

1. Direct implementation
- Implements `ELM-INTENT-AI4X-BOUNDARY` by enforcing remote MCP-oriented request flow.

2. Indirect implementation chain
- `services/stix_contracts` -> `services/result_assembler` -> explicit entrypoints in `tests/` jointly carry `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE`.

## Frozen Guardrails

1. Missing canonical schema catalog path must raise deterministic failure and stay externally observable in explicit entrypoint execution.
2. This layer does not redefine explicit testcase assertion boundaries; it only supplies execution-time contracts.