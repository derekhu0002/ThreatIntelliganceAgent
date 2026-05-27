# ARCHITECTURE

## Scope

This contract freezes the service-layer execution boundary that sits behind the AI4X explicit acceptance entrypoints.
It owns execution-time behavior, deterministic failure signaling, and schema/runtime contracts, but it does not own acceptance testcase definitions.

## Stable Elements

1. `python_listener`
- Owns OPENCODE dispatch behavior, remote request orchestration, and workspace-config-driven agent invocation.

2. `result_assembler`
- Owns structured analysis output assembly and output-shape validation.

3. `stix_contracts`
- Owns canonical schema/runtime catalog resolution and related contract failures surfaced to callers.

## Interfaces

1. Input boundary
- Receives normalized runtime payloads, environment configuration, and request metadata from OPENCODE-facing callers.

2. Output boundary
- Emits validated analysis artifacts or deterministic failures consumable by explicit acceptance tests and coding-stage repairs.

## Dependency Direction

1. `services/python_listener` may depend on `services/result_assembler` and `services/stix_contracts`.
2. `services/result_assembler` may depend on `services/stix_contracts` contract objects but not on test modules.
3. Service modules must not import from `tests` or workspace-local explicit entrypoint helpers.

## Intent Mapping

1. Direct implementation
- Service orchestration behavior realizes the runtime side of `ELM-INTENT-AI4X-BOUNDARY` by keeping AI4X access reachable through the remote MCP-oriented flow.

2. Indirect implementation chain
- `services/stix_contracts` -> `services/result_assembler` -> `services/python_listener` -> `tests/test_ai4x_platform_integration.py` jointly carry `ELM-INTENT-AI4X-EXPLICIT-ACCEPTANCE`.

## Frozen Guardrails

1. Missing canonical schema/runtime dependencies must fail deterministically and remain externally observable from the explicit entrypoints.
2. This layer may produce failure signals consumed by `artifacts/runtime/implementation-design-expected-failures.json`, but it must not redefine explicit testcase assertion boundaries.