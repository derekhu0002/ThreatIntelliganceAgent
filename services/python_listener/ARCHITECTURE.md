# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers event ingress and remote OPENCODE dispatch under `services/python_listener`.

## Stable Elements

- `listener.py`: stable event ingress and output emission entry
- `remote_client.py`: stable OPENCODE session and message dispatch client

## Public Interfaces

- `ThreatIntelListener.process_event(...)`
- `RemoteOpencodeClient.dispatch_analysis(...)`
- workspace alias resolution helpers in `remote_client.py`

## Dependency Direction

- `listener.py` may depend on event normalization, remote dispatch, result validation, and optional Neo4j validation helpers.
- `remote_client.py` may depend on workspace metadata, MCP registration metadata, and result schema helpers.
- Neither file may depend on control-plane prompt wording, skill internals, or root tests.

## Implements Mapping

- This directory directly implements the runtime dispatch side of intention `1738 / Agents` for the AI4X data-consumption acceptance flow.
- Result validation and workspace alias resolution performed here are indirect support for `1738`, not separate top-level intention bindings.

## Explicit Acceptance Baselines Mounted Here

- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`

## Frozen Critical Non-Explicit Guards

- `tests/test_architecture_contract_baselines.py::test_explicit_ai4x_acceptance_entries_remain_at_canonical_paths`

## Protected Fixtures And Baselines

- `data/mock_events/mock_opencti_push_event.json`
- `agent_app/opencode_app/.opencode/agents/ThreatIntelAnalyst_test.md`
- `agent_app/opencode_app/.opencode/opencode.json`
- `agent_app/opencode_app/.opencode/workspace.contract.json`

## Ordinary Supporting Tests

- `tests/test_python_listener.py`
- future local tests under `services/python_listener/tests/` that do not alter the frozen guard surfaces