# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers the OPENCODE control plane under `agent_app/opencode_app/.opencode`.
- It is the primary implementation decomposition by business scenario and agent family.

## Stable Elements

- `agents/`: canonical agent-family definitions
- `skills/`: scenario SOP families
- `tools/`: OPENCODE-visible tool declarations and permission boundaries
- `opencode.json`, `workspace.contract.json`, `AGENTS.md`: workspace metadata and canonical role declarations

## Public Interfaces

- agent markdown entries under `agents/`
- skill directory entries under `skills/`
- JS tool entry points under `tools/`
- workspace metadata in `opencode.json` and `workspace.contract.json`

## Dependency Direction

- agent definitions may reference skill families and tool names, but not root service internals.
- skill families may orchestrate tool usage, but may not embed direct HTTP access when a runtime bridge exists.
- `.opencode/tools/*.js` may call the isolated runtime bridge and may emit tool-scoped permission handoff text.
- this control plane must not depend on root tests.

## Business Scenario And Agent Families

- Threat collaboration family: `ThreatIntelPrimary`, `ThreatIntelAnalyst`, `ThreatIntelSecOps`
- Incident and reporting family: `IncidentResponseAgent`, `IncidentReportingAgent`, `SecuritySituationalAwarenessAgent`
- IOC and attribution family: `IOCTriageAgent`, `ThreatIntelAttributionAnalyst`
- Hunt and graph family: `ThreatHunterAgent`, `AttackPathAgent`, `CypherGraphqlConversionWorker`, unknown threat hunt variants
- Risk and impact family: `SupplyChainRiskAgent`, `VulnerabilityImpactAgent`

These families are stable only as control-plane groupings. Low-level prompts, helper snippets, and transient wording inside a skill are not stable implementation elements.

## Implements Mapping

- `workspace.contract.json`, `opencode.json`, and `AGENTS.md` directly implement `ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE`.
- agent-family definitions directly implement `ELM-TECH-ARTIFACT-AGENT-DEFS`.
- collaboration loop skills directly implement `ELM-APP-PROC-THREAT-COLLAB-SKILL`.
- `.opencode/tools/ai4x_query.js` participates in the direct implementation of `1739 / Tools`.

## Explicit Acceptance Baselines Mounted Here

- `tests/test_opencode_workspace_config.py::test_opencode_workspace_config_declares_canonical_roles_and_aliases`
- `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`

## Frozen Critical Non-Explicit Guards

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_ai4x_query_tool_delegates_to_isolated_runtime_cli_module`
- `tests/test_architecture_contract_baselines.py::test_architecture_traceability_tags_remain_bound_to_canonical_entries`

## Protected Fixtures And Baselines

- `agents/ThreatIntelAnalyst_test.md`
- `tools/ai4x_query.js`
- `workspace.contract.json`
- `opencode.json`

## Ordinary Supporting Tests

- agent-specific contract tests in the repository-level `tests/` tree remain support guardrails, not root acceptance baseline definitions