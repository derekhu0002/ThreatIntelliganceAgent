# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers the OPENCODE control plane under `agent_app/opencode_app/.opencode`.
- It is the primary implementation decomposition by business scenario and agent family.

## Stable Elements

- `agents/`: canonical agent-family definitions
- `skills/`: scenario SOP families
- `tools/`: local compatibility wrappers and OPENCODE-visible tool declarations
- `opencode.json`, `workspace.contract.json`, `AGENTS.md`: workspace metadata, MCP registration boundary, and canonical role declarations

## Public Interfaces

- agent markdown entries under `agents/`
- skill directory entries under `skills/`
- registered MCP tool `ai4x_query`
- JS compatibility wrappers under `tools/`
- workspace metadata and MCP registration in `opencode.json` and `workspace.contract.json`

## Dependency Direction

- agent definitions may reference skill families and tool names, but not root service internals.
- skill families may orchestrate tool usage, but may not embed direct HTTP access when a runtime bridge exists.
- `opencode.json` owns the canonical remote AI4X MCP registration.
- `workspace.contract.json` freezes the MCP server name, transport kind, health probe path, and expected tool surface for that registration.
- `.opencode/tools/*.js` may exist only as transitional compatibility wrappers while remote MCP registration becomes canonical.
- skill and agent prompts must treat `opencti` queries as AI4X Platform-owned `auto` routing: plan GraphQL-friendly minimal reads first and rely on the platform, not the prompt, to fall back to replica when needed.
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
- the AI4X MCP server registration inside `opencode.json` directly implements `1739 / Tools`.
- `.opencode/tools/ai4x_query.js` is transitional support only and no longer defines the canonical `1739` boundary.

## Explicit Acceptance Baselines Mounted Here

- `tests/test_opencode_workspace_config.py::test_opencode_workspace_config_declares_canonical_roles_and_aliases`
- `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`

## Frozen Critical Non-Explicit Guards

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_workspace_contract_declares_remote_ai4x_mcp_server`
- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_explicit_ai4x_acceptance_tests_do_not_execute_local_ai4x_wrapper_directly`
- `tests/test_architecture_contract_baselines.py::test_architecture_traceability_tags_remain_bound_to_canonical_entries`

## Protected Fixtures And Baselines

- `agents/ThreatIntelAnalyst_test.md`
- `workspace.contract.json`
- `opencode.json`

## Ordinary Supporting Tests

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_isolated_runtime_boundary_keeps_local_bridge_surface`
- agent-specific contract tests in the repository-level `tests/` tree remain support guardrails, not root acceptance baseline definitions