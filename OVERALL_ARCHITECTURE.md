# ThreatIntelliganceAgent Overall Implementation Architecture Contract

## Scope

- This file is the unique root entry for the implementation architecture contract.
- It governs only the current workspace `d:\Projects\ThreatIntelliganceAgent`.
- It captures the user-confirmed top-level decomposition choice: primary decomposition follows business scenario and agent family, while shared runtime, orchestration, and contract substrates remain secondary stable elements.

## Repository Facts Confirmed Before This Contract

- `design/KG/SystemArchitecture.json` is the intention architecture source of truth for this task.
- The intention layer exposes explicit AI4X acceptance baselines through `1738 / Agents` and `1739 / Tools`, including the required tests in `tests/test_ai4x_platform_integration.py`.
- The repository previously had no `OVERALL_ARCHITECTURE.md`, and no `ARCHITECTURE.md` files.
- The current implementation already separates an OPENCODE control plane under `agent_app/opencode_app/.opencode`, an isolated Python runtime under `agent_app/opencode_app`, and root-level Python services under `services`.
- Explicit acceptance entry points already physically exist in `tests/test_ai4x_platform_integration.py` and `tests/test_opencode_workspace_config.py` and must remain callable without relocation.

## Global Rules

- Apply clean architecture, SOLID, deep module, separation of concerns, progressive disclosure, and stable abstract dependency direction.
- Stable implementation elements stop at stable directory, stable component, or key entry file granularity. Function-level helpers are not stable contract elements.
- Child `ARCHITECTURE.md` files may refine local responsibilities and local guards, but may not redefine root rules.
- Explicit acceptance baselines are read-only entry points during subsequent `/work` coding stages. Later work may satisfy them, but may not move them, rename them, widen them, or weaken their assertion boundaries.
- Critical non-explicit architecture guards are frozen in this phase only for four categories: architecture boundary, dependency direction, explicit entry correctness, and key implementation traceability.
- Ordinary supporting tests remain extensible during later coding stages as long as they do not violate the frozen guards or the explicit baselines.

## Top-Level Stable Elements

### 1. Agent Family Control Plane

- Location: `agent_app/opencode_app/.opencode`
- Role: primary top-level decomposition for business scenario and agent family orchestration.
- Stable local elements:
  - agent family definitions in `agents/`
  - scenario SOP families in `skills/`
  - control-plane tool declarations in `tools/`
  - workspace metadata and MCP registration boundary in `opencode.json`, `workspace.contract.json`, and `AGENTS.md`
- Local contract: `agent_app/opencode_app/.opencode/ARCHITECTURE.md`

### 2. Isolated Runtime Bridge

- Location: `agent_app/opencode_app`
- Role: secondary transitional substrate that still carries local Python runtime compatibility while the canonical AI4X discovery-and-query boundary moves to remote HTTP MCP.
- Stable local elements:
  - Python CLI bridge in `tools/ai4x_cli.py`
  - mirrored runtime services in `services/`
  - protected runtime data under `data/stix_samples/`
- Local contract: `agent_app/opencode_app/ARCHITECTURE.md`

### 3. Event Ingress And Remote Dispatch

- Location: `services/python_listener`
- Role: event normalization handoff, remote OPENCODE dispatch, and output emission entry.
- Stable local elements:
  - `listener.py`
  - `remote_client.py`
- Local contract: `services/python_listener/ARCHITECTURE.md`

### 4. Structured Result Assembly

- Location: `services/result_assembler`
- Role: result schema authority and structured output assembly.
- Stable local elements:
  - `assembler.py`
  - `schema.py`
  - `analysis_result.schema.json`
- Local contract: `services/result_assembler/ARCHITECTURE.md`

### 5. STIX Contract Authority

- Location: `services/stix_contracts`
- Role: STIX-facing typed contract and schema-catalog authority reused by ingestion, assembly, and runtime bridge.
- Stable local elements:
  - `models.py`
  - `catalog.py`
- Local contract: `services/stix_contracts/ARCHITECTURE.md`

## Primary Decomposition By Business Scenario And Agent Family

The primary implementation architecture follows business scenario and agent family rather than technical layer alone.

- Threat collaboration family:
  - canonical roles `ThreatIntelPrimary`, `ThreatIntelAnalyst`, `ThreatIntelSecOps`
  - collaboration loop and commander workflow in `.opencode/skills/threat-intel-collaboration/` and `.opencode/skills/threat-intel-commander-loop/`
- Incident and reporting family:
  - `IncidentResponseAgent`, `IncidentReportingAgent`, `SecuritySituationalAwarenessAgent`
- IOC and attribution family:
  - `IOCTriageAgent`, `ThreatIntelAttributionAnalyst`
- Hunt and graph investigation family:
  - `ThreatHunterAgent`, `AttackPathAgent`, `CypherGraphqlConversionWorker`, unknown threat hunting skills
- Risk and impact family:
  - `SupplyChainRiskAgent`, `VulnerabilityImpactAgent`

These families are stable only as control-plane decomposition. They do not bypass shared runtime, orchestration, or contract substrates.

## Key Interfaces And Dependency Direction

- Control plane dependency direction:
  - `agents/*` -> `skills/*` -> registered MCP tools
- Workspace registration dependency direction:
  - `agent_app/opencode_app/.opencode/opencode.json` declares the canonical remote AI4X MCP server registration
  - `agent_app/opencode_app/.opencode/workspace.contract.json` freezes the MCP server name, transport kind, health probe, and tool surface
- Runtime bridge dependency direction:
  - local compatibility wrappers under `.opencode/tools/*.js` may still call `agent_app/opencode_app/tools/*.py` -> `agent_app/opencode_app/services/*.py` -> external systems
  - those wrappers are no longer the canonical AI4X implementation boundary once remote MCP registration exists
- OpenCTI query strategy:
  - the registered MCP tool `ai4x_query` submits OpenCTI reads only through AI4X Platform's unified query boundary.
  - callers must treat OpenCTI query routing as platform-owned `auto` mode: prefer the GraphQL-backed path when supported and let the platform fall back to the replica path when GraphQL does not support the requested shape.
- Orchestration dependency direction:
  - `services/python_listener/listener.py` -> event normalization / remote dispatch / result validation
- Contract dependency direction:
  - `services/result_assembler` and `services/python_listener` may depend on `services/stix_contracts`
  - `services/stix_contracts` must not depend back on orchestration or control-plane files
- Forbidden reverse dependencies:
  - root `services/*` must not depend on `.opencode/agents/*` or `.opencode/skills/*`
  - `.opencode/tools/*` must not import root tests
  - explicit AI4X acceptance entrypoints must not treat `.opencode/tools/ai4x_query_local.js` as the canonical path once workspace MCP registration is present
  - scenario families must not embed direct external HTTP logic when a registered MCP boundary or isolated runtime bridge already exists

## Implements Mapping

### Direct Implementations Of Intention Elements

- `agent_app/opencode_app/.opencode` directly implements workspace and agent-definition intent boundaries represented by `ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE`, `ELM-TECH-ARTIFACT-AGENT-DEFS`, and `ELM-APP-PROC-THREAT-COLLAB-SKILL`.
- the remote AI4X MCP registration materialized in `agent_app/opencode_app/.opencode/opencode.json` directly implements the canonical `1739 / Tools` AI4X discovery-and-query boundary.
- `services/python_listener` directly implements the runtime dispatch side of `1738 / Agents` for the explicit AI4X data consumption flow.

### Indirect Implementation Chains

- `agent_app/opencode_app/.opencode/tools/ai4x_query_local.js` now acts only as a local compatibility wrapper. When present, it implements the transitional runtime bridge element rather than the canonical `1739` boundary.
- `agent_app/opencode_app/tools/ai4x_cli.py` implements the transitional isolated runtime bridge element; that bridge supports compatibility flows and migration harnesses but no longer defines the canonical AI4X tool boundary.
- `agent_app/opencode_app/services/ai4x_client.py` implements the local transitional service surface consumed by the compatibility bridge.
- `services/result_assembler` and `services/stix_contracts` implement shared contract substrates that are consumed by `services/python_listener`; therefore they indirectly support `1738` via the orchestration chain rather than directly binding every internal artifact to the intention layer.

## Explicit Acceptance Baselines

These entries are read-only acceptance baselines for later coding stages.

- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_catalog_exposes_available_data_range`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_query_tool_returns_real_data_payload`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure`
- `tests/test_ai4x_platform_integration.py::test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service`
- `tests/test_opencode_workspace_config.py::test_opencode_app_contains_local_tool_runtime_dependencies`

Rules:

- Keep each explicit testcase at its current physical path unless a future implementation-architecture decision redefines the acceptance baseline itself.
- Subsequent coding stages may call these entries directly but may not rewrite their acceptance meaning.

## Frozen Critical Non-Explicit Guards

### Architecture Boundary

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_workspace_contract_declares_remote_ai4x_mcp_server`

### Dependency Direction

- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_explicit_ai4x_acceptance_tests_do_not_execute_local_ai4x_wrapper_directly`

### Explicit Entry Correctness

- `tests/test_architecture_contract_baselines.py::test_explicit_ai4x_acceptance_entries_remain_at_canonical_paths`

### Key Implementation Traceability

- `tests/test_architecture_contract_baselines.py::test_architecture_traceability_tags_remain_bound_to_canonical_entries`

Frozen properties for the four guards:

- their physical entry paths
- their assertion boundary
- their mounted objects
- their traceability target
- their protected fixtures and baselines listed below

## Protected Fixtures And Baselines

- `agent_app/opencode_app/.opencode/agents/ThreatIntelAnalyst_test.md`
- `agent_app/opencode_app/.opencode/workspace.contract.json`
- `agent_app/opencode_app/.opencode/opencode.json`
- `agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json`
- `data/mock_events/mock_opencti_push_event.json`
- `tests/test_ai4x_platform_integration.py`
- `tests/test_opencode_workspace_config.py`

## Ordinary Supporting Test Guardrails

The following remain ordinary supporting guardrails and may be extended during later coding stages without changing the frozen acceptance and architecture guard surfaces.

- `tests/test_stix_contracts.py`
- `tests/test_result_assembler.py`
- `tests/test_mock_opencti_adapter.py`
- `agent_app/opencode_app/tests/test_runtime_architecture_contract.py::test_isolated_runtime_boundary_keeps_local_bridge_surface`
- agent-specific contract tests such as `tests/test_incident_response_agent.py`, `tests/test_ioc_triage_agent.py`, `tests/test_supply_chain_risk_agent.py`, `tests/test_vulnerability_impact_agent.py`, and related peers
- additional runtime or adapter unit tests under corresponding implementation directories

## Contract Index

- `agent_app/opencode_app/.opencode/ARCHITECTURE.md`
- `agent_app/opencode_app/ARCHITECTURE.md`
- `services/python_listener/ARCHITECTURE.md`
- `services/result_assembler/ARCHITECTURE.md`
- `services/stix_contracts/ARCHITECTURE.md`