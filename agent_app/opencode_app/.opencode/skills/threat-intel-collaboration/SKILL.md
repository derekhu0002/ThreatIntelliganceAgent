---
name: threat-intel-collaboration
description: Canonical multi-agent threat-intelligence collaboration contract for remote Primary, Analyst, and SecOps roles.
---

@RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
@ArchitectureID: ELM-APP-PROC-THREAT-COLLAB-SKILL
@ArchitectureID: ELM-APP-COMP-OPENCODE-THREAT-WORKSPACE
@ArchitectureID: ELM-APP-FUNC-CANONICALIZE-THREAT-ANALYST-CONTRACT

# THREAT INTELLIGENCE COLLABORATION CONTRACT

## Trigger conditions

Activate this skill when the remote workspace receives a threat-intelligence push-analysis request containing normalized event context, STIX-relevant entities/observables, and a requirement to return a structured result.

## Delegation order

1. `ThreatIntelPrimary` validates the incoming request contract and owns the final answer.
2. For deterministic remote PUSH requests that already include normalized event context, `ThreatIntelPrimary` must satisfy the contract directly on the remote side and return the full TASK-009 schema result without retired workspace-local compatibility tools.
3. Only if the incoming request does not match that deterministic remote contract may `ThreatIntelPrimary` delegate evidence review to `ThreatIntelAnalyst`.
4. `ThreatIntelAnalyst` must return precise evidence and any traceable writeback summary through surviving canonical runtime capabilities rather than retired workspace-local wrappers.
6. If `ThreatIntelAnalyst` returns no relevant local threat-intelligence evidence, `ThreatIntelPrimary` must skip deep SecOps assessment and return a minimal TASK-009 result stating `未发现本地 STIX 情报关联`.
7. If analyst evidence exists, `ThreatIntelPrimary` delegates operational impact and actions to `ThreatIntelSecOps` using the analyst return payload while retaining final TASK-009 assembly ownership.
8. `ThreatIntelPrimary` merges event context, analyst findings, optional writeback traceability, and optional SecOps output into the final schema response on the remote side.

## Return structure

- Analyst return:
  - `role`
  - `summary`
  - `supporting_evidence_refs`
  - `matched_entities`
  - `relationship_findings`
  - `confidence_notes`
  - `writeback_summary`
- SecOps return:
  - `role`
  - `summary`
  - `verdict`
  - `confidence`
  - `recommended_actions`
- Primary final return:
  - Must satisfy the structured result schema used by `services/result_assembler/`
  - Must include core fields: `schema_version`, `run_id`, `event`, `analysis_conclusion`, `recommended_actions`, and `collaboration_trace`
  - Must include `collaboration_trace.participants`
  - Must include role outputs traceability
  - Must record that the final assembly was performed by the remote Primary role
  
## End conditions

Finish only when:

- STIX evidence has been reviewed,
- SecOps recommendations have been produced,
- the remote Primary has assembled the final structured result,
- and the final payload is ready for listener-side consumption/validation without additional local synthesis.

## Compatibility notes

- `ThreatIntelligenceCommander` maps to `ThreatIntelPrimary`.
- `STIX_EvidenceSpecialist` maps to `ThreatIntelAnalyst`.
- `TARA_analyst` maps to `ThreatIntelSecOps`.
- Retired workspace-local wrappers are not part of the current collaboration contract.
- The canonical collaboration chain is `Primary -> Analyst -> SecOps -> Primary`.
