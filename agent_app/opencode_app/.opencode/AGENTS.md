# Threat Intelligence Agent Orchestration Boundary

<!-- @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE -->

Canonical remote execution workspace: `agent_app/opencode_app/.opencode/`.

The repo-root `.opencode/` is control-plane state only and must not be reused as the remote execution configuration plane.

## Canonical remote team

- `ThreatIntelPrimary` — remote Primary agent, owns delegation and final TASK-009 result assembly.
- `ThreatIntelAnalyst` — STIX-focused sub-agent, the only agent allowed to use the `stix_query` native tool.
- `ThreatIntelSecOps` — security-operations sub-agent, converts evidence into operational impact and actions.

## Legacy compatibility aliases

- `ThreatIntelliganceCommander` → `ThreatIntelPrimary`
- `STIX_EvidenceSpecialist` → `ThreatIntelAnalyst`
- `TARA_analyst` → `ThreatIntelSecOps`

Legacy descriptors remain in place as compatibility shims so existing tests, stubs, and validation assets do not break during migration.

## Boundary rules

- The Python listener remains a thin ingress boundary and must not perform STIX query or orchestration work locally.
- Remote collaboration follows `Primary -> Analyst -> SecOps -> Primary`.
- The final structured result must still satisfy the TASK-009 schema and be assembled on the remote side by `ThreatIntelPrimary`.

For local repository validation, `tools/threat_intel_orchestrator.js` remains a deterministic compatibility stub aligned to the canonical roles above.
