<!-- @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE -->

@RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
@ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE

# OPENCODE WORKSPACE CONTRACT

- The canonical workspace root is `agent_app/opencode_app/.opencode`.
- The repo-root `.opencode/` is control-plane state only.
- `ThreatIntelPrimary`, `ThreatIntelAnalyst`, and `ThreatIntelSecOps` are the canonical agent roles.
- Legacy aliases remain supported through workspace metadata and listener-side canonicalization.
