# Threat Intelligence Agent Orchestration Boundary

This workspace hosts the V1 multi-agent orchestration boundary for threat-intelligence analysis.

- `ThreatIntelliganceCommander`: coordinates the analysis run.
- `STIX_EvidenceSpecialist`: reviews STIX query evidence.
- `TARA_analyst`: converts evidence into risk-focused analysis and actions.

For local repository validation, `tools/threat_intel_orchestrator.js` emits a deterministic collaboration trace using these role definitions.
