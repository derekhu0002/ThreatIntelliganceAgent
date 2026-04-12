---
name: threat-intel-commander-loop
description: Legacy wrapper for the canonical threat-intel-collaboration skill.
---

# THREAT INTELLIGENCE COMMANDER LOOP

This legacy skill name remains for compatibility.

Use the canonical `threat-intel-collaboration` contract.

1. Receive normalized event context and STIX evidence summaries.
2. Delegate evidence interpretation to `ThreatIntelAnalyst` / `STIX_EvidenceSpecialist`.
3. Delegate risk framing and actions to `ThreatIntelSecOps` / `TARA_analyst`.
4. Assemble the final TASK-009-compatible result on the remote primary side.
