---
name: threat-intel-commander-loop
description: Commander workflow for synthesising specialist outputs into a structured threat-intelligence result.
---

# THREAT INTELLIGENCE COMMANDER LOOP

1. Receive normalized event context and STIX evidence summaries.
2. Delegate evidence interpretation to `STIX_EvidenceSpecialist`.
3. Delegate risk framing and actions to `TARA_analyst`.
4. Merge specialist outputs into a traceable final summary with explicit evidence references.
