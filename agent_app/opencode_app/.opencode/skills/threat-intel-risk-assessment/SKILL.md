---
name: threat-intel-risk-assessment
description: Convert evidence-grounded findings into threat impact and recommended actions.
---

# THREAT INTELLIGENCE RISK ASSESSMENT

- Use the event context plus reviewed STIX evidence to estimate likely threat significance.
- Do not call `db_schema_explorer` or `stix_query` from the SecOps role. If evidence is insufficient, request a fresh analyst pass instead.
- Provide a concise conclusion, confidence level, and 2-4 actionable recommendations.
- Keep the output structured and ready for commander synthesis.
