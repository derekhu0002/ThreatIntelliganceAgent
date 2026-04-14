---
name: stix-evidence-review
description: Review STIX 2.1 evidence and extract traceable analyst findings.
---

# STIX EVIDENCE REVIEW

- Use this skill only to review STIX 2.1 JSON already returned by local evidence queries.
- Parse matched entities from query results and preserve their `id`, `type`, `name` or `value`, and any available `confidence` field.
- Parse relationship neighborhoods by extracting `relationship_type`, `direction`, and the peer object for each linked entity.
- Summarize evidence as concrete `matched_entities` and `relationship_findings`; do not invent links that are not present in the STIX bundle.
- Evaluate confidence conservatively:
	- treat explicit STIX `confidence` values as the primary signal,
	- note when confidence is absent, mixed, or inconsistent across matched objects,
	- distinguish high-confidence direct matches from low-confidence contextual associations.
- Highlight only evidence-bearing links such as actor, malware, infrastructure, campaign, or technique relationships that materially support downstream analysis.
- Return analyst-ready evidence notes only. Do not assemble the final TASK-009 response, do not merge SecOps recommendations, and do not perform final remote-primary synthesis.
