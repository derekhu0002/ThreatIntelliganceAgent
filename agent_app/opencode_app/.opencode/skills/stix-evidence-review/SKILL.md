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
- For CVE weaponization scenarios, prioritize evidence that ties a `vulnerability` to `malware`, exploit delivery infrastructure, or actor tradecraft, and state clearly whether the link is direct or inferred through intermediate relationships.
- For TTP hunting scenarios, pivot from `attack-pattern` / technique evidence into linked actors, malware, indicators, and infrastructure, then report the shortest traceable relationship chain that supports the hunt hypothesis.
- For APT profiling scenarios, collect organization-level evidence around actor aliases, linked malware families, attack patterns, and supporting indicators, and separate long-term actor profiling evidence from event-specific corroboration.
- When evidence is sparse for any of the above scenarios, explicitly say which schema-supported pivots were checked and which expected relationships were absent.
- Return analyst-ready evidence notes only. Do not assemble the final TASK-009 response, do not merge SecOps recommendations, and do not perform final remote-primary synthesis.
