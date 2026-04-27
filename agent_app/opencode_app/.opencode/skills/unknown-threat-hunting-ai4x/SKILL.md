---
name: unknown-threat-hunting-ai4x
description: Scenario workflow for graph-based unknown threat hunting that uses a single primary agent plus ai4x_query against OpenCTI.
---

# UNKNOWN THREAT HUNTING OVER AI4X / OPENCTI

Use this skill when the request is a graph-based hunt for an `intrusion-set`, only the primary scenario agent should execute the flow, and the workspace must query `ai4x_platform` through `ai4x_query` rather than by ad hoc HTTP calls.

The required tool sequence for this flow is `catalog -> schema -> query`.

## Primary-agent flow

1. `ThreatIntelUnknownHuntPrimary` identifies the hunt target and keeps the full flow inside the primary agent rather than delegating to scenario subagents.
2. `ThreatIntelUnknownHuntPrimary` calls `ai4x_query` with `command="catalog"` to confirm that `opencti` is available.
3. `ThreatIntelUnknownHuntPrimary` calls `ai4x_query` with `command="schema"` for `source_id=opencti` before building any read-only query.
4. `ThreatIntelUnknownHuntPrimary` runs the first `ai4x_query` `command="query"` call against the target `intrusion-set` to collect one-hop entities and IOC hits.
5. `ThreatIntelUnknownHuntPrimary` uses the IOC hits from that first query to run a second read-only `ai4x_query` `command="query"` call and identify shared infrastructure, related organizations, or reusable indicators.
6. `ThreatIntelUnknownHuntPrimary` returns structured output that explicitly separates direct facts from graph-derived inference and records `derived_leads`, `evidence_paths`, `recommendations`, and a `confidence_statement`.
7. If the target organization is absent or the second-stage pivot produces no new lead, the final result must still be a structured empty-result report that explains the miss rather than a plain failure string.

## Required report fields

- `request_id`
- `target_intrusion_set`
- `summary`
- `related_entities`
- `derived_leads`
- `evidence_paths`
- `recommendations`
- `confidence_statement`