---
name: audit-compliance-check
description: Performs an architecture-to-code compliance audit using the Shared Knowledge Graph as the intent baseline, with read-only graph access.
---

# ARCHITECTURAL COMPLIANCE AUDIT

Use this skill to perform an architecture-to-code compliance check using repo-local reality and intent tools, then return a direct structured result to the caller.

## INPUT DATA
- A Task invocation from `ProjectOrchestrator` to audit the latest implementation batch.
- The input should include the implementation `commit_id` or enough completed task metadata to recover a single reviewed commit ID.

## SHARED KNOWLEDGE GRAPH SCOPE
- The Shared Knowledge Graph MUST conform to `.opencode/schema/archimate3.1/archimate3.1-exchange-model.schema.json`.
- Access Level: `Read Only`.
- Read scope: full intent model in `metadata`, `elements`, `relationships`, `organizations`, `propertyDefinitions`, and `extensions`.
- Focus scope: requirement, task, issue, file, code-construct, dependency, and release-traceability concepts needed to compare architectural intent against implementation reality.
- This agent may use `update_graph_model` only to record the audit outcome and gap summary.

## BEHAVIORAL RULES

1.  **Perform Scan**:
    - Resolve the single git commit ID being audited from the input or from completed runtime tasks.
    - If no single commit ID can be identified, fail the audit handoff as incomplete instead of auditing an ambiguous workspace state.
    - Use `bash` to inspect the reviewed commit with a narrow command such as `git show --stat --oneline <sha>` before running deeper reality analysis.
    - Use `run_reality_scanner` to analyze the codebase and generate a "reality" model that includes explicit trace markers, external architecture mappings, AST-extracted structural symbols, and semantic trace candidates.
    - Read the reviewed tasks and collect any explicit `architectureElementId` values before deciding whether architecture trace evidence is mandatory.

2.  **Compare Models**:
    - Use `query_graph(mode="summary")` and `query_graph(mode="search", scope="architecture", query="...")` to get the current "intent" model.
    - Inspect `architectureCoverage.missingCoreLayers` from the summary before auditing code details.
    - If any of `strategy`, `business`, `application`, or `technology` is missing, fail the audit as an intention-model gap and route back to `SystemArchitect`.
    - Inspect `intentionModel.isIntentModelSufficient`, `intentionModel.architecturalElementCount`, and `intentionModel.crossLayerRelationshipCount`.
    - If the graph contains only runtime-synchronized concepts, lacks architect-managed cross-layer relationships, or is otherwise too thin to act as a real intention contract, fail the audit as an intention-model gap before comparing code details.
    - If the reviewed implementation tasks contain one or more `architectureElementId` values, use `run_reality_scanner` output to confirm that the changed codebase exposes matching architecture trace evidence for those elements.
    - Accept trace evidence from any of these sources: matching `@ArchitectureID` markers, explicit entries in an external `architecture-mapping.yaml|yml|json` file, or mapping-symbol evidence that binds architecture IDs to extracted structural symbols.
    - Treat plain comment markers as only one form of evidence, not as the sole definition of architecture compliance.
    - Use `semanticTraces` as implicit supplementary evidence, not as the sole basis for architectural conformance. High semantic similarity can justify deeper review, but it does not override explicit trace mismatches.
    - Inspect `languageSupport` to understand whether changed files were analyzed through AST-backed providers or fallback extraction. If a changed language has only fallback coverage, lower audit confidence accordingly and state that limitation explicitly.
    - If no explicit trace evidence exists for a required `architectureElementId`, treat that as an implementation traceability gap even if the code otherwise appears plausible.
    - If the reviewed implementation tasks do not contain `architectureElementId`, report that handoff defect first instead of fabricating an ArchitectureID expectation from task titles alone.
    - Compare the "reality" model against the "intent" model to find any discrepancies (gaps), and keep the reviewed commit ID visible in the audit reasoning.

3.  **Report Findings**:
    - If gaps are found, use `generate_gap_report(intentSummary="...", realitySummary="...", gaps="...", recommendedActions="...")` to produce a structured report.
    - Use `update_graph_model(action="record_validation", kind="audit", status="passed|failed", commitId="<sha>", content="...")` to store audit status.
    - If gaps are important enough to track, use `update_graph_model(action="log_issue", kind="ArchitectureGap", title="...", content="...")`.
    - If audit fails, return the exact existing runtime task IDs that are implicated by the gap whenever they can be determined from the reviewed batch. Only recommend new task IDs when the architect must create genuinely new work.
    - Return JSON-like prose with `status`, `reviewed_commit_id`, `gaps`, `resolution_hint`, and `recommended_task_ids` when rework is needed.