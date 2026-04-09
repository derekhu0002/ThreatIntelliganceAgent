---
name: orchestrator-main-loop
description: The primary thinking and delegation loop for the master project orchestrator. It manages the entire system building lifecycle from requirement triage to release and uses the Shared Knowledge Graph as the workflow state source of truth.
---

# PROJECT ORCHESTRATION MAIN LOOP

Use this skill to manage the full development lifecycle with native OpenCode primitives. Use Task-based subagent invocation, direct child-session returns, and the repo-local runtime state tools. Do not assume asynchronous mailboxes or fictional orchestration APIs.

## INPUT DATA
- **Initial Invocation Goal**: The high-level requirement or issue provided by the human when you are first activated.
- **Runtime Inputs**: Structured child results returned by the `ProductManager`, `SystemArchitect`, `Implementation`, `QualityAssurance`, `Audit`, and `ReleaseAgent` subagents.

## SHARED KNOWLEDGE GRAPH SCOPE
- The Shared Knowledge Graph MUST conform to `.opencode/schema/archimate3.1/archimate3.1-exchange-model.schema.json`.
- Access Level: `Read Only`.
- Read scope: project-level context, task backlogs, issue state, release readiness, and high-level traceability across `metadata`, `elements`, `relationships`, `organizations`, and `extensions`.
- This agent may use `query_graph`, `read_project_status`, `update_graph_model`, and `question` to inspect runtime execution state, persist orchestration decisions, and escalate hard blockers to a human.
- This agent MUST NOT perform implementation work itself when a specialist subagent should handle it.

## CORE BEHAVIORAL RULES (MANDATORY)

0.  **Runtime Circuit Breaker**
    - Treat repeated QA or Audit bounce-backs as a circuit-breaker problem, not as open-ended agent conversation.
    - Every persisted runtime task must carry a `retryCount` counter. If an older runtime record does not expose this field, treat it as `0` before making any routing decision.
    - The orchestrator owns this counter. Specialist agents may recommend rework, but they do not decide whether the workflow keeps looping.
    - When QA or Audit fails, identify the exact affected task IDs from the child result before routing rework. If the result does not name concrete task IDs, stop and report the validation handoff as incomplete rather than guessing.
    - Increment `retryCount` for each affected task through `update_graph_model` before routing the next rework attempt.
    - A task may be retried at most 3 times. If incrementing the counter would make `retryCount > 3`, immediately set that task status to `blocked`, persist the blocker reason, and stop automatic delegation.
    - When the circuit breaker opens, the orchestrator MUST call `question` to request human intervention from `Human_Developer`. The escalation must include the task IDs, current `retryCount`, last failing validator (`QA` or `Audit`), failure summary, and the reason automatic routing has been stopped.
        - The circuit-breaker `question` MUST use a single-choice recovery contract rather than an open-ended prompt. Tell the human to choose exactly one option and include these exact labels in the prompt:
            - `[已修复代码]`：`我（人类）已经手动改了代码并 commit，请直接重试 QA/Audit。`
            - `[架构需重构]`：`我决定变更架构，请把任务发回给 SystemArchitect，重置 retryCount。`
            - `[忽略偏差]`：`这是合理的架构偏差，请强行置为 Done。`
        - The `question` prompt MUST also remind the human that `[已修复代码]` is valid only after the manual fix is already committed to git.
        - After the human replies, treat the selected option as a workflow state transition, not as normal chat:
            - If `[已修复代码]` is selected, clear the `blocked` state on the affected tasks, preserve existing retry history, ensure the latest human fix commit is written back to the affected runtime tasks, and then re-enter validation immediately. If the affected tasks do not yet carry the human commit ID, invoke a narrow `Implementation` handoff whose only purpose is to inspect the latest human commit and persist `commitId` for the affected task IDs before QA/Audit resumes.
            - If `[架构需重构]` is selected, clear the `blocked` state on the affected tasks, reset `retryCount` to `0`, route the full failure context back to `SystemArchitect`, and continue in the `full-model` lane.
            - If `[忽略偏差]` is selected, use it only for architecture or audit deviations, not for failed functional QA. Persist the human override rationale through `update_graph_model`, force the affected task state to `done`, and continue only when all remaining release gates are satisfied.
        - After executing the selected recovery path, explicitly report which option was applied and which validator or child agent will run next.
    - Do not invoke `Implementation`, `SystemArchitect`, `Audit`, or `ReleaseAgent` again for a blocked task until the human provides an explicit next step.

1.  **Phase 1: Input Triage**
    - Upon activation, classify the **Initial Invocation Goal** along two axes: `input_type` and `execution_lane`.
    - Set `input_type` to `requirement` for new features, change requests, business requirements, user stories, capability requests, and scope proposals.
    - Set `input_type` to `issue` for bugs, regressions, production problems, failed validations, audit gaps, refactoring requests, or implementation/design defects.
    - Set `execution_lane` to `fast-track` only when the requested change is clearly localized, low-risk, and non-structural.
    - Typical `fast-track` candidates include UI color or spacing tweaks, copy edits, label or spelling fixes, simple content/config corrections, and narrow bug fixes inside an existing module where no new architecture decision is needed.
    - A request is **not** `fast-track` if it introduces or changes a capability boundary, workflow, public API, schema, persistence contract, security behavior, deployment behavior, package/module ownership, cross-module dependency, or any change that would reasonably require new software-unit decomposition.
    - If the lane is ambiguous, default to `full-model`.
    - If `input_type=requirement` and `execution_lane=full-model`, invoke `ProductManager` first through the native Task tool.
    - Expect a direct result from `ProductManager` containing at least `status`, `formal_requirement`, and `element_id` for the approved requirement.
    - Treat that approved requirement as the baseline goal for the subsequent architecture and implementation phases.
    - If `input_type=requirement` and `execution_lane=fast-track`, do not invoke `ProductManager` or `SystemArchitect` initially.
    - For a `fast-track` requirement, call `decompose_goal` with `maxTasks=1` to persist exactly one lightweight runtime task, then verify persistence with `read_project_status(section="tasks")` before invoking `Implementation`.
    - If `input_type=issue`, do not send it to `ProductManager`.
    - Route issue inputs to `SystemArchitect` when the issue concerns architecture intent, missing or incorrect design, software-unit decomposition, legacy-module fit, ArchitectureID traceability expectations, audit gaps, or any change that needs design-level judgment before coding.
    - Route issue inputs to `Implementation` when the issue is already implementation-scoped, code-facing, and can be acted on without new architecture decisions.
    - If `input_type=issue` and `execution_lane=fast-track`, first call `decompose_goal` with `maxTasks=1` so the runtime state records a single task for the change, then route that task to `Implementation`.
    - If an issue appears ambiguous between architecture and implementation, route it to `SystemArchitect` first.
    - For issue-driven invocations outside `fast-track`, skip `decompose_goal` unless `SystemArchitect` explicitly converts the issue into new planned implementation work.
    - A `fast-track` handoff to `Implementation` must explicitly include `lane: "fast-track"`, the original user request, the reason the change was judged non-structural, and an instruction to escalate back to `SystemArchitect` if the implementation turns out to have structural impact.

2.  **Phase 2: Goal Processing & Design Delegation**
    - This phase applies only to `full-model` work: requirement-driven work after `ProductManager` approval, or issue-driven work only when `SystemArchitect` has decided that new planned implementation tasks are required.
    - Do not enter this phase for `fast-track` work unless `Implementation` or `QualityAssurance` explicitly escalates the change back into the `full-model` lane.
    - Using the finalized goal, check workflow state. If it is missing or ambiguous, call `read_project_status(section="overview")` first to bootstrap the persisted project state before planning.
    - Use `decompose_goal` first to create a planning backlog in runtime state based on the formalized goal.
    - Immediately verify persistence with `read_project_status(section="tasks")`.
    - If persisted runtime state still has no tasks after `decompose_goal`, stop and report a runtime-tooling failure. Do not continue to `SystemArchitect` with inferred or remembered planning items.
    - Treat the persisted tasks from `decompose_goal` as planning seeds only. They are not yet valid developer tasks.
    - Then use the native Task tool to invoke `SystemArchitect` with the formalized goal, the full approved requirement, and the exact persisted planning list.
    - If the repository already contains meaningful implementation code, package structure, or established runtime conventions, require `SystemArchitect` to inspect that existing structure before decomposition and decide whether the change should extend an existing module or introduce a new software unit. Do not insert a separate brownfield-classification phase.
    - If the goal came from `ProductManager`, preserve the PM output separately instead of flattening it into a short goal string.
    - Pass the architect a concrete payload that includes `goal`, `formal_requirement`, `requirement_element_id`, `task_ids`, and `tasks`. Example shape: `{ "goal": "...", "formal_requirement": "...full approved requirement...", "requirement_element_id": "ELM-REQ-001", "task_ids": ["TASK-001", "TASK-002"], "tasks":[{"id":"TASK-001","title":"...","status":"todo","kind":"planning"}] }`.
    - Expect a direct result that includes a design summary, a software-unit decomposition, created or updated implementation task IDs, explicit confirmation that human architecture review is approved, and when existing implementation structure was analyzed a statement of which candidate module(s) were selected or rejected.
    - If the architect reports revision requested or does not confirm approved human review, do not continue to implementation. Route back to `SystemArchitect` until the reviewed design is approved.

3.  **Phase 3: Implementation Delegation**
    - For an issue that was routed directly to `Implementation`, use the implementation-oriented issue summary as the handoff baseline instead of waiting for `ProductManager`.
    - For `fast-track` work, use the original user request plus the persisted single-task runtime record as the handoff baseline. Do not wait for `ProductManager` or `SystemArchitect` unless the lane is escalated.
    - After `SystemArchitect` returns successfully for `full-model` work, use `read_project_status` or `query_graph` to determine the active task IDs.
    - Before invoking `Implementation` for `full-model` work, call `query_graph(mode="summary")` and inspect `architectureCoverage.missingCoreLayers`.
    - If any of `strategy`, `business`, `application`, or `technology` is missing for `full-model` work, stop implementation routing and send the workflow back to `SystemArchitect` to complete the intention baseline.
    - Also inspect `intentionModel.isIntentModelSufficient`. If it is `false` for `full-model` work, treat the design as underspecified even if the four layers nominally exist.
    - When the repository appears polyglot, the implementation language is unclear from the task metadata, or environment-specific execution constraints may affect implementation, call `run_reality_scanner` before invoking `Implementation` and inspect both `languageSupport` and `detectedEnvironments`.
    - Extract every `recommendedSkills` and `recommendedTools` entry from both `languageSupport` and `detectedEnvironments`, consolidate and de-duplicate them, and pass those consolidated arrays explicitly in the native Task handoff payload to `Implementation`.
    - Treat those arrays as opaque runtime context. The orchestrator is a generic context router and MUST NOT add any environment-specific branching such as Chrome-, Android-, or iOS-only logic.
    - Require the architect result to identify concrete software units and task IDs derived from those software units.
    - When existing implementation structure was analyzed, require the architect result to show that each implementation task is anchored either to an existing module chosen for extension or to a justified new software unit when no suitable module exists.
    - If the architect result does not reference concrete task IDs, or those tasks are missing software-unit metadata in persisted runtime state, stop and report that the architect handoff is incomplete.
    - For `fast-track` work, require exactly one active runtime task unless the child session explicitly justifies a second tightly-related task.
    - Invoke `Implementation` through the native Task tool with either the software-unit-scoped task IDs and architect summary for `full-model` work, or the single fast-track task ID plus an explicit `lane: "fast-track"` handoff for localized non-structural work.
    - Tell `Implementation` that `fast-track` changes must stay narrowly scoped and must be escalated back to `SystemArchitect` immediately if the code change touches architecture boundaries, schemas, APIs, infra, security behavior, or multiple software units.
    - Expect a direct result that includes completed tasks, blocked tasks, any clarification dependency that was resolved, work performed against the established intention baseline, and the git commit ID for the implementation batch.
    - If the implementation result does not include a commit ID, or completed runtime tasks do not record one, stop and report that the implementation handoff is incomplete.
    - After `Implementation` returns, immediately re-read persisted runtime state with `read_project_status(section="tasks")` or `query_graph(mode="tasks_by_status", status="done")` before advancing.
    - Treat persisted runtime state as the source of truth. A conversational child result is not sufficient by itself to prove implementation completion.

4.  **Phase 4: Parallel Validation**
    - Invoke `QualityAssurance` only if persisted runtime state shows at least one active task, at least one task with status `done`, and a recoverable implementation commit ID for that batch.
    - For `full-model` work, also invoke `Audit`.
    - For `fast-track` work, skip `Audit` by default.
    - Re-check `intentionModel.isIntentModelSufficient` before starting `Audit`. If the intention model is still weak, route back to `SystemArchitect` instead of auditing.
    - If runtime state is empty, unchanged, or contains no `done` task, do not start validation. Re-read state once, then route back to `Implementation` or `SystemArchitect` based on what is missing.
    - When validation setup needs repository execution context, call `run_reality_scanner` and inspect both `languageSupport` and `detectedEnvironments`.
    - Extract every `recommendedSkills` and `recommendedTools` entry from both `languageSupport` and `detectedEnvironments`, consolidate and de-duplicate them, and pass those consolidated arrays explicitly in the native Task handoff payload to `QualityAssurance`.
    - Pass the implementation `commit_id` explicitly to `QualityAssurance` in all lanes, and to `Audit` when `full-model` validation is required.
    - Require `QualityAssurance` and `Audit` to return concrete affected task IDs whenever they fail so retry accounting can be persisted without inference.
    - If a supposedly `fast-track` change is reported by `Implementation` or `QualityAssurance` as structurally impactful, traceability-sensitive, or no longer clearly non-architectural, escalate it into the `full-model` lane and invoke `SystemArchitect` before any release step.
    - Evaluate all child results that are relevant to the active lane before deciding the next step.

5.  **Phase 5: Decision and Rework**
    - **IF** `full-model` QA and Audit both pass, invoke `ReleaseAgent`.
    - **IF** `fast-track` QA passes and no escalation back to architecture was requested, invoke `ReleaseAgent`.
    - **IF** QA fails, require `affected_task_ids` in the QA result, increment `retryCount` for each affected task, and only invoke `Implementation` again when every affected task still has `retryCount <= 3`.
    - **IF** Audit fails, require `recommended_task_ids` in the audit result, increment `retryCount` for each affected task, and only invoke `SystemArchitect` when every affected task still has `retryCount <= 3`.
    - **IF** any affected task exceeds the retry limit after incrementing, set it to `blocked`, stop the workflow, and use `question` to escalate to `Human_Developer` with the full failure context.
    - **IF** the human selects `[已修复代码]`, do not start a fresh planning or coding loop. Resume from validation using the human-fixed commit as the handoff baseline.
    - **IF** the human selects `[架构需重构]`, re-enter the workflow through `SystemArchitect` with `retryCount` reset for the affected logical work items.
    - **IF** the human selects `[忽略偏差]`, allow it to bypass audit-style deviation blockers only. Never treat it as permission to ignore a failing QA result.
    - **IF** a `fast-track` change is escalated because it is no longer local or non-structural, invoke `SystemArchitect`, switch the workflow to `full-model`, and continue with architecture-led decomposition before resuming implementation.
    - **IF** the architect returns `ModelUpdated`, run `Audit` again.
    - **IF** the architect returns `ReworkRequired`, invoke `Implementation` with the refactoring task IDs while preserving retry history on any task IDs that still represent the same logical work item.
    - **IF** runtime state never reflects implementation progress, stop the workflow and report that the implementation agent did not persist execution state through the runtime-backed tools.

6.  **Phase 6: Release Delegation**
    - Invoke `ReleaseAgent` only after both QA and Audit return success.
    - Expect a direct release result that includes the generated release-log path and final summary.

7.  **Phase 7: Conclusion**
    - Report the final status to the user directly from the child-session results.