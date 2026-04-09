"""Structured result assembly for the closed-loop analysis."""

# @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER

from __future__ import annotations

from typing import Any

from .schema import REQUIRED_TOP_LEVEL_FIELDS, RESULT_SCHEMA_VERSION


def assemble_structured_result(
    *,
    run_context: dict[str, Any],
    normalized_event: dict[str, Any],
    evidence_bundle: dict[str, Any],
    collaboration_output: dict[str, Any],
) -> dict[str, Any]:
    evidence_matches = sum(search.get("match_count", 0) for search in evidence_bundle.get("searches", []))
    relationship_count = len(evidence_bundle.get("relationships", []))
    final_assessment = collaboration_output.get("final_assessment", {})

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_id": run_context["run_id"],
        "generated_at": run_context["created_at"],
        "event": {
            "event_id": normalized_event["event_id"],
            "source": normalized_event["source"],
            "event_type": normalized_event["event_type"],
            "triggered_at": normalized_event["triggered_at"],
            "summary": normalized_event["summary"],
            "entity": normalized_event["entity"],
            "observables": normalized_event["observables"],
            "labels": normalized_event.get("labels", []),
            "severity": normalized_event.get("severity"),
        },
        "key_information_summary": [
            normalized_event["summary"],
            f"STIX semantic queries returned {evidence_matches} object matches and {relationship_count} related relationship views.",
            final_assessment.get("summary", "Commander summary unavailable."),
        ],
        "analysis_conclusion": {
            "summary": final_assessment.get("summary", "No conclusion produced."),
            "confidence": final_assessment.get("confidence", "medium"),
            "verdict": final_assessment.get("verdict", "needs-review"),
            "supporting_entities": final_assessment.get("supporting_entities", []),
        },
        "evidence_query_basis": evidence_bundle,
        "recommended_actions": final_assessment.get("recommended_actions", []),
        "collaboration_trace": {
            "participants": collaboration_output.get("participants", []),
            "role_outputs": collaboration_output.get("role_outputs", []),
            "traceability": collaboration_output.get("traceability", {}),
        },
    }

    validate_structured_result(result)
    return result


def validate_structured_result(result: dict[str, Any]) -> None:
    missing = REQUIRED_TOP_LEVEL_FIELDS.difference(result)
    if missing:
        raise ValueError(f"Structured result is missing required fields: {sorted(missing)}")

    participants = result["collaboration_trace"].get("participants", [])
    if len(participants) < 2:
        raise ValueError("Structured result must include at least two participating analysis roles.")
