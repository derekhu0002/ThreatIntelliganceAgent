"""Structured result assembly for the closed-loop analysis."""

# @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER
# @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from services.stix_contracts import AnalysisResultEvent, NormalizedMockOpenCTIEvent, ThreatAnalysisResult, parse_analysis_result

from .schema import RESULT_SCHEMA_VERSION


def _coerce_analysis_result_event(normalized_event: Mapping[str, Any] | NormalizedMockOpenCTIEvent) -> AnalysisResultEvent:
    if isinstance(normalized_event, NormalizedMockOpenCTIEvent):
        payload = {
            "event_id": normalized_event.event_id,
            "source": normalized_event.source,
            "event_type": normalized_event.event_type,
            "triggered_at": normalized_event.triggered_at,
            "summary": normalized_event.summary,
            "entity": normalized_event.entity.model_dump(mode="python"),
            "observables": [observable.model_dump(mode="python") for observable in normalized_event.observables],
            "labels": list(normalized_event.labels),
            "severity": normalized_event.severity,
        }
    else:
        payload = {
            "event_id": normalized_event["event_id"],
            "source": normalized_event["source"],
            "event_type": normalized_event["event_type"],
            "triggered_at": normalized_event["triggered_at"],
            "summary": normalized_event["summary"],
            "entity": normalized_event["entity"],
            "observables": normalized_event["observables"],
            "labels": normalized_event.get("labels", []),
            "severity": normalized_event.get("severity"),
        }
    return AnalysisResultEvent.model_validate(payload)


def assemble_structured_result(
    *,
    run_context: dict[str, Any],
    normalized_event: Mapping[str, Any] | NormalizedMockOpenCTIEvent,
    evidence_bundle: dict[str, Any],
    collaboration_output: dict[str, Any],
) -> ThreatAnalysisResult:
    # @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER
    event_contract = _coerce_analysis_result_event(normalized_event)
    evidence_matches = sum(search.get("match_count", 0) for search in evidence_bundle.get("searches", []))
    relationship_count = len(evidence_bundle.get("relationships", []))
    final_assessment = collaboration_output.get("final_assessment", {})

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_id": run_context["run_id"],
        "generated_at": run_context["created_at"],
        "event": {
            "event_id": event_contract.event_id,
            "source": event_contract.source,
            "event_type": event_contract.event_type,
            "triggered_at": event_contract.triggered_at,
            "summary": event_contract.summary,
            "entity": event_contract.entity.model_dump(mode="python"),
            "observables": [observable.model_dump(mode="python") for observable in event_contract.observables],
            "labels": list(event_contract.labels),
            "severity": event_contract.severity,
        },
        "key_information_summary": [
            event_contract.summary,
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
            "legacy_participants": collaboration_output.get("legacy_participants", []),
            "role_outputs": collaboration_output.get("role_outputs", []),
            "traceability": collaboration_output.get("traceability", {}),
            "assembly_contract": {
                "schema": "TASK-009",
                "assembled_by": final_assessment.get("assembled_by")
                or collaboration_output.get("traceability", {}).get("assembled_by"),
                "assembly_location": "remote-primary",
                "contract_source": "services/result_assembler",
            },
        },
    }

    return validate_structured_result(result)


def validate_structured_result(result: Mapping[str, Any] | ThreatAnalysisResult) -> ThreatAnalysisResult:
    try:
        return parse_analysis_result(result)
    except ValidationError as exc:
        for error in exc.errors():
            if tuple(error.get("loc", ())) == ("collaboration_trace", "participants") and error.get("type") == "too_short":
                raise ValueError("Structured result must include at least two participating analysis roles.") from exc
        raise ValueError(str(exc)) from exc
