import pytest

from services.result_assembler.assembler import assemble_structured_result, validate_structured_result
from services.result_assembler.schema import REQUIRED_TOP_LEVEL_FIELDS, RESULT_SCHEMA_VERSION


def test_assemble_structured_result_populates_required_fields_and_summary_counts() -> None:
    result = assemble_structured_result(
        run_context={
            "run_id": "ti-run-opencti-push-001-20260410T000000Z",
            "created_at": "2026-04-10T00:00:00+00:00",
            "event_id": "opencti-push-001",
            "source": "mock-opencti",
        },
        normalized_event={
            "event_id": "opencti-push-001",
            "source": "mock-opencti",
            "event_type": "opencti.push.indicator",
            "triggered_at": "2026-04-09T12:00:00Z",
            "summary": "Indicator tied to suspicious outbound traffic.",
            "entity": {"id": "indicator--555", "type": "indicator", "name": "Suspicious IP 203.0.113.10"},
            "observables": [{"type": "ipv4-addr", "value": "203.0.113.10"}],
            "labels": ["apt28"],
            "severity": "high",
        },
        evidence_bundle={
            "stix_bundle": "data/stix_samples/threat_intel_bundle.json",
            "searches": [{"match_count": 2}, {"match_count": 1}],
            "relationships": [{"relationship_count": 2}],
        },
        collaboration_output={
            "participants": ["ThreatIntelliganceCommander", "STIX_EvidenceSpecialist"],
            "role_outputs": [{"role": "STIX_EvidenceSpecialist", "summary": "APT28-linked evidence found."}],
            "traceability": {"event_id": "opencti-push-001"},
            "final_assessment": {
                "summary": "Evidence supports a phishing-related threat finding.",
                "confidence": "high",
                "verdict": "confirmed-threat",
                "supporting_entities": ["indicator--555"],
                "recommended_actions": ["Block the indicator"],
            },
        },
    )

    assert REQUIRED_TOP_LEVEL_FIELDS.issubset(result)
    assert result["schema_version"] == RESULT_SCHEMA_VERSION
    assert result["analysis_conclusion"]["supporting_entities"] == ["indicator--555"]
    assert result["recommended_actions"] == ["Block the indicator"]
    assert "3 object matches and 1 related relationship views" in result["key_information_summary"][1]


def test_validate_structured_result_requires_multiple_participants() -> None:
    with pytest.raises(ValueError, match="at least two participating analysis roles"):
        validate_structured_result(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "run_id": "ti-run-1",
                "generated_at": "2026-04-10T00:00:00+00:00",
                "event": {},
                "key_information_summary": [],
                "analysis_conclusion": {},
                "evidence_query_basis": {},
                "recommended_actions": [],
                "collaboration_trace": {"participants": ["ThreatIntelliganceCommander"]},
            }
        )
