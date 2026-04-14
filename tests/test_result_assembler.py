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
            "searches": [
                {
                    "query": "Indicator",
                    "match_count": 2,
                    "matches": [
                        {
                            "id": "indicator--555",
                            "type": "indicator",
                            "name": "Suspicious IP 203.0.113.10",
                            "description": None,
                            "pattern": None,
                            "value": None,
                            "confidence": None,
                        },
                        {
                            "id": "ipv4-addr--666",
                            "type": "ipv4-addr",
                            "name": "203.0.113.10",
                            "description": None,
                            "pattern": None,
                            "value": "203.0.113.10",
                            "confidence": None,
                        },
                    ],
                },
                {
                    "query": "203.0.113.10",
                    "match_count": 1,
                    "matches": [
                        {
                            "id": "ipv4-addr--666",
                            "type": "ipv4-addr",
                            "name": "203.0.113.10",
                            "description": None,
                            "pattern": None,
                            "value": "203.0.113.10",
                            "confidence": None,
                        }
                    ],
                },
            ],
            "relationships": [
                {
                    "stix_id": "indicator--555",
                    "object": {
                        "id": "indicator--555",
                        "type": "indicator",
                        "name": "Suspicious IP 203.0.113.10",
                        "description": None,
                        "pattern": None,
                        "value": None,
                        "confidence": None,
                    },
                    "relationship_count": 2,
                    "relationships": [
                        {
                            "relationship_id": "relationship--1",
                            "relationship_type": "indicates",
                            "direction": "outgoing",
                            "peer": {
                                "id": "intrusion-set--222",
                                "type": "intrusion-set",
                                "name": "APT28",
                                "description": None,
                                "pattern": None,
                                "value": None,
                                "confidence": None,
                            },
                        },
                        {
                            "relationship_id": "relationship--2",
                            "relationship_type": "related-to",
                            "direction": "outgoing",
                            "peer": {
                                "id": "ipv4-addr--666",
                                "type": "ipv4-addr",
                                "name": "203.0.113.10",
                                "description": None,
                                "pattern": None,
                                "value": "203.0.113.10",
                                "confidence": None,
                            },
                        },
                    ],
                }
            ],
        },
        collaboration_output={
            "participants": ["ThreatIntelPrimary", "ThreatIntelAnalyst"],
            "legacy_participants": ["ThreatIntelligenceCommander", "STIX_EvidenceSpecialist"],
            "role_outputs": [{"role": "ThreatIntelAnalyst", "summary": "APT28-linked evidence found."}],
            "traceability": {"event_id": "opencti-push-001", "assembled_by": "ThreatIntelPrimary"},
            "final_assessment": {
                "summary": "Evidence supports a phishing-related threat finding.",
                "confidence": "high",
                "verdict": "confirmed-threat",
                "supporting_entities": ["indicator--555"],
                "assembled_by": "ThreatIntelPrimary",
                "recommended_actions": ["Block the indicator"],
            },
        },
    )

    payload = result.model_dump(mode="python")

    assert REQUIRED_TOP_LEVEL_FIELDS.issubset(payload)
    assert result.schema_version == RESULT_SCHEMA_VERSION
    assert result.analysis_conclusion.supporting_entities == ["indicator--555"]
    assert result.recommended_actions == ["Block the indicator"]
    assert "3 object matches and 1 related relationship views" in result.key_information_summary[1]
    assert payload["collaboration_trace"]["assembly_contract"] == {
        "schema": "TASK-009",
        "assembled_by": "ThreatIntelPrimary",
        "assembly_location": "remote-primary",
        "contract_source": "services/result_assembler",
    }


def test_validate_structured_result_requires_multiple_participants() -> None:
    with pytest.raises(ValueError, match="at least two participating analysis roles"):
        validate_structured_result(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "run_id": "ti-run-1",
                "generated_at": "2026-04-10T00:00:00+00:00",
                "event": {
                    "event_id": "opencti-push-001",
                    "source": "mock-opencti",
                    "event_type": "opencti.push.indicator",
                    "triggered_at": "2026-04-09T12:00:00Z",
                    "summary": "Indicator tied to suspicious outbound traffic.",
                    "entity": {"id": "indicator--555", "type": "indicator", "name": "Suspicious IP"},
                    "observables": [{"type": "ipv4-addr", "value": "203.0.113.10"}],
                    "labels": ["apt28"],
                    "severity": "high",
                },
                "key_information_summary": ["summary"],
                "analysis_conclusion": {
                    "summary": "summary",
                    "confidence": "high",
                    "verdict": "confirmed-threat",
                    "supporting_entities": ["indicator--555"],
                },
                "evidence_query_basis": {
                    "stix_bundle": "data/stix_samples/threat_intel_bundle.json",
                    "searches": [],
                    "relationships": [],
                },
                "recommended_actions": [],
                "collaboration_trace": {
                    "participants": ["ThreatIntelPrimary"],
                    "role_outputs": [],
                    "traceability": {},
                    "assembly_contract": {
                        "schema": "TASK-009",
                        "assembled_by": "ThreatIntelPrimary",
                        "assembly_location": "remote-primary",
                        "contract_source": "services/result_assembler",
                    },
                },
            }
        )


def test_validate_structured_result_rejects_mismatched_nested_search_count() -> None:
    with pytest.raises(ValueError, match="match_count"):
        validate_structured_result(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "run_id": "ti-run-1",
                "generated_at": "2026-04-10T00:00:00+00:00",
                "event": {
                    "event_id": "opencti-push-001",
                    "source": "mock-opencti",
                    "event_type": "opencti.push.indicator",
                    "triggered_at": "2026-04-09T12:00:00Z",
                    "summary": "Indicator tied to suspicious outbound traffic.",
                    "entity": {"id": "indicator--555", "type": "indicator", "name": "Suspicious IP"},
                    "observables": [{"type": "ipv4-addr", "value": "203.0.113.10"}],
                    "labels": ["apt28"],
                    "severity": "high",
                },
                "key_information_summary": ["summary"],
                "analysis_conclusion": {
                    "summary": "summary",
                    "confidence": "high",
                    "verdict": "confirmed-threat",
                    "supporting_entities": ["indicator--555"],
                },
                "evidence_query_basis": {
                    "stix_bundle": "data/stix_samples/threat_intel_bundle.json",
                    "searches": [
                        {
                            "query": "203.0.113.10",
                            "match_count": 2,
                            "matches": [
                                {
                                    "id": "indicator--555",
                                    "type": "indicator",
                                    "name": "Suspicious IP",
                                    "description": None,
                                    "pattern": None,
                                    "value": None,
                                    "confidence": None,
                                }
                            ],
                        }
                    ],
                    "relationships": [],
                },
                "recommended_actions": ["Block the indicator"],
                "collaboration_trace": {
                    "participants": ["ThreatIntelPrimary", "ThreatIntelAnalyst"],
                    "legacy_participants": [],
                    "role_outputs": [{"role": "ThreatIntelAnalyst", "summary": "Evidence found."}],
                    "traceability": {"event_id": "opencti-push-001"},
                    "assembly_contract": {
                        "schema": "TASK-009",
                        "assembled_by": "ThreatIntelPrimary",
                        "assembly_location": "remote-primary",
                        "contract_source": "services/result_assembler",
                    },
                },
            }
        )
