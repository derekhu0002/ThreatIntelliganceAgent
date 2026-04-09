import json
from pathlib import Path

from services.python_listener.listener import ThreatIntelListener


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_listener_process_event_creates_result_with_evidence_and_output_file(
    tmp_path: Path, monkeypatch
) -> None:
    listener = ThreatIntelListener()
    output_path = tmp_path / "listener-result.json"

    def fake_orchestrator(run_context, normalized_event, evidence_bundle):
        assert run_context["event_id"] == normalized_event["event_id"]
        assert evidence_bundle["searches"]
        assert evidence_bundle["relationships"]
        return {
            "participants": ["ThreatIntelliganceCommander", "STIX_EvidenceSpecialist", "TARA_analyst"],
            "role_outputs": [
                {"role": "STIX_EvidenceSpecialist", "summary": "Evidence linked the indicator to APT28."},
                {"role": "TARA_analyst", "summary": "Impact is consistent with credential theft follow-up."},
            ],
            "traceability": {"event_id": normalized_event["event_id"]},
            "final_assessment": {
                "summary": "APT28-linked phishing infrastructure requires containment.",
                "confidence": "high",
                "verdict": "confirmed-threat",
                "supporting_entities": [normalized_event["entity"]["id"]],
                "recommended_actions": ["Block 203.0.113.10", "Hunt for related phishing artifacts"],
            },
        }

    monkeypatch.setattr(listener, "_invoke_orchestrator", fake_orchestrator)

    result = listener.process_event(
        REPO_ROOT / "data/mock_events/mock_opencti_push_event.json",
        output_path,
    )

    written_result = json.loads(output_path.read_text(encoding="utf-8"))
    assert written_result == result
    assert result["run_id"].startswith("ti-run-opencti-push-001-")
    assert result["event"]["event_id"] == "opencti-push-001"
    assert result["analysis_conclusion"]["verdict"] == "confirmed-threat"
    assert len(result["collaboration_trace"]["participants"]) == 3
    assert result["evidence_query_basis"]["searches"][0]["match_count"] >= 1
    assert result["evidence_query_basis"]["relationships"][0]["relationship_count"] >= 1
