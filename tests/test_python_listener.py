import json
from pathlib import Path

from services.remote_opencode_server import start_mock_remote_server
from services.python_listener.listener import ThreatIntelListener


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_listener_process_event_dispatches_remote_request_and_persists_remote_result(tmp_path: Path) -> None:
    output_path = tmp_path / "listener-result.json"

    with start_mock_remote_server(stix_data_path=REPO_ROOT / "data/stix_samples/threat_intel_bundle.json") as server:
        listener = ThreatIntelListener(remote_server_url=server.endpoint_url)
        result = listener.process_event(
            REPO_ROOT / "data/mock_events/mock_opencti_push_event.json",
            output_path,
        )

    dispatched_payload = server.captured_requests[0]

    written_result = json.loads(output_path.read_text(encoding="utf-8"))
    assert written_result == result
    assert dispatched_payload["main_agent"] == "ThreatIntelliganceCommander"
    assert dispatched_payload["stix_elements"]["entity"]["id"] == "indicator--55555555-5555-4555-8555-555555555555"
    assert dispatched_payload["stix_elements"]["observables"][0]["value"] == "203.0.113.10"
    assert dispatched_payload["run_context"]["event_id"] == "opencti-push-001"
    assert "provided STIX entity and observables" in dispatched_payload["prompt"]
    assert result["run_id"].startswith("ti-run-opencti-push-001-")
    assert result["event"]["event_id"] == "opencti-push-001"
    assert result["analysis_conclusion"]["verdict"] == "confirmed-threat"
    assert len(result["collaboration_trace"]["participants"]) == 3
    assert result["evidence_query_basis"]["searches"][0]["match_count"] >= 1
    assert result["evidence_query_basis"]["relationships"][0]["relationship_count"] >= 1
    assert not hasattr(listener, "_collect_evidence")
    assert not hasattr(listener, "_invoke_stix_cli")
    assert not hasattr(listener, "_invoke_orchestrator")
