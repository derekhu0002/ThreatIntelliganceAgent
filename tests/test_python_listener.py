import json
from pathlib import Path

import pytest

from services.remote_opencode_server import start_mock_remote_server
from services.python_listener.listener import ThreatIntelListener
from services.python_listener.remote_client import (
    RemoteDispatchError,
    RemoteOpencodeClient,
    load_default_main_agent,
    resolve_main_agent_alias,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_listener_process_event_dispatches_remote_request_and_persists_remote_result(tmp_path: Path) -> None:
    output_path = tmp_path / "listener-result.json"

    with start_mock_remote_server(stix_data_path=REPO_ROOT / "data/stix_samples/threat_intel_bundle.json") as server:
        listener = ThreatIntelListener(remote_server_url=server.base_url)
        result = listener.process_event(
            REPO_ROOT / "data/mock_events/mock_opencti_push_event.json",
            output_path,
        )

    session_request = server.captured_requests[0]
    message_request = server.captured_requests[1]

    written_result = json.loads(output_path.read_text(encoding="utf-8"))
    assert written_result == result
    assert session_request["path"] == "/session"
    assert session_request["payload"] == {}
    assert message_request["path"].startswith("/session/")
    assert message_request["path"].endswith("/message")
    dispatched_payload = message_request["payload"]
    assert dispatched_payload["agent"] == "ThreatIntelPrimary"
    assert dispatched_payload["format"]["type"] == "json_schema"
    assert dispatched_payload["format"]["schema"]["properties"]["schema_version"]["const"] == "threat-intelligence-agent.v1"
    assert len(dispatched_payload["parts"]) == 1
    prompt_text = dispatched_payload["parts"][0]["text"]
    assert 'Main agent semantic: "ThreatIntelPrimary"' in prompt_text
    assert 'Requested main agent alias: "ThreatIntelPrimary"' in prompt_text
    assert '"id": "indicator--55555555-5555-4555-8555-555555555555"' in prompt_text
    assert '"value": "203.0.113.10"' in prompt_text
    assert '"event_id": "opencti-push-001"' in prompt_text
    assert result["run_id"].startswith("ti-run-opencti-push-001-")
    assert result["event"]["event_id"] == "opencti-push-001"
    assert result["analysis_conclusion"]["verdict"] == "confirmed-threat"
    assert len(result["collaboration_trace"]["participants"]) == 3
    assert result["collaboration_trace"]["participants"] == [
        "ThreatIntelPrimary",
        "ThreatIntelAnalyst",
        "ThreatIntelSecOps",
    ]
    assert result["collaboration_trace"]["legacy_participants"] == [
        "ThreatIntelPrimary",
        "STIX_EvidenceSpecialist",
        "TARA_analyst",
    ]
    assert result["collaboration_trace"]["assembly_contract"]["schema"] == "TASK-009"
    assert result["collaboration_trace"]["assembly_contract"]["assembled_by"] == "ThreatIntelPrimary"
    assert result["evidence_query_basis"]["searches"][0]["match_count"] >= 1
    assert result["evidence_query_basis"]["relationships"][0]["relationship_count"] >= 1
    assert not hasattr(listener, "_collect_evidence")
    assert not hasattr(listener, "_invoke_stix_cli")
    assert not hasattr(listener, "_invoke_orchestrator")


def test_remote_client_raises_when_message_response_has_no_structured_result() -> None:
    client = RemoteOpencodeClient("http://127.0.0.1:8124")

    responses = iter([
        {"id": "session-123"},
        {"message": {"role": "assistant", "content": [{"type": "text", "text": "not-json"}]}},
    ])

    client._post_json = lambda url, payload, action: next(responses)  # type: ignore[method-assign]

    with pytest.raises(RemoteDispatchError, match="did not include a valid structured analysis result"):
        client.dispatch_analysis(
            {
                "main_agent": "ThreatIntelliganceCommander",
                "prompt_text": "Return JSON only",
            }
        )


def test_remote_client_wraps_timeout_as_remote_dispatch_error() -> None:
    client = RemoteOpencodeClient("http://127.0.0.1:8124", timeout_seconds=1.5)
    calls = {"count": 0}

    def fake_open(http_request, timeout):
        calls["count"] += 1
        if calls["count"] == 1:
            raise TimeoutError("timed out")
        raise AssertionError("should not retry after timeout")

    client._opener.open = fake_open  # type: ignore[method-assign]

    with pytest.raises(RemoteDispatchError, match="timed out after 1.5s"):
        client._post_json("http://127.0.0.1:8124/session", {}, action="create remote session")


def test_default_main_agent_is_canonical_and_legacy_aliases_resolve() -> None:
    default_agent = load_default_main_agent(REPO_ROOT)
    assert default_agent == "ThreatIntelPrimary"
    assert resolve_main_agent_alias("ThreatIntelliganceCommander", REPO_ROOT) == "ThreatIntelPrimary"
    assert resolve_main_agent_alias("ThreatIntelPrimary", REPO_ROOT) == "ThreatIntelPrimary"
