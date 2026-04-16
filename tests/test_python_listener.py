import json
import os
from pathlib import Path
import re

import pytest

from services.mock_opencti_adapter import load_and_normalize_event
from services.remote_opencode_server import start_mock_remote_server
from services.python_listener.listener import ThreatIntelListener
from services.python_listener.remote_client import (
    RemoteDispatchError,
    RemoteOpencodeClient,
    load_default_main_agent,
    resolve_main_agent_alias,
)
from services.result_assembler import validate_structured_result


REPO_ROOT = Path(__file__).resolve().parents[1]
STIX_BUNDLE_PATH = REPO_ROOT / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json"
SHARED_GRAPH_PATH = REPO_ROOT / ".opencode/temp/SharedKnowledgeGraph.archimate3.1.json"


def _is_live_environment_ready() -> bool:
    return os.environ.get("live_environment_ready", "").strip().lower() in {"1", "true", "yes", "y"}


# @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
# @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
def _resolve_live_remote_timeout_seconds() -> float:
    configured_timeout = os.environ.get("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "").strip()
    if not configured_timeout:
        return 120.0

    try:
        timeout_seconds = float(configured_timeout)
    except ValueError as exc:
        raise AssertionError("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS must be a positive number when set.") from exc

    if timeout_seconds <= 0:
        raise AssertionError("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS must be a positive number when set.")

    return timeout_seconds


def _load_graph_derived_neo4j_settings(graph_path: Path = SHARED_GRAPH_PATH) -> dict[str, str]:
    graph_payload = json.loads(graph_path.read_text(encoding="utf-8"))
    elements_payload = graph_payload.get("elements", [])
    if isinstance(elements_payload, dict):
        elements = elements_payload.get("element", [])
    else:
        elements = elements_payload

    technology_node = next(
        (
            element
            for element in elements
            if isinstance(element, dict) and element.get("identifier") == "ELM-TECHNOLOGY-NODE"
        ),
        None,
    )
    if technology_node is None:
        raise AssertionError("Shared knowledge graph is missing ELM-TECHNOLOGY-NODE.")

    documentation = "\n".join(
        entry.get("value", "")
        for entry in technology_node.get("documentation", [])
        if isinstance(entry, dict) and isinstance(entry.get("value"), str)
    )

    uri_match = re.search(r"Bolt connection:\s*(?P<value>\S+)", documentation, flags=re.IGNORECASE)
    username_match = re.search(r"Username:\s*(?P<value>\S+)", documentation, flags=re.IGNORECASE)
    password_match = re.search(r"Password:\s*(?P<value>\S+)", documentation, flags=re.IGNORECASE)
    if uri_match is None or username_match is None or password_match is None:
        raise AssertionError("ELM-TECHNOLOGY-NODE documentation must expose Bolt URL, username, and password.")

    return {
        "uri": uri_match.group("value").rstrip("."),
        "username": username_match.group("value").rstrip("."),
        "password": password_match.group("value").rstrip("."),
    }


def _build_live_remote_request(listener: ThreatIntelListener, *, remote_server_url: str) -> dict[str, object]:
    normalized_event = load_and_normalize_event(REPO_ROOT / "data/mock_events/mock_opencti_push_event.json").to_dict()
    run_context = listener._create_run_context(normalized_event)
    neo4j_settings = _load_graph_derived_neo4j_settings()
    natural_language_request = (
        "ThreatIntelPrimary, perform a live end-to-end threat-intelligence assessment for a realistic "
        "vulnerability-analysis and security-incident-analysis scenario. A user on workstation FIN-WS-07 opened "
        "a phishing lure associated with credential theft activity, the host then communicated with 203.0.113.10, "
        "and responders suspect exploitation paths related to CVE-2023-23397 plus follow-on account compromise. "
        "Use the analyst Neo4j flow to correlate vulnerability context, incident entities, and local intelligence "
        f"evidence. The graph-derived Neo4j runtime contract for this live validation is Bolt URL {neo4j_settings['uri']}, "
        f"username {neo4j_settings['username']}, password {neo4j_settings['password']}. Return JSON only and satisfy "
        "the provided json_schema."
    )
    request_context = {
        "request_contract_version": "threat-intelligence-agent.remote-request.v2",
        "main_agent": "ThreatIntelPrimary",
        "requested_main_agent": "ThreatIntelPrimary",
        "remote_server_url": remote_server_url,
        "run_context": run_context,
        "event": normalized_event,
        "stix_elements": {
            "entity": normalized_event["entity"],
            "observables": normalized_event["observables"],
            "labels": normalized_event.get("labels", []),
            "severity": normalized_event.get("severity"),
        },
        "graph_derived_neo4j": neo4j_settings,
        "analysis_request_text": natural_language_request,
    }

    return {
        **request_context,
        "prompt_text": (
            f"{natural_language_request}\n"
            "REQUEST_CONTEXT_JSON:\n```json\n"
            f"{json.dumps(request_context, indent=2, ensure_ascii=False)}\n"
            "```"
        ),
    }


def test_listener_process_event_dispatches_remote_request_and_persists_remote_result(tmp_path: Path) -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-001
    # @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS
    # @ArchitectureID: ELM-DATA-STIX-ARGO-SCHEMA
    output_path = tmp_path / "listener-result.json"

    with start_mock_remote_server(stix_data_path=STIX_BUNDLE_PATH) as server:
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
                "main_agent": "ThreatIntelligenceCommander",
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
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-001
    # @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS
    default_agent = load_default_main_agent(REPO_ROOT)
    assert default_agent == "ThreatIntelPrimary"
    assert resolve_main_agent_alias("ThreatIntelligenceCommander", REPO_ROOT) == "ThreatIntelPrimary"
    assert resolve_main_agent_alias("ThreatIntelPrimary", REPO_ROOT) == "ThreatIntelPrimary"


def test_legacy_alias_resolution_has_deterministic_fallback_without_workspace_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-001
    # @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS
    monkeypatch.setattr(
        "services.python_listener.remote_client.load_workspace_config",
        lambda repo_root: {"default_agent": "ThreatIntelPrimary"},
    )

    assert resolve_main_agent_alias("ThreatIntelligenceCommander", REPO_ROOT) == "ThreatIntelPrimary"


def test_load_graph_derived_neo4j_settings_supports_archimate_exchange_model_shape(tmp_path: Path) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    # @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
    graph_path = tmp_path / "SharedKnowledgeGraph.archimate3.1.json"
    graph_path.write_text(
        json.dumps(
            {
                "elements": {
                    "element": [
                        {
                            "identifier": "ELM-TECHNOLOGY-NODE",
                            "documentation": [
                                {
                                    "value": (
                                        "Bolt connection: bolt://127.0.0.1:7687\n"
                                        "Username: neo4j\n"
                                        "Password: secret"
                                    )
                                }
                            ],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    assert _load_graph_derived_neo4j_settings(graph_path) == {
        "uri": "bolt://127.0.0.1:7687",
        "username": "neo4j",
        "password": "secret",
    }


def test_resolve_live_remote_timeout_seconds_defaults_to_extended_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    # @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
    monkeypatch.delenv("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", raising=False)

    assert _resolve_live_remote_timeout_seconds() == 120.0


def test_resolve_live_remote_timeout_seconds_accepts_positive_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    # @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
    monkeypatch.setenv("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "75")

    assert _resolve_live_remote_timeout_seconds() == 75.0


def test_resolve_live_remote_timeout_seconds_rejects_invalid_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    # @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
    monkeypatch.setenv("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "0")

    with pytest.raises(AssertionError, match="THREAT_INTEL_REMOTE_TIMEOUT_SECONDS must be a positive number"):
        _resolve_live_remote_timeout_seconds()


def test_live_threatintelprimary_e2e_request_uses_graph_derived_neo4j_contract_and_structured_validation() -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    # @ArchitectureID: ELM-APP-FUNC-EXECUTE-ANALYST-NEO4J-FLOW
    if not _is_live_environment_ready():
        pytest.skip(
            "Live E2E execution is blocked until @QualityAssurance confirms live_environment_ready with the human."
        )

    remote_server_url = os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL", "").strip()
    if not remote_server_url:
        pytest.skip("Set THREAT_INTEL_REMOTE_SERVER_URL after the human confirms live_environment_ready.")

    listener = ThreatIntelListener(
        remote_server_url=remote_server_url,
        remote_client=RemoteOpencodeClient(
            remote_server_url,
            timeout_seconds=_resolve_live_remote_timeout_seconds(),
        ),
    )
    request_payload = _build_live_remote_request(listener, remote_server_url=remote_server_url)

    prompt_text = str(request_payload["prompt_text"])
    assert request_payload["main_agent"] == "ThreatIntelPrimary"
    assert "vulnerability-analysis" in prompt_text
    assert "security-incident-analysis" in prompt_text
    assert "graph_derived_neo4j" in prompt_text
    assert "bolt://" in prompt_text

    result = listener.remote_client.dispatch_analysis(request_payload)
    validated = validate_structured_result(result)
    payload = validated.model_dump(mode="python")

    assert payload["schema_version"] == "threat-intelligence-agent.v1"
    assert payload["run_id"] == request_payload["run_context"]["run_id"]
    assert payload["collaboration_trace"]["assembly_contract"]["schema"] == "TASK-009"
    assert payload["collaboration_trace"]["assembly_contract"]["assembled_by"] == "ThreatIntelPrimary"
    assert "ThreatIntelPrimary" in payload["collaboration_trace"]["participants"]
    assert "ThreatIntelAnalyst" in payload["collaboration_trace"]["participants"]
    assert isinstance(payload["recommended_actions"], list)
