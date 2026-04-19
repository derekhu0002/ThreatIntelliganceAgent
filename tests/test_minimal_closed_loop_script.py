import importlib.util
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script_module():
    script_path = REPO_ROOT / "scripts/run_minimal_closed_loop.py"
    spec = importlib.util.spec_from_file_location("run_minimal_closed_loop", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


@contextmanager
def _fake_server(base_url: str):
    class ServerHandle:
        def __init__(self, resolved_base_url: str) -> None:
            self.base_url = resolved_base_url

    yield ServerHandle(base_url)


def test_run_minimal_closed_loop_emits_verification_summary(monkeypatch, capsys) -> None:
    module = _load_script_module()
    recorded = {}

    def fake_run(command, cwd, check, capture_output, text):
        recorded["command"] = command
        recorded["cwd"] = cwd
        payload = {
            "analysis_conclusion": {"summary": "Structured result looks valid."},
            "recommended_actions": ["Block indicator", "Search for related activity"],
            "event": {"event_id": "opencti-push-001"},
            "evidence_query_basis": {
                "writeback_summary": {
                    "attempted": True,
                    "total_updates": 4,
                }
            },
            "collaboration_trace": {
                "participants": [
                    "ThreatIntelPrimary",
                    "ThreatIntelAnalyst",
                    "ThreatIntelSecOps",
                ]
            },
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.delenv("THREAT_INTEL_REMOTE_SERVER_URL", raising=False)
    monkeypatch.setattr(module, "start_mock_remote_server", lambda *, stix_data_path: _fake_server("http://127.0.0.1:8124"))

    module.main()

    output = json.loads(capsys.readouterr().out)
    assert recorded["cwd"] == REPO_ROOT
    assert recorded["command"][:3] == [sys.executable, "-m", "services.python_listener"]
    assert "--remote-server-url" in recorded["command"]
    assert recorded["command"][recorded["command"].index("--remote-server-url") + 1] == "http://127.0.0.1:8124"
    assert recorded["command"][recorded["command"].index("--output") + 1].endswith("artifacts\\runtime\\opencti-push-001-analysis.json")
    assert output["status"] == "passed"
    assert output["remote_endpoint"] == "http://127.0.0.1:8124"
    assert output["participant_count"] == 3
    assert output["recommended_action_count"] == 2
    assert output["neo4j_writeback_total_updates"] == 4


def test_run_minimal_closed_loop_allows_remote_url_override_via_env(monkeypatch, capsys) -> None:
    module = _load_script_module()
    recorded = {}

    def fake_run(command, cwd, check, capture_output, text):
        recorded["command"] = command
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "analysis_conclusion": {"summary": "Structured result looks valid."},
                    "recommended_actions": ["Block indicator"],
                    "collaboration_trace": {"participants": ["ThreatIntelPrimary", "ThreatIntelAnalyst"]},
                    "event": {"event_id": "opencti-push-001"},
                    "evidence_query_basis": {
                        "writeback_summary": {
                            "attempted": True,
                            "total_updates": 1,
                        }
                    },
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setenv("THREAT_INTEL_REMOTE_SERVER_URL", "http://127.0.0.1:9555")

    module.main()

    output = json.loads(capsys.readouterr().out)
    assert recorded["command"][recorded["command"].index("--remote-server-url") + 1] == "http://127.0.0.1:9555"
    assert output["remote_endpoint"] == "http://127.0.0.1:9555"


def test_run_minimal_closed_loop_rejects_missing_writeback_summary(monkeypatch) -> None:
    module = _load_script_module()

    def fake_run(command, cwd, check, capture_output, text):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "analysis_conclusion": {"summary": "Structured result looks valid."},
                    "recommended_actions": ["Block indicator"],
                    "collaboration_trace": {"participants": ["ThreatIntelPrimary", "ThreatIntelAnalyst"]},
                    "event": {"event_id": "opencti-push-001"},
                    "evidence_query_basis": {},
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.delenv("THREAT_INTEL_REMOTE_SERVER_URL", raising=False)
    monkeypatch.setattr(module, "start_mock_remote_server", lambda *, stix_data_path: _fake_server("http://127.0.0.1:8124"))

    try:
        module.main()
    except SystemExit as exc:
        assert str(exc) == "Validation failed: missing Neo4j writeback summary."
    else:
        raise AssertionError("Expected the script to reject results without writeback summary.")
