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
            "run_id": "ti-run-opencti-push-001-20260419T000000Z",
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
    monkeypatch.setattr(module, "ensure_neo4j_validation_container", lambda repo_root: {"uri": "neo4j://127.0.0.1:7698", "database": "neo4j", "username": "neo4j", "password": "11111111"})
    monkeypatch.setattr(module, "reset_validation_projection", lambda event_id, settings: None)
    monkeypatch.setattr(
        module,
        "load_validation_projection",
        lambda run_id, event_id, settings: {
            "participant_count": 3,
            "recommended_action_count": 2,
            "conclusion_summary": "Persisted summary",
        },
    )

    module.main()

    output = json.loads(capsys.readouterr().out)
    summary_path = REPO_ROOT / "artifacts/runtime/opencti-push-001-acceptance-summary.json"
    assert recorded["cwd"] == REPO_ROOT
    assert recorded["command"][:3] == [sys.executable, "-m", "services.python_listener"]
    assert "--remote-server-url" in recorded["command"]
    assert recorded["command"][recorded["command"].index("--remote-server-url") + 1] == "http://127.0.0.1:8124"
    assert recorded["command"][recorded["command"].index("--output") + 1].endswith("artifacts\\runtime\\opencti-push-001-analysis.json")
    assert output["acceptance_case"]["id"] == "1726"
    assert output["acceptance_case"]["type"] == "closed-loop-acceptance"
    assert output["status"] == "passed"
    assert output["acceptance_summary_path"] == "artifacts/runtime/opencti-push-001-acceptance-summary.json"
    assert output["remote_endpoint"] == "http://127.0.0.1:8124"
    assert output["neo4j_uri"] == "neo4j://127.0.0.1:7698"
    assert output["participant_count"] == 3
    assert output["recommended_action_count"] == 2
    assert output["neo4j_writeback_total_updates"] == 4
    assert output["neo4j_persisted_participant_count"] == 3
    assert output["neo4j_persisted_recommended_action_count"] == 2
    assert json.loads(summary_path.read_text(encoding="utf-8")) == output


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
                    "run_id": "ti-run-opencti-push-001-20260419T000000Z",
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
    monkeypatch.setattr(module, "ensure_neo4j_validation_container", lambda repo_root: {"uri": "neo4j://127.0.0.1:7698", "database": "neo4j", "username": "neo4j", "password": "11111111"})
    monkeypatch.setattr(module, "reset_validation_projection", lambda event_id, settings: None)
    monkeypatch.setattr(
        module,
        "load_validation_projection",
        lambda run_id, event_id, settings: {
            "participant_count": 2,
            "recommended_action_count": 1,
            "conclusion_summary": "Persisted summary",
        },
    )

    module.main()

    output = json.loads(capsys.readouterr().out)
    assert output["acceptance_case"]["name"] == "[闭环验收/集成验收]标准高危威胁事件闭环分析"
    assert recorded["command"][recorded["command"].index("--remote-server-url") + 1] == "http://127.0.0.1:9555"
    assert output["remote_endpoint"] == "http://127.0.0.1:9555"


def test_run_minimal_closed_loop_retries_transient_external_listener_failure(monkeypatch, capsys) -> None:
    module = _load_script_module()
    calls = {"count": 0}

    def fake_run(command, cwd, check, capture_output, text):
        calls["count"] += 1
        if calls["count"] == 1:
            raise subprocess.CalledProcessError(
                1,
                command,
                output="",
                stderr="RemoteDispatchError: Failed to dispatch remote message: remote server request timed out after 120.0s",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "run_id": "ti-run-opencti-push-001-20260419T000000Z",
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
    monkeypatch.setattr(module, "ensure_neo4j_validation_container", lambda repo_root: {"uri": "neo4j://127.0.0.1:7698", "database": "neo4j", "username": "neo4j", "password": "11111111"})
    monkeypatch.setattr(module, "reset_validation_projection", lambda event_id, settings: None)
    monkeypatch.setattr(
        module,
        "load_validation_projection",
        lambda run_id, event_id, settings: {
            "participant_count": 2,
            "recommended_action_count": 1,
            "conclusion_summary": "Persisted summary",
        },
    )

    module.main()

    output = json.loads(capsys.readouterr().out)
    assert calls["count"] == 2
    assert output["status"] == "passed"


def test_run_minimal_closed_loop_reexecs_into_repo_venv_when_neo4j_missing(monkeypatch) -> None:
    module = _load_script_module()
    repo_python = REPO_ROOT / ".venv/Scripts/python.exe"
    recorded = {}

    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: None if name == "neo4j" else object())
    monkeypatch.setattr(module, "_resolve_repo_venv_python", lambda repo_root: repo_python)
    monkeypatch.delenv(module.REEXEC_ENV, raising=False)

    def fake_execv(executable, argv):
        recorded["executable"] = executable
        recorded["argv"] = argv
        raise SystemExit(0)

    monkeypatch.setattr(module.os, "execv", fake_execv)

    try:
        module._bootstrap_runtime_python(REPO_ROOT)
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("Expected bootstrap to re-exec into the repo virtual environment.")

    assert recorded["executable"] == str(repo_python)
    assert recorded["argv"][0] == str(repo_python)
    assert recorded["argv"][1] == str((REPO_ROOT / "scripts/run_minimal_closed_loop.py").resolve())


def test_run_minimal_closed_loop_rejects_missing_writeback_summary(monkeypatch) -> None:
    module = _load_script_module()

    def fake_run(command, cwd, check, capture_output, text):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "run_id": "ti-run-opencti-push-001-20260419T000000Z",
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
    monkeypatch.setenv("THREAT_INTEL_USE_MOCK_REMOTE_SERVER", "1")
    monkeypatch.setattr(module, "start_mock_remote_server", lambda *, stix_data_path: _fake_server("http://127.0.0.1:8124"))
    monkeypatch.setattr(module, "ensure_neo4j_validation_container", lambda repo_root: {"uri": "neo4j://127.0.0.1:7698", "database": "neo4j", "username": "neo4j", "password": "11111111"})
    monkeypatch.setattr(module, "reset_validation_projection", lambda event_id, settings: None)

    try:
        module.main()
    except SystemExit as exc:
        assert str(exc) == "Validation failed: missing Neo4j writeback summary."
    else:
        raise AssertionError("Expected the script to reject results without writeback summary.")


def test_run_minimal_closed_loop_rejects_missing_real_neo4j_projection(monkeypatch) -> None:
    module = _load_script_module()

    def fake_run(command, cwd, check, capture_output, text):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "run_id": "ti-run-opencti-push-001-20260419T000000Z",
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
    monkeypatch.delenv("THREAT_INTEL_REMOTE_SERVER_URL", raising=False)
    monkeypatch.setenv("THREAT_INTEL_USE_MOCK_REMOTE_SERVER", "1")
    monkeypatch.setattr(module, "start_mock_remote_server", lambda *, stix_data_path: _fake_server("http://127.0.0.1:8124"))
    monkeypatch.setattr(module, "ensure_neo4j_validation_container", lambda repo_root: {"uri": "neo4j://127.0.0.1:7698", "database": "neo4j", "username": "neo4j", "password": "11111111"})
    monkeypatch.setattr(module, "reset_validation_projection", lambda event_id, settings: None)
    monkeypatch.setattr(
        module,
        "load_validation_projection",
        lambda run_id, event_id, settings: {
            "participant_count": 1,
            "recommended_action_count": 0,
            "conclusion_summary": "",
        },
    )

    try:
        module.main()
    except SystemExit as exc:
        assert str(exc) == "Validation failed: Neo4j persisted fewer than two participant roles."
    else:
        raise AssertionError("Expected the script to reject an incomplete real Neo4j projection.")
