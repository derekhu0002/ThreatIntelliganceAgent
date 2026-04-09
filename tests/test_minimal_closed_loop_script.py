import importlib.util
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script_module():
    script_path = REPO_ROOT / "scripts/run_minimal_closed_loop.py"
    spec = importlib.util.spec_from_file_location("run_minimal_closed_loop", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_run_minimal_closed_loop_emits_verification_summary(monkeypatch, capsys) -> None:
    module = _load_script_module()
    recorded = {}

    def fake_run(command, cwd, check, capture_output, text):
        recorded["command"] = command
        recorded["cwd"] = cwd
        payload = {
            "analysis_conclusion": {"summary": "Structured result looks valid."},
            "recommended_actions": ["Block indicator", "Search for related activity"],
            "collaboration_trace": {
                "participants": [
                    "ThreatIntelliganceCommander",
                    "STIX_EvidenceSpecialist",
                    "TARA_analyst",
                ]
            },
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    module.main()

    output = json.loads(capsys.readouterr().out)
    assert recorded["cwd"] == REPO_ROOT
    assert recorded["command"][:3] == [sys.executable, "-m", "services.python_listener"]
    assert output["status"] == "passed"
    assert output["participant_count"] == 3
    assert output["recommended_action_count"] == 2
