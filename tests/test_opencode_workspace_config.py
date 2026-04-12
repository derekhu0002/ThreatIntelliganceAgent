import json
import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"


def test_opencode_workspace_config_declares_canonical_roles_and_aliases() -> None:
    config = json.loads((WORKSPACE_ROOT / "opencode.json").read_text(encoding="utf-8"))

    assert config["workspace"]["root"] == "agent_app/opencode_app/.opencode"
    assert config["workspace"]["control_plane_root"] == ".opencode"
    assert config["default_agent"] == "ThreatIntelPrimary"
    assert config["agent_roles"] == {
        "primary": "ThreatIntelPrimary",
        "analyst": "ThreatIntelAnalyst",
        "secops": "ThreatIntelSecOps",
    }
    assert config["agent_aliases"] == {
        "ThreatIntelliganceCommander": "ThreatIntelPrimary",
        "STIX_EvidenceSpecialist": "ThreatIntelAnalyst",
        "TARA_analyst": "ThreatIntelSecOps",
    }


def test_stix_query_tool_rejects_non_analyst_agents() -> None:
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"

    completed = subprocess.run(
        ["node", str(tool_path), "search", "--query", "APT28"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "OPENCODE_AGENT_NAME": "ThreatIntelPrimary"},
        check=False,
    )

    assert completed.returncode != 0
    assert "restricted to ThreatIntelAnalyst" in completed.stderr


def test_stix_query_tool_allows_analyst_agents() -> None:
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"

    completed = subprocess.run(
        ["node", str(tool_path), "search", "--query", "APT28"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "OPENCODE_AGENT_NAME": "ThreatIntelAnalyst"},
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["query"] == "APT28"
    assert payload["match_count"] >= 1


@pytest.mark.parametrize(
    ("skill_path", "required_text"),
    [
        (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md", "Primary -> Analyst -> SecOps -> Primary"),
        (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md", "TASK-009"),
        (WORKSPACE_ROOT / "AGENTS.md", "repo-root `.opencode/` is control-plane state only"),
    ],
)
def test_workspace_docs_capture_canonical_collaboration_contract(skill_path: Path, required_text: str) -> None:
    assert required_text in skill_path.read_text(encoding="utf-8")
