import json
import os
import subprocess
import stat
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"
WORKSPACE_CONTRACT_PATH = WORKSPACE_ROOT / "workspace.contract.json"
OPENCODE_CONFIG_PATH = WORKSPACE_ROOT / "opencode.json"
AGENTS_DIR = WORKSPACE_ROOT / "agents"
REQ_ID = "REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001"
AGENT_DEFS_ID = "ELM-TECH-ARTIFACT-AGENT-DEFS"
WORKSPACE_ID = "ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE"
COLLAB_SKILL_ID = "ELM-APP-PROC-THREAT-COLLAB-SKILL"
REQ_TAG = "@Requirement" "ID"
ARCH_TAG = "@Architecture" "ID"


def _run_tool_module(module_path: Path, args: dict, *, agent: str | None = None) -> subprocess.CompletedProcess[str]:
    script = """
import { pathToFileURL } from 'node:url';

const modulePath = process.argv[1];
const args = JSON.parse(process.argv[2]);
const agent = process.argv[3] || '';
const directory = process.argv[4];
const worktree = process.argv[5];

const { default: tool } = await import(pathToFileURL(modulePath).href);

const context = {
  sessionID: 'test-session',
  messageID: 'test-message',
  agent,
  directory,
  worktree,
  abort: new AbortController().signal,
  metadata() {},
  async ask() {},
};

try {
  const output = await tool.execute(args, context);
  process.stdout.write(typeof output === 'string' ? output : JSON.stringify(output));
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
"""

    return subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            script,
            str(module_path),
            json.dumps(args),
            agent or "",
            str(WORKSPACE_ROOT),
            str(REPO_ROOT),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )


def _has_trace_tag(text: str, tag: str, value: str) -> bool:
    return f"{tag}: {value}" in text


def _write_fake_python_executable(tmp_path: Path, stdout_text: str, exit_code: int = 0) -> Path:
    if os.name == "nt":
        script_path = tmp_path / "fake-python.cmd"
        escaped_stdout = stdout_text.replace("^", "^^").replace("%", "%%")
        script_path.write_text(
            "@echo off\n"
            f"<nul set /p ={escaped_stdout}\n"
            f"exit /b {exit_code}\n",
            encoding="utf-8",
        )
        return script_path

    script_path = tmp_path / "fake-python"
    script_path.write_text(
        "#!/bin/sh\n"
        f"printf '%s' {stdout_text!r}\n"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    return script_path


def test_opencode_workspace_config_declares_canonical_roles_and_aliases() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE
    config = json.loads(OPENCODE_CONFIG_PATH.read_text(encoding="utf-8"))
    workspace_contract = json.loads(WORKSPACE_CONTRACT_PATH.read_text(encoding="utf-8"))

    assert config["default_agent"] == "安全运营助手"
    assert workspace_contract["workspace"]["root"] == "agent_app/opencode_app/.opencode"
    assert workspace_contract["workspace"]["control_plane_root"] == ".opencode"
    assert config["mcp"]["ai4x"]["type"] == "remote"
    assert config["mcp"]["ai4x"]["url"].endswith("/mcp")
    assert workspace_contract["mcp_servers"]["ai4x"]["transport"] == "http"
    assert workspace_contract["mcp_servers"]["ai4x"]["healthz"].endswith("/mcp/healthz")
    assert workspace_contract["mcp_servers"]["ai4x"]["canonical"] is True
    assert workspace_contract["mcp_servers"]["ai4x"]["tool_names"] == ["ai4x_query"]
    assert workspace_contract["agent_roles"] == {
        "primary": "ThreatIntelPrimary",
        "analyst": "ThreatIntelAnalyst",
        "secops": "ThreatIntelSecOps",
    }
    assert workspace_contract["agent_aliases"] == {
        "ThreatIntelligenceCommander": "ThreatIntelPrimary",
        "STIX_EvidenceSpecialist": "ThreatIntelAnalyst",
        "TARA_analyst": "ThreatIntelSecOps",
    }


def test_opencode_app_contains_local_tool_runtime_dependencies() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE
    config = json.loads(OPENCODE_CONFIG_PATH.read_text(encoding="utf-8"))
    workspace_contract = json.loads(WORKSPACE_CONTRACT_PATH.read_text(encoding="utf-8"))

    assert "ai4x" in config["mcp"]
    assert config["mcp"]["ai4x"]["type"] == "remote"
    assert workspace_contract["mcp_servers"]["ai4x"]["tool_names"] == ["ai4x_query"]
    assert workspace_contract["mcp_servers"]["ai4x"]["fallback_http_api_allowed"] is True
    assert (REPO_ROOT / "agent_app/opencode_app/tools/__init__.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/tools/ai4x_cli.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/services/__init__.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/services/ai4x_client.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/tools/stix_cli/__main__.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/tools/stix_cli/semantic_query.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json").is_file()


def test_external_duplicate_agent_runtime_files_are_removed() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE
    assert not (REPO_ROOT / "tools/__init__.py").exists()
    assert not (REPO_ROOT / "tools/stix_cli/__main__.py").exists()
    assert not (REPO_ROOT / "tools/stix_cli/semantic_query.py").exists()
    assert not (REPO_ROOT / "data/stix_samples/threat_intel_bundle.json").exists()


def test_ai4x_cli_imports_inside_isolated_opencode_runtime() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE
    isolated_runtime_root = REPO_ROOT / "agent_app/opencode_app"

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import tools.ai4x_cli as cli; print(cli.resolve_ai4x_base_url('http://localhost:8000'))",
        ],
        cwd=isolated_runtime_root,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": str(isolated_runtime_root),
        },
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    ("skill_path", "required_text"),
    [
        (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md", "Primary -> Analyst -> SecOps -> Primary"),
        (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md", "TASK-009"),
        (WORKSPACE_ROOT / "AGENTS.md", "repo-root `.opencode/` is control-plane state only"),
    ],
)
def test_workspace_docs_capture_canonical_collaboration_contract(skill_path: Path, required_text: str) -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-APP-PROC-THREAT-COLLAB-SKILL
    assert required_text in skill_path.read_text(encoding="utf-8")


def test_workspace_does_not_ship_dedicated_acceptance_agent_descriptor() -> None:
    # @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS
    assert not any(path.stem.endswith("_test") for path in AGENTS_DIR.glob("*.md"))
    assert not (WORKSPACE_ROOT / "tools").exists()


def test_collaboration_skill_exposes_traceable_delegation_contract() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-APP-PROC-THREAT-COLLAB-SKILL
    # @ArchitectureID: ELM-APP-FUNC-CANONICALIZE-THREAT-ANALYST-CONTRACT
    skill_text = (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md").read_text(encoding="utf-8")

    assert _has_trace_tag(skill_text, REQ_TAG, REQ_ID)
    assert _has_trace_tag(skill_text, ARCH_TAG, COLLAB_SKILL_ID)
    assert "ThreatIntelAnalyst` must return precise evidence" in skill_text
    assert "without retired workspace-local compatibility tools" in skill_text
    assert "final TASK-009 assembly ownership" in skill_text
    assert "Primary -> Analyst -> SecOps -> Primary" in skill_text
    assert "final assembly was performed by the remote Primary role" in skill_text
