import json
import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"
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


def test_opencode_workspace_config_declares_canonical_roles_and_aliases() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE
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
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"

    completed = _run_tool_module(tool_path, {"command": "search", "query": "APT28"}, agent="ThreatIntelPrimary")

    assert completed.returncode != 0
    assert "restricted to ThreatIntelAnalyst" in completed.stderr


def test_stix_query_tool_allows_analyst_agents() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"

    completed = _run_tool_module(tool_path, {"command": "search", "query": "APT28"}, agent="ThreatIntelAnalyst")

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["query"] == "APT28"
    assert payload["match_count"] >= 1


def test_stix_query_tool_rejects_invalid_json_stdout(tmp_path: Path) -> None:
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"
    fake_python = tmp_path / "fake-python"
    fake_python.write_text("#!/usr/bin/env sh\nprintf 'not-json'\n", encoding="utf-8")
    fake_python.chmod(0o755)

    completed = _run_tool_module(
        tool_path,
        {"command": "search", "query": "APT28", "pythonBin": str(fake_python)},
        agent="ThreatIntelAnalyst",
    )

    assert completed.returncode != 0
    assert "invalid JSON" in completed.stderr


def test_stix_query_tool_rejects_invalid_search_payload_shape(tmp_path: Path) -> None:
    tool_path = WORKSPACE_ROOT / "tools/stix_query.js"
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(
        "#!/usr/bin/env sh\nprintf '%s' '{\"query\":\"APT28\",\"match_count\":\"one\",\"matches\":[]}'\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    completed = _run_tool_module(
        tool_path,
        {"command": "search", "query": "APT28", "pythonBin": str(fake_python)},
        agent="ThreatIntelAnalyst",
    )

    assert completed.returncode != 0
    assert "invalid search payload" in completed.stderr


def test_threat_intel_orchestrator_tool_exports_valid_custom_tool() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS
    tool_path = WORKSPACE_ROOT / "tools/threat_intel_orchestrator.js"
    payload = {
        "run_context": {"run_id": "run-123"},
        "event": {
            "event_id": "evt-001",
            "source": "mail-gateway",
            "severity": "high",
            "summary": "Spearphishing message linked to APT28 infrastructure",
        },
        "evidence_bundle": {
            "searches": [
                {
                    "matches": [
                        {"id": "indicator--1", "name": "APT28", "confidence": 85},
                        {"id": "indicator--2", "name": "Spearphishing Attachment", "confidence": 70},
                    ]
                }
            ],
            "relationships": [
                {
                    "relationships": [
                        {"relationship_type": "uses", "peer": {"name": "Command and Control IP"}}
                    ]
                }
            ],
        },
    }

    completed = _run_tool_module(tool_path, {"inputJson": json.dumps(payload)}, agent="ThreatIntelPrimary")

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["participants"] == ["ThreatIntelPrimary", "ThreatIntelAnalyst", "ThreatIntelSecOps"]
    assert result["final_assessment"]["assembled_by"] == "ThreatIntelPrimary"
    assert result["traceability"]["role_aliases"]["ThreatIntelAnalyst"] == "STIX_EvidenceSpecialist"


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


def test_canonical_agent_descriptors_expose_traceable_role_intent() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS
    primary_text = (AGENTS_DIR / "ThreatIntelPrimary.md").read_text(encoding="utf-8")
    analyst_text = (AGENTS_DIR / "ThreatIntelAnalyst.md").read_text(encoding="utf-8")
    secops_text = (AGENTS_DIR / "ThreatIntelSecOps.md").read_text(encoding="utf-8")

    assert _has_trace_tag(primary_text, REQ_TAG, REQ_ID)
    assert _has_trace_tag(primary_text, ARCH_TAG, AGENT_DEFS_ID)
    assert "TASK-009 structured result assembly" in primary_text

    assert _has_trace_tag(analyst_text, REQ_TAG, REQ_ID)
    assert _has_trace_tag(analyst_text, ARCH_TAG, AGENT_DEFS_ID)
    assert "stix_query" in analyst_text
    assert "Do not assemble the final TASK-009 result" in analyst_text

    assert _has_trace_tag(secops_text, REQ_TAG, REQ_ID)
    assert _has_trace_tag(secops_text, ARCH_TAG, AGENT_DEFS_ID)
    assert "Return structured SecOps output to the primary agent" in secops_text


def test_collaboration_skill_exposes_traceable_delegation_contract() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-APP-PROC-THREAT-COLLAB-SKILL
    skill_text = (WORKSPACE_ROOT / "skills/threat-intel-collaboration/SKILL.md").read_text(encoding="utf-8")

    assert _has_trace_tag(skill_text, REQ_TAG, REQ_ID)
    assert _has_trace_tag(skill_text, ARCH_TAG, COLLAB_SKILL_ID)
    assert "ThreatIntelAnalyst` may use the native `stix_query` tool and no other role may use that tool" in skill_text
    assert "Primary -> Analyst -> SecOps -> Primary" in skill_text
    assert "final assembly was performed by the remote Primary role" in skill_text
