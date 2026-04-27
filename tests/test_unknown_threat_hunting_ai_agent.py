import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"


def _read_workspace_file(relative_path: str) -> str:
    return (WORKSPACE_ROOT / relative_path).read_text(encoding="utf-8")


def test_unknown_threat_hunting_ai_agent_contract() -> None:
    # @ArchitectureID: {79AC0CAE-94BD-414f-9814-2BD51686FC36}
    config = json.loads((WORKSPACE_ROOT / "opencode.json").read_text(encoding="utf-8"))
    workspace_contract = json.loads((WORKSPACE_ROOT / "workspace.contract.json").read_text(encoding="utf-8"))
    canonical_primary_prompt = _read_workspace_file("agents/ThreatIntelPrimary.md")
    canonical_analyst_prompt = _read_workspace_file("agents/ThreatIntelAnalyst.md")
    canonical_secops_prompt = _read_workspace_file("agents/ThreatIntelSecOps.md")
    canonical_collaboration_skill = _read_workspace_file("skills/threat-intel-collaboration/SKILL.md")
    scenario_primary_prompt = _read_workspace_file("agents/ThreatIntelUnknownHuntPrimary.md")
    scenario_skill = _read_workspace_file("skills/unknown-threat-hunting-ai4x/SKILL.md")
    ai4x_tool = _read_workspace_file("tools/ai4x_query.js")

    assert config["default_agent"] == "ThreatIntelPrimary"
    assert workspace_contract["agent_roles"] == {
        "primary": "ThreatIntelPrimary",
        "analyst": "ThreatIntelAnalyst",
        "secops": "ThreatIntelSecOps",
    }

    assert "graph-based unknown threat hunting requests" not in canonical_primary_prompt
    assert "start from the target `intrusion-set`" not in canonical_analyst_prompt
    assert "Never call `ai4x_query` directly. In the unknown threat hunting flow" not in canonical_secops_prompt
    assert "Unknown threat hunting over AI4X / OpenCTI" not in canonical_collaboration_skill

    assert "graph-based unknown threat hunting" in scenario_primary_prompt
    assert "Do not delegate this scenario to a scenario-specific subagent" in scenario_primary_prompt
    assert "Use `ai4x_query` directly in `catalog -> schema -> query` order" in scenario_primary_prompt
    assert "pivot from first-pass IOC hits into a second read-only query" in scenario_primary_prompt
    assert "structured empty-result output" in scenario_primary_prompt
    assert "ai4x_query: true" in scenario_primary_prompt

    assert not (WORKSPACE_ROOT / "agents/ThreatIntelUnknownHuntAnalyst.md").exists()
    assert not (WORKSPACE_ROOT / "agents/ThreatIntelUnknownHuntSecOps.md").exists()

    assert "UNKNOWN THREAT HUNTING OVER AI4X / OPENCTI" in scenario_skill
    assert "`catalog -> schema -> query`" in scenario_skill
    assert "`source_id=opencti`" in scenario_skill
    assert "only the primary scenario agent should execute the flow" in scenario_skill
    assert "keeps the full flow inside the primary agent" in scenario_skill
    assert "direct facts from graph-derived inference" in scenario_skill
    assert "structured empty-result report" in scenario_skill
    assert "`request_id`" in scenario_skill
    assert "`target_intrusion_set`" in scenario_skill
    assert "`derived_leads`" in scenario_skill
    assert "`evidence_paths`" in scenario_skill
    assert "`recommendations`" in scenario_skill
    assert "`confidence_statement`" in scenario_skill

    assert 'const ANALYST_AGENTS = new Set(["ThreatIntelAnalyst", "STIX_EvidenceSpecialist", "ThreatIntelAnalyst_test", "ThreatIntelUnknownHuntPrimary"]);' in ai4x_tool
    assert 'const SECOPS_AGENTS = new Set(["ThreatIntelSecOps", "TARA_analyst"]);' in ai4x_tool
    assert "ThreatIntelSecOps must use analyst-provided AI4X data rather than calling ai4x_query directly." in ai4x_tool