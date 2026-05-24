import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"


def _read_workspace_file(relative_path: str) -> str:
    return (WORKSPACE_ROOT / relative_path).read_text(encoding="utf-8")


def test_unknown_threat_hunting_ai_agent_contract() -> None:
    agent_prompt = _read_workspace_file("agents/ThreatHunterAgent.md")
    scenario_skill = _read_workspace_file("skills/unknown-threat-hunt-graph-hypothesis/SKILL.md")
    ai4x_tool = _read_workspace_file("tools/ai4x_query_local.js")
    architecture = json.loads((REPO_ROOT / "design/KG/SystemArchitecture.json").read_text(encoding="utf-8"))

    assert "ThreatHunterAgent" in agent_prompt
    assert "biz.unknown-threat-hunting" in agent_prompt
    assert "严格单 Skill 路由" in agent_prompt
    assert "默认由单一主 AGENT 完成全链路" in agent_prompt
    assert "catalog -> schema -> query" in agent_prompt
    assert "Pending Confirmations" in agent_prompt
    assert "Boundary Notes" in agent_prompt
    assert "ai4x_query: true" in agent_prompt

    assert "name: unknown-threat-hunt-graph-hypothesis" in scenario_skill
    assert "Trigger & Context (触发条件与上下文)" in scenario_skill
    assert "Prerequisites (槽位/前置依赖提取)" in scenario_skill
    assert "SOP Action Steps (标准作业步骤)" in scenario_skill
    assert "Output Format (输出规范)" in scenario_skill
    assert "Structured Response Contract (结构化响应契约)" in scenario_skill
    assert 'ai4x_query(command="catalog")' in scenario_skill
    assert 'ai4x_query(command="schema", sourceId="opencti")' in scenario_skill
    assert 'ai4x_query(command="schema", sourceId="vehicle_iobe")' in scenario_skill
    assert 'ai4x_query(command="query", sourceId="opencti"' in scenario_skill
    assert "Direct Facts" in scenario_skill
    assert "Ranked Leads" in scenario_skill
    assert "Pending Confirmations" in scenario_skill
    assert "Boundary Notes" in scenario_skill
    assert "`request_id`" in scenario_skill
    assert "`ranked_leads`" in scenario_skill
    assert "`evidence_paths`" in scenario_skill
    assert "`recommended_actions`" in scenario_skill
    assert "`pending_confirmations`" in scenario_skill
    assert "`boundary_notes`" in scenario_skill

    assert 'ThreatHunterAgent' in ai4x_tool
    assert 'ThreatIntelAnalyst_test' in ai4x_tool
    assert 'ThreatIntelSecOps' in ai4x_tool
    assert 'TARA_analyst' in ai4x_tool
    assert "ThreatIntelSecOps must use analyst-provided AI4X data rather than calling ai4x_query_local directly." in ai4x_tool

    threat_hunter_agent = next(element for element in architecture["elements"] if element["name"] == "ThreatHunterAgent")
    assert threat_hunter_agent["browser_path"].endswith("/ThreatHunterAgent")
    assert threat_hunter_agent["attributes"][0]["description"] == (
        "agent_app\\opencode_app\\.opencode\\agents\\ThreatHunterAgent.md"
    )
    assert threat_hunter_agent["attributes"][1]["description"] == (
        "agent_app\\opencode_app\\.opencode\\skills\\unknown-threat-hunt-graph-hypothesis\\SKILL.md"
    )