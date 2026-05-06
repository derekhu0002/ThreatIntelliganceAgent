import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"


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


def _read_workspace_file(relative_path: str) -> str:
    return (WORKSPACE_ROOT / relative_path).read_text(encoding="utf-8")


def test_ioc_triage_agent_contract() -> None:
    agent_prompt = _read_workspace_file("agents/IOCTriageAgent.md")
    skill_prompt = _read_workspace_file("skills/ioc-triage-indicator-priority/SKILL.md")
    ai4x_tool = _read_workspace_file("tools/ai4x_query.js")
    architecture = json.loads((REPO_ROOT / "design/KG/SystemArchitecture.json").read_text(encoding="utf-8"))

    assert "biz.ioc-triage" in agent_prompt
    assert "ioc-triage-indicator-priority" in agent_prompt
    assert "严格单 Skill 路由" in agent_prompt
    assert "渐进式查询" in agent_prompt
    assert "detail" in agent_prompt
    assert "opencti" in agent_prompt
    assert "Recommended Actions" in agent_prompt
    assert "Pending Confirmations" in agent_prompt
    assert "Boundary Notes" in agent_prompt
    assert "ai4x_query: true" in agent_prompt
    assert "biz.incident-response-orchestration" in agent_prompt

    assert "name: ioc-triage-indicator-priority" in skill_prompt
    assert "Trigger & Context (触发条件与上下文)" in skill_prompt
    assert "Prerequisites (槽位/前置依赖提取)" in skill_prompt
    assert "SOP Action Steps (标准作业步骤)" in skill_prompt
    assert "Output Format (输出规范)" in skill_prompt
    assert 'ai4x_query(command="catalog")' in skill_prompt
    assert 'ai4x_query(command="schema", sourceId="opencti")' in skill_prompt
    assert "likely_false_positive" in skill_prompt
    assert "Direct Facts" in skill_prompt
    assert "Inferred Assessments" in skill_prompt
    assert "Pending Confirmations" in skill_prompt
    assert "Empty Result Contract" in skill_prompt
    assert '"IOCTriageAgent"' in ai4x_tool

    ioc_triage_agent = next(
        element for element in architecture["elements"] if element["name"] == "IOCTriageAgent"
    )
    assert ioc_triage_agent["browser_path"].endswith("/IOCTriageAgent")
    assert ioc_triage_agent["attributes"][0]["description"] == (
        "agent_app\\opencode_app\\.opencode\\agents\\IOCTriageAgent.md"
    )
    assert ioc_triage_agent["attributes"][1]["description"] == (
        "agent_app\\opencode_app\\.opencode\\skills\\ioc-triage-indicator-priority\\SKILL.md"
    )


def test_ai4x_query_tool_allows_ioc_triage_agent(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows cmd wrapper cannot reliably fake pythonBin execution for ai4x_query in this harness.")

    tool_path = WORKSPACE_ROOT / "tools/ai4x_query.js"
    fake_python = _write_fake_python_executable(
        tmp_path,
        json.dumps({"version": "test", "total_databases": 1, "databases": [{"source_id": "opencti"}]}),
    )

    completed = _run_tool_module(
        tool_path,
        {"command": "catalog", "pythonBin": str(fake_python)},
        agent="IOCTriageAgent",
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["version"] == "test"
    assert payload["databases"][0]["source_id"] == "opencti"