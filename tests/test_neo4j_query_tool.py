import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"


def _run_tool_module(module_path: Path, args: dict, *, python_bin: str) -> subprocess.CompletedProcess[str]:
    script = """
import { pathToFileURL } from 'node:url';

const modulePath = process.argv[1];
const args = JSON.parse(process.argv[2]);
const directory = process.argv[3];
const worktree = process.argv[4];

const { default: tool } = await import(pathToFileURL(modulePath).href);

const context = {
  sessionID: 'test-session',
  messageID: 'test-message',
  agent: 'ThreatIntelAnalyst',
  directory,
  worktree,
  abort: new AbortController().signal,
  metadata() {},
  async ask() {},
};

try {
  const output = await tool.execute(args, context);
  process.stdout.write(JSON.stringify(output));
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
"""

    env = os.environ.copy()
    env["PYTHON_BIN"] = python_bin

    return subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            script,
            str(module_path),
            json.dumps(args),
            str(WORKSPACE_ROOT),
            str(REPO_ROOT),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _write_fake_python_executable(tmp_path: Path, stdout_text: str, exit_code: int = 0) -> Path:
    script_path = tmp_path / "fake-python"
    script_path.write_text(
        "#!/bin/sh\n"
        f"printf '%s' {stdout_text!r}\n"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    return script_path


def test_neo4j_query_tool_returns_clean_json_payload(tmp_path: Path) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    tool_path = WORKSPACE_ROOT / "tools/neo4j_query.js"
    fake_python = _write_fake_python_executable(
        tmp_path,
        '{"records":[{"n":{"kind":"node","labels":["Indicator"],"properties":{"name":"APT28"}}}],"summary":{"query_type":"r","database":"neo4j","result_available_after_ms":1,"result_consumed_after_ms":2,"counters":{}}}',
    )

    completed = _run_tool_module(
        tool_path,
        {"cypher": "MATCH (n) RETURN n LIMIT 1", "pythonBin": str(fake_python)},
        python_bin=str(fake_python),
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["records"][0]["n"]["kind"] == "node"
    assert payload["records"][0]["n"]["properties"]["name"] == "APT28"
    assert "<Record" not in completed.stdout


def test_neo4j_query_tool_rejects_invalid_json_stdout(tmp_path: Path) -> None:
    # @ArchitectureID: {1CFA011B-787D-4e43-BE86-0AC04FE53394}
    tool_path = WORKSPACE_ROOT / "tools/neo4j_query.js"
    fake_python = _write_fake_python_executable(tmp_path, "not-json")

    completed = _run_tool_module(
        tool_path,
        {"cypher": "MATCH (n) RETURN n LIMIT 1", "pythonBin": str(fake_python)},
        python_bin=str(fake_python),
    )

    assert completed.returncode != 0
    assert "invalid JSON" in completed.stderr
