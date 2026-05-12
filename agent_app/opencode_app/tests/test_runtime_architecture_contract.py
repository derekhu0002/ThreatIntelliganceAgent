from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
OPENCODE_TOOL_PATH = REPO_ROOT / "agent_app/opencode_app/.opencode/tools/ai4x_query.js"
LOCAL_RUNTIME_CLI = REPO_ROOT / "agent_app/opencode_app/tools/ai4x_cli.py"
LOCAL_RUNTIME_SERVICE = REPO_ROOT / "agent_app/opencode_app/services/ai4x_client.py"


def test_isolated_runtime_boundary_keeps_local_bridge_surface() -> None:
    assert LOCAL_RUNTIME_CLI.is_file()
    assert LOCAL_RUNTIME_SERVICE.is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/tools/__init__.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/services/__init__.py").is_file()
    assert not (REPO_ROOT / "tools/__init__.py").exists()
    assert not (REPO_ROOT / "tools/stix_cli/__main__.py").exists()


def test_ai4x_query_tool_delegates_to_isolated_runtime_cli_module() -> None:
    tool_text = OPENCODE_TOOL_PATH.read_text(encoding="utf-8")

    assert 'const cliArgs = ["-m", "tools.ai4x_cli"]' in tool_text
    assert "services.ai4x_client" not in tool_text
    assert "context.worktree" in tool_text