from pathlib import Path
import json


REPO_ROOT = Path(__file__).resolve().parents[3]
OPENCODE_TOOL_PATH = REPO_ROOT / "agent_app/opencode_app/.opencode/tools/ai4x_query.js"
LOCAL_RUNTIME_CLI = REPO_ROOT / "agent_app/opencode_app/tools/ai4x_cli.py"
LOCAL_RUNTIME_SERVICE = REPO_ROOT / "agent_app/opencode_app/services/ai4x_client.py"
WORKSPACE_CONFIG_PATH = REPO_ROOT / "agent_app/opencode_app/.opencode/opencode.json"
WORKSPACE_CONTRACT_PATH = REPO_ROOT / "agent_app/opencode_app/.opencode/workspace.contract.json"


def test_isolated_runtime_boundary_keeps_local_bridge_surface() -> None:
    assert LOCAL_RUNTIME_CLI.is_file()
    assert LOCAL_RUNTIME_SERVICE.is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/tools/__init__.py").is_file()
    assert (REPO_ROOT / "agent_app/opencode_app/services/__init__.py").is_file()
    assert not (REPO_ROOT / "tools/__init__.py").exists()
    assert not (REPO_ROOT / "tools/stix_cli/__main__.py").exists()


def test_workspace_contract_declares_remote_ai4x_mcp_server() -> None:
    workspace_config = json.loads(WORKSPACE_CONFIG_PATH.read_text(encoding="utf-8"))
    workspace_contract = json.loads(WORKSPACE_CONTRACT_PATH.read_text(encoding="utf-8"))

    ai4x_server = workspace_config["mcpServers"]["ai4x"]
    frozen_ai4x_server = workspace_contract["mcp_servers"]["ai4x"]

    assert workspace_config["default_agent"] == "ThreatIntelPrimary"
    assert ai4x_server["transport"] == "http"
    assert ai4x_server["url"].endswith("/mcp")
    assert ai4x_server["healthz"].endswith("/mcp/healthz")
    assert ai4x_server["tools"] == ["ai4x_query"]
    assert frozen_ai4x_server["canonical"] is True
    assert frozen_ai4x_server["fallback_http_api_allowed"] is True
    assert frozen_ai4x_server["tool_names"] == ["ai4x_query"]


def test_explicit_ai4x_acceptance_tests_do_not_execute_local_ai4x_wrapper_directly() -> None:
    ai4x_integration_text = (REPO_ROOT / "tests/test_ai4x_platform_integration.py").read_text(encoding="utf-8")
    explicit_markers = [
        "def test_ai4x_platform_catalog_exposes_available_data_range() -> None:",
        "def test_ai4x_platform_query_tool_returns_real_data_payload() -> None:",
        "def test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure() -> None:",
        "def test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service(tmp_path: Path) -> None:",
    ]
    explicit_sections: list[str] = []
    for marker in explicit_markers:
        start = ai4x_integration_text.index(marker)
        remainder = ai4x_integration_text[start:]
        next_marker = remainder.find("\ndef test_", len(marker))
        explicit_sections.append(remainder if next_marker == -1 else remainder[:next_marker])
    explicit_text = "\n".join(explicit_sections)

    assert 'WORKSPACE_ROOT / "tools/ai4x_query.js"' not in explicit_text
    assert '"-m", "tools.ai4x_cli"' not in explicit_text
    assert "_call_ai4x_query_via_mcp(" in explicit_text
    assert "_require_registered_ai4x_mcp_environment()" in explicit_text