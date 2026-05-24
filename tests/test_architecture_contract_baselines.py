from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AI4X_INTEGRATION_TEST = REPO_ROOT / "tests/test_ai4x_platform_integration.py"
WORKSPACE_CONFIG_TEST = REPO_ROOT / "tests/test_opencode_workspace_config.py"


def test_explicit_ai4x_acceptance_entries_remain_at_canonical_paths() -> None:
    ai4x_text = AI4X_INTEGRATION_TEST.read_text(encoding="utf-8")
    workspace_text = WORKSPACE_CONFIG_TEST.read_text(encoding="utf-8")

    assert "def test_ai4x_platform_catalog_exposes_available_data_range() -> None:" in ai4x_text
    assert "def test_ai4x_platform_query_tool_returns_real_data_payload() -> None:" in ai4x_text
    assert "def test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure() -> None:" in ai4x_text
    assert "def test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service(tmp_path: Path) -> None:" in ai4x_text
    assert "def test_opencode_app_contains_local_tool_runtime_dependencies() -> None:" in workspace_text


def test_architecture_traceability_tags_remain_bound_to_canonical_entries() -> None:
    ai4x_text = AI4X_INTEGRATION_TEST.read_text(encoding="utf-8")
    workspace_text = WORKSPACE_CONFIG_TEST.read_text(encoding="utf-8")

    assert "# @ArchitectureID: 1738" in ai4x_text
    assert "# @ArchitectureID: ELM-TECH-ARTIFACT-OPENCODE-WORKSPACE" in workspace_text
    assert "# @ArchitectureID: ELM-TECH-ARTIFACT-AGENT-DEFS" in workspace_text