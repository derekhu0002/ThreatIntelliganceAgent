from services.stix_contracts import load_stix_schema, resolve_canonical_schema_root


def test_shared_contract_catalog_resolves_canonical_schema_root_and_core_schema() -> None:
    # @RequirementID: REQ-OPENCODE-MULTIAGENT-THREAT-INTEL-001
    # @ArchitectureID: ELM-001
    # @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS
    # @ArchitectureID: ELM-DATA-STIX-ARGO-SCHEMA
    schema_root = resolve_canonical_schema_root()
    core_schema = load_stix_schema("common/core.json")

    assert schema_root.name == "schema"
    assert core_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
