from pathlib import Path

import pytest

from agent_app.opencode_app.tools.stix_cli import advanced_filter, clean_neo4j_value, load_bundle, neighbors, search_entities, summarize_schema


REPO_ROOT = Path(__file__).resolve().parents[1]
STIX_BUNDLE_PATH = REPO_ROOT / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json"


def test_search_entities_returns_expected_matches_for_indicator_and_observable() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    result = search_entities(bundle, "203.0.113.10")
    match_ids = {match["id"] for match in result["matches"]}

    assert result["match_count"] == len(result["matches"])
    assert "indicator--55555555-5555-4555-8555-555555555555" in match_ids
    assert "ipv4-addr--66666666-6666-4666-8666-666666666666" in match_ids


def test_neighbors_returns_relationship_view_for_known_indicator() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    result = neighbors(bundle, "indicator--55555555-5555-4555-8555-555555555555")
    relationship_types = {relationship["relationship_type"] for relationship in result["relationships"]}
    peer_ids = {relationship["peer"]["id"] for relationship in result["relationships"]}

    assert result["relationship_count"] == 2
    assert relationship_types == {"indicates", "related-to"}
    assert "intrusion-set--22222222-2222-4222-8222-222222222222" in peer_ids
    assert "ipv4-addr--66666666-6666-4666-8666-666666666666" in peer_ids


def test_neighbors_rejects_unknown_stix_id() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    with pytest.raises(ValueError, match="was not found"):
        neighbors(bundle, "indicator--missing")


def test_schema_summary_exposes_core_entity_types_and_supported_fields() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    result = summarize_schema(bundle)
    entity_types = {item["entity_type"]: item for item in result["entity_types"]}

    assert "advanced_filter" not in result["supported_query_fields"]
    assert "relationship_target" in result["supported_query_fields"]
    assert "malware" in entity_types
    assert "vulnerability" in entity_types
    assert "attack-pattern" in entity_types
    assert "targets" in result["relationship_types"]
    assert "name" in entity_types["malware"]["key_fields"]


def test_advanced_filter_supports_schema_derived_relationship_pivots() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    result = advanced_filter(
        bundle,
        {"type": "malware", "relationship_target": "CVE-2025-1234"},
    )

    match_ids = {match["id"] for match in result["matches"]}
    relationship_types = {relationship["relationship_type"] for relationship in result["relationships"]}

    assert result["match_count"] == len(result["matches"])
    assert "malware--12340000-0000-4000-8000-000000000001" in match_ids
    assert relationship_types == {"targets"}


def test_advanced_filter_rejects_unknown_fields() -> None:
    bundle = load_bundle(STIX_BUNDLE_PATH)

    with pytest.raises(ValueError, match="Unsupported filter fields"):
        advanced_filter(bundle, {"guessed_field": "APT28"})


def test_clean_neo4j_value_flattens_nodes_relationships_and_records() -> None:
    node_type = type(
        "Node",
        (),
        {
            "__module__": "neo4j.graph",
            "__init__": lambda self, labels, properties: setattr(self, "labels", labels) or setattr(self, "_properties", properties),
            "items": lambda self: self._properties.items(),
        },
    )
    def _relationship_init(self, rel_type, properties, start_node, end_node):
        self.type = rel_type
        self._properties = properties
        self.start_node = start_node
        self.end_node = end_node

    relationship_type = type(
        "Relationship",
        (),
        {
            "__module__": "neo4j.graph",
            "__init__": _relationship_init,
            "items": lambda self: self._properties.items(),
        },
    )
    class Record(tuple):
        __module__ = "neo4j._data"

        def __new__(cls, payload: dict[str, object]):
            instance = super().__new__(cls, tuple(payload.values()))
            instance._payload = payload
            return instance

        def keys(self):
            return self._payload.keys()

        def __getitem__(self, key):
            if isinstance(key, str):
                return self._payload[key]
            return super().__getitem__(key)

    node = node_type({"Indicator"}, {"name": "APT28", "score": 95})
    record = Record(
        {
            "n": node,
            "r": relationship_type("RELATED_TO", {"confidence": 80}, node, node),
        }
    )

    cleaned = clean_neo4j_value(record)

    assert cleaned == {
        "n": {
            "kind": "node",
            "labels": ["Indicator"],
            "properties": {"name": "APT28", "score": 95},
        },
        "r": {
            "kind": "relationship",
            "type": "RELATED_TO",
            "properties": {"confidence": 80},
        },
    }
    assert "element_id" not in str(cleaned)
    assert "<Record" not in str(cleaned)


def test_clean_neo4j_value_flattens_paths_without_driver_wrappers() -> None:
    node_type = type(
        "Node",
        (),
        {
            "__module__": "neo4j.graph",
            "__init__": lambda self, labels, properties: setattr(self, "labels", labels) or setattr(self, "_properties", properties),
            "items": lambda self: self._properties.items(),
        },
    )
    def _relationship_init(self, rel_type, properties, start_node, end_node):
        self.type = rel_type
        self._properties = properties
        self.start_node = start_node
        self.end_node = end_node

    relationship_type = type(
        "Relationship",
        (),
        {
            "__module__": "neo4j.graph",
            "__init__": _relationship_init,
            "items": lambda self: self._properties.items(),
        },
    )
    path_type = type(
        "Path",
        (),
        {
            "__module__": "neo4j.graph",
            "__init__": lambda self, nodes, relationships: setattr(self, "nodes", nodes) or setattr(self, "relationships", relationships),
        },
    )

    alpha = node_type({"Host"}, {"name": "alpha"})
    beta = node_type({"Host"}, {"name": "beta"})
    path = path_type(
        [alpha, beta],
        [relationship_type("CONNECTED_TO", {"weight": 1}, alpha, beta)],
    )

    cleaned = clean_neo4j_value(path)

    assert cleaned["kind"] == "path"
    assert cleaned["length"] == 1
    assert cleaned["nodes"][0]["properties"]["name"] == "alpha"
    assert cleaned["relationships"][0]["type"] == "CONNECTED_TO"
