from pathlib import Path

import pytest

from tools.stix_cli import load_bundle, neighbors, search_entities


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_search_entities_returns_expected_matches_for_indicator_and_observable() -> None:
    bundle = load_bundle(REPO_ROOT / "data/stix_samples/threat_intel_bundle.json")

    result = search_entities(bundle, "203.0.113.10")
    match_ids = {match["id"] for match in result["matches"]}

    assert result["match_count"] == len(result["matches"])
    assert "indicator--55555555-5555-4555-8555-555555555555" in match_ids
    assert "ipv4-addr--66666666-6666-4666-8666-666666666666" in match_ids


def test_neighbors_returns_relationship_view_for_known_indicator() -> None:
    bundle = load_bundle(REPO_ROOT / "data/stix_samples/threat_intel_bundle.json")

    result = neighbors(bundle, "indicator--55555555-5555-4555-8555-555555555555")
    relationship_types = {relationship["relationship_type"] for relationship in result["relationships"]}
    peer_ids = {relationship["peer"]["id"] for relationship in result["relationships"]}

    assert result["relationship_count"] == 2
    assert relationship_types == {"indicates", "related-to"}
    assert "intrusion-set--22222222-2222-4222-8222-222222222222" in peer_ids
    assert "ipv4-addr--66666666-6666-4666-8666-666666666666" in peer_ids


def test_neighbors_rejects_unknown_stix_id() -> None:
    bundle = load_bundle(REPO_ROOT / "data/stix_samples/threat_intel_bundle.json")

    with pytest.raises(ValueError, match="was not found"):
        neighbors(bundle, "indicator--missing")
