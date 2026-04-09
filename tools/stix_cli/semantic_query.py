"""Local STIX 2.1 semantic query helpers."""

# @ArchitectureID: ELM-APP-COMP-STIX-CLI

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_bundle(bundle_path: str | Path) -> dict[str, Any]:
    path = Path(bundle_path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("type") != "bundle":
        raise ValueError("STIX data file must contain a bundle object.")
    bundle.setdefault("objects", [])
    return bundle


def _summary_for_object(stix_object: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": stix_object.get("id"),
        "type": stix_object.get("type"),
        "name": stix_object.get("name") or stix_object.get("value") or stix_object.get("relationship_type"),
        "description": stix_object.get("description"),
        "pattern": stix_object.get("pattern"),
        "value": stix_object.get("value"),
        "confidence": stix_object.get("confidence"),
    }


def search_entities(bundle: dict[str, Any], query: str) -> dict[str, Any]:
    query_text = query.casefold().strip()
    matches: list[dict[str, Any]] = []

    for stix_object in bundle.get("objects", []):
        haystack = " ".join(
            str(stix_object.get(field, ""))
            for field in ("type", "name", "description", "pattern", "value")
        ).casefold()
        if query_text and query_text in haystack:
            matches.append(_summary_for_object(stix_object))

    return {
        "query": query,
        "match_count": len(matches),
        "matches": matches,
    }


def neighbors(bundle: dict[str, Any], stix_id: str) -> dict[str, Any]:
    objects_by_id = {obj.get("id"): obj for obj in bundle.get("objects", []) if obj.get("id")}
    target = objects_by_id.get(stix_id)
    if target is None:
        raise ValueError(f"STIX object '{stix_id}' was not found in the local sample bundle.")

    related: list[dict[str, Any]] = []
    for relationship in bundle.get("objects", []):
        if relationship.get("type") != "relationship":
            continue
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        if stix_id not in {source_ref, target_ref}:
            continue

        direction = "outgoing" if source_ref == stix_id else "incoming"
        peer_id = target_ref if source_ref == stix_id else source_ref
        related.append(
            {
                "relationship_id": relationship.get("id"),
                "relationship_type": relationship.get("relationship_type"),
                "direction": direction,
                "peer": _summary_for_object(objects_by_id.get(peer_id, {"id": peer_id, "type": "unknown"})),
            }
        )

    return {
        "stix_id": stix_id,
        "object": _summary_for_object(target),
        "relationship_count": len(related),
        "relationships": related,
    }
