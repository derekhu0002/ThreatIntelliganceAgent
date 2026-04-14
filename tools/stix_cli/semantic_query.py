"""Local STIX 2.1 semantic query helpers."""

# @ArchitectureID: ELM-APP-COMP-STIX-CLI

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


SUPPORTED_QUERY_FIELDS = {
    "id",
    "type",
    "name",
    "description",
    "pattern",
    "value",
    "relationship_type",
    "relationship_source",
    "relationship_target",
}
CORE_ENTITY_TYPE_ALIASES = {
    "indicator": {"indicator"},
    "malware": {"malware"},
    "threat-actor": {"threat-actor", "intrusion-set"},
    "vulnerability": {"vulnerability"},
    "attack-pattern": {"attack-pattern"},
}
FIELD_PRIORITY = (
    "id",
    "type",
    "name",
    "description",
    "pattern",
    "value",
    "confidence",
    "aliases",
    "is_family",
)


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


def _casefold(value: Any) -> str:
    return str(value or "").casefold().strip()


def _matches_text(candidate: Any, expected: Any) -> bool:
    candidate_text = _casefold(candidate)
    expected_text = _casefold(expected)
    return bool(expected_text) and expected_text in candidate_text


def _summary_matches(summary: dict[str, Any], expected: Any) -> bool:
    return any(
        _matches_text(summary.get(field), expected)
        for field in ("id", "type", "name", "description", "value")
    )


def _object_type_matches(stix_type: Any, expected_type: Any) -> bool:
    actual_type = _casefold(stix_type)
    expected_key = _casefold(expected_type)
    allowed_types = CORE_ENTITY_TYPE_ALIASES.get(expected_key, {expected_key})
    return actual_type in {_casefold(item) for item in allowed_types}


def _build_object_index(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {obj.get("id"): obj for obj in bundle.get("objects", []) if obj.get("id")}


def _relationship_payload(
    relationship: dict[str, Any],
    objects_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_ref = relationship.get("source_ref")
    target_ref = relationship.get("target_ref")
    return {
        "relationship_id": relationship.get("id"),
        "relationship_type": relationship.get("relationship_type"),
        "source": _summary_for_object(objects_by_id.get(source_ref, {"id": source_ref, "type": "unknown"})),
        "target": _summary_for_object(objects_by_id.get(target_ref, {"id": target_ref, "type": "unknown"})),
    }


def summarize_schema(bundle: dict[str, Any]) -> dict[str, Any]:
    objects_by_id = _build_object_index(bundle)
    observed_fields: dict[str, set[str]] = defaultdict(set)
    observed_relationship_types: dict[str, set[str]] = defaultdict(set)
    all_relationship_types: set[str] = set()

    for stix_object in bundle.get("objects", []):
        stix_type = stix_object.get("type")
        if not stix_type:
            continue
        if stix_type == "relationship":
            relationship_type = stix_object.get("relationship_type")
            source_type = objects_by_id.get(stix_object.get("source_ref"), {}).get("type")
            target_type = objects_by_id.get(stix_object.get("target_ref"), {}).get("type")
            if relationship_type:
                all_relationship_types.add(str(relationship_type))
                if source_type:
                    observed_relationship_types[str(source_type)].add(str(relationship_type))
                if target_type:
                    observed_relationship_types[str(target_type)].add(str(relationship_type))
            continue

        observed_fields[str(stix_type)].update(
            key for key, value in stix_object.items() if value not in (None, "", [], {})
        )

    entity_types: list[dict[str, Any]] = []
    for logical_type, aliases in CORE_ENTITY_TYPE_ALIASES.items():
        actual_types = sorted(stix_type for stix_type in observed_fields if stix_type in aliases)
        combined_fields: set[str] = set()
        combined_relationship_types: set[str] = set()

        for actual_type in actual_types:
            combined_fields.update(observed_fields.get(actual_type, set()))
            combined_relationship_types.update(observed_relationship_types.get(actual_type, set()))

        ordered_fields = [field for field in FIELD_PRIORITY if field in combined_fields]
        ordered_fields.extend(sorted(field for field in combined_fields if field not in ordered_fields))

        entity_types.append(
            {
                "entity_type": logical_type,
                "stix_types": actual_types,
                "key_fields": ordered_fields,
                "relationship_types": sorted(combined_relationship_types),
            }
        )

    return {
        "schema_version": "stix-2.1-local-summary.v1",
        "schema_first_guidance": (
            "Use supported_query_fields from this payload to build structured filters before calling advanced_filter."
        ),
        "supported_query_fields": sorted(SUPPORTED_QUERY_FIELDS),
        "relationship_fields": ["relationship_type", "relationship_source", "relationship_target"],
        "relationship_types": sorted(all_relationship_types),
        "entity_types": entity_types,
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


def advanced_filter(bundle: dict[str, Any], filters: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(filters, dict) or not filters:
        raise ValueError("advanced_filter requires a non-empty JSON object of schema-derived filter fields.")

    unknown_fields = sorted(str(key) for key in filters if str(key) not in SUPPORTED_QUERY_FIELDS)
    if unknown_fields:
        raise ValueError(
            "Unsupported filter fields: "
            f"{', '.join(unknown_fields)}. Query schema first via db_schema_explorer and use supported_query_fields only."
        )

    objects_by_id = _build_object_index(bundle)
    relationships = [obj for obj in bundle.get("objects", []) if obj.get("type") == "relationship"]
    direct_filter_keys = [
        key for key in ("id", "type", "name", "description", "pattern", "value") if key in filters
    ]
    relationship_filter_keys = [
        key for key in ("relationship_type", "relationship_source", "relationship_target") if key in filters
    ]

    matched_ids: set[str] = set()
    matched_relationships: dict[str, dict[str, Any]] = {}

    for stix_object in bundle.get("objects", []):
        stix_id = stix_object.get("id")
        stix_type = stix_object.get("type")
        if not stix_id or stix_type == "relationship":
            continue

        direct_match = True
        for key in direct_filter_keys:
            if key == "type":
                direct_match = _object_type_matches(stix_type, filters[key])
            else:
                direct_match = _matches_text(stix_object.get(key), filters[key])
            if not direct_match:
                break

        if not direct_match:
            continue

        object_relationship_matches: list[dict[str, Any]] = []
        for relationship in relationships:
            source_ref = relationship.get("source_ref")
            target_ref = relationship.get("target_ref")
            if stix_id not in {source_ref, target_ref}:
                continue

            source_summary = _summary_for_object(objects_by_id.get(source_ref, {"id": source_ref, "type": "unknown"}))
            target_summary = _summary_for_object(objects_by_id.get(target_ref, {"id": target_ref, "type": "unknown"}))
            peer_summary = target_summary if source_ref == stix_id else source_summary

            relationship_match = True
            if "relationship_type" in filters:
                relationship_match = _matches_text(relationship.get("relationship_type"), filters["relationship_type"])
            if relationship_match and "relationship_source" in filters:
                relationship_match = _summary_matches(source_summary, filters["relationship_source"])
            if relationship_match and "relationship_target" in filters:
                relationship_match = _summary_matches(peer_summary, filters["relationship_target"])

            if relationship_match:
                object_relationship_matches.append(_relationship_payload(relationship, objects_by_id))

        if relationship_filter_keys and not object_relationship_matches:
            continue

        matched_ids.add(stix_id)
        for relationship_payload in object_relationship_matches:
            matched_relationships[relationship_payload["relationship_id"]] = relationship_payload

    matches = [_summary_for_object(objects_by_id[stix_id]) for stix_id in sorted(matched_ids)]
    relationship_list = [matched_relationships[key] for key in sorted(matched_relationships)]

    return {
        "filters": {str(key): filters[key] for key in sorted(filters)},
        "match_count": len(matches),
        "matches": matches,
        "relationship_count": len(relationship_list),
        "relationships": relationship_list,
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
