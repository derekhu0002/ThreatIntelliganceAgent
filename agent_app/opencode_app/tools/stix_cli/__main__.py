"""CLI entry point for local STIX semantic queries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .semantic_query import (
    advanced_filter,
    execute_neo4j_cypher,
    load_bundle,
    neighbors,
    search_entities,
    summarize_schema,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local STIX 2.1 semantic query CLI")
    parser.add_argument(
        "--data",
        default=str(Path("data/stix_samples/threat_intel_bundle.json")),
        help="Path to the local STIX 2.1 sample bundle.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    search_parser = subparsers.add_parser("search", help="Search STIX objects by semantic text match")
    search_parser.add_argument("--query", required=True, help="Query text to match against local STIX objects.")

    neighbor_parser = subparsers.add_parser("neighbors", help="List relationships touching one STIX object")
    neighbor_parser.add_argument("--stix-id", required=True, help="Target STIX object id.")

    advanced_filter_parser = subparsers.add_parser(
        "advanced_filter",
        help="Filter STIX objects using schema-derived field names and relationship pivots",
    )
    advanced_filter_parser.add_argument(
        "--filters-json",
        required=True,
        help="JSON object containing schema-derived filter fields.",
    )

    neo4j_parser = subparsers.add_parser("neo4j-cypher", help="Execute native Cypher against Neo4j")
    neo4j_parser.add_argument("--cypher", required=True, help="Raw Cypher statement to execute.")

    subparsers.add_parser("schema-summary", help="Summarize the supported local STIX schema and query fields")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "neo4j-cypher":
        payload = execute_neo4j_cypher(args.cypher)
    else:
        bundle = load_bundle(args.data)

        if args.command == "search":
            payload = search_entities(bundle, args.query)
        elif args.command == "neighbors":
            payload = neighbors(bundle, args.stix_id)
        elif args.command == "advanced_filter":
            payload = advanced_filter(bundle, json.loads(args.filters_json))
        else:
            payload = summarize_schema(bundle)

    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
