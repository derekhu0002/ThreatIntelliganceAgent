"""CLI entry point for real AI4X Platform API Center access."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.ai4x_client import (  # noqa: E402
    execute_universal_query,
    fetch_schema_catalog,
    fetch_source_schema,
    fetch_source_schema_detail,
    resolve_ai4x_base_url,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real AI4X Platform API Center CLI")
    parser.add_argument("--base-url", default=None, help="Override the AI4X Platform base URL.")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("catalog", help="Fetch the AI4X schema catalog")

    schema_parser = subparsers.add_parser("schema", help="Fetch one AI4X source schema")
    schema_parser.add_argument("--source-id", required=True, help="AI4X source_id to inspect.")

    detail_parser = subparsers.add_parser("detail", help="Fetch one progressive AI4X schema detail view")
    detail_parser.add_argument("--source-id", required=True, help="AI4X source_id to inspect.")
    detail_parser.add_argument(
        "--detail-kind",
        required=True,
        help="Schema detail kind: object, relationship-type, or relationship-schema.",
    )
    detail_parser.add_argument("--type-name", required=True, help="Concrete type name to inspect.")

    query_parser = subparsers.add_parser("query", help="Execute one AI4X universal query")
    query_parser.add_argument("--source-id", required=True, help="AI4X source_id to query.")
    query_parser.add_argument("--cypher", required=True, help="Read-only Cypher to execute.")
    query_parser.add_argument("--params-json", default=None, help="Optional JSON object containing query params.")
    query_parser.add_argument("--limit", type=int, default=None, help="Optional maximum item count.")

    return parser


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "catalog":
        payload = fetch_schema_catalog(base_url=args.base_url)
    elif args.command == "schema":
        payload = fetch_source_schema(args.source_id, base_url=args.base_url)
    elif args.command == "detail":
        payload = {
            "source_id": args.source_id,
            "detail_kind": args.detail_kind,
            "type_name": args.type_name,
            "schema": fetch_source_schema_detail(
                args.source_id,
                args.detail_kind,
                args.type_name,
                base_url=args.base_url,
            ),
        }
    else:
        params = json.loads(args.params_json) if args.params_json else None
        payload = execute_universal_query(
            args.source_id,
            args.cypher,
            params=params,
            limit=args.limit,
            base_url=args.base_url,
        )

    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()