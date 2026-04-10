"""CLI entry point for the Python listener service."""

from __future__ import annotations

import argparse
import json

from .listener import ThreatIntelListener


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Threat Intelligence Agent V1 listener flow")
    parser.add_argument(
        "--event",
        default="data/mock_events/mock_opencti_push_event.json",
        help="Path to the mock OPENCTI push event JSON file.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output path for the structured result artifact.",
    )
    parser.add_argument(
        "--remote-server-url",
        default=None,
        help="Remote OPENCODE SERVER analysis endpoint URL.",
    )
    parser.add_argument(
        "--main-agent",
        default=None,
        help="Optional main agent override for the remote dispatch request.",
    )
    args = parser.parse_args()

    listener = ThreatIntelListener(remote_server_url=args.remote_server_url, main_agent=args.main_agent)
    result = listener.process_event(args.event, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
