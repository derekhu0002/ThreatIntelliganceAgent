"""Python listener service for the minimal closed loop."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from services.mock_opencti_adapter import load_and_normalize_event

from .remote_client import RemoteOpencodeClient, load_default_main_agent


class ThreatIntelListener:
    def __init__(
        self,
        remote_server_url: str | None = None,
        main_agent: str | None = None,
        remote_client: RemoteOpencodeClient | None = None,
    ) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.main_agent = main_agent or load_default_main_agent(self.repo_root)
        resolved_remote_server_url = remote_server_url or os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL")

        if remote_client is not None:
            self.remote_client = remote_client
        elif resolved_remote_server_url:
            self.remote_client = RemoteOpencodeClient(resolved_remote_server_url)
        else:
            raise ValueError("A remote_server_url or THREAT_INTEL_REMOTE_SERVER_URL must be provided.")

    def process_event(self, event_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
        normalized_event = load_and_normalize_event(event_path).to_dict()
        run_context = self._create_run_context(normalized_event)
        remote_request = self._build_remote_request(run_context, normalized_event)
        structured_result = self.remote_client.dispatch_analysis(remote_request)

        destination = Path(output_path or self.repo_root / f"artifacts/runtime/{normalized_event['event_id']}-analysis.json")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(structured_result, indent=2, ensure_ascii=False), encoding="utf-8")
        return structured_result

    def _create_run_context(self, normalized_event: dict[str, Any]) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return {
            "run_id": f"ti-run-{normalized_event['event_id']}-{timestamp}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "event_id": normalized_event["event_id"],
            "source": normalized_event["source"],
        }

    def _build_remote_request(
        self,
        run_context: dict[str, Any],
        normalized_event: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "request_contract_version": "threat-intelligence-agent.remote-request.v1",
            "main_agent": self.main_agent,
            "run_context": run_context,
            "event": normalized_event,
            "stix_elements": {
                "entity": normalized_event["entity"],
                "observables": normalized_event["observables"],
                "labels": normalized_event.get("labels", []),
                "severity": normalized_event.get("severity"),
            },
            "prompt": (
                f"Main agent {self.main_agent} must analyze PUSH event {normalized_event['event_id']} "
                f"using the provided STIX entity and observables, then return a structured result."
            ),
        }
