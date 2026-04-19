"""Python listener service for the minimal closed loop."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from services.mock_opencti_adapter import load_and_normalize_event
from services.neo4j_validation import is_real_neo4j_validation_enabled, persist_validation_projection
from services.result_assembler import validate_structured_result

from .remote_client import (
    DEFAULT_OPENCODE_BASE_URL,
    RemoteOpencodeClient,
    load_default_main_agent,
    resolve_main_agent_alias,
)


class ThreatIntelListener:
    def __init__(
        self,
        remote_server_url: str | None = None,
        main_agent: str | None = None,
        remote_client: RemoteOpencodeClient | None = None,
    ) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        configured_main_agent = main_agent or load_default_main_agent(self.repo_root)
        self.main_agent = resolve_main_agent_alias(configured_main_agent, self.repo_root)
        self.requested_main_agent = configured_main_agent
        resolved_remote_server_url = (
            remote_server_url or os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL") or DEFAULT_OPENCODE_BASE_URL
        )

        if remote_client is not None:
            self.remote_client = remote_client
        else:
            self.remote_client = RemoteOpencodeClient(resolved_remote_server_url)

    def process_event(self, event_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
        normalized_event = load_and_normalize_event(event_path).to_dict()
        run_context = self._create_run_context(normalized_event)
        request_context_path = self._persist_remote_request_context(run_context, normalized_event)
        remote_request = self._build_remote_request(run_context, normalized_event, request_context_path)
        structured_result = self.remote_client.dispatch_analysis(remote_request)

        if is_real_neo4j_validation_enabled():
            structured_result["evidence_query_basis"]["writeback_summary"] = persist_validation_projection(structured_result)
            structured_result = validate_structured_result(structured_result).model_dump(mode="python")

        destination = Path(output_path or self.repo_root / f"artifacts/runtime/{normalized_event['event_id']}-analysis.json")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(structured_result, indent=2, ensure_ascii=False), encoding="utf-8")
        return structured_result

    def _persist_remote_request_context(self, run_context: dict[str, Any], normalized_event: dict[str, Any]) -> str:
        request_context = {
            "request_contract_version": "threat-intelligence-agent.remote-request.v2",
            "main_agent": self.main_agent,
            "requested_main_agent": self.requested_main_agent,
            "run_context": run_context,
            "event": normalized_event,
            "stix_elements": {
                "entity": normalized_event["entity"],
                "observables": normalized_event["observables"],
                "labels": normalized_event.get("labels", []),
                "severity": normalized_event.get("severity"),
            },
        }
        relative_path = Path("artifacts/runtime") / f"{normalized_event['event_id']}-remote-request.json"
        absolute_path = self.repo_root / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.write_text(json.dumps(request_context, indent=2, ensure_ascii=False), encoding="utf-8")
        return relative_path.as_posix()

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
        request_context_path: str,
    ) -> dict[str, Any]:
        request_context = {
            "request_contract_version": "threat-intelligence-agent.remote-request.v2",
            "main_agent": self.main_agent,
            "requested_main_agent": self.requested_main_agent,
            "request_context_path": request_context_path,
            "run_context": run_context,
            "event": normalized_event,
            "stix_elements": {
                "entity": normalized_event["entity"],
                "observables": normalized_event["observables"],
                "labels": normalized_event.get("labels", []),
                "severity": normalized_event.get("severity"),
            },
        }

        return {
            **request_context,
            "prompt_text": (
                "Remote PUSH analysis request. Return JSON only and satisfy the provided json_schema.\n"
                f'Main agent semantic: "{self.main_agent}".\n'
                f'Requested main agent alias: "{self.requested_main_agent}".\n'
                "Call `threat_intel_orchestrator` exactly once.\n"
                "Pass `inputJson` with exactly the JSON object from REQUEST_CONTEXT_JSON below.\n"
                f"Local debug artifact path, if shared workspace file access is available: {request_context_path}.\n"
                "Do not use `inputPath` unless you have confirmed that the local debug artifact path exists in the current runtime workspace.\n"
                "Do not use `task`. Do not use any other tool unless `threat_intel_orchestrator` is unavailable.\n"
                "After the tool returns, emit that result as the final structured output.\n"
                "REQUEST_CONTEXT_JSON:\n```json\n"
                f"{json.dumps(request_context, indent=2, ensure_ascii=False)}\n"
                "```\n"
                f"REQUEST_CONTEXT_PATH: {request_context_path}\n"
            ),
        }
