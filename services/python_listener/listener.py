"""Python listener service for the minimal closed loop."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.mock_opencti_adapter import load_and_normalize_event
from services.result_assembler import assemble_structured_result


class ThreatIntelListener:
    def __init__(
        self,
        stix_data_path: str | Path | None = None,
        orchestrator_script_path: str | Path | None = None,
    ) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]
        self.stix_data_path = Path(stix_data_path or self.repo_root / "data/stix_samples/threat_intel_bundle.json")
        self.orchestrator_script_path = Path(
            orchestrator_script_path
            or self.repo_root / "agent_app/opencode_app/.opencode/tools/threat_intel_orchestrator.js"
        )

    def process_event(self, event_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
        normalized_event = load_and_normalize_event(event_path).to_dict()
        run_context = self._create_run_context(normalized_event)
        evidence_bundle = self._collect_evidence(normalized_event)
        collaboration_output = self._invoke_orchestrator(run_context, normalized_event, evidence_bundle)

        structured_result = assemble_structured_result(
            run_context=run_context,
            normalized_event=normalized_event,
            evidence_bundle=evidence_bundle,
            collaboration_output=collaboration_output,
        )

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

    def _collect_evidence(self, normalized_event: dict[str, Any]) -> dict[str, Any]:
        queries: list[dict[str, Any]] = []
        relationship_views: list[dict[str, Any]] = []
        candidate_ids: list[str] = []
        search_terms = [normalized_event["entity"]["name"], *[obs["value"] for obs in normalized_event["observables"]]]

        for search_term in dict.fromkeys(search_terms):
            result = self._invoke_stix_cli(["search", "--query", search_term])
            queries.append(result)
            for match in result.get("matches", [])[:2]:
                stix_id = match.get("id")
                if stix_id and stix_id not in candidate_ids:
                    candidate_ids.append(stix_id)

        for stix_id in candidate_ids[:3]:
            relationship_views.append(self._invoke_stix_cli(["neighbors", "--stix-id", stix_id]))

        return {
            "stix_bundle": str(self.stix_data_path.relative_to(self.repo_root)),
            "searches": queries,
            "relationships": relationship_views,
        }

    def _invoke_stix_cli(self, command_args: list[str]) -> dict[str, Any]:
        cli_command = [
            sys.executable,
            "-m",
            "tools.stix_cli",
            "--data",
            str(self.stix_data_path),
            *command_args,
        ]
        completed = subprocess.run(
            cli_command,
            cwd=self.repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    def _invoke_orchestrator(
        self,
        run_context: dict[str, Any],
        normalized_event: dict[str, Any],
        evidence_bundle: dict[str, Any],
    ) -> dict[str, Any]:
        node_path = shutil.which("node")
        if not node_path:
            raise RuntimeError("Node.js is required to run the local multi-agent orchestrator script.")

        payload = {
            "run_context": run_context,
            "event": normalized_event,
            "evidence_bundle": evidence_bundle,
        }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp_file:
            temp_file.write(json.dumps(payload, ensure_ascii=False))
            temp_path = Path(temp_file.name)

        try:
            completed = subprocess.run(
                [node_path, str(self.orchestrator_script_path), str(temp_path)],
                cwd=self.repo_root,
                check=True,
                capture_output=True,
                text=True,
            )
        finally:
            temp_path.unlink(missing_ok=True)

        return json.loads(completed.stdout)
