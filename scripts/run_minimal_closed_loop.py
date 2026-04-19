"""Run and verify the Threat Intelligence Agent V1 minimal closed loop."""

# @ArchitectureID: ELM-TECH-ARTIFACT-REPO-ASSETS

from __future__ import annotations

from contextlib import nullcontext
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.remote_opencode_server import start_mock_remote_server


def _resolve_remote_server(repo_root: Path):
    configured_remote_server_url = os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL", "").strip()
    if configured_remote_server_url:
        return configured_remote_server_url, nullcontext()

    stix_bundle_path = repo_root / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json"
    return None, start_mock_remote_server(stix_data_path=stix_bundle_path)


def main() -> None:
    repo_root = REPO_ROOT
    output_path = repo_root / "artifacts/runtime/opencti-push-001-analysis.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    remote_server_url, remote_server_context = _resolve_remote_server(repo_root)

    with remote_server_context as server:
        resolved_remote_server_url = remote_server_url or server.base_url

        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "services.python_listener",
                    "--event",
                    "data/mock_events/mock_opencti_push_event.json",
                    "--output",
                    str(output_path),
                    "--remote-server-url",
                    resolved_remote_server_url,
                ],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            verification_summary = {
                "status": "failed",
                "output_path": str(output_path.relative_to(repo_root)),
                "remote_endpoint": resolved_remote_server_url,
                "return_code": exc.returncode,
                "stderr": exc.stderr.strip(),
            }
            print(json.dumps(verification_summary, indent=2, ensure_ascii=False))
            raise SystemExit(exc.returncode) from exc

    result = json.loads(completed.stdout)
    participants = result["collaboration_trace"]["participants"]
    if len(participants) < 2:
        raise SystemExit("Validation failed: less than two analysis roles participated.")
    if not result["analysis_conclusion"].get("summary"):
        raise SystemExit("Validation failed: missing analysis conclusion summary.")
    if not result.get("recommended_actions"):
        raise SystemExit("Validation failed: missing recommended actions.")
    if result["event"].get("event_id") != "opencti-push-001":
        raise SystemExit("Validation failed: output event id does not match the input event.")

    writeback_summary = result.get("evidence_query_basis", {}).get("writeback_summary")
    if not isinstance(writeback_summary, dict) or not writeback_summary.get("attempted"):
        raise SystemExit("Validation failed: missing Neo4j writeback summary.")
    if int(writeback_summary.get("total_updates", 0)) <= 0:
        raise SystemExit("Validation failed: Neo4j writeback summary reported no persisted updates.")

    verification_summary = {
        "status": "passed",
        "output_path": str(output_path.relative_to(repo_root)),
        "remote_endpoint": resolved_remote_server_url,
        "participant_count": len(participants),
        "recommended_action_count": len(result.get("recommended_actions", [])),
        "neo4j_writeback_total_updates": int(writeback_summary.get("total_updates", 0)),
    }
    print(json.dumps(verification_summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
