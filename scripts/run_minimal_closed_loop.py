"""Run and verify the Threat Intelligence Agent V1 minimal closed loop."""

# @ArchitectureID: ELM-TECH-ARTIFACT-REPO-ASSETS

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _start_mock_remote_server(*, repo_root: Path, stix_data_path: Path):
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from services.remote_opencode_server import start_mock_remote_server

    return start_mock_remote_server(stix_data_path=stix_data_path)


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_path = repo_root / "artifacts/runtime/validation-result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with _start_mock_remote_server(
        repo_root=repo_root,
        stix_data_path=repo_root / "data/stix_samples/threat_intel_bundle.json",
    ) as server:
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
                server.endpoint_url,
            ],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )

    result = json.loads(completed.stdout)
    participants = result["collaboration_trace"]["participants"]
    if len(participants) < 2:
        raise SystemExit("Validation failed: less than two analysis roles participated.")
    if not result["analysis_conclusion"].get("summary"):
        raise SystemExit("Validation failed: missing analysis conclusion summary.")

    verification_summary = {
        "status": "passed",
        "output_path": str(output_path.relative_to(repo_root)),
        "remote_endpoint": server.endpoint_url,
        "participant_count": len(participants),
        "recommended_action_count": len(result.get("recommended_actions", [])),
    }
    print(json.dumps(verification_summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
