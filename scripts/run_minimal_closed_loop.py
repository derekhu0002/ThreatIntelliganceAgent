"""Run and verify the Threat Intelligence Agent V1 minimal closed loop."""

# @ArchitectureID: ELM-TECH-ARTIFACT-REPO-ASSETS

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_path = repo_root / "artifacts/runtime/validation-result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    remote_server_url = os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL", "http://127.0.0.1:8124")

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
                remote_server_url,
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
            "remote_endpoint": remote_server_url,
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

    verification_summary = {
        "status": "passed",
        "output_path": str(output_path.relative_to(repo_root)),
        "remote_endpoint": remote_server_url,
        "participant_count": len(participants),
        "recommended_action_count": len(result.get("recommended_actions", [])),
    }
    print(json.dumps(verification_summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
