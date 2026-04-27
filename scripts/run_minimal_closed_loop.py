"""Run the Threat Intelligence Agent V1 closed-loop acceptance case."""

# @ArchitectureID: ELM-TECH-ARTIFACT-REPO-ASSETS

from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.neo4j_validation import (
    ensure_neo4j_validation_container,
    load_validation_projection,
    neo4j_validation_environment,
    reset_validation_projection,
)
from services.python_listener.remote_client import DEFAULT_OPENCODE_BASE_URL
from services.remote_opencode_server import start_mock_remote_server


ACCEPTANCE_CASE_ID = "1726"
ACCEPTANCE_CASE_NAME = "[闭环验收/集成验收]标准高危威胁事件闭环分析"
ACCEPTANCE_CASE_TYPE = "closed-loop-acceptance"
ACCEPTANCE_SUMMARY_PATH = Path("artifacts/runtime/opencti-push-001-acceptance-summary.json")
USE_MOCK_REMOTE_SERVER_ENV = "THREAT_INTEL_USE_MOCK_REMOTE_SERVER"
REEXEC_ENV = "THREAT_INTEL_MINIMAL_CLOSED_LOOP_REEXEC"


def _is_truthy_env(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _resolve_repo_venv_python(repo_root: Path) -> Path | None:
    candidates = [
        repo_root / ".venv/Scripts/python.exe",
        repo_root / ".venv/bin/python",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _bootstrap_runtime_python(repo_root: Path) -> None:
    if importlib.util.find_spec("neo4j") is not None:
        return
    if _is_truthy_env(os.environ.get(REEXEC_ENV)):
        return

    repo_python = _resolve_repo_venv_python(repo_root)
    if repo_python is None:
        return

    os.environ[REEXEC_ENV] = "1"
    os.execv(str(repo_python), [str(repo_python), str(Path(__file__).resolve()), *sys.argv[1:]])


def _resolve_remote_server(repo_root: Path):
    if _is_truthy_env(os.environ.get(USE_MOCK_REMOTE_SERVER_ENV)):
        stix_bundle_path = repo_root / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json"
        return None, start_mock_remote_server(stix_data_path=stix_bundle_path)

    configured_remote_server_url = os.environ.get("THREAT_INTEL_REMOTE_SERVER_URL", "").strip()
    if configured_remote_server_url:
        os.environ.setdefault("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "120")
        return configured_remote_server_url, nullcontext()

    os.environ.setdefault("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "120")
    return DEFAULT_OPENCODE_BASE_URL, nullcontext()


def _is_retryable_listener_failure(stderr_text: str) -> bool:
    normalized = stderr_text.casefold()
    return "remote server request timed out" in normalized or "remote server returned invalid json" in normalized


def _emit_acceptance_summary(repo_root: Path, summary: dict[str, object]) -> None:
    summary_path = repo_root / ACCEPTANCE_SUMMARY_PATH
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def main() -> None:
    repo_root = REPO_ROOT
    _bootstrap_runtime_python(repo_root)
    output_path = repo_root / "artifacts/runtime/opencti-push-001-analysis.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    event_id = "opencti-push-001"
    neo4j_settings = ensure_neo4j_validation_container(repo_root)
    reset_validation_projection(event_id, settings=neo4j_settings)
    remote_server_url, remote_server_context = _resolve_remote_server(repo_root)

    with neo4j_validation_environment(neo4j_settings), remote_server_context as server:
        resolved_remote_server_url = remote_server_url or server.base_url
        listener_command = [
            sys.executable,
            "-m",
            "services.python_listener",
            "--event",
            "data/mock_events/mock_opencti_push_event.json",
            "--output",
            str(output_path),
            "--remote-server-url",
            resolved_remote_server_url,
        ]
        max_attempts = 2 if remote_server_url else 1

        for attempt in range(1, max_attempts + 1):
            try:
                completed = subprocess.run(
                    listener_command,
                    cwd=repo_root,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                break
            except subprocess.CalledProcessError as exc:
                if attempt < max_attempts and _is_retryable_listener_failure(exc.stderr):
                    continue

                verification_summary = {
                    "acceptance_case": {
                        "id": ACCEPTANCE_CASE_ID,
                        "name": ACCEPTANCE_CASE_NAME,
                        "type": ACCEPTANCE_CASE_TYPE,
                    },
                    "status": "failed",
                    "output_path": str(output_path.relative_to(repo_root)),
                    "acceptance_summary_path": ACCEPTANCE_SUMMARY_PATH.as_posix(),
                    "remote_endpoint": resolved_remote_server_url,
                    "return_code": exc.returncode,
                    "stderr": exc.stderr.strip(),
                }
                _emit_acceptance_summary(repo_root, verification_summary)
                raise SystemExit(exc.returncode) from exc
        else:
            verification_summary = {
                "acceptance_case": {
                    "id": ACCEPTANCE_CASE_ID,
                    "name": ACCEPTANCE_CASE_NAME,
                    "type": ACCEPTANCE_CASE_TYPE,
                },
                "status": "failed",
                "output_path": str(output_path.relative_to(repo_root)),
                "acceptance_summary_path": ACCEPTANCE_SUMMARY_PATH.as_posix(),
                "remote_endpoint": resolved_remote_server_url,
                "return_code": 1,
                "stderr": "Listener subprocess failed without producing a result.",
            }
            _emit_acceptance_summary(repo_root, verification_summary)
            raise SystemExit(1)

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

    validation_snapshot = load_validation_projection(
        run_id=result["run_id"],
        event_id=result["event"]["event_id"],
        settings=neo4j_settings,
    )
    if int(validation_snapshot.get("participant_count", 0)) < 2:
        raise SystemExit("Validation failed: Neo4j persisted fewer than two participant roles.")
    if int(validation_snapshot.get("recommended_action_count", 0)) < 1:
        raise SystemExit("Validation failed: Neo4j persisted no recommended actions.")
    if not str(validation_snapshot.get("conclusion_summary", "")).strip():
        raise SystemExit("Validation failed: Neo4j persisted no conclusion summary.")

    verification_summary = {
        "acceptance_case": {
            "id": ACCEPTANCE_CASE_ID,
            "name": ACCEPTANCE_CASE_NAME,
            "type": ACCEPTANCE_CASE_TYPE,
        },
        "status": "passed",
        "output_path": str(output_path.relative_to(repo_root)),
        "acceptance_summary_path": ACCEPTANCE_SUMMARY_PATH.as_posix(),
        "remote_endpoint": resolved_remote_server_url,
        "neo4j_uri": neo4j_settings["uri"],
        "participant_count": len(participants),
        "recommended_action_count": len(result.get("recommended_actions", [])),
        "neo4j_writeback_total_updates": int(writeback_summary.get("total_updates", 0)),
        "neo4j_persisted_participant_count": int(validation_snapshot.get("participant_count", 0)),
        "neo4j_persisted_recommended_action_count": int(validation_snapshot.get("recommended_action_count", 0)),
    }
    _emit_acceptance_summary(repo_root, verification_summary)


if __name__ == "__main__":
    main()
