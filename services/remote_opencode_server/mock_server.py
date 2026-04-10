"""Mock remote OPENCODE SERVER for local validation."""

# @ArchitectureID: ELM-APP-COMP-AGENT-ORCH

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

from services.result_assembler import assemble_structured_result
from tools.stix_cli.semantic_query import load_bundle, neighbors, search_entities


def _build_evidence_bundle(stix_data_path: Path, normalized_event: dict[str, Any]) -> dict[str, Any]:
    bundle = load_bundle(stix_data_path)
    searches: list[dict[str, Any]] = []
    relationship_views: list[dict[str, Any]] = []
    candidate_ids: list[str] = []
    search_terms = [normalized_event["entity"]["name"], *[item["value"] for item in normalized_event["observables"]]]

    for search_term in dict.fromkeys(search_terms):
        result = search_entities(bundle, search_term)
        searches.append(result)
        for match in result.get("matches", [])[:2]:
            stix_id = match.get("id")
            if stix_id and stix_id not in candidate_ids:
                candidate_ids.append(stix_id)

    for stix_id in candidate_ids[:3]:
        relationship_views.append(neighbors(bundle, stix_id))

    return {
        "stix_bundle": str(stix_data_path),
        "searches": searches,
        "relationships": relationship_views,
    }


def _build_collaboration_output(
    *, main_agent: str, normalized_event: dict[str, Any], evidence_bundle: dict[str, Any]
) -> dict[str, Any]:
    matches = [match for search in evidence_bundle.get("searches", []) for match in search.get("matches", [])]
    relationships = [item for view in evidence_bundle.get("relationships", []) for item in view.get("relationships", [])]
    supporting_ids = list(
        dict.fromkeys(
            [normalized_event["entity"]["id"], *[match.get("id") for match in matches if match.get("id")]]
        )
    )
    related_names = [item.get("peer", {}).get("name") for item in relationships if item.get("peer", {}).get("name")]
    matched_names = [match.get("name") for match in matches if match.get("name")]
    evidence_text = " ".join([normalized_event.get("summary", ""), *matched_names, *related_names])
    mentions_apt28 = "apt28" in evidence_text.casefold()
    verdict = "confirmed-threat" if mentions_apt28 else "needs-review"
    confidence = "high" if mentions_apt28 else "medium"

    return {
        "participants": [main_agent, "STIX_EvidenceSpecialist", "TARA_analyst"],
        "role_outputs": [
            {
                "role": "STIX_EvidenceSpecialist",
                "summary": f"Remote evidence review matched {len(matches)} STIX objects and {len(relationships)} relationships.",
            },
            {
                "role": "TARA_analyst",
                "summary": "Risk review converted remote evidence into containment and hunting recommendations.",
            },
        ],
        "traceability": {
            "event_id": normalized_event["event_id"],
            "main_agent": main_agent,
            "supporting_evidence_refs": supporting_ids,
        },
        "final_assessment": {
            "summary": (
                "The pushed indicator aligns with known APT28-linked phishing activity and warrants containment."
                if mentions_apt28
                else "The pushed indicator remains suspicious and should be triaged with targeted hunting."
            ),
            "confidence": confidence,
            "verdict": verdict,
            "supporting_entities": supporting_ids,
            "recommended_actions": [
                "Block or monitor the observable in network controls.",
                "Hunt for related email, endpoint, and outbound connection activity.",
            ],
        },
    }


def build_remote_response(request_payload: dict[str, Any], stix_data_path: str | Path) -> dict[str, Any]:
    normalized_event = request_payload["event"]
    run_context = request_payload["run_context"]
    main_agent = request_payload["main_agent"]
    evidence_bundle = _build_evidence_bundle(Path(stix_data_path), normalized_event)
    collaboration_output = _build_collaboration_output(
        main_agent=main_agent,
        normalized_event=normalized_event,
        evidence_bundle=evidence_bundle,
    )
    return assemble_structured_result(
        run_context=run_context,
        normalized_event=normalized_event,
        evidence_bundle=evidence_bundle,
        collaboration_output=collaboration_output,
    )


@dataclass
class MockRemoteServerHandle:
    endpoint_url: str
    captured_requests: list[dict[str, Any]] = field(default_factory=list)


class _MockRemoteServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], request_handler_class, stix_data_path: Path) -> None:
        super().__init__(server_address, request_handler_class)
        self.stix_data_path = stix_data_path
        self.captured_requests: list[dict[str, Any]] = []


def _build_handler():
    class MockRemoteHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/analysis-runs":
                self.send_error(404, "Unknown endpoint")
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            self.server.captured_requests.append(payload)  # type: ignore[attr-defined]
            response_payload = build_remote_response(payload, self.server.stix_data_path)  # type: ignore[attr-defined]
            response_body = json.dumps(response_payload, indent=2, ensure_ascii=False).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    return MockRemoteHandler


@contextmanager
def start_mock_remote_server(*, stix_data_path: str | Path) -> Iterator[MockRemoteServerHandle]:
    server = _MockRemoteServer(("127.0.0.1", 0), _build_handler(), Path(stix_data_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    handle = MockRemoteServerHandle(
        endpoint_url=f"http://127.0.0.1:{server.server_port}/analysis-runs",
        captured_requests=server.captured_requests,
    )

    try:
        yield handle
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
