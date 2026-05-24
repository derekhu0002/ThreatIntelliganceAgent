"""Mock remote OPENCODE SERVER for local validation."""

# @ArchitectureID: ELM-APP-COMP-AGENT-ORCH

from __future__ import annotations

import json
import re
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib import error, request

from agent_app.opencode_app.tools.stix_cli.semantic_query import load_bundle, neighbors, search_entities
from services.ai4x_client import AI4XPlatformError, execute_universal_query, fetch_schema_catalog, fetch_source_schema
from services.python_listener.remote_client import load_workspace_config, normalize_workspace_mcp_url
from services.result_assembler import assemble_structured_result


CANONICAL_ROLE_ALIASES = {
    "ThreatIntelligenceCommander": "ThreatIntelPrimary",
    "STIX_EvidenceSpecialist": "ThreatIntelAnalyst",
    "TARA_analyst": "ThreatIntelSecOps",
}


def _canonical_role_name(role_name: str) -> str:
    return CANONICAL_ROLE_ALIASES.get(role_name, role_name)


REQUEST_CONTEXT_BLOCK_PATTERN = re.compile(r"REQUEST_CONTEXT_JSON:\s*```json\s*(.*?)\s*```", re.DOTALL)
REQUEST_CONTEXT_PATH_PATTERN = re.compile(r"REQUEST_CONTEXT_PATH:\s*(?P<path>\S+)")


def _extract_request_context_from_text(text: str) -> dict[str, Any] | None:
    path_match = REQUEST_CONTEXT_PATH_PATTERN.search(text)
    if path_match is not None:
        request_path = Path(path_match.group("path"))
        candidate = request_path if request_path.is_absolute() else Path.cwd() / request_path
        request_context = json.loads(candidate.read_text(encoding="utf-8"))
        if not isinstance(request_context, dict):
            raise ValueError("Parsed request context must be a JSON object.")
        return request_context

    match = REQUEST_CONTEXT_BLOCK_PATTERN.search(text)
    if match is not None:
        request_context = json.loads(match.group(1))
        if not isinstance(request_context, dict):
            raise ValueError("Parsed request context must be a JSON object.")
        return request_context

    marker = "REQUEST_CONTEXT_JSON:"
    marker_index = text.find(marker)
    if marker_index < 0:
        return None

    payload_text = text[marker_index + len(marker):].lstrip()
    if not payload_text:
        return None

    decoder = json.JSONDecoder()
    request_context, _ = decoder.raw_decode(payload_text)
    if not isinstance(request_context, dict):
        raise ValueError("Parsed request context must be a JSON object.")
    return request_context


def _extract_request_context_from_message(message_payload: dict[str, Any]) -> dict[str, Any]:
    parts = message_payload.get("parts")
    if not isinstance(parts, list) or not parts:
        raise ValueError("Missing message parts in mock remote request.")

    for part in parts:
        if not isinstance(part, dict) or part.get("type") != "text":
            continue
        text = part.get("text")
        if not isinstance(text, str):
            continue
        request_context = _extract_request_context_from_text(text)
        if request_context is None:
            continue
        return request_context

    raise ValueError("Unable to extract REQUEST_CONTEXT_JSON from mock remote message payload.")


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

    unique_entity_refs = list(dict.fromkeys([normalized_event["entity"]["id"], *candidate_ids]))
    relationship_count = sum(int(view.get("relationship_count", 0)) for view in relationship_views)
    counters = {
        "nodes_created": len(unique_entity_refs),
        "relationships_created": max(1, relationship_count),
        "properties_set": len(normalized_event.get("labels", [])) + len(normalized_event.get("observables", [])) + 1,
    }
    total_updates = sum(counters.values())

    return {
        "stix_bundle": str(stix_data_path),
        "searches": searches,
        "relationships": relationship_views,
        "writeback_summary": {
            "attempted": True,
            "operation_mode": "read_write",
            "persistence_outcome": "updated" if total_updates > 0 else "idempotent_noop",
            "total_updates": total_updates,
            "counters": counters,
        },
    }


def _select_ai4x_source_id(databases: list[dict[str, Any]]) -> str:
    preferred_ids = ["tara", "vehicle_iobe", "vehicle_func", "ecu_func", "func_design_spec", "ses"]
    for preferred_id in preferred_ids:
        for database in databases:
            if str(database.get("source_id") or "").strip() == preferred_id:
                return preferred_id

    for database in databases:
        source_id = str(database.get("source_id") or "").strip()
        if source_id:
            return source_id

    raise AI4XPlatformError("AI4X catalog returned no usable source_id values.")


def _load_registered_ai4x_mcp_server() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    config = load_workspace_config(repo_root)
    mcp_servers = config.get("mcp")
    if not isinstance(mcp_servers, dict):
        raise AI4XPlatformError("Workspace config must define mcp.ai4x for canonical AI4X access.")

    registration = mcp_servers.get("ai4x")
    if not isinstance(registration, dict):
        raise AI4XPlatformError("Workspace config must define mcp.ai4x for canonical AI4X access.")

    url = str(registration.get("url") or "").strip()
    if not url:
        raise AI4XPlatformError("Workspace config must define mcp.ai4x.url.")

    return {
        "url": normalize_workspace_mcp_url(url),
        "tool": "ai4x_query",
    }


def _post_ai4x_mcp_jsonrpc(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    http_request = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = request.build_opener(request.ProxyHandler({}))
    try:
        with opener.open(http_request, timeout=20.0) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
        raise AI4XPlatformError(f"AI4X MCP request failed with status {exc.code}: {body}") from exc
    except error.URLError as exc:
        raise AI4XPlatformError(f"AI4X MCP request failed: {exc.reason}") from exc

    response_payload = json.loads(body)
    if not isinstance(response_payload, dict):
        raise AI4XPlatformError("AI4X MCP response must be a JSON object.")
    if "error" in response_payload:
        message = response_payload.get("error", {}).get("message")
        raise AI4XPlatformError(f"AI4X MCP returned an error: {message}")
    return response_payload


def _initialize_ai4x_mcp(url: str) -> None:
    _post_ai4x_mcp_jsonrpc(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ThreatIntelliganceAgent-mock-remote-server", "version": "1.0"},
            },
        },
    )


def _call_ai4x_query_via_mcp(url: str, tool_name: str, arguments: dict[str, Any], *, request_id: int) -> dict[str, Any]:
    response_payload = _post_ai4x_mcp_jsonrpc(
        url,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        },
    )
    result = response_payload.get("result")
    if not isinstance(result, dict):
        raise AI4XPlatformError("AI4X MCP tools/call response must contain an object result.")

    structured_content = result.get("structuredContent")
    if isinstance(structured_content, dict):
        return structured_content

    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "text":
                continue
            text = item.get("text")
            if not isinstance(text, str):
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed

    raise AI4XPlatformError("AI4X MCP tools/call response did not expose usable structured content.")


def _build_ai4x_evidence(normalized_event: dict[str, Any], *, ai4x_base_url: str | None = None) -> dict[str, Any]:
    registration = _load_registered_ai4x_mcp_server()
    mcp_url = str(registration["url"])
    tool_name = str(registration["tool"])
    _initialize_ai4x_mcp(mcp_url)

    catalog = _call_ai4x_query_via_mcp(
        mcp_url,
        tool_name,
        {"command": "catalog"},
        request_id=2,
    )
    databases = [item for item in catalog.get("databases", []) if isinstance(item, dict)]
    selected_source_id = _select_ai4x_source_id(databases)
    schema = _call_ai4x_query_via_mcp(
        mcp_url,
        tool_name,
        {"command": "schema", "sourceId": selected_source_id},
        request_id=3,
    )
    query_result = _call_ai4x_query_via_mcp(
        mcp_url,
        tool_name,
        {
            "command": "query",
            "sourceId": selected_source_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5",
            "limit": 5,
        },
        request_id=4,
    )

    return {
        "transport": "remote_http_mcp",
        "mcp_server": {
            "url": mcp_url,
            "tool": tool_name,
        },
        "base_url": ai4x_base_url,
        "catalog": catalog,
        "selected_source_id": selected_source_id,
        "selected_schema": schema,
        "query": query_result,
        "requested_labels": normalized_event.get("labels", []),
        "requested_observables": [
            item.get("value")
            for item in normalized_event.get("observables", [])
            if isinstance(item, dict) and item.get("value")
        ],
    }


def _build_evidence_bundle_for_mode(
    stix_data_path: Path,
    normalized_event: dict[str, Any],
    *,
    ai4x_base_url: str | None = None,
    require_real_ai4x: bool = False,
) -> dict[str, Any]:
    evidence_bundle = _build_evidence_bundle(stix_data_path, normalized_event)
    if require_real_ai4x:
        evidence_bundle["ai4x"] = _build_ai4x_evidence(normalized_event, ai4x_base_url=ai4x_base_url)
    return evidence_bundle


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
    canonical_main_agent = _canonical_role_name(main_agent)

    return {
        "participants": [canonical_main_agent, "ThreatIntelAnalyst", "ThreatIntelSecOps"],
        "legacy_participants": [main_agent, "STIX_EvidenceSpecialist", "TARA_analyst"],
        "role_outputs": [
            {
                "role": "ThreatIntelAnalyst",
                "legacy_role": "STIX_EvidenceSpecialist",
                "summary": f"Remote evidence review matched {len(matches)} STIX objects and {len(relationships)} relationships.",
            },
            {
                "role": "ThreatIntelSecOps",
                "legacy_role": "TARA_analyst",
                "summary": "Risk review converted remote evidence into containment and hunting recommendations.",
            },
        ],
        "traceability": {
            "event_id": normalized_event["event_id"],
            "main_agent": canonical_main_agent,
            "requested_main_agent": main_agent,
            "supporting_evidence_refs": supporting_ids,
            "assembled_by": canonical_main_agent,
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
            "assembled_by": canonical_main_agent,
            "recommended_actions": [
                "Block or monitor the observable in network controls.",
                "Hunt for related email, endpoint, and outbound connection activity.",
            ],
        },
    }


def build_remote_response(
    request_payload: dict[str, Any],
    stix_data_path: str | Path,
    *,
    ai4x_base_url: str | None = None,
    require_real_ai4x: bool = False,
) -> dict[str, Any]:
    normalized_event = request_payload["event"]
    run_context = request_payload["run_context"]
    main_agent = request_payload["main_agent"]
    evidence_bundle = _build_evidence_bundle_for_mode(
        Path(stix_data_path),
        normalized_event,
        ai4x_base_url=ai4x_base_url,
        require_real_ai4x=require_real_ai4x,
    )
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
    ).model_dump(mode="python")


@dataclass
class MockRemoteServerHandle:
    base_url: str
    endpoint_url: str
    captured_requests: list[dict[str, Any]] = field(default_factory=list)


class _MockRemoteServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class,
        stix_data_path: Path,
        *,
        ai4x_base_url: str | None = None,
        require_real_ai4x: bool = False,
    ) -> None:
        super().__init__(server_address, request_handler_class)
        self.stix_data_path = stix_data_path
        self.ai4x_base_url = ai4x_base_url
        self.require_real_ai4x = require_real_ai4x
        self.captured_requests: list[dict[str, Any]] = []
        self.sessions: dict[str, dict[str, Any]] = {}


def _build_handler():
    class MockRemoteHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            self.server.captured_requests.append({"path": self.path, "payload": payload})  # type: ignore[attr-defined]

            if self.path == "/session":
                session_id = f"mock-session-{uuid.uuid4()}"
                self.server.sessions[session_id] = payload  # type: ignore[attr-defined]
                response_payload = {"id": session_id}
            elif self.path.startswith("/session/") and self.path.endswith("/message"):
                path_parts = [segment for segment in self.path.split("/") if segment]
                if len(path_parts) != 3:
                    self.send_error(404, "Unknown endpoint")
                    return
                session_id = path_parts[1]
                if session_id not in self.server.sessions:  # type: ignore[attr-defined]
                    self.send_error(404, "Unknown session")
                    return
                request_context = _extract_request_context_from_message(payload)
                response_payload = {
                    "sessionID": session_id,
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "json",
                                "json": build_remote_response(
                                    request_context,
                                    self.server.stix_data_path,  # type: ignore[attr-defined]
                                    ai4x_base_url=self.server.ai4x_base_url,  # type: ignore[attr-defined]
                                    require_real_ai4x=self.server.require_real_ai4x,  # type: ignore[attr-defined]
                                ),
                            }
                        ],
                    },
                }
            else:
                self.send_error(404, "Unknown endpoint")
                return

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
def start_mock_remote_server(
    *,
    stix_data_path: str | Path,
    ai4x_base_url: str | None = None,
    require_real_ai4x: bool = False,
) -> Iterator[MockRemoteServerHandle]:
    server = _MockRemoteServer(
        ("127.0.0.1", 0),
        _build_handler(),
        Path(stix_data_path),
        ai4x_base_url=ai4x_base_url,
        require_real_ai4x=require_real_ai4x,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    handle = MockRemoteServerHandle(
        base_url=base_url,
        endpoint_url=base_url,
        captured_requests=server.captured_requests,
    )

    try:
        yield handle
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
