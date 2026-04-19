import json
import os
import subprocess
from pathlib import Path
from time import monotonic, sleep
from urllib.parse import urlparse
from urllib import request, error

import pytest

from agent_app.opencode_app.tools.ai4x_cli import resolve_ai4x_base_url as resolve_tool_ai4x_base_url
from services.ai4x_client import probe_ai4x_environment, resolve_ai4x_base_url
from services.python_listener.listener import ThreatIntelListener
from services.python_listener.remote_client import (
    DEFAULT_OPENCODE_BASE_URL,
    RemoteDispatchError,
    RemoteOpencodeClient,
)
from services.remote_opencode_server import start_mock_remote_server


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"
STIX_BUNDLE_PATH = REPO_ROOT / "agent_app/opencode_app/data/stix_samples/threat_intel_bundle.json"
AI4X_BASE_URL = resolve_ai4x_base_url()
OPENCODE_BASE_URL = DEFAULT_OPENCODE_BASE_URL


@pytest.mark.parametrize("resolver", [resolve_ai4x_base_url, resolve_tool_ai4x_base_url])
def test_ai4x_loopback_base_url_is_rewritten_to_container_reachable_host(
    monkeypatch: pytest.MonkeyPatch,
    resolver,
) -> None:
    monkeypatch.setenv("THREAT_INTEL_AI4X_BASE_URL", "http://host.docker.internal:8000")
    assert resolver("http://127.0.0.1:8000") == "http://host.docker.internal:8000"
    assert resolver("http://localhost:8000/") == "http://host.docker.internal:8000"


@pytest.mark.parametrize("resolver", [resolve_ai4x_base_url, resolve_tool_ai4x_base_url])
def test_ai4x_non_loopback_base_url_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    resolver,
) -> None:
    monkeypatch.setenv("THREAT_INTEL_AI4X_BASE_URL", "http://host.docker.internal:8000")
    assert resolver("http://api-center.internal:8000") == "http://api-center.internal:8000"


def _assert_equivalent_ai4x_base_url(actual_base_url: str, expected_base_url: str) -> None:
    actual = urlparse(actual_base_url)
    expected = urlparse(expected_base_url)

    assert actual.scheme == expected.scheme
    assert actual.port == expected.port
    assert actual.hostname in {expected.hostname, "host.docker.internal"}


def _require_real_ai4x_environment() -> dict[str, object]:
    print(f"Probing real AI4X environment...{AI4X_BASE_URL}")
    probe = probe_ai4x_environment(base_url=AI4X_BASE_URL, timeout_seconds=5)
    if not probe.get("ready"):
        failure_reason = f"Real AI4X environment is not ready at {AI4X_BASE_URL}: {probe.get('error', 'unknown error')}"
        print(failure_reason)
        pytest.fail(failure_reason)
    return probe


def _require_real_opencode_server() -> dict[str, object]:
    print(f"Probing real OPENCODE server...{OPENCODE_BASE_URL}")
    client = RemoteOpencodeClient(OPENCODE_BASE_URL, timeout_seconds=15.0)
    try:
        session_response = client._post_json(
            f"{OPENCODE_BASE_URL}/session",
            {},
            action="probe real opencode server",
        )
    except RemoteDispatchError as exc:
        failure_reason = f"Real OPENCODE server is not ready at {OPENCODE_BASE_URL}: {exc}"
        print(failure_reason)
        pytest.fail(failure_reason)

    session_id = session_response.get("id") or session_response.get("sessionID") or session_response.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        failure_reason = (
            f"Real OPENCODE server probe at {OPENCODE_BASE_URL} did not return a usable session id: {session_response}"
        )
        print(failure_reason)
        pytest.fail(failure_reason)

    print(f"real_opencode_probe_session_id={session_id}")
    return session_response


def _load_real_opencode_agents() -> list[dict[str, object]]:
    http_request = request.Request(
        f"{OPENCODE_BASE_URL}/agent",
        headers={"Accept": "application/json"},
        method="GET",
    )
    with request.urlopen(http_request, timeout=15.0) as response:
        payload = response.read().decode(response.headers.get_content_charset("utf-8"))

    parsed = json.loads(payload)
    if not isinstance(parsed, list):
        raise AssertionError(f"Expected {OPENCODE_BASE_URL}/agent to return a JSON array, got: {parsed!r}")
    return [item for item in parsed if isinstance(item, dict)]


def _require_real_opencode_agent(agent_name: str) -> dict[str, object]:
    agents = _load_real_opencode_agents()
    loaded_names = [str(item.get("name") or "").strip() for item in agents]
    for agent in agents:
        if str(agent.get("name") or "").strip() == agent_name:
            print(f"real_opencode_loaded_agent={agent_name}")
            return agent

    failure_reason = (
        f"Real OPENCODE server at {OPENCODE_BASE_URL} has not loaded agent {agent_name}. "
        f"Loaded agents: {loaded_names}"
    )
    print(failure_reason)
    pytest.fail(failure_reason)


def _post_real_opencode_json(
    path: str,
    payload: dict[str, object],
    *,
    timeout: float = 30.0,
    allow_timeout: bool = False,
) -> dict[str, object]:
    opener = request.build_opener(request.ProxyHandler({}))
    http_request = request.Request(
        f"{OPENCODE_BASE_URL}{path}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with opener.open(http_request, timeout=timeout) as response:
            raw_payload = response.read().decode(response.headers.get_content_charset("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        pytest.fail(f"Real OPENCODE POST {path} failed with HTTP {exc.code}: {details}")
    except TimeoutError as exc:
        if allow_timeout:
            return {}
        pytest.fail(f"Real OPENCODE POST {path} timed out after {timeout:.1f}s: {exc}")

    parsed = json.loads(raw_payload)
    assert isinstance(parsed, dict)
    return parsed


def _get_real_opencode_messages(session_id: str) -> list[dict[str, object]]:
    opener = request.build_opener(request.ProxyHandler({}))
    http_request = request.Request(
        f"{OPENCODE_BASE_URL}/session/{session_id}/message",
        headers={"Accept": "application/json"},
        method="GET",
    )
    with opener.open(http_request, timeout=30.0) as response:
        raw_payload = response.read().decode(response.headers.get_content_charset("utf-8"))

    parsed = json.loads(raw_payload)
    assert isinstance(parsed, list)
    return [item for item in parsed if isinstance(item, dict)]


def _iter_ai4x_query_tool_parts(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    tool_parts: list[dict[str, object]] = []
    for message in messages:
        parts = message.get("parts")
        if not isinstance(parts, list):
            continue
        for part in parts:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "tool" and part.get("tool") == "ai4x_query":
                tool_parts.append(part)
    return tool_parts


def _extract_completed_ai4x_query_calls(session_id: str, *, timeout_seconds: float = 120.0) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    deadline = monotonic() + timeout_seconds
    last_messages: list[dict[str, object]] = []

    while monotonic() < deadline:
        messages = _get_real_opencode_messages(session_id)
        last_messages = messages
        completed_calls: list[dict[str, object]] = []

        for tool_part in _iter_ai4x_query_tool_parts(messages):
            state = tool_part.get("state")
            if not isinstance(state, dict):
                continue
            if state.get("status") != "completed":
                continue
            completed_calls.append(tool_part)

        commands = {
            str(call.get("state", {}).get("input", {}).get("command", "")).strip()
            for call in completed_calls
            if isinstance(call.get("state"), dict) and isinstance(call.get("state", {}).get("input"), dict)
        }
        if {"catalog", "schema", "query"}.issubset(commands):
            return messages, completed_calls

        sleep(1.0)

    pytest.fail(
        f"ThreatIntelAnalyst_test did not complete ai4x_query catalog/schema/query calls within {timeout_seconds:.1f}s. "
        f"Last message count: {len(last_messages)}"
    )


def _run_tool_module(module_path: Path, args: dict, *, agent: str = "ThreatIntelAnalyst") -> subprocess.CompletedProcess[str]:
    script = """
import { pathToFileURL } from 'node:url';

const modulePath = process.argv[1];
const args = JSON.parse(process.argv[2]);
const agent = process.argv[3];
const directory = process.argv[4];
const worktree = process.argv[5];

const { default: tool } = await import(pathToFileURL(modulePath).href);

const context = {
  sessionID: 'test-session',
  messageID: 'test-message',
  agent,
  directory,
  worktree,
  abort: new AbortController().signal,
  metadata() {},
  async ask() {},
};

try {
  const output = await tool.execute(args, context);
  process.stdout.write(JSON.stringify(output));
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
"""

    env = os.environ.copy()
    env["THREAT_INTEL_AI4X_BASE_URL"] = AI4X_BASE_URL

    return subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            script,
            str(module_path),
            json.dumps(args),
            agent,
            str(WORKSPACE_ROOT),
            str(REPO_ROOT),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )


def _decode_tool_output(raw_output: str) -> dict[str, object]:
    parsed = json.loads(raw_output)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    assert isinstance(parsed, dict)
    return parsed


def test_ai4x_platform_catalog_exposes_available_data_range() -> None:
    probe = _require_real_ai4x_environment()
    tool_path = WORKSPACE_ROOT / "tools/ai4x_query.js"
    print(f"tool_path={tool_path}")
    
    completed = _run_tool_module(tool_path, {"command": "catalog", "baseUrl": AI4X_BASE_URL}, agent="ThreatIntelAnalyst_test")
    
    assert completed.returncode == 0, completed.stderr
    print(f"AI4X Catalog Tool Output:\n{completed.stdout}")
    payload = _decode_tool_output(completed.stdout)
    assert payload["databases"]
    assert payload["total_databases"] == len(payload["databases"])
    assert probe["catalog"]["total_databases"] == payload["total_databases"]


def test_ai4x_platform_query_tool_returns_real_data_payload() -> None:
    _require_real_ai4x_environment()
    tool_path = WORKSPACE_ROOT / "tools/ai4x_query.js"
    print(f"tool_path={tool_path}")
    catalog_completed = _run_tool_module(tool_path, {"command": "catalog", "baseUrl": AI4X_BASE_URL}, agent="ThreatIntelAnalyst_test")
    assert catalog_completed.returncode == 0, catalog_completed.stderr
    print(f"AI4X Catalog Tool Output:\n{catalog_completed.stdout}")
    catalog_payload = _decode_tool_output(catalog_completed.stdout)
    source_id = next((item["source_id"] for item in catalog_payload["databases"] if item.get("storage") == "neo4j"), catalog_payload["databases"][0]["source_id"])

    completed = _run_tool_module(
        tool_path,
        {
            "command": "query",
            "baseUrl": AI4X_BASE_URL,
            "sourceId": source_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5",
            "limit": 5,
        },
        agent="ThreatIntelAnalyst_test",
    )

    assert completed.returncode == 0, completed.stderr
    payload = _decode_tool_output(completed.stdout)
    assert payload["source_id"] == source_id
    assert "items" in payload
    assert payload.get("count", len(payload.get("items", []))) >= 0


def test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service(tmp_path: Path) -> None:
    # @ArchitectureID: 1738
    _require_real_ai4x_environment()
    output_path = tmp_path / "listener-ai4x-result.json"
    agent_definition = REPO_ROOT / "agent_app/opencode_app/.opencode/agents/ThreatIntelAnalyst_test.md"
    assert agent_definition.is_file()

    with start_mock_remote_server(
        stix_data_path=STIX_BUNDLE_PATH,
        ai4x_base_url=AI4X_BASE_URL,
        require_real_ai4x=True,
    ) as server:
        listener = ThreatIntelListener(
            remote_server_url=server.base_url,
            main_agent="ThreatIntelAnalyst_test",
            remote_client=RemoteOpencodeClient(server.base_url, timeout_seconds=120.0),
        )
        result = listener.process_event(
            REPO_ROOT / "data/mock_events/mock_opencti_push_event.json",
            output_path,
        )

    dispatched_payload = server.captured_requests[1]["payload"]
    ai4x_evidence = result["evidence_query_basis"]["ai4x"]

    assert dispatched_payload["agent"] == "ThreatIntelAnalyst_test"
    _assert_equivalent_ai4x_base_url(ai4x_evidence["base_url"], AI4X_BASE_URL)
    assert ai4x_evidence["catalog"]["databases"]
    assert ai4x_evidence["selected_source_id"]
    assert ai4x_evidence["selected_schema"]["source_id"] == ai4x_evidence["selected_source_id"]
    assert ai4x_evidence["query"]["source_id"] == ai4x_evidence["selected_source_id"]
    assert result["analysis_conclusion"]["summary"]
    assert output_path.is_file()


def test_ai4x_platform_data_consumption_flow_uses_real_opencode_server_and_real_ai4x_service(tmp_path: Path) -> None:
    _require_real_ai4x_environment()
    _require_real_opencode_server()
    _require_real_opencode_agent("ThreatIntelAnalyst_test")
    agent_definition = REPO_ROOT / "agent_app/opencode_app/.opencode/agents/ThreatIntelAnalyst_test.md"
    assert agent_definition.is_file()
    print(f"real_opencode_server_url={OPENCODE_BASE_URL}")
    session_response = _post_real_opencode_json("/session", {"title": "AI4X direct tool validation"}, timeout=15.0)
    session_id = str(session_response.get("id") or "").strip()
    assert session_id

    prompt = (
        "Call ai4x_query directly. First use command=catalog to discover AI4X sources. "
        "Do not pass a localhost or 127.0.0.1 baseUrl; use the tool's configured default endpoint. "
        "Then choose one discovered source_id and call command=schema for that same source_id. "
        "Use the discovered schema/source information to construct a read-only Cypher query, then call command=query for the same source_id. "
        "Do not call any tool except ai4x_query. After the query completes, return a short JSON object with selected_source_id, schema_source_id, query_source_id, cypher, and query_result_received."
    )
    _post_real_opencode_json(
        f"/session/{session_id}/message",
        {
            "agent": "ThreatIntelAnalyst_test",
            "parts": [{"type": "text", "text": prompt}],
        },
        timeout=120.0,
        allow_timeout=True,
    )

    messages, completed_calls = _extract_completed_ai4x_query_calls(session_id, timeout_seconds=120.0)
    print(f"real_opencode_ai4x_session_id={session_id}")
    print(f"real_opencode_ai4x_message_count={len(messages)}")

    catalog_call = next(
        call for call in completed_calls
        if str(call.get("state", {}).get("input", {}).get("command", "")).strip() == "catalog"
    )
    schema_call = next(
        call for call in completed_calls
        if str(call.get("state", {}).get("input", {}).get("command", "")).strip() == "schema"
    )
    query_call = next(
        call for call in completed_calls
        if str(call.get("state", {}).get("input", {}).get("command", "")).strip() == "query"
    )

    catalog_output = query_output = schema_output = None
    for call, name in ((catalog_call, "catalog"), (schema_call, "schema"), (query_call, "query")):
        output = call.get("state", {}).get("output")
        if isinstance(output, str):
            parsed_output = json.loads(output)
            if isinstance(parsed_output, str):
                parsed_output = json.loads(parsed_output)
        else:
            parsed_output = output
        assert isinstance(parsed_output, dict), f"Expected ai4x_query {name} output to be a JSON object"
        if name == "catalog":
            catalog_output = parsed_output
        elif name == "schema":
            schema_output = parsed_output
        else:
            query_output = parsed_output

    assert isinstance(catalog_output, dict)
    assert isinstance(schema_output, dict)
    assert isinstance(query_output, dict)
    assert catalog_output["databases"]

    schema_input = schema_call["state"]["input"]
    query_input = query_call["state"]["input"]
    assert schema_output["source_id"] == str(schema_input["sourceId"])
    assert query_output["source_id"] == str(query_input["sourceId"])
    assert str(query_input["sourceId"]).strip() == schema_output["source_id"]
    assert str(query_input["cypher"]).strip()
    assert query_output.get("count", len(query_output.get("items", []))) >= 0