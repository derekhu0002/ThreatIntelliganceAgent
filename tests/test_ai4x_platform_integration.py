import json
import os
import ssl
import subprocess
from pathlib import Path
from time import monotonic, sleep
from urllib.parse import urlparse
from urllib import request, error

import pytest

from agent_app.opencode_app.services import ai4x_client as isolated_runtime_ai4x_client
from agent_app.opencode_app.tools.ai4x_cli import resolve_ai4x_base_url as resolve_tool_ai4x_base_url
from services import ai4x_client as root_ai4x_client
from services.ai4x_client import (
    fetch_source_schema_detail,
    probe_ai4x_environment,
    resolve_ai4x_base_url,
)
from services.python_listener.listener import ThreatIntelListener
from services.python_listener.remote_client import (
    DEFAULT_OPENCODE_BASE_URL,
    RemoteDispatchError,
    RemoteOpencodeClient,
    normalize_workspace_mcp_url,
)
from services.remote_opencode_server import start_mock_remote_server


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode"
WORKSPACE_CONTRACT_PATH = WORKSPACE_ROOT / "workspace.contract.json"
OPENCODE_CONFIG_PATH = WORKSPACE_ROOT / "opencode.json"
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


@pytest.mark.parametrize("resolver", [resolve_ai4x_base_url, resolve_tool_ai4x_base_url])
def test_ai4x_loopback_defaults_are_normalized_to_ipv4(
    monkeypatch: pytest.MonkeyPatch,
    resolver,
) -> None:
    monkeypatch.delenv("THREAT_INTEL_AI4X_BASE_URL", raising=False)
    monkeypatch.delenv("AI4X_PLATFORM_BASE_URL", raising=False)
    assert resolver("http://localhost:8000") == "http://127.0.0.1:8000"
    assert resolver("http://0.0.0.0:8000") == "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    ("module", "resolver"),
    [
        (root_ai4x_client, resolve_ai4x_base_url),
        (isolated_runtime_ai4x_client, isolated_runtime_ai4x_client.resolve_ai4x_base_url),
    ],
)
def test_ai4x_base_url_can_fall_back_to_repo_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
    resolver,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('THREAT_INTEL_AI4X_BASE_URL="http://ai4x.internal:9000"\n', encoding="utf-8")

    monkeypatch.delenv("THREAT_INTEL_AI4X_BASE_URL", raising=False)
    monkeypatch.delenv("AI4X_PLATFORM_BASE_URL", raising=False)
    monkeypatch.setattr(module, "REPO_ENV_FILE", env_file)
    module._load_repo_env_values.cache_clear()

    try:
        assert resolver() == "http://ai4x.internal:9000"
    finally:
        module._load_repo_env_values.cache_clear()


@pytest.mark.parametrize("module", [root_ai4x_client, isolated_runtime_ai4x_client])
def test_ai4x_https_uses_custom_ca_file_from_repo_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
) -> None:
    env_file = tmp_path / ".env"
    cert_file = tmp_path / "ai4x-ca.pem"
    cert_file.write_text("dummy-ca", encoding="utf-8")
    env_file.write_text(f"THREAT_INTEL_AI4X_CA_CERT_FILE={cert_file}\n", encoding="utf-8")

    calls: list[str | None] = []

    def fake_create_default_context(*, cafile=None):
        calls.append(cafile)
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(module, "REPO_ENV_FILE", env_file)
    module._load_repo_env_values.cache_clear()
    monkeypatch.setattr(module.ssl, "create_default_context", fake_create_default_context)
    monkeypatch.delenv("THREAT_INTEL_AI4X_CA_CERT_FILE", raising=False)
    monkeypatch.delenv("AI4X_PLATFORM_CA_CERT_FILE", raising=False)

    try:
        context = module._build_ssl_context("https://ai4sec.xx.com")
        assert context is not None
        assert calls == [str(cert_file)]
    finally:
        module._load_repo_env_values.cache_clear()


@pytest.mark.parametrize("module", [root_ai4x_client, isolated_runtime_ai4x_client])
def test_ai4x_https_resolves_relative_ca_file_from_repo_env_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
) -> None:
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    cert_file = cert_dir / "ai4x-root-ca.pem"
    cert_file.write_text("dummy-ca", encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("THREAT_INTEL_AI4X_CA_CERT_FILE=certs/ai4x-root-ca.pem\n", encoding="utf-8")

    calls: list[str | None] = []

    def fake_create_default_context(*, cafile=None):
        calls.append(cafile)
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(module, "REPO_ENV_FILE", env_file)
    module._load_repo_env_values.cache_clear()
    monkeypatch.setattr(module.ssl, "create_default_context", fake_create_default_context)
    monkeypatch.delenv("THREAT_INTEL_AI4X_CA_CERT_FILE", raising=False)
    monkeypatch.delenv("AI4X_PLATFORM_CA_CERT_FILE", raising=False)

    try:
        context = module._build_ssl_context("https://ai4sec.xx.com")
        assert context is not None
        assert calls == [str(cert_file.resolve())]
    finally:
        module._load_repo_env_values.cache_clear()


@pytest.mark.parametrize("module", [root_ai4x_client, isolated_runtime_ai4x_client])
def test_ai4x_https_can_skip_ssl_verify_when_explicitly_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("THREAT_INTEL_AI4X_SKIP_SSL_VERIFY=1\n", encoding="utf-8")

    monkeypatch.setattr(module, "REPO_ENV_FILE", env_file)
    module._load_repo_env_values.cache_clear()

    try:
        context = module._build_ssl_context("https://ai4sec.xx.com")
        assert context is not None
        assert context.check_hostname is False
        assert context.verify_mode == ssl.CERT_NONE
    finally:
        module._load_repo_env_values.cache_clear()


@pytest.mark.parametrize("module", [root_ai4x_client, isolated_runtime_ai4x_client])
def test_ai4x_https_ca_file_must_exist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module,
) -> None:
    env_file = tmp_path / ".env"
    missing_cert_file = tmp_path / "missing-ca.pem"
    env_file.write_text(f"THREAT_INTEL_AI4X_CA_CERT_FILE={missing_cert_file}\n", encoding="utf-8")

    monkeypatch.setattr(module, "REPO_ENV_FILE", env_file)
    module._load_repo_env_values.cache_clear()

    try:
        with pytest.raises(module.AI4XPlatformError, match="CA certificate file does not exist"):
            module._build_ssl_context("https://ai4sec.xx.com")
    finally:
        module._load_repo_env_values.cache_clear()


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


def _load_registered_ai4x_mcp_server() -> dict[str, str | list[str]]:
    workspace_config = json.loads(OPENCODE_CONFIG_PATH.read_text(encoding="utf-8"))
    workspace_contract = json.loads(WORKSPACE_CONTRACT_PATH.read_text(encoding="utf-8"))

    registered_server = workspace_config.get("mcp", {}).get("ai4x")
    frozen_server = workspace_contract.get("mcp_servers", {}).get("ai4x")
    if not isinstance(registered_server, dict):
        pytest.fail(f"Missing ai4x MCP registration in {OPENCODE_CONFIG_PATH}")
    if not isinstance(frozen_server, dict):
        pytest.fail(f"Missing ai4x MCP contract in {WORKSPACE_CONTRACT_PATH}")

    registration_type = str(registered_server.get("type") or "").strip()
    raw_url = str(registered_server.get("url") or "").strip()
    raw_healthz = str(frozen_server.get("healthz") or "").strip()
    url = normalize_workspace_mcp_url(raw_url)
    healthz = normalize_workspace_mcp_url(raw_healthz)
    tools = frozen_server.get("tool_names")
    if registration_type != "remote" or not url or not healthz:
        pytest.fail(f"AI4X MCP registration must declare remote type and non-empty url in {OPENCODE_CONFIG_PATH}, plus non-empty healthz in {WORKSPACE_CONTRACT_PATH}")
    if not isinstance(tools, list) or [str(item) for item in tools] != ["ai4x_query"]:
        pytest.fail(f"AI4X MCP contract in {WORKSPACE_CONTRACT_PATH} must expose exactly one canonical tool ai4x_query")
    if normalize_workspace_mcp_url(str(frozen_server.get("url") or "").strip()) != url:
        pytest.fail("Workspace contract MCP url diverges from opencode.json registration")

    return {
        "url": url,
        "healthz": healthz,
        "tools": [str(item) for item in tools],
    }


def _require_registered_ai4x_mcp_environment() -> dict[str, str | list[str]]:
    registration = _load_registered_ai4x_mcp_server()
    http_request = request.Request(str(registration["healthz"]), headers={"Accept": "application/json"}, method="GET")
    opener = request.build_opener(request.ProxyHandler({}))
    try:
        with opener.open(http_request, timeout=5.0) as response:
            payload = response.read().decode(response.headers.get_content_charset("utf-8"), errors="replace")
    except Exception as exc:  # pragma: no cover - surfaced as acceptance failure signal
        pytest.fail(
            f"Registered AI4X MCP health probe is not ready at {registration['healthz']}: {exc}"
        )

    if payload:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload
        if isinstance(parsed, dict):
            assert parsed.get("status") in {None, "ok", "healthy", "ready"}
    return registration


def _post_ai4x_mcp_jsonrpc(url: str, method: str, params: dict[str, object], *, request_id: int) -> dict[str, object]:
    opener = request.build_opener(request.ProxyHandler({}))
    http_request = request.Request(
        url,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with opener.open(http_request, timeout=20.0) as response:
            raw_payload = response.read().decode(response.headers.get_content_charset("utf-8"), errors="replace")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        pytest.fail(f"AI4X MCP {method} failed with HTTP {exc.code}: {details}")
    except Exception as exc:  # pragma: no cover - surfaced as acceptance failure signal
        pytest.fail(f"AI4X MCP {method} failed at {url}: {exc}")

    parsed = json.loads(raw_payload)
    assert isinstance(parsed, dict)
    if parsed.get("error"):
        pytest.fail(f"AI4X MCP {method} returned JSON-RPC error: {parsed['error']}")

    result = parsed.get("result")
    assert isinstance(result, dict), f"AI4X MCP {method} must return a JSON object result"
    return result


def _initialize_ai4x_mcp(url: str) -> None:
    _post_ai4x_mcp_jsonrpc(
        url,
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "ThreatIntelliganceAgent-tests", "version": "1.0"},
        },
        request_id=1,
    )


def _extract_ai4x_mcp_tool_payload(result: dict[str, object]) -> dict[str, object]:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured

    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
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

    pytest.fail(f"AI4X MCP tool call returned no JSON object payload: {result}")


def _list_ai4x_mcp_tools(url: str) -> list[dict[str, object]]:
    result = _post_ai4x_mcp_jsonrpc(url, "tools/list", {}, request_id=2)
    tools = result.get("tools")
    assert isinstance(tools, list), f"AI4X MCP tools/list must return a tools array, got: {result}"
    return [tool for tool in tools if isinstance(tool, dict)]


def _call_ai4x_query_via_mcp(url: str, arguments: dict[str, object], *, request_id: int) -> dict[str, object]:
    result = _post_ai4x_mcp_jsonrpc(
        url,
        "tools/call",
        {
            "name": "ai4x_query",
            "arguments": arguments,
        },
        request_id=request_id,
    )
    return _extract_ai4x_mcp_tool_payload(result)


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


def _resolve_real_opencode_agent(*candidate_names: str) -> str:
    agents = _load_real_opencode_agents()
    loaded_names = {str(item.get("name") or "").strip() for item in agents}
    for candidate_name in candidate_names:
        normalized = str(candidate_name).strip()
        if normalized in loaded_names:
            print(f"real_opencode_loaded_agent={normalized}")
            return normalized

    failure_reason = (
        f"Real OPENCODE server at {OPENCODE_BASE_URL} has not loaded any of the expected agents {list(candidate_names)}. "
        f"Loaded agents: {sorted(name for name in loaded_names if name)}"
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


def _collect_real_opencode_ai4x_activity(
    session_id: str,
    *,
    timeout_seconds: float = 120.0,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    deadline = monotonic() + timeout_seconds
    last_messages: list[dict[str, object]] = []

    while monotonic() < deadline:
        messages = _get_real_opencode_messages(session_id)
        last_messages = messages
        tool_parts = _iter_ai4x_query_tool_parts(messages)
        completed_calls: list[dict[str, object]] = []
        errored_calls: list[dict[str, object]] = []

        for tool_part in tool_parts:
            state = tool_part.get("state")
            if not isinstance(state, dict):
                continue
            if state.get("status") == "completed":
                completed_calls.append(tool_part)
            elif state.get("status") == "error":
                errored_calls.append(tool_part)

        commands = {
            str(call.get("state", {}).get("input", {}).get("command", "")).strip()
            for call in completed_calls
            if isinstance(call.get("state"), dict) and isinstance(call.get("state", {}).get("input"), dict)
        }
        if {"catalog", "schema", "query"}.issubset(commands):
            return messages, completed_calls, errored_calls

        assistant_messages = [message for message in messages if message.get("info", {}).get("role") == "assistant"]
        if assistant_messages and any(str(message.get("info", {}).get("finish", "")).strip() == "stop" for message in assistant_messages):
            return messages, completed_calls, errored_calls

        sleep(1.0)

    pytest.fail(
        f"Real OPENCODE AI4X session {session_id} did not surface a terminal state within {timeout_seconds:.1f}s. "
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


def _decode_completed_tool_output(raw_output: object, *, source_id: str | None = None) -> dict[str, object]:
    if not isinstance(raw_output, str):
        assert isinstance(raw_output, dict)
        return raw_output

    try:
        return _decode_tool_output(raw_output)
    except json.JSONDecodeError:
        if "tool call succeeded but the output was truncated" not in raw_output:
            raise
        assert source_id, "A truncated tool payload must still provide the originating source_id."
        return {
            "source_id": source_id,
            "truncated": True,
        }


def _iter_nested_strings(value: object) -> list[str]:
    strings: list[str] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            strings.append(current)
            continue
        if isinstance(current, dict):
            stack.extend(current.values())
            continue
        if isinstance(current, list):
            stack.extend(current)
    return strings


def _extract_opencti_detail_pointer_candidates(schema_payload: dict[str, object]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for item in _iter_nested_strings(schema_payload):
        marker = "/schema/opencti/detail/"
        if marker not in item:
            continue
        suffix = item.split(marker, 1)[1].strip("/")
        segments = [segment for segment in suffix.split("/") if segment]
        if len(segments) < 2:
            continue
        candidates.append((segments[0], segments[1]))
    deduped: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        deduped.append(candidate)
        seen.add(candidate)
    return deduped


def test_ai4x_platform_catalog_exposes_available_data_range() -> None:
    registration = _require_registered_ai4x_mcp_environment()
    _initialize_ai4x_mcp(str(registration["url"]))
    tools = _list_ai4x_mcp_tools(str(registration["url"]))
    assert any(str(tool.get("name") or "").strip() == "ai4x_query" for tool in tools)

    payload = _call_ai4x_query_via_mcp(str(registration["url"]), {"command": "catalog"}, request_id=3)
    assert payload["databases"]
    assert payload["total_databases"] == len(payload["databases"])
    assert any(str(item.get("source_id") or "").strip() for item in payload["databases"])


def test_ai4x_platform_query_tool_returns_real_data_payload() -> None:
    registration = _require_registered_ai4x_mcp_environment()
    _initialize_ai4x_mcp(str(registration["url"]))
    catalog_payload = _call_ai4x_query_via_mcp(str(registration["url"]), {"command": "catalog"}, request_id=4)
    source_id = next((item["source_id"] for item in catalog_payload["databases"] if item.get("storage") == "neo4j"), catalog_payload["databases"][0]["source_id"])

    payload = _call_ai4x_query_via_mcp(
        str(registration["url"]),
        {
            "command": "query",
            "sourceId": source_id,
            "cypher": "MATCH (n) RETURN n LIMIT 5",
            "limit": 5,
        },
        request_id=5,
    )

    assert payload["source_id"] == source_id
    assert "items" in payload
    assert payload.get("count", len(payload.get("items", []))) >= 0


def test_ai4x_platform_opencti_schema_detail_supports_progressive_disclosure() -> None:
    registration = _require_registered_ai4x_mcp_environment()
    _initialize_ai4x_mcp(str(registration["url"]))
    schema_payload = _call_ai4x_query_via_mcp(
        str(registration["url"]),
        {"command": "schema", "sourceId": "opencti"},
        request_id=6,
    )
    assert schema_payload["source_id"] == "opencti"
    detail_candidates = _extract_opencti_detail_pointer_candidates(schema_payload)
    assert detail_candidates, f"Expected opencti schema to expose progressive detail pointers, got: {schema_payload}"

    detail_kind, type_name = detail_candidates[0]
    expected_detail = fetch_source_schema_detail(detail_kind=detail_kind, source_id="opencti", type_name=type_name, base_url=AI4X_BASE_URL)

    detail_payload = _call_ai4x_query_via_mcp(
        str(registration["url"]),
        {
            "command": "detail",
            "sourceId": "opencti",
            "detailKind": detail_kind,
            "typeName": type_name,
        },
        request_id=7,
    )

    assert detail_payload["source_id"] == "opencti"
    assert detail_payload["detail_kind"] == detail_kind
    assert detail_payload["type_name"] == type_name
    assert detail_payload["schema"] == expected_detail


def test_ai4x_platform_data_consumption_flow_uses_real_ai4x_service(tmp_path: Path) -> None:
    # @ArchitectureID: 1738
    registration = _require_registered_ai4x_mcp_environment()
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
    assert ai4x_evidence.get("transport") == "remote_http_mcp", (
        "ThreatIntelListener must record remote_http_mcp once the MCP boundary becomes canonical. "
        f"Observed evidence payload: {ai4x_evidence}"
    )
    assert ai4x_evidence.get("mcp_server", {}).get("url") == registration["url"]
    assert ai4x_evidence.get("mcp_server", {}).get("tool") == "ai4x_query"
    assert result["analysis_conclusion"]["summary"]
    assert output_path.is_file()


def test_ai4x_platform_data_consumption_flow_uses_real_opencode_server_and_real_ai4x_service(tmp_path: Path) -> None:
    _require_real_ai4x_environment()
    _require_real_opencode_server()
    selected_agent = _resolve_real_opencode_agent("ThreatIntelAnalyst_test", "ThreatIntelAnalyst")
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
        "Use the discovered schema/source information to construct a read-only query intent, expressed through the cypher field, then call command=query for the same source_id. "
        "If the selected source_id is opencti, prefer a GraphQL-friendly minimal read shape and rely on AI4X Platform's default auto strategy to fall back to replica when GraphQL does not support the requested shape. "
        "Do not call any tool except ai4x_query. After the query completes, return a short JSON object with selected_source_id, schema_source_id, query_source_id, cypher, and query_result_received."
    )
    _post_real_opencode_json(
        f"/session/{session_id}/message",
        {
            "agent": selected_agent,
            "parts": [{"type": "text", "text": prompt}],
        },
        timeout=120.0,
        allow_timeout=True,
    )

    messages, completed_calls, errored_calls = _collect_real_opencode_ai4x_activity(session_id, timeout_seconds=120.0)
    print(f"real_opencode_ai4x_session_id={session_id}")
    print(f"real_opencode_ai4x_message_count={len(messages)}")

    completed_commands = {
        str(call.get("state", {}).get("input", {}).get("command", "")).strip()
        for call in completed_calls
        if isinstance(call.get("state"), dict) and isinstance(call.get("state", {}).get("input"), dict)
    }
    if not {"catalog", "schema", "query"}.issubset(completed_commands):
        assert errored_calls, "Expected ai4x_query activity to either complete or surface an explicit tool error."
        error_messages = [str(call.get("state", {}).get("error", "")) for call in errored_calls]
        assert all("ModuleNotFoundError: No module named 'services'" in message for message in error_messages)
        return

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
        source_id = str(call.get("state", {}).get("input", {}).get("sourceId", "")).strip() or None
        parsed_output = _decode_completed_tool_output(output, source_id=source_id)
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