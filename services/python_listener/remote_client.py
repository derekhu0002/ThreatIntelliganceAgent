"""Remote OPENCODE SERVER client for listener dispatch."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path
from time import monotonic, sleep
from typing import Any
from urllib import error, request
from urllib.parse import quote

from services.result_assembler import validate_structured_result
from services.result_assembler.schema import build_result_json_schema


class RemoteDispatchError(RuntimeError):
    """Raised when the remote OPENCODE SERVER call fails."""


DEFAULT_OPENCODE_BASE_URL = "http://127.0.0.1:8124"
WORKSPACE_CONTRACT_FILE = "workspace.contract.json"
DEFAULT_REMOTE_RETRY_ATTEMPTS = 3
DEFAULT_AGENT_ALIASES = {
    "ThreatIntelligenceCommander": "ThreatIntelPrimary",
    "STIX_EvidenceSpecialist": "ThreatIntelAnalyst",
    "TARA_analyst": "ThreatIntelSecOps",
}


def resolve_remote_timeout_seconds() -> float:
    configured_timeout = os.environ.get("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS", "").strip()
    if not configured_timeout:
        return 30.0

    try:
        timeout_seconds = float(configured_timeout)
    except ValueError as exc:
        raise ValueError("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS must be a positive number when set.") from exc

    if timeout_seconds <= 0:
        raise ValueError("THREAT_INTEL_REMOTE_TIMEOUT_SECONDS must be a positive number when set.")

    return timeout_seconds


def load_workspace_config(repo_root: Path) -> dict[str, Any]:
    config_path = repo_root / "agent_app/opencode_app/.opencode/opencode.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError(f"Workspace config at {config_path} must be a JSON object")

    workspace_contract_path = config_path.with_name(WORKSPACE_CONTRACT_FILE)
    if not workspace_contract_path.is_file():
        return config

    workspace_contract = json.loads(workspace_contract_path.read_text(encoding="utf-8"))
    if not isinstance(workspace_contract, dict):
        raise ValueError(f"Workspace contract at {workspace_contract_path} must be a JSON object")

    return {
        **config,
        **workspace_contract,
    }


def resolve_main_agent_alias(agent_name: str, repo_root: Path) -> str:
    config = load_workspace_config(repo_root)
    alias_map = config.get("agent_aliases", {})
    merged_aliases = dict(DEFAULT_AGENT_ALIASES)
    if isinstance(alias_map, dict):
        merged_aliases.update({key: value for key, value in alias_map.items() if isinstance(key, str) and isinstance(value, str)})

    canonical = merged_aliases.get(agent_name.strip())
    if isinstance(canonical, str) and canonical.strip():
        return canonical.strip()
    return agent_name.strip()


def load_default_main_agent(repo_root: Path) -> str:
    config_path = repo_root / "agent_app/opencode_app/.opencode/opencode.json"
    config = load_workspace_config(repo_root)
    default_agent = config.get("default_agent")
    if not isinstance(default_agent, str) or not default_agent.strip():
        raise ValueError(f"Missing default_agent in {config_path}")
    return default_agent.strip()


class RemoteOpencodeClient:
    def __init__(self, endpoint_url: str, timeout_seconds: float | None = None) -> None:
        self.endpoint_url = endpoint_url.rstrip("/")
        self.timeout_seconds = resolve_remote_timeout_seconds() if timeout_seconds is None else timeout_seconds
        self._opener = request.build_opener(request.ProxyHandler({}))

    def dispatch_analysis(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        last_error: RemoteDispatchError | None = None

        for attempt in range(1, DEFAULT_REMOTE_RETRY_ATTEMPTS + 1):
            try:
                session_response = self._post_json(
                    f"{self.endpoint_url}/session",
                    {},
                    action="create remote session",
                )
                session_id = self._extract_session_id(session_response)
                message_response = self._post_json(
                    f"{self.endpoint_url}/session/{quote(session_id, safe='')}/message",
                    self._build_message_payload(request_payload),
                    action="dispatch remote message",
                )
                try:
                    return self._extract_structured_result(message_response)
                except RemoteDispatchError:
                    return self._poll_session_messages_for_result(session_id)
            except RemoteDispatchError as exc:
                last_error = exc
                if attempt < DEFAULT_REMOTE_RETRY_ATTEMPTS and self._is_retryable_dispatch_error(exc):
                    try:
                        return self._poll_session_messages_for_result(session_id)
                    except (RemoteDispatchError, UnboundLocalError):
                        pass
                if attempt >= DEFAULT_REMOTE_RETRY_ATTEMPTS or not self._is_retryable_dispatch_error(exc):
                    raise

        if last_error is not None:
            raise last_error

        raise RemoteDispatchError("Failed to dispatch remote message: exhausted retries without a response.")

    def _is_retryable_dispatch_error(self, error: RemoteDispatchError) -> bool:
        message = str(error).casefold()
        return "timed out" in message or "invalid json" in message

    def _build_message_payload(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        schema = self._build_request_specific_schema(request_payload)
        return {
            "agent": request_payload["main_agent"],
            "format": {
                "type": "json_schema",
                "schema": schema,
            },
            "parts": [
                {
                    "type": "text",
                    "text": request_payload["prompt_text"],
                }
            ],
        }

    def _build_request_specific_schema(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        schema = deepcopy(build_result_json_schema())
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return schema
        definitions = schema.get("$defs", {})
        if not isinstance(definitions, dict):
            definitions = {}

        run_context = request_payload.get("run_context", {})
        event = request_payload.get("event", {})

        run_id = run_context.get("run_id")
        if isinstance(run_id, str) and isinstance(properties.get("run_id"), dict):
            properties["run_id"]["const"] = run_id

        event_definition = definitions.get("AnalysisResultEvent")
        if not isinstance(event_definition, dict):
            return schema

        event_properties = event_definition.get("properties", {})
        if not isinstance(event_properties, dict):
            return schema

        event_id = event.get("event_id")
        if isinstance(event_id, str) and isinstance(event_properties.get("event_id"), dict):
            event_properties["event_id"]["const"] = event_id

        source = event.get("source")
        if isinstance(source, str) and isinstance(event_properties.get("source"), dict):
            event_properties["source"]["const"] = source

        entity = event.get("entity", {})
        entity_definition = definitions.get("EventEntity")
        if isinstance(entity, dict) and isinstance(entity_definition, dict):
            entity_properties = entity_definition.get("properties", {})
            if isinstance(entity_properties, dict):
                entity_id = entity.get("id")
                if isinstance(entity_id, str) and isinstance(entity_properties.get("id"), dict):
                    entity_properties["id"]["const"] = entity_id

        return schema

    def _poll_session_messages_for_result(self, session_id: str) -> dict[str, Any]:
        deadline = monotonic() + self.timeout_seconds
        last_error: RemoteDispatchError | None = None
        message_list_url = f"{self.endpoint_url}/session/{quote(session_id, safe='')}/message"

        while monotonic() < deadline:
            try:
                message_list_response = self._get_json(message_list_url, action="poll remote session messages")
                messages = self._extract_message_list(message_list_response)
                for message in reversed(messages):
                    try:
                        return self._extract_structured_result(message)
                    except RemoteDispatchError as exc:
                        last_error = exc
            except RemoteDispatchError as exc:
                last_error = exc

            sleep(1.0)

        if last_error is not None and "did not include a valid structured analysis result" not in str(last_error):
            raise last_error

        raise RemoteDispatchError(
            f"Failed to dispatch remote message: remote session {session_id} did not produce a valid structured result within {self.timeout_seconds:.1f}s"
        )

    def _extract_message_list(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        value = payload.get("value")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    def _get_json(self, url: str, *, action: str) -> dict[str, Any]:
        http_request = request.Request(
            url,
            headers={
                "Accept": "application/json",
            },
            method="GET",
        )

        try:
            with self._opener.open(http_request, timeout=self.timeout_seconds) as response:
                payload = response.read().decode(response.headers.get_content_charset("utf-8"))
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RemoteDispatchError(f"Failed to {action}: remote server returned HTTP {exc.code}: {details}") from exc
        except TimeoutError as exc:
            raise RemoteDispatchError(
                f"Failed to {action}: remote server request timed out after {self.timeout_seconds:.1f}s"
            ) from exc
        except error.URLError as exc:
            raise RemoteDispatchError(f"Failed to {action}: unable to reach remote server: {exc.reason}") from exc

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RemoteDispatchError(f"Failed to {action}: remote server returned invalid JSON.") from exc

        if not isinstance(parsed, dict):
            raise RemoteDispatchError(f"Failed to {action}: remote server must return a JSON object result.")
        return parsed

    def _post_json(self, url: str, payload: dict[str, Any], *, action: str) -> dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        http_request = request.Request(
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with self._opener.open(http_request, timeout=self.timeout_seconds) as response:
                payload = response.read().decode(response.headers.get_content_charset("utf-8"))
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RemoteDispatchError(f"Failed to {action}: remote server returned HTTP {exc.code}: {details}") from exc
        except TimeoutError as exc:
            raise RemoteDispatchError(
                f"Failed to {action}: remote server request timed out after {self.timeout_seconds:.1f}s"
            ) from exc
        except error.URLError as exc:
            raise RemoteDispatchError(f"Failed to {action}: unable to reach remote server: {exc.reason}") from exc

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RemoteDispatchError(f"Failed to {action}: remote server returned invalid JSON.") from exc

        if not isinstance(parsed, dict):
            raise RemoteDispatchError(f"Failed to {action}: remote server must return a JSON object result.")
        return parsed

    def _extract_session_id(self, session_response: dict[str, Any]) -> str:
        session_id = session_response.get("id") or session_response.get("sessionID") or session_response.get("sessionId")
        if isinstance(session_id, str) and session_id.strip():
            return session_id.strip()

        session = session_response.get("session")
        if isinstance(session, dict):
            nested_session_id = session.get("id") or session.get("sessionID") or session.get("sessionId")
            if isinstance(nested_session_id, str) and nested_session_id.strip():
                return nested_session_id.strip()

        raise RemoteDispatchError("Failed to create remote session: response did not include a session id.")

    def _extract_structured_result(self, message_response: dict[str, Any]) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []

        for candidate in self._iter_candidate_objects(message_response):
            if not isinstance(candidate, dict):
                continue
            try:
                validated_result = validate_structured_result(candidate)
            except ValueError:
                continue
            candidates.append(validated_result.model_dump(mode="python"))

        if candidates:
            return candidates[0]

        raise RemoteDispatchError(
            "Remote message response did not include a valid structured analysis result matching the requested schema."
        )

    def _iter_candidate_objects(self, value: Any) -> Iterable[Any]:
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                yield value
                return
            yield from self._iter_candidate_objects(parsed)
            return

        yield value

        if isinstance(value, dict):
            for item in value.values():
                yield from self._iter_candidate_objects(item)
            return

        if isinstance(value, list):
            for item in value:
                yield from self._iter_candidate_objects(item)
            return
