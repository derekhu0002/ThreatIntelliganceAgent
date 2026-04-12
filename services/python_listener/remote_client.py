"""Remote OPENCODE SERVER client for listener dispatch."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import quote

from services.result_assembler import validate_structured_result
from services.result_assembler.schema import build_result_json_schema


class RemoteDispatchError(RuntimeError):
    """Raised when the remote OPENCODE SERVER call fails."""


DEFAULT_OPENCODE_BASE_URL = "http://127.0.0.1:8124"


def load_workspace_config(repo_root: Path) -> dict[str, Any]:
    config_path = repo_root / "agent_app/opencode_app/.opencode/opencode.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError(f"Workspace config at {config_path} must be a JSON object")
    return config


def resolve_main_agent_alias(agent_name: str, repo_root: Path) -> str:
    config = load_workspace_config(repo_root)
    alias_map = config.get("agent_aliases", {})
    if not isinstance(alias_map, dict):
        return agent_name.strip()
    canonical = alias_map.get(agent_name.strip())
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
    def __init__(self, endpoint_url: str, timeout_seconds: float = 30.0) -> None:
        self.endpoint_url = endpoint_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._opener = request.build_opener(request.ProxyHandler({}))

    def dispatch_analysis(self, request_payload: dict[str, Any]) -> dict[str, Any]:
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
        return self._extract_structured_result(message_response)

    def _build_message_payload(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "agent": request_payload["main_agent"],
            "format": {
                "type": "json_schema",
                "schema": build_result_json_schema(),
            },
            "parts": [
                {
                    "type": "text",
                    "text": request_payload["prompt_text"],
                }
            ],
        }

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
                validate_structured_result(candidate)
            except ValueError:
                continue
            candidates.append(candidate)

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
