"""Remote OPENCODE SERVER client for listener dispatch."""

# @ArchitectureID: ELM-APP-COMP-PY-LISTENER

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib import error, request


class RemoteDispatchError(RuntimeError):
    """Raised when the remote OPENCODE SERVER call fails."""


def load_default_main_agent(repo_root: Path) -> str:
    config_path = repo_root / "agent_app/opencode_app/.opencode/opencode.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    default_agent = config.get("default_agent")
    if not isinstance(default_agent, str) or not default_agent.strip():
        raise ValueError(f"Missing default_agent in {config_path}")
    return default_agent.strip()


class RemoteOpencodeClient:
    def __init__(self, endpoint_url: str, timeout_seconds: float = 30.0) -> None:
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self._opener = request.build_opener(request.ProxyHandler({}))

    def dispatch_analysis(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(request_payload, ensure_ascii=False).encode("utf-8")
        http_request = request.Request(
            self.endpoint_url,
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
            raise RemoteDispatchError(f"Remote server returned HTTP {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RemoteDispatchError(f"Unable to reach remote server: {exc.reason}") from exc

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RemoteDispatchError("Remote server returned invalid JSON.") from exc

        if not isinstance(parsed, dict):
            raise RemoteDispatchError("Remote server must return a JSON object result.")
        return parsed
