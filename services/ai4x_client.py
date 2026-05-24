"""Real AI4X Platform API Center client helpers."""

from __future__ import annotations

import json
import os
import ssl
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import urlparse, urlunparse


DEFAULT_AI4X_BASE_URL = "http://localhost:8000"
DEFAULT_AI4X_TIMEOUT_SECONDS = 15.0
API_CENTER_PREFIX = "/api/v1/api-center"
LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
SUPPORTED_OPENCTI_DETAIL_KINDS = {"object", "relationship-type", "relationship-schema"}
REPO_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class AI4XPlatformError(RuntimeError):
    """Raised when AI4X Platform API Center access fails."""


@lru_cache(maxsize=1)
def _load_repo_env_values() -> dict[str, str]:
    if not REPO_ENV_FILE.is_file():
        return {}

    values: dict[str, str] = {}
    for raw_line in REPO_ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        normalized_key = key.strip()
        normalized_value = value.strip()
        if not normalized_key:
            continue
        if len(normalized_value) >= 2 and normalized_value[0] == normalized_value[-1] and normalized_value[0] in {"'", '"'}:
            normalized_value = normalized_value[1:-1]
        values[normalized_key] = normalized_value

    return values


def _resolve_setting(*names: str) -> str:
    for name in names:
        value = str(os.environ.get(name) or "").strip()
        if value:
            return value

    repo_env_values = _load_repo_env_values()
    for name in names:
        value = str(repo_env_values.get(name) or "").strip()
        if value:
            return value

    return ""


def _resolve_bool_setting(*names: str) -> bool:
    resolved = _resolve_setting(*names).lower()
    return resolved in {"1", "true", "yes", "on"}


def _resolve_repo_relative_path(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return candidate
    return (REPO_ENV_FILE.parent / candidate).resolve()


def _prefer_container_reachable_base_url(resolved: str, configured_fallback: str | None) -> str:
    fallback = str(configured_fallback or "").strip().rstrip("/")
    if not fallback or fallback == resolved:
        return resolved

    resolved_host = urlparse(resolved).hostname
    fallback_host = urlparse(fallback).hostname
    if resolved_host not in LOOPBACK_HOSTNAMES:
        return resolved
    if fallback_host in LOOPBACK_HOSTNAMES or not fallback_host:
        return resolved
    return fallback


def _normalize_python_loopback_base_url(resolved: str) -> str:
    parsed = urlparse(resolved)
    hostname = parsed.hostname
    if hostname not in {"localhost", "0.0.0.0", "::1"}:
        return resolved

    port = f":{parsed.port}" if parsed.port is not None else ""
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth = f"{auth}:{parsed.password}"
        auth = f"{auth}@"

    normalized_netloc = f"{auth}127.0.0.1{port}"
    return urlunparse(parsed._replace(netloc=normalized_netloc))


def resolve_ai4x_base_url(base_url: str | None = None) -> str:
    configured_fallback = _resolve_setting("THREAT_INTEL_AI4X_BASE_URL", "AI4X_PLATFORM_BASE_URL")
    resolved = str(
        base_url
        or configured_fallback
        or DEFAULT_AI4X_BASE_URL
    ).strip()
    if not resolved:
        raise AI4XPlatformError("AI4X base URL must be a non-empty string.")
    preferred = _prefer_container_reachable_base_url(resolved.rstrip("/"), configured_fallback)
    return _normalize_python_loopback_base_url(preferred)


def _resolve_timeout_seconds(timeout_seconds: float | None = None) -> float:
    configured = _resolve_setting("THREAT_INTEL_AI4X_TIMEOUT_SECONDS")
    if timeout_seconds is not None:
        return float(timeout_seconds)
    if not configured:
        return DEFAULT_AI4X_TIMEOUT_SECONDS

    try:
        resolved = float(configured)
    except ValueError as exc:
        raise AI4XPlatformError("THREAT_INTEL_AI4X_TIMEOUT_SECONDS must be numeric when set.") from exc

    if resolved <= 0:
        raise AI4XPlatformError("THREAT_INTEL_AI4X_TIMEOUT_SECONDS must be positive when set.")
    return resolved


def _build_auth_headers() -> dict[str, str]:
    mode = _resolve_setting("THREAT_INTEL_AI4X_AUTH_MODE", "AI4X_PLATFORM_AUTH_MODE") or "none"
    mode = mode.lower()
    if mode == "none":
        return {}
    if mode == "apikey":
        api_key = _resolve_setting("THREAT_INTEL_AI4X_API_KEY", "AI4X_PLATFORM_API_KEY")
        if not api_key:
            raise AI4XPlatformError("AI4X auth mode is apikey but no API key is configured.")
        return {"X-API-Key": api_key}
    if mode == "jwt":
        token = _resolve_setting("THREAT_INTEL_AI4X_JWT", "AI4X_PLATFORM_JWT")
        if not token:
            raise AI4XPlatformError("AI4X auth mode is jwt but no JWT token is configured.")
        return {"Authorization": f"Bearer {token}"}

    raise AI4XPlatformError(f"Unsupported AI4X auth mode: {mode}")


def _build_ssl_context(base_url: str) -> ssl.SSLContext | None:
    if urlparse(base_url).scheme.lower() != "https":
        return None

    if _resolve_bool_setting("THREAT_INTEL_AI4X_SKIP_SSL_VERIFY", "AI4X_PLATFORM_SKIP_SSL_VERIFY"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    ca_cert_file = _resolve_setting("THREAT_INTEL_AI4X_CA_CERT_FILE", "AI4X_PLATFORM_CA_CERT_FILE")
    if ca_cert_file:
        normalized_ca_cert_file = _resolve_repo_relative_path(ca_cert_file)
        if not normalized_ca_cert_file.is_file():
            raise AI4XPlatformError(f"AI4X CA certificate file does not exist: {normalized_ca_cert_file}")
        return ssl.create_default_context(cafile=str(normalized_ca_cert_file))

    return ssl.create_default_context()


def _request_json(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    resolved_base_url = resolve_ai4x_base_url(base_url)
    resolved_timeout_seconds = _resolve_timeout_seconds(timeout_seconds)
    url = f"{resolved_base_url}{path}"
    ssl_context = _build_ssl_context(resolved_base_url)
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Accept": "application/json",
        **_build_auth_headers(),
    }
    if body is not None:
        headers["Content-Type"] = "application/json"

    handlers: list[request.BaseHandler] = [request.ProxyHandler({})]
    if ssl_context is not None:
        handlers.append(request.HTTPSHandler(context=ssl_context))
    opener = request.build_opener(*handlers)
    http_request = request.Request(url, data=body, headers=headers, method=method.upper())

    try:
        with opener.open(http_request, timeout=resolved_timeout_seconds) as response:
            raw_payload = response.read().decode(response.headers.get_content_charset("utf-8"), errors="replace")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise AI4XPlatformError(f"AI4X request failed with HTTP {exc.code}: {details}") from exc
    except TimeoutError as exc:
        raise AI4XPlatformError(
            f"AI4X request to {url} timed out after {resolved_timeout_seconds:.1f}s"
        ) from exc
    except error.URLError as exc:
        raise AI4XPlatformError(f"Unable to reach AI4X service at {url}: {exc.reason}") from exc

    try:
        parsed = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise AI4XPlatformError(f"AI4X service returned invalid JSON for {url}.") from exc

    if not isinstance(parsed, dict):
        raise AI4XPlatformError(f"AI4X service must return a JSON object for {url}.")
    return parsed


def fetch_schema_catalog(*, base_url: str | None = None, timeout_seconds: float | None = None) -> dict[str, Any]:
    return _request_json(
        "GET",
        f"{API_CENTER_PREFIX}/schema/catalog",
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )


def fetch_source_schema(
    source_id: str,
    *,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    normalized_source_id = str(source_id).strip()
    if not normalized_source_id:
        raise AI4XPlatformError("source_id must be a non-empty string.")
    return _request_json(
        "GET",
        f"{API_CENTER_PREFIX}/schema/{normalized_source_id}",
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )


def fetch_source_schema_detail(
    source_id: str,
    detail_kind: str,
    type_name: str,
    *,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    normalized_source_id = str(source_id).strip()
    normalized_detail_kind = str(detail_kind).strip().strip("/")
    normalized_type_name = str(type_name).strip().strip("/")
    if not normalized_source_id:
        raise AI4XPlatformError("source_id must be a non-empty string.")
    if not normalized_detail_kind:
        raise AI4XPlatformError("detail_kind must be a non-empty string.")
    if normalized_source_id == "opencti" and normalized_detail_kind not in SUPPORTED_OPENCTI_DETAIL_KINDS:
        raise AI4XPlatformError(
            "OpenCTI detail_kind must be one of: object, relationship-type, relationship-schema."
        )
    if not normalized_type_name:
        raise AI4XPlatformError("type_name must be a non-empty string.")
    detail_payload = _request_json(
        "GET",
        f"{API_CENTER_PREFIX}/schema/{normalized_source_id}/detail/{normalized_detail_kind}/{normalized_type_name}",
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )
    schema = detail_payload.get("schema")
    if not isinstance(schema, dict):
        raise AI4XPlatformError("AI4X schema detail response must contain a JSON object under 'schema'.")
    return schema


def execute_universal_query(
    source_id: str,
    cypher: str,
    *,
    params: dict[str, Any] | None = None,
    limit: int | None = None,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    normalized_source_id = str(source_id).strip()
    normalized_cypher = str(cypher).strip()
    if not normalized_source_id:
        raise AI4XPlatformError("source_id must be a non-empty string.")
    if not normalized_cypher:
        raise AI4XPlatformError("cypher must be a non-empty string.")

    payload: dict[str, Any] = {
        "source_id": normalized_source_id,
        "cypher": normalized_cypher,
    }
    if params:
        payload["params"] = params
    if limit is not None:
        payload["limit"] = int(limit)

    return _request_json(
        "POST",
        f"{API_CENTER_PREFIX}/query/universal",
        payload=payload,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )


def probe_ai4x_environment(*, base_url: str | None = None, timeout_seconds: float | None = 5.0) -> dict[str, Any]:
    resolved_base_url = resolve_ai4x_base_url(base_url)
    try:
        catalog = fetch_schema_catalog(base_url=resolved_base_url, timeout_seconds=timeout_seconds)
    except AI4XPlatformError as exc:
        return {
            "ready": False,
            "base_url": resolved_base_url,
            "error": str(exc),
        }

    return {
        "ready": True,
        "base_url": resolved_base_url,
        "catalog": catalog,
    }