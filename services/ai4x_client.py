"""Real AI4X Platform API Center client helpers."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request
from urllib.parse import urlparse


DEFAULT_AI4X_BASE_URL = "http://localhost:8000"
DEFAULT_AI4X_TIMEOUT_SECONDS = 15.0
API_CENTER_PREFIX = "/api/v1/api-center"
LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class AI4XPlatformError(RuntimeError):
    """Raised when AI4X Platform API Center access fails."""


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


def resolve_ai4x_base_url(base_url: str | None = None) -> str:
    configured_fallback = (
        os.environ.get("THREAT_INTEL_AI4X_BASE_URL")
        or os.environ.get("AI4X_PLATFORM_BASE_URL")
        or ""
    )
    resolved = str(
        base_url
        or configured_fallback
        or DEFAULT_AI4X_BASE_URL
    ).strip()
    if not resolved:
        raise AI4XPlatformError("AI4X base URL must be a non-empty string.")
    return _prefer_container_reachable_base_url(resolved.rstrip("/"), configured_fallback)


def _resolve_timeout_seconds(timeout_seconds: float | None = None) -> float:
    configured = os.environ.get("THREAT_INTEL_AI4X_TIMEOUT_SECONDS", "").strip()
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
    mode = str(
        os.environ.get("THREAT_INTEL_AI4X_AUTH_MODE")
        or os.environ.get("AI4X_PLATFORM_AUTH_MODE")
        or "none"
    ).strip().lower()
    if mode == "none":
        return {}
    if mode == "apikey":
        api_key = str(
            os.environ.get("THREAT_INTEL_AI4X_API_KEY") or os.environ.get("AI4X_PLATFORM_API_KEY") or ""
        ).strip()
        if not api_key:
            raise AI4XPlatformError("AI4X auth mode is apikey but no API key is configured.")
        return {"X-API-Key": api_key}
    if mode == "jwt":
        token = str(os.environ.get("THREAT_INTEL_AI4X_JWT") or os.environ.get("AI4X_PLATFORM_JWT") or "").strip()
        if not token:
            raise AI4XPlatformError("AI4X auth mode is jwt but no JWT token is configured.")
        return {"Authorization": f"Bearer {token}"}

    raise AI4XPlatformError(f"Unsupported AI4X auth mode: {mode}")


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
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Accept": "application/json",
        **_build_auth_headers(),
    }
    if body is not None:
        headers["Content-Type"] = "application/json"

    opener = request.build_opener(request.ProxyHandler({}))
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