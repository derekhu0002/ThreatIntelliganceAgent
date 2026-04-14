"""Canonical schema catalog helpers for strict contract boundaries."""

# @ArchitectureID: ELM-APP-COMP-STIX-CONTRACT-CATALOG

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal


REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_SCHEMA_ROOT = REPO_ROOT / "agent_app/opencode_app/.opencode/schema"
MOCK_OPENCTI_EVENT_SCHEMA_PATH = REPO_ROOT / "data/mock_events/mock_opencti_event.schema.json"
ANALYSIS_RESULT_SCHEMA_PATH = REPO_ROOT / "services/result_assembler/analysis_result.schema.json"

ContractSchemaName = Literal["mock_opencti_event", "analysis_result"]


class ContractCatalogError(RuntimeError):
    """Raised when the contract catalog cannot resolve expected schema files."""


def resolve_canonical_schema_root() -> Path:
    if not CANONICAL_SCHEMA_ROOT.is_dir():
        raise ContractCatalogError(f"Canonical schema root does not exist: {CANONICAL_SCHEMA_ROOT}")
    return CANONICAL_SCHEMA_ROOT


def _resolve_contract_schema_path(name: ContractSchemaName) -> Path:
    if name == "mock_opencti_event":
        return MOCK_OPENCTI_EVENT_SCHEMA_PATH
    return ANALYSIS_RESULT_SCHEMA_PATH


@lru_cache(maxsize=8)
def load_contract_schema(name: ContractSchemaName) -> dict[str, Any]:
    schema_path = _resolve_contract_schema_path(name)
    if not schema_path.is_file():
        raise ContractCatalogError(f"Contract schema file does not exist: {schema_path}")
    payload = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ContractCatalogError(f"Contract schema file must contain a JSON object: {schema_path}")
    return payload


@lru_cache(maxsize=256)
def load_stix_schema(relative_path: str) -> dict[str, Any]:
    schema_path = resolve_canonical_schema_root() / relative_path
    if not schema_path.is_file():
        raise ContractCatalogError(f"Canonical STIX schema file does not exist: {schema_path}")
    payload = json.loads(schema_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ContractCatalogError(f"Canonical STIX schema file must contain a JSON object: {schema_path}")
    return payload
