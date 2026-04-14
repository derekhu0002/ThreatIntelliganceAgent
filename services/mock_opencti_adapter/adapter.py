"""Mock OPENCTI event adapter."""

# @ArchitectureID: ELM-APP-COMP-MOCK-OPENCTI-ADAPTER
# @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from services.stix_contracts import NormalizedMockOpenCTIEvent, parse_event_contract


class EventContractError(ValueError):
    """Raised when the mock OPENCTI event contract is invalid."""


def normalize_event(raw_event: dict[str, Any]) -> NormalizedMockOpenCTIEvent:
    if not isinstance(raw_event, dict):
        raise EventContractError("The mock OPENCTI payload must be a JSON object.")

    try:
        return parse_event_contract(raw_event)
    except ValidationError as exc:
        raise EventContractError(str(exc)) from exc


def load_and_normalize_event(event_path: str | Path) -> NormalizedMockOpenCTIEvent:
    path = Path(event_path)
    raw_event = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw_event, dict):
        raise EventContractError("The mock OPENCTI payload must be a JSON object.")
    return normalize_event(raw_event)
