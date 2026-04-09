"""Mock OPENCTI event adapter."""

# @ArchitectureID: ELM-APP-COMP-MOCK-OPENCTI-ADAPTER

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class EventContractError(ValueError):
    """Raised when the mock OPENCTI event contract is invalid."""


@dataclass(frozen=True)
class EventEntity:
    id: str
    type: str
    name: str


@dataclass(frozen=True)
class EventObservable:
    type: str
    value: str


@dataclass(frozen=True)
class NormalizedMockOpenCTIEvent:
    contract_version: str
    event_id: str
    event_type: str
    source: str
    triggered_at: str
    summary: str
    entity: EventEntity
    observables: list[EventObservable]
    labels: list[str]
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _require_non_empty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EventContractError(f"Field '{field_name}' must be a non-empty string.")
    return value.strip()


def normalize_event(raw_event: dict[str, Any]) -> NormalizedMockOpenCTIEvent:
    if not isinstance(raw_event, dict):
        raise EventContractError("The mock OPENCTI payload must be a JSON object.")

    entity_raw = raw_event.get("entity")
    if not isinstance(entity_raw, dict):
        raise EventContractError("Field 'entity' must be an object.")

    observables_raw = raw_event.get("observables", [])
    if not isinstance(observables_raw, list) or not observables_raw:
        raise EventContractError("Field 'observables' must be a non-empty array.")

    observables: list[EventObservable] = []
    for index, observable in enumerate(observables_raw):
        if not isinstance(observable, dict):
            raise EventContractError(f"Observable at index {index} must be an object.")
        observables.append(
            EventObservable(
                type=_require_non_empty(observable.get("type"), f"observables[{index}].type"),
                value=_require_non_empty(observable.get("value"), f"observables[{index}].value"),
            )
        )

    labels_raw = raw_event.get("labels", [])
    if not isinstance(labels_raw, list):
        raise EventContractError("Field 'labels' must be an array.")

    labels = [label.strip() for label in labels_raw if isinstance(label, str) and label.strip()]

    return NormalizedMockOpenCTIEvent(
        contract_version=_require_non_empty(raw_event.get("contract_version"), "contract_version"),
        event_id=_require_non_empty(raw_event.get("event_id"), "event_id"),
        event_type=_require_non_empty(raw_event.get("event_type"), "event_type"),
        source=_require_non_empty(raw_event.get("source"), "source"),
        triggered_at=_require_non_empty(raw_event.get("triggered_at"), "triggered_at"),
        summary=_require_non_empty(raw_event.get("summary"), "summary"),
        entity=EventEntity(
            id=_require_non_empty(entity_raw.get("id"), "entity.id"),
            type=_require_non_empty(entity_raw.get("type"), "entity.type"),
            name=_require_non_empty(entity_raw.get("name"), "entity.name"),
        ),
        observables=observables,
        labels=labels,
        severity=_require_non_empty(raw_event.get("severity"), "severity"),
    )


def load_and_normalize_event(event_path: str | Path) -> NormalizedMockOpenCTIEvent:
    path = Path(event_path)
    raw_event = json.loads(path.read_text(encoding="utf-8"))
    return normalize_event(raw_event)
