import json
from pathlib import Path

import pytest

from services.mock_opencti_adapter import EventContractError, load_and_normalize_event, normalize_event


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_mock_event_sample_matches_declared_schema_requirements() -> None:
    schema = json.loads((REPO_ROOT / "data/mock_events/mock_opencti_event.schema.json").read_text(encoding="utf-8"))
    sample = json.loads((REPO_ROOT / "data/mock_events/mock_opencti_push_event.json").read_text(encoding="utf-8"))

    for required_field in schema["required"]:
        assert required_field in sample

    assert set(schema["properties"]["entity"]["required"]).issubset(sample["entity"])
    assert len(sample["observables"]) >= schema["properties"]["observables"]["minItems"]


def test_normalize_event_trims_and_filters_contract_fields() -> None:
    normalized = normalize_event(
        {
            "contract_version": " mock-opencti-event.v1 ",
            "event_id": " event-123 ",
            "event_type": " opencti.push.indicator ",
            "source": " mock-opencti ",
            "triggered_at": " 2026-04-09T12:00:00Z ",
            "summary": " suspicious activity observed ",
            "severity": " high ",
            "labels": [" apt28 ", " phishing "],
            "entity": {
                "id": " indicator--123 ",
                "type": " indicator ",
                "name": " Suspicious IP ",
            },
            "observables": [{"type": " ipv4-addr ", "value": " 203.0.113.10 "}],
        }
    )

    assert normalized.contract_version == "mock-opencti-event.v1"
    assert normalized.event_id == "event-123"
    assert normalized.entity.name == "Suspicious IP"
    assert normalized.observables[0].type == "ipv4-addr"
    assert normalized.observables[0].value == "203.0.113.10"
    assert normalized.labels == ["apt28", "phishing"]
    assert normalized.to_dict()["severity"] == "high"


def test_normalize_event_rejects_invalid_label_values() -> None:
    with pytest.raises(EventContractError, match="labels"):
        normalize_event(
            {
                "contract_version": "mock-opencti-event.v1",
                "event_id": "event-123",
                "event_type": "opencti.push.indicator",
                "source": "mock-opencti",
                "triggered_at": "2026-04-09T12:00:00Z",
                "summary": "suspicious activity observed",
                "severity": "high",
                "labels": ["apt28", ""],
                "entity": {
                    "id": "indicator--123",
                    "type": "indicator",
                    "name": "Suspicious IP",
                },
                "observables": [{"type": "ipv4-addr", "value": "203.0.113.10"}],
            }
        )


def test_load_and_normalize_event_rejects_missing_observables(tmp_path: Path) -> None:
    event_path = tmp_path / "invalid-event.json"
    event_path.write_text(
        json.dumps(
            {
                "contract_version": "mock-opencti-event.v1",
                "event_id": "event-123",
                "event_type": "opencti.push.indicator",
                "source": "mock-opencti",
                "triggered_at": "2026-04-09T12:00:00Z",
                "summary": "missing observables",
                "severity": "high",
                "entity": {"id": "indicator--123", "type": "indicator", "name": "Suspicious IP"},
                "observables": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(EventContractError, match="observables"):
        load_and_normalize_event(event_path)


@pytest.mark.parametrize(
    "event_name",
    [
        "mock_ttp_hunting_event.json",
        "mock_cve_weaponization_event.json",
        "mock_apt_profiling_event.json",
    ],
)
def test_new_mock_scenario_events_match_declared_contract(event_name: str) -> None:
    event = load_and_normalize_event(REPO_ROOT / "data/mock_events" / event_name)

    assert event.contract_version == "mock-opencti-event.v1"
    assert event.event_id
    assert event.entity.name
    assert len(event.observables) >= 1
