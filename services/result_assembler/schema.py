"""Structured threat analysis result schema metadata."""

# @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER

from __future__ import annotations

from copy import deepcopy
from typing import Any


RESULT_SCHEMA_VERSION = "threat-intelligence-agent.v1"

REQUIRED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "run_id",
    "generated_at",
    "event",
    "key_information_summary",
    "analysis_conclusion",
    "evidence_query_basis",
    "recommended_actions",
    "collaboration_trace",
}

RESULT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Threat Intelligence Agent Structured Result",
    "type": "object",
    "required": sorted(REQUIRED_TOP_LEVEL_FIELDS),
    "properties": {
        "schema_version": {"type": "string", "const": RESULT_SCHEMA_VERSION},
        "run_id": {"type": "string", "minLength": 1},
        "generated_at": {"type": "string", "minLength": 1},
        "event": {
            "type": "object",
            "required": ["event_id", "source", "event_type", "triggered_at", "summary", "entity", "observables"],
            "properties": {
                "event_id": {"type": "string", "minLength": 1},
                "source": {"type": "string", "minLength": 1},
                "event_type": {"type": "string", "minLength": 1},
                "triggered_at": {"type": "string", "minLength": 1},
                "summary": {"type": "string"},
                "entity": {"type": "object"},
                "observables": {"type": "array", "items": {"type": "object"}},
                "labels": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        "key_information_summary": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "analysis_conclusion": {
            "type": "object",
            "required": ["summary", "confidence", "verdict", "supporting_entities"],
            "properties": {
                "summary": {"type": "string"},
                "confidence": {"type": "string"},
                "verdict": {"type": "string"},
                "supporting_entities": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
        "evidence_query_basis": {"type": "object"},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "collaboration_trace": {
            "type": "object",
            "required": ["participants", "role_outputs", "traceability"],
            "properties": {
                "participants": {"type": "array", "items": {"type": "string"}, "minItems": 2},
                "role_outputs": {"type": "array", "items": {"type": "object"}},
                "traceability": {"type": "object"},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


def build_result_json_schema() -> dict[str, Any]:
    return deepcopy(RESULT_JSON_SCHEMA)
