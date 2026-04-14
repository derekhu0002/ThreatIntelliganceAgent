"""Structured threat analysis result schema metadata."""

# @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER
# @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS

from __future__ import annotations

from typing import Any

from services.stix_contracts import (
    REQUIRED_TOP_LEVEL_FIELDS,
    RESULT_SCHEMA_VERSION,
    build_analysis_result_json_schema,
)


RESULT_JSON_SCHEMA: dict[str, Any] = build_analysis_result_json_schema()


def build_result_json_schema() -> dict[str, Any]:
    return build_analysis_result_json_schema()
