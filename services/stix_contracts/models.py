"""Strict Pydantic v2 contracts for event, result, and STIX query payloads."""

# @ArchitectureID: ELM-FUNC-GENERATE-SCHEMA-DERIVED-PYTHON-CONTRACTS
# @ArchitectureID: ELM-APP-COMP-STIX-CONTRACT-CATALOG

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .catalog import load_contract_schema, resolve_canonical_schema_root


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
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class StrictContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="python")


class EventEntity(StrictContractModel):
    id: NonEmptyString
    type: NonEmptyString
    name: NonEmptyString


class EventObservable(StrictContractModel):
    type: NonEmptyString
    value: NonEmptyString


class NormalizedMockOpenCTIEvent(StrictContractModel):
    contract_version: NonEmptyString
    event_id: NonEmptyString
    event_type: NonEmptyString
    source: NonEmptyString
    triggered_at: NonEmptyString
    summary: NonEmptyString
    entity: EventEntity
    observables: Annotated[list[EventObservable], Field(min_length=1)]
    labels: list[NonEmptyString] = Field(default_factory=list)
    severity: NonEmptyString


class StixObjectSummary(StrictContractModel):
    id: NonEmptyString
    type: NonEmptyString
    name: str | None = None
    description: str | None = None
    pattern: str | None = None
    value: str | None = None
    confidence: int | float | None = None


class StixSearchResult(StrictContractModel):
    query: NonEmptyString
    match_count: Annotated[int, Field(ge=0)]
    matches: list[StixObjectSummary]

    @model_validator(mode="after")
    def validate_match_count(self) -> "StixSearchResult":
        if self.match_count != len(self.matches):
            raise ValueError("match_count must equal the number of matches.")
        return self


class StixNeighborRelationship(StrictContractModel):
    relationship_id: NonEmptyString
    relationship_type: NonEmptyString
    direction: Literal["incoming", "outgoing"]
    peer: StixObjectSummary


class StixNeighborsResult(StrictContractModel):
    stix_id: NonEmptyString
    object: StixObjectSummary
    relationship_count: Annotated[int, Field(ge=0)]
    relationships: list[StixNeighborRelationship]

    @model_validator(mode="after")
    def validate_relationship_count(self) -> "StixNeighborsResult":
        if self.relationship_count != len(self.relationships):
            raise ValueError("relationship_count must equal the number of relationships.")
        return self


class StixAdvancedFilterRelationship(StrictContractModel):
    relationship_id: NonEmptyString
    relationship_type: NonEmptyString
    source: StixObjectSummary
    target: StixObjectSummary


class StixAdvancedFilterResult(StrictContractModel):
    filters: dict[NonEmptyString, NonEmptyString | int | float | bool]
    match_count: Annotated[int, Field(ge=0)]
    matches: list[StixObjectSummary]
    relationship_count: Annotated[int, Field(ge=0)]
    relationships: list[StixAdvancedFilterRelationship]

    @model_validator(mode="after")
    def validate_counts(self) -> "StixAdvancedFilterResult":
        if not self.filters:
            raise ValueError("filters must contain at least one schema-derived field.")
        if self.match_count != len(self.matches):
            raise ValueError("match_count must equal the number of matches.")
        if self.relationship_count != len(self.relationships):
            raise ValueError("relationship_count must equal the number of relationships.")
        return self


class StixEntitySchemaSummary(StrictContractModel):
    entity_type: NonEmptyString
    stix_types: list[NonEmptyString]
    key_fields: list[NonEmptyString]
    relationship_types: list[NonEmptyString] = Field(default_factory=list)


class StixSchemaSummary(StrictContractModel):
    schema_version: NonEmptyString
    schema_first_guidance: NonEmptyString
    supported_query_fields: list[NonEmptyString]
    relationship_fields: list[NonEmptyString]
    relationship_types: list[NonEmptyString]
    entity_types: list[StixEntitySchemaSummary]


class EvidenceWritebackSummary(StrictContractModel):
    attempted: bool
    operation_mode: Literal["write", "read_write"]
    persistence_outcome: Literal["updated", "idempotent_noop"]
    total_updates: Annotated[int, Field(ge=0)]
    counters: dict[NonEmptyString, int] = Field(default_factory=dict)


class EvidenceQueryBasis(StrictContractModel):
    stix_bundle: NonEmptyString
    searches: list[StixSearchResult] = Field(default_factory=list)
    relationships: list[StixNeighborsResult] = Field(default_factory=list)
    writeback_summary: EvidenceWritebackSummary | None = None

    @model_validator(mode="after")
    def validate_writeback_summary(self) -> "EvidenceQueryBasis":
        if self.writeback_summary is None:
            return self

        if any(value < 0 for value in self.writeback_summary.counters.values()):
            raise ValueError("writeback_summary counters must be non-negative.")
        return self


class AnalysisConclusion(StrictContractModel):
    summary: NonEmptyString
    confidence: NonEmptyString
    verdict: NonEmptyString
    supporting_entities: list[NonEmptyString] = Field(default_factory=list)


class CollaborationRoleOutput(StrictContractModel):
    role: NonEmptyString
    summary: NonEmptyString
    legacy_role: str | None = None


class AssemblyContract(StrictContractModel):
    schema_name: Literal["TASK-009"] = Field(alias="schema")
    assembled_by: NonEmptyString
    assembly_location: Literal["remote-primary"]
    contract_source: NonEmptyString


class CollaborationTrace(StrictContractModel):
    participants: Annotated[list[NonEmptyString], Field(min_length=2)]
    legacy_participants: list[NonEmptyString] = Field(default_factory=list)
    role_outputs: list[CollaborationRoleOutput] = Field(default_factory=list)
    traceability: dict[str, Any]
    assembly_contract: AssemblyContract


class AnalysisResultEvent(StrictContractModel):
    event_id: NonEmptyString
    source: NonEmptyString
    event_type: NonEmptyString
    triggered_at: NonEmptyString
    summary: NonEmptyString
    entity: EventEntity
    observables: Annotated[list[EventObservable], Field(min_length=1)]
    labels: list[NonEmptyString] = Field(default_factory=list)
    severity: NonEmptyString | None = None


class ThreatAnalysisResult(StrictContractModel):
    schema_version: Literal[RESULT_SCHEMA_VERSION]
    run_id: NonEmptyString
    generated_at: NonEmptyString
    event: AnalysisResultEvent
    key_information_summary: Annotated[list[NonEmptyString], Field(min_length=1)]
    analysis_conclusion: AnalysisConclusion
    evidence_query_basis: EvidenceQueryBasis
    recommended_actions: list[NonEmptyString] = Field(default_factory=list)
    collaboration_trace: CollaborationTrace


def parse_event_contract(payload: Mapping[str, Any] | NormalizedMockOpenCTIEvent) -> NormalizedMockOpenCTIEvent:
    if isinstance(payload, NormalizedMockOpenCTIEvent):
        return payload
    return NormalizedMockOpenCTIEvent.model_validate(dict(payload))


def parse_analysis_result(payload: Mapping[str, Any] | ThreatAnalysisResult) -> ThreatAnalysisResult:
    if isinstance(payload, ThreatAnalysisResult):
        return payload
    return ThreatAnalysisResult.model_validate(dict(payload))


def build_analysis_result_json_schema() -> dict[str, Any]:
    schema = ThreatAnalysisResult.model_json_schema()
    existing_schema = load_contract_schema("analysis_result")
    schema["$schema"] = existing_schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
    schema["$id"] = existing_schema.get("$id", "https://local.repo/threat-intelligence-agent/analysis-result.schema.json")
    schema["title"] = existing_schema.get("title", "Threat Intelligence Agent Structured Analysis Result")
    schema.setdefault("description", f"Canonical STIX schema root: {resolve_canonical_schema_root()}")
    return schema
