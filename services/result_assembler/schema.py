"""Structured threat analysis result schema metadata."""

# @ArchitectureID: ELM-APP-COMP-RESULT-ASSEMBLER

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
