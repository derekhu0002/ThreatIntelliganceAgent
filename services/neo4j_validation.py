"""Helpers for container-backed Neo4j validation during local closed-loop runs."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Iterator, Mapping


DEFAULT_NEO4J_URI = "neo4j://127.0.0.1:7698"
DEFAULT_NEO4J_USERNAME = "neo4j"
DEFAULT_NEO4J_PASSWORD = "11111111"
DEFAULT_NEO4J_DATABASE = "neo4j"
DEFAULT_VALIDATION_SCOPE = "minimal_closed_loop"
ENABLE_REAL_VALIDATION_ENV = "THREAT_INTEL_ENABLE_REAL_NEO4J_VALIDATION"


class Neo4jValidationError(RuntimeError):
    """Raised when real Neo4j validation setup or verification fails."""


def is_real_neo4j_validation_enabled() -> bool:
    return os.environ.get(ENABLE_REAL_VALIDATION_ENV, "").strip().lower() in {"1", "true", "yes", "y"}


def resolve_neo4j_validation_settings() -> dict[str, str]:
    return {
        "uri": os.environ.get("NEO4J_URI", DEFAULT_NEO4J_URI).strip() or DEFAULT_NEO4J_URI,
        "username": os.environ.get("NEO4J_USERNAME", DEFAULT_NEO4J_USERNAME).strip() or DEFAULT_NEO4J_USERNAME,
        "password": os.environ.get("NEO4J_PASSWORD", DEFAULT_NEO4J_PASSWORD).strip() or DEFAULT_NEO4J_PASSWORD,
        "database": os.environ.get("NEO4J_DATABASE", DEFAULT_NEO4J_DATABASE).strip() or DEFAULT_NEO4J_DATABASE,
    }


@contextmanager
def neo4j_validation_environment(settings: Mapping[str, str]) -> Iterator[None]:
    previous_values = {
        ENABLE_REAL_VALIDATION_ENV: os.environ.get(ENABLE_REAL_VALIDATION_ENV),
        "NEO4J_URI": os.environ.get("NEO4J_URI"),
        "NEO4J_USERNAME": os.environ.get("NEO4J_USERNAME"),
        "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD"),
        "NEO4J_DATABASE": os.environ.get("NEO4J_DATABASE"),
    }
    os.environ[ENABLE_REAL_VALIDATION_ENV] = "1"
    os.environ["NEO4J_URI"] = str(settings["uri"])
    os.environ["NEO4J_USERNAME"] = str(settings["username"])
    os.environ["NEO4J_PASSWORD"] = str(settings["password"])
    os.environ["NEO4J_DATABASE"] = str(settings["database"])

    try:
        yield
    finally:
        for key, previous_value in previous_values.items():
            if previous_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous_value


def ensure_neo4j_validation_container(repo_root: Path, timeout_seconds: float = 90.0) -> dict[str, str]:
    settings = resolve_neo4j_validation_settings()
    compose_root = repo_root / "agent_app"
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d", "neo4j"],
            cwd=compose_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - environment dependent
        raise Neo4jValidationError(f"Failed to start Neo4j container: {exc.stderr.strip() or exc.stdout.strip()}") from exc

    wait_for_neo4j(settings, timeout_seconds=timeout_seconds)
    return settings


def wait_for_neo4j(settings: Mapping[str, str], timeout_seconds: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            records, _ = execute_neo4j_cypher(
                "RETURN 1 AS ready",
                settings=settings,
            )
        except Exception as exc:  # pragma: no cover - environment dependent
            last_error = exc
            time.sleep(1.0)
            continue

        if records and int(records[0].get("ready", 0)) == 1:
            return

        time.sleep(1.0)

    raise Neo4jValidationError(f"Neo4j container did not become ready within {timeout_seconds:.0f}s: {last_error}")


def reset_validation_projection(
    event_id: str,
    *,
    validation_scope: str = DEFAULT_VALIDATION_SCOPE,
    settings: Mapping[str, str] | None = None,
) -> None:
    execute_neo4j_cypher(
        """
        MATCH (n:ThreatIntelValidation)
        WHERE n.validation_scope = $validation_scope AND n.event_id = $event_id
        DETACH DELETE n
        RETURN 1 AS deleted
        """,
        parameters={"event_id": event_id, "validation_scope": validation_scope},
        settings=settings,
    )


def persist_validation_projection(
    structured_result: Mapping[str, Any],
    *,
    validation_scope: str = DEFAULT_VALIDATION_SCOPE,
    settings: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    event = dict(structured_result.get("event", {}))
    conclusion = dict(structured_result.get("analysis_conclusion", {}))
    collaboration_trace = dict(structured_result.get("collaboration_trace", {}))
    entity = dict(event.get("entity", {}))
    participants = [str(item) for item in collaboration_trace.get("participants", []) if str(item).strip()]
    recommended_actions = [str(item) for item in structured_result.get("recommended_actions", []) if str(item).strip()]

    _, summary = execute_neo4j_cypher(
        """
        MERGE (run:ThreatIntelValidation:ThreatIntelRun {run_id: $run_id})
        SET run.event_id = $event_id,
            run.generated_at = $generated_at,
            run.source = $source,
            run.validation_scope = $validation_scope
        MERGE (event:ThreatIntelValidation:ThreatIntelEvent {event_id: $event_id, validation_scope: $validation_scope})
        SET event.source = $source,
            event.event_type = $event_type,
            event.summary = $event_summary,
            event.severity = $severity
        MERGE (entity:ThreatIntelValidation:ThreatIntelEntity {stix_id: $entity_id, validation_scope: $validation_scope})
        SET entity.event_id = $event_id,
            entity.type = $entity_type,
            entity.name = $entity_name
        MERGE (run)-[:ANALYZED_EVENT]->(event)
        MERGE (event)-[:FOCUSES_ON]->(entity)
        MERGE (conclusion:ThreatIntelValidation:ThreatIntelConclusion {run_id: $run_id, validation_scope: $validation_scope})
        SET conclusion.event_id = $event_id,
            conclusion.summary = $conclusion_summary,
            conclusion.verdict = $verdict,
            conclusion.confidence = $confidence
        MERGE (run)-[:PRODUCED_CONCLUSION]->(conclusion)
        FOREACH (participant_name IN $participants |
            MERGE (participant:ThreatIntelValidation:ThreatIntelParticipant {
                run_id: $run_id,
                event_id: $event_id,
                name: participant_name,
                validation_scope: $validation_scope
            })
            MERGE (run)-[:INCLUDED_PARTICIPANT]->(participant)
        )
        FOREACH (action_text IN $recommended_actions |
            MERGE (action:ThreatIntelValidation:ThreatIntelRecommendedAction {
                run_id: $run_id,
                event_id: $event_id,
                text: action_text,
                validation_scope: $validation_scope
            })
            MERGE (conclusion)-[:RECOMMENDS]->(action)
        )
        RETURN $run_id AS run_id
        """,
        parameters={
            "run_id": structured_result["run_id"],
            "event_id": event["event_id"],
            "generated_at": structured_result["generated_at"],
            "source": event.get("source"),
            "event_type": event.get("event_type"),
            "event_summary": event.get("summary"),
            "severity": event.get("severity"),
            "entity_id": entity.get("id"),
            "entity_type": entity.get("type"),
            "entity_name": entity.get("name"),
            "conclusion_summary": conclusion.get("summary"),
            "verdict": conclusion.get("verdict"),
            "confidence": conclusion.get("confidence"),
            "participants": participants,
            "recommended_actions": recommended_actions,
            "validation_scope": validation_scope,
        },
        settings=settings,
    )
    return _build_writeback_summary(summary)


def load_validation_projection(
    run_id: str,
    event_id: str,
    *,
    validation_scope: str = DEFAULT_VALIDATION_SCOPE,
    settings: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    records, _ = execute_neo4j_cypher(
        """
        MATCH (run:ThreatIntelValidation:ThreatIntelRun {
            run_id: $run_id,
            event_id: $event_id,
            validation_scope: $validation_scope
        })-[:ANALYZED_EVENT]->(event:ThreatIntelValidation:ThreatIntelEvent {
            event_id: $event_id,
            validation_scope: $validation_scope
        })
        MATCH (run)-[:PRODUCED_CONCLUSION]->(conclusion:ThreatIntelValidation:ThreatIntelConclusion {
            run_id: $run_id,
            validation_scope: $validation_scope
        })
        OPTIONAL MATCH (run)-[:INCLUDED_PARTICIPANT]->(participant:ThreatIntelValidation:ThreatIntelParticipant {
            run_id: $run_id,
            validation_scope: $validation_scope
        })
        OPTIONAL MATCH (conclusion)-[:RECOMMENDS]->(action:ThreatIntelValidation:ThreatIntelRecommendedAction {
            run_id: $run_id,
            validation_scope: $validation_scope
        })
        RETURN run.run_id AS run_id,
               event.event_id AS event_id,
               conclusion.summary AS conclusion_summary,
               count(DISTINCT participant) AS participant_count,
               count(DISTINCT action) AS recommended_action_count,
               collect(DISTINCT participant.name) AS participants,
               collect(DISTINCT action.text) AS recommended_actions
        """,
        parameters={
            "run_id": run_id,
            "event_id": event_id,
            "validation_scope": validation_scope,
        },
        settings=settings,
    )
    if not records:
        raise Neo4jValidationError(
            f"Neo4j validation query returned no persisted data for event_id={event_id!r}, run_id={run_id!r}."
        )
    return records[0]


def execute_neo4j_cypher(
    cypher: str,
    *,
    parameters: Mapping[str, Any] | None = None,
    settings: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    resolved_settings = dict(settings or resolve_neo4j_validation_settings())

    try:
        from neo4j import GraphDatabase
    except ImportError as exc:  # pragma: no cover - runtime dependency
        raise Neo4jValidationError("The neo4j Python package is required for real container validation.") from exc

    driver = GraphDatabase.driver(
        resolved_settings["uri"],
        auth=(resolved_settings["username"], resolved_settings["password"]),
    )

    try:
        with driver.session(database=resolved_settings["database"]) as session:
            result = session.run(cypher, parameters or {})
            records = [dict(record.items()) for record in result]
            summary = _clean_summary(result.consume())
    finally:
        driver.close()

    return records, summary


def _clean_summary(summary: Any) -> dict[str, Any]:
    counters = {
        str(key): int(value)
        for key, value in summary.counters.__dict__.items()
        if isinstance(value, int) and value > 0
    }
    database = getattr(summary, "database", None)
    if database is not None and hasattr(database, "name"):
        database = database.name

    return {
        "database": str(database) if database is not None else None,
        "query_type": getattr(summary, "query_type", None),
        "counters": counters,
    }


def _build_writeback_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    counters = {str(key): int(value) for key, value in dict(summary.get("counters", {})).items()}
    total_updates = sum(counters.values())
    query_type = str(summary.get("query_type") or "rw").lower() or "rw"
    return {
        "attempted": True,
        "operation_mode": "read_write" if query_type == "rw" else "write",
        "persistence_outcome": "updated" if total_updates > 0 else "idempotent_noop",
        "total_updates": total_updates,
        "counters": counters,
    }