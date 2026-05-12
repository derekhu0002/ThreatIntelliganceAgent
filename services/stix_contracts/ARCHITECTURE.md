# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers STIX typed contracts and schema catalog authority under `services/stix_contracts`.

## Stable Elements

- `models.py`
- `catalog.py`

## Public Interfaces

- exported typed models from `models.py`
- schema catalog loading from `catalog.py`

## Dependency Direction

- ingestion, orchestration, runtime bridge, and result assembly may depend on this directory.
- this directory must remain independent of control-plane prompts, skills, and agent markdown.

## Implements Mapping

- This directory is an indirect implementation substrate for multiple intention-level analysis flows through `services/python_listener` and `services/result_assembler`.

## Explicit Acceptance Baselines Mounted Here

- no direct explicit acceptance entry is mounted here

## Frozen Critical Non-Explicit Guards

- none beyond the root frozen baseline-traceability guards

## Protected Fixtures And Baselines

- schema catalog assets loaded by `catalog.py`

## Ordinary Supporting Tests

- `tests/test_stix_contracts.py`