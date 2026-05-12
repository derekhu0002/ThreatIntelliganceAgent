# Local Implementation Architecture Contract

Reference root contract: `OVERALL_ARCHITECTURE.md`

## Scope

- This contract covers structured result assembly and result schema authority under `services/result_assembler`.

## Stable Elements

- `assembler.py`
- `schema.py`
- `analysis_result.schema.json`

## Public Interfaces

- `assemble_structured_result(...)`
- `validate_structured_result(...)`
- `build_result_json_schema(...)`

## Dependency Direction

- This directory may depend on shared typed contracts.
- Orchestration code may depend on this directory.
- This directory must not depend on control-plane agent or skill definitions.

## Implements Mapping

- This directory is an indirect implementation substrate for intention `1738 / Agents` through the orchestration chain rooted at `services/python_listener`.

## Explicit Acceptance Baselines Mounted Here

- no direct explicit acceptance entry is mounted here

## Frozen Critical Non-Explicit Guards

- none beyond the root frozen baseline-traceability guards

## Protected Fixtures And Baselines

- `analysis_result.schema.json`

## Ordinary Supporting Tests

- `tests/test_result_assembler.py`