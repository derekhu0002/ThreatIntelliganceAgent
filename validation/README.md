# Threat Intelligence Agent V1 Closed-Loop Acceptance Validation

## STIX CLI

```bash
cd agent_app/opencode_app
python3 -m tools.stix_cli --data data/stix_samples/threat_intel_bundle.json search --query APT28
```

## Closed-loop acceptance case

```bash
python3 scripts/run_minimal_closed_loop.py
```

By default this acceptance case targets the backend OPENCODE SERVER at `http://127.0.0.1:8124`.

To force the local protocol-compatible mock server instead, run:

```bash
THREAT_INTEL_USE_MOCK_REMOTE_SERVER=1 python3 scripts/run_minimal_closed_loop.py
```

The closed-loop acceptance case writes:

- a structured analysis result to `artifacts/runtime/opencti-push-001-analysis.json`
- an acceptance summary to `artifacts/runtime/opencti-push-001-acceptance-summary.json`
