# Threat Intelligence Agent V1 Minimal Validation

## STIX CLI

```bash
python3 -m tools.stix_cli --data data/stix_samples/threat_intel_bundle.json search --query APT28
```

## End-to-end closed loop

```bash
python3 scripts/run_minimal_closed_loop.py
```

The closed-loop validation writes a structured result artifact to `artifacts/runtime/validation-result.json`.
