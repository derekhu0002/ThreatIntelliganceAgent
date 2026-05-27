#!/bin/sh
set -eu

/usr/local/bin/opencode "$@" &
opencode_pid=$!

cleanup() {
  kill "$opencode_pid" 2>/dev/null || true
}

trap cleanup INT TERM

python3 - <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

deadline = time.monotonic() + 60.0
request_data = json.dumps({"title": "opencode cold-start warmup"}).encode("utf-8")
headers = {"Accept": "application/json", "Content-Type": "application/json"}

last_error = "opencode warm-up did not start"
while time.monotonic() < deadline:
    req = urllib.request.Request("http://127.0.0.1:4096/session", data=request_data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as response:
            payload = json.loads(response.read().decode(response.headers.get_content_charset("utf-8"), errors="replace"))
        session_id = payload.get("id") or payload.get("sessionID") or payload.get("sessionId")
        if isinstance(session_id, str) and session_id.strip():
            sys.exit(0)
        last_error = f"missing session id in warm-up response: {payload!r}"
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        last_error = str(exc)
    time.sleep(1.0)

print(f"OPENCODE warm-up failed: {last_error}", file=sys.stderr)
sys.exit(1)
PY

wait "$opencode_pid"