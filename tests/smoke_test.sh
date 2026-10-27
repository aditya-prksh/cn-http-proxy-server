#!/usr/bin/env bash
set -euo pipefail
BASE="http://127.0.0.1:8888"
fail(){ echo "FAIL: $*" >&2; exit 1; }
code=$(curl -sS -o /dev/null -w '%{http_code}' -x "$BASE" http://example.com/ || true)
[[ "$code" == "200" ]] || fail "example.com expected HTTP 200, got $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -x "$BASE" http://blocked.example/ || true)
[[ "$code" == "403" ]] || fail "blocked.example expected HTTP 403, got $code"
# Repeat a GET to exercise the cache path (verify HIT in proxy.log/stdout manually).
for i in 1 2 3 4 5; do curl -sS -o /dev/null -x "$BASE" http://example.com/; done
# Basic concurrency smoke test.
seq 1 8 | xargs -P8 -I{} curl -sS -o /dev/null -x "$BASE" http://example.com/
echo "PASS: forwarding, access-control rejection, repeat requests and concurrent clients smoke-tested."
echo "Note: inspect proxy.log for Cache HIT messages; run this test while proxy_server is running."
