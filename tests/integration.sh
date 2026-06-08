#!/bin/sh
set -euo pipefail

echo "[Torxy] Integration test: healthz and proxy"

echo "Checking /healthz..."
HEALTH=$(curl -sS http://localhost:8080/healthz || true)
echo "healthz response: ${HEALTH}"

echo "$HEALTH" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' || {
  echo "FAIL: /healthz did not return status ok"; exit 1;
}

echo "$HEALTH" | grep -q '"circuits"[[:space:]]*:[[:space:]]*[1-9][0-9]*' || {
  echo "FAIL: /healthz circuits count is zero or missing"; exit 1;
}

echo "/healthz OK"

echo "Testing HTTP proxy forwarding via ident.me..."
PROXY_RESP=$(curl -sS -x http://localhost:8080 http://ident.me/ || true)
if [ -z "$PROXY_RESP" ]; then
  echo "FAIL: proxy did not return a response"; exit 1;
fi

echo "Proxy returned: $PROXY_RESP"

echo "Integration tests passed"
