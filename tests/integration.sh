#!/usr/bin/env bash
# pipefail is a bash builtin, not POSIX sh — the shebang must stay bash.
set -euo pipefail

PROXY_ADDR="${TORXY_PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${TORXY_PROXY_PORT:-8080}"
PROXY="http://${PROXY_ADDR}:${PROXY_PORT}"
ENV_FILE="$(dirname "$0")/../.env"

echo "[Torxy] Integration test: access control, healthz, HTTP forwarding, CONNECT tunnelling"

# Read a value out of .env. The proxy refuses unauthenticated clients whenever credentials
# are configured, so the suite has to present the same ones the running server loaded.
env_value() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -1 | tr -d '\r' | sed 's/^"\(.*\)"$/\1/'
}

AUTH_USER="${PROXY_AUTH_USER:-$(env_value PROXY_AUTH_USER)}"
AUTH_PASS="${PROXY_AUTH_PASSWORD:-$(env_value PROXY_AUTH_PASSWORD)}"

# Both halves must be set for the server to enforce credentials, so the suite treats a
# half-configured pair as "no auth" exactly as AccessController does.
if [ -n "$AUTH_USER" ] && [ -n "$AUTH_PASS" ]; then
  AUTH_ENFORCED=1
  echo "Proxy credentials: configured (user ${AUTH_USER})"
else
  AUTH_ENFORCED=0
  echo "Proxy credentials: none configured — auth assertions will be skipped"
fi

# curl through the proxy, presenting credentials when the deployment requires them.
pcurl() {
  if [ "$AUTH_ENFORCED" -eq 1 ]; then
    curl --proxy-user "${AUTH_USER}:${AUTH_PASS}" -x "$PROXY" "$@"
  else
    curl -x "$PROXY" "$@"
  fi
}

# Send a raw request over bash's /dev/tcp. Needed for two things curl will not do: emit a
# malformed request line, and show us the proxy's own response head when CONNECT fails.
raw_request() {
  exec 3<>"/dev/tcp/${PROXY_ADDR}/${PROXY_PORT}" || return 1
  printf '%b' "$1" >&3
  timeout 15 head -c "${2:-60}" <&3
  exec 3<&- 2>/dev/null || true
  exec 3>&- 2>/dev/null || true
}

probe_status() {
  raw_request "$1" 60 | head -1
}

echo "Checking /healthz..."
HEALTH=$(curl -sS "${PROXY}/healthz" || true)
echo "healthz response: ${HEALTH}"

echo "$HEALTH" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"' || {
  echo "FAIL: /healthz did not return status ok"; exit 1;
}

echo "$HEALTH" | grep -q '"circuits"[[:space:]]*:[[:space:]]*[1-9][0-9]*' || {
  echo "FAIL: /healthz circuits count is zero or missing"; exit 1;
}

echo "$HEALTH" | grep -q '"healthy"[[:space:]]*:[[:space:]]*[1-9][0-9]*' || {
  echo "FAIL: /healthz reports no healthy circuits"; exit 1;
}

echo "/healthz OK"

if [ "$AUTH_ENFORCED" -eq 1 ]; then
  # An anonymising proxy anyone can reach is an open relay, so a missing or wrong
  # credential must be refused on both the forwarding path and the tunnel path.
  echo "Verifying unauthenticated HTTP forwarding is refused..."
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -x "$PROXY" http://api.ipify.org || true)
  [ "$CODE" = "407" ] || {
    echo "FAIL: unauthenticated HTTP request returned ${CODE}, expected 407"; exit 1;
  }

  echo "Verifying wrong credentials are refused..."
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 \
    --proxy-user "${AUTH_USER}:definitely-not-the-password" -x "$PROXY" http://api.ipify.org || true)
  [ "$CODE" = "407" ] || {
    echo "FAIL: wrong credentials returned ${CODE}, expected 407"; exit 1;
  }

  echo "Verifying unauthenticated CONNECT is refused..."
  AUTH_HEAD=$(raw_request 'CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org:443\r\n\r\n' 200 || true)
  case "$AUTH_HEAD" in
    *"407"*) ;;
    *) echo "FAIL: unauthenticated CONNECT not refused with 407 (got: ${AUTH_HEAD:-no response})"; exit 1 ;;
  esac

  # Without this header a client has no way to know it should retry with credentials.
  echo "$AUTH_HEAD" | grep -qi 'Proxy-Authenticate:[[:space:]]*Basic' || {
    echo "FAIL: 407 did not carry a Proxy-Authenticate: Basic challenge"; exit 1;
  }

  echo "Access control OK"
fi

# The IP allowlist is not exercised here: DENY_IP can only be triggered by changing
# PROXY_ALLOWED_IPS and restarting the server. Its CIDR matching — partial-byte prefixes,
# /0, IPv6, cross-family rules — is covered exhaustively in tests/Unit/Security.

echo "Testing HTTP proxy forwarding..."
HTTP_IP=$(pcurl -sS --max-time 60 http://api.ipify.org || true)
if [ -z "$HTTP_IP" ]; then
  echo "FAIL: proxy did not return a response over HTTP"; exit 1;
fi
echo "HTTP exit IP: $HTTP_IP"

echo "Testing HTTPS via CONNECT tunnel..."
HTTPS_IP=$(pcurl -sS --max-time 60 https://api.ipify.org || true)
if [ -z "$HTTPS_IP" ]; then
  echo "FAIL: CONNECT tunnel did not return a response"; exit 1;
fi
echo "HTTPS exit IP: $HTTPS_IP"

echo "Verifying the exit IP is not our own address..."
DIRECT_IP=$(curl -sS --max-time 30 https://api.ipify.org || true)
if [ -n "$DIRECT_IP" ] && [ "$DIRECT_IP" = "$HTTPS_IP" ]; then
  echo "FAIL: tunnelled traffic exited from our real IP ($DIRECT_IP) — Tor was bypassed"; exit 1;
fi
echo "Exit IP differs from direct IP OK"

echo "Verifying TLS is end-to-end (proxy must not be able to MITM)..."
# Pin against the certificate seen on a direct connection. If the tunnel presented a
# different certificate, curl would reject it and this would fail.
PIN=$(openssl s_client -connect api.ipify.org:443 -servername api.ipify.org </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary 2>/dev/null \
  | openssl enc -base64 || true)

if [ -z "$PIN" ]; then
  echo "SKIP: could not compute certificate pin (openssl unavailable)"
else
  pcurl -sS --max-time 60 --pinnedpubkey "sha256//${PIN}" -o /dev/null https://api.ipify.org || {
    echo "FAIL: certificate through the tunnel did not match the real one"; exit 1;
  }
  echo "Certificate pinning through tunnel OK"
fi

echo "Verifying identity headers are stripped..."
HDRS=$(pcurl -sS --max-time 60 \
  -H "X-Forwarded-For: 1.2.3.4" -H "Via: leaky-proxy" -H "X-Real-IP: 5.6.7.8" \
  http://httpbin.org/headers || true)

for LEAK in "X-Forwarded-For" "Via" "X-Real-Ip" "Proxy-Connection"; do
  if echo "$HDRS" | grep -qi "\"${LEAK}\""; then
    echo "FAIL: ${LEAK} leaked to the target"; exit 1;
  fi
done
echo "Header sanitization OK"

echo "Verifying the target's own status code is relayed, not masked as 502..."
for WANT in 404 503; do
  GOT=$(pcurl -sS -o /dev/null -w '%{http_code}' --max-time 60 "http://httpbin.org/status/${WANT}" || true)
  [ "$GOT" = "$WANT" ] || {
    echo "FAIL: target ${WANT} was relayed as ${GOT}"; exit 1;
  }
done
echo "Upstream status relaying OK"

# Bodies are streamed rather than buffered. Every case below fails on a buffering proxy, so
# each is a regression test for a specific defect rather than a general size check.
UPLOAD_ECHO="${TORXY_UPLOAD_ECHO:-http://httpbin.org/post}"
LARGE_FILE="${TORXY_LARGE_FILE:-http://speedtest.tele2.net/20MB.zip}"
LARGE_FILE_BYTES="${TORXY_LARGE_FILE_BYTES:-20971520}"

UPLOAD_TMP=$(mktemp)
trap 'rm -f "$UPLOAD_TMP"' EXIT

# Ask the echo target how many bytes it actually received. react/http's default buffering
# caps a request body at 64 KiB and forwards an EMPTY one past that, answering 200 — so a
# short read here is silent data loss, not a visible error.
upload_seen_length() {
  pcurl -sS --max-time 180 -X POST \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@${UPLOAD_TMP}" "$@" "$UPLOAD_ECHO" 2>/dev/null \
    | grep -o '"Content-Length": "[0-9]*"' | head -1 | grep -o '[0-9]*'
}

for SIZE in 65537 204800; do
  echo "Verifying a ${SIZE}-byte upload arrives intact..."
  head -c "$SIZE" /dev/zero | tr '\0' 'a' > "$UPLOAD_TMP"
  SEEN=$(upload_seen_length || true)

  [ "$SEEN" = "$SIZE" ] || {
    echo "FAIL: target received Content-Length ${SEEN:-none}, expected ${SIZE}"; exit 1;
  }
done
echo "Buffered upload round-trip OK"

# Past RequestBodyReader::MAX_REPLAYABLE_BYTES the body is streamed straight through and the
# request gets a single attempt, so this exercises a different code path from the two above.
echo "Verifying a 5 MiB upload is streamed through intact..."
head -c 5242880 /dev/zero | tr '\0' 'a' > "$UPLOAD_TMP"
SEEN=$(upload_seen_length || true)
[ "$SEEN" = "5242880" ] || {
  echo "FAIL: streamed upload arrived as ${SEEN:-none} bytes, expected 5242880"; exit 1;
}
echo "Streamed upload OK"

# A chunked upload announces no length at all, so it can never be size-checked up front.
# The target reports no Content-Length either, so count the bytes it echoed back instead.
echo "Verifying a chunked upload with no Content-Length arrives intact..."
head -c 300000 /dev/zero | tr '\0' 'b' > "$UPLOAD_TMP"
ECHOED=$(pcurl -sS --max-time 180 -X POST \
  -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/octet-stream' \
  --data-binary "@${UPLOAD_TMP}" "$UPLOAD_ECHO" 2>/dev/null | tr -cd 'b' | wc -c | tr -d ' ')

# The JSON envelope contributes a handful of its own 'b' characters, so allow a small margin.
if [ "${ECHOED:-0}" -lt 300000 ] || [ "${ECHOED:-0}" -gt 300100 ]; then
  echo "FAIL: chunked upload echoed ${ECHOED:-0} body bytes, expected ~300000"; exit 1;
fi
echo "Chunked upload OK"

# Larger than Browser's 16 MiB response buffer. Buffered, this returned 502 and — because a
# size limit is not a transport fault — took a health strike off every circuit it retried on,
# so repeating it drained the pool. Both halves are asserted.
echo "Verifying a ${LARGE_FILE_BYTES}-byte download streams through (this takes a while)..."
DL=$(pcurl -sS --max-time 600 -o /dev/null -w '%{http_code} %{size_download}' "$LARGE_FILE" || true)
echo "large download: ${DL:-no response}"

[ "$DL" = "200 ${LARGE_FILE_BYTES}" ] || {
  echo "FAIL: large download returned '${DL:-nothing}', expected '200 ${LARGE_FILE_BYTES}'"; exit 1;
}

HEALTH_AFTER=$(curl -sS "${PROXY}/healthz" || true)
echo "healthz after large transfer: ${HEALTH_AFTER}"

# The pool must be exactly as healthy as it was before the transfer.
BEFORE_HEALTHY=$(echo "$HEALTH" | grep -o '"healthy"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
AFTER_HEALTHY=$(echo "$HEALTH_AFTER" | grep -o '"healthy"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')

[ "${AFTER_HEALTHY:-0}" = "${BEFORE_HEALTHY:-1}" ] || {
  echo "FAIL: healthy circuits went from ${BEFORE_HEALTHY} to ${AFTER_HEALTHY} — a size limit was charged to circuit health"; exit 1;
}
echo "Large download OK, circuit health intact"

rm -f "$UPLOAD_TMP"
trap - EXIT

echo "Verifying malformed CONNECT is rejected..."
BAD_OK=1
for BAD_REQ in \
  'CONNECT hostnoport HTTP/1.1\r\nHost: x\r\n\r\n' \
  'CONNECT host:abc HTTP/1.1\r\nHost: x\r\n\r\n' \
  'CONNECT host:99999 HTTP/1.1\r\nHost: x\r\n\r\n' \
  'CONNECT 2001:db8::1:443 HTTP/1.1\r\nHost: x\r\n\r\n'
do
  RESP=$(probe_status "$BAD_REQ" || true)
  case "$RESP" in
    *"400"*) ;;
    *) echo "FAIL: malformed CONNECT not rejected with 400 (got: ${RESP:-no response})"; BAD_OK=0 ;;
  esac
done

[ "$BAD_OK" -eq 1 ] || exit 1
echo "Malformed CONNECT rejected OK"

echo "Verifying plain HTTP still routes through the HTTP parser on the same port..."
GOOD=$(probe_status 'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' || true)
case "$GOOD" in
  *"200"*) echo "Demux HTTP path OK" ;;
  *) echo "FAIL: plain HTTP on shared port did not return 200 (got: ${GOOD:-no response})"; exit 1 ;;
esac

echo "Integration tests passed"
