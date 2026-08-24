# Architecture

## Overview

Torxy is built as a small PHP reverse proxy around three main concerns:

1. Accept HTTP requests with ReactPHP.
2. Pick a Tor circuit from the circuit pool.
3. Forward the request through the circuit's SOCKS5 port, resolving DNS inside Tor.

## Main components

- `bin/server.php` bootstraps the app.
- `Torxy\Core\ConnectDemux` splits CONNECT tunnels from ordinary proxy requests.
- `Torxy\Core\ConnectRequest` parses and validates a CONNECT request head.
- `Torxy\Core\ProxyServer` handles incoming requests and response creation.
- `Torxy\Core\RequestBodyReader` decides whether a request body can be held for a retry.
- `Torxy\Core\ConnectTunnel` establishes CONNECT tunnels through a circuit.
- `Torxy\Security\AccessController` decides whether a client may use the proxy at all.
- `Torxy\Security\HeaderSanitizer` strips identity-leaking and hop-by-hop headers.
- `Torxy\Tor\CircuitManager` stores Tor circuits and selects a healthy one per request.
- `Torxy\Tor\CircuitNode` holds one circuit's SOCKS address and its health state.
- `Torxy\Tor\CircuitHealthMonitor` probes circuits that have dropped out of rotation.
- `Torxy\Tor\CircuitRotator` drives time-based `NEWNYM` rotation on the event loop.
- `Torxy\Tor\TorController` talks to the Tor control port and can request `NEWNYM`.
- `Torxy\Core\RequestForwarder` sends the upstream request through the selected circuit.
- `Torxy\Tor\SocksClient` wraps a ReactPHP `Browser` over a `clue/socks-react` SOCKS5
  connector configured with `'dns' => false`, so hostnames are passed to Tor unresolved
  (SOCKS5H behavior) and DNS never leaks to the local resolver.

## Request flow

Two paths share the listening port, split by `ConnectDemux` on the request line:

**Plain HTTP**

Client -> ConnectDemux -> ProxyServer -> AccessController -> HeaderSanitizer -> CircuitManager -> RequestForwarder -> SocksClient -> Tor circuit -> target server

**HTTPS (CONNECT)**

Client -> ConnectDemux -> ProxyServer -> AccessController -> CircuitManager -> ConnectTunnel -> RequestForwarder -> SocksClient -> Tor circuit -> raw byte pipe to target

`React\Http\HttpServer` models traffic as request/response pairs and cannot express a
tunnel, so `ConnectDemux` implements `ServerInterface` and sits between the socket and the
HTTP server. It peeks at the request line, routes `CONNECT` to `ConnectTunnel`, and
re-emits every other connection with the peeked bytes replayed so `HttpServer` parses it
normally.

## Security behavior

- Access is gated before any traffic is forwarded (see *Access control* below).
- Identity headers such as `X-Forwarded-For`, `X-Real-IP`, and `Via` are removed before forwarding.
- Hop-by-hop headers (`Proxy-Connection`, `Connection`, `Transfer-Encoding`, …) are removed
  so the request does not advertise that a proxy is in the path. Responses are filtered
  through the same list on the way back.
- `Proxy-Authorization` is read for the access check and then stripped, so the proxy's own
  credentials are never forwarded to the target.
- `Expect` is stripped too. `React\Http\Io\StreamingServer` already answers the client's
  `100-continue` itself, and react/http's *client* treats an upstream `100` as the final
  response — so forwarding the header would relay an empty `100` in place of the real answer.
- DNS resolution happens inside Tor, not on the local network.
- In a CONNECT tunnel the proxy only copies bytes and never sees plaintext, so the client
  negotiates and validates TLS end-to-end against the real target. The proxy cannot read
  or alter tunnelled traffic.
- The whole CONNECT request head is discarded rather than forwarded, so proxy-specific
  headers never reach the target.
- Errors are logged server-side and returned as generic gateway responses.

## Access control

An anonymising proxy that anyone can reach is an open relay: strangers launder traffic
through the operator's circuits and the operator collects the abuse complaints.
`AccessController` therefore applies two independent, opt-in gates on both the forwarding
path and the tunnel path:

- **Credentials** — `PROXY_AUTH_USER` and `PROXY_AUTH_PASSWORD`. Enforced only when both
  halves are set, so a half-configured pair cannot silently accept an empty password.
  Comparison uses `hash_equals`. Failures answer `407` with a `Proxy-Authenticate` challenge.
- **IP allowlist** — `PROXY_ALLOWED_IPS`, a comma-separated list of bare addresses or CIDR
  blocks (IPv4 and IPv6). Empty disables the check. Failures answer `403`.

The IP check runs first: an address that is not allowlisted is refused without being told
whether credentials would have helped. `/healthz` is answered before either gate so a
monitor does not need credentials.

The container publishes the listener on `127.0.0.1:8080` rather than `8080`, so the proxy
is not reachable from other hosts on the network even before these gates apply.

## Rotation

`CircuitManager` supports three strategies, set via `config/proxy.php`:

- `round_robin` (default) — cycle through the registered circuits in order.
- `random` — pick a registered circuit at random.
- `per_request` — round-robin, and additionally ask the selected circuit's control port for
  `SIGNAL NEWNYM`.

`rotation.interval` (`TOR_ROTATION_INTERVAL`, seconds; `0` disables) drives
`CircuitRotator`, which sends `NEWNYM` to every circuit on a periodic event-loop timer.
`CircuitRotator` is started even when the interval is `0`, because it also supplies the
non-blocking rotation callback that `per_request` uses.

All control-port rotation is asynchronous: `TorController::requestNewCircuitAsync()` speaks
the control protocol over a ReactPHP connector with its own timeout, so nothing blocks the
loop. Rotation is deliberately fire-and-forget — `NEWNYM` only affects streams opened
*after* Tor acts on it, so waiting would delay the current request without changing the exit
it goes out on. The fresh exit lands on the requests that follow.

## Circuit health

Health is recorded where failures actually happen rather than inferred from probes:

- A completed upstream response or an established tunnel marks the circuit healthy.
- A transport failure marks a failure. `SocksClient` sets `withRejectErrorResponse(false)`,
  so a rejected promise is always a transport problem — a `404` or `503` from the target is
  relayed verbatim and is none of the circuit's business.
- A response whose body fails part-way through still marks a failure, even though the head
  already counted as a success and the client's response has already started.
- Failures that are not the circuit's fault are excluded: a client abandoning its upload, and
  a request body too large to buffer. Charging those to circuit health is how a size limit
  used to take the whole pool offline.
- After `health.failure_threshold` *consecutive* failures the circuit drops out of rotation.
  Any success resets the counter.

`CircuitHealthMonitor` runs on a timer (`health.interval`, `0` disables) and probes only
the circuits that are out of rotation, dialling `health.probe_target` through SOCKS to see
whether the path works again. Healthy circuits are not probed: live traffic already reports
on them, and synthetic probes would add load and a fingerprintable periodic pattern.

If every circuit is marked unhealthy, selection hands one back anyway. A stale health
verdict must not take the whole proxy offline, and a real attempt is what re-tests the path.

## Bodies

Bodies are streamed in both directions, never buffered whole. A proxy's only job on the body
is to pass bytes along, so holding them costs memory and imposes ceilings without buying
anything. `StreamingRequestMiddleware` is enabled on the server and `SocksClient` uses
`Browser::requestStreaming()`, so the upstream response resolves at its head and the body is
handed to the client as it arrives. A 100 MiB transfer moves through in roughly the same
resident memory as an empty one.

Both defaults this replaces failed badly. react/http caps a buffered request body at 64 KiB
(`HttpServer::MAXIMUM_BUFFER_SIZE`, independent of `post_max_size`) and forwards an *empty*
body past that while still answering `200` — silent data loss. `Browser` caps a buffered
response at 16 MiB and rejects beyond it, which surfaced as `502`.

Streaming costs the ability to retry, because a consumed body cannot be replayed on another
circuit. `RequestBodyReader` splits on that:

- `Content-Length` known and ≤ 1 MiB — buffered in memory, so the request keeps its full
  three attempts. This covers ordinary form posts and API calls.
- Larger than that, or `Transfer-Encoding: chunked` with no length to check — streamed
  through with a single attempt. Reading it to enable a retry is exactly what would put an
  arbitrary upload into memory.

A body that outgrows its limit is rejected with `413`, never truncated. Forwarding a short
body under the client's own `Content-Length` is the failure mode being replaced.

Response `Content-Length` survives sanitization deliberately: it is what lets react/http
frame the relayed response with the upstream's own length instead of re-chunking it. When
upstream used chunked encoding, `Transfer-Encoding` is stripped and react/http re-derives
chunked framing itself.

Concurrency is bounded explicitly by `LimitConcurrentRequestsMiddleware`. Passing
`StreamingRequestMiddleware` disables the limit react/http would otherwise apply on its own,
and each in-flight request holds a Tor connection open.

## Retries

A client request may be tried on up to three circuits, provided the body is replayable — see
*Bodies* above. On the tunnel path `ConnectTunnel` resolves as soon as it has written
`200 Connection Established` and rejects only while nothing has been written to the client,
so a retry can never replay bytes the client has already started sending as TLS.

Tunnel dials use a tighter 10s timeout than the 30s request timeout, so three attempts keep
the worst case a client waits at the same 30s a single request allows.

Not every failure is the circuit's. A request that fails because the *client* abandoned its
upload is answered `400` without a health strike — otherwise repeated aborts would drain the
pool, which is the same shape of self-inflicted outage the old 16 MiB response cap caused.

## Known limitations

- The 30s request timeout bounds only the wait for the response *head*: `Browser` cancels its
  timer once the head arrives, so a streamed body transfer is unbounded. This is deliberate,
  since any fixed budget would kill a legitimate large download partway through — but a
  stream that stalls mid-body hangs until the underlying connection dies. An idle timeout on
  the body would close this.
- A request body larger than 1 MiB, or of unknown length, gets one attempt instead of three.
- With `round_robin` and a fixed circuit pool, the exit-IP sequence within one rotation
  period is deterministic — an observer sees the same N addresses repeat in a fixed cycle
  until the next `NEWNYM`.
- Health is only ever observed as "this dial failed"; there is no measurement of circuit
  latency or bandwidth, so a slow-but-working exit stays in rotation.
- Each forwarded request and each tunnel constructs a fresh `SocksClient`, so no upstream
  connections are pooled or reused.
- The Tor control password is read from the environment in plaintext and is shared by all
  three Tor instances.
