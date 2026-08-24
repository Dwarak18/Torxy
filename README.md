# Torxy

Torxy is a PHP 8.3 reverse proxy that forwards traffic through a pool of Tor circuits and strips client identity headers before sending requests upstream.

## What it does

- Rotates requests across multiple Tor circuits, with a time-based `NEWNYM` timer
- Requires credentials and/or an IP allowlist, so the proxy is not an open relay
- Tracks circuit health and retries a failed request on another circuit
- Uses ReactPHP for the HTTP server
- Forwards traffic through SOCKS5H so DNS resolves inside Tor
- Tunnels HTTPS with `CONNECT`, so TLS stays end-to-end between client and target
- Sanitizes proxy headers that can leak client identity

## Requirements

- PHP 8.3+
- Composer
- Docker Compose

## Quick start

1. Copy `.env.example` to `.env`, then set:
   - a strong `TOR_CONTROL_PASSWORD`
   - `PROXY_AUTH_USER` and `PROXY_AUTH_PASSWORD`, and/or `PROXY_ALLOWED_IPS`
2. Start the stack:

   ```bash
   docker compose up --build
   ```

3. Send traffic through the proxy at `http://localhost:8080`.

## Configuration

The main settings live in `.env` and `config/proxy.php`.

- `TOR_CONTROL_PASSWORD` is required.
- `TOR1_HOST`, `TOR2_HOST`, and `TOR3_HOST` map to the Tor service hostnames.
- `TOR_SOCKS_PORT` and `TOR_CONTROL_PORT` default to `9050` and `9051`.
- `PROXY_HOST` and `PROXY_PORT` control the listener *inside the container*. Compose
  publishes it on `127.0.0.1:8080` so the proxy is not exposed to the network.
- `PROXY_AUTH_USER` / `PROXY_AUTH_PASSWORD` require Basic proxy credentials. Both must be
  set for the check to apply.
- `PROXY_ALLOWED_IPS` is a comma-separated list of addresses or CIDR blocks. Empty disables
  the check.
- `TOR_ROTATION_STRATEGY` is `round_robin`, `random`, or `per_request`.
- `TOR_ROTATION_INTERVAL` rotates every circuit on a timer, in seconds (`0` disables).
- `TOR_HEALTH_INTERVAL`, `TOR_HEALTH_PROBE_TARGET`, and `TOR_HEALTH_FAILURE_THRESHOLD`
  control when a circuit drops out of rotation and how it is probed back in.

Leaving both access-control settings unset runs the proxy wide open to anything that can
reach the port. That is only safe on a host you fully control.

## Usage

The proxy accepts either:

- full proxy-style URLs in the request target, or
- normal Host-header requests

HTTPS is handled with `CONNECT` tunnelling. The proxy pipes raw bytes once the tunnel is
open, so it never sees the plaintext and the client validates the target's certificate
itself:

```bash
curl --proxy-user user:pass -x http://localhost:8080 https://api.ipify.org
```

`/healthz` reports the circuit pool and needs no credentials:

```bash
curl http://localhost:8080/healthz
```

## Development

```bash
composer check
```

runs the unit tests (PHPUnit) and static analysis (PHPStan, level 6). The live end-to-end
suite needs the Docker stack running:

```bash
bash tests/integration.sh
```

## Project docs

- `docs/setup.md`
- `docs/architecture.md`

## License

Apache-2.0
