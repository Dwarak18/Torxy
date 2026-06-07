# Torxy

Torxy is a PHP 8.3 reverse proxy that forwards traffic through a pool of Tor circuits and strips client identity headers before sending requests upstream.

## What it does

- Rotates requests across multiple Tor circuits
- Uses ReactPHP for the HTTP server
- Forwards traffic through SOCKS5H so DNS resolves inside Tor
- Sanitizes proxy headers that can leak client identity

## Requirements

- PHP 8.3+
- Composer
- Docker Compose

## Quick start

1. Copy `.env.example` to `.env` and set a strong `TOR_CONTROL_PASSWORD`.
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
- `PROXY_HOST` and `PROXY_PORT` control the HTTP listener.

## Usage

The proxy accepts either:

- full proxy-style URLs in the request target, or
- normal Host-header requests

The current circuit selection is round-robin across registered Tor nodes.

## Project docs

- `docs/setup.md`
- `docs/architecture.md`

## License

Apache-2.0
