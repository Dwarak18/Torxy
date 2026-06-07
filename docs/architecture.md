# Architecture

## Overview

Torxy is built as a small PHP reverse proxy around three main concerns:

1. Accept HTTP requests with ReactPHP.
2. Pick a Tor circuit from the circuit pool.
3. Forward the request through Tor with cURL and SOCKS5H.

## Main components

- `bin/server.php` bootstraps the app.
- `Torxy\Core\ProxyServer` handles incoming requests and response creation.
- `Torxy\Security\HeaderSanitizer` strips identity-leaking headers.
- `Torxy\Tor\CircuitManager` stores Tor circuits and returns them in round-robin order.
- `Torxy\Tor\TorController` talks to the Tor control port and can request `NEWNYM`.
- `Torxy\Core\RequestForwarder` sends the upstream request through the selected circuit.
- `Torxy\Tor\SocksClient` uses `curl` with `socks5h://` so DNS resolution happens inside Tor.

## Request flow

Client -> ProxyServer -> HeaderSanitizer -> CircuitManager -> RequestForwarder -> SocksClient -> Tor circuit -> target server

## Security behavior

- Identity headers such as `X-Forwarded-For`, `X-Real-IP`, and `Via` are removed before forwarding.
- TLS verification stays enabled in the cURL client.
- Errors are logged server-side and returned as generic gateway responses.

## Runtime model

The current runtime uses a round-robin circuit pool. The config file contains rotation settings for future expansion, but the active request path uses the registered circuit list directly.
