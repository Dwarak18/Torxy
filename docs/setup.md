# Setup

## Docker Compose

This is the supported way to run Torxy.

1. Copy the sample environment file:

   ```bash
   cp .env.example .env
   ```

2. Set `TOR_CONTROL_PASSWORD` to a strong value.

3. Start the stack:

   ```bash
   docker compose up --build
   ```

4. Check the logs:

   ```bash
   docker compose logs -f torxy-app tor1 tor2 tor3
   ```

## Verify the proxy

With the stack running, send a request through the proxy:

```bash
curl -x http://localhost:8080 https://check.torproject.org/api/ip
```

## Useful service notes

- `torxy-app` is the PHP proxy container.
- `tor1`, `tor2`, and `tor3` are the Tor circuit containers.
- The PHP container keeps `vendor/` in a named volume so dependencies survive bind mounts.

## Troubleshooting

- If the app exits immediately, check that `TOR_CONTROL_PASSWORD` is set.
- If the proxy cannot connect, confirm the Tor services are healthy and reachable on the internal network.
- If dependencies look missing, rebuild the stack with `docker compose up --build`.
