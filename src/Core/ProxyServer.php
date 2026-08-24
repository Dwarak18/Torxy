<?php

declare(strict_types=1);

namespace Torxy\Core;

use React\Http\HttpServer;
use React\Http\Message\Response;
use React\Socket\ConnectionInterface;
use React\Socket\SocketServer;
use React\EventLoop\LoopInterface;
use Psr\Http\Message\ServerRequestInterface;
use Torxy\Tor\CircuitManager;
use Torxy\Tor\CircuitNode;
use Torxy\Tor\SocksClient;
use Torxy\Security\AccessController;
use Torxy\Security\HeaderSanitizer;
use Throwable;

class ProxyServer
{
    /**
     * How many circuits a single client request may be tried on. Tor exits fail often
     * enough that one retry is routine; more than a few just delays a real error.
     */
    private const MAX_ATTEMPTS = 3;

    public function __construct(
        private readonly CircuitManager    $circuitManager,
        private readonly HeaderSanitizer   $headerSanitizer,
        private readonly RequestForwarder  $requestForwarder,
        private readonly ConnectTunnel     $connectTunnel,
        private readonly AccessController  $accessController,
        private readonly string $host,
        private readonly int $port
    ) {}

    public function start(LoopInterface $loop): void
    {
        // Do NOT pass $loop as first arg — react/http v1.x takes handlers only
        $server = new HttpServer(
            fn(ServerRequestInterface $request) => $this->handleRequest($request)
        );

        $socket = new SocketServer("{$this->host}:{$this->port}", [], $loop);

        // CONNECT needs the raw socket, which HttpServer cannot surrender, so split it
        // off before the HTTP parser sees the connection.
        $demux = new ConnectDemux(
            $socket,
            $loop,
            fn(ConnectionInterface $client, ConnectRequest $request) => $this->handleConnect($client, $request)
        );

        $server->listen($demux);

        echo "[Torxy] Proxy listening on http://{$this->host}:{$this->port}" . PHP_EOL;
        echo sprintf(
            "[Torxy] Access control: auth %s, IP allowlist %s\n",
            $this->accessController->isAuthRequired() ? 'required' : 'disabled',
            $this->accessController->hasIpAllowlist() ? 'active' : 'disabled'
        );
    }

    private function handleConnect(ConnectionInterface $client, ConnectRequest $request): void
    {
        $decision = $this->accessController->check(
            $client->getRemoteAddress(),
            $request->header('Proxy-Authorization')
        );

        if ($decision !== AccessController::ALLOW) {
            echo sprintf("[Torxy] CONNECT denied (%s): %s\n", $decision, $request->authority());
            $this->denyTunnel($client, $decision);

            return;
        }

        $this->attemptTunnel($client, $request, self::MAX_ATTEMPTS);
    }

    /**
     * Dial the tunnel, falling back to another circuit while nothing has been written to
     * the client. ConnectTunnel resolves once it has replied `200 Connection Established`,
     * so a failure after that point ends the tunnel rather than retrying it — by then the
     * client is already speaking TLS to the target and the bytes cannot be replayed.
     */
    private function attemptTunnel(ConnectionInterface $client, ConnectRequest $request, int $remaining): void
    {
        try {
            $circuit = $this->circuitManager->getNextNode();
        } catch (Throwable $e) {
            echo "[Torxy] ERROR: {$e->getMessage()}\n";
            $this->writeTunnelStatus($client, 502, 'Bad Gateway');

            return;
        }

        $this->connectTunnel
            ->open($client, $circuit, $request->host, $request->port, $request->earlyData)
            ->then(null, function (Throwable $e) use ($client, $request, $remaining): void {
                if ($remaining > 1) {
                    echo sprintf(
                        "[Torxy] Retrying CONNECT %s (%d attempts left)\n",
                        $request->authority(),
                        $remaining - 1
                    );

                    $this->attemptTunnel($client, $request, $remaining - 1);

                    return;
                }

                if ($this->isTimeout($e)) {
                    $this->writeTunnelStatus($client, 504, 'Gateway Timeout');

                    return;
                }

                $this->writeTunnelStatus($client, 502, 'Bad Gateway');
            });
    }

    private function writeTunnelStatus(ConnectionInterface $client, int $status, string $reason): void
    {
        $client->write(sprintf(
            "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            $status,
            $reason
        ));
        $client->end();
    }

    private function isTimeout(Throwable $e): bool
    {
        $message = strtolower($e->getMessage());

        return str_contains($message, 'timed out') || str_contains($message, 'timeout');
    }

    private function denyTunnel(ConnectionInterface $client, string $decision): void
    {
        $response = $decision === AccessController::DENY_AUTH
            ? "HTTP/1.1 407 Proxy Authentication Required\r\n"
                . "Proxy-Authenticate: Basic realm=\"Torxy\"\r\n"
            : "HTTP/1.1 403 Forbidden\r\n";

        $client->write($response . "Content-Length: 0\r\nConnection: close\r\n\r\n");
        $client->end();
    }

    /**
     * @return Response|\React\Promise\PromiseInterface<Response>
     */
    private function handleRequest(ServerRequestInterface $request): Response|\React\Promise\PromiseInterface
    {
        $method = $request->getMethod();
        $target = $request->getRequestTarget();

        echo "[Torxy] Incoming: {$method} {$target}" . PHP_EOL;

        // Health check — bypasses Tor, confirms ReactPHP is working
        if ($target === '/healthz' || $target === 'http://healthz/') {
            return new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'status'   => 'ok',
                'circuits' => $this->circuitManager->getCircuitCount(),
                'healthy'  => $this->circuitManager->getHealthyCount(),
            ]));
        }

        // CONNECT is intercepted by ConnectDemux before the HTTP parser runs, so reaching
        // here means the demux was bypassed. Never forward it as an ordinary request.
        if ($method === 'CONNECT') {
            return $this->errorResponse(501, 'Not Implemented: CONNECT must be tunnelled');
        }

        // Read Proxy-Authorization from the original request: HeaderSanitizer strips it
        // below so it is never forwarded upstream.
        $decision = $this->accessController->check(
            $request->getServerParams()['REMOTE_ADDR'] ?? null,
            $request->getHeaderLine('Proxy-Authorization')
        );

        if ($decision !== AccessController::ALLOW) {
            echo sprintf("[Torxy] Request denied (%s): %s %s\n", $decision, $method, $target);

            return $this->denyResponse($decision);
        }

        // Reject unforwardable methods up front. Letting SocksClient throw instead would
        // surface a client error as 502 and consume a circuit from the rotation.
        if (!in_array(strtoupper($method), SocksClient::SUPPORTED_METHODS, strict: true)) {
            return $this->errorResponse(501, "Not Implemented: unsupported method {$method}");
        }

        $targetUrl = $this->resolveTargetUrl($request);

        if ($targetUrl === null) {
            return $this->errorResponse(400, 'Bad Request: cannot resolve target URL');
        }

        try {
            $cleanHeaders = $this->headerSanitizer->strip(
                $this->flattenHeaders($request->getHeaders())
            );

            $attemptForward = function (CircuitNode $circuit, int $remaining) use ($method, $targetUrl, $cleanHeaders, $request, &$attemptForward) {
                echo sprintf("[Torxy] Forwarding → %s via %s (attempts left: %d)\n", $targetUrl, $circuit->getIdentifier(), $remaining);

                return $this->requestForwarder->forward(
                    circuit: $circuit,
                    url:     $targetUrl,
                    method:  $method,
                    headers: $cleanHeaders,
                    body:    (string) $request->getBody()
                )->then(
                    function (\Psr\Http\Message\ResponseInterface $response) use ($circuit) {
                        echo "[Torxy] Response: HTTP {$response->getStatusCode()}\n";

                        // The circuit carried a complete response. What status the target
                        // chose to send is none of the circuit's business.
                        $circuit->markSuccess();

                        $forwardHeaders = [];
                        foreach ($response->getHeaders() as $name => $values) {
                            $forwardHeaders[$name] = implode(', ', $values);
                        }

                        $body = (string) $response->getBody();

                        return new Response($response->getStatusCode(), $forwardHeaders, $body);
                    },
                    function (\Throwable $e) use ($circuit, $remaining, &$attemptForward) {
                        echo "[Torxy] ERROR on forward: {$e->getMessage()}\n";

                        // SocksClient does not reject on error responses, so anything that
                        // lands here is a transport failure and counts against the circuit.
                        $circuit->markFailure();

                        if ($remaining > 1) {
                            $next = $this->circuitManager->getNextNode();
                            echo sprintf("[Torxy] Retrying via %s (%d attempts left)\n", $next->getIdentifier(), $remaining - 1);

                            return $attemptForward($next, $remaining - 1);
                        }

                        if ($this->isTimeout($e)) {
                            return $this->errorResponse(504, 'Gateway Timeout');
                        }

                        return $this->errorResponse(502, 'Bad Gateway');
                    }
                );
            };

            return $attemptForward($this->circuitManager->getNextNode(), self::MAX_ATTEMPTS);

        } catch (Throwable $e) {
            echo "[Torxy] ERROR: {$e->getMessage()}\n";
            return $this->errorResponse(502, 'Bad Gateway');
        }
    }

    private function resolveTargetUrl(ServerRequestInterface $request): ?string
    {
        $target = $request->getRequestTarget();

        if (str_starts_with($target, 'http://') || str_starts_with($target, 'https://')) {
            return $target;
        }

        $host = $request->getHeaderLine('Host');

        if ($host === '') {
            return null;
        }

        $scheme = $request->getUri()->getScheme() ?: 'http';

        return "{$scheme}://{$host}{$target}";
    }

    /**
     * PSR-7 exposes each header as a list of values; the forwarder wants one string per
     * header, joined the way RFC 7230 §3.2.2 allows.
     *
     * @param array<string, string[]> $headers
     *
     * @return array<string, string>
     */
    private function flattenHeaders(array $headers): array
    {
        $flat = [];
        foreach ($headers as $name => $values) {
            $flat[$name] = implode(', ', $values);
        }
        return $flat;
    }

    private function denyResponse(string $decision): Response
    {
        if ($decision === AccessController::DENY_AUTH) {
            return new Response(
                407,
                [
                    'Proxy-Authenticate' => 'Basic realm="Torxy"',
                    'Content-Type'       => 'text/plain',
                ],
                'Proxy Authentication Required'
            );
        }

        return new Response(403, ['Content-Type' => 'text/plain'], 'Forbidden');
    }

    private function errorResponse(int $status, string $message): Response
    {
        return new Response(
            $status,
            ['Content-Type' => 'text/plain'],
            $message
        );
    }
}