<?php

declare(strict_types=1);

namespace Torxy\Core;

use React\Http\HttpServer;
use React\Http\Message\Response;
use React\Socket\SocketServer;
use React\EventLoop\LoopInterface;
use Psr\Http\Message\ServerRequestInterface;
use Torxy\Tor\CircuitManager;
use Torxy\Security\HeaderSanitizer;
use Throwable;

class ProxyServer
{
    public function __construct(
        private readonly CircuitManager   $circuitManager,
        private readonly HeaderSanitizer  $headerSanitizer,
        private readonly RequestForwarder $requestForwarder,
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
        $server->listen($socket);

        echo "[Torxy] Proxy listening on http://{$this->host}:{$this->port}" . PHP_EOL;
    }

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
            ]));
        }

        $targetUrl = $this->resolveTargetUrl($request);

        if ($targetUrl === null) {
            return $this->errorResponse(400, 'Bad Request: cannot resolve target URL');
        }

        try {
            $cleanHeaders = $this->headerSanitizer->strip(
                $this->flattenHeaders($request->getHeaders())
            );

            $maxAttempts = 3;

            $attemptForward = function ($circuit, int $remaining) use ($method, $targetUrl, $cleanHeaders, $request, &$attemptForward) {
                echo sprintf("[Torxy] Forwarding → %s via %s (attempts left: %d)\n", $targetUrl, $circuit->getIdentifier(), $remaining);

                return $this->requestForwarder->forward(
                    circuit: $circuit,
                    url:     $targetUrl,
                    method:  $method,
                    headers: $cleanHeaders,
                    body:    (string) $request->getBody()
                )->then(
                    function (\Psr\Http\Message\ResponseInterface $response) {
                        echo "[Torxy] Response: HTTP {$response->getStatusCode()}\n";

                        $forwardHeaders = [];
                        foreach ($response->getHeaders() as $name => $values) {
                            $forwardHeaders[$name] = implode(', ', $values);
                        }

                        $body = (string) $response->getBody();

                        return new Response($response->getStatusCode(), $forwardHeaders, $body);
                    },
                    function (\Throwable $e) use ($remaining, &$attemptForward) {
                        $msg = $e->getMessage();
                        echo "[Torxy] ERROR on forward: {$msg}\n";

                        // Determine if error is retryable (TLS/handshake/connection reset)
                        $lower = strtolower($msg);
                        $isRetryable = str_contains($lower, 'tls') || str_contains($lower, 'handshake') || str_contains($lower, 'connection reset') || str_contains($lower, 'econnreset') || str_contains($lower, 'connection lost');

                        if ($isRetryable && $remaining > 1) {
                            $next = $this->circuitManager->getNextNode();
                            echo sprintf("[Torxy] Retrying via %s (%d attempts left)\n", $next->getIdentifier(), $remaining - 1);
                            return $attemptForward($next, $remaining - 1);
                        }

                        // Map timeout-like errors to 504 Gateway Timeout
                        if (str_contains($lower, 'timeout') || str_contains($lower, 'timed out')) {
                            return $this->errorResponse(504, 'Gateway Timeout');
                        }

                        return $this->errorResponse(502, 'Bad Gateway');
                    }
                );
            };

            // Start attempts using initial circuit from manager
            $first = $this->circuitManager->getNextNode();
            return $attemptForward($first, $maxAttempts);

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

    private function flattenHeaders(array $headers): array
    {
        $flat = [];
        foreach ($headers as $name => $values) {
            $flat[$name] = implode(', ', $values);
        }
        return $flat;
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