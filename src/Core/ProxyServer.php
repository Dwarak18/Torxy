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

    private function handleRequest(ServerRequestInterface $request): Response
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
            $circuit      = $this->circuitManager->getNextNode();
            $cleanHeaders = $this->headerSanitizer->strip(
                $this->flattenHeaders($request->getHeaders())
            );

            echo sprintf(
                "[Torxy] Forwarding → %s via %s\n",
                $targetUrl,
                $circuit->getIdentifier()
            );

            $result = $this->requestForwarder->forward(
                circuit: $circuit,
                url:     $targetUrl,
                method:  $method,
                headers: $cleanHeaders,
                body:    (string) $request->getBody()
            );

            echo "[Torxy] Response: HTTP {$result['status']}\n";

            return new Response($result['status'], [], $result['body']);

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