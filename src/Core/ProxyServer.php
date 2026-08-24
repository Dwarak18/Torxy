<?php

declare(strict_types=1);

namespace Torxy\Core;

use React\Http\HttpServer;
use React\Http\Message\Response;
use React\Http\Middleware\LimitConcurrentRequestsMiddleware;
use React\Http\Middleware\StreamingRequestMiddleware;
use React\Promise\PromiseInterface;
use React\Socket\ConnectionInterface;
use React\Socket\SocketServer;
use React\Stream\ReadableStreamInterface;
use React\EventLoop\LoopInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Torxy\Tor\CircuitManager;
use Torxy\Tor\CircuitNode;
use Torxy\Tor\SocksClient;
use Torxy\Security\AccessController;
use Torxy\Security\HeaderSanitizer;
use OverflowException;
use Throwable;

class ProxyServer
{
    /**
     * How many circuits a single client request may be tried on. Tor exits fail often
     * enough that one retry is routine; more than a few just delays a real error.
     */
    private const MAX_ATTEMPTS = 3;

    /**
     * Ceiling on requests handled at once. react/http applies a limit of its own only while
     * it is buffering bodies for us; StreamingRequestMiddleware turns that off, so the bound
     * becomes ours to set. Each in-flight request holds a Tor connection open.
     */
    private const MAX_CONCURRENT_REQUESTS = 100;

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
            // Stream request bodies instead of buffering them. react/http's default
            // buffering caps a body at 64 KiB and silently forwards an empty one past that,
            // so an upload would appear to succeed while arriving truncated. Enabling this
            // also disables react/http's automatic concurrency limit, which is why the
            // next line restates it.
            new StreamingRequestMiddleware(),
            new LimitConcurrentRequestsMiddleware(self::MAX_CONCURRENT_REQUESTS),
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

    /**
     * True when the upstream request failed because the *client's* upload died rather than
     * the circuit. react/http's Sender rejects with "request body closed unexpectedly" or
     * "request body reported an error" when a streamed request body ends early
     * (vendor/react/http/src/Io/Sender.php).
     */
    private function isClientBodyFailure(Throwable $e): bool
    {
        return str_contains(strtolower($e->getMessage()), 'request body');
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
     * @return Response|PromiseInterface<Response>
     */
    private function handleRequest(ServerRequestInterface $request): Response|PromiseInterface
    {
        $method = $request->getMethod();
        $target = $request->getRequestTarget();

        echo "[Torxy] Incoming: {$method} {$target}" . PHP_EOL;

        // Health check — bypasses Tor, confirms ReactPHP is working
        if ($target === '/healthz' || $target === 'http://healthz/') {
            return $this->discardBody($request, new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'status'   => 'ok',
                'circuits' => $this->circuitManager->getCircuitCount(),
                'healthy'  => $this->circuitManager->getHealthyCount(),
            ])));
        }

        // CONNECT is intercepted by ConnectDemux before the HTTP parser runs, so reaching
        // here means the demux was bypassed. Never forward it as an ordinary request.
        if ($method === 'CONNECT') {
            return $this->discardBody($request, $this->errorResponse(501, 'Not Implemented: CONNECT must be tunnelled'));
        }

        // Read Proxy-Authorization from the original request: HeaderSanitizer strips it
        // below so it is never forwarded upstream.
        $decision = $this->accessController->check(
            $request->getServerParams()['REMOTE_ADDR'] ?? null,
            $request->getHeaderLine('Proxy-Authorization')
        );

        if ($decision !== AccessController::ALLOW) {
            echo sprintf("[Torxy] Request denied (%s): %s %s\n", $decision, $method, $target);

            return $this->discardBody($request, $this->denyResponse($decision));
        }

        // Reject unforwardable methods up front. Letting SocksClient throw instead would
        // surface a client error as 502 and consume a circuit from the rotation.
        if (!in_array(strtoupper($method), SocksClient::SUPPORTED_METHODS, strict: true)) {
            return $this->discardBody($request, $this->errorResponse(501, "Not Implemented: unsupported method {$method}"));
        }

        $targetUrl = $this->resolveTargetUrl($request);

        if ($targetUrl === null) {
            return $this->discardBody($request, $this->errorResponse(400, 'Bad Request: cannot resolve target URL'));
        }

        try {
            $cleanHeaders = $this->headerSanitizer->strip(
                $this->flattenHeaders($request->getHeaders())
            );

            $bodyStream = $request->getBody();
            $size       = $bodyStream->getSize();

            // Empty body, or a buffered one because the streaming middleware is not in the
            // stack. Nothing to hold, so retries stay available.
            if ($size === 0 || !$bodyStream instanceof ReadableStreamInterface) {
                return $this->forward($targetUrl, $method, $cleanHeaders, (string) $bodyStream, self::MAX_ATTEMPTS);
            }

            // Too large to hold, or of unknown length: hand the stream to the forwarder and
            // accept a single attempt. Reading the bytes to enable a retry is what would
            // put an arbitrary upload into memory.
            if (!RequestBodyReader::isReplayable($size)) {
                echo sprintf(
                    "[Torxy] Streaming request body (%s bytes) — no retry available\n",
                    $size === null ? 'chunked, unknown' : (string) $size
                );

                return $this->forward($targetUrl, $method, $cleanHeaders, $bodyStream, 1);
            }

            // Small enough to hold: buffer it so a failed circuit can be retried on another.
            return RequestBodyReader::buffer($bodyStream, RequestBodyReader::MAX_REPLAYABLE_BYTES)->then(
                fn(string $body) => $this->forward($targetUrl, $method, $cleanHeaders, $body, self::MAX_ATTEMPTS),
                function (Throwable $e): Response {
                    echo "[Torxy] ERROR reading request body: {$e->getMessage()}\n";

                    // No circuit was involved, so nothing here reflects on circuit health.
                    return $e instanceof OverflowException
                        ? $this->errorResponse(413, 'Payload Too Large')
                        : $this->errorResponse(400, 'Bad Request: request body was not delivered');
                }
            );

        } catch (Throwable $e) {
            echo "[Torxy] ERROR: {$e->getMessage()}\n";
            return $this->errorResponse(502, 'Bad Gateway');
        }
    }

    /**
     * Pick a circuit and forward, retrying on another one up to $attempts times.
     *
     * @param array<string, string>          $headers
     * @param string|ReadableStreamInterface $body
     *
     * @return PromiseInterface<Response>
     */
    private function forward(
        string $url,
        string $method,
        array $headers,
        string|ReadableStreamInterface $body,
        int $attempts
    ): PromiseInterface {
        return $this->attemptForward($this->circuitManager->getNextNode(), $url, $method, $headers, $body, $attempts);
    }

    /**
     * @param array<string, string>          $headers
     * @param string|ReadableStreamInterface $body
     *
     * @return PromiseInterface<Response>
     */
    private function attemptForward(
        CircuitNode $circuit,
        string $url,
        string $method,
        array $headers,
        string|ReadableStreamInterface $body,
        int $remaining
    ): PromiseInterface {
        echo sprintf("[Torxy] Forwarding → %s via %s (attempts left: %d)\n", $url, $circuit->getIdentifier(), $remaining);

        return $this->requestForwarder->forward(
            circuit: $circuit,
            url:     $url,
            method:  $method,
            headers: $headers,
            body:    $body
        )->then(
            fn(ResponseInterface $response) => $this->relayResponse($response, $circuit),
            function (Throwable $e) use ($circuit, $url, $method, $headers, $body, $remaining) {
                echo "[Torxy] ERROR on forward: {$e->getMessage()}\n";

                // A client that abandons its upload breaks the request without telling us
                // anything about the circuit. Counting it would let repeated aborts drain
                // the whole pool, and there is nothing left to retry with either.
                if ($this->isClientBodyFailure($e)) {
                    return $this->errorResponse(400, 'Bad Request: request body was not delivered');
                }

                // SocksClient does not reject on error responses, so anything else that
                // lands here is a transport failure and counts against the circuit.
                $circuit->markFailure();

                // A stream body is already consumed, so it can never be replayed. $remaining
                // is 1 in that case; this guards the invariant rather than relying on it.
                if ($remaining > 1 && is_string($body)) {
                    $next = $this->circuitManager->getNextNode();
                    echo sprintf("[Torxy] Retrying via %s (%d attempts left)\n", $next->getIdentifier(), $remaining - 1);

                    return $this->attemptForward($next, $url, $method, $headers, $body, $remaining - 1);
                }

                if ($this->isTimeout($e)) {
                    return $this->errorResponse(504, 'Gateway Timeout');
                }

                return $this->errorResponse(502, 'Bad Gateway');
            }
        );
    }

    /**
     * Turn an upstream response into the one the client gets.
     *
     * The body is passed through as a stream, so this returns as soon as the head has
     * arrived and the bytes are relayed as they come. Content-Length survives sanitization,
     * which is what lets react/http frame the response with the upstream length instead of
     * re-chunking it.
     */
    private function relayResponse(ResponseInterface $response, CircuitNode $circuit): Response
    {
        echo "[Torxy] Response: HTTP {$response->getStatusCode()}\n";

        // The circuit carried a complete response head. What status the target chose to
        // send is none of the circuit's business.
        $circuit->markSuccess();

        // An informational response is not an answer — it is a mid-conversation signal that
        // react/http's client hands back as if it were final, leaving nothing to relay. The
        // usual trigger, a forwarded `Expect: 100-continue`, is stripped before the request
        // goes out; anything still arriving here is unsolicited and cannot be passed on.
        if ($response->getStatusCode() < 200) {
            echo "[Torxy] Upstream sent an informational response that cannot be relayed\n";

            return $this->errorResponse(502, 'Bad Gateway');
        }

        // Hop-by-hop headers describe the upstream connection, not this one. Left in place,
        // an upstream `Transfer-Encoding: chunked` would contradict the framing react/http
        // computes for the stream below.
        $forwardHeaders = $this->headerSanitizer->strip(
            $this->flattenHeaders($response->getHeaders())
        );

        $body = $response->getBody();

        if (!$body instanceof ReadableStreamInterface) {
            return new Response($response->getStatusCode(), $forwardHeaders, (string) $body);
        }

        // The head already arrived, so the circuit is recorded healthy. A failure part-way
        // through the body is still a real transport failure on that circuit and has to be
        // recorded, even though the client's response has already started.
        $body->on('error', function (Throwable $e) use ($circuit): void {
            echo sprintf("[Torxy] ERROR mid-body via %s: %s\n", $circuit->getIdentifier(), $e->getMessage());
            $circuit->markFailure();
        });

        return new Response($response->getStatusCode(), $forwardHeaders, $body);
    }

    /**
     * Answer without forwarding, throwing away whatever the client was uploading.
     *
     * A streaming request body that nobody reads leaves the connection waiting for bytes
     * that will never be consumed. Closing it discards the rest of the upload; the client
     * connection itself is protected by react/http and survives to receive $response.
     */
    private function discardBody(ServerRequestInterface $request, Response $response): Response
    {
        $body = $request->getBody();

        if ($body instanceof ReadableStreamInterface) {
            $body->close();
        }

        return $response;
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