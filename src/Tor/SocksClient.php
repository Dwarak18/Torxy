<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;
use React\Promise\PromiseInterface;
use React\Http\Browser;
use React\Socket\Connector;
use React\Socket\ConnectorInterface;
use React\Stream\ReadableStreamInterface;
use Clue\React\Socks\Client as ClueSocksClient;

class SocksClient
{
    private const DEFAULT_TIMEOUT = 30.0;

    /** Methods this client can forward. CONNECT is absent by design — it is tunnelled. */
    public const SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

    private Browser $browser;
    private ConnectorInterface $connector;

    public function __construct(
        string $socksHost,
        int $socksPort,
        float $timeout = self::DEFAULT_TIMEOUT
    ) {
        // Configure SOCKS proxy connector
        $proxy = new ClueSocksClient("socks5://{$socksHost}:{$socksPort}");

        $this->connector = new Connector([
            'tcp' => $proxy,
            'timeout' => $timeout,
            'dns' => false // Force hostname resolution inside Tor (SOCKS5H behavior)
        ]);

        // Create an async HTTP browser using the SOCKS connector
        $this->browser = (new Browser($this->connector))
            ->withTimeout($timeout)
            ->withFollowRedirects(false)      // We want the client to receive the standard redirect
            // A proxy relays the target's answer verbatim, including 404 and 503. Browser
            // rejects those by default, which would both hide the real status behind a 502
            // and make a healthy circuit look like a failing one.
            ->withRejectErrorResponse(false);
    }

    /**
     * Open a raw TCP connection through Tor, for CONNECT tunnelling.
     *
     * The hostname is handed to the SOCKS proxy unresolved, so DNS happens inside Tor
     * exactly as it does for plain HTTP forwarding.
     *
     * @return PromiseInterface<\React\Socket\ConnectionInterface>
     */
    public function connectTcp(string $host, int $port): PromiseInterface
    {
        if ($host === '' || $port < 1 || $port > 65535) {
            throw new RuntimeException("Invalid tunnel target: {$host}:{$port}");
        }

        // An IPv6 literal has to be re-bracketed before it goes into a URI, or the address'
        // own colons make the port ambiguous.
        $authority = str_contains($host, ':') ? "[{$host}]" : $host;

        return $this->connector->connect(sprintf('tcp://%s:%d', $authority, $port));
    }

    /**
     * Forward an HTTP request through the Tor SOCKS5 proxy asynchronously.
     * SOCKS5H resolves DNS inside Tor — prevents DNS leaks.
     *
     * The returned response is *streaming*: it resolves as soon as the response head has
     * arrived, and its body is a ReadableStreamInterface the caller must consume. Buffering
     * it here instead would cap responses at Browser's 16 MiB limit and hold the whole
     * transfer in memory — for a proxy, whose only job is to pass bytes along, both are
     * pure cost.
     *
     * @param array<string, string>                $headers
     * @param string|ReadableStreamInterface       $body    A stream is sent with the client's
     *                                                      own Content-Length, or chunked
     *                                                      when its length is unknown.
     *
     * @return PromiseInterface<\Psr\Http\Message\ResponseInterface>
     */
    public function forward(
        string $url,
        string $method,
        array $headers,
        string|ReadableStreamInterface $body = ''
    ): PromiseInterface {
        $this->validateUrl($url);
        $this->validateMethod($method);

        return $this->browser->requestStreaming(
            $method,
            $url,
            $headers, // react/http standardizes headers array
            $body
        );
    }

    private function validateUrl(string $url): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new RuntimeException("Invalid target URL provided");
        }
    }

    private function validateMethod(string $method): void
    {
        if (!in_array(strtoupper($method), self::SUPPORTED_METHODS, strict: true)) {
            throw new RuntimeException("Unsupported HTTP method: {$method}");
        }
    }
}