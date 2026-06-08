<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;
use React\Promise\PromiseInterface;
use React\Http\Browser;
use React\Socket\Connector;
use Clue\React\Socks\Client as ClueSocksClient;

class SocksClient
{
    private const DEFAULT_TIMEOUT = 30.0;
    private Browser $browser;

    public function __construct(
        string $socksHost,
        int $socksPort,
        float $timeout = self::DEFAULT_TIMEOUT
    ) {
        // Configure SOCKS proxy connector
        $proxy = new ClueSocksClient("socks5://{$socksHost}:{$socksPort}");
        
        $connector = new Connector([
            'tcp' => $proxy,
            'timeout' => $timeout,
            'dns' => false // Force hostname resolution inside Tor (SOCKS5H behavior)
        ]);

        // Create an async HTTP browser using the SOCKS connector
        $this->browser = (new Browser($connector))
            ->withTimeout($timeout)
            ->withFollowRedirects(false); // We want the client to receive the standard redirect
    }

    /**
     * Forward an HTTP request through the Tor SOCKS5 proxy asynchronously.
     * SOCKS5H resolves DNS inside Tor — prevents DNS leaks.
     *
     * @return PromiseInterface<\Psr\Http\Message\ResponseInterface>
     */
    public function forward(
        string $url,
        string $method,
        array $headers,
        string $body = ''
    ): PromiseInterface {
        $this->validateUrl($url);
        $this->validateMethod($method);

        return $this->browser->request(
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
        $allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

        if (!in_array(strtoupper($method), $allowed, strict: true)) {
            throw new RuntimeException("Unsupported HTTP method: {$method}");
        }
    }
}