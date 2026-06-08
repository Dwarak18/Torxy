<?php

declare(strict_types=1);

namespace Torxy\Core;

use Torxy\Tor\CircuitNode;
use Torxy\Tor\SocksClient;
use React\Promise\PromiseInterface;

class RequestForwarder
{
    private const REQUEST_TIMEOUT = 30.0;

    /**
     * Forward an HTTP request through the given Tor circuit's SOCKS5 proxy.
     *
     * @return PromiseInterface<\Psr\Http\Message\ResponseInterface>
     */
    public function forward(
        CircuitNode $circuit,
        string $url,
        string $method,
        array $headers,
        string $body = ''
    ): PromiseInterface {
        $client = new SocksClient(
            socksHost: $circuit->socksHost,
            socksPort: $circuit->socksPort,
            timeout:   self::REQUEST_TIMEOUT
        );

        return $client->forward($url, $method, $headers, $body);
    }
}