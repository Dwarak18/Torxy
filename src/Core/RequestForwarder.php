<?php

declare(strict_types=1);

namespace Torxy\Core;

use Torxy\Tor\CircuitNode;
use Torxy\Tor\SocksClient;

class RequestForwarder
{
    private const REQUEST_TIMEOUT = 30;

    /**
     * Forward an HTTP request through the given Tor circuit's SOCKS5 proxy.
     *
     * @return array{status: int, headers: string, body: string}
     */
    public function forward(
        CircuitNode $circuit,
        string $url,
        string $method,
        array $headers,
        string $body = ''
    ): array {
        $client = new SocksClient(
            socksHost: $circuit->socksHost,
            socksPort: $circuit->socksPort,
            timeout:   self::REQUEST_TIMEOUT
        );

        return $client->forward($url, $method, $headers, $body);
    }
}