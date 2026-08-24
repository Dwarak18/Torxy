<?php

declare(strict_types=1);

namespace Torxy\Core;

use Torxy\Tor\CircuitNode;
use Torxy\Tor\SocksClient;
use React\Promise\PromiseInterface;
use React\Stream\ReadableStreamInterface;

class RequestForwarder
{
    /**
     * Budget for getting an upstream response *head* back. Browser cancels its timeout once
     * the head arrives, so with a streaming response this no longer bounds the body
     * transfer — deliberately, since any fixed budget would kill a legitimate large
     * download partway through.
     */
    private const REQUEST_TIMEOUT = 30.0;

    /**
     * Tunnel dials get a tighter budget than requests because they are retried: at three
     * attempts this keeps the worst case a client can wait at the same 30s a single
     * request allows. The circuit is already built by this point, so a SOCKS dial that has
     * not completed in 10s is far more likely dead than slow.
     */
    private const TUNNEL_TIMEOUT = 10.0;

    /**
     * Forward an HTTP request through the given Tor circuit's SOCKS5 proxy.
     *
     * @param array<string, string>          $headers
     * @param string|ReadableStreamInterface $body    Streamed straight through when it is too
     *                                                large to hold; see RequestBodyReader.
     *
     * @return PromiseInterface<\Psr\Http\Message\ResponseInterface>
     */
    public function forward(
        CircuitNode $circuit,
        string $url,
        string $method,
        array $headers,
        string|ReadableStreamInterface $body = ''
    ): PromiseInterface {
        $client = new SocksClient(
            socksHost: $circuit->socksHost,
            socksPort: $circuit->socksPort,
            timeout:   self::REQUEST_TIMEOUT
        );

        return $client->forward($url, $method, $headers, $body);
    }

    /**
     * Open a raw TCP tunnel to $host:$port through the given circuit, for CONNECT.
     *
     * @return PromiseInterface<\React\Socket\ConnectionInterface>
     */
    public function openTunnel(CircuitNode $circuit, string $host, int $port): PromiseInterface
    {
        $client = new SocksClient(
            socksHost: $circuit->socksHost,
            socksPort: $circuit->socksPort,
            timeout:   self::TUNNEL_TIMEOUT
        );

        return $client->connectTcp($host, $port);
    }
}