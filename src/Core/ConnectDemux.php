<?php

declare(strict_types=1);

namespace Torxy\Core;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use React\Socket\ConnectionInterface;
use React\Socket\ServerInterface;
use Throwable;

/**
 * Splits incoming connections into ordinary proxy requests and CONNECT tunnels.
 *
 * `React\Http\HttpServer` models traffic as request/response pairs, which cannot express
 * a CONNECT tunnel: once established, the proxy must copy raw bytes in both directions
 * for the lifetime of the connection. So this class sits between the socket and the HTTP
 * server. It peeks at the request line, routes CONNECT to a tunnel handler, and re-emits
 * every other connection — with the peeked bytes replayed — so `HttpServer` parses it as
 * it normally would.
 *
 * It implements ServerInterface because that is all `HttpServer::listen()` requires: the
 * server only subscribes to the `connection` event.
 */
final class ConnectDemux extends EventEmitter implements ServerInterface
{
    /** Method token we need to see in full before we can rule CONNECT in or out. */
    private const CONNECT_PREFIX = 'CONNECT ';

    /** Ceiling on a CONNECT request head, so a client cannot make us buffer forever. */
    private const MAX_HEAD_BYTES = 16384;

    /** How long a connection may stay silent before we stop waiting to classify it. */
    private const PEEK_TIMEOUT = 10.0;

    /** @var callable(ConnectionInterface, ConnectRequest): void */
    private $onConnect;

    /**
     * @param callable(ConnectionInterface, ConnectRequest): void $onConnect
     */
    public function __construct(
        private readonly ServerInterface $socket,
        private readonly LoopInterface $loop,
        callable $onConnect
    ) {
        $this->onConnect = $onConnect;

        $this->socket->on('connection', function (ConnectionInterface $connection): void {
            $this->classify($connection);
        });

        $this->socket->on('error', function (Throwable $e): void {
            $this->emit('error', [$e]);
        });
    }

    private function classify(ConnectionInterface $connection): void
    {
        $buffer  = '';
        $settled = false;

        $timer = $this->loop->addTimer(self::PEEK_TIMEOUT, function () use ($connection, &$settled): void {
            if ($settled) {
                return;
            }

            $settled = true;
            $connection->close();
        });

        $onData = function (string $chunk) use ($connection, $timer, &$buffer, &$onData, &$settled): void {
            if ($settled) {
                return;
            }

            $buffer .= $chunk;

            // Still can't tell CONNECT from any other method.
            if (strlen($buffer) < strlen(self::CONNECT_PREFIX)) {
                return;
            }

            if (strncmp($buffer, self::CONNECT_PREFIX, strlen(self::CONNECT_PREFIX)) !== 0) {
                $settled = true;
                $this->loop->cancelTimer($timer);
                $connection->removeListener('data', $onData);

                // Hand the connection to HttpServer, then replay what we consumed. Both
                // steps are synchronous, so the parser is listening before the replay.
                $this->emit('connection', [$connection]);
                $connection->emit('data', [$buffer]);

                return;
            }

            // For CONNECT the entire head must be consumed before piping starts, or
            // leftover header bytes would reach the target as tunnel payload.
            $headEnd = strpos($buffer, "\r\n\r\n");

            if ($headEnd === false) {
                if (strlen($buffer) > self::MAX_HEAD_BYTES) {
                    $settled = true;
                    $this->loop->cancelTimer($timer);
                    $this->reject($connection, '431 Request Header Fields Too Large');
                }

                return;
            }

            $settled = true;
            $this->loop->cancelTimer($timer);
            $connection->removeListener('data', $onData);

            $connectRequest = ConnectRequest::fromHead(
                substr($buffer, 0, $headEnd),
                substr($buffer, $headEnd + 4)
            );

            if ($connectRequest === null) {
                $this->reject($connection, '400 Bad Request');

                return;
            }

            // Hold further reads until the tunnel is piped. Anything the client sends
            // while we dial out through Tor would otherwise arrive with no listener
            // attached and be dropped.
            $connection->pause();

            ($this->onConnect)($connection, $connectRequest);
        };

        $connection->on('data', $onData);
    }

    private function reject(ConnectionInterface $connection, string $status): void
    {
        $connection->write("HTTP/1.1 {$status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        $connection->end();
    }

    public function getAddress(): ?string
    {
        return $this->socket->getAddress();
    }

    public function pause(): void
    {
        $this->socket->pause();
    }

    public function resume(): void
    {
        $this->socket->resume();
    }

    public function close(): void
    {
        $this->socket->close();
    }
}
