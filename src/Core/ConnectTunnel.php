<?php

declare(strict_types=1);

namespace Torxy\Core;

use React\Promise\PromiseInterface;
use React\Socket\ConnectionInterface;
use Throwable;
use Torxy\Tor\CircuitNode;

/**
 * Establishes an HTTP CONNECT tunnel through a Tor circuit.
 *
 * The proxy never sees the tunnelled plaintext. After replying `200 Connection
 * Established` it only copies bytes, so the client negotiates TLS end-to-end with the
 * real target and validates that certificate itself — the proxy cannot read or alter it.
 */
final class ConnectTunnel
{
    public function __construct(
        private readonly RequestForwarder $requestForwarder
    ) {}

    /**
     * @param string $earlyData Bytes the client already sent after the request head.
     *
     * @return PromiseInterface<void> Rejects only while nothing has been written to the
     *         client, so the caller can still retry the dial on another circuit. Once the
     *         tunnel is up — or the client has hung up — it resolves and owns the socket.
     */
    public function open(
        ConnectionInterface $client,
        CircuitNode $circuit,
        string $host,
        int $port,
        string $earlyData = ''
    ): PromiseInterface {
        echo sprintf("[Torxy] CONNECT %s:%d via %s\n", $host, $port, $circuit->getIdentifier());

        // The client can hang up while we are still dialling out through Tor; without this
        // we would leak the upstream connection once it finally opens. The listener is
        // removed as soon as the dial settles so retries do not stack up listeners.
        $aborted = false;
        $onClientClose = function () use (&$aborted): void {
            $aborted = true;
        };
        $client->on('close', $onClientClose);

        return $this->requestForwarder->openTunnel($circuit, $host, $port)->then(
            function (ConnectionInterface $remote) use (
                $client,
                $onClientClose,
                $circuit,
                $earlyData,
                $host,
                $port,
                &$aborted
            ): void {
                $client->removeListener('close', $onClientClose);
                $circuit->markSuccess();

                if ($aborted) {
                    $remote->close();

                    return;
                }

                $client->write("HTTP/1.1 200 Connection Established\r\n\r\n");

                if ($earlyData !== '') {
                    $remote->write($earlyData);
                }

                $client->pipe($remote);
                $remote->pipe($client);

                $client->on('close', fn() => $remote->close());
                $remote->on('close', fn() => $client->close());

                // Lift the pause ConnectDemux applied before handing the tunnel over.
                $client->resume();

                echo sprintf("[Torxy] Tunnel established: %s:%d\n", $host, $port);
            },
            function (Throwable $e) use ($client, $onClientClose, $circuit, $host, $port, &$aborted): void {
                $client->removeListener('close', $onClientClose);

                // The dial failed, which implicates the circuit rather than the request.
                $circuit->markFailure();

                echo sprintf(
                    "[Torxy] CONNECT failed %s:%d via %s — %s\n",
                    $host,
                    $port,
                    $circuit->getIdentifier(),
                    $e->getMessage()
                );

                if ($aborted) {
                    // Nobody left to answer, and nothing worth retrying.
                    return;
                }

                // Nothing has been written to the client yet, so surface this to the caller
                // as a retryable failure instead of committing to an error response here.
                throw $e;
            }
        );
    }
}
