<?php

declare(strict_types=1);

namespace Torxy\Tor;

use React\EventLoop\LoopInterface;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use React\Socket\ConnectionInterface;
use React\Socket\ConnectorInterface;
use RuntimeException;
use Throwable;

/**
 * Speaks the Tor control protocol.
 *
 * Two paths exist deliberately. The blocking one is used once per circuit at startup,
 * before the event loop runs, where blocking is harmless and the simpler code wins. The
 * async one is used for every rotation afterwards, because by then blocking would stall
 * every in-flight request on the loop.
 */
class TorController
{
    /**
     * Bound on blocking control reads. Without it a control port that accepts the TCP
     * connection but never answers would stall startup for default_socket_timeout.
     */
    private const READ_TIMEOUT = 5;

    /** Bound on a whole async control session: connect, authenticate, signal, quit. */
    private const SESSION_TIMEOUT = 10.0;

    private mixed $socket = null;

    public function __construct(
        private readonly string $host,
        private readonly int $controlPort,
        private readonly string $password
    ) {}

    public function connect(): void
    {
        $this->socket = fsockopen(
            $this->host,
            $this->controlPort,
            $errno,
            $errstr,
            timeout: 5
        );

        if ($this->socket === false) {
            throw new RuntimeException(
                "Cannot connect to Tor control port [{$this->host}:{$this->controlPort}]: {$errstr} ({$errno})"
            );
        }

        stream_set_timeout($this->socket, self::READ_TIMEOUT);

        $this->authenticate();
    }

    public function requestNewCircuit(): void
    {
        $response = $this->sendCommand('SIGNAL NEWNYM');

        if (!str_starts_with($response, '250')) {
            throw new RuntimeException("Circuit rotation failed: {$response}");
        }
    }

    /**
     * Signal NEWNYM over a short-lived control connection, without blocking the loop.
     *
     * A fresh connection per rotation rather than the long-lived startup socket: that
     * socket is driven by blocking reads, and interleaving those with loop-driven reads on
     * the same stream would race for the same bytes.
     *
     * @return PromiseInterface<null>
     */
    public function requestNewCircuitAsync(
        ConnectorInterface $connector,
        LoopInterface $loop,
        float $timeout = self::SESSION_TIMEOUT
    ): PromiseInterface {
        $deferred = new Deferred();

        $timer = $loop->addTimer($timeout, function () use ($deferred, $timeout): void {
            $deferred->reject(new RuntimeException(sprintf(
                'Tor control session for %s timed out after %.0fs',
                $this->getIdentifier(),
                $timeout
            )));
        });

        // Settling more than once is a no-op, so the timeout and the session race safely.
        $settle = function (?Throwable $error) use ($deferred, $loop, $timer): void {
            $loop->cancelTimer($timer);

            $error === null ? $deferred->resolve(null) : $deferred->reject($error);
        };

        $connector->connect(sprintf('tcp://%s:%d', $this->host, $this->controlPort))->then(
            fn(ConnectionInterface $connection) => $this->runSession($connection, $settle),
            fn(Throwable $e) => $settle($e)
        );

        return $deferred->promise();
    }

    public function isConnected(): bool
    {
        return $this->socket !== null && is_resource($this->socket);
    }

    public function disconnect(): void
    {
        if ($this->isConnected()) {
            $this->sendCommand('QUIT');
            fclose($this->socket);
            $this->socket = null;
        }
    }

    public function getIdentifier(): string
    {
        return "{$this->host}:{$this->controlPort}";
    }

    /**
     * Drive AUTHENTICATE → SIGNAL NEWNYM → QUIT over an open control connection.
     *
     * @param callable(?Throwable): void $settle
     */
    private function runSession(ConnectionInterface $connection, callable $settle): void
    {
        $buffer = '';
        $awaiting = 'AUTHENTICATE';

        $connection->on('data', function (string $chunk) use (
            &$buffer,
            &$awaiting,
            $connection,
            $settle
        ): void {
            $buffer .= $chunk;

            // Replies are CRLF-terminated lines. `250-` and `250+` mark continuation lines;
            // only `250 ` closes a reply, so state must not advance on the others.
            while (($eol = strpos($buffer, "\r\n")) !== false) {
                $line = substr($buffer, 0, $eol);
                $buffer = substr($buffer, $eol + 2);

                if (str_starts_with($line, '250-') || str_starts_with($line, '250+')) {
                    continue;
                }

                if (!str_starts_with($line, '250 ')) {
                    $settle(new RuntimeException("Tor rejected {$awaiting} on {$this->getIdentifier()}: {$line}"));
                    $connection->close();

                    return;
                }

                if ($awaiting === 'AUTHENTICATE') {
                    $awaiting = 'SIGNAL NEWNYM';
                    $connection->write("SIGNAL NEWNYM\r\n");

                    continue;
                }

                // NEWNYM is acknowledged: the rotation is done. QUIT is sent for a clean
                // close, but its reply is no longer interesting.
                $awaiting = 'QUIT';
                $settle(null);
                $connection->end("QUIT\r\n");

                return;
            }
        });

        $connection->on('error', fn(Throwable $e) => $settle($e));

        $connection->on('close', function () use (&$awaiting, $settle): void {
            if ($awaiting !== 'QUIT') {
                $settle(new RuntimeException(
                    "Tor control connection to {$this->getIdentifier()} closed while awaiting {$awaiting}"
                ));
            }
        });

        // The control port sends no greeting — it stays silent until spoken to.
        $connection->write(sprintf("AUTHENTICATE \"%s\"\r\n", $this->password));
    }

    private function authenticate(): void
    {
        $response = $this->sendCommand(sprintf('AUTHENTICATE "%s"', $this->password));

        if (!str_starts_with($response, '250')) {
            throw new RuntimeException("Tor authentication rejected: {$response}");
        }
    }

    private function sendCommand(string $command): string
    {
        if (!$this->isConnected()) {
            throw new RuntimeException("Not connected to Tor control port");
        }

        fwrite($this->socket, $command . "\r\n");

        return (string) fread($this->socket, 1024);
    }
}
