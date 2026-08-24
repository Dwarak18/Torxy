<?php

declare(strict_types=1);

namespace Torxy\Tor;

use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;
use React\Socket\ConnectionInterface;
use Throwable;

/**
 * Brings circuits that have been taken out of rotation back into it.
 *
 * Failures are recorded where they happen — a failed forward or a failed CONNECT dial —
 * so this only has to answer the opposite question: can a circuit that is currently out
 * of rotation carry traffic again? It probes by opening a real TCP connection through the
 * circuit's SOCKS port, which exercises the entire path: the Tor daemon, the circuit
 * build, and exit reachability.
 *
 * Healthy circuits are deliberately not probed. Live traffic already reports on them, and
 * synthetic probes would only add load and a periodic, fingerprintable pattern.
 */
final class CircuitHealthMonitor
{
    /**
     * Probed by IP so the check does not depend on exit DNS, and on 443 because exit
     * policies that permit anything permit that.
     */
    public const DEFAULT_PROBE_TARGET = '1.1.1.1:443';

    private const DEFAULT_PROBE_TIMEOUT = 10.0;

    private ?TimerInterface $timer = null;

    /**
     * Circuits with a probe in flight, keyed by identifier. Without this a slow probe
     * would be re-issued on every tick and pile up connections against a dead circuit.
     *
     * @var array<string, true>
     */
    private array $inFlight = [];

    public function __construct(
        private readonly CircuitManager $circuitManager,
        private readonly string $probeTarget = self::DEFAULT_PROBE_TARGET,
        private readonly float $probeTimeout = self::DEFAULT_PROBE_TIMEOUT
    ) {}

    public function start(LoopInterface $loop, int $intervalSeconds): void
    {
        if ($intervalSeconds <= 0) {
            echo "[Torxy] Circuit health monitor: disabled" . PHP_EOL;

            return;
        }

        if (self::parseTarget($this->probeTarget) === null) {
            echo sprintf(
                "[Torxy] WARNING: invalid health probe target '%s' — monitor disabled\n",
                $this->probeTarget
            );

            return;
        }

        $this->timer = $loop->addPeriodicTimer(
            $intervalSeconds,
            fn() => $this->probeUnhealthy()
        );

        echo sprintf(
            "[Torxy] Circuit health monitor: every %ds via %s\n",
            $intervalSeconds,
            $this->probeTarget
        );
    }

    public function stop(LoopInterface $loop): void
    {
        if ($this->timer !== null) {
            $loop->cancelTimer($this->timer);
            $this->timer = null;
        }
    }

    private function probeUnhealthy(): void
    {
        foreach ($this->circuitManager->getNodes() as $node) {
            if ($node->isHealthy() || isset($this->inFlight[$node->getIdentifier()])) {
                continue;
            }

            $this->probe($node);
        }
    }

    private function probe(CircuitNode $node): void
    {
        $target = self::parseTarget($this->probeTarget);

        if ($target === null) {
            return;
        }

        [$host, $port] = $target;
        $id = $node->getIdentifier();
        $this->inFlight[$id] = true;

        try {
            $client = new SocksClient(
                socksHost: $node->socksHost,
                socksPort: $node->socksPort,
                timeout:   $this->probeTimeout
            );

            $promise = $client->connectTcp($host, $port);
        } catch (Throwable $e) {
            unset($this->inFlight[$id]);
            echo sprintf("[Torxy] Health probe could not start for %s — %s\n", $id, $e->getMessage());

            return;
        }

        $promise->then(
            function (ConnectionInterface $connection) use ($node, $id): void {
                unset($this->inFlight[$id]);

                // The handshake completing is the whole result; nothing is sent through it.
                $connection->close();
                $node->markSuccess();
            },
            function (Throwable $e) use ($id): void {
                unset($this->inFlight[$id]);

                // Still down. The circuit keeps its failure streak and is probed again
                // on the next tick.
                echo sprintf("[Torxy] Health probe failed for %s — %s\n", $id, $e->getMessage());
            }
        );
    }

    /**
     * @return array{0: string, 1: int}|null
     */
    private static function parseTarget(string $target): ?array
    {
        $separator = strrpos($target, ':');

        if ($separator === false || $separator === 0) {
            return null;
        }

        $host = substr($target, 0, $separator);
        $port = substr($target, $separator + 1);

        if ($host === '' || !ctype_digit($port)) {
            return null;
        }

        $portNumber = (int) $port;

        if ($portNumber < 1 || $portNumber > 65535) {
            return null;
        }

        return [$host, $portNumber];
    }
}
