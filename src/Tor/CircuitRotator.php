<?php

declare(strict_types=1);

namespace Torxy\Tor;

use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;
use React\Socket\Connector;
use React\Socket\ConnectorInterface;
use Throwable;

/**
 * Periodically signals NEWNYM on every circuit so exit IPs do not persist for the life of
 * the process.
 *
 * NEWNYM asks Tor to use fresh circuits for *subsequent* streams; it does not tear down
 * streams already in flight. So a rotation never disturbs a request that is mid-flight,
 * and the new exit IP shows up on the requests that follow.
 *
 * `MaxCircuitDirtiness` in torrc governs the same thing from Tor's side. This exists
 * because that setting is a ceiling on circuit age, not a guarantee of rotation cadence,
 * and because a proxy operator wants one knob they can see in the log.
 */
final class CircuitRotator
{
    private ?TimerInterface $timer = null;
    private ConnectorInterface $connector;

    /**
     * Circuits with a rotation in flight, keyed by identifier. A control port that has
     * stopped answering would otherwise accumulate one pending session per tick.
     *
     * @var array<string, true>
     */
    private array $inFlight = [];

    public function __construct(
        private readonly CircuitManager $circuitManager,
        private readonly LoopInterface $loop,
        ?ConnectorInterface $connector = null
    ) {
        // Plain TCP to the control port: it is reached over the container network, never
        // through Tor itself, so no SOCKS connector belongs here.
        $this->connector = $connector ?? new Connector(['timeout' => 5.0], $loop);
    }

    /**
     * Rotate every circuit every $intervalSeconds. Also makes the `per_request` strategy
     * non-blocking by handing CircuitManager an async dispatcher to use instead of its
     * blocking control-port call.
     */
    public function start(int $intervalSeconds): void
    {
        $this->circuitManager->setRotationDispatcher(
            fn(CircuitNode $node) => $this->rotate($node)
        );

        if ($intervalSeconds <= 0) {
            echo "[Torxy] Timed circuit rotation: disabled" . PHP_EOL;

            return;
        }

        $this->timer = $this->loop->addPeriodicTimer($intervalSeconds, fn() => $this->rotateAll());

        echo sprintf("[Torxy] Timed circuit rotation: every %ds\n", $intervalSeconds);
    }

    public function stop(): void
    {
        if ($this->timer !== null) {
            $this->loop->cancelTimer($this->timer);
            $this->timer = null;
        }
    }

    public function rotateAll(): void
    {
        foreach ($this->circuitManager->getNodes() as $node) {
            $this->rotate($node);
        }
    }

    public function rotate(CircuitNode $node): void
    {
        $id = $node->getIdentifier();

        if (isset($this->inFlight[$id])) {
            return;
        }

        $this->inFlight[$id] = true;

        $node->controller->requestNewCircuitAsync($this->connector, $this->loop)->then(
            function () use ($id): void {
                unset($this->inFlight[$id]);
                echo "[Torxy] Circuit rotated: {$id}" . PHP_EOL;
            },
            function (Throwable $e) use ($id): void {
                unset($this->inFlight[$id]);

                // A failed rotation is not fatal: the circuit still carries traffic on its
                // current exit, and the next tick tries again.
                echo sprintf("[Torxy] WARNING: rotation failed for %s — %s\n", $id, $e->getMessage());
            }
        );
    }
}
