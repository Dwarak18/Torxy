<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;

class CircuitManager
{
    public const STRATEGY_ROUND_ROBIN = 'round_robin';
    public const STRATEGY_RANDOM = 'random';
    public const STRATEGY_PER_REQUEST = 'per_request';

    /** @var CircuitNode[] */
    private array $nodes = [];
    private int $currentIndex = 0;
    private string $strategy;
    private int $failureThreshold;

    /** @var (callable(CircuitNode): void)|null */
    private $rotationDispatcher = null;

    public function __construct(
        string $strategy = self::STRATEGY_ROUND_ROBIN,
        int $failureThreshold = CircuitNode::DEFAULT_FAILURE_THRESHOLD
    ) {
        $this->strategy = $strategy;
        $this->failureThreshold = max(1, $failureThreshold);

        echo sprintf("[Torxy] Rotation strategy: %s\n", $this->strategy);
    }

    public function registerCircuit(
        TorController $controller,
        string $socksHost,
        int $socksPort
    ): void {
        $controller->connect();
        $this->nodes[] = new CircuitNode($controller, $socksHost, $socksPort, $this->failureThreshold);

        echo "[Torxy] Circuit registered: {$controller->getIdentifier()}" . PHP_EOL;
    }

    /**
     * Selects the next CircuitNode according to configured strategy, preferring circuits
     * that are currently healthy.
     */
    public function getNextNode(): CircuitNode
    {
        if ($this->nodes === []) {
            throw new RuntimeException("No Tor circuits available in pool");
        }

        return match ($this->strategy) {
            self::STRATEGY_RANDOM      => $this->selectRandom(),
            self::STRATEGY_PER_REQUEST => $this->selectPerRequest(),
            default                    => $this->selectRoundRobin(),
        };
    }

    /**
     * Supplies a non-blocking way to signal NEWNYM, used by the `per_request` strategy.
     * Set by CircuitRotator at startup; without it that strategy has no way to rotate
     * without blocking the event loop, so it does not try.
     *
     * @param callable(CircuitNode): void $dispatcher
     */
    public function setRotationDispatcher(callable $dispatcher): void
    {
        $this->rotationDispatcher = $dispatcher;
    }

    /**
     * @return CircuitNode[]
     */
    public function getNodes(): array
    {
        return $this->nodes;
    }

    public function disconnectAll(): void
    {
        foreach ($this->nodes as $node) {
            $node->controller->disconnect();
        }

        $this->nodes = [];
        $this->currentIndex = 0;
    }

    public function getCircuitCount(): int
    {
        return count($this->nodes);
    }

    public function getHealthyCount(): int
    {
        return count(array_filter($this->nodes, static fn(CircuitNode $node): bool => $node->isHealthy()));
    }

    public function getStrategy(): string
    {
        return $this->strategy;
    }

    private function selectRoundRobin(): CircuitNode
    {
        $count = count($this->nodes);

        // One full sweep looking for a healthy circuit. The index advances on every visit,
        // so unhealthy circuits are skipped without stalling the rotation.
        for ($i = 0; $i < $count; $i++) {
            $node = $this->advance();

            if ($node->isHealthy()) {
                return $node;
            }
        }

        // Every circuit is marked down. Hand one back anyway: a stale health verdict must
        // not take the whole proxy offline, and a real attempt is what re-tests the path.
        return $this->advance();
    }

    private function selectRandom(): CircuitNode
    {
        $healthy = array_values(array_filter(
            $this->nodes,
            static fn(CircuitNode $node): bool => $node->isHealthy()
        ));

        $pool = $healthy !== [] ? $healthy : $this->nodes;

        return $pool[array_rand($pool)];
    }

    private function selectPerRequest(): CircuitNode
    {
        $node = $this->selectRoundRobin();

        // Fire-and-forget: NEWNYM only affects streams opened after Tor acts on it, so
        // waiting here would delay the request without changing the exit it goes out on.
        // The fresh exit lands on the requests that follow.
        if ($this->rotationDispatcher !== null) {
            ($this->rotationDispatcher)($node);
        }

        return $node;
    }

    private function advance(): CircuitNode
    {
        $node = $this->nodes[$this->currentIndex];
        $this->currentIndex = ($this->currentIndex + 1) % count($this->nodes);

        return $node;
    }
}
