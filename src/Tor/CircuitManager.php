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

    public function __construct(string $strategy = self::STRATEGY_ROUND_ROBIN)
    {
        $this->strategy = $strategy;
        echo sprintf("[Torxy] Rotation strategy: %s\n", $this->strategy);
    }

    public function registerCircuit(
        TorController $controller,
        string $socksHost,
        int $socksPort
    ): void {
        $controller->connect();
        $this->nodes[] = new CircuitNode($controller, $socksHost, $socksPort);

        echo "[Torxy] Circuit registered: {$controller->getIdentifier()}" . PHP_EOL;
    }

    /**
     * Selects the next CircuitNode according to configured strategy.
     */
    public function getNextNode(): CircuitNode
    {
        if (empty($this->nodes)) {
            throw new RuntimeException("No Tor circuits available in pool");
        }

        switch ($this->strategy) {
            case self::STRATEGY_RANDOM:
                $idx = array_rand($this->nodes);
                $this->currentIndex = ($idx + 1) % count($this->nodes);
                return $this->nodes[$idx];

            case self::STRATEGY_PER_REQUEST:
                // Use round-robin selection but request a fresh circuit on the controller
                $node = $this->nodes[$this->currentIndex];
                try {
                    $node->controller->requestNewCircuit();
                } catch (\Throwable $e) {
                    // Log and continue — failure to rotate shouldn't break request handling
                    echo "[Torxy] WARNING: failed to request new circuit: {$e->getMessage()}" . PHP_EOL;
                }
                $this->currentIndex = ($this->currentIndex + 1) % count($this->nodes);
                return $node;

            case self::STRATEGY_ROUND_ROBIN:
            default:
                $node = $this->nodes[$this->currentIndex];
                $this->currentIndex = ($this->currentIndex + 1) % count($this->nodes);
                return $node;
        }
    }

    public function rotateAll(): void
    {
        foreach ($this->nodes as $node) {
            $node->controller->requestNewCircuit();
        }

        sleep(1);
        echo "[Torxy] All circuits rotated" . PHP_EOL;
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

    public function getStrategy(): string
    {
        return $this->strategy;
    }
}