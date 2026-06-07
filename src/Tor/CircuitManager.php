<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;

class CircuitManager
{
    /** @var CircuitNode[] */
    private array $nodes = [];
    private int $currentIndex = 0;

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
     * Round-robin selection across all active circuits.
     */
    public function getNextNode(): CircuitNode
    {
        if (empty($this->nodes)) {
            throw new RuntimeException("No Tor circuits available in pool");
        }

        $node = $this->nodes[$this->currentIndex];
        $this->currentIndex = ($this->currentIndex + 1) % count($this->nodes);

        return $node;
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

        $this->nodes     = [];
        $this->currentIndex = 0;
    }

    public function getCircuitCount(): int
    {
        return count($this->nodes);
    }
}