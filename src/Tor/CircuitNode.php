<?php

declare(strict_types=1);

namespace Torxy\Tor;

/**
 * Represents one Tor circuit — control interface + SOCKS5 connection info.
 *
 * Also carries the circuit's health verdict. A single failure means little: Tor exits go
 * away constantly and any one dial can lose the race. Only a run of consecutive failures
 * takes a circuit out of rotation, and any success clears the count.
 */
class CircuitNode
{
    /** Consecutive transport failures before a circuit is taken out of rotation. */
    public const DEFAULT_FAILURE_THRESHOLD = 3;

    private int $consecutiveFailures = 0;
    private bool $healthy = true;

    public function __construct(
        public readonly TorController $controller,
        public readonly string $socksHost,
        public readonly int $socksPort,
        private readonly int $failureThreshold = self::DEFAULT_FAILURE_THRESHOLD
    ) {}

    public function getIdentifier(): string
    {
        return $this->controller->getIdentifier();
    }

    public function isHealthy(): bool
    {
        return $this->healthy;
    }

    public function getConsecutiveFailures(): int
    {
        return $this->consecutiveFailures;
    }

    /**
     * Record that traffic went through this circuit, clearing any failure streak.
     */
    public function markSuccess(): void
    {
        $this->consecutiveFailures = 0;

        if (!$this->healthy) {
            $this->healthy = true;
            echo "[Torxy] Circuit recovered: {$this->getIdentifier()}" . PHP_EOL;
        }
    }

    /**
     * Record a transport-level failure. Only pass failures that implicate the circuit —
     * an error response from the target says nothing about the path that carried it.
     */
    public function markFailure(): void
    {
        $this->consecutiveFailures++;

        if ($this->healthy && $this->consecutiveFailures >= $this->failureThreshold) {
            $this->healthy = false;

            echo sprintf(
                "[Torxy] Circuit unhealthy after %d consecutive failures: %s\n",
                $this->consecutiveFailures,
                $this->getIdentifier()
            );
        }
    }
}
