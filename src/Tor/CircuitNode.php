<?php

declare(strict_types=1);

namespace Torxy\Tor;

/**
 * Represents one Tor circuit — control interface + SOCKS5 connection info.
 */
class CircuitNode
{
    public function __construct(
        public readonly TorController $controller,
        public readonly string $socksHost,
        public readonly int $socksPort
    ) {}

    public function getIdentifier(): string
    {
        return $this->controller->getIdentifier();
    }
}