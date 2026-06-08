<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;

class TorController
{
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

        $this->authenticate();
    }

    public function requestNewCircuit(): void
    {
        $response = $this->sendCommand('SIGNAL NEWNYM');

        if (!str_starts_with($response, '250')) {
            throw new RuntimeException("Circuit rotation failed: {$response}");
        }
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

    private function authenticate(): void
    {
        // Flush any banner message from Tor before authenticating
        fread($this->socket, 1024);

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