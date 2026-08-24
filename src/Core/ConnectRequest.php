<?php

declare(strict_types=1);

namespace Torxy\Core;

/**
 * A parsed CONNECT request head.
 *
 * Parsing lives here rather than in ConnectDemux so it stays a pure, unit-testable
 * function: malformed authority forms are the kind of thing that is easy to get subtly
 * wrong and awkward to exercise through a live socket.
 */
final class ConnectRequest
{
    /**
     * @param array<string, string> $headers Header names lowercased.
     */
    private function __construct(
        public readonly string $host,
        public readonly int $port,
        public readonly array $headers,
        public readonly string $earlyData
    ) {}

    /**
     * Parse a CONNECT request head (everything before the terminating CRLFCRLF).
     *
     * Returns null when the request is not a well-formed CONNECT in authority-form.
     */
    public static function fromHead(string $head, string $earlyData = ''): ?self
    {
        $lines = explode("\r\n", $head);
        $requestLine = array_shift($lines);

        if ($requestLine === null) {
            return null;
        }

        $parts = explode(' ', trim($requestLine));

        // HTTP methods are case-sensitive, so only exact CONNECT is a tunnel request.
        if (count($parts) < 2 || $parts[0] !== 'CONNECT') {
            return null;
        }

        $authority = self::parseAuthority($parts[1]);

        if ($authority === null) {
            return null;
        }

        $headers = [];

        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }

            $separator = strpos($line, ':');

            if ($separator === false || $separator === 0) {
                continue;
            }

            $headers[strtolower(trim(substr($line, 0, $separator)))] = trim(substr($line, $separator + 1));
        }

        return new self($authority[0], $authority[1], $headers, $earlyData);
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }

    public function authority(): string
    {
        return sprintf('%s:%d', $this->host, $this->port);
    }

    /**
     * CONNECT targets are always authority-form: host:port, IPv6 literals bracketed.
     *
     * @return array{0: string, 1: int}|null
     */
    private static function parseAuthority(string $authority): ?array
    {
        $separator = strrpos($authority, ':');

        if ($separator === false || $separator === 0) {
            return null;
        }

        $host = substr($authority, 0, $separator);
        $port = substr($authority, $separator + 1);

        if ($port === '' || !ctype_digit($port)) {
            return null;
        }

        $port = (int) $port;

        if ($port < 1 || $port > 65535) {
            return null;
        }

        // An IPv6 literal must be bracketed, and the brackets must be balanced.
        if (str_starts_with($host, '[')) {
            if (!str_ends_with($host, ']')) {
                return null;
            }

            $host = substr($host, 1, -1);

            if (@inet_pton($host) === false) {
                return null;
            }
        } elseif ($host === '' || str_contains($host, ']')) {
            return null;
        } elseif (str_contains($host, ':')) {
            // An unbracketed colon means an IPv6 literal missing its brackets: `a::1:443`
            // is genuinely ambiguous about where the address ends and the port begins.
            // Rejecting it here also guarantees the host can be interpolated into a
            // `tcp://host:port` URI downstream without becoming ambiguous again.
            return null;
        }

        return [$host, $port];
    }
}
