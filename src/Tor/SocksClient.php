<?php

declare(strict_types=1);

namespace Torxy\Tor;

use RuntimeException;

class SocksClient
{
    private const DEFAULT_TIMEOUT = 30;

    public function __construct(
        private readonly string $socksHost,
        private readonly int $socksPort,
        private readonly int $timeout = self::DEFAULT_TIMEOUT
    ) {}

    /**
     * Forward an HTTP request through the Tor SOCKS5 proxy.
     * SOCKS5H resolves DNS inside Tor — prevents DNS leaks.
     *
     * @return array{status: int, headers: string, body: string}
     */
    public function forward(
        string $url,
        string $method,
        array $headers,
        string $body = ''
    ): array {
        $this->validateUrl($url);
        $this->validateMethod($method);

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            // SOCKS5H = hostname resolution happens inside Tor (no DNS leak)
            CURLOPT_PROXY          => "socks5h://{$this->socksHost}:{$this->socksPort}",
            CURLOPT_PROXYTYPE      => CURLPROXY_SOCKS5_HOSTNAME,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $this->formatHeaders($headers),
            CURLOPT_CUSTOMREQUEST  => $method,
        ]);

        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response   = curl_exec($ch);
        $curlError  = curl_error($ch);
        $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        curl_close($ch);

        if ($response === false) {
            throw new RuntimeException("SOCKS5 forwarding failed: {$curlError}");
        }

        return [
            'status'  => $statusCode,
            'headers' => substr($response, 0, $headerSize),
            'body'    => substr($response, $headerSize),
        ];
    }

    private function validateUrl(string $url): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new RuntimeException("Invalid target URL provided");
        }
    }

    private function validateMethod(string $method): void
    {
        $allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

        if (!in_array(strtoupper($method), $allowed, strict: true)) {
            throw new RuntimeException("Unsupported HTTP method: {$method}");
        }
    }

    private function formatHeaders(array $headers): array
    {
        $formatted = [];
        foreach ($headers as $key => $value) {
            $formatted[] = "{$key}: {$value}";
        }
        return $formatted;
    }
}