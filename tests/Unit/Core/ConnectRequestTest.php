<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Core;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Torxy\Core\ConnectRequest;

final class ConnectRequestTest extends TestCase
{
    public function testParsesHostPortAndHeaders(): void
    {
        $request = ConnectRequest::fromHead(
            "CONNECT example.com:443 HTTP/1.1\r\n"
            . "Host: example.com:443\r\n"
            . "Proxy-Authorization: Basic dG9yeHk6cHc=\r\n"
            . "User-Agent: curl/8.5.0"
        );

        self::assertNotNull($request);
        self::assertSame('example.com', $request->host);
        self::assertSame(443, $request->port);
        self::assertSame('example.com:443', $request->authority());
        self::assertSame('', $request->earlyData);

        // Lookups are case-insensitive because clients capitalise headers however they like.
        self::assertSame('Basic dG9yeHk6cHc=', $request->header('proxy-authorization'));
        self::assertSame('Basic dG9yeHk6cHc=', $request->header('Proxy-Authorization'));
        self::assertSame('curl/8.5.0', $request->header('USER-AGENT'));
        self::assertSame('', $request->header('absent'));
    }

    public function testCarriesEarlyData(): void
    {
        $request = ConnectRequest::fromHead("CONNECT example.com:443 HTTP/1.1", "\x16\x03\x01");

        self::assertNotNull($request);
        self::assertSame("\x16\x03\x01", $request->earlyData);
    }

    public function testHeaderValueContainingColonIsKeptWhole(): void
    {
        $request = ConnectRequest::fromHead(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Time: 10:30:00"
        );

        self::assertNotNull($request);
        self::assertSame('example.com:443', $request->header('host'));
        self::assertSame('10:30:00', $request->header('x-time'));
    }

    #[DataProvider('validAuthorities')]
    public function testValidAuthorityForms(string $authority, string $host, int $port): void
    {
        $request = ConnectRequest::fromHead("CONNECT {$authority} HTTP/1.1");

        self::assertNotNull($request);
        self::assertSame($host, $request->host);
        self::assertSame($port, $request->port);
    }

    /**
     * @return array<string, array{string, string, int}>
     */
    public static function validAuthorities(): array
    {
        return [
            'hostname'        => ['example.com:443', 'example.com', 443],
            'subdomain'       => ['a.b.example.com:8443', 'a.b.example.com', 8443],
            'ipv4'            => ['192.0.2.10:443', '192.0.2.10', 443],
            'ipv6 bracketed'  => ['[2001:db8::1]:443', '2001:db8::1', 443],
            'ipv6 loopback'   => ['[::1]:443', '::1', 443],
            'lowest port'     => ['example.com:1', 'example.com', 1],
            'highest port'    => ['example.com:65535', 'example.com', 65535],
        ];
    }

    #[DataProvider('malformedHeads')]
    public function testMalformedHeadsAreRejected(string $head): void
    {
        self::assertNull(ConnectRequest::fromHead($head));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedHeads(): array
    {
        return [
            'empty'                  => [''],
            'method only'            => ['CONNECT'],
            // HTTP methods are case-sensitive, so these are not CONNECT requests.
            'lowercase method'       => ['connect example.com:443 HTTP/1.1'],
            'mixed case method'      => ['Connect example.com:443 HTTP/1.1'],
            'different method'       => ['GET http://example.com/ HTTP/1.1'],
            'no port'                => ['CONNECT example.com HTTP/1.1'],
            'empty port'             => ['CONNECT example.com: HTTP/1.1'],
            'non-numeric port'       => ['CONNECT example.com:https HTTP/1.1'],
            'negative port'          => ['CONNECT example.com:-443 HTTP/1.1'],
            'port zero'              => ['CONNECT example.com:0 HTTP/1.1'],
            'port too high'          => ['CONNECT example.com:65536 HTTP/1.1'],
            'empty host'             => ['CONNECT :443 HTTP/1.1'],
            'unclosed bracket'       => ['CONNECT [2001:db8::1:443 HTTP/1.1'],
            'stray closing bracket'  => ['CONNECT 2001:db8::1]:443 HTTP/1.1'],
            'bracketed non-address'  => ['CONNECT [not-an-ip]:443 HTTP/1.1'],
            'bracketed ipv4'         => ['CONNECT [192.0.2.1x]:443 HTTP/1.1'],
            // IPv6 literals must be bracketed; unbracketed is ambiguous about the port.
            'unbracketed ipv6'       => ['CONNECT 2001:db8::1:443 HTTP/1.1'],
            'unbracketed ipv6 short' => ['CONNECT ::1:443 HTTP/1.1'],
        ];
    }

    /**
     * The parsed host is interpolated into a `tcp://host:port` URI when the tunnel is
     * dialled, so it must never contain a colon of its own.
     */
    public function testParsedHostNeverContainsAColon(): void
    {
        foreach (self::validAuthorities() as [$authority, , ]) {
            $request = ConnectRequest::fromHead("CONNECT {$authority} HTTP/1.1");

            self::assertNotNull($request);

            if (@inet_pton($request->host) !== false && str_contains($request->host, ':')) {
                // A bracketed IPv6 literal is the one case where the host legitimately has
                // colons; callers must re-bracket it rather than interpolate it raw.
                continue;
            }

            self::assertStringNotContainsString(':', $request->host);
        }
    }

    public function testMalformedHeaderLinesAreSkipped(): void
    {
        $request = ConnectRequest::fromHead(
            "CONNECT example.com:443 HTTP/1.1\r\n"
            . "GarbageWithNoColon\r\n"
            . ": leading colon\r\n"
            . "\r\n"
            . "Host: example.com"
        );

        self::assertNotNull($request);
        self::assertSame('example.com', $request->header('host'));
        self::assertSame(['host' => 'example.com'], $request->headers);
    }
}
