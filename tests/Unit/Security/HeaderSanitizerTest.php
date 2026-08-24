<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Torxy\Security\HeaderSanitizer;

final class HeaderSanitizerTest extends TestCase
{
    #[DataProvider('strippedHeaderNames')]
    public function testStripsHeaderRegardlessOfCase(string $name): void
    {
        $sanitizer = new HeaderSanitizer();

        self::assertSame([], $sanitizer->strip([$name => 'value']));
        self::assertSame([], $sanitizer->strip([strtoupper($name) => 'value']));
        self::assertSame([], $sanitizer->strip([ucwords($name, '-') => 'value']));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function strippedHeaderNames(): array
    {
        $names = [
            // Identity headers: these carry the real client IP.
            'x-forwarded-for',
            'x-real-ip',
            'x-originating-ip',
            'x-proxyuser-ip',
            'x-remote-ip',
            'x-remote-addr',
            'forwarded',
            'via',
            'cf-connecting-ip',
            'true-client-ip',
            // Hop-by-hop headers (RFC 7230 §6.1): forwarding these announces the proxy.
            'proxy-connection',
            'proxy-authorization',
            'proxy-authenticate',
            'connection',
            'keep-alive',
            'te',
            'trailer',
            'transfer-encoding',
            'upgrade',
        ];

        return array_combine($names, array_map(static fn(string $n): array => [$n], $names));
    }

    public function testKeepsHeadersThatDoNotIdentifyTheClient(): void
    {
        $sanitizer = new HeaderSanitizer();

        $headers = [
            'Host'            => 'example.com',
            'User-Agent'      => 'curl/8.5.0',
            'Accept'          => '*/*',
            'Content-Type'    => 'application/json',
            'Content-Length'  => '17',
            'Authorization'   => 'Bearer token',
            'Cookie'          => 'session=abc',
        ];

        self::assertSame($headers, $sanitizer->strip($headers));
    }

    /**
     * `Authorization` is the target's credential and must survive; `Proxy-Authorization` is
     * ours and must not be forwarded.
     */
    public function testDistinguishesAuthorizationFromProxyAuthorization(): void
    {
        $result = (new HeaderSanitizer())->strip([
            'Authorization'       => 'Bearer token',
            'Proxy-Authorization' => 'Basic dG9yeHk6cHc=',
        ]);

        self::assertSame(['Authorization' => 'Bearer token'], $result);
    }

    public function testStripsAdditionalHeadersCaseInsensitively(): void
    {
        $sanitizer = new HeaderSanitizer(['X-Custom-Trace', 'X-Another']);

        $result = $sanitizer->strip([
            'x-custom-trace' => 'abc',
            'X-ANOTHER'      => 'def',
            'User-Agent'     => 'curl/8.5.0',
        ]);

        self::assertSame(['User-Agent' => 'curl/8.5.0'], $result);
    }

    public function testEmptyHeaderSetStaysEmpty(): void
    {
        self::assertSame([], (new HeaderSanitizer())->strip([]));
    }

    public function testMixedSetRemovesOnlyTheSensitiveHeaders(): void
    {
        $result = (new HeaderSanitizer())->strip([
            'Host'              => 'example.com',
            'X-Forwarded-For'   => '203.0.113.9',
            'Proxy-Connection'  => 'Keep-Alive',
            'Accept'            => '*/*',
            'Via'               => '1.1 torxy',
        ]);

        self::assertSame(['Host' => 'example.com', 'Accept' => '*/*'], $result);
    }
}
