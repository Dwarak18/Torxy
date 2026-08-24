<?php

declare(strict_types=1);

namespace Torxy\Security;

class HeaderSanitizer
{
    /** Headers that leak real client/server identity */
    private const IDENTITY_HEADERS = [
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
    ];

    /**
     * Hop-by-hop headers (RFC 7230 §6.1). A proxy must not forward these:
     * they describe the client-to-proxy connection, not the request itself,
     * and `proxy-*` variants advertise that a proxy is in the path at all.
     */
    private const HOP_BY_HOP_HEADERS = [
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

    /**
     * Headers the proxy answers itself and must therefore not pass on.
     *
     * `Expect: 100-continue` is a negotiation with the *next* hop, and react/http's server
     * already replies `100 Continue` to the client on our behalf. Forwarding it as well
     * invites a second `100` from the target, which react/http's client surfaces as the
     * final response — so the client would receive an empty `100` instead of its answer.
     */
    private const LOCALLY_ANSWERED_HEADERS = [
        'expect',
    ];

    /** @var list<string> */
    private array $strippedHeaders;

    /**
     * @param string[] $additionalHeaders Extra header names to strip, any casing.
     */
    public function __construct(array $additionalHeaders = [])
    {
        $this->strippedHeaders = array_values(array_merge(
            self::IDENTITY_HEADERS,
            self::HOP_BY_HOP_HEADERS,
            self::LOCALLY_ANSWERED_HEADERS,
            array_map('strtolower', $additionalHeaders)
        ));
    }

    /**
     * Remove all headers that could expose real IP or routing path.
     *
     * @param array<string, string> $headers
     *
     * @return array<string, string>
     */
    public function strip(array $headers): array
    {
        return array_filter(
            $headers,
            fn(string $key) => !in_array(strtolower($key), $this->strippedHeaders, strict: true),
            ARRAY_FILTER_USE_KEY
        );
    }
}