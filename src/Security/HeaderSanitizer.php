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

    private array $strippedHeaders;

    public function __construct(array $additionalHeaders = [])
    {
        $this->strippedHeaders = array_merge(
            self::IDENTITY_HEADERS,
            array_map('strtolower', $additionalHeaders)
        );
    }

    /**
     * Remove all headers that could expose real IP or routing path.
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