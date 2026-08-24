<?php

declare(strict_types=1);

namespace Torxy\Security;

/**
 * Decides whether a client is allowed to use the proxy.
 *
 * An anonymising proxy that anyone can reach is an open relay: strangers get to launder
 * their traffic through the operator's Tor circuits and the operator collects the abuse
 * complaints. Both gates below are opt-in, so an operator can run credentials, an IP
 * allowlist, or both.
 */
final class AccessController
{
    public const ALLOW = 'allow';

    /** Caller must authenticate — answer with 407. */
    public const DENY_AUTH = 'deny_auth';

    /** Caller's address is not allowlisted — answer with 403. */
    public const DENY_IP = 'deny_ip';

    private readonly bool $authRequired;

    /** @var string[] */
    private readonly array $allowedIps;

    /**
     * @param string[] $allowedIps Bare addresses or CIDR blocks. Empty disables the check.
     */
    public function __construct(
        private readonly string $username,
        private readonly string $password,
        array $allowedIps = []
    ) {
        // Credentials are only enforced when both halves are configured; a half-configured
        // pair would otherwise silently accept an empty username or password.
        $this->authRequired = $username !== '' && $password !== '';
        $this->allowedIps = array_values(array_filter($allowedIps, static fn(string $r) => $r !== ''));
    }

    public function isAuthRequired(): bool
    {
        return $this->authRequired;
    }

    public function hasIpAllowlist(): bool
    {
        return $this->allowedIps !== [];
    }

    /**
     * @return self::ALLOW|self::DENY_AUTH|self::DENY_IP
     */
    public function check(?string $remoteAddress, string $proxyAuthorization): string
    {
        if ($this->allowedIps !== []) {
            $ip = self::normalizeAddress($remoteAddress);

            if ($ip === null || !$this->addressAllowed($ip)) {
                return self::DENY_IP;
            }
        }

        if ($this->authRequired && !$this->credentialsValid($proxyAuthorization)) {
            return self::DENY_AUTH;
        }

        return self::ALLOW;
    }

    /**
     * Reduce a ReactPHP remote address (`tcp://127.0.0.1:53712`, `tcp://[::1]:53712`)
     * to a bare IP.
     */
    public static function normalizeAddress(?string $address): ?string
    {
        if ($address === null || $address === '') {
            return null;
        }

        $address = preg_replace('#^[a-z0-9+.\-]+://#i', '', $address) ?? $address;

        if (str_starts_with($address, '[')) {
            $close = strpos($address, ']');

            if ($close === false) {
                return null;
            }

            $address = substr($address, 1, $close - 1);
        } elseif (substr_count($address, ':') === 1) {
            // host:port — a bare IPv6 address has more than one colon and no port.
            $address = substr($address, 0, (int) strrpos($address, ':'));
        }

        return $address === '' ? null : $address;
    }

    private function addressAllowed(string $ip): bool
    {
        foreach ($this->allowedIps as $rule) {
            if (self::addressMatches($ip, $rule)) {
                return true;
            }
        }

        return false;
    }

    private static function addressMatches(string $ip, string $rule): bool
    {
        $packedIp = @inet_pton($ip);

        if ($packedIp === false) {
            return false;
        }

        if (!str_contains($rule, '/')) {
            $packedRule = @inet_pton($rule);

            return $packedRule !== false && $packedIp === $packedRule;
        }

        [$subnet, $prefix] = explode('/', $rule, 2);

        if ($prefix === '' || !ctype_digit($prefix)) {
            return false;
        }

        $packedSubnet = @inet_pton($subnet);

        // Differing lengths mean the rule and the address are different IP families.
        if ($packedSubnet === false || strlen($packedSubnet) !== strlen($packedIp)) {
            return false;
        }

        $bits = (int) $prefix;

        if ($bits > strlen($packedIp) * 8) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);

        if ($wholeBytes > 0 && strncmp($packedIp, $packedSubnet, $wholeBytes) !== 0) {
            return false;
        }

        $remainingBits = $bits % 8;

        if ($remainingBits === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $remainingBits)) & 0xFF);

        return ($packedIp[$wholeBytes] & $mask) === ($packedSubnet[$wholeBytes] & $mask);
    }

    private function credentialsValid(string $header): bool
    {
        if (stripos($header, 'basic ') !== 0) {
            return false;
        }

        $decoded = base64_decode(trim(substr($header, 6)), true);

        if ($decoded === false) {
            return false;
        }

        $separator = strpos($decoded, ':');

        if ($separator === false) {
            return false;
        }

        // hash_equals keeps the comparison time-independent of how much of the
        // credential the caller guessed correctly.
        return hash_equals($this->username, substr($decoded, 0, $separator))
            && hash_equals($this->password, substr($decoded, $separator + 1));
    }
}
