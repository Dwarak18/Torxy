<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Torxy\Security\AccessController;

final class AccessControllerTest extends TestCase
{
    private const USER = 'torxy';
    private const PASS = 'correct-horse';

    public function testAllowsEverythingWhenNothingIsConfigured(): void
    {
        $controller = new AccessController('', '');

        self::assertFalse($controller->isAuthRequired());
        self::assertFalse($controller->hasIpAllowlist());
        self::assertSame(AccessController::ALLOW, $controller->check('tcp://203.0.113.9:4444', ''));
    }

    /**
     * A half-configured credential pair must not turn into a gate that accepts an empty
     * username or password.
     */
    #[DataProvider('halfConfiguredCredentials')]
    public function testHalfConfiguredCredentialsDoNotEnableAuth(string $user, string $pass): void
    {
        $controller = new AccessController($user, $pass);

        self::assertFalse($controller->isAuthRequired());
        self::assertSame(AccessController::ALLOW, $controller->check('tcp://127.0.0.1:1', ''));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function halfConfiguredCredentials(): array
    {
        return [
            'username only' => ['torxy', ''],
            'password only' => ['', 'correct-horse'],
            'neither'       => ['', ''],
        ];
    }

    #[DataProvider('credentialHeaders')]
    public function testCredentialChecking(string $header, string $expected): void
    {
        $controller = new AccessController(self::USER, self::PASS);

        self::assertTrue($controller->isAuthRequired());
        self::assertSame($expected, $controller->check('tcp://127.0.0.1:1', $header));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function credentialHeaders(): array
    {
        $valid = 'Basic ' . base64_encode(self::USER . ':' . self::PASS);

        return [
            'exact match'          => [$valid, AccessController::ALLOW],
            'lowercase scheme'     => ['basic ' . base64_encode(self::USER . ':' . self::PASS), AccessController::ALLOW],
            // A password containing a colon must survive: only the first colon separates.
            'colon in password'    => ['Basic ' . base64_encode('torxy:a:b'), AccessController::DENY_AUTH],
            'missing header'       => ['', AccessController::DENY_AUTH],
            'wrong password'       => ['Basic ' . base64_encode(self::USER . ':nope'), AccessController::DENY_AUTH],
            'wrong username'       => ['Basic ' . base64_encode('nobody:' . self::PASS), AccessController::DENY_AUTH],
            'no colon in payload'  => ['Basic ' . base64_encode('torxy'), AccessController::DENY_AUTH],
            'not base64'           => ['Basic !!!not base64!!!', AccessController::DENY_AUTH],
            'bearer scheme'        => ['Bearer ' . base64_encode(self::USER . ':' . self::PASS), AccessController::DENY_AUTH],
            'empty credentials'    => ['Basic ' . base64_encode(':'), AccessController::DENY_AUTH],
        ];
    }

    public function testPasswordContainingColonAuthenticates(): void
    {
        $controller = new AccessController('torxy', 'a:b');

        self::assertSame(
            AccessController::ALLOW,
            $controller->check('tcp://127.0.0.1:1', 'Basic ' . base64_encode('torxy:a:b'))
        );
    }

    #[DataProvider('allowlistCases')]
    public function testIpAllowlist(string $rule, ?string $address, string $expected): void
    {
        $controller = new AccessController('', '', [$rule]);

        self::assertTrue($controller->hasIpAllowlist());
        self::assertSame($expected, $controller->check($address, ''));
    }

    /**
     * @return array<string, array{string, string|null, string}>
     */
    public static function allowlistCases(): array
    {
        return [
            'exact v4 match'          => ['127.0.0.1', 'tcp://127.0.0.1:5555', AccessController::ALLOW],
            'exact v4 mismatch'       => ['127.0.0.1', 'tcp://127.0.0.2:5555', AccessController::DENY_IP],
            'v4 /8 inside'            => ['10.0.0.0/8', 'tcp://10.1.2.3:1', AccessController::ALLOW],
            'v4 /8 outside'           => ['10.0.0.0/8', 'tcp://11.0.0.1:1', AccessController::DENY_IP],
            'v4 /12 inside'           => ['172.16.0.0/12', 'tcp://172.18.0.1:1', AccessController::ALLOW],
            'v4 /12 outside'          => ['172.16.0.0/12', 'tcp://172.32.0.1:1', AccessController::DENY_IP],
            // /31 and /25 exercise the partial-byte mask rather than whole-byte compares.
            'v4 /31 inside'           => ['192.0.2.0/31', 'tcp://192.0.2.1:1', AccessController::ALLOW],
            'v4 /31 outside'          => ['192.0.2.0/31', 'tcp://192.0.2.2:1', AccessController::DENY_IP],
            'v4 /25 inside'           => ['192.0.2.0/25', 'tcp://192.0.2.127:1', AccessController::ALLOW],
            'v4 /25 outside'          => ['192.0.2.0/25', 'tcp://192.0.2.128:1', AccessController::DENY_IP],
            'v4 /0 matches anything'  => ['0.0.0.0/0', 'tcp://203.0.113.7:1', AccessController::ALLOW],
            'v6 exact match'          => ['::1', 'tcp://[::1]:5555', AccessController::ALLOW],
            'v6 prefix inside'        => ['2001:db8::/32', 'tcp://[2001:db8::dead]:1', AccessController::ALLOW],
            'v6 prefix outside'       => ['2001:db8::/32', 'tcp://[2001:db9::dead]:1', AccessController::DENY_IP],
            // A v4 address must never satisfy a v6 rule, or vice versa.
            'v4 address v6 rule'      => ['::/0', 'tcp://10.0.0.1:1', AccessController::DENY_IP],
            'v6 address v4 rule'      => ['0.0.0.0/0', 'tcp://[::1]:1', AccessController::DENY_IP],
            'prefix beyond family'    => ['10.0.0.0/33', 'tcp://10.0.0.1:1', AccessController::DENY_IP],
            'non-numeric prefix'      => ['10.0.0.0/x', 'tcp://10.0.0.1:1', AccessController::DENY_IP],
            'garbage rule'            => ['not-an-ip', 'tcp://10.0.0.1:1', AccessController::DENY_IP],
            'missing address'         => ['10.0.0.0/8', null, AccessController::DENY_IP],
            'empty address'           => ['10.0.0.0/8', '', AccessController::DENY_IP],
        ];
    }

    public function testEmptyAllowlistRulesAreIgnored(): void
    {
        $controller = new AccessController('', '', ['', '10.0.0.0/8', '']);

        self::assertTrue($controller->hasIpAllowlist());
        self::assertSame(AccessController::ALLOW, $controller->check('tcp://10.9.9.9:1', ''));
        self::assertSame(AccessController::DENY_IP, $controller->check('tcp://11.9.9.9:1', ''));
    }

    public function testAllowlistWithOnlyEmptyRulesDisablesTheCheck(): void
    {
        $controller = new AccessController('', '', ['', '']);

        self::assertFalse($controller->hasIpAllowlist());
        self::assertSame(AccessController::ALLOW, $controller->check('tcp://203.0.113.1:1', ''));
    }

    /**
     * The IP gate is checked first: a client that is not allowlisted should be told it is
     * forbidden, not invited to authenticate.
     */
    public function testIpDenialTakesPrecedenceOverAuth(): void
    {
        $controller = new AccessController(self::USER, self::PASS, ['10.0.0.0/8']);

        self::assertSame(
            AccessController::DENY_IP,
            $controller->check('tcp://203.0.113.5:1', 'Basic ' . base64_encode(self::USER . ':' . self::PASS))
        );
    }

    public function testBothGatesMustPass(): void
    {
        $controller = new AccessController(self::USER, self::PASS, ['10.0.0.0/8']);

        self::assertSame(AccessController::DENY_AUTH, $controller->check('tcp://10.0.0.5:1', ''));
        self::assertSame(
            AccessController::ALLOW,
            $controller->check('tcp://10.0.0.5:1', 'Basic ' . base64_encode(self::USER . ':' . self::PASS))
        );
    }

    #[DataProvider('addressForms')]
    public function testNormalizeAddress(?string $input, ?string $expected): void
    {
        self::assertSame($expected, AccessController::normalizeAddress($input));
    }

    /**
     * @return array<string, array{string|null, string|null}>
     */
    public static function addressForms(): array
    {
        return [
            'scheme and port'    => ['tcp://127.0.0.1:53712', '127.0.0.1'],
            'no scheme'          => ['127.0.0.1:53712', '127.0.0.1'],
            'bare v4'            => ['127.0.0.1', '127.0.0.1'],
            'bracketed v6'       => ['tcp://[::1]:53712', '::1'],
            'bracketed v6 no port' => ['[2001:db8::1]', '2001:db8::1'],
            // More than one colon and no brackets: a bare IPv6 address, not host:port.
            'bare v6'            => ['2001:db8::1', '2001:db8::1'],
            'tls scheme'         => ['tls://10.0.0.1:443', '10.0.0.1'],
            'unbalanced bracket' => ['[::1', null],
            'null'               => [null, null],
            'empty'              => ['', null],
        ];
    }
}
