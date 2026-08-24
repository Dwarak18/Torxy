<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Tor;

use PHPUnit\Framework\TestCase;
use Torxy\Tor\CircuitNode;
use Torxy\Tor\TorController;

final class CircuitNodeTest extends TestCase
{
    public function testStartsHealthy(): void
    {
        $node = $this->node();

        self::assertTrue($node->isHealthy());
        self::assertSame(0, $node->getConsecutiveFailures());
    }

    public function testStaysHealthyBelowTheThreshold(): void
    {
        $node = $this->node(threshold: 3);

        $node->markFailure();
        $node->markFailure();

        self::assertTrue($node->isHealthy(), 'two failures must not unseat a circuit at threshold 3');
        self::assertSame(2, $node->getConsecutiveFailures());
    }

    public function testGoesUnhealthyAtTheThreshold(): void
    {
        $node = $this->node(threshold: 3);

        $node->markFailure();
        $node->markFailure();
        $node->markFailure();

        self::assertFalse($node->isHealthy());
        self::assertSame(3, $node->getConsecutiveFailures());
    }

    /**
     * The count is *consecutive*: any success in between resets it, so a circuit that
     * fails intermittently never accumulates its way out of rotation.
     */
    public function testSuccessResetsTheFailureStreak(): void
    {
        $node = $this->node(threshold: 3);

        $node->markFailure();
        $node->markFailure();
        $node->markSuccess();
        $node->markFailure();
        $node->markFailure();

        self::assertTrue($node->isHealthy());
        self::assertSame(2, $node->getConsecutiveFailures());
    }

    public function testSuccessRestoresAnUnhealthyCircuit(): void
    {
        $node = $this->node(threshold: 2);

        $node->markFailure();
        $node->markFailure();
        self::assertFalse($node->isHealthy());

        $node->markSuccess();

        self::assertTrue($node->isHealthy());
        self::assertSame(0, $node->getConsecutiveFailures());
    }

    public function testThresholdOfOneFailsImmediately(): void
    {
        $node = $this->node(threshold: 1);

        $node->markFailure();

        self::assertFalse($node->isHealthy());
    }

    public function testFailuresPastTheThresholdKeepCounting(): void
    {
        $node = $this->node(threshold: 2);

        for ($i = 0; $i < 5; $i++) {
            $node->markFailure();
        }

        self::assertFalse($node->isHealthy());
        self::assertSame(5, $node->getConsecutiveFailures());
    }

    public function testRepeatedSuccessIsIdempotent(): void
    {
        $node = $this->node();

        $node->markSuccess();
        $node->markSuccess();

        self::assertTrue($node->isHealthy());
        self::assertSame(0, $node->getConsecutiveFailures());
    }

    public function testIdentifierComesFromTheController(): void
    {
        $controller = $this->createMock(TorController::class);
        $controller->method('getIdentifier')->willReturn('tor7:9051');

        $node = new CircuitNode($controller, 'tor7', 9050);

        self::assertSame('tor7:9051', $node->getIdentifier());
        self::assertSame('tor7', $node->socksHost);
        self::assertSame(9050, $node->socksPort);
    }

    private function node(int $threshold = CircuitNode::DEFAULT_FAILURE_THRESHOLD): CircuitNode
    {
        $controller = $this->createMock(TorController::class);
        $controller->method('getIdentifier')->willReturn('tor1:9051');

        return new CircuitNode($controller, 'tor1', 9050, $threshold);
    }
}
