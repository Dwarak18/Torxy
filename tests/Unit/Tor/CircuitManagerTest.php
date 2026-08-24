<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Tor;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Torxy\Tor\CircuitManager;
use Torxy\Tor\CircuitNode;
use Torxy\Tor\TorController;

final class CircuitManagerTest extends TestCase
{
    public function testEmptyPoolThrows(): void
    {
        $manager = new CircuitManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('No Tor circuits available in pool');

        $manager->getNextNode();
    }

    public function testRegistrationAuthenticatesTheController(): void
    {
        $controller = $this->controller('tor1');
        $controller->expects($this->once())->method('connect');

        $manager = new CircuitManager();
        $manager->registerCircuit($controller, 'tor1', 9050);

        self::assertSame(1, $manager->getCircuitCount());
        self::assertSame(1, $manager->getHealthyCount());
    }

    public function testRoundRobinCyclesInOrder(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2', 'tor3']);

        self::assertSame(
            ['tor1:9051', 'tor2:9051', 'tor3:9051', 'tor1:9051', 'tor2:9051'],
            $this->take($manager, 5)
        );
    }

    public function testRoundRobinSkipsUnhealthyCircuits(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2', 'tor3']);
        $this->driveUnhealthy($manager->getNodes()[1]);

        self::assertSame(2, $manager->getHealthyCount());
        self::assertSame(
            ['tor1:9051', 'tor3:9051', 'tor1:9051', 'tor3:9051'],
            $this->take($manager, 4)
        );
    }

    /**
     * A stale health verdict must not take the whole proxy offline — a real attempt is what
     * re-tests the path, so selection has to keep handing circuits back.
     */
    public function testFallsBackToAnUnhealthyCircuitWhenAllAreDown(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2']);

        foreach ($manager->getNodes() as $node) {
            $this->driveUnhealthy($node);
        }

        self::assertSame(0, $manager->getHealthyCount());

        $picked = $this->take($manager, 4);

        self::assertCount(4, $picked);

        foreach ($picked as $identifier) {
            self::assertMatchesRegularExpression('/^tor[12]:9051$/', $identifier);
        }
    }

    public function testRecoveryPutsACircuitBackInRotation(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2']);
        $this->driveUnhealthy($manager->getNodes()[0]);

        self::assertSame(['tor2:9051', 'tor2:9051'], $this->take($manager, 2));

        $manager->getNodes()[0]->markSuccess();

        self::assertSame(2, $manager->getHealthyCount());
        self::assertContains('tor1:9051', $this->take($manager, 4));
    }

    public function testRandomStrategyOnlyPicksHealthyCircuits(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2', 'tor3'], CircuitManager::STRATEGY_RANDOM);
        $this->driveUnhealthy($manager->getNodes()[0]);
        $this->driveUnhealthy($manager->getNodes()[2]);

        // Enough draws that a bug allowing an unhealthy pick would show up.
        foreach ($this->take($manager, 50) as $identifier) {
            self::assertSame('tor2:9051', $identifier);
        }
    }

    public function testRandomStrategyFallsBackWhenAllAreDown(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2'], CircuitManager::STRATEGY_RANDOM);

        foreach ($manager->getNodes() as $node) {
            $this->driveUnhealthy($node);
        }

        self::assertCount(10, $this->take($manager, 10));
    }

    public function testPerRequestDispatchesRotationForTheSelectedCircuit(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2'], CircuitManager::STRATEGY_PER_REQUEST);

        $rotated = [];
        $manager->setRotationDispatcher(function (CircuitNode $node) use (&$rotated): void {
            $rotated[] = $node->getIdentifier();
        });

        $selected = $this->take($manager, 3);

        self::assertSame($selected, $rotated, 'every selected circuit should be asked to rotate');
    }

    /**
     * Without a dispatcher the only way to rotate would be a blocking control-port call on
     * the event loop, so the strategy degrades to plain round-robin instead of blocking.
     */
    public function testPerRequestWithoutADispatcherStillSelects(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2'], CircuitManager::STRATEGY_PER_REQUEST);

        self::assertSame(['tor1:9051', 'tor2:9051', 'tor1:9051'], $this->take($manager, 3));
    }

    public function testUnknownStrategyBehavesAsRoundRobin(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2'], 'nonsense');

        self::assertSame(['tor1:9051', 'tor2:9051', 'tor1:9051'], $this->take($manager, 3));
        self::assertSame('nonsense', $manager->getStrategy());
    }

    public function testFailureThresholdIsPassedToRegisteredCircuits(): void
    {
        $manager = new CircuitManager(failureThreshold: 1);
        $manager->registerCircuit($this->controller('tor1'), 'tor1', 9050);

        $manager->getNodes()[0]->markFailure();

        self::assertFalse($manager->getNodes()[0]->isHealthy());
    }

    /**
     * A threshold below 1 would mean a circuit counts as unhealthy before it has failed.
     */
    public function testFailureThresholdIsClampedToAtLeastOne(): void
    {
        $manager = new CircuitManager(failureThreshold: 0);
        $manager->registerCircuit($this->controller('tor1'), 'tor1', 9050);

        self::assertTrue($manager->getNodes()[0]->isHealthy());

        $manager->getNodes()[0]->markFailure();

        self::assertFalse($manager->getNodes()[0]->isHealthy());
    }

    public function testDisconnectAllEmptiesThePool(): void
    {
        $manager = $this->managerWith(['tor1', 'tor2']);

        $manager->disconnectAll();

        self::assertSame(0, $manager->getCircuitCount());
        self::assertSame([], $manager->getNodes());
    }

    /**
     * @param string[] $hosts
     */
    private function managerWith(array $hosts, string $strategy = CircuitManager::STRATEGY_ROUND_ROBIN): CircuitManager
    {
        $manager = new CircuitManager($strategy);

        foreach ($hosts as $host) {
            $manager->registerCircuit($this->controller($host), $host, 9050);
        }

        return $manager;
    }

    /**
     * @return TorController&MockObject
     */
    private function controller(string $host): TorController
    {
        $controller = $this->createMock(TorController::class);
        $controller->method('getIdentifier')->willReturn("{$host}:9051");

        return $controller;
    }

    /**
     * Drive a node to unhealthy regardless of the configured threshold.
     */
    private function driveUnhealthy(CircuitNode $node): void
    {
        while ($node->isHealthy()) {
            $node->markFailure();
        }
    }

    /**
     * @return string[]
     */
    private function take(CircuitManager $manager, int $count): array
    {
        $picked = [];

        for ($i = 0; $i < $count; $i++) {
            $picked[] = $manager->getNextNode()->getIdentifier();
        }

        return $picked;
    }
}
