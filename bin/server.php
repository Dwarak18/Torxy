<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use React\EventLoop\Loop;
use Torxy\Tor\TorController;
use Torxy\Tor\CircuitManager;
use Torxy\Core\ProxyServer;
use Torxy\Core\RequestForwarder;
use Torxy\Security\HeaderSanitizer;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();
$dotenv->required(['TOR_CONTROL_PASSWORD'])->notEmpty();

$config = require __DIR__ . '/../config/proxy.php';

$rotationStrategy = $config['tor']['rotation']['strategy'] ?? 'round_robin';
$manager = new CircuitManager($rotationStrategy);

foreach ($config['tor']['circuits'] as $circuitConfig) {
    $host       = $circuitConfig['host'];
    $maxRetries = 10;
    $retryDelay = 5;

    for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
        try {
            $controller = new TorController(
                host:        $host,
                controlPort: $config['tor']['control_port'],
                password:    $config['tor']['control_password']
            );

            $manager->registerCircuit(
                controller: $controller,
                socksHost:  $host,
                socksPort:  $config['tor']['socks_port']
            );

            break; // success — move to next circuit

        } catch (\Throwable $e) {
            echo sprintf(
                "[Torxy] Circuit %s not ready (attempt %d/%d) — retrying in %ds...\n",
                $host, $attempt, $maxRetries, $retryDelay
            );

            if ($attempt === $maxRetries) {
                echo "[Torxy] WARNING: Circuit {$host} permanently failed — skipping\n";
                break;
            }

            sleep($retryDelay);
        }
    }
}

if ($manager->getCircuitCount() === 0) {
    echo "[Torxy] FATAL: No circuits available. Exiting." . PHP_EOL;
    exit(1);
}

echo sprintf("[Torxy] %d circuit(s) active\n", $manager->getCircuitCount());

$proxy = new ProxyServer(
    circuitManager:   $manager,
    headerSanitizer:  new HeaderSanitizer($config['security']['additional_stripped_headers']),
    requestForwarder: new RequestForwarder(),
    host:             $config['server']['host'],
    port:             $config['server']['port']
);

$loop = Loop::get();
$proxy->start($loop);

if (defined('SIGINT')) {
    $loop->addSignal(SIGINT, function () use ($manager, $loop): void {
        echo "\n[Torxy] Shutting down..." . PHP_EOL;
        $manager->disconnectAll();
        $loop->stop();
    });
}

$loop->run();