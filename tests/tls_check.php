<?php
require __DIR__ . '/../vendor/autoload.php';

use React\Http\Browser;
use React\Socket\Connector;
use Clue\React\Socks\Client as SocksClient;
use React\EventLoop\Loop;

$loop = Loop::get();

$host = $argv[1] ?? 'tor1';
$url = 'https://check.torproject.org/api/ip';

echo "Testing via {$host}:9050\n";

try {
    $proxy = new SocksClient("socks5://{$host}:9050");
    $connector = new Connector(['tcp' => $proxy, 'dns' => false]);
    $browser = new Browser($connector);

    $promise = $browser->request('GET', $url);

    $promise->then(function ($res) use ($host) {
        echo "[{$host}] Success: ";
        echo (string)$res->getBody() . PHP_EOL;
    }, function ($e) use ($host) {
        echo "[{$host}] Error: " . $e->getMessage() . PHP_EOL;
    });

    $loop->run();
} catch (Throwable $e) {
    echo "[{$host}] Exception: " . $e->getMessage() . PHP_EOL;
}

echo "Done. Run this script multiple times or pass tor1|tor2|tor3 as argument." . PHP_EOL;
