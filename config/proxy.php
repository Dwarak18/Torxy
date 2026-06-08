<?php

declare(strict_types=1);

return [
    'server' => [
        'host' => $_ENV['PROXY_HOST'] ?? '0.0.0.0',
        'port' => (int) ($_ENV['PROXY_PORT'] ?? 8080),
    ],

    'tor' => [
        'control_password' => $_ENV['TOR_CONTROL_PASSWORD'] ?? '',
        'socks_port'       => (int) ($_ENV['TOR_SOCKS_PORT'] ?? 9050),
        'control_port'     => (int) ($_ENV['TOR_CONTROL_PORT'] ?? 9051),

        'circuits' => [
            ['host' => $_ENV['TOR1_HOST'] ?? 'tor1'],
            ['host' => $_ENV['TOR2_HOST'] ?? 'tor2'],
            ['host' => $_ENV['TOR3_HOST'] ?? 'tor3'],
        ],

        'rotation' => [
            'strategy' => 'round_robin', // round_robin | random | per_request
            'interval' => 60,            // seconds — for time-based rotation
        ],
    ],

    'security' => [
        'additional_stripped_headers' => [],
    ],
];