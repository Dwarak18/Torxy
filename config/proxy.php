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
            'strategy' => $_ENV['TOR_ROTATION_STRATEGY'] ?? 'round_robin', // round_robin | random | per_request
            'interval' => (int) ($_ENV['TOR_ROTATION_INTERVAL'] ?? 0),     // seconds; 0 disables timed rotation
        ],

        // Circuits are marked unhealthy by real traffic failures and brought back by the
        // monitor's probes, so the interval bounds how long a recovered circuit sits idle.
        'health' => [
            'interval'          => (int) ($_ENV['TOR_HEALTH_INTERVAL'] ?? 30),   // seconds; 0 disables probing
            'probe_target'      => $_ENV['TOR_HEALTH_PROBE_TARGET'] ?? '1.1.1.1:443',
            'failure_threshold' => (int) ($_ENV['TOR_HEALTH_FAILURE_THRESHOLD'] ?? 3),
        ],
    ],

    'security' => [
        'additional_stripped_headers' => [],

        // Credentials clients must present as `Proxy-Authorization: Basic ...`.
        // Leave either blank to run without authentication.
        'auth' => [
            'username' => $_ENV['PROXY_AUTH_USER'] ?? '',
            'password' => $_ENV['PROXY_AUTH_PASSWORD'] ?? '',
        ],

        // Addresses or CIDR blocks permitted to use the proxy. Empty allows any client
        // that can reach the listener.
        'allowed_ips' => array_values(array_filter(
            array_map('trim', explode(',', $_ENV['PROXY_ALLOWED_IPS'] ?? '')),
            static fn(string $rule): bool => $rule !== ''
        )),
    ],
];