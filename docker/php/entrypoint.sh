#!/bin/sh
set -e

# Install dependencies if vendor/ is missing (first run after volume mount)
if [ ! -f /var/www/torxy/vendor/autoload.php ]; then
    echo "[Torxy] Installing composer dependencies..."
    cd /var/www/torxy && composer install --no-dev --optimize-autoloader
fi

exec php bin/server.php