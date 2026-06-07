#!/bin/sh
set -e

if [ -z "${TOR_CONTROL_PASSWORD}" ]; then
    echo "[Torxy] ERROR: TOR_CONTROL_PASSWORD is not set"
    exit 1
fi

HASHED=$(tor --hash-password "${TOR_CONTROL_PASSWORD}" 2>/dev/null | grep "^16:")

if [ -z "$HASHED" ]; then
    echo "[Torxy] ERROR: Failed to generate Tor control password hash"
    exit 1
fi

sed "s|HASHED_PASSWORD_PLACEHOLDER|${HASHED}|g" \
    /etc/tor/torrc.template > /etc/tor/torrc

# Fix ownership so debian-tor can use its DataDirectory
mkdir -p /var/lib/tor
chown -R debian-tor:debian-tor /var/lib/tor
chmod 700 /var/lib/tor

echo "[Torxy] Tor circuit starting..."

# Switch to debian-tor user — Tor requires DataDirectory owner matches running user
exec su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc"