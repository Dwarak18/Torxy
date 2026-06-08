FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    tor \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY torrc.template /etc/tor/torrc.template
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 9050 9051

ENTRYPOINT ["/entrypoint.sh"]