#!/bin/sh
# One-shot dev CA and Redis server certificate, run by the `redis-certs`
# service in docker-compose.yml. NOTHING it writes is committed: the output
# lands on two named volumes, and the CA's private key is never written to
# either (it lives in a temp dir that dies with the container).
#
#   /redis-tls  server.crt, server.key, ca.crt   mounted by `redis` only
#   /redis-ca   ca.crt                           mounted by `api` and `confirm`
#
# So the services can verify the server and cannot read its private key.
#
# THROWAWAY: a 2048-bit RSA CA valid 30 days and a server certificate whose
# SANs are the compose service name `redis` and `localhost`. A deployment uses
# its own CA, issued and rotated by its own PKI, and mints certificates for
# real hostnames. Re-running is a no-op ONLY while the certificate files exist
# and the server certificate has more than a day of validity left. Otherwise
# the CA and the server certificate are both regenerated, and a Redis that is
# already running keeps the OLD certificate in memory: new client connections,
# which trust the NEW CA, then fail with CERTIFICATE_VERIFY_FAILED until Redis
# is restarted. After any regeneration run `docker compose restart redis`.
# Measured 3 October 2026 (project `pstern-regen`, server.crt deleted, script
# re-run, no restart): `redis-cli --tls --cacert /tls/ca.crt ping` answered
# "SSL_connect failed: certificate verify failed"; after the restart, PONG.
set -eu

TLS=/redis-tls
CA=/redis-ca

if [ -s "$TLS/server.crt" ] && [ -s "$TLS/server.key" ] && [ -s "$CA/ca.crt" ] \
   && openssl x509 -in "$TLS/server.crt" -noout -checkend 86400 >/dev/null 2>&1; then
  echo "redis-certs: existing certificate still valid, nothing to do"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout "$work/ca.key" -out "$work/ca.crt" \
  -subj "/CN=postern-dev-redis-ca" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
  -keyout "$work/server.key" -out "$work/server.csr" \
  -subj "/CN=redis" 2>/dev/null

printf 'subjectAltName=DNS:redis,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$work/ext.cnf"

openssl x509 -req -in "$work/server.csr" -days 30 \
  -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -extfile "$work/ext.cnf" -out "$work/server.crt" 2>/dev/null

install -m 0444 "$work/ca.crt" "$TLS/ca.crt"
install -m 0444 "$work/ca.crt" "$CA/ca.crt"
install -m 0444 "$work/server.crt" "$TLS/server.crt"
# The `redis` user in redis:7-alpine is uid 999; the key is readable by it alone.
install -m 0400 -o 999 "$work/server.key" "$TLS/server.key"

echo "redis-certs: wrote a 30-day dev CA and a server certificate for DNS:redis"
