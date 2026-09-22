#!/bin/sh
set -eu

: "${NOCTWEAVE_TURN_SHARED_SECRET:?NOCTWEAVE_TURN_SHARED_SECRET is required}"
: "${TURN_REALM:?TURN_REALM is required}"

turn_config="$(mktemp "${TMPDIR:-/tmp}/noctweave-turnserver.XXXXXX")"
turn_min_port="${TURN_MIN_PORT:-49160}"
turn_max_port="${TURN_MAX_PORT:-49200}"
umask 077

{
  printf '%s\n' \
    "listening-port=3478" \
    "fingerprint" \
    "use-auth-secret" \
    "static-auth-secret=${NOCTWEAVE_TURN_SHARED_SECRET}" \
    "realm=${TURN_REALM}" \
    "server-name=${TURN_REALM}" \
    "min-port=${turn_min_port}" \
    "max-port=${turn_max_port}" \
    "stale-nonce=600" \
    "no-cli" \
    "no-tls" \
    "no-dtls" \
    "no-multicast-peers" \
    "denied-peer-ip=0.0.0.0-0.255.255.255" \
    "denied-peer-ip=10.0.0.0-10.255.255.255" \
    "denied-peer-ip=100.64.0.0-100.127.255.255" \
    "denied-peer-ip=127.0.0.0-127.255.255.255" \
    "denied-peer-ip=169.254.0.0-169.254.255.255" \
    "denied-peer-ip=172.16.0.0-172.31.255.255" \
    "denied-peer-ip=192.0.0.0-192.0.0.255" \
    "denied-peer-ip=192.168.0.0-192.168.255.255" \
    "denied-peer-ip=198.18.0.0-198.19.255.255" \
    "denied-peer-ip=224.0.0.0-255.255.255.255" \
    "denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" \
    "denied-peer-ip=fe80::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" \
    "denied-peer-ip=ff00::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" \
    "user-quota=12" \
    "total-quota=1200"
  if [ -n "${TURN_EXTERNAL_IP:-}" ]; then
    printf '%s\n' "external-ip=${TURN_EXTERNAL_IP}"
  fi
} > "${turn_config}"

unset NOCTWEAVE_TURN_SHARED_SECRET
exec turnserver -c "${turn_config}"
