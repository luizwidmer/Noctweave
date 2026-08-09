#!/bin/sh
set -eu

: "${NOCTWEAVE_TURN_SHARED_SECRET:?NOCTWEAVE_TURN_SHARED_SECRET is required}"
: "${TURN_REALM:?TURN_REALM is required}"

turn_config="/tmp/noctweave-turnserver.conf"
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
    "user-quota=12" \
    "total-quota=1200"
  if [ -n "${TURN_EXTERNAL_IP:-}" ]; then
    printf '%s\n' "external-ip=${TURN_EXTERNAL_IP}"
  fi
} > "${turn_config}"

unset NOCTWEAVE_TURN_SHARED_SECRET
exec turnserver -c "${turn_config}"
