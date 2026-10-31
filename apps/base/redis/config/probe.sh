#!/bin/sh
#
# The probes' check (statefulset.yaml): PING over TLS on <port>, the reply matched with grep -q
# <grep args>. With Redis' own certificate (a client certificate from redis-ca too): a TCP check
# would abort the handshake, which Redis logs as an error each time. As the ACL user probe (PING
# only, any password: external-secret.yaml), so they don't count as NOAUTH errors.
#
# Usage: probe.sh <port> <grep args>

port=$1
shift

redis-cli --tls -h localhost -p "$port" \
  --cacert /etc/redis/secrets/ca.crt \
  --cert /etc/redis/secrets/tls.crt \
  --key /etc/redis/secrets/tls.key \
  --user probe --pass probe --no-auth-warning \
  ping | grep -q "$@"
