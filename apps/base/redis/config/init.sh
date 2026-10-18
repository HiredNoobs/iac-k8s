#!/bin/sh
# Writes this pod's redis.conf and sentinel.conf into /etc/redis-run (an emptyDir: Redis and
# Sentinel rewrite their own files on a failover) before either starts.
#
# Who's master: whatever the other pods' sentinels say. When none answers (the first start, or
# every pod restarting at once) it's redis-0, and redis-1/2 replicate from it. After a full
# restart with another pod as master, redis-0's data wins: anything it hadn't replicated yet is
# lost (replication is asynchronous, normally a fraction of a second behind).
#
# Every pod is reached by its stable name, <pod>.redis.redis.svc, which its certificate has:
# the headless Service publishes it before the pod is ready.
set -eu

SELF="$POD_NAME.redis.redis.svc"
RUN=/etc/redis-run
TLS="--tls --cacert /etc/redis/secrets/ca.crt --cert /etc/redis/secrets/tls.crt --key /etc/redis/secrets/tls.key"

# The master's name from the first other sentinel that knows it.
ask_sentinels() {
  for i in 0 1 2; do
    host="redis-$i.redis.redis.svc"
    [ "$host" = "$SELF" ] && continue
    # shellcheck disable=SC2086
    master=$(REDISCLI_AUTH="$REDIS_SENTINEL_PASSWORD" timeout 5 redis-cli $TLS -h "$host" -p 26379 \
      --user sentinel --no-auth-warning SENTINEL get-master-addr-by-name redis 2> /dev/null | head -n 1) || continue
    if [ -n "$master" ]; then
      echo "$master"
      return 0
    fi
  done
  return 1
}

if master=$(ask_sentinels); then
  echo "The sentinels say the master is $master."
else
  master="redis-0.redis.redis.svc"
  echo "No sentinel answered: $master is the master."
fi

# Redis: the base config (redis.conf) plus how to reach the master as a replica.
cp /usr/local/etc/redis/redis.conf "$RUN/redis.conf"
cat >> "$RUN/redis.conf" << EOF

# Written by init.sh
masteruser replica
masterauth "$REDIS_REPLICA_PASSWORD"
replica-announce-ip $SELF
EOF
if [ "$master" != "$SELF" ]; then
  echo "replicaof $master 6379" >> "$RUN/redis.conf"
  echo "$SELF replicates from $master."
fi

# Sentinel: the base config (sentinel.conf), the master to watch and the ACL users (the
# redis-acl Secret).
cp /usr/local/etc/redis/sentinel.conf "$RUN/sentinel.conf"
cat >> "$RUN/sentinel.conf" << EOF

# Written by init.sh
sentinel announce-ip $SELF
sentinel monitor redis $master 6379 2
sentinel down-after-milliseconds redis 10000
sentinel failover-timeout redis 60000
sentinel parallel-syncs redis 1
sentinel auth-user redis sentinel
sentinel auth-pass redis "$REDIS_SENTINEL_PASSWORD"
sentinel sentinel-user sentinel
sentinel sentinel-pass "$REDIS_SENTINEL_PASSWORD"
EOF
cat /etc/redis/acl/sentinel-users.acl >> "$RUN/sentinel.conf"

chmod 0600 "$RUN/redis.conf" "$RUN/sentinel.conf"
