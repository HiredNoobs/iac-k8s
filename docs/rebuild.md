# Rebuilding a cluster

What runs on a new, empty cluster (built by iac-homelab's ``./build.sh clusters``, see its ``docs/rebuild.md`` for the order around it): Flux applies everything here, it needs Vault's secrets to be there, and the apps' data comes back from Longhorn's backups on the NAS.

## Before Flux

- Vault is unsealed and has every secret below (restored from its snapshot, or put back by hand).
- iac-homelab's ``terraform/vault`` has the new cluster's CA (``terraform/vault/clusters/``) and has been applied: External Secrets Operator logs in with it.
- ``flux`` and the kube context on the management VM (``context-setup``).

## Flux

1. Bootstrap, as in [Flux](flux.md#bootstrap). It also has to be run again for a rebuilt git VM.
2. Straight away, before the infrastructure is ready (Longhorn and the rest take a few minutes): ``flux suspend kustomization apps``. The apps would otherwise start on new, empty volumes.
3. Wait for the infrastructure: ``flux get kustomizations`` shows ``infra-controllers``, ``infra-configs`` and ``infra-operators`` Ready. ``kubectl -n longhorn-system get secret longhorn-backup`` exists (ESO, from ``production/longhorn``), and Longhorn's UI (Settings > Backup Target) shows the NAS share available.
4. Restore the volumes (below).
5. ``flux resume kustomization apps``. The StatefulSets find their restored PVCs by name; ``rabbitmq-topology`` follows ``apps``.

## Volumes

Longhorn backs up every volume to ``cifs://192.168.111.6/longhorn-backups`` each night at 03:00 (``infrastructure/configs/longhorn``, the newest 5 kept). For each volume to bring back, in Longhorn's UI: Backup > the volume > restore its latest backup with **Use Previous Name**, wait for it to finish, then Volume > the restored volume > **Create PV/PVC** with **Use Previous PVC** (the backup knows the PVC's namespace and name). Volumes left out start empty.

| PVC | Namespace | Holds | Restore |
| --- | --- | --- | --- |
| ``data-vaultwarden-0`` | ``vaultwarden`` | The vault itself. | Yes. |
| ``data-authelia-0`` | ``authelia`` | 2FA registrations, consents. Encrypted with ``AUTHELIA_STORAGE_ENCRYPTION_KEY``: Vault's must be the one it was written with. | Yes. |
| ``mealie-data`` | ``mealie`` | Recipes. | Yes. |
| ``data-lldap-0`` | ``lldap`` | Users and groups. Its hourly bootstrap recreates what's in git (``apps/base/lldap/bootstrap``) with Vault's passwords, anything made only in the UI needs the backup. Password hashes depend on ``LLDAP_KEY_SEED``. | Yes. |
| ``data-grafana-0`` | ``monitoring`` | Users, preferences, anything made in the UI. Dashboards and data sources are provisioned from git. | If wanted. |
| ``data-victoriametrics-0``, ``data-victorialogs-0`` | ``monitoring`` | Metrics and logs history. | If wanted. |
| ``data-redis-0..2`` | ``redis`` | contentbot's data (the AOF). | If wanted. |
| ``data-rabbitmq-0..2`` | ``rabbitmq`` | Queued messages. Users and permissions are in git. | No. |
| ``vector-aggregator`` | ``vector`` | Its buffer and downloaded geo data and threat intel, fetched again on start. | No. |

## Vault's secrets

Under ``labv2/`` (kv v2), what each ExternalSecret reads. Where an ExternalSecret has a comment on top, it says what each key is for and how to make one; a secret made anew needs whatever uses it changed too (a client's password, an OIDC digest).

| Path | Read by | Keys |
| --- | --- | --- |
| ``production/cert-manager`` | The ClusterIssuers (DNS-01) | ``api-token`` (Cloudflare, Zone:DNS:Edit) |
| ``production/longhorn`` | Longhorn's backup target | ``CIFS_USERNAME``, ``CIFS_PASSWORD`` (the NAS user of ``longhorn-backups``) |
| ``production/flux-system`` | Flux's commit statuses | ``token`` (flux-bot's, see [Flux](flux.md#commit-statuses)) |
| ``production/alertmanager`` | Alertmanager | ``HEALTHCHECKS_URL``, ``NTFY_TOPIC`` |
| ``production/authelia`` | Authelia, LLDAP's bootstrap | ``AUTHELIA_JWT_SECRET``, ``AUTHELIA_SESSION_SECRET``, ``AUTHELIA_STORAGE_ENCRYPTION_KEY``, ``AUTHELIA_LDAP_PASSWORD``, ``AUTHELIA_OIDC_HMAC_SECRET``, ``AUTHELIA_OIDC_JWKS_KEY``, ``AUTHELIA_OIDC_GRAFANA_CLIENT_SECRET_DIGEST``, ``AUTHELIA_OIDC_MEALIE_CLIENT_SECRET_DIGEST`` |
| ``production/lldap`` | LLDAP | ``LLDAP_JWT_SECRET``, ``LLDAP_KEY_SEED``, ``LLDAP_ADMIN_PASS``, ``HIREDNOOBS_PASSWORD`` |
| ``production/grafana`` | Grafana | ``GRAFANA_ADMIN_PASS``, ``GRAFANA_OIDC_CLIENT_SECRET`` |
| ``production/mealie`` | Mealie | ``OIDC_CLIENT_SECRET`` |
| ``production/homepage`` | Homepage's widgets | ``HOMEPAGE_VAR_*`` (the ones ``apps/base/homepage/config/services.yaml`` uses) |
| ``production/pihole`` | Pi-hole | ``PIHOLE_WEB_ADMIN_PASS``, ``PIHOLE_API_APP_PWHASH`` |
| ``production/redis`` | Redis, the redis-ca ClusterIssuer | ``REDIS_ADMIN_PASSWORD``, ``REDIS_REPLICA_PASSWORD``, ``REDIS_SENTINEL_PASSWORD``, ``REDIS_EXPORTER_PASSWORD``, ``ca.crt``, ``ca.key`` |
| ``production/rabbitmq`` | RabbitMQ, its Topology Operator, the rabbitmq-ca ClusterIssuer | ``RABBITMQ_DEFAULT_USER``, ``RABBITMQ_DEFAULT_PASS``, ``RABBITMQ_ERLANG_COOKIE``, ``ca.crt``, ``ca.key`` |
| ``production/contentbot`` | contentbot, its Redis and RabbitMQ users | ``CYTUBE_USER``, ``CYTUBE_PASS``, ``REDIS_PASSWORD``, ``RABBITMQ_PASSWORD`` |

Redis' and RabbitMQ's CAs signed the certificates of their clients outside the cluster: a new CA means new certificates for them. ``vsecret`` (tools-bin) sets keys and forces the ExternalSecrets reading them to sync.

## Checks

- ``flux get kustomizations``: all Ready. ``kubectl get externalsecrets -A``: all ``SecretSynced``.
- ``deployment status`` (tools-bin): every pod running, no restarts climbing.
- Logging in through Authelia works (Grafana), Vaultwarden has its vault, Pi-hole answers on ``192.168.111.100``.
- Grafana's Overview fills; vmalert shows no rule errors.
- The next night's Longhorn backup runs (Backup in its UI).
