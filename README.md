# iac-k8s

What runs on the Kubernetes clusters, reconciled by [Flux](https://fluxcd.io). The clusters themselves (Talos VMs) are built by ``iac-homelab``.

The upstream is ``git@git.hirednoobs.com:hirednoobs/iac-k8s.git``, every push is mirrored to GitHub (read-only).

## How it works

Flux runs in each cluster (``flux-system`` namespace), pulls this repo over SSH with a read-only deploy key and applies it on an interval, pruning whatever was removed. Nothing outside the cluster applies anything: merge to ``master`` and Flux picks it up within ``interval``, or straight away with ``flux reconcile kustomization flux-system --with-source``. Changes made by hand are reverted on the next reconcile, change the repo instead.

CI (``.forgejo/workflows/lint.yml``) only validates, and must pass before a pull request merges: each Flux Kustomization's path is built (every kustomization must be under one) and checked against the Kubernetes and Flux schemas, Vector's config is validated and its unit tests run, and the ATT&CK coverage files match the alert rules. Renovate (the renovate repo) opens a pull request for each new chart, image or tool version, a merge is a deploy.

The ``flux`` CLI on the management VM (installed by tools-bin's ``context-setup``) is for the bootstrap, upgrades and troubleshooting (``flux get kustomizations``, ``flux logs``, ``flux suspend``/``resume``).

## Layout

| Path | Contents |
| --- | --- |
| ``clusters/<cluster>/`` | Read by Flux as the cluster's entry point. ``flux-system/`` is written by the bootstrap, don't edit it. |
| ``clusters/<cluster>/infrastructure.yaml`` | ``infra-controllers`` (``infrastructure/controllers``), then ``infra-configs`` (``infrastructure/configs``) and ``infra-operators`` (``infrastructure/operators``) once the controllers are ready. |
| ``clusters/<cluster>/apps.yaml`` | ``apps`` (``apps/<cluster>``), once the infrastructure is ready. Then ``rabbitmq-topology`` (``apps/<cluster>/rabbitmq-topology``), RabbitMQ's users and permissions: the Topology Operator's webhook rejects them until ``apps``' ExternalSecrets have created their Secrets. |
| ``infrastructure/controllers/`` | Cluster controllers: ESO, Reloader, cert-manager, kube-vip, Envoy Gateway, Longhorn, metrics-server, kubelet-serving-cert-approver. |
| ``infrastructure/operators/`` | Controllers whose manifests need the other controllers' CRDs (cert-manager Certificates for their webhooks): RabbitMQ's Topology Operator. |
| ``infrastructure/configs/`` | Config using the controllers' CRDs: ClusterSecretStore, ClusterIssuer, StorageClasses, the Gateway. |
| ``apps/base/<app>/`` | One app: namespace, HelmRelease or manifests, ExternalSecret. |
| ``apps/<cluster>/`` | The apps a cluster runs, plus patches for that cluster. Subdirectories are separate Flux Kustomizations (``rabbitmq-topology``). |

Clusters are named after their tools-bin context with a ``-`` (``production.core`` -> ``production-core``).

## Conventions

- The namespace is the app's name.
- Upstream Helm charts as a ``HelmRelease`` at an exact chart version, Kustomize manifests otherwise. Images pinned by digest.
- No secrets in git. One ``ExternalSecret`` per app from Vault (``labv2/production/<app>``), see [Adding an app](docs/apps.md).
- Placement with replicas, ``topologySpreadConstraints`` on ``topology.kubernetes.io/zone``, PDBs and resource requests. ``nodeSelector`` only for hardware (the Longhorn disk), no stack labels.
- Upstream release manifests (no chart) are vendored unmodified, with their URL and checksum in the kustomization, and changed with patches.
- A new controller's CRDs need their schemas added to ``lint.yml`` (download the release's CRDs, pinned by checksum, or pass a vendored manifest, and convert them with ``.forgejo/scripts/crd-schemas.py``), a missing schema fails CI.

## More

| Page | Covers |
| --- | --- |
| [Adding an app](docs/apps.md) | Its secrets (an ExternalSecret from Vault) and its route (an HTTPRoute, Authelia, HTTPS backends). |
| [Flux](docs/flux.md) | The bootstrap, commit statuses on Forgejo, upgrading Flux. |
| [Rebuilding a cluster](docs/rebuild.md) | Flux on a new cluster, the Vault secrets it needs, restoring the volumes from Longhorn's backups. |
