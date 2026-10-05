# iac-k8s

What runs on the Kubernetes clusters, reconciled by [Flux](https://fluxcd.io). The clusters themselves (Talos VMs) are built by ``iac-homelab``.

The upstream is ``git@git.hirednoobs.com:hirednoobs/iac-k8s.git``, every push is mirrored to GitHub (read-only).

## How it works

Flux runs in each cluster (``flux-system`` namespace), pulls this repo over SSH with a read-only deploy key and applies it on an interval, pruning whatever was removed. Nothing outside the cluster applies anything: merge to ``master`` and Flux picks it up within ``interval``, or straight away with ``flux reconcile kustomization flux-system --with-source``. Changes made by hand are reverted on the next reconcile, change the repo instead.

CI (``.forgejo/workflows/lint.yml``) only validates: every kustomization is built and checked against the Kubernetes and Flux schemas.

The ``flux`` CLI on the management VM (installed by tools-bin's ``context-setup``) is for the bootstrap, upgrades and troubleshooting (``flux get kustomizations``, ``flux logs``, ``flux suspend``/``resume``).

## Layout

| Path | Contents |
| --- | --- |
| ``clusters/<cluster>/`` | Read by Flux as the cluster's entry point. ``flux-system/`` is written by the bootstrap, don't edit it. |
| ``clusters/<cluster>/infrastructure.yaml`` | ``infra-controllers`` (``infrastructure/controllers``), then ``infra-configs`` (``infrastructure/configs``) once the controllers are ready. |
| ``clusters/<cluster>/apps.yaml`` | ``apps`` (``apps/<cluster>``), once the infrastructure is ready. |
| ``infrastructure/controllers/`` | Cluster controllers: ESO, Reloader, cert-manager, Longhorn, kube-vip, the gateway. |
| ``infrastructure/configs/`` | Config using the controllers' CRDs: ClusterSecretStore, ClusterIssuer, StorageClasses, the Gateway. |
| ``apps/base/<app>/`` | One app: namespace, HelmRelease or manifests, ExternalSecret. |
| ``apps/<cluster>/`` | The apps a cluster runs, plus patches for that cluster. |

Clusters are named after their tools-bin context with a ``-`` (``production.core`` -> ``production-core``).

## Conventions

- The namespace is the app's name.
- Upstream Helm charts as a ``HelmRelease`` at an exact chart version, Kustomize manifests otherwise. Images pinned by digest.
- No secrets in git. One ``ExternalSecret`` per app from Vault (``labv2/production/<app>``).
- Placement with replicas, ``topologySpreadConstraints`` on ``topology.kubernetes.io/zone``, PDBs and resource requests. ``nodeSelector`` only for hardware (the Longhorn disk), no stack labels.
- A new controller's CRDs need their schemas added to ``lint.yml`` (download the release's CRDs, pinned by checksum, and convert them with ``.forgejo/scripts/crd-schemas.py``), a missing schema fails CI.

## Secrets

External Secrets Operator syncs them from Vault through the ``vault`` ClusterSecretStore (``infrastructure/configs``). ESO logs in with Vault's ``kubernetes/<cluster>`` auth mount, set up by iac-homelab's ``terraform/vault`` root, and can only read ``labv2/<environment>/*``.

One ``ExternalSecret`` per app, every key of the app's Vault secret becomes a key of the Kubernetes secret:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: <app>
  namespace: <app>
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: vault
  target:
    name: <app>
  dataFrom:
    - extract:
        key: production/<app>
```

Annotate the workloads reading it with ``reloader.stakater.com/auto: "true"``, Reloader restarts them when the secret changes.

## Bootstrap

Once per cluster, from the management VM. ``flux`` must be the version in tools-bin's ``FLUX_VERSION`` (``flux version --client``), that's the version installed in the cluster.

1. Create a Forgejo token (Settings -> Applications) named ``flux-bootstrap`` with ``repository: Read and write`` and ``misc: Read``. It's only used by the CLI, to commit ``flux-system/`` and add the deploy key.
2. Bootstrap:

   ```bash
   export GITEA_TOKEN=<token>
   kubeconfig="$KUBE_CONTEXTS/production.core.yaml"

   flux check --pre --kubeconfig "$kubeconfig"
   flux bootstrap gitea --kubeconfig "$kubeconfig" \
     --hostname=git.hirednoobs.com --owner=hirednoobs --repository=iac-k8s --personal --private \
     --branch=master --path=clusters/production-core
   unset GITEA_TOKEN
   ```

3. Delete the token in Forgejo and pull the bootstrap commit.
4. Check: ``flux check``, ``flux get sources git`` and ``flux get kustomizations`` (all Ready).

## Upgrading Flux

Bump ``FLUX_VERSION`` in tools-bin and re-run ``context-setup k8s`` on the management VM, bump ``FLUX_VERSION`` and ``FLUX_CRD_SCHEMAS_SHA256`` in ``lint.yml``, then run the bootstrap again with a new token. It commits the new ``flux-system/`` and Flux upgrades itself.

Re-run the bootstrap too if the git VM is rebuilt: its SSH host key changes and Flux checks it (``known_hosts`` in the ``flux-system`` secret).
