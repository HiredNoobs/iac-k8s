# Flux

Installing Flux in a cluster, its commit statuses on Forgejo, and upgrading it.

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

## Commit statuses

Flux posts each Kustomization's result on the iac-k8s commit it applied (``infrastructure/configs/flux-notifications``). The token belongs to ``flux-bot``, a plain Forgejo user that's a collaborator with Write access on iac-k8s only: Forgejo tokens can't be scoped to one repo, so a token of the owner would reach every repo. It has ``repository: Read and write`` and is in Vault under the key ``token``:

```bash
vault kv put -mount=labv2 production/flux-system token=<token>
```

## Upgrading Flux

Bump ``FLUX_VERSION`` in tools-bin and re-run ``context-setup k8s`` on the management VM, bump ``FLUX_VERSION`` and ``FLUX_CRD_SCHEMAS_SHA256`` in ``lint.yml``, then run the bootstrap again with a new token. It commits the new ``flux-system/`` and Flux upgrades itself.

Re-run the bootstrap too if the git VM is rebuilt: its SSH host key changes and Flux checks it (``known_hosts`` in the ``flux-system`` secret).
