# Adding an app

What an app in ``apps/base/<app>/`` needs beyond its manifests: its secrets from Vault, and its route through the Gateway.

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

## Routing

Everything on ``*.hirednoobs.com`` goes through one Gateway, ``public`` in ``gateway`` (``infrastructure/configs/gateway``), run by Envoy Gateway on the kube-vip IP in its ``EnvoyProxy``. Port 80 only redirects to HTTPS, which uses the wildcard certificate.

An app adds its own ``HTTPRoute``:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: <app>
  namespace: <app>
spec:
  parentRefs:
    - name: public
      namespace: gateway
      sectionName: https
  hostnames:
    - <app>.hirednoobs.com
  rules:
    - backendRefs:
        - name: <service>
          port: <port>
```

Behind Authelia: a ``SecurityPolicy`` targeting the route (copy ``apps/base/homepage/security-policy.yaml``; one per namespace, listing all its routes, as in ``apps/base/monitoring/security-policy.yaml``), and the app's namespace added to the ``authelia`` ReferenceGrant in ``apps/base/authelia/reference-grant.yaml``.

HTTPS backends in the cluster are verified, never ``insecureSkipVerify``: a certificate from a cert-manager CA (``internal-ca`` for anything only the Gateway talks to), then either a ``BackendTLSPolicy`` on the Service (``apps/base/authelia/certificate.yaml``) or, for a ``Backend``, its ``tls.caCertificateRefs`` and ``sni`` (``apps/base/pihole/routes.yaml``). The CA's ``ca.crt`` comes from the app's own certificate Secret, in its namespace.

Sites outside the cluster (the NAS, Proxmox) and the stacks not migrated yet are in ``infrastructure/configs/gateway/routes``, with a ``Backend`` for the upstream. Move a stack's route to its app when it's migrated.
