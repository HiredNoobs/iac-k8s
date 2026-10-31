# Logging

How logs get into VictoriaLogs (``apps/base/monitoring``): Vector (``apps/base/vector``) reads or receives them and maps them to ECS fields. Each config file's header has the detail.

## Two Vectors

- **The collectors** (``daemonset.yaml``, ``config/collector/``), one on each node, read that node's own logs.
- **vector-aggregator** (``aggregator.yaml``, ``config/aggregator/``), one pod, receives what other machines send, so the collectors only ever read their own node.

Both load ``config/common/`` with their own side's files and end in the same pipeline (``config/common/pipeline.yaml``), which writes to VictoriaLogs.

## Sources

| Source | Vector | How it arrives | Parsed by |
| --- | --- | --- | --- |
| Every pod's log lines, with their namespace, pod, container and labels | collectors | read from ``/var/log/pods`` | ``config/collector/pods.yaml``, then an app's own file or ``generic.yaml`` |
| kube-apiserver's audit log (``kubernetes.audit``), what's audited set by iac-homelab's ``terraform/modules/talos-cluster/audit-policy.yaml`` | collectors on the control planes | read from ``/var/log/audit/kube`` | ``config/collector/kubernetes-audit.yaml`` |
| Kubernetes events | collectors | ``kubectl``'s watch (``apps/base/kubectl``), as pod lines | ``config/collector/kubernetes-events.yaml`` |
| The nodes' own Talos logs and the kernel's audit records | collectors | sent by Talos to the ``talos-logs`` Service (``service.yaml``), local to each node | ``config/collector/talos.yaml``, ``talos-audit.yaml`` |
| The LAN's syslog | aggregator | relayed by rsyslog (``apps/base/rsyslog``) to the ``syslog`` Service | ``config/aggregator/syslog.yaml`` |
| The Proxmox hosts' journals | aggregator | through rsyslog, like the syslog | ``config/aggregator/journald.yaml`` |
| The prx-999 VMs' journals | aggregator | sent by their own Vector (iac-homelab's ``vector`` role) through the Gateway (``journald-route.yaml``) | ``config/aggregator/journald.yaml`` |
| Envoy's access log | collectors, then aggregator | parsed by the collectors (``config/collector/envoy.yaml``), handed over through the ``collectors`` Service | ``config/aggregator/collectors.yaml`` |

## Enrichment

The aggregator adds two things to the lines it handles, before the common pipeline:

- **Where public addresses are** (``config/aggregator/geo.yaml``): DB-IP's City and ASN Lite, fetched by ``scripts/geodata.sh``.
- **What's known-bad** (``config/aggregator/threat-intel.yaml``): abuse.ch's ThreatFox and URLhaus, and Spamhaus's DROP, fetched by ``scripts/threatintel.py``.

Both are fetched when the aggregator starts and every 6 hours after that, and Vector reloads them in place. The security detections on these logs are vmalert-logs' rules (``apps/base/monitoring/vmalert-logs/rules/``).

## Tests

``apps/base/vector/tests/`` has unit tests for each source, a file per source under the side that parses it. CI runs them when ``apps/base/vector/`` changes. ``tests/collector/pipeline.yaml`` says how to run them locally.
