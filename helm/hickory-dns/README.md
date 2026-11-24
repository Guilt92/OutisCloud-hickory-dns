# Hickory DNS Helm chart

This chart now renders the control API, authoritative DNS server, and UI. It is
an integration package, not a validated high-availability production topology.

Before installation, provide:

1. A **pre-provisioned ReadWriteMany** PVC in the chart namespace. Set
   `zoneStorage.existingClaim` to its name. The API writes zone files and the DNS
   server mounts the same claim read-only. Helm does not create or delete the
   claim, so uninstall does not delete zone state.
2. An existing `hickory-secrets` Secret with `database-url` and `jwt-secret`
   keys. The database URL must point to an externally managed PostgreSQL
   instance. Do not put secret values in a Helm values file or commit them.
3. Working image references for `controlApi.image`, `dnsServer.image`, and
   `ui.image`. The defaults target the repository's GHCR `main` tags; verify
   that CI published them and pin immutable digest or commit tags in your
   deployment profile.
4. DNS Service type and external DNS delegation appropriate to the test
   environment. The chart does not change delegation or issue certificates.

The DNS init container writes a minimal `named.toml` only when the claim has no
config file. Existing configuration is retained. The control API's publisher
then owns zone/config updates. Keep `controlApi.replicaCount=1` and autoscaling
disabled until deterministic multi-writer publication is implemented.

Validate before deployment:

```sh
helm lint helm/hickory-dns
helm template outis helm/hickory-dns --namespace hickory-dns > /tmp/outis-rendered.yaml
```

The chart has not been applied to a Kubernetes cluster. A cluster test must
verify RWX access, Secret/image availability, DNS UDP/TCP answers, readiness
transition, UI proxying, and upgrade/rollback behavior.
