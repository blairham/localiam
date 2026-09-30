# localiam (server chart)

Runs the localiam server: the Deployment that holds every issued credential and
answers verification. The agent and proxy sidecars go into *your* pods — use the
[localiam-sidecar](../localiam-sidecar/README.md) library chart for those.

⚠ localiam is a **test tool**, not an authentication system. Read
[SECURITY.md](../../SECURITY.md) before running it anywhere shared.

## Install

```sh
helm install localiam ./charts/localiam -n localiam --create-namespace \
  --set-json 'specs={"api":{"podIdentity":{"permissions":{"elastiCache":true,"rds":{"dbUser":"api"}}}}}'
```

The notes printed after install give the server's in-cluster URL and how to
read the generated registration token.

## Values

| Key | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/blairham/localiam` | |
| `image.tag` | chart `appVersion` (`0.0.0`) | Pin an immutable tag or a digest. |
| `region` | `us-east-1` | Region tokens must be scoped to. |
| `registration.token` | generated | Bearer token agents register with. Empty generates one on install and keeps it across upgrades. |
| `registration.existingSecret` | | Use an existing Secret instead. |
| `registration.secretKey` | `register-token` | Key within the Secret. |
| `specs` | `{}` | Per-service specs, keyed by service name. Empty means authenticate only. See [Policy](../../docs/reference/policy.md). |
| `existingSpecsConfigMap` | | Mount specs from your own ConfigMap (one `<service>.yaml` key each) instead. |
| `bootstrapPrincipals` | `[]` | Static credentials for init containers; stored in a Secret. See [bootstrap principals](../../docs/reference/cli.md#bootstrap-principals). |
| `shell.enabled` | `false` | Mount the gated shell at `POST /debug/sh`. |
| `shell.token` / `shell.existingSecret` / `shell.secretKey` | / / `shell-token` | Its bearer token. Read with `optional: true`: a missing Secret leaves the endpoint off (404), not the pod down. |
| `service.type` / `service.port` | `ClusterIP` / `8080` | |
| `networkPolicy.enabled` | `false` | Admit only `networkPolicy.from` to the server. |
| `networkPolicy.from` | `[]` | NetworkPolicy peers — your agents and proxies. |
| `serviceAccount.create` / `.name` / `.annotations` | `true` / / | The server never calls the Kubernetes API; no token is mounted. |
| `podSecurityContext`, `securityContext` | non-root 65532, read-only root, no capabilities, RuntimeDefault seccomp | |
| `resources` | 10m / 32Mi requests, 128Mi limit | |
| `nodeSelector`, `tolerations`, `affinity`, `priorityClassName`, `podAnnotations`, `podLabels`, `imagePullSecrets`, `additionalLabels`, `nameOverride`, `fullnameOverride` | | Standard. |

There is **no `replicaCount`**: the credential store is in memory, so the
Deployment runs exactly one pod with a `Recreate` strategy. A restart forgets
every registered credential — workloads get `unknown access key` until their
agent issues its next credential (at most the agent's `ttl`), or restart them.
Specs are read at startup, so changing `specs` restarts the server.

## Agents in other namespaces

Agents register with the token in `registration.secretKey` of the chart's
Secret. A pod can only read Secrets in its own namespace, so give each
workload namespace a copy — or set `registration.token` explicitly and create
the same Secret there.
