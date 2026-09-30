# localiam-sidecar (library chart)

Container templates for localiam's two sidecars, to include in **your own**
charts: the credential **agent** goes in each workload pod, the auth-terminating
**proxy** in each store's pod. A library chart renders nothing on its own.

The server comes from the [localiam](../localiam/README.md) chart.

## Add the dependency

```yaml
# your chart's Chart.yaml
dependencies:
  - name: localiam-sidecar
    version: 0.0.0
    repository: file://path/to/localiam/charts/localiam-sidecar
```

```sh
helm dependency update
```

## The agent, in a workload pod

```yaml
spec:
  # A native sidecar (Kubernetes >= 1.29): starts before, and serves, your init
  # containers too. Drop `native` and put it under `containers` otherwise.
  initContainers:
    {{- include "localiam-sidecar.agent" (dict
          "service" "api"
          "roleArn" "arn:aws:iam::000000000000:role/api"
          "server" "http://localiam.localiam:8080"
          "registrationSecret" (dict "name" "localiam" "key" "register-token")
          "native" true) | nindent 4 }}
  containers:
    - name: app
      image: my-app
      env:
        {{- include "localiam-sidecar.workloadEnv" (dict "region" "us-east-1") | nindent 8 }}
```

| Key | Default | Meaning |
|---|---|---|
| `service` | *(required)* | The workload's name; selects `<service>.yaml` from the server's specs. |
| `roleArn` | *(required)* | Role the issued credentials authenticate as. |
| `server` | *(required)* | The server's URL. |
| `registrationSecret` | *(required)* | `{name, key}` of a Secret in this namespace holding the registration token (`key` defaults to `register-token`). |
| `image` | `ghcr.io/blairham/localiam:0.0.0` | |
| `port` | `1338` | Loopback port for the Pod Identity contract. |
| `ttl` | `15m` | Credential lifetime; shorten it to surface refresh bugs faster. |
| `native` | `false` | Render `restartPolicy: Always`, for use under `initContainers`. |
| `resources` | | |

`localiam-sidecar.workloadEnv` sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` and
`AWS_CONTAINER_AUTHORIZATION_TOKEN` (and `AWS_REGION` given `region`); pass
`port` if you changed the agent's. Make sure the workload has **no other AWS
credentials** — the SDK prefers environment keys and `~/.aws` over the agent.

## The proxy, in a store's pod

The store listens on loopback with authentication disabled; the proxy owns the
port clients connect to.

```yaml
spec:
  containers:
    - name: redis
      image: redis:7-alpine
      args: [--port, "6380", --bind, 127.0.0.1]
    {{- include "localiam-sidecar.proxy" (dict
          "server" "http://localiam.localiam:8080"
          "redis" (dict "replicationGroup" "my-group")) | nindent 4 }}
```

| Key | Default | Meaning |
|---|---|---|
| `server` | *(required)* | The server's URL. |
| `redis` | | `{port: 6379, backend: 127.0.0.1:6380, replicationGroup (required)}` |
| `postgres` | | `{port: 5432, backend: 127.0.0.1:5433, host (required), signedPort: 5432}` — `host`/`signedPort` are what **clients** are configured with; their tokens are signed over it. |
| `kafka` | | `{port: 9094, backend: 127.0.0.1:9095, host (required), tlsSecret}` — `tlsSecret` names a Secret with `server.pem`/`server-key.pem` from `localiam gen-certs`. |
| `image`, `resources` | | As for the agent. |

At least one of `redis`, `postgres`, `kafka` is required. With `kafka.tlsSecret`,
also add the volume:

```yaml
  volumes:
    {{- include "localiam-sidecar.kafkaTLSVolume" (dict "secretName" "kafka-tls") | nindent 4 }}
```

Both sidecars run non-root (65532) with a read-only root filesystem, no
capabilities and RuntimeDefault seccomp. See [Running in
Kubernetes](../../docs/kubernetes.md) for the whole picture.
