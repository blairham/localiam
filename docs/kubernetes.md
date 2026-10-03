# Running in Kubernetes

A cluster has three kinds of localiam container, all from **one image** — the
subcommand picks the role:

```
 workload pod                      localiam pod               store pod (e.g. Redis)
┌──────────────────────────┐      ┌────────────────┐         ┌───────────────────────────┐
│ app ──► localiam agent ──┼─────►│ localiam server│◄────────┼── localiam proxy :6379    │
│  (SDK)   127.0.0.1:1338  │ reg- │  :8080         │ verify  │        │                  │
└──────────────────────────┘ ister└────────────────┘         │        ▼ loopback         │
        │                                                    │   redis :6380, no auth    │
        └──────────── Redis protocol + IAM token ───────────►└───────────────────────────┘
```

- **agent** — a sidecar in *every workload pod*, on loopback, because EKS Pod
  Identity is per pod and the SDK only trusts a loopback credentials endpoint.
- **server** — one Deployment. Holds every issued credential, answers
  verification.
- **proxy** — a sidecar in *each store's pod*, in front of a store running with
  authentication disabled. Never beside the client: a pod verifying a token it
  minted itself proves nothing.

Why one image rather than one per role: the roles share the verifier, the
credential store and the client code, so separate images would carry the same
binary; one image means one version to pin, and an agent and server that can
never disagree about the registration API. The whole image is about 10 MB.

## The image

```
ghcr.io/blairham/localiam:<version>      linux/amd64, linux/arm64
```

Each release publishes the image tagged with its version (`0.0.0` for the
`v0.0.0` release) and moves `latest` to the newest non-prerelease. **Pin a
version** — the examples below use `0.0.0`; replace it with the release you
want. The image is public, so no pull secret is needed.

To run an unreleased build, build it from source and load it into your
cluster:

```sh
make image                                  # -> localiam:dev
kind load docker-image localiam:dev         # kind; or push to your own registry
```

then use `image: localiam:dev` with `imagePullPolicy: IfNotPresent`.

The image is `gcr.io/distroless/static-debian12:nonroot`: uid 65532, no package
manager, no userland. `/bin/sh` is a [gated shell](../internal/shell/README.md)
for reading `/proc` — it cannot exec anything.

## The server

```yaml
apiVersion: v1
kind: Secret
metadata: {name: localiam}
stringData:
  register-token: change-me            # agents present this to register
---
apiVersion: v1
kind: ConfigMap
metadata: {name: localiam-specs}
data:
  api.yaml: |                           # file name = service name
    podIdentity:
      permissions:
        elastiCache: true
        rds: {dbUser: api}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: localiam}
spec:
  replicas: 1                           # the credential store is in memory
  selector: {matchLabels: {app: localiam}}
  template:
    metadata: {labels: {app: localiam}}
    spec:
      containers:
        - name: localiam
          image: ghcr.io/blairham/localiam:0.0.0
          args: [server, "-listen=:8080", -specs=/specs, "-token=$(REGISTER_TOKEN)"]
          env:
            - name: REGISTER_TOKEN
              valueFrom: {secretKeyRef: {name: localiam, key: register-token}}
          ports: [{containerPort: 8080}]
          readinessProbe: {httpGet: {path: /healthz, port: 8080}}
          volumeMounts: [{name: specs, mountPath: /specs}]
      volumes:
        - name: specs
          configMap: {name: localiam-specs}
---
apiVersion: v1
kind: Service
metadata: {name: localiam}
spec:
  selector: {app: localiam}
  ports: [{port: 8080}]
```

**Run one replica.** Credentials live in the server's memory; a second replica
would not know the first's, and a restart forgets them all (restart the agents
after restarting the server).

## The agent, in a workload's pod

Add the agent as a sidecar and point the workload's SDK at it. Nothing in the
workload's code changes.

```yaml
spec:
  containers:
    - name: app
      image: my-app
      env:
        - name: AWS_CONTAINER_CREDENTIALS_FULL_URI
          value: http://127.0.0.1:1338/v1/credentials
        - name: AWS_CONTAINER_AUTHORIZATION_TOKEN
          value: local                  # any non-empty value unless the agent has -token-file
        - name: AWS_REGION
          value: us-east-1
    - name: localiam
      image: ghcr.io/blairham/localiam:0.0.0
      args: [agent, -service=api, "-role-arn=arn:aws:iam::000000000000:role/api"]
      env:
        - name: LOCALIAM_REGISTER_URL
          value: http://localiam.default.svc.cluster.local:8080
        - name: LOCALIAM_REGISTER_TOKEN
          valueFrom: {secretKeyRef: {name: localiam, key: register-token}}
```

`-service` must match the spec's file name (`api` → `api.yaml`). Make sure the
workload has no other credentials (`AWS_ACCESS_KEY_ID`, a mounted `~/.aws`) —
the SDK prefers those over the container provider.

**Init containers** run before sidecars start, so they cannot reach the agent.
Either make the agent a native sidecar — move it to `initContainers` with
`restartPolicy: Always` (Kubernetes ≥ 1.29), which starts it first — or give the
init step static credentials via the server's
[`-principals`](reference/cli.md#bootstrap-principals).

## A proxy, in a store's pod

The store runs **without authentication**, on loopback, and the proxy owns the
port clients connect to. Redis:

```yaml
spec:
  containers:
    - name: redis
      image: redis:7-alpine
      args: [--port, "6380", --bind, 127.0.0.1]   # loopback only, no auth
    - name: localiam
      image: ghcr.io/blairham/localiam:0.0.0
      args: [proxy, "-redis-listen=:6379", "-redis-backend=127.0.0.1:6380",
             -redis-replication-group=my-group]
      env:
        - name: LOCALIAM_VERIFY_URL
          value: http://localiam.default.svc.cluster.local:8080
      ports: [{containerPort: 6379}]
```

Clients use the replication group id and user they would use against
ElastiCache, and TLS as usual.

**Postgres** — run Postgres with `POSTGRES_HOST_AUTH_METHOD=trust` on
`127.0.0.1:5433` and the proxy with `-pg-listen=:5432
-pg-backend=127.0.0.1:5433`. Set `-pg-host`/`-pg-port` (or `LOCALIAM_PG_HOST`/
`LOCALIAM_PG_PORT`) to the host and port **clients are configured with**,
because that is what their tokens are signed over — in a cluster, usually the
Service's DNS name.

**Kafka** — give the broker a PLAINTEXT listener on `127.0.0.1:9095`, run the
proxy with `-kafka-listen=:9094 -kafka-backend=127.0.0.1:9095
-kafka-host=<name clients dial> -kafka-tls-cert=… -kafka-tls-key=…`, and point
the broker's advertised listener at the proxy's address so Metadata responses
send clients back through it (see [RFC 0002](rfcs/0002-kafka-auth-termination.md)).
Clients must trust the certificate:

```sh
localiam gen-certs -hosts kafka.default.svc.cluster.local,kafka -out certs/
kubectl create secret generic localiam-kafka-tls --from-file=certs/
```

Mount `server.pem`/`server-key.pem` into the proxy, `ca.pem` into each client,
and set the clients' `SSL_CERT_FILE` to it.

The proxy enforces each service's topics, groups and transactional ids; see
[Policy](reference/policy.md#kafka-per-operation).

## Hardening a shared cluster

localiam is a test tool — read [SECURITY.md](../SECURITY.md). If the cluster is
shared:

- Keep the registration token secret: the server always requires `-token`,
  and the chart generates a random one into a Secret.
- Add a NetworkPolicy that lets only workload pods (agents) and store pods
  (proxies) reach the server, and only the proxies reach the stores' loopback
  ports — which they are, if the stores bind `127.0.0.1`.
- Leave `LOCALIAM_SHELL_TOKEN` unset unless you need `POST /debug/sh`; if you
  set it, read it from a Secret with `optional: true`.
- Do not use `exec` lifecycle hooks — the image has nothing to exec.

## Helm

Two charts in [`charts/`](../charts), both defaulting to
`ghcr.io/blairham/localiam:0.0.0`:

- [`localiam`](../charts/localiam/README.md) installs the server: the
  Deployment, Service, registration-token Secret (generated if you give none),
  specs ConfigMap, optional bootstrap principals, optional gated shell and an
  optional NetworkPolicy.
- [`localiam-sidecar`](../charts/localiam-sidecar/README.md) is a library
  chart. The agent and proxies are sidecars in pods *your* charts own, so it
  provides templates to include there — `localiam-sidecar.agent`,
  `localiam-sidecar.workloadEnv`, `localiam-sidecar.proxy` — rather than
  resources of its own.

```sh
helm install localiam ./charts/localiam -n localiam --create-namespace
```

The manifests above are what those charts render, written out by hand.
