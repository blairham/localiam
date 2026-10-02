# Troubleshooting

Every rejection is logged by the server (`verification denied … error=…`) and
returned in `/v1/verify`'s `error` field. The Redis proxy answers a rejected
client with the same `WRONGPASS` ElastiCache would; the Postgres and Kafka
proxies with an authentication failure. **Read the server log** — it names the
reason, the client does not.

## Rejections

| Error | What it means | Usual cause |
|---|---|---|
| `localiam: token expired: expired 3m12s ago (ttl 900s)` | The token's `X-Amz-Date + X-Amz-Expires` is in the past. | **The bug localiam exists to catch**: the client minted one token at startup and reuses it. ElastiCache and RDS tokens live 15 minutes; mint a fresh one per connection (most SDKs' credential-provider hooks do this for you). |
| `localiam: credential expired: <key> lapsed 2m ago` | The token is inside its window, but the **credential** that signed it has expired. | The client caches credentials past their expiry instead of letting the SDK refresh them. Shorten the agent's `-ttl` to reproduce faster. |
| `localiam: token not yet valid: signed 7m0s in the future` | `X-Amz-Date` is more than 5 minutes ahead of the server's clock. | Clock skew between the client's container and the server. |
| `localiam: unknown access key: ASIA…` | The server has never seen the key that signed the token. | The agent was started without `-register`, cannot reach the server, or the server restarted and lost its in-memory store (restart the agents too). Or the client is using credentials that did not come from the agent — check for `AWS_PROFILE`, `AWS_ACCESS_KEY_ID` or `~/.aws` in the client's environment. |
| `localiam: signature mismatch` | The signature does not match the canonical request. | The token was altered in transit, or a hand-written signer canonicalizes differently from AWS. A real bug here — in a client or in localiam — is worth [an issue](https://github.com/blairham/localiam/issues); a token localiam should have **rejected** but accepted is a [security report](../SECURITY.md). |
| `localiam: unexpected host: signed against "a", want "b"` | The token was signed for a different endpoint. | Redis: the client's replication group id differs from the proxy's `-redis-replication-group`. Postgres: the client dials a different host:port than `-pg-host`/`-pg-port` — tokens are signed over the address the **client** was configured with. Kafka: set `-kafka-host` to the name clients dial. |
| `localiam: unexpected action: token is for DBUser "a", startup named "b"` | The RDS token was minted for a different Postgres user. | The client minted with one `--username` and connects as another. |
| `localiam: unexpected action: token is for user "a", AUTH named "b"` | The ElastiCache token was minted for a different Redis user. | Same, for Redis `AUTH <user> <token>`. |
| `localiam: credential scope mismatch: …` | Wrong region or service in `X-Amz-Credential`, or a scope date that disagrees with the signing date. | The client's `AWS_REGION` differs from the server's `-region`, or it signed for the wrong service. |
| `localiam: session token mismatch` | The token carries a different session token than the one issued with its key. | Credentials from two different issues were mixed — typically a client caching pieces of a credential separately. |
| `localiam: malformed token: …` | The token could not be parsed. The detail says which part. | Truncation, a wrong mechanism (an `AWS_MSK_IAM` payload sent as `OAUTHBEARER`), or not a token at all. |
| `localiam: no service spec for "api"` | Authenticated, but `-specs` has no `api.yaml`. | Add the spec, or the agent's `-service` is not the file name. |
| `localiam: api is authenticated but not permitted` | The spec does not grant this connection. | See [Policy](reference/policy.md) — especially rule 2: declaring any `permissions` block replaces the shared role. |

## Setup problems

**`server: -token is required`.** The server refuses to start without a
registration token, because an open registration endpoint lets anyone who can
reach it plant credentials. Pass `-token` (the Helm chart generates one), or
`-open-registration` for a throwaway laptop run.

**The SDK will not use the agent.** It refuses
`AWS_CONTAINER_CREDENTIALS_FULL_URI` over plain HTTP unless the host is
loopback. The agent must `-listen` on `127.0.0.1` and run in the **same pod** as
the workload. The SDK also needs an authorization token:
`AWS_CONTAINER_AUTHORIZATION_TOKEN` or `…_TOKEN_FILE`.

**The agent answers 401.** It was started with `-token-file` and the workload's
`Authorization` header does not match the file's contents — or the workload set
no token at all.

**Credential requests fail with a registration error.** On purpose: when the
agent cannot register a credential with the server, it refuses to hand it out,
because it could never verify. Check `-register` and `-register-token` against
the server's address and `-token`.

**`ImagePullBackOff`.** Check the tag exists — images are published as
`ghcr.io/blairham/localiam:<version>` with no `v` prefix (`0.0.0`, not
`v0.0.0`). A locally built `localiam:dev` exists only on the machine that built
it: load it into the cluster (`kind load docker-image localiam:dev`) and set
`imagePullPolicy: IfNotPresent`. See [Kubernetes](kubernetes.md#the-image).

**A `preStop` hook fails silently.** The image is distroless and its `/bin/sh`
cannot exec, so `preStop: exec: [sleep, 5]` fails and the pod skips its drain.
Use `preStop: sleep: {seconds: 5}` (Kubernetes ≥ 1.30).

**Kafka clients reject the certificate.** They verify against the system trust
store. Generate a CA with `localiam gen-certs`, give the proxy `server.pem` /
`server-key.pem`, and point clients' `SSL_CERT_FILE` at `ca.pem`. The
certificate's `-hosts` must include the name clients dial.

**`TOPIC_AUTHORIZATION_FAILED`, `GROUP_AUTHORIZATION_FAILED` or
`TRANSACTIONAL_ID_AUTHORIZATION_FAILED` from Kafka.** The service's spec does
not grant that topic, group or transactional id; the server log line
`kafka operation denied` names which. A request that mixes an allowed and a
denied topic fails for every topic in it. See
[Policy](reference/policy.md#kafka-per-operation).

## Looking inside a running pod

The image is distroless, but `/bin/sh` is a gated shell that can read `/proc`
and `/sys/fs/cgroup`:

```sh
kubectl exec <pod> -c localiam -- /bin/sh -c 'read -r m < /sys/fs/cgroup/memory.max; echo $m'
```

It cannot run programs and cannot make HTTP requests. To curl the agent's
credentials endpoint from inside the pod, attach a debug container instead:

```sh
kubectl debug -it <pod> --image=curlimages/curl --target=localiam -- \
  curl -s -H 'Authorization: x' http://127.0.0.1:1338/v1/credentials
```

See [the shell's README](../internal/shell/README.md) for what it can do.
