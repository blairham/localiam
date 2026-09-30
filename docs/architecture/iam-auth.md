# Design: IAM auth, end to end

**Status:** Layers 1 and 3 built, with Redis, Postgres and Kafka proxies.
**Code:** `verify/`, `internal/{issuer,policy,proxy,server,client}/`, `cmd/localiam/`

## Purpose

Let a local cluster authenticate to Redis, Postgres and Kafka through the **same IAM
path AWS enforces**, so IAM auth bugs surface on a laptop instead of after
deploy.

## The three layers

| Layer | In AWS | In localiam | Do we build it? |
|---|---|---|---|
| 1. Credential — access key, secret, session token | EKS Pod Identity agent | localiam issuer | **yes** |
| 2. Token — SigV4 presigned | the service's own code | **the same code, untouched** | **no — never** |
| 3. Validation | ElastiCache / RDS / MSK servers | localiam `verify` + proxies | **yes** |

### 🚨 Layer 2 is not ours to write

Every service already mints these tokens in its own code, through a client
library or a small helper:

| Language | Typical minter |
|---|---|
| .NET | `AWS.MSK.Auth` (MSK); hand-rolled SigV4 presign helpers (ElastiCache, RDS) |
| Go | aws-sdk-go-v2 presigner and `feature/rds/auth`; franz-go `sasl/aws` (MSK) |
| Node | `aws-msk-iam-sasl-signer-js` (MSK), `@aws-sdk/rds-signer` (RDS), a hand-rolled `@smithy/signature-v4` presign (ElastiCache) |
| Python | botocore-based credential providers |

All of them sign **offline** — pure SigV4 over resolved credentials, with no
call to AWS. They need credentials, not an endpoint.

So a cluster needs no minter, and writing one would be actively harmful: the cluster
would then exercise *our* minting code instead of the service's, and a bug in
the real path would stay invisible. This is the same tautology the independence
rule (see `AGENTS.md`) exists to prevent, one layer up.

**The services run unchanged. That is the entire point of the exercise.**

🚨 **Four languages, and they do not all format a token the same way.** See
*Two token shapes* below — this is the single most expensive thing to get wrong,
because a parser that handles one shape looks completely healthy while locking
out every service that uses the other.

## Two token shapes

Both of these are in real use and both must verify:

```
postgres:5432?Action=connect&...     aws-sdk-go-v2 feature/rds/auth — Go services
postgres:5432/?Action=connect&...    hand-rolled .NET helpers, and the Node minters
```

aws-sdk-go-v2's RDS signer omits the `/` before the query delimiter; hand-rolled
helpers and Node's `${host}/?${params}` builders include it. The signed
canonical path is `/` either way — the minters sign the same request and differ
only in how they render the result.

⚠ The original verifier required the slash, so it rejected every token minted by
every Go service. The cross-check was green throughout, because it presigned
through the GENERIC signer rather than the RDS one real clients call.
**Cross-check against the exact function real clients call, not a cousin that
signs the same request.** Pinned by `TestRDSAcceptsTheRealSignersToken`.

## Layer 1 — credential issuance

The target is **EKS Pod Identity**, not IRSA: Pod Identity injects
`AWS_CONTAINER_CREDENTIALS_FULL_URI` and
`AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, while IRSA's
`AWS_WEB_IDENTITY_TOKEN_FILE` is a different shape entirely.

⚠ **One SDK constraint decides the topology.** The AWS SDK **rejects**
`AWS_CONTAINER_CREDENTIALS_FULL_URI` over plain HTTP unless the host resolves to
loopback or the ECS/EKS link-local addresses.

The topology is therefore a real decision, recorded in
[RFC 0001](../rfcs/0001-credential-issuance-topology.md): **per-pod sidecar on
loopback**, because a local credential agent reached over loopback is precisely
what Pod Identity is.

`issuer` serves that contract (`GET /v1/credentials`, `Authorization` header from
the token file, the ECS credentials JSON shape Pod Identity reuses). Each minted
credential is pushed to the central `server`, because credentials are issued per
pod but verified at the shared stores — one Kafka broker sees tokens signed by
every pod's agent.

## Layer 3 — validation

Covered in [design/token-verification.md](../design/token-verification.md):
an independent SigV4 implementation, four token shapes across three stores
(because real clients use **both** MSK SASL mechanisms), pinned by cross-check
vectors from third-party implementations.

## Policy

Each service's permissions come from a per-service spec YAML with a
`podIdentity.permissions` block, so a cluster enforces exactly what the service is
granted:

```yaml
podIdentity:
  permissions:
    msk:
      cluster: true
      topics: [requests, events, status, …]
    rds:
      dbUser: worker_app
```

⚠ **The three stores are not equal, and the policy engine should not pretend
they are.** Where IAM policy actually does work:

| Store | What IAM decides | Where real authorization lives |
|---|---|---|
| **Kafka** | per-resource: cluster connect, per-topic, per-group (`msk:` block) | IAM itself — this is the only place policy bites |
| **Postgres** | which `dbUser` you may connect as (`rds.dbUser`) | Postgres GRANTs — already work in a cluster, untouched |
| **Redis** | connect, nothing finer | nowhere — typically one shared IAM user, granted `elasticache:Connect` on the replication group + user ARN |

So the policy engine is deliberately **not** a general IAM implementation: no
conditions, no wildcards beyond a trailing `*` on a name, no `NotAction`, no
deny precedence. It parses the `msk`
block into topic/group grants, takes `rds.dbUser` as an identity, and treats
ElastiCache as connect-only. Anything more is modelling AWS for its own sake.

**The payoff:** a cluster catches "you forgot to add topic X to the service's
`msk.topics`" — which otherwise only fails once deployed. ⚠ Not yet: the server
answers per-topic questions at `/v1/authorize`, but the Kafka proxy does not
ask them, so today only connect-level Kafka policy is enforced. See
[Policy](../reference/policy.md#what-is-enforced-where).

## Fidelity target: lifecycle, not policy

The bugs this is built to catch are **credential lifecycle** bugs:
mint-once-never-refresh, stale token on reconnect, a refresh callback that never
fires. The canonical case is a perfectly well-formed, correctly signed token
that is wrong only about the time.

Policy evaluation is the lower-value half and the only part that would genuinely
need an AWS emulator. Hence the deliberately small subset above.

## Why not LocalStack

It covers **one of three stores, unvalidated**, and would be a paid dependency
that still leaves every verification hook to write:

- [ElastiCache](https://docs.localstack.cloud/user-guide/aws/elasticache/) — Pro tier, and "doesn't support … users/passwords". No IAM auth.
- [MSK](https://github.com/localstack/localstack/issues/10617) — IAM auth is an open enhancement request, backlog. Not implemented.
- [RDS](https://docs.localstack.cloud/aws/services/rds/) — supports the mechanics, but "IAM authentication is not yet validated at this stage". Any token works.

Since layer 2 needs no AWS at all, LocalStack's only real contribution would be
IAM policy evaluation — the half we deliberately scope down.

For unrelated AWS services a cluster may later need (S3, Secrets Manager), reach for
[moto](https://github.com/getmoto/moto) (Apache 2.0) or minio rather than
reopening the Pro question.

## Build order

1. ~~**Issuer + policy loader**~~ — built: `issuer`, `policy`, `server`, `cmd/localiam`.
2. ~~**Redis proxy**~~ — built: `proxy`, an ElastiCache-IAM-terminating RESP proxy in front of an untouched `redis:7-alpine`.
3. ~~**Kafka proxy**~~ — a Go proxy in front of the brokers, decoding only the SASL handshake and splicing the rest. See [RFC 0002](../rfcs/0002-kafka-auth-termination.md): NOT a Java broker callback, and NOT a client sidecar.
4. ~~**Postgres proxy**~~ — the same auth-termination shape as Redis.

TLS comes with the proxies regardless: ElastiCache and RDS both reject IAM auth
in the clear, and real clients demand it, so the cluster needs a self-signed cert
(`localiam gen-certs`). That is upside — a plaintext cluster skips the TLS path
entirely.

⚠ A terminating proxy adds a hop for the connection's life. Fine for correctness
testing, wrong for performance testing. This belongs in an **opt-in overlay**, never the default.

🚨 **Two different sidecars, and conflating them defeats the exercise.** The
credential agent is per-pod on loopback because Pod Identity is per-pod. The
auth terminators (Redis, Postgres, Kafka) sit in front of the STORES. A
terminator next to the client would have a pod verifying a token it minted
itself — anything that can mint can pass that check.

## The image

One image runs every role (`localiam agent`, `server`, `proxy`), published as
`ghcr.io/blairham/localiam:<version>`. The roles share the verifier, the
credential store and the client, so separate images would carry the same
binary; one image also means an agent and a server can never be two versions
that disagree about the registration API.

It is `gcr.io/distroless/static-debian12:nonroot`: no package manager, no libc,
no userland, uid 65532. `kubectl exec` still works because `/bin/sh` is a
[gated shell](../../internal/shell/README.md) — `github.com/blairham/sh` linked
as a library behind a deny-by-default policy. It reads `/proc` and
`/sys/fs/cgroup`, never `environ`, and refuses every exec, write and signal, so
it answers diagnostic questions without handing anyone a userland. The same
shell is reachable over HTTP at `POST /debug/sh` when the server is given
`LOCALIAM_SHELL_TOKEN`.
