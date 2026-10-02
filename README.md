# localiam

[![CI](https://github.com/blairham/localiam/actions/workflows/ci.yml/badge.svg)](https://github.com/blairham/localiam/actions/workflows/ci.yml)
[![CodeQL](https://github.com/blairham/localiam/actions/workflows/codeql.yml/badge.svg)](https://github.com/blairham/localiam/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blairham/localiam/badge)](https://scorecard.dev/viewer/?uri=github.com/blairham/localiam)
[![Go Reference](https://pkg.go.dev/badge/github.com/blairham/localiam/verify.svg)](https://pkg.go.dev/github.com/blairham/localiam/verify)
[![Go version](https://img.shields.io/github/go-mod/go-version/blairham/localiam)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**LocalIAM** verifies the AWS SigV4-presigned tokens services present as
data-plane credentials, so a local cluster can run Redis, Postgres and Kafka with
the **same IAM auth path AWS enforces** instead of plaintext.

Consumed as a **container**, not a Go module — an agent sidecar in each
workload pod, a proxy sidecar beside each store, and one central server.

> [!WARNING]
> localiam is a **test tool**, not an authentication system. The credentials it
> issues are fake, the stores behind its proxies run with authentication
> disabled, and it is built for local and CI environments on networks you
> control. Never expose it to the internet or point it at real credentials or
> data. See [SECURITY.md](SECURITY.md).

## Why

Local environments run plaintext, so an IAM auth path is first exercised against
real AWS. The classic failure: a service mints one ElastiCache token at startup
and never refreshes it; the first reconnect past the 15-minute TTL re-auths with
an expired token and gets `WRONGPASS`. `verify` makes that failure reproducible
on a laptop — `TestAnExpiredTokenIsRejected` is that bug, executable.

## What works

| | Mechanism | Entry point |
|---|---|---|
| Redis | ElastiCache `connect` token as AUTH password | `verify.ElastiCache` |
| Postgres | RDS `connect` token as password | `verify.RDS` |
| Kafka (.NET) | SASL/**OAUTHBEARER**, base64url presigned URL | `verify.MSKOAuthBearer` |
| Kafka (Go) | SASL/**AWS_MSK_IAM**, JSON envelope | `verify.MSKAWSMSKIAM` |

> **Real clients use both Kafka mechanisms.** Go services (franz-go
> `ManagedStreamingIAM`) speak `AWS_MSK_IAM`; .NET services (Confluent.Kafka,
> `AWS.MSK.Auth`) speak `OAUTHBEARER`. Same signature, different envelope — a
> broker adapter must accept both or it locks out half the services.

## Quick start

```sh
make build
./dist/localiam server -listen 127.0.0.1:8080 -token dev &
./dist/localiam agent -service app -role-arn arn:aws:iam::000000000000:role/app \
    -register http://127.0.0.1:8080 -register-token dev &

# the real AWS CLI, pointed at the agent the way EKS Pod Identity points a pod
export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:1338/v1/credentials
export AWS_CONTAINER_AUTHORIZATION_TOKEN=local AWS_REGION=us-east-1
TOKEN=$(aws rds generate-db-auth-token --hostname postgres --port 5432 --username app)

curl -s -X POST 127.0.0.1:8080/v1/verify/rds \
  -d "{\"token\":\"$TOKEN\",\"host\":\"postgres\",\"port\":5432,\"dbUser\":\"app\"}"
# {"ok":true,"service":"app",…}  — and 15 minutes later: "localiam: token expired"
```

[Getting started](docs/getting-started.md) walks through it.

## How it runs

One binary, one image; the subcommand picks the role:

| Role | Command | Runs as |
|---|---|---|
| agent | `localiam agent` | a sidecar container in every workload pod, serving the EKS Pod Identity contract on loopback, so the workload's **unchanged** SDK mints its own tokens |
| server | `localiam server` | one Deployment: holds every issued credential, answers verification, applies per-service [policy](docs/reference/policy.md) |
| proxy | `localiam proxy` | a sidecar container in each store's pod, in front of a Redis, Postgres or Kafka running with auth disabled |
| — | `localiam gen-certs` | once, to make a CA and keypair for the Kafka proxy's TLS |

The image is published as `ghcr.io/blairham/localiam:<version>` for
linux/amd64 and linux/arm64 (`make image` builds one from source). It is
distroless (uid 65532, no userland); `/bin/sh` in it is a [gated
shell](internal/shell/README.md) that can read `/proc` and cannot exec.
Helm charts for the server and the sidecars are in [`charts/`](charts).
See [Running in Kubernetes](docs/kubernetes.md).

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | the quick start above, step by step |
| [Running in Kubernetes](docs/kubernetes.md) | the image, the Helm charts, the server, the agent and proxy sidecars, TLS, hardening |
| [CLI reference](docs/reference/cli.md) | every flag and environment variable |
| [Policy](docs/reference/policy.md) | the per-service spec format, and what is enforced where |
| [HTTP API](docs/reference/http-api.md) | the server's endpoints |
| [Troubleshooting](docs/troubleshooting.md) | every rejection message, and what causes it |
| [Architecture](docs/architecture/iam-auth.md) | why it is built this way |
| [The gated shell](internal/shell/README.md) | what `/bin/sh` and `/debug/sh` can and cannot do |

### Known gaps

- Per-topic Kafka authorization is not enforced: the server can answer it
  (`/v1/authorize`) but the Kafka proxy does not ask. Connect-level policy is
  enforced.
- The credential store is in memory: run one server replica, and restart the
  agents after restarting the server.

## The independence rule

`verify` is a **deliberately independent** implementation of SigV4
canonicalization. It must never import a client library that *mints* these
tokens, or share a canonicalization helper with one.

A verifier that shares its canonical form with the minter cannot detect a
canonicalization bug — both sides are wrong the same way and the tests go green.
Instead the tests pin it to bytes from third-party implementations:
aws-sdk-go-v2's presigner for ElastiCache/RDS/OAUTHBEARER, franz-go for
`AWS_MSK_IAM`.

That is not theoretical either. The first `AWS_MSK_IAM` reconstruction folded
`user-agent` into the signed query; the franz-go cross-check rejected it
immediately. A self-referential test would have passed.

## Tests

```sh
go test ./...
```

Two tiers: **cross-check** (third-party-minted tokens must verify, plus frozen
golden signatures that catch drift in either implementation) and **negative**
(expired, not-yet-valid, tampered, unknown key, wrong host/service/user,
session mismatch, malformed envelopes).

⚠ Tests use AWS's **published** SigV4 example credentials (`AKIDEXAMPLE` /
`wJalrX…EXAMPLEKEY`) so a golden vector carries no real secret.
`.gitleaks.toml` allowlists exactly those strings.

## Contributing

Contributions are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first. The
independence rule above is enforced in review, and contributions require a
signed [CLA](CLA.md). This project follows a [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately, never in a public issue — see
[SECURITY.md](SECURITY.md). A token the verifier should have rejected is a
vulnerability.

Releases are signed with cosign — see
[Verifying a release](SECURITY.md#verifying-a-release).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
