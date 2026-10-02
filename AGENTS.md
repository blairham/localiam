# AGENTS.md — localiam

Guidance for AI coding agents (Claude Code, Cursor, Copilot, Codex, OpenCode, …) working in this repository. This is the **cross-tool single source of truth** — `CLAUDE.md` imports it, so keep durable project context here. The working agreements in `~/Developer/github.com/blairham/AGENTS.md` apply on top.

## Project Overview

**LocalIAM** (`localiam`) verifies the AWS SigV4-presigned tokens services present as data-plane credentials, so a local cluster can run Redis, Postgres and Kafka with the **same IAM auth path AWS enforces** instead of plaintext.

- Module path: `github.com/blairham/localiam`
- Go 1.26
- Repo: `github.com/blairham/localiam` (public). `.github/workflows/ci.yml` runs pre-commit, `go test -race`, a Docker build and the Helm charts; a `v*` tag runs GoReleaser, which publishes the binaries and `ghcr.io/blairham/localiam`.
- **Consumed as a CONTAINER, not a module.** Nothing imports localiam; services run it as an agent sidecar, a proxy sidecar beside a store, and one central server. So the release that matters is the image, not a module tag.

The problem it solves: local environments run plaintext, so an IAM auth path is first exercised against real AWS. The classic failure is a service that mints one ElastiCache token at startup and never refreshes it: the first Redis reconnect past the 15-minute TTL re-auths with an expired token, gets `WRONGPASS`, and the pod stays broken for the rest of its life. An in-cluster broker that accepts any token cannot reproduce that. This one can.

## Quick Reference

```sh
make build                     # -> dist/localiam
make install                   # build + copy to ~/.local/bin
make test                      # go test -race ./...
make fmt                       # gofumpt
make vet                       # go vet ./...
make tidy                      # go mod tidy
make image                     # docker build -t localiam:dev .
make clean                     # rm -rf dist
make check                     # what CI runs — push and let CI run it rather than running it locally

go test ./verify/ -run Expired -v
pre-commit install             # once per checkout

# run the two halves locally
./dist/localiam server -listen :8080 -specs ./internal/policy/testdata -token dev
./dist/localiam agent -service api -role-arn arn:aws:iam::000000000000:role/api \
    -listen 127.0.0.1:1338 -register http://localhost:8080 -register-token dev
```

There is no `lint` target: golangci-lint runs as a pre-commit hook and in CI, never by hand.

## Project Structure

```
verify/                    PUBLIC — the verifier: identity, expiry, scope, signature (stdlib only)
  sigv4.go                 independent SigV4 canonicalization + Verify + validateWindow
  principals.go            access key -> secret/ARN/service store, with credential expiry + Sweep
  stores.go                the four token shapes: ElastiCache, RDS, and BOTH MSK mechanisms
  stores_test.go           CROSS-CHECK tests — vectors minted by third-party implementations
  shapes_test.go           the REAL rds signer, and both path-separator forms
  negative_test.go         rejection tests — expired, tampered, wrong host/user/scope, malformed
internal/                  everything else; promoting out of internal is non-breaking, demoting is not
  issuer/                  the per-pod sidecar: the EKS Pod Identity agent contract
  policy/                  reads podIdentity.permissions from a per-service spec YAML
  proxy/                   auth termination in front of a store (resp, redis, postgres, kafka)
  server/                  the central half: credential registration + verify/authorize API
  client/                  verifier client for a REMOTE localiam server
  shell/                   the gated diagnostic shell (github.com/blairham/sh behind a deny-by-default policy)
cmd/localiam/              one file per subcommand: agent, server, proxy, gencerts; main.go dispatches
cmd/sh/                    the gated shell as a binary, installed at /bin/sh in the image
Dockerfile                 one distroless image, every role, gated /bin/sh
charts/localiam/           Helm chart: the server
charts/localiam-sidecar/   Helm library chart: agent and proxy sidecar templates
docs/architecture/         how it all fits — START HERE
docs/design/               per-subsystem living docs
docs/rfcs/                 decisions
```

The only public package is `verify`. The container is the product, and the
policy contract is the spec YAML, not a Go API.

## Code Conventions

- `.golangci.yml` configures golangci-lint v2. Formatters: gofumpt, gci, goimports, golines at 120 cols.
- `.pre-commit-config.yaml` is the lint surface. golangci-lint and gofumpt are pinned in go.mod's `tool` block; the hook `rev` must match the golangci-lint version there.
- Every commit runs the hooks. Never `--no-verify`.
- Every `.go` file starts with the two-line SPDX header (`// SPDX-FileCopyrightText: 2026 Blair Hamilton`, `// SPDX-License-Identifier: Apache-2.0`), then a blank line. The `check-license-headers` hook fails a commit without it; `go-vulncheck` fails one that pulls in a known-vulnerable dependency.
- Open source under Apache-2.0: `LICENSE`, `NOTICE`, `CONTRIBUTING.md` (independence rule + CLA), `CLA.md`, `SECURITY.md` (private advisories; localiam is a test tool, not an auth system), `CODE_OF_CONDUCT.md`. Keep SECURITY.md's list of what localiam is NOT in step with the code.
- Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, …). No AI co-author trailers.
- en-US spelling.
- Comments explain **why**, matching the density of the existing files. A comment that restates the code is noise; a comment recording the failure or the wrong guess that shaped the code is the point.

## 🚨 The independence rule

`verify` is a **deliberately independent** implementation of SigV4 canonicalization. It must never import a client library or helper that **mints** these tokens — and it must not be refactored to share a canonicalization helper with one.

A verifier that shares its canonical form with the minter **cannot detect a canonicalization bug**: both sides are wrong in the same way and the tests go green. The only thing that makes this verifier worth running is that it derives the canonical form separately and is pinned to bytes produced by *other people's* implementations.

Treat "the verifier now imports a minting package" as a review failure, however tidy the diff looks.

## 🚨 Never write a token minter

Layer 2 — minting the SigV4 token — is **already written, in every language services use**: aws-sdk-go-v2 (`feature/rds/auth`, the presigner) and franz-go in Go, `AWS.MSK.Auth` and hand-rolled helpers in .NET, `aws-msk-iam-sasl-signer-js` and `@aws-sdk/rds-signer` in Node, botocore-based providers in Python. They all sign offline; they need credentials, not an endpoint.

localiam issues **credentials** and **validates tokens**. It never mints one. A minter here would mean localiam exercised our code instead of the service's, which is the same tautology the independence rule prevents one layer up.

## 🚨 Two token shapes, and the trap that hid one

```
postgres:5432?Action=connect&...     aws-sdk-go-v2 feature/rds/auth — Go services
postgres:5432/?Action=connect&...    hand-rolled .NET helpers, and the Node minters
```

The verifier originally required the `/` and so rejected every Go service's
token — while the cross-check stayed green, because it presigned through the
GENERIC signer instead of the RDS one pgx services actually call.

**Cross-check against the exact function real clients call, not a cousin of it
that signs the same request.** Pinned by `TestRDSAcceptsTheRealSignersToken` and
`TestBothTokenShapesParse`.

## 🚨 Both MSK SASL mechanisms are in real use

| Client | Mechanism | Envelope | Entry point |
|---|---|---|---|
| Go (franz-go `ManagedStreamingIAM`) | `AWS_MSK_IAM` | JSON, keys lowercased | `verify.MSKAWSMSKIAM` |
| .NET (Confluent.Kafka → `AWS.MSK.Auth`) | `OAUTHBEARER` | base64url presigned URL | `verify.MSKOAuthBearer` |
| Node (`@confluentinc/kafka-javascript` → `aws-msk-iam-sasl-signer-js`) | `OAUTHBEARER` | base64url presigned URL | `verify.MSKOAuthBearer` |

Same SigV4 signature, different wrapper. A broker adapter that handles only one **locks out half the services**.

⚠ In the `AWS_MSK_IAM` envelope, `user-agent` travels in the payload but is added **after** signing, so it is not part of the canonical query. Folding it in makes every signature mismatch. That was this verifier's first wrong guess and `TestMSKAWSMSKIAMCrossCheck` is what caught it — see `mskJSONToCanonical`.

## 🚨 Two different sidecars — do not conflate them

- The **credential agent** (`issuer`) is per-pod, on loopback, because it stands in for the EKS Pod Identity agent, which is per-pod.
- The **auth terminators** (`proxy`) sit in front of the STORES. Putting one next to the client would mean a pod verifying a token it minted itself — anything that can mint can pass that check.

The Kafka terminator is a **Go proxy in front of the brokers**, not a Java broker callback and not a client sidecar: see `docs/rfcs/0002-kafka-auth-termination.md`, which also explains how pointing `KAFKA_ADVERTISED_LISTENERS` at the proxy sidesteps Metadata rewriting entirely.

## Testing

`go test -race ./...` — CI runs it; locally, narrow with `-run` to the package you touched. Two tiers, and the distinction matters:

- **Cross-check** (`stores_test.go`) — tokens are minted by aws-sdk-go-v2's presigner and by franz-go, never by this package, then verified. Plus frozen golden signatures that catch drift in *either* implementation. This is what keeps the independence rule honest. A changed golden is a finding, not a fix.
- **Negative** (`negative_test.go`) — expired, not-yet-valid, tampered, unknown key, wrong host/service/user, session mismatch, malformed envelopes. `TestAnExpiredTokenIsRejected` is the mint-once-never-refresh bug made executable, paired with `TestATokenInsideItsWindowIsAccepted` so it cannot pass for the wrong reason.

⚠ Tests use AWS's **published** SigV4 example credentials (`AKIDEXAMPLE` / `wJalrX…EXAMPLEKEY`) so a golden vector carries no real secret. `.gitleaks.toml` allowlists those exact strings — never widen that to a pattern like `AKIA[A-Z0-9]{16}`, which would silence the rule that catches a real key.

## Key Dependencies

Test-only, and deliberately so — the verifier itself has no non-stdlib imports:

- `github.com/aws/aws-sdk-go-v2` — the presigner, the **RDS signer** (`feature/rds/auth`, the function pgx-based services call) and the **container credentials provider** (`credentials/endpointcreds`, the one a Pod Identity pod uses), all for cross-check vectors.
- `github.com/twmb/franz-go` — `sasl/aws`, to mint `AWS_MSK_IAM` cross-check vectors.
- `github.com/twmb/franz-go/pkg/kfake` — an in-process Kafka broker, so the Kafka proxy's per-topic authorization is tested end to end with a real client (`kafka_authz_test.go`).

Non-test dependencies are `go.yaml.in/yaml/v3` (policy — the maintained successor to the archived `gopkg.in/yaml.v3`), `github.com/blairham/sh` (the gated shell) and stdlib. `verify` itself has **no** non-stdlib imports, by the independence rule.

## Documentation

`docs/README.md` indexes the layout.

- **Start with `docs/architecture/iam-auth.md`** — the three layers, the policy model, the token shapes.
- `docs/design/token-verification.md` before changing anything in `verify/`.
- `docs/rfcs/0001-credential-issuance-topology.md` for why the agent is a sidecar.
- `docs/rfcs/0002-kafka-auth-termination.md` for why Kafka is a Go proxy.
