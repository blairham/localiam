# localiam docs

## Using it

| Doc | What it covers |
|---|---|
| [getting-started.md](getting-started.md) | **Start here.** Server, agent and the real AWS CLI on one laptop: a token accepted, a token rejected |
| [kubernetes.md](kubernetes.md) | The published image, the server Deployment, the agent and proxy sidecars, TLS, hardening |
| [troubleshooting.md](troubleshooting.md) | Every rejection message, what causes it, and setup problems |

## Reference

| Doc | What it covers |
|---|---|
| [reference/cli.md](reference/cli.md) | Every subcommand, flag and environment variable; bootstrap principals |
| [reference/policy.md](reference/policy.md) | The per-service spec format, pattern matching, and what is enforced where |
| [reference/http-api.md](reference/http-api.md) | The server's endpoints, requests and responses |
| [../internal/shell/README.md](../internal/shell/README.md) | The gated `/bin/sh` and `POST /debug/sh`: what they can and cannot do |

## Design

| Doc | What it covers |
|---|---|
| [architecture/iam-auth.md](architecture/iam-auth.md) | The three layers end to end, why we never write a minter, the policy model, the token shapes, the image |
| [design/token-verification.md](design/token-verification.md) | Why the verifier is a separate implementation, the four token shapes, and what is still unbuilt |
| [rfcs/0001-credential-issuance-topology.md](rfcs/0001-credential-issuance-topology.md) | Sidecar vs central credential issuance — decided, with the SDK constraint that forced it |
| [rfcs/0002-kafka-auth-termination.md](rfcs/0002-kafka-auth-termination.md) | Why Kafka is a Go proxy rather than a Java broker callback, and the Metadata trap it sidesteps |

`architecture/` is cross-cutting "how it all fits", `design/` holds
per-subsystem living docs, and `rfcs/` records decisions.
