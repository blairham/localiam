# RFC: Credential issuance topology

**Status:** Decided — per-pod sidecar.

## Question

A pod needs AWS credentials so its unchanged code can mint SigV4 tokens. In
AWS they arrive via the **EKS Pod Identity agent**. How does a cluster deliver them?

## The constraint that decides it

The AWS SDK **rejects** `AWS_CONTAINER_CREDENTIALS_FULL_URI` over plain HTTP
unless the host resolves to loopback or the ECS/EKS link-local addresses. A
container reaching its host by name is neither, so that path would force HTTPS
and a private CA into the pod's trust store — which then has to re-bundle the
public roots the workload's real AWS calls need.

## Options

| | How | Fidelity | Cost |
|---|---|---|---|
| **A. Per-pod sidecar** | localiam listens on `127.0.0.1`; `AWS_CONTAINER_CREDENTIALS_FULL_URI` points at loopback | **Exact** — same SDK code path as Pod Identity, refresh included | a container per pod |
| B. Central service + `credential_process` | one localiam; pods shell out to fetch | Exercises a path AWS never takes | low |
| C. Central service + HTTPS | one localiam with TLS | Exact, but needs a private CA in every pod's trust store, which then has to re-bundle public roots | high |

## Decision

**A — per-pod sidecar.**

A local credential agent reached over loopback is *precisely what EKS Pod
Identity is*, so the cluster exercises the same SDK provider, the same refresh
machinery and the same failure modes as AWS. It sidesteps the HTTP restriction
legitimately rather than working around it, and needs no TLS, no private CA and
no trust-store surgery.

The cost — one small container per pod — is acceptable because this is an
**opt-in overlay**, not the default. Environments that do not need IAM
fidelity (notably performance testing) keep plaintext and carry no sidecar.

Option B remains the fallback if sidecar overhead ever bites; it is a config
change, not a redesign, because the issuer is the same binary either way.

## Consequences

- localiam ships as a **container image** so it can be a sidecar.
- The issuer serves the Pod Identity agent HTTP contract, not an STS API.
- The verifier needs the issued credentials, so in sidecar mode the issuer and
  the verifier must share a principal store — either the same process, or the
  sidecar registering issued keys with a central verifier.
