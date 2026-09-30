# Design: Data-plane token verification

**Status:** Built — `verify` package complete and tested.
**Code:** `verify/`

## Purpose

Let a local cluster authenticate to Redis, Postgres and Kafka using the **same IAM
token path AWS enforces**, so IAM auth bugs surface on a laptop instead of after
deploy.

## The problem

AWS uses three different data-plane auth mechanisms, all SigV4-derived but each
validated by a different AWS server:

| Store | Mechanism | Typical minter |
|---|---|---|
| Redis | ElastiCache IAM — presigned `elasticache:connect` URL as the AUTH password | aws-sdk-go-v2 presigner (Go), hand-rolled helpers (.NET, Node), botocore providers (Python) |
| Postgres | RDS IAM — presigned `rds-db:connect` URL as the password | `feature/rds/auth` (Go), `@aws-sdk/rds-signer` (Node), hand-rolled helpers (.NET) |
| Kafka | MSK IAM — presigned `kafka-cluster:Connect`, two SASL mechanisms | franz-go (Go), `AWS.MSK.Auth` (.NET), `aws-msk-iam-sasl-signer-js` (Node) |

Local environments run all three in plaintext. The gap is not hypothetical: a
service that mints one ElastiCache token at startup and reuses it for the pod's
life works until the connection drops — which may be days later — and then the
reconnect re-auths with the long-expired token and gets `WRONGPASS`. No
plaintext environment can catch it.

## Why not LocalStack

LocalStack covers **one of the three, unvalidated**:

- **ElastiCache** — Pro tier, and "doesn't support … users/passwords". No IAM auth.
- **MSK** — IAM auth is an open enhancement request, still backlog. Not implemented.
- **RDS** — supports the mechanics, but the docs say outright that "IAM
  authentication is not yet validated at this stage". Any token works.

So LocalStack would be a paid dependency that still leaves all three verification
hooks to write. The minting side needs it even less: every token generator signs
**offline** — pure SigV4 over resolved credentials, no AWS call. The entire gap
is verification.

## The design

Because localiam mints its own credentials, it knows every access key → secret
mapping, so verification is local HMAC: re-sign the presented token and compare.
No network call anywhere in the path.

```
client (unchanged code) --token--> proxy --> verify.Verify --> allow/deny
                                     |
                              Store: accessKeyId -> secret, ARN
```

### 🚨 Independence, not reuse

The verifier is a **separate implementation** of SigV4 canonicalization and must
never share one with the minters. A shared canonical form makes a
canonicalization bug undetectable — both sides wrong the same way, tests green.

It is instead pinned to bytes from third-party implementations: aws-sdk-go-v2's
presigner and franz-go. This caught a real bug on the first run — the initial
`AWS_MSK_IAM` reconstruction folded `user-agent` into the signed query, which
franz-go's vector rejected immediately. A self-referential test would have
passed and shipped it.

### Fidelity target: lifecycle, not policy

The verifier checks identity, expiry, scope, action and host. It does **not**
evaluate IAM policy ("may this role write that topic") — that lives in `policy`,
deliberately small. The bugs actually being chased are mint-once-never-refresh,
stale token on reconnect, and refresh callbacks that never fire — all lifecycle.

## The four token shapes

Three stores, but **four** shapes, because real clients use both MSK SASL
mechanisms — Go via franz-go sends `AWS_MSK_IAM`, .NET via Confluent.Kafka sends
`OAUTHBEARER`. Same signature, different envelope. An adapter that handles one
locks out half the services.

Parameter **order** is never load-bearing: hand-rolled helpers often append
`X-Amz-Signature` last while aws-sdk-go-v2 sorts it in, so the parser lifts the
signature out by name and re-sorts the remainder canonically.

Neither is the **path separator**: aws-sdk-go-v2's RDS signer emits
`host:port?Action=…` while hand-rolled and Node minters emit `host:port/?Action=…`.
Both parse, and the canonical path is normalized to `/`. See
[architecture/iam-auth.md § Two token shapes](../architecture/iam-auth.md#two-token-shapes)
for why that one nearly shipped broken.

## Not built

- **STS shim** — `AssumeRole` issuing short-TTL credentials into the store, for
  credential-level expiry on top of token-level.

⚠ A terminating proxy adds a hop for the connection's life. Fine for
correctness testing, not for performance testing. It should be opt-in, not the
default.
