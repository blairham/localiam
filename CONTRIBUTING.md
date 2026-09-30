# Contributing

Thank you for considering a contribution. Please read the two rules below
before opening a pull request — both are non-negotiable.

## 1. The independence rule

`verify/` is a **deliberately independent** implementation of SigV4
canonicalization. Its non-test code imports the standard library only, and it
must never import, copy or share a helper with anything that **mints** these
tokens (aws-sdk-go-v2, franz-go, an MSK signer, …).

A verifier that shares its canonical form with the minter cannot detect a
canonicalization bug — both sides are wrong the same way and the tests go
green. The tests instead pin the verifier to bytes produced by third-party
implementations.

**A changed golden signature is a finding, not a fix.** If a cross-check in
`verify/stores_test.go` starts failing, the verifier or the SDK has drifted;
do not update the expected value to make it pass. The only legitimate reason
to change a golden is changing the signed test inputs, and then the new value
must be re-derived with an implementation other than this one, which must
first reproduce the old value from the old inputs.

## 2. The Contributor License Agreement

Contributions require a signed CLA; the text is in [`CLA.md`](CLA.md).

**Why.** The project may need to offer different licensing terms in future.
That is only possible if one party can license the whole work, and copyright
in a contribution stays with its author unless licensed onward.

The CLA does **not** take your copyright. You keep it; you grant a license
broad enough to include sublicensing, and you affirm the work is your own —
including that no employer holds rights to it.

## Practical

- Open an issue before a large change, so the design can be agreed first.
- Work on a branch and open a pull request against `main`.
- Commit messages explain the **why**, not a restatement of the diff.
  Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, …).
- Commits must be signed.
- Every `.go` file carries the two-line SPDX header; the pre-commit hook fails
  without it.
- `pre-commit install` once per checkout. The hooks format, lint, scan for
  secrets and check for vulnerable dependencies on every commit; never bypass
  them with `--no-verify`.
- `go test -race ./...` must pass. New behavior needs a test, and a new
  rejection path needs a negative test paired with one that proves the valid
  case still passes.
- Tests use AWS's **published** example credentials (`AKIDEXAMPLE`). Never
  commit anything minted against a real account.

Please also read the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go
through [SECURITY.md](SECURITY.md), never a public issue.
