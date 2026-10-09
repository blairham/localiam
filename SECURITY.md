# Security Policy

## What localiam is, and is not

localiam is a **test tool**. It makes local Redis, Postgres and Kafka demand
AWS IAM data-plane credentials so that credential-handling bugs fail on a
laptop instead of after deploy.

It is **not** an authentication system for anything you care about:

- The credentials it issues are fake. They authenticate to localiam and
  nothing else, and anyone who can reach the agent can obtain them —
  without `-token-file`, the agent accepts any non-empty Authorization
  header.
- The central server keeps every issued secret key in memory. Its
  registration endpoint is protected by one shared bearer token (`-token`),
  which is always required: there is no mode that accepts registrations
  without it.
- The proxies splice traffic to backends that run with authentication
  **disabled** (`POSTGRES_HOST_AUTH_METHOD=trust`, a password-less Redis,
  a PLAINTEXT Kafka listener). The backends must never be reachable except
  through the proxy.
- `localiam gen-certs` writes a private key to disk for a throwaway CA.
- With `LOCALIAM_SHELL_TOKEN` set, `localiam server` mounts `POST /debug/sh`, a
  gated diagnostic shell, on its API port. It cannot exec, write or signal,
  and it reads only `/proc` and `/sys/fs/cgroup` (never `environ`), but it is
  still a shell behind one bearer token. Leave the token unset unless you
  need it.

Run it in local and CI environments only, on networks you control. Never
expose it to the internet, and never point it at real AWS credentials or
real data.

## Supported versions

Only the latest release receives fixes.

## Verifying a release

Releases from `v0.0.1` on are signed with [cosign](https://github.com/sigstore/cosign)
keyless signing: the signature is tied to the GitHub Actions workflow that
built the release, not to a key someone could leak. (`v0.0.0` predates
signing.)

Each tag's release is built by `.github/workflows/release.yml`, which runs the
shared release workflow in [blairham/.github](https://github.com/blairham/.github)
(`.github/workflows/go-release.yml`). The signing identity is that shared
workflow; the certificate also names this repository and the tag, and the
verify commands below check all three.

**Downloads.** `checksums.txt` is signed; it lists the digest of every archive.
Verify the signature, then the archives against it:

```sh
VERSION=v0.0.5
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/blairham/\.github/\.github/workflows/go-release\.yml@' \
  --certificate-github-workflow-repository blairham/localiam \
  --certificate-github-workflow-ref "refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

**Build provenance.** Every archive carries SLSA build provenance — which
workflow run, commit and tag produced it. It is in GitHub's attestation store
and attached to the release as `localiam-$VERSION.intoto.jsonl`:

```sh
gh attestation verify localiam_Linux_x86_64.tar.gz --repo blairham/localiam \
  --signer-workflow blairham/.github/.github/workflows/go-release.yml
```

**Images.** Each published image is signed by digest:

```sh
cosign verify "ghcr.io/blairham/localiam:${VERSION#v}" \
  --certificate-identity-regexp '^https://github\.com/blairham/\.github/\.github/workflows/go-release\.yml@' \
  --certificate-github-workflow-repository blairham/localiam \
  --certificate-github-workflow-ref "refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

It also carries SLSA build provenance, stored in ghcr.io beside it and in the
repository's attestations. The subject is the multi-arch index, so check it by
tag (image tags carry no `v`):

```sh
gh attestation verify "oci://ghcr.io/blairham/localiam:${VERSION#v}" \
  --repo blairham/localiam \
  --signer-workflow blairham/.github/.github/workflows/go-release.yml
```

**Tags released before the move to blairham/.github** (v0.0.4 and earlier)
were signed by this repository's own `goreleaser.yml`. Verify those with
`--certificate-identity "https://github.com/blairham/localiam/.github/workflows/goreleaser.yml@refs/tags/$VERSION"`
(for an image, `--certificate-identity-regexp '^https://github\.com/blairham/localiam/\.github/workflows/goreleaser\.yml@refs/tags/v'`)
in place of the three identity flags above, and run `gh attestation verify`
without `--signer-workflow`. Their archive provenance (after `v0.0.1`) is
attached as `localiam.intoto.jsonl`, and their images carry no provenance.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/blairham/localiam/security/advisories/new).

Please include the affected version or commit, what an attacker can do, and
the steps to reproduce. You should receive a response within a week.

In scope, among others:

- the verifier (`verify/`) accepting a token it should reject — an expired,
  forged, re-scoped or tampered token, or one signed by an unknown key
- a proxy passing traffic to its backend before authentication succeeds
- the agent or server leaking one workload's credentials to another
- the gated shell (`/bin/sh`, `POST /debug/sh`) doing anything its policy
  refuses — an exec, a write, a signal, a read outside `/proc` and
  `/sys/fs/cgroup`, or any read of an `environ` file

Out of scope: anything that follows from running localiam somewhere this
page says not to.
