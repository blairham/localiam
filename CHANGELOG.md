# Changelog

All notable changes to localiam are recorded here. The release workflow
publishes a tag's section as that GitHub release's notes, and fails a release
whose section is missing: before tagging, move `[Unreleased]` under
`## [X.Y.Z] - <date>`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The sections for v0.0.4 and earlier were reconstructed from those releases'
notes when this file was started.

## [Unreleased]

### Security

- Built with Go 1.26.9, which fixes GO-2026-6603 to GO-2026-6617 in the
  standard library's HTTP/2 and TLS. (#13)

### Changed

- CI and release run blairham/.github's shared workflows. Release signatures
  and provenance now carry the shared workflow's identity
  (`blairham/.github/.github/workflows/go-release.yml`); `SECURITY.md` shows
  the new verify commands, and how to verify v0.0.4 and earlier. (#13)
- The provenance bundle attached to a release is named
  `localiam-<tag>.intoto.jsonl` (was `localiam.intoto.jsonl`), and the image
  now carries SLSA build provenance too. (#13)
- Release notes come from this file instead of a generated commit list. (#13)

## [0.0.4] - 2026-10-05

### Fixed

- SigV4 verification accepts a fractional `X-Amz-Expires`, rounded down.
  (#11)

## [0.0.3] - 2026-10-03

### Breaking

- **`-open-registration` is removed.** `localiam server` now always requires
  `-token`; there is no mode that accepts credential registrations without
  one. On a laptop pass any value (`-token dev`) and the same value to the
  agent's `-register-token`. The Helm chart already generates a random token,
  so chart installs need no change. (#10)

### Security

- The registration endpoint and the session-token check now compare tokens in
  constant time, as the agent and the debug shell already did. (#9)

### Changed

- The Kafka proxy names the request type `api` rather than `apiKey` in its
  logs. (#7)

## [0.0.2] - 2026-10-03

### Added

- SLSA build provenance for every release archive. (#6)

## [0.0.1] - 2026-10-02

### Added

- The Kafka proxy enforces per-topic, group and transactional-id policy. (#5)
- `checksums.txt` and the images are signed with keyless cosign. (#3)

## [0.0.0] - 2026-09-30

First release.

[Unreleased]: https://github.com/blairham/localiam/compare/v0.0.4...HEAD
[0.0.4]: https://github.com/blairham/localiam/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/blairham/localiam/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/blairham/localiam/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/blairham/localiam/compare/v0.0.0...v0.0.1
[0.0.0]: https://github.com/blairham/localiam/releases/tag/v0.0.0
