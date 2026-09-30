---
description: Build, vet, format-check and test localiam.
allowed-tools: Bash(go build:*), Bash(go vet:*), Bash(gofmt:*), Bash(go test:*)
---

Run each step and report the first failure with its full output. Do not
summarize a failure — paste it.

```sh
go build ./...
go vet ./...
gofmt -l .          # must print nothing
go test -race ./... -count=1
```

Never run golangci-lint by hand, directly or via `pre-commit run --all-files`:
it runs as the pre-commit hook on every commit and in CI.

If `go test` fails on a cross-check test (`stores_test.go`), that is a signal the
verifier's canonical form has drifted from a third-party implementation — read
the independence rule in AGENTS.md before "fixing" it by changing the expected
value.
