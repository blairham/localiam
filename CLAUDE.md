# CLAUDE.md

@AGENTS.md

<!-- AGENTS.md is the cross-tool source of truth; durable project context goes there, not here. -->

## Claude Code-specific notes

- **Slash commands:** `/check` — build + vet + gofmt + race tests (lint is the commit hook's job).
- **Subagents:** `sigv4-verifier-reviewer` — reviews changes under `verify/` against the independence rule and the cross-check discipline.
- Workflow (worktrees, branches, commits) follows `~/Developer/github.com/blairham/AGENTS.md`.
- The repo sits under `~/Developer/github.com/blairham/` but is **not** a member of any `go.work`, so bare `go build` / `go test` work with no prefix.
