# `internal/shell`: a gated shell for the distroless image

localiam's image is `gcr.io/distroless/static-debian12:nonroot`: no `/bin/sh`,
no coreutils and no package manager, so `kubectl exec` has nothing to run and
"exec in and look at `/proc`" is dead. This package puts a shell back as a Go
library ([`github.com/blairham/sh`](https://github.com/blairham/sh), `dash`
dialect) with a deny-by-default gate in front of every action it takes.

Two front ends, one gate:

| Front end | Where | Reach it with |
|---|---|---|
| `POST /debug/sh` | `localiam server`, mounted only when `LOCALIAM_SHELL_TOKEN` is set | `curl -H "Authorization: Bearer $TOK" --data-binary @probe.sh localhost:8080/debug/sh` |
| `/bin/sh` | `cmd/sh`, built and installed by the Dockerfile | `kubectl exec <pod> -- /bin/sh -c '<script>'` or `kubectl exec -i <pod> -- /bin/sh < probe.sh` |

Both build the same `Shell` with the same `Policy`, so there is one boundary to
review.

## Operating it: what the deployment must get right

The gate is only half the boundary. The other half is how it is exposed:

1. **The image must have no other shell or userland.** Beside busybox, `ls`,
   `wget` and the rest are still there to exec from anything that is not this
   binary, so a gated `/bin/sh` protects nothing. The Dockerfile keeps it
   distroless for that reason.
2. **The endpoint shares the API port.** `localiam server` has one listener,
   so `/debug/sh` is on the same port agents register to. That is acceptable
   only because localiam runs on networks you control (see `SECURITY.md`);
   never route that port through an Ingress, and restrict it with a
   NetworkPolicy so the token is not the only control.
3. **The token comes from a Secret, and an empty token unmounts the
   endpoint.** `Register` mounts nothing without one, so a 404 is proof the
   endpoint is off. Read it with `secretKeyRef.optional: true` so a missing
   Secret leaves the endpoint off rather than failing the pod.
4. **No `exec` lifecycle hooks.** A `preStop: exec: ["sleep", "5"]` needs a
   `sleep` binary; distroless has none and this shell refuses exec anyway.
   Use `preStop: sleep: {seconds: 5}` (Kubernetes >= 1.30).

`/bin/sh` needs no token: it is reachable only by someone who can already
`kubectl exec`, which is its own authorization.

## What it can do

Nothing external. The toolkit is shell builtins plus globbing plus
redirection, pointed at `/proc` and `/sys/fs/cgroup`, which covers most of what
anyone execs in to ask:

```sh
# ps, with no ps
for d in /proc/[0-9]*; do read -r c < "$d/comm"; echo "${d#/proc/} $c"; done

# memory ceiling and current use, from cgroup v2
read -r m < /sys/fs/cgroup/memory.max; read -r c < /sys/fs/cgroup/memory.current; echo "$c / $m"

# OOM and pressure history the pod has seen
while read -r l; do echo "$l"; done < /sys/fs/cgroup/memory.events
```

`sh -c 'script' a b` binds `a` to `$0` and `b` to `$1`, as real `sh` does.

## What it cannot do, and why that is the point

`policy.go` is short and it is the whole security argument; read it rather
than this table.

| Action | Answer |
|---|---|
| `exec`, anything | **Refused, unconditionally**, before the interpreter consults the filesystem, so adding a binary to the image later does not widen it. |
| `signal` | Refused. pid 1 is the service, and an endpoint that can `kill` it is a liveness probe with extra steps. |
| open for **write** | Refused, including inside the roots. `> /proc/sys/...` is a real write on a real kernel knob. |
| read outside `ReadRoots` | Refused. Default roots are `/proc` and `/sys/fs/cgroup`. Paths are cleaned first, so `/proc/1/../../etc/shadow` is tested as `/etc/shadow`. |
| read `*/environ` | Refused, although it sits inside an allowed root. See below. |
| `stat` an ancestor of a root | **Allowed.** Globbing stats each component on the way down, and refusing `stat /proc` made `/proc/1/*` collapse to the literal pattern with exit status 0. Existence of a directory on the way to a root leaks nothing. |

Every action, allowed or refused, is recorded. The HTTP response carries the
trail and a `denied` count; `/bin/sh` prints refusals to stderr. That matters
because **an empty answer and a refused answer look identical on stdout.**

### Why `environ` is a deny rather than a comment

`/proc/<pid>/environ` is where a service's credentials arrive, including this
package's own token, and it is inside `/proc`. Without the deny,
`read -r v < /proc/1/environ` returns every variable. The first probe of it
came back *empty*, which read as safe and was not: it used `while read`,
and a file with no trailing newline never runs a `while read` body. Real dash
behaves identically. `TestTheEnvironmentIsRefusedInsideTheRoots` uses the bare
`read` for that reason and fails if the deny is removed.

## Bounds

8 KiB of script, 256 KiB of output per stream, 4096 trail records, a 5-second
deadline on the HTTP path (the interpreter checks the context at every
command). Each run gets a fresh interpreter, so no variable, function or cwd
survives between two scripts, and there is deliberately no interactive REPL.

## Tests

`go test -race -count=20 ./shell/` is deterministic: no sleeps, and the
allow-side cases use a `t.TempDir()` root rather than `/proc`, so the verdict
does not depend on the kernel. Every rule is mutation-tested: allowing exec,
dropping `path.Clean`, allowing writes, removing the `environ` deny, and
dropping either half of the `$0`/`$@` binding each turn a test red.

⚠ **Keep struct literals in this package keyed.** This repo's `govet
fieldalignment` fixer reorders struct fields on `make check`, and it once
turned a positional literal into a compile error and deleted field doc
comments while doing it. The structs here are already in aligned order, so
the fixer should find nothing to move.
