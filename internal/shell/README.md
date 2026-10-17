# `internal/shell`: the HTTP front end for the gated shell

localiam's image is `gcr.io/distroless/static-debian12:nonroot`: no `/bin/sh`,
no coreutils and no package manager. The gated shell that puts one back, a
shell that **cannot execute anything** and whose reads are bounded to `/proc`
and `/sys/fs/cgroup`, lives in
[`github.com/blairham/sh/gated`](https://github.com/blairham/sh/tree/main/gated).
**Its [README](https://github.com/blairham/sh/blob/main/gated/README.md) is the
model**: what the gate refuses and why, the `environ` deny, the bounds, the
diagnostic recipes, and the tests. It is not repeated here.

localiam exposes it two ways, one gate:

| Front end | Where | Reach it with |
|---|---|---|
| `/bin/sh` | `cmd/sh` (gated's `ExampleMain`), built and installed by the Dockerfile | `kubectl exec <pod> -- /bin/sh -c '<script>'` or `kubectl exec -i <pod> -- /bin/sh < probe.sh` |
| `POST /debug/sh` | this package, mounted by `localiam server` only when `LOCALIAM_SHELL_TOKEN` is set | `curl -H "Authorization: Bearer $TOK" --data-binary @probe.sh localhost:8080/debug/sh` |

Both run `gated.Shell` with `gated.DefaultPolicy`, so there is one boundary to
review and it is upstream. gated deliberately ships no network front end; this
package is localiam's, and it is the only code here.

## The endpoint

- **Request:** the script is the POST body. Over gated's 8 KiB script cap is a
  400 carrying gated's error; well over it is a 413 before the body is
  buffered.
- **Response:** `gated.Result` as JSON: `stdout`, `stderr`, `status`, the
  `trail` of every action, allowed or refused, and the `denied` count. A parse
  failure or a deadline is a 400 whose body is the same `Result` plus an
  `error`, because the trail of whatever ran before it is still worth having.
- **Deadline:** 5 seconds per run.
- **Log:** one `shell: run` line per request with the session (`HOSTNAME`), the
  byte count, status, record count, and the denial count, so the fact that
  somebody ran something survives in the log pipeline even when nobody kept
  the response body.

## Operating it: what the deployment must get right

gated's README lists what any deployment of the shell must get right (no other
shell or userland in the image, no `exec` lifecycle hooks or probes). The
endpoint adds these:

1. **The token comes from a Secret, and an empty token unmounts the
   endpoint.** `Register` mounts nothing without one, so a 404 is proof the
   endpoint is off. Read it with `secretKeyRef.optional: true` so a missing
   Secret leaves the endpoint off rather than failing the pod. The compare is
   constant-time, and a refusal is a bare 403 with no `WWW-Authenticate`.
2. **The endpoint shares the API port.** `localiam server` has one listener,
   so `/debug/sh` is on the same port agents register to. That is acceptable
   only because localiam runs on networks you control (see `SECURITY.md`);
   never route that port through an Ingress, and restrict it with a
   NetworkPolicy so the token is not the only control.
3. **The token is in the pod's environment**, which is why gated's `environ`
   deny matters here specifically: without it, one `read` of
   `/proc/1/environ` through this endpoint would return the endpoint's own
   token.

`/bin/sh` needs no token: it is reachable only by someone who can already
`kubectl exec`, which is its own authorization.

## Tests

`handler_test.go` covers only what this package adds: the 404 with no token,
the 403 for a wrong one, a run that returns output and the exec denial in its
trail, and the body cap agreeing with gated's (the cap is unexported upstream
and copied here, so a disagreement fails a test rather than shifting a status
code). The gate itself is tested in `github.com/blairham/sh/gated`.

⚠ **Keep struct literals in this package keyed.** This repo's `govet
fieldalignment` fixer reorders struct fields, and it once turned a positional
literal into a compile error and deleted field doc comments while doing it.
