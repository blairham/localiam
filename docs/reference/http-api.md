# HTTP API

`localiam server` serves JSON over plain HTTP on `-listen` (default `:8080`).
Proxies run with `localiam proxy` call it to verify tokens; agents call it to
register credentials. Everything is `POST` with a JSON body except `/healthz`.

A rejected token is **not** an HTTP error: verification answers `200` with
`"ok": false` and the reason in `error`. `400` means the request itself was
malformed; `401` means a registration without the right bearer token.

## `GET /healthz`

```json
{"ok": true, "credentials": 3}
```

`credentials` is how many registered credentials the store holds right now.

## `POST /v1/credentials/register`

Called by the agent for every credential it issues. Requires
`Authorization: Bearer <-token>`; `401` otherwise. Only a server started with
`-open-registration` accepts registrations without it.

```json
{
  "principal": {
    "accessKeyId": "ASIA…",
    "secretKey": "…",
    "sessionToken": "…",
    "arn": "arn:aws:iam::000000000000:role/api",
    "service": "api",
    "expiration": "2026-09-30T20:06:34Z"
  }
}
```

`accessKeyId` and `secretKey` are required (`400` otherwise). Registering also
sweeps credentials that have expired. Answers `{"ok": true}`.

## `POST /v1/verify/{store}`

Verifies one presented token. `{store}` is `elasticache`, `rds` or `msk`.

| Store | Request fields |
|---|---|
| `elasticache` | `token`, `replicationGroupId`, `user` |
| `rds` | `token`, `host`, `port`, `dbUser` |
| `msk` | `token`, `mechanism` (`AWS_MSK_IAM`, or `OAUTHBEARER` — the default), `host` (the broker address the client signed against; the AWS regional endpoint is always accepted too) |

```sh
curl -s -X POST localhost:8080/v1/verify/rds \
  -d '{"token":"postgres:5432/?Action=connect&…","host":"postgres","port":5432,"dbUser":"app"}'
```

Accepted:

```json
{"ok": true, "service": "api", "principal": "arn:aws:iam::000000000000:role/api",
 "accessKeyId": "ASIA…", "expiresAt": "2026-09-30T20:06:34Z"}
```

`expiresAt` is when the **token** stops being valid — log it to see how much
life a client's token had left.

Rejected:

```json
{"ok": false, "error": "localiam: token expired: …"}
```

The `error` values are listed in [Troubleshooting](../troubleshooting.md#rejections).
When the server has `-specs`, a valid token is also checked against the
service's connect grant — see [Policy](policy.md#what-is-enforced-where).

For `AWS_MSK_IAM`, `token` is the SASL payload as a string (the JSON envelope);
for `OAUTHBEARER`, the base64url-encoded presigned URL.

## `POST /v1/authorize`

A per-operation policy question, for Kafka, where IAM authorizes per topic and
per group.

```json
{"service": "api", "action": "ReadData", "resource": "events"}
```

| `action` | Checked against |
|---|---|
| `ReadData` | `topics`, `readTopics` |
| `WriteData` | `topics`, `writeTopics`, `adminTopics` |
| `Group` | `groups` |
| `TransactionalId` | `transactionalIds` |
| `Connect` | `cluster` (`resource` ignored) |

Actions are the bare names above, not `kafka-cluster:ReadData`. Answers
`{"allowed": true|false}`, with a `reason` when there is no spec for the service
or no specs are loaded at all (then everything is allowed). An unknown action
is a `400`.

⚠ Nothing in localiam calls this endpoint yet — the Kafka proxy does not
enforce per-topic policy. See [Policy](policy.md#what-is-enforced-where).

## `POST /debug/sh`

The gated diagnostic shell. Exists only when the server was started with
`LOCALIAM_SHELL_TOKEN` set (otherwise `404`). The body is a script, not JSON:

```sh
curl -s -H "Authorization: Bearer $LOCALIAM_SHELL_TOKEN" \
  --data-binary 'for d in /proc/[0-9]*; do read -r c < "$d/comm"; echo "${d#/proc/} $c"; done' \
  localhost:8080/debug/sh
```

```json
{"status": 0, "stdout": "1 localiam\n", "stderr": "", "trail": [], "denied": 0}
```

A wrong token is `403`. `trail` records every action the script took, allowed
or refused, and `denied` counts refusals. Limits: 8 KiB of script, 256 KiB of
output per stream, a 5-second deadline. See
[the shell's README](../../internal/shell/README.md) for what it can and cannot
do.
