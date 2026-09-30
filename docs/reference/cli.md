# CLI reference

One binary, four subcommands. Every role runs from the same binary and the
same image; the subcommand picks the role.

```
localiam agent     [flags]   run the per-pod credential sidecar
localiam server    [flags]   run the central verifier
localiam proxy     [flags]   run an auth-terminating proxy beside a store
localiam gen-certs [flags]   emit a CA + server keypair for the TLS-terminating proxies
```

`localiam <command> -h` prints the same flags as below. Flags that can also come
from the environment say so; **a flag given on the command line wins over the
environment**. The environment exists because Kubernetes and compose templating
substitute into `env:` values but not into `args`.

## `localiam agent`

The per-pod sidecar. Serves the EKS Pod Identity agent contract on loopback, so
the workload's unchanged AWS SDK fetches credentials from it and signs its own
tokens. Each credential it issues is pushed to the server.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-service` | | *(required)* | Workload name, e.g. `api`. Selects the workload's grants from its [service spec](policy.md). |
| `-role-arn` | | *(required)* | Role the issued credentials authenticate as, e.g. `arn:aws:iam::000000000000:role/api`. |
| `-listen` | | `127.0.0.1:1338` | Address for the Pod Identity contract. **Must be loopback**: the AWS SDK refuses `AWS_CONTAINER_CREDENTIALS_FULL_URI` over plain HTTP anywhere else. |
| `-register` | `LOCALIAM_REGISTER_URL` | | Base URL of the server to push credentials to. Empty means credentials are issued but never registered, so no token minted from them will verify. |
| `-register-token` | `LOCALIAM_REGISTER_TOKEN` | | Bearer token the server's `-token` demands. |
| `-token-file` | | | File whose contents the request's `Authorization` header must match (the Pod Identity `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`). **Empty accepts any non-empty header.** |
| `-ttl` | | `15m` | Credential lifetime. Minimum `30s`. Shortening it compresses the mint-once-never-refresh window from hours into minutes. |
| `-account-id` | | `000000000000` | Account id echoed to the SDK. |

The workload points at the agent with:

```sh
AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:1338/v1/credentials
AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/localiam/token   # or AWS_CONTAINER_AUTHORIZATION_TOKEN=…
```

The agent hands the same credential to every request until it is within a minute
of expiry, as the real agent does; see `internal/issuer`. If registration fails,
the credential request fails too — a credential the verifier has never heard of
would only surface later as an unexplainable signature rejection.

## `localiam server`

The central verifier: holds every registered credential and answers the
[HTTP API](http-api.md). It can also host the proxies in the same process.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-listen` | | `:8080` | Address for the HTTP API. |
| `-region` | | `us-east-1` | AWS region tokens must be scoped to. |
| `-token` | | | Bearer token agents must present to register. **Required** — the server refuses to start without one. |
| `-open-registration` | | `false` | Start without `-token` and accept registrations from anyone who can reach the port. For a throwaway laptop run only; the server warns when it is on. |
| `-specs` | | | Directory of service spec `*.yaml` files to enforce. Empty means authenticate only, never authorize. See [Policy](policy.md). |
| `-principals` | | | JSON file of bootstrap principals to preload — for init containers that run before any sidecar is up. See [Bootstrap principals](#bootstrap-principals). |
| `-redis-proxy-listen` | | | Also run the Redis proxy here, e.g. `:6379`. Empty disables it. |
| `-redis-backend` | | | The real Redis the proxy fronts. |
| `-redis-replication-group` | | | ElastiCache replication group id tokens must be signed against. |
| `-pg-proxy-listen` | | | Also run the Postgres proxy here, e.g. `:5432`. |
| `-pg-backend` | `LOCALIAM_PG_BACKEND` | | The real Postgres the proxy fronts. |
| `-pg-host` | `LOCALIAM_PG_HOST` | `postgres` | Hostname RDS tokens are signed against — what the **workload** was configured with. |
| `-pg-port` | `LOCALIAM_PG_PORT` | `5432` | Port RDS tokens are signed against. |
| `-kafka-proxy-listen` | | | Also run the Kafka proxy here, e.g. `:9094`. |
| `-kafka-backend` | `LOCALIAM_KAFKA_BACKEND` | | The real broker's PLAINTEXT listener. |
| `-kafka-tls-cert` / `-kafka-tls-key` | | | PEM keypair presented to Kafka clients. |

| Env | Meaning |
|---|---|
| `LOCALIAM_SHELL_TOKEN` | Mounts the gated diagnostic shell at `POST /debug/sh`. Unset means the endpoint does not exist (404). See [the shell](../../internal/shell/README.md). |
| `HOSTNAME` | Names this pod in the shell's audit trail. |

Proxies hosted by `localiam server` go through the same verification and
connect policy as `/v1/verify`, so where a proxy runs does not change what it
enforces.

The server-hosted Kafka proxy has no `-kafka-host`: it expects tokens signed
against the AWS regional endpoint (`kafka.<region>.amazonaws.com`).

## `localiam proxy`

Auth-terminating proxies, run as a sidecar **in the store's own pod**, in front
of a store that runs with authentication disabled. Each verifies the client's
token against a remote server, then splices the connection through untouched.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-verify-url` | `LOCALIAM_VERIFY_URL` | *(required)* | Base URL of the server. |
| `-redis-listen` | | | Serve the Redis proxy here, e.g. `:6379`. |
| `-redis-backend` | `LOCALIAM_REDIS_BACKEND` | `127.0.0.1:6380` | The real Redis, normally on loopback in this pod. |
| `-redis-replication-group` | | | ElastiCache replication group id tokens must be signed against. |
| `-pg-listen` | | | Serve the Postgres proxy here, e.g. `:5432`. |
| `-pg-backend` | `LOCALIAM_PG_BACKEND` | `127.0.0.1:5433` | The real Postgres, normally on loopback. |
| `-pg-host` | `LOCALIAM_PG_HOST` | `postgres` | Hostname RDS tokens are signed against. |
| `-pg-port` | `LOCALIAM_PG_PORT` | `5432` | Port RDS tokens are signed against. |
| `-kafka-listen` | | | Serve the Kafka proxy here, e.g. `:9094`. |
| `-kafka-backend` | `LOCALIAM_KAFKA_BACKEND` | `127.0.0.1:9095` | The broker's PLAINTEXT listener, normally on loopback. |
| `-kafka-host` | `LOCALIAM_KAFKA_HOST` | | Broker hostname clients dial and sign against. Empty means the AWS regional endpoint. Tokens signed against the regional endpoint are accepted either way, because the Python and Node MSK signers always sign that. |
| `-kafka-tls-cert` / `-kafka-tls-key` | | | PEM keypair presented to Kafka clients. |

At least one of `-redis-listen`, `-pg-listen`, `-kafka-listen` is required.

**TLS.** Real clients demand TLS for IAM auth. The Postgres proxy terminates
TLS itself with a certificate generated at startup: clients use
`sslmode=require`, which encrypts but does not verify, so nothing needs to trust
it. The Kafka proxy needs a certificate its clients **trust** (franz-go and the
librdkafka clients verify against the system pool), so give it one from
`gen-certs` and point clients' `SSL_CERT_FILE` at the CA. Without
`-kafka-tls-cert` it presents a self-signed certificate for `-kafka-host` (or
`kafka`), which a verifying client rejects.

## `localiam gen-certs`

Writes `ca.pem`, `server.pem` and `server-key.pem`: a throwaway CA and a server
keypair it signed, for the Kafka proxy.

| Flag | Default | Meaning |
|---|---|---|
| `-hosts` | `localiam,localhost` | Comma-separated DNS names for the server certificate — the names clients dial. |
| `-out` | `.` | Directory to write the three files into. |

`server-key.pem` is a real private key. It is written `0600`, and `.gitignore`
ignores `/certs/`; never commit it.

## Bootstrap principals

A pod's init containers run before any sidecar starts, so an init step that
needs credentials (a schema migration, say) cannot reach the agent. `-principals`
preloads long-lived static credentials for that case:

```json
[
  {
    "accessKeyId": "AKIDMIGRATE00000000",
    "secretKey": "not-a-real-secret-local-only",
    "arn": "arn:aws:iam::000000000000:role/migrate",
    "service": "migrate"
  }
]
```

`accessKeyId` and `secretKey` are required. `sessionToken` and `expiration`
(RFC 3339) are optional; a principal with an `expiration` stops verifying after
it. The init step sets `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` to the same
values. The proper fix is a native sidecar (`restartPolicy: Always` on an init
container, Kubernetes ≥ 1.29), which starts before other init containers.

## Environment variables, all in one place

| Variable | Used by | Meaning |
|---|---|---|
| `LOCALIAM_REGISTER_URL` | agent | `-register` |
| `LOCALIAM_REGISTER_TOKEN` | agent | `-register-token` |
| `LOCALIAM_VERIFY_URL` | proxy | `-verify-url` |
| `LOCALIAM_REDIS_BACKEND` | proxy | `-redis-backend` |
| `LOCALIAM_PG_BACKEND` | proxy, server | `-pg-backend` |
| `LOCALIAM_PG_HOST` | proxy, server | `-pg-host` |
| `LOCALIAM_PG_PORT` | proxy, server | `-pg-port` |
| `LOCALIAM_KAFKA_BACKEND` | proxy, server | `-kafka-backend` |
| `LOCALIAM_KAFKA_HOST` | proxy | `-kafka-host` |
| `LOCALIAM_SHELL_TOKEN` | server | mounts `POST /debug/sh` |

The server's registration `-token` has no environment variable; pass it as an
argument from a Secret.
