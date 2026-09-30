# Policy: service specs

`localiam server -specs <dir>` loads one YAML file per service and enforces the
AWS permissions it grants. Without `-specs` the server authenticates every
token but authorizes nothing, and says so in its first log line.

The model is deliberately small: it answers the questions the three data planes
actually ask, not general IAM. See [the architecture doc](../architecture/iam-auth.md#policy)
for why.

## File format

**The service name is the file name**: `specs/api.yaml` is the spec for the
workload an agent issued credentials to with `-service api`. A `name:` key is
allowed for readability and ignored.

```yaml
# specs/worker.yaml
podIdentity:
  permissions:
    elastiCache: true          # may authenticate to Redis
    rds:
      dbUser: worker_app       # may connect to Postgres as this user; "*" = any
    msk:
      cluster: true            # may open an MSK connection at all
      topics: [events]         # read + write
      readTopics: [requests]
      writeTopics: [events-processed]
      adminTopics: [scratch-*] # counts as write
      groups: [worker-*]       # consumer groups
      transactionalIds: [worker-txn-*]
```

| Field | Type | Meaning |
|---|---|---|
| `podIdentity.permissions` | map | **Absent means unrestricted** — see below. |
| `…elastiCache` | bool | May authenticate to Redis (`elasticache:Connect`). |
| `…rds.dbUser` | string | The Postgres user the service may connect as. `"*"` means any. Empty or absent means none. |
| `…rds.database` | string | Accepted, **not enforced** — database grants live in Postgres itself. |
| `…msk.cluster` | bool | May open an MSK connection (`kafka-cluster:Connect`). |
| `…msk.topics` | list | Read **and** write. |
| `…msk.readTopics` | list | Read (`DescribeTopic` + `ReadData`). |
| `…msk.writeTopics` | list | Write (`DescribeTopic` + `WriteData`). |
| `…msk.adminTopics` | list | Treated as write. |
| `…msk.configReadTopics` | list | Accepted, **not enforced**. |
| `…msk.groups` | list | Consumer groups (`DescribeGroup` / `AlterGroup`). |
| `…msk.transactionalIds` | list | Transactional ids — a transactional producer needs these explicitly; `cluster` does not cover `InitTransactions`. |

### Patterns

A name matches a pattern exactly, or by prefix when the pattern **ends** in
`*`: `api-*` matches `api-consumers-1` and `api-`, not `api`. `*` alone matches
everything. There is no other wildcard — not `?`, not `*` in the middle, not
regular expressions — and matching is case-sensitive, as IAM's is.

## Two rules that surprise people

**1. No `permissions` block means everything is allowed.** A service with
`podIdentity: {}` (or no `podIdentity` at all) runs on a shared role that
grants everything, so localiam allows everything rather than failing services
that work when deployed.

**2. Declaring *any* permissions block replaces that, it does not add to it.**
The moment a spec has `permissions:`, only what it lists survives. Add an
`msk:` block to a service that used to rely on the shared role for Postgres, and
it can no longer connect to Postgres — deployed, that fails hours later when
pods restart; with localiam it fails immediately. This is the case the policy
model exists to catch.

## What is enforced where

| Store | Checked at connect, by `/v1/verify` | Per-operation |
|---|---|---|
| Redis | `elastiCache` | nothing finer exists in IAM |
| Postgres | `rds.dbUser` matches the user in the startup packet | Postgres `GRANT`s, untouched |
| Kafka | `msk.cluster` | topics, groups and transactional ids via `/v1/authorize` — **see the gap below** |

A token that verifies but whose service has no spec gets
`localiam: no service spec for "<service>"`; one whose spec does not permit the
connection gets `localiam: <service> is authenticated but not permitted`.

⚠ **Gap: per-topic Kafka authorization is not enforced yet.** The server
answers per-operation questions at [`POST /v1/authorize`](http-api.md#post-v1authorize),
but the Kafka proxy only decodes the SASL handshake and then splices the
connection, so nothing calls it. Today a Kafka client that may connect may
produce to and consume from any topic. The connect check (`msk.cluster`) is
enforced.
