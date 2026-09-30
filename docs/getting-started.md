# Getting started

Ten minutes, one laptop, no AWS account and no containers: run the server and
an agent, let the **real AWS CLI** mint an RDS IAM token from the agent's
credentials, and watch localiam accept it — and reject it when it is wrong.

## Prerequisites

- Go 1.26 (to build) — or the container image, see [Kubernetes](kubernetes.md)
- the AWS CLI v2, or any AWS SDK (used only to *mint* tokens, offline)
- `curl`

## 1. Build

```sh
git clone https://github.com/blairham/localiam
cd localiam
make build            # -> dist/localiam
```

## 2. Start the server

The server holds every issued credential and answers verification requests.

```sh
./dist/localiam server -listen 127.0.0.1:8080 -token dev
```

`-token dev` is the bearer token agents must present to register credentials.
With no `-specs`, every authenticated identity is permitted — the server says so
in its first log line. See [Policy](reference/policy.md) to enforce grants.

## 3. Start an agent

The agent stands in for the EKS Pod Identity agent: it issues credentials to a
workload over loopback and registers each one with the server.

```sh
./dist/localiam agent \
  -service app \
  -role-arn arn:aws:iam::000000000000:role/app \
  -listen 127.0.0.1:1338 \
  -register http://127.0.0.1:8080 -register-token dev
```

## 4. Mint a token the way a real service does

Point the AWS CLI at the agent exactly as EKS Pod Identity would point a pod at
its agent, and ask it for an RDS auth token:

```sh
export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:1338/v1/credentials
export AWS_CONTAINER_AUTHORIZATION_TOKEN=local
export AWS_REGION=us-east-1

TOKEN=$(aws rds generate-db-auth-token --hostname postgres --port 5432 --username app)
echo "$TOKEN"
# postgres:5432/?Action=connect&DBUser=app&X-Amz-Algorithm=AWS4-HMAC-SHA256&...
```

Nothing here talks to AWS. The CLI fetched credentials from the agent and signed
the token locally, the same as it would in production.

> Make sure no other credentials are in play (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`,
> `~/.aws/credentials`): the SDK takes the first provider that answers, and the
> container provider comes after the environment and shared-config ones.

## 5. Verify it

```sh
curl -s -X POST http://127.0.0.1:8080/v1/verify/rds \
  -d "{\"token\":\"$TOKEN\",\"host\":\"postgres\",\"port\":5432,\"dbUser\":\"app\"}"
```

```json
{"expiresAt":"…","service":"app","principal":"arn:aws:iam::000000000000:role/app","accessKeyId":"ASIA…","ok":true}
```

Now ask for the wrong user:

```sh
curl -s -X POST http://127.0.0.1:8080/v1/verify/rds \
  -d "{\"token\":\"$TOKEN\",\"host\":\"postgres\",\"port\":5432,\"dbUser\":\"admin\"}"
```

```json
{"error":"localiam: unexpected action: token is for DBUser \"app\", startup named \"admin\"","ok":false}
```

Wait 15 minutes and verify the first token again: `localiam: token expired`.
That is the mint-once-never-refresh bug, caught on a laptop. (`-ttl` on the agent
shortens credential lifetimes if you don't want to wait for the credential
half of it.)

## Next

- [Kubernetes](kubernetes.md) — the same thing in a cluster, with the proxies in
  front of real Redis, Postgres and Kafka.
- [CLI reference](reference/cli.md) — every flag and environment variable.
- [Troubleshooting](troubleshooting.md) — what each rejection means.
- [Architecture](architecture/iam-auth.md) — why it is built this way.
