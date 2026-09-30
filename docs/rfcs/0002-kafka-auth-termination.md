# RFC: Kafka auth termination

**Status:** Decided — a Go proxy in front of the brokers, not a Java broker callback.

## Question

Kafka is the only one of the three stores with a real server-side auth SPI: a
broker-side `AuthenticateCallbackHandler` for SASL/OAUTHBEARER. Earlier plans
assumed that was the obvious hook. Does it have to be?

## No. A Go proxy works, and is better here.

The Java route costs a JVM toolchain in a Go repo, a jar build, a custom
`apache/kafka` image to layer it onto, and a second language to keep in step with
the verifier. The Go route reuses the binary and image we already ship.

The proxy needs to understand very little Kafka:

| Request | Why |
|---|---|
| `ApiVersions` (18) | pass through; clients send it before authenticating |
| `SaslHandshake` (17) | answer with the mechanisms we accept |
| `SaslAuthenticate` (36) | unwrap the payload, verify, allow or refuse |
| everything else | opaque bytes — spliced, never parsed |

Both payload shapes are already handled: `OAUTHBEARER` arrives in the GS2 wrapper
(`n,,^Aauth=Bearer <token>^A^A`) and `AWS_MSK_IAM` as the JSON envelope, and
`verify.MSKOAuthBearer` / `verify.MSKAWSMSKIAM` decode them today.

## The trap we sidestep

The usual reason a Kafka proxy is hard is **Metadata rewriting**. A client
bootstraps against one broker, asks for `Metadata`, learns each broker's
*advertised* address, and then connects to those directly — straight past the
proxy. A general-purpose proxy must therefore decode and rewrite `Metadata`
responses across every protocol version, which is most of the work in projects
like grepplabs/kafka-proxy.

We avoid it completely: **we control the cluster's broker config**, so point
`KAFKA_ADVERTISED_LISTENERS` at the proxy and move the broker's real listener to
a port only the proxy dials. Metadata then advertises the proxy by construction,
and no response is ever rewritten. The cluster also runs `replicas: 1`, so there is
one address to point at.

## 🚨 The proxy is server-side. The credential agent is not.

These are different sidecars and conflating them defeats the exercise:

- The **credential agent** (RFC 0001) is per-pod, on loopback, because it stands
  in for the EKS Pod Identity agent, which is per-pod.
- The **auth terminator** sits in front of the brokers. Putting it next to the
  client would mean a pod verifying a token minted by itself — a check that
  proves nothing, since anything that can mint can pass it.

The same applies to the Redis proxy, which fronts Redis rather than riding along
with each client.

## Consequences

- One Go binary and one image for every role: agent, verifier, Redis proxy, Kafka proxy.
- The cluster's Kafka overlay changes `KAFKA_ADVERTISED_LISTENERS` and the listener
  port; the broker image itself is untouched.
- We take on minimal Kafka framing: the length-prefixed request header, which is
  versioned, and flexible versions (v2+) add tagged fields and compact strings.
  That is the real cost, and it is bounded by the four request types above.
- If a cluster ever needs multiple brokers reachable independently, Metadata
  rewriting comes back. At `replicas: 1` it does not.
