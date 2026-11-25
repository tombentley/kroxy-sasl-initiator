# Concepts

## What SASL initiation means

In Kroxylicious authentication terminology, a component that injects its own
`SaslHandshake`/`SaslAuthenticate` exchange with the broker is performing **SASL initiation**.
`SaslInitiation` is therefore an **upstream** filter: it authenticates the proxy's connection to
the Kafka broker.

```text
Kafka client  --->  client-facing filters  --->  SaslInitiation  --->  Kafka broker
                    TLS/mTLS, SaslTermination,   (proxy's own SASL
                    none                         identity)
```

The downstream client can be anonymous, authenticated by mTLS, or authenticated by
`SaslTermination`. The broker sees the identity selected by `SaslInitiation`, which may be the same
as the client identity or a shared service identity.

`SaslInitiation` is not:

* a client-facing SASL terminator (that is `SaslTermination`);
* a SASL observer or passthrough filter (that is `SaslInspection`);
* a replacement for broker-side ACLs, quotas or audit configuration;
* a mechanism for changing the downstream client's `Subject`;
* a token-exchange or impersonation mechanism.

## Where the filter sits

Recommended order, from the client towards the broker:

```text
... -> SaslTermination (optional) -> ... -> SaslInitiation (last) -> broker
```

`SaslInitiation` must be the last SASL-aware filter because its own internally generated SASL
frames travel towards the broker. If another SASL filter is closer to the broker, it may intercept,
observe or reject those frames. See [Deployment and chain order](deployment.md).

## Difference from `SaslTermination`

`SaslTermination` is a **client-facing** filter. It answers the client's `SaslHandshake` and
`SaslAuthenticate`, authenticates the client against the proxy's own credential store, and
publishes a client `Subject`.

`SaslInitiation` is the mirror image on the **broker-facing** side. It reads the client subject (in
subject mode), selects a broker credential, and runs its own SASL exchange with the broker. It never
calls the client-authentication-success/failure API and never publishes or replaces the client
subject.

They are normally used together:

```text
client --SASL--> SaslTermination --Subject--> SaslInitiation --SASL--> broker
```

This gives per-client broker identities without giving clients the broker credentials.

## Difference from `SaslInspection`

`SaslInspection` observes a client SASL passthrough. It does not terminate the client exchange and
does not create a broker identity selected by the proxy.

`SaslInitiation` is incompatible with client SASL passthrough in the same chain. The initiator
would see the client's `SaslHandshake`/`SaslAuthenticate` frames and reject them, because those
frames are meant for the broker and the broker is about to be driven by the initiator instead.
`SaslInspection` can coexist only if some other filter terminates the client SASL **before** the
initiator; in that case the inspector is not seeing a passthrough.

## Identity modes

### Fixed/shared identity

Every connection using the filter instance authenticates to the broker as the same identity. This
is the simplest deployment and the right choice for a proxy service account.

Consequences:

* broker ACLs, quotas and audit logs see the shared identity;
* per-client authorization, if required, must happen in the proxy (for example an authorizer
  filter);
* the downstream client may be anonymous, mTLS-authenticated or SASL-terminated.

### Subject-derived identity

The filter reads the downstream client's authenticated `Subject`, selects one configured principal
type (default `io.kroxylicious.proxy.authentication.User`), and uses that principal name as the
KeyStore lookup key.

The KeyStore entry can store a broker username different from the lookup key, which supports
mapping:

```text
client "alice"  ->  KeyStore entry "alice"  ->  broker username "svc-alice"
```

Subject mode fails closed. An anonymous subject, a missing principal, a missing KeyStore entry or a
subject change after authentication closes the connection. There is **no fallback** to a fixed
identity.

The subject must be trusted. It normally comes from `SaslTermination` or from a TLS subject builder
on an mTLS listener. A client cannot choose an arbitrary KeyStore alias independently of the
authenticated subject: the subject is the lookup key and the KeyStore is the allow-list.

## When authentication happens

The filter has no connection-established callback. It forwards the client's first `ApiVersions`
exchange unchanged, then initiates upstream authentication on the first request that is not
`ApiVersions`.

A Java Kafka client may send a second `ApiVersions` request after its own SASL termination. That
second request is treated as the trigger and is forwarded only after the upstream SASL exchange
succeeds. While authentication is in progress, the runtime holds later requests and preserves
order; the filter does not maintain its own request queue.

If the client never sent a usable `ApiVersions` response, the filter sends its own `ApiVersions`
request (version 0) before the handshake.

## Reauthentication

When the broker advertises a positive SASL session lifetime, or an OAuth token has a limited
lifetime, the filter proactively reauthenticates using KIP-368. The timing is described in
[Configuration reference](configuration.md#reauthentication). Reauthentication reuses the same
identity and credential; it never switches to a new subject. If the subject changed, the connection
fails closed.

Idle connections may be closed by the broker when their session expires; reauthentication runs at
the next request boundary on an active connection.

## What the client sees

Upstream failures are deliberately generic. The triggering request receives
`UNKNOWN_SERVER_ERROR` and the connection is closed. The broker's error text and SASL payloads are
never forwarded. If the downstream client used `SaslTermination`, it may therefore see a successful
client SASL exchange followed by a generic failure on a later request. This is a deliberate
trade-off: the filter works uniformly for SASL-terminated, mTLS-authenticated and anonymous
clients. Detailed diagnostics remain in the proxy log. See
[Failure semantics and observability](observability.md).

## Limitations

* Exactly one mechanism per filter instance; no negotiation, fallback or retry with another
  mechanism.
* One password per identity. Different passwords for different mechanisms require separate stores
  and filter definitions.
* A separate KeyStore is required for initiation credentials; do not reuse the `SaslTermination`
  store.
* No token exchange or per-user OAuth impersonation.
* No hot reload. Rotate credentials by restarting the proxy.
* No public credential-store SPI in this release.
* GSSAPI/Kerberos, delegation tokens and external KMS/HSM stores are out of scope.
