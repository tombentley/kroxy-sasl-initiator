# SASL Initiation Filter — Requirements and Design Decisions

**Status:** Decisions locked; ready to be condensed into the final high-level plan.  
**Date:** 2026-11-24  
**Baseline considered:** Kroxylicious `0.27.0-SNAPSHOT` (main at `fb1df74`), Kafka `4.3.2`, Java 21.

This document elaborates the requirements for a production-ready `SaslInitiation` filter and records the design decisions. All decisions are now locked as of 2026-11-24; the resulting high-level design is described in §6, and the detailed rationale is preserved in §7. A condensed final plan can be derived from this document without losing the reasoning.

## 1. What "SASL Initiation" means here

From the Kroxylicious authentication terminology ([proposal 004][proposal-004]):

> A component that injects its own `SaslAuthenticate` requests into a SASL exchange with the server is performing **SASL Initiation**.

The filter therefore sits on the **upstream** side of the proxy:

```text
Kafka client  --->  [client-facing authentication filters]  --->  [SaslInitiation]  --->  Kafka broker
                          (TLS/mTLS, SaslTermination,               (proxy's own SASL
                           SaslInspection, none)                     client identity)
```

The filter is **not**:

* a client-facing SASL terminator (that is `SaslTermination`);
* a SASL inspector/passthrough filter;
* a replacement for broker-side authorization;
* a mechanism for changing the downstream client's `Subject`.

It authenticates the **proxy** to the upstream broker. The downstream client may be anonymous, authenticated by mTLS, or authenticated by `SaslTermination`. The broker sees the identity selected by this filter, not necessarily the downstream client's identity.

The existing test-only [`SaslPlainInitiation`][sasl-plain-initiation] demonstrates the protocol injection technique but is not production-ready: it supports only PLAIN, stores credentials in configuration, has no reauthentication, and does not consider subject-based identity selection.

### 1.1 Current situation

Kroxylicious already provides:

* `SaslTermination`, which authenticates clients at the proxy and publishes a `Subject`;
* `SaslInspection`, which observes client SASL passthrough without necessarily terminating it;
* an OAUTHBEARER validation filter that validates tokens before forwarding the SASL exchange;
* a test-only `SaslPlainInitiation` filter that injects PLAIN SASL to the broker.

There is no production-ready mechanism for the proxy to authenticate itself to the broker using SASL, nor a way to choose the broker identity from the client's `Subject`. The upstream feature request [issue 5050][issue-5050] describes the gap and proposes the filter; this project elaborates and extends that request to cover multiple mechanisms and a KeyStore-backed credential source.

### 1.2 Affected projects

* **This project**: the new filter, its configuration, credential store, tooling, tests, and documentation.
* **Kroxylicious runtime/API**: only if a connection-lifecycle hook, subject-change notification, target-cluster information, or public credential-store SPI is required. The default proposal avoids such changes.
* **Kroxylicious design repo**: required only if public API changes are pursued upstream (see D1/D3).
* **Operator**: only if the filter is upstreamed and needs configuration/Secret templating documentation; no Operator code is required for a standalone plugin.

### 1.3 Compatibility considerations

* The filter targets a specific Kroxylicious API baseline (D2). The `Subject`/`Principal` API is in transition; the plan must say which types are used and how the 1.0 migration is handled.
* The filter must support the Kafka broker versions in the chosen compatibility matrix (D16/D27). Handshake v0/raw SASL is already rejected by the runtime.
* Existing proxy configurations are unaffected because this is a new filter type. Existing client applications are unaffected when the filter is configured.
* KeyStore format compatibility is governed by the versioned JSON schema (D9) and the tool (D11).

## 2. Motivation and use cases

### UC1 — Shared service identity

All downstream clients, regardless of how (or whether) they authenticate to the proxy, are represented to the broker by one Kafka identity.

Examples:

* Anonymous/TCP clients behind a trusted network boundary.
* mTLS clients where the broker should see a proxy service account, not the client certificate identity.
* A central proxy that is the only component allowed to hold broker credentials.

Consequences to document: broker ACLs, quotas, and audit logs see the shared identity; per-client authorization must happen in the proxy (e.g. an authorizer filter) if required.

### UC2 — Per-client identity after `SaslTermination`

The downstream `SaslTermination` filter authenticates each client against the proxy's own credential store and publishes a `Subject`. `SaslInitiation` selects the broker credential using that `Subject`, so the broker continues to see and authorize the individual user.

This is the primary identity-propagation use case. It enables:

* credential isolation: clients never hold broker credentials;
* mechanism translation: client uses PLAIN, broker uses SCRAM, etc.;
* retaining broker-side ACLs/RBAC per user.

### UC3 — Per-client identity from mTLS

The client's TLS certificate is mapped to a `Subject` by the configured transport subject builder. `SaslInitiation` uses that subject to select an upstream SASL credential.

This covers mTLS-to-SASL translation and is related to the broader authentication-swapping discussion in [issue 2166][issue-2166] and the MDS impersonation draft [PR 4908][pr-4908]. Full token exchange/impersonation is not automatically in scope (see non-goals).

### UC4 — Protocol/mechanism translation

The proxy can accept one client-facing mechanism and use another broker-facing mechanism. Examples:

| Client-facing | Broker-facing |
|---|---|
| mTLS | `SCRAM-SHA-256` |
| `SaslTermination` with PLAIN | `OAUTHBEARER` |
| `SaslTermination` with OAUTHBEARER | `SCRAM-SHA-512` |
| anonymous | `PLAIN` |

### UC5 — Broker migration and credential lifecycle isolation

Broker credentials can be rotated independently of client credentials and without changing client configuration. The proxy's KeyStore becomes the boundary of broker-credential custody.

### UC6 — OAUTHBEARER upstream authentication

The proxy obtains or supplies an OAuth bearer token and uses it to authenticate to the broker. This may be a shared service token, a shared client-credentials grant, or (if implemented) a per-subject token or client identity.

## 3. Requirements

### 3.1 Functional requirements

**Mechanisms**

* R1. Support `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, and `OAUTHBEARER`.
* R2. Use the IANA-registered mechanism names in configuration and on the wire.
* R3. Prefer delegation to Kafka/JDK SASL client implementations over reimplementing mechanisms. This mirrors `SaslTermination`'s use of Kafka's `SaslServer`.

**Identity selection**

* R4. Support a **fixed/shared identity** mode: one broker identity for every client connection.
* R5. Support a **subject-derived identity** mode: select the broker credential from the downstream client's `Subject`.
* R6. In subject mode, select from a configurable principal type, defaulting to `io.kroxylicious.proxy.authentication.User` (or the equivalent post-1.0 identity API type).
* R7. Fail closed if the configured principal is absent or ambiguous; do not silently fall back to a shared identity unless explicitly configured.
* R8. Define what happens if the downstream subject changes during the connection (e.g. after client reauthentication).

**Credential storage**

* R9. Store password-mechanism credentials (username + plaintext password) in a standard Java KeyStore.
* R10. Support KeyStore location, store type, and store password from proxy configuration, using the existing `PasswordProvider` abstraction (`passwordFile` for production; inline password only for development).
* R11. Never require or encourage broker passwords in plain text in the proxy YAML.
* R12. Define a stable, versioned KeyStore entry format and tooling to create/update/list entries.
* R13. Load credentials at filter initialization; define whether/when reload is supported.
* R14. Apply appropriate file-permission checks and avoid logging sensitive material.

**Protocol behaviour**

* R15. Inject `SaslHandshake` and `SaslAuthenticate` at the correct point in the connection: after the optional client `ApiVersions`, and before the first business RPC.
* R16. Determine SASL API versions from the broker's `ApiVersions` response, or use a defined safe compatibility strategy.
* R17. Handle SASL challenge/response loops for SCRAM and OAUTHBEARER correctly, including the final server message.
* R18. Handle pipelining: the client may send requests before earlier responses arrive; no request may overtake the upstream authentication.
* R19. Reject any downstream attempt to pass `SaslHandshake`/`SaslAuthenticate` through to the broker. Client-facing SASL must be terminated earlier in the chain.
* R20. Handle broker authentication failure by returning a generic error for the triggering request and closing the connection, without exposing broker error details to the client.
* R21. Support KIP-368 (SASL reauthentication) or explicitly declare it out of scope for the first release.
* R22. Preserve the downstream client's `Subject`; this filter must not call `clientSaslAuthenticationSuccess`/`clientSaslAuthenticationFailure` to impersonate a client authentication outcome.

**Composition**

* R23. Work when placed after `SaslTermination` (the recommended order) and when the downstream client is anonymous or mTLS-authenticated.
* R24. Document and, where possible, detect/validate the required filter-chain ordering.
* R25. Ensure the filter's own generated SASL frames are not intercepted by other SASL filters closer to the broker. This normally means placing it last/closest to the broker.

**Observability and operations**

* R26. Emit logs and metrics for authentication attempts, outcomes, duration, mechanism, virtual cluster, and reauthentication. Never include passwords, tokens, or SASL payloads.
* R27. Validate configuration at startup: mechanism, identity mode, KeyStore readability/integrity, required entries, and OAuth settings.
* R28. Provide clear documentation and examples for all mechanisms and both identity modes.

### 3.2 Security requirements

* S1. Broker credentials are secrets: protect at rest, in transit, in memory, and in logs.
* S2. Use TLS for upstream connections where required; warn/document that `PLAIN` over `SASL_PLAINTEXT` exposes passwords.
* S3. Subject-derived identity must use only a trusted downstream `Subject`; anonymous or unauthenticated subjects must not select credentials.
* S4. Do not let a client choose an arbitrary KeyStore alias independently of the authenticated subject. The subject is the lookup key; the KeyStore is the allow-list.
* S5. If the downstream subject changes after upstream authentication, fail closed unless a deliberate, tested reauthentication policy is configured.
* S6. Return generic errors to clients; retain detailed diagnostics only in proxy logs.
* S7. Apply KeyStore file permission checks (owner-only by default, with a documented Kubernetes/OpenShift relaxation).
* S8. Avoid caching broker credentials or tokens in places that outlive the connection unless justified and bounded.
* S9. Document the accepted risk that plaintext passwords/tokens exist in the JVM heap while in use.

### 3.3 Operational requirements

* O1. Support PKCS12 (preferred) and, if cheap, JKS.
* O2. Provide a CLI for creating and managing the KeyStore, because a versioned JSON payload inside a `SecretKeyEntry` is not practical with bare `keytool`.
* O3. Support file-based store passwords for Kubernetes Secret/volume workflows.
* O4. No hot reload in the first release unless explicitly chosen; credential rotation requires restart/reconfiguration.
* O5. Fail fast at startup rather than at first client connection for configuration/store errors.
* O6. Document how the filter interacts with the Operator/Secret templating model if it is contributed upstream.

### 3.4 Quality/compatibility requirements

* Q1. Target a specific Kroxylicious API baseline and document it; the `Subject`/`Identity` API is in transition.
* Q2. Target a defined Kafka broker version range and SASL API version range.
* Q3. Keep the post-authentication request path cheap (avoid deserializing every business request if possible).
* Q4. Provide unit, protocol-level, and real-Kafka integration tests for all supported mechanisms and both identity modes.
* Q5. Follow Kroxylicious conventions for plugin discovery, `@Plugin`, `@PluginImplName`, service files, configuration, logging, metrics, and license headers.

## 4. Goals

* G1. Deliver a production-ready filter factory, not a test-only plugin.
* G2. Support the four named mechanisms with Kafka-compatible protocol behaviour.
* G3. Support both shared identity and per-subject identity selection.
* G4. Store broker passwords in a standard Java KeyStore with a safe, documented format and tooling.
* G5. Compose safely with `SaslTermination` and mTLS authentication.
* G6. Implement correct Kafka SASL initiation, including API version negotiation, pipelining, and (if in scope) reauthentication.
* G7. Fail closed, avoid secret leakage, and provide actionable observability.
* G8. Be usable without changes to client applications.

## 5. Non-goals

* N1. GSSAPI/Kerberos.
* N2. Client-facing SASL termination (use `SaslTermination`).
* N3. SASL passthrough or inspection (use `SaslInspection`).
* N4. Changing the downstream `Subject` or acting as an authorizer.
* N5. Full OAuth token exchange/impersonation (RFC 8693, Confluent MDS impersonation) unless explicitly included later.
* N6. Hot reload/rotation of KeyStore contents in the first release.
* N7. Per-target-cluster credentials when routing to multiple upstream clusters, unless the routing API exposes the necessary target information and this is explicitly in scope.
* N8. Multiple mechanisms with fallback/negotiation within one filter instance.
* N9. Raw SASL (SASL handshake v0) and pre-Kafka-4.0 client behaviour.
* N10. Delegation tokens.
* N11. HSM/KMS-backed credential storage; the first release uses a local Java KeyStore.
* N12. Supporting arbitrary non-Java KeyStore formats or external credential stores unless a public SPI is chosen.

## 6. High-level design

### 6.1 Filter placement

Recommended chain order, client-to-broker:

```text
... -> SaslTermination (optional) -> SaslInitiation (last) -> broker
```

Rationale:

* `SaslTermination` must see and short-circuit the client's SASL frames; `SaslInitiation` must not see them.
* `SaslInitiation`'s own `sendRequest` for `SaslHandshake`/`SaslAuthenticate` travels toward the broker, through filters later in the chain. Placing it last means no other SASL-aware filter observes or intercepts those frames.
* If `SaslInitiation` is placed before `SaslTermination`, it will see client SASL frames and must reject them; this is a misconfiguration.

There is currently no runtime API to validate chain order. The filter can defend itself by rejecting client-originated SASL frames, but cannot know whether a later filter will see its own upstream SASL frames. This must be documented and tested.

### 6.2 Trigger point

The filter has no connection-established callback in the current `Filter` API. It must trigger on a client request.

Chosen rule:

1. Forward the client's initial `ApiVersions` request/response normally. This is important for subject mode: with `SaslTermination`, the client must complete its `ApiVersions` + SASL exchange before a subject exists. Holding `ApiVersions` would deadlock.
2. On the first request that is **not** `ApiVersions` (and not a client SASL frame, which is rejected):
   * fixed mode: start upstream authentication immediately;
   * subject mode: resolve the subject; if eligible, start upstream authentication; otherwise fail closed.
3. While authentication is in progress, return an incomplete `CompletionStage` for the triggering request. The runtime pauses reads and queues later requests, preserving order. This avoids a hand-written buffer and the associated ordering bugs.
4. After successful authentication, forward the triggering request and all subsequent requests normally.
5. If the first client request is not `ApiVersions` (non-standard client), authenticate before forwarding it.

This rule avoids an extra delay on `ApiVersions` and avoids the deadlock between client SASL termination and subject selection.

Alternative: initiate immediately after `ApiVersions` when the subject is already available (fixed mode or mTLS). This saves a small amount of latency but adds state complexity. It can be decided later.

### 6.3 Upstream authentication sequence

High-level sequence for one broker connection:

```text
1. Send ApiVersionsRequest (internal, filter-originated).
2. Choose SaslHandshake/SaslAuthenticate versions supported by the broker.
3. Send SaslHandshakeRequest(mechanism).
4. Create a SASL client for the mechanism with the selected credential.
5. Send the initial SaslAuthenticateRequest.
6. Loop over challenge/response until the SASL client is complete and the broker reports success.
7. Record the broker-reported sessionLifetimeMs (if any).
8. Forward the client request that triggered authentication.
```

The internal requests are sent with `FilterContext.sendRequest`, which gives the filter the broker response asynchronously and preserves the connection's ordering/backpressure rules.

### 6.4 Credential model

The model is deliberately abstracted from the KeyStore and mechanism:

```text
Identity selector  ->  Credential resolver  ->  Mechanism driver
(fixed key /          (KeyStore entry)         (PLAIN / SCRAM / OAUTHBEARER)
 subject principal)
```

* **Identity selector** decides which KeyStore entry to use.
* **Credential resolver** loads and validates the entry, producing either a username/password credential or an OAuth credential/token source.
* **Mechanism driver** creates the appropriate `SaslClient`, runs the challenge/response loop, and extracts the session lifetime.

This keeps mechanism-specific logic separate from identity/store concerns and leaves room for a future credential-store SPI.

### 6.5 Configuration

The configuration uses nested groups (D24):

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-256

      identity:
        mode: subject          # fixed | subject
        # fixed mode:
        # key: proxy-service
        # subject mode:
        principalType: io.kroxylicious.proxy.authentication.User

      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password

      # Only for mechanism: OAUTHBEARER
      # oauthBearer:
      #   tokenEndpointUrl: https://idp.example.com/token
      #   # or a file containing a token:
      #   # tokenEndpointUrl: file:/etc/kroxylicious/token.jwt
      #   scope: kafka
      #   jwtRetriever: org.apache.kafka.common.security.oauthbearer.DefaultJwtRetriever
      #   subjectClaimName: sub

      reauth:
        windowFactor: 0.8      # optional; default 0.8

      clientId: kroxylicious-sasl-initiation   # optional
```

Field defaults and validation:

* `mechanism` is required and must be one of `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `OAUTHBEARER`.
* `identity.mode` is required: `fixed` or `subject`.
* `identity.key` is required for fixed mode when a KeyStore is used; it is rejected for subject mode.
* `identity.principalType` is optional for subject mode; default `io.kroxylicious.proxy.authentication.User`. It must name a singular principal type.
* `keyStore` is required for password mechanisms and for OAuth client-credentials; it is optional only for fixed-identity OAuth with a token file.
* `keyStore.file` and `keyStore.filePassword` are required when `keyStore` is present. `filePassword` is a `PasswordProvider`; `passwordFile` is recommended for production.
* `oauthBearer` is required exactly when `mechanism` is `OAUTHBEARER`; it is rejected for other mechanisms.
* `oauthBearer.tokenEndpointUrl` is required for OAUTHBEARER. A `file:` URL selects a token file; an `http(s)://` URL selects a token endpoint.
* `oauthBearer.scope` and `oauthBearer.subjectClaimName` are optional. The default subject claim is `sub`.
* `oauthBearer.jwtRetriever` is optional; the default is Kafka's `DefaultJwtRetriever`, which selects a retriever based on the endpoint URL.
* `reauth.windowFactor` is optional, must be between 0.5 and 0.95, and defaults to 0.8. Randomized jitter is applied around this factor.
* `clientId` is optional and defaults to `kroxylicious-sasl-initiation`.
* No broker password or OAuth client secret is accepted directly in the YAML; those live in the KeyStore.

### 6.6 KeyStore entry format

PKCS12 container; one `SecretKeyEntry` per identity; alias is derived from the lookup key rather than being the raw username. This follows the existing SCRAM credential-store precedent:

* alias = lowercase hex SHA-256 of the lookup key (UTF-8);
* key bytes = UTF-8 JSON;
* JSON has a `version` field for evolution.

JSON v1 for a password credential:

```json
{
  "version": 1,
  "subject": "alice",
  "username": "alice",
  "password": "correct horse battery staple"
}
```

JSON v1 for an OAuth client credential:

```json
{
  "version": 1,
  "subject": "alice",
  "oauthBearer": {
    "clientId": "alice-client",
    "clientSecret": "...",
    "expectedSubject": "alice"
  }
}
```

Notes:

* `subject` is the lookup key the entry is intended for; it allows validation and avoids silently mapping the wrong credential.
* `username` is the broker authentication ID. It may equal `subject` (direct mapping) or differ (service-account mapping).
* `password` is plaintext because PLAIN/SCRAM clients must present it. The KeyStore password protects it at rest. One password per identity (D12).
* `oauthBearer` is only used for OAUTHBEARER. The global token endpoint, scope, and retriever are configured in the filter's `oauthBearer` group; the entry supplies the per-identity client credentials.
* `expectedSubject` is the token claim value the proxy verifies. It defaults to the entry's `subject`; for a mapped OAuth identity it can name the OAuth client/broker subject explicitly.
* The exact schema is versioned and may be extended; per-mechanism password overrides are not in v1.

### 6.7 Client-visible failure semantics and the termination/initiation coupling trade-off

Broker-side initiation can fail in several ways: the broker rejects the configured mechanism, rejects the credential, returns an unexpected error, or the connection times out. The filter must not expose broker error details to the downstream client.

The chosen behaviour is:

* log the broker error code/message and, for a rejected mechanism, the broker's enabled mechanisms, in a sanitized form;
* return a **generic** Kafka error (`UNKNOWN_SERVER_ERROR`) for the request that triggered initiation;
* close the connection.

The filter must **not** return `UNSUPPORTED_SASL_MECHANISM` or `SASL_AUTHENTICATION_FAILED` to the downstream client merely because the upstream broker rejected the mechanism or credential. The downstream client might not be using SASL at all: it could be anonymous or mTLS-authenticated, in which case a SASL-specific error is semantically wrong.

#### The coupling tension

There is a real design tension here:

* If the downstream client is using `SaslTermination`, the proxy has already told the client that its SASL exchange succeeded. The upstream initiation only happens later, when the first business request arrives. If initiation then fails, the client sees a failure **after** a successful SASL exchange, and the proxy can only report a generic business-request error.
* A cleaner client experience would be to make the downstream SASL termination wait for the upstream initiation and fail the client's `SaslAuthenticate` with a SASL-specific error. That requires the two state machines to be coupled: the termination filter would need to know the initiation outcome, either through a shared authentication-outcome API or by combining termination and initiation into one filter.
* Coupling would improve errors for SASL-terminated clients, but it would not help mTLS or anonymous clients, where there is no client SASL exchange to attach the error to. It would also make filter composition/order assumptions much stronger and reduce the reusability of `SaslInitiation`.

The chosen design deliberately keeps the filters decoupled. It accepts slightly odd client-visible behaviour (a generic error/disconnect after a successful client SASL exchange) in exchange for a filter that works uniformly with SASL termination, mTLS, and anonymous clients. The detailed failure reason remains in the proxy logs.

**Future work:** consider a shared authentication-outcome notification or a combined `SaslTerminationAndInitiation` filter for deployments that always use client SASL termination and want SASL-specific error mapping. This should be a separate design decision, not a hidden coupling in the initial filter.

## 7. Key design decisions

All decisions below are locked as of 2026-11-24. The detailed sections preserve the options considered and the rationale, so the final plan can be condensed from them without losing the reasoning.

### 7.1 Decision summary

| ID | Decision | Recommendation | Status |
|----|----------|----------------|--------|
| D1 | Delivery model | Prototype standalone, structure for upstream | Decided |
| D2 | Target API/version baseline | Latest released Kroxylicious; Kafka 4.3.x clients; Kafka 4.0+ brokers | Decided |
| D3 | Public credential-store SPI? | Built-in KeyStore with internal abstraction; no public SPI in v1 | Decided |
| D4 | Naming | `SaslInitiation` | Decided |
| D5 | Mechanisms per instance | Exactly one; one handshake; no retry | Decided |
| D6 | Identity modes | `fixed` and `subject`; no fallback; fail closed | Decided |
| D7 | Principal selection | Configurable singular principal, default `User` | Decided |
| D8 | Identity mapping | Keyed mapping with stored broker username | Decided |
| D9 | KeyStore entry model | Versioned JSON in PKCS12 `SecretKeyEntry`; hashed alias | Decided |
| D10 | KeyStore password/type/lifecycle | Dedicated PKCS12 file, required password, owner-only, load once | Decided |
| D11 | KeyStore tooling | Custom CLI | Decided |
| D12 | Password granularity | One password per identity | Decided |
| D13 | OAUTHBEARER source | Fixed token/client-credentials; per-subject client credentials; verify token subject; no impersonation | Decided |
| D14 | Credential-store extensibility | Defer public SPI | Decided |
| D15 | Trigger point | First non-`ApiVersions` request; no runtime hook | Decided |
| D16 | API versions | Filter sends its own `ApiVersions` at trigger; broker 4.0+ | Decided |
| D17 | Client SASL frames | Reject and close; SASL-specific error only because the client is SASL-aware | Decided |
| D18 | Buffering | Runtime backpressure via incomplete stage | Decided |
| D19 | Failure semantics | Generic error then close; no retry; no SASL-specific error for upstream failure | Decided |
| D20 | Reauthentication | Proactive KIP-368 at 80% of effective lifetime; same identity; close on subject change | Decided |
| D21 | Post-auth interception | Intercept all requests always | Decided |
| D22 | Routing/multi-target | One target per client connection in v1 | Decided |
| D23 | Token/credential caching | Shared bounded OAuth token cache | Decided |
| D24 | Configuration schema | Nested groups + `PasswordProvider`; field names and validation locked in §6.5 | Decided |
| D25 | Secret handling | No secret logging; pragmatic zeroization via a local destroyable wrapper | Decided |
| D26 | Observability | Metrics + structured logs; no sensitive labels | Decided |
| D27 | Test matrix | Unit + protocol + real Kafka integration | Decided |
| D28 | Documentation | Full concept/config/security/ops docs | Decided |

### 7.2 Decision record

The following were agreed on 2026-11-24:

1. **Delivery:** prototype as a standalone plugin in this project, structured for later upstream donation.
2. **Baseline:** target the latest released Kroxylicious line and Kafka 4.3.x, pinned for reproducible builds.
3. **Identity mapping:** KeyStore entries are keyed by the client subject but may store a different broker username. Direct mapping is the special case where the names match.
4. **OAUTHBEARER:** support shared token-file/client-credentials for fixed identity and per-subject OAuth client credentials in the KeyStore for subject mode. Token exchange/impersonation and per-subject static tokens are future work.
5. **Reauthentication:** implement proactive, scheduled KIP-368 reauthentication in the first release.
6. **Trigger:** initiate on the first request that is not `ApiVersions`; do not require a runtime connection-lifecycle hook.
7. **Credential extensibility:** built-in KeyStore only in v1, behind an internal abstraction; do not expose a public credential-store SPI yet.
8. **Tooling:** provide a custom KeyStore-management CLI.
9. **KeyStore entry format:** versioned JSON inside a PKCS12 `SecretKeyEntry`; alias is lowercase hex SHA-256 of the lookup key.
10. **Password granularity:** one password per identity. Different PLAIN/SCRAM passwords require separate KeyStore files (or a future schema extension).
11. **Broker auth failure:** return a generic `UNKNOWN_SERVER_ERROR` for the triggering request, log sanitized details, and close; no retry.
12. **Subject change:** if the downstream subject changes after upstream authentication, close the connection.
13. **Post-auth interception:** intercept all requests, even after authentication. This simplifies subject-change detection and reauthentication pausing; the performance cost is accepted.
14. **Routing scope:** one target cluster per client connection in v1; routing/multi-target is future work.
15. **Broker versions:** Kafka 4.0+ brokers.
16. **OAuth:** use Kafka's `FileJwtRetriever`/`ClientCredentialsJwtRetriever` per identity; for per-subject OAuth, verify the token's subject claim against the selected subject. No token exchange.
17. **KeyStore sharing:** use a dedicated PKCS12 file for initiation credentials, separate from `SaslTermination`'s SCRAM credential store.
18. **Per-subject OAuth storage:** store OAuth client credentials (`clientId`/`clientSecret`) in the KeyStore entry; Kafka's `ClientCredentialsJwtRetriever` obtains the token. Fixed identity may also use a shared token file.
19. **OAuth token cache:** use a shared bounded cache keyed by identity, respecting token expiry.
20. **Reauthentication timing:** reauthenticate at 80% of the effective lifetime (the earlier of broker session lifetime and token expiry), with a configurable factor.
21. **No eligible subject:** fail closed immediately with a generic error and close.
22. **Configuration style:** nested `identity`, `keyStore`, `oauthBearer`, and `reauth` groups.
23. **Naming:** `SaslInitiation`.
24. **Mechanisms:** exactly one configured mechanism; one `SaslHandshake`; on rejection, log the broker's enabled mechanisms and fail; no second handshake. Kafka's own client behaves the same.
25. **Identity modes:** `fixed` and `subject` only; no fallback.
26. **Principal selection:** configurable singular principal type, default `User`; require exactly one; fail closed.
27. **Upstream failure error code:** generic `UNKNOWN_SERVER_ERROR`; never a SASL-specific error for an upstream broker failure; then close.
28. **Termination/initiation coupling:** deliberately decoupled; accept slightly odd client-visible errors for SASL-terminated clients in exchange for uniform support of mTLS/anonymous clients. See §6.7.
29. **Secret handling:** pragmatic zeroization using a local destroyable wrapper inspired by `DestroyableRawSecretKey`; no dependency on the KMS module.
30. **Observability, testing, documentation:** metrics + structured logs; unit + protocol + real Kafka tests; full concept/config/security/ops docs.

### 7.3 Detailed decisions

### D1 — Delivery model: standalone plugin or upstream first-party module?

**Question:** Is this a separate repository/artifact that depends on `kroxylicious-api` (provided), or a module contributed to the Kroxylicious repository?

**Options:**

* A. Standalone external plugin (this project), using the published Kroxylicious API and a released version.
* B. First-party module under `kroxylicious-filters/kroxylicious-sasl-initiation`.
* C. Prototype standalone, then upstream once stable.

**Recommendation:** C, unless the intent is explicitly upstream-first. The upstream issue [5050][issue-5050] asks for a production-ready filter, but also carries `design-proposal-needed` because it may involve public API/config decisions. A standalone implementation is faster to iterate and can still be structured for upstream donation.

**Decision (2026-11-24):** Prototype standalone in this project, structured for later upstream donation.

**Impact:** package names, module layout, whether a `kroxylicious/design` proposal is required, release/publishing, dependency on unreleased APIs.

---

### D2 — Target API/version baseline?

**Question:** Which Kroxylicious and Kafka versions does the filter target?

**Current facts:** main is `0.27.0-SNAPSHOT`; Kafka clients are `4.3.2`; the `Subject`/`Principal` API is deprecated in favour of `io.kroxylicious.identity`, with removal planned for 1.0. `FilterContext.authenticatedSubject()` currently returns the deprecated `io.kroxylicious.proxy.authentication.Subject`, which implements the new `Identity` bridge.

**Options:**

* A. Target the latest released Kroxylicious version (currently 0.26.x), pinned.
* B. Target current main / next release.
* C. Target both via reflection/compatibility layers (not recommended).

**Recommendation:** pin to a specific released version for a standalone plugin; if upstream, target main. Use `io.kroxylicious.identity.Identity`/`Principal` internally where possible, and isolate the deprecated `Subject` type at the `FilterContext` boundary so the 1.0 migration is small.

**Decision (2026-11-24):** Target the latest released Kroxylicious line and Kafka 4.3.x clients, pinned for reproducible builds. Minimum supported broker version is Kafka 4.0.

**Impact:** API compatibility, build stability, identity principal type, testing baseline.

---

### D3 — Public extensibility SPI or built-in KeyStore only?

**Question:** Should the credential source be a public plugin SPI (analogous to `ScramCredentialStoreService`) or a built-in KeyStore configuration?

**Options:**

* A. Built-in KeyStore only. Simplest; matches "use a standard Java KeyStore".
* B. Public `SaslInitiationCredentialStore` SPI + first-party KeyStore provider. Matches `SaslTermination`'s extensibility; enables Vault/KMS/DB in future.
* C. Internal credential-resolver abstraction with a KeyStore implementation; expose an SPI only if needed later.

**Recommendation:** C for the first release. The requirement explicitly names Java KeyStore, and a public SPI adds API surface, lifecycle, and security review. Keep the internal design clean enough to promote it later. If upstream-first (D1=B), a public SPI would require a design proposal and should be decided deliberately.

**Decision (2026-11-24):** Built-in KeyStore only in v1, behind an internal abstraction; no public credential-store SPI yet.

**Impact:** public API, module structure, configuration shape, design-proposal requirement.

---

### D4 — Filter and artifact naming?

**Question:** `SaslInitiation` vs `SaslInitiator`; package/artifact names; config key names.

**Recommendation:** `SaslInitiation` (consistent with `SaslTermination`), package `com.github.tombentley.kroxylicious.filter.sasl.initiation`, artifact `kroxylicious-sasl-initiation` if upstream. Use "initiation" for the concept and "initiator" only in prose if needed.

**Decision (2026-11-24):** Use `SaslInitiation` for the filter type, module, and documentation.

**Impact:** user-facing config, docs, package names.

---

### D5 — One mechanism per filter instance, or a list with fallback?

**Question:** Does one `SaslInitiation` filter configure exactly one broker-facing mechanism, or multiple mechanisms with negotiation/fallback?

**Options:**

* A. Single `mechanism` per filter instance. The proxy chooses the mechanism; there is no client negotiation.
* B. Ordered list of mechanisms; try each until one succeeds.
* C. Per-target-cluster mechanism configuration.

**Recommendation:** A. The initiator is not negotiating with the client; it chooses a broker mechanism. Multiple mechanisms can be expressed as multiple filter definitions in different virtual clusters, or added later. Fallback complicates error semantics and can mask misconfiguration.

**Decision (2026-11-24):** Exactly one configured mechanism. The filter sends exactly one `SaslHandshakeRequest` naming that mechanism; the broker's handshake response is authoritative. If the broker rejects it with `UNSUPPORTED_SASL_MECHANISM`, the filter logs the broker's enabled mechanisms and fails the connection. It does **not** perform a second handshake with another mechanism.

**Verification:** Kafka 4.3.2's `SaslClientAuthenticator.handleSaslHandshakeResponse` also treats a non-`NONE` handshake response as terminal. It throws `UnsupportedSaslMechanismException` containing the broker's enabled mechanisms; it does not retry. So "no retry" matches Kafka's own client behaviour. The broker's mechanism list is a diagnostic, not a negotiation opportunity.

**Impact:** config schema, state machine, testing matrix.

---

### D6 — Identity modes and fallback semantics?

**Question:** What identity modes are supported, and what happens when the preferred identity is unavailable?

**Options:**

* A. `fixed` and `subject`, with fail-closed subject mode and no fallback.
* B. `fixed`, `subject`, and `subject-with-fixed-fallback`.
* C. A general plugin/selector SPI.

**Recommendation:** A for v1. Fail closed is the safe default; an explicit fallback can be added later if a real use case appears. A general selector plugin can be future work.

**Decision (2026-11-24):** Support `fixed` and `subject` only, with no fallback. A business request in subject mode without an eligible subject fails closed immediately.

**Impact:** security model, config, error handling.

---

### D7 — Which principal identifies the client?

**Question:** How does subject mode choose a principal from `Subject`?

**Options:**

* A. Always the `User` principal. Current `Subject` invariants guarantee exactly one `User` in a non-empty subject.
* B. Configurable principal class (FQCN), required to be a "singular" principal type; require exactly one matching principal.
* C. Configurable predicate/mapper plugin.

**Recommendation:** B, defaulting to `User`. This supports custom subject builders and future principal types while preserving a simple default. Use `Identity.uniquePrincipalOfType()` (or the old `Subject` equivalent) and fail closed if absent or ambiguous. Validate the class at startup.

**Decision (2026-11-24):** Configurable singular principal type, default `User`; require exactly one matching principal; fail closed otherwise.

**Impact:** config, identity API dependency, subject-builder compatibility.

---

### D8 — Direct identity mapping or keyed mapping?

**Question:** Does the broker username always equal the downstream principal name, or can a KeyStore entry map a client subject to a different broker identity?

**Options:**

* A. Direct: broker authcid = selected principal name; KeyStore lookup by that name.
* B. Keyed mapping: KeyStore entry is keyed by the client subject/principal, but contains the broker username, which may differ. This supports "alice -> svc-alice".
* C. External mapper plugin.

**Recommendation:** B built-in. It subsumes A (stored username may equal subject) and is more operationally useful. Validate that the stored `subject` matches the lookup key. Keep the door open to a mapper plugin later.

**Decision (2026-11-24):** Keyed mapping is supported; the KeyStore entry may store a broker username different from the lookup subject. Direct mapping is the special case where they match.

**Impact:** KeyStore schema, lookup algorithm, documentation, security review (a mapping must not let an arbitrary client select an arbitrary service account beyond what the KeyStore authorizes).

---

### D9 — KeyStore entry model and alias scheme?

**Question:** How are credentials represented inside the Java KeyStore?

**Options:**

* A. PKCS12 `SecretKeyEntry` containing versioned JSON; alias = hash(lookup key). (Follows the existing SCRAM store.)
* B. Raw UTF-8 password bytes in a `SecretKeyEntry`; username/config stored separately.
* C. Standard `keytool -importpass` PBE entries; no custom JSON.
* D. One KeyStore file per identity (simple but operationally heavy).

**Recommendation:** A. It supports username/password/OAuth fields, future schema evolution, and alias restrictions/case-insensitivity. Use lowercase hex SHA-256 of the exact lookup key; store the original subject/username inside the JSON. Do not use raw aliases, because JKS/PKCS12 alias handling and `keytool` restrictions are awkward.

**Decision (2026-11-24):** Versioned JSON inside a PKCS12 `SecretKeyEntry`; alias is lowercase hex SHA-256 of the lookup key.

**Impact:** tooling, compatibility, security, migration.

---

### D10 — KeyStore password, type, permissions, and lifecycle?

**Question:** How is the KeyStore protected and loaded?

**Options:**

* A. PKCS12 only; required `filePassword` via `PasswordProvider`; owner-only file permissions; load once at initialization.
* B. PKCS12 + JKS; password optional for JKS; same permission policy.
* C. Add hot reload/file watching.

**Recommendation:** A. JKS cannot store `SecretKeyEntry` objects (`KeyStoreException: Cannot store non-PrivateKeys`), so the JSON-in-a-secret-key format requires PKCS12. Require a non-empty store password; use the same password for entry protection unless a key password is explicitly needed. Enforce POSIX permissions (owner-only by default, documented relaxation for Kubernetes) and load once at factory initialization. Leave hot reload out of v1.

**Decision (2026-11-24):** Dedicated PKCS12 file for initiation credentials (not shared with `SaslTermination`); required store password; owner-only permissions with a documented Kubernetes relaxation; load once at initialization. The remaining detail (whether to support a separate key password) defaults to "same as store password".

**Impact:** operations, security, Kubernetes/Operator integration.

---

### D11 — KeyStore tooling?

**Question:** How do users create and maintain the KeyStore?

**Options:**

* A. Custom CLI (`sasl-initiation-credential-tool`) with create/add/update/remove/list, interactive password prompts, and an "insecure options" gate for CLI passwords.
* B. Document a Java snippet or `keytool` workaround.
* C. Library API only.

**Recommendation:** A. The versioned JSON payload is not practical with bare `keytool`; a CLI reduces user error and can enforce the schema, alias hashing, file permissions, and password handling. It can be a separate module/jar if standalone.

**Decision (2026-11-24):** Provide a custom CLI.

**Impact:** project size, distribution, docs, testing.

---

### D12 — One password per identity or per mechanism?

**Question:** If the same identity is used for PLAIN and SCRAM, and the broker has different passwords for those mechanisms, how is that represented?

**Options:**

* A. One `password` field per identity, used for whichever password mechanism is configured. Different passwords require separate KeyStore entries/files.
* B. A map of mechanism -> password inside each entry.
* C. Separate KeyStore files per mechanism.

**Recommendation:** A for v1; document the limitation. Kafka deployments usually use the same password for PLAIN and SCRAM for a user, but not always. B can be added compatibly later via the versioned schema. If this is a known requirement, choose B now.

**Decision (2026-11-24):** One password per identity. Different passwords require separate KeyStore files until the schema is extended.

**Impact:** KeyStore schema, tooling, config.

---

### D13 — OAUTHBEARER credential/token source?

**Question:** Where does the OAuth bearer token come from, and does it support per-subject identity?

**Options:**

* A. Fixed identity only in v1: a token file (`FileJwtRetriever`) or shared client credentials (`ClientCredentialsJwtRetriever`) + token endpoint.
* B. Per-subject tokens stored in the KeyStore.
* C. Per-subject OAuth client credentials in the KeyStore, using Kafka's `ClientCredentialsJwtRetriever`; the token's `sub` is the OAuth client identity, which may be mapped/aliased to the Kafka principal.
* D. Token exchange/impersonation (RFC 8693 / `JwtBearerJwtRetriever` / MDS) to obtain a token whose `sub` matches the downstream subject.
* E. Reuse the downstream client's OAUTHBEARER token (requires a new API; `ClientSaslContext` does not expose the token).

**Recommendation:** A+B/C for v1: support a token file or client-credentials grant for fixed identity, and optionally per-subject token/client-credentials entries in the KeyStore for subject mode. Treat D (true impersonation) as future work / a separate proposal. Do not do E. If per-subject OAuth is not required for v1, explicitly limit subject mode to password mechanisms and document it.

**Decision (2026-11-24):** Fixed identity supports a shared token file (Kafka `FileJwtRetriever`) or shared OAuth client credentials (Kafka `ClientCredentialsJwtRetriever`). Subject mode stores per-subject OAuth client credentials in the KeyStore and uses `ClientCredentialsJwtRetriever`; the proxy verifies the retrieved token's subject claim. Token exchange/impersonation and per-subject static tokens are out of scope for v1.

**Key sub-decision:** what "identity" means for OAUTHBEARER subject mode. A client-credentials token identifies the OAuth client, not necessarily the downstream `User`. The chosen model therefore requires the KeyStore entry to map the client subject to an OAuth client identity and an expected token subject. If exact subject impersonation is required, token exchange is the only correct answer and remains future work.

**Impact:** config, KeyStore schema, token caching/refresh, reauthentication, IdP integration, testing.

---

### D14 — Credential store extensibility?

See D3. If the answer is a public SPI, define:

* lifecycle (initialize/build/close) like `ScramCredentialStoreService`;
* async lookup (`CompletionStage`);
* credential types without Kafka-internal dependencies;
* exception model;
* plugin name/config resolution via `@PluginImplName` / `@PluginImplConfig`;
* how OAUTH token suppliers fit (they are not just username/password).

**Recommendation:** defer unless required; if deferred, keep the internal interface shaped so it can become public.

**Decision (2026-11-24):** Defer; no public SPI in v1.

---

### D15 — Trigger point and connection lifecycle hook?

**Question:** Should initiation start on the first request, or should the runtime notify the filter when a connection is established?

**Options:**

* A. First-request trigger, as described in §6.2. No runtime API change.
* B. Add a connection-established callback to the filter API so the filter can initiate immediately.
* C. Hybrid: first-request trigger now; pursue B upstream later.

**Recommendation:** A/C. The current API has no connection lifecycle callback. First-request trigger is sufficient and avoids an API change. It does mean the filter must be interested in every request type until authenticated, which has a performance cost; the upstream issue comment already flags this. After authentication, restrict `shouldHandleRequest` as much as the reauthentication/subject-change policy allows.

**Decision (2026-11-24):** Trigger on the first request that is not `ApiVersions`; do not require a runtime connection-lifecycle hook.

**Impact:** runtime API scope, performance, latency, design-proposal requirement.

---

### D16 — API_VERSIONS handling and broker version negotiation?

**Question:** How does the filter learn the broker's SASL API versions?

**Options:**

* A. Use the client's `ApiVersions` response (cache it). Saves a round trip, but depends on the request being forwarded to the same broker connection and not being modified.
* B. Send the filter's own `ApiVersions` after the trigger. Deterministic, one extra round trip, works with routing/target selection.
* C. Use fixed SASL versions (handshake v1, authenticate v2) without negotiation; fail if unsupported.

**Recommendation:** B. It is simpler to reason about and avoids coupling to the client's request routing. Use a version supported by the target broker; derive the `SaslHandshake`/`SaslAuthenticate` max versions from the response. Require handshake v1 (encapsulated SASL; the runtime already rejects v0). Define the minimum broker version in the plan.

**Decision (2026-11-24):** The filter sends its own `ApiVersions` request at trigger time. Use API_VERSIONS v0 for this internal SASL bootstrap, matching Kafka 4.3.2's `SaslClientAuthenticator` ("Always use version 0 request since brokers treat requests with schema exceptions as GSSAPI tokens"). Derive the `SaslHandshake`/`SaslAuthenticate` versions from the response. Minimum supported broker is Kafka 4.0.

**Impact:** compatibility, latency, routing behaviour, tests.

---

### D17 — Client-originated SASL frames and chain order?

**Question:** What happens if the filter sees a downstream `SaslHandshake` or `SaslAuthenticate`?

**Options:**

* A. Reject and close the connection. The initiator owns broker SASL; clients must be terminated earlier.
* B. Forward them to the broker (passthrough) until/unless initiation has started.
* C. Configuration option to allow passthrough.

**Recommendation:** A. This is an explicit requirement from [issue 5050][issue-5050]. Document that `SaslTermination` (or another client-facing auth mechanism) must precede `SaslInitiation`, and that `SaslInspection` passthrough is incompatible. Because the client is demonstrably SASL-aware in this case, a SASL-specific error is appropriate: `UNSUPPORTED_SASL_MECHANISM` for a handshake, `SASL_AUTHENTICATION_FAILED` or `ILLEGAL_SASL_STATE` for an authenticate. This is distinct from an *upstream broker* failure, which must use a generic error (D19).

**Decision (2026-11-24):** Reject client-originated SASL frames and close the connection. Use a SASL-specific error only because the client is already speaking SASL; never use one for upstream broker failures.

**Impact:** composition, error codes, docs, tests.

---

### D18 — Buffering/backpressure and pipelining?

**Question:** Does the filter buffer requests while authenticating, or rely on the runtime's read-pause/backpressure?

**Options:**

* A. Return an incomplete `CompletionStage` for the triggering request; the runtime pauses reads and queues later requests. No explicit buffer.
* B. Manually buffer requests and complete their futures after authentication (as the test filter does).

**Recommendation:** A. It uses the documented filter contract, preserves ordering, and avoids duplicating runtime logic. The filter must still be defensive about unexpected requests during authentication (e.g. if the runtime delivers a queued request before the stage completes).

**Decision (2026-11-24):** Rely on runtime backpressure via an incomplete `CompletionStage`; no hand-written request buffer.

**Impact:** implementation complexity, ordering, error handling, tests.

---

### D19 — Failure semantics and retries?

**Question:** What does the client see when broker authentication fails?

**Options:**

* A. Return a generic error response for the triggering request (`UNKNOWN_SERVER_ERROR`), then close.
* B. Close immediately without a response.
* C. Return `SASL_AUTHENTICATION_FAILED` and close.
* D. Retry transient failures (e.g. reconnect) before failing.

**Recommendation:** A (or B if we want to avoid fabricating an error for non-SASL clients), with no retry on authentication failure. Log the broker error code/message at WARN/DEBUG in a sanitized form; do not forward it. On network/timeout, close and let the client reconnect. If `sendRequest` times out, fail the connection.

**Decision (2026-11-24):** Return a generic `UNKNOWN_SERVER_ERROR` for the triggering request, log sanitized details, and close; no retry. Do not return `UNSUPPORTED_SASL_MECHANISM` or `SASL_AUTHENTICATION_FAILED` for an upstream broker failure, because the downstream client may not be using SASL. See §6.7 for the termination/initiation coupling trade-off.

**Impact:** client UX, security (information leakage), metrics.

---

### D20 — KIP-368 reauthentication and subject change?

**Question:** Does v1 implement broker reauthentication, and what happens to the identity?

**Options:**

* A. No reauthentication in v1; document that sessions are closed/reconnected when the broker's session lifetime expires.
* B. Lazy reauthentication: on a request after the refresh deadline, reauthenticate before forwarding. Simpler; idle connections may be closed by the broker.
* C. Proactive scheduled reauthentication: schedule before expiry, pause requests while it runs. More robust, more complex.
* D. Reauthenticate with the original credential/identity; close if the downstream subject changed.
* E. Reauthenticate as the new subject (if downstream reauthenticated as a different identity).

**Recommendation:** C+D if "production-ready" includes KIP-368; B+D if a simpler first release is acceptable. Never do E implicitly. The broker's `sessionLifetimeMs` drives the refresh deadline; for OAUTHBEARER also consider token expiry. If the downstream subject changes, fail closed (close) unless a future explicit policy allows reauthentication as the new identity. Reusing the same `SaslClient` for reauth is not correct for SCRAM; create a fresh one.

**Decision (2026-11-24):** Implement proactive, scheduled KIP-368 reauthentication in the first release. Reauthenticate at 80% of the effective lifetime (the earlier of the broker-reported session lifetime and the token expiry), with a configurable factor. Add randomized jitter to avoid a reauthentication storm across many connections; Kafka's own client uses a random 85-95% window, so the configured 80% is a conservative base. If the downstream subject changes after upstream authentication, close the connection. Reauthenticate with the same identity only.

**Impact:** state machine complexity, request handling/performance, tests, security.

---

### D21 — Post-authentication request handling and performance?

**Question:** After authentication, which requests does the filter intercept?

**Options:**

* A. Intercept all requests. Simple, allows subject-change detection and lazy reauth; costs deserialization for every request.
* B. Intercept only `ApiVersions`, `SaslHandshake`, `SaslAuthenticate` after auth. Cheap, but cannot detect subject changes or lazy reauth; relies on proactive scheduling.
* C. Mode-dependent: fixed mode uses B (plus proactive reauth); subject mode uses A (to detect subject changes).
* D. Add a runtime API for subject-change notifications, enabling B in all modes.

**Recommendation:** A for simplicity and security, accepting the deserialization cost. The performance-optimised alternatives can be revisited after measuring real workloads. If subject-change detection is later moved to a runtime notification, B becomes viable.

**Decision (2026-11-24):** Intercept all requests, including after authentication. This makes subject-change detection and reauthentication pausing straightforward; the performance cost is accepted for v1.

**Impact:** performance, security, reauth design, runtime API scope.

---

### D22 — Multiple server connections, routing, and multiple target clusters?

**Question:** Does the filter support a client connection that fans out to multiple broker connections/target clusters?

**Options:**

* A. v1 supports the standard one-target-cluster, one-server-connection-per-client-connection model. Routing/multi-target is out of scope or best-effort.
* B. Support per-route/per-target authentication, requiring target-cluster information in the filter context/routing API.
* C. Support only direct routing for v1.

**Recommendation:** A/C. The current `FilterContext` exposes the virtual cluster but not a target-cluster identity, and the routing API is still evolving. Document the limitation and test the non-routing path. If routing is required, define how `sendRequest` selects the target and how per-target state is keyed before committing.

**Decision (2026-11-24):** Support one target cluster per client connection in v1; routing/multi-target is future work.

**Impact:** routing support, config, API dependencies, tests.

---

### D23 — Token/credential caching and concurrency?

**Question:** Do we cache OAuth tokens or credentials across connections, and how do we avoid blocking the event loop?

**Options:**

* A. No cross-connection cache; each connection authenticates independently. Simple, but can load the IdP/broker.
* B. Per-filter-factory token cache keyed by subject/client identity, with expiry and bounded size.
* C. Per-connection cache only.

**Recommendation:** A for password mechanisms (in-memory store lookup is cheap) and B for OAuth client-credentials/token retrieval if the IdP load is a concern. Never block the filter dispatch thread on HTTP; use a worker executor and `completeOnFilterDispatchThread`. Bound caches and respect token expiry. Clear on close.

**Decision (2026-11-24):** Password lookups are in-memory. OAuth tokens use a shared, bounded, expiring cache keyed by identity, scoped to the filter factory.

**Impact:** performance, IdP load, memory, security, metrics.

---

### D24 — Configuration schema shape and secret handling?

**Question:** What exactly does the YAML look like, and how are secret fields typed?

**Recommendation:** Use a record-based config with Jackson, `@JsonProperty(required = true)` for mandatory fields, and `PasswordProvider` for all secrets that appear in config (store password, OAuth client secret if configured there). Do not put broker passwords in YAML. Provide a stable, documented schema; validate unknown/incompatible combinations at initialization. See §6.5 for a sketch.

**Decision (2026-11-24):** Use nested groups (`identity`, `keyStore`, `oauthBearer`, `reauth`) with the field names and validation rules in §6.5. No broker password or OAuth client secret is accepted in YAML.

**Impact:** user experience, documentation, compatibility, plugin machinery.

---

### D25 — Secret handling, zeroization, and logging?

**Question:** How aggressively do we protect secrets in memory and logs?

**Recommendation:**

* Never include passwords/tokens in `toString()`, config dumps, or logs.
* Prefer `char[]`/`byte[]` for passwords and zeroize after use where feasible. Accept/document the JVM heap risk for KeyStore JSON and Kafka token objects.
* Use `PasswordProvider` for config secrets; use the KeyStore for broker passwords.
* Log mechanism, outcome, broker error code, session id, virtual cluster, and subject/broker username at an appropriate level; never log SASL payloads.
* Redact broker error messages before forwarding; log sanitized details.
* Add tests that assert secrets do not appear in logs/`toString()`.

**Decision (2026-11-24):** Pragmatic zeroization. Implement a local destroyable secret/password wrapper inspired by Kroxylicious's `DestroyableRawSecretKey` (`io.kroxylicious.kms.service.DestroyableRawSecretKey`), but do not depend on the KMS module. The wrapper owns `byte[]`/`char[]` material, zeroes it on destroy, and is idempotent. Use it for decoded KeyStore passwords and other avoidable copies; document the remaining JVM heap risk.

**Impact:** security review, implementation complexity, test design.

---

### D26 — Observability?

**Question:** Which metrics/logs are required?

**Recommendation:**

* Metrics: authentication attempts/success/failure by mechanism and virtual cluster; authentication duration; reauthentication attempts/failures; token retrieval duration/outcome; maybe connection-close reason. Avoid subject/principal labels.
* Logs: structured, key-value; INFO on successful auth (subject/broker username, mechanism), WARN on failure/reauth, DEBUG for protocol details; no payloads/secrets.
* Consider Micrometer conventions used by `SaslTermination`.

**Decision (2026-11-24):** Metrics + structured logs as described, with no identity labels on metrics.

**Impact:** operations, cardinality, security.

---

### D27 — Testing and compatibility matrix?

**Question:** What is the minimum test coverage for "production-ready"?

**Recommendation:**

* Unit: config parsing/validation; KeyStore loading/alias hashing/permissions/malformed entries; identity selection (fixed/subject/absent/ambiguous/mapped); state machine; SASL client loops; error paths; secret redaction.
* Protocol-level: use Kafka's `SaslServer` or a mock broker to exercise PLAIN/SCRAM/OAUTHBEARER challenge loops, API version negotiation, pipelining, reauth.
* Integration: real Kafka for each mechanism; fixed identity with anonymous/TCP clients; subject identity via `SaslTermination` (client PLAIN/SCRAM/OAUTH) and mTLS; mechanism translation; failure cases; reauth with short session lifetime; client SASL passthrough rejection; chain ordering.
* Tooling: CLI integration tests, file permissions, PKCS12.
* Compatibility: defined broker version range; PKCS12 store type.
* Performance: assert post-auth filters avoid unnecessary deserialization; measure auth latency.

**Decision (2026-11-24):** Unit + protocol-level + real-Kafka integration coverage as described.

**Impact:** project schedule, CI, test infrastructure.

---

### D28 — Documentation and operational model?

**Question:** What must be documented before release?

**Recommendation:**

* Concept page: what initiation is, when to use it, how it differs from termination/inspection.
* Configuration reference for every field and mechanism.
* KeyStore creation/rotation and CLI usage, including Kubernetes Secret examples.
* Filter-chain ordering and composition with `SaslTermination`, mTLS, and anonymous clients.
* Mechanism/identity support matrix and limitations.
* Security warnings (PLAIN over plaintext, KeyStore custody, memory, subject trust).
* Failure behaviour and observability.
* Migration from the test `SaslPlainInitiation` filter.

**Decision (2026-11-24):** Full concept/config/security/ops documentation as described.

**Impact:** adoption, support burden, upstream review.

## 8. Cross-cutting risks

1. **Filter chain misuse.** Placing `SaslInitiation` before `SaslTermination` or before another SASL-aware filter will break authentication. The filter can reject client SASL frames but cannot validate the whole chain. Documentation and integration tests are essential; a future runtime validation API would help.
2. **Post-authentication interception cost.** The chosen design intercepts all requests, including after authentication, to detect subject changes and to pause for reauthentication. This costs deserialization on every business request. The trade-off is deliberate and should be measured; a future subject-change notification or connection-lifecycle hook could restore the optimisation.
3. **Identity-change security.** If a downstream client reauthenticates as a different user on an existing connection, the subject-mode initiator detects the changed subject on the next request and closes. This is a security-critical behaviour and must be tested, including during an in-flight proactive reauthentication.
4. **OAUTHBEARER identity semantics.** A client-credentials token identifies the OAuth client, not necessarily the downstream user. True per-user impersonation requires token exchange, which is a materially larger feature. The v1 design verifies the token subject against the KeyStore's expected subject, but the mapping remains deployment-defined.
5. **KeyStore plaintext risk.** The KeyStore protects passwords at rest, but the proxy must hold them in plaintext in memory to perform SASL. The threat model must state this explicitly. The local destroyable-secret wrapper reduces avoidable copies but cannot eliminate JVM/Kafka-internal copies.
6. **Routing/multi-target ambiguity.** If a client connection can reach multiple target clusters, per-target credentials and per-target SASL state are not addressed by the current API. Do not claim support without testing.
7. **Kafka API version compatibility.** SASL handshake v0/raw SASL is rejected by Kroxylicious; the filter requires handshake v1 and derives the handshake/authenticate versions from the broker's `ApiVersions` response. The internal bootstrap uses API_VERSIONS v0, matching Kafka's own client.
8. **Secret leakage via errors.** Kafka broker error messages can contain details. Forward only generic errors; log sanitized details.
9. **Client-visible error semantics.** When the downstream client used `SaslTermination`, it may have already seen a successful SASL exchange before an upstream initiation failure is discovered. The client then receives a generic error/disconnect on a later request. Coupling the termination and initiation state machines would improve this, but would harm mTLS/anonymous support and composability; see §6.7.

## 9. Next steps

All the key decisions in this document are now recorded as decided, with the rationale preserved in the decision record below. The remaining work is to turn this into the final high-level plan and then the implementation plan:

1. Condense the requirements, use cases, goals, non-goals, and chosen design into the final `plan` document.
2. Produce a module/deliverable breakdown (filter, KeyStore/credential handling, CLI, tests, docs).
3. Produce an implementation and test plan.
4. Validate the locked configuration schema in §6.5 against the actual plugin configuration machinery during implementation.
5. Confirm the exact released Kroxylicious/Kafka versions to pin when the project build is created.

## 10. Rejected alternatives

* **Coupling the `SaslTermination` and `SaslInitiation` state machines.** Rejected for v1 because it only improves errors for SASL-terminated clients, cannot help mTLS/anonymous clients, and drastically strengthens filter-ordering/composition assumptions. See §6.7; a combined filter or shared authentication-outcome API is future work.
* **Multiple mechanisms with fallback/negotiation.** Rejected because the initiator chooses a broker mechanism rather than negotiating with the client. Kafka's own client also treats a rejected handshake as terminal. Multiple mechanisms can be expressed as separate filter definitions.
* **Public `SaslInitiationCredentialStore` SPI.** Deferred. The first release is KeyStore-only behind an internal abstraction; a public SPI would add API, lifecycle, and security review surface.
* **JKS KeyStore format.** Rejected because JKS cannot store `SecretKeyEntry` objects (`KeyStoreException: Cannot store non-PrivateKeys`); the versioned JSON-in-a-secret-key design requires PKCS12.
* **Per-subject static OAuth tokens in the KeyStore.** Deferred. Per-subject OAuth uses client credentials and Kafka's `ClientCredentialsJwtRetriever`; token exchange/impersonation is future work.
* **Reusing the downstream client's OAUTHBEARER token.** Rejected because `ClientSaslContext` does not expose the token and it would couple initiation to a specific client mechanism.
* **Using the client's `ApiVersions` response to learn SASL versions.** Rejected in favour of the filter sending its own v0 `ApiVersions` request, which is deterministic and matches Kafka's `SaslClientAuthenticator`.
* **Lazy or absent reauthentication.** Rejected in favour of proactive, jittered KIP-368 reauthentication for production readiness.
* **Hot reloading KeyStore contents.** Deferred; credentials are loaded once at initialization.
* **Per-target-cluster credentials under routing.** Deferred; v1 supports one target per client connection.

## 11. References

* [Proposal 004 — Terminology for Authentication][proposal-004]
* [Proposal 006 — Filter API to expose client SASL information][proposal-006]
* [Proposal 124 — SASL Termination][proposal-124]
* [Kroxylicious issue 5050 — Production-ready Sasl Initiation Filter][issue-5050]
* [Kroxylicious issue 2166 — Authentication swapping support][issue-2166]
* [Test-only SaslPlainInitiation][sasl-plain-initiation]
* [Kroxylicious SASL termination implementation][sasl-termination]
* [Kafka SaslClientAuthenticator][kafka-sasl-client-authenticator]
* [Kroxylicious DestroyableRawSecretKey][destroyable-raw-secret-key]
* RFC 4616 (PLAIN), RFC 5802 (SCRAM), RFC 6750 (OAUTHBEARER), RFC 4422 (SASL)
* KIP-43, KIP-84, KIP-255, KIP-368

[proposal-004]: https://github.com/kroxylicious/design/blob/main/proposals/004-terminology-for-authentication.md
[proposal-006]: https://github.com/kroxylicious/design/blob/main/proposals/006-filter-api-to-expose-client-sasl-info.md
[proposal-124]: https://github.com/kroxylicious/design/blob/main/proposals/124-sasl-termination.md
[issue-5050]: https://github.com/kroxylicious/kroxylicious/issues/5050
[issue-2166]: https://github.com/kroxylicious/kroxylicious/issues/2166
[pr-4908]: https://github.com/kroxylicious/kroxylicious/pull/4908
[sasl-plain-initiation]: https://github.com/kroxylicious/kroxylicious/blob/main/kroxylicious-integration-tests/src/test/java/io/kroxylicious/it/testplugins/SaslPlainInitiationFilter.java
[sasl-termination]: https://github.com/kroxylicious/kroxylicious/tree/main/kroxylicious-filters/kroxylicious-sasl-termination
[kafka-sasl-client-authenticator]: https://github.com/apache/kafka/blob/4.3.2/clients/src/main/java/org/apache/kafka/common/security/authenticator/SaslClientAuthenticator.java
[destroyable-raw-secret-key]: https://github.com/kroxylicious/kroxylicious/blob/main/kroxylicious-kms/src/main/java/io/kroxylicious/kms/service/DestroyableRawSecretKey.java
