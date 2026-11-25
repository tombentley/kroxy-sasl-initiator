# SASL Initiation — Implementation and Test Plan

**Status:** Proposed implementation plan.  
**Date:** 2026-11-24.  
**Requirements baseline:** [`plan/sasl-initiation.md`](./sasl-initiation.md), decisions locked 2026-11-24.  
**Target:** a standalone, production-ready `SaslInitiation` filter implementing the v1 design.

This document turns the design into a sequence of small, reviewable commits. Each commit is intended to be a self-contained PR
that leaves the build green, adds tests for the behaviour it introduces, and does not pull work forward from later commits.

---

## 1. How to use this plan

* **Commit 0 is this document.** The first implementation commit is Commit 1.
* Each numbered section in §6 describes exactly one commit/PR: its goal, what it adds, the files it touches, the tests it
  must contain, and a copy-paste prompt for the implementation agent.
* Implement commits in order. Each commit assumes the previous commits are merged.
* Do not implement future commits "while you are there". If a change is needed in an earlier abstraction, make a small
  preparatory commit and update this plan.
* Every commit must be green with:

  ```shell
  mvn verify
  ```

  and, before merge, with the CI quality profile:

  ```shell
  mvn verify -Pci
  ```

  Static analysis is opt-in because it is slower. Before merge, also run:

  ```shell
  mvn verify -Pspotbugs
  ```

  The `spotbugs` profile runs SpotBugs at maximum effort with the low threshold and fails the build on any finding.
  CI enables it alongside `-Pci`.

  Integration tests that need Docker must be skipped cleanly when Docker is unavailable; CI runs them with Docker.
* The plan deliberately keeps runtime/API changes to Kroxylicious out of scope. If a commit discovers that a runtime
  change is unavoidable, stop and record it as a blocker in §8 rather than silently depending on a snapshot.

### 1.1 Non-negotiable constraints

These apply to every commit:

* Target the released Kroxylicious API baseline in §2.1. Do not use `0.27.0-SNAPSHOT` unless this plan is explicitly
  updated.
* The filter type is `SaslInitiation`. The Java package root is `com.github.tombentley.kroxylicious.filter.sasl.initiation`.
* Use the IANA SASL mechanism names exactly: `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `OAUTHBEARER`.
* Delegate mechanism work to Kafka/JDK SASL clients. Do not reimplement PLAIN, SCRAM or OAUTHBEARER framing.
* Never log or include in exceptions: passwords, OAuth client secrets, bearer tokens, SASL auth bytes, or raw broker
  error messages.
* Never call `FilterContext.clientSaslAuthenticationSuccess` or `clientSaslAuthenticationFailure` from this filter. It
  must not impersonate a client authentication outcome.
* Never accept a broker password or OAuth client secret directly in proxy YAML.
* Never add a public credential-store SPI. Keep the internal abstraction clean enough to promote later.
* Never add hot reload, multiple mechanisms per instance, identity fallback, or a retry/second handshake.
* Use `io.kroxylicious.kafka.common.message.*` / `io.kroxylicious.kafka.common.protocol.*` for Kafka protocol classes.
  Kroxylicious 0.26.0 shades these; do **not** import `org.apache.kafka.common.message.*` in filter code.
* Kafka's SASL client APIs remain in `org.apache.kafka.common.security.*`.
* Add the Apache-2.0 license header to every new source file. Follow the Kroxylicious formatter/import order.
* Document nullness with the SpotBugs annotations (see §2.4). Every package has a `package-info.java` that makes
  `@NonNull` the default, so code only adds `@Nullable` where a value may genuinely be null. Do not scatter redundant
  `@NonNull` annotations through the code.

---

## 2. Baseline, modules and API notes

### 2.1 Pinned baseline

| Component | Version | Notes |
|---|---|---|
| Java | 21 | Kroxylicious 0.26.0 baseline |
| Kroxylicious | **0.26.0** | Latest release at plan time (2026-11-19); latest released line per D2 |
| Kroxylicious JUnit 5 extension | **0.16.0** | `io.kroxylicious.testing:testing-junit5-extension` |
| Kafka clients | **4.3.2** | Client-side SASL implementations and test broker |
| Minimum Kafka broker | 4.0 | Kafka 4.3.2 used in tests |
| Maven | 3.9+ | Reproducible builds with pinned plugins |
| JUnit | 5.14.x | Use the JUnit BOM |
| AssertJ / Mockito / Log4j2 | 3.27.x / 5.24.x / 2.26.x | Match Kroxylicious 0.26.0 where practical |

If Kroxylicious 0.27.0 is released before implementation starts, update the baseline in a dedicated commit and re-run the
full matrix. Do not mix 0.26.0 and 0.27.0 APIs.

### 2.2 Artifacts and module layout

Use a Maven multi-module project. Proposed coordinates are intentionally under a distinct group ID so the prototype
cannot be confused with upstream artifacts; if the filter is later donated upstream, only coordinates and parent POM change.

```text
kroxylicious-sasl-initiation-parent
├── kroxylicious-sasl-initiation-credentials   # KeyStore model/store, secret wrapper, permissions
├── kroxylicious-sasl-initiation               # Filter plugin
├── kroxylicious-sasl-initiation-credential-tool  # CLI (picocli, shaded executable)
├── kroxylicious-sasl-initiation-integration-tests # Real-Kafka ITs
└── kroxylicious-sasl-initiation-system-tests  # Black-box system tests (later)
```

Suggested group ID: `com.github.tombentley.kroxylicious.sasl`; version `0.1.0-SNAPSHOT` during development. The filter jar is
`kroxylicious-sasl-initiation-0.1.0.jar`. The CLI is `sasl-initiation-credential-tool`.

Java packages:

```text
com.github.tombentley.kroxylicious.filter.sasl.initiation               # SaslInitiation factory, filter, state machine
com.github.tombentley.kroxylicious.filter.sasl.initiation.config        # config records, mechanism/identity enums
com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials   # KeyStore store, entries, secrets, permissions
com.github.tombentley.kroxylicious.filter.sasl.initiation.identity      # fixed/subject selectors, snapshot adapter
com.github.tombentley.kroxylicious.filter.sasl.initiation.mechanism     # SASL client drivers and callback handlers
com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth         # token service, cache, retrievers/validators
com.github.tombentley.kroxylicious.filter.sasl.initiation.metrics       # Micrometer metrics and log keys
com.github.tombentley.kroxylicious.filter.sasl.initiation.cli           # CLI (in the tool module)
```

### 2.3 API facts the implementation must account for

1. **Shaded protocol classes.** In 0.26.0, `FilterContext`, `RequestFilter` and `ApiVersionsResponseFilter` use
   `io.kroxylicious.kafka.common.message.*`, `io.kroxylicious.kafka.common.protocol.ApiKeys` and
   `io.kroxylicious.kafka.common.protocol.Errors`. The filter's internal SASL work still uses
   `org.apache.kafka.common.security.*` and `javax.security.sasl.*`.
2. **Factory lifecycle.** `FilterFactory.initialize` is called once per virtual cluster; `createFilter` is called once
   per connection. Load the KeyStore and build immutable credential maps in `initialize`. `close(initData)` releases
   shared resources. `FilterFactoryContext.filterDispatchExecutor()` is available during `createFilter` and is the
   connection's filter-dispatch thread. Do not call it during `initialize`.
3. **No per-filter close callback.** `Filter` is a marker interface. Do not hold a per-frame `FilterContext` after the
   callback that supplied it. A one-shot scheduled task per authenticated connection is acceptable, but it must only set a
   flag; it must not perform I/O using a stale context.
4. **`sendRequest` semantics.** `FilterContext.sendRequest` sends towards the broker through filters upstream of this
   filter and returns the broker response only to this filter. The response does not pass through this filter's own
   `ApiVersionsResponseFilter`. Therefore the filter's own `ApiVersions` response must be handled inline, not via
   `onApiVersionsResponse`.
5. **Backpressure.** Returning an incomplete `CompletionStage` causes the runtime to pause downstream reads and queue
   already-decoded frames. The filter must not maintain a request queue. Per D18/D33, rely on this behaviour.
6. **Identity API transition.** `FilterContext.authenticatedSubject()` currently returns the deprecated
   `io.kroxylicious.proxy.authentication.Subject`; `User` is in the same package. Isolate all use of these types in one
   `IdentityAdapter` class, and use `io.kroxylicious.identity.Principal` where possible, so the 1.0 migration is local.
7. **Client authentication composition.** In 0.26.0, `SaslTermination` supports SCRAM and OAUTHBEARER, not PLAIN. The
   design's "SaslTermination with PLAIN" example is not directly testable with released code; composition tests use SCRAM
   termination. This commit does not add a test-only PLAIN terminator, so no PLAIN-termination result is claimed.
8. **Test support.** Use the published test-support jars rather than reinventing:

   | Artifact | Use |
   |---|---|
   | `io.kroxylicious:kroxylicious-filter-test-support` | `MockFilterContext`, `MockFilterContextAssert`, message/record test utilities |
   | `io.kroxylicious:kroxylicious-integration-test-support` | `KroxyliciousTesters`, `KroxyliciousConfigUtils`, `NamedFilterDefinitionBuilder`, `MockServer`, raw `KafkaClient` |
   | `io.kroxylicious:kroxylicious-certificate-test-support` / extension `KeytoolCertificateGenerator` | mTLS certificates |
   | `io.kroxylicious.testing:testing-junit5-extension` + `testing-impl` | Real Kafka broker provisioning, `@SaslMechanism`, `@BrokerConfig`, `@Tls` |
   | `io.kroxylicious:kroxylicious-kafka-message-json` | Protocol message assertions/JSON fixtures where useful |

### 2.4 Nullness annotations

Nullness is documented with the SpotBugs annotations (`com.github.spotbugs:spotbugs-annotations`, `provided` scope,
version managed by the parent POM). Every Java package, including test-only packages, must have a `package-info.java`
with the package-level defaults:

```java
@ReturnValuesAreNonnullByDefault
@DefaultAnnotationForParameters(NonNull.class)
@DefaultAnnotation(NonNull.class)
package com.github.tombentley.kroxylicious.filter.sasl.initiation.example;

import edu.umd.cs.findbugs.annotations.DefaultAnnotation;
import edu.umd.cs.findbugs.annotations.DefaultAnnotationForParameters;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.ReturnValuesAreNonnullByDefault;
```

Rules:

* Fields, method return values and parameters are non-null by default. Do not add `@NonNull` to them.
* Add `@edu.umd.cs.findbugs.annotations.Nullable` only where null is genuinely accepted or returned. Examples are
  optional inputs that may be absent, record components that model an optional JSON field, and internal buffers that
  are cleared after destruction.
* Treat framework-injected fields (for example picocli `@Spec` and `@Option` fields) as non-null once the framework has
  initialized them; do not annotate them merely because they are null before injection.
* SpotBugs cannot see framework injection. Where it reports `NP_NONNULL_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR` for such a
  field, add a narrow, justified `@SuppressFBWarnings` rather than weakening the package defaults. The CLI package uses
  one package-level suppression because every affected field is populated by picocli before the command runs.
* Once a value has been validated or defaulted (for example in a record compact constructor), the stored value and its
  accessor should be non-null. Do not publish `@Nullable` accessors for values the constructor guarantees.
* Annotate the narrowest element that is nullable. For a record component, put `@Nullable` on the component so the
  accessor, field and canonical-constructor parameter all carry it.
* Tests follow the same convention. Test classes that live in a production package inherit that package's
  `package-info.java`; do not add a second `package-info.java` for the same package under `src/test/java`. Test-only
  packages (for example the integration-test package) still get their own file, and nullable test inputs still use
  `@Nullable`.

---

## 3. Architecture for the implementation

### 3.1 Runtime object graph

```text
SaslInitiation (FilterFactory)
  initialize(config)
    ├── KeyStoreCredentialStore.load(...)  -> immutable Map<subject, Credential>
    ├── IdentitySelector (fixed | subject)
    ├── OAuthTokenService (only for OAUTHBEARER)
    ├── SaslInitiationMetrics
    └── InitData (immutable, shared per virtual cluster)

  createFilter(context, initData)
    └── SaslInitiationFilter
          ├── SaslExchange (Kafka protocol state machine)
          ├── MechanismDriver (PLAIN/SCRAM | OAUTHBEARER)
          ├── IdentityGuard (subject change detection)
          └── ReauthScheduler (per connection, one-shot)
```

The credential store, identity selector and token service are shared per virtual cluster. The filter instance, exchange
state and reauth deadline are per connection. No mutable state is shared between connections.

### 3.2 Protocol state machine

```text
AWAITING_TRIGGER
  ApiVersions request        -> forward, cache versions, stay
  client SASL frame          -> reject with SASL-specific error, close
  first other request        -> resolve identity, start auth
AUTHENTICATING
  any request                -> authStage.thenCompose(forward)   (no filter queue)
  auth success               -> AUTHENTICATED, forward trigger, arm reauth
  auth failure               -> generic error for trigger, close
AUTHENTICATED
  client SASL frame          -> reject, close
  reauth deadline reached    -> start reauth on this request, then forward
  subject changed            -> generic error, close
  otherwise                  -> forward
REAUTHENTICATING
  any request                -> reauthStage.thenCompose(forward)
  success                    -> AUTHENTICATED, update deadline
  failure / subject change   -> generic error, close
FAILED / CLOSED
  any request                -> generic error, close (or drop+close)
```

Initial authentication sequence:

1. Use the cached client `ApiVersions` response if it contains usable SASL versions; otherwise send the filter's own
   `ApiVersionsRequest` v0 with client ID `kroxylicious-sasl-initiation`.
2. Choose `SaslHandshake` and `SaslAuthenticate` versions. Require handshake v1+, authenticate v1+ (v1 carries
   `sessionLifetimeMs`). Cap at the client's latest supported version.
3. Send `SaslHandshake(mechanism)`.
4. Resolve the selected credential and create a fresh `SaslClient` via `Sasl.createSaslClient`, with a callback handler
   appropriate to the mechanism.
5. Send the initial `SaslAuthenticate` token. Loop over challenge/response until the `SaslClient` reports complete **and**
   the broker's final response reports success. Always consume the broker response to the last client token.
6. Record `sessionLifetimeMs` and arm reauthentication if positive.
7. Forward the triggering request and all later requests.

The exchange loop is mechanism-agnostic. Mechanism-specific code is confined to `MechanismDriver` plus its callback
handler.

### 3.3 Identity, credentials and mechanisms

```text
IdentitySelector  ->  lookup key  ->  CredentialStore  ->  Credential  ->  MechanismDriver  ->  SaslClient
```

* `FixedIdentitySelector` returns `identity.key`.
* `SubjectIdentitySelector` reads `FilterContext.authenticatedSubject()`, requires a non-anonymous subject, requires
  exactly one principal of the configured singular type, and returns its name.
* `CredentialStore` is an in-memory map built from the PKCS12 file at initialization. A missing entry is a fail-closed
  condition.
* `Credential` is either `PasswordCredential(username, secret)` or
  `OAuthClientCredential(clientId, secret, expectedSubject)`.
* `PasswordMechanismDriver` supports PLAIN, SCRAM-SHA-256 and SCRAM-SHA-512.
* `OAuthBearerMechanismDriver` obtains a validated token before creating the `SaslClient`, so no blocking token retrieval
  happens on the filter-dispatch thread.

### 3.4 Reauthentication timing

After successful authentication:

```text
brokerLifetime   = response.sessionLifetimeMs (0 means no broker-requested reauth)
tokenRemaining   = token.lifetimeMs - now        (OAUTHBEARER only)
effectiveLifetime = min(positive lifetimes)      (or the one that is present)
jitteredFactor   = clamp(windowFactor + uniform(-0.05, +0.05), 0.5, 0.95)
reauthDelay      = effectiveLifetime * jitteredFactor
hardDeadline     = effectiveLifetime             (fail closed after this)
```

A one-shot task arms `reauthDue` at `reauthDelay`. Reauthentication is performed at the next request boundary (before
forwarding that request), which avoids storing a per-frame `FilterContext` and avoids I/O from a stale connection
context. Active connections reauthenticate before the broker's session expires; idle connections may be closed by the
broker at expiry, which is acceptable and documented.

If the downstream subject changed before or during reauthentication, fail closed. Reuse the original lookup key and
credential; create a fresh `SaslClient`; do not send `ApiVersions` again. Update the deadline from the new
`sessionLifetimeMs` and token expiry.

### 3.5 Failure semantics

| Condition | Client sees | Connection |
|---|---|---|
| Client sends `SaslHandshake` | `UNSUPPORTED_SASL_MECHANISM` | Close |
| Client sends `SaslAuthenticate` | `ILLEGAL_SASL_STATE` | Close |
| Broker rejects handshake | `UNKNOWN_SERVER_ERROR` | Close |
| Broker rejects authenticate | `UNKNOWN_SERVER_ERROR` | Close |
| Missing/ambiguous subject | `UNKNOWN_SERVER_ERROR` | Close |
| Missing KeyStore entry | `UNKNOWN_SERVER_ERROR` | Close |
| Token retrieval/validation fails | `UNKNOWN_SERVER_ERROR` | Close |
| Upstream timeout/network failure | `UNKNOWN_SERVER_ERROR` | Close |

Broker errors are logged with the error code, mechanism and (for handshake rejection) the broker's enabled mechanisms.
Do not forward broker error messages or SASL payloads.

### 3.6 KeyStore and secret handling

* PKCS12 only. One `SecretKeyEntry` per identity, alias = lowercase hex SHA-256 of the UTF-8 lookup key.
* Entry payload is UTF-8 JSON with a required `version: 1`. Password and OAuth variants are defined in §6.2.
* The store is loaded once at initialization. Every entry is validated; every alias must equal `hash(entry.subject)`;
  duplicate subjects and wrong entry types fail startup.
* The store password is a `PasswordProvider`. `passwordFile` is recommended. Convert to `char[]`, destroy after load.
* Check owner-only permissions on the store and password file on POSIX. Provide a documented, explicit escape hatch for
  Kubernetes/OpenShift secret volumes.
* Use a local `DestroyableSecret` wrapper for avoidable copies. Do not claim complete zeroization: Jackson, Kafka and JVM
  internals make copies. Document the residual heap risk.

---

## 4. Test strategy

### 4.1 Test layers

| Layer | What it proves | Tools | Location |
|---|---|---|---|
| Unit | Pure config, JSON, KeyStore, identity, timing, cache, callbacks | JUnit, AssertJ, Mockito, `@TempDir` | `src/test/java`, `*Test` |
| Protocol/unit-filter | Kafka SASL framing, state machine, error paths, pipelining | `MockFilterContext` + Kafka `SaslServer`/`SaslClient`; `MockServer` where needed | `*Test` |
| Integration | Real Kafka broker, real proxy runtime, real client | `KafkaClusterExtension`, `KroxyliciousTesters`, `@SaslMechanism`, `@BrokerConfig`, `@Tls` | `*IT` in integration-tests module |
| System | Packaged proxy process, plugin discovery, config file, CLI, real network | Testcontainers Kafka + Kroxylicious distribution + subprocess | system-tests module, `*SystemIT` |

Unit and protocol tests must be fast and run on every build. Integration tests use in-VM Kafka by default and must not
need Docker unless the test is explicitly OAUTH/container-based. System tests are tagged and run in a separate CI job.

### 4.2 Real-Kafka integration harness

Every integration test class:

```java
@ExtendWith(KafkaClusterExtension.class)
@ExtendWith(NettyLeakDetectorExtension.class)
class SomethingIT {
    @Test
    void scenario(@SaslMechanism(value = "SCRAM-SHA-256",
                                 principals = { @SaslMechanism.Principal(user = "alice", password = "...") })
                  KafkaCluster cluster,
                  Topic topic) {
        var filter = new NamedFilterDefinitionBuilder("sasl-initiation", SaslInitiation.class.getName())
                .withConfig(...)
                .build();
        var config = proxy(cluster)
                .addToFilterDefinitions(filter)
                .addToDefaultFilters(filter.name());
        try (var tester = kroxyliciousTester(config);
             var producer = tester.producer(Map.of())) {
            // ...
        }
    }
}
```

Use `@BrokerConfig(name = "connections.max.reauth.ms", value = "5000")` for reauth tests. Use
`@SaslMechanism(value = "OAUTHBEARER")` plus the OAUTH broker config from §6.10 for OAUTH tests. Use
`KeytoolCertificateGenerator`/`@Tls` for mTLS tests.

### 4.3 Required coverage matrix

| Scenario | Identity | Downstream auth | Upstream mechanism | Layer |
|---|---|---|---|---|
| Shared service identity | fixed | anonymous | PLAIN / SCRAM-256 / SCRAM-512 / OAUTH | unit + IT |
| Shared service identity | fixed | mTLS | SCRAM | IT |
| Per-client identity | subject | `SaslTermination` SCRAM | PLAIN / SCRAM-512 | IT |
| Per-client identity | subject | `SaslTermination` OAUTH | SCRAM | IT |
| Per-client identity | subject | mTLS | SCRAM | IT |
| Mapped identity | subject | SCRAM | SCRAM | IT |
| No eligible subject | subject | anonymous | any | unit + IT |
| Client SASL passthrough | any | client SASL | any | IT |
| Misordered chain | any | client SASL | any | IT |
| Broker rejects mechanism | fixed | anonymous | any | unit + IT |
| Wrong/unknown broker credential | fixed | anonymous | PLAIN/SCRAM | unit + IT |
| Reauthentication | fixed/subject | any | SCRAM/OAUTH | unit + IT |
| Subject change after auth | subject | reauth as different user | SCRAM | unit + IT |
| Routing, two targets | fixed/subject | any | different creds per route | IT |
| Token cache/expiry | subject | OAUTH | OAUTH | unit + IT |
| Packaging/CLI/config | fixed/subject | any | PLAIN/SCRAM | system |

### 4.4 CI

* `build`: `mvn verify` on every push. Runs unit, protocol and in-VM integration tests.
* `integration-docker`: runs OAUTH/mTLS/container-backed ITs. Required before merge.
* `system-tests`: nightly/manual, `mvn verify -Psystem-tests`, requires Docker.
* `compatibility`: nightly, runs the PLAIN/SCRAM integration tests against Kafka 4.0.x and 4.3.x where the extension
  supports container provisioning. Do not block the main build on this until it is stable.

---

## 5. Commit sequence overview

| # | Commit | Theme | Main tests | Depends on |
|---|---|---|---|---|
| 0 | `docs: add SASL initiation implementation plan` | This document | — | — |
| 1 | `build: bootstrap SASL initiation plugin project` | Modules, pins, CI, no-op filter | Unit + smoke IT | 0 |
| 2 | `feat: add PKCS12 credential store for SASL initiation` | KeyStore model/store/secrets/permissions | Unit | 1 |
| 3 | `feat: add SASL initiation credential management CLI` | CLI create/add/update/remove/list | Unit + CLI IT | 2 |
| 4 | `feat: add SASL initiation configuration and identity selection` | Nested config, validation, selectors | Unit | 2 |
| 5 | `feat: implement PLAIN SASL initiation` | Filter state machine + PLAIN + fixed identity | Protocol + IT | 4 |
| 6 | `feat: support SCRAM-SHA-256 and SCRAM-SHA-512` | SCRAM driver + callbacks | Protocol + IT | 5 |
| 7 | `feat: support subject-derived broker identities` | Subject mode, fail closed, subject guard | Unit + protocol | 6 |
| 8 | `test: cover SASL initiation composition with client authentication` | `SaslTermination`, mTLS, chain order | IT | 7 |
| 9 | `feat: add OAUTHBEARER support to SASL initiation` | OAuth config/entry/token service/driver | Unit + protocol | 7 |
| 10 | `test: cover OAUTHBEARER against a real Kafka broker` | OAUTH ITs | IT (Docker) | 9 |
| 11 | `feat: implement KIP-368 reauthentication` | Deadline/jitter/fresh client/subject guard | Unit + protocol | 9 |
| 12 | `test: cover reauthentication and pipelining against real Kafka` | Reauth IT, subject change, backpressure | IT | 11 |
| 13 | `feat: support per-route SASL initiation` | Leaf route placement, per-target creds | IT | 8 |
| 14 | `feat: add SASL initiation metrics and structured logs` | Metrics/logs/redaction | Unit + IT | 11 |
| 15 | `docs: document SASL initiation` | Concept/config/security/ops/migration | Docs + example validation | 10, 13 |
| 16 | `test: add black-box system test harness` | Proxy process + Kafka container + CLI | System | 12 |
| 17 | `test: extend system test coverage` | Subject, mTLS, reauth, OAUTH | System | 16 |
| 18 | `build: package SASL initiation for release` | Distribution, examples, release checklist | System + packaging | 17 |

The commit boundary between 9/10 and 11/12 is deliberate: OAUTH is useful and testable before reauthentication, and
reauthentication is complex enough to deserve its own implementation and integration PRs.

---

## 6. Detailed commits

Each subsection is one PR. The prompt is written so it can be given to an implementation agent without additional
context, though the agent should still read `plan/sasl-initiation.md` and this section.

---

### Commit 1 — `build: bootstrap SASL initiation plugin project`

**Goal:** Create a compiling, testable multi-module project with the pinned baseline, plugin discovery, and a no-op
`SaslInitiation` filter proving the proxy/test harness works end to end.

**Adds**

* Maven parent and four modules: `credentials`, filter, CLI, integration-tests.
* Dependency management pinning Kroxylicious 0.26.0 BOM, Kafka clients 4.3.2, JUnit 5.14.x, AssertJ, Mockito, Log4j2,
  Micrometer, Jackson, picocli.
* Maven Enforcer (Java 21), Surefire, Failsafe, formatter/import-sort/checkstyle/license plugin configuration matching
  Kroxylicious conventions as closely as practical for a standalone project.
* A minimal `SaslInitiation` filter factory with `@Plugin(configType = SaslInitiationConfig.class)`, a placeholder
  `SaslInitiationConfig` containing only `mechanism`, and a filter that forwards every request/response unchanged.
* `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory`.
* `package-info.java` files for every package, carrying the nullness defaults from §2.4.
* A smoke integration test that configures the no-op filter on a plain Kafka cluster and produces/consumes a record.
* GitHub Actions workflow for `mvn verify`.
* README with build/run/test instructions.

**Tests**

* Unit: factory is discoverable via `ServiceLoader`; config record rejects null; filter forwards.
* Integration: `KafkaClusterExtension` real Kafka, plaintext client, no-op filter, produce/consume.
* Build: `mvn verify` green, formatter/license checks green.

**Not in this commit:** KeyStore, credentials, identity, SASL protocol, CLI behaviour.

**Prompt**

~~~text
Read plan/sasl-initiation.md, plan/sasl-initiation-implementation.md §2 and §6 Commit 1.

You are working in a repository whose only content is the plan directory. Create the initial Maven multi-module
project for a standalone Kroxylicious SASL initiation plugin.

Requirements:
- Java release 21, Maven 3.9+.
- Parent `kroxylicious-sasl-initiation-parent`, groupId `com.github.tombentley.kroxylicious.sasl`, version `0.1.0-SNAPSHOT`.
- Modules: `kroxylicious-sasl-initiation-credentials`, `kroxylicious-sasl-initiation`,
  `kroxylicious-sasl-initiation-credential-tool`, `kroxylicious-sasl-initiation-integration-tests`.
- Import `io.kroxylicious:kroxylicious-bom:0.26.0` in dependencyManagement. Pin `org.apache.kafka:kafka-clients:4.3.2`,
  `io.kroxylicious.testing:testing-junit5-extension:0.16.0`, `io.kroxylicious.testing:testing-impl:0.16.0`,
  JUnit 5.14.x, AssertJ 3.27.x, Mockito 5.24.x, Log4j2 2.26.x, Micrometer 1.17.x, Jackson 2.22.x, picocli 4.7.x.
- Use `kroxylicious-api` as `provided`, `kafka-clients` as `provided`, Jackson annotations/databind as `provided`,
  SLF4J as `provided`, Micrometer as `provided`.
- Add test dependencies on `kroxylicious-filter-test-support`, `kroxylicious-integration-test-support`,
  `kroxylicious-runtime`, `testing-junit5-extension`, `testing-impl`, `kafka_2.13:4.3.2` (or the version the extension
  requires), JUnit, AssertJ, Mockito, Log4j2 test binding.
- Configure Surefire for `*Test`, Failsafe for `*IT`, with JUnit 5. Configure the formatter/import-sort/license/checkstyle
  plugins following Kroxylicious conventions. Keep the configuration self-contained; do not depend on the Kroxylicious
  parent POM.
- Add a `SaslInitiation` class in `com.github.tombentley.kroxylicious.filter.sasl.initiation` annotated with
  `@Plugin(configType = SaslInitiationConfig.class)`. `SaslInitiationConfig` is a record with a required `mechanism`
  String for now; validate it is non-empty. `initialize` returns the config. `createFilter` returns a filter that
  forwards every request and every response unchanged.
- Register the factory in `src/main/resources/META-INF/services/io.kroxylicious.proxy.filter.FilterFactory` as
  `com.github.tombentley.kroxylicious.filter.sasl.initiation.SaslInitiation`.
- Add a unit test asserting ServiceLoader discovers the factory and `initialize`/`createFilter` work.
- Add an integration test class `SaslInitiationSmokeIT` using `@ExtendWith(KafkaClusterExtension.class)`,
  `@ExtendWith(NettyLeakDetectorExtension.class)`, a real `KafkaCluster`, `Topic`, `KroxyliciousTesters.kroxyliciousTester`,
  the no-op filter via `NamedFilterDefinitionBuilder`, and a plaintext producer/consumer round trip.
- Add a GitHub Actions workflow that runs `mvn verify`.
- Add a README describing the project, modules, and how to run unit/IT tests.
- Add Apache-2.0 license headers to all source files.
- Add `package-info.java` for every package, including test-only packages, with the nullness annotations from §2.4:
  `@DefaultAnnotation(NonNull.class)`, `@DefaultAnnotationForParameters(NonNull.class)` and
  `@ReturnValuesAreNonnullByDefault`. Add `com.github.spotbugs:spotbugs-annotations` as a `provided` dependency
  (managed in the parent POM).

Do not implement KeyStore, credentials, identity selection, SASL protocol, reauthentication, CLI commands or OAUTH in
this commit. Do not use `0.27.0-SNAPSHOT`. Do not import `org.apache.kafka.common.message.*` in filter code.

Acceptance: `mvn verify` passes, the smoke IT passes against a real Kafka cluster, and formatting/license checks pass.
~~~

---

### Commit 2 — `feat: add PKCS12 credential store for SASL initiation`

**Goal:** Implement the versioned PKCS12 credential store, alias hashing, strict entry validation, file-permission
checks, and a destroyable secret wrapper. This is the credential foundation used by both the filter and the CLI.

**Adds**

* `CredentialEntry` model for v1 JSON:
  * password: `{"version":1,"subject":"alice","username":"alice","password":"..."}`
  * OAuth: `{"version":1,"subject":"alice","oauthBearer":{"clientId":"...","clientSecret":"...","expectedSubject":"alice"}}`
* `CredentialEntryCodec` using Jackson with strict unknown-field handling and version validation.
* `KeyStoreCredentialStore` that loads a PKCS12 file once, validates every alias/entry, and builds an immutable
  `Map<String, Credential>` keyed by `subject`.
* `Credential` sealed interface and implementations `PasswordCredential`, `OAuthClientCredential`.
* `CredentialKind` enum (`PASSWORD`, `OAUTH`) so the store can validate entry types without depending on the filter's
  `Mechanism` enum (which arrives in Commit 4).
* `CredentialStoreException` with clear, non-secret-bearing messages.
* `KeyStorePermissions` (owner-only POSIX check, create-with-owner-only, documented escape hatch).
* `DestroyableSecret` (owns `char[]`/`byte[]`, idempotent destroy).
* Alias hashing utility (lowercase hex SHA-256 UTF-8).
* Unit tests for all of the above.

**Design constraints**

* PKCS12 only; load with `KeyStore.getInstance("PKCS12")`.
* Alias must equal `hex(sha256(entry.subject))`; otherwise fail.
* Reject duplicate subjects, unknown version, unknown fields, missing fields, empty fields, non-secret-key entries,
  wrong entry type for the expected credential kind, and empty stores.
* Fixed mode requires the configured key to exist; subject mode requires the store to contain at least one entry.
* The store password is supplied as `PasswordProvider`; convert to `char[]`, load, then destroy.
* Do not log entry contents. Log only file path, entry count and success/failure.
* Do not implement the CLI or filter integration in this commit.

**Tests**

* Alias hashing known vectors, case, Unicode.
* JSON round-trip, malformed JSON, wrong version, unknown field, missing field, both variants.
* Store load success with multiple entries; missing file; wrong password; corrupt file; non-PKCS12 file; non-secret entry;
  alias mismatch; duplicate subject; empty store; wrong type for the expected credential kind.
* Secret destroy zeroes material and is idempotent; `toString` redacts.
* POSIX permissions: world/group-readable file rejected; owner-only accepted; escape hatch exercised; non-POSIX skipped.
* Fixed-key lookup and subject lookup.

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.4-§6.6 and D9/D10/D12/D25, and plan/sasl-initiation-implementation.md §2, §3.6 and §6
Commit 2.

Implement the credential foundation in module `kroxylicious-sasl-initiation-credentials`.

Requirements:
- Package `com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials`.
- Define the v1 JSON schema exactly as specified in §6.2 of the implementation plan:
  * password entry: version, subject, username, password.
  * oauth entry: version, subject, oauthBearer {clientId, clientSecret, expectedSubject?}.
  Use Jackson with strict unknown-field handling. `version` must be exactly 1.
- Alias = lowercase hex SHA-256 of the UTF-8 `subject`. Provide a utility and known-vector tests.
- `KeyStoreCredentialStore.load(Path file, PasswordProvider filePassword, CredentialKind expectedKind)`:
  * PKCS12 only. Store the UTF-8 JSON bytes as a `SecretKeySpec(bytes, "AES")` in a `SecretKeyEntry`, protected with
    the store password (same password as the store), matching the existing Kroxylicious SCRAM credential-store pattern.
  * Load all entries, decrypt with the store password, decode JSON, validate alias == hash(entry.subject).
  * Build an immutable map keyed by subject. Reject duplicate subjects.
  * Reject non-SecretKeyEntry entries, unknown/malformed entries, empty stores, and entries whose type does not match the
    expected `CredentialKind`.
  * For fixed mode, also expose `require(String key)` that fails if absent.
  * Destroy the store-password char[] after load. Keep entry secrets in a local `DestroyableSecret` wrapper.
- `Credential` sealed interface: `PasswordCredential(String username, DestroyableSecret password)` and
  `OAuthClientCredential(String clientId, DestroyableSecret clientSecret, String expectedSubject)`.
  Implement `toString` redaction and `AutoCloseable`/destroy semantics.
- `DestroyableSecret`: owns char[] or byte[], zeroes on destroy, idempotent, never prints contents.
- `KeyStorePermissions`: POSIX owner-only check for the store and password file. Provide a documented escape hatch for
  Kubernetes/OpenShift (an environment variable with a clear name, e.g.
  `KROXYLICIOUS_SASL_INITIATION_ALLOW_INSECURE_PERMISSIONS=true`). Non-POSIX is a no-op.
- Add a `KeyStoreCredentialStoreException` with actionable but non-secret messages.

Tests:
- JSON/schema tests for both variants, malformed/unknown/missing fields, wrong version, null/empty values.
- KeyStore tests with `@TempDir`: create a PKCS12 store in the test, add entries, round-trip; wrong password; corrupt
  file; missing file; non-PKCS12 file; certificate entry; alias mismatch; duplicate subject; empty store; wrong
  mechanism type.
- `DestroyableSecret` zeroization and idempotence.
- Permission tests using `@EnabledOnOs` for POSIX; assert group/other-readable files are rejected and owner-only accepted;
  exercise the escape hatch.
- Assert that `toString()` of credentials/config-like objects never contains the secret.

Do not add the CLI, filter integration, identity selection or SASL protocol in this commit. Do not use the Kroxylicious
SCRAM credential-store classes as a runtime dependency; copy/adapt the relevant pattern with attribution if useful.

Acceptance: `mvn -pl kroxylicious-sasl-initiation-credentials verify` passes; no secret appears in logs or assertions.
~~~

---

### Commit 3 — `feat: add SASL initiation credential management CLI`

**Goal:** Provide a safe CLI to create and maintain the PKCS12 store, because the versioned JSON payload is not practical
with bare `keytool`.

**Adds**

* `sasl-initiation-credential-tool` module with picocli commands:
  * `create` — create a new store, fail if it exists.
  * `add-password` — add a password entry; fail if subject exists.
  * `add-oauth` — add an OAuth client-credential entry; fail if subject exists.
  * `update-password` / `update-oauth` — replace an existing entry.
  * `remove` — remove an entry.
  * `list` — list subjects and non-secret metadata only.
* Secret input options: interactive console, `--password-file`, `--password-stdin`; no inline password by default.
  Provide an explicitly insecure `--password` option gated behind `--insecure-allow-password-argument`.
* Store-password input: interactive or file; same gating.
* Owner-only file creation and permission checks.
* Exit codes and error messages suitable for scripts; never print secrets.
* Shaded executable jar configuration (picocli only; do not shade Kroxylicious/Kafka).
* Unit/CLI integration tests.

**Tests**

* `create` creates PKCS12 with `rw-------`; refuses existing file; wrong password fails.
* `add-password`/`add-oauth` round-trip through `KeyStoreCredentialStore`; alias hashed; subject/username/expected
  subject preserved.
* Duplicate add fails; update succeeds; remove succeeds; list output contains no secrets.
* Interactive and file-based password input; stdin input; insecure gate.
* Wrong store password, wrong file, malformed existing store.
* CLI stdout/stderr assertions for secret redaction.

**Prompt**

~~~text
Read plan/sasl-initiation.md D9-D12, O2-O3 and plan/sasl-initiation-implementation.md §2, §3.6 and §6 Commit 3.

Implement the CLI in module `kroxylicious-sasl-initiation-credential-tool`, package
`com.github.tombentley.kroxylicious.filter.sasl.initiation.cli`.

Use picocli 4.7.x and the credential store from the previous commit. Commands:
- `create --file <path>`: create a new PKCS12 store. Fail if the file exists. Create with POSIX `rw-------`; use the
  permission helper. Store password from interactive console or `--store-password-file`/`--store-password-stdin`.
- `add-password --file <path> --subject <s> --username <u>`: password from interactive console, `--password-file` or
  `--password-stdin`. Fail if subject already exists.
- `add-oauth --file <path> --subject <s> --client-id <id>`: client secret from interactive/file/stdin. Optional
  `--expected-subject`; default to the subject.
- `update-password` and `update-oauth`: same inputs, fail if subject does not exist.
- `remove --file <path> --subject <s>`.
- `list --file <path>`: print subject, type and username/expectedSubject. Never print password, client secret, aliases or
  entry bytes.

Secret handling:
- Do not accept inline passwords by default.
- Provide `--password <value>` only when `--insecure-allow-password-argument` is also supplied; document the risk in the
  help text.
- Interactive input must use `Console.readPassword` and not echo.
- File/stdin input reads the first line and trims the line ending only.
- Destroy password char[] copies after use; never include secrets in exceptions or help output.

Add tests:
- Use `CommandLine(new SaslInitiationCredentialTool()).execute(args)` with `@TempDir`.
- Round-trip every command through `KeyStoreCredentialStore`.
- Assert file permissions on POSIX.
- Assert duplicate/update/remove semantics and exit codes.
- Capture stdout/stderr and assert known secrets never appear.
- Test missing file, wrong store password, malformed store, missing subject, insecure flag gating.

Configure a shaded executable jar for the CLI; exclude Kroxylicious, Kafka, Jackson, SLF4J and Micrometer from shading.
Add a `bin/sasl-initiation-credential-tool` launcher later in the packaging commit; for now the shaded jar is enough.

Do not implement the filter or SASL protocol in this commit.

Acceptance: CLI tests pass, files are owner-only, and no test can find a secret in CLI output.
~~~

---

### Commit 4 — `feat: add SASL initiation configuration and identity selection`

**Goal:** Introduce the full nested configuration schema (minus OAUTHBEARER, which comes later) and the fixed/subject
identity selectors, with startup validation and fail-closed semantics.

**Adds**

* `SaslInitiationConfig` with nested `identity`, `keyStore`, `reauth` groups, using Jackson records and
  `PasswordProvider`:
  ```yaml
  mechanism: SCRAM-SHA-256
  identity:
    mode: fixed | subject
    key: proxy-service            # fixed only, required when KeyStore is used
    principalType: io.kroxylicious.proxy.authentication.User  # subject only, optional
  keyStore:
    file: /etc/kroxylicious/sasl-initiation.p12
    filePassword:
      passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
  reauth:
    windowFactor: 0.8
  ```
* `Mechanism` enum for `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` (OAUTH added in Commit 9).
* `IdentityMode` enum.
* `IdentitySelector` interface with `FixedIdentitySelector`, `SubjectIdentitySelector`.
* `IdentityAdapter` isolating the deprecated `Subject`/`User` API and returning an `IdentitySnapshot`.
* Config validation for:
  * mechanism required and known;
  * identity mode required;
  * fixed key required iff a KeyStore is configured, rejected in subject mode;
  * subject principal type must be a singular `Principal` type, default `User`;
  * KeyStore required for password mechanisms; file and filePassword required;
  * reauth window factor 0.5–0.95, default 0.8;
  * unknown/incompatible combinations rejected.
* Factory wiring: `initialize` validates config, loads the KeyStore and builds the selector. The filter remains a
  pass-through until Commit 5.
* Unit tests.

**Design constraints**

* Do not accept passwords in YAML; only `PasswordProvider` for the store password.
* `identity.key` is a lookup key, not necessarily the broker username.
* Subject selector must fail on anonymous, absent or ambiguous principal; never fall back to fixed.
* `principalType` is loaded via `Class.forName`, must implement `io.kroxylicious.identity.Principal` (or the deprecated
  bridge), and must be a singular principal type via `SingularPrincipals.isSingular`.
* Isolate all deprecated `Subject`/`User` usage in `IdentityAdapter`; suppress deprecation warnings narrowly.
* Startup validation must fail fast, before any client connection.

**Tests**

* Config parsing/validation for every valid and invalid combination.
* `PasswordProvider` file/inline behaviour; missing password file fails at initialization.
* Fixed selector returns the configured key.
* Subject selector: `User` default; custom singular principal; anonymous -> fail; absent -> fail; multiple -> fail.
* `IdentitySnapshot` equality/change detection.
* Factory `initialize` loads a real test store and fails on malformed entries.
* Filter still forwards a request/response unchanged (no regressions).

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.5, D6-D8, D24 and plan/sasl-initiation-implementation.md §2.3, §3.3 and §6 Commit 4.

Implement the configuration and identity layer.

Config:
- Create `SaslInitiationConfig` and nested records in `com.github.tombentley.kroxylicious.filter.sasl.initiation.config`.
- Use Jackson records with `@JsonProperty(required = true)` where appropriate and canonical-constructor validation.
- The YAML shape is exactly the one in §6.5 of the implementation plan, but `mechanism` is limited to PLAIN,
  SCRAM-SHA-256 and SCRAM-SHA-512 for this commit. OAUTHBEARER is added later.
- `identity.mode` is `fixed` or `subject`.
- In fixed mode, `identity.key` is required when `keyStore` is present and rejected in subject mode. For now a KeyStore
  is always required for password mechanisms.
- `identity.principalType` is optional in subject mode and defaults to `io.kroxylicious.proxy.authentication.User`.
  Load it with `Class.forName`, verify it implements `io.kroxylicious.identity.Principal` and is singular via
  `SingularPrincipals.isSingular`.
- `keyStore.file` and `keyStore.filePassword` are required when `keyStore` is present. `filePassword` is a
  `PasswordProvider`.
- `reauth.windowFactor` is optional, default 0.8, must be in [0.5, 0.95].
- Reject unknown/incompatible combinations with actionable `PluginConfigurationException`/`IllegalArgumentException`
  messages. Never include passwords.

Identity:
- Create `IdentitySelector` in `com.github.tombentley.kroxylicious.filter.sasl.initiation.identity`.
- `FixedIdentitySelector` returns the configured key.
- `SubjectIdentitySelector` reads `FilterContext.authenticatedSubject()` at request time. It must fail closed if the
  subject is anonymous, if no principal of the configured type is present, or if more than one is present.
- Create `IdentityAdapter` to isolate deprecated `io.kroxylicious.proxy.authentication.Subject`/`User` usage. Return an
  immutable `IdentitySnapshot` containing the lookup key and a stable set of principal type/name pairs.
- Do not cache a subject across requests.

Factory:
- Wire `SaslInitiation.initialize` to validate config, map `Mechanism` to `CredentialKind`, load the KeyStore via
  `KeyStoreCredentialStore`, and build the identity selector. The filter remains a pass-through in this commit.
- Fail initialization on missing/invalid store, missing fixed key, wrong entry type, insecure permissions (unless the
  documented escape hatch is set).

Tests:
- Config parsing and validation for all valid/invalid combinations, including missing fields, unknown mechanism, wrong
  identity mode, key in subject mode, missing key/idStore, invalid window factor, non-singular principal type.
- Fixed and subject selector tests with `MockFilterContext` and real `Subject` instances.
- `IdentitySnapshot` equality and change detection.
- Factory initialization with a real test PKCS12 store; malformed/missing entries fail.
- Regression: the pass-through filter still forwards.

Do not implement SASL protocol, PLAIN/SCRAM exchanges, reauthentication, OAUTH or the CLI in this commit. Do not call
`clientSaslAuthenticationSuccess`/`Failure`.

Acceptance: unit tests pass; a misconfigured filter fails at startup, not at first client connection.
~~~

---

### Commit 5 — `feat: implement PLAIN SASL initiation`

**Goal:** Implement the Kafka SASL initiation protocol and the PLAIN mechanism, with fixed identity, correct trigger
point, `ApiVersions` handling, challenge/response loop, generic failure semantics, and client-SASL rejection.

**Adds**

* `SaslInitiationFilter` implementing `RequestFilter` and `ApiVersionsResponseFilter`.
* `SaslExchange` state machine:
  * `AWAITING_TRIGGER`, `AUTHENTICATING`, `AUTHENTICATED`, `FAILED`.
  * `ApiVersions` forwarding and caching.
  * Own `ApiVersionsRequest` v0 fallback with client ID `kroxylicious-sasl-initiation`.
  * Version selection and validation.
  * `SaslHandshake` + `SaslAuthenticate` loop.
  * `sessionLifetimeMs` capture (no reauth yet).
  * Generic error + close on upstream failure.
  * Client `SaslHandshake`/`SaslAuthenticate` rejection with SASL-specific errors.
* `MechanismDriver` abstraction and `PasswordMechanismDriver` for PLAIN.
* `SaslClientCallbackHandler` for PLAIN (`NameCallback`, `PasswordCallback`).
* `RequestHeaderFactory` with the fixed client ID.
* Test fake broker using Kafka's `PlainSaslServer`, driven through `MockFilterContext.withSendRequestHandler`.
* Real-Kafka PLAIN integration test with fixed identity.

**Design constraints**

* Trigger on the first request that is not `ApiVersions` and not a client SASL frame.
* Forward the client `ApiVersions` response unchanged and cache it.
* Do not send `ApiVersions` if a usable cached response exists.
* Require handshake v1+ and authenticate v1+; cap at `ApiKeys.latestVersion()`.
* Use `FilterContext.sendRequest`; do not write raw frames.
* Do not call `clientSaslAuthenticationSuccess`/`Failure`.
* Do not add a buffer: return a stage chained on the auth stage. Do not store requests in a list.
* Do not implement SCRAM, OAUTH, subject mode integration, reauth, or metrics in this commit. Subject selector exists
  from Commit 4 but the test matrix here is fixed identity.
* Fail closed if the subject mode is configured but no subject is available (basic behaviour; full composition tests in
  Commit 8).

**Tests**

* Unit/protocol with fake broker:
  * Happy path: client `ApiVersions` -> business request triggers auth -> handshake -> auth -> request forwarded.
  * No client `ApiVersions`: filter sends its own v0 request.
  * Cached `ApiVersions` response used; no extra request.
  * `ApiVersions` response missing SASL keys -> fallback.
  * Broker handshake error -> generic `UNKNOWN_SERVER_ERROR`, close; log includes enabled mechanisms, not payload.
  * Broker auth error (wrong password) -> generic error, close.
  * `sendRequest` exceptional completion -> generic error, close.
  * Client `SaslHandshake` -> `UNSUPPORTED_SASL_MECHANISM`, close.
  * Client `SaslAuthenticate` -> `ILLEGAL_SASL_STATE`, close.
  * No `clientSaslAuthenticationSuccess`/`Failure` gestures recorded.
  * Pipelined second business request returns an incomplete stage while auth is in progress; after auth completes,
    re-dispatch forwards it; no filter-level buffer.
* Real Kafka:
  * `@SaslMechanism(value="PLAIN", principals=...)`; fixed identity; producer/consumer round trip through proxy.
  * Wrong password -> client fails within timeout; connection closes; broker error not exposed.
  * Unsupported mechanism -> generic failure.

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.2, §6.3, §6.7, D15-D19 and plan/sasl-initiation-implementation.md §2.3, §3.2, §3.5 and
§6 Commit 5.

Implement the SASL initiation protocol with PLAIN support.

Core:
- `SaslInitiation` factory creates `SaslInitiationFilter`.
- `SaslInitiationFilter` implements `io.kroxylicious.proxy.filter.RequestFilter` and
  `io.kroxylicious.proxy.filter.ApiVersionsResponseFilter`.
- `shouldHandleRequest` returns true for all request types, including after authentication (D21), so subject changes and
  reauthentication deadlines are observed on every request.
- State: AWAITING_TRIGGER, AUTHENTICATING, AUTHENTICATED, FAILED. Keep the state machine explicit and testable.
- On `ApiVersions` request before auth: forward unchanged. On `ApiVersions` response: cache max versions for
  SASL_HANDSHAKE and SASL_AUTHENTICATE, then forward unchanged.
- On first non-ApiVersions request: if no usable cached versions, send an `ApiVersionsRequestData` v0 (client ID
  `kroxylicious-sasl-initiation`) via `FilterContext.sendRequest`; validate its error code and SASL entries, then send
  `SaslHandshake`, then the PLAIN exchange. If the cached response or the filter's own response lacks usable SASL
  entries, fail closed.
- Choose handshake/authenticate versions as min(broker max, ApiKeys.latestVersion()). Require handshake >= 1 and
  authenticate >= 1; fail closed otherwise.
- PLAIN exchange: create `SaslClient` with `Sasl.createSaslClient(new String[]{"PLAIN"}, null, null, "localhost",
  configs, callbackHandler)`, where the callback handler supplies `NameCallback` and `PasswordCallback` from the
  resolved credential. Send the initial token (`evaluateChallenge(new byte[0])` when the client has an initial
  response, otherwise an empty token), then loop over `SaslAuthenticateRequestData`/`SaslAuthenticateResponseData`
  until the client is complete and the final broker response is success. Treat null auth bytes as empty; treat
  unexpected non-empty auth bytes after the client is complete as a protocol error.
- Record `sessionLifetimeMs` but do not schedule reauth in this commit.
- Dispose the `SaslClient` and destroy the credential material after the exchange (success or failure). Reauthentication
  will create a fresh one.
- On success, forward the triggering request and later requests with `FilterContext.forwardRequest`.
- On failure, return
  `context.requestFilterResultBuilder().errorResponse(header, request, Errors.UNKNOWN_SERVER_ERROR).withCloseConnection()`;
  never forward broker error text.
- Reject client-originated `SASL_HANDSHAKE` with `Errors.UNSUPPORTED_SASL_MECHANISM` and `SASL_AUTHENTICATE` with
  `Errors.ILLEGAL_SASL_STATE`; close the connection.
- Return an incomplete stage for requests arriving during authentication, chained on the auth stage. Do not maintain a
  request list.
- Never call `clientSaslAuthenticationSuccess`/`clientSaslAuthenticationFailure`.
- Use `io.kroxylicious.kafka.common.message.*`/`protocol.*` for protocol classes. Use `org.apache.kafka.common.security.*`
  and `javax.security.sasl.*` for SASL.

Testing:
- Add a fake broker test helper that implements `FilterContext.SendRequestHandler` and uses Kafka's `PlainSaslServer`
  (initialise `PlainSaslServerProvider`). It should respond to ApiVersions, SaslHandshake and SaslAuthenticate.
- Unit tests with `MockFilterContext` for the happy path, fallback ApiVersions, cached ApiVersions, handshake rejection,
  auth rejection, exceptional sendRequest, client SASL frame rejection, no client-auth gestures, and pipelining
  (second request's stage incomplete until auth completes).
- Integration test `SaslPlainInitiationIT` with a real Kafka cluster configured with `@SaslMechanism(value="PLAIN",
  principals={...})`, fixed identity, and a producer/consumer round trip. Add wrong-password and unsupported-mechanism
  cases.

Do not implement SCRAM, OAUTHBEARER, reauthentication, routing, metrics, or the CLI in this commit. Subject mode may use
the selector from Commit 4 but is not the focus of this commit's integration tests.

Acceptance: `mvn verify` passes; protocol tests exercise every state transition; the real-Kafka PLAIN IT passes.
~~~

---

### Commit 6 — `feat: support SCRAM-SHA-256 and SCRAM-SHA-512`

**Goal:** Add the two SCRAM mechanisms through the same generic exchange, demonstrating that the state machine is
mechanism-agnostic.

**Adds**

* SCRAM support in `PasswordMechanismDriver`:
  * initialise `ScramSaslClientProvider`;
  * callback handler for `NameCallback`, `PasswordCallback`, `ScramExtensionsCallback`;
  * mechanism selection from config.
* Config enum values `SCRAM-SHA-256`, `SCRAM-SHA-512`.
* Protocol tests with Kafka's `ScramSaslServer`.
* Real-Kafka SCRAM integration tests for both mechanisms.

**Tests**

* SCRAM challenge/response loop with server-first and server-final messages.
* Wrong password and unknown user -> generic error/close.
* Missing/empty SCRAM extensions handled.
* Both mechanisms select the correct `SaslClient`.
* Real Kafka: fixed identity SCRAM-SHA-256 and SCRAM-SHA-512 round trips; wrong password fails.
* Mechanism mismatch (config SCRAM, broker only PLAIN) -> generic error/close with enabled mechanisms logged.

**Prompt**

~~~text
Read plan/sasl-initiation.md R1-R3, D5, D12 and plan/sasl-initiation-implementation.md §3.2-§3.3 and §6 Commit 6.

Extend the SASL initiation implementation to SCRAM-SHA-256 and SCRAM-SHA-512.

Requirements:
- Extend `Mechanism` and config validation with SCRAM-SHA-256 and SCRAM-SHA-512.
- Extend `PasswordMechanismDriver` to create the appropriate Kafka/JDK SaslClient:
  * initialise `ScramSaslClientProvider`;
  * provide a callback handler that supports `NameCallback`, `PasswordCallback` and `ScramExtensionsCallback`;
  * use the configured broker username and password from the KeyStore entry.
- Keep the exchange loop generic. Do not special-case SCRAM server messages in the filter.
- Do not add OAUTHBEARER, reauthentication or subject-mode integration tests in this commit.

Tests:
- A fake SCRAM broker using Kafka's `ScramSaslServer` and `ScramFormatter`. Use a test callback handler that returns a
  `ScramCredential` for the expected user. Exercise both mechanisms.
- Unit/protocol tests: success, wrong password, unknown user, mechanism mismatch, missing/empty extensions, final server
  message handling, and no client-auth gestures.
- Integration tests `SaslScramInitiationIT` with real Kafka and `@SaslMechanism(value="SCRAM-SHA-256"/"SCRAM-SHA-512",
  principals=...)`; fixed identity; produce/consume; wrong password; unsupported mechanism.

Do not add reauthentication. Do not add a second handshake or fallback mechanism.

Acceptance: both SCRAM mechanisms pass against a real Kafka broker; the same filter code path is used for PLAIN and
SCRAM.
~~~

---

### Commit 7 — `feat: support subject-derived broker identities`

**Goal:** Make subject mode real: resolve the downstream subject at trigger time, select the KeyStore entry, map to the
stored broker username, fail closed when no eligible subject/entry exists, and detect subject changes after
authentication.

**Adds**

* Subject-mode wiring in the filter.
* `CredentialResolver` lookup by lookup key, with fail-closed behavior.
* `IdentityGuard` that snapshots the downstream identity and checks it on every subsequent request.
* Post-authentication re-check: if the subject changed between trigger and auth success, fail closed.
* Logging of broker username/subject outcome without secrets.
* Unit/protocol tests for subject mode and subject changes.

**Design constraints**

* Fixed mode is unchanged.
* Subject mode never falls back to fixed identity.
* The KeyStore is the allow-list: the subject is the lookup key; a client cannot choose an alias.
* The entry's `subject` must equal the lookup key; `username` may differ.
* If `authenticatedSubject()` changes after auth, close. Do not reauthenticate as the new subject.
* Do not call `clientSaslAuthenticationSuccess`/`Failure`.

**Tests**

* Subject mode with `MockFilterContext.withAuthenticatedSubject`:
  * `User("alice")` selects entry `alice`, authenticates as stored `username` (including mapped `svc-alice`).
  * anonymous -> generic error/close.
  * no `User` -> generic error/close.
  * wrong principal type -> generic error/close.
  * missing KeyStore entry -> generic error/close.
  * subject changes after auth -> generic error/close on next request.
  * subject changes during auth -> fail closed.
* Fixed mode regression: subject changes do not affect the shared identity.
* Real Kafka integration: subject mode with a test-only filter that publishes a fixed `Subject` (e.g. a small
  `FixedSubjectFilter` test plugin) and per-user upstream credentials; verify mapped usernames and fail-closed cases.
  (Full `SaslTermination` and mTLS composition is Commit 8.)

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.2, §6.4, D6-D8, R4-R8, S3-S5 and plan/sasl-initiation-implementation.md §3.3 and §6
Commit 7.

Complete subject-derived identity support.

Requirements:
- At the trigger point, resolve the identity using the configured `IdentitySelector`. In subject mode this reads
  `FilterContext.authenticatedSubject()`; it must never fall back to a fixed identity.
- `CredentialResolver` looks up the credential by lookup key. A missing entry, wrong entry type, or entry whose `subject`
  does not equal the lookup key is a fail-closed error: generic `UNKNOWN_SERVER_ERROR` for the triggering request and
  close.
- The KeyStore entry's `username` is the broker authentication ID; it may differ from the subject.
- After successful authentication, store an immutable `IdentitySnapshot` for subject mode. On every later request,
  compare the current downstream identity with the snapshot. If it changed, return a generic error and close. Do not
  reauthenticate as the new identity.
- Re-check the subject after authentication completes; if it changed between trigger and success, fail closed.
- Never call `clientSaslAuthenticationSuccess`/`clientSaslAuthenticationFailure`.
- Log subject and broker username at an appropriate level, never passwords/tokens/payloads.
- Fixed mode must behave exactly as before.

Tests:
- Unit/protocol tests with `MockFilterContext` for: subject selects entry; mapped username; anonymous; absent principal;
  ambiguous/custom principal; missing entry; entry subject mismatch; subject change after auth; subject change during
  auth; fixed-mode subject change unaffected.
- Integration test with a test-only `FixedSubjectFilter` that calls `clientSaslAuthenticationSuccess` with a configured
  `Subject`, placed before `SaslInitiation`, plus a real Kafka broker with per-user credentials. Verify success, mapped
  username, and fail-closed cases.

Do not add `SaslTermination`/mTLS composition tests, OAUTHBEARER, reauthentication or metrics in this commit.

Acceptance: subject mode fails closed in every negative case and never exposes a broker error or credential detail.
~~~

---

### Commit 8 — `test: cover SASL initiation composition with client authentication`

**Goal:** Prove the filter composes correctly with real client-facing authentication and with mTLS, and that
misconfiguration fails safely.

**Adds**

* Integration-test dependencies on `kroxylicious-sasl-termination` and
  `kroxylicious-scram-credential-store-provider-file` (0.26.0).
* Separate PKCS12 files for `SaslTermination` client credentials and `SaslInitiation` upstream credentials, with
  different store passwords, so the tests exercise D17 rather than sharing one store.
* A test-only `CompositionObserverFilter`, placed after `SaslInitiation`, that parses the initiator's own PLAIN/SCRAM
  handshake/auth frames, records the broker authorization id and upstream mechanism, and adds those plus the downstream
  subject to produced record headers. This verifies the broker-visible identity without relying only on a successful
  produce.
* ITs for:
  * `SaslTermination` SCRAM-SHA-256 client -> `SaslInitiation` PLAIN upstream, with distinct client and broker
    identities.
  * `SaslTermination` SCRAM-SHA-256 client -> `SaslInitiation` SCRAM-SHA-512 upstream (mechanism translation).
  * per-user credentials and mapped usernames (`alice` -> `svc-alice`).
  * mTLS client -> `SaslInitiation` SCRAM-SHA-512 upstream, using `KeytoolCertificateGenerator` and `@Tls`, with a
    `clientTlsSanDnsName` subject builder.
  * anonymous client -> fixed identity upstream.
  * subject mode with anonymous client -> generic failure and close.
  * client SASL directly into `SaslInitiation` with no termination -> `UNSUPPORTED_SASL_MECHANISM` and close.
  * `SaslInitiation` before `SaslTermination` -> the same rejection, documented as a misconfiguration.
* A small code fix for the composition case where a Kafka client sends a second `ApiVersions` request after client
  SASL termination. Only the first client `ApiVersions` exchange is forwarded before initiation; later ones trigger
  upstream authentication and are forwarded afterwards, otherwise the broker rejects them as unexpected during its
  SASL handshake state.
* Documentation of the required chain order and the `SaslTermination` mechanism limitation.

**Tests**

* Real Kafka for every scenario above.
* Assert the downstream subject seen by the later observer is unchanged by `SaslInitiation`.
* Assert the observer parses the configured upstream mechanism and authorization id from the initiator's own frames.
* Assert client-visible failures are generic and connections close; handshake rejection exposes no broker mechanism
  list or error text.

**Mechanism limitation:** released `SaslTermination` 0.26.0 supports SCRAM and OAUTHBEARER, not PLAIN. The composition
tests therefore use SCRAM client termination. No PLAIN-termination claim is made; covering it would require a clearly
marked test-only terminator or an upstream `SaslTermination` change.

**Prompt**

~~~text
Read plan/sasl-initiation.md §1, §6.1, §6.7, R19, R22-R25, S3-S6 and plan/sasl-initiation-implementation.md §2.3(7) and
§6 Commit 8.

Add integration coverage for composition with client-facing authentication.

Requirements:
- Add test-scope dependencies on `kroxylicious-sasl-termination` and
  `kroxylicious-scram-credential-store-provider-file` (0.26.0).
- Create ITs using real Kafka via `KafkaClusterExtension` and `KroxyliciousTesters`.
- Build two separate credential stores:
  * one for `SaslTermination` client credentials (SCRAM);
  * one for `SaslInitiation` upstream credentials.
  This verifies D17 (dedicated store).
- Scenarios:
  1. Client SCRAM-SHA-256 termination -> upstream PLAIN initiation; client and broker identities differ; produce/consume.
  2. Client SCRAM-SHA-256 termination -> upstream SCRAM-SHA-512 initiation (mechanism translation).
  3. Per-user mapping: downstream `alice` maps to upstream `svc-alice` via the initiation KeyStore.
  4. mTLS client -> upstream SCRAM initiation, using `KeytoolCertificateGenerator` and `@Tls`.
  5. Anonymous client + fixed identity -> upstream SCRAM.
  6. Anonymous client + subject mode -> generic failure/close.
  7. Kafka client configured with SASL directly against a proxy that has `SaslInitiation` but no termination -> the
     client's SaslHandshake is rejected with `UNSUPPORTED_SASL_MECHANISM` and the connection closes.
  8. Misordered chain (`SaslInitiation` before `SaslTermination`) -> same rejection; document as misconfiguration.
- Assert the downstream subject seen by a later test filter is unchanged by `SaslInitiation`.
- Assert broker-visible identity: use per-user ACLs or a small test observer filter that records the upstream
  authorization id; do not rely only on "produce succeeded".
- Assert no broker error message or SASL payload reaches the client.

Note: `SaslTermination` 0.26.0 supports SCRAM and OAUTHBEARER, not PLAIN. Do not claim a PLAIN-termination test unless
you add a clearly marked test-only terminator. Update the docs/plan accordingly.

Do not add OAUTHBEARER initiation or reauthentication in this commit.

Acceptance: the composition matrix passes; misordered/passthrough configurations fail safely and are documented.
~~~

---

### Commit 9 — `feat: add OAUTHBEARER support to SASL initiation`

**Goal:** Add OAUTHBEARER as a first-class mechanism: config, KeyStore OAuth entries, token retrieval/validation/cache,
per-subject client credentials, expected-subject verification, and an asynchronous token service that never blocks the
filter-dispatch thread.

**Adds**

* `OAUTHBEARER` in `Mechanism` and `oauthBearer` config group:
  ```yaml
  oauthBearer:
    tokenEndpointUrl: https://idp.example.com/token   # or file:/...
    scope: kafka
    jwtRetriever: org.apache.kafka.common.security.oauthbearer.DefaultJwtRetriever
    subjectClaimName: sub
  ```
* Config validation:
  * `oauthBearer` required exactly for OAUTHBEARER, rejected otherwise;
  * `tokenEndpointUrl` required, `file:`/`http:`/`https:` schemes;
  * KeyStore required for subject mode and fixed HTTP client-credentials; absent for fixed `file:` token mode;
  * `jwtRetriever` must implement `JwtRetriever`;
  * `subjectClaimName` default `sub`.
* `OAuthTokenService`:
  * creates a `JwtRetriever` and `JwtValidator` per identity;
  * uses a worker executor/virtual threads for blocking retrieval;
  * verifies the token subject against `expectedSubject` where applicable;
  * bounded, expiring, single-flight token cache;
  * closes retrievers/validators on factory close.
* `OAuthBearerMechanismDriver` and callback handler.
* Unit/protocol tests with a fake OAuth token source and Kafka's `OAuthBearerSaslServer`.
* No real-Kafka OAUTH ITs yet (Commit 10).

**Design constraints**

* Do not block the event loop on HTTP. Retrieve/validate the token before creating the `SaslClient`; supply it
  synchronously via `OAuthBearerTokenCallback`.
* Fixed token-file mode trusts the file and does not require a KeyStore entry; subject mode and fixed client-credentials
  require an entry and verify `principalName()` against `expectedSubject`.
* Token cache key is the lookup key; maximum size is fixed (e.g. 1024) and cache entries expire using token lifetime with
  a safety margin.
* Use Kafka's `JwtRetriever`/`JwtValidator` APIs; do not parse JWTs manually.
* Never log tokens or client secrets.
* No token exchange/impersonation.

**Tests**

* Config validation for all OAUTH/non-OAUTH combinations; retriever class validation.
* KeyStore OAuth entry round-trip and type mismatch.
* Token service: cache hit, expiry/refresh, safety margin, bounded size, single-flight concurrency, subject mismatch,
  retriever failure, validator failure, close.
* Protocol: OAUTH exchange with Kafka's `OAuthBearerSaslServer` and a test validator; fixed token file; fixed client
  credentials; subject mode entry; wrong expected subject -> fail closed.
* Assert token retrieval runs off the filter-dispatch thread (e.g. a blocking fake retriever and an event-loop assertion).
* No token/secret in logs or exceptions.

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.5, §6.6, D13, D23, R1, R17, S1-S9 and plan/sasl-initiation-implementation.md §3.3-§3.4
and §6 Commit 9.

Add OAUTHBEARER support (configuration and mechanism; real-Kafka ITs come next commit).

Config:
- Add OAUTHBEARER to `Mechanism`.
- Add `oauthBearer` group with `tokenEndpointUrl`, optional `scope`, optional `jwtRetriever`, optional
  `subjectClaimName` (default `sub`).
- Validate: oauthBearer required exactly for OAUTHBEARER; tokenEndpointUrl required and a file/http/https URI; KeyStore
  required for subject mode and fixed HTTP client-credentials, absent for fixed file-token mode; jwtRetriever class must
  implement `org.apache.kafka.common.security.oauthbearer.JwtRetriever`; subjectClaimName non-empty.

Token service:
- Package `com.github.tombentley.kroxylicious.filter.sasl.initiation.oauth`.
- `OAuthTokenService` per factory initialization data. Per identity, instantiate and configure a `JwtRetriever`
  (default `DefaultJwtRetriever`) and a `JwtValidator` (`DefaultJwtValidator`/`ClientJwtValidator`).
- For fixed file-token mode, use `FileJwtRetriever` and no KeyStore entry; trust the file.
- For fixed HTTP client-credentials and subject mode, use the KeyStore entry's clientId/clientSecret and
  `ClientCredentialsJwtRetriever`; verify `OAuthBearerToken.principalName()` equals `expectedSubject`.
- Build the Kafka config map/JAAS entries needed by the retriever (`sasl.oauthbearer.token.endpoint.url`,
  `sasl.oauthbearer.scope`, `sasl.oauthbearer.client.credentials.client.id`,
  `sasl.oauthbearer.client.credentials.client.secret`, `sasl.oauthbearer.sub.claim.name`).
- Never call `retrieve()` on the filter-dispatch thread. Use a dedicated worker executor (virtual threads are fine).
  The filter must wrap the returned token stage with
  `FilterDispatchExecutor.completeOnFilterDispatchThread(...)` before chaining any state mutation, so all filter state
  changes stay on the connection's filter-dispatch thread.
- Implement a bounded, expiring, single-flight token cache keyed by lookup key. Maximum size 1024. Refresh before expiry
  with a safety margin (min(60s, 10% of lifetime)). Remove expired entries.
- Close retrievers/validators/cache on factory close.

Mechanism:
- `OAuthBearerMechanismDriver` creates a `SaslClient` for OAUTHBEARER with a callback handler that supplies
  `OAuthBearerTokenCallback` and `SaslExtensionsCallback`.
- Retrieve/validate the token asynchronously first, then create the SaslClient synchronously with the token.
- Use the generic exchange loop from Commit 5.

Tests:
- Config validation matrix.
- KeyStore OAuth entry round-trip; wrong type; missing expectedSubject default.
- Token service unit tests with fake `JwtRetriever`/`JwtValidator` and a mutable clock: cache hit, expiry, safety margin,
  bounded size, single-flight, subject mismatch, retriever/validator failure, close.
- Protocol tests with Kafka's `OAuthBearerSaslServer` and a test validation callback; fixed token file, fixed client
  credentials, subject-mode entry, wrong expected subject.
- A test that blocks in the fake retriever and asserts the filter-dispatch thread is not blocked.
- Assert no token/client secret in logs, exceptions or `toString()`.

Do not add real-Kafka OAUTH ITs, reauthentication or token exchange in this commit.

Acceptance: OAUTH config/unit/protocol tests pass and no token retrieval blocks the filter thread.
~~~

---

### Commit 10 — `test: cover OAUTHBEARER against a real Kafka broker`

**Goal:** Prove OAUTHBEARER works against a real broker and a real OAuth token endpoint, including fixed and
subject-derived identities and expected-subject verification.

**Adds**

* Docker-gated ITs using `mock-oauth2-server` (or the same OAuth container pattern as Kroxylicious
  `BaseOauthBearerIT`) and Kafka `@SaslMechanism("OAUTHBEARER")` with `@BrokerConfig` JWKS/validator settings.
* Tests:
  * fixed identity with a token file;
  * fixed identity with client credentials;
  * subject mode with per-subject OAuth client credentials;
  * expected-subject mismatch -> fail closed;
  * expired token -> fail closed/refresh;
  * token cache reuse across connections (where observable);
  * client `SaslTermination` OAUTH -> upstream SCRAM (composition).
* Test helpers for generating test JWTs/JWKS (use `JwsTestUtils` from `kroxylicious-filter-test-support` where useful).
* Documentation notes for OAUTH operational setup.

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.5-§6.7, D13, D23, UC6 and plan/sasl-initiation-implementation.md §4.2 and §6 Commit 10.

Add real-Kafka OAUTHBEARER integration tests.

Requirements:
- Add Docker-gated tests (use `@EnabledIf` with `DockerClientFactory.instance().isDockerAvailable()`).
- Use a mock OAuth/OIDC server container (the same image/pattern as Kroxylicious `BaseOauthBearerIT`:
  `ghcr.io/navikt/mock-oauth2-server`). Expose a fixed port if required by the broker JWKS URL. Set
  `org.apache.kafka.sasl.oauthbearer.allowed.urls` for the in-VM broker and client.
- Configure the real Kafka broker with `@SaslMechanism(value="OAUTHBEARER")` and `@BrokerConfig`:
  `listener.name.external.oauthbearer.sasl.server.callback.handler.class=...OAuthBearerValidatorCallbackHandler`,
  `listener.name.external.sasl.oauthbearer.jwt.validator.class=...BrokerJwtValidator`,
  `listener.name.external.sasl.oauthbearer.jwks.endpoint.url=<JWKS>`,
  `listener.name.external.sasl.oauthbearer.expected.audience=<audience>`.
- Tests:
  1. Fixed identity with `oauthBearer.tokenEndpointUrl=file:<token>`; no initiation KeyStore; produce/consume.
  2. Fixed identity with client credentials in the initiation KeyStore; token endpoint HTTP; produce/consume.
  3. Subject mode via a test `FixedSubjectFilter` (or `SaslTermination` OAUTH) with per-subject client credentials in
     the initiation KeyStore; verify the upstream token subject matches `expectedSubject`.
  4. Wrong `expectedSubject` -> generic failure/close.
  5. Expired token -> token service refresh or fail closed, depending on configuration; assert no token is logged.
  6. Client `SaslTermination` OAUTH -> `SaslInitiation` SCRAM (composition), if the OAuth container and termination
     config make this practical.
- Assert secrets/tokens never appear in proxy logs (capture or inspect test logs).
- Tag the tests so they are excluded when Docker is unavailable and run in the Docker CI job.

Do not implement reauthentication in this commit. Do not add token exchange/impersonation.

Acceptance: OAUTH fixed and subject modes work end to end against a real broker; negative subject/expiry cases fail
closed; Docker-less builds skip cleanly.
~~~

---

### Commit 11 — `feat: implement KIP-368 reauthentication`

**Goal:** Add proactive, jittered KIP-368 reauthentication with the same identity, fresh `SaslClient`, deadline
scheduling, request-boundary execution, and fail-closed subject/token checks.

**Adds**

* `ReauthScheduler` / reauth deadline calculation:
  * effective lifetime from broker `sessionLifetimeMs` and token expiry;
  * `windowFactor` default 0.8, jitter ±0.05 clamped to [0.5, 0.95];
  * one-shot scheduled task that arms `reauthDue`;
  * hard deadline enforcement.
* Reauth state in `SaslInitiationFilter` (`REAUTHENTICATING`).
* Reauth exchange:
  * reuse cached API versions (no `ApiVersions`);
  * fresh `SaslClient` and fresh credential/token;
  * send `SaslHandshake` + `SaslAuthenticate` loop;
  * update `sessionLifetimeMs` and reschedule.
* Subject guard during reauth:
  * capture identity before reauth;
  * re-check after reauth;
  * fail closed if changed.
* Token refresh before reauth for OAUTHBEARER.
* Failure handling: generic error for the triggering request, close.
* Unit/protocol tests with a fake clock/scheduler and fake broker.

**Design constraints**

* Do not send `ApiVersions` during reauth.
* Do not retry a failed reauth.
* Do not reuse a `SaslClient`; SCRAM requires a fresh one.
* Do not perform I/O from the scheduled task. It only sets `reauthDue`; the next request starts reauth. This is the
  request-boundary execution decision in §3.4.
* If the hard deadline is reached before reauth, fail closed.
* If the broker reported `sessionLifetimeMs=0` and there is no token expiry, do not schedule reauth.
* Do not add metrics yet; use logs.

**Tests**

* Unit with fake clock:
  * default 0.8 factor and jitter bounds;
  * window factor validation already covered;
  * broker lifetime only, token expiry only, min of both;
  * no schedule when lifetime is 0/absent;
  * request before deadline forwards without reauth;
  * request at/after deadline triggers reauth before forwarding;
  * reauth success reschedules;
  * reauth failure -> generic error/close, no retry;
  * hard deadline missed -> fail closed;
  * subject changes before/during reauth -> fail closed;
  * OAUTH token refresh before reauth;
  * no `ApiVersions` during reauth; one handshake and one auth loop;
  * no `clientSaslAuthenticationSuccess`/`Failure`.
* Protocol tests with fake broker for SCRAM and OAUTH reauth.
* Pipelining: requests arriving during reauth chain on the reauth stage; no filter-level queue.

**Prompt**

~~~text
Read plan/sasl-initiation.md D20, R21, R8, S5 and plan/sasl-initiation-implementation.md §3.4 and §6 Commit 11.

Implement KIP-368 reauthentication.

Requirements:
- After successful initial authentication, compute effective lifetime = min(positive broker sessionLifetimeMs, token
  remaining lifetime). If neither is present, do not schedule.
- Compute delay = effectiveLifetime * clamp(windowFactor + uniform(-0.05, +0.05), 0.5, 0.95). `windowFactor` comes from
  config (default 0.8).
- Schedule a one-shot task on `FilterDispatchExecutor` that only sets `reauthDue=true`. Do not perform I/O in the task.
- On the next request at/after the deadline, before forwarding, perform reauth:
  * reuse cached handshake/authenticate versions; do not send ApiVersions;
  * resolve the same identity and credential; fail closed if the subject changed or the entry is gone;
  * for OAUTHBEARER, refresh the token if needed;
  * create a fresh SaslClient and run the handshake + authenticate loop;
  * update sessionLifetimeMs and reschedule.
- Requests arriving during reauth must chain on the reauth stage; do not buffer.
- If reauth fails, return a generic `UNKNOWN_SERVER_ERROR` for the triggering request and close. No retry.
- If the hard deadline (effective lifetime) is reached before reauth completes/start, fail closed.
- If the subject changes before or during reauth, fail closed.
- Never call `clientSaslAuthenticationSuccess`/`Failure`.
- Log reauth attempt/outcome with mechanism, virtual cluster, session id, error code; never secrets.

Tests:
- Use a mutable `Clock` and a controllable scheduler/executor in unit tests.
- Cover deadline calculation, jitter bounds, no-lifetime case, request-before/at deadline, success reschedule, failure,
  hard-deadline miss, subject change before/during reauth, token refresh, no ApiVersions, fresh SaslClient, no client-auth
  gestures.
- Protocol tests with fake SCRAM and OAUTH brokers.
- Pipelining test: requests during reauth return incomplete stages and are forwarded in order after success.

Do not add real-Kafka reauth ITs or metrics in this commit.

Acceptance: reauth is deterministic under a fake clock, uses the same identity, and fails closed on every error or
subject change.
~~~

---

### Commit 12 — `test: cover reauthentication and pipelining against real Kafka`

**Goal:** Prove reauthentication works against a real broker with a short session lifetime, that subject changes close
the connection, and that pipelined requests during authentication/reauthentication remain bounded and ordered.

**Adds**

* Real-Kafka reauth IT:
  * `@BrokerConfig(name="connections.max.reauth.ms", value="5000")`;
  * long-running producer/consumer or admin activity spanning multiple reauth windows;
  * assert no client-visible errors and reauth logs/metrics occur (metrics arrive in Commit 14; use logs for now).
* Subject-change IT:
  * test-only `SubjectSwitcher` filter that changes the downstream subject after a request/round;
  * subject-mode `SaslInitiation` closes the connection;
  * fixed mode is unaffected.
* Pipelining/backpressure IT:
  * use raw `KafkaClient` or `MockServer` to delay SASL responses;
  * send many requests back-to-back while authentication/reauth is in progress;
  * assert deterministic ordering, bounded memory/queues, and no request overtakes authentication.
* Any fixes required by real-runtime behaviour, without adding a filter-level queue.

**Prompt**

~~~text
Read plan/sasl-initiation.md D18, D20, D33, risk 10 and plan/sasl-initiation-implementation.md §4.2 and §6 Commit 12.

Add real-Kafka coverage for reauthentication, subject change and pipelining.

Requirements:
- Reauth IT:
  * real Kafka cluster with `@BrokerConfig(name="connections.max.reauth.ms", value="5000")`;
  * fixed identity SCRAM;
  * keep the connection active for longer than 5 seconds (produce/consume loop or repeated admin calls);
  * assert all operations succeed and the proxy logs reauthentication (do not assert on metrics yet).
- Subject change IT:
  * add a test-only `SubjectSwitcher` filter (or equivalent) that calls `clientSaslAuthenticationSuccess` with a
    different `Subject` after a configured number of requests;
  * subject-mode `SaslInitiation` must return a generic error and close;
  * fixed-mode `SaslInitiation` must continue using the shared identity.
- Pipelining/backpressure IT:
  * use `io.kroxylicious.testing.integration.client.KafkaClient` (raw protocol client) and/or `MockServer` to delay
    SaslAuthenticate responses;
  * pipeline many client requests while authentication/reauth is in progress;
  * assert no request overtakes authentication, the connection processes/fails deterministically, and the proxy does not
    accumulate an unbounded filter-level queue.
- If the test exposes an unbounded already-decoded-frame queue, record it as a runtime issue in §8; do not add a
  filter-level queue as a workaround.
- Do not add metrics yet.

Acceptance: reauth is transparent to a real client; subject change closes the connection; pipelined requests are bounded
and ordered.
~~~

---

### Commit 13 — `feat: support per-route SASL initiation`

**Goal:** Validate and demonstrate the D22 routing model: `SaslInitiation` on each leaf route's filter chain, with
per-target credentials and independent authentication state.

**Adds**

* A simple test `PassThroughRouter`/`SplitRouter` in the integration-tests module (or reuse the pattern from Kroxylicious
  `PassThroughRouterFactory`) registered as a test plugin.
* IT with two Kafka clusters (or two routes to clusters with different SASL credentials):
  * route A uses KeyStore entry/credentials A;
  * route B uses credentials B;
  * client fans out to both routes through one virtual cluster;
  * each upstream connection authenticates independently.
* IT showing a virtual-cluster-level initiator is not suitable for routing (documented failure), or a unit/IT assertion
  that the route-level filter is the supported configuration.
* Documentation updates for leaf-route placement.
* Any small logging/clarity fixes.

**Implementation notes**

* The routing IT uses two real Kafka clusters, not two routes to the same cluster. The runtime caches upstream
  connections by target address, so two routes to the same broker address share one connection; independent per-route
  credentials require distinct upstream targets.
* Routing is gated by `Feature.ROUTING` in the test harness.
* The leaf-route configuration example lives in `plan/sasl-initiation.md` §6.1 and the README.

**Prompt**

~~~text
Read plan/sasl-initiation.md §6.1, D22, R25, risk 6 and plan/sasl-initiation-implementation.md §4.2 and §6 Commit 13.

Add routing coverage and any small fixes needed for per-route placement.

Requirements:
- Add a test-only router plugin to the integration-tests module that forwards requests to a named route (adapt the
  Kroxylicious `PassThroughRouterFactory` pattern). Register it via `META-INF/services/io.kroxylicious.proxy.router.RouterFactory`.
- Configure two real Kafka clusters (or two routes with different SASL credentials) and two route-level filter
  definitions, each with its own `SaslInitiation` config/KeyStore.
- Verify a client connection that fans out to both routes authenticates independently to each upstream and that each
  upstream sees the expected identity.
- Verify route-level filter state is per upstream connection, not shared.
- Verify the client subject is still readable by the route filter and is not changed.
- Add a test or explicit assertion documenting that a virtual-cluster-level initiator is not the supported routing
  placement (it runs before target selection).
- Update docs/plan with the leaf-route configuration example.
- Do not add new mechanisms or reauth behaviour.

Acceptance: the routing IT passes with per-route credentials; the unsupported placement is clearly documented.
~~~

---

### Commit 14 — `feat: add SASL initiation metrics and structured logs`

**Goal:** Make the filter operable: metrics for authentication/reauth/token retrieval and structured, secret-free logs.

**Adds**

* `SaslInitiationMetrics` using Micrometer `Metrics.globalRegistry`, following `SaslTermination` conventions.
* Metrics:
  * `kroxylicious_filter_sasl_initiation_auth_attempts_total` tags `mechanism`, `virtual_cluster`, `outcome`.
  * `kroxylicious_filter_sasl_initiation_auth_duration_seconds` tags `mechanism`, `virtual_cluster`.
  * `kroxylicious_filter_sasl_initiation_reauth_attempts_total` tags `mechanism`, `virtual_cluster`, `outcome`.
  * `kroxylicious_filter_sasl_initiation_reauth_duration_seconds`.
  * `kroxylicious_filter_sasl_initiation_token_retrieval_duration_seconds` tags `outcome`.
  * Optional `..._connection_closed_total` tags `reason`.
* Structured logs with key-value fields: session id, virtual cluster, mechanism, outcome, broker username, subject,
  reauth flag, broker error code. No passwords/tokens/SASL payloads.
* Redaction tests using a Log4j2 `ListAppender` or equivalent.
* Unit tests with `SimpleMeterRegistry`; one IT metrics assertion if practical.

**Tests**

* Metrics count success/failure/reauth/token outcomes with correct tags; no subject/username tags.
* Duration timers recorded.
* Logs contain expected fields and never known secrets.
* `toString()` of config/credential objects redacts secrets.
* Integration: management endpoint exposes the new metrics after a successful/failed auth (optional but preferred).

**Prompt**

~~~text
Read plan/sasl-initiation.md D26, R26, S1-S6 and plan/sasl-initiation-implementation.md §3.5 and §6 Commit 14.

Add metrics and structured logging.

Requirements:
- Add `SaslInitiationMetrics` using `io.micrometer.core.instrument.Metrics.globalRegistry`, following
  `SaslTermination`'s conventions.
- Register counters/timers:
  * auth attempts total, tags mechanism, virtual_cluster, outcome (success/failure);
  * auth duration seconds, tags mechanism, virtual_cluster;
  * reauth attempts total, tags mechanism, virtual_cluster, outcome;
  * reauth duration seconds;
  * token retrieval duration seconds, tag outcome;
  * optional connection closed total, tag reason.
  Do not add subject/username tags.
- Record metrics on initial auth, reauth, token retrieval and failure paths.
- Add structured logs using `LOGGER.atInfo()/atWarn()/atDebug().addKeyValue(...)`:
  sessionId, virtualCluster, mechanism, outcome, brokerUsername, subject, reauth, errorCode.
  Never log passwords, client secrets, bearer tokens, auth bytes, or raw broker error messages.
- Add a log redaction/sanitizer for broker error messages if any message is logged: strip CR/LF, cap length, never include
  payloads.
- Tests:
  * `SimpleMeterRegistry` added to `Metrics.globalRegistry`; assert counters/timers and tags for success, failure,
    reauth, token retrieval.
  * No subject/username in metric tags.
  * Log capture test: run successful and failed auth, assert expected fields appear and known secrets/tokens do not.
  * `toString()` tests for config/credential objects.
- Optionally add an integration assertion against the proxy management/Prometheus metrics endpoint.

Do not change the protocol/state machine semantics in this commit.

Acceptance: metrics are exposed with bounded tags; logs are actionable and contain no secrets.
~~~

---

### Commit 15 — `docs: document SASL initiation`

**Goal:** Produce the documentation required for a production-ready first release: concept, configuration reference,
KeyStore/CLI operations, security, observability, routing, failure semantics, and migration.

**Adds**

* `docs/` AsciiDoc or Markdown pages:
  * concept: what SASL initiation is, how it differs from termination/inspection;
  * configuration reference for every field and mechanism;
  * KeyStore creation/rotation with the CLI and Kubernetes Secret examples;
  * filter-chain ordering and composition with `SaslTermination`, mTLS, anonymous clients;
  * routing/leaf-route placement;
  * mechanism/identity support matrix and limitations;
  * security warnings (PLAIN over plaintext, KeyStore custody, memory, subject trust, no hot reload);
  * failure semantics and observability;
  * migration from the test `SaslPlainInitiation` filter.
* Example YAML files for fixed/subject, PLAIN/SCRAM/OAUTH, mTLS, routing.
* README updates.
* A test that parses/validates the example configs where practical.

**Prompt**

~~~text
Read plan/sasl-initiation.md §1, §6.5-§6.7, D24-D28 and plan/sasl-initiation-implementation.md §6 Commit 15.

Write the documentation for the first release.

Deliver:
- A concept page explaining SASL initiation, the upstream position in the chain, and the difference from
  SaslTermination/SaslInspection.
- A configuration reference for every field in `SaslInitiationConfig` with defaults and validation rules.
- KeyStore and CLI operations:
  * create/add/update/remove/list;
  * password-file and interactive workflows;
  * POSIX permissions and the Kubernetes/OpenShift relaxation;
  * rotation by restart (no hot reload in v1).
- Chain-order guidance: `SaslTermination` (or mTLS) before `SaslInitiation`; `SaslInitiation` last/closest to the
  broker; reject client SASL passthrough; document that `SaslInspection` passthrough is incompatible.
- Routing guidance: configure on each leaf route chain, not the virtual-cluster chain.
- Mechanism/identity matrix and limitations: one mechanism per instance, one password per identity, separate stores for
  termination/initiation, no fallback, no token exchange.
- Security section: PLAIN over SASL_PLAINTEXT warning, KeyStore custody, JVM heap copies, subject trust, generic client
  errors, no secrets in logs.
- Failure semantics table and observability/metric names.
- Migration notes from the test-only `SaslPlainInitiation`.
- Example YAML files for fixed/subject, PLAIN/SCRAM/OAUTH, mTLS, routing.
- Update README with a quick start.
- Add a test that loads/validates the example configuration snippets where practical (e.g. Jackson config records).

Do not make unrelated code changes. If documentation reveals a mismatch with the implementation, record it in §8.

Acceptance: a new user can configure, secure, operate and troubleshoot the filter from the docs alone.
~~~

---

### Commit 16 — `test: add black-box system test harness`

**Goal:** Test the packaged plugin as a real deployment: Kafka in a container, Kroxylicious distribution on the
classpath-plugins path, config file, CLI-generated KeyStore, proxy subprocess, and real clients.

**Adds**

* `kroxylicious-sasl-initiation-system-tests` module with `*SystemIT` tests and a `system-tests` Maven profile.
* Harness:
  * Testcontainers Kafka 4.3.x with SASL_PLAINTEXT listener and PLAIN/SCRAM users;
  * Kroxylicious 0.26.0 binary distribution unpacked into `target/`;
  * `classpath-plugins/sasl-initiation/` containing the built filter, credentials and CLI jars;
  * config YAML written to a temp directory;
  * CLI-generated PKCS12 store and password file;
  * proxy subprocess started with `bin/kroxylicious-start.sh --config ...`; wait for readiness; stop cleanly; capture logs.
* Smoke system tests:
  * fixed identity PLAIN;
  * fixed identity SCRAM-SHA-256;
  * produce/consume through the proxy;
  * assertion that no known secret appears in proxy logs.
* CI profile and README instructions.

**Prompt**

~~~text
Read plan/sasl-initiation.md D1, D2, O1-O6, D27 and plan/sasl-initiation-implementation.md §4.1 and §6 Commit 16.

Create the black-box system test module.

Requirements:
- Module `kroxylicious-sasl-initiation-system-tests`, tests named `*SystemIT`, activated by `-Psystem-tests`; skipped by
  default.
- Use Testcontainers to run Kafka 4.3.x with a SASL_PLAINTEXT listener. Configure PLAIN and SCRAM-SHA-256 users. Reuse
  the container configuration pattern from the Kroxylicious JUnit extension/its tests where practical.
- Unpack the Kroxylicious 0.26.0 binary distribution into `target/kroxylicious`. The distribution is published as a
  GitHub release artifact (`kroxylicious-app-0.26.0-bin.tar.gz`); download it with a pinned version/checksum in the test
  setup, or unpack a locally supplied distribution via a system property. Create `classpath-plugins/sasl-initiation/`
  and copy the built
  `kroxylicious-sasl-initiation`, `kroxylicious-sasl-initiation-credentials` and CLI jars there.
- Generate a PKCS12 initiation credential store with the CLI (or the credential library if the CLI is not yet packaged)
  and write a `passwordFile`.
- Write a proxy config YAML with a `filterDefinitions` entry of type `SaslInitiation`, a cluster definition pointing at
  the Kafka container, a virtual cluster, and management settings.
- Start the proxy as a subprocess using `bin/kroxylicious-start.sh --config <file>`; wait for the bootstrap port; run a
  real Kafka producer/consumer; stop the process; capture stdout/stderr.
- Tests:
  * fixed identity PLAIN;
  * fixed identity SCRAM-SHA-256;
  * produce/consume through the proxy;
  * assert the proxy logs do not contain the known broker password, store password or client secret.
- Add a `system-tests` GitHub Actions job (nightly/manual) with Docker.
- Document how to run the system tests and how to point them at a different Kafka version.

Do not add subject mode, mTLS, OAUTH or reauth system tests in this commit; those come next.

Acceptance: the smoke system tests run the packaged proxy as a black box and pass in CI with Docker.
~~~

---

### Commit 17 — `test: extend system test coverage`

**Goal:** Extend the black-box suite to the identity/composition and reauthentication scenarios that matter operationally.

**Adds**

* System tests for:
  * subject mode via `SaslTermination` SCRAM (client SCRAM, upstream SCRAM/PLAIN, mapped users);
  * mTLS client -> upstream SCRAM;
  * reauthentication with a short broker session lifetime;
  * failure cases: wrong upstream credential, unsupported mechanism, client SASL passthrough;
  * OAUTHBEARER fixed/subject if the container setup is practical (otherwise document as a follow-up).
* Test configuration/KeyStore helpers shared with the smoke tests.
* CI job updates.

**Prompt**

~~~text
Read plan/sasl-initiation.md §4.3, D20-D22, D27 and plan/sasl-initiation-implementation.md §4.3 and §6 Commit 17.

Extend the black-box system tests.

Requirements:
- Reuse the harness from Commit 16.
- Add tests:
  1. Subject mode: client `SaslTermination` SCRAM; upstream `SaslInitiation` SCRAM-SHA-512 or PLAIN; per-user
     credentials; mapped username; produce/consume.
  2. mTLS client -> upstream SCRAM initiation; use test certificates and a TLS gateway.
  3. Reauthentication: Kafka container with a short `connections.max.reauth.ms` (e.g. 5000ms); keep the client active;
     assert operations continue without errors and proxy logs show reauth.
  4. Failure cases: wrong upstream credential, unsupported mechanism, client SASL passthrough; assert generic client
     failure and connection close; assert no broker error text/secret in the client or logs.
  5. OAUTHBEARER fixed/subject if the OAuth container can be run alongside Kafka; otherwise record as a follow-up.
- Keep tests tagged and Docker-gated; update the system-tests CI job.
- Do not add new production features in this commit; fix only bugs exposed by the tests.

Acceptance: the system test matrix covers the operational deployment modes and remains stable in CI.
~~~

---

### Commit 18 — `build: package SASL initiation for release`

**Goal:** Produce a distributable plugin/CLI bundle, examples, and a release checklist for the first standalone v1
release.

**Adds**

* Assembly/zip:
  ```text
  sasl-initiation-0.1.0/
    classpath-plugins/sasl-initiation/
      kroxylicious-sasl-initiation-0.1.0.jar
      kroxylicious-sasl-initiation-credentials-0.1.0.jar
    bin/sasl-initiation-credential-tool
    examples/*.yaml
    README.md
    LICENSE
  ```
* Shaded CLI executable jar (picocli only).
* Reproducible build settings; dependency analysis; license/notice; changelog.
* Version `0.1.0`, release notes, and a checklist:
  * unit + protocol + integration + system tests;
  * formatter/import/license/checkstyle;
  * dependency analysis;
  * no secrets in the repository or artifacts;
  * example configs validated;
  * plugin discovered by the packaged proxy.
* Optionally publish to a local Maven repository/artifact store; do not publish upstream coordinates without review.

**Prompt**

~~~text
Read plan/sasl-initiation.md D1, D2, D4, D28, O4-O6 and plan/sasl-initiation-implementation.md §2.2 and §6 Commit 18.

Package the first standalone release.

Requirements:
- Add a Maven assembly/zip producing the layout in §6 Commit 18:
  * `classpath-plugins/sasl-initiation/` with the filter and credentials jars (and any runtime dependencies not provided
    by the proxy);
  * `bin/sasl-initiation-credential-tool` launcher for the shaded CLI jar;
  * `examples/` with validated fixed/subject, PLAIN/SCRAM/OAUTH, mTLS and routing YAML;
  * README and LICENSE.
- Shade only the CLI's picocli dependency; exclude Kroxylicious, Kafka, Jackson, SLF4J and Micrometer from shaded output.
- Ensure the filter jar contains `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory` and no bundled
  Kroxylicious/Kafka classes.
- Set version `0.1.0`, update the changelog/README, and add a release checklist.
- Run:
  * `mvn verify`;
  * `mvn verify -Psystem-tests` (with Docker);
  * formatter/import/license/checkstyle;
  * dependency analysis;
  * a smoke check that the packaged proxy discovers the plugin and the CLI runs.
- Do not publish to Maven Central or upstream coordinates in this commit.

Acceptance: the assembly can be installed into a Kroxylicious distribution's `classpath-plugins/` directory and used
with the example config; the full test matrix is green.
~~~

---

## 7. Traceability

| Requirement | Where addressed |
|---|---|
| R1 mechanisms | 5 (PLAIN), 6 (SCRAM), 9/10 (OAUTH) |
| R2 IANA names | 4, 6, 9 |
| R3 delegate to Kafka/JDK SASL | 5, 6, 9 |
| R4 fixed identity | 4, 5 |
| R5 subject identity | 4, 7, 8 |
| R6 principal type | 4 |
| R7 fail closed | 4, 7 |
| R8 subject change | 7, 11, 12 |
| R9 KeyStore | 2 |
| R10 PasswordProvider/PKCS12 | 2, 4 |
| R11 no plaintext YAML secrets | 2, 3, 4 |
| R12 versioned format/tooling | 2, 3 |
| R13 load once/no reload | 2, 4 |
| R14 permissions/no secret logging | 2, 14 |
| R15 trigger point/injection | 5 |
| R16 API versions | 5 |
| R17 challenge/response loops | 5, 6, 9 |
| R18 pipelining/backpressure | 5, 11, 12 |
| R19 reject client SASL | 5, 8 |
| R20 generic broker failure | 5 |
| R21 KIP-368 | 11, 12 |
| R22 preserve subject | 4, 7, 14 |
| R23 composition | 8 |
| R24 chain order docs/detection | 8, 15 |
| R25 routing | 13 |
| R26 observability | 14 |
| R27 startup validation | 4, 9 |
| R28 documentation | 15 |
| S1 secrets | 2, 9, 14 |
| S2 PLAIN/TLS warning | 15 |
| S3 trusted subject | 4, 7 |
| S4 KeyStore allow-list | 2, 7 |
| S5 subject change | 7, 11, 12 |
| S6 generic errors | 5, 9 |
| S7 permissions | 2 |
| S8 caching bounds | 9 |
| S9 heap risk | 2, 15 |
| S10 no enumeration defence | 7, 15 |
| O1 PKCS12 | 2 |
| O2 CLI | 3 |
| O3 password files | 2, 3 |
| O4 no hot reload | 2, 15 |
| O5 fail fast | 4 |
| O6 Operator docs | 15 |
| Q1 API baseline | 1, 2 |
| Q2 broker/API range | 1, 5 |
| Q3 post-auth cost | 5, 7, 14 |
| Q4 unit/protocol/real Kafka | all feature commits |
| Q5 Kroxylicious conventions | 1 |

---

## 8. Risks, open questions and follow-ups

### 8.1 Open questions resolved by this plan

1. **Baseline.** Pin Kroxylicious 0.26.0, JUnit extension 0.16.0, Kafka 4.3.2, Java 21. Update only in a dedicated commit
   if 0.27.0 is released.
2. **Reauthentication execution.** The scheduled task only arms `reauthDue`; reauthentication runs at the next request
   boundary. This avoids storing a per-frame `FilterContext` and avoids I/O from a stale connection context. Active
   connections reauthenticate before broker expiry; idle connections may be closed by the broker. If strict
   timer-initiated reauth is required, it needs a runtime connection-lifecycle/close API and should be a separate design
   change.
3. **OAuth fixed token file.** A fixed `file:` token has no KeyStore entry, so it is trusted as an operator-controlled
   secret and is not subject-mapped. Subject mode and fixed client-credentials entries verify `expectedSubject`. This
   should be called out in docs.
4. **`identity.key` in fixed token-file mode.** It is optional because there is no KeyStore lookup; use the internal key
   `fixed` for cache/metrics. In fixed KeyStore modes it is required.
5. **KeyStore permission escape hatch.** Use a clearly named environment variable such as
   `KROXYLICIOUS_SASL_INITIATION_ALLOW_INSECURE_PERMISSIONS=true`, documented for Kubernetes/OpenShift. Do not enable it
   by default.
6. **OAuth token cache.** Use an internal bounded cache (maximum 1024, expiry with safety margin, single-flight) rather
   than adding Caffeine, to keep the plugin dependency set small.
7. **Reauth jitter.** `windowFactor` default 0.8 with uniform ±0.05 jitter, clamped to [0.5, 0.95]. This is earlier than
   Kafka's 85–95% window and deliberately conservative.
8. **Client SASL errors.** `UNSUPPORTED_SASL_MECHANISM` for client handshake; `ILLEGAL_SASL_STATE` for client
   authenticate. Upstream failures always use `UNKNOWN_SERVER_ERROR`.
9. **SaslTermination PLAIN.** Released `SaslTermination` supports SCRAM/OAUTH, not PLAIN. The composition matrix tests
   released SCRAM termination only and does not add a test-only PLAIN terminator. Covering PLAIN termination would
   require such a filter or an upstream change.
10. **System test architecture.** Use a Testcontainers Kafka plus a real Kroxylicious distribution subprocess, rather
    than Strimzi/Kubernetes. This tests packaging, plugin discovery, config, CLI and networking without requiring a
    cluster. Add a Kubernetes/Operator system test later if the filter is upstreamed.

### 8.2 Known risks

* **Filter-chain misuse.** The filter can reject client SASL frames but cannot validate that a later filter will not
  intercept its own SASL frames. Documentation and composition ITs are mandatory.
* **Post-auth deserialization cost.** D21 requires intercepting every request for subject-change detection and reauth.
  Measure before optimizing; a runtime subject-change notification would allow a cheaper mode later.
* **Identity-change security.** Subject change detection must be tested during initial auth, normal operation and
  reauth. A missed change is a security bug.
* **OAuth identity semantics.** Client-credentials tokens identify the OAuth client, not necessarily the downstream user.
  Expected-subject mapping is deployment-defined; token exchange remains out of scope.
* **KeyStore plaintext in memory.** The proxy must hold plaintext credentials/tokens in memory. Document the residual
  risk; the destroyable-secret wrapper only reduces avoidable copies.
* **Pipelined frames during auth.** The filter relies on runtime backpressure and keeps no request queue.
  Commit 12's `SaslInitiationPipeliningIT` pipelines 400 metadata requests while a delayed `SaslAuthenticate` keeps the
  deferred stage open. It confirms that only the in-flight request is dispatched, no business request reaches the broker
  before authentication or reauthentication completes, and requests are forwarded in order after release. The runtime
  still decodes frames already present in the Netty read buffer and chains them in `FilterHandler.readFuture`; that
  memory is bounded by the read/socket buffer and the deferred-stage timeout, not by request count. Revisit if a runtime
  read-batch or byte limit is introduced; do not add a filter-level queue.
* **Kafka API versions.** The filter requires handshake v1+ and authenticate v1+ (for session lifetime). Kafka 4.0+ is
  the supported floor. Test the floor in the nightly compatibility job.
* **Secret leakage via errors.** Only log sanitized broker error codes/messages; never forward broker error text.

### 8.3 Follow-ups (not v1)

* Public credential-store SPI (`SaslInitiationCredentialStore`), including async lookup and lifecycle.
* Token exchange/impersonation (RFC 8693/MDS) for true per-user OAuth.
* Per-subject static OAuth tokens.
* Hot KeyStore reload/rotation.
* Runtime connection-lifecycle hook to initiate immediately and to close from a timer.
* Runtime subject-change notification to avoid intercepting every post-auth request.
* Combined `SaslTerminationAndInitiation` filter or shared authentication-outcome notification for SASL-specific client
  errors.
* Kubernetes Operator/Secret templating integration and a Strimzi-based system test.
* Performance benchmarks for post-auth interception and reauth storms.

---

## 9. Appendix — Test matrix and example configuration

### 9.1 Test matrix (minimum before v1)

| # | Test | Layer | Commit |
|---|---|---|---|
| 1 | Plugin discovery + no-op pass-through | unit + IT | 1 |
| 2 | KeyStore JSON/alias/permissions/secrets | unit | 2 |
| 3 | CLI create/add/update/remove/list | unit/CLI | 3 |
| 4 | Config validation + fixed/subject selectors | unit | 4 |
| 5 | PLAIN fixed identity happy path | protocol + IT | 5 |
| 6 | PLAIN failures, client SASL rejection, ApiVersions fallback | protocol | 5 |
| 7 | Pipelining during auth (stage incomplete, no buffer) | protocol | 5 |
| 8 | SCRAM-256/512 fixed identity | protocol + IT | 6 |
| 9 | Subject mode + mapped username + fail closed | protocol + IT | 7 |
| 10 | Subject change after auth (generic error + close; fixed mode unaffected) | protocol + IT | 7, 12 |
| 11 | SaslTermination SCRAM -> upstream PLAIN/SCRAM | IT | 8 |
| 12 | mTLS -> upstream SCRAM | IT | 8 |
| 13 | Chain order/misorder + passthrough rejection | IT | 8 |
| 14 | OAuth config/token service/cache | unit | 9 |
| 15 | OAuth fixed token file/client credentials | IT | 10 |
| 16 | OAuth subject mode + expected subject | IT | 10 |
| 17 | Reauth deadline/jitter/fresh client/subject guard | unit/protocol | 11 |
| 18 | Reauth against real Kafka with short lifetime | IT | 12 |
| 19 | Pipelining/backpressure during auth and reauth | protocol + IT | 5, 12 |
| 20 | Routing per-leaf-route credentials | IT | 13 |
| 21 | Metrics/log redaction | unit + IT | 14 |
| 22 | Docs/examples validated | unit/docs | 15 |
| 23 | Packaged proxy + CLI + Kafka container smoke | system | 16 |
| 24 | Subject/mTLS/reauth/failure system tests | system | 17 |
| 25 | Release assembly/plugin discovery | system/packaging | 18 |

### 9.2 Minimal fixed-identity configuration

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-256
      identity:
        mode: fixed
        key: proxy-service
      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
      reauth:
        windowFactor: 0.8

virtualClusters:
  - name: demo
    target:
      cluster: demo-cluster
    gateways:
      - name: default
        portIdentifiesNode:
          bootstrapAddress: localhost:9192
    filters:
      - sasl-initiation
```

### 9.3 Minimal subject-identity configuration

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-512
      identity:
        mode: subject
        principalType: io.kroxylicious.proxy.authentication.User
      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
```

### 9.4 OAUTHBEARER sketch

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: OAUTHBEARER
      identity:
        mode: subject
        principalType: io.kroxylicious.proxy.authentication.User
      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
      oauthBearer:
        tokenEndpointUrl: https://idp.example.com/token
        scope: kafka
        jwtRetriever: org.apache.kafka.common.security.oauthbearer.ClientCredentialsJwtRetriever
        subjectClaimName: sub
```

The KeyStore entry:

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

### 9.5 CLI sketch

```shell
sasl-initiation-credential-tool create --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password

sasl-initiation-credential-tool add-password --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --subject alice --username svc-alice --password-file /run/secrets/alice.password

sasl-initiation-credential-tool list --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password
```
