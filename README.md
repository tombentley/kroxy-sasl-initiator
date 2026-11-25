# Kroxylicious SASL Initiation

A standalone [Kroxylicious](https://kroxylicious.io) filter plugin that authenticates the proxy to an
upstream Apache Kafka broker using SASL.

The project currently implements PKCS12 credential storage, the credential-management CLI, fixed and subject-derived
identity selection, and PLAIN/SCRAM-SHA-256/SCRAM-SHA-512 initiation against a real Kafka broker. OAUTHBEARER and
KIP-368 reauthentication arrive in later commits.

## Requirements

- Java 21
- Maven 3.9 or later

## Modules

| Module | Purpose |
| --- | --- |
| `kroxylicious-sasl-initiation-credentials` | PKCS12 credential store, credential model and secret handling (future commits). |
| `kroxylicious-sasl-initiation` | The `SaslInitiation` filter plugin and its configuration. |
| `kroxylicious-sasl-initiation-credential-tool` | Command line tooling for managing initiation credentials (future commits). |
| `kroxylicious-sasl-initiation-integration-tests` | Integration tests that run against a real Kafka broker. |

The parent project is `kroxylicious-sasl-initiation-parent` (`com.github.tombentley.kroxylicious.sasl:0.1.0-SNAPSHOT`). The filter
targets Kroxylicious `0.26.0` and Kafka clients `4.3.2`. The Kroxylicious parent POM is deliberately not used, so
the build is self-contained.

## Building

```shell
mvn verify
```

This compiles all modules, runs unit tests (`*Test` via Surefire), runs integration tests (`*IT` via Failsafe), and
checks formatting, import order, license headers and Checkstyle rules.

Static analysis is opt-in because it is slower:

```shell
mvn -Pspotbugs verify
```

The `spotbugs` profile runs SpotBugs at maximum effort with the low threshold and fails the build on any finding in
production classes. CI runs this profile as well.

Formatting and license checks are validation-only by default. To apply the fixes locally:

```shell
mvn -Pformat verify
```

## Running tests

Unit tests only:

```shell
mvn test
```

Integration tests only (after the modules are installed or from the reactor root):

```shell
mvn -pl kroxylicious-sasl-initiation-integration-tests -am verify
```

The integration tests use the in-VM Kafka broker from
[`kroxylicious-testing`](https://github.com/kroxylicious/kroxylicious-junit5-extension), so Docker is not required for
the plaintext smoke test. Pass `-DskipITs=true` to skip integration tests, or `-DskipUTs=true` to skip unit tests.

## Using the filter

The plugin is registered through `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory`. A minimal filter
definition looks like this:

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
```

Create the PKCS12 store with `sasl-initiation-credential-tool`; do not put broker passwords directly in the proxy YAML.

## Composition and chain order

Client-facing authentication must happen before SASL initiation, from the client towards the broker:

```text
client -> ... -> SaslTermination (optional) -> ... -> SaslInitiation (last) -> broker
```

* `SaslTermination` must see and terminate the client's `SaslHandshake`/`SaslAuthenticate` frames.
* `SaslInitiation` must be last, so its own upstream SASL frames are not intercepted by another SASL filter.
* An anonymous or mTLS-authenticated client can go directly to `SaslInitiation`; no client SASL termination is required.
* If client SASL frames reach `SaslInitiation` (no termination filter, or `SaslInitiation` placed before
  `SaslTermination`), the filter rejects the handshake with `UNSUPPORTED_SASL_MECHANISM` and closes the connection.
  This is a misconfiguration, not a supported passthrough mode.

Use a separate credential store for initiation credentials and for any client-facing SCRAM credential store. The
integration-test composition matrix covers this separation, mapped identities, mechanism translation, mTLS, anonymous
clients, and the unsafe configurations above.

### Routing

When the virtual cluster uses a router, configure `SaslInitiation` on each **leaf route's** filter chain, not on the
virtual-cluster filter chain. Each leaf route then authenticates its own upstream connection and can use its own
credential store:

```yaml
filterDefinitions:
  - name: sasl-initiation-route-a
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-256
      identity:
        mode: fixed
        key: route-a-service
      keyStore:
        file: /etc/kroxylicious/route-a.p12
        filePassword:
          passwordFile: /etc/kroxylicious/route-a.p12.password

  - name: sasl-initiation-route-b
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-256
      identity:
        mode: fixed
        key: route-b-service
      keyStore:
        file: /etc/kroxylicious/route-b.p12
        filePassword:
          passwordFile: /etc/kroxylicious/route-b.p12.password

routerDefinitions:
  - name: leaf-router
    type: <router plugin type>
    config: {}
    routes:
      - name: route-a
        id: 0
        filters: [sasl-initiation-route-a]
        target:
          cluster: cluster-a
      - name: route-b
        id: 1
        filters: [sasl-initiation-route-b]
        target:
          cluster: cluster-b

virtualClusters:
  - name: demo
    target:
      router: leaf-router
    # Client-facing authentication may go here, but not SaslInitiation.
    filters: [sasl-termination]
    gateways:
      - name: default
        portIdentifiesNode:
          bootstrapAddress: localhost:9192
```

A virtual-cluster-level initiator is **not** a supported routing placement. It runs before the router selects a target,
so it cannot authenticate every leaf route and its internal SASL frames can go to the wrong upstream (or to no target).
The runtime does not currently reject this configuration. Use one leaf route per upstream connection; routes that
resolve to the same upstream address can share a connection and therefore cannot have independent per-route
credentials.

Kroxylicious 0.26.0 `SaslTermination` supports SCRAM and OAUTHBEARER, but not PLAIN. A client-facing PLAIN terminator is
therefore not tested; the composition tests use SCRAM client termination.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
