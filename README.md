# Kroxylicious SASL Initiation

A standalone [Kroxylicious](https://kroxylicious.io) filter plugin that authenticates the proxy to an
upstream Apache Kafka broker using SASL.

The first release supports `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` and `OAUTHBEARER`, fixed and
subject-derived identities, a PKCS12 credential store with a management CLI, KIP-368
reauthentication, bounded metrics and structured logs. It targets Kroxylicious `0.26.0`, Kafka
clients `4.3.2`, Kafka brokers `4.0+` and Java 21.

## Documentation

* [Concepts: what SASL initiation is and where it sits](docs/concepts.md)
* [Configuration reference](docs/configuration.md)
* [KeyStore and CLI operations, permissions and rotation](docs/operations.md)
* [Deployment, chain order, mTLS and routing](docs/deployment.md)
* [Security](docs/security.md)
* [Failure semantics and observability](docs/observability.md)
* [Migration from the test-only `SaslPlainInitiation`](docs/migration.md)
* [Packaged proxy system tests](docs/system-tests.md)
* [Example YAML files](docs/examples/)

## Requirements

- Java 21
- Maven 3.9 or later to build from source
- A Kroxylicious 0.26.0 runtime
- Kafka 4.0 or later brokers

## Modules

| Module | Purpose |
| --- | --- |
| `kroxylicious-sasl-initiation-credentials` | PKCS12 credential store, credential model, secret handling and file permissions. |
| `kroxylicious-sasl-initiation` | The `SaslInitiation` filter plugin and its configuration. |
| `kroxylicious-sasl-initiation-credential-tool` | CLI for creating and maintaining initiation credentials. |
| `kroxylicious-sasl-initiation-integration-tests` | Integration tests against real Kafka brokers. |
| `kroxylicious-sasl-initiation-system-tests` | Black-box tests of the packaged proxy, Docker Kafka and the CLI. |

The parent project is `kroxylicious-sasl-initiation-parent`
(`io.github.tombentley.kroxylicious.sasl:0.1.0-SNAPSHOT`). The Kroxylicious parent POM is
deliberately not used, so the build is self-contained.

## Maven Central

Release artifacts are published to Maven Central under the `io.github.tombentley.kroxylicious.sasl`
groupId. The parent POM, credentials module, filter plugin and credential tool are published; the
integration-tests and system-tests modules are not.

To consume the filter from a Maven build:

```xml
<dependency>
    <groupId>io.github.tombentley.kroxylicious.sasl</groupId>
    <artifactId>kroxylicious-sasl-initiation</artifactId>
    <version>0.1.0</version>
</dependency>
```

The filter depends on `kroxylicious-sasl-initiation-credentials`, which Maven resolves
transitively. The CLI is published as
`io.github.tombentley.kroxylicious.sasl:kroxylicious-sasl-initiation-credential-tool`. The filter
and the CLI declare their Kroxylicious, Kafka, Jackson and SLF4J dependencies as `provided` because
the Kroxylicious runtime supplies them.

See [.github/README.md](.github/README.md) for the one-time publishing setup and the release
workflow.

## Quick start

### 1. Get the CLI

A release distribution provides a `sasl-initiation-credential-tool` launcher. From a source checkout,
build the modules and define a helper:

```shell
mvn -q -DskipTests -DskipITs install
mvn -q -pl kroxylicious-sasl-initiation-credential-tool \
  dependency:build-classpath -Dmdep.outputFile=target/cli-classpath.txt

sasl-initiation-credential-tool() {
  java -cp "kroxylicious-sasl-initiation-credential-tool/target/kroxylicious-sasl-initiation-credential-tool-0.1.0-SNAPSHOT-all.jar:$(cat kroxylicious-sasl-initiation-credential-tool/target/cli-classpath.txt)" \
    io.github.tombentley.kroxylicious.filter.sasl.initiation.cli.SaslInitiationCredentialTool "$@"
}
```

The CLI needs the Kroxylicious, Jackson and SLF4J runtime jars; the distribution launcher already
supplies them. See [KeyStore and CLI operations](docs/operations.md) for the full option reference.

### 2. Create the credential store

```shell
printf '%s\n' "$STORE_PASSWORD" > /etc/kroxylicious/sasl-initiation.p12.password
chmod 600 /etc/kroxylicious/sasl-initiation.p12.password

sasl-initiation-credential-tool create \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password

printf '%s\n' "$BROKER_PASSWORD" > /etc/kroxylicious/broker-password
chmod 600 /etc/kroxylicious/broker-password

sasl-initiation-credential-tool add-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject proxy-service \
  --username svc-proxy \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/broker-password
```

Never put broker passwords in the Kroxylicious YAML.

### 3. Configure the filter

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

Put the filter last on the virtual cluster's chain, closest to the broker:

```yaml
virtualClusters:
  - name: demo
    target:
      cluster: kafka
    filters:
      - sasl-initiation
    gateways:
      - name: default
        portIdentifiesNode:
          bootstrapAddress: localhost:9192
```

Use TLS on the upstream cluster, especially with `PLAIN`. See the
[configuration reference](docs/configuration.md) and the
[examples](docs/examples/).

### 4. Operate it

* Rotate credentials by updating the KeyStore and restarting the proxy. There is no hot reload.
* Keep the store and password file owner-only (`0600`). Kubernetes/OpenShift Secret volumes may need
  the documented permission escape hatch.
* Watch `kroxylicious_filter_sasl_initiation_auth_attempts_total`,
  `..._reauth_attempts_total`, and `..._connection_closed_total` for failures.

## Composition and chain order

Client-facing authentication must happen before SASL initiation, from the client towards the broker:

```text
client -> ... -> SaslTermination (optional) -> ... -> SaslInitiation (last) -> broker
```

* `SaslTermination` must see and terminate the client's `SaslHandshake`/`SaslAuthenticate` frames.
* `SaslInitiation` must be last, so its own upstream SASL frames are not intercepted by another SASL
  filter.
* An anonymous or mTLS-authenticated client can go directly to `SaslInitiation`; no client SASL
  termination is required.
* If client SASL frames reach `SaslInitiation`, the filter rejects them with
  `UNSUPPORTED_SASL_MECHANISM` (handshake) or `ILLEGAL_SASL_STATE` (authenticate) and closes the
  connection. This is a misconfiguration, not a supported passthrough mode.
* `SaslInspection` passthrough is incompatible. It can coexist only if another filter terminates
  client SASL before the initiator.

Use a separate credential store for initiation credentials and for any client-facing SCRAM
credential store.

### Routing

When the virtual cluster uses a router, configure `SaslInitiation` on each **leaf route's** filter
chain, not on the virtual-cluster filter chain. Each leaf route then authenticates its own upstream
connection and can use its own mechanism and credential store:

```yaml
routerDefinitions:
  - name: leaf-router
    type: com.example.router.FanOutRouter
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
    # Client-facing filters may go here, but not SaslInitiation.
    filters: [sasl-termination]
```

A virtual-cluster-level initiator is **not** a supported routing placement. It runs before the
router selects a target, so it cannot authenticate every leaf route and its internal SASL frames can
go to the wrong upstream (or to no target). The runtime does not currently reject this
configuration. Routes that resolve to the same upstream address can share a connection and therefore
cannot have independent per-route credentials.

## Building

```shell
mvn verify
```

This compiles all modules, runs unit tests (`*Test` via Surefire), runs integration tests (`*IT` via
Failsafe), and checks formatting, import order, license headers and Checkstyle rules.

Static analysis is opt-in because it is slower:

```shell
mvn -Pspotbugs verify
```

The `spotbugs` profile runs SpotBugs at maximum effort with the low threshold and fails the build on
any finding in production classes. CI runs this profile as well.

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
[`kroxylicious-testing`](https://github.com/kroxylicious/kroxylicious-junit5-extension), so Docker is
not required for the plaintext smoke test. Pass `-DskipITs=true` to skip integration tests, or
`-DskipUTs=true` to skip unit tests.

### System tests

The black-box system tests run the packaged Kroxylicious distribution with a Docker Kafka broker.
They are opt-in and skipped by default:

```shell
mvn -Psystem-tests \
  -pl kroxylicious-sasl-initiation-system-tests -am \
  -DskipUTs=true \
  verify
```

Docker is required. The harness downloads and verifies the pinned Kroxylicious 0.26.0 distribution,
unpacks it into `target/kroxylicious`, generates a PKCS12 credential store with the CLI, and starts
the proxy as a subprocess. To use a different Kafka broker version, add
`-Dkafka.container.version=4.3.1` or `-Dkafka.container.image=...`. See
[docs/system-tests.md](docs/system-tests.md) for the local distribution and troubleshooting options.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
