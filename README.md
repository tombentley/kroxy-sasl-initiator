# Kroxylicious SASL Initiation

A standalone [Kroxylicious](https://kroxylicious.io) filter plugin that authenticates the proxy to an
upstream Apache Kafka broker using SASL.

This repository is at the bootstrap stage. The current commit establishes the Maven multi-module project, pins the
supported dependency baseline, and provides a no-op `SaslInitiation` filter that proves plugin discovery and the
proxy integration-test harness work end to end. Credential storage, identity selection, the SASL protocol state
machine and reauthentication arrive in later commits.

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
      mechanism: PLAIN
```

At this stage the filter forwards every request and response unchanged; `mechanism` is validated as non-empty but is
not yet used to authenticate.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
