# Packaged proxy system tests

The `kroxylicious-sasl-initiation-system-tests` module tests the filter as a real deployment: a
Kafka broker in a container, the released Kroxylicious distribution on its `classpath-plugins` path,
a configuration file, a CLI-created PKCS12 credential store, the proxy as a subprocess, and ordinary
Kafka producer/consumer clients. The tests never link against the production filter classes.

The module is not part of the default reactor. Running `mvn verify` does not need Docker and does
not run these tests.

## Prerequisites

* Java 21.
* Maven 3.9 or later.
* A working Docker daemon. Testcontainers uses the standard Docker socket. On Podman hosts, point
  `DOCKER_HOST` at a compatible socket or use a Docker-compatible VM.
* Network access to the GitHub release page for the pinned Kroxylicious distribution, unless a local
  distribution is supplied.

## Running the tests

From the repository root:

```shell
mvn -Psystem-tests \
  -pl kroxylicious-sasl-initiation-system-tests -am \
  -DskipUTs=true \
  verify
```

The `-Psystem-tests` profile adds the module to the reactor. Failsafe runs classes matching
`*SystemIT`. Unit tests in the dependency modules are skipped by `-DskipUTs=true`; remove it to run
them as well.

When Docker is unavailable the tests are skipped with a clear assumption failure rather than
failing the build. The nightly/manual `system-tests` GitHub Actions job runs the same command with
Docker available.

## What the harness does

For each test run the harness:

1. Resolves the Kroxylicious distribution:
   * by default, downloads `kroxylicious-app-0.26.0-bin.tar.gz` from the GitHub release;
   * verifies it against the pinned SHA-256 checksum;
   * unpacks it into `kroxylicious-sasl-initiation-system-tests/target/kroxylicious`.
2. Copies the built filter, credentials and credential-tool jars into
   `target/kroxylicious/classpath-plugins/sasl-initiation/`.
3. Starts a single-node KRaft Kafka container from `apache/kafka:4.3.2` with:
   * a `SASL_PLAINTEXT` listener exposed to the host;
   * a `PLAIN` user and a `SCRAM-SHA-256` user;
   * PLAINTEXT inter-broker and controller listeners.
4. Creates a PKCS12 store with the packaged CLI and writes the store password to a `passwordFile`.
5. Writes a proxy YAML file containing a `SaslInitiation` `filterDefinitions` entry, a cluster
   definition pointing at the Kafka container, a virtual cluster and a management endpoint, then
   starts `bin/kroxylicious-start.sh --config <file>`.
6. Waits for the proxy bootstrap port, creates a topic, produces and consumes through the proxy,
   stops the proxy and captures stdout/stderr.

The test methods cover fixed identity with `PLAIN`, fixed identity with `SCRAM-SHA-256`, producing
and consuming multiple records, and log hygiene. The log-hygiene test asserts that the broker
passwords and the credential-store password never appear in the proxy stdout/stderr.

## Pointing the tests at a different Kafka version

The broker image version defaults to the project's `kafka.version` property (`4.3.2`). Override the
image tag without changing the client dependency:

```shell
mvn -Psystem-tests \
  -pl kroxylicious-sasl-initiation-system-tests -am \
  -DskipUTs=true \
  -Dkafka.container.version=4.3.1 \
  verify
```

Or supply a complete image reference, for example to use a mirrored registry:

```shell
mvn -Psystem-tests \
  -pl kroxylicious-sasl-initiation-system-tests -am \
  -DskipUTs=true \
  -Dkafka.container.image=registry.example.com/apache/kafka:4.3.2 \
  verify
```

The filter supports Kafka brokers 4.0 and later. Older broker versions are outside the compatibility
matrix.

## Using a local Kroxylicious distribution

Set `kroxylicious.distribution` to an unpacked distribution directory or to a `tar.gz` file:

```shell
mvn -Psystem-tests \
  -pl kroxylicious-sasl-initiation-system-tests -am \
  -DskipUTs=true \
  -Dkroxylicious.distribution=/opt/kroxylicious-app-0.26.0-bin.tar.gz \
  verify
```

A `tar.gz` is unpacked into `target/kroxylicious`; an unpacked directory is used in place and must be
writable so that the harness can add `classpath-plugins/sasl-initiation/`. When the archive is for a
version other than the default, also supply its checksum:

```shell
-Dkroxylicious.distribution.sha256=<sha256>
```

The default checksum is pinned to the published `0.26.0` release artifact. If no checksum is
configured for a non-default version, the harness fails rather than downloading unverified code.

## Diagnostics

The config, proxy stdout/stderr, CLI output and generated credential files are written to the JUnit
temporary directory for each test. On success JUnit removes the directory; on failure it is
retained so that the logs can be inspected. Set `-Dkafka.container.image` to a known-good image and
check `docker version` first if the container cannot start.

The proxy log configuration used by the harness enables `DEBUG` logging for
`io.github.tombentley`, so the log-hygiene assertions also cover debug output from the filter.
