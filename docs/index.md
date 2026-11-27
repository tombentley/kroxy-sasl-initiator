# SASL Initiation documentation

This documentation describes the first release of the `SaslInitiation` filter. It is written for
Kroxylicious operators who need to configure, secure, run and troubleshoot upstream SASL
authentication.

Start here:

| Page | What it covers |
| --- | --- |
| [Concepts](concepts.md) | What SASL initiation is, where it sits in the chain, and how it differs from `SaslTermination` and `SaslInspection`. |
| [Configuration reference](configuration.md) | Every `SaslInitiationConfig` field, defaults, validation, mechanism and identity matrix, and limitations. |
| [KeyStore and CLI operations](operations.md) | Creating and maintaining the PKCS12 KeyStore, password workflows, file permissions, Kubernetes/OpenShift, and rotation by restart. |
| [Deployment and chain order](deployment.md) | Filter ordering, composition with client authentication, mTLS, and per-route routing placement. |
| [Security](security.md) | PLAIN over plaintext, KeyStore custody, JVM heap exposure, subject trust, generic errors and log hygiene. |
| [Failure semantics and observability](observability.md) | Client-visible failures, metrics, structured log keys and troubleshooting. |
| [Migration from `SaslPlainInitiation`](migration.md) | Moving from the test-only filter to the production filter. |
| [Packaged proxy system tests](system-tests.md) | Running the black-box tests against the released distribution, Docker and a real Kafka broker. |
| [Examples](examples/) | Complete YAML examples for fixed/subject identity, PLAIN/SCRAM/OAUTHBEARER, mTLS and routing. |

## First-release scope

* Mechanisms: `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`, `OAUTHBEARER`.
* Identity modes: fixed/shared identity and subject-derived identity, with no fallback.
* Credentials: a dedicated PKCS12 KeyStore containing versioned JSON entries.
* KIP-368 proactive reauthentication is supported.
* KeyStore contents are loaded once at startup. There is no hot reload; rotate by restart.
* Kafka 4.0 or later brokers. SASL handshake v1 and authentication v1 or later are required.

The filter authenticates the **proxy** to the broker. It does not terminate client SASL and does
not change the downstream client subject.
