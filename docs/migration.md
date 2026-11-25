# Migration from the test-only `SaslPlainInitiation`

The Kroxylicious integration-test suite contains a test-only `SaslPlainInitiation` filter. It
demonstrates injecting a PLAIN exchange into the upstream connection, but it is not a production
feature:

* it supports only PLAIN;
* it stores broker credentials in the proxy configuration;
* it has no reauthentication;
* it has no subject-derived identity selection;
* its lifecycle and error semantics are test-oriented.

This release replaces it with the `SaslInitiation` filter. There is no wire-protocol compatibility
requirement between the two filters; migrate the configuration and credentials.

## Migration steps

### 1. Create the initiation KeyStore

Do not copy a `SaslTermination` SCRAM store. Create a dedicated PKCS12 store:

```shell
printf '%s\n' "$STORE_PASSWORD" > /etc/kroxylicious/sasl-initiation.p12.password
chmod 600 /etc/kroxylicious/sasl-initiation.p12.password

sasl-initiation-credential-tool create \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password

printf '%s\n' "$OLD_BROKER_PASSWORD" > /etc/kroxylicious/broker-password
chmod 600 /etc/kroxylicious/broker-password

sasl-initiation-credential-tool add-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject proxy-service \
  --username "$OLD_BROKER_USERNAME" \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/broker-password
```

Choose a lookup key (`proxy-service` above). It need not equal the broker username. In fixed mode
the same key goes in `identity.key`.

### 2. Replace the filter definition

If the old test-only configuration looked like this:

```yaml
filterDefinitions:
  - name: sasl-plain-initiation
    type: SaslPlainInitiation
    config:
      username: svc-proxy
      password: old-inline-password
```

replace it with:

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: PLAIN
      identity:
        mode: fixed
        key: proxy-service
      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
```

The old inline password is no longer accepted. Delete it from the YAML and from any ConfigMap,
helm values, environment variable or source repository that held it. Rotate the broker password if
it was exposed.

### 3. Keep, or change, the chain position

The production filter has the same upstream placement requirement: it must be last, closest to the
broker. If the old test filter was configured next to other SASL filters, verify the order from
[Deployment and chain order](deployment.md).

### 4. Add reauthentication if the broker requests it

No configuration is required for the default proactive reauthentication. It activates when the
broker reports a positive `sessionLifetimeMs`, at a jittered 80% of the effective lifetime. Tune it
only if needed:

```yaml
reauth:
  windowFactor: 0.8
```

### 5. Restart and verify

Restart all proxy instances so the new plugin and KeyStore are loaded. Verify:

* a produce/consume round trip through the proxy;
* an `INFO` "SASL initiation authenticated the upstream connection" log event;
* no `auth-failure` increase in `connection_closed_total`;
* broker-side authorization still gives the expected identity access.

## Behaviour changes to expect

| Area | Test-only `SaslPlainInitiation` | `SaslInitiation` |
| --- | --- | --- |
| Mechanisms | PLAIN only | PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER |
| Credentials | Inline in YAML | PKCS12 KeyStore, never broker secrets in YAML |
| Identity | One fixed identity | Fixed or subject-derived, with keyed username mapping |
| Subject mode | Not available | Available with fail-closed semantics |
| Reauthentication | None | Proactive KIP-368 with jitter |
| Client SASL | Test-oriented | Explicitly rejected if it reaches the initiator |
| Failure details | Test-oriented | Generic client error, sanitized proxy logs |
| Rotation | Edit config/restart | Update KeyStore and restart; no hot reload |
| Multiple mechanisms | No | One per filter instance; use separate definitions for different mechanisms |

## Coexistence and rollback

The two filter types are distinct. Do not run both on the same target connection: each would try to
drive the upstream SASL exchange.

For a staged migration, deploy the new filter under a new virtual cluster or route, verify it, then
move clients. Once the old test filter is removed from the configuration and no process references
it, the inline broker password should be rotated because it was stored in configuration.
