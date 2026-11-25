# Configuration reference

The filter type is `SaslInitiation`. Its configuration record is
`com.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig`.

## Shape

```yaml
filterDefinitions:
  - name: sasl-initiation
    type: SaslInitiation
    config:
      mechanism: SCRAM-SHA-256

      identity:
        mode: subject          # fixed | subject
        # Fixed mode only:
        # key: proxy-service
        # Subject mode only:
        # principalType: io.kroxylicious.proxy.authentication.User

      keyStore:
        file: /etc/kroxylicious/sasl-initiation.p12
        filePassword:
          passwordFile: /etc/kroxylicious/sasl-initiation.p12.password

      # Only for mechanism: OAUTHBEARER
      # oauthBearer:
      #   tokenEndpointUrl: https://idp.example.com/token
      #   scope: kafka
      #   jwtRetriever: org.apache.kafka.common.security.oauthbearer.DefaultJwtRetriever
      #   subjectClaimName: sub

      reauth:
        windowFactor: 0.8
```

All nested groups are ordinary records. Unknown fields, missing required fields and invalid
combinations are rejected when the plugin is initialized, before the first client connection.

## Top-level fields

| Field | Required | Type | Default | Validation and meaning |
| --- | --- | --- | --- | --- |
| `mechanism` | Yes | string | — | Exactly one IANA mechanism name: `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` or `OAUTHBEARER`. Case-sensitive. No fallback, negotiation or retry with another mechanism. |
| `identity` | Yes | object | — | How the credential lookup key is selected. See [Identity fields](#identity-fields). |
| `keyStore` | Conditional | object | — | PKCS12 credential store. Required for every password mechanism and for OAuth client-credentials. Must be **omitted** for fixed-identity `OAUTHBEARER` with a `file:` token. See [KeyStore fields](#keystore-fields). |
| `oauthBearer` | Conditional | object | — | Required exactly when `mechanism` is `OAUTHBEARER`; rejected for PLAIN and SCRAM. See [OAuth fields](#oauth-fields). |
| `reauth` | No | object | `windowFactor: 0.8` | Optional KIP-368 reauthentication timing. See [Reauthentication](#reauthentication). |

Secrets do **not** belong in this configuration. Broker passwords and OAuth client secrets live in
the KeyStore. The only secret accepted here is the KeyStore password, through the
`PasswordProvider` in `keyStore.filePassword`.

## Identity fields

| Field | Required | Type | Default | Validation and meaning |
| --- | --- | --- | --- | --- |
| `identity.mode` | Yes | string | — | `fixed` or `subject`. Case-sensitive. |
| `identity.key` | Fixed mode only: yes; subject mode: forbidden | string | — | The KeyStore lookup key. It is not necessarily the broker username. In fixed mode it is required even when a fixed OAuth token file is used; there it also names the token-cache entry. Must not be blank. |
| `identity.principalType` | Subject mode only: no; fixed mode: forbidden | string (FQCN) | `io.kroxylicious.proxy.authentication.User` | The singular principal type whose name becomes the lookup key. The class must be on the classpath, implement `io.kroxylicious.identity.Principal`, and be a singular principal type (`@SingularPrincipal`/`@Unique`). |

### Fixed-mode lookup

`identity.key` must exist in the KeyStore unless the mode is fixed `OAUTHBEARER` with a trusted
token file (which has no KeyStore). Startup fails immediately if the KeyStore has no entry for the
key. The stored entry may contain a broker username different from the key.

### Subject-mode lookup

At the authentication trigger, the filter reads the client's current authenticated subject. It
requires a non-anonymous subject with exactly the configured singular principal type and uses that
principal's name as the KeyStore lookup key.

Fail-closed conditions:

* no authenticated subject or an anonymous subject;
* no principal of the configured type;
* no KeyStore entry for the selected name;
* a later subject change, including during reauthentication.

There is no fallback. The KeyStore is the allow-list; a client cannot choose an arbitrary alias.

## KeyStore fields

| Field | Required | Type | Default | Validation and meaning |
| --- | --- | --- | --- | --- |
| `keyStore.file` | Yes when `keyStore` is present | path string | — | Path to the PKCS12 store. Must exist, be a regular readable file, start with a PKCS12 header, and contain at least one valid entry. |
| `keyStore.filePassword` | Yes when `keyStore` is present | `PasswordProvider` | — | Password for the store and its entries. Production should use `passwordFile`; inline `password` is for development only. |

`PasswordProvider` forms used in the examples:

```yaml
keyStore:
  file: /etc/kroxylicious/sasl-initiation.p12
  filePassword:
    passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
```

```yaml
keyStore:
  file: ./local-development.p12
  filePassword:
    password: development-only-password
```

On POSIX, the store file and a `passwordFile` must have no group or other permissions. Use mode
`0600`. See [KeyStore and CLI operations](operations.md#file-permissions).

`keyStore` is not accepted for fixed-identity `OAUTHBEARER` with a `file:` token. A fixed HTTP
token endpoint and all subject-mode OAuth configurations require a KeyStore containing OAuth
client-credential entries.

## OAuth fields

`oauthBearer` is required exactly for `OAUTHBEARER`.

| Field | Required | Type | Default | Validation and meaning |
| --- | --- | --- | --- | --- |
| `oauthBearer.tokenEndpointUrl` | Yes | URI string | — | Token endpoint or token file. Scheme must be `file`, `http` or `https`. A `file:` URL must include a path and is valid only with fixed identity. An HTTP(S) URL must include a host. |
| `oauthBearer.scope` | No | string | none | OAuth scope sent to the token endpoint. Must not be blank when configured. |
| `oauthBearer.jwtRetriever` | No | string (FQCN) | `org.apache.kafka.common.security.oauthbearer.DefaultJwtRetriever` | Kafka `JwtRetriever` implementation. Must be on the classpath and implement `org.apache.kafka.common.security.oauthbearer.JwtRetriever`. The default selects the appropriate retriever from the endpoint URL. |
| `oauthBearer.subjectClaimName` | No | string | `sub` | Claim that contains the token subject. Must not be blank when configured. |

OAuth credential sources:

| Configuration | Credential source | Subject verification |
| --- | --- | --- |
| Fixed identity + `file:` token | Operator-controlled token file; no KeyStore entry. `identity.key` is still required as the stable cache key. | The token file is trusted and is not subject-mapped. |
| Fixed identity + HTTP(S) endpoint | OAuth `clientId`/`clientSecret` from the KeyStore entry for `identity.key`. | The token's configured subject claim must equal the entry's `expectedSubject`. |
| Subject identity + HTTP(S) endpoint | OAuth `clientId`/`clientSecret` from the KeyStore entry for the selected subject. | The token's configured subject claim must equal the selected subject or the entry's explicit `expectedSubject`. |

A `file:` token is invalid in subject mode. Token exchange/impersonation is not supported. Treat a
fixed token file as a shared service credential.

### OAuth token cache

Validated tokens are held in a shared bounded cache (maximum 1024 identities), keyed by lookup key.
Concurrent retrievals for one identity are coalesced. A token is refreshed a safety margin before
expiry (10% of remaining lifetime, capped at 60 seconds) and is never used after expiry. Token
retrieval runs on a worker executor, not on the connection's filter-dispatch thread.

## Reauthentication

| Field | Required | Type | Default | Validation and meaning |
| --- | --- | --- | --- | --- |
| `reauth.windowFactor` | No | number | `0.8` | Fraction of the effective session lifetime at which reauthentication is attempted. Must be finite and between `0.5` and `0.95` inclusive. |

The effective lifetime is the smaller positive value of:

* the broker-reported `sessionLifetimeMs` from the final `SaslAuthenticate` response;
* the remaining OAuth token lifetime, when using OAUTHBEARER.

A uniform jitter of ±0.05 is added to `windowFactor`, then the result is clamped to
`[0.5, 0.95]`. If there is no positive lifetime, no reauthentication is scheduled.

The one-shot scheduler only marks reauthentication as due. The exchange starts at the next request
boundary before that request is forwarded. If reauthentication has not completed before the hard
deadline (the effective lifetime), the connection fails closed. Idle connections may be closed by
the broker at session expiry.

Reauthentication reuses the original identity and credential and does not send `ApiVersions`
again. A subject change before or during reauthentication fails closed; the filter never retries
as the new identity.

## Mechanism and identity support matrix

| Mechanism | Credential kind | Fixed identity | Subject identity | KeyStore |
| --- | --- | --- | --- | --- |
| `PLAIN` | username + password | Yes | Yes | Required |
| `SCRAM-SHA-256` | username + password | Yes | Yes | Required |
| `SCRAM-SHA-512` | username + password | Yes | Yes | Required |
| `OAUTHBEARER` | token file | Yes | No | Must be omitted |
| `OAUTHBEARER` | OAuth client credentials | Yes | Yes | Required (OAuth entries) |

Mechanism translation is supported: the client-facing mechanism (mTLS, `SaslTermination` SCRAM,
`SaslTermination` OAUTHBEARER or anonymous) is independent of the broker-facing mechanism.

## Validation and startup behaviour

The following are validated during plugin initialization, so a misconfiguration fails at startup
rather than on the first client connection:

* the mechanism and identity mode are present and supported;
* `identity.key` is present in fixed mode and forbidden in subject mode;
* `identity.principalType` is a resolvable, singular principal type;
* `keyStore` is present or absent as required by the mechanism and OAuth source;
* `keyStore.file` and `keyStore.filePassword` are present and the store is readable;
* the store is PKCS12, non-empty and every entry has the expected credential kind;
* every alias equals the SHA-256 hash of its entry subject and subjects are unique;
* fixed-mode lookup succeeds;
* OAuth fields and URL schemes are valid and the retriever class is available;
* `reauth.windowFactor` is in range;
* file permissions are owner-only where required, unless the documented escape hatch is set.

## Limitations

* One mechanism per filter instance. The filter sends exactly one `SaslHandshake`; a broker
  rejection is terminal and does not trigger a second handshake with another mechanism.
* One password per identity. Different passwords for different mechanisms require separate stores
  and filter definitions.
* Separate stores are required for `SaslTermination` and `SaslInitiation`; the entry models and
  credential kinds differ.
* No identity fallback. A missing or ineligible subject fails closed.
* No token exchange or per-user OAuth impersonation.
* No hot reload. Credentials are loaded once at startup; rotate by restart.
* No public credential-store SPI, HSM/KMS store, GSSAPI or delegation-token support.
* The filter does not configure upstream TLS. Configure TLS on the target cluster separately.

## Examples

* [Fixed identity with PLAIN](examples/fixed-plain.yaml)
* [Fixed identity with SCRAM](examples/fixed-scram.yaml)
* [Subject identity with SCRAM and `SaslTermination`](examples/subject-scram.yaml)
* [Fixed identity with an OAuth token file](examples/oauth-fixed-token.yaml)
* [Subject identity with OAuth client credentials](examples/oauth-subject-client-credentials.yaml)
* [mTLS client with subject-derived SCRAM](examples/mtls-subject-scram.yaml)
* [Routing with one initiator per leaf route](examples/routing-two-routes.yaml)
