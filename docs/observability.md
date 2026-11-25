# Failure semantics and observability

## Failure semantics

Upstream authentication failures are deliberately opaque to clients.

| Condition | Client sees | Connection | Metric/log signal |
| --- | --- | --- | --- |
| Client sends `SaslHandshake` to the initiator | `UNSUPPORTED_SASL_MECHANISM` | Close | `connection_closed_total{reason="client-sasl-frame"}`; WARN "Rejecting client-originated SASL frame" |
| Client sends `SaslAuthenticate` to the initiator | `ILLEGAL_SASL_STATE` | Close | `connection_closed_total{reason="client-sasl-frame"}`; WARN "Rejecting client-originated SASL frame" |
| Broker rejects the configured mechanism | `UNKNOWN_SERVER_ERROR` | Close | `auth_attempts_total{outcome="failure"}`, `connection_closed_total{reason="auth-failure"}`; WARN with `brokerErrorCode` and `enabledMechanisms` |
| Broker rejects the credential | `UNKNOWN_SERVER_ERROR` | Close | `auth_attempts_total{outcome="failure"}`, `connection_closed_total{reason="auth-failure"}`; WARN with `brokerErrorCode` |
| No authenticated subject / anonymous subject | `UNKNOWN_SERVER_ERROR` | Close | authentication failure metrics; WARN "could not select a broker identity" |
| Configured principal type absent from subject | `UNKNOWN_SERVER_ERROR` | Close | authentication failure metrics; WARN identity-selection failure |
| Missing KeyStore entry | `UNKNOWN_SERVER_ERROR` | Close | authentication failure metrics; WARN "could not select a usable broker credential" |
| OAuth token retrieval or validation fails | `UNKNOWN_SERVER_ERROR` | Close | `token_retrieval_duration_seconds{outcome="failure"}` plus authentication failure metrics |
| Token subject does not match `expectedSubject` | `UNKNOWN_SERVER_ERROR` | Close | token retrieval failure metric; WARN "The retrieved OAuth token subject does not match the expected subject" |
| Upstream timeout/network failure | `UNKNOWN_SERVER_ERROR` | Close | authentication failure metrics; WARN "SASL initiation failed" |
| Subject changed after authentication | `UNKNOWN_SERVER_ERROR` | Close | `connection_closed_total{reason="subject-change"}`; WARN with previous/current subject |
| Proactive reauthentication fails | `UNKNOWN_SERVER_ERROR` | Close | `reauth_attempts_total{outcome="failure"}`, `connection_closed_total{reason="reauth-failure"}` |
| Session hard deadline reached | `UNKNOWN_SERVER_ERROR` | Close | `connection_closed_total{reason="session-expired"}` |
| Invalid configuration or KeyStore at startup | Proxy fails to start | — | Startup exception with a non-secret configuration message |

Broker error text and SASL payloads are never forwarded. The broker's enabled mechanism list is
logged only as a diagnostic; the filter does not retry with another mechanism.

If the downstream client used `SaslTermination`, it may have already seen a successful client SASL
exchange before an upstream initiation failure is discovered on a later request. It then receives a
generic error/disconnect. This is the deliberate decoupling described in
[Concepts](concepts.md#what-the-client-sees).

## Metrics

Metrics are registered with Micrometer's global registry, following the SASL termination filter
conventions. Timers expose the usual Micrometer `_count`, `_sum` and `_max` series in addition to
the base name.

| Metric | Type | Tags | Meaning |
| --- | --- | --- | --- |
| `kroxylicious_filter_sasl_initiation_auth_attempts_total` | counter | `mechanism`, `virtual_cluster`, `outcome` (`success`/`failure`) | Initial SASL initiation attempts. |
| `kroxylicious_filter_sasl_initiation_auth_duration_seconds` | timer | `mechanism`, `virtual_cluster` | Duration of initial authentication, including API negotiation, handshake and challenge/response. |
| `kroxylicious_filter_sasl_initiation_reauth_attempts_total` | counter | `mechanism`, `virtual_cluster`, `outcome` (`success`/`failure`) | KIP-368 reauthentication attempts. |
| `kroxylicious_filter_sasl_initiation_reauth_duration_seconds` | timer | `mechanism`, `virtual_cluster` | Duration of reauthentication attempts. |
| `kroxylicious_filter_sasl_initiation_token_retrieval_duration_seconds` | timer | `outcome` (`success`/`failure`) | OAuth bearer token retrieval and validation duration. |
| `kroxylicious_filter_sasl_initiation_connection_closed_total` | counter | `reason` | Connections closed by the filter. |

`reason` values are bounded:

| Reason | Meaning |
| --- | --- |
| `client-sasl-frame` | Client SASL reached the initiator. Fix the chain order or client termination. |
| `auth-failure` | Initial upstream authentication failed. |
| `reauth-failure` | Proactive reauthentication failed. |
| `subject-change` | The downstream subject changed. |
| `session-expired` | The hard session deadline was reached before reauthentication completed. |

Subject names, broker usernames, token principals and other identity values are **never** metric
tags. This avoids unbounded cardinality and avoids exposing identities through the metrics endpoint.

Useful alert ideas:

* a sustained increase in `connection_closed_total` with `reason="auth-failure"` (credential or
  broker misconfiguration);
* any `reason="subject-change"` (should be exceptional);
* `reason="client-sasl-frame"` (chain-order misconfiguration);
* a rising `reauth-failure` rate (broker session lifetime, credential or IdP problem);
* OAuth token retrieval failures (IdP availability, client credentials, subject mismatch).

## Structured logs

Logs are structured key/value events. Identity values may appear in logs; passwords, client secrets,
bearer tokens, SASL payloads and raw broker error messages never do.

Common keys:

| Key | Meaning |
| --- | --- |
| `sessionId` | Connection/session identifier. |
| `virtualCluster` | Virtual cluster name. |
| `mechanism` | Configured SASL mechanism. |
| `reauth` | `true` for reauthentication events. |
| `outcome` | `success` or `failure`. |
| `subject` | Selected downstream lookup key (subject mode or fixed key). |
| `brokerUsername` | Broker username for password mechanisms. |
| `tokenPrincipal` | Expected/actual token principal for OAUTHBEARER. |
| `errorCode` | Client-visible Kafka error code (normally `UNKNOWN_SERVER_ERROR`). |
| `brokerErrorCode` | Broker error code retained for diagnostics. |
| `enabledMechanisms` | Broker's enabled mechanisms when a handshake is rejected. |
| `errorType` | Exception type, never a secret-bearing message. |
| `errorDetail` | Sanitized, length-capped diagnostic detail. |
| `reason` | Reauthentication/close reason. |
| `sessionLifetimeMs` | Broker-reported session lifetime on successful reauthentication events. |
| `previousSubject`, `currentSubject` | Subject-change diagnostics. |
| `reauthAtMs`, `hardDeadlineMs` | Armed reauthentication timing (DEBUG). |

Typical events:

* `SASL initiation authenticated the upstream connection` (INFO, success).
* `KIP-368 SASL reauthentication succeeded` (INFO).
* `SASL initiation failed` / `KIP-368 SASL reauthentication failed` (WARN).
* `The broker rejected the SASL handshake` (WARN, includes `brokerErrorCode` and
  `enabledMechanisms`).
* `The broker rejected SASL authentication` (WARN, includes `brokerErrorCode`).
* `The downstream subject changed after SASL authentication; closing the connection` (WARN).
* `Rejecting client-originated SASL frame; client SASL must be terminated before SaslInitiation`
  (WARN).
* Credential selection and reauth-arming details at DEBUG.

The credential store loader logs only the file path, credential kind and entry count. It never logs
entry contents.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| Client error `UNSUPPORTED_SASL_MECHANISM` and log "Rejecting client-originated SASL frame" | No `SaslTermination`, a misordered chain, or `SaslInspection` passthrough. Put client authentication before the initiator and the initiator last. |
| Client error `ILLEGAL_SASL_STATE` | A client `SaslAuthenticate` reached the initiator. Same chain-order fix as above. |
| All clients get a generic error immediately after a successful client SASL exchange | Initial upstream authentication failed. Search the proxy log for `SASL initiation failed`, `brokerErrorCode`, `enabledMechanisms` and the selected `subject`/`brokerUsername`. |
| Log says broker rejected the handshake | The broker does not have the configured mechanism enabled, or the configured mechanism name is wrong. `enabledMechanisms` shows what the broker offers. The filter never retries with a different mechanism. |
| Log says broker rejected authentication | Wrong username/password or OAuth client/secret, broker-side credential not created, or (PLAIN/SCRAM) the wrong per-identity password. Check the KeyStore entry with `list`, then update it. |
| Subject mode: "could not select a broker identity" | The client is anonymous, the subject builder/termination filter does not publish the configured principal type, or the subject is missing. Check `identity.principalType` and downstream authentication. |
| Subject mode: "No PASSWORD credential is configured for key ..." | Add an entry whose `--subject` equals the selected principal name, or configure a different singular principal type. |
| Subject change warnings | The client reauthenticated as a different user on an existing connection. The filter closes rather than switching broker identity. This is expected security behaviour. |
| OAuth token subject mismatch | The token's configured subject claim does not equal `expectedSubject`/the selected subject. Check `oauthBearer.subjectClaimName`, the IdP token claims and the KeyStore `--expected-subject`. |
| OAuth token retrieval failures | Check the token endpoint URL, network/TLS trust, client ID/secret, scope, and IdP availability. Look for `token_retrieval_duration_seconds{outcome="failure"}`. |
| Startup fails with a KeyStore error | Check the path, PKCS12 format, store password, entry count, credential kind, alias integrity and file permissions. See [KeyStore troubleshooting](operations.md#troubleshooting-credential-files). |
| Authentication succeeds, then connections fail at reauthentication | Check broker `connections.max.reauth.ms`, credential validity, IdP/token lifetime, and clock skew. Look at `reauth_attempts_total{outcome="failure"}` and the reauth WARN event. |
| Logs contain subject or username but no secret | Expected. Restrict log access; the filter intentionally logs identity context for operations. |
