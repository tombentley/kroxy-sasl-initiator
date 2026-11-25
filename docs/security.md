# Security

Broker credentials are secrets. This page describes the security properties, the remaining risks,
and the operational controls expected in a production deployment.

## PLAIN over SASL_PLAINTEXT

`PLAIN` sends the broker username and password in clear text inside the SASL exchange. It is safe
only when the upstream connection is protected by TLS. Do not use `PLAIN` over
`SASL_PLAINTEXT`/plaintext, even on a trusted network.

The filter does not configure upstream transport security. Configure TLS on the target cluster in
the Kroxylicious configuration and verify the broker certificate. `SCRAM` avoids sending the
password itself, but it still does not provide transport confidentiality or broker authentication;
use TLS for those.

## KeyStore custody

The PKCS12 store is the boundary of broker-credential custody.

* Keep it outside source control and outside the proxy configuration file.
* Restrict read access to the proxy service account. On POSIX, use owner-only mode (`0600`) for the
  store and password file. The filter rejects group/other permissions unless the documented
  Kubernetes/OpenShift escape hatch is set.
* Treat the store password file as another secret. Use a Secret manager or Kubernetes Secret, not
  an inline password in YAML, except for local development.
* Use a dedicated store for initiation credentials. Do not reuse the `SaslTermination` SCRAM store;
  the formats and trust boundaries differ.
* Back up the store securely. A backup is as sensitive as the broker credentials it contains.
* Prefer one store per target cluster or trust boundary when routes use different upstreams.
* Restrict who can run the CLI. Anyone who can read the store and the password can extract broker
  credentials.

The KeyStore protects credentials at rest. It does not protect them from a compromised proxy
process, a heap dump, a debugger or an attacker with the store password.

## PLAIN, SCRAM and OAuth secrets in memory

PLAIN and SCRAM clients must present the plaintext password, and OAuth clients must present the
client secret and bearer token. The proxy therefore holds plaintext secret material in the JVM heap
while credentials and connections are in use.

The implementation uses a destroyable wrapper for avoidable copies and zeroes temporary buffers
where practical. It cannot eliminate copies made by Jackson, the JDK SASL implementation, Kafka's
OAuth classes, strings and the garbage collector. Residual heap exposure is an accepted risk for
this release.

Operational controls:

* Restrict access to heap dumps, core dumps, JFR recordings and debug endpoints.
* Do not enable verbose protocol logging that could capture SASL bytes.
* Keep the proxy and its dependencies patched.
* Treat a process with the KeyStore mounted as having broker credentials.

## Subject trust

Subject-derived identity is only as trustworthy as the downstream subject.

* Use subject mode only behind a trusted client authenticator: `SaslTermination` or a TLS subject
  builder on an mTLS listener.
* Anonymous subjects are rejected. There is no fallback to a fixed identity.
* The subject is the lookup key; the KeyStore is the allow-list. A client cannot select an arbitrary
  KeyStore alias independently of its authenticated subject.
* The mapping is controlled by the KeyStore entry. A client subject may map to a different broker
  username, but only to mappings the operator has created.
* If the subject changes after upstream authentication, the filter fails closed and closes the
  connection. It never reauthenticates as the new identity. This includes changes during proactive
  reauthentication.

Do not configure subject mode on a listener where clients can choose their own principal without
authentication.

## OAUTHBEARER identity semantics

A client-credentials token identifies the OAuth client, not necessarily the downstream human user.
The filter obtains a token with the KeyStore entry's client credentials and verifies the token's
configured subject claim against the entry's `expectedSubject` (which defaults to the lookup
subject). This check catches a token for the wrong client/subject; it is not a general
impersonation feature.

A fixed-identity `file:` token is trusted as an operator-controlled secret and is not subject-mapped.
Treat it as a shared service token.

Token exchange (RFC 8693) and MDS-style impersonation are not supported. Do not describe a
deployment as per-user OAuth unless the IdP and the configured client credentials actually issue
tokens whose subject is the user.

## Client-visible errors

Upstream failures return a generic `UNKNOWN_SERVER_ERROR` for the triggering request and close the
connection. The proxy does not forward broker error text, enabled-mechanism details or SASL payloads
to clients.

This prevents broker diagnostics from becoming an information leak. Detailed diagnostics are
available only in the proxy logs, where they are sanitized and access-controlled.

The filter is not a client-authentication endpoint. In subject mode it acts on a subject established
by a trusted downstream authenticator; all upstream failures look the same to the client. The
release does not add a timing/enumeration defence beyond this. Revisit that if termination and
initiation are ever coupled, or if a downstream mechanism allows unauthenticated attacker-chosen
subjects.

## Logging and metrics

The filter never logs passwords, OAuth client secrets, bearer tokens, SASL authentication bytes or
raw broker error messages.

* Logs use structured key/value fields such as `sessionId`, `virtualCluster`, `mechanism`,
  `outcome`, `subject`, `brokerUsername`, `tokenPrincipal`, `errorCode`, `brokerErrorCode` and
  `enabledMechanisms`.
* Subject and broker usernames may appear in logs. Restrict access to proxy logs accordingly.
* Metrics carry bounded tags only: mechanism, virtual cluster, outcome and close reason. Subject
  names, broker usernames and other identity values are never metric tags.
* Diagnostics that originate from upstream are passed through a sanitizer that strips control
  characters and caps length. Callers never pass secrets or raw payloads to it.

See [Failure semantics and observability](observability.md) for the exact metric names and log
fields.

## Credential rotation

There is no hot reload. The KeyStore is loaded once at startup, so a running process keeps using the
credentials it loaded even if the file changes. Rotate by updating the store and restarting every
proxy instance. Plan broker-side credential changes so that old and new credentials overlap during a
rolling restart where the broker supports it.

## Deployment checklist

* [ ] Upstream TLS is enabled and the broker certificate is verified.
* [ ] `PLAIN` is not used over plaintext.
* [ ] The initiation KeyStore is separate from the client-termination store.
* [ ] Store and password files are owner-only, or the Kubernetes/OpenShift escape hatch is
      deliberately enabled for a platform-controlled volume.
* [ ] The store password is supplied by `passwordFile`, not inline YAML.
* [ ] The broker password/OAuth client secret is not present in YAML, ConfigMaps or source control.
* [ ] Subject mode is used only behind a trusted client authenticator.
* [ ] `SaslInitiation` is last in the chain and on each leaf route under routing.
* [ ] Metric and log access is restricted; no secret-bearing debug logging is enabled.
* [ ] A restart-based rotation procedure is documented and tested.
