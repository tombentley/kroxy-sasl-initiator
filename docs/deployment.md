# Deployment and chain order

## Recommended order

Order filters from the client towards the broker. `SaslInitiation` belongs last, closest to the
broker:

```text
client
  -> transport TLS/mTLS
  -> SaslTermination (optional)
  -> other filters
  -> SaslInitiation (last)
  -> upstream Kafka broker
```

Why:

* `SaslTermination`, if used, must see and answer the client's `SaslHandshake`/`SaslAuthenticate`
  frames. They must not reach the initiator.
* The initiator's own `SaslHandshake`/`SaslAuthenticate` requests travel towards the broker through
  anything later in the chain. Placing it last prevents another SASL-aware filter from observing or
  intercepting those frames.
* If `SaslInitiation` is placed before `SaslTermination`, it sees the client's SASL frames and
  rejects them. This is a misconfiguration, not a passthrough mode.

The runtime does not currently validate the whole chain. The filter can defend itself by rejecting
client-originated SASL frames, but it cannot know whether a later filter will intercept its own
upstream frames. Correct placement is therefore an operational requirement, and the integration
tests cover both the correct order and the unsafe configurations.

## Composition matrix

| Downstream client authentication | Fixed identity | Subject identity |
| --- | --- | --- |
| Anonymous / trusted network | Supported | Fails closed (no subject) |
| mTLS | Supported | Supported when the TLS subject builder publishes the configured principal type |
| `SaslTermination` with SCRAM | Supported | Supported; the terminated user becomes the lookup key |
| `SaslTermination` with OAUTHBEARER | Supported | Supported; the terminated user becomes the lookup key |
| Client SASL passthrough / `SaslInspection` passthrough | Not supported | Not supported |

Clients never need to know the broker credentials. The client-facing mechanism and the
broker-facing mechanism are independent; for example, an mTLS client can be mapped to a SCRAM
broker identity, or a SCRAM-terminated client can be mapped to an OAUTHBEARER broker identity.

`SaslTermination` in the target Kroxylicious baseline supports SCRAM and OAUTHBEARER, not PLAIN.
Use the mechanisms your Kroxylicious release supports for the client-facing side.

## Anonymous clients

Fixed identity works with anonymous clients. Subject mode does not: the filter requires a
non-anonymous subject and fails closed with a generic error.

If the broker should see a shared proxy service account, use fixed identity. If the broker should
see individual users, terminate client authentication first or use mTLS with a subject builder.

## mTLS clients

With mTLS, the client certificate is mapped to a subject by the transport subject builder. Configure
the builder to publish the principal type used by `identity.principalType`, normally
`io.kroxylicious.proxy.authentication.User`.

Example: [mTLS client with subject-derived SCRAM](examples/mtls-subject-scram.yaml).

The client certificate must be trusted by the proxy listener. `SaslInitiation` does not configure
the listener TLS or the upstream broker TLS; both are separate cluster/gateway settings.

## `SaslInspection` and client SASL passthrough

`SaslInspection` observes a client SASL exchange without necessarily terminating it. That is
incompatible with `SaslInitiation` in the same chain: the initiator needs to drive the upstream SASL
exchange itself, and the broker must not also be driven by the client's passthrough exchange.

`SaslInspection` can coexist only when another filter terminates the client SASL before the
initiator. At that point the inspection is no longer observing a passthrough, and the client frames
do not reach the initiator.

Direct client SASL passthrough is rejected:

* a client `SaslHandshake` receives `UNSUPPORTED_SASL_MECHANISM` and the connection closes;
* a client `SaslAuthenticate` receives `ILLEGAL_SASL_STATE` and the connection closes.

These are the only cases where the initiator returns SASL-specific errors, because the client has
demonstrably sent SASL frames to the wrong place. Upstream broker failures always return the generic
error described in [Failure semantics](observability.md#failure-semantics).

## Routing

When the virtual cluster uses a router, configure `SaslInitiation` on each **leaf route's** filter
chain, not on the virtual-cluster filter chain.

```yaml
routerDefinitions:
  - name: leaf-router
    type: com.example.router.FanOutRouter   # replace with your router plugin
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
    # Client-facing filters may go here. SaslInitiation must not.
    filters: [sasl-termination]
```

Why per route:

* The route selects the target cluster. A virtual-cluster-level initiator runs before target
  selection, so its internally generated `ApiVersions`/`SaslHandshake` frames can go to the wrong
  upstream or to no target.
* Per-route placement gives each leaf route its own filter instance and SASL state. A client
  connection that fans out to multiple routes authenticates each upstream connection independently.
* Each leaf route can have its own filter definition, mechanism and credential store.
* The client subject remains visible to the route filter through the request context. The initiator
  reads it and never changes it.

The runtime does not currently reject a virtual-cluster-level initiator under routing. The routing
integration test demonstrates that such a placement does not authenticate every leaf route; treat
it as an unsupported configuration.

Routes that resolve to the same upstream address can share an upstream connection. Per-route filters
cannot be relied on to separate credentials for the same broker connection. Use one route per
upstream connection when credentials must differ.

Example: [Routing with one initiator per leaf route](examples/routing-two-routes.yaml).
