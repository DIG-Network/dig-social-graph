# dig-social-graph

The **networkless core** of the DIG social graph — the pure, deterministic engine that dig-app uses
to maintain its social connections. It owns the connection state machine, the peer-exchange wire
types, and the store-maintenance orchestration policy, and it reaches the outside world only through
four injected [seams](src/seams.rs). It holds no keys, opens no sockets, watches no chain, and
touches no disk of its own.

See [`SPEC.md`](SPEC.md) for the normative contract.

## What a connection is

Two peers are **connected** only when each holds the other's profile — the social analogue of the
mutual-`peer_id` proof. The handshake obeys four locked decisions:

- **Offer-first** — the requestor presents their own profile first; you cannot take a peer's profile
  without offering your own.
- **Symmetric** — both sides select a profile and consent.
- **Synchronous** — completion requires both peers online; an offline peer parks the connection in
  `PendingRendezvous` until both return.
- **Mutual** — `Connected` is entered only after both ends have offered and subscribed to each
  other's store.

Consent is mandatory and revocable.

## What crosses the wire

Not a profile blob — a **store coordinate** (`StoreCoords`: `did` + `launcher_id` + `committed_root`)
sealed to the recipient (§5.4). The receiver subscribes to that store, resolves the profile locally,
and verifies the DID↔store pairing + merkle proofs itself (via
[dig-identity](https://github.com/DIG-Network/dig-identity)), so the profile stays chain-anchored and
authoritative.

## The four seams

| Seam | Responsibility | Real impl (dig-app) |
|------|----------------|---------------------|
| `Transport` | relay sealed envelopes; report peer presence | mTLS peer channel |
| `EnvelopeSealer` | seal/open to a recipient key | dig-message |
| `StoreSubscriber` | subscribe/unsubscribe a profile store | Subscription |
| `Persistence` | load/store the graph, sealed at rest | keystore sealer |

## Scope

This is **SG-1** of the dig-social-graph epic (DIG-Network/dig_ecosystem#986): the networkless core
+ SPEC + state machine + seams. The end-to-end crypto (SG-2), consent hardening (SG-3), dig-app
wiring + live rendezvous (SG-4), and UI (SG-5) build on top of this crate.

## License

GPL-2.0-only.
