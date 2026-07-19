# dig-social-graph — SPEC

Normative contract for the DIG social-graph core. An independent reimplementation MUST agree with
this document. Keywords MUST / SHOULD / MAY are used in the RFC 2119 sense.

This crate is **SG-1**: the networkless, chainless, keyless core. It defines the connection state
machine, the peer-exchange wire types (including their byte-stable canonical encodings), the four
seams through which dig-app supplies the real world, and the orchestration policy that maps
connection lifecycle to seam actions. It performs no cryptography, networking, chain access, or disk
I/O itself.

## 1. Model

A **connection** is the local node's relationship with one peer, identified by the peer's DID. Two
peers are **connected** iff each holds the other's profile and the handshake completed while both
were online — the social analogue of the mutual-`peer_id` proof.

The four locked protocol decisions bind every implementation:

1. **Offer-first.** A requestor MUST present its own profile offer inside the request; a connection
   cannot advance without the initiator's offer. Taking a peer's profile without offering one's own
   is unrepresentable.
2. **Symmetric.** Both peers select a profile and consent. Each end passes through an *offered* state
   before `Connected`.
3. **Synchronous.** `Connected` is reached only via a live confirmation. If the counterpart is
   offline, the connection parks in `PendingRendezvous` and resumes when both are online.
4. **Mutual.** There is exactly one `Connected` state, entered only after both ends have offered and
   subscribed to the other's store. One-sided completion has no representation.

Consent is **mandatory** (an inbound request MUST be explicitly approved or denied before any profile
is served) and **revocable** (a `Connected` peer MAY be revoked).

## 2. Connection state machine

States (perspective = the local node):

| State | Meaning |
|-------|---------|
| `Requested` | Outbound: request created with our offer attached; not yet delivered. |
| `RequestorOffered` | Outbound: our request reached the peer; awaiting accept/deny. |
| `AwaitingRecipientSelect` | Inbound: peer's request (with their offer) received; awaiting our profile selection + consent. |
| `RecipientOffered` | Inbound: we approved, selected, and offered back; awaiting mutual confirmation. |
| `Connected` | Mutual + live: both offered, both subscribed, completed while both online. |
| `PendingRendezvous(Suspended)` | A valid in-flight handshake parked because the peer is offline. |
| `Denied` | Terminal: one side declined. |
| `Revoked` | Terminal: a live connection was ended by either side. |

`Suspended` ∈ { `Requested`, `RequestorOffered`, `RecipientOffered` } — only in-flight states can be
parked, so `PendingRendezvous` can never wrap a terminal or connected state.

The transition function `apply(state, event) -> Result<state>` is pure and total: every pair not
listed below MUST be rejected as an illegal transition (never silently ignored).

| From | Event | To |
|------|-------|----|
| `Requested` | `RequestDelivered` | `RequestorOffered` |
| `RequestorOffered` | `AcceptReceived` | `Connected` |
| `RequestorOffered` | `Denied` | `Denied` |
| `AwaitingRecipientSelect` | `Approved` | `RecipientOffered` |
| `AwaitingRecipientSelect` | `Denied` | `Denied` |
| `RecipientOffered` | `MutualConfirmed` | `Connected` |
| `Requested` \| `RequestorOffered` \| `RecipientOffered` | `PeerWentOffline` | `PendingRendezvous(<from>)` |
| `PendingRendezvous(s)` | `PeerCameOnline` | `s` (the suspended state) |
| `Connected` | `Revoked` | `Revoked` |

Initial state of an outbound connection is `Requested`; of an inbound connection,
`AwaitingRecipientSelect`.

## 3. Wire types

### 3.1 StoreCoords

The plaintext an offer carries — the coordinates locating a peer's IdentityProfile store. What is
exchanged is a coordinate, NOT an inline profile: the receiver subscribes to the store, resolves the
profile locally, and verifies the DID↔store pairing and merkle proofs itself (dig-identity).

Fields: `did` (a `did:chia:` DID), `launcher_id` (`Bytes32`), `committed_root` (`Bytes32`).

**Invariant:** `launcher_id == did.launcher_id()`. Coordinates arriving over the wire MUST be
validated against this before use; a mismatch is rejected (it would bind a DID to a store it does not
own).

Canonical wire bytes (what the sealer seals):

```
u16(BE) did_len ‖ did_utf8[did_len] ‖ launcher_id[32] ‖ committed_root[32]
```

Decoders MUST reject truncated buffers, trailing bytes, non-UTF-8 or non-`did:chia:` DIDs, and
launcher-id/DID mismatches.

### 3.2 SealedOffer

A `StoreCoords` sealed to the recipient's identity key (§5.4 end-to-end). The core treats the
ciphertext as opaque bytes; sealing/opening is the `EnvelopeSealer` seam. An intermediary relaying an
offer MUST see ciphertext only.

### 3.3 Messages

- `ConnectRequest { requestor_offer: SealedOffer }` — offer-first: the requestor's own offer is
  carried in the request.
- `ConnectAccept { recipient_offer: SealedOffer }` — the recipient's chosen offer, sealed back.
- `ConnectDeny` — consent withheld; no offer.
- `Revoke` — end a live connection.

`SocialMessage` is the tagged union of the four. Canonical wire bytes:

```
tag(u8) [ ‖ u32(BE) offer_len ‖ offer_ciphertext ]
tag: 0=Request, 1=Accept, 2=Deny, 3=Revoke
```

Request/Accept carry a length-prefixed sealed offer; Deny/Revoke carry no body. Decoders MUST reject
unknown tags, truncation, and trailing bytes.

### 3.4 SealedEnvelope

Addressing wrapper delivered over the peer channel: `sender` (declared sender DID), `recipient`, and
`payload` (a serialized `SocialMessage`). The sensitive content — the offered coordinates — is sealed
inside each `SealedOffer`, so a relay sees only the message kind (unavoidable routing metadata) and
the addressing DIDs (§5.4). The declared `sender` MUST be validated against the sealing key by the
crypto seam (SG-2); the networkless core carries it unverified.

## 4. Seams

The core's only contact with the outside world. dig-app supplies real implementations; custody of
keys, network, chain, and storage stays on the user side (#908).

- **`Transport`** — `send(&SealedEnvelope)` (relay over the live mTLS peer channel; MUST NOT read the
  payload) and `is_peer_online(&Did)` (drives rendezvous). Real impl: the node peer channel
  (#980/#985).
- **`EnvelopeSealer`** — `seal(recipient, plaintext) -> Vec<u8>` /
  `open(our_secret, ciphertext) -> OpenedEnvelope` to a recipient's **BLS-G1 identity key**
  (dig-identity slot `0x0010`). `seal` takes only the recipient `Did` (the impl resolves its G1 public
  key via `resolve_bls_public_key` and encapsulates); `open` additionally takes our own `&SecretKey`,
  because G1 decapsulation is a Diffie-Hellman (`sk · peer_g1`) over raw key material and MUST NOT be
  routed through a sign-only wallet callback (the #908 signing seam yields signatures, not DH secrets).
  The app supplies the key per call; the core never retains it. `open` returns an `OpenedEnvelope`
  carrying the recovered plaintext **and the cryptographically-authenticated sender** (the DID launcher
  id the seal's BLS-G2 signature attributes the message to), which the manager binds for DID validation
  (§5). Real impl: `DigMessageSealer` over dig-message v0.3.1 `seal_message`/`open_message`
  (BLS-G1-DHKEM auth-mode, #796/#1160), resolving keys via the injected `KeyResolver`
  (production `ChainKeyResolver` → `resolve_bls_public_key`) and stamping/checking freshness through an
  injected `Clock`.
- **`StoreSubscriber`** — `subscribe(&StoreCoords)` / `unsubscribe(&StoreCoords)`. Real impl: the
  Subscription primitive (#979).
- **`Persistence`** — `load()` / `store(&SocialGraph)`, sealed at rest in the dig-app user data dir
  (NC-2/3). Real impl: the keystore sealer (DIGOP1).

## 5. Orchestration policy

The manager maps lifecycle to seam actions:

- **request** — validate our coords; seal them to the peer; record the outbound intent
  (`Requested`); if the peer is online, deliver and move to `RequestorOffered`, else park
  (`PendingRendezvous(Requested)`).
- **inbound request** — open + validate the peer's offer (DID validation, below); record
  `AwaitingRecipientSelect`. No profile is served yet (consent gate).
- **approve** — validate our coords; seal them back; **subscribe** to the peer's store; move to
  `RecipientOffered`; send the accept.
- **inbound accept** — open + validate the peer's offer (DID validation, below); **subscribe**; move
  to `Connected`.

**DID validation (§5.4).** Opening a peer's offer is trustworthy only after three checks, in order:
(1) the seal authenticates the sealer via its BLS-G2 signature over the sender's chain-resolved G1
identity key (a bad/mismatched sender key fails closed); (2) that authenticated sealer MUST equal the
DID the envelope declares as its sender — otherwise an on-path relay could re-attribute a
validly-sealed offer to a different peer; (3) the offered coordinates' DID MUST be that same
authenticated sealer, so nobody can seal an offer pointing at a store DID they do not control. The
sealer additionally enforces the dig-message anti-replay guard (a replayed envelope is rejected) and
freshness/expiry window.
- **deny** — notify; move to `Denied`.
- **revoke** — **unsubscribe**; notify; move to `Revoked`.
- **rendezvous** — a peer coming online resumes a parked connection to its suspended state.

Offering or accepting subscribes (we now maintain the peer's store); revoking unsubscribes. The
manager persists after each successful mutation.

## 6. Persistence & determinism

The `SocialGraph` is keyed by peer DID in a sorted map, so its `serde` form is a deterministic,
stable round-trip suitable for sealing and comparison at rest. The `serde` form (used for at-rest
state) is distinct from the canonical wire bytes (used for the p2p exchange); DIDs serialize as
`did:chia:` strings and 32-byte identifiers as lowercase hex.

## 7. Dependency posture

The only DIG dependency is **dig-identity** (canonical `Did` / `Bytes32` / profile types) — an
acyclic leaf. The chain (Subscription), network (node engine), and crypto (dig-message) are reached
through seams, never as direct dependencies. `Cargo.lock` MUST contain no other DIG crate.
