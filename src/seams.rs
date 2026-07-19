//! The four injected seams — the crate's only contact with the outside world.
//!
//! The social-graph core is deliberately inert: it holds no keys, opens no sockets, watches no
//! chain, and touches no disk. Everything it cannot do purely is expressed as a trait that dig-app
//! implements with the real machinery. This keeps the core a pure, exhaustively testable leaf and
//! keeps custody of keys/network/chain/storage where it belongs — in the user-side dig-app (#908).
//!
//! | Seam | Real implementation (in dig-app, later) | Depends on |
//! |------|------------------------------------------|------------|
//! | [`Transport`] | deliver ciphertext over the mTLS peer channel | connect-leg (#980/#985) |
//! | [`EnvelopeSealer`] | seal/open to a recipient's BLS-G1 identity key | dig-message (#796/#1160) |
//! | [`StoreSubscriber`] | subscribe/unsubscribe a profile store | Subscription (#979) |
//! | [`Persistence`] | load/store the graph sealed at rest | keystore sealer (DIGOP1) |
//!
//! The seams are synchronous: the core drives them as simple, sequential steps. dig-app's real
//! implementations may bridge to async I/O internally.

use dig_identity::bls::SecretKey;
use dig_identity::Did;

use crate::{error::Result, graph::SocialGraph, wire::SealedEnvelope};

/// Delivers sealed envelopes to peers over the live node-to-node channel, and reports peer presence
/// for the synchronous rendezvous.
///
/// The transport is a dumb ciphertext relay — it never sees plaintext (§5.4).
pub trait Transport {
    /// Deliver a sealed envelope to its recipient over the live peer channel.
    fn send(&self, envelope: &SealedEnvelope) -> Result<()>;

    /// Whether the given peer is currently reachable (drives rendezvous: offline → park, online →
    /// resume).
    fn is_peer_online(&self, peer: &Did) -> Result<bool>;
}

/// Seals plaintext to a recipient's **BLS-G1 identity key** and opens ciphertext addressed to us
/// (§5.4).
///
/// This is the end-to-end crypto boundary. The networkless core never performs cryptography itself;
/// SG-2 (#991) supplies the real dig-message-backed implementation (DHKEM-over-G1, #1160).
///
/// # Why the two directions are asymmetric
///
/// The two halves need different key material, and the split is deliberate — it encodes the #908
/// custody boundary at the type level:
///
/// - **[`seal`](EnvelopeSealer::seal)** takes only the recipient's [`Did`]. The implementation
///   resolves that DID to its 48-byte BLS-G1 public key (slot `0x0010`, via
///   `dig_identity::resolve_bls_public_key`) and encapsulates to it. No private key is involved, so
///   sealing needs nothing from us.
/// - **[`open`](EnvelopeSealer::open)** takes our own **[`SecretKey`]** by reference. G1
///   decapsulation is a Diffie-Hellman (`sk · peer_g1`, `dig_identity::bls::g1_dh`) — it needs the
///   raw scalar, **not** a signature. It therefore **cannot** be routed through a sign-only wallet
///   callback (the #908 signing seam produces signatures, never DH shared secrets). The key is
///   *supplied* to `open` per call — the app unlocks it, lends it for the decapsulation, and the
///   networkless core neither stores nor derives it.
///
/// The `&SecretKey` parameter is the whole point of this seam's shape: it makes "opening needs raw
/// key material" a compile-time fact SG-2 must honour, rather than a convention it could violate by
/// reaching for the sign-only path.
pub trait EnvelopeSealer {
    /// Seal `plaintext` so that only `recipient`'s BLS-G1 identity key can open it.
    ///
    /// The implementation resolves `recipient`'s G1 public key (slot `0x0010`) and encapsulates to
    /// it; no secret key of ours is involved.
    fn seal(&self, recipient: &Did, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Open ciphertext addressed to us, returning the recovered plaintext.
    ///
    /// `our_secret` is our BLS-G1 identity secret key, supplied by the app for this decapsulation
    /// (G1-ECDH decap — not a signature; see the trait docs for why it must be a real key, not a
    /// sign-only callback).
    fn open(&self, our_secret: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Maintains the local `.dig` store for a connected peer's profile by subscribing to its singleton.
///
/// This is where the connection lifecycle drives the Subscription primitive (#979): offering or
/// accepting subscribes; revoking unsubscribes. The core decides *when*; the seam does the chain
/// work.
pub trait StoreSubscriber {
    /// Begin maintaining the store at `coords` (subscribe to its singleton).
    fn subscribe(&self, coords: &crate::wire::StoreCoords) -> Result<()>;

    /// Stop maintaining the store at `coords` (unsubscribe).
    fn unsubscribe(&self, coords: &crate::wire::StoreCoords) -> Result<()>;
}

/// Loads and stores the social graph, sealed at rest in the dig-app user data dir (NC-2/3).
pub trait Persistence {
    /// Load the persisted graph, or a fresh empty graph if none exists yet.
    fn load(&self) -> Result<SocialGraph>;

    /// Persist the current graph, sealed at rest.
    fn store(&self, graph: &SocialGraph) -> Result<()>;
}
