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
//! | [`EnvelopeSealer`] | seal/open to a recipient's X25519 IK | dig-message (#796) |
//! | [`StoreSubscriber`] | subscribe/unsubscribe a profile store | Subscription (#979) |
//! | [`Persistence`] | load/store the graph sealed at rest | keystore sealer (DIGOP1) |
//!
//! The seams are synchronous: the core drives them as simple, sequential steps. dig-app's real
//! implementations may bridge to async I/O internally.

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

/// Seals plaintext to a recipient's identity key and opens ciphertext addressed to us (§5.4).
///
/// This is the end-to-end crypto boundary. The networkless core never performs cryptography itself;
/// SG-2 supplies the real dig-message-backed implementation.
pub trait EnvelopeSealer {
    /// Seal `plaintext` so that only `recipient`'s identity key can open it.
    fn seal(&self, recipient: &Did, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Open ciphertext addressed to us, returning the recovered plaintext.
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
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
