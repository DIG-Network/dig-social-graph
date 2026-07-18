//! # dig-social-graph — the networkless core of the DIG social graph
//!
//! This crate is **SG-1**: the pure, deterministic heart of dig-app's social connections. It owns
//! the connection state machine, the peer-exchange wire types, and the store-maintenance
//! orchestration policy — and NOTHING else. It holds no keys, opens no sockets, watches no chain,
//! and touches no disk. Every effect that needs the outside world is expressed as one of four
//! injected [seams], so the core is a pure leaf that dig-app wires to real machinery later.
//!
//! ## The connection, in one picture
//!
//! Two peers become **connected** only when each holds the other's profile — the social analogue of
//! the mutual-`peer_id` proof. Four locked protocol decisions shape the handshake (see [`state`]):
//!
//! - **Offer-first** — the requestor presents their own profile first; you cannot take a peer's
//!   profile without offering your own.
//! - **Symmetric** — both sides select a profile and consent.
//! - **Synchronous** — completion requires both peers online; an offline peer parks the connection
//!   in [`PendingRendezvous`](state::ConnectionState::PendingRendezvous) until both return.
//! - **Mutual** — [`Connected`](state::ConnectionState::Connected) is entered only after both ends
//!   have offered and subscribed to each other's store.
//!
//! Consent is mandatory and revocable.
//!
//! ## What crosses the wire is a coordinate, not a blob
//!
//! A profile is never shipped inline. A peer ships [`StoreCoords`] — the `did` +
//! `launcher_id` + `committed_root` that locate its IdentityProfile store — sealed to the recipient
//! (§5.4). The receiver subscribes to that store, resolves the profile locally, and verifies the
//! DID↔store pairing + merkle proofs itself (via [dig-identity]). The profile stays authoritative
//! (chain-anchored) instead of trusting bytes a peer hands over.
//!
//! ## The four seams
//!
//! | Seam | Responsibility | Real impl (dig-app) |
//! |------|----------------|---------------------|
//! | [`Transport`] | relay sealed envelopes; report peer presence | mTLS peer channel |
//! | [`EnvelopeSealer`] | seal/open to a recipient key | dig-message |
//! | [`StoreSubscriber`] | subscribe/unsubscribe a profile store | Subscription |
//! | [`Persistence`] | load/store the graph, sealed at rest | keystore sealer |
//!
//! ## Dependency posture
//!
//! The only DIG dependency is [dig-identity] (for the canonical `Did` / `Bytes32` / profile types) —
//! an acyclic leaf. The chain (dig-store Subscription), the network (the node engine), and the
//! crypto (dig-message) are all reached through seams, never as direct dependencies.
//!
//! [dig-identity]: https://github.com/DIG-Network/dig-identity

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod error;
pub mod graph;
pub mod manager;
pub mod seams;
pub mod state;
pub mod wire;

pub use error::{Error, Result};
pub use graph::{Connection, SocialGraph};
pub use manager::SocialGraphManager;
pub use seams::{EnvelopeSealer, Persistence, StoreSubscriber, Transport};
pub use state::{ConnectionEvent, ConnectionState, Suspended};
pub use wire::{
    ConnectAccept, ConnectDeny, ConnectRequest, Revoke, SealedEnvelope, SealedOffer, SocialMessage,
    StoreCoords,
};

// Re-export the canonical Chia/DID types the public API speaks, so consumers pin the same versions.
pub use dig_identity::{Bytes32, Did};
