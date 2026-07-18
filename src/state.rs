//! The networkless connection state machine — a pure, deterministic transition function.
//!
//! Every state is described from the **local node's perspective** for a single peer. A connection
//! is one of two symmetric journeys plus their terminal/suspended states:
//!
//! - **Outbound** (I am the requestor): [`Requested`] → [`RequestorOffered`] → [`Connected`].
//! - **Inbound** (I am the recipient): [`AwaitingRecipientSelect`] → [`RecipientOffered`] →
//!   [`Connected`].
//!
//! The four locked protocol decisions are encoded structurally, so a wrong handshake is
//! unrepresentable rather than merely discouraged:
//!
//! - **Offer-first.** The only way to leave the initial state is by having attached an offer
//!   ([`ConnectionEvent::RequestSent`] is emitted by [`SocialGraph`] only once a valid own-offer
//!   exists), so you can never take a peer's profile without presenting your own.
//! - **Symmetric.** Both sides pass through an *offered* state ([`RequestorOffered`] /
//!   [`RecipientOffered`]) before [`Connected`] — each end selects a profile and consents.
//! - **Synchronous.** [`Connected`] is reachable only from an offered state via a live
//!   confirmation ([`AcceptReceived`] / [`MutualConfirmed`]); when the counterpart is offline the
//!   connection parks in [`PendingRendezvous`] and resumes when both are online again.
//! - **Mutual.** There is exactly one [`Connected`] state, and it is entered only after both ends
//!   have offered — one-sided completion has no representation.
//!
//! Consent is mandatory ([`AwaitingRecipientSelect`] must be resolved by [`Approved`] or
//! [`Denied`]) and revocable ([`Connected`] → [`Revoked`]).
//!
//! [`Requested`]: ConnectionState::Requested
//! [`RequestorOffered`]: ConnectionState::RequestorOffered
//! [`AwaitingRecipientSelect`]: ConnectionState::AwaitingRecipientSelect
//! [`RecipientOffered`]: ConnectionState::RecipientOffered
//! [`Connected`]: ConnectionState::Connected
//! [`PendingRendezvous`]: ConnectionState::PendingRendezvous
//! [`Denied`]: ConnectionState::Denied
//! [`Revoked`]: ConnectionState::Revoked
//! [`AcceptReceived`]: ConnectionEvent::AcceptReceived
//! [`MutualConfirmed`]: ConnectionEvent::MutualConfirmed
//! [`Approved`]: ConnectionEvent::Approved
//! [`SocialGraph`]: crate::graph::SocialGraph

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The lifecycle of one peer connection, from the local node's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Outbound: I have created a request and attached my own offer, but it is not yet delivered.
    Requested,
    /// Outbound: my request (carrying my offer) reached the peer; I await their accept or deny.
    RequestorOffered,
    /// Inbound: a peer's request (carrying their offer) arrived; I must select which of my profiles
    /// to present and approve or deny. Consent is mandatory here — no profile is served until this
    /// resolves.
    AwaitingRecipientSelect,
    /// Inbound: I approved, selected my profile, and sent my offer back; I await mutual confirmation
    /// that both ends now hold each other's profile.
    RecipientOffered,
    /// Mutual and live: both ends offered, both subscribed to the other's store, completed while
    /// both were online. The social analogue of the mutual-`peer_id` proof.
    Connected,
    /// A valid handshake is in flight but the counterpart is offline; it resumes when both are
    /// online again. Carries the [`Suspended`] state to resume into.
    PendingRendezvous(Suspended),
    /// Terminal: the request was declined by one side.
    Denied,
    /// Terminal: a previously [`Connected`](ConnectionState::Connected) peer was revoked by either
    /// side (stop serving + unsubscribe).
    Revoked,
}

/// The subset of states a connection may be suspended from while awaiting a synchronous rendezvous.
///
/// Only in-flight states can be suspended, so [`PendingRendezvous`](ConnectionState::PendingRendezvous)
/// can never wrap a terminal or already-connected state — the illegal cases are unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Suspended {
    /// Suspended from [`ConnectionState::Requested`].
    Requested,
    /// Suspended from [`ConnectionState::RequestorOffered`].
    RequestorOffered,
    /// Suspended from [`ConnectionState::RecipientOffered`].
    RecipientOffered,
}

impl Suspended {
    /// The concrete state to resume into once both peers are online again.
    fn resume(self) -> ConnectionState {
        match self {
            Suspended::Requested => ConnectionState::Requested,
            Suspended::RequestorOffered => ConnectionState::RequestorOffered,
            Suspended::RecipientOffered => ConnectionState::RecipientOffered,
        }
    }

    /// The suspendable form of a state, or `None` if the state cannot be parked for rendezvous.
    fn of(state: ConnectionState) -> Option<Suspended> {
        match state {
            ConnectionState::Requested => Some(Suspended::Requested),
            ConnectionState::RequestorOffered => Some(Suspended::RequestorOffered),
            ConnectionState::RecipientOffered => Some(Suspended::RecipientOffered),
            _ => None,
        }
    }
}

/// The triggers that drive a connection between states. Each event carries no payload — the data
/// (offers, resolved store coordinates, presented DID) lives on the [`Connection`](crate::graph::Connection);
/// the machine decides only the next *state*, which keeps it a small, exhaustively testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionEvent {
    /// Outbound: the local node created a request with its own offer attached (offer-first).
    RequestSent,
    /// Outbound: the request was delivered to the peer.
    RequestDelivered,
    /// Inbound: a peer's request (with their offer) was received.
    RequestReceived,
    /// Inbound: the local user selected a profile and approved the request.
    Approved,
    /// The request was declined (by the local user inbound, or by the peer outbound).
    Denied,
    /// Outbound: the peer's acceptance (with their offer) arrived — both ends now hold each other.
    AcceptReceived,
    /// Inbound: confirmation that the requestor subscribed to our store — the connection is mutual.
    MutualConfirmed,
    /// The counterpart went offline mid-handshake; park until both are online.
    PeerWentOffline,
    /// The counterpart is online again; resume the parked handshake.
    PeerCameOnline,
    /// A live connection was revoked by either side.
    Revoked,
}

impl ConnectionState {
    /// The initial state for a connection the local node **initiates** (outbound, offer-first).
    pub const fn initiated() -> Self {
        ConnectionState::Requested
    }

    /// Apply an [`ConnectionEvent`] and return the next state, or [`Error::IllegalTransition`] if the
    /// event is not accepted in the current state.
    ///
    /// This is the single source of truth for the connection lifecycle. It is a pure, total function
    /// of `(state, event)` — no I/O, no hidden state — so every path (and every illegal pair) is
    /// unit-testable in isolation.
    pub fn apply(self, event: ConnectionEvent) -> Result<ConnectionState> {
        use ConnectionEvent as E;
        use ConnectionState as S;

        let next = match (self, event) {
            // Outbound requestor journey.
            (S::Requested, E::RequestDelivered) => S::RequestorOffered,
            (S::RequestorOffered, E::AcceptReceived) => S::Connected,
            (S::RequestorOffered, E::Denied) => S::Denied,

            // Inbound recipient journey.
            (S::AwaitingRecipientSelect, E::Approved) => S::RecipientOffered,
            (S::AwaitingRecipientSelect, E::Denied) => S::Denied,
            (S::RecipientOffered, E::MutualConfirmed) => S::Connected,

            // Synchronous rendezvous: park any in-flight state, resume it when both are online.
            (state, E::PeerWentOffline) => match Suspended::of(state) {
                Some(suspended) => S::PendingRendezvous(suspended),
                None => return Err(illegal(self, event)),
            },
            (S::PendingRendezvous(suspended), E::PeerCameOnline) => suspended.resume(),

            // Revocation of a live connection.
            (S::Connected, E::Revoked) => S::Revoked,

            _ => return Err(illegal(self, event)),
        };
        Ok(next)
    }

    /// Whether this is a terminal state (no further transitions are possible).
    pub const fn is_terminal(self) -> bool {
        matches!(self, ConnectionState::Denied | ConnectionState::Revoked)
    }

    /// Whether both ends hold each other's profile (the connection is live and mutual).
    pub const fn is_connected(self) -> bool {
        matches!(self, ConnectionState::Connected)
    }
}

/// Build the [`Error::IllegalTransition`] for a rejected `(state, event)` pair.
fn illegal(state: ConnectionState, event: ConnectionEvent) -> Error {
    Error::IllegalTransition { state, event }
}
