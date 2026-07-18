//! The managed social-graph state: the set of per-peer [`Connection`]s and the operations that
//! advance them.
//!
//! [`SocialGraph`] is a plain, serializable value — dig-app seals it at rest via the
//! [`Persistence`](crate::seams::Persistence) seam (NC-2/3). It owns no I/O; it applies
//! [`ConnectionEvent`]s through the pure [state machine](crate::state) and records the data
//! (offers, resolved coordinates, the presented DID) alongside each state.

use std::collections::BTreeMap;

use dig_identity::Did;
use serde::{Deserialize, Serialize};

use crate::{
    codec,
    error::{Error, Result},
    state::{ConnectionEvent, ConnectionState},
    wire::StoreCoords,
};

/// One peer connection: its lifecycle [`state`](Connection::state) plus the data the handshake
/// accumulates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// The remote peer's DID — the connection's identity and map key.
    #[serde(with = "codec::did_str")]
    pub peer: Did,
    /// Where this connection is in its lifecycle. PRIVATE by design: the state may only change
    /// through [`Connection::apply`] (the pure state machine), never by direct assignment — so no
    /// consumer can inject an illegal state (e.g. a fabricated `Connected`). Read it via
    /// [`Connection::state`].
    state: ConnectionState,
    /// Which of the local user's DIDs is presented to THIS peer (decoupled from the globally active
    /// profile). `None` until the local side has offered.
    #[serde(with = "codec::opt_did_str", default)]
    pub presented_local_did: Option<Did>,
    /// The coordinates of the profile store WE offered this peer (our own, plaintext).
    #[serde(default)]
    pub our_offer: Option<StoreCoords>,
    /// The coordinates of the peer's profile store, recovered from their offer. `None` until we have
    /// opened and validated their offer.
    #[serde(default)]
    pub their_store: Option<StoreCoords>,
}

impl Connection {
    /// Create a connection in a given starting state for a peer.
    fn new(peer: Did, state: ConnectionState) -> Self {
        Self {
            peer,
            state,
            presented_local_did: None,
            our_offer: None,
            their_store: None,
        }
    }

    /// The connection's current lifecycle state (read-only; mutate only via [`apply`](Connection::apply)).
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Advance this connection by one [`ConnectionEvent`], updating [`state`](Connection::state) via
    /// the pure state machine. This is the ONLY way the state changes.
    pub fn apply(&mut self, event: ConnectionEvent) -> Result<()> {
        self.state = self.state.apply(event)?;
        Ok(())
    }
}

/// The full set of the local node's peer connections, keyed by peer DID.
///
/// Backed by a [`BTreeMap`] so serialization is deterministic (stable key order) — important for a
/// value that is sealed and compared at rest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialGraph {
    connections: BTreeMap<String, Connection>,
}

impl SocialGraph {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of connections tracked.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the graph tracks no connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// The connection for a peer, if one exists.
    pub fn get(&self, peer: &Did) -> Option<&Connection> {
        self.connections.get(peer.as_str())
    }

    /// A mutable handle to a peer's connection, if one exists.
    pub fn get_mut(&mut self, peer: &Did) -> Option<&mut Connection> {
        self.connections.get_mut(peer.as_str())
    }

    /// Iterate all connections in deterministic (peer-DID) order.
    pub fn iter(&self) -> impl Iterator<Item = &Connection> {
        self.connections.values()
    }

    /// Insert or replace a connection. Crate-internal: connections enter the graph ONLY through
    /// [`initiate`](SocialGraph::initiate) / [`receive_request`](SocialGraph::receive_request), which
    /// fix the initial state — so an external caller cannot smuggle in a connection with a fabricated
    /// state via a raw insert.
    pub(crate) fn upsert(&mut self, connection: Connection) {
        self.connections
            .insert(connection.peer.as_str().to_owned(), connection);
    }

    /// Remove a peer's connection, returning it if present.
    pub fn remove(&mut self, peer: &Did) -> Option<Connection> {
        self.connections.remove(peer.as_str())
    }

    /// Begin an OUTBOUND connection to a peer (offer-first).
    ///
    /// Offer-first is enforced structurally: an outbound connection cannot exist without our own
    /// offer, so this records `our_offer` + `presented_local_did` and puts the connection in
    /// [`ConnectionState::Requested`]. Returns [`Error::Invariant`] if a connection to the peer
    /// already exists (call sites should revoke/remove first).
    pub fn initiate(
        &mut self,
        peer: Did,
        presented_local_did: Did,
        our_offer: StoreCoords,
    ) -> Result<&Connection> {
        if self.connections.contains_key(peer.as_str()) {
            return Err(Error::Invariant("a connection to this peer already exists"));
        }
        let mut connection = Connection::new(peer.clone(), ConnectionState::initiated());
        connection.presented_local_did = Some(presented_local_did);
        connection.our_offer = Some(our_offer);
        self.upsert(connection);
        Ok(self
            .get(&peer)
            .expect("connection was just inserted for this peer"))
    }

    /// Record an INBOUND request from a peer, storing their validated store coordinates and moving
    /// the connection to [`ConnectionState::AwaitingRecipientSelect`] (awaiting the local user's
    /// profile selection + consent).
    ///
    /// `their_store` MUST already be validated ([`StoreCoords::validate`]). Returns
    /// [`Error::Invariant`] if a connection to the peer already exists.
    pub fn receive_request(&mut self, peer: Did, their_store: StoreCoords) -> Result<&Connection> {
        if self.connections.contains_key(peer.as_str()) {
            return Err(Error::Invariant("a connection to this peer already exists"));
        }
        let mut connection =
            Connection::new(peer.clone(), ConnectionState::AwaitingRecipientSelect);
        connection.their_store = Some(their_store);
        self.upsert(connection);
        Ok(self
            .get(&peer)
            .expect("connection was just inserted for this peer"))
    }
}
