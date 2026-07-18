//! The networkless orchestrator that drives the four seams through the connection lifecycle.
//!
//! [`SocialGraphManager`] is the thin policy layer that turns user intents (request, approve, deny,
//! revoke) and inbound messages into the right sequence of seam calls + state transitions:
//!
//! - **Offer/accept → subscribe.** Presenting or accepting an offer means we now maintain the
//!   peer's profile store, so the manager drives [`StoreSubscriber::subscribe`].
//! - **Revoke → unsubscribe.** Ending a connection stops maintaining the peer's store.
//! - **Seal every offer.** Outbound offers are sealed to the recipient
//!   ([`EnvelopeSealer::seal`]) before delivery; inbound offers are opened + validated.
//! - **Synchronous rendezvous.** An offline peer parks the connection in
//!   [`PendingRendezvous`](crate::state::ConnectionState::PendingRendezvous); [`resume_peer`]
//!   completes it once they are back online.
//!
//! It performs no I/O of its own — every effect flows through a seam, so the whole flow is
//! deterministic and testable with in-memory seam doubles.
//!
//! [`resume_peer`]: SocialGraphManager::resume_peer

use dig_identity::Did;

use crate::{
    error::{Error, Result},
    graph::SocialGraph,
    seams::{EnvelopeSealer, Persistence, StoreSubscriber, Transport},
    state::ConnectionEvent,
    wire::{
        ConnectAccept, ConnectDeny, ConnectRequest, Revoke, SealedEnvelope, SealedOffer,
        SocialMessage, StoreCoords,
    },
};

/// Drives the social-graph lifecycle over the four injected seams.
pub struct SocialGraphManager<T, S, Sub, P> {
    transport: T,
    sealer: S,
    subscriber: Sub,
    persistence: P,
    graph: SocialGraph,
}

impl<T, S, Sub, P> SocialGraphManager<T, S, Sub, P>
where
    T: Transport,
    S: EnvelopeSealer,
    Sub: StoreSubscriber,
    P: Persistence,
{
    /// Build a manager, loading the persisted graph through the [`Persistence`] seam.
    pub fn load(transport: T, sealer: S, subscriber: Sub, persistence: P) -> Result<Self> {
        let graph = persistence.load()?;
        Ok(Self {
            transport,
            sealer,
            subscriber,
            persistence,
            graph,
        })
    }

    /// The current graph (read-only).
    pub fn graph(&self) -> &SocialGraph {
        &self.graph
    }

    /// Initiate an OUTBOUND connection, presenting our own profile first (offer-first).
    ///
    /// Seals our coordinates to the peer, records the intent, and either delivers the request (peer
    /// online → [`RequestorOffered`]) or parks it (peer offline →
    /// [`PendingRendezvous`]). Persists before returning.
    ///
    /// [`RequestorOffered`]: crate::state::ConnectionState::RequestorOffered
    /// [`PendingRendezvous`]: crate::state::ConnectionState::PendingRendezvous
    pub fn request(
        &mut self,
        peer: Did,
        presented_local_did: Did,
        our_coords: StoreCoords,
    ) -> Result<()> {
        our_coords.validate()?;
        let offer = self.seal_offer(&peer, &our_coords)?;
        self.graph
            .initiate(peer.clone(), presented_local_did.clone(), our_coords)?;

        let message = SocialMessage::Request(ConnectRequest {
            requestor_offer: offer,
        });
        self.deliver_or_park(
            &presented_local_did,
            &peer,
            &message,
            ConnectionEvent::RequestDelivered,
        )?;
        self.persist()
    }

    /// Approve an INBOUND request: select which profile to present, seal it back, subscribe to the
    /// peer's store, and move to [`RecipientOffered`].
    ///
    /// Enforces offer-first symmetry — approval requires presenting our own offer.
    ///
    /// [`RecipientOffered`]: crate::state::ConnectionState::RecipientOffered
    pub fn approve(
        &mut self,
        peer: &Did,
        presented_local_did: Did,
        our_coords: StoreCoords,
    ) -> Result<()> {
        our_coords.validate()?;
        let their_store = self.require_their_store(peer)?;
        let offer = self.seal_offer(peer, &our_coords)?;

        // We now maintain the peer's profile store.
        self.subscriber.subscribe(&their_store).map_err(seam)?;

        let connection = self.require_connection_mut(peer)?;
        connection.presented_local_did = Some(presented_local_did.clone());
        connection.our_offer = Some(our_coords);
        connection.apply(ConnectionEvent::Approved)?;

        let message = SocialMessage::Accept(ConnectAccept {
            recipient_offer: offer,
        });
        self.send(&presented_local_did, peer, &message)?;
        self.persist()
    }

    /// Deny an inbound request — consent withheld. Notifies the peer and moves to
    /// [`Denied`](crate::state::ConnectionState::Denied).
    pub fn deny(&mut self, peer: &Did, presented_local_did: &Did) -> Result<()> {
        let message = SocialMessage::Deny(ConnectDeny);
        self.send(presented_local_did, peer, &message)?;
        self.require_connection_mut(peer)?
            .apply(ConnectionEvent::Denied)?;
        self.persist()
    }

    /// Revoke a live connection — stop serving + unsubscribe the peer's store, notify them, and move
    /// to [`Revoked`](crate::state::ConnectionState::Revoked).
    pub fn revoke(&mut self, peer: &Did, presented_local_did: &Did) -> Result<()> {
        if let Some(their_store) = self.graph.get(peer).and_then(|c| c.their_store.clone()) {
            self.subscriber.unsubscribe(&their_store).map_err(seam)?;
        }
        let message = SocialMessage::Revoke(Revoke);
        self.send(presented_local_did, peer, &message)?;
        self.require_connection_mut(peer)?
            .apply(ConnectionEvent::Revoked)?;
        self.persist()
    }

    /// Handle an inbound sealed envelope from a peer, dispatching on the message kind.
    pub fn handle_incoming(&mut self, envelope: &SealedEnvelope) -> Result<()> {
        let message = SocialMessage::from_canonical_bytes(&envelope.payload)?;
        match message {
            SocialMessage::Request(request) => self.on_request(&envelope.sender, &request),
            SocialMessage::Accept(accept) => self.on_accept(&envelope.sender, &accept),
            SocialMessage::Deny(_) => self.on_deny(&envelope.sender),
            SocialMessage::Revoke(_) => self.on_revoke(&envelope.sender),
        }
    }

    /// Resume a parked connection once the peer is back online (synchronous rendezvous).
    pub fn resume_peer(&mut self, peer: &Did) -> Result<()> {
        self.require_connection_mut(peer)?
            .apply(ConnectionEvent::PeerCameOnline)?;
        self.persist()
    }

    // --- inbound handlers -------------------------------------------------------------------

    /// Record an inbound request: open + validate the peer's offer, park it awaiting our consent.
    fn on_request(&mut self, sender: &Did, request: &ConnectRequest) -> Result<()> {
        let their_store = self.open_offer(&request.requestor_offer)?;
        self.graph.receive_request(sender.clone(), their_store)?;
        self.persist()
    }

    /// Complete an outbound handshake: open the peer's offer, subscribe, mark [`Connected`].
    ///
    /// [`Connected`]: crate::state::ConnectionState::Connected
    fn on_accept(&mut self, sender: &Did, accept: &ConnectAccept) -> Result<()> {
        let their_store = self.open_offer(&accept.recipient_offer)?;
        self.subscriber.subscribe(&their_store).map_err(seam)?;
        let connection = self.require_connection_mut(sender)?;
        connection.their_store = Some(their_store);
        connection.apply(ConnectionEvent::AcceptReceived)?;
        self.persist()
    }

    /// Record an inbound denial.
    fn on_deny(&mut self, sender: &Did) -> Result<()> {
        self.require_connection_mut(sender)?
            .apply(ConnectionEvent::Denied)?;
        self.persist()
    }

    /// Record an inbound revocation: unsubscribe + mark revoked.
    fn on_revoke(&mut self, sender: &Did) -> Result<()> {
        if let Some(their_store) = self.graph.get(sender).and_then(|c| c.their_store.clone()) {
            self.subscriber.unsubscribe(&their_store).map_err(seam)?;
        }
        self.require_connection_mut(sender)?
            .apply(ConnectionEvent::Revoked)?;
        self.persist()
    }

    // --- helpers ----------------------------------------------------------------------------

    /// Seal our coordinates to a recipient, producing a [`SealedOffer`].
    fn seal_offer(&self, recipient: &Did, coords: &StoreCoords) -> Result<SealedOffer> {
        let ciphertext = self
            .sealer
            .seal(recipient, &coords.to_canonical_bytes())
            .map_err(seam)?;
        Ok(SealedOffer::new(ciphertext))
    }

    /// Open + validate a peer's sealed offer into [`StoreCoords`].
    fn open_offer(&self, offer: &SealedOffer) -> Result<StoreCoords> {
        let plaintext = self.sealer.open(&offer.ciphertext).map_err(seam)?;
        StoreCoords::from_canonical_bytes(&plaintext)
    }

    /// Deliver a message if the peer is online, else park the connection for rendezvous.
    fn deliver_or_park(
        &mut self,
        sender: &Did,
        recipient: &Did,
        message: &SocialMessage,
        on_delivered: ConnectionEvent,
    ) -> Result<()> {
        if self.transport.is_peer_online(recipient).map_err(seam)? {
            self.send(sender, recipient, message)?;
            self.require_connection_mut(recipient)?
                .apply(on_delivered)?;
        } else {
            self.require_connection_mut(recipient)?
                .apply(ConnectionEvent::PeerWentOffline)?;
        }
        Ok(())
    }

    /// Envelope + deliver a message over the transport (no state change).
    fn send(&self, sender: &Did, recipient: &Did, message: &SocialMessage) -> Result<()> {
        let envelope = SealedEnvelope {
            sender: sender.clone(),
            recipient: recipient.clone(),
            payload: message.to_canonical_bytes(),
        };
        self.transport.send(&envelope).map_err(seam)
    }

    /// The peer's validated store coordinates, or an error if the request was never received.
    fn require_their_store(&self, peer: &Did) -> Result<StoreCoords> {
        self.graph
            .get(peer)
            .and_then(|c| c.their_store.clone())
            .ok_or(Error::Invariant("no inbound offer recorded for this peer"))
    }

    /// A mutable handle to a known connection, or an error if none is tracked.
    fn require_connection_mut(&mut self, peer: &Did) -> Result<&mut crate::graph::Connection> {
        self.graph
            .get_mut(peer)
            .ok_or(Error::Invariant("no connection tracked for this peer"))
    }

    /// Persist the graph through the [`Persistence`] seam.
    fn persist(&self) -> Result<()> {
        self.persistence.store(&self.graph)
    }
}

/// Adapt a seam's boxed error into [`Error::Seam`].
fn seam(err: Error) -> Error {
    match err {
        Error::Seam(_) => err,
        other => Error::Seam(other.to_string()),
    }
}
