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

use dig_identity::bls::SecretKey;
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

        // Guard-before-side-effect: validate the transition FIRST, so an approve that is not legal
        // in the current state cannot subscribe to the peer's store ahead of the consent gate.
        let connection = self.require_connection_mut(peer)?;
        connection.apply(ConnectionEvent::Approved)?;
        connection.presented_local_did = Some(presented_local_did.clone());
        connection.our_offer = Some(our_coords);

        // Only now that consent is recorded do we begin maintaining the peer's profile store.
        self.subscriber.subscribe(&their_store).map_err(seam)?;

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
        // Guard-before-side-effect: only a live connection can be revoked.
        self.require_connection_mut(peer)?
            .apply(ConnectionEvent::Revoked)?;
        self.tear_down_data_plane(peer)?;
        let message = SocialMessage::Revoke(Revoke);
        self.send(presented_local_did, peer, &message)?;
        self.persist()
    }

    /// Handle an inbound sealed envelope from a peer, dispatching on the message kind.
    ///
    /// `our_secret` is our BLS-G1 identity key, needed to open (decapsulate) any sealed offer the
    /// message carries; the app supplies it per call and the core never retains it (#908 boundary).
    pub fn handle_incoming(
        &mut self,
        our_secret: &SecretKey,
        envelope: &SealedEnvelope,
    ) -> Result<()> {
        let message = SocialMessage::from_canonical_bytes(&envelope.payload)?;
        match message {
            SocialMessage::Request(request) => {
                self.on_request(our_secret, &envelope.sender, &request)
            }
            SocialMessage::Accept(accept) => self.on_accept(our_secret, &envelope.sender, &accept),
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
    fn on_request(
        &mut self,
        our_secret: &SecretKey,
        sender: &Did,
        request: &ConnectRequest,
    ) -> Result<()> {
        let their_store = self.open_offer(our_secret, sender, &request.requestor_offer)?;
        self.graph.receive_request(sender.clone(), their_store)?;
        self.persist()
    }

    /// Complete an outbound handshake: open the peer's offer, subscribe, mark [`Connected`].
    ///
    /// [`Connected`]: crate::state::ConnectionState::Connected
    fn on_accept(
        &mut self,
        our_secret: &SecretKey,
        sender: &Did,
        accept: &ConnectAccept,
    ) -> Result<()> {
        let their_store = self.open_offer(our_secret, sender, &accept.recipient_offer)?;

        // Guard-before-side-effect: validate the transition FIRST. A replayed or injected Accept on
        // a Revoked/Denied/otherwise-ineligible connection must NOT subscribe — otherwise it would
        // resurrect the data-plane of a revoked connection or bypass the handshake ordering.
        let connection = self.require_connection_mut(sender)?;
        connection.apply(ConnectionEvent::AcceptReceived)?;
        connection.their_store = Some(their_store.clone());

        self.subscriber.subscribe(&their_store).map_err(seam)?;
        self.persist()
    }

    /// Record an inbound denial.
    fn on_deny(&mut self, sender: &Did) -> Result<()> {
        self.require_connection_mut(sender)?
            .apply(ConnectionEvent::Denied)?;
        self.persist()
    }

    /// Record an inbound revocation: mark revoked, then tear down the data-plane.
    fn on_revoke(&mut self, sender: &Did) -> Result<()> {
        // Guard-before-side-effect: only a live connection can be revoked.
        self.require_connection_mut(sender)?
            .apply(ConnectionEvent::Revoked)?;
        self.tear_down_data_plane(sender)?;
        self.persist()
    }

    // --- helpers ----------------------------------------------------------------------------

    /// Stop maintaining a peer's profile store and drop its coordinates, so a revoked connection has
    /// no data-plane left for a late or replayed `Accept` to resurrect (invariant #4).
    fn tear_down_data_plane(&mut self, peer: &Did) -> Result<()> {
        if let Some(their_store) = self.graph.get(peer).and_then(|c| c.their_store.clone()) {
            self.subscriber.unsubscribe(&their_store).map_err(seam)?;
        }
        if let Some(connection) = self.graph.get_mut(peer) {
            connection.their_store = None;
        }
        Ok(())
    }

    /// Seal our coordinates to a recipient, producing a [`SealedOffer`].
    fn seal_offer(&self, recipient: &Did, coords: &StoreCoords) -> Result<SealedOffer> {
        let ciphertext = self
            .sealer
            .seal(recipient, &coords.to_canonical_bytes())
            .map_err(seam)?;
        Ok(SealedOffer::new(ciphertext))
    }

    /// Open + validate a peer's sealed offer into [`StoreCoords`], decapsulating with our BLS-G1
    /// secret key (supplied by the app, never retained — #908) and binding the DID identity (§5.4).
    ///
    /// Three checks make the offer trustworthy, in order:
    ///
    /// 1. The seam authenticates the sealer (its BLS-G2 signature over the chain-resolved identity
    ///    key) and returns that identity as [`OpenedEnvelope::sender`].
    /// 2. That authenticated sealer MUST equal the DID the envelope claims to be from
    ///    (`declared_sender`) — otherwise an on-path relay could re-attribute a validly-sealed offer
    ///    to a different peer.
    /// 3. The offerer must OWN the store it offers: the offered coordinates' DID must be that same
    ///    authenticated sealer (so nobody can seal an offer pointing at a DID they do not control).
    ///
    /// [`OpenedEnvelope`]: crate::seams::OpenedEnvelope
    fn open_offer(
        &self,
        our_secret: &SecretKey,
        declared_sender: &Did,
        offer: &SealedOffer,
    ) -> Result<StoreCoords> {
        let opened = self
            .sealer
            .open(our_secret, &offer.ciphertext)
            .map_err(seam)?;

        if opened.sender != declared_sender.launcher_id() {
            return Err(Error::Invariant(
                "sealed sender does not match the envelope's declared sender DID",
            ));
        }

        let coords = StoreCoords::from_canonical_bytes(&opened.plaintext)?;
        if coords.did.launcher_id() != opened.sender {
            return Err(Error::Invariant(
                "offered store DID does not match the authenticated sealer",
            ));
        }
        Ok(coords)
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
