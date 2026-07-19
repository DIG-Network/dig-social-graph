//! End-to-end orchestration over in-memory seams: the manager seals offers, drives subscriptions,
//! delivers messages, parks/resumes on presence, and persists — all without any real I/O.

mod common;
use common::{
    make_coords, make_did, make_secret, MemPersistence, MockSubscriber, MockTransport,
    PassthroughSealer,
};

use dig_social_graph::{
    ConnectionState, SealedEnvelope, SocialGraphManager, SocialMessage, StoreCoords,
};

type Mgr = SocialGraphManager<MockTransport, PassthroughSealer, MockSubscriber, MemPersistence>;

/// Build a manager plus handles to the seam doubles for assertions.
fn manager(online: bool) -> (Mgr, MockTransport, MockSubscriber, MemPersistence) {
    let transport = if online {
        MockTransport::online()
    } else {
        MockTransport::default()
    };
    let subscriber = MockSubscriber::default();
    let persistence = MemPersistence::default();
    let mgr = SocialGraphManager::load(
        transport.clone(),
        PassthroughSealer,
        subscriber.clone(),
        persistence.clone(),
    )
    .unwrap();
    (mgr, transport, subscriber, persistence)
}

/// The offer sealed inside the single sent message, decoded back to coordinates (passthrough sealer).
fn sent_offer_coords(transport: &MockTransport) -> StoreCoords {
    let sent = transport.sent.borrow();
    let envelope = sent.last().expect("a message was sent");
    match SocialMessage::from_canonical_bytes(&envelope.payload).unwrap() {
        SocialMessage::Request(r) => {
            StoreCoords::from_canonical_bytes(&r.requestor_offer.ciphertext).unwrap()
        }
        SocialMessage::Accept(a) => {
            StoreCoords::from_canonical_bytes(&a.recipient_offer.ciphertext).unwrap()
        }
        other => panic!("expected an offer-bearing message, got {other:?}"),
    }
}

#[test]
fn outbound_request_online_offers_first_and_delivers() {
    let (mut mgr, transport, _sub, persistence) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let my_coords = make_coords(&me, 0xAA);

    mgr.request(peer.clone(), me.clone(), my_coords.clone())
        .unwrap();

    let conn = mgr.graph().get(&peer).unwrap();
    assert_eq!(conn.state(), ConnectionState::RequestorOffered);
    assert_eq!(conn.presented_local_did.as_ref(), Some(&me));
    // Offer-first: our own coordinates were the thing offered.
    assert_eq!(sent_offer_coords(&transport), my_coords);
    // Persisted.
    assert_eq!(persistence.saved.borrow().len(), 1);
}

#[test]
fn outbound_request_offline_parks_for_rendezvous_then_resumes() {
    let (mut mgr, transport, _sub, _p) = manager(false);
    let me = make_did(0x01);
    let peer = make_did(0x02);

    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    assert!(matches!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::PendingRendezvous(_)
    ));
    assert!(transport.sent.borrow().is_empty(), "offline: nothing sent");

    mgr.resume_peer(&peer).unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::Requested
    );
}

#[test]
fn cannot_request_the_same_peer_twice() {
    let (mut mgr, _t, _s, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    assert!(mgr
        .request(peer, me.clone(), make_coords(&me, 0xAA))
        .is_err());
}

#[test]
fn inbound_request_then_approve_subscribes_and_offers_back() {
    let (mut mgr, transport, subscriber, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);
    let my_coords = make_coords(&me, 0xAA);

    // Peer's request arrives (offer sealed = canonical coords via passthrough).
    let request = SocialMessage::Request(dig_social_graph::ConnectRequest {
        requestor_offer: dig_social_graph::SealedOffer::new(their_coords.to_canonical_bytes()),
    });
    let envelope = SealedEnvelope {
        sender: peer.clone(),
        recipient: me.clone(),
        payload: request.to_canonical_bytes(),
    };
    mgr.handle_incoming(&make_secret(0x01), &envelope).unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::AwaitingRecipientSelect
    );

    // Approve: subscribe to their store, offer ours back.
    mgr.approve(&peer, me.clone(), my_coords.clone()).unwrap();
    let conn = mgr.graph().get(&peer).unwrap();
    assert_eq!(conn.state(), ConnectionState::RecipientOffered);
    assert_eq!(conn.their_store.as_ref(), Some(&their_coords));
    assert_eq!(subscriber.subscribed.borrow().as_slice(), &[their_coords]);
    assert_eq!(sent_offer_coords(&transport), my_coords);
}

#[test]
fn approve_without_inbound_request_is_rejected() {
    let (mut mgr, _t, _s, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    assert!(mgr
        .approve(&peer, me.clone(), make_coords(&me, 0xAA))
        .is_err());
}

#[test]
fn outbound_accept_received_reaches_connected_and_subscribes() {
    let (mut mgr, _t, subscriber, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();

    let accept = SocialMessage::Accept(dig_social_graph::ConnectAccept {
        recipient_offer: dig_social_graph::SealedOffer::new(their_coords.to_canonical_bytes()),
    });
    let envelope = SealedEnvelope {
        sender: peer.clone(),
        recipient: me.clone(),
        payload: accept.to_canonical_bytes(),
    };
    mgr.handle_incoming(&make_secret(0x01), &envelope).unwrap();

    let conn = mgr.graph().get(&peer).unwrap();
    assert_eq!(conn.state(), ConnectionState::Connected);
    assert_eq!(conn.their_store.as_ref(), Some(&their_coords));
    assert_eq!(subscriber.subscribed.borrow().len(), 1);
}

#[test]
fn revoke_unsubscribes_and_terminates() {
    let (mut mgr, _t, subscriber, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    // Drive to Connected as the requestor.
    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    let accept = SocialMessage::Accept(dig_social_graph::ConnectAccept {
        recipient_offer: dig_social_graph::SealedOffer::new(their_coords.to_canonical_bytes()),
    });
    mgr.handle_incoming(
        &make_secret(0x01),
        &SealedEnvelope {
            sender: peer.clone(),
            recipient: me.clone(),
            payload: accept.to_canonical_bytes(),
        },
    )
    .unwrap();

    mgr.revoke(&peer, &me).unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::Revoked
    );
    assert_eq!(subscriber.unsubscribed.borrow().as_slice(), &[their_coords]);
}

#[test]
fn inbound_deny_terminates_outbound_connection() {
    let (mut mgr, _t, _s, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();

    let deny = SocialMessage::Deny(dig_social_graph::ConnectDeny);
    mgr.handle_incoming(
        &make_secret(0x01),
        &SealedEnvelope {
            sender: peer.clone(),
            recipient: me.clone(),
            payload: deny.to_canonical_bytes(),
        },
    )
    .unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::Denied
    );
}

#[test]
fn local_deny_notifies_and_terminates() {
    let (mut mgr, transport, _s, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);
    mgr.handle_incoming(
        &make_secret(0x01),
        &SealedEnvelope {
            sender: peer.clone(),
            recipient: me.clone(),
            payload: SocialMessage::Request(dig_social_graph::ConnectRequest {
                requestor_offer: dig_social_graph::SealedOffer::new(
                    their_coords.to_canonical_bytes(),
                ),
            })
            .to_canonical_bytes(),
        },
    )
    .unwrap();

    mgr.deny(&peer, &me).unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::Denied
    );
    assert!(matches!(
        SocialMessage::from_canonical_bytes(&transport.sent.borrow().last().unwrap().payload)
            .unwrap(),
        SocialMessage::Deny(_)
    ));
}

#[test]
fn persistence_failure_surfaces() {
    let (mut mgr, _t, _s, persistence) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    persistence.fail.set(true);
    assert!(mgr
        .request(peer, me.clone(), make_coords(&me, 0xAA))
        .is_err());
}

/// An accept envelope from `peer` to `me` offering `their_coords` (passthrough-sealed).
fn accept_envelope(
    peer: &dig_social_graph::Did,
    me: &dig_social_graph::Did,
    their: &StoreCoords,
) -> SealedEnvelope {
    SealedEnvelope {
        sender: peer.clone(),
        recipient: me.clone(),
        payload: SocialMessage::Accept(dig_social_graph::ConnectAccept {
            recipient_offer: dig_social_graph::SealedOffer::new(their.to_canonical_bytes()),
        })
        .to_canonical_bytes(),
    }
}

/// A request envelope from `peer` to `me` offering `their_coords` (passthrough-sealed).
fn request_envelope(
    peer: &dig_social_graph::Did,
    me: &dig_social_graph::Did,
    their: &StoreCoords,
) -> SealedEnvelope {
    SealedEnvelope {
        sender: peer.clone(),
        recipient: me.clone(),
        payload: SocialMessage::Request(dig_social_graph::ConnectRequest {
            requestor_offer: dig_social_graph::SealedOffer::new(their.to_canonical_bytes()),
        })
        .to_canonical_bytes(),
    }
}

/// Regression (guard-before-side-effect): a replayed Accept AFTER revoke must NOT re-subscribe —
/// the transition is illegal in `Revoked`, so the subscribe side-effect never fires and the revoked
/// connection's data-plane is not resurrected.
#[test]
fn replayed_accept_after_revoke_does_not_resubscribe() {
    let (mut mgr, _t, subscriber, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    let accept = accept_envelope(&peer, &me, &their_coords);
    mgr.handle_incoming(&make_secret(0x01), &accept).unwrap();
    mgr.revoke(&peer, &me).unwrap();

    let subscribes_after_revoke = subscriber.subscribed.borrow().len();
    // Replay the exact same Accept the peer sent earlier.
    assert!(mgr.handle_incoming(&make_secret(0x01), &accept).is_err());
    assert_eq!(
        subscriber.subscribed.borrow().len(),
        subscribes_after_revoke,
        "a replayed Accept on a Revoked connection must not subscribe"
    );
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::Revoked
    );
}

/// Regression (consent gate): an Accept injected while the connection is still awaiting the local
/// user's approval must NOT subscribe — the transition is illegal pre-consent.
#[test]
fn accept_before_consent_does_not_subscribe() {
    let (mut mgr, _t, subscriber, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    // Inbound request → AwaitingRecipientSelect (not yet approved).
    mgr.handle_incoming(
        &make_secret(0x01),
        &request_envelope(&peer, &me, &their_coords),
    )
    .unwrap();
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::AwaitingRecipientSelect
    );

    // An injected Accept must be rejected without any subscribe.
    assert!(mgr
        .handle_incoming(
            &make_secret(0x01),
            &accept_envelope(&peer, &me, &their_coords)
        )
        .is_err());
    assert!(subscriber.subscribed.borrow().is_empty());
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::AwaitingRecipientSelect
    );
}

/// Regression (invariant #4): revoke clears `their_store`, so a revoked connection has no data-plane
/// coordinates left for a late/replayed Accept to resurrect.
#[test]
fn revoke_clears_their_store() {
    let (mut mgr, _t, _s, _p) = manager(true);
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    mgr.request(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    mgr.handle_incoming(
        &make_secret(0x01),
        &accept_envelope(&peer, &me, &their_coords),
    )
    .unwrap();
    assert!(mgr.graph().get(&peer).unwrap().their_store.is_some());

    mgr.revoke(&peer, &me).unwrap();
    assert!(
        mgr.graph().get(&peer).unwrap().their_store.is_none(),
        "revoke must clear their_store"
    );
}
