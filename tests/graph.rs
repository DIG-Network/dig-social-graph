//! The managed graph collection: insert/lookup/iterate/remove and deterministic serde.

mod common;
use common::{make_coords, make_did};

use dig_social_graph::{Connection, ConnectionState, SocialGraph, StoreCoords};

#[test]
fn empty_graph_is_empty() {
    let graph = SocialGraph::new();
    assert!(graph.is_empty());
    assert_eq!(graph.len(), 0);
}

#[test]
fn initiate_records_offer_first_intent() {
    let mut graph = SocialGraph::new();
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let coords = make_coords(&me, 0xAA);
    graph
        .initiate(peer.clone(), me.clone(), coords.clone())
        .unwrap();

    let conn = graph.get(&peer).unwrap();
    assert_eq!(conn.state, ConnectionState::Requested);
    assert_eq!(conn.our_offer.as_ref(), Some(&coords));
    assert_eq!(conn.their_store, None);
    assert_eq!(graph.len(), 1);
}

#[test]
fn receive_request_stores_peer_coords() {
    let mut graph = SocialGraph::new();
    let peer = make_did(0x02);
    let their: StoreCoords = make_coords(&peer, 0xBB);
    graph.receive_request(peer.clone(), their.clone()).unwrap();
    let conn = graph.get(&peer).unwrap();
    assert_eq!(conn.state, ConnectionState::AwaitingRecipientSelect);
    assert_eq!(conn.their_store.as_ref(), Some(&their));
}

#[test]
fn duplicate_peer_is_rejected_both_directions() {
    let mut graph = SocialGraph::new();
    let me = make_did(0x01);
    let peer = make_did(0x02);
    graph
        .initiate(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    assert!(graph
        .initiate(peer.clone(), me.clone(), make_coords(&me, 0xAA))
        .is_err());
    assert!(graph
        .receive_request(peer, make_coords(&make_did(0x02), 0xBB))
        .is_err());
}

#[test]
fn remove_and_iter_and_get_mut() {
    let mut graph = SocialGraph::new();
    let me = make_did(0x01);
    let a = make_did(0x02);
    let b = make_did(0x03);
    graph
        .initiate(a.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    graph
        .initiate(b.clone(), me.clone(), make_coords(&me, 0xAA))
        .unwrap();
    assert_eq!(graph.iter().count(), 2);

    graph
        .get_mut(&a)
        .unwrap()
        .apply(dig_social_graph::ConnectionEvent::RequestDelivered)
        .unwrap();
    assert_eq!(
        graph.get(&a).unwrap().state,
        ConnectionState::RequestorOffered
    );

    let removed = graph.remove(&a).unwrap();
    assert_eq!(removed.peer, a);
    assert!(graph.get(&a).is_none());
    assert_eq!(graph.len(), 1);
}

#[test]
fn graph_serde_round_trips_deterministically() {
    let mut graph = SocialGraph::new();
    let me = make_did(0x01);
    for filler in [0x02u8, 0x03, 0x04] {
        let peer = make_did(filler);
        graph
            .initiate(peer, me.clone(), make_coords(&me, 0xAA))
            .unwrap();
    }
    let json = serde_json::to_string(&graph).unwrap();
    let again =
        serde_json::to_string(&serde_json::from_str::<SocialGraph>(&json).unwrap()).unwrap();
    assert_eq!(json, again, "serde is a stable round-trip");
}

#[test]
fn connection_upsert_replaces() {
    let mut graph = SocialGraph::new();
    let me = make_did(0x01);
    let peer = make_did(0x02);
    let mut conn = Connection {
        peer: peer.clone(),
        state: ConnectionState::Connected,
        presented_local_did: Some(me),
        our_offer: None,
        their_store: None,
    };
    graph.upsert(conn.clone());
    conn.state = ConnectionState::Revoked;
    graph.upsert(conn);
    assert_eq!(graph.get(&peer).unwrap().state, ConnectionState::Revoked);
    assert_eq!(graph.len(), 1);
}
