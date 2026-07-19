//! The [`EnvelopeSealer`] seam is BLS-G1-aware: `open` is *supplied* the app-held `&SecretKey` it
//! needs for G1 decapsulation. These tests pin that contract — a sealer implementation receives the
//! exact secret key the manager was handed, and a BLS-shaped mock round-trips through the manager —
//! so SG-2 (#991) can drop in the real dig-message DHKEM-over-G1 seal against a stable seam.

mod common;
use common::{make_coords, make_did, make_secret, MemPersistence, MockSubscriber, MockTransport};

use std::cell::RefCell;
use std::rc::Rc;

use dig_social_graph::{
    ConnectRequest, ConnectionState, Did, EnvelopeSealer, Result, SealedEnvelope, SealedOffer,
    SecretKey, SocialGraphManager, SocialMessage,
};

/// A sealer that records the secret key bytes handed to every `open`, proving the seam supplies the
/// app-held `&SecretKey` (G1 decap material, not a sign-only callback). Sealing/opening themselves
/// are the identity function so the offered coordinates stay decodable.
#[derive(Clone, Default)]
struct RecordingSealer {
    opened_with: Rc<RefCell<Vec<[u8; 32]>>>,
}

impl EnvelopeSealer for RecordingSealer {
    fn seal(&self, _recipient: &Did, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, our_secret: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.opened_with.borrow_mut().push(our_secret.to_bytes());
        Ok(ciphertext.to_vec())
    }
}

#[test]
fn open_is_supplied_the_apps_secret_key() {
    let transport = MockTransport::online();
    let sealer = RecordingSealer::default();
    let mut mgr = SocialGraphManager::load(
        transport,
        sealer.clone(),
        MockSubscriber::default(),
        MemPersistence::default(),
    )
    .unwrap();

    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);
    let our_key = make_secret(0x07);

    // An inbound request forces the manager to open the peer's offer — using the key we supply.
    let request = SocialMessage::Request(ConnectRequest {
        requestor_offer: SealedOffer::new(their_coords.to_canonical_bytes()),
    });
    let envelope = SealedEnvelope {
        sender: peer.clone(),
        recipient: me,
        payload: request.to_canonical_bytes(),
    };
    mgr.handle_incoming(&our_key, &envelope).unwrap();

    // The seam received exactly the secret key the caller supplied — the BLS decap contract holds.
    assert_eq!(
        sealer.opened_with.borrow().as_slice(),
        &[our_key.to_bytes()],
        "open must be handed the app-supplied BLS-G1 secret key"
    );
    assert_eq!(
        mgr.graph().get(&peer).unwrap().state(),
        ConnectionState::AwaitingRecipientSelect
    );
}

#[test]
fn opened_coordinates_round_trip_through_the_seam() {
    let transport = MockTransport::online();
    let mut mgr = SocialGraphManager::load(
        transport,
        RecordingSealer::default(),
        MockSubscriber::default(),
        MemPersistence::default(),
    )
    .unwrap();

    let me = make_did(0x01);
    let peer = make_did(0x02);
    let their_coords = make_coords(&peer, 0xBB);

    let request = SocialMessage::Request(ConnectRequest {
        requestor_offer: SealedOffer::new(their_coords.to_canonical_bytes()),
    });
    mgr.handle_incoming(
        &make_secret(0x01),
        &SealedEnvelope {
            sender: peer.clone(),
            recipient: me,
            payload: request.to_canonical_bytes(),
        },
    )
    .unwrap();

    // The coordinates recovered by the seam are exactly what the peer offered.
    assert_eq!(
        mgr.graph().get(&peer).unwrap().their_store.as_ref(),
        Some(&their_coords)
    );
}
