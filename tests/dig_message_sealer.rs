//! Custody KATs for the real [`DigMessageSealer`] — the dig-message BLS-G1-DHKEM auth-seal (§5.4).
//!
//! These exercise the ACTUAL crypto (no passthrough): a profile offer sealed to a recipient's BLS-G1
//! identity key round-trips only for that recipient, only from the authenticated sender, and only
//! once — and a relay sees nothing but ciphertext. The chain is stood in for by an in-memory
//! [`KeyResolver`] registry so the seal/open composition is proven end-to-end without a live node.

mod common;
use common::{make_coords, make_did, make_secret};

use std::collections::HashMap;

use dig_identity::bls::public_key_bytes;
use dig_social_graph::{
    manager::SocialGraphManager,
    sealer::{Clock, DigMessageSealer, KeyResolver},
    ConnectRequest, ConnectionState, Did, EnvelopeSealer, Error, Result, SealedEnvelope,
    SealedOffer, SecretKey, SocialMessage,
};

// The wall-clock the seal timestamp + open freshness check share; a fixed value keeps KATs
// deterministic and well inside the freshness window.
const NOW_MS: u64 = 1_700_000_000_000;

/// A fixed-time clock so seal (timestamp) and open (freshness) agree deterministically.
#[derive(Clone, Copy)]
struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// An in-memory DID → G1 key registry standing in for chain resolution.
#[derive(Clone, Default)]
struct TestResolver {
    keys: HashMap<Did, [u8; 48]>,
}
impl TestResolver {
    fn with(entries: &[(&Did, [u8; 48])]) -> Self {
        let keys = entries.iter().map(|(d, k)| ((*d).clone(), *k)).collect();
        Self { keys }
    }
}
impl KeyResolver for TestResolver {
    fn resolve_g1(&self, did: &Did) -> Result<[u8; 48]> {
        self.keys
            .get(did)
            .copied()
            .ok_or(Error::Seam("no key for did".into()))
    }
}

/// A sealer for `sender_did`/`sender_sk` that resolves every party in `registry`, at [`NOW_MS`].
fn sealer(
    sender_sk: SecretKey,
    sender_did: &Did,
    registry: &[(&Did, [u8; 48])],
) -> DigMessageSealer<TestResolver, FixedClock> {
    DigMessageSealer::with_clock(
        sender_sk,
        sender_did,
        0,
        TestResolver::with(registry),
        FixedClock(NOW_MS),
    )
}

/// A sender/recipient identity: a deterministic key + its DID + its published G1 key.
struct Party {
    did: Did,
    sk: SecretKey,
    g1: [u8; 48],
}
fn party(filler: u8) -> Party {
    let sk = make_secret(filler);
    Party {
        did: make_did(filler),
        g1: public_key_bytes(&sk),
        sk,
    }
}

#[test]
fn seal_open_round_trips_to_the_recipient() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let coords = make_coords(&sender.did, 0xAB);

    let registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &registry);
    let rx = sealer(recipient.sk, &recipient.did, &registry);

    let ciphertext = tx
        .seal(&recipient.did, &coords.to_canonical_bytes())
        .unwrap();
    // The app supplies the recipient's own secret to `open` (0x22, the recipient's filler).
    let opened = rx.open(&make_secret(0x22), &ciphertext).unwrap();

    assert_eq!(opened.plaintext, coords.to_canonical_bytes());
    assert_eq!(
        opened.sender,
        sender.did.launcher_id(),
        "open authenticates the sealing DID"
    );
}

#[test]
fn wrong_recipient_cannot_open() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let intruder_sk = make_secret(0x33);
    let coords = make_coords(&sender.did, 0xAB);

    let registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &registry);
    let rx = sealer(make_secret(0x22), &recipient.did, &registry);

    let ciphertext = tx
        .seal(&recipient.did, &coords.to_canonical_bytes())
        .unwrap();
    assert!(
        rx.open(&intruder_sk, &ciphertext).is_err(),
        "a non-recipient key must fail to decapsulate"
    );
}

#[test]
fn wrong_sender_key_fails_signature() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let coords = make_coords(&sender.did, 0xAB);

    // The recipient resolves the sender DID to a DIFFERENT (wrong) G1 key, so the seal's BLS-G2
    // sender signature cannot verify.
    let wrong_g1 = public_key_bytes(&make_secret(0x99));
    let tx_registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let rx_registry = [(&sender.did, wrong_g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &tx_registry);
    let rx = sealer(make_secret(0x22), &recipient.did, &rx_registry);

    let ciphertext = tx
        .seal(&recipient.did, &coords.to_canonical_bytes())
        .unwrap();
    assert!(
        rx.open(&make_secret(0x22), &ciphertext).is_err(),
        "a mismatched sender key must fail the signature check"
    );
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let coords = make_coords(&sender.did, 0xAB);

    let registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &registry);
    let rx = sealer(make_secret(0x22), &recipient.did, &registry);

    let mut ciphertext = tx
        .seal(&recipient.did, &coords.to_canonical_bytes())
        .unwrap();
    *ciphertext.last_mut().unwrap() ^= 0xFF;
    assert!(
        rx.open(&make_secret(0x22), &ciphertext).is_err(),
        "a flipped ciphertext byte must fail the AEAD"
    );
}

#[test]
fn replayed_envelope_is_rejected() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let coords = make_coords(&sender.did, 0xAB);

    let registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &registry);
    let rx = sealer(make_secret(0x22), &recipient.did, &registry);

    let ciphertext = tx
        .seal(&recipient.did, &coords.to_canonical_bytes())
        .unwrap();
    assert!(rx.open(&make_secret(0x22), &ciphertext).is_ok());
    assert!(
        rx.open(&make_secret(0x22), &ciphertext).is_err(),
        "the replay guard must reject the second open of the same envelope"
    );
}

#[test]
fn relay_sees_only_ciphertext() {
    let sender = party(0x11);
    let recipient = party(0x22);
    let coords = make_coords(&sender.did, 0xAB);
    let plaintext = coords.to_canonical_bytes();

    let registry = [(&sender.did, sender.g1), (&recipient.did, recipient.g1)];
    let tx = sealer(sender.sk, &sender.did, &registry);
    let ciphertext = tx.seal(&recipient.did, &plaintext).unwrap();

    assert!(
        !ciphertext
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_slice()),
        "the sealed bytes must not contain the plaintext offer an intermediary could read"
    );
}

// --- manager-level DID validation with the real seal --------------------------------------------

type RealMgr = SocialGraphManager<
    common::MockTransport,
    DigMessageSealer<TestResolver, FixedClock>,
    common::MockSubscriber,
    common::MemPersistence,
>;

fn manager_for(recipient: &Party, registry: &[(&Did, [u8; 48])]) -> RealMgr {
    SocialGraphManager::load(
        common::MockTransport::online(),
        sealer(make_secret(0x22), &recipient.did, registry),
        common::MockSubscriber::default(),
        common::MemPersistence::default(),
    )
    .unwrap()
    // `recipient` filler is fixed at 0x22 by the callers below.
}

/// An inbound request carrying `offer`, declaring `declared_sender`.
fn inbound_request(declared_sender: &Did, me: &Did, offer: SealedOffer) -> SealedEnvelope {
    SealedEnvelope {
        sender: declared_sender.clone(),
        recipient: me.clone(),
        payload: SocialMessage::Request(ConnectRequest {
            requestor_offer: offer,
        })
        .to_canonical_bytes(),
    }
}

#[test]
fn manager_accepts_a_genuinely_sealed_offer() {
    let peer = party(0x11);
    let me = party(0x22);
    let their_coords = make_coords(&peer.did, 0xBB);

    let registry = [(&peer.did, peer.g1), (&me.did, me.g1)];
    let peer_sealer = sealer(peer.sk, &peer.did, &registry);
    let offer = SealedOffer::new(
        peer_sealer
            .seal(&me.did, &their_coords.to_canonical_bytes())
            .unwrap(),
    );

    let mut mgr = manager_for(&me, &registry);
    mgr.handle_incoming(
        &make_secret(0x22),
        &inbound_request(&peer.did, &me.did, offer),
    )
    .unwrap();

    let conn = mgr.graph().get(&peer.did).unwrap();
    assert_eq!(conn.state(), ConnectionState::AwaitingRecipientSelect);
    assert_eq!(conn.their_store.as_ref(), Some(&their_coords));
}

#[test]
fn manager_rejects_a_relay_reattributed_sender() {
    let peer = party(0x11);
    let me = party(0x22);
    let stranger = party(0x44);
    let their_coords = make_coords(&peer.did, 0xBB);

    let registry = [
        (&peer.did, peer.g1),
        (&me.did, me.g1),
        (&stranger.did, stranger.g1),
    ];
    let peer_sealer = sealer(peer.sk, &peer.did, &registry);
    // A genuinely peer-sealed offer, but a relay swaps the envelope's declared sender to `stranger`.
    let offer = SealedOffer::new(
        peer_sealer
            .seal(&me.did, &their_coords.to_canonical_bytes())
            .unwrap(),
    );

    let mut mgr = manager_for(&me, &registry);
    let err = mgr
        .handle_incoming(
            &make_secret(0x22),
            &inbound_request(&stranger.did, &me.did, offer),
        )
        .unwrap_err();

    assert!(
        matches!(err, Error::Seam(_) | Error::Invariant(_)),
        "a re-attributed sender must be rejected, got {err:?}"
    );
    assert!(
        mgr.graph().get(&peer.did).is_none() && mgr.graph().get(&stranger.did).is_none(),
        "no connection may be recorded for a rejected offer"
    );
}

#[test]
fn manager_rejects_an_offer_for_a_foreign_store() {
    let peer = party(0x11);
    let me = party(0x22);
    let victim = party(0x55);
    // The peer seals coordinates for a store it does NOT own (the victim's DID).
    let foreign_coords = make_coords(&victim.did, 0xBB);

    let registry = [
        (&peer.did, peer.g1),
        (&me.did, me.g1),
        (&victim.did, victim.g1),
    ];
    let peer_sealer = sealer(peer.sk, &peer.did, &registry);
    let offer = SealedOffer::new(
        peer_sealer
            .seal(&me.did, &foreign_coords.to_canonical_bytes())
            .unwrap(),
    );

    let mut mgr = manager_for(&me, &registry);
    assert!(
        mgr.handle_incoming(
            &make_secret(0x22),
            &inbound_request(&peer.did, &me.did, offer)
        )
        .is_err(),
        "an offer whose store DID is not the authenticated sealer must be rejected"
    );
}
