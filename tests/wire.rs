//! Wire-type contracts: the canonical byte encodings round-trip, malformed buffers are rejected,
//! the DID↔launcher-id invariant is enforced, and the persisted `serde` form round-trips.

mod common;
use common::{make_coords, make_did};

use dig_social_graph::{
    Bytes32, ConnectAccept, ConnectDeny, ConnectRequest, Error, Revoke, SealedOffer, SocialMessage,
    StoreCoords,
};

#[test]
fn store_coords_canonical_bytes_round_trip() {
    let did = make_did(0x11);
    let coords = make_coords(&did, 0x22);
    let bytes = coords.to_canonical_bytes();
    let decoded = StoreCoords::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, coords);
}

#[test]
fn store_coords_rejects_launcher_mismatch() {
    let did = make_did(0x11);
    // Hand-build coordinates whose launcher id does not match the DID.
    let bogus = StoreCoords {
        did,
        launcher_id: Bytes32::from([0xFF; 32]),
        committed_root: Bytes32::from([0x22; 32]),
    };
    assert!(matches!(bogus.validate(), Err(Error::Invariant(_))));
}

#[test]
fn store_coords_from_did_derives_matching_launcher() {
    let did = make_did(0x11);
    let coords = StoreCoords::from_did(did.clone(), Bytes32::from([0x22; 32]));
    assert_eq!(coords.launcher_id, did.launcher_id());
    coords.validate().unwrap();
}

#[test]
fn store_coords_decode_rejects_malformed_buffers() {
    assert!(matches!(
        StoreCoords::from_canonical_bytes(&[0x00]),
        Err(Error::Wire(_))
    ));
    let did = make_did(0x11);
    let mut bytes = make_coords(&did, 0x22).to_canonical_bytes();
    bytes.push(0xAB); // trailing byte
    assert!(matches!(
        StoreCoords::from_canonical_bytes(&bytes),
        Err(Error::Wire(_))
    ));
}

#[test]
fn social_message_canonical_bytes_round_trip() {
    let offer = SealedOffer::new(vec![1, 2, 3, 4]);
    let messages = [
        SocialMessage::Request(ConnectRequest {
            requestor_offer: offer.clone(),
        }),
        SocialMessage::Accept(ConnectAccept {
            recipient_offer: offer,
        }),
        SocialMessage::Deny(ConnectDeny),
        SocialMessage::Revoke(Revoke),
    ];
    for message in messages {
        let bytes = message.to_canonical_bytes();
        assert_eq!(
            SocialMessage::from_canonical_bytes(&bytes).unwrap(),
            message
        );
    }
}

#[test]
fn social_message_decode_rejects_bad_input() {
    assert!(matches!(
        SocialMessage::from_canonical_bytes(&[]),
        Err(Error::Wire(_))
    ));
    assert!(matches!(
        SocialMessage::from_canonical_bytes(&[9]), // unknown tag
        Err(Error::Wire(_))
    ));
    assert!(matches!(
        SocialMessage::from_canonical_bytes(&[2, 0xFF]), // Deny with trailing bytes
        Err(Error::Wire(_))
    ));
}

#[test]
fn store_coords_serde_round_trip() {
    let did = make_did(0x11);
    let coords = make_coords(&did, 0x22);
    let json = serde_json::to_string(&coords).unwrap();
    // DID is a did:chia: string; the 32-byte fields are lowercase hex.
    assert!(json.contains("did:chia:"));
    let decoded: StoreCoords = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, coords);
}

#[test]
fn store_coords_serde_rejects_bad_hex_length() {
    let json = r#"{"did":"did:chia:1abc","launcher_id":"00","committed_root":"00"}"#;
    assert!(serde_json::from_str::<StoreCoords>(json).is_err());
}
