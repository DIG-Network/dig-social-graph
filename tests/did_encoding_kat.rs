//! Known-answer tests pinning the canonical `did:chia:` bech32m encoding.
//!
//! WHY a KAT and not a round-trip: `resolve_sender_g1` (`src/sealer.rs`) reconstructs the sender's
//! DID string from the launcher id the seal authenticates, then resolves a key from it. The seal
//! binds the launcher, so the STRING must be reproduced byte-identically by every build or a peer
//! resolves a different DID and the open fails closed — senders silently split from receivers.
//!
//! The encoding is produced by `chia-sdk-utils`' bech32m codec over a `Bytes32` supplied by
//! `dig-identity`, so BOTH of those dependencies sit underneath this wire-visible value. The
//! existing `did()` test helper encodes and then parses back, which is self-consistent: it stays
//! green even if the codec changed, because the parse follows whatever the encode produced. Only a
//! pinned literal can detect a codec change, which is exactly what a dependency bump can introduce.
//!
//! These vectors were captured independently under both the pre-bump dependency set
//! (dig-identity 0.4.2 / chia-sdk-utils 0.30) and the current one (dig-identity 0.7.1 /
//! chia-sdk-utils 0.36.0) and compared: byte-identical, which is the evidence that the move to the
//! chia-0.36 ceiling preserves seal compatibility with already-deployed peers.

use chia_sdk_utils::Address;
use dig_identity::did::DID_CHIA_PREFIX;
use dig_identity::{Bytes32, Did};

/// Encode a launcher id exactly as `resolve_sender_g1` does.
fn encode_did(launcher: [u8; 32]) -> String {
    Address::new(Bytes32::from(launcher), DID_CHIA_PREFIX.to_string())
        .encode()
        .expect("the canonical did:chia: codec must encode any 32-byte launcher id")
}

#[test]
fn did_chia_prefix_is_the_wire_literal() {
    // Restating the constant would be a tautology; the point is that the WIRE value is this.
    assert_eq!(DID_CHIA_PREFIX, "did:chia:");
}

#[test]
fn launcher_id_encodes_to_the_pinned_did_string() {
    assert_eq!(
        encode_did([0x01; 32]),
        "did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s",
    );
    assert_eq!(
        encode_did([0x02; 32]),
        "did:chia:1qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq4msw0c",
    );
}

#[test]
fn the_pinned_string_parses_back_to_a_did() {
    // Closes the loop the KAT opens: the pinned literal is not merely stable, it is the value the
    // resolver path actually accepts. A codec that changed only its PARSE side would pass the
    // assertions above while still breaking `resolve_sender_g1`.
    let text = "did:chia:1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqscdhf6s";
    assert!(Did::parse(text).is_some(), "the pinned DID must parse");
}
