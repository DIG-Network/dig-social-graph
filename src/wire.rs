//! The types exchanged between peers to build a connection.
//!
//! Two principles shape these types:
//!
//! 1. **What crosses the wire is a store COORDINATE, not a profile blob.** A peer never ships its
//!    profile inline; it ships [`StoreCoords`] — the `did` + `launcher_id` + `committed_root` that
//!    locate its IdentityProfile store on-chain. The receiver then subscribes to that store
//!    (via the [`StoreSubscriber`](crate::seams::StoreSubscriber) seam), resolves the profile
//!    locally, and verifies the DID↔store pairing and merkle proofs itself. This keeps the profile
//!    authoritative (chain-anchored) rather than trusting bytes a peer hands over.
//! 2. **Every offer is sealed to the recipient (§5.4).** The plaintext [`StoreCoords`] is encrypted
//!    to the recipient's identity key, producing a [`SealedOffer`], before it ever reaches the
//!    transport. The networkless core treats the ciphertext as opaque; the real sealing/opening is
//!    the [`EnvelopeSealer`](crate::seams::EnvelopeSealer) seam (dig-message).

use dig_identity::{Bytes32, Did};
use serde::{Deserialize, Serialize};

use crate::{codec, error::Error, error::Result};

/// The on-chain coordinates that locate a peer's IdentityProfile store.
///
/// This is the plaintext an offer carries. It is never sent in the clear — it is sealed into a
/// [`SealedOffer`] first. `launcher_id` is the DID's singleton launcher id and MUST equal
/// `did.launcher_id()`; [`StoreCoords::validate`] enforces that invariant so a coordinate can never
/// point a DID at a foreign store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreCoords {
    /// The peer's decentralized identifier (`did:chia:…`).
    #[serde(with = "codec::did_str")]
    pub did: Did,
    /// The DID singleton's launcher id. MUST equal `did.launcher_id()`.
    #[serde(with = "codec::hex_bytes32")]
    pub launcher_id: Bytes32,
    /// The committed profile-store root the offerer is vouching for at offer time.
    #[serde(with = "codec::hex_bytes32")]
    pub committed_root: Bytes32,
}

impl StoreCoords {
    /// Build coordinates from a DID and a committed root, deriving the launcher id from the DID so
    /// the two can never disagree.
    pub fn from_did(did: Did, committed_root: Bytes32) -> Self {
        let launcher_id = did.launcher_id();
        Self {
            did,
            launcher_id,
            committed_root,
        }
    }

    /// Check that `launcher_id` matches the DID's own launcher id.
    ///
    /// Coordinates that arrive over the wire (e.g. after opening a [`SealedOffer`]) MUST be
    /// validated before use — a mismatch means the coordinate is trying to bind a DID to a store it
    /// does not own.
    pub fn validate(&self) -> Result<()> {
        if self.launcher_id == self.did.launcher_id() {
            Ok(())
        } else {
            Err(Error::Invariant(
                "store launcher_id does not match the DID's launcher id",
            ))
        }
    }
}

impl StoreCoords {
    /// Encode to the canonical peer-wire byte form:
    /// `u16(BE) did_len ‖ did_utf8 ‖ launcher_id[32] ‖ committed_root[32]`.
    ///
    /// This is the byte-stable contract the [`EnvelopeSealer`](crate::seams::EnvelopeSealer) seals,
    /// distinct from the `serde` form used for at-rest persistence. Two implementations that agree
    /// on these bytes agree on the offer.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let did = self.did.as_str().as_bytes();
        let mut out = Vec::with_capacity(2 + did.len() + 64);
        out.extend_from_slice(&(did.len() as u16).to_be_bytes());
        out.extend_from_slice(did);
        out.extend_from_slice(self.launcher_id.as_ref());
        out.extend_from_slice(self.committed_root.as_ref());
        out
    }

    /// Decode from the canonical peer-wire byte form produced by [`to_canonical_bytes`].
    ///
    /// Validates the length-prefix and total size, the DID string, and the DID↔launcher-id pairing
    /// invariant ([`validate`]).
    ///
    /// [`to_canonical_bytes`]: StoreCoords::to_canonical_bytes
    /// [`validate`]: StoreCoords::validate
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let did_len = bytes
            .get(0..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
            .ok_or(Error::Wire("truncated: missing did length prefix"))?;
        let did_end = 2 + did_len;
        let did_bytes = bytes
            .get(2..did_end)
            .ok_or(Error::Wire("truncated: did shorter than its length prefix"))?;
        let did_str =
            core::str::from_utf8(did_bytes).map_err(|_| Error::Wire("did is not valid utf-8"))?;
        let did = Did::parse(did_str).ok_or(Error::Wire("not a valid did:chia: string"))?;

        let launcher = bytes
            .get(did_end..did_end + 32)
            .ok_or(Error::Wire("truncated: missing launcher id"))?;
        let root = bytes
            .get(did_end + 32..did_end + 64)
            .ok_or(Error::Wire("truncated: missing committed root"))?;
        if bytes.len() != did_end + 64 {
            return Err(Error::Wire("trailing bytes after committed root"));
        }

        let coords = Self {
            did,
            launcher_id: Bytes32::new(launcher.try_into().expect("slice is exactly 32 bytes")),
            committed_root: Bytes32::new(root.try_into().expect("slice is exactly 32 bytes")),
        };
        coords.validate()?;
        Ok(coords)
    }
}

/// A [`StoreCoords`] sealed to the recipient's identity key (§5.4 end-to-end).
///
/// The core holds only the ciphertext; it neither seals nor opens. The
/// [`EnvelopeSealer`](crate::seams::EnvelopeSealer) seam performs the real cryptography, so an
/// intermediary that relays this offer sees ciphertext only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOffer {
    /// The opaque sealed bytes of the offered [`StoreCoords`].
    pub ciphertext: Vec<u8>,
}

impl SealedOffer {
    /// Wrap already-sealed ciphertext.
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }
}

/// A connection request — the requestor presents their own offer FIRST (offer-first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    /// The requestor's own profile offer, sealed to the recipient.
    pub requestor_offer: SealedOffer,
}

/// A connection acceptance — the recipient selected a profile and offers it back (symmetric).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectAccept {
    /// The recipient's chosen profile offer, sealed to the requestor.
    pub recipient_offer: SealedOffer,
}

/// A connection denial — the recipient declined. Carries no offer; consent was withheld.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectDeny;

/// A revocation — either side ends a live connection (stop serving + unsubscribe).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoke;

/// The tagged union of everything a peer may send over a connection channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocialMessage {
    /// A new connection request (offer-first).
    Request(ConnectRequest),
    /// Acceptance of a request (symmetric offer back).
    Accept(ConnectAccept),
    /// Denial of a request.
    Deny(ConnectDeny),
    /// Revocation of a live connection.
    Revoke(Revoke),
}

/// Canonical message-kind tags for the wire encoding.
mod tag {
    pub const REQUEST: u8 = 0;
    pub const ACCEPT: u8 = 1;
    pub const DENY: u8 = 2;
    pub const REVOKE: u8 = 3;
}

impl SocialMessage {
    /// Encode to the canonical peer-wire byte form: a one-byte kind tag, followed for Request/Accept
    /// by `u32(BE) len ‖ sealed_offer_ciphertext`. Deny and Revoke carry no body.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        fn with_offer(kind: u8, offer: &SealedOffer) -> Vec<u8> {
            let mut out = Vec::with_capacity(5 + offer.ciphertext.len());
            out.push(kind);
            out.extend_from_slice(&(offer.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&offer.ciphertext);
            out
        }
        match self {
            SocialMessage::Request(r) => with_offer(tag::REQUEST, &r.requestor_offer),
            SocialMessage::Accept(a) => with_offer(tag::ACCEPT, &a.recipient_offer),
            SocialMessage::Deny(_) => vec![tag::DENY],
            SocialMessage::Revoke(_) => vec![tag::REVOKE],
        }
    }

    /// Decode from the canonical peer-wire byte form produced by [`to_canonical_bytes`].
    ///
    /// [`to_canonical_bytes`]: SocialMessage::to_canonical_bytes
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let (&kind, rest) = bytes
            .split_first()
            .ok_or(Error::Wire("empty message buffer"))?;
        let read_offer = || -> Result<SealedOffer> {
            let len = rest
                .get(0..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .ok_or(Error::Wire("truncated: missing offer length prefix"))?;
            let body = rest.get(4..4 + len).ok_or(Error::Wire(
                "truncated: offer shorter than its length prefix",
            ))?;
            if rest.len() != 4 + len {
                return Err(Error::Wire("trailing bytes after offer"));
            }
            Ok(SealedOffer::new(body.to_vec()))
        };
        match kind {
            tag::REQUEST => Ok(SocialMessage::Request(ConnectRequest {
                requestor_offer: read_offer()?,
            })),
            tag::ACCEPT => Ok(SocialMessage::Accept(ConnectAccept {
                recipient_offer: read_offer()?,
            })),
            tag::DENY if rest.is_empty() => Ok(SocialMessage::Deny(ConnectDeny)),
            tag::REVOKE if rest.is_empty() => Ok(SocialMessage::Revoke(Revoke)),
            tag::DENY | tag::REVOKE => Err(Error::Wire("trailing bytes after bodyless message")),
            _ => Err(Error::Wire("unknown message kind tag")),
        }
    }
}

/// A [`SocialMessage`] addressed for delivery over the peer channel.
///
/// The sensitive content — the offered [`StoreCoords`] — is already sealed to the recipient inside
/// each [`SealedOffer`], so an intermediary that relays this envelope cannot read a profile
/// reference (§5.4); only the message *kind* (an unavoidable routing detail) and the addressing DIDs
/// are visible. `sender` is the header-declared DID whose public key SG-2 validates against the
/// sealing key — the networkless core carries it but does not verify it (that is the crypto seam's
/// job).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// The declared sender DID (validated against the sealing key in SG-2).
    #[serde(with = "codec::did_str")]
    pub sender: Did,
    /// The intended recipient DID.
    #[serde(with = "codec::did_str")]
    pub recipient: Did,
    /// The serialized [`SocialMessage`] — its sensitive offers are individually sealed.
    pub payload: Vec<u8>,
}
