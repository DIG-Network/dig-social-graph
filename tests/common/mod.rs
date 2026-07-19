//! Shared test helpers: minting canonical `did:chia:` DIDs and coordinates, plus in-memory seam
//! doubles that record every call so orchestration can be asserted deterministically.
//!
//! Each integration-test binary is its own crate and uses only a subset of these helpers, so unused
//! items here are expected — silence the per-binary dead-code lint rather than fragment the module.
#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use chia_sdk_utils::Address;
use dig_identity::bls::master_secret_key_from_seed;
use dig_social_graph::{
    Bytes32, Did, EnvelopeSealer, Error, Persistence, Result, SealedEnvelope, SecretKey,
    SocialGraph, StoreCoords, StoreSubscriber, Transport,
};

/// Mint a well-formed `did:chia:` DID from a single filler byte (mirrors dig-identity's test helper).
pub fn make_did(filler: u8) -> Did {
    let launcher = [filler; 32];
    let text = Address::new(Bytes32::from(launcher), "did:chia:".to_string())
        .encode()
        .expect("encodes a did:chia: address");
    Did::parse(&text).expect("parses the minted did")
}

/// A deterministic BLS-G1 secret key for tests, standing in for the app-held identity key the
/// [`EnvelopeSealer::open`] seam needs to decapsulate an inbound offer.
pub fn make_secret(filler: u8) -> SecretKey {
    master_secret_key_from_seed(&[filler; 32])
}

/// Coordinates for a DID with a committed root filled from `root_filler`.
pub fn make_coords(did: &Did, root_filler: u8) -> StoreCoords {
    StoreCoords::from_did(did.clone(), Bytes32::from([root_filler; 32]))
}

/// A transport double: records sent envelopes and reports a toggleable peer-online flag.
#[derive(Clone, Default)]
pub struct MockTransport {
    pub sent: Rc<RefCell<Vec<SealedEnvelope>>>,
    pub online: Rc<Cell<bool>>,
}

impl MockTransport {
    /// A transport whose peer is online.
    pub fn online() -> Self {
        let t = Self::default();
        t.online.set(true);
        t
    }
}

impl Transport for MockTransport {
    fn send(&self, envelope: &SealedEnvelope) -> Result<()> {
        self.sent.borrow_mut().push(envelope.clone());
        Ok(())
    }

    fn is_peer_online(&self, _peer: &Did) -> Result<bool> {
        Ok(self.online.get())
    }
}

/// A sealer double: sealing and opening are the identity function, so a "sealed" offer is exactly
/// its canonical coordinate bytes (lets tests decode what was offered).
#[derive(Clone, Default)]
pub struct PassthroughSealer;

impl EnvelopeSealer for PassthroughSealer {
    fn seal(&self, _recipient: &Did, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, _our_secret: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}

/// A subscriber double: records subscribe/unsubscribe calls in order.
#[derive(Clone, Default)]
pub struct MockSubscriber {
    pub subscribed: Rc<RefCell<Vec<StoreCoords>>>,
    pub unsubscribed: Rc<RefCell<Vec<StoreCoords>>>,
}

impl StoreSubscriber for MockSubscriber {
    fn subscribe(&self, coords: &StoreCoords) -> Result<()> {
        self.subscribed.borrow_mut().push(coords.clone());
        Ok(())
    }

    fn unsubscribe(&self, coords: &StoreCoords) -> Result<()> {
        self.unsubscribed.borrow_mut().push(coords.clone());
        Ok(())
    }
}

/// A persistence double: keeps the last stored graph in memory.
#[derive(Clone, Default)]
pub struct MemPersistence {
    pub saved: Rc<RefCell<SocialGraph>>,
    pub fail: Rc<Cell<bool>>,
}

impl Persistence for MemPersistence {
    fn load(&self) -> Result<SocialGraph> {
        Ok(self.saved.borrow().clone())
    }

    fn store(&self, graph: &SocialGraph) -> Result<()> {
        if self.fail.get() {
            return Err(Error::Seam("persistence disabled".into()));
        }
        *self.saved.borrow_mut() = graph.clone();
        Ok(())
    }
}
