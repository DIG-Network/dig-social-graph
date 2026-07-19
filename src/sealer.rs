//! The real [`EnvelopeSealer`] — dig-message's BLS-G1-DHKEM auth-mode seal/open (§5.4).
//!
//! [`DigMessageSealer`] is SG-2: the concrete implementation of the SG-1 [`EnvelopeSealer`] seam. It
//! turns a plaintext offer into a message that ONLY the recipient's BLS-G1 identity key can open, and
//! that provably came from our identity — layered on top of the mTLS transport, so an intermediary
//! that relays the ciphertext learns neither the offered coordinates nor a forgeable sender (§5.4).
//!
//! One Chia BLS12-381 keypair does BOTH jobs: the **G2 signature** authenticates the sender and the
//! static **G1 Diffie-Hellman** term seals to the recipient — no separate encryption key. The seal
//! targets the recipient's 48-byte compressed G1 identity key (slot `0x0010`,
//! [`dig_identity::resolve_bls_public_key`]).
//!
//! ## The two seams this needs
//!
//! Sealing and opening both need to turn a DID into its published G1 key, and both need a clock (the
//! seal is freshness- and replay-bound, SPEC §5.6). Rather than pull the whole chain stack into this
//! pure-ish crate, those are themselves small injected seams:
//!
//! - [`KeyResolver`] — DID → 48-byte G1 identity key. The production adapter [`ChainKeyResolver`]
//!   wraps a [`dig_identity::ChainSource`] and [`dig_identity::resolve_bls_public_key`]; tests use a
//!   trivial in-memory registry so the real crypto can be exercised without a chain.
//! - [`Clock`] — wall-clock milliseconds for the seal timestamp + the open freshness/expiry check.
//!   [`SystemClock`] is the production impl; tests inject a fixed clock for deterministic KATs.

use std::cell::RefCell;

use chia_sdk_utils::Address;
use dig_identity::did::DID_CHIA_PREFIX;
use dig_identity::{bls::SecretKey, resolve_bls_public_key, Bytes32, ChainSource, Did};
use dig_message::{
    decode_envelope, encode_envelope, open_message, seal_message, InteractionShape, MessageError,
    ReplayGuard, SealParams,
};

use crate::error::{Error, Result};
use crate::seams::{EnvelopeSealer, OpenedEnvelope};

/// The dig-message type id of a sealed social-graph connection offer (a [`crate::wire::StoreCoords`]).
///
/// dig-message groups message types into bands; the social-graph band sits after IPC (`0x0600`). The
/// value only needs to be stable between our own seal and open — it is bound into the seal transcript
/// so a type-confusion splice is rejected. (Follow-up: register this band upstream in dig-message's
/// registry so no other protocol reuses it.)
pub const SOCIAL_GRAPH_BAND: u32 = 0x0000_0700;

/// The message type of a sealed connection offer.
pub const MSG_TYPE_CONNECTION_OFFER: u32 = SOCIAL_GRAPH_BAND;

/// Resolves a DID to its chain-authenticated 48-byte compressed BLS12-381 G1 identity public key
/// (slot `0x0010`).
///
/// This is the seam the seal (recipient key) and the open (sender key, for signature verification)
/// both consume. The production impl authenticates against chain state; a test impl can serve a
/// fixed registry so the seal/open crypto is exercised without a live chain.
pub trait KeyResolver {
    /// Resolve `did` to its 48-byte compressed G1 identity key, or fail if the DID publishes none.
    fn resolve_g1(&self, did: &Did) -> Result<[u8; 48]>;
}

/// The production [`KeyResolver`]: chain-authenticated G1 resolution via dig-identity.
///
/// It delegates to [`dig_identity::resolve_bls_public_key`] over the app-supplied [`ChainSource`], so
/// a caller can only ever obtain a key that a chain-authenticated DID actually published (never one
/// attached by an unauthenticated party).
pub struct ChainKeyResolver<S> {
    source: S,
}

impl<S: ChainSource> ChainKeyResolver<S> {
    /// Build a resolver over a chain source.
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S: ChainSource> KeyResolver for ChainKeyResolver<S> {
    fn resolve_g1(&self, did: &Did) -> Result<[u8; 48]> {
        resolve_bls_public_key(did.as_str(), &self.source)
            .map_err(|e| Error::Seam(format!("resolve BLS G1 identity key: {e}")))
    }
}

/// A source of wall-clock time in Unix milliseconds — the seal's freshness + expiry basis (SPEC §5.6).
pub trait Clock {
    /// The current wall-clock time in Unix milliseconds.
    fn now_ms(&self) -> u64;
}

/// The production [`Clock`]: the system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// The real dig-message-backed [`EnvelopeSealer`] (§5.4).
///
/// Holds our own identity secret key (to sign + seal outbound offers), our DID + key epoch, a
/// [`KeyResolver`] (to resolve recipient/sender G1 keys), a [`Clock`], and the per-process anti-replay
/// state: a strictly-monotonic outbound counter and the inbound [`ReplayGuard`]. The `open` seam is
/// *supplied* the app-held recipient secret key per call (G1 decap needs the raw scalar, not a
/// signature — the #908 custody boundary), so the sealer never stores the key it decapsulates with.
pub struct DigMessageSealer<R, C = SystemClock> {
    sender_sk: SecretKey,
    sender_launcher: Bytes32,
    sender_epoch: u32,
    resolver: R,
    clock: C,
    /// Strictly-monotonic outbound counter (SPEC §5.6 anti-replay). A single process-wide counter is
    /// monotonic for every recipient's sub-sequence, which is all the receiver's guard requires.
    counter: RefCell<u64>,
    /// Inbound anti-replay guard: freshness window + bounded sliding-window dedup per sender.
    replay_guard: RefCell<ReplayGuard>,
}

impl<R: KeyResolver> DigMessageSealer<R, SystemClock> {
    /// Build a sealer for our identity, using the system clock.
    ///
    /// `sender_sk` is our BLS-G1 identity secret key (the ONE key that signs AND seals); `sender_did`
    /// is our DID; `sender_epoch` disambiguates key rotation (0 until a rotation model exists).
    pub fn new(sender_sk: SecretKey, sender_did: &Did, sender_epoch: u32, resolver: R) -> Self {
        Self::with_clock(sender_sk, sender_did, sender_epoch, resolver, SystemClock)
    }
}

impl<R: KeyResolver, C: Clock> DigMessageSealer<R, C> {
    /// Build a sealer with an explicit clock (deterministic tests supply a fixed clock).
    pub fn with_clock(
        sender_sk: SecretKey,
        sender_did: &Did,
        sender_epoch: u32,
        resolver: R,
        clock: C,
    ) -> Self {
        Self {
            sender_sk,
            sender_launcher: sender_did.launcher_id(),
            sender_epoch,
            resolver,
            clock,
            counter: RefCell::new(0),
            replay_guard: RefCell::new(ReplayGuard::new()),
        }
    }

    /// The next strictly-monotonic outbound counter.
    fn next_counter(&self) -> u64 {
        let mut counter = self.counter.borrow_mut();
        let value = *counter;
        *counter += 1;
        value
    }

    /// Resolve an authenticated sender launcher id to its G1 key, reconstructing the canonical
    /// `did:chia:` string from the launcher via the bech32m codec (the seal binds the launcher, not
    /// the full string). Returns `None` to fail the open closed on an unresolvable sender.
    fn resolve_sender_g1(&self, launcher: Bytes32) -> Option<[u8; 48]> {
        let did_str = Address::new(launcher, DID_CHIA_PREFIX.to_string())
            .encode()
            .ok()?;
        let did = Did::parse(&did_str)?;
        self.resolver.resolve_g1(&did).ok()
    }
}

impl<R: KeyResolver, C: Clock> EnvelopeSealer for DigMessageSealer<R, C> {
    fn seal(&self, recipient: &Did, plaintext: &[u8]) -> Result<Vec<u8>> {
        let recipient_pub = self.resolver.resolve_g1(recipient)?;
        let envelope = seal_message(&SealParams {
            sender_sk: &self.sender_sk,
            sender: self.sender_launcher,
            sender_epoch: self.sender_epoch,
            recipient: recipient.launcher_id(),
            recipient_pub: &recipient_pub,
            message_type: MSG_TYPE_CONNECTION_OFFER,
            shape: InteractionShape::OneShot,
            correlation_id: Bytes32::from([0u8; 32]),
            stream: None,
            counter: self.next_counter(),
            timestamp_ms: self.clock.now_ms(),
            expires_at: 0,
            payload: plaintext,
        })
        .map_err(message_error)?;
        encode_envelope(&envelope).map_err(message_error)
    }

    fn open(&self, our_secret: &SecretKey, ciphertext: &[u8]) -> Result<OpenedEnvelope> {
        let envelope = decode_envelope(ciphertext).map_err(message_error)?;
        let now_ms = self.clock.now_ms();
        let mut guard = self.replay_guard.borrow_mut();
        let opened = open_message(
            our_secret,
            &envelope,
            |launcher, _epoch| self.resolve_sender_g1(launcher),
            &mut guard,
            now_ms,
        )
        .map_err(message_error)?;
        Ok(OpenedEnvelope {
            sender: opened.sender,
            plaintext: opened.payload,
        })
    }
}

/// Adapt a dig-message failure into a seam-level [`Error::Seam`] — every seal/open failure mode
/// (unresolvable sender, bad point, bad signature, expiry, replay, decompression bomb) surfaces here.
fn message_error(err: MessageError) -> Error {
    Error::Seam(format!("dig-message seal/open: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_utils::Address;
    use dig_identity::bls::{master_secret_key_from_seed, public_key_bytes};
    use dig_identity::pairing::{SingletonLineage, StoreRecord};
    use dig_identity::profile::Profile;
    use dig_identity::ChainStoreState;

    fn did(filler: u8) -> Did {
        let text = Address::new(Bytes32::from([filler; 32]), DID_CHIA_PREFIX.to_string())
            .encode()
            .unwrap();
        Did::parse(&text).unwrap()
    }

    #[test]
    fn system_clock_reports_a_plausible_wall_clock() {
        // Well after 2020 — proves the epoch conversion, not a frozen zero.
        assert!(SystemClock.now_ms() > 1_600_000_000_000);
    }

    /// A resolver mapping one DID to a fixed key, for the system-clock construction path.
    struct OneKey(Did, [u8; 48]);
    impl KeyResolver for OneKey {
        fn resolve_g1(&self, did: &Did) -> Result<[u8; 48]> {
            if *did == self.0 {
                Ok(self.1)
            } else {
                Err(Error::Seam("unknown did".into()))
            }
        }
    }

    #[test]
    fn new_uses_the_system_clock_and_seals() {
        let sender_sk = master_secret_key_from_seed(&[1u8; 32]);
        let recipient_sk = master_secret_key_from_seed(&[2u8; 32]);
        let recipient = did(0x02);
        let sealer = DigMessageSealer::new(
            sender_sk,
            &did(0x01),
            0,
            OneKey(recipient.clone(), public_key_bytes(&recipient_sk)),
        );
        // A seal through the system-clock constructor produces a non-empty envelope.
        assert!(!sealer.seal(&recipient, b"hello").unwrap().is_empty());
    }

    /// A chain source with no singleton for any launcher — resolution fails closed.
    struct EmptyChain;
    impl ChainSource for EmptyChain {
        type Error = &'static str;
        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> std::result::Result<Option<SingletonLineage>, Self::Error> {
            Ok(None)
        }
        fn find_stores_for_did(
            &self,
            _did: &Did,
        ) -> std::result::Result<Vec<ChainStoreState>, Self::Error> {
            Ok(vec![])
        }
        fn fetch_profile(
            &self,
            _store: &StoreRecord,
            _root_hash: Bytes32,
        ) -> std::result::Result<Profile, Self::Error> {
            Err("no profile")
        }
    }

    #[test]
    fn chain_key_resolver_fails_closed_without_a_singleton() {
        let resolver = ChainKeyResolver::new(EmptyChain);
        assert!(matches!(
            resolver.resolve_g1(&did(0x07)),
            Err(Error::Seam(_))
        ));
    }
}
