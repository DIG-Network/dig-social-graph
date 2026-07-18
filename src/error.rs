//! The crate's error surface.
//!
//! Two failure kinds only, because the networkless core does very little that can fail: an
//! [`Error::IllegalTransition`] when a [`ConnectionEvent`] is applied to a state that does not
//! accept it (the state machine is a total function — every illegal pair is rejected, never
//! silently ignored), and an [`Error::Seam`] when an injected seam (transport, sealer, subscriber,
//! persistence) reports a failure the core cannot resolve itself.
//!
//! [`ConnectionEvent`]: crate::state::ConnectionEvent

use crate::state::{ConnectionEvent, ConnectionState};

/// The crate result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything the social-graph core can fail with.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`ConnectionEvent`] was applied to a [`ConnectionState`] that does not accept it. The
    /// state machine rejects every such pair rather than transitioning to a wrong state.
    #[error("illegal transition: {event:?} is not valid in state {state:?}")]
    IllegalTransition {
        /// The state the connection was in.
        state: ConnectionState,
        /// The event that was not accepted.
        event: ConnectionEvent,
    },

    /// A caller invariant was violated — e.g. requesting a connection with no offer of one's own
    /// (offer-first forbids taking a peer's profile without presenting your own).
    #[error("invariant violated: {0}")]
    Invariant(&'static str),

    /// An injected seam (transport / sealer / subscriber / persistence) failed. The message is
    /// supplied by the seam implementation in dig-app; the core only relays it.
    #[error("seam failure: {0}")]
    Seam(String),

    /// A byte buffer could not be decoded as the expected canonical wire type (truncated, wrong
    /// length, or an unknown tag).
    #[error("malformed wire bytes: {0}")]
    Wire(&'static str),
}
