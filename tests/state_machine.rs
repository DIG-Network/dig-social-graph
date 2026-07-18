//! Exhaustive coverage of the pure connection state machine: every legal transition, the rendezvous
//! park/resume, and rejection of every illegal `(state, event)` pair.

use dig_social_graph::{ConnectionEvent as E, ConnectionState as S, Error, Suspended};

/// The full outbound requestor journey to a mutual connection.
#[test]
fn outbound_journey_reaches_connected() {
    let s = S::initiated();
    assert_eq!(s, S::Requested);
    let s = s.apply(E::RequestDelivered).unwrap();
    assert_eq!(s, S::RequestorOffered);
    let s = s.apply(E::AcceptReceived).unwrap();
    assert_eq!(s, S::Connected);
    assert!(s.is_connected());
}

/// The full inbound recipient journey to a mutual connection.
#[test]
fn inbound_journey_reaches_connected() {
    let s = S::AwaitingRecipientSelect
        .apply(E::Approved)
        .unwrap()
        .apply(E::MutualConfirmed)
        .unwrap();
    assert_eq!(s, S::Connected);
}

/// Either side may decline; both denial paths terminate.
#[test]
fn denial_paths_terminate() {
    assert_eq!(S::RequestorOffered.apply(E::Denied).unwrap(), S::Denied);
    assert_eq!(
        S::AwaitingRecipientSelect.apply(E::Denied).unwrap(),
        S::Denied
    );
    assert!(S::Denied.is_terminal());
}

/// A live connection can be revoked, and revocation is terminal.
#[test]
fn connected_can_be_revoked() {
    let s = S::Connected.apply(E::Revoked).unwrap();
    assert_eq!(s, S::Revoked);
    assert!(s.is_terminal());
    assert!(!s.is_connected());
}

/// Every in-flight state parks on peer-offline and resumes to exactly the same state.
#[test]
fn in_flight_states_park_and_resume() {
    for (state, suspended) in [
        (S::Requested, Suspended::Requested),
        (S::RequestorOffered, Suspended::RequestorOffered),
        (S::RecipientOffered, Suspended::RecipientOffered),
    ] {
        let parked = state.apply(E::PeerWentOffline).unwrap();
        assert_eq!(parked, S::PendingRendezvous(suspended));
        let resumed = parked.apply(E::PeerCameOnline).unwrap();
        assert_eq!(resumed, state, "resume must restore the exact parked state");
    }
}

/// Terminal and connected states cannot be parked for rendezvous.
#[test]
fn non_in_flight_states_cannot_park() {
    for state in [
        S::Connected,
        S::Denied,
        S::Revoked,
        S::AwaitingRecipientSelect,
    ] {
        assert!(matches!(
            state.apply(E::PeerWentOffline),
            Err(Error::IllegalTransition { .. })
        ));
    }
}

/// A representative sweep of illegal pairs is rejected rather than silently ignored.
#[test]
fn illegal_transitions_are_rejected() {
    let illegal = [
        (S::Requested, E::AcceptReceived),
        (S::Requested, E::Approved),
        (S::AwaitingRecipientSelect, E::AcceptReceived),
        (S::RecipientOffered, E::AcceptReceived),
        (S::Connected, E::AcceptReceived),
        (S::Connected, E::Approved),
        (S::Denied, E::Revoked),
        (S::Revoked, E::PeerCameOnline),
        (S::RequestorOffered, E::PeerCameOnline),
    ];
    for (state, event) in illegal {
        let err = state.apply(event).unwrap_err();
        match err {
            Error::IllegalTransition { state: s, event: e } => {
                assert_eq!(s, state);
                assert_eq!(e, event);
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }
}

/// The error renders both the state and the event for debuggability.
#[test]
fn illegal_transition_error_is_descriptive() {
    let err = S::Connected.apply(E::Approved).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("Connected"));
    assert!(text.contains("Approved"));
}
