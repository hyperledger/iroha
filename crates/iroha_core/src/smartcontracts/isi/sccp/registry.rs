//! Route registry and activation states (`specs/sccp.md` §4.14.1, §4.14.2). Owner: ws33; ws20
//! implemented the read accessors.
//!
//! `Staged` → `Bidirectional` ⇄ `Paused`; `Bidirectional`/`Paused` → `InboundOnly` →
//! `Retired`. Every transition except the automatic frozen-void transition is Parliament
//! enacted. At most one revision per route is `Bidirectional` or `Paused`.

use super::{Error, store};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        events::{SccpEvent, SccpRevisionActivationChangedV1},
        registry::SccpRouteActivationV1,
    },
};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP registry: {reason}").into())
}

/// Return the route revision of `network` that is `Bidirectional`, if any.
#[must_use]
pub fn bidirectional_revision(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
) -> Option<u32> {
    store::routes::get(world, &network)
        .and_then(|route| route.bidirectional_revision())
        .map(|revision| revision.revision)
}

/// Emit `RevisionActivationChanged` for `(network, revision)` moving `from → to` (`None` is
/// absent: registration and removal).
pub fn emit_activation_changed(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    from: Option<SccpRouteActivationV1>,
    to: Option<SccpRouteActivationV1>,
) {
    state_transaction
        .world
        .emit_events(Some(SccpEvent::RevisionActivationChanged(
            SccpRevisionActivationChangedV1 {
                network,
                revision,
                from,
                to,
            },
        )));
}

/// Move revision `revision` of `network` to activation state `to`, emitting
/// `RevisionActivationChanged`.
///
/// Only §4.14.2 transitions are allowed, and a transition into `Bidirectional` or `Paused`
/// requires that no other revision of the route is live. Checks that depend on the action
/// (light-client usability, retirement preconditions) belong to the caller.
///
/// # Errors
///
/// Fails when the revision does not exist, the transition is not allowed, or another revision
/// is live.
pub fn set_activation(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    to: SccpRouteActivationV1,
) -> Result<(), Error> {
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    if to.is_live()
        && route
            .revisions
            .values()
            .any(|other| other.revision != revision && other.activation.is_live())
    {
        return Err(refuse(format_args!(
            "another revision of {} is live",
            network.profile_key()
        )));
    }
    let record = route
        .revisions
        .get_mut(&revision)
        .ok_or_else(|| refuse(format_args!("revision {revision} does not exist")))?;
    let from = record.activation;
    if !from.can_transition_to(to) {
        return Err(refuse(format_args!(
            "revision {revision} cannot move from {from:?} to {to:?}"
        )));
    }
    record.activation = to;
    if to == SccpRouteActivationV1::Bidirectional {
        record.ever_activated = true;
    }
    store::routes::insert(state_transaction, network, route)?;
    emit_activation_changed(state_transaction, network, revision, Some(from), Some(to));
    Ok(())
}

/// Apply a proven frozen void: set `destination_frozen` and move a live revision to
/// `InboundOnly` (§4.14.2, §4.16). Return whether the revision changed, so a replayed frozen
/// void of an already frozen and drained revision is reported as changing nothing.
///
/// # Errors
///
/// Fails when the revision does not exist.
pub fn apply_frozen_void(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
) -> Result<bool, Error> {
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    let record = route
        .revisions
        .get_mut(&revision)
        .ok_or_else(|| refuse(format_args!("revision {revision} does not exist")))?;
    let from = record.activation;
    let moved = from.is_live();
    if record.destination_frozen && !moved {
        return Ok(false);
    }
    record.destination_frozen = true;
    if moved {
        record.activation = SccpRouteActivationV1::InboundOnly;
    }
    store::routes::insert(state_transaction, network, route)?;
    if moved {
        emit_activation_changed(
            state_transaction,
            network,
            revision,
            Some(from),
            Some(SccpRouteActivationV1::InboundOnly),
        );
    }
    Ok(true)
}

/// Return whether the latest destination control of `(network, revision)` pauses minting
/// (§4.14.6). An unknown revision is not paused.
#[must_use]
pub fn destination_paused(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
) -> bool {
    store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .is_some_and(|revision| revision.destination_paused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_route};

    fn activation(
        stx: &StateTransaction<'_, '_>,
        network: SccpNetworkV1,
        revision: u32,
    ) -> SccpRouteActivationV1 {
        store::routes::get(&*stx.world, &network)
            .and_then(|route| route.revisions.get(&revision))
            .expect("revision")
            .activation
    }

    #[test]
    fn accessors_read_the_stored_route() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        assert_eq!(bidirectional_revision(&*stx.world, network), None);
        assert!(!destination_paused(&*stx.world, network, 1));
        let mut route = sample_route(network);
        let revision = route.revisions.get_mut(&1).expect("sample revision");
        revision.activation = SccpRouteActivationV1::Bidirectional;
        revision.destination_paused = true;
        store::routes::insert(&mut stx, network, route).expect("route");
        assert_eq!(bidirectional_revision(&*stx.world, network), Some(1));
        assert!(destination_paused(&*stx.world, network, 1));
        assert!(!destination_paused(&*stx.world, network, 2));
    }

    #[test]
    fn transitions_follow_the_table_and_keep_one_live_revision() {
        use SccpRouteActivationV1 as A;

        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::BscMainnet;
        let mut route = sample_route(network);
        let mut second = route.revisions.get(&1).cloned().expect("revision");
        second.revision = 2;
        route.revisions.insert(2, second);
        store::routes::insert(&mut stx, network, route).expect("route");

        set_activation(&mut stx, network, 1, A::Retired).expect_err("Staged → Retired");
        set_activation(&mut stx, network, 1, A::Bidirectional).expect("activate");
        assert!(
            store::routes::get(&*stx.world, &network)
                .and_then(|route| route.revisions.get(&1))
                .expect("revision")
                .ever_activated
        );
        let error = set_activation(&mut stx, network, 2, A::Bidirectional).expect_err("two live");
        assert!(error.to_string().contains("live"), "{error}");
        set_activation(&mut stx, network, 1, A::Paused).expect("pause");
        set_activation(&mut stx, network, 1, A::Bidirectional).expect("resume");
        set_activation(&mut stx, network, 1, A::InboundOnly).expect("deactivate");
        set_activation(&mut stx, network, 2, A::Bidirectional).expect("successor");
        set_activation(&mut stx, network, 1, A::Retired).expect("retire");
        assert_eq!(activation(&stx, network, 1), A::Retired);
        set_activation(&mut stx, network, 3, A::Bidirectional).expect_err("unknown revision");
    }

    #[test]
    fn a_frozen_void_drains_a_live_revision_only() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::BscMainnet;
        apply_frozen_void(&mut stx, network, 1).expect_err("no route");
        store::routes::insert(&mut stx, network, sample_route(network)).expect("route");
        assert_eq!(
            apply_frozen_void(&mut stx, network, 1),
            Ok(true),
            "staged stays staged"
        );
        assert_eq!(activation(&stx, network, 1), SccpRouteActivationV1::Staged);
        assert_eq!(
            apply_frozen_void(&mut stx, network, 1),
            Ok(false),
            "a replay changes nothing"
        );
        set_activation(&mut stx, network, 1, SccpRouteActivationV1::Bidirectional)
            .expect("activate");
        set_activation(&mut stx, network, 1, SccpRouteActivationV1::Paused).expect("pause");
        assert_eq!(apply_frozen_void(&mut stx, network, 1), Ok(true), "frozen");
        assert_eq!(
            activation(&stx, network, 1),
            SccpRouteActivationV1::InboundOnly
        );
        assert_eq!(
            apply_frozen_void(&mut stx, network, 1),
            Ok(false),
            "a drained replay changes nothing"
        );
        assert!(
            store::routes::get(&*stx.world, &network)
                .and_then(|route| route.revisions.get(&1))
                .expect("revision")
                .destination_frozen
        );
    }
}
