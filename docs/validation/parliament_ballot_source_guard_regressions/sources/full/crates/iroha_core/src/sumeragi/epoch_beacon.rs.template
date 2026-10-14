//! Consensus-native epoch pulse demand and original-prestate witness admission.
//!
//! Demand is consensus-native only: a root that owns global control requires the pulse at the
//! `NPoS` pre-boundary height and nowhere else. Governance state creates no pulse obligation;
//! a Parliament sortition waits governance-locally for the native pulse of its frozen slot.
//!
//! The producer supplies the canonical pulse independently of transaction bytes after real
//! work is selected. Followers verify that exact signed witness; local aggregation timing
//! never grants validity. The original schedule owner applies it once before transaction effects.

pub(crate) mod control;
pub(crate) mod producer;

use crate::{
    beacon::{
        GlobalThresholdBeaconPulseLinkV1, GlobalThresholdBeaconSessionBindingV1,
        authenticated_global_threshold_beacon_roster_hash_iter_v1,
        validate_persisted_global_threshold_beacon_pulse_v1,
        verify_finalized_global_threshold_beacon_pulse_v1,
    },
    state::{BlockHashRead, GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, WorldReadOnly},
};
use iroha_data_model::sumeragi::epoch::{BeaconEpochBindingV1, InstalledBeaconEpochBindingV1};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    },
    governance::types::BeaconSessionId,
    parameter::system::ConsensusMode,
    sumeragi::epoch::ValidatorEpochContextV1,
};
use mv::storage::StorageReadOnly;

/// No public constructor or mutable proof field: only exact prestate verification produces it.
#[derive(Debug)]
pub(crate) struct VerifiedEpochPulse {
    pulse: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    link: Option<GlobalThresholdBeaconPulseLinkV1>,
}
impl VerifiedEpochPulse {
    /// The fixed-width canonical witness; copying it creates no nested allocation.
    pub(crate) fn pulse(&self) -> Option<FinalizedGlobalThresholdBeaconPulseV1> {
        self.pulse
    }
    /// The exact verified persistence cursor. It cannot be supplied by a transaction.
    pub(crate) fn link(&self) -> Option<GlobalThresholdBeaconPulseLinkV1> {
        self.link
    }
}

/// Whether this signed root owns the global control plane. Private roots use one
/// permissioned committee and cannot acquire parent epoch or beacon custody: a Dataspace
/// root in another mode, under an installed beacon binding, with an active global beacon
/// key session or with any stored pulse is refused. Governance rows are not consulted.
fn owns_global_control(
    scope: SumeragiRootScope,
    world: &impl WorldReadOnly,
    current: &ValidatorEpochContextV1,
) -> Result<bool, String> {
    scope.validate().map_err(|error| error.to_string())?;
    if matches!(scope, SumeragiRootScope::Global) {
        return Ok(true);
    }
    if current.mode != ConsensusMode::Permissioned
        || current.authorization.beacon != BeaconEpochBindingV1::Bootstrap
        || world.active_global_beacon_key_session().is_some()
        || world.global_beacon_pulses().iter().next().is_some()
    {
        return Err("private root cannot own global epoch or beacon control".into());
    }
    Ok(false)
}

/// Whether this authenticated root requests mandatory native control work at the given height.
///
/// True exactly at the `NPoS` pre-boundary height of a root that owns global control. No
/// governance state takes part: a pending Parliament slot never makes a pulse mandatory and
/// never blocks a block that carries none.
pub(crate) fn required(
    scope: SumeragiRootScope,
    world: &impl WorldReadOnly,
    current: &ValidatorEpochContextV1,
    height: u64,
) -> Result<bool, String> {
    if !owns_global_control(scope, world, current)? {
        return Ok(false);
    }
    let native = current.mode == ConsensusMode::Npos
        && height.checked_add(1) == Some(current.authorization.last_height);
    #[cfg(all(test, sumeragi_core_mutation = "HC224"))]
    {
        Ok(native
            || world
                .parliament_required_beacon_pulse_slots()
                .get(&(BeaconSessionId::for_network_v1(&current.network_id), height))
                .is_some_and(|attempts| !attempts.is_empty()))
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC224")))]
    {
        Ok(native)
    }
}

/// Verify presence/absence and actual threshold proof at the immutable committed cut.
/// This function consumes no node-local certificate signer subset or aggregator state.
#[expect(
    clippy::large_types_passed_by_value,
    reason = "the supplied pulse is validated and transferred into the retained native schedule result"
)]
pub(crate) fn capture(
    scope: SumeragiRootScope,
    world: &impl WorldReadOnly,
    hashes: &(impl BlockHashRead + ?Sized),
    current: &ValidatorEpochContextV1,
    height: u64,
    supplied: Option<FinalizedGlobalThresholdBeaconPulseV1>,
    expected_context: Option<GlobalThresholdBeaconPulseContextV1>,
) -> Result<VerifiedEpochPulse, String> {
    current.validate()?;
    match (height, expected_context.as_ref()) {
        (1, None) if supplied.is_none() => {}
        (1, _) => {
            return Err(
                "signed genesis cannot contain a native pulse or native parent context".into(),
            );
        }
        (_, Some(context)) => {
            context.validate().map_err(str::to_owned)?;
            if context.epoch != current.authorization.epoch
                || context.epoch_context_id != current.context_id()?
            {
                return Err(
                    "native beacon expected context differs from the authenticated epoch".into(),
                );
            }
        }
        (_, None) => {
            return Err(
                "native beacon admission lacks its independently checked native context".into(),
            );
        }
    }
    if height < current.authorization.first_height
        || height > current.authorization.last_height
        || u64::try_from(hashes.hash_count())
            .ok()
            .and_then(|height| height.checked_add(1))
            != Some(height)
    {
        return Err("native beacon witness is outside its exact committed prestate".into());
    }
    let demanded = required(scope, world, current, height)?;
    let Some(pulse) = supplied else {
        return if demanded {
            Err("mandatory native beacon control witness is absent".into())
        } else {
            Ok(VerifiedEpochPulse {
                pulse: None,
                link: None,
            })
        };
    };
    if !demanded {
        return Err("native beacon control witness was not requested".into());
    }
    if pulse.network_id != current.network_id
        || pulse.height != height
        || pulse.round != crate::beacon::GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1
    {
        return Err("native beacon witness changes its network, height or round".into());
    }
    let parent = height
        .checked_sub(1)
        .filter(|height| *height > 0)
        .ok_or("native beacon witness lacks finalized parent")?;
    let index = usize::try_from(parent - 1).map_err(|_| "native beacon parent index overflows")?;
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: parent,
        block_hash: *hashes
            .hash_at(index)
            .ok_or("native beacon parent is absent")?,
    };
    validate_pending_slot(world, current, height)?;
    if world.global_beacon_pulses().get(&pulse.pulse_id).is_some() {
        return Err("native beacon witness repeats a committed pulse".into());
    }
    if world.active_global_beacon_key_session() != Some(pulse.session_id) {
        return Err("native beacon witness uses an inactive session".into());
    }
    let record = world
        .global_beacon_key_sessions()
        .get(&pulse.session_id)
        .ok_or("native beacon session is absent")?;
    record.validate().map_err(|error| error.to_string())?;
    let installed = InstalledBeaconEpochBindingV1 {
        session_id: pulse.session_id,
        transcript_hash: pulse.transcript_hash,
    };
    if !record.is_active_at(height)
        || record.session.adaptive_dkg.finalized_at_height > parent
        || record.session.adaptive_dkg.session.authority_generation
            != current.authorization.authority_generation
        || (current.authorization.beacon != BeaconEpochBindingV1::Bootstrap
            && current.authorization.beacon != BeaconEpochBindingV1::Installed(installed))
    {
        return Err("native beacon witness changes the authorized generation or transcript".into());
    }
    let peers = current.committee.iter().map(|seat| &seat.validator);
    let roster_hash =
        authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, peers)
            .map_err(|error| error.to_string())?;
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: current.network_id,
        session_id: pulse.session_id,
        roster_hash,
        transcript_hash: record.session.transcript_hash,
    };
    let session = &record.session;
    session
        .check_binding(&binding)
        .map_err(|error| error.to_string())?;
    let link = verify_finalized_global_threshold_beacon_pulse_v1(
        session,
        &pulse,
        anchor,
        expected_context
            .as_ref()
            .ok_or("native pulse has no parent context")?,
    )
    .map_err(|error| error.to_string())?;
    if validate_persisted_global_threshold_beacon_pulse_v1(&pulse)
        .map_err(|error| error.to_string())?
        != link
    {
        return Err("native beacon witness has a noncanonical public cursor".into());
    }
    Ok(VerifiedEpochPulse {
        pulse: Some(pulse),
        link: Some(link),
    })
}

/// Reuse the exact committed cursor/slot checks before creating a local reducer and when
/// admitting a transported witness. A local producer never signs a slot already closed by State.
fn validate_pending_slot(
    world: &impl WorldReadOnly,
    current: &ValidatorEpochContextV1,
    height: u64,
) -> Result<(), String> {
    let slot = (BeaconSessionId::for_network_v1(&current.network_id), height);
    if world.global_beacon_pulse_slots().get(&slot).is_some()
        || world.global_beacon_pulse_slots().iter().count()
            != world.global_beacon_pulses().iter().count()
    {
        return Err("native beacon witness repeats or contradicts committed pulse history".into());
    }
    if let Some(previous) = world
        .global_beacon_latest_pulse()
        .get(&GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY)
    {
        previous.validate().map_err(|error| error.to_string())?;
        if (
            height,
            crate::beacon::GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1,
        ) <= (previous.height, previous.round)
        {
            return Err("native beacon witness does not advance pulse history".into());
        }
    } else if world.global_beacon_pulses().iter().next().is_some() {
        return Err("native beacon history lost its latest cursor".into());
    }
    Ok(())
}

#[cfg(test)]
mod root_scope_tests {
    use super::*;
    use crate::{
        query::store::LiveQueryStore,
        state::{State, World},
        sumeragi::lanes::routing::test_support,
    };
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{NetworkId, governance::types::GovernanceAttemptId};
    use iroha_model_base::topology::DataSpaceId;
    use std::collections::BTreeSet;

    #[test]
    fn signed_private_genesis_has_no_global_control_or_provider_requirement() {
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"parent"),
            )),
            dataspace_id: DataSpaceId::new((1_u64 << 40) + 13),
        };
        let genesis = test_support::signed_genesis(scope);
        let epoch = crate::sumeragi::epoch::authenticated_genesis(&genesis)
            .map(|genesis| genesis.into_parts().0)
            .unwrap();
        let state = State::new_for_testing(
            World::new(),
            crate::kura::Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let view = state.view();
        assert!(!required(scope, view.world(), &epoch, 1).unwrap());
        let captured = capture(
            scope,
            view.world(),
            view.block_hashes(),
            &epoch,
            1,
            None,
            None,
        )
        .unwrap();
        assert!(captured.pulse().is_none());
        assert!(captured.link().is_none());
        let mut wrong_mode = epoch.clone();
        wrong_mode.mode = ConsensusMode::Npos;
        assert!(required(scope, view.world(), &wrong_mode, 1).is_err());
    }

    /// A retained governance slot row creates no control demand on any root: the private root
    /// stays a no-control root that admits its witness-free block, and the Global root does
    /// not request a pulse for the row either. Only the native signals refuse a private root.
    #[test]
    fn retained_parliament_slot_row_creates_no_demand_on_private_or_global_root() {
        let scope = SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"parent"),
            )),
            dataspace_id: DataSpaceId::new(13),
        };
        let epoch =
            crate::sumeragi::epoch::authenticated_genesis(&test_support::signed_genesis(scope))
                .map(|genesis| genesis.into_parts().0)
                .unwrap();
        let mut world = test_support::world(scope);
        let slot = (BeaconSessionId::for_network_v1(&epoch.network_id), 7);
        let row = BTreeSet::from([GovernanceAttemptId::new([7; 32])]);
        world
            .parliament_required_beacon_pulse_slots
            .insert(slot, row.clone());
        let view = world.view();
        assert_eq!(
            view.parliament_required_beacon_pulse_slots().get(&slot),
            Some(&row)
        );
        assert_eq!(required(scope, &view, &epoch, 7), Ok(false));
        assert_eq!(
            required(SumeragiRootScope::Global, &view, &epoch, 7),
            Ok(false)
        );
        assert_eq!(owns_global_control(scope, &view, &epoch), Ok(false));
        // The private root's witness-free genesis is admitted with the row present, and a
        // later ordinary height reaches the demand decision instead of a custody refusal.
        let state = State::new_for_testing(
            World::new(),
            crate::kura::Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let hashes = state.view();
        let captured = capture(scope, &view, hashes.block_hashes(), &epoch, 1, None, None).unwrap();
        assert!(captured.pulse().is_none() && captured.link().is_none());
        // The native refusal signals are unchanged by the row.
        let mut wrong_mode = epoch.clone();
        wrong_mode.mode = ConsensusMode::Npos;
        assert!(
            required(scope, &view, &wrong_mode, 7)
                .unwrap_err()
                .contains("global epoch or beacon")
        );
    }
}
