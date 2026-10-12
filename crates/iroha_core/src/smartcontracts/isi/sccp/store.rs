//! Typed access to every SCCP v1 world map and cell (`specs/sccp.md` §4). Owner: ws20
//! (complete).
//!
//! Each map has one submodule named after its world field without the `sccp_` prefix. Readers
//! take any [`WorldReadOnly`] scope (committed view, block or transaction); writers take the
//! executing [`StateTransaction`], so every write rolls back with its transaction. The world
//! field inventory itself lives in `crate::state` (`WorldData` and its block, transaction and
//! view projections) and is persisted by the SCCP snapshot envelope.
//!
//! **Stored invariants.** Some maps carry a structural invariant between key and value (for
//! example a route is stored under its own network). Each map's `valid_entry` is the single
//! definition of that rule: `insert` refuses an entry that breaks it, and snapshot restore
//! rejects one, so every committed state restores. The counter maps [`pending_counts`] and
//! [`governance_revisions`] hold no zero entries: absent means zero, and [`set_pending_counts`]
//! and [`set_governance_revision`] remove the entry when the value returns to zero.

use super::Error;
use crate::state::{StateTransaction, WorldReadOnly};
use core::ops::RangeBounds;
use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{
        commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
        control::{SccpControlRecordV1, SccpLeafRefV1},
        governance::SccpGovernanceSubjectV1,
        inbound::SccpInboundRecordV1,
        light_client::{
            SCCP_LC_GENESIS_PROFILE_VERSION_V1, SccpLcCheckpointV1, SccpLcConsensusSetV1,
            SccpLcProfileActivationV1, SccpLightClientV1,
        },
        outbound::SccpOutboundMessageRecordV1,
        params::{SCCP_MESSAGES_MAX_PER_BLOCK_V1, SccpParametersV1},
        registry::SccpRouteV1,
    },
};
use mv::storage::StorageReadOnly;

/// Keep the original local refusal armed until the enclosing block aborts.
fn storage_refusal(
    state: &mut StateTransaction<'_, '_>,
    error: mv::storage::AdmittedStorageError,
) -> Error {
    state.arm_local_storage_refusal(crate::state::StateStorageAdmissionError::World(error));
    Error::InvariantViolation("SCCP original map allocation did not complete".into())
}
macro_rules! insert_map {
    ($state:ident, sccp_committee_generations, $key:ident, $value:ident) => {
        $state
            .world
            .sccp_committee_generations
            .try_insert_admitted($key, $value)
            .map_err(|(_, error)| storage_refusal($state, error))
    };
    ($state:ident, sccp_anchor_chunks, $key:ident, $value:ident) => {
        $state
            .world
            .sccp_anchor_chunks
            .try_insert_admitted($key, $value)
            .map_err(|(_, error)| storage_refusal($state, error))
    };
    ($state:ident, $field:ident, $key:ident, $value:ident) => {
        Ok::<_, Error>($state.world.$field.insert($key, $value))
    };
}
macro_rules! remove_map {
    ($state:ident, sccp_committee_generations, $key:ident) => {
        match $state
            .world
            .sccp_committee_generations
            .try_remove_admitted($key)
        {
            Ok(previous) => previous,
            Err((_, error)) => {
                let _ = storage_refusal($state, error);
                None
            }
        }
    };
    ($state:ident, sccp_anchor_chunks, $key:ident) => {
        match $state.world.sccp_anchor_chunks.try_remove_admitted($key) {
            Ok(previous) => previous,
            Err((_, error)) => {
                let _ = storage_refusal($state, error);
                None
            }
        }
    };
    ($state:ident, $field:ident, $key:ident) => {
        $state.world.$field.remove($key)
    };
}

/// Generate the typed helpers of one SCCP storage map, optionally with a stored invariant
/// `valid(key_pattern, value_pattern) => rule` over borrowed keys and values.
macro_rules! storage_map {
    ($(#[$meta:meta])* $module:ident => $field:ident: $key:ty => $value:ty) => {
        storage_map!(
            $(#[$meta])* $module => $field: $key => $value, valid(_key, _value) => true
        );
    };
    (
        $(#[$meta:meta])* $module:ident => $field:ident: $key:ty => $value:ty,
        valid($key_pattern:pat, $value_pattern:pat) => $rule:expr
        $(, index($index:ident, $indexed_value:ident) => $indexed:expr)?
    ) => {
        $(#[$meta])*
        pub mod $module {
            use super::*;

            /// Return whether `(key, value)` satisfies this map's stored invariant, which
            /// [`insert`] and snapshot restore enforce.
            #[must_use]
            pub fn valid_entry(key: &$key, value: &$value) -> bool {
                let ($key_pattern, $value_pattern) = (key, value);
                $rule
            }

            /// Borrow the value stored at `key`.
            #[must_use]
            pub fn get<'world>(
                world: &'world (impl WorldReadOnly + ?Sized),
                key: &$key,
            ) -> Option<&'world $value> {
                world.$field().get(key)
            }

            /// Return whether `key` is present.
            #[must_use]
            pub fn contains(world: &(impl WorldReadOnly + ?Sized), key: &$key) -> bool {
                world.$field().get(key).is_some()
            }

            /// Insert `value` at `key` in the executing transaction, returning the previous
            /// value.
            ///
            /// # Errors
            ///
            /// Fails with an invariant violation, leaving the map unchanged, when the entry
            /// breaks the map's stored invariant ([`valid_entry`]).
            pub fn insert(
                state_transaction: &mut StateTransaction<'_, '_>,
                key: $key,
                value: $value,
            ) -> Result<Option<$value>, Error> {
                if !valid_entry(&key, &value) {
                    return Err(Error::InvariantViolation(
                        concat!(
                            "SCCP: refusing an entry that breaks the stored invariant of ",
                            stringify!($field)
                        )
                        .into(),
                    ));
                }
                $(let $indexed_value = &value; let indexed = $indexed;)?
                let previous = insert_map!(state_transaction, $field, key, value)?;
                $(
                    if indexed {
                        state_transaction.world.$index.insert(key, ());
                    } else {
                        state_transaction.world.$index.remove(key);
                    }
                )?
                Ok(previous)
            }

            /// Remove `key` in the executing transaction, returning the previous value.
            pub fn remove(
                state_transaction: &mut StateTransaction<'_, '_>,
                key: $key,
            ) -> Option<$value> {
                let previous = remove_map!(state_transaction, $field, key);
                $(
                    if previous.is_some() {
                        state_transaction.world.$index.remove(key);
                    }
                )?
                previous
            }

            /// Iterate every entry in ascending key order.
            pub fn iter<'world>(
                world: &'world (impl WorldReadOnly + ?Sized),
            ) -> impl DoubleEndedIterator<Item = (&'world $key, &'world $value)> + 'world {
                world.$field().iter()
            }

            /// Iterate the entries whose keys fall in `bounds`, in ascending key order.
            pub fn range<'world>(
                world: &'world (impl WorldReadOnly + ?Sized),
                bounds: impl RangeBounds<$key>,
            ) -> impl DoubleEndedIterator<Item = (&'world $key, &'world $value)> + 'world {
                world.$field().range::<$key>(bounds)
            }

            /// Return the number of entries.
            #[must_use]
            pub fn len(world: &(impl WorldReadOnly + ?Sized)) -> usize {
                world.$field().len()
            }

            /// Return whether the map holds no entry.
            #[must_use]
            pub fn is_empty(world: &(impl WorldReadOnly + ?Sized)) -> bool {
                world.$field().is_empty()
            }
        }
    };
}

/// Generate the typed helpers of one SCCP cell.
macro_rules! cell_value {
    ($(#[$meta:meta])* $module:ident => $field:ident: $value:ty) => {
        $(#[$meta])*
        pub mod $module {
            use super::*;

            /// Borrow the current value.
            #[must_use]
            pub fn get(world: &(impl WorldReadOnly + ?Sized)) -> &$value {
                world.$field()
            }

            /// Replace the value in the executing transaction, returning the previous value.
            pub fn set(state_transaction: &mut StateTransaction<'_, '_>, value: $value) -> $value {
                core::mem::replace(state_transaction.world.$field.get_mut(), value)
            }
        }
    };
}

cell_value! {
    /// SCCP v1 consensus parameters; SCCP exists on a network iff present (§4.1).
    parameters => sccp_parameters: Option<SccpParametersV1>
}
cell_value! {
    /// Genesis reset nonce of this Taira identity (§4.18).
    reset_nonce => sccp_reset_nonce: Option<[u8; 32]>
}
storage_map! {
    /// Immutable committee trust and liability records (§4.2).
    committee_generations => sccp_committee_generations: u64 => crate::smartcontracts::isi::sccp::generation_record::RetainedSccpGeneration,
    valid(generation, record) => *generation == record.generation && record.is_well_formed(),
    index(sccp_destination_pending_generations, record) => record.end.is_some() && record.dest_cleared_lc.is_none()
}
cell_value! {
    /// Current committee generation; zero before initialization.
    committee_current => sccp_committee_current: u64
}
cell_value! {
    /// Bounded liability clock of the executing block (§4.8 S0).
    liability_clock => sccp_liability_clock: u64
}
cell_value! {
    /// Consecutive heights missing authenticated SCCP inputs (§4.6).
    degraded_run => sccp_degraded_run: u32
}
cell_value! {
    /// Consensus anchors in the not-yet-complete chunk (§4.2 A1).
    anchor_open => sccp_anchor_open: crate::smartcontracts::isi::sccp::anchor_record::RetainedSccpAnchors
}
storage_map! {
    /// Immutable roots of complete 4096-height anchor chunks (§4.2 A1).
    anchor_chunks => sccp_anchor_chunks: u64 => [u8; 32],
    valid(chunk, _root) => chunk.checked_add(1).and_then(|count| count.checked_mul(4096)).is_some()
}
storage_map! {
    /// Leaf references by `(height, commitment_index)` (§4.5); see [`super::leaves`]. Indices
    /// stay below the 512-leaf block limit.
    block_leaves => sccp_block_leaves: (u64, u32) => SccpLeafRefV1,
    valid((_height, index), _leaf) => *index < SCCP_MESSAGES_MAX_PER_BLOCK_V1
}
storage_map! {
    /// Block commitment roots of SCCP-bearing heights (§4.5), each of 1..=512 leaves.
    block_commitments => sccp_block_commitments: u64 => SccpBlockCommitmentV1,
    valid(_height, commitment) =>
        (1..=SCCP_MESSAGES_MAX_PER_BLOCK_V1).contains(&commitment.message_count)
}
cell_value! {
    /// History accumulator size and peaks (§3.5).
    history => sccp_history: SccpHistoryStateV1
}
storage_map! {
    /// History leaves by index as `(height, leaf)` (§3.5).
    history_leaves => sccp_history_leaves: u64 => (u64, [u8; 32])
}
storage_map! {
    /// Outbound message records by message id (§4.4).
    outbound_messages => sccp_outbound_messages: [u8; 32] => SccpOutboundMessageRecordV1
}
storage_map! {
    /// Outbound message ids by `(network, revision, nonce)` (§4.4).
    outbound_by_nonce => sccp_outbound_by_nonce: (SccpNetworkV1, u32, u64) => [u8; 32]
}
storage_map! {
    /// Destination control records by `(network, revision, control_nonce)` (§4.14.6), whose
    /// leaf indices stay below the 512-leaf block limit.
    control_messages => sccp_control_messages: (SccpNetworkV1, u32, u64) => SccpControlRecordV1,
    valid(key, record) => key.0.is_external() && key.1 != 0 && key.2 != 0 && record.has_valid_shape()
}
storage_map! {
    /// Current emergency parts and their original certificate cause (§4.14.7).
    fast_pauses => sccp_fast_pauses: SccpNetworkV1 => crate::smartcontracts::isi::sccp::pause_record::RetainedSccpFastPause,
    valid(network, record) => network.is_external() && record.has_valid_shape()
}
storage_map! {
    /// Nonzero Parliament suspension deadlines (§4.14.7); zero removes the entry.
    fast_pause_suspended_until_ms => sccp_fast_pause_suspended_until_ms: SccpNetworkV1 => u64,
    valid(network, until) => network.is_external() && *until != 0
}
storage_map! {
    /// Independent current-head primary/backup rounds, retaining original endorsement graphs.
    fast_pause_rounds => sccp_fast_pause_rounds: (SccpNetworkV1, iroha_data_model::sccp::fast_pause::SccpPanelRoleV1) => crate::smartcontracts::isi::sccp::pause_record::RetainedSccpFastPauseRound,
    valid(key, _record) => key.0.is_external()
}
cell_value! {
    /// Chain-wide original draw and accepted members; empty before the first valid boundary.
    pause_panel => sccp_pause_panel: Option<crate::smartcontracts::isi::sccp::pause_record::RetainedSccpPausePanel>
}
storage_map! {
    /// Route registry by external network (§4.14.1), each route under its own network.
    routes => sccp_routes: SccpNetworkV1 => SccpRouteV1,
    valid(network, route) => *network == route.network
}
storage_map! {
    /// Globally unique destination words to `(network, revision)`; never freed (§4.14.1).
    destination_words => sccp_destination_words: [u8; 32] => (SccpNetworkV1, u32)
}
storage_map! {
    /// Per-subject SCCP governance revision counters; absent means 0 and no entry is 0
    /// (§4.14.3). Write through [`set_governance_revision`](super::set_governance_revision).
    governance_revisions => sccp_governance_revisions: SccpGovernanceSubjectV1 => u64,
    valid(_subject, revision) => *revision != 0
}
storage_map! {
    /// Inbound message records by message id (§4.12).
    inbound_messages => sccp_inbound_messages: [u8; 32] => SccpInboundRecordV1
}
storage_map! {
    /// Pending `(inbound, refund)` settlement counts per `(network, revision)` (§4.14.2);
    /// absent means `(0, 0)` and no entry is `(0, 0)`. Write through
    /// [`set_pending_counts`](super::set_pending_counts).
    pending_counts => sccp_pending_counts: (SccpNetworkV1, u32) => (u64, u64),
    valid(_key, (inbound, refunds)) => *inbound != 0 || *refunds != 0
}
storage_map! {
    /// Inbound light clients by source network (§4.13.1).
    light_clients => sccp_light_clients: SccpNetworkV1 => SccpLightClientV1
}
storage_map! {
    /// Authenticated source consensus sets by `(network, set_id)` (§4.13.1).
    light_client_sets => sccp_light_client_sets: (SccpNetworkV1, u64) => SccpLcConsensusSetV1
}
storage_map! {
    /// Finalized source checkpoints by `(network, source_height)` (§4.13.1).
    light_client_checkpoints => sccp_light_client_checkpoints: (SccpNetworkV1, u64) => SccpLcCheckpointV1
}
storage_map! {
    /// Lowest checkpoint height per `(network, stride bucket)`, kept permanently (§4.13.1).
    light_client_stride_index => sccp_light_client_stride_index: (SccpNetworkV1, u64) => u64
}
storage_map! {
    /// Parliament-activated light-client profile versions by `(network, version)` (§4.13.2):
    /// an external network, a version above the genesis version 1 and a nonzero profile hash.
    light_client_profiles => sccp_light_client_profiles: (SccpNetworkV1, u32) => SccpLcProfileActivationV1,
    valid((network, version), activation) => network.is_external()
        && *version > SCCP_LC_GENESIS_PROFILE_VERSION_V1
        && activation.profile_hash != [0; 32]
}

/// Return the governance revision of `subject`, which is 0 when absent (§4.14.3).
#[must_use]
pub fn governance_revision(
    world: &(impl WorldReadOnly + ?Sized),
    subject: &SccpGovernanceSubjectV1,
) -> u64 {
    governance_revisions::get(world, subject)
        .copied()
        .unwrap_or(0)
}

/// Set the governance revision of `subject`, removing its entry at 0, and return the previous
/// revision (0 when absent).
pub fn set_governance_revision(
    state_transaction: &mut StateTransaction<'_, '_>,
    subject: SccpGovernanceSubjectV1,
    revision: u64,
) -> u64 {
    let previous = if revision == 0 {
        state_transaction
            .world
            .sccp_governance_revisions
            .remove(subject)
    } else {
        state_transaction
            .world
            .sccp_governance_revisions
            .insert(subject, revision)
    };
    previous.unwrap_or(0)
}

/// Return the pending `(inbound, refund)` counts of `(network, revision)`, `(0, 0)` when absent
/// (§4.14.2).
#[must_use]
pub fn pending_count(
    world: &(impl WorldReadOnly + ?Sized),
    key: &(SccpNetworkV1, u32),
) -> (u64, u64) {
    pending_counts::get(world, key).copied().unwrap_or((0, 0))
}

/// Set the pending `(inbound, refund)` counts of `(network, revision)`, removing the entry at
/// `(0, 0)`, and return the previous counts (`(0, 0)` when absent).
pub fn set_pending_counts(
    state_transaction: &mut StateTransaction<'_, '_>,
    key: (SccpNetworkV1, u32),
    counts: (u64, u64),
) -> (u64, u64) {
    let previous = if counts == (0, 0) {
        state_transaction.world.sccp_pending_counts.remove(key)
    } else {
        state_transaction
            .world
            .sccp_pending_counts
            .insert(key, counts)
    };
    previous.unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_route};

    #[test]
    fn generation_and_anchor_stores_preserve_validation_and_transaction_rollback() {
        use crate::smartcontracts::isi::sccp::test_support::sample_generation;
        use iroha_data_model::sccp::generation::SccpAnchorV1;
        let state = blank_state();
        let mut block = state.block(header(5));
        let budget = state.ivm_execution_budget();
        let original = super::super::generation_record::RetainedSccpGeneration::admit(
            &sample_generation(1),
            &budget,
        )
        .unwrap();
        assert!(committee_generations::valid_entry(&1, &original));
        assert!(!committee_generations::valid_entry(&2, &original));
        {
            let mut stx = block.transaction();
            assert!(committee_generations::insert(&mut stx, 2, original.clone()).is_err());
            assert!(committee_generations::is_empty(&*stx.world));
            assert_eq!(
                committee_generations::insert(&mut stx, 1, original.clone()).unwrap(),
                None
            );
            assert_eq!(committee_generations::get(&*stx.world, &1), Some(&original));
            assert!(stx.world.sccp_destination_pending_generations.is_empty());
            let mut ended = original.clone();
            ended.end = Some(iroha_data_model::sccp::generation::SccpGenerationEndV1 {
                end_height: 5,
                end_timestamp_ms: 5_000,
                next_committee_root: original.committee_root,
                successor_validity_ms: original.validity_ms,
            });
            assert!(committee_generations::insert(&mut stx, 2, ended.clone()).is_err());
            assert!(stx.world.sccp_destination_pending_generations.is_empty());
            committee_generations::insert(&mut stx, 1, ended.clone()).unwrap();
            assert_eq!(
                stx.world.sccp_destination_pending_generations.get(&1),
                Some(&())
            );
            let mut cleared = ended.clone();
            cleared.dest_cleared_lc = Some(5_000);
            committee_generations::insert(&mut stx, 1, cleared).unwrap();
            assert!(stx.world.sccp_destination_pending_generations.is_empty());
            committee_generations::insert(&mut stx, 1, ended.clone()).unwrap();
            assert!(committee_generations::remove(&mut stx, 1).is_some());
            assert!(stx.world.sccp_destination_pending_generations.is_empty());
            committee_generations::insert(&mut stx, 1, ended).unwrap();
            assert_eq!(committee_current::set(&mut stx, 1), 0);
            assert_eq!(liability_clock::set(&mut stx, 1_000), 0);
            assert_eq!(degraded_run::set(&mut stx, 2), 0);
            assert_eq!(*committee_current::get(&*stx.world), 1);
            assert_eq!(*liability_clock::get(&*stx.world), 1_000);
            assert_eq!(*degraded_run::get(&*stx.world), 2);
            let anchor = SccpAnchorV1 {
                core_hash: [1; 32],
                result: [2; 32],
            };
            let anchors =
                super::super::anchor_record::RetainedSccpAnchors::admit(&[anchor], &budget)
                    .unwrap();
            assert!(anchor_open::set(&mut stx, anchors).as_slice().is_empty());
            assert_eq!(anchor_open::get(&*stx.world).as_slice(), &[anchor]);
            assert!(anchor_chunks::insert(&mut stx, u64::MAX, [3; 32]).is_err());
            assert_eq!(anchor_chunks::insert(&mut stx, 0, [3; 32]).unwrap(), None);
            assert_eq!(anchor_chunks::get(&*stx.world, &0), Some(&[3; 32]));
            // Dropping the complete transaction retains neither metadata nor new trust state.
        }
        assert!(committee_generations::is_empty(&block.world));
        assert!(block.world.sccp_destination_pending_generations.is_empty());
        assert!(anchor_chunks::is_empty(&block.world));
        assert!(anchor_open::get(&block.world).as_slice().is_empty());
        assert_eq!(*committee_current::get(&block.world), 0);
        assert_eq!(*liability_clock::get(&block.world), 0);
        assert_eq!(*degraded_run::get(&block.world), 0);
    }

    #[test]
    fn pause_stores_reject_local_network_and_preserve_funded_transaction_rollback() {
        use crate::smartcontracts::isi::sccp::{
            pause_record::{
                RetainedSccpFastPause, RetainedSccpFastPauseRound, RetainedSccpPausePanel,
            },
            test_support::{sample_fast_pause, sample_fast_pause_round, sample_pause_panel},
        };
        use iroha_data_model::sccp::fast_pause::SccpPanelRoleV1;
        let state = blank_state();
        let budget = state.ivm_execution_budget();
        let mut block = state.block(header(5));
        let before = budget.reserved_bytes();
        let pause = RetainedSccpFastPause::admit(&sample_fast_pause(1), &budget).unwrap();
        let round =
            RetainedSccpFastPauseRound::admit(&sample_fast_pause_round(1), &budget).unwrap();
        let panel = RetainedSccpPausePanel::admit(&sample_pause_panel(1), &budget).unwrap();
        let retained = budget.reserved_bytes();
        let network = SccpNetworkV1::EthereumMainnet;
        {
            let mut stx = block.transaction();
            assert!(
                fast_pauses::insert(&mut stx, SccpNetworkV1::SoraTaira, pause.clone()).is_err()
            );
            assert!(
                fast_pause_rounds::insert(
                    &mut stx,
                    (SccpNetworkV1::SoraTaira, SccpPanelRoleV1::Primary),
                    round.clone()
                )
                .is_err()
            );
            assert!(fast_pause_suspended_until_ms::insert(&mut stx, network, 0).is_err());
            assert!(
                fast_pause_suspended_until_ms::insert(&mut stx, SccpNetworkV1::SoraTaira, 1)
                    .is_err()
            );
            assert_eq!(
                fast_pauses::insert(&mut stx, network, pause.clone()).unwrap(),
                None
            );
            assert_eq!(
                fast_pause_rounds::insert(
                    &mut stx,
                    (network, SccpPanelRoleV1::Primary),
                    round.clone()
                )
                .unwrap(),
                None
            );
            assert_eq!(
                fast_pause_suspended_until_ms::insert(&mut stx, network, 5_000).unwrap(),
                None
            );
            assert_eq!(pause_panel::set(&mut stx, Some(panel.clone())), None);
            assert_eq!(fast_pauses::get(&*stx.world, &network), Some(&pause));
            assert_eq!(
                fast_pause_rounds::get(&*stx.world, &(network, SccpPanelRoleV1::Primary)),
                Some(&round)
            );
            assert_eq!(pause_panel::get(&*stx.world), &Some(panel.clone()));
        }
        assert!(fast_pauses::is_empty(&block.world));
        assert!(fast_pause_rounds::is_empty(&block.world));
        assert!(fast_pause_suspended_until_ms::is_empty(&block.world));
        assert!(pause_panel::get(&block.world).is_none());
        assert_eq!(
            budget.reserved_bytes(),
            retained,
            "rollback preserves the original readers' graphs"
        );
        drop((pause, round, panel));
        assert_eq!(budget.reserved_bytes(), before);
    }

    #[test]
    fn storage_helpers_write_read_iterate_and_roll_back() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let record = |paused| SccpControlRecordV1 {
            track: 1,
            parliament_paused: paused,
            fast_pause_until_ms: 0,
            height: 3,
            commitment_index: 0,
            leaf: [1; 32],
            certificate_id: [2; 32],
            effect_hash: [5; 32],
        };
        {
            let mut stx = block.transaction();
            assert!(control_messages::is_empty(&*stx.world));
            let first = (SccpNetworkV1::EthereumMainnet, 1, 1);
            let second = (SccpNetworkV1::BscMainnet, 1, 1);
            assert_eq!(
                control_messages::insert(&mut stx, second, record(false)),
                Ok(None)
            );
            assert_eq!(
                control_messages::insert(&mut stx, first, record(true)),
                Ok(None)
            );
            assert_eq!(control_messages::len(&*stx.world), 2);
            assert!(control_messages::contains(&*stx.world, &first));
            assert_eq!(
                control_messages::get(&*stx.world, &second),
                Some(&record(false))
            );
            let keys: Vec<_> = control_messages::iter(&*stx.world)
                .map(|(key, _)| *key)
                .collect();
            assert_eq!(
                keys,
                vec![first, second],
                "iteration is in ascending key order"
            );
            assert_eq!(
                control_messages::remove(&mut stx, first),
                Some(record(true))
            );
            assert!(!control_messages::contains(&*stx.world, &first));
            // Dropping the transaction rolls every write back.
        }
        let stx = block.transaction();
        assert!(control_messages::is_empty(&*stx.world));
    }

    #[test]
    fn range_helpers_select_one_height_of_compound_keys() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        for (height, index) in [(4_u64, 0_u32), (5, 0), (5, 1), (6, 0)] {
            block_leaves::insert(
                &mut stx,
                (height, index),
                SccpLeafRefV1::transfer([u8::try_from(height).unwrap(); 32]),
            )
            .expect("an index below the block limit");
        }
        let at_five: Vec<_> = block_leaves::range(&*stx.world, (5, 0)..=(5, u32::MAX))
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(at_five, vec![(5, 0), (5, 1)]);
    }

    #[test]
    fn cell_helpers_replace_and_return_the_previous_value() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        assert_eq!(*reset_nonce::get(&*stx.world), None);
        assert_eq!(reset_nonce::set(&mut stx, Some([7; 32])), None);
        assert_eq!(reset_nonce::set(&mut stx, Some([8; 32])), Some([7; 32]));
        assert_eq!(*reset_nonce::get(&*stx.world), Some([8; 32]));
        assert_eq!(*parameters::get(&*stx.world), None);
        assert_eq!(
            parameters::set(&mut stx, Some(SccpParametersV1::taira_default())),
            None
        );
        assert!(parameters::get(&*stx.world).is_some());
        assert_eq!(
            history::set(
                &mut stx,
                SccpHistoryStateV1 {
                    size: 1,
                    peaks: vec![[3; 32]],
                }
            ),
            SccpHistoryStateV1::default()
        );
    }

    #[test]
    fn governance_revision_defaults_to_zero() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let subject = SccpGovernanceSubjectV1::Route(SccpNetworkV1::EthereumMainnet);
        assert_eq!(governance_revision(&*stx.world, &subject), 0);
        governance_revisions::insert(&mut stx, subject, 4).expect("a nonzero revision");
        assert_eq!(governance_revision(&*stx.world, &subject), 4);
        routes::insert(
            &mut stx,
            SccpNetworkV1::EthereumMainnet,
            sample_route(SccpNetworkV1::EthereumMainnet),
        )
        .expect("a route under its own network");
        assert_eq!(routes::len(&*stx.world), 1);
    }

    #[test]
    fn inserts_refuse_entries_that_break_a_stored_invariant() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let refused = |result: Result<_, Error>| {
            let error = result.expect_err("the entry breaks its map's invariant");
            assert!(error.to_string().contains("stored invariant"), "{error}");
        };
        refused(
            block_leaves::insert(
                &mut stx,
                (4, SCCP_MESSAGES_MAX_PER_BLOCK_V1),
                SccpLeafRefV1::transfer([1; 32]),
            )
            .map(drop),
        );
        refused(
            block_commitments::insert(
                &mut stx,
                4,
                SccpBlockCommitmentV1 {
                    root: [1; 32],
                    message_count: 0,
                    history_index: 0,
                },
            )
            .map(drop),
        );
        refused(
            routes::insert(
                &mut stx,
                SccpNetworkV1::BscMainnet,
                sample_route(SccpNetworkV1::EthereumMainnet),
            )
            .map(drop),
        );
        refused(
            governance_revisions::insert(&mut stx, SccpGovernanceSubjectV1::Parameters, 0)
                .map(drop),
        );
        refused(pending_counts::insert(&mut stx, (SccpNetworkV1::BscMainnet, 1), (0, 0)).map(drop));
        let activation = |profile_hash| SccpLcProfileActivationV1 {
            profile_hash,
            activation_height: 4,
            proposal_id: [1; 32],
        };
        for (key, profile_hash) in [
            ((SccpNetworkV1::EthereumMainnet, 1), [1; 32]),
            ((SccpNetworkV1::EthereumMainnet, 0), [1; 32]),
            ((SccpNetworkV1::SoraTaira, 2), [1; 32]),
            ((SccpNetworkV1::EthereumMainnet, 2), [0; 32]),
        ] {
            refused(
                light_client_profiles::insert(&mut stx, key, activation(profile_hash)).map(drop),
            );
        }
        assert!(light_client_profiles::is_empty(&*stx.world));
        assert_eq!(
            light_client_profiles::insert(
                &mut stx,
                (SccpNetworkV1::EthereumMainnet, 2),
                activation([1; 32])
            ),
            Ok(None)
        );
        assert!(block_leaves::is_empty(&*stx.world));
        assert!(block_commitments::is_empty(&*stx.world));
        assert!(routes::is_empty(&*stx.world));
        assert!(governance_revisions::is_empty(&*stx.world));
        assert!(pending_counts::is_empty(&*stx.world));
        let route = sample_route(SccpNetworkV1::EthereumMainnet);
        assert!(routes::valid_entry(&SccpNetworkV1::EthereumMainnet, &route));
        assert_eq!(
            routes::insert(&mut stx, SccpNetworkV1::EthereumMainnet, route),
            Ok(None)
        );
    }

    #[test]
    fn counter_setters_keep_absent_as_zero() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let key = (SccpNetworkV1::BscMainnet, 2);
        assert_eq!(pending_count(&*stx.world, &key), (0, 0));
        assert_eq!(set_pending_counts(&mut stx, key, (2, 0)), (0, 0));
        assert_eq!(set_pending_counts(&mut stx, key, (1, 1)), (2, 0));
        assert_eq!(pending_count(&*stx.world, &key), (1, 1));
        assert_eq!(set_pending_counts(&mut stx, key, (0, 0)), (1, 1));
        assert!(
            !pending_counts::contains(&*stx.world, &key),
            "a count back at zero leaves no entry"
        );
        let subject = SccpGovernanceSubjectV1::Parameters;
        assert_eq!(set_governance_revision(&mut stx, subject, 3), 0);
        assert_eq!(governance_revision(&*stx.world, &subject), 3);
        assert_eq!(set_governance_revision(&mut stx, subject, 0), 3);
        assert!(governance_revisions::is_empty(&*stx.world));
    }
}
