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
//! example a roster is stored under its own generation). Each map's `valid_entry` is the single
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
        attestation::{
            SccpAttestationStatusV1, SccpAttestationSubjectV1, SccpBlockCommitmentV1,
            SccpHistoryStateV1,
        },
        control::{SccpControlRecordV1, SccpLeafRefV1},
        governance::SccpGovernanceSubjectV1,
        inbound::SccpInboundRecordV1,
        keys::{SccpAttestationFaultRecordV1, SccpBridgeKeyStateV1},
        keys_index::SccpPruneCursorV1,
        light_client::{
            SCCP_LC_GENESIS_PROFILE_VERSION_V1, SccpLcCheckpointV1, SccpLcConsensusSetV1,
            SccpLcProfileActivationV1, SccpLightClientV1,
        },
        outbound::SccpOutboundMessageRecordV1,
        params::{SCCP_MESSAGES_MAX_PER_BLOCK_V1, SccpParametersV1},
        registry::SccpRouteV1,
        roster::SccpBridgeRosterV1,
    },
};
use iroha_model_base::peer::PeerId;
use mv::storage::StorageReadOnly;

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
                Ok(state_transaction.world.$field.insert(key, value))
            }

            /// Remove `key` in the executing transaction, returning the previous value.
            pub fn remove(
                state_transaction: &mut StateTransaction<'_, '_>,
                key: $key,
            ) -> Option<$value> {
                state_transaction.world.$field.remove(key)
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
    /// Bridge-key state per peer (§4.2.1).
    bridge_keys => sccp_bridge_keys: PeerId => SccpBridgeKeyStateV1
}
storage_map! {
    /// Permanent bridge-key address to owning peer index; addresses are never reused (§4.2.1).
    /// The zero address is never an owner.
    bridge_key_owners => sccp_bridge_key_owners: [u8; 20] => PeerId,
    valid(address, _peer) => *address != [0; 20]
}
storage_map! {
    /// Bridge roster generations by generation number (§4.3.1), each under its own generation.
    rosters => sccp_rosters: u64 => SccpBridgeRosterV1,
    valid(generation, roster) => *generation == roster.generation
}
cell_value! {
    /// Current bridge roster generation (§4.3.1).
    roster_current => sccp_roster_current: u64
}
cell_value! {
    /// Generation whose heartbeat block was forced (§4.3.2).
    heartbeat_marker => sccp_heartbeat_marker: Option<u64>
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
    /// Attestation subjects by height (§4.6), each under its own height.
    attestation_subjects => sccp_attestation_subjects: u64 => SccpAttestationSubjectV1,
    valid(height, subject) => *height == subject.height
}
storage_map! {
    /// Attestation signer bitmaps by subject height (§4.6).
    attestation_status => sccp_attestation_status: u64 => SccpAttestationStatusV1
}
storage_map! {
    /// Stored attestation signatures by `(height, signer_index)` (§4.8).
    attestation_signatures => sccp_attestation_signatures: (u64, u8) => [u8; 65]
}
storage_map! {
    /// Equivocation faults by `(address, height)` (§4.11).
    attestation_faults => sccp_attestation_faults: ([u8; 20], u64) => SccpAttestationFaultRecordV1
}
storage_map! {
    /// Last height each bridge-key address signed (§4.9 liveness).
    member_last_signed => sccp_member_last_signed: [u8; 20] => u64
}
storage_map! {
    /// Stalled rotation heights to the outgoing generation (§4.3.3).
    handoff_stalled => sccp_handoff_stalled: u64 => u64
}
cell_value! {
    /// Resumable position of the bounded pruning step (§4.10).
    prune_cursor => sccp_prune_cursor: SccpPruneCursorV1
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
    valid(_key, record) => record.commitment_index < SCCP_MESSAGES_MAX_PER_BLOCK_V1
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
    use crate::smartcontracts::isi::sccp::test_support::{
        blank_state, header, peer, sample_bridge_key_state, sample_route,
    };

    #[test]
    fn storage_helpers_write_read_iterate_and_roll_back() {
        let state = blank_state();
        let mut block = state.block(header(3));
        {
            let mut stx = block.transaction();
            assert!(bridge_keys::is_empty(&*stx.world));
            let first = peer(1);
            let second = peer(2);
            assert_eq!(
                bridge_keys::insert(&mut stx, first.clone(), sample_bridge_key_state(1)),
                Ok(None)
            );
            assert_eq!(
                bridge_keys::insert(&mut stx, second.clone(), sample_bridge_key_state(2)),
                Ok(None)
            );
            assert_eq!(bridge_keys::len(&*stx.world), 2);
            assert!(bridge_keys::contains(&*stx.world, &first));
            assert_eq!(
                bridge_keys::get(&*stx.world, &second),
                Some(&sample_bridge_key_state(2))
            );
            let keys: Vec<_> = bridge_keys::iter(&*stx.world)
                .map(|(key, _)| key.clone())
                .collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted, "iteration is in ascending key order");
            assert_eq!(
                bridge_keys::remove(&mut stx, first.clone()),
                Some(sample_bridge_key_state(1))
            );
            assert!(!bridge_keys::contains(&*stx.world, &first));
            // Dropping the transaction rolls every write back.
        }
        let stx = block.transaction();
        assert!(bridge_keys::is_empty(&*stx.world));
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
        assert_eq!(*roster_current::get(&*stx.world), 0);
        assert_eq!(roster_current::set(&mut stx, 7), 0);
        assert_eq!(roster_current::set(&mut stx, 8), 7);
        assert_eq!(*roster_current::get(&*stx.world), 8);
        assert_eq!(*parameters::get(&*stx.world), None);
        assert_eq!(
            parameters::set(&mut stx, Some(SccpParametersV1::taira_default())),
            None
        );
        assert!(parameters::get(&*stx.world).is_some());
        assert_eq!(heartbeat_marker::set(&mut stx, Some(3)), None);
        assert_eq!(
            prune_cursor::set(
                &mut stx,
                SccpPruneCursorV1 {
                    signatures_height: 2,
                    rotation_height: 1,
                }
            ),
            SccpPruneCursorV1::default()
        );
    }

    #[test]
    fn governance_revision_defaults_to_zero() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let subject = SccpGovernanceSubjectV1::Route(SccpNetworkV1::EthereumMainnet);
        assert_eq!(governance_revision(&*stx.world, &subject), 0);
        governance_revisions::insert(&mut stx, subject.clone(), 4).expect("a nonzero revision");
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
        use crate::smartcontracts::isi::sccp::test_support::{peer, sample_roster};
        use iroha_data_model::sccp::attestation::SccpBlockCommitmentV1;
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let refused = |result: Result<_, Error>| {
            let error = result.expect_err("the entry breaks its map's invariant");
            assert!(error.to_string().contains("stored invariant"), "{error}");
        };
        refused(bridge_key_owners::insert(&mut stx, [0; 20], peer(1)).map(drop));
        refused(rosters::insert(&mut stx, 2, sample_roster(1, 5)).map(drop));
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
        assert!(bridge_key_owners::is_empty(&*stx.world));
        assert!(rosters::is_empty(&*stx.world));
        assert!(block_leaves::is_empty(&*stx.world));
        assert!(block_commitments::is_empty(&*stx.world));
        assert!(routes::is_empty(&*stx.world));
        assert!(governance_revisions::is_empty(&*stx.world));
        assert!(pending_counts::is_empty(&*stx.world));
        assert!(rosters::valid_entry(&1, &sample_roster(1, 5)));
        assert_eq!(rosters::insert(&mut stx, 1, sample_roster(1, 5)), Ok(None));
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
        assert_eq!(set_governance_revision(&mut stx, subject.clone(), 3), 0);
        assert_eq!(governance_revision(&*stx.world, &subject), 3);
        assert_eq!(set_governance_revision(&mut stx, subject.clone(), 0), 3);
        assert!(governance_revisions::is_empty(&*stx.world));
    }
}
