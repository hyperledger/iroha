//! Commit-QC authentication of SCCP state through the execution witness (`specs/sccp.md` §4.5).
//! Owner: ws20 (complete).
//!
//! The Commit QC certifies the block's `ExecutionCommitment`, whose `ordinary_writes_root` and
//! `post_state_root` cover the witnessed write set only (`crate::sumeragi::commitment`). SCCP
//! stores are not recorded key by key. Instead, every height at which any SCCP world field
//! changed contributes one synthetic write under [`SCCP_STATE_DELTA_WITNESS_KEY_V1`] whose value
//! binds the height and the hash of the canonical SCCP delta of the block overlay (the SCCP
//! portion of the World execution write set: every written key in canonical order with its new
//! value or its deletion). Two executions that differ in any SCCP write therefore certify
//! different roots. Every node starts from the same genesis state, so agreement on every
//! height's delta is agreement on the complete SCCP state that bridge keys sign statements from.
//!
//! A height without SCCP writes adds nothing, so blocks of a network without SCCP keep their
//! exact witness.

use iroha_crypto::Hash;
use iroha_data_model::block::consensus::ExecKv;

/// Synthetic execution-witness key of the SCCP state delta of one height.
///
/// Its first byte `0xD8` follows the fixed synthetic keys of
/// `iroha_data_model::execution_witness::ExecutionWitnessKeyTagV1` (`0xD4..=0xD7`) and is
/// disjoint from every recorder family and from the lane-context key.
/// TODO(ws20-followup): reserve `0xD8` as `SccpStateDelta` in `ExecutionWitnessKeyTagV1`
/// (`crates/iroha_data_model/src/execution_witness.rs`, outside this workstream's paths) so the
/// registry's compile-time disjointness covers it.
pub const SCCP_STATE_DELTA_WITNESS_KEY_V1: &[u8] = b"\xd8iroha:sccp:state-delta:v1";

/// Return the synthetic witness write of the SCCP delta `delta` of block `height`, or `None`
/// when the block changed no SCCP field.
///
/// The value is the headered Norito frame of `(height, digest)`, where `digest` is the Iroha
/// [`Hash`] of the canonical delta bytes.
#[must_use]
pub fn state_delta_witness_write(height: u64, delta: &[u8]) -> Option<ExecKv> {
    if delta.is_empty() {
        return None;
    }
    let digest: [u8; 32] = Hash::new(delta).into();
    let value = norito::to_bytes(&(height, digest))
        .expect("an SCCP state-delta witness value always encodes");
    Some(ExecKv {
        key: SCCP_STATE_DELTA_WITNESS_KEY_V1.to_vec(),
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        exec_witness::{roots::witness_pairs, smt::compute_post_state_root},
        smartcontracts::isi::sccp::{store, test_support::blank_state},
    };
    use iroha_data_model::{
        block::{BlockHeader, consensus::ExecWitness},
        sccp::params::SccpParametersV1,
    };
    use std::num::NonZeroU64;

    #[test]
    fn the_key_is_disjoint_from_every_other_witness_family() {
        use iroha_data_model::execution_witness::{
            ExecutionWitnessKeyTagV1 as Tag, FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
            PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1, VALIDATION_FEE_POLICY_WITNESS_KEY_V1,
        };
        let tags = [
            Tag::AccountMetadata,
            Tag::DomainMetadata,
            Tag::NftMetadata,
            Tag::AssetDefinitionMetadata,
            Tag::AssetBalance,
            Tag::AssetDefinitionTotalSupply,
            Tag::AccountRoleBinding,
            Tag::Role,
            Tag::AccountPermission,
            Tag::RolePermission,
            Tag::ValidationFeePolicy,
            Tag::ParliamentTimedOvnCasting,
            Tag::FastpqOrdinarySourceStatements,
        ];
        assert!(
            tags.iter()
                .all(|tag| *tag as u8 != SCCP_STATE_DELTA_WITNESS_KEY_V1[0])
        );
        for fixed in [
            VALIDATION_FEE_POLICY_WITNESS_KEY_V1,
            PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1,
            FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1,
            iroha_data_model::sumeragi_finality::SUMERAGI_LANE_STATE_WITNESS_KEY,
        ] {
            assert_ne!(fixed[0], SCCP_STATE_DELTA_WITNESS_KEY_V1[0]);
        }
    }

    #[test]
    fn the_write_binds_the_height_and_the_delta() {
        assert_eq!(state_delta_witness_write(5, &[]), None);
        let write = state_delta_witness_write(5, b"delta").expect("a nonempty delta");
        assert_eq!(write.key, SCCP_STATE_DELTA_WITNESS_KEY_V1);
        let (height, digest): (u64, [u8; 32]) =
            norito::decode_from_bytes(&write.value).expect("headered value");
        assert_eq!(height, 5);
        assert_eq!(digest, <[u8; 32]>::from(Hash::new(b"delta")));
        assert_ne!(state_delta_witness_write(6, b"delta"), Some(write.clone()));
        assert_ne!(state_delta_witness_write(5, b"other"), Some(write));
    }

    /// Execute one fixture height with `parameters` written to SCCP state (or no SCCP write)
    /// and capture its ordinary execution witness.
    fn captured_witness(parameters: Option<SccpParametersV1>) -> crate::state::CapturedExecWitness {
        crate::state::native_capture_fixture::with_native_capture_source(
            false,
            |_, mut state_block, _recording, mut source, _| {
                if let Some(parameters) = parameters {
                    let mut transaction = state_block.transaction();
                    store::parameters::set(&mut transaction, Some(parameters));
                    transaction.apply();
                }
                crate::state::native_capture_fixture::seal_native_source(
                    &mut state_block,
                    &mut source,
                )
                .unwrap();
                state_block
                    .capture_exec_witness()
                    .expect("capture the original completed source");
                state_block
                    .take_exec_witness()
                    .expect("the captured witness")
            },
        )
    }

    #[test]
    fn late_recording_cannot_own_the_sccp_witness() {
        let state = blank_state();
        let header = BlockHeader::new(NonZeroU64::MIN, None, None, 0, 0);
        let mut state_block = state.block(header);
        let _recording = crate::exec_witness::begin_exec_witness_capture()
            .expect("a fresh recorder after block construction");
        let tx_set_hash: [u8; 32] =
            iroha_data_model::nexus::axt_ordered_transaction_set_digest_v1(std::iter::empty::<
                &iroha_data_model::transaction::TransactionEntrypoint,
            >())
            .expect("empty transaction set digest")
            .into();
        state_block.set_fastpq_tx_set_hash(tx_set_hash);
        state_block
            .finalize_fastpq_source_inventory(&[], &[], &[])
            .expect("empty source inventory");
        assert_eq!(
            state_block.capture_exec_witness(),
            Err("State execution has no original recorder".into())
        );
        assert!(state_block.take_exec_witness().is_none());
        assert!(state_block.take_fastpq_witness_context().is_none());
    }

    /// `(ordinary_writes_root, post_state_root)` as `crate::sumeragi::commitment` derives them.
    fn certified_roots(witness: &ExecWitness) -> (Hash, Hash) {
        let (reads, writes) = witness_pairs(witness);
        let root = compute_post_state_root(&reads, &writes);
        assert!(!writes.is_empty());
        (root, root)
    }

    #[test]
    fn sccp_writes_change_the_certified_roots() {
        let first = SccpParametersV1::taira_default();
        let mut second = first;
        second.max_exempt_transactions_per_block = first.max_exempt_transactions_per_block + 1;
        let without = captured_witness(None);
        assert!(
            without
                .writes
                .iter()
                .all(|write| write.key != SCCP_STATE_DELTA_WITNESS_KEY_V1),
            "a height without SCCP writes keeps its exact witness"
        );
        let one = captured_witness(Some(first));
        let other = captured_witness(Some(second));
        for witness in [&one, &other] {
            assert_eq!(
                witness
                    .writes
                    .iter()
                    .filter(|write| write.key == SCCP_STATE_DELTA_WITNESS_KEY_V1)
                    .count(),
                1
            );
        }
        let roots = [
            certified_roots(&without),
            certified_roots(&one),
            certified_roots(&other),
        ];
        for (index, left) in roots.iter().enumerate() {
            for right in &roots[index + 1..] {
                assert_ne!(left.0, right.0, "ordinary_writes_root");
                assert_ne!(left.1, right.1, "post_state_root");
            }
        }
        assert_eq!(
            certified_roots(&captured_witness(Some(first))),
            roots[1],
            "the SCCP witness is deterministic"
        );
    }
}
