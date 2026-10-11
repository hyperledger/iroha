//! Historical receipt proofs from the original archived writes and native finality.
//!
//! An archive is untrusted until its exact carrier and complete ordinary-write root agree
//! with the authenticated native chain. Current World values cannot substitute for it.
//! Ordinary writes retain exact original-pool allocation custody through historical proof
//! construction; compact casting leaves retain their exact array charge. TODO(S8): admit the
//! remaining native proof graph and
//! receipt/tree scratch before allocation; this scoped write owner does not fund those graphs.

mod amx_intents;
mod amx_read;
pub use amx_intents::{
    NativeAmxPreparedRelayErrorV1, NativeAmxPreparedRelayPollV1, NativeAmxPreparedRelayReadV1,
    prepared_amx_relays,
};
mod ordinary_writes;
mod reward_history;
pub use amx_read::{
    NativeAmxRecordProofErrorV1, NativeAmxRecordProofIssuedV1, NativeAmxRecordProofOwnedV1,
    NativeAmxRecordProofPollV1, NativeAmxRecordProofReadV1,
};
pub(crate) use reward_history::{committed_fee_evidence, committed_reward_exposure};

pub(crate) mod lane_payload;

use crate::{
    query::native_context_archive::NativeContextArchive, state::StateReadOnly,
    sumeragi::finality::build_proof,
};
use iroha_data_model::{
    block::{consensus::ExecWitness, decode_framed_signed_block},
    sumeragi_amx::AmxRecordKind,
    sumeragi_finality::{NativeLaneStateProof, SumeragiFinalityProof},
    validation_fee::ValidationFeePolicyWitnessProofV1,
};

type CastingBinding =
    iroha_data_model::parliament_casting::ParliamentTimedOvnCastingContextBindingV1;

struct OriginalReceiptSource {
    finality: SumeragiFinalityProof,
    witness: iroha_allocation::RetainedPayload<ExecWitness>,
    casting_bindings: ordinary_writes::CastingOwner,
}

fn original_source(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<OriginalReceiptSource, String> {
    // Genesis R is unsigned. Historical execution capabilities require a successor;
    // these operation endpoints serve exact committed non-genesis operations only.
    if height < 2 {
        return Err("historical receipt requires a certified non-genesis execution".into());
    }
    let finality = build_proof(view, height).map_err(|error| error.to_string())?;
    let decoded = finality
        .decode_checked()
        .map_err(|error| error.to_string())?;
    let budget = view.prepared_contract_cache().execution_budget().clone();
    let archive = NativeContextArchive::open_existing(
        view.kura(),
        budget.clone(),
        view.kura().native_context_archive_max_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let bytes = archive
        .read_exact(height, finality.block_header.hash())
        .map_err(|error| error.to_string())?;
    let projection =
        ordinary_writes::decode_projection(&bytes, &budget).map_err(|error| error.to_string())?;
    if projection.carrier_height != height
        || projection.carrier_hash != finality.block_header.hash()
    {
        return Err("original write archive names another certified carrier".into());
    }
    if !projection.casting_bindings.belongs_to(&budget) {
        return Err("original casting array belongs to another allocation pool".into());
    }
    let witness = projection.witness;
    let path = NativeLaneStateProof::from_witness(witness.get(), &budget)
        .map_err(|error| error.to_string())?;
    if !path.verify(
        *view.network_id(),
        height,
        decoded.execution().ordinary_writes_root,
    ) || !path
        .matches_state_payload(*view.network_id(), height, projection.lane_payload)
        .map_err(|error| error.to_string())?
    {
        return Err("archived original writes differ from certified native execution".into());
    }
    archive
        .recheck_namespace()
        .map_err(|error| error.to_string())?;
    Ok(OriginalReceiptSource {
        finality,
        witness,
        casting_bindings: projection.casting_bindings,
    })
}

/// Prove one AMX record from its original persisted native execution.
///
/// The original archive job, decoded witness and certified carrier survive every refusal.
/// The completed proof retains all concrete field allocations from that same execution pool.
/// This API creates no target transaction, monetary authority or relayer policy.
///
/// Acquisition is lazy. Call `poll` or `complete` on the returned job; either retains the
/// original descriptor, partial prefix and completed fields when a typed refusal is returned.
pub fn amx_record_proof<'v, V: StateReadOnly>(
    view: &'v V,
    height: u64,
    kind: AmxRecordKind,
    transaction: [u8; 32],
) -> NativeAmxRecordProofReadV1<'v, V> {
    NativeAmxRecordProofReadV1::new(view, height, kind, transaction)
}

/// Prove one private-root registration or cursor from its exact original parent execution.
///
/// The returned proof contains public registration state only. Callers separately authenticate
/// parent finality and verify the record proof; current World state never substitutes for a
/// missing historical write. Absence is reported only after authenticating the complete archive.
/// The original archive shares the finite execution pool; the existing native receipt proof/tree
/// scratch qualification TODO at this module's boundary also applies to this reader.
///
/// # Errors
/// Uncertified height, missing/corrupt archive, inconsistent commitments or malformed public record.
pub fn private_dataspace_record_proof(
    view: &impl StateReadOnly,
    height: u64,
    dataspace: iroha_model_base::topology::DataSpaceId,
) -> Result<Option<iroha_data_model::private_dataspace::PrivateDataspaceRecordProof>, String> {
    use iroha_data_model::private_dataspace::{
        PrivateDataspaceRecord, PrivateDataspaceRecordProof,
    };
    let source = original_source(view, height)?;
    let key = iroha_data_model::private_dataspace::private_dataspace_record_witness_key(dataspace);
    let Some(written) = source
        .witness
        .get()
        .writes
        .iter()
        .rev()
        .find(|write| write.key == key)
    else {
        return Ok(None);
    };
    let record: PrivateDataspaceRecord = norito::decode_canonical_with_limits(
        &written.value,
        norito::canonical_decode_limits(written.value.len()),
    )
    .map_err(|error| error.to_string())?;
    record.validate().map_err(|error| error.to_string())?;
    if record.dataspace_id != dataspace || record.witness_key() != written.key {
        return Err("private-root archive key differs from its record".into());
    }
    let decoded = source
        .finality
        .decode_checked()
        .map_err(|error| error.to_string())?;
    let block = norito::core::with_decode_limits_scope(
        norito::canonical_decode_limits(source.finality.block_wire.len()),
        || decode_framed_signed_block(&source.finality.block_wire),
    )
    .map_err(|error| error.to_string())?;
    let certificate = block
        .commit_certificate()
        .ok_or("private-root record carrier lacks a native certificate")?;
    let result =
        iroha_data_model::sumeragi_finality::result_of_preimage(certificate.result_preimage());
    let proof = PrivateDataspaceRecordProof::from_writes(
        *view.network_id(),
        height,
        result.0,
        source
            .witness
            .get()
            .writes
            .iter()
            .map(|write| (write.key.as_slice(), write.value.as_slice())),
        record,
    )
    .map_err(|error| error.to_string())?;
    let value = norito::encode_canonical(&proof.record).map_err(|error| error.to_string())?;
    if proof
        .inclusion
        .root(&key, &value)
        .map_err(|error| error.to_string())?
        != decoded.execution().ordinary_writes_root
    {
        return Err("private-root record differs from certified original writes".into());
    }
    Ok(Some(proof))
}

/// Derive the exact fee policy opening from a certified historical execution.
///
/// # Errors
/// Missing or corrupt original archive, invalid native finality, or inconsistent policy write.
pub fn validation_fee_policy_witness(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<ValidationFeePolicyWitnessProofV1, String> {
    let source = original_source(view, height)?;
    let (proof, root) =
        crate::receiver_snapshot::validation_fee_policy_witness_proof_v1(source.witness.get())?;
    let execution = source
        .finality
        .decode_checked()
        .map_err(|error| error.to_string())?;
    if root != execution.execution().ordinary_writes_root || !proof.verify(root) {
        return Err("fee policy opening differs from the certified ordinary-write root".into());
    }
    Ok(proof)
}

/// Derive one block's complete native fee accounting corpus from certified original writes.
///
/// # Errors
/// Missing or corrupt original archive, invalid native finality, or an inconsistent corpus.
pub fn fee_evidence_block_proof(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<iroha_data_model::fee_evidence::FeeEvidenceBlockProofV1, String> {
    let source = original_source(view, height)?;
    fee_evidence_from_source(&source, height)
}

fn fee_evidence_from_source(
    source: &OriginalReceiptSource,
    height: u64,
) -> Result<iroha_data_model::fee_evidence::FeeEvidenceBlockProofV1, String> {
    let (proof, root) =
        crate::receiver_snapshot::fee_evidence_block_proof_v1(source.witness.get())?;
    let execution = source
        .finality
        .decode_checked()
        .map_err(|error| error.to_string())?;
    if root != execution.execution().ordinary_writes_root
        || !proof.verify(root)
        || proof.snapshot_witness.commitment()?.evaluated_height != height
    {
        return Err("fee evidence differs from the certified ordinary-write root".into());
    }
    Ok(proof)
}

/// Read one immutable fee receipt, allocation or claim with compact finality membership.
///
/// # Errors
/// See [`fee_evidence_block_proof`].
pub fn fee_evidence_record_proof(
    view: &impl StateReadOnly,
    height: u64,
    key: &iroha_model_base::state_path::StatePath,
) -> Result<Option<iroha_data_model::fee_evidence::FeeEvidenceRecordProofV1>, String> {
    Ok(fee_evidence_block_proof(view, height)?.record_proof(key))
}

/// Export a complete bounded accounting window from certified original writes.
///
/// The caller must independently authenticate the anchor's opening checkpoint and closing
/// block; the exported proof is verified against it before it is returned.
///
/// # Errors
/// Invalid or unbounded window, or any missing/corrupt historical evidence.
pub fn fee_evidence_window_proof(
    view: &impl StateReadOnly,
    anchor: &iroha_data_model::fee_evidence::FeeEvidenceTrustAnchorV1,
) -> Result<iroha_data_model::fee_evidence::FeeEvidenceWindowProofV1, String> {
    use iroha_data_model::fee_evidence::{FeeEvidenceFinalizedBlockV1, FeeEvidenceWindowProofV1};
    let opening = anchor.opening_height();
    if opening < 2
        || anchor.closing_height <= opening
        || anchor.closing_height - opening
            >= u64::try_from(iroha_data_model::sumeragi::finality::NATIVE_FINALITY_MAX_BLOCK_COUNT)
                .unwrap_or(u64::MAX)
    {
        return Err("invalid or unbounded native fee window".into());
    }
    let mut blocks = Vec::new();
    for height in opening..=anchor.closing_height {
        let source = original_source(view, height)?;
        let evidence = fee_evidence_from_source(&source, height)?;
        let (policy_witness, _) =
            crate::receiver_snapshot::validation_fee_policy_witness_proof_v1(source.witness.get())?;
        let registry = evidence.registry().cloned();
        blocks.push(FeeEvidenceFinalizedBlockV1 {
            finality: source.finality,
            evidence,
            policy_witness,
            registry,
        });
    }
    let proof = FeeEvidenceWindowProofV1 { version: 1, blocks };
    proof.verify(anchor)?;
    Ok(proof)
}

/// Construct a historical casting membership proof from original execution leaves.
///
/// # Errors
/// Missing original source, mismatched root/count, invalid ordering or unavailable membership.
pub fn parliament_casting_proof(
    view: &impl StateReadOnly,
    height: u64,
    ballot_attempt_id: iroha_data_model::parliament_types::BallotAttemptId,
) -> Result<
    Option<iroha_data_model::parliament_casting::ParliamentTimedOvnFinalizedCastingProofV1>,
    String,
> {
    use iroha_crypto::{HashOf, MerkleTree};
    use iroha_data_model::parliament_casting::{
        ParliamentTimedOvnCastingContextMembershipProofV1,
        ParliamentTimedOvnCastingSnapshotCommitmentV1, ParliamentTimedOvnFinalizedCastingProofV1,
    };
    let source = original_source(view, height)?;
    let (snapshot_witness, root) =
        crate::receiver_snapshot::parliament_timed_ovn_casting_witness_proof_v1(
            source.witness.get(),
        )?;
    let decoded = source
        .finality
        .decode_checked()
        .map_err(|error| error.to_string())?;
    let expected = ParliamentTimedOvnCastingSnapshotCommitmentV1::from_ordered_bindings(
        height,
        source.casting_bindings.as_slice(),
    )?;
    if root != decoded.execution().ordinary_writes_root
        || !snapshot_witness.verify(root)
        || snapshot_witness.commitment()? != expected
        || source
            .casting_bindings
            .as_slice()
            .iter()
            .any(|binding| binding.network_id != *view.network_id().as_bytes())
    {
        return Err("casting leaves differ from certified native snapshot".into());
    }
    let Ok(index) = source
        .casting_bindings
        .as_slice()
        .binary_search_by_key(&ballot_attempt_id, |binding| binding.ballot_attempt_id)
    else {
        return Ok(None);
    };
    let tree = MerkleTree::<CastingBinding>::from_iter(
        source.casting_bindings.as_slice().iter().map(HashOf::new),
    );
    let leaf_index = u32::try_from(index).map_err(|_| "casting leaf index exceeds u32")?;
    let membership_proof = ParliamentTimedOvnCastingContextMembershipProofV1::new(
        tree.get_proof(leaf_index)
            .ok_or("casting membership proof is absent")?,
    );
    let proof = ParliamentTimedOvnFinalizedCastingProofV1 {
        snapshot_witness,
        // This fixed-size leaf has no nested allocation; the original array stays charged.
        binding: source.casting_bindings.as_slice()[index].clone(),
        membership_proof,
    };
    if !proof.verify(root) {
        return Err("casting membership differs from certified native write root".into());
    }
    Ok(Some(proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};

    #[test]
    fn actual_native_receipt_source_rejects_absent_and_subquorum_history() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                .unwrap();
        assert!(original_source(&chain.state().view(), 1).is_err());
        chain.commit(Vec::new());
        let view = chain.state().view();
        let source = original_source(&view, 2).unwrap();
        assert!(!source.witness.get().writes.is_empty());
        assert!(validation_fee_policy_witness(&view, 2).is_ok());
        assert!(
            parliament_casting_proof(
                &view,
                2,
                iroha_data_model::parliament_types::BallotAttemptId::new([7; 32])
            )
            .unwrap()
            .is_none()
        );
        assert!(original_source(&view, 3).is_err());
        drop(view);
        chain.commit(Vec::new());
        chain.corrupt_local_quorum_for_test(3, Signers::BelowQuorum);
        assert!(original_source(&chain.state().view(), 3).is_err());
    }

    #[test]
    fn original_archive_corruption_never_falls_back_to_current_world() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                .unwrap();
        chain.commit(Vec::new());
        assert!(original_source(&chain.state().view(), 2).is_ok());
        let directory = chain.kura().store_root().join("native-contexts");
        let mut changed = 0;
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("00000000000000000002-")
            {
                std::fs::write(entry.path(), b"corrupt original archive").unwrap();
                changed += 1;
            }
        }
        assert_eq!(changed, 1);
        assert!(original_source(&chain.state().view(), 2).is_err());
    }

    #[test]
    fn canonical_archive_lane_substitutions_fail_against_actual_native_result() {
        use crate::state::NativeExecutionProjectionV1;
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(crate::state::World::new(), 1_000))
                .unwrap();
        chain.commit(Vec::new());
        assert!(original_source(&chain.state().view(), 2).is_ok());
        let records = std::fs::read_dir(chain.kura().store_root().join("native-contexts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("00000000000000000002-")
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        let path = &records[0];
        let original = std::fs::read(path).unwrap();
        let projection: NativeExecutionProjectionV1 = norito::decode_canonical_with_limits(
            &original,
            norito::canonical_decode_limits(original.len()),
        )
        .unwrap();
        for change in 0..4 {
            let mut changed = projection.clone();
            match change {
                0 => changed.lanes.incarnations += 1,
                1 => changed.lanes.last_transition += 1,
                2 => changed.carrier_height = 3,
                _ => {
                    changed.carrier_hash = iroha_crypto::HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::new(b"foreign carrier"),
                    )
                }
            }
            std::fs::write(path, norito::encode_canonical(&changed).unwrap()).unwrap();
            assert!(
                original_source(&chain.state().view(), 2).is_err(),
                "changed canonical field {change}"
            );
        }
        // Keep the complete canonical outer frame/checksum but replace the lane field with
        // malformed payload bytes. Framing cannot authenticate a raw lane claim.
        let view = norito::core::from_bytes_view(&original).unwrap();
        for malformed in [&[][..], &[0xFF][..]] {
            let mut payload = view.as_bytes();
            let mut replaced = Vec::new();
            for field_index in 0..5 {
                let (length, prefix) =
                    norito::core::read_len_from_slice_with_flags(payload, view.flags()).unwrap();
                let value = &payload[prefix..prefix + length];
                payload = &payload[prefix + length..];
                let value = if field_index == 2 { malformed } else { value };
                norito::core::write_len_with_flags(&mut replaced, value.len() as u64, view.flags())
                    .unwrap();
                replaced.extend_from_slice(value);
            }
            assert!(payload.is_empty());
            let frame = norito::core::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(
                &replaced,
                view.flags(),
            )
            .unwrap();
            std::fs::write(path, frame).unwrap();
            assert!(original_source(&chain.state().view(), 2).is_err());
        }
        std::fs::write(path, original).unwrap();
        assert!(
            original_source(&chain.state().view(), 2).is_ok(),
            "only the original native-bound bytes restore the source"
        );
    }
}
