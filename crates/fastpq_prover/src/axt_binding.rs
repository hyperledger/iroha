use crate::{
    Error, OperationKind, ProofSemantics, PublicInputs, Result, StateTransition, TransitionBatch,
    gadgets::transfer::decode_transcripts, proof::enforce_default_verify_batch_limits,
    validate_batch_semantics,
};
use iroha_crypto::Hash;
pub use iroha_data_model::nexus::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES;
use iroha_data_model::transaction::signed::TransactionEntrypoint;
use iroha_data_model::{
    account::AccountId,
    asset::id::AssetDefinitionId,
    fastpq::{
        FastpqOperationKind, FastpqPublicInputs, FastpqRolePermissionDelta, FastpqStateTransition,
        FastpqTransitionBatch, TRANSFER_TRANSCRIPTS_METADATA_KEY,
    },
    nexus::{
        AxtEffectBinding, AxtFastpqBinding, AxtFinalizedSpendAnchorV1, AxtProofEnvelope,
        AxtRemoteSpendClaimV1, AxtSourceSuccessReceiptV1, AxtSourceTransferOccurrenceV1, ProofBlob,
        axt_ordered_transaction_set_digest_v1, compute_remote_spend_claim_commitment_v1,
    },
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use norito::{NoritoSerialize, decode_from_bytes, to_bytes};
use sha2::Digest;
#[path = "axt_binding/source_occurrence.rs"]
pub mod source_occurrence;
pub use source_occurrence::set_axt_source_transfer_occurrences;
/// Metadata key binding the structured AXT FASTPQ payload into the proof trace.
pub const AXT_FASTPQ_BINDING_METADATA_KEY: &str = "axt_fastpq_binding";
/// Metadata key binding an optional AXT amount into the `FastPQ` proof trace.
///
/// The value is the exact little-endian `u128` carried by
/// [`AxtProofEnvelope::committed_amount`]. It is inserted before the batch seal
/// is derived, so changing the outer envelope amount invalidates verification.
pub const AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY: &str = "axt_fastpq_committed_amount_v1";
/// Metadata key binding the required non-zero manifest root into the proof trace.
pub const AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY: &str = "axt_fastpq_manifest_root_v1";
/// Metadata key binding the exact optional DA commitment into the proof trace.
///
/// The always-present value is exactly 33 bytes: a zero tag followed by a
/// zeroed 32-byte tail for `None`, or a one tag followed by the commitment.
pub const AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY: &str = "axt_fastpq_da_commitment_v1";
/// Metadata key binding the optional proof expiry into the `FastPQ` proof trace.
///
/// The value is always present and is exactly one little-endian `u64`: zero
/// encodes no expiry, while every non-zero value encodes `Some(expiry_slot)`.
/// Requiring the key even for no-expiry proofs prevents pre-binding proof
/// payloads from being relabelled as unbounded after the fact.
pub const AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY: &str = "axt_fastpq_expiry_slot_v1";
/// Metadata key sealing a concrete FASTPQ batch to its AXT statement.
///
/// The seal is computed over the carried batch after AXT metadata has been
/// inserted and with this field removed. It prevents descriptor-only synthetic
/// batches from being accepted as AXT proof material.
pub const AXT_FASTPQ_BATCH_SEAL_METADATA_KEY: &str = "axt_fastpq_batch_seal_v1";
/// Metadata key carrying the canonical preimages of proof-bound remote-spend commitments.
///
/// The preimages let the verifier link every advertised handle commitment to
/// one concrete transfer transcript. A hash-only commitment cannot establish
/// this relation because its descriptor binding is not recoverable.
pub const AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY: &str = "axt_fastpq_remote_spend_claims_v1";
/// Canonical proof-trace metadata binding a successful source receipt claim to
/// each exact ordered remote-spend transfer occurrence.
pub const AXT_FASTPQ_SOURCE_TRANSFER_OCCURRENCES_METADATA_KEY: &str =
    "axt_fastpq_source_transfer_occurrences_v1";
/// Canonical FASTPQ parameter name used by maintained AXT flows.
pub const DEFAULT_PARAMETER: &str = fastpq_isi::FASTPQ_FINAL_V1_ID;
/// Maximum encoded AXT `FastPQ` batch/proof payload accepted before decoding.
const DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES: usize = 1024 * 1024;
const AXT_STATEMENT_DOMAIN: &[u8] = b"fastpq:axt:statement:v1";
const AXT_BATCH_SEAL_DOMAIN: &[u8] = b"fastpq:axt:batch-seal:v1";
const ENTRY_HASH_METADATA_KEY: &str = "entry_hash";
#[path = "axt_binding/compact.rs"]
mod compact;

/// Result returned after an AXT `FastPQ` envelope has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxtVerifiedProof {
    /// Digest of the statement bound to the AXT descriptor and `FastPQ` batch.
    pub statement_digest: [u8; 32],
    /// Digest of the envelope-carried `FastPQ` proof payload.
    pub proof_digest: Hash,
    /// Proven pre-execution state root.
    pub old_root: [u8; 32],
    /// Proven post-execution state root.
    pub new_root: [u8; 32],
    /// Proven transaction/statement-set commitment.
    pub tx_set_hash: [u8; 32],
    /// Optional expiry authenticated by the proof-bound batch metadata.
    pub expiry_slot: Option<u64>,
    /// Proof-bound claimed success-receipt digest, if exact occurrences were supplied.
    /// Finalized State must authenticate the receipt before admitting a spend.
    pub source_success_receipt_digest: Option<[u8; 32]>,
}
/// Canonicalize a structured AXT FASTPQ binding before proving or verification.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when required binding fields are empty,
/// malformed, or use an unsupported claim type.
pub fn canonicalize_binding(binding: &AxtFastpqBinding) -> Result<AxtFastpqBinding> {
    Ok(AxtFastpqBinding {
        parameter: normalized_parameter(&binding.parameter)?,
        source_dsid: binding.source_dsid,
        source_dataspace: required_string(&binding.source_dataspace, "source_dataspace")?,
        source_receipt_id: required_string(&binding.source_receipt_id, "source_receipt_id")?,
        source_tx_commitment: required_digest(
            &binding.source_tx_commitment,
            "source_tx_commitment",
        )?,
        claim_type: normalized_claim_type(&binding.claim_type)?,
        claim_digest: required_digest(&binding.claim_digest, "claim_digest")?,
        witness_commitment: required_digest(&binding.witness_commitment, "witness_commitment")?,
        policy_commitment: required_digest(&binding.policy_commitment, "policy_commitment")?,
        verified_effect_type: required_string(
            &binding.verified_effect_type,
            "verified_effect_type",
        )?,
        corridor: binding.corridor.trim().to_string(),
        verifier_id: normalized_verifier_id(&binding.verifier_id)?,
        verifier_version: normalized_verifier_version(&binding.verifier_version)?,
        target_dsids: required_target_dsids(&binding.target_dsids)?,
        effect_binding: binding
            .effect_binding
            .as_ref()
            .map(canonicalize_effect_binding)
            .transpose()?,
        remote_spend_intent_commitments: canonical_remote_spend_intent_commitments(
            &binding.remote_spend_intent_commitments,
        )?,
    })
}
/// Validate canonical masked artifact bytes for the `proof` field of an AXT envelope.
///
/// # Errors
/// Rejects an artifact that does not prove the exact bound batch and AXT context.
pub fn encode_axt_fastpq_payload(batch: &TransitionBatch, proof: Vec<u8>) -> Result<Vec<u8>> {
    let binding = embedded_axt_binding(batch)?;
    compact::verify_bound(batch, &proof, &binding)?;
    Ok(proof)
}

/// Attach canonical remote-spend claim preimages before sealing an AXT batch.
///
/// `claims` must be ordered so their V1 commitments exactly equal the
/// binding's strictly ordered commitment set. The subsequent AXT binder and
/// verifier additionally require an exact one-to-one match with the batch's
/// transfer transcripts.
///
/// # Errors
///
/// Returns [`Error::InvalidAxtBinding`] when the batch has already been sealed
/// or the supplied claims do not exactly reconstruct the binding commitment
/// set. Returns [`Error::Encode`] when canonical Norito encoding fails.
pub fn set_axt_remote_spend_claims(
    batch: &mut TransitionBatch,
    binding: &AxtFastpqBinding,
    claims: &[AxtRemoteSpendClaimV1],
) -> Result<()> {
    if batch
        .metadata
        .contains_key(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY)
    {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend claims must be attached before the AXT batch is sealed".into(),
        });
    }
    let canonical = require_canonical_binding(binding)?;
    let commitments: Vec<_> = claims
        .iter()
        .map(compute_remote_spend_claim_commitment_v1)
        .collect();
    if commitments != canonical.remote_spend_intent_commitments {
        return Err(Error::InvalidAxtBinding {
            details:
                "remote-spend claim preimages do not exactly reconstruct the binding commitment set"
                    .into(),
        });
    }
    if claims.is_empty() {
        batch
            .metadata
            .remove(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY);
    } else {
        batch.metadata.insert(
            AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.into(),
            encode_canonical_norito(&claims.to_vec())?,
        );
    }
    Ok(())
}

/// Produce the canonical masked artifact for an explicitly bound AXT batch.
///
/// The binding independently selects the transfer claim. Metadata-only carriers
/// are rejected before private construction. This entry point uses the default
/// CPU proving and verification limits and self-verifies before returning.
/// The original caller pool and prepaid reservation fund touched-tree backing
/// only. Foreign reservations fail before preparation; other public/frame/proof
/// allocations are separate. The checked demand is given by
/// [`crate::gadgets::public_transfer_statement::TransferSmtBuildLimits::allocation_bytes`].
/// Use [`crate::offline_compact::prove_quantity_axt_artifact`] with an independently
/// authenticated public statement/context for explicit work or device policies.
/// Successful consistency verification does not grant source finality or spend authority.
///
/// # Errors
/// Rejects batch/resource limits, noncanonical or mismatched bindings, unsupported
/// claims, invalid witnesses or failed proof verification. Concurrent production
/// returns [`Error::ProducerBusy`]; callers may retry the unchanged request after
/// the active producer releases its permit.
pub fn prove_axt_bound_batch(
    batch: &TransitionBatch,
    binding: &AxtFastpqBinding,
    budget: &iroha_allocation::AllocationBudget,
    reservation: &mut iroha_allocation::AllocationReservation,
) -> Result<Vec<u8>> {
    compact::prove(batch, binding, budget, reservation)
}

/// Require a canonical AXT binding to select the witnessed transfer profile.
///
/// Generic contract and block-admission consumers must call this before
/// treating successful AXT verification as an execution fact. Opaque
/// authorization/compliance-labelled carriers are intentionally rejected:
/// they are only data carriers for specialized paths that independently
/// authenticate the referenced effect.
///
/// # Errors
///
/// Returns [`Error::InvalidAxtBinding`] when `binding` is not canonical and
/// [`Error::InvalidProofSemantics`] when it selects an opaque profile.
pub fn validate_axt_transfer_claim_binding(binding: &AxtFastpqBinding) -> Result<()> {
    let canonical = require_canonical_binding(binding)?;
    match axt_proof_semantics(&canonical)? {
        ProofSemantics::AxtTransferClaim => Ok(()),
        semantics => Err(Error::InvalidProofSemantics {
            profile: semantics.name(),
            details: "generic AXT consumers require a witnessed transfer claim; opaque effect carriers require independent authenticated-effect validation"
                .into(),
        }),
    }
}

/// Verify a proof against a batch and its canonical outer AXT statement.
///
/// The explicit binding is the trusted semantics selector. It must exactly
/// match the proof-bound batch metadata; metadata by itself never enables AXT
/// semantics through an unbound or artifact-selected claim.
///
/// # Errors
///
/// Returns an error when the batch or proof exceeds the default verifier
/// resource limits, `binding` is not canonical, the batch does not exactly
/// match it, the selected AXT semantic profile rejects the batch, or
/// cryptographic proof verification fails.
pub fn verify_axt_bound_batch(
    batch: &TransitionBatch,
    proof: &[u8],
    binding: &AxtFastpqBinding,
) -> Result<()> {
    compact::verify_bound(batch, proof, binding)
}
/// Decode the canonical AXT binding already embedded in a `FastPQ` batch.
///
/// This helper never mutates the batch. It is intended for export paths that need to package proof
/// material after the batch has already been bound before proof generation.
///
/// # Errors
/// Returns [`Error::MissingMetadata`] when the batch carries no AXT binding and
/// [`Error::InvalidAxtBinding`] when the embedded binding does not match the
/// concrete batch metadata.
pub fn embedded_axt_binding(batch: &TransitionBatch) -> Result<AxtFastpqBinding> {
    let encoded = required_metadata(batch, AXT_FASTPQ_BINDING_METADATA_KEY)?;
    let binding = decode_canonical_binding(encoded)?;
    let _ = verify_batch_matches_canonical_binding(batch, &binding, None, None)?;
    Ok(binding)
}
/// Build an AXT proof envelope from an already AXT-bound batch and proof.
///
/// The batch must already contain canonical AXT metadata and the batch seal created before proof
/// generation. This helper does not add or repair AXT binding metadata after the fact.
///
/// # Errors
/// Returns an error when the embedded binding or proof metadata is
/// missing/malformed, the supplied manifest or DA commitment differs from the
/// proof-bound value, the binding does not match the batch, or the proof payload
/// cannot be encoded within the verifier's inner payload limit.
pub fn axt_proof_envelope_from_bound_batch(
    batch: &TransitionBatch,
    proof: Vec<u8>,
    manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
) -> Result<AxtProofEnvelope> {
    let binding = embedded_axt_binding(batch)?;
    let committed_amount = proof_bound_committed_amount(batch)?;
    let proof_bound_manifest_root = proof_bound_manifest_root(batch)?;
    require_proof_mirror(
        "envelope manifest_root",
        manifest_root,
        proof_bound_manifest_root,
    )?;
    let proof_bound_da_commitment = proof_bound_da_commitment(batch)?;
    require_proof_mirror(
        "envelope da_commitment",
        da_commitment,
        proof_bound_da_commitment,
    )?;
    let encoded_proof = encode_axt_fastpq_payload(batch, proof)?;
    enforce_axt_fastpq_payload_limit(&encoded_proof)?;
    Ok(AxtProofEnvelope {
        dsid: DataSpaceId::new(binding.source_dsid),
        manifest_root,
        da_commitment,
        proof: encoded_proof,
        fastpq_binding: Some(binding),
        committed_amount,
        amount_commitment: None,
    })
}
/// Build an AXT proof blob from an already AXT-bound batch and proof.
///
/// # Errors
/// Returns an error when envelope construction or Norito encoding fails, or
/// when the supplied expiry differs from the proof-bound value.
pub fn axt_proof_blob_from_bound_batch(
    batch: &TransitionBatch,
    proof: Vec<u8>,
    manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
    expiry_slot: Option<u64>,
) -> Result<ProofBlob> {
    let proof_bound_expiry = proof_bound_expiry_slot(batch)?;
    if expiry_slot != proof_bound_expiry {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof blob expiry_slot does not match proof-bound batch metadata".into(),
        });
    }
    let envelope = axt_proof_envelope_from_bound_batch(batch, proof, manifest_root, da_commitment)?;
    let payload = encode_canonical_norito(&envelope)?;
    enforce_axt_proof_blob_payload_limit(&payload)?;
    Ok(ProofBlob {
        payload,
        expiry_slot,
    })
}
/// Bind an already-captured FASTPQ batch to an AXT statement without an amount or expiry.
///
/// This convenience wrapper delegates to [`bind_axt_batch_with_proof_metadata`]
/// with neither a committed amount nor an expiry. Manifest, DA, and the
/// authenticated no-expiry sentinel are still mandatory proof metadata. This
/// is an intentional first-release hard cut: proofs made before these metadata
/// fields were required must be regenerated.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when the binding is malformed or does not match the batch
/// parameter/public dataspace, and [`Error::Encode`] when Norito serialization fails.
pub fn bind_axt_batch(
    batch: &mut TransitionBatch,
    binding: &AxtFastpqBinding,
    manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
) -> Result<()> {
    bind_axt_batch_with_proof_metadata(batch, binding, manifest_root, da_commitment, None, None)
}
/// Bind an already-captured FASTPQ batch and optional amount to an AXT statement.
///
/// This helper inserts the canonical AXT binding, required manifest root,
/// canonical optional DA commitment, optional fixed-width committed amount,
/// authenticated no-expiry sentinel, and the batch seal required by
/// [`verify_axt_proof_envelope`]. Call it only after the batch transitions and
/// public inputs have been finalized and the batch already carries the
/// execution `entry_hash` metadata matching `source_tx_commitment`; changing
/// the batch after this call invalidates the proof-bound seal.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when the binding is malformed, the
/// manifest root or committed amount is zero, or the binding does not match
/// the batch parameter/public dataspace, and [`Error::Encode`] when Norito
/// serialization fails.
pub fn bind_axt_batch_with_committed_amount(
    batch: &mut TransitionBatch,
    binding: &AxtFastpqBinding,
    manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
    committed_amount: Option<u128>,
) -> Result<()> {
    bind_axt_batch_with_proof_metadata(
        batch,
        binding,
        manifest_root,
        da_commitment,
        committed_amount,
        None,
    )
}
/// Bind an already-captured FASTPQ batch and its proof-level metadata to an AXT statement.
///
/// This helper inserts the canonical AXT binding, required manifest root,
/// canonical optional DA commitment, optional fixed-width committed amount,
/// required expiry encoding, and batch seal before proof generation. `None`
/// expiry is encoded as an authenticated zero sentinel; `Some(0)` is never
/// accepted.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when the binding is malformed, an
/// amount or explicit expiry is zero, or the binding does not match the batch
/// parameter/public dataspace. Returns [`Error::Encode`] when Norito
/// serialization fails.
pub fn bind_axt_batch_with_proof_metadata(
    batch: &mut TransitionBatch,
    binding: &AxtFastpqBinding,
    manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
    committed_amount: Option<u128>,
    expiry_slot: Option<u64>,
) -> Result<()> {
    if manifest_root.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidAxtBinding {
            details: "AXT manifest_root must be non-zero".into(),
        });
    }
    if committed_amount == Some(0) {
        return Err(Error::InvalidAxtBinding {
            details: "AXT committed_amount must be non-zero".into(),
        });
    }
    if expiry_slot == Some(0) {
        return Err(Error::InvalidAxtBinding {
            details: "AXT expiry_slot must be non-zero when present".into(),
        });
    }
    let canonical = canonicalize_binding(binding)?;
    let context = BindingContext::from_binding(&canonical)?;
    require_execution_header(&batch.parameter, batch.public_inputs.dsid, &canonical)?;
    require_concrete_execution_batch(batch, &context)?;
    validate_batch_semantics(batch, axt_proof_semantics(&canonical)?)?;
    require_transfer_claim_witnesses(batch, &context, canonical.claim_type.as_str())?;
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    batch
        .metadata
        .remove(AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY);
    batch.metadata.remove(AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY);
    batch.metadata.remove(AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY);
    batch.metadata.remove(AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY);
    insert_binding_metadata(batch, &context)?;
    if let Some(amount) = committed_amount {
        batch.metadata.insert(
            AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY.into(),
            amount.to_le_bytes().to_vec(),
        );
    }
    batch.metadata.insert(
        AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY.into(),
        expiry_slot.unwrap_or(0).to_le_bytes().to_vec(),
    );
    batch.metadata.insert(
        AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.into(),
        manifest_root.to_vec(),
    );
    batch.metadata.insert(
        AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.into(),
        encode_optional_da_commitment(da_commitment),
    );
    require_remote_spend_transcript_linkage(batch, &canonical)?;
    let seal = axt_batch_seal(batch, &canonical)?;
    batch
        .metadata
        .insert(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY.into(), seal.to_vec());
    Ok(())
}
/// Verify an AXT envelope carrying the canonical masked transfer artifact.
///
/// This verifies the envelope-level manifest, DA, and amount mirrors and
/// returns the authenticated expiry. A caller starting from [`ProofBlob`] must
/// use [`verify_axt_proof_blob`] or
/// [`verify_axt_proof_envelope_with_outer_metadata`] so the outer expiry mirror
/// is exact-compared as well.
///
/// The complete public statement and canonical AXT context are bound to every
/// child proof. Finality and permission checks remain the caller's responsibility;
/// use the anchored entry point when verifying finalized-source spend evidence.
/// Metadata-only opaque effect carriers have no transfer relation and are rejected.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when the envelope is missing the structured
/// binding/payload or when the carried batch does not bind to the AXT statement. Returns
/// any `FastPQ` proof verification error for invalid proof material.
pub fn verify_axt_proof_envelope(envelope: &AxtProofEnvelope) -> Result<AxtVerifiedProof> {
    verify_axt_proof_envelope_inner(envelope, None, None)
}

/// Verify a transfer proof against an independently authenticated finalized anchor.
///
/// The caller must resolve the exact anchor from immutable finalized consensus
/// state and authenticate its network, lane/incarnation, block, QC, committee,
/// issuer signatures and spend nonce. It must also establish successful finalized
/// execution and the exact transfer facts for the selected source transaction.
/// Merely supplying an anchor does not authenticate it, and this function does not authorize a spend by itself.
///
/// Exact ordered canonical transaction wires must reproduce the anchor's set
/// digest and contain the binding's execution-call identity exactly once. The
/// proof's pre/post roots and transaction-set digest are then compared byte for
/// byte with that anchor before cryptographic verification. No local transfer
/// subtree root or sorted execution-identity digest is substituted. Only the
/// witnessed transfer profile is admitted; opaque effect carriers cannot be used.
///
/// # Errors
/// Rejects an invalid anchor, absent/non-positive expiry, excessive transaction
/// witness, wrong transaction order/wires or execution membership, any mismatch
/// in the public roots, dataspace, DA commitment or expiry, and invalid proofs.
///
/// TODO: export this entry point again once an admission path resolves the
/// authoritative finalized anchor; until then it is compiled only for tests.
#[cfg(test)]
fn verify_axt_proof_envelope_against_anchor_v1(
    envelope: &AxtProofEnvelope,
    expiry_slot: Option<u64>,
    authoritative_anchor: &AxtFinalizedSpendAnchorV1,
    ordered_transactions: &[TransactionEntrypoint],
) -> Result<AxtVerifiedProof> {
    verify_axt_proof_envelope_against_anchor_inner_v1(
        envelope,
        expiry_slot,
        authoritative_anchor,
        ordered_transactions,
        None,
    )
}

/// Verify one exact proof-bound transfer and its caller-supplied source receipt claim.
///
/// This verifies both the finalized-anchor claim and the full transfer
/// occurrence, so matching only the common receipt digest cannot
/// substitute a different transfer from the same source execution. The receipt
/// and anchor remain caller-supplied claims: a State/Kura/QC/DA owner must
/// independently authenticate source success, its post-transaction root, the
/// effect set, and the finalized anchor before this result can be used for
/// admission. This function does not verify issuer authority or authorize a
/// remote spend by itself.
///
/// # Errors
/// Rejects malformed or inconsistent source claims, an occurrence absent from
/// the proof-bound FASTPQ transcript, and every anchored proof error.
pub fn verify_axt_proof_envelope_against_anchor_and_claimed_source_v1(
    envelope: &AxtProofEnvelope,
    expiry_slot: Option<u64>,
    authoritative_anchor: &AxtFinalizedSpendAnchorV1,
    ordered_transactions: &[TransactionEntrypoint],
    claimed_receipt: &AxtSourceSuccessReceiptV1,
    claimed_occurrence: &AxtSourceTransferOccurrenceV1,
) -> Result<AxtVerifiedProof> {
    claimed_occurrence
        .validate()
        .map_err(|error| Error::InvalidAxtBinding {
            details: format!("invalid claimed AXT source transfer occurrence: {error}"),
        })?;
    let receipt_digest = claimed_receipt.digest_v1();
    if claimed_receipt.finalized_anchor_digest != authoritative_anchor.digest_v1()
        || claimed_receipt.source_tx_commitment != claimed_occurrence.source_tx_commitment
        || claimed_receipt.source_tx_index != claimed_occurrence.source_tx_index
        || claimed_receipt.post_transaction_state_root == [0; 32]
        || claimed_receipt.effect_set_digest == [0; 32]
        || claimed_occurrence.source_success_receipt_digest != receipt_digest
    {
        return Err(Error::InvalidAxtBinding {
            details: "claimed AXT source success receipt does not match the anchor and transfer occurrence".into(),
        });
    }
    let verified = verify_axt_proof_envelope_against_anchor_inner_v1(
        envelope,
        expiry_slot,
        authoritative_anchor,
        ordered_transactions,
        Some(claimed_occurrence),
    )?;
    if verified.source_success_receipt_digest != Some(receipt_digest) {
        return Err(Error::InvalidAxtBinding {
            details: "claimed AXT source success receipt differs from proof-bound metadata".into(),
        });
    }
    Ok(verified)
}

fn verify_axt_proof_envelope_against_anchor_inner_v1(
    envelope: &AxtProofEnvelope,
    expiry_slot: Option<u64>,
    authoritative_anchor: &AxtFinalizedSpendAnchorV1,
    ordered_transactions: &[TransactionEntrypoint],
    claimed_occurrence: Option<&AxtSourceTransferOccurrenceV1>,
) -> Result<AxtVerifiedProof> {
    enforce_axt_fastpq_payload_limit(&envelope.proof)?;
    if ordered_transactions.len() > iroha_data_model::nexus::MAX_AXT_FINALIZED_TRANSACTIONS_V1 {
        return Err(Error::VerifierLimitExceeded {
            limit: "max_axt_finalized_transactions",
            actual: ordered_transactions.len(),
            max: iroha_data_model::nexus::MAX_AXT_FINALIZED_TRANSACTIONS_V1,
        });
    }
    authoritative_anchor
        .validate()
        .map_err(|error| Error::InvalidAxtBinding {
            details: format!("invalid authoritative AXT finalized anchor: {error}"),
        })?;
    if expiry_slot.is_none_or(|expiry| expiry == 0) {
        return Err(Error::InvalidAxtBinding {
            details: "anchored AXT proof requires a non-zero expiry_slot".into(),
        });
    }
    if envelope.dsid != authoritative_anchor.dataspace_id {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof dataspace does not match authoritative finalized anchor".into(),
        });
    }
    if envelope.da_commitment != Some(authoritative_anchor.da_manifest_digest.into()) {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof DA manifest does not match authoritative finalized anchor".into(),
        });
    }
    let binding = envelope
        .fastpq_binding
        .as_ref()
        .ok_or_else(|| Error::InvalidAxtBinding {
            details: "AXT proof envelope is missing fastpq_binding".into(),
        })?;
    validate_axt_transfer_claim_binding(binding)?;
    let canonical = require_canonical_binding(binding)?;
    let transaction_set_digest = axt_ordered_transaction_set_digest_v1(ordered_transactions)
        .map_err(|error| Error::InvalidAxtBinding {
            details: format!("invalid AXT finalized transaction witness: {error}"),
        })?;
    if transaction_set_digest != authoritative_anchor.transaction_set_digest {
        return Err(Error::InvalidAxtBinding {
            details: "AXT ordered transaction wires do not match authoritative finalized anchor"
                .into(),
        });
    }
    let source_execution =
        decode_hex_digest(&canonical.source_tx_commitment, "source_tx_commitment")?;
    let mut source_positions = ordered_transactions
        .iter()
        .enumerate()
        .filter(|(_, transaction)| transaction.execution_call_hash().as_ref() == &source_execution);
    let source_position = source_positions.next().map(|(index, _)| index);
    if source_position.is_none() || source_positions.next().is_some() {
        return Err(Error::InvalidAxtBinding {
            details:
                "AXT source execution must occur exactly once in the finalized transaction set"
                    .into(),
        });
    }
    let source_position = u32::try_from(source_position.expect("one source execution exists"))
        .expect("bounded finalized transaction set fits u32");
    verify_axt_proof_envelope_inner(
        envelope,
        Some((authoritative_anchor, expiry_slot, source_position)),
        claimed_occurrence,
    )
}

fn verify_axt_proof_envelope_inner(
    envelope: &AxtProofEnvelope,
    finalized: Option<(&AxtFinalizedSpendAnchorV1, Option<u64>, u32)>,
    claimed_occurrence: Option<&AxtSourceTransferOccurrenceV1>,
) -> Result<AxtVerifiedProof> {
    compact::verify_envelope(envelope, finalized, claimed_occurrence)
}
fn require_finalized_public_inputs_v1(
    inputs: &PublicInputs,
    anchor: &AxtFinalizedSpendAnchorV1,
) -> Result<()> {
    if inputs.dsid != dsid_bytes(anchor.dataspace_id.as_u64()) {
        return Err(Error::InvalidAxtBinding {
            details: "FastPQ public dsid does not match authoritative finalized anchor".into(),
        });
    }
    for (field, actual, expected) in [
        ("old_root", &inputs.old_root, anchor.pre_state_root.as_ref()),
        (
            "new_root",
            &inputs.new_root,
            anchor.post_state_root.as_ref(),
        ),
        (
            "tx_set_hash",
            &inputs.tx_set_hash,
            anchor.transaction_set_digest.as_ref(),
        ),
    ] {
        if actual != expected {
            return Err(Error::InvalidAxtBinding {
                details: format!(
                    "FastPQ public {field} does not match authoritative finalized anchor"
                ),
            });
        }
    }
    Ok(())
}

fn enforce_axt_fastpq_payload_limit(payload: &[u8]) -> Result<()> {
    if payload.len() > DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES {
        return Err(Error::VerifierLimitExceeded {
            limit: "max_axt_fastpq_payload_bytes",
            actual: payload.len(),
            max: DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES,
        });
    }
    Ok(())
}
/// Verify an AXT proof blob and require its advertised expiry to match the proof trace.
///
/// # Errors
/// Returns an error when the blob is empty or oversized, carries the forbidden
/// explicit zero expiry, is not a canonical [`AxtProofEnvelope`], fails
/// `FastPQ` verification, or advertises an expiry different from the
/// proof-bound batch metadata.
pub fn verify_axt_proof_blob(proof: &ProofBlob) -> Result<AxtVerifiedProof> {
    if proof.payload.is_empty() {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof blob payload must not be empty".into(),
        });
    }
    enforce_axt_proof_blob_payload_limit(&proof.payload)?;
    if proof.expiry_slot == Some(0) {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof blob expiry_slot must be non-zero when present".into(),
        });
    }
    let envelope: AxtProofEnvelope = decode_from_bytes(&proof.payload)
        .map_err(|source| Error::AxtProofPayloadDecode { source })?;
    if encode_canonical_norito(&envelope)?.as_slice() != proof.payload {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof envelope must use canonical Norito bytes".into(),
        });
    }
    verify_axt_proof_envelope_with_outer_metadata(&envelope, proof.expiry_slot)
}
fn enforce_axt_proof_blob_payload_limit(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES {
        return Err(Error::VerifierLimitExceeded {
            limit: "max_axt_proof_blob_payload_bytes",
            actual: payload.len(),
            max: MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES,
        });
    }
    Ok(())
}
/// Verify an already-decoded AXT proof envelope and its outer expiry mirror.
///
/// This is the one-decode variant for block and host validation paths that
/// must inspect routing fields before invoking the expensive verifier.
///
/// # Errors
/// Returns any error from [`verify_axt_proof_envelope`] or an
/// [`Error::InvalidAxtBinding`] when `expiry_slot` differs from the value
/// authenticated by the proof batch.
pub fn verify_axt_proof_envelope_with_outer_metadata(
    envelope: &AxtProofEnvelope,
    expiry_slot: Option<u64>,
) -> Result<AxtVerifiedProof> {
    let verified = verify_axt_proof_envelope(envelope)?;
    require_proof_mirror("blob expiry_slot", expiry_slot, verified.expiry_slot)?;
    Ok(verified)
}
/// Convert a prover batch into the shared `FastPQ` data-model representation.
#[must_use]
pub fn transition_batch_to_model(batch: &TransitionBatch) -> FastpqTransitionBatch {
    FastpqTransitionBatch {
        parameter: batch.parameter.clone(),
        public_inputs: FastpqPublicInputs {
            dsid: batch.public_inputs.dsid,
            slot: batch.public_inputs.slot,
            old_root: batch.public_inputs.old_root,
            new_root: batch.public_inputs.new_root,
            perm_root: batch.public_inputs.perm_root,
            tx_set_hash: batch.public_inputs.tx_set_hash,
        },
        transitions: batch
            .transitions
            .iter()
            .map(|transition| FastpqStateTransition {
                key: transition.key.clone(),
                pre_value: transition.pre_value.clone(),
                post_value: transition.post_value.clone(),
                operation: operation_to_model(&transition.operation),
            })
            .collect(),
        metadata: batch.metadata.clone(),
    }
}
/// Convert a shared `FastPQ` data-model batch into the prover representation.
#[must_use]
pub fn transition_batch_from_model(dto: &FastpqTransitionBatch) -> TransitionBatch {
    let mut batch = TransitionBatch::new(
        dto.parameter.clone(),
        PublicInputs {
            dsid: dto.public_inputs.dsid,
            slot: dto.public_inputs.slot,
            old_root: dto.public_inputs.old_root,
            new_root: dto.public_inputs.new_root,
            perm_root: dto.public_inputs.perm_root,
            tx_set_hash: dto.public_inputs.tx_set_hash,
        },
    );
    for transition in &dto.transitions {
        batch.push(StateTransition::new(
            transition.key.clone(),
            transition.pre_value.clone(),
            transition.post_value.clone(),
            operation_from_model(&transition.operation),
        ));
    }
    batch.metadata = dto.metadata.clone();
    batch
}
#[cfg(test)]
fn transition_batch_from_model_owned(dto: FastpqTransitionBatch) -> TransitionBatch {
    let FastpqTransitionBatch {
        parameter,
        public_inputs,
        transitions,
        metadata,
    } = dto;
    let mut batch = TransitionBatch::new(
        parameter,
        PublicInputs {
            dsid: public_inputs.dsid,
            slot: public_inputs.slot,
            old_root: public_inputs.old_root,
            new_root: public_inputs.new_root,
            perm_root: public_inputs.perm_root,
            tx_set_hash: public_inputs.tx_set_hash,
        },
    );
    for transition in transitions {
        batch.push(StateTransition::new(
            transition.key,
            transition.pre_value,
            transition.post_value,
            operation_from_model_owned(transition.operation),
        ));
    }
    batch.metadata = metadata;
    batch
}
fn operation_to_model(operation: &OperationKind) -> FastpqOperationKind {
    match operation {
        OperationKind::Transfer => FastpqOperationKind::Transfer,
        OperationKind::Mint => FastpqOperationKind::Mint,
        OperationKind::Burn => FastpqOperationKind::Burn,
        OperationKind::RoleGrant {
            role_id,
            permission_id,
            epoch,
        } => FastpqOperationKind::RoleGrant(FastpqRolePermissionDelta {
            role_id: *role_id,
            permission_id: *permission_id,
            epoch: *epoch,
        }),
        OperationKind::RoleRevoke {
            role_id,
            permission_id,
            epoch,
        } => FastpqOperationKind::RoleRevoke(FastpqRolePermissionDelta {
            role_id: *role_id,
            permission_id: *permission_id,
            epoch: *epoch,
        }),
        OperationKind::MetaSet => FastpqOperationKind::MetaSet,
    }
}
fn operation_from_model(operation: &FastpqOperationKind) -> OperationKind {
    match operation {
        FastpqOperationKind::Transfer => OperationKind::Transfer,
        FastpqOperationKind::Mint => OperationKind::Mint,
        FastpqOperationKind::Burn => OperationKind::Burn,
        FastpqOperationKind::RoleGrant(delta) => OperationKind::RoleGrant {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::RoleRevoke(delta) => OperationKind::RoleRevoke {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::MetaSet => OperationKind::MetaSet,
    }
}
#[cfg(test)]
fn operation_from_model_owned(operation: FastpqOperationKind) -> OperationKind {
    match operation {
        FastpqOperationKind::Transfer => OperationKind::Transfer,
        FastpqOperationKind::Mint => OperationKind::Mint,
        FastpqOperationKind::Burn => OperationKind::Burn,
        FastpqOperationKind::RoleGrant(delta) => OperationKind::RoleGrant {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::RoleRevoke(delta) => OperationKind::RoleRevoke {
            role_id: delta.role_id,
            permission_id: delta.permission_id,
            epoch: delta.epoch,
        },
        FastpqOperationKind::MetaSet => OperationKind::MetaSet,
    }
}
struct BindingContext<'a> {
    binding: &'a AxtFastpqBinding,
    source_tx_commitment: [u8; 32],
    claim_digest: [u8; 32],
    witness_commitment: [u8; 32],
    policy_commitment: [u8; 32],
    effect_type: String,
}
impl<'a> BindingContext<'a> {
    fn from_binding(binding: &'a AxtFastpqBinding) -> Result<Self> {
        Ok(Self {
            binding,
            source_tx_commitment: decode_hex_digest(
                &binding.source_tx_commitment,
                "source_tx_commitment",
            )?,
            claim_digest: decode_hex_digest(&binding.claim_digest, "claim_digest")?,
            witness_commitment: decode_hex_digest(
                &binding.witness_commitment,
                "witness_commitment",
            )?,
            policy_commitment: decode_hex_digest(&binding.policy_commitment, "policy_commitment")?,
            effect_type: required_string(&binding.verified_effect_type, "verified_effect_type")?,
        })
    }
}
fn verify_batch_matches_canonical_binding(
    batch: &TransitionBatch,
    canonical_binding: &AxtFastpqBinding,
    source_tx_index: Option<u32>,
    claimed_occurrence: Option<&AxtSourceTransferOccurrenceV1>,
) -> Result<Option<[u8; 32]>> {
    let context = BindingContext::from_binding(canonical_binding)?;
    require_execution_header(
        &batch.parameter,
        batch.public_inputs.dsid,
        canonical_binding,
    )?;
    require_concrete_execution_batch(batch, &context)?;
    validate_batch_semantics(batch, axt_proof_semantics(canonical_binding)?)?;
    let encoded = required_metadata(batch, AXT_FASTPQ_BINDING_METADATA_KEY)?;
    let decoded = decode_canonical_binding(encoded)?;
    if &decoded != canonical_binding {
        return Err(Error::InvalidAxtBinding {
            details: "FastPQ batch metadata binding does not match AXT binding".into(),
        });
    }
    require_metadata_eq(batch, "source_tx_commitment", &context.source_tx_commitment)?;
    require_metadata_eq(batch, "claim_digest", &context.claim_digest)?;
    require_metadata_eq(batch, "witness_commitment", &context.witness_commitment)?;
    require_metadata_eq(batch, "policy_commitment", &context.policy_commitment)?;
    require_metadata_eq(
        batch,
        "source_receipt_id",
        canonical_binding.source_receipt_id.as_bytes(),
    )?;
    require_metadata_eq(
        batch,
        "target_dsids",
        &encode_target_dsids(&canonical_binding.target_dsids),
    )?;
    require_metadata_eq(
        batch,
        "verified_effect_type",
        context.effect_type.as_bytes(),
    )?;
    if !canonical_binding.corridor.is_empty() {
        require_metadata_eq(batch, "corridor", canonical_binding.corridor.as_bytes())?;
    }
    let _ = proof_bound_committed_amount(batch)?;
    let _ = proof_bound_expiry_slot(batch)?;
    let _ = proof_bound_manifest_root(batch)?;
    let _ = proof_bound_da_commitment(batch)?;
    let seal = axt_batch_seal(batch, canonical_binding)?;
    require_metadata_eq(batch, AXT_FASTPQ_BATCH_SEAL_METADATA_KEY, &seal)?;
    require_transfer_claim_witnesses(batch, &context, canonical_binding.claim_type.as_str())?;
    require_remote_spend_transcript_linkage(batch, canonical_binding)?;
    source_occurrence::validate_bound_occurrences(
        batch,
        canonical_binding,
        source_tx_index,
        claimed_occurrence,
    )
}

fn axt_proof_semantics(binding: &AxtFastpqBinding) -> Result<ProofSemantics> {
    match binding.claim_type.as_str() {
        "tx_predicate" | "value_conservation" => Ok(ProofSemantics::AxtTransferClaim),
        "authorization" | "compliance" => Ok(ProofSemantics::AxtOpaqueEffect),
        claim_type => Err(Error::InvalidAxtBinding {
            details: format!("unsupported claim_type: {claim_type}"),
        }),
    }
}
fn required_metadata<'a>(batch: &'a TransitionBatch, key: &str) -> Result<&'a [u8]> {
    batch
        .metadata
        .get(key)
        .map(Vec::as_slice)
        .ok_or_else(|| Error::MissingMetadata {
            key: key.to_string(),
        })
}
fn require_metadata_eq(batch: &TransitionBatch, key: &str, expected: &[u8]) -> Result<()> {
    let actual = required_metadata(batch, key)?;
    require_public_value_eq(key, actual, expected)
}
fn require_public_value_eq(key: &str, actual: &[u8], expected: &[u8]) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::InvalidAxtBinding {
            details: format!("FastPQ batch metadata `{key}` does not match AXT binding"),
        })
    }
}
fn proof_bound_committed_amount(batch: &TransitionBatch) -> Result<Option<u128>> {
    parse_committed_amount(
        batch
            .metadata
            .get(AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY)
            .map(Vec::as_slice),
    )
}
fn parse_committed_amount(encoded: Option<&[u8]>) -> Result<Option<u128>> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let bytes: [u8; core::mem::size_of::<u128>()] =
        encoded.try_into().map_err(|_| Error::MetadataLength {
            key: AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY.to_owned(),
            expected: core::mem::size_of::<u128>(),
            actual: encoded.len(),
        })?;
    let amount = u128::from_le_bytes(bytes);
    if amount == 0 {
        return Err(Error::InvalidAxtBinding {
            details: "proof-bound AXT committed_amount must be non-zero".into(),
        });
    }
    Ok(Some(amount))
}
fn proof_bound_expiry_slot(batch: &TransitionBatch) -> Result<Option<u64>> {
    let encoded = required_metadata(batch, AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY)?;
    parse_expiry_slot(encoded)
}
fn parse_expiry_slot(encoded: &[u8]) -> Result<Option<u64>> {
    let bytes: [u8; core::mem::size_of::<u64>()] =
        encoded.try_into().map_err(|_| Error::MetadataLength {
            key: AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY.to_owned(),
            expected: core::mem::size_of::<u64>(),
            actual: encoded.len(),
        })?;
    let expiry_slot = u64::from_le_bytes(bytes);
    Ok((expiry_slot != 0).then_some(expiry_slot))
}
fn proof_bound_manifest_root(batch: &TransitionBatch) -> Result<[u8; 32]> {
    let encoded = required_metadata(batch, AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY)?;
    parse_manifest_root(encoded)
}
fn parse_manifest_root(encoded: &[u8]) -> Result<[u8; 32]> {
    let root: [u8; 32] = encoded.try_into().map_err(|_| Error::MetadataLength {
        key: AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.to_owned(),
        expected: 32,
        actual: encoded.len(),
    })?;
    if root.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidAxtBinding {
            details: "proof-bound AXT manifest_root must be non-zero".into(),
        });
    }
    Ok(root)
}
fn proof_bound_da_commitment(batch: &TransitionBatch) -> Result<Option<[u8; 32]>> {
    let encoded = required_metadata(batch, AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY)?;
    parse_da_commitment(encoded)
}
fn parse_da_commitment(encoded: &[u8]) -> Result<Option<[u8; 32]>> {
    if encoded.len() != 33 {
        return Err(Error::MetadataLength {
            key: AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.to_owned(),
            expected: 33,
            actual: encoded.len(),
        });
    }
    let commitment: [u8; 32] = encoded[1..]
        .try_into()
        .expect("fixed metadata length checked above");
    match encoded[0] {
        0 if commitment == [0; 32] => Ok(None),
        0 => Err(Error::InvalidAxtBinding {
            details: "proof-bound AXT absent da_commitment must have a zeroed payload".into(),
        }),
        1 => Ok(Some(commitment)),
        _ => Err(Error::InvalidAxtBinding {
            details: "proof-bound AXT da_commitment has an unsupported option tag".into(),
        }),
    }
}
fn encode_optional_da_commitment(commitment: Option<[u8; 32]>) -> Vec<u8> {
    commitment.map_or_else(
        || vec![0; 33],
        |commitment| {
            let mut encoded = Vec::with_capacity(33);
            encoded.push(1);
            encoded.extend_from_slice(&commitment);
            encoded
        },
    )
}
fn require_concrete_execution_batch(
    batch: &TransitionBatch,
    context: &BindingContext<'_>,
) -> Result<()> {
    require_execution_rows(batch.transitions.len())?;
    require_metadata_eq(
        batch,
        ENTRY_HASH_METADATA_KEY,
        &context.source_tx_commitment,
    )
}
fn require_execution_header(
    parameter: &str,
    dsid: [u8; 16],
    binding: &AxtFastpqBinding,
) -> Result<()> {
    if parameter != binding.parameter {
        return Err(Error::InvalidAxtBinding {
            details: "FastPQ batch parameter does not match AXT binding".into(),
        });
    }
    if dsid != dsid_bytes(binding.source_dsid) {
        return Err(Error::InvalidAxtBinding {
            details: "FastPQ batch public dsid does not match AXT binding".into(),
        });
    }
    Ok(())
}
fn require_execution_rows(count: usize) -> Result<()> {
    if count == 0 {
        return Err(Error::InvalidAxtBinding {
            details: "AXT FastPQ batch must contain execution-captured state transitions".into(),
        });
    }
    Ok(())
}
fn require_transfer_claim_witnesses(
    batch: &TransitionBatch,
    context: &BindingContext<'_>,
    claim_type: &str,
) -> Result<()> {
    if matches!(claim_type, "tx_predicate" | "value_conservation") {
        let transcripts =
            decode_transcripts(&batch.metadata)?.ok_or_else(|| Error::MissingMetadata {
                key: TRANSFER_TRANSCRIPTS_METADATA_KEY.to_owned(),
            })?;
        require_transfer_batch_hashes(
            &context.source_tx_commitment,
            transcripts.iter().map(|transcript| transcript.batch_hash),
        )?;
    }
    Ok(())
}
fn require_transfer_batch_hashes(
    source_tx_commitment: &[u8; 32],
    hashes: impl IntoIterator<Item = Hash>,
) -> Result<()> {
    let mut hashes = hashes.into_iter().peekable();
    if hashes.peek().is_none() {
        return Err(Error::InvalidAxtBinding {
            details: "transfer AXT claim must carry at least one transfer transcript".into(),
        });
    }
    if hashes.any(|hash| hash.as_ref() != source_tx_commitment.as_slice()) {
        return Err(Error::InvalidAxtBinding {
            details: "transfer transcript batch_hash does not match source_tx_commitment".into(),
        });
    }
    Ok(())
}
fn decode_bound_remote_spend_claims(
    encoded_claims: &[u8],
    binding: &AxtFastpqBinding,
) -> Result<Vec<AxtRemoteSpendClaimV1>> {
    let claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(encoded_claims)
        .map_err(|source| Error::TransferMetadataDecode { source })?;
    if encode_canonical_norito(&claims)?.as_slice() != encoded_claims {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend claim metadata must use canonical Norito bytes".into(),
        });
    }
    validate_remote_spend_claim_preimages(&claims, binding)?;
    Ok(claims)
}
fn validate_remote_spend_claim_preimages(
    claims: &[AxtRemoteSpendClaimV1],
    binding: &AxtFastpqBinding,
) -> Result<()> {
    for claim in claims {
        claim
            .handle_replay_key
            .validate()
            .map_err(|error| Error::InvalidAxtBinding {
                details: format!(
                    "remote-spend claim contains an invalid handle replay key: {error}"
                ),
            })?;
    }
    let commitments: Vec<_> = claims
        .iter()
        .map(compute_remote_spend_claim_commitment_v1)
        .collect();
    if commitments != binding.remote_spend_intent_commitments {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend claim metadata does not exactly reconstruct the binding commitment set"
                .into(),
        });
    }
    Ok(())
}

fn canonical_remote_spend_source_asset(binding: &AxtFastpqBinding) -> Result<AssetDefinitionId> {
    let source_asset_literal = binding
        .effect_binding
        .as_ref()
        .and_then(|effect| effect.source_asset_definition_id.as_deref())
        .ok_or_else(|| Error::InvalidAxtBinding {
            details: "remote-spend commitments require one exact source_asset_definition_id".into(),
        })?;
    let source_asset: AssetDefinitionId =
        source_asset_literal
            .parse()
            .map_err(|error| Error::InvalidAxtBinding {
                details: format!(
                    "remote-spend source_asset_definition_id is not canonical: {error}"
                ),
            })?;
    if source_asset.to_string() != source_asset_literal {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend source_asset_definition_id must use its canonical literal"
                .into(),
        });
    }
    Ok(source_asset)
}

fn require_remote_spend_transcript_linkage(
    batch: &TransitionBatch,
    binding: &AxtFastpqBinding,
) -> Result<()> {
    let encoded_claims = batch
        .metadata
        .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY);
    if !require_remote_spend_claim_presence(binding, encoded_claims.is_some())? {
        return Ok(());
    }
    let encoded_claims = encoded_claims.ok_or_else(|| Error::MissingMetadata {
        key: AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.to_owned(),
    })?;
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let claims = decode_bound_remote_spend_claims(encoded_claims, binding)?;
    let source_asset = canonical_remote_spend_source_asset(binding)?;

    let transcripts =
        decode_transcripts(&batch.metadata)?.ok_or_else(|| Error::MissingMetadata {
            key: TRANSFER_TRANSCRIPTS_METADATA_KEY.to_owned(),
        })?;
    require_remote_spend_transfer_facts(
        binding,
        &source_asset,
        &claims,
        transcripts.iter().flat_map(|transcript| {
            transcript.deltas.iter().map(|delta| AxtTransferFact {
                asset: &delta.asset_definition,
                from: &delta.from_account,
                to: &delta.to_account,
                amount: &delta.amount,
            })
        }),
    )
}
fn require_remote_spend_claim_presence(binding: &AxtFastpqBinding, supplied: bool) -> Result<bool> {
    if binding.remote_spend_intent_commitments.is_empty() {
        if supplied {
            return Err(Error::InvalidAxtBinding {
                details: "remote-spend claim metadata is forbidden when the binding commitment set is empty"
                    .into(),
            });
        }
        return Ok(false);
    }
    if !matches!(
        binding.claim_type.as_str(),
        "tx_predicate" | "value_conservation"
    ) {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend commitments require a transfer claim; opaque AXT proofs cannot authorize handles"
                .into(),
        });
    }
    Ok(true)
}
/// Borrowed public transfer identity; no private SMT data can be represented.
pub struct AxtTransferFact<'a> {
    /// Complete canonical asset identity.
    pub(crate) asset: &'a AssetDefinitionId,
    /// Complete canonical sender identity.
    pub(crate) from: &'a AccountId,
    /// Complete canonical receiver identity.
    pub(crate) to: &'a AccountId,
    /// Exact public amount, without lossy scale conversion.
    pub(crate) amount: &'a Quantity,
}
fn require_remote_spend_transfer_facts<'a>(
    binding: &AxtFastpqBinding,
    source_asset: &'a AssetDefinitionId,
    claims: &[AxtRemoteSpendClaimV1],
    facts: impl IntoIterator<Item = AxtTransferFact<'a>>,
) -> Result<()> {
    let mut transcript_facts = Vec::new();
    for fact in facts {
        if fact.asset != source_asset {
            return Err(Error::InvalidAxtBinding {
                details: "remote-spend proof contains a transfer for an asset other than source_asset_definition_id"
                    .into(),
            });
        }
        transcript_facts.push((
            fact.asset.clone(),
            fact.from.clone(),
            fact.to.clone(),
            fact.amount.clone(),
        ));
    }

    let mut claim_facts = Vec::with_capacity(claims.len());
    for claim in claims {
        if claim.handle_replay_key.asset_dsid.as_u64() != binding.source_dsid {
            return Err(Error::InvalidAxtBinding {
                details:
                    "remote-spend claim handle asset_dsid does not match the proof source_dsid"
                        .into(),
            });
        }
        if claim.kind != "transfer" {
            return Err(Error::InvalidAxtBinding {
                details: "remote-spend FASTPQ V1 claims must use the exact `transfer` operation"
                    .into(),
            });
        }
        if &claim.asset_definition_id != source_asset {
            return Err(Error::InvalidAxtBinding {
                details: "remote-spend claim asset_definition_id does not match source_asset_definition_id"
                    .into(),
            });
        }
        let from = canonical_remote_account(&claim.from, "from")?;
        let to = canonical_remote_account(&claim.to, "to")?;
        claim_facts.push((
            claim.asset_definition_id.clone(),
            from,
            to,
            claim.effective_amount.clone(),
        ));
    }
    transcript_facts.sort_unstable();
    claim_facts.sort_unstable();
    if claim_facts != transcript_facts {
        return Err(Error::InvalidAxtBinding {
            details: "remote-spend claims must match transfer transcripts one-for-one (asset, accounts, amount, and cardinality)"
                .into(),
        });
    }
    Ok(())
}
fn canonical_remote_account(value: &str, field: &str) -> Result<AccountId> {
    if value.trim() != value {
        return Err(Error::InvalidAxtBinding {
            details: format!("remote-spend {field} account must use canonical I105 text"),
        });
    }
    // The canonical parser validates the configured chain discriminant and literal
    // under the caller's inherited inbound budget before returning the account.
    AccountId::parse_encoded(value).map_err(|error| Error::InvalidAxtBinding {
        details: format!("remote-spend {field} account is not canonical I105: {error}"),
    })
}

/// Exact public metadata byte fields accepted by the offline compact relation.
///
/// The type cannot carry the legacy batch seal or private transcript metadata.
#[derive(Clone, Copy)]
pub struct AxtPublicMetadataBytes<'a> {
    /// Concrete execution parameter, exact-compared to the canonical binding.
    pub(crate) parameter: &'a str,
    /// Original execution entrypoint commitment.
    pub(crate) entry_hash: &'a [u8],
    /// Optional exact sixteen-byte nonzero scalar.
    pub(crate) committed_amount: Option<&'a [u8]>,
    /// Required eight-byte expiry, with zero representing absence.
    pub(crate) expiry_slot: &'a [u8],
    /// Required nonzero 32-byte manifest root.
    pub(crate) manifest_root: &'a [u8],
    /// Required 33-byte canonical option encoding.
    pub(crate) da_commitment: &'a [u8],
    /// Complete ordered source occurrence claims committed before proof challenges.
    pub(crate) source_transfer_occurrences: &'a [AxtSourceTransferOccurrenceV1],
}

/// Pre-proof outer metadata mirrors; completed-proof commitments are excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(
    name = "fastpq_prover::axt_binding::AxtProofContextMirrors",
    frame = "fastpq_prover::compact_v1::AxtProofContextMirrorsV1"
)]
pub struct AxtProofContextMirrors {
    /// Exact outer envelope dataspace.
    pub(crate) dsid: DataSpaceId,
    /// Exact outer envelope manifest.
    pub(crate) manifest_root: [u8; 32],
    /// Exact outer envelope DA option.
    pub(crate) da_commitment: Option<[u8; 32]>,
    /// Exact outer envelope scalar; business-amount resolution remains external.
    pub(crate) committed_amount: Option<u128>,
    /// Exact outer proof-blob expiry.
    pub(crate) expiry_slot: Option<u64>,
}

/// Check path-free prepared facts using the same AXT predicates as legacy replay.
///
/// The caller must first apply its public resource bounds. This validates the
/// public relation, not source finality, permissions, or handle signatures.
pub fn validate_axt_public_transfer_facts<V>(
    binding: &AxtFastpqBinding,
    metadata: AxtPublicMetadataBytes<'_>,
    prepared: &crate::gadgets::public_transfer_statement::PreparedPublicTransfers<'_, V>,
    claims: Option<&[AxtRemoteSpendClaimV1]>,
) -> Result<()> {
    validate_axt_transfer_claim_binding(binding)?;
    if prepared.semantics() != ProofSemantics::AxtTransferClaim {
        return Err(Error::InvalidProofSemantics {
            profile: prepared.semantics().name(),
            details: "compact AXT context requires the AXT transfer profile".into(),
        });
    }
    let context = BindingContext::from_binding(binding)?;
    require_execution_header(metadata.parameter, prepared.public_inputs().dsid, binding)?;
    require_execution_rows(prepared.transitions().len())?;
    require_public_value_eq(
        ENTRY_HASH_METADATA_KEY,
        metadata.entry_hash,
        &context.source_tx_commitment,
    )?;
    require_transfer_batch_hashes(
        &context.source_tx_commitment,
        prepared.claims().iter().map(|claim| claim.batch_hash),
    )?;
    if !require_remote_spend_claim_presence(binding, claims.is_some())? {
        return source_occurrence::validate_public_occurrences(
            binding,
            prepared.claims(),
            &[],
            metadata.source_transfer_occurrences,
            None,
            None,
        )
        .map(|_| ());
    }
    let claims = claims.ok_or_else(|| Error::MissingMetadata {
        key: AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.to_owned(),
    })?;
    validate_remote_spend_claim_preimages(claims, binding)?;
    let source_asset = canonical_remote_spend_source_asset(binding)?;
    require_remote_spend_transfer_facts(
        binding,
        &source_asset,
        claims,
        prepared.claims().iter().flat_map(|transcript| {
            transcript.deltas.iter().map(|delta| AxtTransferFact {
                asset: &delta.asset_definition,
                from: &delta.from_account,
                to: &delta.to_account,
                amount: &delta.amount,
            })
        }),
    )?;
    source_occurrence::validate_public_occurrences(
        binding,
        prepared.claims(),
        claims,
        metadata.source_transfer_occurrences,
        None,
        None,
    )
    .map(|_| ())
}

/// Parse the exact legacy public encodings and compare their outer mirrors.
pub fn validate_axt_public_metadata(
    binding: &AxtFastpqBinding,
    metadata: AxtPublicMetadataBytes<'_>,
    outer: AxtProofContextMirrors,
) -> Result<()> {
    if binding.source_dsid != outer.dsid.as_u64() {
        return Err(Error::InvalidAxtBinding {
            details: "AXT proof envelope source_dsid does not match dsid".into(),
        });
    }
    let amount = parse_committed_amount(metadata.committed_amount)?;
    let expiry = parse_expiry_slot(metadata.expiry_slot)?;
    let manifest = parse_manifest_root(metadata.manifest_root)?;
    require_proof_mirror("envelope manifest_root", outer.manifest_root, manifest)?;
    let da = parse_da_commitment(metadata.da_commitment)?;
    require_proof_mirror("envelope da_commitment", outer.da_commitment, da)?;
    require_proof_mirror("envelope committed_amount", outer.committed_amount, amount)?;
    require_proof_mirror("blob expiry_slot", outer.expiry_slot, expiry)
}

fn require_proof_mirror<T: PartialEq + Copy>(field: &str, actual: T, expected: T) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidAxtBinding {
            details: format!("AXT proof {field} does not match proof-bound batch metadata"),
        });
    }
    Ok(())
}
fn axt_statement_digest<T: NoritoSerialize>(
    envelope: &AxtProofEnvelope,
    binding: &AxtFastpqBinding,
    batch: &T,
) -> Result<[u8; 32]> {
    let mut payload = Vec::new();
    payload.extend_from_slice(AXT_STATEMENT_DOMAIN);
    payload.extend_from_slice(&envelope.dsid.as_u64().to_le_bytes());
    payload.extend_from_slice(&envelope.manifest_root);
    if let Some(da_commitment) = envelope.da_commitment {
        payload.extend_from_slice(&da_commitment);
    }
    payload.extend_from_slice(&encode_canonical_norito(binding)?);
    payload.extend_from_slice(&encode_canonical_norito(batch)?);
    Ok(Hash::new(payload).into())
}
fn axt_batch_seal(
    batch: &TransitionBatch,
    canonical_binding: &AxtFastpqBinding,
) -> Result<[u8; 32]> {
    let mut sealed_batch = batch.clone();
    sealed_batch
        .metadata
        .remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut payload = Vec::new();
    payload.extend_from_slice(AXT_BATCH_SEAL_DOMAIN);
    payload.extend_from_slice(&encode_canonical_norito(canonical_binding)?);
    payload.extend_from_slice(&encode_canonical_norito(&sealed_batch)?);
    Ok(Hash::new(payload).into())
}
fn insert_binding_metadata(
    batch: &mut TransitionBatch,
    context: &BindingContext<'_>,
) -> Result<()> {
    batch.metadata.insert(
        AXT_FASTPQ_BINDING_METADATA_KEY.into(),
        encode_canonical_norito(context.binding)?,
    );
    batch.metadata.insert(
        "source_tx_commitment".into(),
        context.source_tx_commitment.to_vec(),
    );
    batch
        .metadata
        .insert("claim_digest".into(), context.claim_digest.to_vec());
    batch.metadata.insert(
        "witness_commitment".into(),
        context.witness_commitment.to_vec(),
    );
    batch.metadata.insert(
        "policy_commitment".into(),
        context.policy_commitment.to_vec(),
    );
    batch.metadata.insert(
        "source_receipt_id".into(),
        context.binding.source_receipt_id.as_bytes().to_vec(),
    );
    batch.metadata.insert(
        "target_dsids".into(),
        encode_target_dsids(&context.binding.target_dsids),
    );
    batch.metadata.insert(
        "verified_effect_type".into(),
        context.effect_type.as_bytes().to_vec(),
    );
    if !context.binding.corridor.is_empty() {
        batch.metadata.insert(
            "corridor".into(),
            context.binding.corridor.as_bytes().to_vec(),
        );
    }
    Ok(())
}
fn required_string(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(Error::InvalidAxtBinding {
            details: format!("{field} must not be empty"),
        })
    } else {
        Ok(trimmed.to_string())
    }
}
fn required_digest(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    decode_hex_digest(&trimmed, field)?;
    Ok(trimmed)
}
fn normalized_parameter(value: &str) -> Result<String> {
    required_string(value, "parameter")
}
fn normalized_verifier_id(value: &str) -> Result<String> {
    let verifier_id = required_string(value, "verifier_id")?.to_ascii_lowercase();
    if verifier_id == "fastpq" {
        Ok(verifier_id)
    } else {
        Err(Error::InvalidAxtBinding {
            details: format!("unsupported AXT verifier_id: {value}"),
        })
    }
}
fn normalized_verifier_version(value: &str) -> Result<String> {
    let verifier_version = required_string(value, "verifier_version")?.to_ascii_lowercase();
    if verifier_version == "v1" {
        Ok(verifier_version)
    } else {
        Err(Error::InvalidAxtBinding {
            details: format!("unsupported AXT verifier_version: {value}"),
        })
    }
}
fn required_target_dsids(values: &[u64]) -> Result<Vec<u64>> {
    if values.is_empty() {
        return Err(Error::InvalidAxtBinding {
            details: "target_dsids must not be empty".into(),
        });
    }
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(Error::InvalidAxtBinding {
                details: format!("target_dsids contains duplicate value: {}", pair[0]),
            });
        }
        if pair[0] > pair[1] {
            return Err(Error::InvalidAxtBinding {
                details: format!(
                    "target_dsids must be strictly ordered: {} precedes {}",
                    pair[0], pair[1]
                ),
            });
        }
    }
    Ok(values.to_vec())
}
fn canonical_remote_spend_intent_commitments(values: &[[u8; 32]]) -> Result<Vec<[u8; 32]>> {
    if values.len() > iroha_data_model::nexus::MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 {
        return Err(Error::InvalidAxtBinding {
            details: format!(
                "remote_spend_intent_commitments exceeds the V1 limit of {}",
                iroha_data_model::nexus::MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1
            ),
        });
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(Error::InvalidAxtBinding {
                details: "remote_spend_intent_commitments must be strictly ordered and unique"
                    .into(),
            });
        }
    }
    Ok(values.to_vec())
}
fn normalized_claim_type(value: &str) -> Result<String> {
    let claim_type = value.trim().to_ascii_lowercase();
    match claim_type.as_str() {
        "authorization" | "compliance" | "tx_predicate" | "value_conservation" => Ok(claim_type),
        _ => Err(Error::InvalidAxtBinding {
            details: format!("unsupported claim_type: {value}"),
        }),
    }
}
fn canonicalize_effect_binding(binding: &AxtEffectBinding) -> Result<AxtEffectBinding> {
    Ok(AxtEffectBinding {
        destination_domain: canonical_optional_string(
            binding.destination_domain.as_deref(),
            "effect_binding.destination_domain",
        )?,
        destination_account_id: canonical_optional_string(
            binding.destination_account_id.as_deref(),
            "effect_binding.destination_account_id",
        )?,
        vault_account_id: canonical_optional_string(
            binding.vault_account_id.as_deref(),
            "effect_binding.vault_account_id",
        )?,
        issuance_account_id: canonical_optional_string(
            binding.issuance_account_id.as_deref(),
            "effect_binding.issuance_account_id",
        )?,
        source_asset_definition_id: canonical_optional_string(
            binding.source_asset_definition_id.as_deref(),
            "effect_binding.source_asset_definition_id",
        )?,
        destination_asset_definition_id: canonical_optional_string(
            binding.destination_asset_definition_id.as_deref(),
            "effect_binding.destination_asset_definition_id",
        )?,
        source_amount_i64: binding.source_amount_i64,
        destination_amount_i64: binding.destination_amount_i64,
    })
}
fn canonical_optional_string(value: Option<&str>, field: &str) -> Result<Option<String>> {
    value.map(|value| required_string(value, field)).transpose()
}
fn require_canonical_binding(binding: &AxtFastpqBinding) -> Result<AxtFastpqBinding> {
    let canonical = canonicalize_binding(binding)?;
    if &canonical != binding {
        return Err(Error::InvalidAxtBinding {
            details: "AXT FASTPQ binding must use its exact canonical field representation".into(),
        });
    }
    Ok(canonical)
}
fn encode_canonical_norito<T: NoritoSerialize>(value: &T) -> Result<Vec<u8>> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    to_bytes(value).map_err(Error::Encode)
}
fn decode_canonical_binding(encoded: &[u8]) -> Result<AxtFastpqBinding> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let binding: AxtFastpqBinding =
        decode_from_bytes(encoded).map_err(|source| Error::TransferMetadataDecode { source })?;
    if encode_canonical_norito(&binding)?.as_slice() != encoded {
        return Err(Error::InvalidAxtBinding {
            details: "FastPQ batch metadata binding must use canonical Norito bytes".into(),
        });
    }
    require_canonical_binding(&binding)
}
#[cfg(test)]
fn decode_axt_fastpq_payload(
    encoded: &[u8],
) -> Result<iroha_data_model::fastpq::FastpqAxtCompactArtifactV1> {
    compact::decode(encoded)
}
fn dsid_bytes(source_dsid: u64) -> [u8; 16] {
    let mut output = [0_u8; 16];
    output[..8].copy_from_slice(&DataSpaceId::new(source_dsid).as_u64().to_le_bytes());
    output
}
fn encode_target_dsids(values: &[u64]) -> Vec<u8> {
    let mut output = Vec::with_capacity(values.len() * 8);
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output
}
fn decode_hex_digest(value: &str, field: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).map_err(|err| Error::InvalidAxtBinding {
        details: format!("{field} is not valid hex: {err}"),
    })?;
    decoded.try_into().map_err(|_| Error::InvalidAxtBinding {
        details: format!("{field} must be exactly 32 bytes"),
    })
}
/// Deterministic manifest digest for a binding payload.
///
/// # Errors
/// Returns [`Error::InvalidAxtBinding`] when the binding is not canonical and
/// [`Error::Encode`] when Norito serialization of the canonical binding fails.
pub fn batch_manifest_sha256(binding: &AxtFastpqBinding) -> Result<String> {
    let canonical = canonicalize_binding(binding)?;
    let bytes = encode_canonical_norito(&canonical)?;
    Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
}
#[cfg(test)]
#[path = "axt_binding/tests.rs"]
mod tests;
