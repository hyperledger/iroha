//! Canonical Phase-III terminal C1/C2 verification for ZK-AMS.
//!
//! Only the PBS prover consumes the six-family output of encrypted Phase II/III materialization.
//! Settlement supplies the exact governed strict public inputs and verifies the complete public
//! Nova history from a fresh relaxed mask through every strict witness and Equation-(7) cross-term
//! commitment. The replayed final instance must equal the compact public batch anchor exactly
//! before the native setup-free Relaxed Spartan proof is accepted. Plaintext `E,rE,W,rW` families
//! never cross the verifier API or proof wire.
//!
//! Soundness and mask freshness are distinct obligations. Absorbing the mask, each strict instance,
//! and each cross-term commitment before the nonzero Nova challenge makes an invalid mask/strict
//! relation a degree-two random- oracle forgery. Privacy additionally requires the mask to be
//! fresh; that is enforced at encrypted ingress by the authenticated full-roster mask-share
//! ceremony bound to the roster/epoch/transcript context, not by trusting a prover-supplied digest
//! at this terminal boundary.
#[cfg(test)]
use super::keccak256;
#[cfg(test)]
use super::{
    Scalar, ZkAmsMkheErrorV1,
    manifest::release_profile_v1,
    phase23_encrypted::{
        ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1,
        ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1, ZkAmsPhase23MapKindV1,
        ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsPhase23SparseMapManifestV1,
        ZkAmsPhase23SparseMapV1, validate_materialized_accumulators_v1, validate_sparse_map_v1,
        zk_ams_phase23_release_relation_v1,
    },
};
#[cfg(test)]
use crate::vega::{
    VegaPointWireV1, VegaScalarWireV1,
    commitment::{Commitment, CommitmentKey},
    masked_relaxed::{
        MASKED_RELAXED_COMMITMENT_COLUMNS_V1, MAX_MASKED_RELAXED_STRICT_INSTANCES_V1,
        MaskedRelaxedProofWireV1, prove_precomputed_masked_relaxed_v1,
        verify_and_replay_masked_relaxed_v1,
    },
    nifs::NovaNifs,
    r1cs::{Instance, RelaxedInstance, RelaxedWitness, Shape, SparseMatrix},
};
#[cfg(test)]
use std::sync::Arc;
const PHASE3_TERMINAL_VERSION_V1: u8 = 1;
#[cfg(test)]
const PHASE3_CONTEXT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.terminal-context";
#[cfg(test)]
const PHASE3_MAP_SET_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.paper-order-map-set";
#[cfg(test)]
const PHASE3_KEY_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.commitment-key";
#[cfg(test)]
const PHASE3_BATCH_ANCHOR_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.batch-anchor";
#[cfg(test)]
const PHASE3_ORDERED_PUBLIC_INPUTS_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.phase3.ordered-public-inputs";
#[cfg(test)]
const PHASE3_GOVERNED_BATCH_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.governed-batch";
#[cfg(test)]
const PHASE3_FOLD_HISTORY_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.fold-history";
#[cfg(test)]
const PHASE3_NIFS_VERIFIER_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.nifs-verifier";
#[cfg(test)]
const PHASE3_PROOF_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.terminal-proof";
#[cfg(test)]
const PHASE3_TERMINAL_INSTANCE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.terminal-instance";
#[cfg(test)]
const PHASE3_RECEIPT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.terminal-receipt";
#[cfg(test)]
const PHASE3_COMPOSITION_CONTEXT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.composition-context";
#[cfg(test)]
const PHASE3_COMPOSITION_GENERIC_CONTEXT_TAG_V1: &[u8] = b"generic-proof-context";
#[cfg(test)]
const PHASE3_COMPOSITION_TERMINAL_CONTEXT_TAG_V1: &[u8] = b"terminal-context-digest";
#[cfg(test)]
const PHASE3_COMPOSITION_GOVERNED_BATCH_TAG_V1: &[u8] = b"governed-batch-digest";
const PHASE3_IMPLEMENTATION_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase3.terminal-implementation";
const PHASE3_C1_SCHEMA_V1: &[u8] = b"C1:Com(E,rE)+Com(W,rW)+(A*Z)*(B*Z)=u*(C*Z)+E:Z=(W,x,u)";
const PHASE3_C2_SCHEMA_V1: &[u8] =
    b"C2:tagged-length-framed(generic-proof-context,terminal-context-digest,governed-batch-digest)+full-public-mask+ordered-strict-inputs+ordered-W-commitments+ordered-T-commitments+Nova-replay+exact-IaccN-anchor+C1-Relaxed-Spartan";
/// Hard cap checked before decoding one canonical terminal proof.
pub const ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1: usize =
    super::super::MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1;
/// Exact consensus context of one terminal Phase-III proof.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase3TerminalContextV1 {
    /// Context schema version.
    pub version: u8,
    /// Exact RNS-BGV profile digest of the materialized ciphertexts.
    pub profile_digest: [u8; 32],
    /// Exact fixed-roster digest.
    pub roster_digest: [u8; 32],
    /// Governed nonzero roster epoch.
    pub epoch: u64,
    /// Transcript/key-ceremony digest.
    pub transcript_digest: [u8; 32],
    /// Nonzero batch identifier.
    pub batch_id: [u8; 32],
    /// Digest of the canonical ordered settlement inputs.
    pub ordered_batch_input_digest: [u8; 32],
    /// Digest of the exact maps, shared commitment key, and dimensions.
    pub nifs_verifier_digest: [u8; 32],
    /// Digest binding every preceding context field.
    pub digest: [u8; 32],
}
#[cfg(test)]
impl ZkAmsPhase3TerminalContextV1 {
    /// Construct one complete terminal context.
    pub fn new(
        profile_digest: [u8; 32],
        roster_digest: [u8; 32],
        epoch: u64,
        transcript_digest: [u8; 32],
        batch_id: [u8; 32],
        ordered_batch_input_digest: [u8; 32],
        nifs_verifier_digest: [u8; 32],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        let mut context = Self {
            version: PHASE3_TERMINAL_VERSION_V1,
            profile_digest,
            roster_digest,
            epoch,
            transcript_digest,
            batch_id,
            ordered_batch_input_digest,
            nifs_verifier_digest,
            digest: [0; 32],
        };
        validate_terminal_context_fields(context)?;
        context.digest = terminal_context_digest(context);
        validate_terminal_context(context)?;
        Ok(context)
    }
}
/// Digest the exact canonical ordered public settlement inputs. This is the
/// sole meaning of `ordered_batch_input_digest` in the first-release context.
#[cfg(test)]
pub fn zk_ams_phase3_ordered_public_inputs_digest_v1(
    strict_public_inputs: &[Vec<[u8; 32]>],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    preflight_governed_rows(strict_public_inputs)?;
    let scalar_count = strict_public_inputs
        .iter()
        .try_fold(0_usize, |total, inputs| {
            total
                .checked_add(inputs.len())
                .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
        })?;
    let row_framing_bytes = strict_public_inputs
        .len()
        .checked_mul(8)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let frame_len = PHASE3_ORDERED_PUBLIC_INPUTS_DOMAIN_V1
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(row_framing_bytes))
        .and_then(|length| {
            scalar_count
                .checked_mul(32)
                .and_then(|bytes| length.checked_add(bytes))
        })
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_len)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(PHASE3_ORDERED_PUBLIC_INPUTS_DOMAIN_V1);
    frame.extend_from_slice(&usize_to_u32(strict_public_inputs.len())?.to_be_bytes());
    for (index, inputs) in strict_public_inputs.iter().enumerate() {
        frame.extend_from_slice(&usize_to_u32(index)?.to_be_bytes());
        frame.extend_from_slice(&usize_to_u32(inputs.len())?.to_be_bytes());
        for input in inputs {
            Scalar::from_be_bytes_exact(*input)
                .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
            frame.extend_from_slice(input);
        }
    }
    Ok(keccak256(&frame))
}
/// Compact public representation of the final replayed accumulator instance
/// `I_acc,N`. The context digest binds the commitments and public `u,x` to the
/// exact roster epoch, transcript, batch, ordered inputs, maps, and verifier.
#[cfg(test)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[norito(decode_from_slice)]
pub struct ZkAmsPhase3BatchAnchorV1 {
    /// Anchor schema version.
    pub version: u8,
    /// Digest of the complete terminal context.
    pub context_digest: [u8; 32],
    /// Hyrax commitment to the private final `W_f` witness.
    pub witness_commitment: Vec<VegaPointWireV1>,
    /// Hyrax commitment to the private final `E_f` error vector.
    pub error_commitment: Vec<VegaPointWireV1>,
    /// Public relaxed-R1CS scalar `u_f`.
    pub relaxation: VegaScalarWireV1,
    /// Public relaxed-R1CS inputs `x_f` in canonical order.
    pub public_inputs: Vec<VegaScalarWireV1>,
    /// Digest binding the ordered fields above.
    pub digest: [u8; 32],
}
#[cfg(test)]
impl ZkAmsPhase3BatchAnchorV1 {
    /// Construct a context-bound public relaxed instance from exact canonical
    /// commitment points and T256 scalars.
    pub fn new(
        context: ZkAmsPhase3TerminalContextV1,
        witness_commitment: Vec<VegaPointWireV1>,
        error_commitment: Vec<VegaPointWireV1>,
        relaxation: [u8; 32],
        public_inputs: Vec<[u8; 32]>,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        validate_terminal_context(context)?;
        preflight_batch_anchor_lengths(
            witness_commitment.len(),
            error_commitment.len(),
            public_inputs.len(),
        )?;
        commitment_from_wire(&witness_commitment)?;
        commitment_from_wire(&error_commitment)?;
        let relaxation = Scalar::from_be_bytes_exact(relaxation)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        let public_inputs = public_inputs
            .into_iter()
            .map(|input| {
                Scalar::from_be_bytes_exact(input)
                    .map(VegaScalarWireV1::from_scalar)
                    .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut anchor = Self {
            version: PHASE3_TERMINAL_VERSION_V1,
            context_digest: context.digest,
            witness_commitment,
            error_commitment,
            relaxation: VegaScalarWireV1::from_scalar(relaxation),
            public_inputs,
            digest: [0; 32],
        };
        anchor.digest = batch_anchor_digest(&anchor)?;
        Ok(anchor)
    }
}
/// Exact governed strict public inputs supplied independently by settlement.
#[cfg(test)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[norito(decode_from_slice)]
pub struct ZkAmsPhase3GovernedBatchV1 {
    /// Batch schema version.
    pub version: u8,
    /// Digest of the complete terminal context.
    pub context_digest: [u8; 32],
    /// Ordered strict public inputs, one vector per governed admission.
    pub strict_public_inputs: Vec<Vec<VegaScalarWireV1>>,
    /// Digest binding the ordered fields above.
    pub digest: [u8; 32],
}
#[cfg(test)]
impl ZkAmsPhase3GovernedBatchV1 {
    /// Construct the exact governed batch and require its public-input digest
    /// to equal the independently supplied terminal context.
    pub fn new(
        context: ZkAmsPhase3TerminalContextV1,
        strict_public_inputs: Vec<Vec<[u8; 32]>>,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        validate_terminal_context(context)?;
        if zk_ams_phase3_ordered_public_inputs_digest_v1(&strict_public_inputs)?
            != context.ordered_batch_input_digest
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let strict_public_inputs = strict_public_inputs
            .into_iter()
            .map(|inputs| {
                inputs
                    .into_iter()
                    .map(|input| {
                        Scalar::from_be_bytes_exact(input)
                            .map(VegaScalarWireV1::from_scalar)
                            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut batch = Self {
            version: PHASE3_TERMINAL_VERSION_V1,
            context_digest: context.digest,
            strict_public_inputs,
            digest: [0; 32],
        };
        batch.digest = governed_batch_digest(&batch)?;
        Ok(batch)
    }
}
/// Public precomputed Nova history generated before PBS materialization. The
/// proof transports these commitments; this type is the prover-side input.
#[cfg(test)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[cfg_attr(feature = "schema-structural", derive(::iroha_schema::IntoSchema))]
#[norito(decode_from_slice)]
pub struct ZkAmsPhase3FoldHistoryV1 {
    /// History schema version.
    pub version: u8,
    /// Digest of the complete terminal context.
    pub context_digest: [u8; 32],
    /// Fresh public relaxed mask instance.
    pub mask: ZkAmsPhase3BatchAnchorV1,
    /// Ordered strict witness commitments.
    pub strict_witness_commitments: Vec<Vec<VegaPointWireV1>>,
    /// Ordered decrypted Equation-(7) cross-term commitments.
    pub cross_term_commitments: Vec<Vec<VegaPointWireV1>>,
    /// Digest binding the ordered fields above.
    pub digest: [u8; 32],
}
#[cfg(test)]
impl ZkAmsPhase3FoldHistoryV1 {
    /// Construct an exact bounded public fold history.
    pub fn new(
        context: ZkAmsPhase3TerminalContextV1,
        mask: ZkAmsPhase3BatchAnchorV1,
        strict_witness_commitments: Vec<Vec<VegaPointWireV1>>,
        cross_term_commitments: Vec<Vec<VegaPointWireV1>>,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        validate_terminal_context(context)?;
        preflight_fold_history_lengths(
            &mask,
            &strict_witness_commitments,
            &cross_term_commitments,
        )?;
        if mask.context_digest != context.digest || mask.digest == [0; 32] {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        if mask.digest != batch_anchor_digest(&mask)? {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        for commitment in strict_witness_commitments
            .iter()
            .chain(&cross_term_commitments)
        {
            commitment_from_wire(commitment)?;
        }
        let mut history = Self {
            version: PHASE3_TERMINAL_VERSION_V1,
            context_digest: context.digest,
            mask,
            strict_witness_commitments,
            cross_term_commitments,
            digest: [0; 32],
        };
        history.digest = fold_history_digest(&history)?;
        Ok(history)
    }
}
/// Public output of the PBS terminal prover. The materialized witness remains
/// prover-local; settlement receives only this anchor and canonical proof.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase3TerminalProverOutputV1 {
    /// Compact final replayed public instance.
    pub batch_anchor: ZkAmsPhase3BatchAnchorV1,
    /// Exact canonical terminal proof bytes.
    pub proof_bytes: Vec<u8>,
}
/// Opaque in-process result of one public terminal verification.
///
/// Private fields and the absence of `Clone`, `Copy`, and serialization are
/// deliberate. This value records what the current verifier invocation
/// checked; it is never cross-job, cross-process, or persistent authority.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub struct ZkAmsPhase3TerminalReceiptV1 {
    /// Receipt schema version.
    version: u8,
    /// Digest of the complete consensus context.
    context_digest: [u8; 32],
    /// Digest of the exact framed generic and terminal composition context.
    composition_context_digest: [u8; 32],
    /// Digest of the verified compact final batch anchor.
    batch_anchor_digest: [u8; 32],
    /// Digest of the original paper-order `A`, `B`, and `C` maps.
    map_set_digest: [u8; 32],
    /// Digest of the exact governed strict public inputs.
    governed_batch_digest: [u8; 32],
    /// Digest of the complete public mask/fold history.
    fold_history_digest: [u8; 32],
    /// Digest of the verifier-reconstructed terminal relaxed instance.
    terminal_instance_digest: [u8; 32],
    /// Digest of the exact canonical proof bytes.
    proof_digest: [u8; 32],
    /// Receipt digest binding the ordered fields above.
    digest: [u8; 32],
}
#[cfg(test)]
impl ZkAmsPhase3TerminalReceiptV1 {
    /// Receipt schema version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }
    /// Digest of the complete consensus context.
    #[must_use]
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }
    /// Digest of the exact framed generic and terminal composition context.
    #[must_use]
    pub const fn composition_context_digest(&self) -> [u8; 32] {
        self.composition_context_digest
    }
    /// Digest of the verified compact final batch anchor.
    #[must_use]
    pub const fn batch_anchor_digest(&self) -> [u8; 32] {
        self.batch_anchor_digest
    }
    /// Digest of the original paper-order `A`, `B`, and `C` maps.
    #[must_use]
    pub const fn map_set_digest(&self) -> [u8; 32] {
        self.map_set_digest
    }
    /// Digest of the exact governed strict public inputs.
    #[must_use]
    pub const fn governed_batch_digest(&self) -> [u8; 32] {
        self.governed_batch_digest
    }
    /// Digest of the complete public mask/fold history.
    #[must_use]
    pub const fn fold_history_digest(&self) -> [u8; 32] {
        self.fold_history_digest
    }
    /// Digest of the verifier-reconstructed terminal relaxed instance.
    #[must_use]
    pub const fn terminal_instance_digest(&self) -> [u8; 32] {
        self.terminal_instance_digest
    }
    /// Digest of the exact canonical proof bytes.
    #[must_use]
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }
    /// Digest binding every ordered receipt field.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
/// Digestible implementation state while release-size evidence remains open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase3TerminalImplementationV1 {
    /// Implementation schema version.
    pub version: u8,
    /// Maximum canonical terminal proof size.
    pub max_proof_bytes: u32,
    /// Digest of the exact native C1 checker.
    pub c1_schema_digest: [u8; 32],
    /// Digest of the exact transcript-bound C2 construction.
    pub c2_schema_digest: [u8; 32],
    /// Pinned release-parameter positive/adversarial KAT digest, absent now.
    pub release_kat_digest: [u8; 32],
    /// True only after the complete release-size KAT has executed.
    pub release_kat_complete: bool,
    /// Digest binding this fail-closed state.
    pub digest: [u8; 32],
}
/// Return the exact terminal implementation state without closing its release KAT gate.
#[must_use]
pub fn zk_ams_phase3_terminal_implementation_v1() -> ZkAmsPhase3TerminalImplementationV1 {
    let mut implementation = ZkAmsPhase3TerminalImplementationV1 {
        version: PHASE3_TERMINAL_VERSION_V1,
        max_proof_bytes: ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1 as u32,
        c1_schema_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase3.c1-schema",
            PHASE3_C1_SCHEMA_V1,
        ),
        c2_schema_digest: super::native_outer_schema_v1(
            b"iroha.zk-ams.v1.phase3.c2-schema",
            PHASE3_C2_SCHEMA_V1,
        ),
        release_kat_digest: [0; 32],
        release_kat_complete: false,
        digest: [0; 32],
    };
    let mut hash = super::native_outer_identity_v1(
        super::NativeOuterIdentityRoleV1::Release,
        PHASE3_IMPLEMENTATION_DOMAIN_V1,
        6,
    );
    hash.push_field(&[implementation.version])
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&implementation.max_proof_bytes.to_be_bytes())
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&implementation.c1_schema_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&implementation.c2_schema_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&implementation.release_kat_digest)
        .expect("fixed bounded MKHE identity field");
    hash.push_field(&[implementation.release_kat_complete.into()])
        .expect("fixed bounded MKHE identity field");
    implementation.digest = *hash
        .finish()
        .expect("exact MKHE outer identity field count")
        .as_bytes();
    implementation
}
#[cfg(test)]
struct TerminalProfile {
    shape: Arc<Shape>,
    commitment_key: CommitmentKey,
    map_set_digest: [u8; 32],
    nifs_verifier_digest: [u8; 32],
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum TerminalRelationSourceV1<'a> {
    CanonicalRelease,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "external relation injection is test-only")
    )]
    External {
        maps: [&'a ZkAmsPhase23SparseMapV1; 3],
        expected_shape: &'a Shape,
    },
}
#[cfg(test)]
impl TerminalRelationSourceV1<'_> {
    const fn is_release(self) -> bool {
        matches!(self, Self::CanonicalRelease)
    }
}
#[cfg(test)]
impl TerminalProfile {
    fn validate(&self) -> Result<(), ZkAmsMkheErrorV1> {
        let key_digest = commitment_key_digest(&self.commitment_key)?;
        let expected_nifs_digest = nifs_verifier_digest(
            &self.shape,
            self.map_set_digest,
            key_digest,
            MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
        )?;
        if self.map_set_digest == [0; 32]
            || self.nifs_verifier_digest == [0; 32]
            || self.nifs_verifier_digest != expected_nifs_digest
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        Ok(())
    }
}
/// Owns materialized scalars after they leave the single consuming accumulator owner and until they
/// are transferred into the guarded folded witness. Deliberately neither `Clone` nor `Debug`.
#[cfg(test)]
struct ZeroizingTerminalScalarVecV1(Vec<Scalar>);
#[cfg(test)]
std::thread_local! {
    static TERMINAL_SCALAR_VEC_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static TERMINAL_RELAXED_WITNESS_ZEROIZED_DROPS_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static TERMINAL_STRUCTURED_DIGEST_ENTRIES_V1: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn terminal_scalar_vec_zeroized_drop_count_v1() -> usize {
    TERMINAL_SCALAR_VEC_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
fn terminal_relaxed_witness_zeroized_drop_count_v1() -> usize {
    TERMINAL_RELAXED_WITNESS_ZEROIZED_DROPS_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
fn terminal_structured_digest_entry_count_v1() -> usize {
    TERMINAL_STRUCTURED_DIGEST_ENTRIES_V1
        .try_with(std::cell::Cell::get)
        .unwrap_or(0)
}
#[cfg(test)]
fn reset_terminal_structured_digest_entry_count_v1() {
    let _ = TERMINAL_STRUCTURED_DIGEST_ENTRIES_V1.try_with(|entries| entries.set(0));
}
#[cfg(test)]
fn note_terminal_structured_digest_entry_v1() {
    let _ = TERMINAL_STRUCTURED_DIGEST_ENTRIES_V1
        .try_with(|entries| entries.set(entries.get().saturating_add(1)));
}
#[cfg(test)]
impl ZeroizingTerminalScalarVecV1 {
    fn new(values: Vec<Scalar>) -> Self {
        Self(values)
    }
    fn as_slice(&self) -> &[Scalar] {
        &self.0
    }
    fn take(&mut self) -> Vec<Scalar> {
        core::mem::take(&mut self.0)
    }
}
#[cfg(test)]
impl Drop for ZeroizingTerminalScalarVecV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let had_values = !self.0.is_empty();
        let values = core::hint::black_box(&mut self.0);
        for value in values.iter_mut() {
            value.clear_secret();
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if had_values && values.iter().all(|value| value.is_zero()) {
            let _ = TERMINAL_SCALAR_VEC_ZEROIZED_DROPS_V1
                .try_with(|drops| drops.set(drops.get().saturating_add(1)));
        }
        let _ = core::hint::black_box(&mut *values);
    }
}
/// Move-only RAII owner for the consumed final folded witness.
///
/// It covers construction errors, receipt rejection, and unwinding. On the
/// success path ownership is handed directly to the proof layer, whose
/// `SecretRelaxedWitness` guard performs the same erasure on every exit.
#[cfg(test)]
struct ZeroizingTerminalRelaxedWitnessV1(Option<RelaxedWitness>);
#[cfg(test)]
impl ZeroizingTerminalRelaxedWitnessV1 {
    fn new(witness: RelaxedWitness) -> Self {
        Self(Some(witness))
    }
    fn take(&mut self) -> Result<RelaxedWitness, ZkAmsMkheErrorV1> {
        self.0.take().ok_or(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    }
    fn as_ref(&self) -> &RelaxedWitness {
        self.0.as_ref().expect("guarded witness is present")
    }
}
#[cfg(test)]
impl Drop for ZeroizingTerminalRelaxedWitnessV1 {
    fn drop(&mut self) {
        if let Some(witness) = &mut self.0 {
            for values in [
                &mut witness.values,
                &mut witness.witness_blindings,
                &mut witness.error,
                &mut witness.error_blindings,
            ] {
                for value in values.iter_mut() {
                    value.clear_secret();
                }
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            #[cfg(test)]
            if witness.values.iter().all(|value| value.is_zero())
                && witness
                    .witness_blindings
                    .iter()
                    .all(|value| value.is_zero())
                && witness.error.iter().all(|value| value.is_zero())
                && witness.error_blindings.iter().all(|value| value.is_zero())
            {
                let _ = TERMINAL_RELAXED_WITNESS_ZEROIZED_DROPS_V1
                    .try_with(|drops| drops.set(drops.get().saturating_add(1)));
            }
            let _ = core::hint::black_box(witness);
        }
    }
}
/// Borrowed exact terminal rows used by the private cross-basis bridge.
///
/// The slices remain owned by [`ZkAmsPhase3PreparedTerminalMaterializationV1`]
/// and cannot outlive it.  Their order is fixed as every `E,rE` row followed
/// by every `W,rW` row.  This view deliberately has no constructor, codec, or
/// owned-vector return path.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "cross-basis kernel remains source-and-packing sealed until its consuming owner is wired"
)]
pub(super) struct ZkAmsPhase3PreparedTerminalOpeningsV1<'a> {
    context_digest: [u8; 32],
    materialized_digest: [u8; 32],
    error_values: &'a [Scalar],
    error_blindings: &'a [Scalar],
    error_commitment: &'a Commitment,
    witness_values: &'a [Scalar],
    witness_blindings: &'a [Scalar],
    witness_commitment: &'a Commitment,
}
#[cfg(test)]
#[allow(
    dead_code,
    reason = "cross-basis kernel remains source-and-packing sealed until its consuming owner is wired"
)]
impl<'a> ZkAmsPhase3PreparedTerminalOpeningsV1<'a> {
    /// Digest of the exact terminal context checked before borrowing rows.
    pub(super) const fn context_digest_v1(&self) -> [u8; 32] {
        self.context_digest
    }
    /// Digest of the consumed padding-free materialization.
    pub(super) const fn materialized_digest_v1(&self) -> [u8; 32] {
        self.materialized_digest
    }
    /// Exact `E` scalars in canonical terminal row order.
    pub(super) const fn error_values_v1(&self) -> &'a [Scalar] {
        self.error_values
    }
    /// One Hyrax blinding scalar for every `E` row.
    pub(super) const fn error_blindings_v1(&self) -> &'a [Scalar] {
        self.error_blindings
    }
    /// Existing Hyrax commitment to the exact `E,rE` opening above.
    pub(super) const fn error_commitment_v1(&self) -> &'a Commitment {
        self.error_commitment
    }
    /// Exact `W` scalars in canonical terminal row order.
    pub(super) const fn witness_values_v1(&self) -> &'a [Scalar] {
        self.witness_values
    }
    /// One Hyrax blinding scalar for every `W` row.
    pub(super) const fn witness_blindings_v1(&self) -> &'a [Scalar] {
        self.witness_blindings
    }
    /// Existing Hyrax commitment to the exact `W,rW` opening above.
    pub(super) const fn witness_commitment_v1(&self) -> &'a Commitment {
        self.witness_commitment
    }
}
/// Move-only prepared terminal materialization for one private bridge proof.
///
/// Construction consumes the six-family materialization, recomputes the
/// complete relaxed-R1CS assignment, and recomputes both Hyrax commitments
/// from `E,rE,W,rW`.  The same guarded opening may then be borrowed by the
/// cross-basis bridge and is finally consumed by the terminal prover.  This is
/// not an RNS-Link receipt and makes no claim that the materialized scalars
/// equal plaintexts in untrusted BGV records.
#[cfg(test)]
pub(super) struct ZkAmsPhase3PreparedTerminalMaterializationV1 {
    context_digest: [u8; 32],
    materialized_digest: [u8; 32],
    instance: RelaxedInstance,
    witness: ZeroizingTerminalRelaxedWitnessV1,
}
#[cfg(test)]
impl ZkAmsPhase3PreparedTerminalMaterializationV1 {
    fn validate_context_v1(
        &self,
        context: ZkAmsPhase3TerminalContextV1,
    ) -> Result<(), ZkAmsMkheErrorV1> {
        if self.context_digest != context.digest
            || self.context_digest == [0; 32]
            || self.materialized_digest == [0; 32]
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        Ok(())
    }
    /// Borrow the exact checked openings without transferring any owner.
    pub(super) fn openings_for_cross_basis_v1(
        &self,
        context: ZkAmsPhase3TerminalContextV1,
    ) -> Result<ZkAmsPhase3PreparedTerminalOpeningsV1<'_>, ZkAmsMkheErrorV1> {
        self.validate_context_v1(context)?;
        let witness = self.witness.as_ref();
        if witness.error.is_empty()
            || witness.values.is_empty()
            || witness.error_blindings.len() != self.instance.error_commitment.len()
            || witness.witness_blindings.len() != self.instance.witness_commitment.len()
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        Ok(ZkAmsPhase3PreparedTerminalOpeningsV1 {
            context_digest: self.context_digest,
            materialized_digest: self.materialized_digest,
            error_values: &witness.error,
            error_blindings: &witness.error_blindings,
            error_commitment: &self.instance.error_commitment,
            witness_values: &witness.values,
            witness_blindings: &witness.witness_blindings,
            witness_commitment: &self.instance.witness_commitment,
        })
    }
    /// Consume the same prepared opening only for the exact checked context.
    fn consume_for_terminal_v1(
        self,
        context: ZkAmsPhase3TerminalContextV1,
    ) -> Result<(RelaxedInstance, ZeroizingTerminalRelaxedWitnessV1), ZkAmsMkheErrorV1> {
        self.validate_context_v1(context)?;
        Ok((self.instance, self.witness))
    }
}
/// Compute the exact terminal NIFS verifier identity from the shared canonical
/// shape and compact paper-order map manifest.
#[cfg(test)]
pub fn zk_ams_phase3_nifs_verifier_digest_v1() -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let profile = build_terminal_profile(TerminalRelationSourceV1::CanonicalRelease)?;
    Ok(profile.nifs_verifier_digest)
}
/// Generate one canonical setup-free terminal proof and its compact public
/// final batch anchor. The six materialized families are consumed only here.
#[cfg(test)]
pub fn prove_zk_ams_phase3_terminal_v1(
    proof_context: &super::super::ZkAmsProofContextV1<'_>,
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    fold_history: &ZkAmsPhase3FoldHistoryV1,
    materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
) -> Result<ZkAmsPhase3TerminalProverOutputV1, ZkAmsMkheErrorV1> {
    super::require_release_ready_v1()?;
    prove_terminal_inner(
        proof_context,
        context,
        governed_batch,
        fold_history,
        materialized,
        TerminalRelationSourceV1::CanonicalRelease,
    )
}
/// Verify one exact-canonical terminal proof from public settlement data only.
/// The verifier never receives `E_f,rE_f,W_f,rW_f`.
#[cfg(test)]
pub fn verify_zk_ams_phase3_terminal_v1(
    proof_context: &super::super::ZkAmsProofContextV1<'_>,
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    batch_anchor: &ZkAmsPhase3BatchAnchorV1,
    proof_bytes: &[u8],
) -> Result<ZkAmsPhase3TerminalReceiptV1, ZkAmsMkheErrorV1> {
    super::require_release_ready_v1()?;
    verify_terminal_inner(
        proof_context,
        context,
        governed_batch,
        batch_anchor,
        TerminalRelationSourceV1::CanonicalRelease,
        proof_bytes,
    )
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn prove_terminal_inner(
    proof_context: &super::super::ZkAmsProofContextV1<'_>,
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    fold_history: &ZkAmsPhase3FoldHistoryV1,
    materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
    relation_source: TerminalRelationSourceV1<'_>,
) -> Result<ZkAmsPhase3TerminalProverOutputV1, ZkAmsMkheErrorV1> {
    let require_release_profile = relation_source.is_release();
    // Keep malformed artifacts on the cheap boundary. The opaque native
    // opening constructor below repeats these checks before it can mint.
    validate_terminal_context(context)?;
    validate_materialized_accumulators_v1(&materialized)?;
    validate_context_materialized_binding(context, &materialized, require_release_profile)?;
    let profile = build_terminal_profile(relation_source)?;
    if context.nifs_verifier_digest != profile.nifs_verifier_digest {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let strict_public_inputs = validate_governed_batch(context, governed_batch, &profile.shape)?;
    if usize::from(materialized.fold_count) != strict_public_inputs.len() {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let (mask, strict_instances, folds) =
        fold_history_to_protocol(context, governed_batch, fold_history, &profile.shape)?;
    let verified_materialization = verify_native_materialized_opening_v1(
        context,
        materialized,
        &profile,
        require_release_profile,
    )?;
    let (materialized_instance, mut materialized_witness) =
        verified_materialization.consume_for_terminal_v1(context)?;
    let batch_anchor = batch_anchor_from_instance(context, &materialized_instance)?;
    let context_frame = terminal_composition_context_frame(proof_context, context, governed_batch)?;
    let history_proof = prove_precomputed_masked_relaxed_v1(
        super::super::COMPOSITION_DOMAIN_V1,
        &context_frame,
        super::super::COMMITMENT_KEY_LABEL_V1,
        &profile.shape,
        &mask,
        &strict_instances,
        &folds,
        materialized_witness.take()?,
        1,
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    if fold_history_digest_from_proof(context, &history_proof, &profile.shape)?
        != fold_history.digest
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let encoded = super::super::encode_zk_ams_admission_relation_wire_v1(history_proof)
        .map_err(|_| ZkAmsMkheErrorV1::WireTooLarge)?;
    verify_terminal_inner(
        proof_context,
        context,
        governed_batch,
        &batch_anchor,
        relation_source,
        &encoded,
    )?;
    Ok(ZkAmsPhase3TerminalProverOutputV1 {
        batch_anchor,
        proof_bytes: encoded,
    })
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn verify_terminal_inner(
    proof_context: &super::super::ZkAmsProofContextV1<'_>,
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    batch_anchor: &ZkAmsPhase3BatchAnchorV1,
    relation_source: TerminalRelationSourceV1<'_>,
    proof_bytes: &[u8],
) -> Result<ZkAmsPhase3TerminalReceiptV1, ZkAmsMkheErrorV1> {
    let require_release_profile = relation_source.is_release();
    if proof_bytes.len() > ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1 {
        return Err(ZkAmsMkheErrorV1::WireTooLarge);
    }
    validate_terminal_context(context)?;
    let profile = build_terminal_profile(relation_source)?;
    if context.nifs_verifier_digest != profile.nifs_verifier_digest {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    if require_release_profile && context.profile_digest != release_profile_v1().digest()? {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    let strict_public_inputs = validate_governed_batch(context, governed_batch, &profile.shape)?;
    let batch_anchor_instance = batch_anchor_to_instance(
        batch_anchor,
        context,
        &profile.shape,
        MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
    )?;
    let relation = super::super::decode_zk_ams_admission_relation_wire_v1(
        strict_public_inputs.len(),
        proof_bytes,
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    let context_frame = terminal_composition_context_frame(proof_context, context, governed_batch)?;
    let terminal = verify_and_replay_masked_relaxed_v1(
        super::super::COMPOSITION_DOMAIN_V1,
        &context_frame,
        super::super::COMMITMENT_KEY_LABEL_V1,
        &profile.shape,
        &strict_public_inputs,
        &relation,
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    if terminal != batch_anchor_instance {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let fold_history_digest = fold_history_digest_from_proof(context, &relation, &profile.shape)?;
    let proof_digest = terminal_proof_bytes_digest(proof_bytes);
    let composition_context_digest = keccak256(&context_frame);
    terminal_receipt(
        context,
        composition_context_digest,
        batch_anchor.digest,
        profile.map_set_digest,
        governed_batch.digest,
        fold_history_digest,
        &terminal,
        proof_digest,
    )
}
#[cfg(test)]
fn validate_terminal_context_fields(
    context: ZkAmsPhase3TerminalContextV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    if context.version != PHASE3_TERMINAL_VERSION_V1
        || context.epoch == 0
        || [
            context.profile_digest,
            context.roster_digest,
            context.transcript_digest,
            context.batch_id,
            context.ordered_batch_input_digest,
            context.nifs_verifier_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn validate_terminal_context(
    context: ZkAmsPhase3TerminalContextV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    validate_terminal_context_fields(context)?;
    if context.digest == [0; 32] || context.digest != terminal_context_digest(context) {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
fn terminal_composition_context_frame(
    proof_context: &super::super::ZkAmsProofContextV1<'_>,
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {
    validate_terminal_context(context)?;
    validate_governed_batch_fields(context, governed_batch)?;
    let generic_context = super::super::context_frame(proof_context)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(PHASE3_COMPOSITION_CONTEXT_DOMAIN_V1.len() + 2)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(PHASE3_COMPOSITION_CONTEXT_DOMAIN_V1);
    frame.push(PHASE3_TERMINAL_VERSION_V1);
    frame.push(3);
    append_terminal_composition_field(
        &mut frame,
        PHASE3_COMPOSITION_GENERIC_CONTEXT_TAG_V1,
        &generic_context,
    )?;
    append_terminal_composition_field(
        &mut frame,
        PHASE3_COMPOSITION_TERMINAL_CONTEXT_TAG_V1,
        &context.digest,
    )?;
    append_terminal_composition_field(
        &mut frame,
        PHASE3_COMPOSITION_GOVERNED_BATCH_TAG_V1,
        &governed_batch.digest,
    )?;
    Ok(frame)
}
#[cfg(test)]
fn append_terminal_composition_field(
    frame: &mut Vec<u8>,
    tag: &[u8],
    value: &[u8],
) -> Result<(), ZkAmsMkheErrorV1> {
    let tag_len =
        u16::try_from(tag.len()).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let value_len =
        u32::try_from(value.len()).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let additional = 2_usize
        .checked_add(tag.len())
        .and_then(|length| length.checked_add(4))
        .and_then(|length| length.checked_add(value.len()))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame
        .try_reserve_exact(additional)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(&tag_len.to_be_bytes());
    frame.extend_from_slice(tag);
    frame.extend_from_slice(&value_len.to_be_bytes());
    frame.extend_from_slice(value);
    Ok(())
}
#[cfg(test)]
fn terminal_context_digest(context: ZkAmsPhase3TerminalContextV1) -> [u8; 32] {
    keccak256(&terminal_context_frame(context))
}
#[cfg(test)]
fn terminal_context_frame(context: ZkAmsPhase3TerminalContextV1) -> Vec<u8> {
    let mut frame = Vec::with_capacity(288);
    frame.extend_from_slice(PHASE3_CONTEXT_DOMAIN_V1);
    frame.push(context.version);
    frame.extend_from_slice(&context.profile_digest);
    frame.extend_from_slice(&context.roster_digest);
    frame.extend_from_slice(&context.epoch.to_be_bytes());
    frame.extend_from_slice(&context.transcript_digest);
    frame.extend_from_slice(&context.batch_id);
    frame.extend_from_slice(&context.ordered_batch_input_digest);
    frame.extend_from_slice(&context.nifs_verifier_digest);
    frame
}
#[cfg(test)]
fn validate_context_materialized_binding(
    context: ZkAmsPhase3TerminalContextV1,
    materialized: &ZkAmsPhase23MaterializedAccumulatorsV1,
    require_release_profile: bool,
) -> Result<(), ZkAmsMkheErrorV1> {
    if context.profile_digest != materialized.profile_digest
        || context.roster_digest != materialized.roster_digest
        || context.transcript_digest != materialized.transcript_digest
        || context.batch_id != materialized.batch_id
        || context.ordered_batch_input_digest != materialized.ordered_batch_input_digest
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    if require_release_profile && context.profile_digest != release_profile_v1().digest()? {
        return Err(ZkAmsMkheErrorV1::InvalidProfile);
    }
    Ok(())
}
#[cfg(test)]
fn batch_anchor_from_instance(
    context: ZkAmsPhase3TerminalContextV1,
    instance: &RelaxedInstance,
) -> Result<ZkAmsPhase3BatchAnchorV1, ZkAmsMkheErrorV1> {
    let mut anchor = ZkAmsPhase3BatchAnchorV1 {
        version: PHASE3_TERMINAL_VERSION_V1,
        context_digest: context.digest,
        witness_commitment: commitment_to_wire(&instance.witness_commitment)?,
        error_commitment: commitment_to_wire(&instance.error_commitment)?,
        relaxation: VegaScalarWireV1::from_scalar(instance.relaxation),
        public_inputs: instance
            .public_inputs
            .iter()
            .copied()
            .map(VegaScalarWireV1::from_scalar)
            .collect(),
        digest: [0; 32],
    };
    anchor.digest = batch_anchor_digest(&anchor)?;
    Ok(anchor)
}
#[cfg(test)]
fn preflight_governed_rows<T>(rows: &[Vec<T>]) -> Result<(), ZkAmsMkheErrorV1> {
    if rows.is_empty()
        || rows.len() > MAX_MASKED_RELAXED_STRICT_INSTANCES_V1
        || rows.iter().any(|row| {
            row.is_empty() || row.len() > super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1
        })
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
fn preflight_batch_anchor_lengths(
    witness_commitment_points: usize,
    error_commitment_points: usize,
    public_inputs: usize,
) -> Result<(), ZkAmsMkheErrorV1> {
    if witness_commitment_points == 0
        || witness_commitment_points > ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1
        || error_commitment_points == 0
        || error_commitment_points > ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1
        || public_inputs == 0
        || public_inputs > super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
fn preflight_batch_anchor_release_maxima(
    anchor: &ZkAmsPhase3BatchAnchorV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    preflight_batch_anchor_lengths(
        anchor.witness_commitment.len(),
        anchor.error_commitment.len(),
        anchor.public_inputs.len(),
    )
}
#[cfg(test)]
fn preflight_batch_anchor_shape(
    anchor: &ZkAmsPhase3BatchAnchorV1,
    shape: &Shape,
    commitment_columns: usize,
) -> Result<(), ZkAmsMkheErrorV1> {
    preflight_batch_anchor_release_maxima(anchor)?;
    let witness_rows = commitment_rows(shape.variable_count(), commitment_columns)?;
    let error_rows = commitment_rows(shape.constraint_count(), commitment_columns)?;
    if anchor.witness_commitment.len() != witness_rows
        || anchor.error_commitment.len() != error_rows
        || anchor.public_inputs.len() != shape.public_input_count()
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
fn preflight_fold_history_lengths(
    mask: &ZkAmsPhase3BatchAnchorV1,
    strict_witness_commitments: &[Vec<VegaPointWireV1>],
    cross_term_commitments: &[Vec<VegaPointWireV1>],
) -> Result<(), ZkAmsMkheErrorV1> {
    preflight_batch_anchor_release_maxima(mask)?;
    if strict_witness_commitments.is_empty()
        || strict_witness_commitments.len() > MAX_MASKED_RELAXED_STRICT_INSTANCES_V1
        || strict_witness_commitments.len() != cross_term_commitments.len()
        || strict_witness_commitments
            .iter()
            .any(|commitment| commitment.len() != mask.witness_commitment.len())
        || cross_term_commitments
            .iter()
            .any(|commitment| commitment.len() != mask.error_commitment.len())
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(())
}
#[cfg(test)]
fn preflight_fold_history_shape(
    history: &ZkAmsPhase3FoldHistoryV1,
    shape: &Shape,
) -> Result<(), ZkAmsMkheErrorV1> {
    preflight_fold_history_lengths(
        &history.mask,
        &history.strict_witness_commitments,
        &history.cross_term_commitments,
    )?;
    preflight_batch_anchor_shape(&history.mask, shape, MASKED_RELAXED_COMMITMENT_COLUMNS_V1)
}
#[cfg(test)]
fn batch_anchor_digest(anchor: &ZkAmsPhase3BatchAnchorV1) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    preflight_batch_anchor_release_maxima(anchor)?;
    #[cfg(test)]
    note_terminal_structured_digest_entry_v1();
    let mut candidate = anchor.clone();
    candidate.digest = [0; 32];
    let encoded = norito::codec::encode_adaptive(&candidate);
    let frame_len = PHASE3_BATCH_ANCHOR_DOMAIN_V1
        .len()
        .checked_add(encoded.len())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_len)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(PHASE3_BATCH_ANCHOR_DOMAIN_V1);
    frame.extend_from_slice(&encoded);
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn governed_batch_digest(batch: &ZkAmsPhase3GovernedBatchV1) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    preflight_governed_rows(&batch.strict_public_inputs)?;
    #[cfg(test)]
    note_terminal_structured_digest_entry_v1();
    let mut candidate = batch.clone();
    candidate.digest = [0; 32];
    let encoded = norito::codec::encode_adaptive(&candidate);
    let frame_len = PHASE3_GOVERNED_BATCH_DOMAIN_V1
        .len()
        .checked_add(encoded.len())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_len)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(PHASE3_GOVERNED_BATCH_DOMAIN_V1);
    frame.extend_from_slice(&encoded);
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn fold_history_digest(history: &ZkAmsPhase3FoldHistoryV1) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    preflight_fold_history_lengths(
        &history.mask,
        &history.strict_witness_commitments,
        &history.cross_term_commitments,
    )?;
    #[cfg(test)]
    note_terminal_structured_digest_entry_v1();
    let mut candidate = history.clone();
    candidate.digest = [0; 32];
    let encoded = norito::codec::encode_adaptive(&candidate);
    let frame_len = PHASE3_FOLD_HISTORY_DOMAIN_V1
        .len()
        .checked_add(encoded.len())
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(frame_len)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    frame.extend_from_slice(PHASE3_FOLD_HISTORY_DOMAIN_V1);
    frame.extend_from_slice(&encoded);
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn validate_governed_batch_fields(
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
) -> Result<Vec<Vec<Scalar>>, ZkAmsMkheErrorV1> {
    preflight_governed_rows(&governed_batch.strict_public_inputs)?;
    if governed_batch.version != PHASE3_TERMINAL_VERSION_V1
        || governed_batch.context_digest != context.digest
        || governed_batch.digest == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    if governed_batch.digest != governed_batch_digest(governed_batch)? {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let strict_public_inputs = governed_batch
        .strict_public_inputs
        .iter()
        .map(|inputs| scalars_from_wire(inputs))
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_inputs = strict_public_inputs
        .iter()
        .map(|inputs| {
            inputs
                .iter()
                .copied()
                .map(Scalar::to_be_bytes)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if zk_ams_phase3_ordered_public_inputs_digest_v1(&encoded_inputs)?
        != context.ordered_batch_input_digest
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(strict_public_inputs)
}
#[cfg(test)]
fn validate_governed_batch(
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    shape: &Shape,
) -> Result<Vec<Vec<Scalar>>, ZkAmsMkheErrorV1> {
    preflight_governed_rows(&governed_batch.strict_public_inputs)?;
    if governed_batch
        .strict_public_inputs
        .iter()
        .any(|inputs| inputs.len() != shape.public_input_count())
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    validate_governed_batch_fields(context, governed_batch)
}
#[cfg(test)]
fn fold_history_to_protocol(
    context: ZkAmsPhase3TerminalContextV1,
    governed_batch: &ZkAmsPhase3GovernedBatchV1,
    history: &ZkAmsPhase3FoldHistoryV1,
    shape: &Shape,
) -> Result<(RelaxedInstance, Vec<Instance>, Vec<NovaNifs>), ZkAmsMkheErrorV1> {
    let strict_public_inputs = validate_governed_batch(context, governed_batch, shape)?;
    let count = strict_public_inputs.len();
    preflight_fold_history_shape(history, shape)?;
    if history.version != PHASE3_TERMINAL_VERSION_V1
        || history.context_digest != context.digest
        || history.digest == [0; 32]
        || history.strict_witness_commitments.len() != count
        || history.cross_term_commitments.len() != count
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    if history.digest != fold_history_digest(history)? {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let mask = batch_anchor_to_instance(
        &history.mask,
        context,
        shape,
        MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
    )?;
    let strict_instances = history
        .strict_witness_commitments
        .iter()
        .zip(strict_public_inputs)
        .map(|(commitment, public_inputs)| {
            Ok::<Instance, ZkAmsMkheErrorV1>(Instance {
                witness_commitment: commitment_from_wire(commitment)?,
                public_inputs,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let folds = history
        .cross_term_commitments
        .iter()
        .map(|commitment| {
            Ok::<NovaNifs, ZkAmsMkheErrorV1>(NovaNifs {
                cross_term_commitment: commitment_from_wire(commitment)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((mask, strict_instances, folds))
}
#[cfg(test)]
fn preflight_fold_history_proof_shape(
    proof: &MaskedRelaxedProofWireV1,
    shape: &Shape,
) -> Result<(), ZkAmsMkheErrorV1> {
    let count = usize::from(proof.strict_instance_count);
    let witness_rows =
        commitment_rows(shape.variable_count(), MASKED_RELAXED_COMMITMENT_COLUMNS_V1)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    let error_rows = commitment_rows(
        shape.constraint_count(),
        MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?;
    if count == 0
        || count > MAX_MASKED_RELAXED_STRICT_INSTANCES_V1
        || witness_rows > ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1
        || error_rows > ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1
        || shape.public_input_count() == 0
        || shape.public_input_count() > super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1
        || proof.mask_witness_commitment.points.len() != witness_rows
        || proof.mask_error_commitment.points.len() != error_rows
        || proof.mask_public_inputs.len() != shape.public_input_count()
        || proof.strict_witness_commitments.len() != count
        || proof.cross_term_commitments.len() != count
        || proof
            .strict_witness_commitments
            .iter()
            .any(|commitment| commitment.points.len() != witness_rows)
        || proof
            .cross_term_commitments
            .iter()
            .any(|commitment| commitment.points.len() != error_rows)
    {
        return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
    }
    Ok(())
}
#[cfg(test)]
fn fold_history_digest_from_proof(
    context: ZkAmsPhase3TerminalContextV1,
    proof: &MaskedRelaxedProofWireV1,
    shape: &Shape,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    preflight_fold_history_proof_shape(proof, shape)?;
    let mut mask = ZkAmsPhase3BatchAnchorV1 {
        version: PHASE3_TERMINAL_VERSION_V1,
        context_digest: context.digest,
        witness_commitment: proof.mask_witness_commitment.points.clone(),
        error_commitment: proof.mask_error_commitment.points.clone(),
        relaxation: proof.mask_relaxation,
        public_inputs: proof.mask_public_inputs.clone(),
        digest: [0; 32],
    };
    mask.digest = batch_anchor_digest(&mask)?;
    let mut history = ZkAmsPhase3FoldHistoryV1 {
        version: PHASE3_TERMINAL_VERSION_V1,
        context_digest: context.digest,
        mask,
        strict_witness_commitments: proof
            .strict_witness_commitments
            .iter()
            .map(|commitment| commitment.points.clone())
            .collect(),
        cross_term_commitments: proof
            .cross_term_commitments
            .iter()
            .map(|commitment| commitment.points.clone())
            .collect(),
        digest: [0; 32],
    };
    history.digest = fold_history_digest(&history)?;
    Ok(history.digest)
}
#[cfg(test)]
fn batch_anchor_to_instance(
    anchor: &ZkAmsPhase3BatchAnchorV1,
    context: ZkAmsPhase3TerminalContextV1,
    shape: &Shape,
    commitment_columns: usize,
) -> Result<RelaxedInstance, ZkAmsMkheErrorV1> {
    preflight_batch_anchor_shape(anchor, shape, commitment_columns)?;
    if anchor.version != PHASE3_TERMINAL_VERSION_V1
        || anchor.context_digest != context.digest
        || anchor.digest == [0; 32]
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    if anchor.digest != batch_anchor_digest(anchor)? {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let public_inputs = scalars_from_wire(&anchor.public_inputs)?;
    Ok(RelaxedInstance {
        witness_commitment: commitment_from_wire(&anchor.witness_commitment)?,
        error_commitment: commitment_from_wire(&anchor.error_commitment)?,
        relaxation: scalar_from_wire(anchor.relaxation)?,
        public_inputs,
    })
}
#[cfg(test)]
fn build_terminal_profile(
    relation_source: TerminalRelationSourceV1<'_>,
) -> Result<TerminalProfile, ZkAmsMkheErrorV1> {
    let commitment_columns = MASKED_RELAXED_COMMITMENT_COLUMNS_V1;
    let (shape, release_manifest, external_maps) = match relation_source {
        TerminalRelationSourceV1::CanonicalRelease => {
            let relation = zk_ams_phase23_release_relation_v1()?;
            (
                Arc::clone(relation.shape()),
                Some(*relation.manifest()),
                None,
            )
        }
        TerminalRelationSourceV1::External {
            maps,
            expected_shape,
        } => {
            let reconstructed = Arc::new(shape_from_paper_order_maps(
                maps,
                expected_shape.variable_count(),
                expected_shape.public_input_count(),
            )?);
            if reconstructed.as_ref() != expected_shape {
                return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
            }
            (reconstructed, None, Some(maps))
        }
    };
    let public_input_count = shape.public_input_count();
    let variable_count = shape.variable_count();
    let commitment_key =
        CommitmentKey::derive(super::super::COMMITMENT_KEY_LABEL_V1, commitment_columns)
            .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?;
    let map_set_digest = if let Some(manifest) = release_manifest {
        map_set_digest_from_manifest(
            manifest.abc(),
            variable_count,
            public_input_count,
            shape.constraint_count(),
            commitment_columns,
        )?
    } else {
        map_set_digest(
            external_maps.ok_or(ZkAmsMkheErrorV1::InvalidPhase23Fold)?,
            variable_count,
            public_input_count,
            shape.constraint_count(),
            commitment_columns,
        )?
    };
    let commitment_key_digest = commitment_key_digest(&commitment_key)?;
    let nifs_verifier_digest = nifs_verifier_digest(
        &shape,
        map_set_digest,
        commitment_key_digest,
        commitment_columns,
    )?;
    let profile = TerminalProfile {
        shape,
        commitment_key,
        map_set_digest,
        nifs_verifier_digest,
    };
    profile.validate()?;
    Ok(profile)
}
#[cfg(test)]
fn shape_from_paper_order_maps(
    maps: [&ZkAmsPhase23SparseMapV1; 3],
    variable_count: usize,
    public_input_count: usize,
) -> Result<Shape, ZkAmsMkheErrorV1> {
    if maps[0].kind != ZkAmsPhase23MapKindV1::A
        || maps[1].kind != ZkAmsPhase23MapKindV1::B
        || maps[2].kind != ZkAmsPhase23MapKindV1::C
        || maps.iter().any(|map| validate_sparse_map_v1(map).is_err())
        || maps.iter().any(|map| map.row_count != maps[0].row_count)
        || maps
            .iter()
            .any(|map| map.column_count != maps[0].column_count)
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let expected_columns = variable_count
        .checked_add(public_input_count)
        .and_then(|value| value.checked_add(1))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if usize::try_from(maps[0].column_count)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
        != expected_columns
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let rows = usize::try_from(maps[0].row_count)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let a = sparse_matrix_from_paper_order(maps[0], variable_count, public_input_count)?;
    let b = sparse_matrix_from_paper_order(maps[1], variable_count, public_input_count)?;
    let c = sparse_matrix_from_paper_order(maps[2], variable_count, public_input_count)?;
    Shape::new(rows, variable_count, public_input_count, a, b, c)
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)
}
#[cfg(test)]
fn sparse_matrix_from_paper_order(
    map: &ZkAmsPhase23SparseMapV1,
    variable_count: usize,
    public_input_count: usize,
) -> Result<SparseMatrix, ZkAmsMkheErrorV1> {
    let rows =
        usize::try_from(map.row_count).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let columns =
        usize::try_from(map.column_count).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut entries = Vec::with_capacity(map.column_indices.len());
    for row in 0..rows {
        let start = usize::try_from(map.row_offsets[row])
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        let end = usize::try_from(map.row_offsets[row + 1])
            .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
        for index in start..end {
            let paper_column = usize::try_from(map.column_indices[index])
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
            let internal_column =
                paper_to_internal_column(paper_column, variable_count, public_input_count)?;
            let coefficient = Scalar::from_be_bytes_exact(map.coefficients[index])
                .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
            entries.push((row, internal_column, coefficient));
        }
    }
    // The paper-order x/u permutation can disturb within-row ordering. Sort
    // after the exact bijection and let SparseMatrix reject every duplicate.
    entries.sort_unstable_by_key(|entry| (entry.0, entry.1));
    SparseMatrix::new(rows, columns, &entries).map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)
}
#[cfg(test)]
fn paper_to_internal_column(
    paper_column: usize,
    variable_count: usize,
    public_input_count: usize,
) -> Result<usize, ZkAmsMkheErrorV1> {
    let paper_u = variable_count
        .checked_add(public_input_count)
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    if paper_column < variable_count {
        Ok(paper_column)
    } else if paper_column < paper_u {
        paper_column
            .checked_sub(variable_count)
            .and_then(|public_index| variable_count.checked_add(1 + public_index))
            .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
    } else if paper_column == paper_u {
        Ok(variable_count)
    } else {
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    }
}
#[cfg(test)]
fn map_set_digest(
    maps: [&ZkAmsPhase23SparseMapV1; 3],
    variable_count: usize,
    public_input_count: usize,
    constraint_count: usize,
    commitment_columns: usize,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut identities = [(ZkAmsPhase23MapKindV1::A, [0; 32]); 3];
    for (index, (expected_kind, map)) in [
        ZkAmsPhase23MapKindV1::A,
        ZkAmsPhase23MapKindV1::B,
        ZkAmsPhase23MapKindV1::C,
    ]
    .into_iter()
    .zip(maps)
    .enumerate()
    {
        if map.kind != expected_kind {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        validate_sparse_map_v1(map)?;
        identities[index] = (expected_kind, map.digest);
    }
    map_set_digest_from_identities(
        identities,
        variable_count,
        public_input_count,
        constraint_count,
        commitment_columns,
    )
}
#[cfg(test)]
fn map_set_digest_from_manifest(
    maps: [ZkAmsPhase23SparseMapManifestV1; 3],
    variable_count: usize,
    public_input_count: usize,
    constraint_count: usize,
    commitment_columns: usize,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let expected_columns = variable_count
        .checked_add(public_input_count)
        .and_then(|columns| columns.checked_add(1))
        .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    let mut identities = [(ZkAmsPhase23MapKindV1::A, [0; 32]); 3];
    for (index, (expected_kind, map)) in [
        ZkAmsPhase23MapKindV1::A,
        ZkAmsPhase23MapKindV1::B,
        ZkAmsPhase23MapKindV1::C,
    ]
    .into_iter()
    .zip(maps)
    .enumerate()
    {
        if map.version() != PHASE3_TERMINAL_VERSION_V1
            || map.kind() != expected_kind
            || usize::try_from(map.row_count())
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
                != constraint_count
            || usize::try_from(map.column_count())
                .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?
                != expected_columns
            || map.digest() == [0; 32]
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        identities[index] = (expected_kind, map.digest());
    }
    map_set_digest_from_identities(
        identities,
        variable_count,
        public_input_count,
        constraint_count,
        commitment_columns,
    )
}
#[cfg(test)]
fn map_set_digest_from_identities(
    identities: [(ZkAmsPhase23MapKindV1, [u8; 32]); 3],
    variable_count: usize,
    public_input_count: usize,
    constraint_count: usize,
    commitment_columns: usize,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut frame = Vec::with_capacity(192);
    frame.extend_from_slice(PHASE3_MAP_SET_DOMAIN_V1);
    frame.push(PHASE3_TERMINAL_VERSION_V1);
    frame.extend_from_slice(&usize_to_u32(variable_count)?.to_be_bytes());
    frame.extend_from_slice(&usize_to_u32(public_input_count)?.to_be_bytes());
    frame.extend_from_slice(&usize_to_u32(constraint_count)?.to_be_bytes());
    frame.extend_from_slice(&usize_to_u32(commitment_columns)?.to_be_bytes());
    for (kind, digest) in identities {
        frame.push(kind as u8);
        frame.extend_from_slice(&digest);
    }
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn commitment_key_digest(key: &CommitmentKey) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut frame = Vec::with_capacity(
        PHASE3_KEY_DOMAIN_V1.len()
            + key
                .columns()
                .checked_add(1)
                .and_then(|points| points.checked_mul(64))
                .ok_or(ZkAmsMkheErrorV1::ResourceCeilingExceeded)?,
    );
    frame.extend_from_slice(PHASE3_KEY_DOMAIN_V1);
    frame.extend_from_slice(&usize_to_u32(key.columns())?.to_be_bytes());
    for generator in key.generators() {
        frame.extend_from_slice(
            &generator
                .to_transcript_bytes()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
        );
    }
    frame.extend_from_slice(
        &key.hiding_generator()
            .to_transcript_bytes()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidKeyMaterial)?,
    );
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn nifs_verifier_digest(
    shape: &Shape,
    map_set_digest: [u8; 32],
    commitment_key_digest: [u8; 32],
    commitment_columns: usize,
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut frame = Vec::with_capacity(256);
    frame.extend_from_slice(PHASE3_NIFS_VERIFIER_DOMAIN_V1);
    frame.push(PHASE3_TERMINAL_VERSION_V1);
    frame.extend_from_slice(PHASE3_C1_SCHEMA_V1);
    frame.extend_from_slice(PHASE3_C2_SCHEMA_V1);
    frame.extend_from_slice(&map_set_digest);
    frame.extend_from_slice(&commitment_key_digest);
    for value in [
        shape.variable_count(),
        shape.public_input_count(),
        shape.constraint_count(),
        commitment_columns,
    ] {
        frame.extend_from_slice(&usize_to_u32(value)?.to_be_bytes());
    }
    Ok(keccak256(&frame))
}
#[cfg(test)]
fn verify_native_materialized_opening_v1(
    context: ZkAmsPhase3TerminalContextV1,
    mut materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
    profile: &TerminalProfile,
    require_release_profile: bool,
) -> Result<ZkAmsPhase3PreparedTerminalMaterializationV1, ZkAmsMkheErrorV1> {
    validate_terminal_context(context)?;
    validate_materialized_accumulators_v1(&materialized)?;
    validate_context_materialized_binding(context, &materialized, require_release_profile)?;
    profile.validate()?;
    if context.nifs_verifier_digest != profile.nifs_verifier_digest
        || materialized.x.len() != profile.shape.public_input_count()
        || materialized.u.len() != 1
        || materialized.e.len() != profile.shape.constraint_count()
        || materialized.w.len() != profile.shape.variable_count()
        || materialized.r_e.len()
            != commitment_rows(
                profile.shape.constraint_count(),
                MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
            )?
        || materialized.r_w.len()
            != commitment_rows(
                profile.shape.variable_count(),
                MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
            )?
    {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let materialized_digest = materialized.digest;
    let mut public_inputs = ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.x));
    let relaxation_values = ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.u));
    let mut error = ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.e));
    let mut error_blindings =
        ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.r_e));
    let mut values = ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.w));
    let mut witness_blindings =
        ZeroizingTerminalScalarVecV1::new(core::mem::take(&mut materialized.r_w));
    let relaxation = relaxation_values.as_slice()[0];
    profile
        .shape
        .validate_relaxed_assignment(
            values.as_slice(),
            relaxation,
            public_inputs.as_slice(),
            error.as_slice(),
        )
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let witness_commitment = profile
        .commitment_key
        .commit(values.as_slice(), witness_blindings.as_slice())
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let error_commitment = profile
        .commitment_key
        .commit(error.as_slice(), error_blindings.as_slice())
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let witness = ZeroizingTerminalRelaxedWitnessV1::new(RelaxedWitness {
        values: values.take(),
        witness_blindings: witness_blindings.take(),
        error: error.take(),
        error_blindings: error_blindings.take(),
    });
    let instance = RelaxedInstance {
        witness_commitment,
        error_commitment,
        public_inputs: public_inputs.take(),
        relaxation,
    };
    Ok(ZkAmsPhase3PreparedTerminalMaterializationV1 {
        context_digest: context.digest,
        materialized_digest,
        instance,
        witness,
    })
}
#[cfg(test)]
fn terminal_proof_bytes_digest(encoded: &[u8]) -> [u8; 32] {
    let mut frame = Vec::with_capacity(PHASE3_PROOF_DOMAIN_V1.len() + encoded.len());
    frame.extend_from_slice(PHASE3_PROOF_DOMAIN_V1);
    frame.extend_from_slice(encoded);
    keccak256(&frame)
}
#[cfg(test)]
fn terminal_instance_digest(terminal: &RelaxedInstance) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut frame = Vec::with_capacity(256);
    frame.extend_from_slice(PHASE3_TERMINAL_INSTANCE_DOMAIN_V1);
    frame.extend_from_slice(&commitment_digest(&terminal.witness_commitment)?);
    frame.extend_from_slice(&commitment_digest(&terminal.error_commitment)?);
    frame.extend_from_slice(&terminal.relaxation.to_be_bytes());
    frame.extend_from_slice(&usize_to_u32(terminal.public_inputs.len())?.to_be_bytes());
    for input in &terminal.public_inputs {
        frame.extend_from_slice(&input.to_be_bytes());
    }
    Ok(keccak256(&frame))
}
#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "fixed terminal receipt axes remain explicit to preserve canonical digest order"
)]
fn terminal_receipt(
    context: ZkAmsPhase3TerminalContextV1,
    composition_context_digest: [u8; 32],
    batch_anchor_digest: [u8; 32],
    map_set_digest: [u8; 32],
    governed_batch_digest: [u8; 32],
    fold_history_digest: [u8; 32],
    terminal: &RelaxedInstance,
    proof_digest: [u8; 32],
) -> Result<ZkAmsPhase3TerminalReceiptV1, ZkAmsMkheErrorV1> {
    let terminal_instance_digest = terminal_instance_digest(terminal)?;
    let mut receipt = ZkAmsPhase3TerminalReceiptV1 {
        version: PHASE3_TERMINAL_VERSION_V1,
        context_digest: context.digest,
        composition_context_digest,
        batch_anchor_digest,
        map_set_digest,
        governed_batch_digest,
        fold_history_digest,
        terminal_instance_digest,
        proof_digest,
        digest: [0; 32],
    };
    let mut frame = Vec::with_capacity(256);
    frame.extend_from_slice(PHASE3_RECEIPT_DOMAIN_V1);
    frame.push(receipt.version);
    frame.extend_from_slice(&receipt.context_digest);
    frame.extend_from_slice(&receipt.composition_context_digest);
    frame.extend_from_slice(&receipt.batch_anchor_digest);
    frame.extend_from_slice(&receipt.map_set_digest);
    frame.extend_from_slice(&receipt.governed_batch_digest);
    frame.extend_from_slice(&receipt.fold_history_digest);
    frame.extend_from_slice(&receipt.terminal_instance_digest);
    frame.extend_from_slice(&receipt.proof_digest);
    receipt.digest = keccak256(&frame);
    Ok(receipt)
}
#[cfg(test)]
fn commitment_digest(commitment: &Commitment) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    commitment
        .transcript_bytes()
        .map(|bytes| keccak256(&bytes))
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)
}
#[cfg(test)]
fn commitment_to_wire(commitment: &Commitment) -> Result<Vec<VegaPointWireV1>, ZkAmsMkheErrorV1> {
    commitment
        .points()
        .iter()
        .copied()
        .map(|point| {
            VegaPointWireV1::from_point(point).map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)
        })
        .collect()
}
#[cfg(test)]
fn commitment_from_wire(points: &[VegaPointWireV1]) -> Result<Commitment, ZkAmsMkheErrorV1> {
    Commitment::from_points(
        points
            .iter()
            .copied()
            .map(|point| {
                point
                    .to_point()
                    .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
}
#[cfg(test)]
fn scalar_from_wire(value: VegaScalarWireV1) -> Result<Scalar, ZkAmsMkheErrorV1> {
    value
        .to_scalar()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
}
#[cfg(test)]
fn scalars_from_wire(values: &[VegaScalarWireV1]) -> Result<Vec<Scalar>, ZkAmsMkheErrorV1> {
    values.iter().copied().map(scalar_from_wire).collect()
}
#[cfg(test)]
fn commitment_rows(length: usize, columns: usize) -> Result<usize, ZkAmsMkheErrorV1> {
    if length == 0 || columns == 0 {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(length.div_ceil(columns))
}
#[cfg(test)]
fn usize_to_u32(value: usize) -> Result<u32, ZkAmsMkheErrorV1> {
    u32::try_from(value).map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::{
        circuit::CircuitAssignment,
        masked_relaxed::{
            MaskedRelaxedRandomErrorV1, MaskedRelaxedRandomSourceV1, MaskedRelaxedStreamConfigV1,
            precompute_masked_relaxed_stream_v1,
        },
        zk_ams::mkhe::phase23_encrypted::ZkAmsPhase23AccumulatorShapeV1,
    };
    use std::{
        collections::BTreeSet,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::OnceLock,
    };
    const TEST_ROWS: usize = MASKED_RELAXED_COMMITMENT_COLUMNS_V1;
    #[derive(Clone)]
    struct KatRandom {
        seed: [u8; 32],
        counter: u64,
    }
    impl KatRandom {
        fn new() -> Self {
            Self {
                seed: keccak256(b"iroha.zk-ams.v1.phase3.full-history-test-random"),
                counter: 0,
            }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for KatRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            for (chunk_index, chunk) in destination.chunks_mut(32).enumerate() {
                let mut frame = Vec::with_capacity(48);
                frame.extend_from_slice(&self.seed);
                frame.extend_from_slice(&self.counter.to_be_bytes());
                frame.extend_from_slice(&(chunk_index as u64).to_be_bytes());
                let block = keccak256(&frame);
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
            self.counter = self.counter.wrapping_add(1);
            Ok(())
        }
    }
    #[derive(Clone)]
    struct Fixture {
        maps: [ZkAmsPhase23SparseMapV1; 3],
        shape: Arc<Shape>,
        proof_context: super::super::super::ZkAmsProofContextV1<'static>,
        context: ZkAmsPhase3TerminalContextV1,
        governed: ZkAmsPhase3GovernedBatchV1,
        history: ZkAmsPhase3FoldHistoryV1,
        materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
        output: ZkAmsPhase3TerminalProverOutputV1,
    }
    fn s(value: u64) -> Scalar {
        Scalar::from_u64(value)
    }
    fn map_refs(maps: &[ZkAmsPhase23SparseMapV1; 3]) -> [&ZkAmsPhase23SparseMapV1; 3] {
        [&maps[0], &maps[1], &maps[2]]
    }
    fn external_relation<'a>(
        maps: &'a [ZkAmsPhase23SparseMapV1; 3],
        shape: &'a Shape,
    ) -> TerminalRelationSourceV1<'a> {
        TerminalRelationSourceV1::External {
            maps: map_refs(maps),
            expected_shape: shape,
        }
    }
    fn diagonal_map(kind: ZkAmsPhase23MapKindV1, columns: Vec<u32>) -> ZkAmsPhase23SparseMapV1 {
        ZkAmsPhase23SparseMapV1::new(
            kind,
            TEST_ROWS as u32,
            (TEST_ROWS + 2) as u32,
            1,
            (0..=TEST_ROWS as u32).collect(),
            columns,
            vec![Scalar::one().to_be_bytes(); TEST_ROWS],
        )
        .expect("canonical synthetic paper-order map")
    }
    fn test_maps() -> [ZkAmsPhase23SparseMapV1; 3] {
        [
            diagonal_map(ZkAmsPhase23MapKindV1::A, (0..TEST_ROWS as u32).collect()),
            // Paper order is W[0..TEST_ROWS], x, u.
            diagonal_map(
                ZkAmsPhase23MapKindV1::B,
                vec![(TEST_ROWS + 1) as u32; TEST_ROWS],
            ),
            diagonal_map(ZkAmsPhase23MapKindV1::C, vec![TEST_ROWS as u32; TEST_ROWS]),
        ]
    }
    fn strict_assignment(shape: &Arc<Shape>, public_input: u64) -> CircuitAssignment {
        let assignment = CircuitAssignment {
            shape: Arc::clone(shape),
            witness: vec![s(public_input); TEST_ROWS],
            public_inputs: vec![s(public_input)],
        };
        shape
            .validate_strict_assignment(&assignment.witness, &assignment.public_inputs)
            .expect("synthetic strict assignment satisfies W*u=u*x");
        assignment
    }
    fn proof_context() -> super::super::super::ZkAmsProofContextV1<'static> {
        super::super::super::ZkAmsProofContextV1 {
            chain_id: b"taira-zk-ams-terminal-test",
            genesis_hash: [0x11; 32],
            action_index: super::super::super::ZK_AMS_ACTION_INDEX_V1,
            statement_digest: [0x12; 32],
            parameter_id: [0x13; 32],
            parameter_digest: [0x14; 32],
            verifier_digest: [0x15; 32],
            statement_schema_digest: [0x16; 32],
            engine_manifest_digest: [0x17; 32],
            generator_digest: [0x18; 32],
        }
    }
    fn materialized_digest_for_test(
        materialized: &ZkAmsPhase23MaterializedAccumulatorsV1,
    ) -> [u8; 32] {
        let mut frame = Vec::new();
        frame.extend_from_slice(b"iroha.zk-ams.v1.phase23.materialized");
        frame.push(materialized.version);
        frame.extend_from_slice(&materialized.profile_digest);
        frame.extend_from_slice(&materialized.roster_digest);
        frame.extend_from_slice(&materialized.transcript_digest);
        frame.extend_from_slice(&materialized.batch_id);
        frame.extend_from_slice(&materialized.ordered_batch_input_digest);
        frame.push(materialized.fold_count);
        for length in [
            materialized.shape.x,
            1,
            materialized.shape.e,
            materialized.shape.r_e,
            materialized.shape.w,
            materialized.shape.r_w,
        ] {
            frame.extend_from_slice(&length.to_be_bytes());
        }
        for family in [
            materialized.x.as_slice(),
            materialized.u.as_slice(),
            materialized.e.as_slice(),
            materialized.r_e.as_slice(),
            materialized.w.as_slice(),
            materialized.r_w.as_slice(),
        ] {
            for value in family {
                frame.extend_from_slice(&value.to_be_bytes());
            }
        }
        keccak256(&frame)
    }
    fn reseal_materialized(
        mut materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
    ) -> ZkAmsPhase23MaterializedAccumulatorsV1 {
        materialized.digest = [0; 32];
        materialized.digest = materialized_digest_for_test(&materialized);
        materialized
    }
    fn reseal_anchor(mut anchor: ZkAmsPhase3BatchAnchorV1) -> ZkAmsPhase3BatchAnchorV1 {
        anchor.digest = [0; 32];
        anchor.digest = batch_anchor_digest(&anchor).expect("bounded anchor digest");
        anchor
    }
    fn reseal_history(mut history: ZkAmsPhase3FoldHistoryV1) -> ZkAmsPhase3FoldHistoryV1 {
        history.digest = [0; 32];
        history.digest = fold_history_digest(&history).expect("bounded fold-history digest");
        history
    }
    fn reseal_governed(mut governed: ZkAmsPhase3GovernedBatchV1) -> ZkAmsPhase3GovernedBatchV1 {
        governed.digest = [0; 32];
        governed.digest = governed_batch_digest(&governed).expect("bounded governed digest");
        governed
    }
    fn reseal_context(mut context: ZkAmsPhase3TerminalContextV1) -> ZkAmsPhase3TerminalContextV1 {
        context.digest = terminal_context_digest(context);
        context
    }
    fn build_fixture() -> Fixture {
        let maps = test_maps();
        let shape = Arc::new(
            shape_from_paper_order_maps(map_refs(&maps), TEST_ROWS, 1)
                .expect("synthetic terminal shape"),
        );
        let profile = build_terminal_profile(external_relation(&maps, &shape))
            .expect("synthetic terminal profile");
        let strict_public_inputs = vec![vec![s(3)], vec![s(4)]];
        let governed_bytes = strict_public_inputs
            .iter()
            .map(|public_inputs| {
                public_inputs
                    .iter()
                    .copied()
                    .map(Scalar::to_be_bytes)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let ordered_digest =
            zk_ams_phase3_ordered_public_inputs_digest_v1(&governed_bytes).unwrap();
        let context = ZkAmsPhase3TerminalContextV1::new(
            [0x21; 32],
            [0x22; 32],
            7,
            [0x23; 32],
            [0x24; 32],
            ordered_digest,
            profile.nifs_verifier_digest,
        )
        .expect("terminal context");
        let governed = ZkAmsPhase3GovernedBatchV1::new(context, governed_bytes)
            .expect("governed strict inputs");
        let proof_context = proof_context();
        let context_frame = terminal_composition_context_frame(&proof_context, context, &governed)
            .expect("canonical terminal composition context frame");
        let strict_values = [3_u64, 4];
        let precomputation = precompute_masked_relaxed_stream_v1(
            MaskedRelaxedStreamConfigV1::new(
                super::super::super::COMPOSITION_DOMAIN_V1,
                &context_frame,
                super::super::super::COMMITMENT_KEY_LABEL_V1,
                Arc::clone(&shape),
                &strict_public_inputs,
                1,
            ),
            |index| Ok(strict_assignment(&shape, strict_values[index])),
            &mut KatRandom::new(),
        )
        .expect("canonical masked Nova precomputation");
        let mask = batch_anchor_from_instance(context, &precomputation.mask_instance)
            .expect("public mask anchor");
        let strict_witness_commitments = precomputation
            .strict_instances
            .iter()
            .map(|instance| commitment_to_wire(&instance.witness_commitment))
            .collect::<Result<Vec<_>, _>>()
            .expect("strict commitment wires");
        let cross_term_commitments = precomputation
            .folds
            .iter()
            .map(|fold| commitment_to_wire(&fold.cross_term_commitment))
            .collect::<Result<Vec<_>, _>>()
            .expect("cross-term commitment wires");
        let history = ZkAmsPhase3FoldHistoryV1::new(
            context,
            mask,
            strict_witness_commitments,
            cross_term_commitments,
        )
        .expect("complete public fold history");
        let fold_count = precomputation.strict_instances.len() as u8;
        let (instance, witness) = precomputation.into_folded_opening();
        let RelaxedInstance {
            public_inputs,
            relaxation,
            ..
        } = instance;
        let RelaxedWitness {
            values,
            witness_blindings,
            error,
            error_blindings,
        } = witness;
        let materialized = reseal_materialized(ZkAmsPhase23MaterializedAccumulatorsV1 {
            version: 1,
            profile_digest: context.profile_digest,
            roster_digest: context.roster_digest,
            transcript_digest: context.transcript_digest,
            batch_id: context.batch_id,
            ordered_batch_input_digest: context.ordered_batch_input_digest,
            fold_count,
            shape: ZkAmsPhase23AccumulatorShapeV1::new(1, TEST_ROWS as u32, 1, TEST_ROWS as u32, 1)
                .expect("synthetic accumulator shape"),
            x: public_inputs,
            u: vec![relaxation],
            e: error,
            r_e: error_blindings,
            w: values,
            r_w: witness_blindings,
            digest: [0; 32],
        });
        let output = prove_terminal_inner(
            &proof_context,
            context,
            &governed,
            &history,
            materialized.clone(),
            external_relation(&maps, &shape),
        )
        .expect("full-history terminal proof");
        Fixture {
            maps,
            shape,
            proof_context,
            context,
            governed,
            history,
            materialized,
            output,
        }
    }
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(build_fixture)
    }
    impl Fixture {
        fn verify(
            &self,
            proof_context: &super::super::super::ZkAmsProofContextV1<'_>,
            context: ZkAmsPhase3TerminalContextV1,
            governed: &ZkAmsPhase3GovernedBatchV1,
            anchor: &ZkAmsPhase3BatchAnchorV1,
            proof: &[u8],
        ) -> Result<ZkAmsPhase3TerminalReceiptV1, ZkAmsMkheErrorV1> {
            verify_terminal_inner(
                proof_context,
                context,
                governed,
                anchor,
                external_relation(&self.maps, &self.shape),
                proof,
            )
        }
        fn prove_with(
            &self,
            governed: &ZkAmsPhase3GovernedBatchV1,
            history: &ZkAmsPhase3FoldHistoryV1,
            materialized: ZkAmsPhase23MaterializedAccumulatorsV1,
        ) -> Result<ZkAmsPhase3TerminalProverOutputV1, ZkAmsMkheErrorV1> {
            prove_terminal_inner(
                &self.proof_context,
                self.context,
                governed,
                history,
                materialized,
                external_relation(&self.maps, &self.shape),
            )
        }
    }
    #[test]
    fn complete_history_proves_exact_final_anchor_on_the_standard_core_wire() {
        let fixture = fixture();
        let receipt = fixture
            .verify(
                &fixture.proof_context,
                fixture.context,
                &fixture.governed,
                &fixture.output.batch_anchor,
                &fixture.output.proof_bytes,
            )
            .expect("settlement verifies full public history and final anchor");
        let relation = super::super::super::decode_zk_ams_admission_relation_wire_v1(
            fixture.governed.strict_public_inputs.len(),
            &fixture.output.proof_bytes,
        )
        .expect("exact standard admission proof wire");
        assert_eq!(
            super::super::super::encode_zk_ams_admission_relation_wire_v1(relation.clone())
                .unwrap(),
            fixture.output.proof_bytes
        );
        assert_eq!(
            relation.strict_instance_count, 2,
            "the proof contains exactly the two governed folds"
        );
        assert_eq!(
            fold_history_digest_from_proof(fixture.context, &relation, &fixture.shape).unwrap(),
            fixture.history.digest
        );
        assert_eq!(receipt.context_digest(), fixture.context.digest);
        assert_eq!(receipt.version(), PHASE3_TERMINAL_VERSION_V1);
        assert_eq!(
            receipt.map_set_digest(),
            build_terminal_profile(external_relation(&fixture.maps, &fixture.shape))
                .unwrap()
                .map_set_digest
        );
        assert_eq!(
            receipt.composition_context_digest(),
            keccak256(
                &terminal_composition_context_frame(
                    &fixture.proof_context,
                    fixture.context,
                    &fixture.governed,
                )
                .unwrap()
            )
        );
        assert_eq!(
            receipt.batch_anchor_digest(),
            fixture.output.batch_anchor.digest
        );
        assert_eq!(receipt.governed_batch_digest(), fixture.governed.digest);
        assert_eq!(receipt.fold_history_digest(), fixture.history.digest);
        assert_eq!(
            receipt.proof_digest(),
            terminal_proof_bytes_digest(&fixture.output.proof_bytes)
        );
        assert_ne!(receipt.terminal_instance_digest(), [0; 32]);
        assert_ne!(receipt.digest(), [0; 32]);
        let implementation = zk_ams_phase3_terminal_implementation_v1();
        assert_eq!(
            implementation.max_proof_bytes as usize,
            super::super::super::MAX_ZK_AMS_ADMISSION_RELATION_PROOF_BYTES_V1
        );
        assert!(!implementation.release_kat_complete);
        assert_eq!(implementation.release_kat_digest, [0; 32]);
        // Public release entrypoints cannot bypass the common readiness gate.
        assert_eq!(
            prove_zk_ams_phase3_terminal_v1(
                &fixture.proof_context,
                fixture.context,
                &fixture.governed,
                &fixture.history,
                fixture.materialized.clone(),
            ),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
        assert_eq!(
            verify_zk_ams_phase3_terminal_v1(
                &fixture.proof_context,
                fixture.context,
                &fixture.governed,
                &fixture.output.batch_anchor,
                &fixture.output.proof_bytes,
            ),
            Err(ZkAmsMkheErrorV1::ReleaseUnavailable)
        );
    }
    #[test]
    fn terminal_consumed_witness_owners_zeroize_success_error_and_unwind() {
        let before_scalar_success = terminal_scalar_vec_zeroized_drop_count_v1();
        drop(ZeroizingTerminalScalarVecV1::new(vec![s(7)]));
        assert_eq!(
            terminal_scalar_vec_zeroized_drop_count_v1(),
            before_scalar_success + 1
        );
        fn reject_scalars(_values: ZeroizingTerminalScalarVecV1) -> Result<(), ZkAmsMkheErrorV1> {
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        }
        let before_scalar_error = terminal_scalar_vec_zeroized_drop_count_v1();
        assert_eq!(
            reject_scalars(ZeroizingTerminalScalarVecV1::new(vec![s(7)])),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
        assert_eq!(
            terminal_scalar_vec_zeroized_drop_count_v1(),
            before_scalar_error + 1
        );
        let before_scalar_unwind = terminal_scalar_vec_zeroized_drop_count_v1();
        let scalar_unwind = catch_unwind(AssertUnwindSafe(|| {
            let _owner = ZeroizingTerminalScalarVecV1::new(vec![s(9)]);
            panic!("intentional terminal scalar erasure audit");
        }));
        assert!(scalar_unwind.is_err());
        assert_eq!(
            terminal_scalar_vec_zeroized_drop_count_v1(),
            before_scalar_unwind + 1
        );
        let witness_owner = || {
            ZeroizingTerminalRelaxedWitnessV1::new(RelaxedWitness {
                values: vec![s(3)],
                witness_blindings: vec![s(4)],
                error: vec![s(5)],
                error_blindings: vec![s(6)],
            })
        };
        let before_witness_success = terminal_relaxed_witness_zeroized_drop_count_v1();
        drop(witness_owner());
        assert_eq!(
            terminal_relaxed_witness_zeroized_drop_count_v1(),
            before_witness_success + 1
        );
        fn reject_witness(
            _witness: ZeroizingTerminalRelaxedWitnessV1,
        ) -> Result<(), ZkAmsMkheErrorV1> {
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        }
        let before_witness_error = terminal_relaxed_witness_zeroized_drop_count_v1();
        assert_eq!(
            reject_witness(witness_owner()),
            Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
        );
        assert_eq!(
            terminal_relaxed_witness_zeroized_drop_count_v1(),
            before_witness_error + 1
        );
        let before_witness_unwind = terminal_relaxed_witness_zeroized_drop_count_v1();
        let witness_unwind = catch_unwind(AssertUnwindSafe(|| {
            let _witness = witness_owner();
            panic!("intentional terminal folded-witness erasure audit");
        }));
        assert!(witness_unwind.is_err());
        assert_eq!(
            terminal_relaxed_witness_zeroized_drop_count_v1(),
            before_witness_unwind + 1
        );
    }
    #[test]
    fn prepared_terminal_materialization_is_equation_checked_borrowed_and_context_bound() {
        let fixture = fixture();
        let profile = build_terminal_profile(external_relation(&fixture.maps, &fixture.shape))
            .expect("synthetic terminal profile");
        let prepared = verify_native_materialized_opening_v1(
            fixture.context,
            fixture.materialized.clone(),
            &profile,
            false,
        )
        .expect("valid relaxed assignment and both Hyrax openings");
        {
            let openings = prepared
                .openings_for_cross_basis_v1(fixture.context)
                .expect("exact prepared rows borrow under their context");
            assert_eq!(openings.context_digest_v1(), fixture.context.digest);
            assert_eq!(
                openings.materialized_digest_v1(),
                fixture.materialized.digest
            );
            assert_eq!(openings.error_values_v1(), fixture.materialized.e);
            assert_eq!(openings.error_blindings_v1(), fixture.materialized.r_e);
            assert_eq!(openings.witness_values_v1(), fixture.materialized.w);
            assert_eq!(openings.witness_blindings_v1(), fixture.materialized.r_w);
            assert_eq!(
                openings.error_commitment_v1().len(),
                fixture.materialized.r_e.len()
            );
            assert_eq!(
                openings.witness_commitment_v1().len(),
                fixture.materialized.r_w.len()
            );
        }
        let (instance, witness) = prepared
            .consume_for_terminal_v1(fixture.context)
            .expect("exact checked artifact consumes the capability");
        assert_eq!(
            batch_anchor_from_instance(fixture.context, &instance).unwrap(),
            fixture.output.batch_anchor
        );
        assert_eq!(witness.as_ref().values.len(), fixture.materialized.w.len());
        assert_eq!(witness.as_ref().error.len(), fixture.materialized.e.len());
        let prepared = verify_native_materialized_opening_v1(
            fixture.context,
            fixture.materialized.clone(),
            &profile,
            false,
        )
        .unwrap();
        let mut wrong_context = fixture.context;
        wrong_context.digest[0] ^= 1;
        assert!(prepared.openings_for_cross_basis_v1(wrong_context).is_err());
        assert!(prepared.consume_for_terminal_v1(wrong_context).is_err());
        let mut wrong_materialized = fixture.materialized.clone();
        wrong_materialized.digest[0] ^= 1;
        assert!(
            verify_native_materialized_opening_v1(
                fixture.context,
                wrong_materialized,
                &profile,
                false,
            )
            .is_err()
        );
        let mut wrong_profile =
            build_terminal_profile(external_relation(&fixture.maps, &fixture.shape)).unwrap();
        wrong_profile.nifs_verifier_digest[0] ^= 1;
        assert!(
            verify_native_materialized_opening_v1(
                fixture.context,
                fixture.materialized.clone(),
                &wrong_profile,
                false,
            )
            .is_err()
        );
    }
    #[test]
    fn canonical_wire_rejects_truncation_trailing_oversize_and_adversarial_mutations() {
        let fixture = fixture();
        let proof = &fixture.output.proof_bytes;
        let mut truncations = BTreeSet::new();
        truncations.extend(0..proof.len().min(128));
        truncations.extend(proof.len().saturating_sub(128)..proof.len());
        truncations.extend([proof.len() / 4, proof.len() / 2, proof.len() * 3 / 4]);
        for end in truncations {
            assert!(
                fixture
                    .verify(
                        &fixture.proof_context,
                        fixture.context,
                        &fixture.governed,
                        &fixture.output.batch_anchor,
                        &proof[..end],
                    )
                    .is_err(),
                "truncation at {end} unexpectedly verified"
            );
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(
            fixture
                .verify(
                    &fixture.proof_context,
                    fixture.context,
                    &fixture.governed,
                    &fixture.output.batch_anchor,
                    &trailing,
                )
                .is_err()
        );
        assert_eq!(
            fixture.verify(
                &fixture.proof_context,
                fixture.context,
                &fixture.governed,
                &fixture.output.batch_anchor,
                &vec![0; ZK_AMS_PHASE3_MAX_TERMINAL_PROOF_BYTES_V1 + 1],
            ),
            Err(ZkAmsMkheErrorV1::WireTooLarge)
        );
        let baseline =
            super::super::super::decode_zk_ams_admission_relation_wire_v1(2, proof).unwrap();
        let assert_rejected = |relation: MaskedRelaxedProofWireV1, label: &str| {
            let changed = super::super::super::encode_zk_ams_admission_relation_wire_v1(relation)
                .expect("bounded mutated wire");
            assert!(
                fixture
                    .verify(
                        &fixture.proof_context,
                        fixture.context,
                        &fixture.governed,
                        &fixture.output.batch_anchor,
                        &changed,
                    )
                    .is_err(),
                "{label} unexpectedly verified"
            );
        };
        let mut changed = baseline.clone();
        changed.strict_instance_count = 1;
        assert_rejected(changed, "false strict count");
        let mut changed = baseline.clone();
        changed.strict_witness_commitments.pop();
        assert_rejected(changed, "missing strict commitment");
        let mut changed = baseline.clone();
        changed.cross_term_commitments[0] = changed.cross_term_commitments[1].clone();
        assert_rejected(changed, "substituted cross term");
        let mut changed = baseline.clone();
        let relaxation = scalar_from_wire(changed.mask_relaxation).unwrap();
        changed.mask_relaxation = VegaScalarWireV1::from_scalar(relaxation + Scalar::one());
        assert_rejected(changed, "post-transcript public-mask mutation");
        let mut changed = baseline.clone();
        changed.outer_claims[0] = VegaScalarWireV1::from_raw_bytes_for_test([0xff; 32]);
        assert_rejected(changed, "noncanonical scalar");
        let mut changed = baseline;
        changed.witness_opening.clear();
        assert_rejected(changed, "post-transcript Spartan-opening removal");
    }
    #[test]
    fn governed_inputs_history_core_context_and_final_anchor_are_exact() {
        let fixture = fixture();
        let mut governed = fixture.governed.clone();
        governed.strict_public_inputs.swap(0, 1);
        governed = reseal_governed(governed);
        assert!(
            fixture
                .verify(
                    &fixture.proof_context,
                    fixture.context,
                    &governed,
                    &fixture.output.batch_anchor,
                    &fixture.output.proof_bytes,
                )
                .is_err()
        );
        let mut governed = fixture.governed.clone();
        governed.strict_public_inputs[0][0] = VegaScalarWireV1::from_scalar(s(9));
        governed = reseal_governed(governed);
        assert!(
            fixture
                .verify(
                    &fixture.proof_context,
                    fixture.context,
                    &governed,
                    &fixture.output.batch_anchor,
                    &fixture.output.proof_bytes,
                )
                .is_err()
        );
        for mutation in 0..5 {
            let mut history = fixture.history.clone();
            match mutation {
                0 => history.strict_witness_commitments.swap(0, 1),
                1 => history.cross_term_commitments.swap(0, 1),
                2 => history
                    .strict_witness_commitments
                    .pop()
                    .map(drop)
                    .unwrap_or(()),
                3 => {
                    let value = scalar_from_wire(history.mask.relaxation).unwrap();
                    history.mask.relaxation = VegaScalarWireV1::from_scalar(value + Scalar::one());
                    history.mask = reseal_anchor(history.mask);
                }
                4 => history.context_digest[0] ^= 1,
                _ => unreachable!(),
            }
            if mutation == 2 {
                // The canonical digest encoder rejects a missing commitment
                // before it can be resealed. The prover must reject the same
                // malformed history as well.
                assert_eq!(
                    fold_history_digest(&history),
                    Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
                );
            } else {
                history = reseal_history(history);
            }
            assert!(
                fixture
                    .prove_with(&fixture.governed, &history, fixture.materialized.clone())
                    .is_err(),
                "history mutation {mutation} reached a proof"
            );
        }
        for mutation in 0..6 {
            let mut anchor = fixture.output.batch_anchor.clone();
            match mutation {
                0 => anchor.version += 1,
                1 => anchor.context_digest[0] ^= 1,
                2 => anchor.witness_commitment = anchor.error_commitment.clone(),
                3 => anchor.relaxation = VegaScalarWireV1::from_scalar(s(9)),
                4 => anchor.public_inputs[0] = VegaScalarWireV1::from_scalar(s(9)),
                5 => anchor.digest[0] ^= 1,
                _ => unreachable!(),
            }
            if mutation != 5 {
                anchor = reseal_anchor(anchor);
            }
            assert!(
                fixture
                    .verify(
                        &fixture.proof_context,
                        fixture.context,
                        &fixture.governed,
                        &anchor,
                        &fixture.output.proof_bytes,
                    )
                    .is_err(),
                "final anchor mutation {mutation} unexpectedly verified"
            );
        }
        for mutation in 0..9 {
            let mut proof_context = fixture.proof_context;
            match mutation {
                0 => proof_context.chain_id = b"other-chain",
                1 => proof_context.genesis_hash[0] ^= 1,
                2 => proof_context.statement_digest[0] ^= 1,
                3 => proof_context.parameter_id[0] ^= 1,
                4 => proof_context.parameter_digest[0] ^= 1,
                5 => proof_context.verifier_digest[0] ^= 1,
                6 => proof_context.statement_schema_digest[0] ^= 1,
                7 => proof_context.engine_manifest_digest[0] ^= 1,
                8 => proof_context.generator_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                fixture
                    .verify(
                        &proof_context,
                        fixture.context,
                        &fixture.governed,
                        &fixture.output.batch_anchor,
                        &fixture.output.proof_bytes,
                    )
                    .is_err(),
                "core context mutation {mutation} unexpectedly verified"
            );
        }
        let mut invalid_action = fixture.proof_context;
        invalid_action.action_index = 1;
        assert!(
            fixture
                .verify(
                    &invalid_action,
                    fixture.context,
                    &fixture.governed,
                    &fixture.output.batch_anchor,
                    &fixture.output.proof_bytes,
                )
                .is_err()
        );
        for mutation in 0..7 {
            let mut context = fixture.context;
            match mutation {
                0 => context.profile_digest[0] ^= 1,
                1 => context.roster_digest[0] ^= 1,
                2 => context.epoch += 1,
                3 => context.transcript_digest[0] ^= 1,
                4 => context.batch_id[0] ^= 1,
                5 => context.ordered_batch_input_digest[0] ^= 1,
                6 => context.nifs_verifier_digest[0] ^= 1,
                _ => unreachable!(),
            }
            // A stale digest is always rejected before proof replay.
            assert!(
                fixture
                    .verify(
                        &fixture.proof_context,
                        context,
                        &fixture.governed,
                        &fixture.output.batch_anchor,
                        &fixture.output.proof_bytes,
                    )
                    .is_err(),
                "unsealed terminal context mutation {mutation} unexpectedly verified"
            );
        }
        // Recompute every wrapper digest so these cases reach proof replay.
        // The original proof must still fail because the terminal transcript
        // commits the exact roster, epoch, transcript, and batch identities.
        for mutation in 0..4 {
            let mut context = fixture.context;
            match mutation {
                0 => context.roster_digest[0] ^= 1,
                1 => context.epoch += 1,
                2 => context.transcript_digest[0] ^= 1,
                3 => context.batch_id[0] ^= 1,
                _ => unreachable!(),
            }
            context = reseal_context(context);
            let mut governed = fixture.governed.clone();
            governed.context_digest = context.digest;
            governed = reseal_governed(governed);
            let mut anchor = fixture.output.batch_anchor.clone();
            anchor.context_digest = context.digest;
            anchor = reseal_anchor(anchor);
            assert!(
                fixture
                    .verify(
                        &fixture.proof_context,
                        context,
                        &governed,
                        &anchor,
                        &fixture.output.proof_bytes,
                    )
                    .is_err(),
                "resealed terminal transcript mutation {mutation} unexpectedly verified"
            );
        }
    }
    #[test]
    fn prover_rejects_every_bad_materialized_family_metadata_and_fold_count() {
        let fixture = fixture();
        for mutation in 0..15 {
            let mut materialized = fixture.materialized.clone();
            match mutation {
                0 => materialized.x[0] = s(9),
                1 => materialized.u[0] = s(9),
                2 => materialized.e[0] = s(9),
                3 => materialized.r_e[0] = s(9),
                4 => materialized.w[0] = s(9),
                5 => materialized.r_w[0] = s(9),
                6 => materialized.u.clear(),
                7 => {
                    materialized.w.pop();
                }
                8 => materialized.shape.x = 2,
                9 => materialized.fold_count = 1,
                10 => materialized.profile_digest[0] ^= 1,
                11 => materialized.roster_digest[0] ^= 1,
                12 => materialized.transcript_digest[0] ^= 1,
                13 => materialized.batch_id[0] ^= 1,
                14 => materialized.ordered_batch_input_digest[0] ^= 1,
                _ => unreachable!(),
            }
            materialized = reseal_materialized(materialized);
            assert!(
                fixture
                    .prove_with(&fixture.governed, &fixture.history, materialized)
                    .is_err(),
                "materialized mutation {mutation} reached a proof"
            );
        }
    }
    #[test]
    fn hostile_nested_dimensions_fail_before_structured_digest_clone_entry() {
        let fixture = fixture();
        let scalar = fixture.governed.strict_public_inputs[0][0];
        let witness_point = fixture.history.strict_witness_commitments[0][0];
        let error_point = fixture.history.cross_term_commitments[0][0];
        let mut governed = fixture.governed.clone();
        governed.strict_public_inputs[0] =
            vec![scalar; super::super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1 + 1];
        reset_terminal_structured_digest_entry_count_v1();
        assert!(governed_batch_digest(&governed).is_err());
        assert_eq!(terminal_structured_digest_entry_count_v1(), 0);
        let mut governed = fixture.governed.clone();
        governed.strict_public_inputs =
            vec![vec![scalar]; MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 + 1];
        reset_terminal_structured_digest_entry_count_v1();
        assert!(governed_batch_digest(&governed).is_err());
        assert_eq!(terminal_structured_digest_entry_count_v1(), 0);
        for mutation in 0..3 {
            let mut anchor = fixture.output.batch_anchor.clone();
            match mutation {
                0 => {
                    anchor.public_inputs =
                        vec![scalar; super::super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1 + 1];
                }
                1 => {
                    anchor.witness_commitment =
                        vec![witness_point; ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1 + 1];
                }
                2 => {
                    anchor.error_commitment =
                        vec![error_point; ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1 + 1];
                }
                _ => unreachable!(),
            }
            reset_terminal_structured_digest_entry_count_v1();
            assert!(batch_anchor_digest(&anchor).is_err());
            assert_eq!(
                terminal_structured_digest_entry_count_v1(),
                0,
                "oversized anchor mutation {mutation} entered digest cloning"
            );
        }
        for mutation in 0..3 {
            let mut history = fixture.history.clone();
            match mutation {
                0 => {
                    history.strict_witness_commitments =
                        vec![vec![witness_point]; MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 + 1];
                    history.cross_term_commitments =
                        vec![vec![error_point]; MAX_MASKED_RELAXED_STRICT_INSTANCES_V1 + 1];
                }
                1 => {
                    history.strict_witness_commitments[0] =
                        vec![witness_point; ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1 + 1];
                }
                2 => {
                    history.cross_term_commitments[0] =
                        vec![error_point; ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1 + 1];
                }
                _ => unreachable!(),
            }
            reset_terminal_structured_digest_entry_count_v1();
            assert!(fold_history_digest(&history).is_err());
            assert_eq!(
                terminal_structured_digest_entry_count_v1(),
                0,
                "oversized fold-history mutation {mutation} entered digest cloning"
            );
        }
        let mut bounded_wrong_anchor = fixture.output.batch_anchor.clone();
        bounded_wrong_anchor.witness_commitment.push(witness_point);
        reset_terminal_structured_digest_entry_count_v1();
        assert!(
            batch_anchor_to_instance(
                &bounded_wrong_anchor,
                fixture.context,
                &fixture.shape,
                MASKED_RELAXED_COMMITMENT_COLUMNS_V1,
            )
            .is_err()
        );
        assert_eq!(terminal_structured_digest_entry_count_v1(), 0);
        let mut bounded_wrong_governed = fixture.governed.clone();
        bounded_wrong_governed.strict_public_inputs[0].push(scalar);
        reset_terminal_structured_digest_entry_count_v1();
        assert!(
            validate_governed_batch(fixture.context, &bounded_wrong_governed, &fixture.shape,)
                .is_err()
        );
        assert_eq!(terminal_structured_digest_entry_count_v1(), 0);
        let mut relation = super::super::super::decode_zk_ams_admission_relation_wire_v1(
            fixture.governed.strict_public_inputs.len(),
            &fixture.output.proof_bytes,
        )
        .expect("bounded standard admission proof");
        relation.strict_witness_commitments[0].points =
            vec![witness_point; ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1 + 1];
        reset_terminal_structured_digest_entry_count_v1();
        assert!(
            fold_history_digest_from_proof(fixture.context, &relation, &fixture.shape).is_err()
        );
        assert_eq!(terminal_structured_digest_entry_count_v1(), 0);
    }
    #[test]
    fn count_map_and_constructor_boundaries_fail_closed() {
        let fixture = fixture();
        assert!(zk_ams_phase3_ordered_public_inputs_digest_v1(&[]).is_err());
        assert!(
            zk_ams_phase3_ordered_public_inputs_digest_v1(&vec![vec![s(1).to_be_bytes()]; 9])
                .is_err()
        );
        assert!(zk_ams_phase3_ordered_public_inputs_digest_v1(&[Vec::new()]).is_err());
        assert!(zk_ams_phase3_ordered_public_inputs_digest_v1(&[vec![[0xff; 32]]]).is_err());
        assert!(
            zk_ams_phase3_ordered_public_inputs_digest_v1(&[vec![
                s(1).to_be_bytes();
                super::super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1
            ]])
            .is_ok()
        );
        assert!(
            zk_ams_phase3_ordered_public_inputs_digest_v1(&[vec![
                s(1).to_be_bytes();
                super::super::super::ZK_AMS_ADMISSION_PUBLIC_INPUTS_V1
                    + 1
            ]])
            .is_err()
        );
        let mut missing = fixture.history.clone();
        missing.cross_term_commitments.pop();
        assert!(
            ZkAmsPhase3FoldHistoryV1::new(
                fixture.context,
                missing.mask,
                missing.strict_witness_commitments,
                missing.cross_term_commitments,
            )
            .is_err()
        );
        assert!(
            ZkAmsPhase3FoldHistoryV1::new(
                fixture.context,
                fixture.history.mask.clone(),
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
        let mut swapped = map_refs(&fixture.maps);
        swapped.swap(0, 1);
        assert!(
            verify_terminal_inner(
                &fixture.proof_context,
                fixture.context,
                &fixture.governed,
                &fixture.output.batch_anchor,
                TerminalRelationSourceV1::External {
                    maps: swapped,
                    expected_shape: &fixture.shape,
                },
                &fixture.output.proof_bytes,
            )
            .is_err()
        );
        for mutation in 0..3 {
            let mut malformed = fixture.maps.clone();
            match mutation {
                0 => malformed[0].row_offsets[1] = 2,
                1 => malformed[1].column_indices[1] = malformed[1].column_count,
                2 => malformed[2].digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                verify_terminal_inner(
                    &fixture.proof_context,
                    fixture.context,
                    &fixture.governed,
                    &fixture.output.batch_anchor,
                    external_relation(&malformed, &fixture.shape),
                    &fixture.output.proof_bytes,
                )
                .is_err(),
                "malformed map {mutation} unexpectedly verified"
            );
        }
        let mut wrong_context = fixture.context;
        wrong_context.epoch += 1;
        wrong_context = reseal_context(wrong_context);
        let exact_inputs = fixture
            .governed
            .strict_public_inputs
            .iter()
            .map(|inputs| {
                inputs
                    .iter()
                    .map(|input| scalar_from_wire(*input).unwrap().to_be_bytes())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(ZkAmsPhase3GovernedBatchV1::new(wrong_context, exact_inputs).is_ok());
        assert!(
            validate_governed_batch(
                fixture.context,
                &ZkAmsPhase3GovernedBatchV1::new(
                    wrong_context,
                    vec![vec![s(3).to_be_bytes()], vec![s(4).to_be_bytes()],]
                )
                .unwrap(),
                &fixture.shape,
            )
            .is_err()
        );
    }
    #[test]
    fn release_terminal_fast_path_uses_shared_shape_and_compact_manifest() {
        let source = include_str!("terminal.rs");
        let release_entrypoints = source
            .split("pub fn zk_ams_phase3_nifs_verifier_digest_v1")
            .nth(1)
            .and_then(|tail| tail.split("fn prove_terminal_inner").next())
            .expect("release terminal entrypoints");
        assert!(release_entrypoints.contains("TerminalRelationSourceV1::CanonicalRelease"));
        assert!(!release_entrypoints.contains("ZkAmsPhase23SparseMapV1"));
        assert!(!release_entrypoints.contains("release_maps_v1"));
        let profile_builder = source
            .split("fn build_terminal_profile")
            .nth(1)
            .and_then(|tail| tail.split("fn shape_from_paper_order_maps").next())
            .expect("terminal profile builder");
        assert!(profile_builder.contains("zk_ams_phase23_release_relation_v1"));
        assert!(profile_builder.contains("Arc::clone(relation.shape())"));
        assert!(profile_builder.contains("map_set_digest_from_manifest"));
    }
    #[test]
    fn prepared_terminal_hook_is_move_only_borrowed_and_error_then_witness_ordered() {
        let source = include_str!("terminal.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("terminal production source");
        let owner = production
            .split("pub(super) struct ZkAmsPhase3PreparedTerminalMaterializationV1")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl ZkAmsPhase3PreparedTerminalMaterializationV1")
                    .next()
            })
            .expect("prepared owner source");
        assert!(owner.contains("instance: RelaxedInstance"));
        assert!(owner.contains("witness: ZeroizingTerminalRelaxedWitnessV1"));
        assert!(!owner.contains("Vec<"));
        assert!(
            !production.contains("impl Clone for ZkAmsPhase3PreparedTerminalMaterializationV1")
        );
        let view = production
            .split("pub(super) struct ZkAmsPhase3PreparedTerminalOpeningsV1")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl<'a> ZkAmsPhase3PreparedTerminalOpeningsV1")
                    .next()
            })
            .expect("prepared borrowed view source");
        let error_offset = view.find("error_values:").expect("error rows");
        let witness_offset = view.find("witness_values:").expect("witness rows");
        assert!(error_offset < witness_offset);
        assert!(view.contains("&'a [Scalar]"));
        assert!(view.contains("&'a Commitment"));
        assert!(!view.contains("Vec<"));
        let borrow = production
            .split("pub(super) fn openings_for_cross_basis_v1")
            .nth(1)
            .and_then(|tail| tail.split("fn consume_for_terminal_v1").next())
            .expect("prepared borrow source");
        assert!(borrow.contains("self.validate_context_v1(context)?"));
        assert!(borrow.contains("error_values: &witness.error"));
        assert!(borrow.contains("witness_values: &witness.values"));
        assert!(borrow.contains("error_commitment: &self.instance.error_commitment"));
        assert!(borrow.contains("witness_commitment: &self.instance.witness_commitment"));
        assert!(!borrow.contains("core::mem::take"));
    }
    #[test]
    fn settlement_surface_and_standard_wire_never_carry_plaintext_families() {
        let source = include_str!("terminal.rs");
        let prover_start = source
            .find("pub fn prove_zk_ams_phase3_terminal_v1")
            .expect("public prover source");
        let prover_end = source[prover_start..]
            .find(" {")
            .map(|offset| prover_start + offset)
            .expect("public prover signature end");
        let prover_signature = &source[prover_start..prover_end];
        assert!(prover_signature.contains("materialized: ZkAmsPhase23MaterializedAccumulatorsV1"));
        assert!(
            !prover_signature.contains("materialized: &ZkAmsPhase23MaterializedAccumulatorsV1")
        );
        let native_opening = source
            .split("fn verify_native_materialized_opening_v1")
            .nth(1)
            .and_then(|tail| tail.split("fn terminal_proof_bytes_digest").next())
            .expect("native materialized opening source");
        assert!(native_opening.contains("core::mem::take(&mut materialized.x)"));
        assert!(!native_opening.contains("from_be_bytes_exact"));
        let verifier_start = source
            .find("pub fn verify_zk_ams_phase3_terminal_v1")
            .expect("public verifier source");
        let verifier_end = source[verifier_start..]
            .find(" {")
            .map(|offset| verifier_start + offset)
            .expect("public verifier signature end");
        let signature = &source[verifier_start..verifier_end];
        assert!(signature.contains("ZkAmsPhase3GovernedBatchV1"));
        assert!(signature.contains("ZkAmsPhase3BatchAnchorV1"));
        assert!(!signature.contains("Materialized"));
        assert!(!signature.contains("materialized"));
        let fixture = fixture();
        let mut public_wire = norito::codec::encode_adaptive(&fixture.output.batch_anchor);
        public_wire.extend_from_slice(&fixture.output.proof_bytes);
        let encode_scalars = |values: &[Scalar]| {
            values
                .iter()
                .flat_map(|value| value.to_be_bytes())
                .collect::<Vec<_>>()
        };
        let mut blinding_marker = encode_scalars(&fixture.materialized.r_e);
        blinding_marker.extend_from_slice(&encode_scalars(&fixture.materialized.r_w));
        let private_markers = [
            encode_scalars(&fixture.materialized.e),
            encode_scalars(&fixture.materialized.w),
            blinding_marker,
        ];
        for marker in private_markers {
            assert!(marker.len() >= 64);
            assert!(
                !public_wire
                    .windows(marker.len())
                    .any(|window| window == marker),
                "a raw private accumulator-family sequence crossed settlement"
            );
        }
    }
}
#[cfg(test)]
#[path = "terminal_release_kat.rs"]
mod release_kat_tests;
