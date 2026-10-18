//! Native-wallet custody and proving for one atomic private-settlement leg.
//!
//! The owner bundle defined here is an owner-only local file format. It is not
//! a network protocol and deliberately has no JSON representation. Public
//! callers receive only an opaque inspection plus the statement, encrypted
//! auditor capsule, and self-verified proof. Spending secrets and membership
//! paths are decoded only inside Rust and the consumed byte buffer is wiped on
//! every success or failure path.

use super::relation::{atomic_private_settlement_program_id_v1, internal_statement_v1};
use super::{
    facade::{AtomicPrivateSettlementProofErrorV1, prove_atomic_private_settlement_v1},
    relation::{
        AtomicPrivateSettlementInputWitnessV1, AtomicPrivateSettlementProverWitnessV1,
        atomic_private_settlement_audit_input_commitment_v1,
    },
};
use crate::privacy_engines::atomic_private_settlement::audit::private_settlement_audit_plaintext_commitment_v1;
#[cfg(any(test, feature = "test-utils"))]
use crate::privacy_engines::proof_managed_accumulator::plan_two_leaf_proof_managed_transition_v1;
use iroha_crypto::Hash;
use iroha_data_model::nexus::{
    ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1,
    PRIVATE_SETTLEMENT_INPUT_SLOTS_V1, PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1,
    PrivateSettlementAuditCapsuleV1, PrivateSettlementAuditPlaintextV1,
    PrivateSettlementAuditPolicyV1, PrivateSettlementCommitteeAuthorityV1,
    PrivateSettlementDeltaV1, PrivateSettlementProofIntentV1, PrivateSettlementProofStatementV1,
    PrivateSettlementProvisionalLegMaterialV1, PrivateSettlementSidecarAvailabilityBodyV1,
    private_settlement_proof_digest_v1,
};
use iroha_data_model::nexus::{
    PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1, PrivateSettlementAuditNoteOpeningV1,
    PrivateSettlementAuditOutputV1,
};
#[cfg(any(test, feature = "test-utils"))]
use iroha_data_model::privacy::{
    PrivacyCommitmentV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1,
    PrivacyPoolProgramNamespaceV1, PrivacyProtocolIdV1, PrivacyRootV1,
};
use iroha_data_model::privacy::{PrivacyEncryptedOutputV1, PrivacyNullifierV1};
use rand_core_06::CryptoRng;
use rand_core_06::RngCore;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::privacy_engines::ivm_private_note::PRIVATE_NOTE_TREE_DEPTH_V1;
use crate::privacy_engines::ivm_private_note::encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1;
use crate::privacy_engines::ivm_private_note::{
    PrivateNotePlaintextV1, PrivateNoteRelationProfileV1, derive_note_authority_v1,
    derive_note_nullifier_v1, derive_profiled_input_commitment_v1,
    derive_profiled_output_commitment_v1,
};

const OWNER_BUNDLE_MAGIC_V1: &[u8; 4] = b"APWB";
const OWNER_BUNDLE_VERSION_V1: u8 = 1;
const MAX_WALLET_ID_BYTES_V1: usize = 512;
const DIGEST_BYTES_V1: usize = Hash::LENGTH;

/// Hard local bound for one owner-only private-settlement witness bundle.
pub const ATOMIC_PRIVATE_SETTLEMENT_WALLET_BUNDLE_MAX_BYTES_V1: usize = 512 * 1_024;

/// One wallet-local input secret and its depth-32 membership witness.
///
/// This type intentionally implements neither `Clone`, `Debug`, Norito, nor
/// JSON traits. It exists solely to move secret material into the owner-only
/// bundle encoder or the native prover.
pub struct AtomicPrivateSettlementInputSecretV1 {
    spending_secret: [u8; 32],
    leaf_position: u32,
    authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
}

impl AtomicPrivateSettlementInputSecretV1 {
    /// Construct one non-serializable secret input.
    ///
    /// # Errors
    ///
    /// Rejects a zero spending secret or a path containing a reserved-zero
    /// sibling before owner-bundle construction.
    pub fn new(
        spending_secret: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
    ) -> Result<Self, AtomicPrivateSettlementWalletErrorV1> {
        if spending_secret.iter().all(|byte| *byte == 0)
            || authentication_path
                .iter()
                .any(|sibling| sibling.iter().all(|byte| *byte == 0))
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
        }
        Ok(Self {
            spending_secret,
            leaf_position,
            authentication_path,
        })
    }
}

impl Drop for AtomicPrivateSettlementInputSecretV1 {
    fn drop(&mut self) {
        self.spending_secret.zeroize();
        self.leaf_position = 0;
        self.authentication_path.zeroize();
    }
}

/// Public, non-secret inspection retained beside an opaque wallet handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicPrivateSettlementWalletInspectionV1 {
    /// Wallet-local identifier selected by the native owner application.
    pub wallet_id: String,
    /// Digest of the immutable bundle intent used by the proof transcript.
    pub proof_binding_digest: Hash,
    /// Digest of the exact public fixed-shape statement.
    pub statement_digest: Hash,
    /// Digest of the exact encrypted auditor capsule.
    pub capsule_digest: Hash,
    /// Commitment to the restricted auditor plaintext.
    pub audit_plaintext_commitment: Hash,
}

/// Public artifacts emitted by one terminal native proving operation.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementPreparedProofV1 {
    /// Exact fixed-shape public statement proved by `proof`.
    pub statement: PrivateSettlementProofStatementV1,
    /// Canonical self-verified private-settlement STARK proof.
    pub proof: Vec<u8>,
    /// Padded ciphertext decryptable only by governed local auditors.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
}

impl core::fmt::Debug for AtomicPrivateSettlementPreparedProofV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AtomicPrivateSettlementPreparedProofV1(<restricted>)")
    }
}

/// Public artifacts for one proof-complete leg and its fixed-shape state delta.
///
/// This remains a native client-side value: it contains restricted proof and
/// capsule bytes, but no spending secret, note opening, or membership path.
/// The delta is derived mechanically from the self-verified proof statement.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementPreparedLegV1 {
    /// Exact fixed-shape public statement proved by `proof`.
    pub statement: PrivateSettlementProofStatementV1,
    /// Canonical self-verified private-settlement STARK proof.
    pub proof: Vec<u8>,
    /// Fixed-shape opaque state transition committed by the committee.
    pub delta: PrivateSettlementDeltaV1,
    /// Padded ciphertext decryptable only by governed local auditors.
    pub audit_capsule: PrivateSettlementAuditCapsuleV1,
}

impl core::fmt::Debug for AtomicPrivateSettlementPreparedLegV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AtomicPrivateSettlementPreparedLegV1(<restricted>)")
    }
}

/// Complete one self-verified native proof into the canonical fixed-shape delta.
///
/// The proof statement already binds the successor root and epoch. Nodes still
/// derive and compare that successor frontier independently before Prepare.
/// This helper deliberately accepts no post-proof transition material.
///
/// # Errors
///
/// Rejects an invalid statement or proof size, a substituted capsule, an
/// canonical encoding failure, or any derived delta that does not exactly
/// match the proof statement.
pub fn complete_atomic_private_settlement_prepared_leg_v1(
    prepared: AtomicPrivateSettlementPreparedProofV1,
) -> Result<AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementWalletErrorV1> {
    let AtomicPrivateSettlementPreparedProofV1 {
        statement,
        proof,
        audit_capsule,
    } = prepared;
    statement
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    if proof.is_empty() || proof.len() > PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    let statement_digest = statement
        .digest()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let capsule_digest = audit_capsule
        .digest()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    if capsule_digest != statement.audit_capsule_digest {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    let delta = PrivateSettlementDeltaV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        bundle_id: statement.bundle_id,
        leg_ordinal: statement.leg_ordinal,
        route: statement.route,
        pool_id: statement.pool_id,
        asset_binding_commitment: statement.asset_binding_commitment,
        old_root: statement.old_root,
        new_root: statement.new_root,
        old_epoch: statement.old_epoch,
        new_epoch: statement.new_epoch,
        nullifiers: statement.nullifiers.clone(),
        output_commitments: statement.output_commitments.clone(),
        encrypted_outputs: statement.encrypted_outputs.clone(),
        statement_digest,
        proof_digest: private_settlement_proof_digest_v1(&proof),
        capsule_digest,
        audit_policy_digest: statement.audit_policy_digest,
        audit_key_epoch: statement.audit_key_epoch,
    };
    delta
        .validate_against(&statement)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    Ok(AtomicPrivateSettlementPreparedLegV1 {
        statement,
        proof,
        delta,
        audit_capsule,
    })
}

/// Governed material needed to content-address one proof-complete leg.
///
/// This is a native client-side construction value rather than a wire object.
/// Its private fields force callers through [`Self::new`], which rejects a
/// substituted policy, committee, proof, capsule, or retention boundary before
/// an all-leg manifest can be assembled.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementProvisionalLegInputV1 {
    prepared: AtomicPrivateSettlementPreparedLegV1,
    audit_policy: PrivateSettlementAuditPolicyV1,
    committee_authority: PrivateSettlementCommitteeAuthorityV1,
    retention_until_height: u64,
}

impl core::fmt::Debug for AtomicPrivateSettlementProvisionalLegInputV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AtomicPrivateSettlementProvisionalLegInputV1(<restricted>)")
    }
}

impl AtomicPrivateSettlementProvisionalLegInputV1 {
    /// Bind one proof-complete leg to its governed policy and exact committee.
    ///
    /// Committee proof-of-possession cryptography is intentionally rechecked by
    /// the receiving node. This local boundary validates the public committee
    /// shape and every statement, delta, proof, capsule, policy, and retention
    /// binding needed to construct the immutable sidecar content address.
    ///
    /// # Errors
    ///
    /// Rejects malformed or substituted restricted material.
    pub fn new(
        prepared: AtomicPrivateSettlementPreparedLegV1,
        audit_policy: PrivateSettlementAuditPolicyV1,
        committee_authority: PrivateSettlementCommitteeAuthorityV1,
        retention_until_height: u64,
    ) -> Result<Self, AtomicPrivateSettlementWalletErrorV1> {
        let input = Self {
            prepared,
            audit_policy,
            committee_authority,
            retention_until_height,
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
        let statement = &self.prepared.statement;
        statement
            .validate()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        if self.prepared.proof.is_empty()
            || self.prepared.proof.len() > PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
        }
        self.prepared
            .delta
            .validate_against(statement)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        self.audit_policy
            .validate()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        self.committee_authority
            .validate()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        self.prepared
            .audit_capsule
            .validate_against(&self.audit_policy)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;

        let authority_digest = self
            .committee_authority
            .digest()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        let capsule_digest = self
            .prepared
            .audit_capsule
            .digest()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        let aad = &self.prepared.audit_capsule.aad;
        let audit_plaintext_commitment = statement.audit_plaintext_commitment;
        if self.prepared.delta.proof_digest
            != private_settlement_proof_digest_v1(&self.prepared.proof)
            || capsule_digest != statement.audit_capsule_digest
            || self.committee_authority.route != statement.route
            || authority_digest != aad.authority_digest
            || self.audit_policy.body.dataspace_id != statement.route.dataspace_id
            || self.audit_policy.policy_digest != statement.audit_policy_digest
            || self.audit_policy.body.key_epoch != statement.audit_key_epoch
            || self.audit_policy.body.auditors.iter().any(|auditor| {
                self.committee_authority
                    .validators
                    .iter()
                    .any(|validator| validator.public_key() == &auditor.signing_key)
            })
            || !self
                .audit_policy
                .is_active_at(statement.authority_context_height)
            || self
                .audit_policy
                .body
                .retirement_height
                .is_some_and(|retirement| statement.expiry_height >= retirement)
            || aad.network_id != statement.network_id
            || aad.bundle_id != statement.bundle_id
            || aad.leg_ordinal != statement.leg_ordinal
            || aad.route != statement.route
            || aad.authority_context_height != statement.authority_context_height
            || aad.audit_policy_digest != statement.audit_policy_digest
            || aad.audit_key_epoch != statement.audit_key_epoch
            || aad.plaintext_commitment != audit_plaintext_commitment
            || self.retention_until_height < statement.expiry_height
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
        }
        Ok(())
    }
}

/// Canonical all-leg provisional manifest and its restricted sidecar materials.
///
/// Every material contains the same finalized provisional manifest. Only the
/// availability-certificate digests remain reserved zeroes; committees replace
/// those fields after independently persisting and certifying each sidecar.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementProvisionalBundleV1 {
    /// Exact manifest committed by every restricted sidecar.
    pub manifest: AtomicPrivateSettlementV1,
    /// One immutable sidecar material per canonical manifest leg.
    pub materials: Vec<PrivateSettlementProvisionalLegMaterialV1>,
}

impl core::fmt::Debug for AtomicPrivateSettlementProvisionalBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AtomicPrivateSettlementProvisionalBundleV1")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("participant_count", &self.materials.len())
            .finish_non_exhaustive()
    }
}

/// Consume exact public proof intent with actual proof-complete legs.
///
/// Real sidecar and delta commitments are computed before the provisional manifest exists.
/// No caller placeholder digest or incomplete full manifest crosses this boundary. Availability
/// certificates are obtained later over these immutable exact materials.
/// # Errors
/// Missing/reordered/cross-intent artifacts, incomplete proof or ciphertext, invalid authority,
/// non-canonical encoding, or original fixed sidecar bounds.
pub fn finalize_atomic_private_settlement_provisional_bundle_v1(
    intent: PrivateSettlementProofIntentV1,
    inputs: Vec<AtomicPrivateSettlementProvisionalLegInputV1>,
) -> Result<AtomicPrivateSettlementProvisionalBundleV1, AtomicPrivateSettlementWalletErrorV1> {
    use iroha_data_model::nexus::{
        PrivateSettlementLegCommitmentV1, private_settlement_sidecar_material_bytes_len_v1,
        private_settlement_sidecar_material_digest_v1,
    };
    intent
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    if inputs.len() != intent.legs.len() {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    let mut legs = Vec::with_capacity(inputs.len());
    let mut bodies = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        input.validate()?;
        let leg = &intent.legs[index];
        let prepared = &input.prepared;
        if usize::from(prepared.statement.leg_ordinal) != index {
            return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
        }
        super::relation::validate_public_binding_v1(
            &intent,
            &prepared.statement,
            *intent.network_id.as_genesis_hash().as_ref(),
            intent.authority_context_height,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        let payload_digest = private_settlement_sidecar_material_digest_v1(
            &prepared.statement,
            &prepared.proof,
            &prepared.delta,
            &prepared.audit_capsule,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        let payload_bytes = u32::try_from(
            private_settlement_sidecar_material_bytes_len_v1(
                &prepared.statement,
                &prepared.proof,
                &prepared.delta,
                &prepared.audit_capsule,
            )
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        let delta_digest = prepared
            .delta
            .digest()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        legs.push(PrivateSettlementLegCommitmentV1 {
            ordinal: leg.ordinal,
            route: leg.route,
            pool_id: leg.pool_id,
            asset_binding_commitment: leg.asset_binding_commitment,
            audit_policy_digest: leg.audit_policy_digest,
            payload_digest,
            delta_digest,
            availability_certificate_digest: Hash::prehashed([0; Hash::LENGTH]),
        });
        bodies.push(PrivateSettlementSidecarAvailabilityBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: intent.network_id,
            bundle_id: intent.bundle_id,
            leg_ordinal: leg.ordinal,
            route: leg.route,
            authority_digest: input
                .committee_authority
                .digest()
                .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?,
            authority_context_height: intent.authority_context_height,
            payload_digest,
            payload_bytes,
            retention_until_height: input.retention_until_height,
        });
    }
    let manifest = intent
        .bind_provisional_artifacts(legs)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let mut materials = Vec::with_capacity(inputs.len());
    for (input, availability_body) in inputs.into_iter().zip(bodies) {
        let material = PrivateSettlementProvisionalLegMaterialV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest: manifest.clone(),
            audit_policy: input.audit_policy,
            committee_authority: input.committee_authority,
            statement: input.prepared.statement,
            proof: input.prepared.proof,
            delta: input.prepared.delta,
            audit_capsule: input.prepared.audit_capsule,
            availability_body,
        };
        material
            .validate()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
        materials.push(material);
    }
    Ok(AtomicPrivateSettlementProvisionalBundleV1 {
        manifest,
        materials,
    })
}

/// Canonical origin and successor state for one newly governed settlement pool.
///
/// The membership witnesses remain encapsulated and can only be consumed into
/// the native owner-bundle encoder.  Public governance receives the sorted
/// origin commitments and roots, never the spending secrets or paths.
#[cfg(any(test, feature = "test-utils"))]
pub struct AtomicPrivateSettlementBootstrapPlanV1 {
    /// Strictly ordered commitments supplied to pool activation.
    pub initial_commitments: [PrivacyCommitmentV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    /// Root produced by the exact governed origin commitment set.
    pub old_root: PrivacyRootV1,
    /// Root after appending all three fixed output commitments in statement order.
    pub new_root: PrivacyRootV1,
    /// Epoch assigned to the governed origin root.
    pub old_epoch: u64,
    /// Epoch assigned to the derived successor root.
    pub new_epoch: u64,
    inputs: [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
}

#[cfg(any(test, feature = "test-utils"))]
impl AtomicPrivateSettlementBootstrapPlanV1 {
    /// Consume the plan into the owner-only input witnesses used by the bundle encoder.
    #[must_use]
    pub fn into_input_secrets(
        self,
    ) -> [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1] {
        self.inputs
    }
}

/// Stable, redacted native-wallet failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AtomicPrivateSettlementWalletErrorV1 {
    /// Owner-bundle framing, length, or canonical encoding is invalid.
    #[error("atomic private-settlement owner bundle is invalid")]
    InvalidBundle,
    /// The wallet identifier is malformed or differs from the opaque-handle binding.
    #[error("atomic private-settlement wallet binding is invalid")]
    WalletBinding,
    /// A public manifest, statement, policy, capsule, or digest was substituted.
    #[error("atomic private-settlement public binding is invalid")]
    PublicBinding,
    /// Secret material is zero, malformed, or does not control the committed note.
    #[error("atomic private-settlement secret material is invalid")]
    SecretMaterial,
    /// Native proving or its independent self-verification failed.
    #[error("atomic private-settlement native proof failed")]
    Proof(#[from] AtomicPrivateSettlementProofErrorV1),
}

fn validate_preparation_context_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    statement
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let leg = manifest
        .legs
        .get(usize::from(statement.leg_ordinal))
        .ok_or(AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    if statement.network_id != manifest.network_id
        || statement.bundle_id != manifest.bundle_id
        || statement.authority_context_height != manifest.authority_context_height
        || statement.route != leg.route
        || statement.pool_id != leg.pool_id
        || statement.asset_binding_commitment != leg.asset_binding_commitment
        || statement.audit_policy_digest != leg.audit_policy_digest
        || statement.fee_intent_digest != manifest.fee_intent_digest
        || statement.reimbursement_terms_commitment != manifest.reimbursement_terms_commitment
        || statement.reimbursement_leg_ordinal != manifest.reimbursement_leg_ordinal
        || statement.expiry_height != manifest.expiry_height
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    Ok(())
}

/// Derive a positive funding note before choosing a settlement bundle.
///
/// A funded input commitment is independent of the later bundle, authority
/// height and virtual dummy. This lets a wallet establish its pool first and
/// then prove a spend against an observed finalized authority context. The
/// caller supplies the spending-authority digest and retains its secret.
///
/// # Errors
///
/// Rejects inactive, zero-value or dummy openings and malformed note fields.
/// The opening remains unchanged on failure.
pub fn prepare_atomic_private_settlement_funding_note_v1(
    opening: &mut PrivateSettlementAuditNoteOpeningV1,
) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
    if !opening.active || opening.value == 0 || opening.dummy_domain.is_some() {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    let profile =
        PrivateNoteRelationProfileV1::exact_three_output_balanced([[1_u8; 32]; 3], [1; 32]);
    let note = PrivateNotePlaintextV1::new_profiled_input_v1(
        opening.value,
        opening.spending_authority,
        opening.rho,
        opening.blinding,
        opening.memo_digest,
        profile,
    )
    .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    let commitment = derive_profiled_input_commitment_v1(&note, profile)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    opening.commitment = commitment;
    Ok(())
}

/// Derive both fixed input commitments under the settlement-only note profile.
///
/// Inactive slots receive their unique bundle-bound dummy memo here.  Active
/// memo digests are owner-selected and retained.  The caller must have already
/// populated each spending-authority digest from its spending secret.
/// After this step, set the statement's `audit_input_commitment` with
/// [`atomic_private_settlement_audit_input_commitment_v1`] before deriving outputs.
///
/// # Errors
///
/// Rejects an invalid public context, fixed-slot shape, dummy domain, or note opening.
pub fn prepare_atomic_private_settlement_input_openings_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    openings: &mut [PrivateSettlementAuditNoteOpeningV1],
) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
    validate_preparation_context_v1(manifest, statement)?;
    prepare_input_openings_from_bound_context_v1(
        &manifest.proof_intent(),
        statement.leg_ordinal,
        openings,
    )
}

/// Derive the two stable pool/program nullifiers for prepared input openings.
///
/// # Errors
///
/// Rejects a substituted public context, wrong spending secret, malformed
/// opening, or duplicate nullifier.
pub fn derive_atomic_private_settlement_input_nullifiers_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    openings: &[PrivateSettlementAuditNoteOpeningV1],
    spending_secrets: &[[u8; 32]; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
) -> Result<
    [PrivacyNullifierV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    AtomicPrivateSettlementWalletErrorV1,
> {
    validate_preparation_context_v1(manifest, statement)?;
    let openings: &[PrivateSettlementAuditNoteOpeningV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1] =
        openings
            .try_into()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    let internal = internal_statement_v1(&manifest.proof_intent(), statement)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let mut nullifiers = [PrivacyNullifierV1::new([0_u8; 32]); PRIVATE_SETTLEMENT_INPUT_SLOTS_V1];
    for (index, (opening, secret)) in openings.iter().zip(spending_secrets).enumerate() {
        if derive_note_authority_v1(secret)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?
            != opening.spending_authority
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
        }
        nullifiers[index] =
            derive_note_nullifier_v1(&internal, secret, &opening.rho, opening.commitment)
                .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    }
    if nullifiers[0] == nullifiers[1] {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    Ok(nullifiers)
}

/// Finalize and encrypt the fixed recipient, change, and reimbursement outputs.
///
/// This operation derives the three role memos from the exact committed audit
/// plaintext, recomputes each commitment, and encrypts with fresh authenticated
/// nonces while retaining only the caller-supplied capsule opening.
///
/// # Errors
///
/// Rejects a substituted context, wrong fixed shape, malformed note/view key,
/// or unavailable/unsafe encryption randomness.
pub fn prepare_atomic_private_settlement_outputs_v1(
    rng: &mut (impl RngCore + CryptoRng),
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    outputs: &mut [PrivateSettlementAuditOutputV1],
) -> Result<Vec<PrivacyEncryptedOutputV1>, AtomicPrivateSettlementWalletErrorV1> {
    validate_preparation_context_v1(manifest, statement)?;
    prepare_outputs_from_bound_context_v1(rng, statement, outputs)
}

#[cfg(any(test, feature = "test-utils"))]
/// Build exact membership witnesses and the validator-derived successor root
/// for a newly activated two-note settlement pool.
///
/// # Errors
///
/// Rejects zero/duplicate commitments, reserved-zero spending secrets, or an
/// accumulator construction failure. Binding each
/// secret to its audit-opened commitment is performed by the owner-bundle
/// encoder once the corresponding openings are supplied.
pub fn plan_atomic_private_settlement_bootstrap_v1(
    pool_id: iroha_data_model::privacy::PrivacyPoolIdV1,
    input_commitments: [PrivacyCommitmentV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    output_commitments: [PrivacyCommitmentV1; PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1],
    input_spending_secrets: [[u8; 32]; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
) -> Result<AtomicPrivateSettlementBootstrapPlanV1, AtomicPrivateSettlementWalletErrorV1> {
    if pool_id.is_zero() {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    let namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
            pool_id,
            program_id: atomic_private_settlement_program_id_v1()
                .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?,
        }),
    );
    let planned = plan_two_leaf_proof_managed_transition_v1(
        namespace,
        input_commitments,
        &output_commitments,
    )
    .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    let inputs = [
        AtomicPrivateSettlementInputSecretV1::new(
            input_spending_secrets[0],
            planned.input_positions[0],
            planned.authentication_paths[0],
        )?,
        AtomicPrivateSettlementInputSecretV1::new(
            input_spending_secrets[1],
            planned.input_positions[1],
            planned.authentication_paths[1],
        )?,
    ];
    Ok(AtomicPrivateSettlementBootstrapPlanV1 {
        initial_commitments: planned.initial_commitments,
        old_root: planned.old_root,
        new_root: planned.new_root,
        old_epoch: 1,
        new_epoch: 2,
        inputs,
    })
}

#[cfg(any(test, feature = "test-utils"))]
/// Reconstruct original membership inputs for a newly activated two-note fixture pool.
/// This calls the canonical existing frontier planner without appending any outputs. It
/// constructs no transaction, completed manifest, statement, proof or synthetic authority.
/// # Errors
/// Invalid original pool/commitments, reserved secret or unavailable canonical membership path.
pub fn plan_atomic_private_settlement_initial_inputs_v1(
    pool_id: iroha_data_model::privacy::PrivacyPoolIdV1,
    initial_commitments: [PrivacyCommitmentV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    spending_secrets: [[u8; 32]; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
) -> Result<
    [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    AtomicPrivateSettlementWalletErrorV1,
> {
    if pool_id.is_zero() {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    let namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
            pool_id,
            program_id: atomic_private_settlement_program_id_v1()
                .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?,
        }),
    );
    let planned = plan_two_leaf_proof_managed_transition_v1(namespace, initial_commitments, &[])
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    Ok([
        AtomicPrivateSettlementInputSecretV1::new(
            spending_secrets[0],
            planned.input_positions[0],
            planned.authentication_paths[0],
        )?,
        AtomicPrivateSettlementInputSecretV1::new(
            spending_secrets[1],
            planned.input_positions[1],
            planned.authentication_paths[1],
        )?,
    ])
}

#[cfg(test)]
mod initial_inputs_tests {
    use super::*;
    #[test]
    fn initial_inputs_reuse_exact_bootstrap_membership_without_output_placeholders() {
        let pool = iroha_data_model::privacy::PrivacyPoolIdV1::new([9; 32]);
        let commitments = [
            PrivacyCommitmentV1::new([2; 32]),
            PrivacyCommitmentV1::new([1; 32]),
        ];
        let secrets = [[3; 32], [4; 32]];
        let original =
            plan_atomic_private_settlement_initial_inputs_v1(pool, commitments, secrets).unwrap();
        let with_outputs = plan_atomic_private_settlement_bootstrap_v1(
            pool,
            commitments,
            [
                PrivacyCommitmentV1::new([5; 32]),
                PrivacyCommitmentV1::new([6; 32]),
                PrivacyCommitmentV1::new([7; 32]),
            ],
            secrets,
        )
        .unwrap();
        for (original, later) in original.iter().zip(&with_outputs.inputs) {
            assert_eq!(original.spending_secret, later.spending_secret);
            assert_eq!(original.leaf_position, later.leaf_position);
            assert_eq!(original.authentication_path, later.authentication_path);
        }
        assert!(
            plan_atomic_private_settlement_initial_inputs_v1(pool, [commitments[0]; 2], secrets)
                .is_err()
        );
        assert!(
            plan_atomic_private_settlement_initial_inputs_v1(
                pool,
                commitments,
                [[0; 32], secrets[1]]
            )
            .is_err()
        );
    }
}

struct DecodedOwnerBundleV1 {
    inspection: AtomicPrivateSettlementWalletInspectionV1,
    audit_plaintext: PrivateSettlementAuditPlaintextV1,
    inputs: [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
}

struct Cursor<'a> {
    source: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self { source, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], AtomicPrivateSettlementWalletErrorV1> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
        let bytes = self
            .source
            .get(self.offset..end)
            .ok_or(AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, AtomicPrivateSettlementWalletErrorV1> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle,
        )?))
    }

    fn u32(&mut self) -> Result<u32, AtomicPrivateSettlementWalletErrorV1> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle,
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AtomicPrivateSettlementWalletErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)
    }

    fn finish(self) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
        if self.offset == self.source.len() {
            Ok(())
        } else {
            Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle)
        }
    }
}

struct ZeroizeSliceOnDrop<'a>(&'a mut [u8]);

impl Drop for ZeroizeSliceOnDrop<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn validate_wallet_id(wallet_id: &str) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
    if wallet_id.is_empty()
        || wallet_id.len() > MAX_WALLET_ID_BYTES_V1
        || !wallet_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0
                    && matches!(byte, b'_' | b'-' | b'.' | b':' | b'+' | b'/' | b'@' | b'#'))
        })
        || wallet_id.contains("..")
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::WalletBinding);
    }
    Ok(())
}

fn hash_from_bytes(bytes: [u8; DIGEST_BYTES_V1]) -> Hash {
    Hash::prehashed(bytes)
}

fn validate_public_artifacts(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
    policy: &PrivateSettlementAuditPolicyV1,
    audit_plaintext: &PrivateSettlementAuditPlaintextV1,
) -> Result<AtomicPrivateSettlementWalletInspectionV1, AtomicPrivateSettlementWalletErrorV1> {
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    statement
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    policy
        .validate()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    capsule
        .validate_against(policy)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    audit_plaintext
        .validate_against_manifest(manifest)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let leg = manifest
        .legs
        .get(usize::from(statement.leg_ordinal))
        .ok_or(AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let proof_binding_digest = manifest
        .proof_binding_digest()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let statement_digest = statement
        .digest()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let capsule_digest = capsule
        .digest()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let audit_plaintext_bytes = Zeroizing::new(
        norito::encode_canonical(audit_plaintext)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?,
    );
    let audit_plaintext_commitment =
        private_settlement_audit_plaintext_commitment_v1(&audit_plaintext_bytes)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let audit_input_commitment =
        atomic_private_settlement_audit_input_commitment_v1(&audit_plaintext.inputs)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let authoritative_audit_policy_digest = policy.policy_digest;
    if statement.network_id != manifest.network_id
        || statement.bundle_id != manifest.bundle_id
        || statement.route != leg.route
        || statement.pool_id != leg.pool_id
        || statement.asset_binding_commitment != leg.asset_binding_commitment
        || statement.audit_policy_digest != authoritative_audit_policy_digest
        || statement.audit_policy_digest != leg.audit_policy_digest
        || statement.audit_key_epoch != policy.body.key_epoch
        || statement.audit_plaintext_commitment != audit_plaintext_commitment
        || statement.audit_input_commitment != audit_input_commitment
        || statement.audit_capsule_digest != capsule_digest
        || capsule.aad.network_id != statement.network_id
        || capsule.aad.bundle_id != statement.bundle_id
        || capsule.aad.leg_ordinal != statement.leg_ordinal
        || capsule.aad.route != statement.route
        || capsule.aad.plaintext_commitment != audit_plaintext_commitment
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding);
    }
    Ok(AtomicPrivateSettlementWalletInspectionV1 {
        wallet_id: String::new(),
        proof_binding_digest,
        statement_digest,
        capsule_digest,
        audit_plaintext_commitment,
    })
}

fn decode_owner_bundle(
    material: &[u8],
) -> Result<DecodedOwnerBundleV1, AtomicPrivateSettlementWalletErrorV1> {
    if material.is_empty() || material.len() > ATOMIC_PRIVATE_SETTLEMENT_WALLET_BUNDLE_MAX_BYTES_V1
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    let mut cursor = Cursor::new(material);
    if cursor.take(OWNER_BUNDLE_MAGIC_V1.len())? != OWNER_BUNDLE_MAGIC_V1
        || cursor.take(1)? != [OWNER_BUNDLE_VERSION_V1]
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    let wallet_id_len = usize::from(cursor.u16()?);
    if wallet_id_len == 0 || wallet_id_len > MAX_WALLET_ID_BYTES_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::WalletBinding);
    }
    let wallet_id = core::str::from_utf8(cursor.take(wallet_id_len)?)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::WalletBinding)?
        .to_owned();
    validate_wallet_id(&wallet_id)?;
    let proof_binding_digest = hash_from_bytes(cursor.array()?);
    let statement_digest = hash_from_bytes(cursor.array()?);
    let capsule_digest = hash_from_bytes(cursor.array()?);
    let audit_plaintext_commitment = hash_from_bytes(cursor.array()?);
    if [
        proof_binding_digest,
        statement_digest,
        capsule_digest,
        audit_plaintext_commitment,
    ]
    .iter()
    .any(|digest| digest.as_ref().iter().all(|byte| *byte == 0))
    {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    let plaintext_len = usize::try_from(cursor.u32()?)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    if plaintext_len == 0 || plaintext_len > ATOMIC_PRIVATE_SETTLEMENT_WALLET_BUNDLE_MAX_BYTES_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    let plaintext_bytes = cursor.take(plaintext_len)?;
    let audit_plaintext =
        norito::decode_canonical::<PrivateSettlementAuditPlaintextV1>(plaintext_bytes)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let computed_plaintext_commitment =
        private_settlement_audit_plaintext_commitment_v1(plaintext_bytes)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    if computed_plaintext_commitment != audit_plaintext_commitment {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    let mut inputs = Vec::with_capacity(PRIVATE_SETTLEMENT_INPUT_SLOTS_V1);
    for _ in 0..PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 {
        let spending_secret = cursor.array()?;
        let leaf_position = cursor.u32()?;
        let mut authentication_path = [[0_u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1];
        for sibling in &mut authentication_path {
            *sibling = cursor.array()?;
        }
        inputs.push(AtomicPrivateSettlementInputSecretV1::new(
            spending_secret,
            leaf_position,
            authentication_path,
        )?);
    }
    cursor.finish()?;
    let inputs: [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1] = inputs
        .try_into()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    Ok(DecodedOwnerBundleV1 {
        inspection: AtomicPrivateSettlementWalletInspectionV1 {
            wallet_id,
            proof_binding_digest,
            statement_digest,
            capsule_digest,
            audit_plaintext_commitment,
        },
        audit_plaintext,
        inputs,
    })
}

/// Encode one owner-only wallet bundle for later isolated proving.
///
/// The result must be written by a native wallet to an owner-only regular file;
/// it must never be returned through Python, Torii, logs, events, or telemetry.
///
/// # Errors
///
/// Rejects malformed public artifacts, a malformed wallet identifier, secret
/// inputs that do not control the audit-opened notes, or an oversized bundle.
#[cfg(any(test, feature = "test-utils"))]
pub fn encode_atomic_private_settlement_wallet_bundle_v1(
    wallet_id: &str,
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
    policy: &PrivateSettlementAuditPolicyV1,
    audit_plaintext: &PrivateSettlementAuditPlaintextV1,
    inputs: &[AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
) -> Result<Zeroizing<Vec<u8>>, AtomicPrivateSettlementWalletErrorV1> {
    validate_wallet_id(wallet_id)?;
    let mut inspection =
        validate_public_artifacts(manifest, statement, capsule, policy, audit_plaintext)?;
    inspection.wallet_id = wallet_id.to_owned();
    if audit_plaintext.inputs.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    for (secret, opening) in inputs.iter().zip(&audit_plaintext.inputs) {
        if derive_note_authority_v1(&secret.spending_secret)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?
            != opening.spending_authority
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
        }
    }
    let plaintext = Zeroizing::new(
        norito::encode_canonical(audit_plaintext)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?,
    );
    let wallet_id_len = u16::try_from(wallet_id.len())
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::WalletBinding)?;
    let plaintext_len = u32::try_from(plaintext.len())
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::InvalidBundle)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        4 + 1
            + 2
            + wallet_id.len()
            + DIGEST_BYTES_V1 * 4
            + 4
            + plaintext.len()
            + PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 * (32 + 4 + PRIVATE_NOTE_TREE_DEPTH_V1 * 32),
    ));
    encoded.extend_from_slice(OWNER_BUNDLE_MAGIC_V1);
    encoded.push(OWNER_BUNDLE_VERSION_V1);
    encoded.extend_from_slice(&wallet_id_len.to_be_bytes());
    encoded.extend_from_slice(wallet_id.as_bytes());
    encoded.extend_from_slice(inspection.proof_binding_digest.as_ref());
    encoded.extend_from_slice(inspection.statement_digest.as_ref());
    encoded.extend_from_slice(inspection.capsule_digest.as_ref());
    encoded.extend_from_slice(inspection.audit_plaintext_commitment.as_ref());
    encoded.extend_from_slice(&plaintext_len.to_be_bytes());
    encoded.extend_from_slice(&plaintext);
    for input in inputs {
        encoded.extend_from_slice(&input.spending_secret);
        encoded.extend_from_slice(&input.leaf_position.to_be_bytes());
        for sibling in &input.authentication_path {
            encoded.extend_from_slice(sibling);
        }
    }
    if encoded.len() > ATOMIC_PRIVATE_SETTLEMENT_WALLET_BUNDLE_MAX_BYTES_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::InvalidBundle);
    }
    Ok(encoded)
}

/// Inspect public binding metadata without returning any owner material.
///
/// # Errors
///
/// Rejects malformed, non-canonical, zero-digest, or oversized owner bundles.
pub fn inspect_atomic_private_settlement_wallet_bundle_v1(
    material: &[u8],
) -> Result<AtomicPrivateSettlementWalletInspectionV1, AtomicPrivateSettlementWalletErrorV1> {
    decode_owner_bundle(material).map(|decoded| decoded.inspection)
}

/// Consume and wipe one owner bundle while producing a self-verified proof.
///
/// `material` is wiped on every return path, including malformed input and
/// proof failure. The caller must remove its opaque handle before entering this
/// function so a process crash or callback failure cannot make the witness
/// reusable.
///
/// # Errors
///
/// Rejects any public-artifact substitution, wrong wallet binding, malformed
/// secret material, invalid membership witness, unavailable prover entropy, or
/// failed proof self-verification.
#[allow(clippy::too_many_arguments)]
pub fn consume_atomic_private_settlement_wallet_bundle_v1(
    material: &mut [u8],
    expected_wallet_id: &str,
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    capsule: &PrivateSettlementAuditCapsuleV1,
    policy: &PrivateSettlementAuditPolicyV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
) -> Result<AtomicPrivateSettlementPreparedProofV1, AtomicPrivateSettlementWalletErrorV1> {
    let material = ZeroizeSliceOnDrop(material);
    validate_wallet_id(expected_wallet_id)?;
    let decoded = decode_owner_bundle(&*material.0)?;
    let mut expected = validate_public_artifacts(
        manifest,
        statement,
        capsule,
        policy,
        &decoded.audit_plaintext,
    )?;
    expected.wallet_id = expected_wallet_id.to_owned();
    if decoded.inspection != expected {
        return Err(if decoded.inspection.wallet_id == expected.wallet_id {
            AtomicPrivateSettlementWalletErrorV1::PublicBinding
        } else {
            AtomicPrivateSettlementWalletErrorV1::WalletBinding
        });
    }
    let [first, second] = decoded.inputs;
    let inputs = [
        AtomicPrivateSettlementInputWitnessV1::new(
            first.spending_secret,
            first.leaf_position,
            first.authentication_path,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?,
        AtomicPrivateSettlementInputWitnessV1::new(
            second.spending_secret,
            second.leaf_position,
            second.authentication_path,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?,
    ];
    let witness = AtomicPrivateSettlementProverWitnessV1::new(decoded.audit_plaintext, inputs);
    let proof = prove_atomic_private_settlement_v1(
        manifest,
        statement,
        canonical_genesis_hash,
        current_height,
        &witness,
    )?;
    Ok(AtomicPrivateSettlementPreparedProofV1 {
        statement: statement.clone(),
        proof,
        audit_capsule: capsule.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        privacy_engines::atomic_private_settlement::{
            audit::{
                private_settlement_audit_plaintext_commitment_v1,
                seal_private_settlement_audit_capsule_v1_with_rng,
            },
            test_fixtures::{
                aps_provisional_material_fixture_v1,
                aps_sidecar_material_fixture_v1 as sidecar_fixture,
            },
        },
        privacy_engines::{
            atomic_private_settlement::relation::{
                atomic_private_settlement_output_memo_digests_v1,
                atomic_private_settlement_program_id_v1, internal_statement_v1,
            },
            ivm_private_note::{
                PrivateNotePlaintextV1, PrivateNoteRelationProfileV1,
                accumulator_leaf_digest_for_testing_v1, accumulator_node_digest_for_testing_v1,
                derive_note_nullifier_v1, derive_profiled_output_commitment_v1,
                encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1,
            },
        },
    };
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_data_model::nexus::{
        PrivateSettlementAuditAadV1, PrivateSettlementAuditPayerAuthorizationV1,
        PrivateSettlementAuditPayerSignatureV1, PrivateSettlementCapsulePaddingV1,
        PrivateSettlementLegCommitmentV1,
    };
    use iroha_data_model::privacy::{PrivacyNullifierV1, PrivacyRootV1};
    use rand_08::{SeedableRng as _, rngs::StdRng};

    #[test]
    fn funding_note_survives_later_authority_context_and_virtual_dummy() {
        let fixture = sidecar_fixture();
        let mut openings = fixture.plaintext.inputs.clone();
        let expected = openings[0].commitment;
        openings[0].commitment = PrivacyCommitmentV1::new([0; 32]);
        prepare_atomic_private_settlement_funding_note_v1(&mut openings[0])
            .expect("prepare funding before a settlement exists");
        assert_eq!(openings[0].commitment, expected);

        let mut manifest = fixture.sidecar.manifest;
        let mut statement = fixture.sidecar.payload.statement;
        let old_dummy = openings[1].commitment;
        manifest.authority_context_height += 3;
        manifest.bundle_id = manifest.computed_bundle_id().expect("later bundle");
        statement.authority_context_height = manifest.authority_context_height;
        statement.bundle_id = manifest.bundle_id;
        prepare_atomic_private_settlement_input_openings_v1(&manifest, &statement, &mut openings)
            .expect("bind a spend after extra admission blocks");
        assert_eq!(openings[0].commitment, expected);
        assert_ne!(openings[1].commitment, old_dummy);
    }

    #[test]
    fn funding_note_rejects_inactive_zero_and_dummy_without_mutation() {
        let fixture = sidecar_fixture();
        for mutation in 0..3 {
            let mut opening = fixture.plaintext.inputs[0].clone();
            match mutation {
                0 => opening.active = false,
                1 => opening.value = 0,
                2 => opening.dummy_domain = Some(Hash::new(b"not a funding note")),
                _ => unreachable!(),
            }
            let before = opening.clone();
            assert!(prepare_atomic_private_settlement_funding_note_v1(&mut opening).is_err());
            assert_eq!(opening, before);
        }
    }

    fn input_secrets() -> [AtomicPrivateSettlementInputSecretV1; 2] {
        [
            AtomicPrivateSettlementInputSecretV1::new(
                [0x81; 32],
                0,
                core::array::from_fn(|level| [0x40 + u8::try_from(level).unwrap(); 32]),
            )
            .expect("first secret"),
            AtomicPrivateSettlementInputSecretV1::new(
                [0x82; 32],
                1,
                core::array::from_fn(|level| [0x80 + u8::try_from(level).unwrap(); 32]),
            )
            .expect("second secret"),
        ]
    }

    fn rebind_prepared_leg_fixture_v1(
        mut prepared: AtomicPrivateSettlementPreparedLegV1,
        manifest: &AtomicPrivateSettlementV1,
        leg: &PrivateSettlementLegCommitmentV1,
        policy: &PrivateSettlementAuditPolicyV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
    ) -> AtomicPrivateSettlementPreparedLegV1 {
        prepared.statement.bundle_id = manifest.bundle_id;
        prepared.statement.leg_ordinal = leg.ordinal;
        prepared.statement.route = leg.route;
        prepared.statement.pool_id = leg.pool_id;
        prepared.statement.asset_binding_commitment = leg.asset_binding_commitment;
        prepared.statement.audit_policy_digest = policy.policy_digest;
        prepared.statement.audit_key_epoch = policy.body.key_epoch;

        prepared.audit_capsule.aad.bundle_id = manifest.bundle_id;
        prepared.audit_capsule.aad.leg_ordinal = leg.ordinal;
        prepared.audit_capsule.aad.route = leg.route;
        prepared.audit_capsule.aad.authority_digest =
            authority.digest().expect("fixture authority digest");
        prepared.audit_capsule.aad.audit_policy_digest = policy.policy_digest;
        prepared.audit_capsule.aad.audit_key_epoch = policy.body.key_epoch;
        prepared.statement.audit_capsule_digest = prepared
            .audit_capsule
            .digest()
            .expect("fixture capsule digest");
        prepared
            .statement
            .validate()
            .expect("rebound fixture statement");

        prepared.delta.bundle_id = manifest.bundle_id;
        prepared.delta.leg_ordinal = leg.ordinal;
        prepared.delta.route = leg.route;
        prepared.delta.pool_id = leg.pool_id;
        prepared.delta.asset_binding_commitment = leg.asset_binding_commitment;
        prepared.delta.statement_digest = prepared
            .statement
            .digest()
            .expect("fixture statement digest");
        prepared.delta.proof_digest = private_settlement_proof_digest_v1(&prepared.proof);
        prepared.delta.capsule_digest = prepared.statement.audit_capsule_digest;
        prepared.delta.audit_policy_digest = policy.policy_digest;
        prepared.delta.audit_key_epoch = policy.body.key_epoch;
        prepared
            .delta
            .validate_against(&prepared.statement)
            .expect("rebound fixture delta");
        prepared
    }

    fn membership_root(
        input: u8,
        leaf: [u8; 32],
        leaf_position: u32,
        path: &[[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
    ) -> [u8; 32] {
        let mut current = leaf;
        let mut position = leaf_position;
        for (level, sibling) in path.iter().enumerate() {
            let level = u8::try_from(level).expect("depth-32 level fits u8");
            current = if position & 1 == 0 {
                accumulator_node_digest_for_testing_v1(input, level, &current, sibling)
            } else {
                accumulator_node_digest_for_testing_v1(input, level, sibling, &current)
            }
            .expect("fixture accumulator node");
            position >>= 1;
        }
        assert_eq!(position, 0, "fixture leaf position fits depth-32 tree");
        current
    }

    #[test]
    fn preproof_authorization_inputs_match_original_nullifiers_and_reject_changed_secrets() {
        let fixture = sidecar_fixture();
        let intent = fixture.sidecar.manifest.proof_intent();
        let expected = fixture.sidecar.payload.statement.nullifiers.clone();
        let mut inputs = fixture.plaintext.inputs.clone();
        let derived = prepare_atomic_private_settlement_authorization_inputs_v1(
            &intent,
            0,
            &mut inputs,
            &[[0x81; 32], [0x82; 32]],
        )
        .unwrap();
        assert_eq!(derived.as_slice(), expected.as_slice());
        assert_eq!(inputs, fixture.plaintext.inputs);
        let mut inputs = fixture.plaintext.inputs.clone();
        let before = inputs.clone();
        assert!(
            prepare_atomic_private_settlement_authorization_inputs_v1(
                &intent,
                0,
                &mut inputs,
                &[[0x91; 32], [0x82; 32]]
            )
            .is_err()
        );
        assert_eq!(
            inputs, before,
            "substituted secret refuses before mutating input openings"
        );
        assert!(
            prepare_atomic_private_settlement_authorization_inputs_v1(
                &intent,
                255,
                &mut inputs,
                &[[0x81; 32], [0x82; 32]]
            )
            .is_err()
        );
    }

    #[test]
    fn input_preparation_rejects_noncanonical_activity() {
        let fixture = sidecar_fixture();
        for mutation in 0..3 {
            let mut inputs = fixture.plaintext.inputs.clone();
            match mutation {
                0 => inputs[1].active = true,
                1 => inputs[0].active = false,
                2 => inputs[0].dummy_domain = Some(Hash::prehashed([0xEF; 32])),
                _ => unreachable!(),
            }
            assert!(
                prepare_atomic_private_settlement_input_openings_v1(
                    &fixture.sidecar.manifest,
                    &fixture.sidecar.payload.statement,
                    &mut inputs,
                )
                .is_err(),
                "activity must be the canonical positive-value predicate"
            );
        }
    }

    #[test]
    fn native_owner_bundle_produces_and_self_verifies_three_output_proof() {
        let fixture = sidecar_fixture();
        let manifest = fixture.sidecar.manifest.clone();
        let policy = fixture.sidecar.policy.clone();
        let mut statement = fixture.sidecar.payload.statement.clone();
        let mut plaintext = fixture.plaintext.clone();

        let internal = internal_statement_v1(&manifest.proof_intent(), &statement)
            .expect("internal statement");
        let input_commitments = [
            plaintext.inputs[0].commitment,
            plaintext.inputs[1].commitment,
        ];
        let leaves = [
            accumulator_leaf_digest_for_testing_v1(&internal, 0, input_commitments[0])
                .expect("first accumulator leaf"),
            accumulator_leaf_digest_for_testing_v1(&internal, 1, input_commitments[1])
                .expect("second accumulator leaf"),
        ];
        let mut first_path = core::array::from_fn(|level| {
            [0xB0_u8.wrapping_add(u8::try_from(level).expect("path level fits u8")); 32]
        });
        let mut second_path = first_path;
        first_path[0] = leaves[1];
        second_path[0] = leaves[0];
        let first_root = membership_root(0, leaves[0], 0, &first_path);
        let second_root = membership_root(1, leaves[1], 1, &second_path);
        assert_eq!(first_root, second_root, "adjacent leaves share one root");
        statement.old_root = PrivacyRootV1::new(first_root);

        let internal = internal_statement_v1(&manifest.proof_intent(), &statement)
            .expect("root-bound statement");
        let spending_secrets = [[0x81; 32], [0x82; 32]];
        statement.nullifiers = plaintext
            .inputs
            .iter()
            .zip(spending_secrets)
            .zip(input_commitments)
            .map(|((opening, secret), commitment)| {
                derive_note_nullifier_v1(&internal, &secret, &opening.rho, commitment)
                    .expect("stable input nullifier")
            })
            .collect::<Vec<PrivacyNullifierV1>>();

        let payer = KeyPair::from_seed(vec![0x38; 32], Algorithm::Ed25519);
        let payer_body = plaintext
            .payer_authorization_body(&statement.nullifiers)
            .expect("payer authorization body");
        plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            payer_body.clone(),
            vec![PrivateSettlementAuditPayerSignatureV1::new(
                payer.public_key().clone(),
                SignatureOf::try_new(payer.private_key(), &payer_body)
                    .expect("payer authorization signature"),
            )],
        );

        let plaintext_commitment = plaintext.commitment().expect("audit plaintext commitment");
        statement.audit_plaintext_commitment = plaintext_commitment;
        statement.audit_input_commitment =
            atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)
                .expect("audit input commitment");
        let output_memos = atomic_private_settlement_output_memo_digests_v1(&manifest, &statement)
            .expect("fixed settlement output memos");
        let profile = PrivateNoteRelationProfileV1::exact_three_output_balanced(
            output_memos,
            statement.audit_input_commitment,
        );
        let program_id = atomic_private_settlement_program_id_v1().expect("settlement program");
        let mut output_rng = StdRng::seed_from_u64(0x4150_535f_5741_4c4c);
        let mut encrypted_outputs = Vec::with_capacity(plaintext.outputs.len());
        for (index, (output, memo)) in plaintext.outputs.iter_mut().zip(output_memos).enumerate() {
            output.note.memo_digest = memo;
            let note = PrivateNotePlaintextV1::new_profiled_output_v1(
                output.note.value,
                output.note.spending_authority,
                output.note.rho,
                output.note.blinding,
                output.note.memo_digest,
                index,
                profile,
            )
            .expect("profiled settlement output");
            output.note.commitment = derive_profiled_output_commitment_v1(&note, index, profile)
                .expect("settlement output commitment");
            encrypted_outputs.push(
                encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1(
                    &mut output_rng,
                    statement.pool_id,
                    program_id,
                    &note,
                    output.note.commitment,
                    output.recipient_view_key,
                    &output.encryption_opening.ephemeral_secret,
                )
                .expect("settlement output ciphertext"),
            );
        }
        statement.output_commitments = plaintext
            .outputs
            .iter()
            .map(|output| output.note.commitment)
            .collect();
        statement.encrypted_outputs = encrypted_outputs;
        assert_eq!(
            plaintext.commitment().expect("stable audit commitment"),
            plaintext_commitment,
            "derived output memos and commitments are excluded from the non-circular audit commitment"
        );

        let audit_plaintext = Zeroizing::new(
            norito::encode_canonical(&plaintext).expect("canonical audit plaintext"),
        );
        assert_eq!(
            private_settlement_audit_plaintext_commitment_v1(&audit_plaintext)
                .expect("encoded plaintext commitment"),
            plaintext_commitment
        );
        let aad = PrivateSettlementAuditAadV1 {
            network_id: manifest.network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: statement.leg_ordinal,
            route: statement.route,
            authority_digest: fixture
                .sidecar
                .authority
                .digest()
                .expect("authority digest"),
            authority_context_height: manifest.authority_context_height,
            audit_policy_digest: policy.policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            plaintext_commitment,
        };
        let mut capsule_rng =
            iroha_crypto::rng_from_seed_slice(b"positive native settlement wallet capsule");
        let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
            &audit_plaintext,
            aad,
            PrivateSettlementCapsulePaddingV1::KiB16,
            &policy,
            &mut capsule_rng,
        )
        .expect("settlement audit capsule");
        statement.audit_capsule_digest = capsule.digest().expect("capsule digest");
        statement.validate().expect("valid proof statement");

        let inputs = [
            AtomicPrivateSettlementInputSecretV1::new([0x81; 32], 0, first_path)
                .expect("first membership secret"),
            AtomicPrivateSettlementInputSecretV1::new([0x82; 32], 1, second_path)
                .expect("second membership secret"),
        ];
        let encoded = encode_atomic_private_settlement_wallet_bundle_v1(
            "bank-a-wallet-positive",
            &manifest,
            &statement,
            &capsule,
            &policy,
            &plaintext,
            &inputs,
        )
        .expect("owner bundle");
        let mut material = encoded.to_vec();
        let phase_capture = super::super::facade::phase_test_support::PhaseCaptureV1::new(true);
        let prepared = phase_capture
            .with_default(|| {
                consume_atomic_private_settlement_wallet_bundle_v1(
                    &mut material,
                    "bank-a-wallet-positive",
                    &manifest,
                    &statement,
                    &capsule,
                    &policy,
                    *manifest.network_id.as_genesis_hash().as_ref(),
                    manifest.authority_context_height,
                )
            })
            .expect("self-verified native proof");
        let proof_phase_events = phase_capture.assert_one_successful_invocation_v1();
        assert!(!prepared.proof.is_empty());
        assert_eq!(prepared.statement, statement);
        assert_eq!(prepared.audit_capsule, capsule);
        let mut substituted_statement = prepared.statement.clone();
        substituted_statement.new_root = PrivacyRootV1::new([0xE8; 32]);
        substituted_statement
            .validate()
            .expect("successor substitution remains structurally valid");
        assert!(
            phase_capture.with_default(|| {
                crate::privacy_engines::atomic_private_settlement::verify_atomic_private_settlement_v1(
                    &manifest,
                    &substituted_statement,
                    *manifest.network_id.as_genesis_hash().as_ref(),
                    manifest.authority_context_height,
                    &prepared.proof,
                )
            })
            .is_err(),
            "a proof must not verify after successor-root substitution"
        );
        assert_eq!(
            phase_capture.events_v1(),
            proof_phase_events,
            "the subsequent public verifier must not add facade construction/self-verification events"
        );
        let debug = format!("{prepared:?}");
        assert_eq!(
            debug,
            "AtomicPrivateSettlementPreparedProofV1(<restricted>)"
        );
        assert!(!debug.contains(&hex::encode(&prepared.proof)));

        let mut unchanged_successor = prepared.clone();
        unchanged_successor.statement.new_root = unchanged_successor.statement.old_root;
        assert!(
            complete_atomic_private_settlement_prepared_leg_v1(unchanged_successor).is_err(),
            "an unchanged proof-bound successor root must fail closed"
        );
        let mut substituted_capsule = prepared.clone();
        substituted_capsule.audit_capsule.ciphertext[0] ^= 1;
        assert!(
            complete_atomic_private_settlement_prepared_leg_v1(substituted_capsule).is_err(),
            "a capsule substitution must fail before delta construction"
        );
        let prepared_leg = complete_atomic_private_settlement_prepared_leg_v1(prepared)
            .expect("native proof completes into a canonical delta");
        prepared_leg
            .delta
            .validate_against(&prepared_leg.statement)
            .expect("derived delta is statement-bound");
        assert_eq!(
            prepared_leg.delta.proof_digest,
            private_settlement_proof_digest_v1(&prepared_leg.proof)
        );
        assert_eq!(
            prepared_leg.delta.capsule_digest,
            prepared_leg
                .audit_capsule
                .digest()
                .expect("prepared capsule digest")
        );
        let leg_debug = format!("{prepared_leg:?}");
        assert_eq!(
            leg_debug,
            "AtomicPrivateSettlementPreparedLegV1(<restricted>)"
        );
        assert!(!leg_debug.contains(&hex::encode(&prepared_leg.proof)));
        assert!(material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn owner_bundle_inspection_returns_only_public_bindings() {
        let fixture = sidecar_fixture();
        let sidecar = &fixture.sidecar;
        let encoded = encode_atomic_private_settlement_wallet_bundle_v1(
            "bank-a-wallet-7",
            &sidecar.manifest,
            &sidecar.payload.statement,
            &sidecar.payload.audit_capsule,
            &sidecar.policy,
            &fixture.plaintext,
            &input_secrets(),
        )
        .expect("owner bundle");
        let inspected = inspect_atomic_private_settlement_wallet_bundle_v1(&encoded)
            .expect("public inspection");
        assert_eq!(inspected.wallet_id, "bank-a-wallet-7");
        assert_eq!(
            inspected.proof_binding_digest,
            sidecar
                .manifest
                .proof_binding_digest()
                .expect("proof binding")
        );
        assert_eq!(
            inspected.statement_digest,
            sidecar
                .payload
                .statement
                .digest()
                .expect("statement digest")
        );
        assert_eq!(
            inspected.capsule_digest,
            sidecar
                .payload
                .audit_capsule
                .digest()
                .expect("capsule digest")
        );
        let mut substituted_statement = sidecar.payload.statement.clone();
        substituted_statement.audit_input_commitment = [0xE7; 32];
        assert!(
            encode_atomic_private_settlement_wallet_bundle_v1(
                "bank-a-wallet-7",
                &sidecar.manifest,
                &substituted_statement,
                &sidecar.payload.audit_capsule,
                &sidecar.policy,
                &fixture.plaintext,
                &input_secrets(),
            )
            .is_err(),
            "an owner bundle cannot wrap audit openings under a substituted AIR binding"
        );
    }

    #[test]
    fn terminal_proof_failure_still_zeroizes_owner_bundle() {
        let fixture = sidecar_fixture();
        let sidecar = &fixture.sidecar;
        let encoded = encode_atomic_private_settlement_wallet_bundle_v1(
            "bank-a-wallet-7",
            &sidecar.manifest,
            &sidecar.payload.statement,
            &sidecar.payload.audit_capsule,
            &sidecar.policy,
            &fixture.plaintext,
            &input_secrets(),
        )
        .expect("owner bundle");
        let mut material = encoded.to_vec();
        let result = consume_atomic_private_settlement_wallet_bundle_v1(
            &mut material,
            "bank-a-wallet-7",
            &sidecar.manifest,
            &sidecar.payload.statement,
            &sidecar.payload.audit_capsule,
            &sidecar.policy,
            *sidecar.manifest.network_id.as_genesis_hash().as_ref(),
            sidecar.manifest.authority_context_height,
        );
        assert!(result.is_err(), "fixture paths deliberately miss the root");
        assert!(material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn statement_substitution_is_rejected_before_proving_and_zeroized() {
        let fixture = sidecar_fixture();
        let sidecar = &fixture.sidecar;
        let encoded = encode_atomic_private_settlement_wallet_bundle_v1(
            "bank-a-wallet-7",
            &sidecar.manifest,
            &sidecar.payload.statement,
            &sidecar.payload.audit_capsule,
            &sidecar.policy,
            &fixture.plaintext,
            &input_secrets(),
        )
        .expect("owner bundle");
        let mut material = encoded.to_vec();
        let mut substituted = sidecar.payload.statement.clone();
        substituted.old_epoch += 1;
        let result = consume_atomic_private_settlement_wallet_bundle_v1(
            &mut material,
            "bank-a-wallet-7",
            &sidecar.manifest,
            &substituted,
            &sidecar.payload.audit_capsule,
            &sidecar.policy,
            *sidecar.manifest.network_id.as_genesis_hash().as_ref(),
            sidecar.manifest.authority_context_height,
        );
        assert_eq!(
            result,
            Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding)
        );
        assert!(material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn provisional_leg_input_and_bundle_shape_fail_closed() {
        let fixture = sidecar_fixture();
        let material = aps_provisional_material_fixture_v1(
            &fixture.sidecar.manifest,
            &fixture.sidecar.policy,
            &fixture.sidecar.authority,
            &fixture.sidecar.payload,
        );
        let prepared = AtomicPrivateSettlementPreparedLegV1 {
            statement: material.statement.clone(),
            proof: material.proof.clone(),
            delta: material.delta.clone(),
            audit_capsule: material.audit_capsule.clone(),
        };
        let input = AtomicPrivateSettlementProvisionalLegInputV1::new(
            prepared.clone(),
            material.audit_policy.clone(),
            material.committee_authority.clone(),
            material.availability_body.retention_until_height,
        )
        .expect("fixture leg input");
        assert_eq!(
            format!("{input:?}"),
            "AtomicPrivateSettlementProvisionalLegInputV1(<restricted>)"
        );
        assert_eq!(
            finalize_atomic_private_settlement_provisional_bundle_v1(
                material.manifest.proof_intent(),
                vec![input.clone()],
            ),
            Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding),
            "a two-leg manifest cannot be finalized from one sidecar"
        );
        assert_eq!(
            finalize_atomic_private_settlement_provisional_bundle_v1(
                material.manifest.proof_intent(),
                vec![input.clone(), input],
            ),
            Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding),
            "a duplicate leg cannot occupy the next canonical ordinal"
        );

        for missing in [true, false] {
            let mut malformed = prepared.clone();
            if missing {
                malformed.proof.clear();
            } else {
                malformed.statement.encrypted_outputs.clear();
            }
            assert!(
                AtomicPrivateSettlementProvisionalLegInputV1::new(
                    malformed,
                    material.audit_policy.clone(),
                    material.committee_authority.clone(),
                    material.availability_body.retention_until_height
                )
                .is_err(),
                "missing proof or ciphertext cannot cross the prepared-artifact boundary"
            );
        }
        let mut substituted_ciphertext = prepared.clone();
        substituted_ciphertext.audit_capsule.ciphertext[0] ^= 1;
        assert!(
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                substituted_ciphertext,
                material.audit_policy.clone(),
                material.committee_authority.clone(),
                material.availability_body.retention_until_height
            )
            .is_err(),
            "ciphertext substitution must fail before bundle assembly"
        );
        let mut substituted_proof = prepared.clone();
        substituted_proof.proof[0] ^= 1;
        assert_eq!(
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                substituted_proof,
                material.audit_policy.clone(),
                material.committee_authority.clone(),
                material.availability_body.retention_until_height,
            ),
            Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding),
            "proof substitution must fail before bundle assembly"
        );
        assert_eq!(
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                prepared,
                material.audit_policy,
                material.committee_authority,
                material.manifest.expiry_height - 1,
            ),
            Err(AtomicPrivateSettlementWalletErrorV1::PublicBinding),
            "retention must cover the full settlement expiry"
        );
    }

    #[test]
    fn provisional_bundle_builder_composes_two_canonical_legs() {
        let fixture = sidecar_fixture();
        let material = aps_provisional_material_fixture_v1(
            &fixture.sidecar.manifest,
            &fixture.sidecar.policy,
            &fixture.sidecar.authority,
            &fixture.sidecar.payload,
        );
        let base_prepared = AtomicPrivateSettlementPreparedLegV1 {
            statement: material.statement.clone(),
            proof: material.proof.clone(),
            delta: material.delta.clone(),
            audit_capsule: material.audit_capsule.clone(),
        };
        let mut manifest = material.manifest.clone();

        let mut second_policy_body = material.audit_policy.body.clone();
        second_policy_body.dataspace_id = manifest.legs[1].route.dataspace_id;
        second_policy_body.policy_id = Hash::new(b"wallet-two-leg-second-policy");
        second_policy_body.revision = second_policy_body
            .revision
            .checked_add(1)
            .expect("fixture policy revision");
        let second_policy = PrivateSettlementAuditPolicyV1::new(second_policy_body)
            .expect("second dataspace policy");
        manifest.legs[1].audit_policy_digest = second_policy.policy_digest;
        manifest.bundle_id = manifest.computed_bundle_id().expect("two-leg bundle id");

        let first_authority = material.committee_authority.clone();
        let mut second_authority = first_authority.clone();
        second_authority.route = manifest.legs[1].route;
        second_authority
            .validate()
            .expect("second dataspace authority");
        let first_leg = manifest.legs[0].clone();
        let second_leg = manifest.legs[1].clone();
        let first_prepared = rebind_prepared_leg_fixture_v1(
            base_prepared.clone(),
            &manifest,
            &first_leg,
            &material.audit_policy,
            &first_authority,
        );
        let second_prepared = rebind_prepared_leg_fixture_v1(
            base_prepared,
            &manifest,
            &second_leg,
            &second_policy,
            &second_authority,
        );
        let inputs = vec![
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                first_prepared,
                material.audit_policy,
                first_authority,
                material.availability_body.retention_until_height,
            )
            .expect("first canonical input"),
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                second_prepared,
                second_policy,
                second_authority,
                material.availability_body.retention_until_height,
            )
            .expect("second canonical input"),
        ];

        let mut foreign_intent = manifest.proof_intent();
        foreign_intent.material.expiry_height += 1;
        foreign_intent.bundle_id = foreign_intent.computed_bundle_id().unwrap();
        assert!(
            finalize_atomic_private_settlement_provisional_bundle_v1(
                foreign_intent,
                inputs.clone()
            )
            .is_err(),
            "proof-complete artifacts cannot be reused under another intent"
        );
        let bundle = finalize_atomic_private_settlement_provisional_bundle_v1(
            manifest.proof_intent(),
            inputs,
        )
        .expect("two canonical legs compose into one provisional bundle");
        assert_eq!(bundle.materials.len(), 2);
        assert_ne!(
            bundle.manifest.legs[0].payload_digest,
            bundle.manifest.legs[1].payload_digest
        );
        assert_ne!(
            bundle.manifest.legs[0].delta_digest,
            bundle.manifest.legs[1].delta_digest
        );
        for (ordinal, material) in bundle.materials.iter().enumerate() {
            assert_eq!(usize::from(material.statement.leg_ordinal), ordinal);
            assert_eq!(material.manifest, bundle.manifest);
            assert_eq!(
                material.availability_body.payload_digest,
                bundle.manifest.legs[ordinal].payload_digest
            );
            assert_eq!(
                material.delta.digest().expect("material delta digest"),
                bundle.manifest.legs[ordinal].delta_digest
            );
            material.validate().expect("final material validates");
        }
    }
}

#[path = "wallet/preparation.rs"]
mod preparation;
pub use preparation::*;

fn prepare_input_openings_from_bound_context_v1(
    manifest: &PrivateSettlementProofIntentV1,
    leg_ordinal: u8,
    openings: &mut [PrivateSettlementAuditNoteOpeningV1],
) -> Result<(), AtomicPrivateSettlementWalletErrorV1> {
    if openings.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    // Fixed output memos are immaterial to input-note validation.  Using one
    // closed non-zero placeholder avoids a circular dependency on the audit
    // plaintext commitment while retaining the settlement selectors.
    let profile =
        PrivateNoteRelationProfileV1::exact_three_output_balanced([[1_u8; 32]; 3], [1; 32]);
    for (index, opening) in openings.iter_mut().enumerate() {
        if opening.active != (opening.value != 0)
            || (opening.active && opening.dummy_domain.is_some())
        {
            return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
        }
        if !opening.active {
            let dummy_domain = opening
                .dummy_domain
                .ok_or(AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
            opening.memo_digest = super::relation::dummy_input_memo_from_bound_leg_v1(
                manifest,
                leg_ordinal,
                index,
                dummy_domain,
            )
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
        }
        let note = PrivateNotePlaintextV1::new_profiled_input_v1(
            opening.value,
            opening.spending_authority,
            opening.rho,
            opening.blinding,
            opening.memo_digest,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
        opening.commitment = derive_profiled_input_commitment_v1(&note, profile)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
    }
    if openings[0].commitment == openings[1].commitment {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    Ok(())
}

fn prepare_outputs_from_bound_context_v1(
    rng: &mut (impl RngCore + CryptoRng),
    statement: &PrivateSettlementProofStatementV1,
    outputs: &mut [PrivateSettlementAuditOutputV1],
) -> Result<Vec<PrivacyEncryptedOutputV1>, AtomicPrivateSettlementWalletErrorV1> {
    if outputs.len() != PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1 {
        return Err(AtomicPrivateSettlementWalletErrorV1::SecretMaterial);
    }
    let fixed_memos = super::relation::output_memo_digests_from_bound_preparation_v1(statement)
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let profile = PrivateNoteRelationProfileV1::exact_three_output_balanced(
        fixed_memos,
        statement.audit_input_commitment,
    );
    let program_id = atomic_private_settlement_program_id_v1()
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::PublicBinding)?;
    let mut encrypted = Vec::with_capacity(PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1);
    for (index, (output, memo)) in outputs.iter_mut().zip(fixed_memos).enumerate() {
        output.note.memo_digest = memo;
        let note = PrivateNotePlaintextV1::new_profiled_output_v1(
            output.note.value,
            output.note.spending_authority,
            output.note.rho,
            output.note.blinding,
            output.note.memo_digest,
            index,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
        output.note.commitment = derive_profiled_output_commitment_v1(&note, index, profile)
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?;
        encrypted.push(
            encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1(
                rng,
                statement.pool_id,
                program_id,
                &note,
                output.note.commitment,
                output.recipient_view_key,
                &output.encryption_opening.ephemeral_secret,
            )
            .map_err(|_| AtomicPrivateSettlementWalletErrorV1::SecretMaterial)?,
        );
    }
    Ok(encrypted)
}
