//! Settlement-specific binding of the fixed IVM private-note relation.

use super::super::ivm_private_note::{
    IvmPrivateNoteInputWitnessV1, IvmPrivateNoteOutputWitnessV1, IvmPrivateNoteWitnessV1,
    PRIVATE_NOTE_TREE_DEPTH_V1, PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1, PrivateInstructionV1,
    PrivateNotePlaintextV1, PrivateNoteRelationProfileV1, PrivateOpcodeV1, PrivateProgramV1,
    derive_ivm_private_recipient_id_v1, derive_note_authority_v1,
    derive_private_note_input_openings_commitment_v1, derive_private_program_id_v1,
    derive_profiled_input_commitment_v1, derive_profiled_output_commitment_v1,
    preflight_private_note_relation_with_profile_v1,
    validate_ivm_private_wallet_encryption_opening_v1,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    account::AccountController,
    asset::{AssetBalanceScope, AssetDefinitionId},
    block::BlockHeader,
    nexus::{
        AtomicPrivateSettlementV1, PRIVATE_SETTLEMENT_INPUT_SLOTS_V1,
        PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1, PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1,
        PrivateSettlementAuditNoteOpeningV1, PrivateSettlementAuditPlaintextV1,
        PrivateSettlementProofStatementV1,
    },
    privacy::{
        IrohaIvmPrivateNoteStarkStatementV1, PrivacyActionDigestV1, PrivacyEngineManifestDigestV1,
        PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyStatementContextV1,
        PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1, PrivacyValueBalanceV1,
        PrivacyVerifierDigestV1,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use sha2::{Digest as _, Sha256};
use std::{fmt, str::FromStr as _};
use thiserror::Error;
use zeroize::Zeroize;

const SETTLEMENT_CONTEXT_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.context.v1";
const SETTLEMENT_PARAMETER_ID_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.parameter-id.v1";
const SETTLEMENT_PARAMETER_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.parameter.v1";
const SETTLEMENT_VERIFIER_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.verifier.v1";
const SETTLEMENT_SCHEMA_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.schema.v1";
const SETTLEMENT_ENGINE_DOMAIN_V1: &[u8] = b"iroha.atomic-private-settlement.engine.v1";
const SETTLEMENT_CHANGE_MEMO_DOMAIN_V1: &[u8] =
    b"iroha.atomic-private-settlement.output.payer-change.v1";
const SETTLEMENT_DUMMY_INPUT_MEMO_DOMAIN_V1: &[u8] =
    b"iroha.atomic-private-settlement.input.dummy.v1";

/// Semantic descriptor for the settlement-only IVM relation binding.
pub const ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1: &[u8] = b"iroha-atomic-private-settlement-relation-v1:separate-from-transparent-amx:ivm-private-note-fixed-2-input-3-output:balanced-only:positive-input-membership-only:zero-valued-virtual-dummies-with-nonzero-authority-rho-blinding-and-path:input-openings=public-air-sha256-binding-of-exact-ordered-value-authority-rho-blinding-memo:payer=purpose-separated-fixed-input-controller-authorization:output-memos=auditor-plaintext-commitment+payer-change-role+sponsor-reimbursement-terms:reimbursement-success-fee-carriers=2:asset=salted-auditor-approved-pool-binding:public=canonical-manifest-intent-proof-binding+statement+genesis:post-proof-artifacts=manifest+committee-qc+carrier:successor=proof-statement-bound-root+epoch:successor-correctness=validator-derived-frontier";

/// Public, redacted failure at the settlement proof relation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum AtomicPrivateSettlementRelationErrorV1 {
    /// The public manifest is malformed or not self-authenticating.
    #[error("atomic private settlement manifest is invalid")]
    InvalidManifest,
    /// The fixed-shape public leg statement is malformed or mismatched.
    #[error("atomic private settlement proof statement is invalid")]
    InvalidStatement,
    /// The trusted genesis hash does not identify the statement network.
    #[error("atomic private settlement network binding is invalid")]
    InvalidNetworkBinding,
    /// The current global height is outside the statement validity window.
    #[error("atomic private settlement proof statement is not live")]
    NotLive,
    /// Auditor-only business material is malformed or not bound to the statement.
    #[error("atomic private settlement audit material is invalid")]
    InvalidAuditMaterial,
    /// A fixed note opening, secret, membership path, or value relation is invalid.
    #[error("atomic private settlement private-note witness is invalid")]
    InvalidWitness,
    /// Canonical Norito encoding unexpectedly failed.
    #[error("atomic private settlement canonical encoding failed")]
    CanonicalEncoding,
    /// A closed implementation invariant is inconsistent.
    #[error("atomic private settlement relation profile is inconsistent")]
    Invariant,
}

fn framed_digest_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], AtomicPrivateSettlementRelationErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(fields.len())
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?
            .to_be_bytes(),
    );
    for field in fields {
        hasher.update(
            u64::try_from(field.len())
                .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?
                .to_be_bytes(),
        );
        hasher.update(field);
    }
    Ok(hasher.finalize().into())
}

fn network_from_genesis_v1(canonical_genesis_hash: [u8; 32]) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed(canonical_genesis_hash),
    ))
}

/// Wallet-local secret and membership material for one fixed input slot.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementInputWitnessV1 {
    spending_secret: [u8; 32],
    leaf_position: u32,
    authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
}

impl AtomicPrivateSettlementInputWitnessV1 {
    /// Construct one input witness without exposing it through serialization.
    ///
    /// # Errors
    ///
    /// Rejects a zero secret or any reserved-zero authentication sibling.
    pub fn new(
        spending_secret: [u8; 32],
        leaf_position: u32,
        authentication_path: [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
    ) -> Result<Self, AtomicPrivateSettlementRelationErrorV1> {
        if spending_secret.iter().all(|byte| *byte == 0)
            || authentication_path
                .iter()
                .any(|sibling| sibling.iter().all(|byte| *byte == 0))
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidWitness);
        }
        Ok(Self {
            spending_secret,
            leaf_position,
            authentication_path,
        })
    }
}

impl fmt::Debug for AtomicPrivateSettlementInputWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AtomicPrivateSettlementInputWitnessV1(<redacted>)")
    }
}

impl Drop for AtomicPrivateSettlementInputWitnessV1 {
    fn drop(&mut self) {
        self.spending_secret.zeroize();
        self.leaf_position = 0;
        self.authentication_path.zeroize();
    }
}

/// Complete wallet-local witness for one settlement leg.
#[derive(Clone, PartialEq, Eq)]
pub struct AtomicPrivateSettlementProverWitnessV1 {
    audit_plaintext: PrivateSettlementAuditPlaintextV1,
    inputs: [AtomicPrivateSettlementInputWitnessV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
}

impl AtomicPrivateSettlementProverWitnessV1 {
    /// Construct the exact two-input witness and auditor plaintext.
    #[must_use]
    pub fn new(
        audit_plaintext: PrivateSettlementAuditPlaintextV1,
        inputs: [AtomicPrivateSettlementInputWitnessV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    ) -> Self {
        Self {
            audit_plaintext,
            inputs,
        }
    }

    /// Borrow the auditor-only plaintext for capsule construction.
    #[must_use]
    pub const fn audit_plaintext(&self) -> &PrivateSettlementAuditPlaintextV1 {
        &self.audit_plaintext
    }
}

impl fmt::Debug for AtomicPrivateSettlementProverWitnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AtomicPrivateSettlementProverWitnessV1(<redacted>)")
    }
}

fn settlement_program_v1() -> Result<PrivateProgramV1, AtomicPrivateSettlementRelationErrorV1> {
    let mut instructions = [PrivateInstructionV1::HALT; PRIVATE_PROGRAM_INSTRUCTION_COUNT_V1];
    instructions[0] = PrivateInstructionV1::new(PrivateOpcodeV1::AddChecked, 6, 0, 2, 0)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?;
    instructions[1] = PrivateInstructionV1::new(PrivateOpcodeV1::AddChecked, 7, 1, 3, 0)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?;
    instructions[2] = PrivateInstructionV1::new(PrivateOpcodeV1::AssertEqual, 0, 6, 7, 0)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?;
    PrivateProgramV1::new(instructions)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)
}

/// Return the fixed program identifier used by settlement wallet ciphertext AAD.
pub fn atomic_private_settlement_program_id_v1()
-> Result<iroha_data_model::privacy::PrivacyProgramIdV1, AtomicPrivateSettlementRelationErrorV1> {
    derive_private_program_id_v1(&settlement_program_v1()?)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)
}

fn synthetic_asset_v1() -> Result<AssetDefinitionId, AtomicPrivateSettlementRelationErrorV1> {
    let domain = DomainId::try_new("privacy", "universal")
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?;
    let name = Name::from_str("atomic_private_settlement")
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?;
    Ok(AssetDefinitionId::derive_from_components(domain, name))
}

pub fn validate_public_binding_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    canonical_genesis_hash: [u8; 32],
    current_height: u64,
) -> Result<(), AtomicPrivateSettlementRelationErrorV1> {
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidManifest)?;
    statement
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidStatement)?;
    if canonical_genesis_hash.iter().all(|byte| *byte == 0)
        || network_from_genesis_v1(canonical_genesis_hash) != manifest.network_id
        || statement.network_id != manifest.network_id
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidNetworkBinding);
    }
    if current_height < manifest.authority_context_height || current_height > manifest.expiry_height
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::NotLive);
    }
    let leg = manifest
        .legs
        .get(usize::from(statement.leg_ordinal))
        .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidStatement)?;
    if statement.bundle_id != manifest.bundle_id
        || statement.route != leg.route
        || statement.authority_context_height != manifest.authority_context_height
        || statement.pool_id != leg.pool_id
        || statement.asset_binding_commitment != leg.asset_binding_commitment
        || statement.audit_policy_digest != leg.audit_policy_digest
        || statement.fee_intent_digest != manifest.fee_intent_digest
        || statement.reimbursement_terms_commitment != manifest.reimbursement_terms_commitment
        || statement.reimbursement_leg_ordinal != manifest.reimbursement_leg_ordinal
        || statement.expiry_height != manifest.expiry_height
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidStatement);
    }
    Ok(())
}

/// Derive the three verifier-fixed output memo digests.
///
/// Slot zero binds all non-circular auditor material, slot one binds the
/// payer-change role to the exact leg, and slot two binds the private sponsor
/// reimbursement terms selected by the public bundle.
pub fn atomic_private_settlement_output_memo_digests_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
) -> Result<[[u8; 32]; PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1], AtomicPrivateSettlementRelationErrorV1>
{
    manifest
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidManifest)?;
    statement
        .validate()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidStatement)?;
    let change_material = norito::encode_canonical(&(
        (
            statement.network_id,
            statement.bundle_id,
            statement.leg_ordinal,
            statement.route,
            statement.authority_context_height,
            statement.pool_id,
            statement.asset_binding_commitment,
            statement.audit_plaintext_commitment,
            statement.audit_input_commitment,
        ),
        (
            statement.audit_policy_digest,
            statement.audit_key_epoch,
            statement.fee_intent_digest,
            statement.reimbursement_terms_commitment,
            statement.reimbursement_leg_ordinal,
            statement.expiry_height,
            statement.proof_profile_digest,
        ),
    ))
    .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?;
    let change = framed_digest_v1(
        SETTLEMENT_CHANGE_MEMO_DOMAIN_V1,
        &[
            &change_material,
            PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1,
        ],
    )?;
    Ok([
        *statement.audit_plaintext_commitment.as_ref(),
        change,
        *statement.reimbursement_terms_commitment.as_ref(),
    ])
}

/// Derive the unique memo digest for one zero-valued input cover note.
///
/// The digest commits the bundle, leg, fixed slot index, and auditor-visible
/// nonzero dummy domain without exposing that domain on the public plane.
pub fn atomic_private_settlement_dummy_input_memo_digest_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    input_index: usize,
    dummy_domain: Hash,
) -> Result<[u8; 32], AtomicPrivateSettlementRelationErrorV1> {
    framed_digest_v1(
        SETTLEMENT_DUMMY_INPUT_MEMO_DOMAIN_V1,
        &[
            manifest.bundle_id.as_ref(),
            &[statement.leg_ordinal],
            &u64::try_from(input_index)
                .map_err(|_| AtomicPrivateSettlementRelationErrorV1::Invariant)?
                .to_be_bytes(),
            dummy_domain.as_ref(),
        ],
    )
}

fn context_digest_v1(
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<[u8; 32], AtomicPrivateSettlementRelationErrorV1> {
    let digest = framed_digest_v1(domain, fields)?;
    if digest.iter().all(|byte| *byte == 0) {
        return Err(AtomicPrivateSettlementRelationErrorV1::Invariant);
    }
    Ok(digest)
}

pub fn internal_statement_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
) -> Result<IrohaIvmPrivateNoteStarkStatementV1, AtomicPrivateSettlementRelationErrorV1> {
    let proof_binding_digest = manifest
        .proof_binding_digest()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?;
    let statement_bytes = norito::encode_canonical(statement)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?;
    let context_material = context_digest_v1(
        SETTLEMENT_CONTEXT_DOMAIN_V1,
        &[proof_binding_digest.as_ref(), &statement_bytes],
    )?;
    let parameter_id = context_digest_v1(
        SETTLEMENT_PARAMETER_ID_DOMAIN_V1,
        &[PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1],
    )?;
    let parameter_digest = context_digest_v1(
        SETTLEMENT_PARAMETER_DOMAIN_V1,
        &[
            PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1,
            ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1,
        ],
    )?;
    let verifier_digest = context_digest_v1(
        SETTLEMENT_VERIFIER_DOMAIN_V1,
        &[ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1],
    )?;
    let schema_digest = context_digest_v1(
        SETTLEMENT_SCHEMA_DOMAIN_V1,
        &[PRIVATE_SETTLEMENT_PROOF_PROFILE_DESCRIPTOR_V1],
    )?;
    let engine_digest = context_digest_v1(
        SETTLEMENT_ENGINE_DOMAIN_V1,
        &[ATOMIC_PRIVATE_SETTLEMENT_RELATION_DESCRIPTOR_V1],
    )?;
    let mut internal = IrohaIvmPrivateNoteStarkStatementV1 {
        context: PrivacyStatementContextV1 {
            network_id: statement.network_id,
            action_index: u32::from(statement.leg_ordinal),
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(context_material),
            parameter_id: PrivacyParameterIdV1::new(parameter_id),
            parameter_digest: PrivacyParameterDigestV1::new(parameter_digest),
            verifier_digest: PrivacyVerifierDigestV1::new(verifier_digest),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new(schema_digest),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new(engine_digest),
        },
        asset_definition_id: synthetic_asset_v1()?,
        public_balance_scope: AssetBalanceScope::Global,
        pool_id: statement.pool_id,
        program_id: atomic_private_settlement_program_id_v1()?,
        action_digest: PrivacyActionDigestV1::new([0; 32]),
        state_root: statement.old_root,
        root_epoch: statement.old_epoch,
        nullifiers: statement.nullifiers.clone(),
        output_commitments: statement.output_commitments.clone(),
        encrypted_outputs: statement.encrypted_outputs.clone(),
        value_balance: PrivacyValueBalanceV1::balanced(),
        execution_epoch: statement.old_epoch,
    };
    internal.action_digest = internal
        .computed_action_digest()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?;
    Ok(internal)
}

pub fn relation_profile_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
) -> Result<PrivateNoteRelationProfileV1, AtomicPrivateSettlementRelationErrorV1> {
    Ok(PrivateNoteRelationProfileV1::exact_three_output_balanced(
        atomic_private_settlement_output_memo_digests_v1(manifest, statement)?,
        statement.audit_input_commitment,
    ))
}

/// Commit the exact two auditor-visible input openings used by the proof.
///
/// The private nonce and blinding are included, so honestly randomized openings
/// do not permit testing pairs of public note commitments. Activity is derived
/// from the value and must agree with the capsule's declared selector. The
/// result preserves all 256 SHA-256 bits without Iroha entity-hash markers.
///
/// # Errors
///
/// Rejects a noncanonical fixed-slot shape, activity, dummy domain, note
/// opening, or commitment before producing a digest.
pub fn atomic_private_settlement_audit_input_commitment_v1(
    openings: &[PrivateSettlementAuditNoteOpeningV1],
) -> Result<[u8; 32], AtomicPrivateSettlementRelationErrorV1> {
    if openings.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
    }
    // Note validation is independent of the finalized binding. This profile
    // is used only to construct the openings whose digest is being computed.
    let profile = PrivateNoteRelationProfileV1::exact_three_output_balanced(
        [[1; 32]; PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1],
        [1; 32],
    );
    let mut notes = Vec::with_capacity(PRIVATE_SETTLEMENT_INPUT_SLOTS_V1);
    for opening in openings {
        if opening.active != (opening.value != 0)
            || opening.memo_digest == [0; 32]
            || if opening.active {
                opening.dummy_domain.is_some()
            } else {
                opening
                    .dummy_domain
                    .is_none_or(|domain| domain == Hash::prehashed([0; 32]))
            }
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        let note = PrivateNotePlaintextV1::new_profiled_input_v1(
            opening.value,
            opening.spending_authority,
            opening.rho,
            opening.blinding,
            opening.memo_digest,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
        if derive_profiled_input_commitment_v1(&note, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?
            != opening.commitment
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        notes.push(note);
    }
    derive_private_note_input_openings_commitment_v1(&notes)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
}

fn validate_audit_plaintext_against_statement_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    plaintext: &PrivateSettlementAuditPlaintextV1,
) -> Result<(), AtomicPrivateSettlementRelationErrorV1> {
    plaintext
        .validate_against_manifest(manifest)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
    let commitment = plaintext
        .commitment()
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?;
    if plaintext.leg_ordinal != statement.leg_ordinal
        || plaintext.route != statement.route
        || plaintext.pool_id != statement.pool_id
        || plaintext
            .asset_binding_commitment()
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?
            != statement.asset_binding_commitment
        || plaintext.fee_intent_digest != statement.fee_intent_digest
        || plaintext.settlement_expiry_height != statement.expiry_height
        || commitment != statement.audit_plaintext_commitment
        || (plaintext.leg_ordinal == statement.reimbursement_leg_ordinal)
            != (plaintext.sponsor_reimbursement_amount != 0)
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
    }
    if plaintext.leg_ordinal == statement.reimbursement_leg_ordinal
        && plaintext
            .reimbursement_terms_commitment()
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::CanonicalEncoding)?
            != statement.reimbursement_terms_commitment
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
    }
    Ok(())
}

fn validate_output_view_key_authorizations_v1(
    plaintext: &PrivateSettlementAuditPlaintextV1,
) -> Result<(), AtomicPrivateSettlementRelationErrorV1> {
    for (index, output) in plaintext.outputs.iter().enumerate() {
        let expected_body = plaintext
            .output_view_key_authorization_body(index)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
        let authorization = &output.view_key_authorization;
        if output.role != expected_body.role || authorization.body != expected_body {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        match expected_body.authorized_account.controller() {
            AccountController::Single(signatory) => {
                let [entry] = authorization.signatures.as_slice() else {
                    return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
                };
                if &entry.signer != signatory
                    || entry.signature.verify(signatory, &expected_body).is_err()
                {
                    return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
                }
            }
            AccountController::Multisig(policy) => {
                if authorization.signatures.is_empty()
                    || authorization
                        .signatures
                        .windows(2)
                        .any(|pair| pair[0].signer >= pair[1].signer)
                {
                    return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
                }
                let mut approved_weight = 0_u32;
                for entry in &authorization.signatures {
                    let member = policy
                        .members()
                        .iter()
                        .find(|member| member.public_key() == &entry.signer)
                        .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
                    entry
                        .signature
                        .verify(&entry.signer, &expected_body)
                        .map_err(|_| {
                            AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial
                        })?;
                    approved_weight = approved_weight
                        .checked_add(u32::from(member.weight()))
                        .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
                }
                if approved_weight < u32::from(policy.threshold()) {
                    return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
                }
            }
        }
    }
    Ok(())
}

fn validate_payer_input_authorization_v1(
    plaintext: &PrivateSettlementAuditPlaintextV1,
    statement: &PrivateSettlementProofStatementV1,
) -> Result<(), AtomicPrivateSettlementRelationErrorV1> {
    let expected_body = plaintext
        .payer_authorization_body(&statement.nullifiers)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
    let authorization = &plaintext.payer_authorization;
    if authorization.body != expected_body {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
    }
    match expected_body.payer.controller() {
        AccountController::Single(signatory) => {
            let [entry] = authorization.signatures.as_slice() else {
                return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
            };
            if &entry.signer != signatory
                || entry.signature.verify(signatory, &expected_body).is_err()
            {
                return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
            }
        }
        AccountController::Multisig(policy) => {
            if authorization.signatures.is_empty()
                || authorization
                    .signatures
                    .windows(2)
                    .any(|pair| pair[0].signer >= pair[1].signer)
            {
                return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
            }
            let mut approved_weight = 0_u32;
            for entry in &authorization.signatures {
                let member = policy
                    .members()
                    .iter()
                    .find(|member| member.public_key() == &entry.signer)
                    .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
                entry
                    .signature
                    .verify(&entry.signer, &expected_body)
                    .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
                approved_weight = approved_weight
                    .checked_add(u32::from(member.weight()))
                    .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
            }
            if approved_weight < u32::from(policy.threshold()) {
                return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
            }
        }
    }
    Ok(())
}

/// Recompute every note commitment and recipient binding visible to an auditor.
///
/// Input nullifiers remain proof-only because the capsule intentionally never
/// contains spending secrets. All commitment openings, fixed output memos,
/// dummy-input memo domains, role-account authorization thresholds, one-time
/// output recipients, and ciphertext encryption openings are checked here
/// without revealing a spending secret to ordinary committee validators.
#[doc(hidden)]
pub fn validate_audit_openings_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    plaintext: &PrivateSettlementAuditPlaintextV1,
) -> Result<(), AtomicPrivateSettlementRelationErrorV1> {
    validate_audit_plaintext_against_statement_v1(manifest, statement, plaintext)?;
    if atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)?
        != statement.audit_input_commitment
    {
        return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
    }
    validate_payer_input_authorization_v1(plaintext, statement)?;
    validate_output_view_key_authorizations_v1(plaintext)?;
    let profile = relation_profile_v1(manifest, statement)?;
    for (index, opening) in plaintext.inputs.iter().enumerate() {
        if !opening.active
            && opening.memo_digest
                != atomic_private_settlement_dummy_input_memo_digest_v1(
                    manifest,
                    statement,
                    index,
                    opening
                        .dummy_domain
                        .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?,
                )?
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        let note = PrivateNotePlaintextV1::new_profiled_input_v1(
            opening.value,
            opening.spending_authority,
            opening.rho,
            opening.blinding,
            opening.memo_digest,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
        if derive_profiled_input_commitment_v1(&note, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?
            != opening.commitment
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
    }
    let fixed_memos = atomic_private_settlement_output_memo_digests_v1(manifest, statement)?;
    let program_id = atomic_private_settlement_program_id_v1()?;
    for (index, (output, expected_memo)) in plaintext.outputs.iter().zip(fixed_memos).enumerate() {
        if output.note.memo_digest != expected_memo
            || derive_ivm_private_recipient_id_v1(output.recipient_view_key)
                .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?
                != statement.encrypted_outputs[index].recipient
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        let note = PrivateNotePlaintextV1::new_profiled_output_v1(
            output.note.value,
            output.note.spending_authority,
            output.note.rho,
            output.note.blinding,
            output.note.memo_digest,
            index,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
        if derive_profiled_output_commitment_v1(&note, index, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?
            != output.note.commitment
            || output.note.commitment != statement.output_commitments[index]
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        validate_ivm_private_wallet_encryption_opening_v1(
            statement.pool_id,
            program_id,
            &note,
            output.note.commitment,
            &statement.encrypted_outputs[index],
            output.recipient_view_key,
            &output.encryption_opening.ephemeral_secret,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?;
    }
    Ok(())
}

pub struct CompiledAtomicPrivateSettlementRelationV1 {
    pub(crate) internal_statement: IrohaIvmPrivateNoteStarkStatementV1,
    pub(crate) witness: IvmPrivateNoteWitnessV1,
    pub(crate) profile: PrivateNoteRelationProfileV1,
}

pub fn compile_witness_v1(
    manifest: &AtomicPrivateSettlementV1,
    statement: &PrivateSettlementProofStatementV1,
    witness: &AtomicPrivateSettlementProverWitnessV1,
) -> Result<CompiledAtomicPrivateSettlementRelationV1, AtomicPrivateSettlementRelationErrorV1> {
    validate_audit_openings_v1(manifest, statement, &witness.audit_plaintext)?;
    let internal_statement = internal_statement_v1(manifest, statement)?;
    let profile = relation_profile_v1(manifest, statement)?;
    let fixed_memos = atomic_private_settlement_output_memo_digests_v1(manifest, statement)?;

    let mut inputs = Vec::with_capacity(PRIVATE_SETTLEMENT_INPUT_SLOTS_V1);
    for (index, (opening, spend)) in witness
        .audit_plaintext
        .inputs
        .iter()
        .zip(&witness.inputs)
        .enumerate()
    {
        if !opening.active
            && opening.memo_digest
                != atomic_private_settlement_dummy_input_memo_digest_v1(
                    manifest,
                    statement,
                    index,
                    opening
                        .dummy_domain
                        .ok_or(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?,
                )?
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        if derive_note_authority_v1(&spend.spending_secret)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?
            != opening.spending_authority
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidWitness);
        }
        let note = PrivateNotePlaintextV1::new_profiled_input_v1(
            opening.value,
            opening.spending_authority,
            opening.rho,
            opening.blinding,
            opening.memo_digest,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
        if derive_profiled_input_commitment_v1(&note, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?
            != opening.commitment
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidWitness);
        }
        let input = IvmPrivateNoteInputWitnessV1::new_with_profile_v1(
            note,
            spend.spending_secret,
            spend.leaf_position,
            spend.authentication_path,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
        if input
            .nullifier_with_profile_v1(&internal_statement, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?
            != statement.nullifiers[index]
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidWitness);
        }
        inputs.push(input);
    }

    let mut outputs = Vec::with_capacity(PRIVATE_SETTLEMENT_OUTPUT_SLOTS_V1);
    for (index, (output, expected_memo)) in witness
        .audit_plaintext
        .outputs
        .iter()
        .zip(fixed_memos)
        .enumerate()
    {
        if output.note.memo_digest != expected_memo
            || derive_ivm_private_recipient_id_v1(output.recipient_view_key)
                .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)?
                != statement.encrypted_outputs[index].recipient
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial);
        }
        let note = PrivateNotePlaintextV1::new_profiled_output_v1(
            output.note.value,
            output.note.spending_authority,
            output.note.rho,
            output.note.blinding,
            output.note.memo_digest,
            index,
            profile,
        )
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
        let commitment = derive_profiled_output_commitment_v1(&note, index, profile)
            .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
        if commitment != output.note.commitment || commitment != statement.output_commitments[index]
        {
            return Err(AtomicPrivateSettlementRelationErrorV1::InvalidWitness);
        }
        outputs.push(
            IvmPrivateNoteOutputWitnessV1::new_with_profile_v1(note, index, profile)
                .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?,
        );
    }

    let private_witness = IvmPrivateNoteWitnessV1::new_with_profile_v1(
        settlement_program_v1()?,
        inputs,
        outputs,
        profile,
    )
    .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
    preflight_private_note_relation_with_profile_v1(&internal_statement, &private_witness, profile)
        .map_err(|_| AtomicPrivateSettlementRelationErrorV1::InvalidWitness)?;
    Ok(CompiledAtomicPrivateSettlementRelationV1 {
        internal_statement,
        witness: private_witness,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::{
        atomic_private_settlement::{
            test_fixtures::aps_sidecar_material_fixture_v1 as sidecar_fixture,
            wallet::{
                derive_atomic_private_settlement_input_nullifiers_v1,
                prepare_atomic_private_settlement_input_openings_v1,
                prepare_atomic_private_settlement_outputs_v1,
            },
        },
        ivm_private_note::{
            accumulator_leaf_digest_for_testing_v1, accumulator_node_digest_for_testing_v1,
            ivm_private_recipient_public_key_v1,
        },
        proof_managed_accumulator::{
            append_proof_managed_commitments_v1, build_proof_managed_frontier_v1,
        },
    };
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
    use iroha_data_model::{
        account::{AccountId, MultisigMember, MultisigPolicy},
        nexus::{
            PrivateSettlementAuditOutputRoleV1, PrivateSettlementAuditPayerAuthorizationBodyV1,
            PrivateSettlementAuditPayerAuthorizationV1, PrivateSettlementAuditPayerSignatureV1,
            PrivateSettlementAuditViewKeyAuthorizationBodyV1,
            PrivateSettlementAuditViewKeyAuthorizationV1, PrivateSettlementAuditViewKeySignatureV1,
        },
        privacy::{
            PrivacyCommitmentV1, PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyNullifierV1,
            PrivacyPoolProgramNamespaceV1, PrivacyProtocolIdV1, PrivacyRootV1,
        },
    };
    use rand_08::{SeedableRng as _, rngs::StdRng};

    fn signature_entry(
        signer: &KeyPair,
        body: &PrivateSettlementAuditViewKeyAuthorizationBodyV1,
    ) -> PrivateSettlementAuditViewKeySignatureV1 {
        PrivateSettlementAuditViewKeySignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), body).expect("authorization signs"),
        )
    }

    fn payer_signature_entry(
        signer: &KeyPair,
        body: &PrivateSettlementAuditPayerAuthorizationBodyV1,
    ) -> PrivateSettlementAuditPayerSignatureV1 {
        PrivateSettlementAuditPayerSignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), body).expect("payer authorization signs"),
        )
    }

    fn recommit_audit_input(opening: &mut PrivateSettlementAuditNoteOpeningV1) {
        let profile =
            PrivateNoteRelationProfileV1::exact_three_output_balanced([[1; 32]; 3], [1; 32]);
        let note = PrivateNotePlaintextV1::new_profiled_input_v1(
            opening.value,
            opening.spending_authority,
            opening.rho,
            opening.blinding,
            opening.memo_digest,
            profile,
        )
        .expect("input opening constructs");
        opening.commitment =
            derive_profiled_input_commitment_v1(&note, profile).expect("input commitment");
    }

    fn continuation_membership_path(
        statement: &IrohaIvmPrivateNoteStarkStatementV1,
        commitments: &[PrivacyCommitmentV1],
        mut position: usize,
    ) -> ([u8; 32], [[u8; 32]; PRIVATE_NOTE_TREE_DEPTH_V1]) {
        let mut nodes: Vec<_> = commitments
            .iter()
            .map(|commitment| {
                accumulator_leaf_digest_for_testing_v1(statement, 0, *commitment)
                    .expect("historical leaf")
            })
            .collect();
        let mut empty: [u8; 32] =
            Sha256::digest(b"iroha.privacy.proof-managed-note-tree.empty-leaf.v1").into();
        let path = core::array::from_fn(|level| {
            let sibling = nodes.get(position ^ 1).copied().unwrap_or(empty);
            let level = u8::try_from(level).expect("depth fits u8");
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    accumulator_node_digest_for_testing_v1(
                        0,
                        level,
                        &pair[0],
                        pair.get(1).unwrap_or(&empty),
                    )
                    .expect("historical subtree")
                })
                .collect();
            empty = accumulator_node_digest_for_testing_v1(0, level, &empty, &empty)
                .expect("empty subtree");
            position >>= 1;
            sibling
        });
        assert_eq!(position, 0);
        (nodes[0], path)
    }

    #[test]
    fn wallet_continues_settlement_with_fresh_virtual_dummy_without_bootstrap() {
        let fixture = sidecar_fixture();
        let mut manifest = fixture.sidecar.manifest;
        let mut statement = fixture.sidecar.payload.statement;
        let mut plaintext = fixture.plaintext;
        let namespace = PrivacyNamespaceV1::new(
            PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
                pool_id: statement.pool_id,
                program_id: atomic_private_settlement_program_id_v1().expect("program"),
            }),
        );
        let mut historical_commitments: Vec<_> = plaintext
            .inputs
            .iter()
            .map(|input| input.commitment)
            .collect();
        historical_commitments.sort_unstable();
        let mut frontier = build_proof_managed_frontier_v1(namespace, &historical_commitments)
            .expect("one governed origin");
        let mut rng = StdRng::seed_from_u64(0x4150_535f_434f_4e54);
        let recipient = KeyPair::from_seed(vec![0x39; 32], Algorithm::Ed25519);
        let sponsor = KeyPair::from_seed(vec![0x23; 32], Algorithm::Ed25519);
        let mut previous_dummy_nullifier = None;
        for settlement in 0_u8..2 {
            let payer = KeyPair::from_seed(
                vec![if settlement == 0 { 0x38 } else { 0x39 }; 32],
                Algorithm::Ed25519,
            );
            manifest.authority_context_height = 10 + u64::from(settlement);
            manifest.bundle_id = manifest.computed_bundle_id().expect("fresh bundle");
            statement.bundle_id = manifest.bundle_id;
            statement.authority_context_height = manifest.authority_context_height;
            statement.old_root = frontier.root;
            statement.old_epoch = 1 + u64::from(settlement);
            statement.new_epoch = statement.old_epoch + 1;
            // Output preparation precedes the deterministic frontier append.
            statement.new_root = PrivacyRootV1::new([0xE0 + settlement; 32]);
            plaintext.bundle_id = manifest.bundle_id;
            plaintext.payer = AccountId::new(payer.public_key().clone());
            plaintext.amount = plaintext.inputs[0].value - 5;
            plaintext.outputs[0].note.value = plaintext.amount;
            prepare_atomic_private_settlement_input_openings_v1(
                &manifest,
                &statement,
                &mut plaintext.inputs,
            )
            .expect("prepare live note and current-bundle virtual dummy");
            if settlement != 0 {
                assert!(
                    !historical_commitments.contains(&plaintext.inputs[1].commitment),
                    "the second bundle's dummy was never inserted into the pool"
                );
            }
            let secrets = [[if settlement == 0 { 0x81 } else { 0x91 }; 32], [0x82; 32]];
            statement.nullifiers = derive_atomic_private_settlement_input_nullifiers_v1(
                &manifest,
                &statement,
                &plaintext.inputs,
                &secrets,
            )
            .expect("pool-scoped nullifiers")
            .to_vec();
            if let Some(previous) = previous_dummy_nullifier {
                assert_ne!(
                    statement.nullifiers[1], previous,
                    "dummy cannot replay the old nullifier"
                );
            }
            previous_dummy_nullifier = Some(statement.nullifiers[1]);
            let payer_body = plaintext
                .payer_authorization_body(&statement.nullifiers)
                .expect("current payer authorization");
            plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
                payer_body.clone(),
                vec![payer_signature_entry(&payer, &payer_body)],
            );
            for (index, key) in [&recipient, &payer, &sponsor].into_iter().enumerate() {
                plaintext.outputs[index].recipient_view_key = ivm_private_recipient_public_key_v1(
                    &[0xA1 + u8::try_from(index).unwrap() + settlement * 3; 32],
                )
                .expect("fresh output view key");
                plaintext.outputs[index].note.rho[0] ^= settlement;
                let body = plaintext
                    .output_view_key_authorization_body(index)
                    .expect("output role authorization");
                plaintext.outputs[index].view_key_authorization =
                    PrivateSettlementAuditViewKeyAuthorizationV1::new(
                        body.clone(),
                        vec![signature_entry(key, &body)],
                    );
            }
            statement.audit_plaintext_commitment =
                plaintext.commitment().expect("audit commitment");
            statement.audit_input_commitment =
                atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)
                    .expect("AIR input binding");
            statement.encrypted_outputs = prepare_atomic_private_settlement_outputs_v1(
                &mut rng,
                &manifest,
                &statement,
                &mut plaintext.outputs,
            )
            .expect("current fixed output ciphertexts");
            statement.output_commitments = plaintext
                .outputs
                .iter()
                .map(|output| output.note.commitment)
                .collect();
            let next_frontier = append_proof_managed_commitments_v1(
                namespace,
                frontier.tree_size,
                frontier.leaf,
                &frontier.ommers,
                frontier.root,
                &statement.output_commitments,
            )
            .expect("append outputs to the existing frontier");
            statement.new_root = next_frontier.root;
            let active_position = historical_commitments
                .iter()
                .position(|commitment| *commitment == plaintext.inputs[0].commitment)
                .expect("the actual funding note is already in the pool");
            let internal = internal_statement_v1(&manifest, &statement).expect("current statement");
            let (root, path) =
                continuation_membership_path(&internal, &historical_commitments, active_position);
            assert_eq!(
                PrivacyRootV1::new(root),
                frontier.root,
                "path matches canonical frontier"
            );
            let witness = AtomicPrivateSettlementProverWitnessV1::new(
                plaintext.clone(),
                [
                    AtomicPrivateSettlementInputWitnessV1::new(
                        secrets[0],
                        u32::try_from(active_position).unwrap(),
                        path,
                    )
                    .expect("live membership"),
                    AtomicPrivateSettlementInputWitnessV1::new(
                        secrets[1],
                        u32::try_from(active_position ^ 1).unwrap(),
                        [[0xED; 32]; PRIVATE_NOTE_TREE_DEPTH_V1],
                    )
                    .expect("virtual dummy secret and fixed-shape path"),
                ],
            );
            compile_witness_v1(&manifest, &statement, &witness)
                .unwrap_or_else(|error| {
                    panic!(
                        "full audit validation and relation preflight reject settlement {settlement}: {error:?}"
                    )
                });
            historical_commitments.extend(&statement.output_commitments);
            frontier = next_frontier;
            plaintext.inputs[0] = plaintext.outputs[0].note.clone();
        }
        assert_eq!(
            frontier.tree_size, 8,
            "one origin and two three-output appends"
        );
    }

    #[test]
    fn audit_input_commitment_preserves_both_raw_sha256_low_bit_parities() {
        let fixture = sidecar_fixture();
        let mut inputs = fixture.plaintext.inputs.clone();
        let profile =
            PrivateNoteRelationProfileV1::exact_three_output_balanced([[1; 32]; 3], [1; 32]);
        let mut observed_parities = [false; 2];
        for nonce in 0_u8..=u8::MAX {
            inputs[0].rho[0] = nonce;
            recommit_audit_input(&mut inputs[0]);
            let notes = inputs
                .iter()
                .map(|opening| {
                    PrivateNotePlaintextV1::new_profiled_input_v1(
                        opening.value,
                        opening.spending_authority,
                        opening.rho,
                        opening.blinding,
                        opening.memo_digest,
                        profile,
                    )
                    .expect("canonical input note")
                })
                .collect::<Vec<_>>();
            let raw_digest = derive_private_note_input_openings_commitment_v1(&notes)
                .expect("raw SHA-256 digest consumed by the AIR");
            let public_digest = atomic_private_settlement_audit_input_commitment_v1(&inputs)
                .expect("public input opening commitment");
            assert_eq!(
                public_digest, raw_digest,
                "the public field must not apply Iroha entity-hash marker bits"
            );
            observed_parities[usize::from(raw_digest[31] & 1)] = true;
            if observed_parities == [true; 2] {
                break;
            }
        }
        assert_eq!(observed_parities, [true; 2]);
    }

    #[test]
    fn audit_input_commitment_binds_order_and_every_opening_field() {
        let fixture = sidecar_fixture();
        let inputs = fixture.plaintext.inputs.clone();
        let expected = atomic_private_settlement_audit_input_commitment_v1(&inputs)
            .expect("canonical input commitment");
        assert_eq!(
            expected,
            fixture.sidecar.payload.statement.audit_input_commitment
        );
        for field in 0..5 {
            let mut substituted = inputs.clone();
            match field {
                0 => substituted[0].value += 1,
                1 => substituted[0].spending_authority[0] ^= 1,
                2 => substituted[0].rho[0] ^= 1,
                3 => substituted[0].blinding[0] ^= 1,
                4 => substituted[0].memo_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                atomic_private_settlement_audit_input_commitment_v1(&substituted).is_err(),
                "a stale note commitment cannot open substituted field {field}"
            );
            recommit_audit_input(&mut substituted[0]);
            assert_ne!(
                atomic_private_settlement_audit_input_commitment_v1(&substituted)
                    .expect("substituted opening is self-consistent"),
                expected,
                "the full input hash must bind field {field}"
            );
        }
        let mut reordered = inputs.clone();
        reordered.reverse();
        assert_ne!(
            atomic_private_settlement_audit_input_commitment_v1(&reordered)
                .expect("reordered openings remain well-formed"),
            expected
        );
        assert!(atomic_private_settlement_audit_input_commitment_v1(&inputs[..1]).is_err());
        let mut wrong_activity = inputs.clone();
        wrong_activity[1].active = true;
        wrong_activity[1].dummy_domain = None;
        assert!(atomic_private_settlement_audit_input_commitment_v1(&wrong_activity).is_err());
        let mut missing_domain = inputs;
        missing_domain[1].dummy_domain = None;
        assert!(atomic_private_settlement_audit_input_commitment_v1(&missing_domain).is_err());
    }

    #[test]
    fn auditor_rejects_self_consistent_resigned_input_substitution() {
        let fixture = sidecar_fixture();
        let mut statement = fixture.sidecar.payload.statement;
        let mut plaintext = fixture.plaintext;
        plaintext.inputs[0].value -= 1;
        plaintext.inputs[1].value = 1;
        plaintext.inputs[1].active = true;
        plaintext.inputs[1].dummy_domain = None;
        for input in &mut plaintext.inputs {
            recommit_audit_input(input);
        }
        let payer = KeyPair::from_seed(vec![0x38; 32], Algorithm::Ed25519);
        let body = plaintext
            .payer_authorization_body(&statement.nullifiers)
            .expect("substituted payer body");
        plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            body.clone(),
            vec![payer_signature_entry(&payer, &body)],
        );
        statement.audit_plaintext_commitment =
            plaintext.commitment().expect("refreshed capsule hash");
        validate_audit_plaintext_against_statement_v1(
            &fixture.sidecar.manifest,
            &statement,
            &plaintext,
        )
        .expect("substituted plaintext has the same balanced value and public context");
        validate_payer_input_authorization_v1(&plaintext, &statement)
            .expect("the cooperating payer signed the substituted funding provenance");
        assert_ne!(
            atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)
                .expect("self-consistent substitute input openings"),
            statement.audit_input_commitment
        );
        assert_eq!(
            validate_audit_openings_v1(&fixture.sidecar.manifest, &statement, &plaintext),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial),
            "the auditor must match the capsule openings to the AIR input binding"
        );
    }

    #[test]
    fn internal_statement_allows_post_proof_artifacts_to_be_finalized() {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        let canonical_genesis_hash = *manifest.network_id.as_genesis_hash().as_ref();
        validate_public_binding_v1(manifest, statement, canonical_genesis_hash, 10)
            .expect("provisional manifest binds public intent");
        let provisional =
            internal_statement_v1(manifest, statement).expect("provisional statement compiles");

        let mut finalized_manifest = manifest.clone();
        finalized_manifest.legs[0].payload_digest = iroha_crypto::Hash::new(b"final payload");
        finalized_manifest.legs[0].availability_certificate_digest =
            iroha_crypto::Hash::new(b"final availability certificate");
        finalized_manifest.legs[0].delta_digest = iroha_crypto::Hash::new(b"final delta");
        validate_public_binding_v1(&finalized_manifest, statement, canonical_genesis_hash, 10)
            .expect("finalized manifest binds the same public intent");
        assert_eq!(
            provisional,
            internal_statement_v1(&finalized_manifest, statement)
                .expect("finalized statement compiles")
        );
    }

    #[test]
    fn exact_role_accounts_authorize_every_fixed_output_view_key() {
        let fixture = sidecar_fixture();
        validate_output_view_key_authorizations_v1(&fixture.plaintext)
            .expect("fixture role accounts authorize all view keys");

        let mut substituted_recipient = fixture.plaintext.clone();
        substituted_recipient.outputs[0].recipient_view_key =
            ivm_private_recipient_public_key_v1(&[0xE1; 32]).expect("alternate view key");
        assert_eq!(
            validate_output_view_key_authorizations_v1(&substituted_recipient),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let wrong_sponsor = KeyPair::from_seed(vec![0xE2; 32], Algorithm::Ed25519);
        let mut substituted_sponsor = fixture.plaintext.clone();
        let sponsor_body = substituted_sponsor.outputs[2]
            .view_key_authorization
            .body
            .clone();
        substituted_sponsor.outputs[2].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                sponsor_body.clone(),
                vec![signature_entry(&wrong_sponsor, &sponsor_body)],
            );
        assert_eq!(
            validate_output_view_key_authorizations_v1(&substituted_sponsor),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut wrong_role = fixture.plaintext;
        wrong_role.outputs[1].role = PrivateSettlementAuditOutputRoleV1::SponsorReimbursement;
        assert_eq!(
            validate_output_view_key_authorizations_v1(&wrong_role),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );
    }

    #[test]
    fn payer_authorization_binds_every_fixed_input_and_context_field() {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        validate_payer_input_authorization_v1(&fixture.plaintext, statement)
            .expect("fixture payer authorizes both fixed input slots");

        let payer = KeyPair::from_seed(vec![0x38; 32], Algorithm::Ed25519);
        let attacker = KeyPair::from_seed(vec![0xE7; 32], Algorithm::Ed25519);
        let mut wrong_payer = fixture.plaintext.clone();
        wrong_payer.payer = AccountId::new(attacker.public_key().clone());
        assert_eq!(
            validate_payer_input_authorization_v1(&wrong_payer, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial),
            "the original payer signature cannot authorize a substituted payer"
        );
        let wrong_payer_body = wrong_payer
            .payer_authorization_body(&statement.nullifiers)
            .expect("substituted payer body");
        wrong_payer.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            wrong_payer_body.clone(),
            vec![payer_signature_entry(&attacker, &wrong_payer_body)],
        );
        assert_eq!(
            validate_audit_openings_v1(manifest, statement, &wrong_payer),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial),
            "a self-signed substituted payer cannot open the proof-bound audit commitment"
        );

        let mut substituted_input = fixture.plaintext.clone();
        substituted_input.inputs[0].commitment = PrivacyCommitmentV1::new([0xE8; 32]);
        assert_eq!(
            validate_payer_input_authorization_v1(&substituted_input, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut substituted_ordinal = fixture.plaintext.clone();
        let mut ordinal_body = substituted_ordinal.payer_authorization.body.clone();
        ordinal_body.inputs[0].input_ordinal = 1;
        substituted_ordinal.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            ordinal_body.clone(),
            vec![payer_signature_entry(&payer, &ordinal_body)],
        );
        assert_eq!(
            validate_payer_input_authorization_v1(&substituted_ordinal, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut substituted_statement = statement.clone();
        substituted_statement.nullifiers[0] = PrivacyNullifierV1::new([0xE9; 32]);
        assert_eq!(
            validate_payer_input_authorization_v1(&fixture.plaintext, &substituted_statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut substituted_authority = fixture.plaintext.clone();
        substituted_authority.inputs[0].spending_authority[0] ^= 1;
        assert_eq!(
            validate_payer_input_authorization_v1(&substituted_authority, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut substituted_selector = fixture.plaintext.clone();
        substituted_selector.inputs[1].active = true;
        assert_eq!(
            validate_payer_input_authorization_v1(&substituted_selector, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut substituted_expiry = fixture.plaintext.clone();
        let mut expiry_body = substituted_expiry.payer_authorization.body.clone();
        expiry_body.expiry_height -= 1;
        substituted_expiry.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            expiry_body.clone(),
            vec![payer_signature_entry(&payer, &expiry_body)],
        );
        assert_eq!(
            validate_payer_input_authorization_v1(&substituted_expiry, statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );
    }

    #[test]
    fn multisig_payer_authorization_requires_controller_weight() {
        let fixture = sidecar_fixture();
        let statement = fixture.sidecar.payload.statement.clone();
        let first = KeyPair::from_seed(vec![0xEA; 32], Algorithm::Ed25519);
        let second = KeyPair::from_seed(vec![0xEB; 32], Algorithm::Ed25519);
        let third = KeyPair::from_seed(vec![0xEC; 32], Algorithm::Ed25519);
        let policy = MultisigPolicy::new(
            3,
            vec![
                MultisigMember::new(first.public_key().clone(), 2).expect("first member"),
                MultisigMember::new(second.public_key().clone(), 1).expect("second member"),
                MultisigMember::new(third.public_key().clone(), 1).expect("third member"),
            ],
        )
        .expect("weighted threshold controller");
        let mut plaintext = fixture.plaintext;
        plaintext.payer = AccountId::new_multisig(policy);
        let body = plaintext
            .payer_authorization_body(&statement.nullifiers)
            .expect("multisig payer authorization body");
        plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            body.clone(),
            vec![payer_signature_entry(&first, &body)],
        );
        assert_eq!(
            validate_payer_input_authorization_v1(&plaintext, &statement),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
            body.clone(),
            vec![
                payer_signature_entry(&first, &body),
                payer_signature_entry(&second, &body),
            ],
        );
        validate_payer_input_authorization_v1(&plaintext, &statement)
            .expect("weighted payer authorization reaches threshold");
    }

    #[test]
    fn multisig_view_key_authorization_requires_controller_threshold() {
        let fixture = sidecar_fixture();
        let first = KeyPair::from_seed(vec![0xE3; 32], Algorithm::Ed25519);
        let second = KeyPair::from_seed(vec![0xE4; 32], Algorithm::Ed25519);
        let third = KeyPair::from_seed(vec![0xE5; 32], Algorithm::Ed25519);
        let policy = MultisigPolicy::new(
            3,
            vec![
                MultisigMember::new(first.public_key().clone(), 2).expect("first member"),
                MultisigMember::new(second.public_key().clone(), 1).expect("second member"),
                MultisigMember::new(third.public_key().clone(), 1).expect("third member"),
            ],
        )
        .expect("weighted threshold controller");
        let mut plaintext = fixture.plaintext;
        plaintext.recipient = AccountId::new_multisig(policy);
        let body = plaintext
            .output_view_key_authorization_body(0)
            .expect("multisig authorization body");
        plaintext.outputs[0].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![signature_entry(&first, &body)],
            );
        assert_eq!(
            validate_output_view_key_authorizations_v1(&plaintext),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        plaintext.outputs[0].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![
                    signature_entry(&first, &body),
                    signature_entry(&second, &body),
                ],
            );
        validate_output_view_key_authorizations_v1(&plaintext)
            .expect("weighted authorization reaches threshold");
    }

    #[test]
    fn auditor_rejects_tampered_or_unusable_output_ciphertext() {
        let fixture = sidecar_fixture();
        let manifest = &fixture.sidecar.manifest;
        let statement = &fixture.sidecar.payload.statement;
        assert!(
            !fixture.plaintext.outputs[1].note.active,
            "the payer-change slot exercises encrypted zero-value cover handling"
        );
        validate_audit_openings_v1(manifest, statement, &fixture.plaintext)
            .expect("fixture ciphertexts open to committed notes");

        let mut tampered = statement.clone();
        let last = tampered.encrypted_outputs[0].ciphertext.len() - 1;
        tampered.encrypted_outputs[0].ciphertext[last] ^= 1;
        assert_eq!(
            validate_audit_openings_v1(manifest, &tampered, &fixture.plaintext),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );

        let mut unusable = statement.clone();
        unusable.encrypted_outputs[2].ephemeral_public_key =
            iroha_data_model::privacy::PrivacyEncryptionKeyV1::new(
                ivm_private_recipient_public_key_v1(&[0xE6; 32])
                    .expect("alternate ephemeral public key"),
            );
        assert_eq!(
            validate_audit_openings_v1(manifest, &unusable, &fixture.plaintext),
            Err(AtomicPrivateSettlementRelationErrorV1::InvalidAuditMaterial)
        );
    }
}
