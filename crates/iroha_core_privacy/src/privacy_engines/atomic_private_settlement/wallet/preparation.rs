//! General native preparation from authenticated public context and existing wallet secrets.
//! No plaintext witness is encoded, persisted or returned by this owner.
use super::*;
use crate::privacy_engines::{
    atomic_private_settlement::{
        audit::{
            PrivateSettlementAuditCryptoErrorV1, seal_private_settlement_audit_capsule_v1_with_rng,
        },
        relation::{
            AtomicPrivateSettlementRelationErrorV1, atomic_private_settlement_program_id_v1,
        },
    },
    ivm_private_note::derive_note_nullifier_for_namespace_v1,
    proof_managed_accumulator::{
        ProofManagedAccumulatorErrorV1, append_proof_managed_commitments_v1,
        validate_proof_managed_frontier_v1,
    },
    prover_randomness::{TryCryptoProverRandomnessErrorV1, derive_healthy_try_crypto_seed_v1},
};
use iroha_data_model::{
    nexus::{
        PrivateSettlementAuditAadV1, PrivateSettlementCapsulePaddingV1,
        PrivateSettlementProofProfileV1, VerifiedPrivateSettlementOpeningsV1,
    },
    privacy::{
        PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyPoolProgramNamespaceV1,
        PrivacyProtocolIdV1, PrivacyRootV1,
    },
};

/// Wallet-owned original openings and signatures, consumed once by native preparation.
///
/// The wallet reserves notes durably before returning this value, binds authorizations to the
/// independently requested business terms, and can recover that same reservation. Neither this
/// type nor its secret inputs have a serialization implementation.
pub struct AtomicPrivateSettlementAuthorizedWalletLegV1 {
    plaintext: PrivateSettlementAuditPlaintextV1,
    inputs: [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
}
impl AtomicPrivateSettlementAuthorizedWalletLegV1 {
    /// Move original authorized openings and membership secrets into native custody.
    #[must_use]
    pub fn new(
        plaintext: PrivateSettlementAuditPlaintextV1,
        inputs: [AtomicPrivateSettlementInputSecretV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    ) -> Self {
        Self { plaintext, inputs }
    }
    /// Inspect business terms before moving witnesses into the bounded producer.
    #[must_use]
    pub fn plaintext(&self) -> &PrivateSettlementAuditPlaintextV1 {
        &self.plaintext
    }
}
impl std::fmt::Debug for AtomicPrivateSettlementAuthorizedWalletLegV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AtomicPrivateSettlementAuthorizedWalletLegV1(<restricted>)")
    }
}

/// Closed preparation failures preserve the existing cryptographic/resource causes.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum AtomicPrivateSettlementPreparationErrorV1 {
    /// Context, user intent or exact signed opening does not agree.
    #[error("private preparation context or authorized opening differs")]
    Binding,
    /// Existing canonical codec failed without exposing witness contents.
    #[error("private preparation canonical encoding failed")]
    Encoding,
    /// Native wallet validation failed.
    #[error(transparent)]
    Wallet(#[from] AtomicPrivateSettlementWalletErrorV1),
    /// Original compact-frontier validation or append failed.
    #[error(transparent)]
    Frontier(#[from] ProofManagedAccumulatorErrorV1),
    /// Existing exact relation validation or compilation failed.
    #[error(transparent)]
    Relation(#[from] AtomicPrivateSettlementRelationErrorV1),
    /// Governed capsule sealing failed.
    #[error(transparent)]
    Audit(#[from] PrivateSettlementAuditCryptoErrorV1),
    /// Original cryptographic source is unavailable or unhealthy.
    #[error(transparent)]
    Randomness(#[from] TryCryptoProverRandomnessErrorV1),
    /// Genuine prover or mandatory independent verification failed.
    #[error(transparent)]
    Proof(#[from] AtomicPrivateSettlementProofErrorV1),
}

/// Prepare original input commitments and nullifiers before the wallet signs its payer body.
///
/// This consumes no signature authority and constructs no incomplete public statement. The
/// wallet retains these same notes and secrets in its existing reservation; the native producer
/// later rederives and checks every value before proving membership and conservation.
/// # Errors
/// Invalid intent/leg, wrong fixed input shape, substituted spending authority or duplicate input.
pub fn prepare_atomic_private_settlement_authorization_inputs_v1(
    intent: &PrivateSettlementProofIntentV1,
    ordinal: u8,
    openings: &mut [PrivateSettlementAuditNoteOpeningV1],
    spending_secrets: &[[u8; 32]; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
) -> Result<
    [PrivacyNullifierV1; PRIVATE_SETTLEMENT_INPUT_SLOTS_V1],
    AtomicPrivateSettlementPreparationErrorV1,
> {
    use AtomicPrivateSettlementPreparationErrorV1 as E;
    intent.validate().map_err(|_| E::Binding)?;
    let leg = intent.legs.get(usize::from(ordinal)).ok_or(E::Binding)?;
    if openings.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1 {
        return Err(E::Binding);
    }
    for (opening, secret) in openings.iter().zip(spending_secrets) {
        if derive_note_authority_v1(secret).map_err(|_| E::Binding)? != opening.spending_authority {
            return Err(E::Binding);
        }
    }
    prepare_input_openings_from_bound_context_v1(intent, ordinal, openings)?;
    let program = atomic_private_settlement_program_id_v1()?;
    let mut nullifiers = [PrivacyNullifierV1::new([0; 32]); PRIVATE_SETTLEMENT_INPUT_SLOTS_V1];
    for (index, (opening, secret)) in openings.iter().zip(spending_secrets).enumerate() {
        nullifiers[index] = derive_note_nullifier_for_namespace_v1(
            leg.pool_id,
            program,
            secret,
            &opening.rho,
            opening.commitment,
        )
        .map_err(|_| E::Binding)?;
    }
    if nullifiers[0] == nullifiers[1] {
        return Err(E::Binding);
    }
    Ok(nullifiers)
}

/// Plan, seal, prove and self-verify a general non-bootstrap private pool transition.
///
/// Only the existing fixed 2-input/3-output relation is used. Before proving, the original
/// frontier is rehashed, stable nullifiers and ordered outputs are checked against the exact
/// authenticated replay tables, and original payer/view authorizations are verified by the
/// existing relation. The draft is deliberately incomplete until actual values exist; no fake
/// proof, ciphertext or nonzero placeholder is accepted as an authenticated artifact.
/// # Errors
/// Foreign context/intent, unavailable original secrets/entropy, bad authorization or membership,
/// replay conflict, malformed frontier, fixed resource refusal or proof/self-verification failure.
pub fn prepare_atomic_private_settlement_leg_v1(
    manifest: &PrivateSettlementProofIntentV1,
    ordinal: u8,
    context: &VerifiedPrivateSettlementOpeningsV1<'_, '_>,
    wallet: AtomicPrivateSettlementAuthorizedWalletLegV1,
    padding: PrivateSettlementCapsulePaddingV1,
) -> Result<AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementPreparationErrorV1> {
    use AtomicPrivateSettlementPreparationErrorV1 as E;
    let cut = context.context().pool_cut();
    let pool = cut.pool();
    let governance = context.governance();
    let policy = context.policy();
    let leg = manifest.legs.get(usize::from(ordinal)).ok_or(E::Binding)?;
    context
        .context()
        .verify_intent(manifest, ordinal)
        .map_err(|_| E::Binding)?;
    if manifest.expiry_height != context.expiry_height() {
        return Err(E::Binding);
    }
    let program_id = atomic_private_settlement_program_id_v1()?;
    let namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        PrivacyNamespaceScopeV1::PoolProgram(PrivacyPoolProgramNamespaceV1 {
            pool_id: pool.pool_id,
            program_id,
        }),
    );
    validate_proof_managed_frontier_v1(
        namespace,
        pool.tree_size,
        pool.leaf,
        &pool.ommers,
        pool.root,
    )?;
    let AtomicPrivateSettlementAuthorizedWalletLegV1 {
        mut plaintext,
        inputs,
    } = wallet;
    if plaintext.leg_ordinal != ordinal
        || plaintext.asset_definition_id != governance.body.asset_definition_id
        || plaintext.asset_binding_salt != governance.body.asset_binding_salt
    {
        return Err(E::Binding);
    }
    let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
    // Private construction state only. The fully bound public statement is validated below
    // after its real nullifiers, encrypted outputs, successor root and capsule exist.
    let mut statement = PrivateSettlementProofStatementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        profile,
        proof_profile_digest: profile.digest(),
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal: ordinal,
        route: leg.route,
        authority_context_height: cut.height(),
        pool_id: pool.pool_id,
        asset_binding_commitment: leg.asset_binding_commitment,
        old_root: pool.root,
        new_root: PrivacyRootV1::new([0; 32]),
        old_epoch: pool.epoch,
        new_epoch: pool.epoch.checked_add(1).ok_or(E::Binding)?,
        nullifiers: Vec::new(),
        output_commitments: Vec::new(),
        encrypted_outputs: Vec::new(),
        audit_plaintext_commitment: Hash::prehashed([0; 32]),
        audit_input_commitment: [0; 32],
        audit_capsule_digest: Hash::prehashed([0; 32]),
        audit_policy_digest: policy.policy_digest,
        audit_key_epoch: policy.body.key_epoch,
        fee_intent_digest: manifest.fee_intent_digest,
        reimbursement_terms_commitment: manifest.reimbursement_terms_commitment,
        reimbursement_leg_ordinal: manifest.reimbursement_leg_ordinal,
        expiry_height: manifest.expiry_height,
    };
    prepare_input_openings_from_bound_context_v1(manifest, ordinal, &mut plaintext.inputs)?;
    for (opening, secret) in plaintext.inputs.iter().zip(&inputs) {
        if derive_note_authority_v1(&secret.spending_secret).map_err(|_| E::Binding)?
            != opening.spending_authority
        {
            return Err(E::Binding);
        }
        let nullifier = derive_note_nullifier_for_namespace_v1(
            pool.pool_id,
            program_id,
            &secret.spending_secret,
            &opening.rho,
            opening.commitment,
        )
        .map_err(|_| E::Binding)?;
        cut.verify_nullifier_absent(nullifier)
            .map_err(|_| E::Binding)?;
        statement.nullifiers.push(nullifier);
    }
    if statement.nullifiers.len() != PRIVATE_SETTLEMENT_INPUT_SLOTS_V1
        || statement.nullifiers[0] == statement.nullifiers[1]
        || plaintext.payer_authorization.body
            != plaintext
                .payer_authorization_body(&statement.nullifiers)
                .map_err(|_| E::Binding)?
    {
        return Err(E::Binding);
    }
    statement.audit_plaintext_commitment = plaintext.commitment().map_err(|_| E::Encoding)?;
    statement.audit_input_commitment =
        atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)?;
    let seed = derive_healthy_try_crypto_seed_v1(
        &mut rand::rngs::OsRng,
        b"iroha:private-settlement:wallet-output-nonces:v1",
    )?;
    let mut output_rng = iroha_crypto::rng_from_seed_slice(seed.as_ref());
    statement.encrypted_outputs =
        prepare_outputs_from_bound_context_v1(&mut output_rng, &statement, &mut plaintext.outputs)?;
    statement.output_commitments = plaintext
        .outputs
        .iter()
        .map(|output| output.note.commitment)
        .collect();
    for commitment in &statement.output_commitments {
        cut.verify_output_absent(*commitment)
            .map_err(|_| E::Binding)?;
    }
    let successor = append_proof_managed_commitments_v1(
        namespace,
        pool.tree_size,
        pool.leaf,
        &pool.ommers,
        pool.root,
        &statement.output_commitments,
    )?;
    statement.new_root = successor.root;
    plaintext
        .validate_against_proof_intent(manifest)
        .map_err(|_| E::Binding)?;
    let canonical = Zeroizing::new(norito::encode_canonical(&plaintext).map_err(|_| E::Encoding)?);
    let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
        &canonical,
        PrivateSettlementAuditAadV1 {
            network_id: manifest.network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: ordinal,
            route: leg.route,
            authority_digest: context
                .context()
                .authority()
                .digest()
                .map_err(|_| E::Encoding)?,
            authority_context_height: cut.height(),
            audit_policy_digest: policy.policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            plaintext_commitment: statement.audit_plaintext_commitment,
        },
        padding,
        policy,
        &mut rand::rngs::OsRng,
    )?;
    drop(canonical);
    statement.audit_capsule_digest = capsule.digest().map_err(|_| E::Encoding)?;
    statement.validate().map_err(|_| E::Binding)?;
    let [first, second] = inputs;
    let witness = AtomicPrivateSettlementProverWitnessV1::new(
        plaintext,
        [
            AtomicPrivateSettlementInputWitnessV1::new(
                first.spending_secret,
                first.leaf_position,
                first.authentication_path,
            )?,
            AtomicPrivateSettlementInputWitnessV1::new(
                second.spending_secret,
                second.leaf_position,
                second.authentication_path,
            )?,
        ],
    );
    let proof = super::super::facade::prove_atomic_private_settlement_intent_v1(
        manifest,
        &statement,
        *manifest.network_id.as_genesis_hash().as_ref(),
        cut.height(),
        &witness,
    )?;
    drop(witness);
    Ok(complete_atomic_private_settlement_prepared_leg_v1(
        AtomicPrivateSettlementPreparedProofV1 {
            statement,
            proof,
            audit_capsule: capsule,
        },
    )?)
}
