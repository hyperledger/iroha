//! Release stage and canonical fixture construction for Vega.
// This is a private continuation of the parent release-evidence module.
use super::*;
pub(super) const VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1: u64 = 1_785_024_000_000;
const VEGA_RELEASE_GENESIS_HASH_V1: [u8; 32] = [0xa7; 32];
pub(super) const VEGA_RELEASE_ACTION_INDEX_V1: u32 = VEGA_PRIVACY_ACTION_INDEX_V1;
pub(super) const VEGA_RELEASE_CREATION_TIME_MS_V1: u64 = VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1 - 1;
pub(super) const VEGA_RELEASE_NONCE_V1: u32 = 26;
pub(super) const VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1: u64 = 1_048_576;
pub(super) const VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1: u64 = 2_359_296;
pub(super) const VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1: u64 = 21;
#[cfg(test)]
pub(super) const VEGA_RELEASE_MC_UPSTREAM_COMMIT_V1: &str =
    "c0ee259053cd12eaf43ed71b5cde375452b3ee4d";
#[cfg(test)]
pub(super) const VEGA_RELEASE_MC_WIRE_DESCRIPTOR_V1: &str = "canonical-mc-2-plus-6-sha256-steps";
const VEGA_RELEASE_MC_STEP_COUNT_V1: usize = 8;
const VEGA_RELEASE_MC_SHARED_VARIABLES_V1: usize = 524_288;
const VEGA_RELEASE_MC_STEP_PRECOMMITTED_VARIABLES_V1: usize = 2_048;
const VEGA_RELEASE_MC_STEP_REST_VARIABLES_V1: usize = 522_240;
const VEGA_RELEASE_MC_CORE_PRECOMMITTED_VARIABLES_V1: usize = 2_048;
const VEGA_RELEASE_MC_CORE_REST_VARIABLES_V1: usize = 522_240;
const VEGA_RELEASE_MC_STEP_CONSTRAINTS_V1: usize = 262_144;
const VEGA_RELEASE_MC_STEP_VARIABLES_V1: usize = 1_048_576;
const VEGA_RELEASE_MC_CORE_CONSTRAINTS_V1: usize = 262_144;
const VEGA_RELEASE_MC_CORE_VARIABLES_V1: usize = 1_048_576;
const VEGA_RELEASE_MC_SHARED_COMMITMENT_POINTS_V1: usize = 256;
const VEGA_RELEASE_MC_STEP_PRECOMMITTED_POINTS_V1: usize = 1;
const VEGA_RELEASE_MC_STEP_REST_POINTS_V1: usize = 255;
const VEGA_RELEASE_MC_STEP_PUBLIC_VALUES_V1: usize = 1;
const VEGA_RELEASE_MC_CORE_PRECOMMITTED_POINTS_V1: usize = 1;
const VEGA_RELEASE_MC_CORE_REST_POINTS_V1: usize = 255;
const VEGA_RELEASE_MC_CORE_PUBLIC_VALUES_V1: usize = 18;
const VEGA_RELEASE_MC_EVALUATION_RESPONSE_SCALARS_V1: usize = 2_048;
const VEGA_RELEASE_MC_VERIFIER_ROUNDS_V1: usize = 47;
const VEGA_RELEASE_MC_VERIFIER_PUBLIC_VALUES_V1: usize = 6;
const VEGA_RELEASE_MC_NOVA_CROSS_TERM_POINTS_V1: usize = 16;
const VEGA_RELEASE_MC_RANDOM_WITNESS_POINTS_V1: usize = 47;
const VEGA_RELEASE_MC_RANDOM_ERROR_POINTS_V1: usize = 16;
const VEGA_RELEASE_MC_RANDOM_PUBLIC_VALUES_V1: usize = 49;
const VEGA_RELEASE_MC_VERIFIER_CONSTRAINTS_V1: usize = 512;
const VEGA_RELEASE_MC_VERIFIER_VARIABLES_V1: usize = 1_504;
const VEGA_RELEASE_MC_RELAXED_OUTER_ROUNDS_V1: usize = 9;
const VEGA_RELEASE_MC_RELAXED_INNER_ROUNDS_V1: usize = 12;
const VEGA_RELEASE_MC_RELAXED_OPENING_SCALARS_V1: usize = 32;
pub(super) const VEGA_RELEASE_PUBLIC_INPUT_COUNT_V1: usize = 14;
const fn vega_release_verifier_challenges_v1() -> [usize; VEGA_RELEASE_MC_VERIFIER_ROUNDS_V1] {
    let mut values = [1; VEGA_RELEASE_MC_VERIFIER_ROUNDS_V1];
    values[3] = 0;
    values[44] = 0;
    values[45] = 0;
    values[46] = 0;
    values
}
pub(super) struct VegaReleaseFixtureV1 {
    pub(super) public_input: VegaPrivacyActionPublicInputV1,
    pub(super) issuer_record: PrivacyVegaIssuerRecordV1,
    pub(super) issuer_authentication_sig_structure: Vec<u8>,
    pub(super) mobile_security_object_payload: Vec<u8>,
    pub(super) birth_date_issuer_signed_item: Vec<u8>,
    pub(super) issuer_signature: P256Signature,
    pub(super) issuer_high_s_signature: P256Signature,
    pub(super) device_signing_key: P256SigningKey,
    pub(super) genesis_hash: [u8; 32],
}
pub(super) fn vega_release_transaction_context_v1()
-> Result<VegaPrivacyActionTransactionContextV1, PrivacyReleaseEvidenceErrorClassV1> {
    Ok(VegaPrivacyActionTransactionContextV1 {
        network_id: release_network_id_from_genesis_hash(VEGA_RELEASE_GENESIS_HASH_V1),
        authority: privacy_release_account_v1(0x56)?,
        creation_time: Duration::from_millis(VEGA_RELEASE_CREATION_TIME_MS_V1),
        time_to_live: Some(Duration::from_secs(60)),
        nonce: NonZeroU32::new(VEGA_RELEASE_NONCE_V1),
        fee_payment: FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(5_000_000)),
        metadata: Metadata::default(),
    })
}
pub(super) fn run_vega_stage_v1(
    case_kind: PrivacyReleaseCaseKindV1,
) -> Result<StageMaterialV1, PrivacyReleaseEvidenceErrorClassV1> {
    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    compiled_privacy_profile_v1(protocol_id).map_err(|error| match error {
        crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
            protocol_id: unavailable,
        } if unavailable == protocol_id => PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
        _ => PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed,
    })?;
    let fixture = vega_release_fixture_v1()?;
    let VegaReleaseFixtureV1 {
        public_input,
        issuer_record,
        issuer_authentication_sig_structure,
        mobile_security_object_payload,
        birth_date_issuer_signed_item,
        issuer_signature,
        issuer_high_s_signature,
        device_signing_key,
        genesis_hash,
    } = fixture;
    let witness_material = VegaPrivacyActionWitnessMaterialV1::new(
        issuer_authentication_sig_structure.clone(),
        mobile_security_object_payload.clone(),
        birth_date_issuer_signed_item.clone(),
        &issuer_signature.to_bytes(),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let proof_seed = stage_purpose_seed_v1(
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        case_kind,
        b"figure9-proof-randomness",
    )?;
    let mut proof_rng = EvidenceRng06::new(proof_seed);
    let prepared = prepare_vega_privacy_action_with_rng_v1(
        vega_release_transaction_context_v1()?,
        public_input,
        witness_material,
        &device_signing_key,
        genesis_hash,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
        &mut proof_rng,
    )
    .map_err(|error| match error {
        crate::privacy_engines::vega::VegaPrivacyActionBuildErrorV1::CompiledProfileUnavailable => {
            PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable
        }
        _ => PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected,
    })?;
    let (statement, proof) = {
        let (intent, submission) = prepared
            .release_evidence_payload_v1()
            .privacy_transaction_intent_binding_if_present_v1()
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
            .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        if intent.as_bytes() != &prepared.transaction_intent_digest()
            || submission.envelope.statement_digest.as_bytes() != &prepared.statement_digest()
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
        let PrivacyStatementV1::VegaExistingCredentialZkV1(statement) =
            &submission.envelope.statement
        else {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        };
        let PrivacyProofV1::VegaExistingCredentialZkV1(proof) = &submission.envelope.proof else {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        };
        if proof.as_bytes().len()
            != usize::try_from(prepared.proof_bytes())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
        }
        (statement.clone(), proof.as_bytes().to_vec())
    };
    validate_vega_authoritative_issuer_binding_v1(&statement, &issuer_record)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let binding = VegaMdlConsensusBindingV1::from_context(&statement.context, genesis_hash);
    let device_signature: P256Signature = device_signing_key
        .sign_prehash(statement.device_authentication_digest.as_bytes())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let device_signature = device_signature.normalize_s().unwrap_or(device_signature);
    let (device_r, device_s) = device_signature.split_scalars();
    let device_high_s_signature =
        P256Signature::from_scalars(device_r.to_repr(), (-*device_s).to_repr())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if issuer_high_s_signature.normalize_s().is_none()
        || device_high_s_signature.normalize_s().is_none()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let noncanonical_witnesses: [(&[u8], VegaMdlWitnessV1); 2] = [
        (
            b"figure9-issuer-high-s-rejection",
            VegaMdlWitnessV1::new(
                issuer_authentication_sig_structure.clone(),
                mobile_security_object_payload.clone(),
                birth_date_issuer_signed_item.clone(),
                &issuer_high_s_signature.to_bytes(),
                &device_signature.to_bytes(),
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?,
        ),
        (
            b"figure9-device-high-s-rejection",
            VegaMdlWitnessV1::new(
                issuer_authentication_sig_structure,
                mobile_security_object_payload,
                birth_date_issuer_signed_item,
                &issuer_signature.to_bytes(),
                &device_high_s_signature.to_bytes(),
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?,
        ),
    ];
    for (purpose, noncanonical_witness) in noncanonical_witnesses {
        let mut noncanonical_rng = EvidenceRng06::new(stage_purpose_seed_v1(
            PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            case_kind,
            purpose,
        )?);
        let noncanonical_config = VegaMdlProverConfigV1::new(1)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
        if prove_mdl_figure9_v1(
            &statement,
            &binding,
            VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
            noncanonical_witness,
            noncanonical_config,
            &mut noncanonical_rng,
        )
        .is_ok()
        {
            return Err(PrivacyReleaseEvidenceErrorClassV1::NonCanonicalWitnessAccepted);
        }
    }
    verify_mdl_figure9_v1(
        &statement,
        &binding,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
        &proof,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    let authoritative_network_id =
        release_network_id_from_genesis_hash(VEGA_RELEASE_GENESIS_HASH_V1);
    let authoritative_action_index = VEGA_RELEASE_ACTION_INDEX_V1;
    if statement.context.network_id != authoritative_network_id
        || statement.context.action_index != authoritative_action_index
        || genesis_hash != VEGA_RELEASE_GENESIS_HASH_V1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    verify_vega_release_production_envelope_v1(
        &statement,
        Some(&issuer_record),
        &proof,
        &authoritative_network_id,
        genesis_hash,
        authoritative_action_index,
        VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
    )?;
    let dimensions = vega_mdl_proof_dimensions_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let total_app_constraints = dimensions
        .step_constraints
        .checked_mul(dimensions.num_steps)
        .and_then(|value| value.checked_add(dimensions.core_constraints))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let max_circuit_variables =
        u64::try_from(dimensions.step_variables.max(dimensions.core_variables))
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let relaxed_sumcheck_rounds = dimensions
        .relaxed_outer_rounds
        .checked_add(dimensions.relaxed_inner_rounds)
        .and_then(|rounds| u64::try_from(rounds).ok())
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if VEGA_MDL_PUBLIC_INPUT_COUNT_V1 != VEGA_RELEASE_PUBLIC_INPUT_COUNT_V1
        || dimensions.num_steps != VEGA_RELEASE_MC_STEP_COUNT_V1
        || dimensions.shared_variables != VEGA_RELEASE_MC_SHARED_VARIABLES_V1
        || dimensions.step_precommitted_variables != VEGA_RELEASE_MC_STEP_PRECOMMITTED_VARIABLES_V1
        || dimensions.step_rest_variables != VEGA_RELEASE_MC_STEP_REST_VARIABLES_V1
        || dimensions.core_precommitted_variables != VEGA_RELEASE_MC_CORE_PRECOMMITTED_VARIABLES_V1
        || dimensions.core_rest_variables != VEGA_RELEASE_MC_CORE_REST_VARIABLES_V1
        || dimensions.step_constraints != VEGA_RELEASE_MC_STEP_CONSTRAINTS_V1
        || dimensions.step_variables != VEGA_RELEASE_MC_STEP_VARIABLES_V1
        || dimensions.core_constraints != VEGA_RELEASE_MC_CORE_CONSTRAINTS_V1
        || dimensions.core_variables != VEGA_RELEASE_MC_CORE_VARIABLES_V1
        || dimensions.shared_commitment_points != VEGA_RELEASE_MC_SHARED_COMMITMENT_POINTS_V1
        || dimensions.step_precommitted_points != VEGA_RELEASE_MC_STEP_PRECOMMITTED_POINTS_V1
        || dimensions.step_rest_points != VEGA_RELEASE_MC_STEP_REST_POINTS_V1
        || dimensions.step_public_values != VEGA_RELEASE_MC_STEP_PUBLIC_VALUES_V1
        || dimensions.step_challenges != 0
        || dimensions.core_precommitted_points != VEGA_RELEASE_MC_CORE_PRECOMMITTED_POINTS_V1
        || dimensions.core_rest_points != VEGA_RELEASE_MC_CORE_REST_POINTS_V1
        || dimensions.core_public_values != VEGA_RELEASE_MC_CORE_PUBLIC_VALUES_V1
        || dimensions.core_challenges != 0
        || dimensions.evaluation_response_scalars != VEGA_RELEASE_MC_EVALUATION_RESPONSE_SCALARS_V1
        || dimensions.verifier_round_commitment_points != [1; VEGA_RELEASE_MC_VERIFIER_ROUNDS_V1]
        || dimensions.verifier_public_values != VEGA_RELEASE_MC_VERIFIER_PUBLIC_VALUES_V1
        || dimensions.verifier_challenges_per_round != vega_release_verifier_challenges_v1()
        || dimensions.nova_cross_term_points != VEGA_RELEASE_MC_NOVA_CROSS_TERM_POINTS_V1
        || dimensions.random_witness_commitment_points != VEGA_RELEASE_MC_RANDOM_WITNESS_POINTS_V1
        || dimensions.random_error_commitment_points != VEGA_RELEASE_MC_RANDOM_ERROR_POINTS_V1
        || dimensions.random_public_values != VEGA_RELEASE_MC_RANDOM_PUBLIC_VALUES_V1
        || dimensions.verifier_constraints != VEGA_RELEASE_MC_VERIFIER_CONSTRAINTS_V1
        || dimensions.verifier_variables != VEGA_RELEASE_MC_VERIFIER_VARIABLES_V1
        || dimensions.relaxed_outer_rounds != VEGA_RELEASE_MC_RELAXED_OUTER_ROUNDS_V1
        || dimensions.relaxed_outer_coefficients != 3
        || dimensions.relaxed_inner_rounds != VEGA_RELEASE_MC_RELAXED_INNER_ROUNDS_V1
        || dimensions.relaxed_inner_coefficients != 2
        || dimensions.relaxed_opening_scalars != VEGA_RELEASE_MC_RELAXED_OPENING_SCALARS_V1
        || total_app_constraints != VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1
        || max_circuit_variables != VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1
        || relaxed_sumcheck_rounds != VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let original_material = norito::encode_canonical(
        &PrivacyStatementV1::VegaExistingCredentialZkV1(statement.clone()),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let (public_statement_material, failure_class) = match case_kind {
        PrivacyReleaseCaseKindV1::PositiveCanonicalEndToEnd
        | PrivacyReleaseCaseKindV1::MaximumShapeResource => (
            original_material,
            PrivacyReleaseFailureClassV1::NotApplicable,
        ),
        PrivacyReleaseCaseKindV1::PublicStatementBindingMutation => {
            let mut stale_epoch = statement.clone();
            stale_epoch.issuer_record_epoch = stale_epoch
                .issuer_record_epoch
                .checked_add(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            refresh_vega_device_authentication_digest_v1(&mut stale_epoch, genesis_hash)?;
            let mut wrong_issuer = statement.clone();
            let mut issuer_id = *wrong_issuer.issuer_id.as_bytes();
            issuer_id[0] ^= 0x80;
            wrong_issuer.issuer_id = PrivacyIssuerIdV1::new(issuer_id);
            refresh_vega_device_authentication_digest_v1(&mut wrong_issuer, genesis_hash)?;
            let mut wrong_record_digest = statement.clone();
            let mut record_digest = *wrong_record_digest.issuer_record_digest.as_bytes();
            record_digest[0] ^= 0x80;
            wrong_record_digest.issuer_record_digest =
                iroha_data_model::privacy::PrivacyVegaIssuerRecordDigestV1::new(record_digest);
            refresh_vega_device_authentication_digest_v1(&mut wrong_record_digest, genesis_hash)?;
            let mut wrong_issuer_key = statement.clone();
            let substitute_signing_key = P256SigningKey::from_bytes((&[3_u8; 32]).into())
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            wrong_issuer_key.issuer_public_key =
                vega_compressed_public_key_v1(&substitute_signing_key)?;
            refresh_vega_device_authentication_digest_v1(&mut wrong_issuer_key, genesis_hash)?;
            let mut wrong_network = statement.clone();
            wrong_network.context.network_id = release_network_id_from_genesis_hash([0xa8; 32]);
            let mut wrong_action_index = statement.clone();
            wrong_action_index.context.action_index = wrong_action_index
                .context
                .action_index
                .checked_add(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            // These are binding mutations, so they deliberately retain the canonical statement's
            // H_dev. Re-derivation correctly refuses the wrong network and sole-action index.
            for issuer_mutation in [
                &stale_epoch,
                &wrong_issuer,
                &wrong_record_digest,
                &wrong_issuer_key,
            ] {
                if validate_vega_authoritative_issuer_binding_v1(issuer_mutation, &issuer_record)
                    .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            for mutation in [
                &stale_epoch,
                &wrong_issuer,
                &wrong_record_digest,
                &wrong_issuer_key,
                &wrong_network,
                &wrong_action_index,
            ] {
                let mutated_binding =
                    VegaMdlConsensusBindingV1::from_context(&mutation.context, genesis_hash);
                if verify_mdl_figure9_v1(
                    mutation,
                    &mutated_binding,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                    &proof,
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
                if verify_vega_release_production_envelope_v1(
                    mutation,
                    Some(&issuer_record),
                    &proof,
                    &authoritative_network_id,
                    genesis_hash,
                    authoritative_action_index,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            let revoked_record = PrivacyVegaIssuerRecordV1::new(
                issuer_record.issuer_id,
                issuer_record
                    .record_epoch
                    .checked_add(1)
                    .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?,
                issuer_record.issuer_public_key,
                issuer_record.document_type,
                issuer_record.namespace,
                issuer_record.digest_algorithm,
                issuer_record.issuer_authentication_algorithm,
                issuer_record.device_authentication_algorithm,
                Some(issuer_record.record_digest),
                PrivacyVegaIssuerRecordLifecycleV1::Revoked,
            )
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
            for issuer_state in [None, Some(&revoked_record)] {
                if verify_vega_release_production_envelope_v1(
                    &statement,
                    issuer_state,
                    &proof,
                    &authoritative_network_id,
                    genesis_hash,
                    authoritative_action_index,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            let mut wrong_genesis_hash = genesis_hash;
            wrong_genesis_hash[0] ^= 0x80;
            for (wrong_genesis, wrong_timestamp) in [
                (wrong_genesis_hash, VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1),
                (genesis_hash, 0),
            ] {
                if verify_vega_release_production_envelope_v1(
                    &statement,
                    Some(&issuer_record),
                    &proof,
                    &authoritative_network_id,
                    wrong_genesis,
                    authoritative_action_index,
                    wrong_timestamp,
                )
                .is_ok()
                {
                    return Err(
                        PrivacyReleaseEvidenceErrorClassV1::PublicStatementMutationAccepted,
                    );
                }
            }
            (
                norito::encode_canonical(&PrivacyStatementV1::VegaExistingCredentialZkV1(
                    stale_epoch,
                ))
                .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
                PrivacyReleaseFailureClassV1::PublicStatementBindingRejected,
            )
        }
        PrivacyReleaseCaseKindV1::ProofCorruptionAndTruncation => {
            let mut corrupt_header = proof.clone();
            let first = corrupt_header
                .first_mut()
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *first ^= 0x80;
            if verify_mdl_figure9_v1(
                &statement,
                &binding,
                VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                &corrupt_header,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_vega_release_production_native_rejection_v1(
                verify_vega_release_production_envelope_v1(
                    &statement,
                    Some(&issuer_record),
                    &corrupt_header,
                    &authoritative_network_id,
                    genesis_hash,
                    authoritative_action_index,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let mut corrupt_interior = proof.clone();
            let interior_index = corrupt_interior.len() / 2;
            let interior = corrupt_interior
                .get_mut(interior_index)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            *interior ^= 0x01;
            if verify_mdl_figure9_v1(
                &statement,
                &binding,
                VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                &corrupt_interior,
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted);
            }
            require_vega_release_production_native_rejection_v1(
                verify_vega_release_production_envelope_v1(
                    &statement,
                    Some(&issuer_record),
                    &corrupt_interior,
                    &authoritative_network_id,
                    genesis_hash,
                    authoritative_action_index,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofCorruptionAccepted,
            )?;
            let truncated_length = proof
                .len()
                .checked_sub(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
            if verify_mdl_figure9_v1(
                &statement,
                &binding,
                VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                &proof[..truncated_length],
            )
            .is_ok()
            {
                return Err(PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted);
            }
            require_vega_release_production_native_rejection_v1(
                verify_vega_release_production_envelope_v1(
                    &statement,
                    Some(&issuer_record),
                    &proof[..truncated_length],
                    &authoritative_network_id,
                    genesis_hash,
                    authoritative_action_index,
                    VEGA_RELEASE_TRUSTED_TIMESTAMP_MS_V1,
                ),
                PrivacyReleaseEvidenceErrorClassV1::ProofTruncationAccepted,
            )?;
            (
                original_material,
                PrivacyReleaseFailureClassV1::CanonicalWireCorruptionAndTruncationRejected,
            )
        }
    };
    Ok(StageMaterialV1 {
        public_statement_material,
        proof_artifacts: single_proof_artifact_v1(
            proof,
            u64::try_from(MAX_VEGA_PROOF_BYTES_V1).expect("closed Vega proof ceiling fits u64"),
        ),
        failure_class,
        resources: PrivacyReleaseResourceFactsV1 {
            primary_units: total_app_constraints,
            primary_ceiling: VEGA_RELEASE_MC_TOTAL_APP_CONSTRAINTS_V1,
            secondary_units: max_circuit_variables,
            secondary_ceiling: VEGA_RELEASE_MC_MAX_CIRCUIT_VARIABLES_V1,
            relation_depth: relaxed_sumcheck_rounds,
            relation_depth_ceiling: VEGA_RELEASE_MC_RELAXED_SUMCHECK_ROUNDS_V1,
        },
    })
}
pub(super) fn require_vega_release_production_native_rejection_v1(
    result: Result<(), PrivacyReleaseEvidenceErrorClassV1>,
    accepted_class: PrivacyReleaseEvidenceErrorClassV1,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    match result {
        Err(PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected) => Ok(()),
        Ok(()) => Err(accepted_class),
        Err(_) => Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant),
    }
}
pub(super) fn verify_vega_release_production_envelope_v1(
    statement: &VegaExistingCredentialStatementV1,
    issuer_record: Option<&PrivacyVegaIssuerRecordV1>,
    proof: &[u8],
    authoritative_network_id: &NetworkId,
    genesis_hash: [u8; 32],
    authoritative_action_index: u32,
    block_timestamp_ms: u64,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    let protocol_id = PrivacyProtocolIdV1::VegaExistingCredentialZkV1;
    let profile = compiled_privacy_profile_v1(protocol_id).map_err(|error| match error {
        crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
            protocol_id: unavailable,
        } if unavailable == protocol_id => PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable,
        _ => PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed,
    })?;
    let activation = profile.activation_record(PrivacyProtocolLifecycleV1::Active(
        PrivacyActiveLifecycleV1 {
            proposed_at_height: 1,
            activated_at_height: 2,
            state_since_height: 2,
        },
    ));
    let typed_statement = PrivacyStatementV1::VegaExistingCredentialZkV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::VegaExistingCredentialZkV1(PrivacyProofBytesV1::new(proof.to_vec())),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected)?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let effects = verify_privacy_envelope_v1(
        &envelope,
        PrivacyVerificationContextV1 {
            activation: &activation,
            consensus_limits: &limits,
            network_id: authoritative_network_id,
            genesis_hash,
            current_height: 2,
            expected_action_index: authoritative_action_index,
            block_timestamp_ms,
            pgc_state: None,
            orchard_state: None,
            proof_managed_state: None,
            zk_x509_state: None,
            bootle_lantern_policy: None,
            vega_issuer_record: issuer_record,
        },
    )
    .map_err(|source| match source {
        PrivacyVerificationErrorV1::NativeVega(_) => {
            PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected
        }
        _ => PrivacyReleaseEvidenceErrorClassV1::ProductionEnvelopeRejected,
    })?;
    if effects.protocol_id() != PrivacyProtocolIdV1::VegaExistingCredentialZkV1
        || effects.statement_digest() != statement_digest
        || effects.action_index() != authoritative_action_index
        || effects.encoded_action_bytes() == 0
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(())
}
pub(super) fn refresh_vega_device_authentication_digest_v1(
    statement: &mut VegaExistingCredentialStatementV1,
    genesis_hash: [u8; 32],
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    let binding = VegaMdlConsensusBindingV1::from_context(&statement.context, genesis_hash);
    statement.device_authentication_digest =
        derive_device_authentication_digest_v1(statement, &binding)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    Ok(())
}
pub(super) fn vega_release_fixture_v1()
-> Result<VegaReleaseFixtureV1, PrivacyReleaseEvidenceErrorClassV1> {
    let issuer_signing_key = P256SigningKey::from_bytes((&[1_u8; 32]).into())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let device_signing_key = P256SigningKey::from_bytes((&[2_u8; 32]).into())
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let issuer_public_key = vega_compressed_public_key_v1(&issuer_signing_key)?;
    let issuer_record = PrivacyVegaIssuerRecordV1::new(
        PrivacyIssuerIdV1::new([0x40; 32]),
        1,
        issuer_public_key,
        PrivacyCredentialDocumentTypeV1::Iso18013_5Mdl,
        PrivacyVegaMdlNamespaceV1::OrgIso18013_5_1,
        PrivacyVegaMdlDigestAlgorithmV1::Sha256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        PrivacyVegaMdlSignatureAlgorithmV1::CoseSign1Es256,
        None,
        PrivacyVegaIssuerRecordLifecycleV1::Active,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let device_uncompressed = device_signing_key.verifying_key().to_encoded_point(false);
    let device_x = device_uncompressed
        .x()
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let device_y = device_uncompressed
        .y()
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let birth_inner = vega_cbor_map_v1(vec![
        (vega_cbor_text_v1("digestID"), vega_cbor_unsigned_v1(1)),
        (vega_cbor_text_v1("random"), vega_cbor_bytes_v1(&[0x42; 16])),
        (
            vega_cbor_text_v1("elementIdentifier"),
            vega_cbor_text_v1("birth_date"),
        ),
        (
            vega_cbor_text_v1("elementValue"),
            vega_cbor_text_v1("1980-06-15"),
        ),
    ]);
    let birth_item = vega_cbor_tag_v1(24, vega_cbor_bytes_v1(&birth_inner));
    let birth_digest: [u8; 32] = Sha256::digest(&birth_item).into();
    let device_key = vega_cbor_map_v1(vec![
        (vega_cbor_unsigned_v1(1), vega_cbor_unsigned_v1(2)),
        (vega_cbor_negative_v1(-1), vega_cbor_unsigned_v1(1)),
        (vega_cbor_negative_v1(-2), vega_cbor_bytes_v1(device_x)),
        (vega_cbor_negative_v1(-3), vega_cbor_bytes_v1(device_y)),
    ]);
    let validity_info = vega_cbor_map_v1(vec![
        (
            vega_cbor_text_v1("signed"),
            vega_cbor_tag_v1(0, vega_cbor_text_v1("2025-01-01T00:00:00Z")),
        ),
        (
            vega_cbor_text_v1("validFrom"),
            vega_cbor_tag_v1(0, vega_cbor_text_v1("2025-01-01T00:00:00Z")),
        ),
        (
            vega_cbor_text_v1("validUntil"),
            vega_cbor_tag_v1(0, vega_cbor_text_v1("2035-08-17T12:34:56Z")),
        ),
    ]);
    let value_digests = vega_cbor_map_v1(vec![(
        vega_cbor_text_v1("org.iso.18013.5.1"),
        vega_cbor_map_v1(vec![(
            vega_cbor_unsigned_v1(1),
            vega_cbor_bytes_v1(&birth_digest),
        )]),
    )]);
    let mso_inner = vega_cbor_map_v1(vec![
        (vega_cbor_text_v1("version"), vega_cbor_text_v1("1.0")),
        (
            vega_cbor_text_v1("digestAlgorithm"),
            vega_cbor_text_v1("SHA-256"),
        ),
        (vega_cbor_text_v1("valueDigests"), value_digests),
        (
            vega_cbor_text_v1("deviceKeyInfo"),
            vega_cbor_map_v1(vec![(vega_cbor_text_v1("deviceKey"), device_key)]),
        ),
        (
            vega_cbor_text_v1("docType"),
            vega_cbor_text_v1("org.iso.18013.5.1.mDL"),
        ),
        (vega_cbor_text_v1("validityInfo"), validity_info),
    ]);
    let mso_payload = vega_cbor_tag_v1(24, vega_cbor_bytes_v1(&mso_inner));
    let sig_structure = vega_cbor_array_v1(vec![
        vega_cbor_text_v1("Signature1"),
        vega_cbor_bytes_v1(&[0xa1, 0x01, 0x26]),
        vega_cbor_bytes_v1(&[]),
        vega_cbor_bytes_v1(&mso_payload),
    ]);
    let genesis_hash = VEGA_RELEASE_GENESIS_HASH_V1;
    let public_input = VegaPrivacyActionPublicInputV1 {
        issuer_record,
        presentation_date: PrivacyVegaMdlDateV1 {
            year: 2026,
            month: 7,
            day: 26,
        },
        minimum_age_years: 18,
        reader_challenge: PrivacyChallengeV1::new([0x31; 32]),
        session_transcript_digest: PrivacySessionTranscriptDigestV1::new([0x32; 32]),
    };
    let issuer_digest: [u8; 32] = Sha256::digest(&sig_structure).into();
    let issuer_signature: P256Signature = issuer_signing_key
        .sign_prehash(&issuer_digest)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let issuer_signature = issuer_signature.normalize_s().unwrap_or(issuer_signature);
    let (issuer_r, issuer_s) = issuer_signature.split_scalars();
    let issuer_high_s_signature =
        P256Signature::from_scalars(issuer_r.to_repr(), (-*issuer_s).to_repr())
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    if issuer_high_s_signature.normalize_s().is_none() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(VegaReleaseFixtureV1 {
        public_input,
        issuer_record,
        issuer_authentication_sig_structure: sig_structure,
        mobile_security_object_payload: mso_payload,
        birth_date_issuer_signed_item: birth_item,
        issuer_signature,
        issuer_high_s_signature,
        device_signing_key,
        genesis_hash,
    })
}
fn vega_compressed_public_key_v1(
    signing_key: &P256SigningKey,
) -> Result<PrivacyP256PointV1, PrivacyReleaseEvidenceErrorClassV1> {
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    Ok(PrivacyP256PointV1::new(bytes))
}
fn vega_cbor_head_v1(major: u8, argument: u64) -> Vec<u8> {
    let argument_bytes = argument.to_be_bytes();
    match argument {
        0..=23 => vec![
            (major << 5) | u8::try_from(argument).expect("CBOR immediate argument is at most 23"),
        ],
        24..=0xff => vec![
            (major << 5) | 24,
            u8::try_from(argument).expect("CBOR one-byte argument is at most 255"),
        ],
        0x100..=0xffff => vec![(major << 5) | 25, argument_bytes[6], argument_bytes[7]],
        0x1_0000..=0xffff_ffff => vec![
            (major << 5) | 26,
            argument_bytes[4],
            argument_bytes[5],
            argument_bytes[6],
            argument_bytes[7],
        ],
        _ => {
            let mut encoded = vec![(major << 5) | 27];
            encoded.extend_from_slice(&argument_bytes);
            encoded
        }
    }
}
fn vega_cbor_unsigned_v1(value: u64) -> Vec<u8> {
    vega_cbor_head_v1(0, value)
}
fn vega_cbor_negative_v1(value: i64) -> Vec<u8> {
    debug_assert!(value < 0);
    let argument = u64::try_from(-(i128::from(value)) - 1)
        .expect("negative i64 has a non-negative CBOR argument fitting u64");
    vega_cbor_head_v1(1, argument)
}
fn vega_cbor_bytes_v1(value: &[u8]) -> Vec<u8> {
    let mut encoded = vega_cbor_head_v1(
        2,
        u64::try_from(value.len()).expect("slice length fits CBOR u64"),
    );
    encoded.extend_from_slice(value);
    encoded
}
fn vega_cbor_text_v1(value: &str) -> Vec<u8> {
    let mut encoded = vega_cbor_head_v1(
        3,
        u64::try_from(value.len()).expect("string length fits CBOR u64"),
    );
    encoded.extend_from_slice(value.as_bytes());
    encoded
}
fn vega_cbor_array_v1(values: Vec<Vec<u8>>) -> Vec<u8> {
    let mut encoded = vega_cbor_head_v1(
        4,
        u64::try_from(values.len()).expect("array length fits CBOR u64"),
    );
    for value in values {
        encoded.extend_from_slice(&value);
    }
    encoded
}
fn vega_cbor_map_v1(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    entries.sort_by(|left, right| {
        left.0
            .len()
            .cmp(&right.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut encoded = vega_cbor_head_v1(
        5,
        u64::try_from(entries.len()).expect("map length fits CBOR u64"),
    );
    for (key, value) in entries {
        encoded.extend_from_slice(&key);
        encoded.extend_from_slice(&value);
    }
    encoded
}
fn vega_cbor_tag_v1(tag: u64, value: Vec<u8>) -> Vec<u8> {
    let mut encoded = vega_cbor_head_v1(6, tag);
    encoded.extend_from_slice(&value);
    encoded
}
