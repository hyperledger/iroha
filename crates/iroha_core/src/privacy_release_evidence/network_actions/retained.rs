//! Deterministic network-bound builders for retained native privacy engines.
//!
//! This module is reachable only through the non-shipping `privacy-release-evidence` feature. It
//! keeps every witness inside `iroha_core` and returns ordinary production transactions and
//! governance records so integration gates exercise the exact Torii, DA/RBC, verifier, and atomic
//! state-transition paths used by validators.
use super::{
    PrivacyReleaseTransactionContextV1, network_seed_v1, signed_payload_v1, statement_context_v1,
    transaction_payload_v1,
};
use crate::{
    privacy_engines::{
        anonymous_pgc::{
            AnonymousPgcParametersV1, AnonymousPgcPoolInvariantV1, TwistedElGamalCiphertextV1,
            TwistedElGamalKeyPairV1, TwistedElGamalPublicKeyV1, add_ciphertexts,
            bootstrap::{
                AnonymousPgcBootstrapStatementV1, AnonymousPgcBootstrapWitnessV1,
                PGC_BOOTSTRAP_INITIAL_EPOCH_V1, prove_bootstrap, verify_bootstrap_encoded,
            },
            encrypt_with_randomness,
            payment::{
                AnonymousPgcPaymentStatementV1, AnonymousPgcPaymentWitnessV1,
                encrypt_signed_with_randomness, prove_payment, verify_payment_encoded,
            },
        },
        bootle_lantern::{
            issuer::{
                BootleLanternBlindIssuanceResponseV1, BootleLanternFileIssuanceStoreV1,
                BootleLanternIssuanceAuthorizationV1, BootleLanternIssuanceStoreConfigV1,
                BootleLanternIssuerKeyPairV1, BootleLanternIssuerPolicyMetadataV1,
                holder_finalize_blind_issuance_v1, holder_prepare_blind_issuance_with_rng_v1,
                issuer_authorize_blind_issuance_with_rng_v1,
                issuer_blind_issue_once_encoded_with_rng_v1,
            },
            prove_bound_presentation_v1,
        },
        fcmp_plus_plus::{
            FcmpOutputTupleV1, FcmpRuntimeContextBindingV1, FcmpWalletNoteV1,
            derive_fcmp_runtime_context_hash_v1, encrypt_fcmp_wallet_note_v1,
            fcmp_recipient_public_key_v1, prove_fcmp_plus_plus_v1,
            release_evidence_access::fcmp_release_fixture_v1,
        },
        ivm_private_note::{
            ivm_private_note_network_fixture_v1, prove_ivm_private_note_v1_with_rng,
        },
        p256::{SecretScalarV1, TranscriptBindingV1},
        verange::{
            VeRangeBitLengthV1, VeRangeParametersV1, VeRangeType1BatchStatementV1, commit,
            prove_batch,
        },
        zk_ace::{ZkAcePrivacyWitnessV1, prove_zk_ace_privacy_v1_with_rng},
    },
    privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1},
    privacy_release_evidence::{EvidenceRng06, EvidenceRng09, PrivacyReleaseEvidenceErrorClassV1},
    privacy_state::compute_privacy_pgc_account_state_root_v1,
};
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::{
    prelude::{AccountId, AssetDefinitionId},
    privacy::{
        AnonymousPgcKOutOfNStatementV1, BootleLanternAllowedAttributeValuesV1,
        BootleLanternAttributeValueV1, BootleLanternDisclosedAttributeV1,
        BootleLanternIssuerPolicyV1, IrohaBootleLanternAnoncredStatementV1,
        IrohaIvmPrivateNoteStarkStatementV1, MoneroFcmpPlusPlusStatementV1,
        PrivacyConsensusLimitsV1, PrivacyFcmpInputPublicV1, PrivacyFcmpKeyImageV1,
        PrivacyFcmpOutputTupleV1, PrivacyFcmpPoolBootstrapV1, PrivacyFcmpTreeRootV1,
        PrivacyIssuerIdV1, PrivacyIvmPrivateNotePoolBootstrapV1, PrivacyNamespaceScopeV1,
        PrivacyNamespaceV1, PrivacyNativeConsensusBindingV1, PrivacyP256CiphertextV1,
        PrivacyP256PointV1, PrivacyParameterIdV1, PrivacyPgcAccountBootstrapV1,
        PrivacyPgcAccountV1, PrivacyPgcBootstrapProofBytesV1, PrivacyPolicyIdV1, PrivacyPoolIdV1,
        PrivacyPoolNamespaceV1, PrivacyProofBytesV1, PrivacyProofEnvelopeV1,
        PrivacyProofManagedPoolBootstrapV1, PrivacyProofV1, PrivacyRootV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyVeRangeBitLengthV1, PrivacyZkAcePolicyLifecycleV1,
        PrivacyZkAcePolicyRecordV1, VeRangeTransparentRangeStatementV1,
        ZkAcePqAuthorizationStatementV1,
    },
    transaction::SignedTransaction,
    zk::{ZkAcePrivacyPublicInputsV1, derive_zk_ace_privacy_authorization_digest},
};
use rand_core_06::{CryptoRng, Error as RngError06, RngCore};
use zeroize::Zeroizing;
struct UnavailableIssuanceRngV1;
impl RngCore for UnavailableIssuanceRngV1 {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0);
    }
    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError06> {
        Err(RngError06::new("cached issuance must not read randomness"))
    }
}
impl CryptoRng for UnavailableIssuanceRngV1 {}
/// One canonical network-bound VeRange action.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseVeRangeNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one VeRange proof.
    pub transaction: SignedTransaction,
    /// Exact public statement carried by `transaction`.
    pub statement: VeRangeTransparentRangeStatementV1,
}
/// One canonical network-bound Bootle/Lantern presentation and its required
/// authoritative issuer policy.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseBootleLanternNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one presentation proof.
    pub transaction: SignedTransaction,
    /// Exact initial policy that validators must register before submission.
    pub policy: BootleLanternIssuerPolicyV1,
    /// Genuine independently generated successor policy used to prove that
    /// key rotation invalidates credentials issued under the initial scope.
    pub successor_policy: BootleLanternIssuerPolicyV1,
    /// Exact public statement carried by `transaction`.
    pub statement: IrohaBootleLanternAnoncredStatementV1,
}
/// One canonical Anonymous-PGC account bootstrap and successor payment.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseAnonymousPgcNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one PGC payment proof.
    pub transaction: SignedTransaction,
    /// Exact governed account-table bootstrap required before submission.
    pub bootstrap: PrivacyPgcAccountBootstrapV1,
    /// Exact native proof authenticating `bootstrap` to this chain/genesis.
    pub bootstrap_proof: PrivacyPgcBootstrapProofBytesV1,
    /// Exact public payment statement carried by `transaction`.
    pub statement: AnonymousPgcKOutOfNStatementV1,
}
/// One canonical FCMP++ action and its complete authoritative output-set bootstrap.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseFcmpNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one FCMP++ proof.
    pub transaction: SignedTransaction,
    /// Exact proof-managed bootstrap required before submission.
    pub bootstrap: PrivacyProofManagedPoolBootstrapV1,
    /// Exact public statement carried by `transaction`.
    pub statement: MoneroFcmpPlusPlusStatementV1,
}
/// One canonical private-IVM note action and its authoritative program-pool bootstrap.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseIvmPrivateNoteNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one private-note proof.
    pub transaction: SignedTransaction,
    /// Exact proof-managed bootstrap required before submission.
    pub bootstrap: PrivacyProofManagedPoolBootstrapV1,
    /// Exact public statement carried by `transaction`.
    pub statement: IrohaIvmPrivateNoteStarkStatementV1,
}
/// Final governed ZK-ACE transfer shape retained for fail-closed evidence.
///
/// Production builders cannot return this type until the independent qROM
/// reduction and implementation review are registered.
#[derive(Clone, Debug)]
pub struct PrivacyReleaseZkAceNetworkActionV1 {
    /// Ordinary signed transaction carrying exactly one ZK-ACE proof.
    pub transaction: SignedTransaction,
    /// Exact active policy required before submission.
    pub policy: PrivacyZkAcePolicyRecordV1,
    /// Exact public statement carried by `transaction`.
    pub statement: ZkAcePqAuthorizationStatementV1,
}
fn evidence_error() -> PrivacyReleaseEvidenceErrorClassV1 {
    PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
}
fn validate_context_and_signer_v1(
    context: &PrivacyReleaseTransactionContextV1,
    private_key: &PrivateKey,
) -> Result<(), PrivacyReleaseEvidenceErrorClassV1> {
    if context.genesis_hash == [0; 32]
        || context.network_id.as_bytes() != &context.genesis_hash
        || context
            .authority
            .try_signatory()
            .is_none_or(|expected| expected != &PublicKey::from(private_key.clone()))
    {
        return Err(evidence_error());
    }
    Ok(())
}
fn draft_intent_v1(
    context: &PrivacyReleaseTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<PrivacyTransactionIntentDigestV1, PrivacyReleaseEvidenceErrorClassV1> {
    let intent = transaction_payload_v1(context, envelope)?
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| evidence_error())?;
    if intent.is_zero() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(intent)
}
fn finish_transaction_v1(
    context: &PrivacyReleaseTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
    expected_intent: PrivacyTransactionIntentDigestV1,
    private_key: &PrivateKey,
) -> Result<SignedTransaction, PrivacyReleaseEvidenceErrorClassV1> {
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| evidence_error())?;
    let payload = transaction_payload_v1(context, envelope)?;
    let observed = payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if observed != expected_intent {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    signed_payload_v1(payload, expected_intent, private_key)
}
/// Bind the proof-free envelope used only to derive a transaction intent.
fn placeholder_envelope_v1(
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
) -> Result<PrivacyProofEnvelopeV1, PrivacyReleaseEvidenceErrorClassV1> {
    final_envelope_v1(profile, statement, proof)
}
/// Bind the canonical envelope and require the compiled profile's identities.
///
/// The canonical binder derives every envelope identity from the statement;
/// this builder additionally refuses a statement whose context was not built
/// from `profile`.
fn final_envelope_v1(
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
) -> Result<PrivacyProofEnvelopeV1, PrivacyReleaseEvidenceErrorClassV1> {
    let envelope = PrivacyProofEnvelopeV1::bind_v1(statement, proof)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if !profile.matches_envelope_v1(&envelope) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(envelope)
}
fn secret_scalar_v1(
    master: [u8; 32],
    purpose: &[u8],
    index: u8,
) -> Result<SecretScalarV1, PrivacyReleaseEvidenceErrorClassV1> {
    let seed = network_seed_v1(master, purpose, index);
    // A small, nonzero big-endian scalar is canonical for P-256. Hash-derived
    // high bytes are intentionally not interpreted directly because arbitrary
    // 256-bit strings may exceed the scalar modulus.
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(
        &u64::from_be_bytes(seed[..8].try_into().expect("eight bytes"))
            .max(1)
            .to_be_bytes(),
    );
    SecretScalarV1::from_bytes(bytes).map_err(|_| evidence_error())
}
/// Reject a governed ZK-ACE transfer before constructing a proof.
///
/// Otherwise-valid inputs return
/// [`PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable`] while qROM
/// qualification remains incomplete.
pub fn build_privacy_release_zk_ace_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    source: AccountId,
    destination: AccountId,
    asset_definition_id: AssetDefinitionId,
    amount: u128,
    fixture_seed: [u8; 32],
    proof_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseZkAceNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    if amount == 0 || source == destination {
        return Err(evidence_error());
    }
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
    )
    .map_err(|error| match error {
        crate::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable { .. } => {
            PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable
        }
        _ => evidence_error(),
    })?;
    let identity_root = network_seed_v1(fixture_seed, b"zk-ace-identity-root", 0);
    let identity_blinding = network_seed_v1(fixture_seed, b"zk-ace-identity-blinding", 0);
    let replay_secret = network_seed_v1(fixture_seed, b"zk-ace-replay-secret", 0);
    let witness = ZkAcePrivacyWitnessV1::try_new(identity_root, identity_blinding, replay_secret)
        .map_err(|_| evidence_error())?;
    let policy = PrivacyZkAcePolicyRecordV1::new(
        PrivacyPolicyIdV1::new(network_seed_v1(fixture_seed, b"zk-ace-policy-id", 0)),
        witness.identity_commitment_v1(),
        iroha_data_model::privacy::PrivacyPolicyDigestV1::new(network_seed_v1(
            fixture_seed,
            b"zk-ace-policy-digest",
            0,
        )),
        iroha_data_model::privacy::PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1,
        asset_definition_id.clone(),
        vec![source.clone()],
        PrivacyZkAcePolicyLifecycleV1::Active,
    )
    .map_err(|_| evidence_error())?;
    let mut statement = ZkAcePqAuthorizationStatementV1 {
        context: statement_context_v1(&transaction_context, profile),
        identity_commitment: policy.identity_commitment,
        policy_id: policy.policy_id,
        policy_digest: policy.policy_digest,
        source,
        destination,
        asset_definition_id,
        public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
        amount,
        authorization_epoch: policy.authorization_epoch,
        replay_nullifier: Default::default(),
    };
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            PrivacyStatementV1::ZkAcePqAuthorizationV1(statement.clone()),
            PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    let authorization_inputs =
        ZkAcePrivacyPublicInputsV1::new(statement.clone(), transaction_context.genesis_hash);
    let authorization_digest = derive_zk_ace_privacy_authorization_digest(&authorization_inputs)
        .map_err(|_| evidence_error())?;
    statement.replay_nullifier =
        witness.replay_nullifier_v1(&authorization_digest, &transaction_context.network_id);
    let public_inputs =
        ZkAcePrivacyPublicInputsV1::new(statement.clone(), transaction_context.genesis_hash);
    let mut rng = EvidenceRng09::new(network_seed_v1(proof_seed, b"zk-ace-proof", 0));
    let proof = prove_zk_ace_privacy_v1_with_rng(&public_inputs, &witness, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let envelope = final_envelope_v1(
        profile,
        PrivacyStatementV1::ZkAcePqAuthorizationV1(statement.clone()),
        PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(proof)),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    Ok(PrivacyReleaseZkAceNetworkActionV1 {
        transaction,
        policy,
        statement,
    })
}
/// Build one transaction-intent- and genesis-bound native VeRange action.
///
/// Values are restricted to the canonical 32-bit profile and the closed
/// one-to-eight aggregation bound before any proof allocation.
pub fn build_privacy_release_verange_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    asset_definition_id: AssetDefinitionId,
    policy_id: PrivacyPolicyIdV1,
    values: Vec<u64>,
    fixture_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseVeRangeNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    const MAX_AGGREGATION: usize = 8;
    if values.is_empty()
        || values.len() > MAX_AGGREGATION
        || values.iter().any(|value| *value > u64::from(u32::MAX))
        || policy_id.is_zero()
    {
        return Err(evidence_error());
    }
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
    )
    .map_err(|_| evidence_error())?;
    let native_profile = VeRangeBitLengthV1::Bits32;
    let blindings = (0..values.len())
        .map(|index| {
            secret_scalar_v1(
                fixture_seed,
                b"verange-blinding",
                u8::try_from(index).expect("VeRange bound fits u8"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = values
        .iter()
        .zip(&blindings)
        .map(|(value, blinding)| {
            commit(native_profile, *value, blinding).map_err(|_| evidence_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut statement = VeRangeTransparentRangeStatementV1 {
        context: statement_context_v1(&transaction_context, profile),
        asset_definition_id,
        policy_id,
        value_commitments: commitments
            .iter()
            .map(|point| PrivacyP256PointV1::new(*point.as_bytes()))
            .collect(),
        bit_length: PrivacyVeRangeBitLengthV1::Bits32,
        aggregation_count: u32::try_from(values.len()).expect("VeRange bound fits u32"),
    };
    let draft_statement = PrivacyStatementV1::VeRangeTransparentRangeV1(statement.clone());
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            draft_statement,
            PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::VeRangeTransparentRangeV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let parameters =
        VeRangeParametersV1::for_profile(native_profile).map_err(|_| evidence_error())?;
    let transcript = TranscriptBindingV1 {
        network_id: transaction_context.network_id.as_bytes(),
        genesis_hash: transaction_context.genesis_hash,
        action_index: 0,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    };
    let native_statement =
        VeRangeType1BatchStatementV1::new(native_profile, commitments, transcript)
            .map_err(|_| evidence_error())?;
    let mut rng = EvidenceRng06::new(network_seed_v1(fixture_seed, b"verange-proof", 0));
    let proof = prove_batch(&native_statement, &values, &blindings, &mut rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
        .encode();
    let envelope = final_envelope_v1(
        profile,
        typed_statement,
        PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(proof)),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    Ok(PrivacyReleaseVeRangeNetworkActionV1 {
        transaction,
        statement,
    })
}
/// Build one transaction-intent-, governed-policy-, and genesis-bound native
/// Bootle/Lantern presentation.
pub fn build_privacy_release_bootle_lantern_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    fixture_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseBootleLanternNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
    )
    .map_err(|_| evidence_error())?;
    let issuer_id = PrivacyIssuerIdV1::new(network_seed_v1(fixture_seed, b"bootle-issuer", 0));
    let policy_id = PrivacyPolicyIdV1::new(network_seed_v1(fixture_seed, b"bootle-policy", 0));
    let issuer_parameter_id =
        PrivacyParameterIdV1::new(network_seed_v1(fixture_seed, b"bootle-issuer-parameter", 0));
    let disclosed_value = BootleLanternAttributeValueV1::new([1; 8]);
    let allowed_values = (0..8)
        .map(|index| BootleLanternAllowedAttributeValuesV1 {
            values: if index == 1 {
                vec![disclosed_value]
            } else {
                Vec::new()
            },
        })
        .collect::<Vec<_>>();
    let context = statement_context_v1(&transaction_context, profile);
    let mut keygen_rng =
        EvidenceRng06::new(network_seed_v1(fixture_seed, b"bootle-issuer-keygen", 0));
    let issuer_key_pair =
        BootleLanternIssuerKeyPairV1::generate_with_rng_v1(issuer_parameter_id, &mut keygen_rng)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let policy = issuer_key_pair
        .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
            issuer_id,
            policy_id,
            epoch: 1,
            required_disclosure_bitmap: 0b0000_0010,
            allowed_values: allowed_values.clone(),
        })
        .map_err(|_| evidence_error())?;
    let issuance_store_directory = tempfile::tempdir().map_err(|_| evidence_error())?;
    let issuance_store_root = issuance_store_directory
        .path()
        .join("bootle-issuance-store");
    let issuance_store = BootleLanternFileIssuanceStoreV1::open(
        &issuance_store_root,
        BootleLanternIssuanceStoreConfigV1::default(),
    )
    .map_err(|_| evidence_error())?;
    let mut authorization_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"bootle-issuer-authorization",
        0,
    ));
    let authorization = issuer_authorize_blind_issuance_with_rng_v1(
        &issuer_key_pair,
        &context,
        transaction_context.genesis_hash,
        &policy,
        network_seed_v1(fixture_seed, b"bootle-requester-authorization", 0),
        100,
        200,
        &issuance_store,
        &mut authorization_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let authorization = BootleLanternIssuanceAuthorizationV1::decode_exact(
        &authorization.encode().map_err(|_| evidence_error())?,
    )
    .map_err(|_| evidence_error())?;
    let mut statement = IrohaBootleLanternAnoncredStatementV1 {
        context: context.clone(),
        issuer_id: policy.issuer_id,
        policy_id: policy.policy_id,
        issuer_policy_epoch: policy.epoch,
        issuer_policy_record_digest: policy.record_digest,
        issuer_parameter_id: policy.issuer_parameter_id,
        issuer_parameter_digest: policy.issuer_parameter_digest,
        disclosures: vec![BootleLanternDisclosedAttributeV1 {
            index: 1,
            value: disclosed_value,
        }],
    };
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone()),
            PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    let mut attributes = [[0_u8; 8]; 8];
    attributes[1] = [1; 8];
    let mut holder_issuance_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"bootle-holder-issuance-master",
        0,
    ));
    let (issuance_request, issuance_state) = holder_prepare_blind_issuance_with_rng_v1(
        &context,
        transaction_context.genesis_hash,
        &policy,
        &authorization,
        attributes,
        &mut holder_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let issuance_request_wire = issuance_request
        .encode()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed)?;
    let mut issuer_issuance_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"bootle-issuer-issuance-master",
        0,
    ));
    let issuance_response = issuer_blind_issue_once_encoded_with_rng_v1(
        &issuer_key_pair,
        &context,
        transaction_context.genesis_hash,
        &policy,
        &authorization,
        &issuance_request_wire,
        100,
        &issuance_store,
        &mut issuer_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let response_wire = issuance_response.encode().map_err(|_| evidence_error())?;
    drop(issuance_store);
    let issuance_store = BootleLanternFileIssuanceStoreV1::open(
        &issuance_store_root,
        BootleLanternIssuanceStoreConfigV1::default(),
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let mut unavailable_issuance_rng = UnavailableIssuanceRngV1;
    let cached_response = issuer_blind_issue_once_encoded_with_rng_v1(
        &issuer_key_pair,
        &context,
        transaction_context.genesis_hash,
        &policy,
        &authorization,
        &issuance_request_wire,
        201,
        &issuance_store,
        &mut unavailable_issuance_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    if cached_response.encode().map_err(|_| evidence_error())? != response_wire {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let issuance_response = BootleLanternBlindIssuanceResponseV1::decode_exact(&response_wire)
        .map_err(|_| evidence_error())?;
    let credential = holder_finalize_blind_issuance_v1(
        issuance_state,
        &context,
        transaction_context.genesis_hash,
        &policy,
        issuance_response,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let witness = credential
        .presentation_witness_v1(&statement, &policy, transaction_context.genesis_hash)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let mut rng = EvidenceRng06::new(network_seed_v1(fixture_seed, b"bootle-proof", 0));
    let proof = prove_bound_presentation_v1(
        &statement,
        &policy,
        transaction_context.genesis_hash,
        &witness,
        &mut rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
    .encode();
    let envelope = final_envelope_v1(
        profile,
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone()),
        PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(proof)),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    let successor_parameter_id = PrivacyParameterIdV1::new(network_seed_v1(
        fixture_seed,
        b"bootle-successor-issuer-parameter",
        0,
    ));
    let mut successor_keygen_rng =
        EvidenceRng06::new(network_seed_v1(fixture_seed, b"bootle-successor-keygen", 0));
    let successor_key_pair = BootleLanternIssuerKeyPairV1::generate_with_rng_v1(
        successor_parameter_id,
        &mut successor_keygen_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let successor_policy = successor_key_pair
        .active_policy_v1(BootleLanternIssuerPolicyMetadataV1 {
            issuer_id,
            policy_id,
            epoch: policy
                .epoch
                .checked_add(1)
                .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?,
            required_disclosure_bitmap: policy.required_disclosure_bitmap,
            allowed_values,
        })
        .map_err(|_| evidence_error())?;
    successor_policy
        .validate_rotation_successor(&policy)
        .map_err(|_| evidence_error())?;
    if successor_policy.issuer_public_matrix == policy.issuer_public_matrix {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut successor_statement = statement.clone();
    successor_statement.issuer_policy_epoch = successor_policy.epoch;
    successor_statement.issuer_policy_record_digest = successor_policy.record_digest;
    successor_statement.issuer_parameter_id = successor_policy.issuer_parameter_id;
    successor_statement.issuer_parameter_digest = successor_policy.issuer_parameter_digest;
    if credential
        .presentation_witness_v1(
            &successor_statement,
            &successor_policy,
            transaction_context.genesis_hash,
        )
        .is_ok()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(PrivacyReleaseBootleLanternNetworkActionV1 {
        transaction,
        policy,
        successor_policy,
        statement,
    })
}
fn model_pgc_ciphertext_v1(ciphertext: TwistedElGamalCiphertextV1) -> PrivacyP256CiphertextV1 {
    PrivacyP256CiphertextV1 {
        left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
        right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
    }
}
fn model_pgc_accounts_v1(
    public_keys: &[TwistedElGamalPublicKeyV1],
    balances: &[TwistedElGamalCiphertextV1],
) -> Result<Vec<PrivacyPgcAccountV1>, PrivacyReleaseEvidenceErrorClassV1> {
    if public_keys.len() != balances.len() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    Ok(public_keys
        .iter()
        .zip(balances)
        .map(|(public_key, balance)| PrivacyPgcAccountV1 {
            public_key: PrivacyP256PointV1::new(*public_key.as_point().as_bytes()),
            encrypted_balance: model_pgc_ciphertext_v1(*balance),
        })
        .collect())
}
/// Build a chain-bound Anonymous-PGC bootstrap proof and one transaction-bound
/// payment that advances its complete encrypted account table exactly once.
///
/// `bootstrap_action_index` must be the index at which the caller will place
/// `BootstrapPrivacyPgcAccountsV1`; release gates normally submit that
/// governance instruction alone and therefore pass zero.
pub fn build_privacy_release_anonymous_pgc_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    asset_definition_id: AssetDefinitionId,
    pool_id: PrivacyPoolIdV1,
    bootstrap_action_index: u32,
    fixture_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseAnonymousPgcNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    const ACCOUNT_COUNT: usize = 16;
    const OPENING_BALANCE: u32 = 100;
    const RECIPIENT_COUNT: usize = 2;
    const SENDER_INDEX: usize = 7;
    const RECIPIENT_INDICES: [usize; RECIPIENT_COUNT] = [2, 12];
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
    )
    .map_err(|_| evidence_error())?;
    let parameters = AnonymousPgcParametersV1::get().map_err(|_| evidence_error())?;
    if profile.parameter_digest.as_bytes() != &parameters.parameter_digest() {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut key_pairs = (0..ACCOUNT_COUNT)
        .map(|index| {
            let secret = secret_scalar_v1(
                fixture_seed,
                b"anonymous-pgc-account-secret",
                u8::try_from(index).expect("PGC account bound fits u8"),
            )?;
            TwistedElGamalKeyPairV1::from_secret(secret).map_err(|_| evidence_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
    let public_keys = key_pairs
        .iter()
        .map(TwistedElGamalKeyPairV1::public_key)
        .collect::<Vec<_>>();
    let opening_randomness = (0..ACCOUNT_COUNT)
        .map(|index| {
            secret_scalar_v1(
                fixture_seed,
                b"anonymous-pgc-opening-randomness",
                u8::try_from(index).expect("PGC account bound fits u8"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let opening_ciphertexts = public_keys
        .iter()
        .copied()
        .zip(&opening_randomness)
        .map(|(key, randomness)| {
            encrypt_with_randomness(key, OPENING_BALANCE, randomness).map_err(|_| evidence_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let namespace = PrivacyNamespaceV1::new(
        iroha_data_model::privacy::PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 { pool_id }),
    );
    let accounts = model_pgc_accounts_v1(&public_keys, &opening_ciphertexts)?;
    let total_supply = OPENING_BALANCE
        .checked_mul(u32::try_from(ACCOUNT_COUNT).expect("PGC account bound fits u32"))
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let initial_root = compute_privacy_pgc_account_state_root_v1(
        namespace,
        PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        &accounts,
    )
    .map_err(|_| evidence_error())?;
    let bootstrap = PrivacyPgcAccountBootstrapV1 {
        namespace,
        initial_root,
        initial_epoch: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        accounts,
    };
    bootstrap.validate().map_err(|_| evidence_error())?;
    let bootstrap_digest = bootstrap.digest().map_err(|_| evidence_error())?;
    let namespace_encoding = norito::to_bytes(&namespace).map_err(|_| evidence_error())?;
    let bootstrap_binding = TranscriptBindingV1 {
        network_id: transaction_context.network_id.as_bytes(),
        genesis_hash: transaction_context.genesis_hash,
        action_index: bootstrap_action_index,
        statement_digest: *bootstrap_digest.as_bytes(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    };
    let native_bootstrap = AnonymousPgcBootstrapStatementV1::new(
        &namespace_encoding,
        *initial_root.as_bytes(),
        PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        total_supply,
        &public_keys,
        &opening_ciphertexts,
        bootstrap_binding,
    )
    .map_err(|_| evidence_error())?;
    let opening_balances = [OPENING_BALANCE; ACCOUNT_COUNT];
    let bootstrap_witness = AnonymousPgcBootstrapWitnessV1 {
        balances: &opening_balances,
        randomness: &opening_randomness,
    };
    let mut bootstrap_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"anonymous-pgc-bootstrap-proof",
        0,
    ));
    let bootstrap_proof =
        prove_bootstrap(&native_bootstrap, &bootstrap_witness, &mut bootstrap_rng)
            .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
            .encode();
    let verified_bootstrap = verify_bootstrap_encoded(&native_bootstrap, &bootstrap_proof)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if verified_bootstrap.total_supply() != total_supply
        || verified_bootstrap.account_count() != ACCOUNT_COUNT
        || verified_bootstrap.bootstrap_table_digest() != native_bootstrap.bootstrap_table_digest()
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let bootstrap_proof = PrivacyPgcBootstrapProofBytesV1::new(bootstrap_proof);
    let bootstrap_proof_digest = bootstrap_proof.digest().map_err(|_| evidence_error())?;
    let mut transfer_values = vec![0_i64; ACCOUNT_COUNT];
    transfer_values[RECIPIENT_INDICES[0]] = 20;
    transfer_values[RECIPIENT_INDICES[1]] = 30;
    transfer_values[SENDER_INDEX] = -50;
    let transfer_randomness = (0..ACCOUNT_COUNT)
        .map(|index| {
            secret_scalar_v1(
                fixture_seed,
                b"anonymous-pgc-transfer-randomness",
                u8::try_from(index).expect("PGC account bound fits u8"),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let transfer_ciphertexts = public_keys
        .iter()
        .copied()
        .zip(&transfer_values)
        .zip(&transfer_randomness)
        .map(|((key, value), randomness)| {
            encrypt_signed_with_randomness(key, *value, randomness).map_err(|_| evidence_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_ciphertexts = opening_ciphertexts
        .iter()
        .copied()
        .zip(transfer_ciphertexts.iter().copied())
        .map(|(current, transfer)| add_ciphertexts(current, transfer).map_err(|_| evidence_error()))
        .collect::<Result<Vec<_>, _>>()?;
    let next_accounts = model_pgc_accounts_v1(&public_keys, &next_ciphertexts)?;
    let next_epoch = PGC_BOOTSTRAP_INITIAL_EPOCH_V1
        .checked_add(1)
        .ok_or(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let next_root = compute_privacy_pgc_account_state_root_v1(
        namespace,
        next_epoch,
        total_supply,
        &next_accounts,
    )
    .map_err(|_| evidence_error())?;
    if next_root == initial_root || next_root == PrivacyRootV1::new([0; 32]) {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut statement = AnonymousPgcKOutOfNStatementV1 {
        context: statement_context_v1(&transaction_context, profile),
        asset_definition_id,
        pool_id,
        account_state_root: initial_root,
        account_state_root_epoch: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
        next_account_state_root: next_root,
        next_account_state_root_epoch: next_epoch,
        anonymity_set_public_keys: public_keys
            .iter()
            .map(|key| PrivacyP256PointV1::new(*key.as_point().as_bytes()))
            .collect(),
        transfer_ciphertexts: transfer_ciphertexts
            .iter()
            .copied()
            .map(model_pgc_ciphertext_v1)
            .collect(),
        recipient_count: u32::try_from(RECIPIENT_COUNT).expect("PGC recipient count fits u32"),
    };
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement.clone()),
            PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let payment_binding = TranscriptBindingV1 {
        network_id: transaction_context.network_id.as_bytes(),
        genesis_hash: transaction_context.genesis_hash,
        action_index: 0,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: parameters.generator_digest(),
    };
    let invariant = AnonymousPgcPoolInvariantV1::new(
        total_supply,
        *bootstrap_digest.as_bytes(),
        *bootstrap_proof_digest.as_bytes(),
    )
    .map_err(|_| evidence_error())?;
    let native_statement = AnonymousPgcPaymentStatementV1::new(
        &public_keys,
        &transfer_ciphertexts,
        &opening_ciphertexts,
        RECIPIENT_COUNT,
        invariant,
        payment_binding,
    )
    .map_err(|_| evidence_error())?;
    let witness = AnonymousPgcPaymentWitnessV1 {
        transfer_values: &transfer_values,
        transfer_randomness: &transfer_randomness,
        sender_index: SENDER_INDEX,
        sender_secret: key_pairs[SENDER_INDEX].secret_scalar(),
    };
    let mut payment_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"anonymous-pgc-payment-proof",
        0,
    ));
    let proof = prove_payment(&native_statement, &witness, &mut payment_rng)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?
        .encode();
    let verified_payment = verify_payment_encoded(&native_statement, &proof)
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeVerifierRejected)?;
    if verified_payment.next_balance_ciphertexts() != next_ciphertexts {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let envelope = final_envelope_v1(
        profile,
        typed_statement,
        PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(proof)),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    Ok(PrivacyReleaseAnonymousPgcNetworkActionV1 {
        transaction,
        bootstrap,
        bootstrap_proof,
        statement,
    })
}
fn model_fcmp_output_v1(output: FcmpOutputTupleV1) -> PrivacyFcmpOutputTupleV1 {
    let (output_key, linking_tag_generator, amount_commitment) = output.components();
    PrivacyFcmpOutputTupleV1 {
        output_key,
        linking_tag_generator,
        amount_commitment,
    }
}
fn fcmp_scalar_v1(value: u64) -> [u8; 32] {
    let mut scalar = [0_u8; 32];
    scalar[..8].copy_from_slice(&value.to_le_bytes());
    scalar
}
/// Build one canonical one-input/one-output native FCMP++ transaction.
///
/// Reusing the same `fixture_seed` with a distinct transaction context
/// re-proves a fresh transaction with the same stable key image, which lets a
/// network gate distinguish protocol replay from exact transaction replay.
pub fn build_privacy_release_fcmp_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    asset_definition_id: AssetDefinitionId,
    pool_id: PrivacyPoolIdV1,
    fixture_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseFcmpNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
    )
    .map_err(|_| evidence_error())?;
    let (inputs, output_openings, root) =
        fcmp_release_fixture_v1(false).map_err(|_| evidence_error())?;
    if inputs.len() != 1 || output_openings.len() != 1 || root.layers() != 1 {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let initial_native_outputs = inputs[0].release_origin_outputs_v1().to_vec();
    if initial_native_outputs.len() != 1 {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let initial_outputs = initial_native_outputs
        .iter()
        .copied()
        .map(model_fcmp_output_v1)
        .collect::<Vec<_>>();
    let bootstrap =
        PrivacyProofManagedPoolBootstrapV1::MoneroFcmpPlusPlusV1(PrivacyFcmpPoolBootstrapV1 {
            pool_id,
            asset_definition_id: asset_definition_id.clone(),
            initial_outputs,
        });
    bootstrap.validate().map_err(|_| evidence_error())?;
    let native_public_inputs = inputs
        .iter()
        .map(|input| input.public_input().map_err(|_| evidence_error()))
        .collect::<Result<Vec<_>, _>>()?;
    let model_inputs = native_public_inputs
        .iter()
        .map(|input| PrivacyFcmpInputPublicV1 {
            output_key_tilde: input.output_key_tilde,
            linking_tag_generator_tilde: input.linking_tag_generator_tilde,
            rerandomization_commitment: input.rerandomization_commitment,
            pseudo_out: input.pseudo_out,
            key_image: PrivacyFcmpKeyImageV1::new(input.key_image),
        })
        .collect::<Vec<_>>();
    let outputs = output_openings
        .iter()
        .map(|opening| model_fcmp_output_v1(opening.output()))
        .collect::<Vec<_>>();
    // The closed one-layer release fixture creates its output key as 43*B
    // (zero T blinding). Reconstructing the wallet note here is independently
    // checked against the public tuple and opening; fixture drift therefore
    // fails closed before encryption or proof allocation.
    let spend_x = Zeroizing::new(fcmp_scalar_v1(43));
    let output_y = Zeroizing::new([0_u8; 32]);
    let commitment_mask = output_openings[0].commitment_mask();
    let output_note = FcmpWalletNoteV1::new_borrowed(
        output_openings[0].output(),
        &spend_x,
        &output_y,
        output_openings[0].amount(),
        &commitment_mask,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let recipient_secret = network_seed_v1(fixture_seed, b"fcmp-recipient", 0);
    let recipient_public =
        fcmp_recipient_public_key_v1(recipient_secret).map_err(|_| evidence_error())?;
    let mut encryption_rng =
        EvidenceRng06::new(network_seed_v1(fixture_seed, b"fcmp-encrypted-output", 0));
    let encrypted_output = encrypt_fcmp_wallet_note_v1(
        &mut encryption_rng,
        pool_id,
        outputs[0],
        &output_note,
        recipient_public,
    )
    .map_err(|_| evidence_error())?;
    let mut statement = MoneroFcmpPlusPlusStatementV1 {
        context: statement_context_v1(&transaction_context, profile),
        asset_definition_id,
        pool_id,
        output_set_root: PrivacyFcmpTreeRootV1 {
            layers: root.layers(),
            point: root.point(),
        },
        root_epoch: 1,
        inputs: model_inputs,
        outputs,
        encrypted_outputs: vec![encrypted_output],
    };
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement.clone()),
            PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant)?;
    let runtime_context = derive_fcmp_runtime_context_hash_v1(&FcmpRuntimeContextBindingV1 {
        network_id: &transaction_context.network_id,
        action_index: 0,
        statement_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    });
    let mut proof_rng = EvidenceRng06::new(network_seed_v1(fixture_seed, b"fcmp-proof", 0));
    let proof = prove_fcmp_plus_plus_v1(
        &mut proof_rng,
        runtime_context,
        &inputs,
        &output_openings,
        root,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    if proof.public_inputs() != native_public_inputs {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let envelope = final_envelope_v1(
        profile,
        typed_statement,
        PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(proof.proof_wire().to_vec())),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    Ok(PrivacyReleaseFcmpNetworkActionV1 {
        transaction,
        bootstrap,
        statement,
    })
}
/// Build one canonical one-input/one-output private-IVM note transaction.
///
/// Reusing the same pool and fixture seed with a distinct transaction context
/// preserves the stable note nullifier while re-binding and re-proving the
/// complete action, enabling protocol-level replay coverage after restart.
pub fn build_privacy_release_ivm_private_note_network_action_v1(
    transaction_context: PrivacyReleaseTransactionContextV1,
    asset_definition_id: AssetDefinitionId,
    pool_id: PrivacyPoolIdV1,
    reserve_account: AccountId,
    fixture_seed: [u8; 32],
    private_key: &PrivateKey,
) -> Result<PrivacyReleaseIvmPrivateNoteNetworkActionV1, PrivacyReleaseEvidenceErrorClassV1> {
    validate_context_and_signer_v1(&transaction_context, private_key)?;
    let profile = compiled_privacy_profile_v1(
        iroha_data_model::privacy::PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
    )
    .map_err(|_| evidence_error())?;
    let mut fixture_rng = EvidenceRng06::new(network_seed_v1(
        fixture_seed,
        b"ivm-private-note-fixture",
        0,
    ));
    let fixture =
        ivm_private_note_network_fixture_v1(pool_id, asset_definition_id.clone(), &mut fixture_rng)
            .map_err(|_| evidence_error())?;
    let input_commitments = fixture
        .witness
        .inputs()
        .iter()
        .map(|input| input.commitment_v1().map_err(|_| evidence_error()))
        .collect::<Result<Vec<_>, _>>()?;
    let bootstrap = PrivacyProofManagedPoolBootstrapV1::IrohaIvmPrivateNoteStarkV1(
        PrivacyIvmPrivateNotePoolBootstrapV1 {
            pool_id,
            asset_definition_id,
            public_balance_scope: fixture.statement.public_balance_scope,
            reserve_account,
            program_id: fixture.statement.program_id,
            initial_note_commitments: input_commitments,
        },
    );
    bootstrap.validate().map_err(|_| evidence_error())?;
    let expected_root = crate::privacy_engines::proof_managed_pool_initial_root_v1(&bootstrap)
        .map_err(|_| evidence_error())?;
    if expected_root != fixture.statement.state_root
        || fixture.statement.root_epoch != 1
        || fixture.statement.execution_epoch != 1
    {
        return Err(PrivacyReleaseEvidenceErrorClassV1::EvidenceInvariant);
    }
    let mut statement = fixture.statement;
    statement.context = statement_context_v1(&transaction_context, profile);
    statement.action_digest = statement
        .computed_action_digest()
        .map_err(|_| evidence_error())?;
    let intent = draft_intent_v1(
        &transaction_context,
        placeholder_envelope_v1(
            profile,
            PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement.clone()),
            PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1::new(Vec::new())),
        )?,
    )?;
    statement.context.transaction_intent_digest = intent;
    statement.action_digest = statement
        .computed_action_digest()
        .map_err(|_| evidence_error())?;
    let limits = PrivacyConsensusLimitsV1::taira_default();
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        transaction_context.genesis_hash,
        &limits,
    )
    .map_err(|_| evidence_error())?;
    let mut proof_rng =
        EvidenceRng09::new(network_seed_v1(fixture_seed, b"ivm-private-note-proof", 0));
    let proof = prove_ivm_private_note_v1_with_rng(
        &statement,
        &consensus_binding,
        &limits,
        &fixture.witness,
        &mut proof_rng,
    )
    .map_err(|_| PrivacyReleaseEvidenceErrorClassV1::NativeProverRejected)?;
    let envelope = final_envelope_v1(
        profile,
        PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement.clone()),
        PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1::new(proof)),
    )?;
    let transaction = finish_transaction_v1(&transaction_context, envelope, intent, private_key)?;
    Ok(PrivacyReleaseIvmPrivateNoteNetworkActionV1 {
        transaction,
        bootstrap,
        statement,
    })
}
// Stateful retained-network action builders are defined below. Keeping them
// in this module lets all six paths share the exact two-pass intent and final
// envelope checks above.
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::transaction::FeePaymentIntent;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use std::time::Duration;
    fn context(key_pair: &KeyPair) -> PrivacyReleaseTransactionContextV1 {
        PrivacyReleaseTransactionContextV1 {
            network_id: crate::privacy_release_evidence::release_network_id_from_genesis_hash(
                [0xA7; 32],
            ),
            authority: AccountId::new(key_pair.public_key().clone()),
            creation_time: Duration::from_secs(1_800_000_000),
            time_to_live: Some(Duration::from_secs(3_600)),
            nonce: None,
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            metadata: Metadata::default(),
            genesis_hash: [0xA7; 32],
        }
    }
    fn asset() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("domain"),
            "release_asset".parse::<Name>().expect("asset name"),
        )
    }
    #[test]
    fn scalar_derivation_is_nonzero_and_domain_separated() {
        let left = secret_scalar_v1([7; 32], b"left", 0).expect("left scalar");
        let right = secret_scalar_v1([7; 32], b"right", 0).expect("right scalar");
        assert_ne!(
            format!("{left:?}"),
            "",
            "redacted scalar formatting remains available"
        );
        // Distinct derivations produce distinct commitments without exposing
        // either secret scalar.
        let left_commitment = commit(VeRangeBitLengthV1::Bits32, 1, &left).expect("left commit");
        let right_commitment = commit(VeRangeBitLengthV1::Bits32, 1, &right).expect("right commit");
        assert_ne!(left_commitment, right_commitment);
    }
    #[test]
    fn invalid_context_and_closed_builder_bounds_reject_before_proving() {
        let key_pair = KeyPair::try_from_seed(vec![0x11; 32], Algorithm::Ed25519)
            .expect("release builder keypair");
        let valid = context(&key_pair);
        assert_eq!(
            build_privacy_release_verange_network_action_v1(
                valid.clone(),
                asset(),
                PrivacyPolicyIdV1::new([0x31; 32]),
                Vec::new(),
                [0x41; 32],
                key_pair.private_key(),
            )
            .expect_err("empty VeRange batch must reject"),
            PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
        );
        assert_eq!(
            build_privacy_release_verange_network_action_v1(
                valid.clone(),
                asset(),
                PrivacyPolicyIdV1::new([0x31; 32]),
                vec![1; 9],
                [0x41; 32],
                key_pair.private_key(),
            )
            .expect_err("over-bound VeRange batch must reject"),
            PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
        );
        assert_eq!(
            build_privacy_release_zk_ace_network_action_v1(
                valid.clone(),
                valid.authority.clone(),
                AccountId::new(
                    KeyPair::try_from_seed(vec![0x22; 32], Algorithm::Ed25519)
                        .expect("destination keypair")
                        .public_key()
                        .clone(),
                ),
                asset(),
                0,
                [0x51; 32],
                [0x52; 32],
                key_pair.private_key(),
            )
            .expect_err("zero ZK-ACE amount must reject"),
            PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
        );
        assert_eq!(
            build_privacy_release_zk_ace_network_action_v1(
                valid.clone(),
                valid.authority.clone(),
                AccountId::new(
                    KeyPair::try_from_seed(vec![0x23; 32], Algorithm::Ed25519)
                        .expect("destination keypair")
                        .public_key()
                        .clone(),
                ),
                asset(),
                1,
                [0x53; 32],
                [0x54; 32],
                key_pair.private_key(),
            )
            .expect_err("ZK-ACE must remain unavailable without qROM qualification"),
            PrivacyReleaseEvidenceErrorClassV1::ProtocolUnavailable
        );
        let mut zero_genesis = valid.clone();
        zero_genesis.genesis_hash = [0; 32];
        assert_eq!(
            build_privacy_release_bootle_lantern_network_action_v1(
                zero_genesis,
                [0x61; 32],
                key_pair.private_key(),
            )
            .expect_err("zero-genesis Bootle/Lantern context must reject"),
            PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
        );
        let wrong_key = KeyPair::try_from_seed(vec![0x33; 32], Algorithm::Ed25519)
            .expect("wrong release builder keypair");
        assert_eq!(
            validate_context_and_signer_v1(&valid, wrong_key.private_key())
                .expect_err("wrong signing authority must reject"),
            PrivacyReleaseEvidenceErrorClassV1::FixtureConstructionFailed
        );
    }
}
