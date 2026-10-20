//! PyO3-free native privacy action construction and inspection.
//!
//! This module is shared by the Python extension and the isolated wallet
//! worker. Secret-bearing request types intentionally implement neither
//! serialization nor `Debug`: an adapter must parse bounded wallet-local
//! material directly into the typed constructors below, and the only returned
//! wire is a complete signed transaction.
use core::{fmt, num::NonZeroU32, time::Duration};
use iroha_core_privacy::{
    privacy_engines::{
        ZK_X509_CREDENTIAL_PROOF_MAX_BYTES_V1,
        anonymous_pgc::{
            AnonymousPgcParametersV1, AnonymousPgcPoolInvariantV1, TwistedElGamalCiphertextV1,
            TwistedElGamalPublicKeyV1, add_ciphertexts,
            payment::{
                AnonymousPgcPaymentStatementV1, AnonymousPgcPaymentWitnessV1,
                encrypt_signed_with_randomness, prove_payment,
            },
        },
        bootle_lantern::{
            prove_bound_presentation_v1, relation::BootleLanternPresentationWitnessV1,
        },
        fcmp_plus_plus::{
            FcmpOutputCommitmentOpeningV1, FcmpProofInputPublicV1, FcmpProverInputV1,
            FcmpRuntimeContextBindingV1, FcmpTreeRootV1, FcmpWalletNoteV1,
            derive_fcmp_runtime_context_hash_v1, encrypt_fcmp_wallet_note_v1,
            prove_fcmp_plus_plus_v1,
        },
        ivm_private_note::{
            IvmPrivateNoteInputWitnessV1, IvmPrivateNoteOutputWitnessV1, IvmPrivateNoteWitnessV1,
            PrivateProgramV1, derive_private_program_id_v1,
            encrypt_ivm_private_wallet_note_with_os_rng_v1, prove_ivm_private_note_v1,
        },
        jindo::{
            JindoPrivacyActionTransactionContextV1, JindoPrivacyActionWitnessV1,
            build_signed_privacy_action_v1 as build_signed_jindo_privacy_action_v1,
        },
        orchard::{
            OrchardActionPublicV1, OrchardChangeProverInputV1, OrchardSpendProverInputV1,
            authorize_orchard_bundle_v1, prepare_orchard_bundle_v1,
        },
        p256::{DeviceSigningKeyV1, SecretScalarV1, TranscriptBindingV1},
        pq_masp::{
            PqMaspInputWitnessV1, PqMaspOutputWitnessV1, PqMaspWitnessV1,
            derive_pq_masp_authorization_key_digest_from_secret_v1,
            derive_pq_masp_note_encryption_keys_digest_v1, encrypt_pq_masp_note_v1,
            prove_pq_masp_v1,
        },
        validate_zk_x509_credential_proof_container_v1,
        vega::{
            VegaPrivacyActionPublicInputV1, VegaPrivacyActionTransactionContextV1,
            VegaPrivacyActionWitnessMaterialV1, build_signed_vega_privacy_action_v1,
        },
        verange::{
            VeRangeBitLengthV1, VeRangeParametersV1, VeRangeType1BatchStatementV1, commit,
            prove_batch,
        },
        zk_ams::{
            ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1, ZK_AMS_RING_SIZES_V1,
            ZkAmsBatchCredentialWitnessV1, ZkAmsPrivacyActionGovernanceV1,
            ZkAmsPrivacyActionTransactionContextV1, ZkAmsSeedSecretV1,
            prepare_zk_ams_batch_admission_transaction_intent_v1,
            prepare_zk_ams_provision_account_transaction_intent_v1,
            prove_zk_ams_batch_admission_v1, sign_zk_ams_provision_statement_v1,
            zk_ams_generator_digest_v1, zk_ams_key_image_v1, zk_ams_registry_transition_root_v1,
            zk_ams_seed_public_key_v1,
        },
    },
    privacy_profiles::{CompiledPrivacyProfileV1, compiled_privacy_profile_v1},
    privacy_state::derive_privacy_pgc_account_state_root_v1,
};
use iroha_crypto::{Hash, HashOf, PrivateKey, PublicKey};
use iroha_data_model::{
    asset::{AssetBalanceScope, AssetDefinitionId},
    isi::privacy::SubmitPrivacyProofV1,
    prelude::{AccountId, NetworkId},
    privacy::{
        AnonymousPgcKOutOfNStatementV1, BootleLanternAttributeValueV1,
        BootleLanternDisclosedAttributeV1, BootleLanternIssuerPolicyV1,
        IrohaBootleLanternAnoncredStatementV1, IrohaIvmPrivateNoteStarkStatementV1,
        IrohaZkAmsProofV1, IrohaZkAmsStatementV1, IrohaZkX509StarkP256StatementV1,
        MoneroFcmpPlusPlusStatementV1, OrchardHalo2ActionsStatementV1, PqMaspStarkStatementV1,
        PrivacyActionDigestV1, PrivacyConsensusLimitsV1, PrivacyFcmpInputPublicV1,
        PrivacyFcmpKeyImageV1, PrivacyFcmpOutputTupleV1, PrivacyFcmpTreeRootV1,
        PrivacyNamespaceScopeV1, PrivacyNamespaceV1, PrivacyNativeConsensusBindingV1,
        PrivacyNoteEncryptionKeyDigestV1, PrivacyOrchardActionV1, PrivacyP256CiphertextV1,
        PrivacyP256PointV1, PrivacyPgcAccountBootstrapDigestV1, PrivacyPgcAccountV1,
        PrivacyPgcBootstrapProofDigestV1, PrivacyPolicyIdV1, PrivacyPoolIdV1,
        PrivacyPoolNamespaceV1, PrivacyPqAuthorizationProfileV1, PrivacyPqNoteEncryptionProfileV1,
        PrivacyProofBytesV1, PrivacyProofEnvelopeV1, PrivacyProofV1, PrivacyProtocolIdV1,
        PrivacyRootV1, PrivacyStatementContextV1, PrivacyStatementDigestV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyValueBalanceDirectionV1, PrivacyValueBalanceV1,
        PrivacyVeRangeBitLengthV1, PrivacyZkAmsActionV1, PrivacyZkAmsAdmissionAnchorV1,
        PrivacyZkAmsBatchAdmissionV1, PrivacyZkAmsKeyImageV1, PrivacyZkAmsPersonhoodCredentialV1,
        PrivacyZkAmsProvisionAccountV1, PrivacyZkAmsSeedPublicKeyV1,
        VeRangeTransparentRangeStatementV1,
    },
    transaction::{
        Executable, ExecutableBatchItem, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        TransactionPayload, executable::ContractInvocation,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::topology::DataSpaceId;
use iroha_version::codec::EncodeVersioned;
use iroha_zkp_halo2::vega::ZkAmsMaskedProverConfigV1;
use rand_core_06::OsRng;
use zeroize::Zeroizing;
use zk_ace_prover::{
    ZkAcePrivacyActionTransactionContextV1, ZkAcePrivacyTransferV1, ZkAcePrivacyWitnessV1,
    build_signed_zk_ace_privacy_transfer_v1,
};
/// Maximum wallet-local secret bundle accepted by the shared worker boundary.
pub const PRIVACY_NATIVE_ACTION_MAX_SECRET_BUNDLE_BYTES_V1: usize = 8 * 1024 * 1024;
/// Maximum public dispatcher request accepted before typed construction.
pub const PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1: usize = 1024 * 1024;
/// Maximum complete versioned signed transaction returned by this module.
///
/// This is exactly Taira's first-release `max_tx_bytes` admission bound. A
/// wallet must never spend prover work constructing a response that the target
/// network will reject solely for its canonical wire size.
pub const PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1: usize = 10 * 1024 * 1024;
/// Maximum canonical typed ZK-X509 statement archive accepted from a worker.
pub const PRIVACY_ZK_X509_MAX_STATEMENT_ARCHIVE_BYTES_V1: usize = 256 * 1024;
/// Exact maximum X5S1 proof returned by the profile-owned worker.
///
/// Public proof bytes cross their own boundary and are not wallet-local secret
/// bundles. The complete signed transaction is bounded separately.
pub const PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1: usize = ZK_X509_CREDENTIAL_PROOF_MAX_BYTES_V1;
/// Parse the sole canonical public spelling of a transparent balance scope.
///
/// `dataspace:0` is intentionally unrepresentable because dataspace zero is
/// the universal coordinator route, not a restricted balance partition.
#[must_use]
pub(crate) fn parse_canonical_public_balance_scope_v1(value: &str) -> Option<AssetBalanceScope> {
    if value == "global" {
        return Some(AssetBalanceScope::Global);
    }
    let raw = value.strip_prefix("dataspace:")?;
    if raw.is_empty()
        || raw.len() > 20
        || raw.starts_with('0')
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let dataspace = raw.parse::<u64>().ok()?;
    if dataspace == DataSpaceId::UNIVERSAL.as_u64() {
        return None;
    }
    Some(AssetBalanceScope::Dataspace(DataSpaceId::new(dataspace)))
}
/// Return the sole canonical public spelling of a valid balance scope.
#[must_use]
pub(crate) fn canonical_public_balance_scope_v1(scope: AssetBalanceScope) -> Option<String> {
    match scope {
        AssetBalanceScope::Global => Some("global".to_owned()),
        AssetBalanceScope::Dataspace(dataspace) if dataspace != DataSpaceId::UNIVERSAL => {
            Some(format!("dataspace:{}", dataspace.as_u64()))
        }
        AssetBalanceScope::Dataspace(_) => None,
    }
}
/// Capability bit for hidden amounts.
pub const PRIVACY_NATIVE_FEATURE_HIDE_AMOUNT_V1: u8 = 1;
/// Capability bit for hidden senders.
pub const PRIVACY_NATIVE_FEATURE_HIDE_SENDER_V1: u8 = 1 << 1;
/// Capability bit for hidden receivers.
pub const PRIVACY_NATIVE_FEATURE_HIDE_RECEIVER_V1: u8 = 1 << 2;
/// Capability bit for hidden asset types.
pub const PRIVACY_NATIVE_FEATURE_HIDE_ASSET_TYPE_V1: u8 = 1 << 3;
/// Capability bit for post-quantum operation.
pub const PRIVACY_NATIVE_FEATURE_POST_QUANTUM_V1: u8 = 1 << 4;
/// One exact retained first-release wallet-adapter capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyNativeActionCapabilityV1 {
    /// Canonical consensus protocol identifier.
    pub protocol_id: PrivacyProtocolIdV1,
    /// Canonical BOI public-operation schema, with no aliases.
    pub operation_schema: &'static str,
    /// Closed execution classification rendered by the Privacy Lab.
    pub execution_mode: &'static str,
    /// Exact feature bits: amount=1, sender=2, receiver=4, asset=8, PQ=16.
    pub privacy_feature_mask: u8,
}
/// Complete retained native-adapter registry.
///
/// Every exact-v1 protocol appears exactly once. ZK-X509 uses its dedicated
/// fixed-capacity profile-owned worker request rather than the generic secret
/// wallet bundle, but it is still a first-class typed action here.
pub const PRIVACY_NATIVE_ACTION_CAPABILITIES_V1: [PrivacyNativeActionCapabilityV1; 12] = [
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
        operation_schema: "zk_ace_authorization_action_v1",
        execution_mode: "authorization_action",
        privacy_feature_mask: 0,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        operation_schema: "anonymous_pgc_payment_action_v1",
        execution_mode: "payment_action",
        privacy_feature_mask: 6,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
        operation_schema: "verange_range_proof_v1",
        execution_mode: "component",
        privacy_feature_mask: 1,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::IrohaZkAmsV1,
        operation_schema: "zk_ams_admission_and_provisioning_v1",
        execution_mode: "admission_action",
        privacy_feature_mask: 2,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
        operation_schema: "vega_credential_presentation_v1",
        execution_mode: "presentation_action",
        privacy_feature_mask: 2,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        operation_schema: "zk_x509_identity_presentation_v1",
        execution_mode: "presentation_action",
        privacy_feature_mask: 2,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
        operation_schema: "jindo_polynomial_evaluation_v1",
        execution_mode: "component",
        privacy_feature_mask: 0,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
        operation_schema: "bootle_lantern_credential_presentation_v1",
        execution_mode: "presentation_action",
        privacy_feature_mask: 2,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
        operation_schema: "orchard_note_action_v1",
        execution_mode: "note_action",
        privacy_feature_mask: 7,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
        operation_schema: "fcmp_membership_payment_v1",
        execution_mode: "payment_action",
        privacy_feature_mask: 2,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
        operation_schema: "ivm_private_note_action_v1",
        execution_mode: "note_action",
        privacy_feature_mask: 7,
    },
    PrivacyNativeActionCapabilityV1 {
        protocol_id: PrivacyProtocolIdV1::PqMaspStarkV1,
        operation_schema: "pq_masp_note_action_v1",
        execution_mode: "note_action",
        privacy_feature_mask: 31,
    },
];
/// Resolve one retained adapter by its sole canonical public-operation schema.
#[must_use]
pub fn privacy_native_action_capability_for_schema_v1(
    operation_schema: &str,
) -> Option<&'static PrivacyNativeActionCapabilityV1> {
    PRIVACY_NATIVE_ACTION_CAPABILITIES_V1
        .iter()
        .find(|capability| capability.operation_schema == operation_schema)
}
/// Resolve one retained adapter by exact consensus protocol.
#[must_use]
pub fn privacy_native_action_capability_for_protocol_v1(
    protocol_id: PrivacyProtocolIdV1,
) -> Option<&'static PrivacyNativeActionCapabilityV1> {
    PRIVACY_NATIVE_ACTION_CAPABILITIES_V1
        .iter()
        .find(|capability| capability.protocol_id == protocol_id)
}
/// Exact signature-bound transaction fields for one direct native action.
#[derive(Clone)]
pub struct PrivacyActionTransactionContextV1 {
    /// Exact genesis-header-derived transaction security domain.
    pub network_id: NetworkId,
    /// Exact direct single-key authority.
    pub authority: AccountId,
    /// Creation time resolved once before two-pass construction.
    pub creation_time: Duration,
    /// Optional transaction lifetime.
    pub time_to_live: Option<Duration>,
    /// Optional transaction nonce.
    pub nonce: Option<NonZeroU32>,
    /// Exact signed fee intent.
    pub fee_payment: FeePaymentIntent,
    /// Exact signed metadata.
    pub metadata: Metadata,
}
impl fmt::Debug for PrivacyActionTransactionContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyActionTransactionContextV1")
            .field("network_id", &self.network_id)
            .field("authority", &self.authority)
            .field("creation_time", &self.creation_time)
            .field("time_to_live", &self.time_to_live)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}
/// One canonical governed ZK-ACE authorization transfer.
pub struct ZkAceAuthorizationActionRequestV1 {
    /// Complete public transfer effect and governed policy.
    pub transfer: ZkAcePrivacyTransferV1,
    /// Complete wallet-local identity and replay witness.
    pub witness: ZkAcePrivacyWitnessV1,
}
/// One canonical VeRange batch.
pub struct VeRangeActionRequestV1 {
    /// Transparent asset whose hidden values are constrained.
    pub asset_definition_id: AssetDefinitionId,
    /// Governed range policy.
    pub policy_id: PrivacyPolicyIdV1,
    /// Sole 32- or 64-bit native relation.
    pub bit_length: VeRangeBitLengthV1,
    /// One to eight private values.
    pub values: Vec<u64>,
    /// Canonical nonzero openings aligned with `values`.
    pub blindings: Vec<SecretScalarV1>,
}
/// Secret material for one canonical ZK-AMS admission anchor.
pub struct ZkAmsAdmissionCredentialRequestV1 {
    /// Exact canonical personhood credential.
    pub credential: PrivacyZkAmsPersonhoodCredentialV1,
    /// Canonical low-s ES256 issuer signature.
    pub issuer_signature: Zeroizing<[u8; 64]>,
    /// Secret opening of the credential seed public key.
    pub seed_secret: ZkAmsSeedSecretV1,
}
/// One canonical ordered ZK-AMS admission batch.
pub struct ZkAmsBatchAdmissionActionRequestV1 {
    /// Exact authoritative issuer, registry, and policy records.
    pub governance: ZkAmsPrivacyActionGovernanceV1,
    /// Current authoritative account-registry root.
    pub account_registry_root: PrivacyRootV1,
    /// Epoch of the current account-registry root.
    pub account_registry_root_epoch: u64,
    /// One to eight ordered credentials and their private openings.
    pub credentials: Vec<ZkAmsAdmissionCredentialRequestV1>,
}
/// One canonical anonymous ZK-AMS account-provisioning request.
pub struct ZkAmsProvisionAccountActionRequestV1 {
    /// Exact authoritative issuer, registry, and policy records.
    pub governance: ZkAmsPrivacyActionGovernanceV1,
    /// Current authoritative account-registry root.
    pub account_registry_root: PrivacyRootV1,
    /// Epoch of the current account-registry root.
    pub account_registry_root_epoch: u64,
    /// Complete admitted seed-key ring in strict canonical order.
    pub admitted_seed_key_ring: Vec<PrivacyZkAmsSeedPublicKeyV1>,
    /// Account created by successful anonymous provisioning.
    pub account_id: AccountId,
    /// Wallet-local opening whose public member determines the signer index.
    pub seed_secret: ZkAmsSeedSecretV1,
}
/// Closed first-release ZK-AMS action.
pub enum ZkAmsActionRequestV1 {
    /// Ordered credential admission and root transition.
    BatchAdmission(ZkAmsBatchAdmissionActionRequestV1),
    /// Anonymous account provisioning.
    ProvisionAccount(ZkAmsProvisionAccountActionRequestV1),
}
/// One canonical Vega mDL predicate presentation.
pub struct VegaCredentialPresentationActionRequestV1 {
    /// Public governed issuer record, predicate, challenge, and session.
    pub input: VegaPrivacyActionPublicInputV1,
    /// Exact private ISO 18013-5 document material.
    pub witness_material: VegaPrivacyActionWitnessMaterialV1,
    /// Holder device ES256 signing key; `H_dev` is derived inside the builder.
    pub device_signing_key: DeviceSigningKeyV1,
    /// Trusted block time used by the closed presentation-validity policy.
    pub trusted_block_timestamp_ms: u64,
}
/// One fixed-capacity ZK-X509 proof returned by the isolated worker.
///
/// The private certificate, CRL, and accumulator witness never cross this
/// boundary. This wrapper makes the nonempty exact first-release byte ceiling
/// a type invariant before any action can be dispatched.
pub struct ZkX509CredentialProofBytesV1(Vec<u8>);
impl ZkX509CredentialProofBytesV1 {
    /// Accept one nonempty proof no larger than the exact first-release ceiling.
    pub fn try_new(encoded: Vec<u8>) -> Result<Self, PrivacyNativeActionErrorV1> {
        if encoded.is_empty() || encoded.len() > PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1 {
            return Err(PrivacyNativeActionErrorV1::at("zk-x509-proof-cap"));
        }
        Ok(Self(encoded))
    }
    /// Borrow the exact worker response without copying it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consume the bounded wrapper into the exact proof bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
/// One intent-bound ZK-X509 identity presentation returned by the isolated worker.
pub struct ZkX509IdentityPresentationActionRequestV1 {
    /// Exact intent-bound public statement.
    pub statement: IrohaZkX509StarkP256StatementV1,
    /// Sole canonical two-record `X5S1` proof container.
    pub proof: ZkX509CredentialProofBytesV1,
}
/// One canonical Jindo polynomial-evaluation action.
pub struct JindoPolynomialEvaluationActionRequestV1 {
    /// Complete canonical private polynomial batch and evaluation point.
    pub witness: JindoPrivacyActionWitnessV1,
}
/// One canonical Bootle/Lantern credential presentation.
pub struct BootleLanternPresentationActionRequestV1 {
    /// Exact active authoritative issuer-policy archive.
    pub policy: BootleLanternIssuerPolicyV1,
    /// Strictly increasing public disclosure indices.
    pub disclosure_indices: Vec<u8>,
    /// Complete wallet-local credential witness.
    pub witness: BootleLanternPresentationWitnessV1,
}
/// One complete governed Anonymous-PGC payment request.
pub struct AnonymousPgcPaymentActionRequestV1 {
    /// Public asset represented by the encrypted account table.
    pub asset_definition_id: AssetDefinitionId,
    /// Governed PGC pool.
    pub pool_id: PrivacyPoolIdV1,
    /// Current authoritative account-table epoch.
    pub current_epoch: u64,
    /// Supply proven by the admitted pool bootstrap.
    pub total_supply: u32,
    /// Digest of the admitted canonical bootstrap payload.
    pub bootstrap_digest: PrivacyPgcAccountBootstrapDigestV1,
    /// Digest of the admitted canonical bootstrap proof.
    pub bootstrap_proof_digest: PrivacyPgcBootstrapProofDigestV1,
    /// Complete authoritative account table in strict public-key order.
    pub current_accounts: Vec<PrivacyPgcAccountV1>,
    /// Signed transfer values aligned with the complete table.
    pub transfer_values: Vec<i64>,
    /// Secret transfer openings aligned with the complete table.
    pub transfer_randomness: Vec<SecretScalarV1>,
    /// Hidden sender index.
    pub sender_index: usize,
    /// Secret key controlling the hidden sender account.
    pub sender_secret: SecretScalarV1,
}
/// One wallet-owned FCMP++ output and its recipient encryption key.
pub struct FcmpWalletOutputRequestV1 {
    /// Complete spendable wallet note/opening for the newly created tuple.
    pub note: FcmpWalletNoteV1,
    /// Exact X25519 public key of its recipient.
    pub recipient_public_key: [u8; 32],
}
/// One complete FCMP++ payment request.
pub struct FcmpMembershipPaymentActionRequestV1 {
    /// Public asset represented by the output set.
    pub asset_definition_id: AssetDefinitionId,
    /// Governed FCMP++ pool.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact retained typed root.
    pub output_set_root: FcmpTreeRootV1,
    /// Epoch of the retained root.
    pub root_epoch: u64,
    /// One or two complete membership/rerandomization witnesses.
    pub inputs: Vec<FcmpProverInputV1>,
    /// One to four complete wallet-owned outputs.
    pub outputs: Vec<FcmpWalletOutputRequestV1>,
}
/// One complete Orchard V3 bundle request.
pub struct OrchardNoteActionRequestV1 {
    /// Public asset represented by the Orchard pool.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact transparent reserve partition used by directional value bridges.
    pub public_balance_scope: AssetBalanceScope,
    /// Governed Orchard pool.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact retained anchor.
    pub anchor: PrivacyRootV1,
    /// Epoch of the retained anchor.
    pub anchor_epoch: u64,
    /// Last admissible block height.
    pub expiry_height: u64,
    /// Wallet-owned note spends.
    pub spends: Vec<OrchardSpendProverInputV1>,
    /// Wallet-controlled change outputs.
    pub changes: Vec<OrchardChangeProverInputV1>,
    /// One-or-two action padding floor.
    pub minimum_action_count: u8,
}
/// Immutable ordered deployed-contract calls surrounding one direct Orchard submission.
///
/// Only by-reference contract calls are accepted; this is not an arbitrary instruction carrier.
/// Call arguments are already canonical schema-bound records. Their schema, live code binding,
/// permissions and business semantics remain validator checks. The caller must obtain this plan
/// from its independently approved scenario, never from the transaction being inspected.
#[derive(Clone, PartialEq, Eq)]
pub struct OrchardOrderedContractCallsV1 {
    before: Vec<ContractInvocation>,
    after: Vec<ContractInvocation>,
}
impl OrchardOrderedContractCallsV1 {
    /// Freeze nonempty ordered call sequences on both sides of the native submission.
    ///
    /// # Errors
    /// Rejects empty sides, a complete Batch exceeding the existing default transaction item
    /// limit, or a call-plan frame exceeding the existing public native request byte limit.
    pub fn try_new(
        before: Vec<ContractInvocation>,
        after: Vec<ContractInvocation>,
    ) -> Result<Self, PrivacyNativeActionErrorV1> {
        let calls = Self { before, after };
        calls.validate()?;
        Ok(calls)
    }
    fn validate(&self) -> Result<(), PrivacyNativeActionErrorV1> {
        if self.before.is_empty() || self.after.is_empty() {
            return Err(PrivacyNativeActionErrorV1::at("orchard-ordered-empty-side"));
        }
        let limit = iroha_data_model::parameter::TransactionParameters::default()
            .max_instructions()
            .get();
        let before = u64::try_from(self.before.len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-call-count"))?;
        let after = u64::try_from(self.after.len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-call-count"))?;
        if before >= limit
            || after >= limit
            || before
                .checked_add(after)
                .and_then(|count| count.checked_add(1))
                .is_none_or(|count| count > limit)
        {
            return Err(PrivacyNativeActionErrorV1::at("orchard-ordered-call-count"));
        }
        // Count both existing typed vector frames without cloning or allocating a payload.
        let before_bytes = norito::canonical_frame_len(&self.before)
            .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-call-encoding"))?;
        let after_bytes = norito::canonical_frame_len(&self.after)
            .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-call-encoding"))?;
        let bytes = before_bytes
            .checked_add(after_bytes)
            .ok_or_else(|| PrivacyNativeActionErrorV1::at("orchard-ordered-call-bytes"))?;
        if bytes > PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1 {
            return Err(PrivacyNativeActionErrorV1::at("orchard-ordered-call-bytes"));
        }
        Ok(())
    }
    /// Borrow the exact calls before the native submission.
    #[must_use]
    pub fn before(&self) -> &[ContractInvocation] {
        &self.before
    }
    /// Borrow the exact calls after the native submission.
    #[must_use]
    pub fn after(&self) -> &[ContractInvocation] {
        &self.after
    }
    /// Original signed Batch ordinal of the sole direct native submission.
    /// This is distinct from its protocol action index, which remains zero.
    #[must_use]
    pub fn direct_instruction_index(&self) -> usize {
        self.before.len()
    }
}
/// Exact authenticated public result of checking an independently supplied Orchard call plan.
#[derive(Debug)]
pub struct InspectedOrchardOrderedActionV1 {
    action: InspectedPrivacyActionV1,
    direct_instruction_index: usize,
}
impl InspectedOrchardOrderedActionV1 {
    /// Borrow the authenticated action and complete original transaction hash.
    #[must_use]
    pub const fn action(&self) -> &InspectedPrivacyActionV1 {
        &self.action
    }
    /// Original signed Batch ordinal, never a nested or protocol-action ordinal.
    #[must_use]
    pub const fn direct_instruction_index(&self) -> usize {
        self.direct_instruction_index
    }
}
/// One private-IVM created note and its recipient encryption key.
pub struct IvmPrivateNoteOutputRequestV1 {
    /// Complete output-note opening.
    pub witness: IvmPrivateNoteOutputWitnessV1,
    /// Exact X25519 recipient public key.
    pub recipient_public_key: [u8; 32],
}
/// One complete private-IVM note action request.
pub struct IvmPrivateNoteActionRequestV1 {
    /// Public asset manipulated by the program.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact transparent reserve partition used by directional value bridges.
    pub public_balance_scope: AssetBalanceScope,
    /// Governed private-note pool.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact retained program-state root.
    pub state_root: PrivacyRootV1,
    /// Epoch of the retained root and this execution.
    pub root_epoch: u64,
    /// Exact fixed-width private program.
    pub program: PrivateProgramV1,
    /// One or two complete consumed-note witnesses.
    pub inputs: Vec<IvmPrivateNoteInputWitnessV1>,
    /// One or two complete created notes and recipients.
    pub outputs: Vec<IvmPrivateNoteOutputRequestV1>,
}
/// One PQ-MASP created note and its recipient encryption key.
pub struct PqMaspOutputRequestV1 {
    /// Complete output-note opening.
    pub witness: PqMaspOutputWitnessV1,
    /// Exact ML-KEM-768 recipient public key.
    pub recipient_public_key: Vec<u8>,
}
/// One complete PQ-MASP action request.
pub struct PqMaspNoteActionRequestV1 {
    /// Public asset represented by the PQ note pool.
    pub asset_definition_id: AssetDefinitionId,
    /// Governed PQ-MASP pool.
    pub pool_id: PrivacyPoolIdV1,
    /// Exact retained note-tree anchor.
    pub anchor: PrivacyRootV1,
    /// Epoch of the retained anchor and authorization.
    pub anchor_epoch: u64,
    /// One or two complete consumed-note witnesses.
    pub inputs: Vec<PqMaspInputWitnessV1>,
    /// One or two complete created notes and recipients.
    pub outputs: Vec<PqMaspOutputRequestV1>,
    /// Exact ML-DSA-65 authorization secret key.
    pub authorization_secret_key: Zeroizing<Vec<u8>>,
}
/// Closed dispatcher request shared by wallet adapters.
#[expect(
    clippy::large_enum_variant,
    reason = "boxing a variant would break the public Rust request API"
)]
pub enum PrivacyNativeActionRequestV1 {
    /// Governed ZK-ACE authorization transfer.
    ZkAce(ZkAceAuthorizationActionRequestV1),
    /// Anonymous-PGC encrypted-account payment.
    AnonymousPgc(AnonymousPgcPaymentActionRequestV1),
    /// VeRange transparent-setup range relation.
    VeRange(VeRangeActionRequestV1),
    /// ZK-AMS admission or provisioning action.
    ZkAms(ZkAmsActionRequestV1),
    /// Vega mDL credential presentation.
    Vega(VegaCredentialPresentationActionRequestV1),
    /// ZK-X509 identity presentation returned by the profile-owned worker.
    ZkX509(ZkX509IdentityPresentationActionRequestV1),
    /// Jindo polynomial-evaluation relation.
    Jindo(JindoPolynomialEvaluationActionRequestV1),
    /// Bootle/Lantern anonymous-credential presentation.
    BootleLantern(BootleLanternPresentationActionRequestV1),
    /// Orchard V3 note action.
    Orchard(OrchardNoteActionRequestV1),
    /// Monero FCMP++ payment.
    FcmpPlusPlus(FcmpMembershipPaymentActionRequestV1),
    /// Native private-IVM note execution.
    IvmPrivateNote(IvmPrivateNoteActionRequestV1),
    /// Post-quantum MASP action.
    PqMasp(PqMaspNoteActionRequestV1),
}
impl PrivacyNativeActionRequestV1 {
    /// Exact consensus protocol selected by this closed typed variant.
    #[must_use]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        match self {
            Self::ZkAce(_) => PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
            Self::AnonymousPgc(_) => PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
            Self::VeRange(_) => PrivacyProtocolIdV1::VeRangeTransparentRangeV1,
            Self::ZkAms(_) => PrivacyProtocolIdV1::IrohaZkAmsV1,
            Self::Vega(_) => PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
            Self::ZkX509(_) => PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
            Self::Jindo(_) => PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
            Self::BootleLantern(_) => PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1,
            Self::Orchard(_) => PrivacyProtocolIdV1::OrchardHalo2ActionsV1,
            Self::FcmpPlusPlus(_) => PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1,
            Self::IvmPrivateNote(_) => PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
            Self::PqMasp(_) => PrivacyProtocolIdV1::PqMaspStarkV1,
        }
    }
}
/// Closed, non-secret failure returned by native action construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyNativeActionErrorV1 {
    stage: &'static str,
}
impl PrivacyNativeActionErrorV1 {
    const fn at(stage: &'static str) -> Self {
        Self { stage }
    }
    /// Stable, non-secret failure stage.
    #[must_use]
    pub const fn stage(self) -> &'static str {
        self.stage
    }
}
impl fmt::Display for PrivacyNativeActionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native privacy action failed at {}", self.stage)
    }
}
impl std::error::Error for PrivacyNativeActionErrorV1 {}
/// Complete signed result returned by every native builder.
pub struct SignedPrivacyActionV1 {
    signed_transaction: SignedTransaction,
    protocol_id: PrivacyProtocolIdV1,
    transaction_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    adaptive_signed_transaction_bytes: u32,
    versioned_signed_transaction_bytes: u32,
}
impl fmt::Debug for SignedPrivacyActionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPrivacyActionV1")
            .field("protocol_id", &self.protocol_id)
            .field("transaction_hash", &self.transaction_hash)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .field(
                "versioned_signed_transaction_bytes",
                &self.versioned_signed_transaction_bytes,
            )
            .finish_non_exhaustive()
    }
}
impl SignedPrivacyActionV1 {
    /// Borrow the exact signed transaction.
    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed_transaction
    }
    /// Consume the result into the exact signed transaction.
    #[must_use]
    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.signed_transaction
    }
    /// Encode the sole canonical versioned signed-transaction response.
    pub fn encode_versioned(&self) -> Result<Vec<u8>, PrivacyNativeActionErrorV1> {
        let bytes = self.signed_transaction.encode_versioned();
        if bytes.len() > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1 {
            return Err(PrivacyNativeActionErrorV1::at(
                "signed-transaction-response-cap",
            ));
        }
        Ok(bytes)
    }
    /// Exact first-release protocol.
    #[must_use]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        self.protocol_id
    }
    /// Canonical transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact encoded proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical proof-envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    /// Versioned signed-transaction response byte count.
    #[must_use]
    pub const fn versioned_signed_transaction_bytes(&self) -> u32 {
        self.versioned_signed_transaction_bytes
    }
}
/// Authenticated public inspection of one signed native action.
pub struct InspectedPrivacyActionV1 {
    protocol_id: PrivacyProtocolIdV1,
    transaction_hash: [u8; 32],
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    adaptive_signed_transaction_bytes: u32,
    statement: PrivacyStatementV1,
}
impl fmt::Debug for InspectedPrivacyActionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectedPrivacyActionV1")
            .field("protocol_id", &self.protocol_id)
            .field("transaction_hash", &self.transaction_hash)
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .finish_non_exhaustive()
    }
}
impl InspectedPrivacyActionV1 {
    /// Exact protocol authenticated by signature, intent, statement, and proof shape.
    #[must_use]
    pub const fn protocol_id(&self) -> PrivacyProtocolIdV1 {
        self.protocol_id
    }
    /// Borrow the authenticated typed public statement.
    #[must_use]
    pub const fn statement(&self) -> &PrivacyStatementV1 {
        &self.statement
    }
    /// Canonical transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical transaction-intent digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical typed-statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the canonical proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
}
fn validate_context(
    context: &PrivacyActionTransactionContextV1,
) -> Result<(), PrivacyNativeActionErrorV1> {
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(PrivacyNativeActionErrorV1::at("transaction-creation-time"));
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(PrivacyNativeActionErrorV1::at("transaction-ttl"));
    }
    transaction_payload(context, None).map(|_| ())
}
fn validate_signing_authority(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), PrivacyNativeActionErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("multisig-authority"))?;
    let derived = PublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(PrivacyNativeActionErrorV1::at("authority-key-mismatch"));
    }
    Ok(())
}
fn transaction_payload(
    context: &PrivacyActionTransactionContextV1,
    envelope: Option<PrivacyProofEnvelopeV1>,
) -> Result<TransactionPayload, PrivacyNativeActionErrorV1> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_metadata(context.metadata.clone());
    if let Some(envelope) = envelope {
        builder = builder.with_instructions([SubmitPrivacyProofV1::new(envelope)]);
    }
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map_err(|_| PrivacyNativeActionErrorV1::at("transaction-context"))
}
fn statement_context(
    context: &PrivacyActionTransactionContextV1,
    profile: CompiledPrivacyProfileV1,
) -> PrivacyStatementContextV1 {
    PrivacyStatementContextV1 {
        network_id: context.network_id,
        action_index: 0,
        transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    }
}
/// Bind the one canonical envelope and require the compiled profile's identities.
///
/// `PrivacyProofEnvelopeV1::bind_v1` derives every envelope identity and the
/// statement digest from the typed statement. This adapter additionally
/// refuses a statement whose context was not built from `profile`.
fn bind_envelope(
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
    stage: &'static str,
) -> Result<PrivacyProofEnvelopeV1, PrivacyNativeActionErrorV1> {
    let envelope = PrivacyProofEnvelopeV1::bind_v1(statement, proof)
        .map_err(|_| PrivacyNativeActionErrorV1::at(stage))?;
    if !profile.matches_envelope_v1(&envelope) {
        return Err(PrivacyNativeActionErrorV1::at(stage));
    }
    Ok(envelope)
}
/// Bind the canonical pre-proof envelope used only for transaction-intent
/// projection.
///
/// The intent algorithm erases proof bytes, the statement's intent digest and
/// the envelope's statement digest before hashing, so this proof-free envelope
/// is never emitted as a verifier-visible envelope.
fn intent_projection_envelope(
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
) -> Result<PrivacyProofEnvelopeV1, PrivacyNativeActionErrorV1> {
    bind_envelope(profile, statement, proof, "transaction-intent")
}
fn derive_intent(
    context: &PrivacyActionTransactionContextV1,
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
) -> Result<PrivacyTransactionIntentDigestV1, PrivacyNativeActionErrorV1> {
    transaction_payload(
        context,
        Some(intent_projection_envelope(profile, statement, proof)?),
    )?
    .privacy_transaction_intent_digest_v1()
    .map_err(|_| PrivacyNativeActionErrorV1::at("transaction-intent"))
}
fn finalize(
    context: &PrivacyActionTransactionContextV1,
    profile: CompiledPrivacyProfileV1,
    statement: PrivacyStatementV1,
    proof: PrivacyProofV1,
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_signing_authority(&context.authority, private_key)?;
    let statement_digest = statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("statement-digest"))?;
    let statement_bytes = u32::try_from(
        norito::to_bytes(&statement)
            .map_err(|_| PrivacyNativeActionErrorV1::at("statement-encoding"))?
            .len(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("statement-length"))?;
    let proof_bytes = u32::try_from(proof.bytes().as_bytes().len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("proof-length"))?;
    let envelope = bind_envelope(profile, statement, proof, "proof-envelope-validation")?;
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| PrivacyNativeActionErrorV1::at("proof-envelope-validation"))?;
    let envelope_encoding = norito::to_bytes(&envelope)
        .map_err(|_| PrivacyNativeActionErrorV1::at("proof-envelope-encoding"))?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("proof-envelope-length"))?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let payload = transaction_payload(context, Some(envelope))?;
    let intent = payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("final-intent-binding"))?;
    let signed_transaction = TransactionBuilder::from_payload(payload)
        .map_err(|_| PrivacyNativeActionErrorV1::at("final-payload"))?
        .try_sign(private_key)
        .map_err(|_| PrivacyNativeActionErrorV1::at("transaction-signing"))?;
    let signed_intent = signed_transaction
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("signed-intent"))?;
    if signed_intent != intent {
        return Err(PrivacyNativeActionErrorV1::at("signed-intent-drift"));
    }
    let adaptive = norito::codec::encode_adaptive(&signed_transaction);
    let adaptive_signed_transaction_bytes = u32::try_from(adaptive.len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("adaptive-transaction-length"))?;
    let versioned = signed_transaction.encode_versioned();
    if versioned.len() > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1 {
        return Err(PrivacyNativeActionErrorV1::at(
            "signed-transaction-response-cap",
        ));
    }
    let versioned_signed_transaction_bytes = u32::try_from(versioned.len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("versioned-transaction-length"))?;
    Ok(SignedPrivacyActionV1 {
        transaction_hash: *signed_transaction.hash().as_ref(),
        signed_transaction,
        protocol_id: profile.protocol_id,
        transaction_intent_digest: *intent.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
        adaptive_signed_transaction_bytes,
        versioned_signed_transaction_bytes,
    })
}
fn compiled_profile(
    protocol_id: PrivacyProtocolIdV1,
) -> Result<CompiledPrivacyProfileV1, PrivacyNativeActionErrorV1> {
    compiled_privacy_profile_v1(protocol_id)
        .map_err(|_| PrivacyNativeActionErrorV1::at("compiled-profile"))
}
fn require_genesis(canonical_genesis_hash: [u8; 32]) -> Result<(), PrivacyNativeActionErrorV1> {
    if canonical_genesis_hash == [0; 32] {
        return Err(PrivacyNativeActionErrorV1::at("canonical-genesis-hash"));
    }
    Ok(())
}
pub(crate) fn network_id_from_genesis_hash_bytes(canonical_genesis_hash: [u8; 32]) -> NetworkId {
    NetworkId::from_genesis_hash(
        HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(Hash::prehashed(
            canonical_genesis_hash,
        )),
    )
}
fn validate_action_preflight(
    context: &PrivacyActionTransactionContextV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<(), PrivacyNativeActionErrorV1> {
    require_genesis(canonical_genesis_hash)?;
    validate_context(context)?;
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(PrivacyNativeActionErrorV1::at("transaction-network-id"));
    }
    validate_signing_authority(&context.authority, private_key)
}
fn wrap_canonical_signed_transaction_v1(
    signed_transaction: SignedTransaction,
    expected_protocol: PrivacyProtocolIdV1,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(&signed_transaction, expected_protocol)?;
    let versioned = signed_transaction.encode_versioned();
    if versioned.len() > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1 {
        return Err(PrivacyNativeActionErrorV1::at(
            "signed-transaction-response-cap",
        ));
    }
    Ok(SignedPrivacyActionV1 {
        protocol_id: inspected.protocol_id,
        transaction_hash: inspected.transaction_hash,
        transaction_intent_digest: inspected.transaction_intent_digest,
        statement_digest: inspected.statement_digest,
        proof_envelope_hash: inspected.proof_envelope_hash,
        statement_bytes: inspected.statement_bytes,
        proof_bytes: inspected.proof_bytes,
        encoded_proof_envelope_bytes: inspected.encoded_proof_envelope_bytes,
        adaptive_signed_transaction_bytes: inspected.adaptive_signed_transaction_bytes,
        versioned_signed_transaction_bytes: u32::try_from(versioned.len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("versioned-transaction-length"))?,
        signed_transaction,
    })
}
/// Build and sign one canonical governed ZK-ACE authorization transfer.
pub fn build_signed_zk_ace_authorization_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkAceAuthorizationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let native_context = ZkAcePrivacyActionTransactionContextV1 {
        network_id: context.network_id,
        authority: context.authority,
        creation_time: context.creation_time,
        time_to_live: context.time_to_live,
        nonce: context.nonce,
        fee_payment: context.fee_payment,
        metadata: context.metadata,
    };
    let signed = build_signed_zk_ace_privacy_transfer_v1(
        native_context,
        request.transfer,
        request.witness,
        canonical_genesis_hash,
        private_key,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ace-building"))?;
    wrap_canonical_signed_transaction_v1(
        signed.into_signed_transaction(),
        PrivacyProtocolIdV1::ZkAcePqAuthorizationV1,
    )
}
/// Build and sign one canonical Jindo polynomial-evaluation action.
pub fn build_signed_jindo_polynomial_evaluation_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: JindoPolynomialEvaluationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let native_context = JindoPrivacyActionTransactionContextV1 {
        network_id: context.network_id,
        authority: context.authority,
        creation_time: context.creation_time,
        time_to_live: context.time_to_live,
        nonce: context.nonce,
        fee_payment: context.fee_payment,
        metadata: context.metadata,
    };
    let signed = build_signed_jindo_privacy_action_v1(
        native_context,
        request.witness,
        canonical_genesis_hash,
        private_key,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("jindo-building"))?;
    wrap_canonical_signed_transaction_v1(
        signed.into_signed_transaction(),
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
    )
}
/// Build and sign one canonical Vega mDL predicate presentation.
pub fn build_signed_vega_credential_presentation_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: VegaCredentialPresentationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let native_context = VegaPrivacyActionTransactionContextV1 {
        network_id: context.network_id,
        authority: context.authority,
        creation_time: context.creation_time,
        time_to_live: context.time_to_live,
        nonce: context.nonce,
        fee_payment: context.fee_payment,
        metadata: context.metadata,
    };
    let signed = build_signed_vega_privacy_action_v1(
        native_context,
        request.input,
        request.witness_material,
        &request.device_signing_key,
        canonical_genesis_hash,
        request.trusted_block_timestamp_ms,
        private_key,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("vega-building"))?;
    wrap_canonical_signed_transaction_v1(
        signed.into_signed_transaction(),
        PrivacyProtocolIdV1::VegaExistingCredentialZkV1,
    )
}
fn validate_zk_x509_action_statement_v1(
    context: &PrivacyActionTransactionContextV1,
    profile: CompiledPrivacyProfileV1,
    statement: &IrohaZkX509StarkP256StatementV1,
    require_bound_intent: bool,
) -> Result<(), PrivacyNativeActionErrorV1> {
    let mut expected_context = statement_context(context, profile);
    expected_context.transaction_intent_digest = statement.context.transaction_intent_digest;
    if statement.context != expected_context {
        return Err(PrivacyNativeActionErrorV1::at("zk-x509-statement-context"));
    }
    if statement.wallet_account != context.authority {
        return Err(PrivacyNativeActionErrorV1::at("zk-x509-wallet-authority"));
    }
    let intent_is_zero = statement
        .context
        .transaction_intent_digest
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0);
    if intent_is_zero == require_bound_intent {
        return Err(PrivacyNativeActionErrorV1::at("zk-x509-intent-state"));
    }
    // Structural statement validation requires a nonzero intent. During the
    // prepare pass, substitute only that erased derived field; every public
    // governance, window, usage, disclosure, and account field remains exact.
    let mut structural = statement.clone();
    if intent_is_zero {
        structural.context.transaction_intent_digest =
            PrivacyTransactionIntentDigestV1::new([1; 32]);
    }
    PrivacyStatementV1::IrohaZkX509StarkP256V1(structural)
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-x509-statement"))
}
/// Derive the sole transaction intent that a profile-owned ZK-X509 worker must bind.
///
/// The supplied draft statement must carry the exact transaction/profile
/// context with an all-zero intent. Proof bytes and the intent itself are
/// erased by the canonical intent projection, so this pass performs no prover
/// work and has fixed memory use. The same production-qualified compiled
/// profile used for signing is required before an intent can be prepared.
pub fn prepare_zk_x509_identity_presentation_action_intent_v1(
    context: &PrivacyActionTransactionContextV1,
    canonical_genesis_hash: [u8; 32],
    statement: &IrohaZkX509StarkP256StatementV1,
) -> Result<PrivacyTransactionIntentDigestV1, PrivacyNativeActionErrorV1> {
    require_genesis(canonical_genesis_hash)?;
    validate_context(context)?;
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(PrivacyNativeActionErrorV1::at("transaction-network-id"));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1)?;
    validate_zk_x509_action_statement_v1(context, profile, statement, false)?;
    derive_intent(
        context,
        profile,
        PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone()),
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(Vec::new())),
    )
}
/// Validate and sign one profile-owned ZK-X509 identity presentation.
///
/// Like unsigned preparation, this path accepts only the production profile
/// returned by [`compiled_privacy_profile_v1`]. It fails at `compiled-profile`
/// while release captures or verifier readiness remain unavailable.
pub fn build_signed_zk_x509_identity_presentation_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkX509IdentityPresentationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaZkX509StarkP256V1)?;
    build_signed_zk_x509_identity_presentation_action_after_preflight_v1(
        context,
        request,
        canonical_genesis_hash,
        private_key,
        profile,
    )
}
fn build_signed_zk_x509_identity_presentation_action_after_preflight_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkX509IdentityPresentationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
    profile: CompiledPrivacyProfileV1,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_zk_x509_action_statement_v1(&context, profile, &request.statement, true)?;
    let expected_intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::IrohaZkX509StarkP256V1(request.statement.clone()),
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    if request.statement.context.transaction_intent_digest != expected_intent {
        return Err(PrivacyNativeActionErrorV1::at("zk-x509-intent-binding"));
    }
    validate_zk_x509_credential_proof_container_v1(
        &request.statement,
        canonical_genesis_hash,
        request.proof.as_bytes(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("zk-x509-proof-container"))?;
    finalize(
        &context,
        profile,
        PrivacyStatementV1::IrohaZkX509StarkP256V1(request.statement),
        PrivacyProofV1::IrohaZkX509StarkP256V1(PrivacyProofBytesV1::new(
            request.proof.into_bytes(),
        )),
        private_key,
    )
}
/// Build and sign one canonical VeRange transparent-setup range action.
pub fn build_signed_verange_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: VeRangeActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let values = Zeroizing::new(request.values);
    if values.is_empty() || values.len() > 8 || values.len() != request.blindings.len() {
        return Err(PrivacyNativeActionErrorV1::at("verange-witness-shape"));
    }
    if request.bit_length == VeRangeBitLengthV1::Bits32
        && values.iter().any(|value| *value > u64::from(u32::MAX))
    {
        return Err(PrivacyNativeActionErrorV1::at("verange-value-range"));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)?;
    let parameters = VeRangeParametersV1::for_profile(request.bit_length)
        .map_err(|_| PrivacyNativeActionErrorV1::at("verange-parameters"))?;
    if parameters.parameter_digest() != *profile.parameter_digest.as_bytes() {
        return Err(PrivacyNativeActionErrorV1::at("verange-parameter-digest"));
    }
    let commitments = values
        .iter()
        .copied()
        .zip(&request.blindings)
        .map(|(value, blinding)| commit(request.bit_length, value, blinding))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyNativeActionErrorV1::at("verange-commitment"))?;
    let aggregation_count = u32::try_from(commitments.len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("verange-aggregation-count"))?;
    let mut statement = VeRangeTransparentRangeStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        policy_id: request.policy_id,
        value_commitments: commitments
            .iter()
            .map(|commitment| PrivacyP256PointV1::new(*commitment.as_bytes()))
            .collect(),
        bit_length: match request.bit_length {
            VeRangeBitLengthV1::Bits32 => PrivacyVeRangeBitLengthV1::Bits32,
            VeRangeBitLengthV1::Bits64 => PrivacyVeRangeBitLengthV1::Bits64,
        },
        aggregation_count,
    };
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::VeRangeTransparentRangeV1(statement.clone()),
        PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::VeRangeTransparentRangeV1(statement);
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("verange-statement-digest"))?;
    let transcript = TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
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
        VeRangeType1BatchStatementV1::new(request.bit_length, commitments, transcript)
            .map_err(|_| PrivacyNativeActionErrorV1::at("verange-native-statement"))?;
    let proof = prove_batch(&native_statement, &values, &request.blindings, &mut OsRng)
        .map_err(|_| PrivacyNativeActionErrorV1::at("verange-proving"))?
        .encode();
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::VeRangeTransparentRangeV1(PrivacyProofBytesV1::new(proof)),
        private_key,
    )
}
/// Build and sign one canonical Bootle/Lantern credential presentation.
pub fn build_signed_bootle_lantern_presentation_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: BootleLanternPresentationActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    request
        .policy
        .validate()
        .map_err(|_| PrivacyNativeActionErrorV1::at("bootle-policy"))?;
    if request
        .disclosure_indices
        .iter()
        .any(|index| usize::from(*index) >= request.witness.attributes.len())
        || request
            .disclosure_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(PrivacyNativeActionErrorV1::at("bootle-disclosure-indices"));
    }
    let disclosures = request
        .disclosure_indices
        .iter()
        .copied()
        .map(|index| BootleLanternDisclosedAttributeV1 {
            index,
            value: BootleLanternAttributeValueV1::new(
                request.witness.attributes[usize::from(index)],
            ),
        })
        .collect::<Vec<_>>();
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1)?;
    let mut statement = IrohaBootleLanternAnoncredStatementV1 {
        context: statement_context(&context, profile),
        issuer_id: request.policy.issuer_id,
        policy_id: request.policy.policy_id,
        issuer_policy_epoch: request.policy.epoch,
        issuer_policy_record_digest: request.policy.record_digest,
        issuer_parameter_id: request.policy.issuer_parameter_id,
        issuer_parameter_digest: request.policy.issuer_parameter_digest,
        disclosures,
    };
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement.clone()),
        PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    let proof = prove_bound_presentation_v1(
        &statement,
        &request.policy,
        canonical_genesis_hash,
        &request.witness,
        &mut OsRng,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("bootle-proving"))?
    .encode();
    finalize(
        &context,
        profile,
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(statement),
        PrivacyProofV1::IrohaBootleLanternAnoncredV1(PrivacyProofBytesV1::new(proof)),
        private_key,
    )
}
fn zk_ams_transaction_context(
    context: &PrivacyActionTransactionContextV1,
) -> ZkAmsPrivacyActionTransactionContextV1 {
    ZkAmsPrivacyActionTransactionContextV1 {
        network_id: context.network_id,
        authority: context.authority.clone(),
        creation_time: context.creation_time,
        time_to_live: context.time_to_live,
        nonce: context.nonce,
        fee_payment: context.fee_payment.clone(),
        metadata: context.metadata.clone(),
    }
}
fn zk_ams_transcript_binding<'a>(
    context: &'a PrivacyActionTransactionContextV1,
    profile: CompiledPrivacyProfileV1,
    canonical_genesis_hash: [u8; 32],
    statement_digest: PrivacyStatementDigestV1,
) -> TranscriptBindingV1<'a> {
    TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
        action_index: 0,
        statement_digest: *statement_digest.as_bytes(),
        parameter_id: *profile.parameter_id.as_bytes(),
        parameter_digest: *profile.parameter_digest.as_bytes(),
        verifier_digest: *profile.verifier_digest.as_bytes(),
        statement_schema_digest: *profile.statement_schema_digest.as_bytes(),
        engine_manifest_digest: *profile.engine_manifest_digest.as_bytes(),
        generator_digest: zk_ams_generator_digest_v1(),
    }
}
/// Build and sign one canonical ordered ZK-AMS credential-admission batch.
pub fn build_signed_zk_ams_batch_admission_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkAmsBatchAdmissionActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if request.account_registry_root_epoch == 0
        || request.credentials.is_empty()
        || request.credentials.len() > ZK_AMS_MAX_ADMISSION_BATCH_SIZE_V1
    {
        return Err(PrivacyNativeActionErrorV1::at("zk-ams-admission-shape"));
    }
    let next_epoch = request
        .account_registry_root_epoch
        .checked_add(1)
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("zk-ams-successor-epoch"))?;
    let anchors = request
        .credentials
        .iter()
        .map(|credential| PrivacyZkAmsAdmissionAnchorV1 {
            phc_hash: credential.credential.digest(),
            seed_public_key: credential.credential.seed_public_key,
        })
        .collect::<Vec<_>>();
    let batch_size = u32::try_from(anchors.len())
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-batch-size"))?;
    let mut next_root = request.account_registry_root;
    for (index, anchor) in anchors.iter().copied().enumerate() {
        next_root = zk_ams_registry_transition_root_v1(
            request.governance.registry_id,
            next_root,
            request.account_registry_root_epoch,
            next_epoch,
            batch_size,
            u32::try_from(index)
                .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-anchor-index"))?,
            anchor,
        );
    }
    let action = PrivacyZkAmsBatchAdmissionV1 {
        account_registry_root: request.account_registry_root,
        account_registry_root_epoch: request.account_registry_root_epoch,
        next_account_registry_root: next_root,
        next_account_registry_root_epoch: next_epoch,
        anchors,
    };
    let native_context = zk_ams_transaction_context(&context);
    let statement = prepare_zk_ams_batch_admission_transaction_intent_v1(
        &native_context,
        request.governance,
        action,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-admission-intent"))?;
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaZkAmsV1)?;
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-admission-statement-digest"))?;
    let binding =
        zk_ams_transcript_binding(&context, profile, canonical_genesis_hash, statement_digest);
    let witnesses = request
        .credentials
        .iter()
        .map(|credential| {
            ZkAmsBatchCredentialWitnessV1::new(
                &credential.credential,
                &credential.issuer_signature,
                &credential.seed_secret,
            )
        })
        .collect::<Vec<_>>();
    let config = ZkAmsMaskedProverConfigV1::new(1)
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-admission-config"))?;
    let proof =
        prove_zk_ams_batch_admission_v1(&statement, &binding, &witnesses, config, &mut OsRng)
            .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-admission-proving"))?;
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::MaskedRelaxedSpartanBatchAdmission(
            PrivacyProofBytesV1::new(proof),
        )),
        private_key,
    )
}
/// Build and sign one canonical anonymous ZK-AMS account provisioning.
pub fn build_signed_zk_ams_provision_account_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkAmsProvisionAccountActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if request.account_registry_root_epoch == 0
        || !ZK_AMS_RING_SIZES_V1.contains(&request.admitted_seed_key_ring.len())
        || request
            .admitted_seed_key_ring
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(PrivacyNativeActionErrorV1::at("zk-ams-provision-shape"));
    }
    let signer_public_key =
        PrivacyZkAmsSeedPublicKeyV1::new(zk_ams_seed_public_key_v1(&request.seed_secret));
    let signer_index = request
        .admitted_seed_key_ring
        .binary_search(&signer_public_key)
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-provision-signer"))?;
    let key_image = PrivacyZkAmsKeyImageV1::new(
        zk_ams_key_image_v1(&request.seed_secret)
            .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-provision-key-image"))?,
    );
    let action = PrivacyZkAmsProvisionAccountV1 {
        account_registry_root: request.account_registry_root,
        account_registry_root_epoch: request.account_registry_root_epoch,
        admitted_seed_key_ring: request.admitted_seed_key_ring,
        account_id: request.account_id,
        key_image,
    };
    let native_context = zk_ams_transaction_context(&context);
    let statement = prepare_zk_ams_provision_account_transaction_intent_v1(
        &native_context,
        request.governance,
        action,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-provision-intent"))?;
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaZkAmsV1)?;
    let typed_statement = PrivacyStatementV1::IrohaZkAmsV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-provision-statement-digest"))?;
    let binding =
        zk_ams_transcript_binding(&context, profile, canonical_genesis_hash, statement_digest);
    let proof = sign_zk_ams_provision_statement_v1(
        &statement,
        &binding,
        signer_index,
        &request.seed_secret,
        &mut OsRng,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("zk-ams-provision-proving"))?;
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::IrohaZkAmsV1(IrohaZkAmsProofV1::Ristretto255LsagProvisionAccount(
            PrivacyProofBytesV1::new(proof),
        )),
        private_key,
    )
}
/// Build and sign one of the two canonical ZK-AMS action kinds.
pub fn build_signed_zk_ams_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: ZkAmsActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    match request {
        ZkAmsActionRequestV1::BatchAdmission(request) => {
            build_signed_zk_ams_batch_admission_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        ZkAmsActionRequestV1::ProvisionAccount(request) => {
            build_signed_zk_ams_provision_account_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
    }
}
fn pgc_ciphertext(ciphertext: TwistedElGamalCiphertextV1) -> PrivacyP256CiphertextV1 {
    PrivacyP256CiphertextV1 {
        left: PrivacyP256PointV1::new(*ciphertext.left().as_bytes()),
        right: PrivacyP256PointV1::new(*ciphertext.right().as_bytes()),
    }
}
fn pgc_native_account_table(
    accounts: &[PrivacyPgcAccountV1],
) -> Result<
    (
        Vec<TwistedElGamalPublicKeyV1>,
        Vec<TwistedElGamalCiphertextV1>,
    ),
    PrivacyNativeActionErrorV1,
> {
    let public_keys = accounts
        .iter()
        .map(|account| {
            TwistedElGamalPublicKeyV1::from_sec1_bytes(account.public_key.as_bytes())
                .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-account-public-key"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let balances = accounts
        .iter()
        .map(|account| {
            TwistedElGamalCiphertextV1::from_sec1_bytes(
                account.encrypted_balance.left.as_bytes(),
                account.encrypted_balance.right.as_bytes(),
            )
            .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-account-ciphertext"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((public_keys, balances))
}
/// Build and sign one canonical Anonymous-PGC payment.
pub fn build_signed_anonymous_pgc_payment_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: AnonymousPgcPaymentActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    let transfer_values = Zeroizing::new(request.transfer_values);
    let profile = compiled_profile(PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)?;
    let namespace = PrivacyNamespaceV1::new(
        PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1,
        PrivacyNamespaceScopeV1::Pool(PrivacyPoolNamespaceV1 {
            pool_id: request.pool_id,
        }),
    );
    let current_root = derive_privacy_pgc_account_state_root_v1(
        namespace,
        request.current_epoch,
        request.total_supply,
        &request.current_accounts,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-current-account-root"))?;
    if transfer_values.len() != request.current_accounts.len()
        || request.transfer_randomness.len() != request.current_accounts.len()
        || request.sender_index >= request.current_accounts.len()
    {
        return Err(PrivacyNativeActionErrorV1::at("pgc-witness-shape"));
    }
    let recipient_count = transfer_values.iter().filter(|value| **value > 0).count();
    let recipient_count_u32 = u32::try_from(recipient_count)
        .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-recipient-count"))?;
    let (public_keys, current_balances) = pgc_native_account_table(&request.current_accounts)?;
    let transfer_ciphertexts = public_keys
        .iter()
        .copied()
        .zip(transfer_values.iter())
        .zip(&request.transfer_randomness)
        .map(|((key, value), randomness)| {
            encrypt_signed_with_randomness(key, *value, randomness)
                .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-transfer-encryption"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_balances = current_balances
        .iter()
        .copied()
        .zip(transfer_ciphertexts.iter().copied())
        .map(|(current, transfer)| {
            add_ciphertexts(current, transfer)
                .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-successor-ciphertext"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_accounts = request
        .current_accounts
        .iter()
        .map(|account| account.public_key)
        .zip(next_balances.iter().copied())
        .map(|(public_key, encrypted_balance)| PrivacyPgcAccountV1 {
            public_key,
            encrypted_balance: pgc_ciphertext(encrypted_balance),
        })
        .collect::<Vec<_>>();
    let next_epoch = request
        .current_epoch
        .checked_add(1)
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("pgc-successor-epoch"))?;
    let next_root = derive_privacy_pgc_account_state_root_v1(
        namespace,
        next_epoch,
        request.total_supply,
        &next_accounts,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-successor-account-root"))?;
    let mut statement = AnonymousPgcKOutOfNStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        pool_id: request.pool_id,
        account_state_root: current_root,
        account_state_root_epoch: request.current_epoch,
        next_account_state_root: next_root,
        next_account_state_root_epoch: next_epoch,
        anonymity_set_public_keys: request
            .current_accounts
            .iter()
            .map(|account| account.public_key)
            .collect(),
        transfer_ciphertexts: transfer_ciphertexts
            .iter()
            .copied()
            .map(pgc_ciphertext)
            .collect(),
        recipient_count: recipient_count_u32,
    };
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement.clone()),
        PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::AnonymousPgcKOutOfNV1(statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-statement-digest"))?;
    let parameters = AnonymousPgcParametersV1::get()
        .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-parameters"))?;
    let transcript = TranscriptBindingV1 {
        network_id: context.network_id.as_bytes(),
        genesis_hash: canonical_genesis_hash,
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
        request.total_supply,
        *request.bootstrap_digest.as_bytes(),
        *request.bootstrap_proof_digest.as_bytes(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-bootstrap-invariant"))?;
    let native_statement = AnonymousPgcPaymentStatementV1::new(
        &public_keys,
        &transfer_ciphertexts,
        &current_balances,
        recipient_count,
        invariant,
        transcript,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-native-statement"))?;
    let native_witness = AnonymousPgcPaymentWitnessV1 {
        transfer_values: &transfer_values,
        transfer_randomness: &request.transfer_randomness,
        sender_index: request.sender_index,
        sender_secret: &request.sender_secret,
    };
    let proof = prove_payment(&native_statement, &native_witness, &mut OsRng)
        .map_err(|_| PrivacyNativeActionErrorV1::at("pgc-proving"))?
        .encode();
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::AnonymousPgcKOutOfNV1(PrivacyProofBytesV1::new(proof)),
        private_key,
    )
}
fn orchard_value_balance(value: i64) -> PrivacyValueBalanceV1 {
    match value.cmp(&0) {
        core::cmp::Ordering::Equal => PrivacyValueBalanceV1::balanced(),
        core::cmp::Ordering::Less => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::IntoPool,
            amount: u128::from(value.unsigned_abs()),
        },
        core::cmp::Ordering::Greater => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::OutOfPool,
            amount: u128::from(value.unsigned_abs()),
        },
    }
}
fn orchard_action(action: &OrchardActionPublicV1) -> PrivacyOrchardActionV1 {
    PrivacyOrchardActionV1 {
        nullifier: action.nullifier,
        randomized_key: action.randomized_key,
        note_commitment: action.note_commitment,
        ephemeral_key: action.ephemeral_key,
        encrypted_note: action.encrypted_note.to_vec(),
        outgoing_ciphertext: action.outgoing_ciphertext.to_vec(),
        value_commitment: action.value_commitment,
    }
}
/// Build and sign one canonical Orchard V3 note action.
pub fn build_signed_orchard_note_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: OrchardNoteActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    build_signed_orchard_action_v1(context, request, None, canonical_genesis_hash, private_key)
}
/// Build one native Orchard action inside a fixed signed ordered contract-call Batch.
///
/// The entire context and both call sequences enter the transaction-intent projection before
/// native authorization. The returned wire is the original complete signed Batch, never a
/// standalone proof wrapped by an adapter afterward. Witnesses remain native Rust values.
///
/// # Errors
/// Rejects invalid context, oversized calls, native proving/authorization failures, or any
/// final context, call-order, source-ordinal or intent mismatch.
pub fn build_signed_orchard_note_action_with_contract_calls_v1(
    context: PrivacyActionTransactionContextV1,
    request: OrchardNoteActionRequestV1,
    calls: OrchardOrderedContractCallsV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    build_signed_orchard_action_v1(
        context,
        request,
        Some(calls),
        canonical_genesis_hash,
        private_key,
    )
}
fn orchard_ordered_payload(
    context: &PrivacyActionTransactionContextV1,
    calls: &OrchardOrderedContractCallsV1,
    envelope: Option<PrivacyProofEnvelopeV1>,
) -> Result<TransactionPayload, PrivacyNativeActionErrorV1> {
    let mut items = calls
        .before
        .iter()
        .cloned()
        .map(ExecutableBatchItem::ContractCall)
        .collect::<Vec<_>>();
    if let Some(envelope) = envelope {
        items.push(ExecutableBatchItem::Instruction(
            SubmitPrivacyProofV1::new(envelope).into(),
        ));
    }
    items.extend(
        calls
            .after
            .iter()
            .cloned()
            .map(ExecutableBatchItem::ContractCall),
    );
    // Use the canonical builder so ordered attachment descriptors are rebound as well.
    TransactionBuilder::from_payload(transaction_payload(context, None)?)
        .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-context"))?
        .with_executable(Executable::Batch(items.into()))
        .into_payload()
        .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-payload"))
}
/// Validate the complete public ordered plan before the wallet consumes private custody.
pub(crate) fn validate_orchard_ordered_context(
    context: &PrivacyActionTransactionContextV1,
    calls: &OrchardOrderedContractCallsV1,
) -> Result<(), PrivacyNativeActionErrorV1> {
    validate_context(context)?;
    // The signed model stores milliseconds; never silently round an independently fixed plan.
    if context.creation_time.subsec_nanos() % 1_000_000 != 0
        || context
            .time_to_live
            .is_some_and(|ttl| ttl.subsec_nanos() % 1_000_000 != 0)
    {
        return Err(PrivacyNativeActionErrorV1::at(
            "orchard-ordered-context-precision",
        ));
    }
    calls.validate()?;
    let bytes = norito::canonical_frame_len(&orchard_ordered_payload(context, calls, None)?)
        .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-ordered-context-encoding"))?;
    if bytes > PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1 {
        return Err(PrivacyNativeActionErrorV1::at(
            "orchard-ordered-request-bytes",
        ));
    }
    Ok(())
}
fn build_signed_orchard_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: OrchardNoteActionRequestV1,
    calls: Option<OrchardOrderedContractCallsV1>,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if let Some(calls) = &calls {
        validate_orchard_ordered_context(&context, calls)?;
    }
    if request.anchor_epoch == 0 || request.expiry_height == 0 {
        return Err(PrivacyNativeActionErrorV1::at("orchard-epoch-or-expiry"));
    }
    if canonical_public_balance_scope_v1(request.public_balance_scope).is_none() {
        return Err(PrivacyNativeActionErrorV1::at(
            "orchard-public-balance-scope",
        ));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)?;
    let prepared = prepare_orchard_bundle_v1(
        request.anchor.into_bytes(),
        request.spends,
        request.changes,
        request.minimum_action_count,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-prepare"))?;
    let draft = prepared.public_draft().clone();
    if draft.anchor != request.anchor.into_bytes() {
        return Err(PrivacyNativeActionErrorV1::at("orchard-anchor-drift"));
    }
    let mut statement = OrchardHalo2ActionsStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        public_balance_scope: request.public_balance_scope,
        pool_id: request.pool_id,
        anchor: request.anchor,
        anchor_epoch: request.anchor_epoch,
        actions: draft.actions.iter().map(orchard_action).collect(),
        value_balance: orchard_value_balance(draft.value_balance),
        expiry_height: request.expiry_height,
    };
    let draft_envelope = intent_projection_envelope(
        profile,
        PrivacyStatementV1::OrchardHalo2ActionsV1(statement.clone()),
        PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    let draft_payload = match &calls {
        Some(calls) => orchard_ordered_payload(&context, calls, Some(draft_envelope))?,
        None => transaction_payload(&context, Some(draft_envelope))?,
    };
    let intent = draft_payload
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("transaction-intent"))?;
    statement.context.transaction_intent_digest = intent;
    let consensus_limits = PrivacyConsensusLimitsV1::taira_default();
    let binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        canonical_genesis_hash,
        &consensus_limits,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-consensus-binding"))?;
    let proved = authorize_orchard_bundle_v1(prepared, binding, &consensus_limits)
        .map_err(|_| PrivacyNativeActionErrorV1::at("orchard-authorization"))?;
    if proved.public.anchor != draft.anchor
        || proved.public.value_balance != draft.value_balance
        || proved.public.actions != draft.actions
    {
        return Err(PrivacyNativeActionErrorV1::at("orchard-public-drift"));
    }
    let typed_statement = PrivacyStatementV1::OrchardHalo2ActionsV1(statement);
    if let Some(calls) = &calls {
        let envelope = bind_envelope(
            profile,
            typed_statement,
            PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(proved.authorization)),
            "proof-envelope-validation",
        )?;
        envelope
            .validate_with_limits(&consensus_limits)
            .map_err(|_| PrivacyNativeActionErrorV1::at("proof-envelope-validation"))?;
        let payload = orchard_ordered_payload(&context, calls, Some(envelope))?;
        if payload
            .validate_privacy_transaction_intent_binding_v1()
            .map_err(|_| PrivacyNativeActionErrorV1::at("final-intent-binding"))?
            != intent
        {
            return Err(PrivacyNativeActionErrorV1::at("signed-intent-drift"));
        }
        let signed = TransactionBuilder::from_payload(payload)
            .map_err(|_| PrivacyNativeActionErrorV1::at("final-payload"))?
            .try_sign(private_key)
            .map_err(|_| PrivacyNativeActionErrorV1::at("transaction-signing"))?;
        inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
            &signed, &context, calls,
        )?;
        return wrap_canonical_signed_transaction_v1(signed, profile.protocol_id);
    }
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::OrchardHalo2ActionsV1(PrivacyProofBytesV1::new(proved.authorization)),
        private_key,
    )
}
fn model_fcmp_output(note: &FcmpWalletNoteV1) -> PrivacyFcmpOutputTupleV1 {
    let (output_key, linking_tag_generator, amount_commitment) = note.output().components();
    PrivacyFcmpOutputTupleV1 {
        output_key,
        linking_tag_generator,
        amount_commitment,
    }
}
fn model_fcmp_input(input: FcmpProofInputPublicV1) -> PrivacyFcmpInputPublicV1 {
    PrivacyFcmpInputPublicV1 {
        output_key_tilde: input.output_key_tilde,
        linking_tag_generator_tilde: input.linking_tag_generator_tilde,
        rerandomization_commitment: input.rerandomization_commitment,
        pseudo_out: input.pseudo_out,
        key_image: PrivacyFcmpKeyImageV1::new(input.key_image),
    }
}
fn fcmp_runtime_context_hash(
    context: &PrivacyActionTransactionContextV1,
    statement_digest: PrivacyStatementDigestV1,
    profile: CompiledPrivacyProfileV1,
) -> [u8; 32] {
    derive_fcmp_runtime_context_hash_v1(&FcmpRuntimeContextBindingV1 {
        network_id: &context.network_id,
        action_index: 0,
        statement_digest,
        parameter_id: profile.parameter_id,
        parameter_digest: profile.parameter_digest,
        verifier_digest: profile.verifier_digest,
        statement_schema_digest: profile.statement_schema_digest,
        engine_manifest_digest: profile.engine_manifest_digest,
    })
}
/// Build and sign one canonical FCMP++ membership payment.
pub fn build_signed_fcmp_membership_payment_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: FcmpMembershipPaymentActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if request.root_epoch == 0 {
        return Err(PrivacyNativeActionErrorV1::at("fcmp-root-epoch"));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)?;
    let native_public_inputs = request
        .inputs
        .iter()
        .map(FcmpProverInputV1::public_input)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyNativeActionErrorV1::at("fcmp-public-input"))?;
    let outputs = request
        .outputs
        .iter()
        .map(|output| model_fcmp_output(&output.note))
        .collect::<Vec<_>>();
    let output_openings = request
        .outputs
        .iter()
        .map(|output| output.note.commitment_opening())
        .collect::<Result<Vec<FcmpOutputCommitmentOpeningV1>, _>>()
        .map_err(|_| PrivacyNativeActionErrorV1::at("fcmp-output-opening"))?;
    let encrypted_outputs = request
        .outputs
        .iter()
        .zip(&outputs)
        .map(|(output, model)| {
            encrypt_fcmp_wallet_note_v1(
                &mut OsRng,
                request.pool_id,
                *model,
                &output.note,
                output.recipient_public_key,
            )
            .map_err(|_| PrivacyNativeActionErrorV1::at("fcmp-output-encryption"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut statement = MoneroFcmpPlusPlusStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        pool_id: request.pool_id,
        output_set_root: PrivacyFcmpTreeRootV1 {
            layers: request.output_set_root.layers(),
            point: request.output_set_root.point(),
        },
        root_epoch: request.root_epoch,
        inputs: native_public_inputs
            .iter()
            .copied()
            .map(model_fcmp_input)
            .collect(),
        outputs,
        encrypted_outputs,
    };
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement.clone()),
        PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    let typed_statement = PrivacyStatementV1::MoneroFcmpPlusPlusV1(statement);
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("fcmp-statement-digest"))?;
    let runtime_context = fcmp_runtime_context_hash(&context, statement_digest, profile);
    let proved = prove_fcmp_plus_plus_v1(
        &mut OsRng,
        runtime_context,
        &request.inputs,
        &output_openings,
        request.output_set_root,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("fcmp-proving"))?;
    if proved.public_inputs() != native_public_inputs {
        return Err(PrivacyNativeActionErrorV1::at("fcmp-public-input-drift"));
    }
    finalize(
        &context,
        profile,
        typed_statement,
        PrivacyProofV1::MoneroFcmpPlusPlusV1(PrivacyProofBytesV1::new(
            proved.proof_wire().to_vec(),
        )),
        private_key,
    )
}
fn checked_private_note_sums(
    inputs: &[IvmPrivateNoteInputWitnessV1],
    outputs: &[IvmPrivateNoteOutputRequestV1],
) -> Result<(u128, u128), PrivacyNativeActionErrorV1> {
    let input_sum = inputs.iter().try_fold(0_u128, |sum, input| {
        sum.checked_add(input.note().value())
            .ok_or_else(|| PrivacyNativeActionErrorV1::at("ivm-input-value-overflow"))
    })?;
    let output_sum = outputs.iter().try_fold(0_u128, |sum, output| {
        sum.checked_add(output.witness.note().value())
            .ok_or_else(|| PrivacyNativeActionErrorV1::at("ivm-output-value-overflow"))
    })?;
    Ok((input_sum, output_sum))
}
fn private_note_value_balance(input_sum: u128, output_sum: u128) -> PrivacyValueBalanceV1 {
    match input_sum.cmp(&output_sum) {
        core::cmp::Ordering::Equal => PrivacyValueBalanceV1::balanced(),
        core::cmp::Ordering::Greater => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::OutOfPool,
            amount: input_sum - output_sum,
        },
        core::cmp::Ordering::Less => PrivacyValueBalanceV1 {
            direction: PrivacyValueBalanceDirectionV1::IntoPool,
            amount: output_sum - input_sum,
        },
    }
}
/// Build and sign one canonical native private-IVM note action.
pub fn build_signed_ivm_private_note_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: IvmPrivateNoteActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if request.root_epoch == 0 {
        return Err(PrivacyNativeActionErrorV1::at("ivm-root-epoch"));
    }
    if canonical_public_balance_scope_v1(request.public_balance_scope).is_none() {
        return Err(PrivacyNativeActionErrorV1::at("ivm-public-balance-scope"));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)?;
    let program_id = derive_private_program_id_v1(&request.program)
        .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-program-id"))?;
    let (input_sum, output_sum) = checked_private_note_sums(&request.inputs, &request.outputs)?;
    let output_commitments = request
        .outputs
        .iter()
        .map(|output| {
            iroha_core_privacy::privacy_engines::ivm_private_note::derive_note_commitment_v1(
                output.witness.note(),
            )
            .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-output-commitment"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encrypted_outputs = request
        .outputs
        .iter()
        .zip(&output_commitments)
        .map(|(output, commitment)| {
            let encrypted = encrypt_ivm_private_wallet_note_with_os_rng_v1(
                request.pool_id,
                program_id,
                output.witness.note(),
                output.recipient_public_key,
            )
            .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-output-encryption"))?;
            if encrypted.commitment != *commitment {
                return Err(PrivacyNativeActionErrorV1::at(
                    "ivm-output-commitment-drift",
                ));
            }
            Ok(encrypted)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut statement = IrohaIvmPrivateNoteStarkStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        public_balance_scope: request.public_balance_scope,
        pool_id: request.pool_id,
        program_id,
        action_digest: PrivacyActionDigestV1::new([0; 32]),
        state_root: request.state_root,
        root_epoch: request.root_epoch,
        nullifiers: Vec::new(),
        output_commitments,
        encrypted_outputs,
        value_balance: private_note_value_balance(input_sum, output_sum),
        execution_epoch: request.root_epoch,
    };
    statement.nullifiers = request
        .inputs
        .iter()
        .map(|input| {
            input
                .nullifier_v1(&statement)
                .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-input-nullifier"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement.clone()),
        PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    statement.action_digest = statement
        .computed_action_digest()
        .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-action-digest"))?;
    if statement.action_digest.is_zero()
        || statement
            .computed_action_digest()
            .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-action-redigest"))?
            != statement.action_digest
    {
        return Err(PrivacyNativeActionErrorV1::at("ivm-action-digest-drift"));
    }
    let consensus_limits = PrivacyConsensusLimitsV1::taira_default();
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        canonical_genesis_hash,
        &consensus_limits,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-consensus-binding"))?;
    let output_witnesses = request
        .outputs
        .into_iter()
        .map(|output| output.witness)
        .collect();
    let witness = IvmPrivateNoteWitnessV1::new(request.program, request.inputs, output_witnesses)
        .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-witness"))?;
    let proof =
        prove_ivm_private_note_v1(&statement, &consensus_binding, &consensus_limits, &witness)
            .map_err(|_| PrivacyNativeActionErrorV1::at("ivm-proving"))?;
    finalize(
        &context,
        profile,
        PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(statement),
        PrivacyProofV1::IrohaIvmPrivateNoteStarkV1(PrivacyProofBytesV1::new(proof)),
        private_key,
    )
}
/// Build and sign one canonical PQ-MASP note action.
pub fn build_signed_pq_masp_note_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: PqMaspNoteActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    validate_action_preflight(&context, canonical_genesis_hash, private_key)?;
    if request.anchor_epoch == 0 {
        return Err(PrivacyNativeActionErrorV1::at("pq-masp-anchor-epoch"));
    }
    let profile = compiled_profile(PrivacyProtocolIdV1::PqMaspStarkV1)?;
    let authorization_key_digest = derive_pq_masp_authorization_key_digest_from_secret_v1(
        request.authorization_secret_key.as_slice(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-authorization-key"))?;
    let mut statement = PqMaspStarkStatementV1 {
        context: statement_context(&context, profile),
        asset_definition_id: request.asset_definition_id,
        pool_id: request.pool_id,
        anchor: request.anchor,
        anchor_epoch: request.anchor_epoch,
        nullifiers: Vec::new(),
        output_commitments: Vec::new(),
        encrypted_outputs: Vec::new(),
        authorization_profile: PrivacyPqAuthorizationProfileV1::MlDsa65,
        authorization_key_digest,
        note_encryption_profile: PrivacyPqNoteEncryptionProfileV1::MlKem768XChaCha20Poly1305,
        note_encryption_key_digest: PrivacyNoteEncryptionKeyDigestV1::new([1; 32]),
        authorization_epoch: request.anchor_epoch,
    };
    let mut output_witnesses = Vec::with_capacity(request.outputs.len());
    for output in request.outputs {
        let (commitment, encrypted) = encrypt_pq_masp_note_v1(
            &statement,
            output.witness.note(),
            &output.recipient_public_key,
        )
        .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-output-encryption"))?;
        statement.output_commitments.push(commitment);
        statement.encrypted_outputs.push(encrypted);
        output_witnesses.push(output.witness);
    }
    statement.note_encryption_key_digest =
        derive_pq_masp_note_encryption_keys_digest_v1(&statement)
            .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-encryption-key-digest"))?;
    statement.nullifiers = request
        .inputs
        .iter()
        .map(|input| {
            input
                .nullifier_v1(&statement)
                .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-input-nullifier"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let intent = derive_intent(
        &context,
        profile,
        PrivacyStatementV1::PqMaspStarkV1(statement.clone()),
        PrivacyProofV1::PqMaspStarkV1(PrivacyProofBytesV1::new(Vec::new())),
    )?;
    statement.context.transaction_intent_digest = intent;
    let consensus_limits = PrivacyConsensusLimitsV1::taira_default();
    let consensus_binding = PrivacyNativeConsensusBindingV1::new(
        &statement.context,
        canonical_genesis_hash,
        &consensus_limits,
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-consensus-binding"))?;
    let witness = PqMaspWitnessV1::new(request.inputs, output_witnesses)
        .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-witness"))?;
    let proof = prove_pq_masp_v1(
        &statement,
        &consensus_binding,
        &consensus_limits,
        &witness,
        request.authorization_secret_key.as_slice(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("pq-masp-proving"))?;
    finalize(
        &context,
        profile,
        PrivacyStatementV1::PqMaspStarkV1(statement),
        PrivacyProofV1::PqMaspStarkV1(PrivacyProofBytesV1::new(proof)),
        private_key,
    )
}
/// Consume and dispatch any retained first-release native action request.
pub fn build_signed_privacy_native_action_v1(
    context: PrivacyActionTransactionContextV1,
    request: PrivacyNativeActionRequestV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    match request {
        PrivacyNativeActionRequestV1::ZkAce(request) => {
            build_signed_zk_ace_authorization_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::AnonymousPgc(request) => {
            build_signed_anonymous_pgc_payment_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::VeRange(request) => {
            build_signed_verange_action_v1(context, request, canonical_genesis_hash, private_key)
        }
        PrivacyNativeActionRequestV1::ZkAms(request) => {
            build_signed_zk_ams_action_v1(context, request, canonical_genesis_hash, private_key)
        }
        PrivacyNativeActionRequestV1::Vega(request) => {
            build_signed_vega_credential_presentation_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::ZkX509(request) => {
            build_signed_zk_x509_identity_presentation_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::Jindo(request) => {
            build_signed_jindo_polynomial_evaluation_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::BootleLantern(request) => {
            build_signed_bootle_lantern_presentation_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::Orchard(request) => build_signed_orchard_note_action_v1(
            context,
            request,
            canonical_genesis_hash,
            private_key,
        ),
        PrivacyNativeActionRequestV1::FcmpPlusPlus(request) => {
            build_signed_fcmp_membership_payment_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::IvmPrivateNote(request) => {
            build_signed_ivm_private_note_action_v1(
                context,
                request,
                canonical_genesis_hash,
                private_key,
            )
        }
        PrivacyNativeActionRequestV1::PqMasp(request) => build_signed_pq_masp_note_action_v1(
            context,
            request,
            canonical_genesis_hash,
            private_key,
        ),
    }
}
fn inspect_signed(
    signed: &SignedTransaction,
    expected_protocol: PrivacyProtocolIdV1,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    signed
        .verify_signature()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-signature"))?;
    let (intent, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-intent"))?
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("inspect-missing-action"))?;
    let envelope = &submission.envelope;
    if envelope.protocol_id != expected_protocol
        || envelope.statement.protocol_id() != expected_protocol
        || envelope.proof.protocol_id() != expected_protocol
    {
        return Err(PrivacyNativeActionErrorV1::at(
            "inspect-protocol-variant-drift",
        ));
    }
    envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-envelope"))?;
    let statement_encoding = norito::to_bytes(&envelope.statement)
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-statement-encoding"))?;
    let envelope_encoding = norito::to_bytes(envelope)
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-envelope-encoding"))?;
    Ok(InspectedPrivacyActionV1 {
        protocol_id: expected_protocol,
        transaction_hash: *signed.hash().as_ref(),
        transaction_intent_digest: *intent.as_bytes(),
        statement_digest: *envelope.statement_digest.as_bytes(),
        proof_envelope_hash: *Hash::new(&envelope_encoding).as_ref(),
        statement_bytes: u32::try_from(statement_encoding.len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-statement-length"))?,
        proof_bytes: u32::try_from(envelope.proof.bytes().as_bytes().len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-proof-length"))?,
        encoded_proof_envelope_bytes: u32::try_from(envelope_encoding.len())
            .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-envelope-length"))?,
        adaptive_signed_transaction_bytes: u32::try_from(
            norito::codec::encode_adaptive(signed).len(),
        )
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-transaction-length"))?,
        statement: envelope.statement.clone(),
    })
}
/// Authenticate and inspect any retained first-release native action.
pub fn inspect_signed_privacy_native_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    signed
        .verify_signature()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-signature"))?;
    let (_, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-intent"))?
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("inspect-missing-action"))?;
    let protocol_id = submission.envelope.protocol_id;
    privacy_native_action_capability_for_protocol_v1(protocol_id)
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("inspect-unsupported-protocol"))?;
    inspect_signed(signed, protocol_id)
}
/// Authenticate and inspect one exact governed ZK-ACE authorization action.
pub fn inspect_signed_privacy_zk_ace_authorization_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::ZkAcePqAuthorizationV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::ZkAcePqAuthorizationV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-zk-ace-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact Anonymous-PGC payment action.
pub fn inspect_signed_privacy_anonymous_pgc_payment_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::AnonymousPgcKOutOfNV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::AnonymousPgcKOutOfNV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-pgc-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact VeRange action.
pub fn inspect_signed_privacy_verange_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::VeRangeTransparentRangeV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::VeRangeTransparentRangeV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-verange-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect either exact ZK-AMS action kind.
pub fn inspect_signed_privacy_zk_ams_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::IrohaZkAmsV1)?;
    if !matches!(inspected.statement(), PrivacyStatementV1::IrohaZkAmsV1(_)) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-zk-ams-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact ZK-AMS admission batch.
pub fn inspect_signed_privacy_zk_ams_batch_admission_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed_privacy_zk_ams_action_v1(signed)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::IrohaZkAmsV1(IrohaZkAmsStatementV1 {
            action: PrivacyZkAmsActionV1::BatchAdmission(_),
            ..
        })
    ) {
        return Err(PrivacyNativeActionErrorV1::at(
            "inspect-zk-ams-admission-action",
        ));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact ZK-AMS account provisioning.
pub fn inspect_signed_privacy_zk_ams_provision_account_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed_privacy_zk_ams_action_v1(signed)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::IrohaZkAmsV1(IrohaZkAmsStatementV1 {
            action: PrivacyZkAmsActionV1::ProvisionAccount(_),
            ..
        })
    ) {
        return Err(PrivacyNativeActionErrorV1::at(
            "inspect-zk-ams-provision-action",
        ));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact Vega credential presentation.
pub fn inspect_signed_privacy_vega_credential_presentation_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::VegaExistingCredentialZkV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::VegaExistingCredentialZkV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-vega-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact ZK-X509 identity presentation.
pub fn inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
    signed: &SignedTransaction,
    canonical_genesis_hash: [u8; 32],
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    require_genesis(canonical_genesis_hash)?;
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::IrohaZkX509StarkP256V1)?;
    let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) = inspected.statement() else {
        return Err(PrivacyNativeActionErrorV1::at("inspect-zk-x509-statement"));
    };
    let (_, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-zk-x509-intent"))?
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("inspect-missing-action"))?;
    validate_zk_x509_credential_proof_container_v1(
        statement,
        canonical_genesis_hash,
        submission.envelope.proof.bytes().as_bytes(),
    )
    .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-zk-x509-proof-container"))?;
    Ok(inspected)
}
/// Authenticate and inspect one exact Jindo polynomial-evaluation action.
pub fn inspect_signed_privacy_jindo_polynomial_evaluation_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(
        signed,
        PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1,
    )?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::IrohaJindoPolynomialCommitmentV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-jindo-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact Bootle/Lantern presentation.
pub fn inspect_signed_privacy_bootle_lantern_presentation_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::IrohaBootleLanternAnoncredV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::IrohaBootleLanternAnoncredV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-bootle-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact Orchard V3 note action.
pub fn inspect_signed_privacy_orchard_note_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::OrchardHalo2ActionsV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::OrchardHalo2ActionsV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-orchard-statement"));
    }
    Ok(inspected)
}
/// Authenticate a complete Orchard Batch against independently fixed context and calls.
///
/// Comparison covers network, authority, creation time, TTL, nonce, fees, metadata, attachment
/// descriptors, every call address/code hash/entrypoint/argument record, and the sole original
/// direct submission ordinal. Do not derive `expected_context` or `expected_calls` from `signed`.
/// This authenticates source and envelope structure; validator proof/state admission is separate.
///
/// # Errors
/// Rejects invalid signatures/intents, non-Orchard envelopes, oversized plans/wire, any context
/// or call mismatch, and any additional, moved, nested or standalone submission.
pub fn inspect_signed_privacy_orchard_note_action_with_contract_calls_v1(
    signed: &SignedTransaction,
    expected_context: &PrivacyActionTransactionContextV1,
    expected_calls: &OrchardOrderedContractCallsV1,
) -> Result<InspectedOrchardOrderedActionV1, PrivacyNativeActionErrorV1> {
    validate_orchard_ordered_context(expected_context, expected_calls)?;
    if signed.encode_versioned().len() > PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1 {
        return Err(PrivacyNativeActionErrorV1::at(
            "signed-transaction-response-cap",
        ));
    }
    let action = inspect_signed_privacy_orchard_note_action_v1(signed)?;
    let (_, submission) = signed
        .privacy_transaction_intent_binding_if_present_v1()
        .map_err(|_| PrivacyNativeActionErrorV1::at("inspect-intent"))?
        .ok_or_else(|| PrivacyNativeActionErrorV1::at("inspect-missing-action"))?;
    if !compiled_profile(PrivacyProtocolIdV1::OrchardHalo2ActionsV1)?
        .matches_envelope_v1(&submission.envelope)
    {
        return Err(PrivacyNativeActionErrorV1::at("inspect-orchard-profile"));
    }
    let expected_payload = orchard_ordered_payload(
        expected_context,
        expected_calls,
        Some(submission.envelope.clone()),
    )?;
    if signed.payload() != &expected_payload || action.statement().context().action_index != 0 {
        return Err(PrivacyNativeActionErrorV1::at(
            "inspect-orchard-ordered-payload",
        ));
    }
    Ok(InspectedOrchardOrderedActionV1 {
        action,
        direct_instruction_index: expected_calls.direct_instruction_index(),
    })
}
/// Authenticate and inspect one exact FCMP++ membership payment action.
pub fn inspect_signed_privacy_fcmp_membership_payment_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::MoneroFcmpPlusPlusV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::MoneroFcmpPlusPlusV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-fcmp-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact native private-IVM note action.
pub fn inspect_signed_privacy_ivm_private_note_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1)?;
    if !matches!(
        inspected.statement(),
        PrivacyStatementV1::IrohaIvmPrivateNoteStarkV1(_)
    ) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-ivm-statement"));
    }
    Ok(inspected)
}
/// Authenticate and inspect one exact PQ-MASP note action.
pub fn inspect_signed_privacy_pq_masp_note_action_v1(
    signed: &SignedTransaction,
) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1> {
    let inspected = inspect_signed(signed, PrivacyProtocolIdV1::PqMaspStarkV1)?;
    if !matches!(inspected.statement(), PrivacyStatementV1::PqMaspStarkV1(_)) {
        return Err(PrivacyNativeActionErrorV1::at("inspect-pq-masp-statement"));
    }
    Ok(inspected)
}
#[cfg(test)]
mod tests {
    use super::*;
    include!("privacy_native_actions_orchard_ordered_tests.rs");
    use iroha_data_model::privacy::{
        PrivacyAttributeDigestV1, PrivacyCertificateKeyDigestV1, PrivacyChallengeV1,
        PrivacyEngineManifestDigestV1, PrivacyIssuerIdV1, PrivacyNullifierV1,
        PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyStatementSchemaDigestV1,
        PrivacyVerifierDigestV1, PrivacyX509ExtendedKeyUsageV1, PrivacyX509KeyUsageRequirementV1,
        PrivacyX509KeyUsageV1, PrivacyZkX509CertificatePolicyRecordDigestV1,
        PrivacyZkX509CrlRecordDigestV1, PrivacyZkX509DisclosedAttributeV1,
        PrivacyZkX509TrustAnchorRecordDigestV1,
    };
    use std::collections::BTreeSet;
    fn signing_key() -> PrivateKey {
        "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
            .parse()
            .expect("fixed Ed25519 private key")
    }
    fn foreign_signing_key() -> PrivateKey {
        "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
            .parse()
            .expect("fixed foreign Ed25519 private key")
    }
    fn action_context() -> PrivacyActionTransactionContextV1 {
        let private_key = signing_key();
        PrivacyActionTransactionContextV1 {
            network_id: network_id_from_genesis_hash_bytes([1; 32]),
            authority: AccountId::new(PublicKey::from(private_key)),
            creation_time: Duration::from_millis(1_800_000_000_123),
            time_to_live: Some(Duration::from_secs(60)),
            nonce: NonZeroU32::new(7),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            metadata: Metadata::default(),
        }
    }
    fn x509_draft_statement(
        context: &PrivacyActionTransactionContextV1,
    ) -> IrohaZkX509StarkP256StatementV1 {
        IrohaZkX509StarkP256StatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: context.network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
                parameter_id: PrivacyParameterIdV1::new([0x21; 32]),
                parameter_digest: PrivacyParameterDigestV1::new([0x22; 32]),
                verifier_digest: PrivacyVerifierDigestV1::new([0x23; 32]),
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new([0x24; 32]),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new([0x25; 32]),
            },
            trust_anchor_id: PrivacyIssuerIdV1::new([0x11; 32]),
            certificate_policy_id: PrivacyPolicyIdV1::new([0x12; 32]),
            trust_anchor_record_digest: PrivacyZkX509TrustAnchorRecordDigestV1::new([0x13; 32]),
            trust_anchor_record_epoch: 3,
            certificate_policy_record_digest: PrivacyZkX509CertificatePolicyRecordDigestV1::new(
                [0x14; 32],
            ),
            certificate_policy_record_epoch: 4,
            crl_record_digest: PrivacyZkX509CrlRecordDigestV1::new([0x15; 32]),
            crl_record_epoch: 5,
            subject_public_key_digest: PrivacyCertificateKeyDigestV1::new([0x16; 32]),
            ca_membership_root: PrivacyRootV1::new([0x17; 32]),
            ca_membership_root_epoch: 6,
            key_usage: PrivacyX509KeyUsageV1 {
                digital_signature: PrivacyX509KeyUsageRequirementV1::new(true),
                content_commitment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_encipherment: PrivacyX509KeyUsageRequirementV1::new(false),
                key_agreement: PrivacyX509KeyUsageRequirementV1::new(false),
            },
            extended_key_usages: vec![
                PrivacyX509ExtendedKeyUsageV1::ClientAuthentication,
                PrivacyX509ExtendedKeyUsageV1::WalletIdentity,
            ],
            disclosed_attributes: vec![PrivacyZkX509DisclosedAttributeV1 {
                index: 0,
                attribute_digest: PrivacyAttributeDigestV1::new([0x18; 32]),
            }],
            presentation_not_before_unix_seconds: 1_800_000_000,
            presentation_not_after_unix_seconds: 1_800_000_300,
            wallet_account: context.authority.clone(),
            wallet_challenge: PrivacyChallengeV1::new([0x19; 32]),
            certificate_nullifier: PrivacyNullifierV1::new([0x1A; 32]),
        }
    }
    #[test]
    fn public_balance_scope_literals_are_exact_and_never_alias_universal() {
        for (literal, expected) in [
            ("global", AssetBalanceScope::Global),
            (
                "dataspace:1",
                AssetBalanceScope::Dataspace(DataSpaceId::new(1)),
            ),
            (
                "dataspace:18446744073709551615",
                AssetBalanceScope::Dataspace(DataSpaceId::new(u64::MAX)),
            ),
        ] {
            let parsed = parse_canonical_public_balance_scope_v1(literal)
                .expect("canonical scope must parse");
            assert_eq!(parsed, expected);
            assert_eq!(
                canonical_public_balance_scope_v1(parsed).as_deref(),
                Some(literal)
            );
        }
        for hostile in [
            "",
            "Global",
            "GLOBAL",
            " global",
            "global ",
            "universal",
            "dataspace:",
            "dataspace:0",
            "dataspace:00",
            "dataspace:01",
            "dataspace:+1",
            "dataspace:-1",
            "dataspace: 1",
            "dataspace:1 ",
            "dataspace:１",
            "dataspace:18446744073709551616",
            "dataspace:999999999999999999999",
            "dataspace:universal",
        ] {
            assert_eq!(
                parse_canonical_public_balance_scope_v1(hostile),
                None,
                "hostile scope {hostile:?} was accepted"
            );
        }
        assert_eq!(
            canonical_public_balance_scope_v1(
                AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL,)
            ),
            None
        );
        let oversized = format!("dataspace:{}", "9".repeat(4_096));
        assert_eq!(parse_canonical_public_balance_scope_v1(&oversized), None);
    }
    #[test]
    fn retained_capability_table_is_the_exact_reviewed_twelve() {
        let expected = [
            (
                "zk-ace-pq-authorization-v1",
                "zk_ace_authorization_action_v1",
                "authorization_action",
                0,
            ),
            (
                "anonymous-pgc-k-out-of-n-v1",
                "anonymous_pgc_payment_action_v1",
                "payment_action",
                6,
            ),
            (
                "verange-transparent-range-v1",
                "verange_range_proof_v1",
                "component",
                1,
            ),
            (
                "iroha-zk-ams-v1",
                "zk_ams_admission_and_provisioning_v1",
                "admission_action",
                2,
            ),
            (
                "vega-existing-credential-zk-v1",
                "vega_credential_presentation_v1",
                "presentation_action",
                2,
            ),
            (
                "iroha-zk-x509-stark-p256-v1",
                "zk_x509_identity_presentation_v1",
                "presentation_action",
                2,
            ),
            (
                "iroha-jindo-polynomial-commitment-v1",
                "jindo_polynomial_evaluation_v1",
                "component",
                0,
            ),
            (
                "iroha-bootle-lantern-anoncred-v1",
                "bootle_lantern_credential_presentation_v1",
                "presentation_action",
                2,
            ),
            (
                "orchard-halo2-actions-v1",
                "orchard_note_action_v1",
                "note_action",
                7,
            ),
            (
                "monero-fcmp-plus-plus-v1",
                "fcmp_membership_payment_v1",
                "payment_action",
                2,
            ),
            (
                "iroha-ivm-private-note-stark-v1",
                "ivm_private_note_action_v1",
                "note_action",
                7,
            ),
            (
                "pq-masp-stark-v1",
                "pq_masp_note_action_v1",
                "note_action",
                31,
            ),
        ];
        assert_eq!(PRIVACY_NATIVE_ACTION_CAPABILITIES_V1.len(), expected.len());
        for (actual, expected) in PRIVACY_NATIVE_ACTION_CAPABILITIES_V1.iter().zip(expected) {
            assert_eq!(actual.protocol_id.canonical_label(), expected.0);
            assert_eq!(actual.operation_schema, expected.1);
            assert_eq!(actual.execution_mode, expected.2);
            assert_eq!(actual.privacy_feature_mask, expected.3);
            assert_eq!(
                privacy_native_action_capability_for_schema_v1(expected.1),
                Some(actual)
            );
            assert_eq!(
                privacy_native_action_capability_for_protocol_v1(actual.protocol_id),
                Some(actual)
            );
        }
    }
    #[test]
    fn retained_capability_keys_are_unique_and_x509_is_profile_owned_but_first_class() {
        let protocols = PRIVACY_NATIVE_ACTION_CAPABILITIES_V1
            .iter()
            .map(|row| row.protocol_id.canonical_label())
            .collect::<BTreeSet<_>>();
        let schemas = PRIVACY_NATIVE_ACTION_CAPABILITIES_V1
            .iter()
            .map(|row| row.operation_schema)
            .collect::<BTreeSet<_>>();
        assert_eq!(protocols.len(), PRIVACY_NATIVE_ACTION_CAPABILITIES_V1.len());
        assert_eq!(schemas.len(), PRIVACY_NATIVE_ACTION_CAPABILITIES_V1.len());
        let x509 = privacy_native_action_capability_for_protocol_v1(
            PrivacyProtocolIdV1::IrohaZkX509StarkP256V1,
        )
        .expect("X509 is one of the exact twelve retained actions");
        assert_eq!(x509.operation_schema, "zk_x509_identity_presentation_v1");
        assert_eq!(
            privacy_native_action_capability_for_schema_v1("zk_x509_identity_presentation_v1"),
            Some(x509)
        );
    }
    #[test]
    fn capability_schema_lookup_rejects_every_alias_form() {
        for alias in [
            "",
            " ",
            "JINDO_POLYNOMIAL_EVALUATION_V1",
            "jindo-polynomial-evaluation-v1",
            "jindo_polynomial_evaluation_v1 ",
            " jindo_polynomial_evaluation_v1",
            "jindo_polynomial_evaluation_v1\0",
            "orchard_note_action",
            "pq_masp_note_action_v0",
            "anonymous_pgc_payment_action_v2",
        ] {
            assert!(
                privacy_native_action_capability_for_schema_v1(alias).is_none(),
                "unexpected alias accepted: {alias:?}"
            );
        }
    }
    #[test]
    fn transport_caps_preserve_request_and_signed_transaction_bounds() {
        const {
            assert!(PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1 > 0);
            assert!(
                PRIVACY_ZK_X509_MAX_STATEMENT_ARCHIVE_BYTES_V1
                    < PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1
            );
            assert!(
                PRIVACY_NATIVE_ACTION_MAX_DISPATCH_REQUEST_BYTES_V1
                    < PRIVACY_NATIVE_ACTION_MAX_SECRET_BUNDLE_BYTES_V1
            );
            assert!(
                PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1
                    < PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1
            );
            assert!(
                PRIVACY_NATIVE_ACTION_MAX_SECRET_BUNDLE_BYTES_V1
                    < PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1
            );
        }
        assert_eq!(
            u64::try_from(PRIVACY_NATIVE_ACTION_MAX_SIGNED_TRANSACTION_BYTES_V1)
                .expect("native action response cap fits u64"),
            iroha_data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes()
                .get(),
            "native action output must equal Taira's canonical transaction admission cap"
        );
    }
    #[test]
    fn canonical_genesis_binding_rejects_only_the_reserved_zero_digest() {
        assert_eq!(
            require_genesis([0; 32])
                .expect_err("zero genesis must fail")
                .stage(),
            "canonical-genesis-hash"
        );
        for digest in [[1; 32], [u8::MAX; 32]] {
            require_genesis(digest).expect("nonzero genesis is accepted");
        }
    }
    #[test]
    fn signing_authority_must_be_the_exact_direct_account_key() {
        let context = action_context();
        validate_signing_authority(&context.authority, &signing_key())
            .expect("matching direct key");
        assert_eq!(
            validate_signing_authority(&context.authority, &foreign_signing_key())
                .expect_err("foreign key must fail")
                .stage(),
            "authority-key-mismatch"
        );
    }
    #[test]
    fn shared_preflight_rejects_before_any_protocol_specific_work() {
        let context = action_context();
        assert_eq!(
            validate_action_preflight(&context, [0; 32], &foreign_signing_key())
                .expect_err("reserved genesis must fail before authority inspection")
                .stage(),
            "canonical-genesis-hash"
        );
        let mut invalid_context = action_context();
        invalid_context.time_to_live = Some(Duration::ZERO);
        assert_eq!(
            validate_action_preflight(&invalid_context, [1; 32], &foreign_signing_key())
                .expect_err("invalid transaction context must fail before authority inspection")
                .stage(),
            "transaction-context"
        );
        assert_eq!(
            validate_action_preflight(&context, [2; 32], &foreign_signing_key())
                .expect_err("foreign transaction network must fail before authority inspection")
                .stage(),
            "transaction-network-id"
        );
        assert_eq!(
            validate_action_preflight(&context, [1; 32], &foreign_signing_key())
                .expect_err("foreign authority key must fail before proving")
                .stage(),
            "authority-key-mismatch"
        );
        validate_action_preflight(&context, [1; 32], &signing_key())
            .expect("complete preflight must accept the exact direct key");
    }
    #[test]
    fn transaction_context_rejects_invalid_values_before_proving() {
        let mut context = action_context();
        validate_context(&context).expect("baseline context");
        context = action_context();
        context.creation_time = Duration::from_secs(u64::MAX);
        assert_eq!(
            validate_context(&context)
                .expect_err("millisecond-overflowing creation time must fail")
                .stage(),
            "transaction-creation-time"
        );
        context = action_context();
        context.time_to_live = Some(Duration::from_secs(u64::MAX));
        assert_eq!(
            validate_context(&context)
                .expect_err("millisecond-overflowing TTL must fail")
                .stage(),
            "transaction-ttl"
        );
        context = action_context();
        context.time_to_live = Some(Duration::ZERO);
        assert_eq!(
            validate_context(&context)
                .expect_err("zero TTL must fail canonical payload construction")
                .stage(),
            "transaction-context"
        );
    }
    #[test]
    fn x509_intent_and_signing_require_the_production_compiled_profile() {
        let genesis = [0xA5; 32];
        let mut context = action_context();
        context.network_id = network_id_from_genesis_hash_bytes(genesis);
        let statement = x509_draft_statement(&context);
        assert_eq!(
            prepare_zk_x509_identity_presentation_action_intent_v1(&context, [0; 32], &statement)
                .expect_err("reserved genesis must fail before profile lookup")
                .stage(),
            "canonical-genesis-hash"
        );
        assert_eq!(
            prepare_zk_x509_identity_presentation_action_intent_v1(
                &context, [0xA6; 32], &statement,
            )
            .expect_err("foreign transaction network must fail before profile lookup")
            .stage(),
            "transaction-network-id"
        );
        assert_eq!(
            prepare_zk_x509_identity_presentation_action_intent_v1(&context, genesis, &statement)
                .expect_err("intent preparation must remain closed before qualification")
                .stage(),
            "compiled-profile"
        );

        assert_eq!(
            build_signed_zk_x509_identity_presentation_action_v1(
                context.clone(),
                ZkX509IdentityPresentationActionRequestV1 {
                    statement: statement.clone(),
                    proof: ZkX509CredentialProofBytesV1::try_new(vec![1])
                        .expect("nonempty bounded proof reaches only the profile gate"),
                },
                genesis,
                &signing_key(),
            )
            .expect_err("signing must remain closed before qualification")
            .stage(),
            "compiled-profile"
        );
        assert_eq!(
            build_signed_zk_x509_identity_presentation_action_v1(
                context,
                ZkX509IdentityPresentationActionRequestV1 {
                    statement,
                    proof: ZkX509CredentialProofBytesV1::try_new(vec![1])
                        .expect("nonempty bounded proof reaches only preflight"),
                },
                genesis,
                &foreign_signing_key(),
            )
            .expect_err("a foreign transaction key is rejected before profile lookup")
            .stage(),
            "authority-key-mismatch"
        );
    }
    #[test]
    fn x509_public_proof_boundary_accepts_its_ceiling_beyond_secret_bundle_capacity() {
        let bytes = vec![0xA5; PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1];
        assert!(bytes.len() > PRIVACY_NATIVE_ACTION_MAX_SECRET_BUNDLE_BYTES_V1);
        let proof = ZkX509CredentialProofBytesV1::try_new(bytes.clone())
            .expect("public proof capacity is independent of the secret bundle boundary");
        assert_eq!(proof.as_bytes(), bytes.as_slice());
        assert_eq!(proof.into_bytes(), bytes);
        assert_eq!(
            ZkX509CredentialProofBytesV1::try_new(Vec::new())
                .err()
                .expect("empty X5S1 must fail at the typed boundary")
                .stage(),
            "zk-x509-proof-cap"
        );
        assert_eq!(
            ZkX509CredentialProofBytesV1::try_new(vec![
                0xA5;
                PRIVACY_ZK_X509_MAX_PROOF_BYTES_V1 + 1
            ])
            .err()
            .expect("oversized X5S1 must fail at the typed boundary")
            .stage(),
            "zk-x509-proof-cap"
        );
    }
    #[test]
    fn every_exact_inspector_rejects_a_validly_signed_transaction_without_an_action() {
        let context = action_context();
        let signed = TransactionBuilder::from_payload(
            transaction_payload(&context, None).expect("empty canonical payload"),
        )
        .expect("payload round-trip")
        .try_sign(&signing_key())
        .expect("canonical direct signature");
        assert_eq!(
            inspect_signed_privacy_native_action_v1(&signed)
                .expect_err("generic inspector must require one native action")
                .stage(),
            "inspect-missing-action"
        );
        type Inspector =
            fn(&SignedTransaction) -> Result<InspectedPrivacyActionV1, PrivacyNativeActionErrorV1>;
        let inspectors: [Inspector; 13] = [
            inspect_signed_privacy_zk_ace_authorization_action_v1,
            inspect_signed_privacy_anonymous_pgc_payment_action_v1,
            inspect_signed_privacy_verange_action_v1,
            inspect_signed_privacy_zk_ams_action_v1,
            inspect_signed_privacy_zk_ams_batch_admission_action_v1,
            inspect_signed_privacy_zk_ams_provision_account_action_v1,
            inspect_signed_privacy_vega_credential_presentation_action_v1,
            inspect_signed_privacy_jindo_polynomial_evaluation_action_v1,
            inspect_signed_privacy_bootle_lantern_presentation_action_v1,
            inspect_signed_privacy_orchard_note_action_v1,
            inspect_signed_privacy_fcmp_membership_payment_action_v1,
            inspect_signed_privacy_ivm_private_note_action_v1,
            inspect_signed_privacy_pq_masp_note_action_v1,
        ];
        for inspect in inspectors {
            assert_eq!(
                inspect(&signed)
                    .expect_err("protocol inspector must require one native action")
                    .stage(),
                "inspect-missing-action"
            );
        }
        assert_eq!(
            inspect_signed_privacy_zk_x509_identity_presentation_action_v1(&signed, [1; 32])
                .expect_err("X509 inspector must require one native action")
                .stage(),
            "inspect-missing-action"
        );
    }
}
