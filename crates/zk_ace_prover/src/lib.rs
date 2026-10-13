//! Fail-closed native-Rust transaction builder for the disabled ZK-ACE candidate.
//!
//! The typed policy, witness, and transaction shapes remain available for validation and future
//! migration, but no compiled native verifier profile is activatable. Every otherwise valid
//! preparation or build attempt therefore returns
//! [`ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable`] before private-witness
//! hashing, entropy or proof work.
use core::{num::NonZeroU32, time::Duration};
pub use iroha_core_privacy::privacy_engines::zk_ace::{
    ZkAcePrivacyWitnessV1, ZkAcePrivacyWitnessValidationErrorV1,
};
use iroha_core_privacy::{
    privacy_engines::zk_ace::{
        ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1, ZkAceNativeErrorV1, ZkAceTryCryptoRngV1,
        prove_zk_ace_privacy_v1, prove_zk_ace_privacy_v1_with_rng,
    },
    privacy_profiles::compiled_privacy_profile_v1,
};
use iroha_crypto::{Hash, PrivateKey, PublicKey};
use iroha_data_model::{
    asset::AssetBalanceScope,
    isi::privacy::SubmitPrivacyProofV1,
    prelude::{AccountId, AssetDefinitionId, NetworkId},
    privacy::{
        PrivacyConsensusLimitsV1, PrivacyPolicyIdV1, PrivacyProofBytesV1, PrivacyProofEnvelopeV1,
        PrivacyProofV1, PrivacyProtocolIdV1, PrivacyStatementContextV1, PrivacyStatementV1,
        PrivacyTransactionIntentDigestV1, PrivacyZkAcePolicyLifecycleV1,
        PrivacyZkAcePolicyRecordV1, PrivacyZkAcePolicyRecordValidationErrorV1,
        PrivacyZkAceReplayNullifierV1, ZkAcePqAuthorizationStatementV1,
    },
    transaction::{
        FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionPayload,
        signed::TransactionSignatureError,
    },
    zk::{ZkAcePrivacyPublicInputsV1, derive_zk_ace_privacy_authorization_digest},
};
use iroha_model_base::metadata::Metadata;
/// Exact public-transfer input for the disabled native ZK-ACE candidate.
///
/// The governed policy is owned and validated at construction. Its asset,
/// identity commitment, policy digest, epoch, and source allowlist become the
/// statement; callers cannot supply parallel copies of those fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAcePrivacyTransferV1 {
    policy: PrivacyZkAcePolicyRecordV1,
    source: AccountId,
    destination: AccountId,
    public_balance_scope: AssetBalanceScope,
    amount: u128,
}
impl ZkAcePrivacyTransferV1 {
    /// Construct a canonical candidate transparent transfer.
    ///
    /// This validates the input shape only; the production preparation and
    /// signing APIs remain fail-closed while no compiled profile is available.
    ///
    /// # Errors
    ///
    /// Rejects malformed or revoked policy state, zero value, a self-transfer,
    /// or a source outside the canonical governed allowlist.
    pub fn try_new(
        policy: PrivacyZkAcePolicyRecordV1,
        source: AccountId,
        destination: AccountId,
        public_balance_scope: AssetBalanceScope,
        amount: u128,
    ) -> Result<Self, ZkAcePrivacyActionBuildErrorV1> {
        policy
            .validate()
            .map_err(ZkAcePrivacyActionBuildErrorV1::InvalidPolicy)?;
        if policy.lifecycle != PrivacyZkAcePolicyLifecycleV1::Active {
            return Err(ZkAcePrivacyActionBuildErrorV1::PolicyNotActive);
        }
        if amount == 0 {
            return Err(ZkAcePrivacyActionBuildErrorV1::ZeroAmount);
        }
        if source == destination {
            return Err(ZkAcePrivacyActionBuildErrorV1::SourceEqualsDestination);
        }
        if policy.source_allowlist.binary_search(&source).is_err() {
            return Err(ZkAcePrivacyActionBuildErrorV1::SourceNotAllowed);
        }
        if matches!(
            public_balance_scope,
            AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL)
        ) {
            return Err(ZkAcePrivacyActionBuildErrorV1::UniversalDataspaceScope);
        }
        Ok(Self {
            policy,
            source,
            destination,
            public_balance_scope,
            amount,
        })
    }
    /// Governed policy selected by this transfer.
    #[must_use]
    pub const fn policy(&self) -> &PrivacyZkAcePolicyRecordV1 {
        &self.policy
    }
    /// Exact transparent source account.
    #[must_use]
    pub const fn source(&self) -> &AccountId {
        &self.source
    }
    /// Exact transparent destination account.
    #[must_use]
    pub const fn destination(&self) -> &AccountId {
        &self.destination
    }
    /// Exact transparent balance partition authorized by this transfer.
    #[must_use]
    pub const fn public_balance_scope(&self) -> AssetBalanceScope {
        self.public_balance_scope
    }
    /// Exact atomic amount.
    #[must_use]
    pub const fn amount(&self) -> u128 {
        self.amount
    }
}
/// Exact signature-bound transaction fields for one direct ZK-ACE action.
#[derive(Clone, Debug)]
pub struct ZkAcePrivacyActionTransactionContextV1 {
    /// Exact genesis-header-derived transaction security domain.
    pub network_id: NetworkId,
    /// Exact single-key transaction authority.
    pub authority: AccountId,
    /// Required creation time, resolved once before two-pass construction.
    pub creation_time: Duration,
    /// Optional transaction TTL.
    pub time_to_live: Option<Duration>,
    /// Optional transaction nonce.
    pub nonce: Option<NonZeroU32>,
    /// Exact signature-bound fee payer and maxima.
    pub fee_payment: FeePaymentIntent,
    /// Exact transaction metadata.
    pub metadata: Metadata,
}
/// Validator-visible effect the disabled ZK-ACE candidate would authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAcePrivacyTransferEffectV1 {
    /// Governed policy lineage.
    pub policy_id: PrivacyPolicyIdV1,
    /// Exact authorization epoch.
    pub authorization_epoch: u64,
    /// Transparent source account.
    pub source: AccountId,
    /// Transparent destination account.
    pub destination: AccountId,
    /// Transparent asset definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact transparent balance partition.
    pub public_balance_scope: AssetBalanceScope,
    /// Atomic amount.
    pub amount: u128,
    /// Replay marker consumed atomically with the transfer.
    pub replay_nullifier: PrivacyZkAceReplayNullifierV1,
}
/// Candidate proving output ready for exact-authority signing.
///
/// The final payload remains private so callers cannot add instructions,
/// attachments, or substitute an envelope after proving. Public preparation
/// APIs cannot currently construct this type because the compiled profile is
/// fail-closed.
pub struct ZkAcePreparedPrivacyTransferV1 {
    payload: TransactionPayload,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    effect: ZkAcePrivacyTransferEffectV1,
}
impl core::fmt::Debug for ZkAcePreparedPrivacyTransferV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkAcePreparedPrivacyTransferV1")
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field("effect", &self.effect)
            .finish_non_exhaustive()
    }
}
impl ZkAcePreparedPrivacyTransferV1 {
    /// Canonical proof-empty transaction projection digest.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Digest of the complete protocol-tagged final statement.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Hash of the exact canonical proof envelope.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Exact native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Exact validator-visible transfer and replay effect.
    #[must_use]
    pub const fn effect(&self) -> &ZkAcePrivacyTransferEffectV1 {
        &self.effect
    }
}
/// Complete signed result for the disabled candidate ZK-ACE path.
pub struct SignedZkAcePrivacyTransferV1 {
    signed_transaction: SignedTransaction,
    transaction_hash: [u8; 32],
    adaptive_signed_transaction_bytes: u32,
    transaction_intent_digest: [u8; 32],
    statement_digest: [u8; 32],
    proof_envelope_hash: [u8; 32],
    statement_bytes: u32,
    proof_bytes: u32,
    encoded_proof_envelope_bytes: u32,
    effect: ZkAcePrivacyTransferEffectV1,
}
impl core::fmt::Debug for SignedZkAcePrivacyTransferV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedZkAcePrivacyTransferV1")
            .field("transaction_hash", &self.transaction_hash)
            .field(
                "adaptive_signed_transaction_bytes",
                &self.adaptive_signed_transaction_bytes,
            )
            .field("transaction_intent_digest", &self.transaction_intent_digest)
            .field("statement_digest", &self.statement_digest)
            .field("proof_envelope_hash", &self.proof_envelope_hash)
            .field("statement_bytes", &self.statement_bytes)
            .field("proof_bytes", &self.proof_bytes)
            .field(
                "encoded_proof_envelope_bytes",
                &self.encoded_proof_envelope_bytes,
            )
            .field("effect", &self.effect)
            .finish_non_exhaustive()
    }
}
impl SignedZkAcePrivacyTransferV1 {
    /// Borrow the exact signed transaction.
    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedTransaction {
        &self.signed_transaction
    }
    /// Consume the result and return the exact signed transaction.
    #[must_use]
    pub fn into_signed_transaction(self) -> SignedTransaction {
        self.signed_transaction
    }
    /// Canonical signed transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }
    /// Canonical adaptive signed-transaction byte count.
    #[must_use]
    pub const fn adaptive_signed_transaction_bytes(&self) -> u32 {
        self.adaptive_signed_transaction_bytes
    }
    /// Canonical transaction intent.
    #[must_use]
    pub const fn transaction_intent_digest(&self) -> [u8; 32] {
        self.transaction_intent_digest
    }
    /// Canonical typed statement digest.
    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
    /// Canonical proof envelope hash.
    #[must_use]
    pub const fn proof_envelope_hash(&self) -> [u8; 32] {
        self.proof_envelope_hash
    }
    /// Canonical typed-statement byte count.
    #[must_use]
    pub const fn statement_bytes(&self) -> u32 {
        self.statement_bytes
    }
    /// Exact native proof byte count.
    #[must_use]
    pub const fn proof_bytes(&self) -> u32 {
        self.proof_bytes
    }
    /// Canonical encoded envelope byte count.
    #[must_use]
    pub const fn encoded_proof_envelope_bytes(&self) -> u32 {
        self.encoded_proof_envelope_bytes
    }
    /// Exact validator-visible transfer and replay effect.
    #[must_use]
    pub const fn effect(&self) -> &ZkAcePrivacyTransferEffectV1 {
        &self.effect
    }
}
/// Closed failure set for canonical ZK-ACE preparation and signing.
#[derive(Debug)]
pub enum ZkAcePrivacyActionBuildErrorV1 {
    /// The governed record is malformed or its self-digest was tampered.
    InvalidPolicy(PrivacyZkAcePolicyRecordValidationErrorV1),
    /// A revoked policy cannot authorize a new action.
    PolicyNotActive,
    /// The atomic transfer amount is zero.
    ZeroAmount,
    /// A self-transfer is not a canonical authorization action.
    SourceEqualsDestination,
    /// The source is absent from the governed sorted allowlist.
    SourceNotAllowed,
    /// The universal coordinator is a route, never a restricted balance partition.
    UniversalDataspaceScope,
    /// The witness does not open the governed identity commitment.
    IdentityCommitmentMismatch,
    /// The caller supplied the all-zero genesis sentinel.
    ZeroGenesisHash,
    /// The signed transaction domain differs from the supplied canonical genesis hash.
    NetworkIdMismatch,
    /// Creation time cannot be represented in the transaction wire.
    CreationTimeOutOfRange,
    /// TTL cannot be represented in the transaction wire.
    TimeToLiveOutOfRange,
    /// Fee intent or metadata violates canonical transaction policy.
    InvalidTransactionContext,
    /// The locally compiled native profile is unavailable.
    CompiledProfileUnavailable,
    /// The replay-nullifier authorization projection could not be encoded.
    AuthorizationDigest,
    /// Native proving or entropy preflight failed.
    Native(ZkAceNativeErrorV1),
    /// The unsigned payload could not derive a canonical intent.
    TransactionIntent,
    /// The final typed statement could not derive its digest.
    StatementDigest,
    /// Canonical statement encoding failed.
    StatementEncoding,
    /// Intrinsic envelope validation rejected locally produced output.
    EnvelopeValidation,
    /// The final payload did not reproduce the draft-derived intent.
    FinalIntentBinding,
    /// Canonical envelope encoding failed.
    EnvelopeEncoding,
    /// A canonical byte length overflowed its bounded result field.
    EncodedLengthOverflow,
    /// The authority is multisig and unsupported by this constructor.
    UnsupportedAuthority,
    /// The supplied private key does not control the exact authority.
    AuthorityKeyMismatch,
    /// The signature backend failed without exposing key material.
    TransactionSigning,
    /// The signed payload no longer carries the prepared intent.
    SignedIntentMismatch,
}
impl core::fmt::Display for ZkAcePrivacyActionBuildErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPolicy(error) => {
                write!(formatter, "ZK-ACE policy record is invalid: {error}")
            }
            Self::Native(error) => write!(formatter, "native ZK-ACE proving failed: {error}"),
            other => formatter.write_str(match other {
                Self::PolicyNotActive => "ZK-ACE policy is not active",
                Self::ZeroAmount => "ZK-ACE transfer amount must be non-zero",
                Self::SourceEqualsDestination => "ZK-ACE source and destination must differ",
                Self::SourceNotAllowed => "ZK-ACE source is not authorized by the policy",
                Self::UniversalDataspaceScope => {
                    "ZK-ACE public balance scope cannot be the universal dataspace"
                }
                Self::IdentityCommitmentMismatch => {
                    "ZK-ACE witness identity commitment differs from the governed policy"
                }
                Self::ZeroGenesisHash => "ZK-ACE action requires a non-zero canonical genesis hash",
                Self::NetworkIdMismatch => {
                    "ZK-ACE action transaction network does not match the canonical genesis hash"
                }
                Self::CreationTimeOutOfRange => {
                    "ZK-ACE action creation time cannot be represented in milliseconds"
                }
                Self::TimeToLiveOutOfRange => {
                    "ZK-ACE action TTL cannot be represented in milliseconds"
                }
                Self::InvalidTransactionContext => {
                    "ZK-ACE action transaction context is not canonical"
                }
                Self::CompiledProfileUnavailable => {
                    "the compiled native ZK-ACE profile is unavailable"
                }
                Self::AuthorizationDigest => "ZK-ACE authorization projection could not be encoded",
                Self::TransactionIntent => "ZK-ACE transaction-intent derivation failed",
                Self::StatementDigest => "ZK-ACE statement digest derivation failed",
                Self::StatementEncoding => {
                    "the locally produced ZK-ACE statement could not be encoded"
                }
                Self::EnvelopeValidation => {
                    "the locally produced ZK-ACE proof envelope failed validation"
                }
                Self::FinalIntentBinding => {
                    "the locally produced ZK-ACE payload failed intent validation"
                }
                Self::EnvelopeEncoding => {
                    "the locally produced ZK-ACE proof envelope could not be encoded"
                }
                Self::EncodedLengthOverflow => "a canonical ZK-ACE action byte length overflowed",
                Self::UnsupportedAuthority => {
                    "the ZK-ACE action authority is not a single-key authority"
                }
                Self::AuthorityKeyMismatch => {
                    "the supplied ZK-ACE signing key does not control the authority"
                }
                Self::TransactionSigning => "ZK-ACE transaction signing failed",
                Self::SignedIntentMismatch => {
                    "signed ZK-ACE action intent differs from the prepared intent"
                }
                Self::InvalidPolicy(_) | Self::Native(_) => {
                    unreachable!("formatted in the outer match")
                }
            }),
        }
    }
}
impl std::error::Error for ZkAcePrivacyActionBuildErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ZkAceNativeErrorV1> for ZkAcePrivacyActionBuildErrorV1 {
    fn from(error: ZkAceNativeErrorV1) -> Self {
        Self::Native(error)
    }
}
fn validate_transaction_context_v1(
    context: &ZkAcePrivacyActionTransactionContextV1,
) -> Result<(), ZkAcePrivacyActionBuildErrorV1> {
    if context.creation_time.as_millis() > u128::from(u64::MAX) {
        return Err(ZkAcePrivacyActionBuildErrorV1::CreationTimeOutOfRange);
    }
    if context
        .time_to_live
        .is_some_and(|ttl| ttl.as_millis() > u128::from(u64::MAX))
    {
        return Err(ZkAcePrivacyActionBuildErrorV1::TimeToLiveOutOfRange);
    }
    transaction_payload_without_instructions_v1(context)
        .map(|_| ())
        .map_err(|()| ZkAcePrivacyActionBuildErrorV1::InvalidTransactionContext)
}
fn transaction_payload_without_instructions_v1(
    context: &ZkAcePrivacyActionTransactionContextV1,
) -> Result<TransactionPayload, ()> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder.into_payload().map_err(|_| ())
}
fn validate_signing_authority_v1(
    authority: &AccountId,
    private_key: &PrivateKey,
) -> Result<(), ZkAcePrivacyActionBuildErrorV1> {
    let expected = authority
        .try_signatory()
        .ok_or(ZkAcePrivacyActionBuildErrorV1::UnsupportedAuthority)?;
    let derived = PublicKey::from(private_key.clone());
    if expected != &derived {
        return Err(ZkAcePrivacyActionBuildErrorV1::AuthorityKeyMismatch);
    }
    Ok(())
}
fn transaction_payload_v1(
    context: &ZkAcePrivacyActionTransactionContextV1,
    envelope: PrivacyProofEnvelopeV1,
) -> Result<TransactionPayload, ZkAcePrivacyActionBuildErrorV1> {
    let mut builder = TransactionBuilder::new(
        context.network_id,
        context.authority.clone(),
        context.fee_payment.clone(),
    )
    .with_instructions([SubmitPrivacyProofV1::new(envelope)])
    .with_metadata(context.metadata.clone());
    builder.set_creation_time(context.creation_time);
    if let Some(ttl) = context.time_to_live {
        builder.set_ttl(ttl);
    }
    if let Some(nonce) = context.nonce {
        builder.set_nonce(nonce);
    }
    builder
        .into_payload()
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::InvalidTransactionContext)
}
/// Bind the proof-free envelope used only to derive the transaction intent.
fn placeholder_envelope_v1(
    statement: PrivacyStatementV1,
) -> Result<PrivacyProofEnvelopeV1, ZkAcePrivacyActionBuildErrorV1> {
    PrivacyProofEnvelopeV1::bind_v1(
        statement,
        PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(Vec::new())),
    )
    .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EnvelopeValidation)
}
fn prepare_zk_ace_privacy_transfer_with_prover_v1<F>(
    context: &ZkAcePrivacyActionTransactionContextV1,
    transfer: ZkAcePrivacyTransferV1,
    witness: &ZkAcePrivacyWitnessV1,
    canonical_genesis_hash: [u8; 32],
    prove: F,
) -> Result<ZkAcePreparedPrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1>
where
    F: FnOnce(
        &ZkAcePrivacyPublicInputsV1,
        &ZkAcePrivacyWitnessV1,
    ) -> Result<Vec<u8>, ZkAceNativeErrorV1>,
{
    if canonical_genesis_hash == [0; 32] {
        return Err(ZkAcePrivacyActionBuildErrorV1::ZeroGenesisHash);
    }
    if context.network_id.as_bytes() != &canonical_genesis_hash {
        return Err(ZkAcePrivacyActionBuildErrorV1::NetworkIdMismatch);
    }
    validate_transaction_context_v1(context)?;
    transfer
        .policy
        .validate()
        .map_err(ZkAcePrivacyActionBuildErrorV1::InvalidPolicy)?;
    if transfer.policy.lifecycle != PrivacyZkAcePolicyLifecycleV1::Active {
        return Err(ZkAcePrivacyActionBuildErrorV1::PolicyNotActive);
    }
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::ZkAcePqAuthorizationV1)
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable)?;
    validate_identity_commitment_v1(&transfer, witness)?;
    let native_statement = ZkAcePqAuthorizationStatementV1 {
        context: PrivacyStatementContextV1 {
            network_id: context.network_id,
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0; 32]),
            parameter_id: profile.parameter_id,
            parameter_digest: profile.parameter_digest,
            verifier_digest: profile.verifier_digest,
            statement_schema_digest: profile.statement_schema_digest,
            engine_manifest_digest: profile.engine_manifest_digest,
        },
        identity_commitment: transfer.policy.identity_commitment,
        policy_id: transfer.policy.policy_id,
        policy_digest: transfer.policy.policy_digest,
        source: transfer.source.clone(),
        destination: transfer.destination.clone(),
        asset_definition_id: transfer.policy.asset_definition_id.clone(),
        public_balance_scope: transfer.public_balance_scope,
        amount: transfer.amount,
        authorization_epoch: transfer.policy.authorization_epoch,
        replay_nullifier: PrivacyZkAceReplayNullifierV1::default(),
    };
    let draft_statement = PrivacyStatementV1::ZkAcePqAuthorizationV1(native_statement.clone());
    let draft_payload = transaction_payload_v1(context, placeholder_envelope_v1(draft_statement)?)?;
    let transaction_intent_digest = draft_payload
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::TransactionIntent)?;
    let mut final_statement = native_statement;
    final_statement.context.transaction_intent_digest = transaction_intent_digest;
    let authorization_inputs =
        ZkAcePrivacyPublicInputsV1::new(final_statement.clone(), canonical_genesis_hash);
    let authorization_digest = derive_zk_ace_privacy_authorization_digest(&authorization_inputs)
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::AuthorizationDigest)?;
    final_statement.replay_nullifier =
        witness.replay_nullifier_v1(&authorization_digest, &context.network_id);
    let typed_statement = PrivacyStatementV1::ZkAcePqAuthorizationV1(final_statement.clone());
    let statement_digest = typed_statement
        .digest()
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::StatementDigest)?;
    let statement_bytes = u32::try_from(
        norito::to_bytes(&typed_statement)
            .map_err(|_| ZkAcePrivacyActionBuildErrorV1::StatementEncoding)?
            .len(),
    )
    .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let public_inputs =
        ZkAcePrivacyPublicInputsV1::new(final_statement.clone(), canonical_genesis_hash);
    let proof = prove(&public_inputs, witness)?;
    let proof_bytes = u32::try_from(proof.len())
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    if proof_bytes != ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1 {
        return Err(ZkAcePrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    let final_envelope = PrivacyProofEnvelopeV1::bind_v1(
        typed_statement,
        PrivacyProofV1::ZkAcePqAuthorizationV1(PrivacyProofBytesV1::new(proof)),
    )
    .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EnvelopeValidation)?;
    if !profile.matches_envelope_v1(&final_envelope) {
        return Err(ZkAcePrivacyActionBuildErrorV1::EnvelopeValidation);
    }
    final_envelope
        .validate_with_limits(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EnvelopeValidation)?;
    let envelope_encoding = norito::to_bytes(&final_envelope)
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EnvelopeEncoding)?;
    let encoded_proof_envelope_bytes = u32::try_from(envelope_encoding.len())
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    let proof_envelope_hash = *Hash::new(&envelope_encoding).as_ref();
    let final_payload = transaction_payload_v1(context, final_envelope)?;
    let validated_intent = final_payload
        .validate_privacy_transaction_intent_binding_v1()
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::FinalIntentBinding)?;
    if validated_intent != transaction_intent_digest {
        return Err(ZkAcePrivacyActionBuildErrorV1::FinalIntentBinding);
    }
    let effect = ZkAcePrivacyTransferEffectV1 {
        policy_id: transfer.policy.policy_id,
        authorization_epoch: transfer.policy.authorization_epoch,
        source: transfer.source,
        destination: transfer.destination,
        asset_definition_id: transfer.policy.asset_definition_id,
        public_balance_scope: transfer.public_balance_scope,
        amount: transfer.amount,
        replay_nullifier: final_statement.replay_nullifier,
    };
    Ok(ZkAcePreparedPrivacyTransferV1 {
        payload: final_payload,
        transaction_intent_digest: *transaction_intent_digest.as_bytes(),
        statement_digest: *statement_digest.as_bytes(),
        proof_envelope_hash,
        statement_bytes,
        proof_bytes,
        encoded_proof_envelope_bytes,
        effect,
    })
}
fn validate_identity_commitment_v1(
    transfer: &ZkAcePrivacyTransferV1,
    witness: &ZkAcePrivacyWitnessV1,
) -> Result<(), ZkAcePrivacyActionBuildErrorV1> {
    if witness.identity_commitment_v1() != transfer.policy.identity_commitment {
        return Err(ZkAcePrivacyActionBuildErrorV1::IdentityCommitmentMismatch);
    }
    Ok(())
}

/// Validate one direct ZK-ACE candidate transfer and fail closed before proving.
///
/// # Errors
///
/// Fails closed for invalid public policy, context or genesis. While the profile
/// is unavailable, returns
/// [`ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable`] before hashing
/// the witness or using `randomness`. The final qROM Fiat-Shamir reduction, six-lane collision
/// and multi-target accounting, and independent implementation review remain
/// unregistered for the exact compiled profile.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the owning convenience API keeps transfer inputs uniform"
)]
pub fn prepare_zk_ace_privacy_transfer_with_rng_v1<R: ZkAceTryCryptoRngV1 + ?Sized>(
    context: ZkAcePrivacyActionTransactionContextV1,
    transfer: ZkAcePrivacyTransferV1,
    witness: ZkAcePrivacyWitnessV1,
    canonical_genesis_hash: [u8; 32],
    randomness: &mut R,
) -> Result<ZkAcePreparedPrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1> {
    prepare_zk_ace_privacy_transfer_with_prover_v1(
        &context,
        transfer,
        &witness,
        canonical_genesis_hash,
        |public_inputs, witness| {
            prove_zk_ace_privacy_v1_with_rng(public_inputs, witness, randomness)
        },
    )
}
/// Validate one direct ZK-ACE candidate transfer and fail closed before using
/// operating-system entropy.
///
/// # Errors
///
/// Returns [`ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable`] for
/// an otherwise valid request while the candidate engine is disabled.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the owning convenience API keeps transfer inputs uniform"
)]
pub fn prepare_zk_ace_privacy_transfer_v1(
    context: ZkAcePrivacyActionTransactionContextV1,
    transfer: ZkAcePrivacyTransferV1,
    witness: ZkAcePrivacyWitnessV1,
    canonical_genesis_hash: [u8; 32],
) -> Result<ZkAcePreparedPrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1> {
    prepare_zk_ace_privacy_transfer_with_prover_v1(
        &context,
        transfer,
        &witness,
        canonical_genesis_hash,
        prove_zk_ace_privacy_v1,
    )
}
/// Sign an exact prepared ZK-ACE payload.
///
/// # Errors
///
/// Returns an error when the authority, signature, intent, or encoding is invalid.
pub fn sign_prepared_zk_ace_privacy_transfer_v1(
    prepared: ZkAcePreparedPrivacyTransferV1,
    private_key: &PrivateKey,
) -> Result<SignedZkAcePrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1> {
    validate_signing_authority_v1(prepared.payload.authority(), private_key)?;
    let expected_intent = prepared.transaction_intent_digest;
    let signed_transaction = TransactionBuilder::from_payload(prepared.payload)
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::InvalidTransactionContext)?
        .try_sign(private_key)
        .map_err(|error| match error {
            TransactionSignatureError::UnsupportedMultisigAuthority => {
                ZkAcePrivacyActionBuildErrorV1::UnsupportedAuthority
            }
            TransactionSignatureError::AuthorityKeyMismatch => {
                ZkAcePrivacyActionBuildErrorV1::AuthorityKeyMismatch
            }
            TransactionSignatureError::InvalidFeePaymentIntent(_) => {
                ZkAcePrivacyActionBuildErrorV1::InvalidTransactionContext
            }
            _ => ZkAcePrivacyActionBuildErrorV1::TransactionSigning,
        })?;
    let signed_intent = signed_transaction
        .privacy_transaction_intent_digest_v1()
        .map_err(|_| ZkAcePrivacyActionBuildErrorV1::SignedIntentMismatch)?;
    if signed_intent.as_bytes() != &expected_intent {
        return Err(ZkAcePrivacyActionBuildErrorV1::SignedIntentMismatch);
    }
    let transaction_hash = *signed_transaction.hash().as_ref();
    let adaptive_signed_transaction_bytes =
        u32::try_from(norito::codec::encode_adaptive(&signed_transaction).len())
            .map_err(|_| ZkAcePrivacyActionBuildErrorV1::EncodedLengthOverflow)?;
    Ok(SignedZkAcePrivacyTransferV1 {
        signed_transaction,
        transaction_hash,
        adaptive_signed_transaction_bytes,
        transaction_intent_digest: expected_intent,
        statement_digest: prepared.statement_digest,
        proof_envelope_hash: prepared.proof_envelope_hash,
        statement_bytes: prepared.statement_bytes,
        proof_bytes: prepared.proof_bytes,
        encoded_proof_envelope_bytes: prepared.encoded_proof_envelope_bytes,
        effect: prepared.effect,
    })
}
/// Validate a signed ZK-ACE candidate request and fail closed before proving.
///
/// # Errors
///
/// Returns [`ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable`] for
/// an otherwise valid request after signing-authority preflight and before
/// entropy or proof work.
pub fn build_signed_zk_ace_privacy_transfer_with_rng_v1<R: ZkAceTryCryptoRngV1 + ?Sized>(
    context: ZkAcePrivacyActionTransactionContextV1,
    transfer: ZkAcePrivacyTransferV1,
    witness: ZkAcePrivacyWitnessV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
    randomness: &mut R,
) -> Result<SignedZkAcePrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1> {
    validate_signing_authority_v1(&context.authority, private_key)?;
    let prepared = prepare_zk_ace_privacy_transfer_with_rng_v1(
        context,
        transfer,
        witness,
        canonical_genesis_hash,
        randomness,
    )?;
    sign_prepared_zk_ace_privacy_transfer_v1(prepared, private_key)
}
/// Validate a signed ZK-ACE candidate request and fail closed before proving.
///
/// # Errors
///
/// Returns [`ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable`] for
/// an otherwise valid request after signing-authority preflight and before
/// operating-system entropy or proof work.
pub fn build_signed_zk_ace_privacy_transfer_v1(
    context: ZkAcePrivacyActionTransactionContextV1,
    transfer: ZkAcePrivacyTransferV1,
    witness: ZkAcePrivacyWitnessV1,
    canonical_genesis_hash: [u8; 32],
    private_key: &PrivateKey,
) -> Result<SignedZkAcePrivacyTransferV1, ZkAcePrivacyActionBuildErrorV1> {
    validate_signing_authority_v1(&context.authority, private_key)?;
    let prepared =
        prepare_zk_ace_privacy_transfer_v1(context, transfer, witness, canonical_genesis_hash)?;
    sign_prepared_zk_ace_privacy_transfer_v1(prepared, private_key)
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core_privacy::privacy_engines::zk_ace::ZkAceTryRngCoreV1;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::privacy::{
        PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1, PrivacyPolicyDigestV1,
        PrivacyZkAceIdentityCommitmentV1, PrivacyZkAcePolicyRecordDigestV1,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use std::str::FromStr as _;
    fn key_pair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive deterministic ZK-ACE test key")
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(key_pair(seed).public_key().clone())
    }
    fn asset(name: &str) -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("test domain"),
            Name::from_str(name).expect("asset name"),
        )
    }
    fn witness(seed: u8) -> ZkAcePrivacyWitnessV1 {
        ZkAcePrivacyWitnessV1::try_new(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
        )
        .expect("valid test witness")
    }
    fn policy(witness: &ZkAcePrivacyWitnessV1, source: AccountId) -> PrivacyZkAcePolicyRecordV1 {
        PrivacyZkAcePolicyRecordV1::new(
            PrivacyPolicyIdV1::new([0x41; 32]),
            witness.identity_commitment_v1(),
            PrivacyPolicyDigestV1::new([0x42; 32]),
            PRIVACY_ZK_ACE_POLICY_INITIAL_EPOCH_V1,
            asset("zkace"),
            vec![source],
            PrivacyZkAcePolicyLifecycleV1::Active,
        )
        .expect("valid ZK-ACE policy")
    }
    fn context(authority: AccountId) -> ZkAcePrivacyActionTransactionContextV1 {
        ZkAcePrivacyActionTransactionContextV1 {
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([0x77; 32])
            )),
            authority,
            creation_time: Duration::from_secs(1_700_000_000),
            time_to_live: Some(Duration::from_secs(3_600)),
            nonce: NonZeroU32::new(7),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            metadata: Metadata::default(),
        }
    }
    fn transfer_and_witness() -> (ZkAcePrivacyTransferV1, ZkAcePrivacyWitnessV1) {
        let source = account(1);
        let witness = witness(0x11);
        let transfer = ZkAcePrivacyTransferV1::try_new(
            policy(&witness, source.clone()),
            source,
            account(2),
            AssetBalanceScope::Global,
            19,
        )
        .expect("valid transfer");
        (transfer, witness)
    }
    #[derive(Debug)]
    struct InjectedEntropyError;
    impl core::fmt::Display for InjectedEntropyError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected entropy failure")
        }
    }
    struct PanicEntropyRng;
    impl ZkAceTryRngCoreV1 for PanicEntropyRng {
        type Error = InjectedEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("fail-closed ZK-ACE request reached entropy")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("fail-closed ZK-ACE request reached entropy")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            panic!("fail-closed ZK-ACE request reached entropy")
        }
    }
    impl ZkAceTryCryptoRngV1 for PanicEntropyRng {}
    #[test]
    fn witness_is_closed_nonzero_secret_state() {
        for (root, blinding, replay, expected) in [
            (
                [0; 32],
                [1; 32],
                [2; 32],
                ZkAcePrivacyWitnessValidationErrorV1::ZeroIdentityRoot,
            ),
            (
                [1; 32],
                [0; 32],
                [2; 32],
                ZkAcePrivacyWitnessValidationErrorV1::ZeroIdentityBlinding,
            ),
            (
                [1; 32],
                [2; 32],
                [0; 32],
                ZkAcePrivacyWitnessValidationErrorV1::ZeroReplaySecret,
            ),
        ] {
            assert!(matches!(
                ZkAcePrivacyWitnessV1::try_new(root, blinding, replay),
                Err(actual) if actual == expected
            ));
        }
    }
    #[test]
    fn transfer_constructor_rejects_policy_and_action_ambiguity() {
        let source = account(1);
        let destination = account(2);
        let witness = witness(0x11);
        let active = policy(&witness, source.clone());
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                active.clone(),
                source.clone(),
                destination.clone(),
                AssetBalanceScope::Global,
                0,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::ZeroAmount)
        ));
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                active.clone(),
                source.clone(),
                source.clone(),
                AssetBalanceScope::Global,
                1,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::SourceEqualsDestination)
        ));
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                active.clone(),
                account(3),
                destination.clone(),
                AssetBalanceScope::Global,
                1,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::SourceNotAllowed)
        ));
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                active.clone(),
                source.clone(),
                destination.clone(),
                AssetBalanceScope::Dataspace(iroha_model_base::topology::DataSpaceId::UNIVERSAL,),
                1,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::UniversalDataspaceScope)
        ));
        let revoked = PrivacyZkAcePolicyRecordV1::new(
            active.policy_id,
            active.identity_commitment,
            active.policy_digest,
            active.authorization_epoch + 1,
            active.asset_definition_id.clone(),
            active.source_allowlist.clone(),
            PrivacyZkAcePolicyLifecycleV1::Revoked,
        )
        .expect("self-consistent revoked record");
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                revoked,
                source.clone(),
                destination.clone(),
                AssetBalanceScope::Global,
                1,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::PolicyNotActive)
        ));
        let mut tampered = active;
        tampered.record_digest = PrivacyZkAcePolicyRecordDigestV1::new([0xA5; 32]);
        assert!(matches!(
            ZkAcePrivacyTransferV1::try_new(
                tampered,
                source,
                destination,
                AssetBalanceScope::Global,
                1,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::InvalidPolicy(_))
        ));
    }
    #[test]
    fn deterministic_failures_precede_entropy_and_signing_key_is_preflighted() {
        let authority = account(1);
        let (transfer, _) = transfer_and_witness();
        let wrong_witness = witness(0x31);
        assert!(matches!(
            prepare_zk_ace_privacy_transfer_with_rng_v1(
                context(authority.clone()),
                transfer,
                wrong_witness,
                [0x77; 32],
                &mut PanicEntropyRng,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable)
        ));
        let (transfer, witness) = transfer_and_witness();
        assert!(matches!(
            prepare_zk_ace_privacy_transfer_with_rng_v1(
                context(authority.clone()),
                transfer,
                witness,
                [0; 32],
                &mut PanicEntropyRng,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::ZeroGenesisHash)
        ));
        let (transfer, witness) = transfer_and_witness();
        assert!(matches!(
            build_signed_zk_ace_privacy_transfer_with_rng_v1(
                context(authority),
                transfer,
                witness,
                [0x77; 32],
                key_pair(9).private_key(),
                &mut PanicEntropyRng,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::AuthorityKeyMismatch)
        ));
    }
    #[test]
    fn identity_binding_rejects_wrong_witness_independently_of_engine_availability() {
        let (transfer, valid_witness) = transfer_and_witness();
        assert!(validate_identity_commitment_v1(&transfer, &valid_witness).is_ok());
        assert!(matches!(
            validate_identity_commitment_v1(&transfer, &witness(0x31)),
            Err(ZkAcePrivacyActionBuildErrorV1::IdentityCommitmentMismatch)
        ));
    }
    #[test]
    fn otherwise_valid_preparation_fails_before_entropy() {
        let (transfer, witness) = transfer_and_witness();
        assert!(matches!(
            prepare_zk_ace_privacy_transfer_with_rng_v1(
                context(account(1)),
                transfer,
                witness,
                [0x77; 32],
                &mut PanicEntropyRng,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable)
        ));
        let (transfer, witness) = transfer_and_witness();
        assert!(matches!(
            build_signed_zk_ace_privacy_transfer_with_rng_v1(
                context(account(1)),
                transfer,
                witness,
                [0x77; 32],
                key_pair(1).private_key(),
                &mut PanicEntropyRng,
            ),
            Err(ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable)
        ));
        let protocol_id = PrivacyProtocolIdV1::ZkAcePqAuthorizationV1;
        assert!(matches!(
            compiled_privacy_profile_v1(protocol_id),
            Err(iroha_core_privacy::privacy_profiles::CompiledPrivacyProfileErrorV1::EngineUnavailable {
                protocol_id: rejected,
            }) if rejected == protocol_id
        ));
    }
    #[test]
    fn operating_system_preparation_is_also_fail_closed() {
        let (transfer, witness) = transfer_and_witness();
        assert!(matches!(
            prepare_zk_ace_privacy_transfer_v1(context(account(1)), transfer, witness, [0x77; 32],),
            Err(ZkAcePrivacyActionBuildErrorV1::CompiledProfileUnavailable)
        ));
    }
    #[test]
    fn explicit_policy_commitment_fixture_is_nonzero() {
        let witness = witness(0x21);
        let commitment: PrivacyZkAceIdentityCommitmentV1 = witness.identity_commitment_v1();
        assert!(!commitment.is_zero());
    }
}
