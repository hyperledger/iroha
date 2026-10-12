//! Canonical public statement claimed by one proved IVM execution.
//!
//! These values bind a proof's public inputs. Constructing or hashing a value
//! here does not establish finality, state completeness, or execution validity.
// TODO: Connect this public statement to a verified Core State/Kura/QC/DA
// anchor and a complete masked IVM AIR/FRI relation before private admission.

use crate::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    smart_contract::ContractAddress,
    transaction::{
        FeePaymentIntent, SignedTransaction,
        executable::ContractArgumentRecord,
        signed::{IvmProvedTransactionIntentDigestV1, IvmProvedTransactionIntentErrorV1},
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_schema::{Ident, IntoSchema};
use norito::codec::{Decode, Encode};
use thiserror::Error;

use super::VerifyingKeyId;

/// Domain separator for the canonical public execution-statement digest.
pub const IVM_EXECUTION_STATEMENT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.ivm.execution-statement.v1";

/// A claimed complete State-owned root at a finalized block.
///
/// The distinct type prevents accidental substitution of a witness-subset or
/// transfer-batch root at API boundaries. This is still only a public claim:
/// a future Core-owned handle must establish State/Kura/QC/DA ownership before
/// the root can authorize execution or an AXT spend.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::proof::IvmCompleteStateRootClaimV1")]
pub struct IvmCompleteStateRootClaimV1([u8; 32]);

impl IvmCompleteStateRootClaimV1 {
    /// Construct an unverified public root claim from its exact bytes.
    #[must_use]
    pub const fn claimed(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the claimed complete-root bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Claimed finalized prestate and execution context for one proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmFinalizedPrestateClaimV1")]
pub struct IvmFinalizedPrestateClaimV1 {
    /// Exact finalized block whose state precedes execution.
    pub block_hash: HashOf<BlockHeader>,
    /// Finalized block height.
    pub block_height: u64,
    /// Claimed root over every authoritative persisted execution table.
    pub complete_state_root: IvmCompleteStateRootClaimV1,
    /// Exact consensus height-context commitment.
    pub height_context_hash: Hash,
    /// Exact deterministic IVM environment and block-context commitment.
    pub execution_context_hash: Hash,
    /// Commitment to the finality certificate that owns this anchor.
    pub finality_qc_hash: Hash,
    /// Commitment to the mandatory signed DA/RBC manifest.
    pub da_manifest_hash: Hash,
}

/// Commitment to the claimed complete ordered access-dependency transcript.
///
/// The transcript must cover all point reads, absences, range rows and writes.
/// A complete execution relation must prove that no dependency was omitted;
/// this data-model commitment alone cannot prove that property.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmAccessDependencyClaimV1")]
pub struct IvmAccessDependencyClaimV1 {
    /// Canonical commitment to all ordered access descriptors and observations.
    pub complete_transcript_hash: Hash,
    /// Number of point inclusion or absence observations.
    pub point_read_count: u32,
    /// Number of complete bounded range observations.
    pub range_read_count: u32,
    /// Number of ordered writes or deletes.
    pub write_count: u32,
}

/// Public result-table claim for the final ABI V1 return convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmReturnClaimV1")]
pub struct IvmReturnClaimV1 {
    /// Exact number of initialized result words, at most 8,192.
    pub initialized_word_count: u16,
    /// Commitment to the ordered, typed canonical public return record.
    pub canonical_record_hash: Hash,
}

/// Claimed ordered public effects or events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmOrderedOutputClaimV1")]
pub struct IvmOrderedOutputClaimV1 {
    /// Exact number of ordered items.
    pub item_count: u32,
    /// Commitment to the canonical ordered payload, including empty output.
    pub canonical_payload_hash: Hash,
}

/// The exact verifier relation and registered key authorized for this proof.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmVerifierProfileV1")]
pub struct IvmVerifierProfileV1 {
    /// Proving backend and proof format.
    pub backend: Ident,
    /// Pinned digest of the complete execution relation and verifier parameters.
    pub relation_digest: Hash,
    /// Registered verifier key identity.
    pub verifying_key_id: VerifyingKeyId,
    /// Exact registered verifier key commitment.
    pub verifying_key_commitment: Hash,
}

/// Final V1 public statement for a native IVM execution proof.
///
/// The normalized signed intent binds all independent transaction fields while
/// avoiding a cycle through proof bytes and proof-derived outputs. The remaining
/// fields bind the exact claimed execution. Core must compare them with current
/// signed authority, fee, code, finalized context and state dependencies, then
/// verify the complete IVM relation before applying effects. There is no
/// binding-only production proof path.
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::proof::IvmExecutionStatementV1")]
pub struct IvmExecutionStatementV1 {
    /// Exact genesis-header-derived network identity.
    pub network_id: NetworkId,
    /// Canonical signed payload with only proof-derived fields normalized.
    pub normalized_signed_intent: IvmProvedTransactionIntentDigestV1,
    /// Exact signed transaction authority.
    pub authority: AccountId,
    /// Exact signed fee payer, charge limits and gas limit.
    pub fee_payment: FeePaymentIntent,
    /// Exact deployed instance called by this execution.
    pub contract_address: ContractAddress,
    /// Exact active code hash and final ABI V1 manifest hash.
    pub code_hash: Hash,
    /// Final first-release ABI number; only 1 is valid.
    pub abi_version: u16,
    /// Exact ABI and syscall descriptor hash.
    pub abi_hash: Hash,
    /// Exact entrypoint selector.
    pub selector: String,
    /// Canonical public argument record, when the entrypoint takes arguments.
    pub public_arguments: Option<ContractArgumentRecord>,
    /// Claimed finalized complete prestate and context.
    pub finalized_prestate: IvmFinalizedPrestateClaimV1,
    /// Claimed complete point, range and write dependencies.
    pub access_dependencies: IvmAccessDependencyClaimV1,
    /// Exact public ABI result count and ordered return-record commitment.
    pub returns: IvmReturnClaimV1,
    /// Ordered transactional effect commitment.
    pub effects: IvmOrderedOutputClaimV1,
    /// Ordered deterministic event commitment.
    pub events: IvmOrderedOutputClaimV1,
    /// Exact public gas consumed by the proved execution.
    pub exact_gas_used: u64,
    /// Pinned verifier profile, relation and key.
    pub verifier_profile: IvmVerifierProfileV1,
}

/// Digest of the canonical V1 public statement.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::proof::IvmExecutionStatementDigestV1")]
pub struct IvmExecutionStatementDigestV1([u8; 32]);

impl IvmExecutionStatementDigestV1 {
    /// Return the fixed-width digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Failure to form a canonical, bounded V1 execution-statement digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IvmExecutionStatementErrorV1 {
    /// The statement advertises an ABI other than the only first-release ABI.
    #[error("IVM execution statement requires ABI V1")]
    WrongAbi,
    /// The claimed result table exceeds the 8,192-word ABI ceiling.
    #[error("IVM execution statement result table exceeds 8,192 words")]
    ResultTableTooLarge,
    /// The entrypoint selector is absent.
    #[error("IVM execution statement requires an entrypoint selector")]
    EmptySelector,
    /// Canonical Norito encoding failed.
    #[error("canonical IVM execution statement encoding failed")]
    EncodingFailure,
    /// Canonical byte length does not fit the digest frame.
    #[error("IVM execution statement length overflow")]
    LengthOverflow,
}

impl IvmExecutionStatementV1 {
    /// Check the fixed first-release public shape before hashing or admission.
    ///
    /// This checks only local syntax and ABI bounds. It does not establish a
    /// finalized anchor, complete state, or sound proof.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-V1 ABI, oversized result table or empty selector.
    pub fn validate_shape(&self) -> Result<(), IvmExecutionStatementErrorV1> {
        if self.abi_version != 1 {
            return Err(IvmExecutionStatementErrorV1::WrongAbi);
        }
        if usize::from(self.returns.initialized_word_count)
            > crate::smart_contract::entrypoint::MAX_ENTRYPOINT_RETURN_WORDS
        {
            return Err(IvmExecutionStatementErrorV1::ResultTableTooLarge);
        }
        if self.selector.is_empty() {
            return Err(IvmExecutionStatementErrorV1::EmptySelector);
        }
        Ok(())
    }

    /// Compare duplicated public signed fields with one proved transaction.
    ///
    /// This is a binding check, not permission to execute or apply effects.
    /// Core must also validate the remaining fields and the complete relation.
    ///
    /// # Errors
    ///
    /// Returns an error when the signed payload has no canonical proved intent.
    pub fn matches_signed_transaction(
        &self,
        signed: &SignedTransaction,
    ) -> Result<bool, IvmProvedTransactionIntentErrorV1> {
        let signed_intent = signed.ivm_proved_intent_digest_v1()?;
        Ok(signed.network_id() == Some(&self.network_id)
            && signed.authority() == &self.authority
            && signed.fee_payment_intent() == &self.fee_payment
            && signed_intent == self.normalized_signed_intent)
    }

    /// Hash the complete canonical public statement under its V1 domain.
    ///
    /// Ambient Norito packed-layout flags do not change this digest. The
    /// canonical bytes are length-framed before BLAKE3 hashing.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed V1 shape or canonical encoding failure.
    pub fn digest(&self) -> Result<IvmExecutionStatementDigestV1, IvmExecutionStatementErrorV1> {
        self.validate_shape()?;
        let encoded = norito::encode_canonical(self)
            .map_err(|_| IvmExecutionStatementErrorV1::EncodingFailure)?;
        let length = u64::try_from(encoded.len())
            .map_err(|_| IvmExecutionStatementErrorV1::LengthOverflow)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(IVM_EXECUTION_STATEMENT_DIGEST_DOMAIN_V1);
        hasher.update(&length.to_le_bytes());
        hasher.update(&encoded);
        Ok(IvmExecutionStatementDigestV1(*hasher.finalize().as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proof::{ProofAttachment, ProofBox},
        transaction::{
            Executable, IvmBytecode, IvmProved, TransactionBuilder,
            signed_attachments::{PlannedActionV1, SignedAttachmentPlanV1},
        },
    };
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey, PublicKey};
    use iroha_model_base::topology::DataSpaceId;
    use iroha_primitives::const_vec::ConstVec;
    use std::num::NonZeroU64;

    fn other_authority() -> AccountId {
        AccountId::new(
            KeyPair::from_seed(vec![0xA5; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }

    fn fixture() -> (IvmExecutionStatementV1, SignedTransaction) {
        let private_key: PrivateKey =
            "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
                .parse()
                .expect("fixed test key");
        let authority = AccountId::new(PublicKey::from(private_key.clone()));
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed([0x31; Hash::LENGTH]),
        ));
        let fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000));
        let attachment = ProofAttachment::new_ref(
            "stark/fri".into(),
            ProofBox::new("stark/fri".into(), vec![1, 2, 3]),
            VerifyingKeyId::new("stark/fri", "ivm-v1"),
        );
        let mut attachments = SignedAttachmentPlanV1::new();
        attachments.push_action(
            PlannedActionV1::ivm_proved_execution(&attachment).expect("execution carrier"),
        );
        let executable = Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 4]),
            overlay: ConstVec::new_empty(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas"),
        });
        let signed = TransactionBuilder::new(network_id, authority.clone(), fee_payment.clone())
            .with_executable(executable)
            .with_attachment_plan(attachments)
            .expect("valid execution carrier")
            .sign(&private_key);
        let statement = IvmExecutionStatementV1 {
            network_id,
            normalized_signed_intent: signed.ivm_proved_intent_digest_v1().expect("intent"),
            authority: authority.clone(),
            fee_payment,
            contract_address: ContractAddress::derive(
                &network_id,
                &authority,
                7,
                DataSpaceId::new(1),
            )
            .expect("contract address"),
            code_hash: Hash::new(b"code"),
            abi_version: 1,
            abi_hash: Hash::new(b"abi-v1"),
            selector: "transfer".to_owned(),
            public_arguments: None,
            finalized_prestate: IvmFinalizedPrestateClaimV1 {
                block_hash: HashOf::from_untyped_unchecked(Hash::new(b"block")),
                block_height: 10,
                complete_state_root: IvmCompleteStateRootClaimV1::claimed([3; 32]),
                height_context_hash: Hash::new(b"height-context"),
                execution_context_hash: Hash::new(b"execution-context"),
                finality_qc_hash: Hash::new(b"qc"),
                da_manifest_hash: Hash::new(b"da"),
            },
            access_dependencies: IvmAccessDependencyClaimV1 {
                complete_transcript_hash: Hash::new(b"accesses"),
                point_read_count: 2,
                range_read_count: 1,
                write_count: 1,
            },
            returns: IvmReturnClaimV1 {
                initialized_word_count: 2,
                canonical_record_hash: Hash::new(b"return"),
            },
            effects: IvmOrderedOutputClaimV1 {
                item_count: 1,
                canonical_payload_hash: Hash::new(b"effect"),
            },
            events: IvmOrderedOutputClaimV1 {
                item_count: 1,
                canonical_payload_hash: Hash::new(b"event"),
            },
            exact_gas_used: 123,
            verifier_profile: IvmVerifierProfileV1 {
                backend: "stark/fri".into(),
                relation_digest: Hash::new(b"complete-ivm-relation"),
                verifying_key_id: VerifyingKeyId::new("stark/fri", "ivm-v1"),
                verifying_key_commitment: Hash::new(b"verifying-key"),
            },
        };
        (statement, signed)
    }

    #[test]
    fn canonical_statement_roundtrips_and_binds_signed_intent() {
        let (statement, signed) = fixture();
        assert!(
            statement
                .matches_signed_transaction(&signed)
                .expect("intent")
        );
        let encoded = norito::encode_canonical(&statement).expect("encode statement");
        assert_eq!(
            norito::decode_canonical::<IvmExecutionStatementV1>(&encoded).expect("decode"),
            statement
        );
        let digest = statement.digest().expect("digest");
        assert_ne!(digest.into_bytes(), [0; 32]);
        let alternate =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate);
        assert_eq!(statement.digest().expect("canonical under flags"), digest);

        let mut with_arguments = statement.clone();
        with_arguments.public_arguments =
            Some(ContractArgumentRecord::try_new(vec![1, 2, 3]).expect("bounded arguments"));
        let encoded_arguments = norito::encode_canonical(&with_arguments).expect("arguments");
        assert_eq!(
            norito::decode_canonical::<IvmExecutionStatementV1>(&encoded_arguments)
                .expect("decode arguments"),
            with_arguments
        );

        let mut changed = statement.clone();
        changed.authority = other_authority();
        assert!(!changed.matches_signed_transaction(&signed).expect("intent"));
        changed.authority = statement.authority.clone();
        changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"other genesis"),
        ));
        assert!(!changed.matches_signed_transaction(&signed).expect("intent"));
        changed.network_id = statement.network_id;
        changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(20_000));
        assert!(!changed.matches_signed_transaction(&signed).expect("intent"));
        changed.fee_payment = statement.fee_payment.clone();
        changed.normalized_signed_intent =
            IvmProvedTransactionIntentDigestV1::from_bytes_for_test([9; 32]);
        assert!(!changed.matches_signed_transaction(&signed).expect("intent"));
    }

    #[test]
    fn every_public_statement_field_changes_the_digest() {
        let (statement, _) = fixture();
        let expected = statement.digest().expect("baseline");
        let mutations: Vec<fn(&mut IvmExecutionStatementV1)> = vec![
            |s| {
                s.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"other network"),
                ))
            },
            |s| {
                s.normalized_signed_intent =
                    IvmProvedTransactionIntentDigestV1::from_bytes_for_test([7; 32])
            },
            |s| s.authority = other_authority(),
            |s| s.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(20_000)),
            |s| {
                s.contract_address =
                    ContractAddress::derive(&s.network_id, &s.authority, 8, DataSpaceId::new(1))
                        .expect("other address")
            },
            |s| s.code_hash = Hash::new(b"other code"),
            |s| s.abi_version = 2,
            |s| s.abi_hash = Hash::new(b"other abi"),
            |s| s.selector = "other".to_owned(),
            |s| {
                s.public_arguments =
                    Some(ContractArgumentRecord::try_new(vec![1]).expect("argument"))
            },
            |s| {
                s.finalized_prestate.block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"other block"))
            },
            |s| s.finalized_prestate.block_height += 1,
            |s| {
                s.finalized_prestate.complete_state_root =
                    IvmCompleteStateRootClaimV1::claimed([4; 32])
            },
            |s| s.finalized_prestate.height_context_hash = Hash::new(b"other height context"),
            |s| s.finalized_prestate.execution_context_hash = Hash::new(b"other execution context"),
            |s| s.finalized_prestate.finality_qc_hash = Hash::new(b"other qc"),
            |s| s.finalized_prestate.da_manifest_hash = Hash::new(b"other da"),
            |s| s.access_dependencies.complete_transcript_hash = Hash::new(b"other dependencies"),
            |s| s.access_dependencies.point_read_count += 1,
            |s| s.access_dependencies.range_read_count += 1,
            |s| s.access_dependencies.write_count += 1,
            |s| s.returns.initialized_word_count += 1,
            |s| s.returns.canonical_record_hash = Hash::new(b"other return"),
            |s| s.effects.item_count += 1,
            |s| s.effects.canonical_payload_hash = Hash::new(b"other effects"),
            |s| s.events.item_count += 1,
            |s| s.events.canonical_payload_hash = Hash::new(b"other events"),
            |s| s.exact_gas_used += 1,
            |s| s.verifier_profile.backend = "other/fri".into(),
            |s| s.verifier_profile.relation_digest = Hash::new(b"other relation"),
            |s| s.verifier_profile.verifying_key_id = VerifyingKeyId::new("stark/fri", "other-v1"),
            |s| s.verifier_profile.verifying_key_commitment = Hash::new(b"other vk"),
        ];
        for (index, mutate) in mutations.into_iter().enumerate() {
            let mut changed = statement.clone();
            mutate(&mut changed);
            if index == 6 {
                assert_eq!(
                    changed.digest(),
                    Err(IvmExecutionStatementErrorV1::WrongAbi)
                );
            } else {
                assert_ne!(
                    changed.digest().expect("changed digest"),
                    expected,
                    "field {index}"
                );
            }
        }
    }

    #[test]
    fn malformed_abi_result_table_and_selector_are_rejected() {
        let (mut statement, _) = fixture();
        statement.abi_version = 2;
        assert_eq!(
            statement.digest(),
            Err(IvmExecutionStatementErrorV1::WrongAbi)
        );
        statement.abi_version = 1;
        statement.returns.initialized_word_count = 8_193;
        assert_eq!(
            statement.digest(),
            Err(IvmExecutionStatementErrorV1::ResultTableTooLarge)
        );
        statement.returns.initialized_word_count = 8_192;
        statement.selector.clear();
        assert_eq!(
            statement.digest(),
            Err(IvmExecutionStatementErrorV1::EmptySelector)
        );
    }
}
