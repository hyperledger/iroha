//! Canonical signed intent for a proved IVM transaction.
//!
//! A proof must bind an intent fixed before the proof and execution outputs exist.
//! This module projects the complete unsigned payload onto its ordered intent,
//! which removes only the generated fields that would otherwise make its digest
//! self-referential, and requires the explicitly declared execution proof carrier.

use super::{Executable, SignedTransaction, TransactionPayload};
use crate::transaction::signed_attachments::{ActionOperationV1, SignedAttachmentsV1};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use thiserror::Error;

/// Domain separator for the canonical proved-IVM signed intent digest.
pub const IVM_PROVED_TRANSACTION_INTENT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.ivm-proved.transaction-intent-digest.v1";

/// Digest of a proved-IVM transaction's canonical normalized unsigned payload.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::transaction::signed::IvmProvedTransactionIntentDigestV1")]
pub struct IvmProvedTransactionIntentDigestV1([u8; 32]);

impl IvmProvedTransactionIntentDigestV1 {
    #[cfg(test)]
    pub(crate) const fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the fixed-width digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Failure to project a proved-IVM transaction onto its canonical signed intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IvmProvedTransactionIntentErrorV1 {
    /// The transaction does not carry a proved IVM executable.
    #[error("proved-IVM intent requires an IvmProved executable")]
    WrongExecutable,
    /// No action declares the execution proof carrier, or more than one does.
    #[error("proved-IVM intent requires exactly one declared execution proof carrier")]
    MissingProofAttachment,
    /// Canonical Norito encoding of the normalized unsigned payload failed.
    #[error("canonical proved-IVM intent payload encoding failed")]
    PayloadEncodingFailure,
    /// The canonical payload length cannot be represented in the fixed digest frame.
    #[error("proved-IVM intent payload length overflow")]
    PayloadLengthOverflow,
}

fn normalized_proved_payload(
    payload: &TransactionPayload,
) -> Result<TransactionPayload, IvmProvedTransactionIntentErrorV1> {
    if !matches!(payload.instructions, Executable::IvmProved(_)) {
        return Err(IvmProvedTransactionIntentErrorV1::WrongExecutable);
    }
    // The execution proof carrier is selected by its declared operation, not
    // by its position among the attachments.
    let mut execution_carriers = payload
        .attachments
        .iter()
        .flat_map(SignedAttachmentsV1::actions)
        .filter(|action| action.operation == ActionOperationV1::IvmProvedExecution);
    if execution_carriers.next().is_none() || execution_carriers.next().is_some() {
        return Err(IvmProvedTransactionIntentErrorV1::MissingProofAttachment);
    }
    // The ordered intent clears the overlay and the event and gas commitments
    // (execution outputs), every attachment occurrence's bytes, the length and
    // hash of every generated proof and every derived statement digest. The
    // bytecode, every other signed field and each carrier's backend,
    // verifying-key identity and commitment (through its public-input digest)
    // stay bound.
    Ok(payload.ordered_intent_normalized_payload_v1())
}

impl TransactionPayload {
    /// Return the exact canonical unsigned-payload preimage for a proved-IVM intent.
    ///
    /// The complete payload remains in the preimage, including the exact network
    /// or genesis domain, authority, fees, time, nonce, metadata, bytecode and
    /// the proof-free public inputs of every proof carrier (backend and
    /// verifying-key identity and commitment). Only generated values are
    /// normalized: every attachment occurrence's bytes with the length and hash
    /// of each generated proof, each derived statement digest, and the proved
    /// executable's overlay and two output commitments.
    ///
    /// This helper does not authorize private execution. Admission must verify
    /// a complete execution relation before it applies effects.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-proved executable, a missing or repeated
    /// execution proof carrier, or canonical encoding failure.
    pub fn ivm_proved_intent_projection_bytes_v1(
        &self,
    ) -> Result<Vec<u8>, IvmProvedTransactionIntentErrorV1> {
        norito::encode_canonical(&normalized_proved_payload(self)?)
            .map_err(|_| IvmProvedTransactionIntentErrorV1::PayloadEncodingFailure)
    }

    /// Hash the canonical normalized unsigned payload with a typed V1 domain.
    ///
    /// Length framing prevents concatenation ambiguity. Proof bytes and
    /// execution outputs can change without feeding a hash of themselves back
    /// into the proof statement; all independent signed fields remain bound.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical projection or fixed-width length
    /// conversion fails.
    pub fn ivm_proved_intent_digest_v1(
        &self,
    ) -> Result<IvmProvedTransactionIntentDigestV1, IvmProvedTransactionIntentErrorV1> {
        let encoded = self.ivm_proved_intent_projection_bytes_v1()?;
        let length = u64::try_from(encoded.len())
            .map_err(|_| IvmProvedTransactionIntentErrorV1::PayloadLengthOverflow)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(IVM_PROVED_TRANSACTION_INTENT_DIGEST_DOMAIN_V1);
        hasher.update(&length.to_le_bytes());
        hasher.update(&encoded);
        Ok(IvmProvedTransactionIntentDigestV1(
            *hasher.finalize().as_bytes(),
        ))
    }
}

impl SignedTransaction {
    /// Derive the proved-IVM intent from this transaction's signed payload.
    ///
    /// Authorization signatures are outside the intent preimage; the complete
    /// payload, apart from proof-derived fields, remains bound.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a canonically projectable
    /// proved-IVM transaction.
    pub fn ivm_proved_intent_digest_v1(
        &self,
    ) -> Result<IvmProvedTransactionIntentDigestV1, IvmProvedTransactionIntentErrorV1> {
        self.payload.ivm_proved_intent_digest_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Level,
        account::AccountId,
        isi::{InstructionBox, Log},
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
        transaction::{
            IvmBytecode, IvmProved, TransactionBuilder, TransactionDomain,
            signed::FeePaymentIntent,
            signed_attachments::{PlannedActionV1, SignedAttachmentPlanV1},
        },
    };
    use iroha_crypto::Hash;
    use iroha_crypto::{PrivateKey, PublicKey};
    use iroha_model_base::{metadata::Metadata, name::Name};
    use iroha_primitives::json::Json;
    use std::{
        num::{NonZeroU32, NonZeroU64},
        str::FromStr,
    };

    fn proof_attachment(backend: &str, name: &str, proof_bytes: Vec<u8>) -> ProofAttachment {
        let mut attachment = ProofAttachment::new_ref(
            backend.into(),
            ProofBox::new(backend.into(), proof_bytes),
            VerifyingKeyId::new(backend, name),
        );
        attachment.envelope_hash = Some(Hash::new(&attachment.proof.bytes).into());
        attachment
    }

    /// Declare the first attachment as the execution proof carrier and every
    /// later one as an independent transaction-level proof carrier.
    fn carrier_plan(attachments: &[ProofAttachment]) -> SignedAttachmentPlanV1 {
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(
            PlannedActionV1::ivm_proved_execution(&attachments[0]).expect("execution carrier"),
        );
        for attachment in &attachments[1..] {
            plan.push_action(
                PlannedActionV1::transaction_proof(attachment).expect("independent carrier"),
            );
        }
        plan
    }

    fn carriers(payload: &TransactionPayload) -> Vec<ProofAttachment> {
        payload
            .attachments
            .as_ref()
            .expect("fixture attachments")
            .proof_carriers_v1()
            .expect("canonical carriers")
            .into_iter()
            .map(|(_, attachment)| attachment)
            .collect()
    }

    fn set_carriers(payload: &mut TransactionPayload, attachments: &[ProofAttachment]) {
        payload.attachments = Some(carrier_plan(attachments).declare());
        payload
            .bind_attachment_statements_v1()
            .expect("bound statements");
    }

    fn fixture_payload() -> (TransactionPayload, PrivateKey) {
        let private_key: PrivateKey =
            "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
                .parse()
                .expect("fixed test key");
        let authority = AccountId::new(PublicKey::from(private_key.clone()));
        let mut first = proof_attachment("stark/fri", "ivm_v1", vec![1, 2, 3]);
        first.vk_commitment = Some([7; 32]);
        let attachments = [
            first,
            proof_attachment("halo2/ipa", "independent", vec![4, 5, 6]),
        ];
        let executable = Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![1, 2, 3, 4]),
            overlay: vec![InstructionBox::from(Log::new(Level::INFO, "effect".into()))].into(),
            events_commitment: Hash::new(b"events"),
            gas_policy_commitment: Hash::new(b"gas"),
        });
        let mut builder = TransactionBuilder::new(
            super::super::test_network_id(0x31),
            authority,
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_000)),
        )
        .with_executable(executable)
        .with_attachment_plan(carrier_plan(&attachments))
        .expect("valid carriers");
        builder.set_nonce(NonZeroU32::new(3).expect("nonzero"));
        (builder.into_payload().expect("valid payload"), private_key)
    }

    fn assert_retained_mutation(
        payload: &TransactionPayload,
        mutate: impl FnOnce(&mut TransactionPayload),
    ) {
        let expected = payload
            .ivm_proved_intent_digest_v1()
            .expect("baseline intent");
        let mut changed = payload.clone();
        mutate(&mut changed);
        assert_ne!(
            changed
                .ivm_proved_intent_digest_v1()
                .expect("changed intent"),
            expected
        );
    }

    fn assert_derived_mutation(
        payload: &TransactionPayload,
        mutate: impl FnOnce(&mut TransactionPayload),
    ) {
        let expected = payload
            .ivm_proved_intent_projection_bytes_v1()
            .expect("baseline projection");
        let mut changed = payload.clone();
        mutate(&mut changed);
        assert_ne!(changed, *payload, "mutation must change signed payload");
        assert_eq!(
            changed
                .ivm_proved_intent_projection_bytes_v1()
                .expect("changed projection"),
            expected
        );
        assert_eq!(
            changed
                .ivm_proved_intent_digest_v1()
                .expect("changed intent"),
            payload
                .ivm_proved_intent_digest_v1()
                .expect("baseline intent")
        );
    }

    fn mutate_first_attachment(
        payload: &mut TransactionPayload,
        change: impl FnOnce(&mut ProofAttachment),
    ) {
        let mut attachments = carriers(payload);
        change(&mut attachments[0]);
        set_carriers(payload, &attachments);
    }

    #[test]
    fn every_independent_signed_field_remains_in_the_intent() {
        let (payload, _) = fixture_payload();
        assert_retained_mutation(&payload, |changed| {
            changed.domain = TransactionDomain::Network(super::super::test_network_id(0x32));
        });
        assert_retained_mutation(&payload, |changed| {
            changed.domain = TransactionDomain::Genesis;
        });
        assert_retained_mutation(&payload, |changed| {
            let other: PrivateKey =
                "802620AF3F96DEEF44348FEB516C057558972CEC4C75C4DB9C5B3AAC843668854BF828"
                    .parse()
                    .expect("fixed other test key");
            changed.authority = AccountId::new(PublicKey::from(other));
        });
        assert_retained_mutation(&payload, |changed| changed.creation_time_ms += 1);
        assert_retained_mutation(&payload, |changed| {
            changed.time_to_live_ms = NonZeroU64::new(1);
        });
        assert_retained_mutation(&payload, |changed| {
            changed.nonce = NonZeroU32::new(4);
        });
        assert_retained_mutation(&payload, |changed| {
            changed.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(10_001));
        });
        assert_retained_mutation(&payload, |changed| {
            let mut metadata = Metadata::default();
            metadata.insert(
                Name::from_str("intent_context").expect("valid key"),
                Json::from(1_u64),
            );
            changed.metadata = metadata;
        });
        assert_retained_mutation(&payload, |changed| {
            let Executable::IvmProved(proved) = &mut changed.instructions else {
                panic!("fixture is proved IVM")
            };
            proved.bytecode = IvmBytecode::from_compiled(vec![1, 2, 3, 5]);
        });
        assert_retained_mutation(&payload, |changed| {
            mutate_first_attachment(changed, |attachment| {
                attachment.vk_ref = VerifyingKeyId::new("stark/fri", "other_vk");
            });
        });
        assert_retained_mutation(&payload, |changed| {
            mutate_first_attachment(changed, |attachment| {
                attachment.backend = "halo2/ipa".into();
                attachment.proof.backend = "halo2/ipa".into();
                attachment.vk_ref = VerifyingKeyId::new("halo2/ipa", "ivm_v1");
            });
        });
        assert_retained_mutation(&payload, |changed| {
            mutate_first_attachment(changed, |attachment| {
                attachment.vk_commitment = Some([8; 32]);
            });
        });
        // The proof-free public inputs of an independent carrier stay bound.
        assert_retained_mutation(&payload, |changed| {
            let mut attachments = carriers(changed);
            attachments[1].vk_ref = VerifyingKeyId::new("halo2/ipa", "other_independent");
            set_carriers(changed, &attachments);
        });
        // So does the order of the declared actions.
        assert_retained_mutation(&payload, |changed| {
            let attachments = carriers(changed);
            let mut plan = SignedAttachmentPlanV1::new();
            plan.push_action(
                PlannedActionV1::transaction_proof(&attachments[1]).expect("independent carrier"),
            );
            plan.push_action(
                PlannedActionV1::ivm_proved_execution(&attachments[0]).expect("execution carrier"),
            );
            changed.attachments = Some(plan.declare());
            changed
                .bind_attachment_statements_v1()
                .expect("bound statements");
        });
    }

    #[test]
    fn only_proof_derived_fields_are_normalized() {
        let (payload, private_key) = fixture_payload();
        assert_derived_mutation(&payload, |changed| {
            let Executable::IvmProved(proved) = &mut changed.instructions else {
                panic!("fixture is proved IVM")
            };
            proved.overlay = Vec::<InstructionBox>::new().into();
        });
        assert_derived_mutation(&payload, |changed| {
            let Executable::IvmProved(proved) = &mut changed.instructions else {
                panic!("fixture is proved IVM")
            };
            proved.events_commitment = Hash::new(b"other events");
        });
        assert_derived_mutation(&payload, |changed| {
            let Executable::IvmProved(proved) = &mut changed.instructions else {
                panic!("fixture is proved IVM")
            };
            proved.gas_policy_commitment = Hash::new(b"other gas");
        });
        assert_derived_mutation(&payload, |changed| {
            mutate_first_attachment(changed, |attachment| {
                attachment.proof.bytes = vec![9, 8, 7];
                attachment.envelope_hash = Some(Hash::new(&attachment.proof.bytes).into());
            });
        });
        assert_derived_mutation(&payload, |changed| {
            mutate_first_attachment(changed, |attachment| {
                attachment.envelope_hash = None;
            });
        });
        // Every generated proof is excluded, not only the execution carrier's.
        assert_derived_mutation(&payload, |changed| {
            let mut attachments = carriers(changed);
            attachments[1].proof.bytes = vec![4, 5, 7];
            attachments[1].envelope_hash = Some(Hash::new(&attachments[1].proof.bytes).into());
            set_carriers(changed, &attachments);
        });

        let signed = TransactionBuilder::from_payload(payload.clone())
            .expect("ordinary payload")
            .sign(&private_key);
        assert_eq!(
            signed.ivm_proved_intent_digest_v1().expect("signed intent"),
            payload
                .ivm_proved_intent_digest_v1()
                .expect("payload intent")
        );
        let mut tampered = signed.clone();
        mutate_first_attachment(tampered.payload_mut(), |attachment| {
            attachment.proof.bytes = vec![9, 8, 7];
            attachment.envelope_hash = Some(Hash::new(&attachment.proof.bytes).into());
        });
        assert_ne!(tampered.hash(), signed.hash());
        tampered
            .verify_signature()
            .expect_err("normalizing an intent does not weaken transaction signatures");
    }

    #[test]
    fn projection_rejects_missing_carrier_or_wrong_executable() {
        let (mut payload, _) = fixture_payload();
        payload.attachments = None;
        assert!(matches!(
            payload.ivm_proved_intent_digest_v1(),
            Err(IvmProvedTransactionIntentErrorV1::MissingProofAttachment)
        ));
        payload.instructions = Executable::Ivm(IvmBytecode::from_compiled(vec![1, 2, 3]));
        assert!(matches!(
            payload.ivm_proved_intent_digest_v1(),
            Err(IvmProvedTransactionIntentErrorV1::WrongExecutable)
        ));
    }

    #[test]
    fn execution_carrier_is_selected_by_operation_not_by_position() {
        let (payload, _) = fixture_payload();
        let attachments = carriers(&payload);

        // An independent carrier alone is not an execution proof carrier.
        let mut independent_only = payload.clone();
        independent_only.attachments = Some(
            SignedAttachmentPlanV1::transaction_proofs(&attachments)
                .expect("independent carriers")
                .declare(),
        );
        assert!(matches!(
            independent_only.ivm_proved_intent_digest_v1(),
            Err(IvmProvedTransactionIntentErrorV1::MissingProofAttachment)
        ));

        // The execution carrier may follow an independent one.
        let mut execution_second = payload.clone();
        let mut plan = SignedAttachmentPlanV1::new();
        plan.push_action(
            PlannedActionV1::transaction_proof(&attachments[1]).expect("independent carrier"),
        );
        plan.push_action(
            PlannedActionV1::ivm_proved_execution(&attachments[0]).expect("execution carrier"),
        );
        execution_second.attachments = Some(plan.declare());
        execution_second
            .bind_attachment_statements_v1()
            .expect("bound statements");
        execution_second
            .validate_signed_attachments_v1()
            .expect("valid reordered declaration");
        execution_second
            .ivm_proved_intent_digest_v1()
            .expect("intent with the carrier in second position");

        // Two execution carriers are ambiguous.
        let mut repeated = payload.clone();
        let mut plan = SignedAttachmentPlanV1::new();
        for attachment in &attachments {
            plan.push_action(
                PlannedActionV1::ivm_proved_execution(attachment).expect("execution carrier"),
            );
        }
        repeated.attachments = Some(plan.declare());
        assert!(matches!(
            repeated.ivm_proved_intent_digest_v1(),
            Err(IvmProvedTransactionIntentErrorV1::MissingProofAttachment)
        ));
    }

    #[test]
    fn projection_ignores_ambient_norito_encode_flags() {
        let (payload, _) = fixture_payload();
        let expected = payload
            .ivm_proved_intent_projection_bytes_v1()
            .expect("canonical projection");
        let alternate =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate);
        assert_eq!(
            payload
                .ivm_proved_intent_projection_bytes_v1()
                .expect("canonical projection under alternate ambient flags"),
            expected
        );
    }
}
