//! Bind privacy authorization to one original signed native instruction occurrence.

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    isi::{InstructionBox, privacy::SubmitPrivacyProofV1},
    transaction::{Executable, ExecutableBatchItem, SignedTransaction, TransactionEntrypoint},
};

use super::{StateReadOnly, StateTransaction};

/// Original signed source; an equal instruction emitted by a child has no direct authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PrivacyDirectSourceV1 {
    authority: AccountId,
    transaction_hash: HashOf<SignedTransaction>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    call_hash: Hash,
    entrypoint_index: u64,
    instruction_index: usize,
}

fn direct_submission_at(
    transaction: &SignedTransaction,
    index: usize,
) -> Option<&SubmitPrivacyProofV1> {
    let instruction = match transaction.instructions() {
        Executable::Instructions(instructions) => instructions.get(index),
        Executable::Batch(items) => items.get(index).and_then(|item| match item {
            ExecutableBatchItem::Instruction(instruction) => Some(instruction),
            ExecutableBatchItem::ContractCall(_) => None,
        }),
        Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => None,
    }?;
    instruction.as_any().downcast_ref::<SubmitPrivacyProofV1>()
}

impl StateTransaction<'_, '_> {
    /// Attach the authenticated root identity to an already validated privacy binding.
    ///
    /// Only signed-body admission calls this method. A sealed reveal retains its actual outer
    /// entry hash and its distinct inner execution call hash; it is never relabelled External.
    pub(crate) fn bind_privacy_transaction_source_v1(
        &mut self,
        transaction: &SignedTransaction,
    ) -> Result<(), ValidationFail> {
        self.current_direct_privacy_instruction_index = None;
        let Some(binding) = self.privacy_transaction_intent_binding.as_mut() else {
            return Ok(());
        };
        binding.source = None;
        let fail = || {
            ValidationFail::NotPermitted(
                "privacy submission requires its authenticated signed root source".into(),
            )
        };
        let transaction_hash = transaction.hash();
        let call_hash = Hash::from(transaction.hash_as_entrypoint());
        if self.execution_callback_active()
            || transaction.network_id() != Some(self.network_id())
            || transaction.verify_signature().is_err()
            || self.current_tx_hash != Some(transaction_hash)
            || self.tx_call_hash != Some(call_hash)
        {
            return Err(fail());
        }
        let entrypoint_hash = self.current_network_entrypoint_hash.ok_or_else(fail)?;
        let entrypoint_index = self.current_entrypoint_index.ok_or_else(fail)?;
        let length = match transaction.instructions() {
            Executable::Instructions(instructions) => instructions.len(),
            Executable::Batch(items) => items.len(),
            Executable::ContractCall(_) | Executable::Ivm(_) | Executable::IvmProved(_) => {
                return Err(fail());
            }
        };
        let mut occurrences = (0..length).filter_map(|index| {
            direct_submission_at(transaction, index).map(|submission| (index, submission))
        });
        let (instruction_index, submission) = occurrences.next().ok_or_else(fail)?;
        if occurrences.next().is_some() {
            return Err(fail());
        }
        let submission_hash =
            crate::privacy::privacy_signed_submission_hash_v1(submission).map_err(|_| fail())?;
        if let Some(binding) = self.privacy_transaction_intent_binding.as_mut() {
            if binding.digest
                != submission
                    .envelope
                    .statement
                    .context()
                    .transaction_intent_digest
                || binding.submission_hash != submission_hash
            {
                return Err(fail());
            }
            binding.source = Some(PrivacyDirectSourceV1 {
                authority: transaction.authority().clone(),
                transaction_hash,
                entrypoint_hash,
                call_hash,
                entrypoint_index,
                instruction_index,
            });
        }
        Ok(())
    }

    /// Arm only the original signed privacy member immediately before direct native dispatch.
    pub(crate) fn arm_direct_privacy_instruction_v1(
        &mut self,
        transaction: &SignedTransaction,
        authority: &AccountId,
        instruction: &InstructionBox,
        index: usize,
        direct: bool,
    ) {
        self.current_direct_privacy_instruction_index = None;
        if !direct || self.execution_callback_active() {
            return;
        }
        let Some(binding) = self.privacy_transaction_intent_binding.as_ref() else {
            return;
        };
        let Some(source) = binding.source.as_ref() else {
            return;
        };
        let actual = instruction.as_any().downcast_ref::<SubmitPrivacyProofV1>();
        if !binding.consumed
            && source.instruction_index == index
            && source.transaction_hash == transaction.hash()
            && source.authority == *authority
            && transaction.authority() == authority
            && actual.is_some()
            && direct_submission_at(transaction, index) == actual
        {
            self.current_direct_privacy_instruction_index = Some(index);
            if !self.privacy_direct_source_matches(authority) {
                self.current_direct_privacy_instruction_index = None;
            }
        }
    }

    /// Recheck source and active direct frame before consuming proof authority.
    pub(super) fn privacy_direct_source_matches(&self, authority: &AccountId) -> bool {
        self.privacy_transaction_intent_binding
            .as_ref()
            .and_then(|binding| binding.source.as_ref())
            .is_some_and(|source| {
                !self.execution_callback_active()
                    && authority == &source.authority
                    && self.current_tx_hash == Some(source.transaction_hash)
                    && self.current_network_entrypoint_hash == Some(source.entrypoint_hash)
                    && self.tx_call_hash == Some(source.call_hash)
                    && self.current_entrypoint_index == Some(source.entrypoint_index)
                    && self.current_direct_privacy_instruction_index
                        == Some(source.instruction_index)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{
            PrivacyTransactionIntentConsumptionErrorV1, State, World,
            seed_committed_transaction_context,
        },
    };
    use iroha_data_model::{
        block::BlockHeader,
        privacy::{
            PrivacyProtocolIdV1, PrivacyTransactionIntentDigestV1, privacy_action_role_samples_v1,
        },
        smart_contract::ContractAddress,
        transaction::{FeePaymentIntent, TransactionBuilder, executable::ContractInvocation},
    };
    use iroha_model_base::topology::DataSpaceId;
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

    fn state() -> State {
        State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    // These structural proof bytes exercise admission/source binding only. No test submits them
    // to a verifier or treats them as a valid privacy payment.
    fn signed(state: &State, mode: u8) -> (SignedTransaction, SubmitPrivacyProofV1, usize) {
        let envelope = privacy_action_role_samples_v1()
            .unwrap()
            .into_iter()
            .find(|sample| {
                sample.envelope.protocol_id == PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1
            })
            .unwrap()
            .envelope;
        let mut submission = SubmitPrivacyProofV1::new(envelope);
        submission.envelope.statement.context_mut().network_id = *state.network_id_ref();
        submission.envelope.statement.context_mut().action_index = 0;
        let build = |submission: SubmitPrivacyProofV1| {
            let mut builder = TransactionBuilder::new(
                *state.network_id_ref(),
                ALICE_ID.clone(),
                FeePaymentIntent::authority(Vec::new(), None),
            );
            builder.set_creation_time(core::time::Duration::from_millis(1));
            if mode == 2 {
                let call = ContractInvocation {
                    contract_address: ContractAddress::derive(
                        state.network_id_ref(),
                        &ALICE_ID,
                        0,
                        DataSpaceId::UNIVERSAL,
                    )
                    .unwrap(),
                    expected_code_hash: Hash::new(b"privacy source contract"),
                    entrypoint: "run".into(),
                    arguments: None,
                };
                builder.with_executable(Executable::Batch(
                    vec![
                        ExecutableBatchItem::ContractCall(call.clone()),
                        ExecutableBatchItem::Instruction(submission.into()),
                        ExecutableBatchItem::ContractCall(call),
                    ]
                    .into(),
                ))
            } else if mode == 1 {
                builder.with_executable(Executable::Batch(
                    vec![ExecutableBatchItem::Instruction(submission.into())].into(),
                ))
            } else {
                builder.with_instructions([submission])
            }
        };
        let intent = build(submission.clone())
            .into_payload()
            .unwrap()
            .privacy_transaction_intent_digest_v1()
            .unwrap();
        submission
            .envelope
            .statement
            .context_mut()
            .transaction_intent_digest = intent;
        submission.envelope.statement_digest = submission.envelope.statement.digest().unwrap();
        let signed = build(submission.clone()).sign(ALICE_KEYPAIR.private_key());
        (signed, submission, usize::from(mode == 2))
    }

    fn bind(transaction: &mut StateTransaction<'_, '_>, signed: &SignedTransaction) {
        seed_committed_transaction_context(
            transaction,
            &TransactionEntrypoint::External(signed.clone()),
            3,
        );
        transaction.bind_privacy_transaction_intent_v1(
            crate::privacy::signed_privacy_transaction_intent_binding_v1(signed).unwrap(),
        );
        transaction
            .bind_privacy_transaction_source_v1(signed)
            .unwrap();
    }

    fn consume(
        transaction: &mut StateTransaction<'_, '_>,
        submission: &SubmitPrivacyProofV1,
    ) -> Result<(), PrivacyTransactionIntentConsumptionErrorV1> {
        transaction.consume_privacy_transaction_intent_v1(
            &ALICE_ID,
            submission
                .envelope
                .statement
                .context()
                .transaction_intent_digest,
            crate::privacy::privacy_signed_submission_hash_v1(submission).unwrap(),
        )
    }

    #[test]
    fn privacy_transaction_intent_binding_is_exact_one_shot_and_transaction_scoped() {
        let state = state();
        for mode in [0, 1, 2] {
            let (signed, submission, index) = signed(&state, mode);
            let mut block = state.block(BlockHeader::new(
                core::num::NonZeroU64::MIN,
                None,
                None,
                0,
                0,
            ));
            {
                let mut transaction = block.transaction();
                assert_eq!(
                    consume(&mut transaction, &submission),
                    Err(PrivacyTransactionIntentConsumptionErrorV1::MissingBinding)
                );
                bind(&mut transaction, &signed);
                assert_eq!(
                    consume(&mut transaction, &submission),
                    Err(PrivacyTransactionIntentConsumptionErrorV1::NotDirectOccurrence)
                );
                transaction.arm_direct_privacy_instruction_v1(
                    &signed,
                    &ALICE_ID,
                    &submission.clone().into(),
                    index,
                    true,
                );
                let digest = submission
                    .envelope
                    .statement
                    .context()
                    .transaction_intent_digest;
                let hash = crate::privacy::privacy_signed_submission_hash_v1(&submission).unwrap();
                assert_eq!(
                    transaction.consume_privacy_transaction_intent_v1(
                        &ALICE_ID,
                        PrivacyTransactionIntentDigestV1::new([0xA1; 32]),
                        hash,
                    ),
                    Err(PrivacyTransactionIntentConsumptionErrorV1::DigestMismatch)
                );
                assert_eq!(
                    transaction.consume_privacy_transaction_intent_v1(
                        &ALICE_ID,
                        digest,
                        Hash::new(b"substituted proof"),
                    ),
                    Err(PrivacyTransactionIntentConsumptionErrorV1::SubmissionMismatch)
                );
                consume(&mut transaction, &submission).unwrap();
                assert_eq!(transaction.current_direct_privacy_instruction_index, None);
                assert_eq!(
                    consume(&mut transaction, &submission),
                    Err(PrivacyTransactionIntentConsumptionErrorV1::AlreadyConsumed)
                );
                bind(&mut transaction, &signed);
                assert_eq!(transaction.current_direct_privacy_instruction_index, None);
                transaction.arm_direct_privacy_instruction_v1(
                    &signed,
                    &ALICE_ID,
                    &submission.clone().into(),
                    index,
                    true,
                );
                consume(&mut transaction, &submission).unwrap();
            }
            let mut next = block.transaction();
            assert_eq!(
                consume(&mut next, &submission),
                Err(PrivacyTransactionIntentConsumptionErrorV1::MissingBinding)
            );
        }
    }

    #[test]
    fn privacy_direct_occurrence_rejects_identical_nested_submission_and_wrong_ordinal() {
        let state = state();
        let (signed, submission, index) = signed(&state, 2);
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        bind(&mut transaction, &signed);
        for (direct, ordinal) in [(false, index), (true, 0), (true, 2)] {
            transaction.arm_direct_privacy_instruction_v1(
                &signed,
                &ALICE_ID,
                &submission.clone().into(),
                ordinal,
                direct,
            );
            assert_eq!(
                consume(&mut transaction, &submission),
                Err(PrivacyTransactionIntentConsumptionErrorV1::NotDirectOccurrence)
            );
        }
        transaction.arm_direct_privacy_instruction_v1(
            &signed,
            &ALICE_ID,
            &submission.clone().into(),
            index,
            true,
        );
        transaction.active_trigger_execution_depth = 1;
        assert_eq!(
            consume(&mut transaction, &submission),
            Err(PrivacyTransactionIntentConsumptionErrorV1::NotDirectOccurrence)
        );
        transaction.active_trigger_execution_depth = 0;
        transaction.arm_direct_privacy_instruction_v1(
            &signed,
            &ALICE_ID,
            &submission.clone().into(),
            index,
            true,
        );
        consume(&mut transaction, &submission).unwrap();
    }

    #[test]
    fn privacy_direct_occurrence_rejects_changed_source_and_authority() {
        let state = state();
        let (signed, submission, index) = signed(&state, 2);
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        for changed in 0..6 {
            let mut transaction = block.transaction();
            bind(&mut transaction, &signed);
            transaction.arm_direct_privacy_instruction_v1(
                &signed,
                &ALICE_ID,
                &submission.clone().into(),
                index,
                true,
            );
            match changed {
                0 => transaction.current_tx_hash = None,
                1 => transaction.current_network_entrypoint_hash = None,
                2 => transaction.tx_call_hash = None,
                3 => transaction.current_entrypoint_index = Some(4),
                4 => transaction.current_direct_privacy_instruction_index = Some(index + 1),
                _ => {}
            }
            let authority = if changed == 5 { &*BOB_ID } else { &*ALICE_ID };
            assert_eq!(
                transaction.consume_privacy_transaction_intent_v1(
                    authority,
                    submission
                        .envelope
                        .statement
                        .context()
                        .transaction_intent_digest,
                    crate::privacy::privacy_signed_submission_hash_v1(&submission).unwrap(),
                ),
                Err(PrivacyTransactionIntentConsumptionErrorV1::NotDirectOccurrence)
            );
        }
    }

    #[test]
    fn privacy_direct_occurrence_rebinding_clears_the_frame_and_checks_root_identity() {
        let state = state();
        let (signed, submission, index) = signed(&state, 2);
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        bind(&mut transaction, &signed);
        transaction.arm_direct_privacy_instruction_v1(
            &signed,
            &ALICE_ID,
            &submission.clone().into(),
            index,
            true,
        );
        transaction.bind_privacy_transaction_intent_v1(None);
        assert_eq!(transaction.current_direct_privacy_instruction_index, None);
        assert_eq!(
            consume(&mut transaction, &submission),
            Err(PrivacyTransactionIntentConsumptionErrorV1::MissingBinding)
        );
        bind(&mut transaction, &signed);
        transaction.current_tx_hash = None;
        assert!(
            transaction
                .bind_privacy_transaction_source_v1(&signed)
                .is_err()
        );
        transaction.arm_direct_privacy_instruction_v1(
            &signed,
            &ALICE_ID,
            &submission.clone().into(),
            index,
            true,
        );
        assert_eq!(
            consume(&mut transaction, &submission),
            Err(PrivacyTransactionIntentConsumptionErrorV1::NotDirectOccurrence)
        );
    }

    #[test]
    fn privacy_direct_occurrence_preserves_sealed_reveal_source_identity() {
        use iroha_data_model::transaction::signed::{
            SealedTransactionReveal, compute_sealed_transaction_commitment,
        };
        let state = state();
        let (signed, submission, index) = signed(&state, 0);
        let salt = [5; 32];
        let commitment =
            compute_sealed_transaction_commitment(state.network_id_ref(), &signed, salt, 10);
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            signed.clone(),
            salt,
        ));
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        seed_committed_transaction_context(&mut transaction, &reveal, 3);
        transaction.bind_privacy_transaction_intent_v1(
            crate::privacy::signed_privacy_transaction_intent_binding_v1(&signed).unwrap(),
        );
        transaction
            .bind_privacy_transaction_source_v1(&signed)
            .unwrap();
        transaction.arm_direct_privacy_instruction_v1(
            &signed,
            &ALICE_ID,
            &submission.clone().into(),
            index,
            true,
        );
        assert_eq!(
            transaction.current_network_entrypoint_hash,
            Some(reveal.hash())
        );
        assert_ne!(reveal.hash(), signed.hash_as_entrypoint());
        consume(&mut transaction, &submission).unwrap();
    }
}
