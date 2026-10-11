//! Bind native Load issuance to the exact signed external instruction and payer.

use std::collections::BTreeMap;

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    account::AccountId,
    isi::{
        error::InstructionExecutionError,
        kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};

use super::{StateReadOnly, StateTransaction};

/// Immutable source for Loads whose success can be proved from native block results.
#[derive(Debug)]
pub(super) struct KagemushaLoadEntrypointBindingV1 {
    authority: AccountId,
    transaction_hash: HashOf<SignedTransaction>,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    entrypoint_index: u64,
    instructions: BTreeMap<usize, KagemushaWalletLedgerV1>,
}

impl StateTransaction<'_, '_> {
    /// Bind Loads only from the actual authenticated external transaction entrypoint.
    ///
    /// Clearing or replacing the source also clears the active instruction frame.
    /// Contract overlays, mixed batches and sealed reveals have no direct Load source.
    pub(crate) fn bind_kagemusha_load_entrypoint_v1(
        &mut self,
        transaction: Option<&SignedTransaction>,
    ) {
        self.kagemusha_load_entrypoint_binding = None;
        self.current_direct_kagemusha_load_instruction_index = None;
        let Some(transaction) = transaction else {
            return;
        };
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return;
        };
        let instructions: BTreeMap<_, _> = instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                let load = instruction
                    .as_any()
                    .downcast_ref::<KagemushaWalletLedgerV1>()?;
                matches!(load.action, KagemushaWalletLedgerActionV1::IssueLoad { .. })
                    .then(|| (index, load.clone()))
            })
            .collect();
        if instructions.is_empty() {
            return;
        }
        let Some(entrypoint_index) = self.current_entrypoint_index else {
            return;
        };
        let transaction_hash = transaction.hash();
        let entrypoint_hash = transaction.hash_as_entrypoint();
        if transaction.network_id() != Some(self.network_id())
            || transaction.verify_signature().is_err()
            || self.current_tx_hash != Some(transaction_hash)
            || self.current_network_entrypoint_hash != Some(entrypoint_hash)
            || self.tx_call_hash != Some(Hash::from(entrypoint_hash))
        {
            return;
        }
        self.kagemusha_load_entrypoint_binding = Some(KagemushaLoadEntrypointBindingV1 {
            authority: transaction.authority().clone(),
            transaction_hash,
            entrypoint_hash,
            entrypoint_index,
            instructions,
        });
    }

    /// Require the exact signed Load in its direct native execution frame before any debit.
    ///
    /// This check is immutable: a rejected attempt cannot consume authorization. The
    /// ledger owns successful-request idempotence and the next-ordinal comparison.
    pub(crate) fn require_direct_kagemusha_load(
        &self,
        instruction: &KagemushaWalletLedgerV1,
        authority: &AccountId,
    ) -> Result<(), InstructionExecutionError> {
        let valid = self
            .kagemusha_load_entrypoint_binding
            .as_ref()
            .is_some_and(|binding| {
                !self.execution_callback_active()
                    && authority == &binding.authority
                    && self.current_tx_hash == Some(binding.transaction_hash)
                    && self.current_network_entrypoint_hash == Some(binding.entrypoint_hash)
                    && self.tx_call_hash == Some(Hash::from(binding.entrypoint_hash))
                    && self.current_entrypoint_index == Some(binding.entrypoint_index)
                    && self
                        .current_direct_kagemusha_load_instruction_index
                        .is_some_and(|index| binding.instructions.get(&index) == Some(instruction))
            });
        if valid {
            Ok(())
        } else {
            Err(InstructionExecutionError::InvariantViolation(
                "KAGEMUSHA Load requires the exact signed payer and direct external instruction"
                    .into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World, seed_committed_transaction_context},
    };
    use iroha_data_model::{
        block::BlockHeader,
        isi::{InstructionBox, Log},
        transaction::{ExecutableBatchItem, FeePaymentIntent, TransactionBuilder},
    };
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};

    fn state() -> State {
        State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    fn load(ordinal: u128) -> KagemushaWalletLedgerV1 {
        KagemushaWalletLedgerV1::new(
            [1; 32],
            KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: [2; 32],
                asset: [3; 32],
                ordinal,
                request_id: [4; 32],
                amount: 10,
                charge: None,
            },
        )
    }

    fn signed(state: &State, executable: Executable) -> SignedTransaction {
        TransactionBuilder::new(
            *state.network_id_ref(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_executable(executable)
        .sign(ALICE_KEYPAIR.private_key())
    }

    fn bind(transaction: &mut StateTransaction<'_, '_>, signed: SignedTransaction) {
        seed_committed_transaction_context(
            transaction,
            &TransactionEntrypoint::External(signed),
            3,
        );
    }

    #[test]
    fn direct_load_binding_matches_exact_instruction_and_preserves_failed_retries() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        let first = load(1);
        let second = load(2);
        let source = signed(
            &state,
            Executable::Instructions(
                vec![
                    InstructionBox::from(Log::new(
                        iroha_logger::Level::INFO,
                        "before loads".into(),
                    )),
                    first.clone().into(),
                    second.clone().into(),
                ]
                .into(),
            ),
        );
        bind(&mut transaction, source);
        transaction.current_direct_kagemusha_load_instruction_index = Some(1);
        assert!(
            transaction
                .require_direct_kagemusha_load(&first, &ALICE_ID)
                .is_ok()
        );
        assert!(
            transaction
                .require_direct_kagemusha_load(&second, &ALICE_ID)
                .is_err()
        );
        for field in 0..7 {
            let mut changed = first.clone();
            if let KagemushaWalletLedgerActionV1::IssueLoad {
                wallet,
                asset,
                ordinal,
                request_id,
                amount,
                charge,
            } = &mut changed.action
            {
                match field {
                    0 => changed.scheme = [9; 32],
                    1 => *wallet = [9; 32],
                    2 => *asset = [9; 32],
                    3 => *ordinal = 9,
                    4 => *request_id = [9; 32],
                    5 => *amount = 9,
                    _ => {
                        *charge = Some(
                            iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLoadChargeV1 {
                                quote: vec![9],
                                beneficiary: BOB_ID.clone(),
                            },
                        )
                    }
                }
            }
            assert!(
                transaction
                    .require_direct_kagemusha_load(&changed, &ALICE_ID)
                    .is_err()
            );
            assert!(
                transaction
                    .require_direct_kagemusha_load(&first, &ALICE_ID)
                    .is_ok()
            );
        }
        transaction.current_direct_kagemusha_load_instruction_index = Some(2);
        assert!(
            transaction
                .require_direct_kagemusha_load(&second, &ALICE_ID)
                .is_ok()
        );
        assert!(
            transaction
                .require_direct_kagemusha_load(&first, &ALICE_ID)
                .is_err()
        );
    }

    #[test]
    fn direct_load_binding_rejects_nested_frames_and_changed_payers() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        let load = load(1);
        bind(
            &mut transaction,
            signed(
                &state,
                Executable::Instructions(vec![load.clone().into()].into()),
            ),
        );
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
        transaction.current_direct_kagemusha_load_instruction_index = Some(0);
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &BOB_ID)
                .is_err()
        );
        transaction.active_trigger_execution_depth = 1;
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
        transaction.active_trigger_execution_depth = 0;
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_ok()
        );
        transaction.current_direct_kagemusha_load_instruction_index = None;
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
    }

    #[test]
    fn direct_load_binding_rejects_changed_transaction_context() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        let load = load(1);
        let source = signed(
            &state,
            Executable::Instructions(vec![load.clone().into()].into()),
        );
        for field in 0..4 {
            bind(&mut transaction, source.clone());
            transaction.current_direct_kagemusha_load_instruction_index = Some(0);
            match field {
                0 => transaction.current_tx_hash = None,
                1 => transaction.current_network_entrypoint_hash = None,
                2 => transaction.tx_call_hash = None,
                _ => transaction.current_entrypoint_index = Some(4),
            }
            assert!(
                transaction
                    .require_direct_kagemusha_load(&load, &ALICE_ID)
                    .is_err()
            );
            transaction.bind_kagemusha_load_entrypoint_v1(Some(&source));
            transaction.current_direct_kagemusha_load_instruction_index = Some(0);
            // A different source index is valid only after a fresh source binding.
            assert_eq!(
                transaction
                    .require_direct_kagemusha_load(&load, &ALICE_ID)
                    .is_ok(),
                field == 3
            );
        }
    }

    #[test]
    fn direct_load_binding_does_not_survive_rebinding_or_a_new_overlay() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let load = load(1);
        {
            let mut transaction = block.transaction();
            let source = signed(
                &state,
                Executable::Instructions(vec![load.clone().into()].into()),
            );
            for replacement in [
                None,
                Some(signed(
                    &state,
                    Executable::Instructions(
                        vec![Log::new(iroha_logger::Level::INFO, "ordinary".into()).into()].into(),
                    ),
                )),
                Some(signed(
                    &state,
                    Executable::Batch(
                        vec![ExecutableBatchItem::Instruction(load.clone().into())].into(),
                    ),
                )),
            ] {
                bind(&mut transaction, source.clone());
                transaction.current_direct_kagemusha_load_instruction_index = Some(0);
                transaction.bind_kagemusha_load_entrypoint_v1(replacement.as_ref());
                assert!(
                    transaction
                        .current_direct_kagemusha_load_instruction_index
                        .is_none()
                );
                transaction.current_direct_kagemusha_load_instruction_index = Some(0);
                assert!(
                    transaction
                        .require_direct_kagemusha_load(&load, &ALICE_ID)
                        .is_err()
                );
            }
        }
        let mut transaction = block.transaction();
        transaction.current_direct_kagemusha_load_instruction_index = Some(0);
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
    }

    #[test]
    fn direct_load_binding_rejects_forged_signatures_and_foreign_networks() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        let load = load(1);
        let forged = TransactionBuilder::new(
            *state.network_id_ref(),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([load.clone()])
        .build_with_signature(iroha_crypto::Signature::from_bytes(&[0; 64]));
        assert!(forged.verify_signature().is_err());
        let foreign = TransactionBuilder::new(
            iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"foreign network"),
            )),
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([load.clone()])
        .sign(ALICE_KEYPAIR.private_key());
        for source in [forged, foreign] {
            bind(&mut transaction, source);
            transaction.current_direct_kagemusha_load_instruction_index = Some(0);
            assert!(
                transaction
                    .require_direct_kagemusha_load(&load, &ALICE_ID)
                    .is_err()
            );
        }
    }

    #[test]
    fn sealed_reveal_cannot_inherit_external_load_authority() {
        use iroha_data_model::transaction::signed::{
            SealedTransactionReveal, compute_sealed_transaction_commitment,
        };
        let state = state();
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::MIN,
            None,
            None,
            0,
            0,
        ));
        let mut transaction = block.transaction();
        let load = load(1);
        let source = signed(
            &state,
            Executable::Instructions(vec![load.clone().into()].into()),
        );
        bind(&mut transaction, source.clone());
        transaction.current_direct_kagemusha_load_instruction_index = Some(0);
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_ok()
        );
        let salt = [5; 32];
        let commitment =
            compute_sealed_transaction_commitment(state.network_id_ref(), &source, salt, 10);
        let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
            commitment,
            source.clone(),
            salt,
        ));
        seed_committed_transaction_context(&mut transaction, &reveal, 3);
        transaction.current_direct_kagemusha_load_instruction_index = Some(0);
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
        // The executor receives the signed body, but its source is still the reveal.
        transaction.bind_kagemusha_load_entrypoint_v1(Some(&source));
        transaction.current_direct_kagemusha_load_instruction_index = Some(0);
        assert!(
            transaction
                .require_direct_kagemusha_load(&load, &ALICE_ID)
                .is_err()
        );
    }
}
