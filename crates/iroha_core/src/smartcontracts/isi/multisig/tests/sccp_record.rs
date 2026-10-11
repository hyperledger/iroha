//! A multisig proposal approved by signed transactions records an outbound SCCP message from
//! the multisig account; an opaque proposal or approval of the same record cannot
//! (`specs/sccp.md` §4.4).

use super::*;
use crate::execution_attempt::ExecutionAttemptError;
use crate::smartcontracts::isi::sccp::{
    escrow,
    test_support::{
        ONE_XOR, install_outbound_route, outbound_record, outbound_sender, set_xor_balance,
    },
};
use iroha_data_model::sccp::escrow::sccp_taira_xor_asset_definition_id;

fn signatory(seed: u8) -> AccountId {
    new_account_id(&KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519))
}

fn assert_opaque_record_rejection(result: Result<(), ExecutionAttemptError<ValidationFail>>) {
    assert!(
        matches!(&result, Err(ExecutionAttemptError::Rejected(ValidationFail::NotPermitted(message)))
            if message.contains("derived `RecordSccpMessage`")),
        "{result:?}"
    );
}

fn bind_scope(tx: &mut StateTransaction<'_, '_>) {
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
}

/// Register the multisig account of `signatories` with `quorum`, live SCCP for an Ethereum
/// record, and 10 XOR held by the multisig account. Return the multisig account.
fn install_multisig_sender(
    tx: &mut StateTransaction<'_, '_>,
    registrar: &AccountId,
    signatories: BTreeMap<AccountId, u8>,
    quorum: NonZeroU16,
) -> AccountId {
    let spec = MultisigSpec::new(signatories, quorum, nonzero!(60_000_u64));
    let multisig = AccountId::new_multisig(multisig_policy_from_spec(&spec).unwrap());
    bind_scope(tx);
    for account in spec.signatories.keys().chain(core::iter::once(&multisig)) {
        if tx.world.accounts.get(account).is_none() {
            tx.world.accounts.insert(
                account.clone(),
                Account::new(account.clone())
                    .build(registrar)
                    .into_key_value()
                    .1,
            );
        }
    }
    install_outbound_route(tx, 100 * ONE_XOR);
    set_xor_balance(tx, &multisig, 10 * ONE_XOR);
    persist_multisig_account_state(
        tx,
        None,
        &MultisigAccountState::new(multisig.clone(), None, spec),
    )
    .unwrap();
    multisig
}

fn assert_recorded_from(tx: &StateTransaction<'_, '_>, multisig: &AccountId) {
    assert_eq!(outbound_sender(&*tx.world, 0), Some(multisig.clone()));
    assert_eq!(
        tx.world
            .assets
            .get(&AssetId::of(
                sccp_taira_xor_asset_definition_id(),
                multisig.clone()
            ))
            .map(|value| value.as_ref().clone()),
        Some(escrow::xor_quantity(8 * ONE_XOR).unwrap())
    );
}

#[test]
fn signed_multisig_approval_records_and_opaque_paths_cannot() {
    // Instruction execution needs the immutable root scope of an original signed genesis.
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        2,
        2_000,
        |block, signer1, _, _| record_through_signed_multisig(block, signer1),
    );
}

fn record_through_signed_multisig(block: &mut crate::state::StateBlock<'_>, signer1: &AccountId) {
    let signer2 = signatory(72);
    let proposal_call = Hash::prehashed([0xE1; Hash::LENGTH]);
    let approval_call = Hash::prehashed([0xE2; Hash::LENGTH]);
    block.admit_fastpq_source_for_testing(proposal_call);
    block.admit_fastpq_source_for_testing(approval_call);
    let mut tx = block.transaction_for_callback_testing();
    let multisig = install_multisig_sender(
        &mut tx,
        signer1,
        BTreeMap::from([(signer1.clone(), 1), (signer2.clone(), 1)]),
        nonzero!(2_u16),
    );

    let instructions: Vec<InstructionBox> = vec![outbound_record(2, [0x22; 20]).into()];
    let instructions_hash = HashOf::new(&instructions);
    let proposal = MultisigPropose::new(multisig.clone(), instructions.clone(), None);
    // A trigger body or contract output may not create the proposal.
    let opaque_proposal: InstructionBox = proposal.clone().into();
    assert_opaque_record_rejection(
        crate::deferred_authority::reject_opaque_instruction_authority(
            core::iter::once(&opaque_proposal),
            &tx,
        ),
    );
    // Signed path: signer 1 proposes.
    tx.tx_call_hash = Some(proposal_call);
    execute_propose(&mut tx, signer1, &proposal).expect("signed proposal");
    assert!(outbound_sender(&*tx.world, 0).is_none());
    // An opaque approval resolves the live proposal and is refused.
    let approval = MultisigApprove::new(multisig.clone(), instructions_hash);
    let opaque_approval: InstructionBox = approval.clone().into();
    assert_opaque_record_rejection(
        crate::deferred_authority::reject_opaque_instruction_authority(
            core::iter::once(&opaque_approval),
            &tx,
        ),
    );
    // Signed path: signer 2's approval reaches quorum and records from the multisig account.
    tx.tx_call_hash = Some(approval_call);
    execute_approve(&mut tx, &signer2, &approval).expect("signed approval records");
    assert_recorded_from(&tx, &multisig);
}

#[test]
fn signed_transactions_record_through_multisig_end_to_end() {
    // The complete signed-transaction executor admits the propose and approve transactions;
    // the approval that reaches quorum records from the multisig account.
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        2,
        2_000,
        |block, authority, _, _| {
            let key_pair = KeyPair::from_seed(vec![55; 32], Algorithm::Ed25519);
            assert_eq!(*authority, new_account_id(&key_pair));
            // The signed authority alone carries quorum weight, so its own signed
            // transactions both propose and approve.
            let multisig = {
                let mut tx = block.transaction_for_callback_testing();
                let multisig = install_multisig_sender(
                    &mut tx,
                    authority,
                    BTreeMap::from([(authority.clone(), 2), (signatory(73), 1)]),
                    nonzero!(2_u16),
                );
                tx.apply();
                multisig
            };
            let instructions: Vec<InstructionBox> = vec![outbound_record(2, [0x22; 20]).into()];
            let steps: [InstructionBox; 2] = [
                MultisigPropose::new(multisig.clone(), instructions.clone(), None).into(),
                MultisigApprove::new(multisig.clone(), HashOf::new(&instructions)).into(),
            ];
            for (step, instruction) in steps.into_iter().enumerate() {
                let signed = iroha_data_model::transaction::TransactionBuilder::new(
                    block.network_id,
                    authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(
                        Vec::new(),
                        NonZeroU64::new(100_000_000),
                    ),
                )
                .with_executable(Executable::Instructions(vec![instruction].into()))
                .sign(key_pair.private_key());
                let call = Hash::from(signed.hash_as_entrypoint());
                let mut tx = block.transaction_for_fastpq_testing(call);
                bind_scope(&mut tx);
                Executor::Initial
                    .execute_transaction(
                        &mut tx,
                        authority,
                        signed,
                        &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                    )
                    .map_err(crate::execution_attempt::expect_completed_rejection)
                    .expect("signed multisig transaction");
                if step == 0 {
                    assert!(outbound_sender(&*tx.world, 0).is_none());
                } else {
                    assert_recorded_from(&tx, &multisig);
                }
                tx.complete_direct_callbacks(call)
                    .expect("complete the signed transaction's callbacks");
                tx.apply();
            }
            let tx = block.transaction_for_callback_testing();
            assert_recorded_from(&tx, &multisig);
        },
    );
}
