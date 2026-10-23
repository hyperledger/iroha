//! FI off-ramp accounting and two-party linkage lifecycle checks.

use super::*;
use iroha_data_model::{
    asset::fi_link::{AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiV1},
    isi::asset_fi::{
        SetAssetFiLinkAttestationV1, SetAssetFiLinkV1, SetAssetFiV1, TransferToLinkedFiV1,
    },
};

pub(super) fn setup(f: &Fixture, tx: &mut StateTransaction<'_, '_>) -> AssetFiLinkV1 {
    SetAssetFiV1 {
        fi: AssetFiV1 {
            asset_definition_id: f.definition.clone(),
            fi_account_id: f.payee.clone(),
            revision: 1,
            enabled: true,
        },
    }
    .execute(&f.owner, tx)
    .unwrap();
    SetAssetFiLinkAttestationV1 {
        attestation: AssetFiLinkAttestationV1 {
            asset_definition_id: f.definition.clone(),
            account_id: f.first.clone(),
            fi_account_id: f.payee.clone(),
            reference_digest: [19; 32],
            revision: 1,
            enabled: true,
        },
    }
    .execute(&f.payee, tx)
    .unwrap();
    let link = AssetFiLinkV1 {
        asset_definition_id: f.definition.clone(),
        account_id: f.first.clone(),
        fi_account_id: f.payee.clone(),
        reference_digest: [19; 32],
        fi_revision: 1,
        attestation_revision: 1,
        revision: 1,
        enabled: true,
        controller: None,
        waterfall: false,
        reverse_waterfall: false,
    };
    SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 1,
    }
    .execute(&f.first, tx)
    .unwrap();
    link
}

fn off_ramp(f: &Fixture, amount: u32) -> TransferToLinkedFiV1 {
    TransferToLinkedFiV1 {
        asset_definition_id: f.definition.clone(),
        account_id: f.first.clone(),
        amount: amount.into(),
        expected_link_revision: 1,
        expected_policy_revision: 1,
    }
}

#[test]
fn linked_fi_defund_excludes_spending_but_enforces_gross_outgoing() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-spend-and-outgoing"));
    let mut policy = f.policy(1, 50, 0);
    policy.daily_outgoing_limit = Some(6_u32.into());
    SetAssetUidPolicyV1 { policy }
        .execute(&f.owner, &mut tx)
        .unwrap();
    setup(&f, &mut tx);
    f.transfer(&mut tx, &f.first, &f.payee, 1)
        .expect_err("ordinary transfer to a linked FI still counts as PAY");
    off_ramp(&f, 5).execute(&f.first, &mut tx).unwrap();
    let view = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 1)
        .unwrap()
        .remove(0);
    assert_eq!(view.daily_spend_usage, Quantity::zero());
    assert_eq!(view.daily_outgoing_usage, Quantity::from(5_u32));
    assert_eq!(view.beneficial_holdings, Quantity::from(45_u32));
    off_ramp(&f, 2)
        .execute(&f.first, &mut tx)
        .expect_err("legitimate defunding still obeys the separate gross ceiling");
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(35_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(5_u32));
    off_ramp(&f, 1)
        .execute(&f.payee, &mut tx)
        .expect_err("FI attestation is not customer debit authority");
}

#[test]
fn eligible_fi_and_retail_uid_membership_are_disjoint_in_both_update_orders() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-membership-disjoint"));
    f.configure(&mut tx, 1, 50, 50);
    SetAssetFiV1 {
        fi: AssetFiV1 {
            asset_definition_id: f.definition.clone(),
            fi_account_id: f.first.clone(),
            revision: 1,
            enabled: true,
        },
    }
    .execute(&f.owner, &mut tx)
    .expect_err("a UID wallet cannot acquire an FI exemption");
    setup(&f, &mut tx);
    let mut policy = f.policy(2, 50, 50);
    policy.accounts.insert(f.payee.clone());
    SetAssetUidPolicyV1 { policy }
        .execute(&f.owner, &mut tx)
        .expect_err("an eligible FI account cannot join a retail holding bucket");
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    asset_uid::validate_persistence(tx.world()).unwrap();
}

#[test]
fn fi_reference_and_capabilities_require_distinct_authorities_and_exact_revisions() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-two-party-link"));
    f.configure(&mut tx, 1, 50, 50);
    let mut link = setup(&f, &mut tx);
    link.revision = 2;
    SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 1,
    }
    .execute(&f.payee, &mut tx)
    .expect_err("FI cannot approve wallet capability");
    SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 2,
    }
    .execute(&f.first, &mut tx)
    .expect_err("stale policy consent cannot activate link");
    let mut foreign = link.clone();
    foreign.reference_digest = [20; 32];
    SetAssetFiLinkV1 {
        link: foreign,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .expect_err("owner cannot invent an FI-attested reference");
    let attestation = AssetFiLinkAttestationV1 {
        asset_definition_id: f.definition.clone(),
        account_id: f.first.clone(),
        fi_account_id: f.payee.clone(),
        reference_digest: [19; 32],
        revision: 2,
        enabled: false,
    };
    SetAssetFiLinkAttestationV1 {
        attestation: attestation.clone(),
    }
    .execute(&f.first, &mut tx)
    .expect_err("wallet cannot forge FI attestation");
    SetAssetFiLinkAttestationV1 { attestation }
        .execute(&f.payee, &mut tx)
        .unwrap();
    off_ramp(&f, 1)
        .execute(&f.first, &mut tx)
        .expect_err("FI revocation immediately stops the old owner link");
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
    // A stale/revoked reference does not prevent its owner explicitly disabling it.
    link.enabled = false;
    SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 1,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
}

#[test]
fn linked_fi_usage_and_missing_relationships_preserve_exact_calendar_state() {
    use iroha_data_model::asset::uid::AssetUidDailyWindowV1;
    let (f, state) = fixture(40, 10);
    // 2026-10-24 noon UTC is the final day of Israel daylight time. Its next
    // local day lasts 25 hours; a policy update must not invent a UTC reset.
    let now = 1_792_843_200_000;
    let mut block = state.block(header(1, now));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-calendar-usage"));
    let mut policy = f.policy(1, 50, 10);
    policy.daily_window = AssetUidDailyWindowV1::JerusalemDay;
    policy.daily_outgoing_limit = Some(20_u32.into());
    SetAssetUidPolicyV1 {
        policy: policy.clone(),
    }
    .execute(&f.owner, &mut tx)
    .unwrap();
    let query = iroha_data_model::query::asset_fi::FindAssetFiLinkV1 {
        asset_definition_id: f.definition.clone(),
        account_id: f.first.clone(),
        fi_account_id: f.payee.clone(),
        reference_digest: [19; 32],
    };
    let missing = crate::state::asset_fi::view(tx.world(), &query, now, 1).unwrap();
    assert!(missing.fi.is_none() && missing.attestation.is_none() && missing.link.is_none());
    assert_eq!((missing.ledger_time_ms, missing.as_of_height), (now, 1));
    setup(&f, &mut tx);
    f.transfer(&mut tx, &f.second, &f.attestor, 4).unwrap();
    off_ramp(&f, 7).execute(&f.first, &mut tx).unwrap();
    let before = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), now, 1)
        .unwrap()
        .remove(0);
    assert_eq!(before.daily_spend_usage, Quantity::from(4_u32));
    assert_eq!(before.daily_outgoing_usage, Quantity::from(11_u32));
    policy.revision = 2;
    policy.daily_spend_limit = Some(3_u32.into());
    policy.daily_outgoing_limit = Some(12_u32.into());
    SetAssetUidPolicyV1 { policy }
        .execute(&f.owner, &mut tx)
        .unwrap();
    let after = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), now, 1)
        .unwrap()
        .remove(0);
    assert_eq!(after.day_start_ms, before.day_start_ms);
    assert_eq!(after.daily_spend_usage, before.daily_spend_usage);
    assert_eq!(after.daily_outgoing_usage, before.daily_outgoing_usage);
    f.transfer(&mut tx, &f.second, &f.attestor, 1)
        .expect_err("lowering the spending cap preserves previously charged spending");
    let mut withdrawal = off_ramp(&f, 1);
    withdrawal.expected_policy_revision = 2;
    withdrawal.clone().execute(&f.first, &mut tx).unwrap();
    withdrawal
        .execute(&f.first, &mut tx)
        .expect_err("the independent outgoing allowance is now exhausted");
    asset_uid::validate_persistence(tx.world()).unwrap();
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    let current = crate::state::asset_fi::view(tx.world(), &query, now, 1).unwrap();
    assert!(current.fi.unwrap().enabled);
    assert!(current.attestation.unwrap().enabled);
    assert!(current.link.unwrap().enabled);
}

pub(super) fn controller(
    f: &Fixture,
    state: &State,
) -> crate::executor::ContractRuntimeExecutionContext {
    use iroha_data_model::{
        account::{AccountDetails, AccountValue},
        smart_contract::ContractAddress,
    };
    let address = ContractAddress::derive(
        &state.network_id,
        &f.owner,
        911,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let subject = address.subject_id();
    let code = Hash::new("fi-link-reader-controller");
    let mut world = state.world.block();
    world.accounts.insert(
        subject.clone(),
        AccountValue::new(AccountDetails::default()),
    );
    world.contract_instances.insert(address.clone(), code);
    world
        .contract_subject_addresses
        .insert(subject.clone(), address.clone());
    world.contract_subject_bindings.insert(
        address.clone(),
        crate::smartcontracts::code::ContractSubjectBinding::new_direct(&address, f.owner.clone())
            .with_active_code_hash(code),
    );
    world.commit();
    crate::executor::ContractRuntimeExecutionContext {
        contract_address: address,
        contract_subject: subject,
        contract_alias: None,
        entrypoint: "settle".into(),
    }
}

#[test]
fn uid_quote_requires_reader_grant_and_meters_even_terminal_escrows() {
    use crate::{
        smartcontracts::isi::query::QueryExecutionBudget,
        state::asset_uid_reader::{self, AssetUidHoldingQuoteError},
    };
    use iroha_data_model::isi::asset_uid::SetAssetUidPolicyReaderV1;
    let (f, state) = fixture(40, 10);
    let context = controller(&f, &state);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("uid-private-metered-quote"));
    f.configure(&mut tx, 1, 50, 100);
    let budget = QueryExecutionBudget::from_weighted_limit(1_000_000, 1, 1);
    let quote = |tx: &StateTransaction<'_, '_>, account: &AccountId, budget| {
        asset_uid_reader::quote_for_contract(
            tx.world(),
            &context.contract_subject,
            &context,
            &f.definition,
            account,
            &Quantity::from(10_u32),
            budget,
        )
    };
    quote(&tx, &f.first, budget)
        .expect_err("contract deployment is not permission to link UID wallets");
    let grant = SetAssetUidPolicyReaderV1 {
        asset_definition_id: f.definition.clone(),
        controller: context.contract_address.clone(),
        revision: 1,
        enabled: true,
    };
    grant
        .clone()
        .execute(&f.first, &mut tx)
        .expect_err("wallet cannot grant global UID quotes");
    grant.clone().execute(&f.owner, &mut tx).unwrap();
    let (before, before_stats) = quote(&tx, &f.first, budget).unwrap();
    assert_eq!(before.beneficial_holdings, Quantity::from(50_u32));
    assert_eq!(before.required_overflow, Quantity::from(10_u32));
    quote(&tx, &f.owner, budget).expect_err("unbound accounts do not fall back to liquid balance");
    let exhausted = QueryExecutionBudget::from_weighted_limit(0, 1, 1);
    assert!(matches!(
        quote(&tx, &f.first, exhausted),
        Err(AssetUidHoldingQuoteError::Query(
            iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
        ))
    ));
    let opening = f.escrow("metered-quote-escrow", 30, 50_000);
    let id = opening.escrow_id;
    opening.execute(&f.first, &mut tx).unwrap();
    let (locked, locked_stats) = quote(&tx, &f.first, budget).unwrap();
    assert_eq!(locked, before);
    assert!(locked_stats.processed_items() > before_stats.processed_items());
    AttestEscrowCondition::new(
        id,
        "confirmed".parse().unwrap(),
        ConditionalEscrowValue::Bool(true),
        Some(Hash::new("metered scanner confirmation")),
    )
    .execute(&f.attestor, &mut tx)
    .unwrap();
    let (released, released_stats) = quote(&tx, &f.first, budget).unwrap();
    assert_eq!(released.beneficial_holdings, Quantity::from(20_u32));
    assert_eq!(
        released_stats.processed_items(),
        before_stats.processed_items() + 2,
        "terminal seller index and retained escrow record still consume work"
    );
    let limits = norito::DecodeLimits::new(1, 1, 1, 1, 1);
    let (deferred, _) =
        norito::core::with_decode_limits_measured(limits, || quote(&tx, &f.first, budget));
    match deferred {
        Err(AssetUidHoldingQuoteError::Local(owner)) => {
            assert!(
                owner.decode_refusal().is_some(),
                "original enclosing decode refusal survives"
            );
        }
        other => panic!("enclosing local memory refusal must not reject the contract: {other:?}"),
    }
    SetAssetUidPolicyReaderV1 {
        revision: 2,
        enabled: false,
        ..grant
    }
    .execute(&f.owner, &mut tx)
    .unwrap();
    quote(&tx, &f.first, budget).expect_err("revocation takes effect immediately");
    asset_uid_reader::validate_persistence(tx.world()).unwrap();
}

#[test]
fn linked_fi_controller_requires_current_owner_consent_frame_and_beneficial_excess() {
    use crate::executor::Executor;
    let (f, state) = fixture(40, 10);
    let context = controller(&f, &state);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let mut block = state.block(header(2, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-controller-overflow"));
    f.configure(&mut tx, 1, 50, 0);
    let mut link = setup(&f, &mut tx);
    f.configure(&mut tx, 2, 20, 0);
    let transfer = TransferToLinkedFiV1 {
        amount: 30_u32.into(),
        expected_policy_revision: 2,
        ..off_ramp(&f, 30)
    };
    let run = |tx: &mut StateTransaction<'_, '_>,
               value: TransferToLinkedFiV1,
               frame: Option<&crate::executor::ContractRuntimeExecutionContext>| {
        Executor::Initial.execute_instruction_with_contract_runtime_context(
            tx,
            &context.contract_subject,
            value.into(),
            frame,
        )
    };
    run(&mut tx, transfer.clone(), Some(&context))
        .expect_err("beneficial excess alone does not authorize a controller");
    link.revision = 2;
    link.controller = Some(context.contract_address.clone());
    link.waterfall = true;
    SetAssetFiLinkV1 {
        link: link.clone(),
        expected_policy_revision: 2,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    run(&mut tx, transfer.clone(), Some(&context))
        .expect_err("old link revision cannot authorize sweep");
    let transfer = TransferToLinkedFiV1 {
        expected_link_revision: 2,
        ..transfer
    };
    run(&mut tx, transfer.clone(), None)
        .expect_err("subject identity is not authenticated controller frame");
    run(
        &mut tx,
        TransferToLinkedFiV1 {
            amount: 31_u32.into(),
            ..transfer.clone()
        },
        Some(&context),
    )
    .expect_err("owner waterfall consent does not authorize more than current excess");
    let wrong = crate::executor::ContractRuntimeExecutionContext {
        contract_subject: f.owner.clone(),
        ..context.clone()
    };
    run(&mut tx, transfer.clone(), Some(&wrong))
        .expect_err("inconsistent controller frame is denied");
    run(&mut tx, transfer.clone(), Some(&context)).unwrap();
    let receipt = fi_receipt(tx.world(), &f, &Hash::new("fi-controller-overflow"), 0);
    assert_eq!(receipt.authority, context.contract_subject);
    assert_eq!(receipt.link, link);
    assert_eq!(receipt.instruction, transfer);
    assert_eq!(receipt.uid_policy_revision, 2);
    let actual = receipt
        .controller
        .expect("actual authenticated controller frame");
    assert_eq!(actual.address, context.contract_address);
    assert_eq!(actual.subject, context.contract_subject);
    assert_eq!(actual.entrypoint, context.entrypoint);
    assert_eq!(f.holdings(&tx), Quantity::from(20_u32));
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(10_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(30_u32));
    run(&mut tx, transfer, Some(&context)).expect_err("a replay has no beneficial excess left");
    let view = asset_uid::views(tx.world(), &f.definition, Some(&[7; 32]), 1_000, 2)
        .unwrap()
        .remove(0);
    assert_eq!(view.daily_spend_usage, Quantity::zero());
    assert_eq!(view.daily_outgoing_usage, Quantity::from(30_u32));
    link.revision = 3;
    link.waterfall = false;
    SetAssetFiLinkV1 {
        link,
        expected_policy_revision: 2,
    }
    .execute(&f.first, &mut tx)
    .unwrap();
    f.configure(&mut tx, 3, 10, 0);
    run(
        &mut tx,
        TransferToLinkedFiV1 {
            amount: 10_u32.into(),
            expected_link_revision: 3,
            expected_policy_revision: 3,
            ..off_ramp(&f, 10)
        },
        Some(&context),
    )
    .expect_err("revoked owner waterfall flag cannot be bypassed by an active controller");
    assert_eq!(
        fi_receipt_count(tx.world()),
        1,
        "refused controller calls add no receipts"
    );
    // Fixture-only removal isolates the receipt's historical controller retention.
    tx.world
        .smart_contract_state
        .remove(crate::state::asset_fi::link_key(&f.definition, &f.first));
    assert!(
        crate::state::asset_fi::retained(tx.world(), None, Some(&context.contract_subject))
            .unwrap()
    );
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
}

fn fi_receipt(
    world: &impl WorldReadOnly,
    f: &Fixture,
    call: &Hash,
    index: u64,
) -> iroha_data_model::asset::fi_link::AssetFiTransferReceiptV1 {
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, call, index);
    norito::decode_canonical(
        world
            .smart_contract_state()
            .get(&key)
            .expect("native FI receipt"),
    )
    .expect("canonical native FI receipt")
}

fn fi_receipt_count(world: &impl WorldReadOnly) -> usize {
    world
        .smart_contract_state()
        .iter()
        .filter(|(key, _)| {
            key.as_ref()
                .starts_with(crate::state::asset_fi::RECEIPT_ROOT)
        })
        .count()
}

fn world_balance(world: &impl WorldReadOnly, f: &Fixture, account: &AccountId) -> Quantity {
    world
        .assets()
        .get(&f.asset(account))
        .map(|value| value.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}

#[test]
fn linked_fi_receipts_bind_distinct_identical_occurrences_to_full_execution_facts() {
    let (f, state) = fixture(40, 10);
    let call = Hash::new("fi-receipt-identical-occurrences");
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(call);
    f.configure(&mut tx, 1, 50, 0);
    let link = setup(&f, &mut tx);
    let fi = crate::state::asset_fi::fi(tx.world(), &f.definition, &f.payee)
        .unwrap()
        .unwrap();
    let attestation = crate::state::asset_fi::attestation(
        tx.world(),
        &f.definition,
        &f.first,
        &f.payee,
        &link.reference_digest,
    )
    .unwrap()
    .unwrap();
    let policy = f.policy(1, 50, 0);
    let instruction = off_ramp(&f, 3);
    let instruction_hash =
        Hash::new(asset_uid::encode(&InstructionBox::from(instruction.clone())).unwrap());
    let policy_hash = Hash::new(asset_uid::encode(&policy).unwrap());
    for index in 0_u64..2 {
        instruction.clone().execute(&f.first, &mut tx).unwrap();
        let record = fi_receipt(tx.world(), &f, &call, index);
        assert_eq!(record.asset_incarnation, *tx.world().axt_asset_incarnations().get(&f.definition).unwrap());
        assert_eq!(record.network, state.network_id);
        assert_eq!(record.execution_call_hash, call);
        assert_eq!(record.instruction, instruction);
        assert_eq!(record.instruction_hash, instruction_hash);
        assert_eq!(record.authority, f.first);
        assert!(record.controller.is_none());
        assert_eq!(record.fi, fi);
        assert_eq!(record.attestation, attestation);
        assert_eq!(record.link, link);
        assert_eq!(record.uid, [7; 32]);
        assert_eq!(record.uid_policy_revision, policy.revision);
        assert_eq!(record.uid_policy_hash, policy_hash);
        assert_eq!(
            (record.execution_height, record.execution_time_ms),
            (1, 1_000)
        );
        assert_eq!(record.transcript_index, index);
        let bytes = asset_uid::encode(&record).unwrap();
        assert_eq!(
            norito::decode_canonical::<iroha_data_model::asset::fi_link::AssetFiTransferReceiptV1>(
                &bytes
            )
            .unwrap(),
            record
        );
        let transcript = &tx.retail_fee_transcripts_for_test()[usize::try_from(index).unwrap()];
        assert_eq!(transcript.batch_hash, record.execution_call_hash);
        assert_eq!(
            transcript.authority_digest,
            crate::fastpq::authority_digest(&record.authority)
        );
        assert_eq!(transcript.deltas.len(), 1);
        let delta = &transcript.deltas[0];
        assert_eq!(delta.from_account, record.instruction.account_id);
        assert_eq!(delta.to_account, record.fi.fi_account_id);
        assert_eq!(
            delta.asset_definition,
            record.instruction.asset_definition_id
        );
        assert_eq!(delta.amount, record.instruction.amount);
        assert_eq!(
            delta.from_balance_after,
            Quantity::from(40 - 3 * u32::try_from(index + 1).unwrap())
        );
        assert_eq!(
            delta.to_balance_after,
            Quantity::from(3 * u32::try_from(index + 1).unwrap())
        );
    }
    assert_eq!(fi_receipt_count(tx.world()), 2);
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(34_u32));
    assert_eq!(f.balance(&tx, &f.payee), Quantity::from(6_u32));
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
}

#[test]
fn linked_fi_receipts_exclude_generic_payments_and_refused_instructions() {
    let (f, state) = fixture(40, 10);
    let call = Hash::new("fi-receipt-refusal-and-ordinary-payment");
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(call);
    f.configure(&mut tx, 1, 50, 10);
    setup(&f, &mut tx);
    f.transfer(&mut tx, &f.first, &f.payee, 2).unwrap();
    assert_eq!(
        fi_receipt_count(tx.world()),
        0,
        "FI destination is not a native defund purpose"
    );
    let initial_transcripts = tx.pending_transfer_transcript_count_for_testing();
    for (instruction, authority) in [
        (
            TransferToLinkedFiV1 {
                expected_link_revision: 2,
                ..off_ramp(&f, 1)
            },
            &f.first,
        ),
        (
            TransferToLinkedFiV1 {
                expected_policy_revision: 2,
                ..off_ramp(&f, 1)
            },
            &f.first,
        ),
        (off_ramp(&f, 1), &f.payee),
        (off_ramp(&f, 100), &f.first),
    ] {
        instruction
            .execute(authority, &mut tx)
            .expect_err("refused native FI transfer");
        assert_eq!(fi_receipt_count(tx.world()), 0);
        assert_eq!(
            tx.pending_transfer_transcript_count_for_testing(),
            initial_transcripts
        );
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(38_u32));
        assert_eq!(f.balance(&tx, &f.payee), Quantity::from(2_u32));
    }
}

#[test]
fn linked_fi_receipt_ordinal_includes_prior_ordinary_and_applied_same_call_occurrences() {
    let (f, state) = fixture(40, 10);
    let call = Hash::new("fi-receipt-applied-and-pending-ordinal");
    let mut block = state.block(header(1, 1_000));
    {
        let mut tx = block.transaction_for_fastpq_testing(call);
        f.configure(&mut tx, 1, 50, 10);
        setup(&f, &mut tx);
        f.transfer(&mut tx, &f.first, &f.payee, 1).unwrap();
        off_ramp(&f, 2).execute(&f.first, &mut tx).unwrap();
        assert_eq!(fi_receipt(tx.world(), &f, &call, 1).transcript_index, 1);
        let absent = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 0);
        assert!(tx.world().smart_contract_state().get(&absent).is_none());
        tx.apply();
    }
    let mut tx = block.transaction_for_fastpq_testing(call);
    off_ramp(&f, 2).execute(&f.first, &mut tx).unwrap();
    assert_eq!(fi_receipt(tx.world(), &f, &call, 2).transcript_index, 2);
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 1);
    assert_eq!(fi_receipt_count(tx.world()), 2);
    assert_eq!(f.balance(&tx, &f.first), Quantity::from(35_u32));
}

#[test]
fn linked_fi_receipt_survives_revocation_policy_update_and_world_roundtrip() {
    let (f, state) = fixture(40, 10);
    state
        .block(header(1, 999))
        .commit_world_overlay_for_testing()
        .unwrap();
    let call = Hash::new("fi-receipt-before-revocation");
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 0);
    let original;
    {
        let mut block = state.block(header(2, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(call);
        f.configure(&mut tx, 1, 50, 0);
        setup(&f, &mut tx);
        off_ramp(&f, 3).execute(&f.first, &mut tx).unwrap();
        original = tx.world().smart_contract_state().get(&key).unwrap().clone();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    {
        let mut block = state.block(header(3, 2_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-receipt-revocation"));
        let mut link = crate::state::asset_fi::link(tx.world(), &f.definition, &f.first)
            .unwrap()
            .unwrap();
        link.revision = 2;
        link.enabled = false;
        SetAssetFiLinkV1 {
            link,
            expected_policy_revision: 1,
        }
        .execute(&f.first, &mut tx)
        .unwrap();
        SetAssetFiLinkAttestationV1 {
            attestation: AssetFiLinkAttestationV1 {
                revision: 2,
                enabled: false,
                ..crate::state::asset_fi::attestation(
                    tx.world(),
                    &f.definition,
                    &f.first,
                    &f.payee,
                    &[19; 32],
                )
                .unwrap()
                .unwrap()
            },
        }
        .execute(&f.payee, &mut tx)
        .unwrap();
        SetAssetFiV1 {
            fi: AssetFiV1 {
                asset_definition_id: f.definition.clone(),
                fi_account_id: f.payee.clone(),
                revision: 2,
                enabled: false,
            },
        }
        .execute(&f.owner, &mut tx)
        .unwrap();
        f.configure(&mut tx, 2, 50, 10);
        off_ramp(&f, 1)
            .execute(&f.first, &mut tx)
            .expect_err("revocation stops new transfers");
        assert_eq!(tx.world().smart_contract_state().get(&key), Some(&original));
        crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    let restored = crate::state::deserialize::decode_world_component_for_testing(&state.world)
        .expect("immutable FI receipt survives canonical World decoding after revocation");
    let view = restored.view();
    assert_eq!(view.smart_contract_state().get(&key), Some(&original));
    let record = fi_receipt(&view, &f, &call, 0);
    assert_eq!(record.link.revision, 1);
    assert!(record.link.enabled && record.fi.enabled && record.attestation.enabled);
    assert_eq!(record.uid_policy_revision, 1);
    assert_eq!(
        (record.execution_height, record.execution_time_ms),
        (2, 1_000)
    );
    crate::state::asset_fi::validate_persistence(&view).unwrap();
}

#[test]
fn linked_fi_receipt_alone_retains_references_and_rejects_a_changed_canonical_path() {
    let (f, state) = fixture(40, 10);
    let call = Hash::new("fi-receipt-retention-and-restore-shape");
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(call);
    f.configure(&mut tx, 1, 50, 0);
    let link = setup(&f, &mut tx);
    off_ramp(&f, 3).execute(&f.first, &mut tx).unwrap();
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 0);
    let bytes = tx.world().smart_contract_state().get(&key).unwrap().clone();
    // Remove the current rows only in this fixture. Retention must be supplied by
    // the immutable receipt itself, not accidentally by a current relationship.
    for current in [
        crate::state::asset_fi::fi_key(&f.definition, &f.payee),
        crate::state::asset_fi::attestation_key(
            &f.definition,
            &f.first,
            &f.payee,
            &link.reference_digest,
        ),
        crate::state::asset_fi::link_key(&f.definition, &f.first),
    ] {
        tx.world.smart_contract_state.remove(current);
    }
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    assert!(crate::state::asset_fi::retained(tx.world(), Some(&f.definition), None).unwrap());
    for account in [&f.first, &f.payee] {
        assert!(crate::state::asset_fi::retained(tx.world(), None, Some(account)).unwrap());
    }
    assert!(!crate::state::asset_fi::retained(tx.world(), None, Some(&f.attestor)).unwrap());
    let mut changed = fi_receipt(tx.world(), &f, &call, 0);
    changed.transcript_index = 1;
    tx.world
        .smart_contract_state
        .insert(key.clone(), asset_uid::encode(&changed).unwrap());
    crate::state::asset_fi::validate_persistence(tx.world())
        .expect_err("receipt body must match its immutable occurrence path");
    tx.world
        .smart_contract_state
        .insert(key.clone(), bytes.clone());
    let mut changed = fi_receipt(tx.world(), &f, &call, 0);
    changed.instruction.amount = Quantity::from(4_u32);
    tx.world
        .smart_contract_state
        .insert(key.clone(), asset_uid::encode(&changed).unwrap());
    crate::state::asset_fi::validate_persistence(tx.world())
        .expect_err("instruction substitution must fail its canonical hash");
    tx.world.smart_contract_state.insert(key, bytes);
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
}

#[test]
fn linked_fi_receipt_and_movement_disappear_on_outer_transaction_rollback() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    {
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-receipt-outer-rollback"));
        f.configure(&mut tx, 1, 50, 0);
        setup(&f, &mut tx);
        off_ramp(&f, 3).execute(&f.first, &mut tx).unwrap();
        assert_eq!(fi_receipt_count(tx.world()), 1);
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(37_u32));
        // Drop the exclusive State transaction without applying it.
    }
    assert_eq!(fi_receipt_count(&block.world), 0);
    assert_eq!(
        world_balance(&block.world, &f, &f.first),
        Quantity::from(40_u32)
    );
    assert_eq!(world_balance(&block.world, &f, &f.payee), Quantity::zero());
    assert!(block.transfer_transcripts_are_empty_for_testing());
}

#[test]
fn linked_fi_receipt_collision_poison_prevents_apply_of_prior_successful_movements() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    {
        let mut tx = block.transaction_for_fastpq_testing(Hash::new("fi-receipt-collision-setup"));
        f.configure(&mut tx, 1, 50, 10);
        setup(&f, &mut tx);
        tx.apply();
    }
    let call = Hash::new("fi-receipt-collision");
    let collision = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 1);
    {
        let mut tx = block.transaction_for_fastpq_testing(call);
        f.transfer(&mut tx, &f.first, &f.attestor, 1).unwrap();
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(39_u32));
        // Only a native test can inject this opaque journal collision. It must
        // refuse before principal debit and poison the already reserved occurrence.
        tx.world
            .smart_contract_state
            .insert(collision.clone(), vec![0xa5]);
        off_ramp(&f, 3)
            .execute(&f.first, &mut tx)
            .expect_err("immutable receipt key collision");
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(39_u32));
        assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
        assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 1);
        tx.apply();
    }
    assert!(block.world.smart_contract_state.get(&collision).is_none());
    assert_eq!(fi_receipt_count(&block.world), 0);
    assert_eq!(
        world_balance(&block.world, &f, &f.first),
        Quantity::from(40_u32)
    );
    assert_eq!(
        world_balance(&block.world, &f, &f.attestor),
        Quantity::zero()
    );
    assert_eq!(world_balance(&block.world, &f, &f.payee), Quantity::zero());
    assert!(block.transfer_transcripts_are_empty_for_testing());
    let view = asset_uid::views(&block.world, &f.definition, Some(&[7; 32]), 1_000, 1).unwrap();
    assert_eq!(view[0].daily_spend_usage, Quantity::zero());
    assert_eq!(view[0].daily_outgoing_usage, Quantity::zero());
}

#[test]
fn linked_fi_receipt_inserted_before_callback_failure_is_discarded_on_apply() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    {
        let mut tx =
            block.transaction_for_fastpq_testing(Hash::new("fi-receipt-post-insert-setup"));
        f.configure(&mut tx, 1, 50, 10);
        setup(&f, &mut tx);
        tx.apply();
    }
    let call = Hash::new("fi-receipt-post-insert-failure");
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 1);
    {
        let mut tx = block.transaction_for_fastpq_testing(call);
        f.transfer(&mut tx, &f.first, &f.payee, 1).unwrap();
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(39_u32));
        // A genuine prior transfer supplies the callback's delta-shaped fixture.
        // This test aborts after insertion, before any second monetary plan; it
        // exercises receipt rollback, not a new movement or witness certificate.
        let delta = tx.retail_fee_transcripts_for_test()[0].deltas[0].clone();
        let link = crate::state::asset_fi::link(tx.world(), &f.definition, &f.first)
            .unwrap()
            .unwrap();
        let policy = asset_uid::member_policy(tx.world(), &f.definition, &f.first)
            .unwrap()
            .unwrap();
        let capture = crate::state::asset_fi::receipt::Capture::admitted(
            &tx,
            &off_ramp(&f, 1),
            &f.first,
            None,
            link,
            &policy,
        )
        .unwrap();
        tx.apply_with_prepared_transfer_transcripts(&f.first, call, vec![delta.clone()], |tx| {
            capture.insert_before_movement(tx, call, &delta)?;
            assert!(
                tx.world().smart_contract_state().get(&key).is_some(),
                "the production receipt was inserted before the injected callback error"
            );
            assert_eq!(fi_receipt(tx.world(), &f, &call, 1).transcript_index, 1);
            Err::<(), Error>(crate::state::asset_fi::reject(
                "fixture failure after receipt insertion",
            ))
        })
        .expect_err("callback failure must poison the entire transaction");
        assert!(
            tx.world().smart_contract_state().get(&key).is_some(),
            "provisional state remains owned by the rollback overlay until drop"
        );
        assert_eq!(
            tx.pending_transfer_transcript_count_for_testing(),
            1,
            "a failed callback never stages the prepared occurrence"
        );
        tx.apply();
    }
    assert!(block.world.smart_contract_state.get(&key).is_none());
    assert_eq!(fi_receipt_count(&block.world), 0);
    assert_eq!(
        world_balance(&block.world, &f, &f.first),
        Quantity::from(40_u32)
    );
    assert_eq!(world_balance(&block.world, &f, &f.payee), Quantity::zero());
    assert!(block.transfer_transcripts_are_empty_for_testing());
    let view = asset_uid::views(&block.world, &f.definition, Some(&[7; 32]), 1_000, 1).unwrap();
    assert_eq!(view[0].daily_spend_usage, Quantity::zero());
    assert_eq!(view[0].daily_outgoing_usage, Quantity::zero());
}

#[test]
fn linked_fi_capture_requires_the_exact_valid_registry_incarnation_before_movement() {
    for corrupt in [false, true] {
        let (f, state) = fixture(40, 10);
        let call = Hash::new([u8::from(corrupt), 71]);
        let mut block = state.block(header(1, 1_000));
        let mut tx = block.transaction_for_fastpq_testing(call);
        f.configure(&mut tx, 1, 50, 10);
        setup(&f, &mut tx);
        let admitted = *tx.world().axt_asset_incarnations().get(&f.definition).unwrap();
        tx.world.axt_asset_incarnations.remove(f.definition.clone());
        // A token for another definition cannot supply the selected definition.
        let foreign = AssetDefinitionId::derive_from_components(
            DomainId::try_new("uid", "universal").unwrap(), "foreign".parse().unwrap());
        tx.world.axt_asset_incarnations.insert(foreign, admitted);
        if corrupt {
            // Follow the existing AXT JSON corruption fixture: the typed Hash
            // marker is syntactically valid, while the logical token is zero.
            let invalid = invalid_fi_incarnation(admitted);
            assert!(invalid.validate().is_err());
            tx.world.axt_asset_incarnations.insert(f.definition.clone(), invalid);
        }
        let before = tx.pending_transfer_transcript_count_for_testing();
        off_ramp(&f, 1).execute(&f.first, &mut tx).expect_err("missing or invalid exact incarnation refuses capture before debit");
        assert_eq!(fi_receipt_count(tx.world()), 0);
        assert_eq!(tx.pending_transfer_transcript_count_for_testing(), before);
        assert_eq!(f.balance(&tx, &f.first), Quantity::from(40_u32));
        assert_eq!(f.balance(&tx, &f.payee), Quantity::zero());
    }
}

#[test]
fn linked_fi_historical_incarnation_is_immutable_and_independent_of_the_current_map() {
    use iroha_data_model::nexus::AxtAssetIncarnationV1;
    let (f, state) = fixture(40, 10);
    let call = Hash::new("fi-historical-incarnation");
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction_for_fastpq_testing(call);
    f.configure(&mut tx, 1, 50, 10);
    setup(&f, &mut tx);
    let admitted = *tx.world().axt_asset_incarnations().get(&f.definition).unwrap();
    off_ramp(&f, 1).execute(&f.first, &mut tx).unwrap();
    let key = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, 0);
    let original = crate::state::asset_fi::receipt::read_record(tx.world(), &key).unwrap();
    assert_eq!(original.asset_incarnation, admitted);
    let later = AxtAssetIncarnationV1::try_from_bytes(*Hash::new("later-registration").as_ref()).unwrap();
    tx.world.axt_asset_incarnations.insert(f.definition.clone(), later);
    assert_eq!(crate::state::asset_fi::receipt::read_record(tx.world(), &key).unwrap(), original);
    // The occurrence itself must retain a valid token, even when today's map is valid.
    let mut corrupt = original;
    corrupt.asset_incarnation = invalid_fi_incarnation(admitted);
    tx.world.smart_contract_state.insert(key.clone(), asset_uid::encode(&corrupt).unwrap());
    assert!(crate::state::asset_fi::receipt::read_record(tx.world(), &key).is_err());
}

fn invalid_fi_incarnation(valid: iroha_data_model::nexus::AxtAssetIncarnationV1) -> iroha_data_model::nexus::AxtAssetIncarnationV1 {
    let mut value = norito::json::to_value(&valid).unwrap();
    value.as_array_mut().expect("transparent incarnation JSON tuple")[0] =
        norito::json::to_value(&Hash::prehashed([0; Hash::LENGTH])).unwrap();
    norito::json::from_value(value).expect("logical-zero hash is syntactically decodable")
}

#[test]
fn linked_fi_receipts_do_not_reinterpret_ordinary_logical_prefix_rows() {
    let (f, state) = fixture(40, 10);
    let mut block = state.block(header(1, 1_000));
    let mut tx = block.transaction();
    let ordinary: iroha_model_base::state_path::StatePath =
        "asset_fi_transfer_receipt_v1/ordinary".parse().unwrap();
    let bytes = b"ordinary user bytes, not a native receipt".to_vec();
    tx.world
        .smart_contract_state
        .insert(ordinary.clone(), bytes.clone());
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    assert!(!crate::state::asset_fi::retained(tx.world(), Some(&f.definition), None).unwrap());
    assert!(!crate::state::asset_fi::retained(tx.world(), None, Some(&f.first)).unwrap());
    assert_eq!(fi_receipt_count(tx.world()), 0);
    assert_eq!(
        tx.world().smart_contract_state().get(&ordinary),
        Some(&bytes)
    );

    let call = Hash::new("reserved native receipt path");
    let native = crate::state::asset_fi::receipt::key(&f.definition, &f.first, &call, u64::MAX);
    assert!(
        native
            .as_ref()
            .starts_with("sc/native/asset_fi_transfer_receipt_v1/")
    );
    assert!(
        native.as_ref().len() <= 256,
        "shared fixed key formatter must admit the maximal ordinal"
    );
    tx.world
        .smart_contract_state
        .insert(native.clone(), bytes.clone());
    crate::state::asset_fi::validate_persistence(tx.world())
        .expect_err("the native physical namespace still enforces canonical receipts");
    tx.world.smart_contract_state.remove(native);
    crate::state::asset_fi::validate_persistence(tx.world()).unwrap();
    assert_eq!(
        tx.world().smart_contract_state().get(&ordinary),
        Some(&bytes)
    );
}
