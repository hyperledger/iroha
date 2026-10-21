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
}
