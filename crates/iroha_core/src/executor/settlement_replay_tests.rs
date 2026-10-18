//! Real native payment execution, duplicate fees and certified replay.

use std::{num::NonZeroU64, time::Duration};

use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    ValidationFail,
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    executor::SettlementReplayDispositionV1,
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements,
        InstructionBox, Mint, Register, SettleAtomic, SettlementId,
    },
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        error::TransactionRejectionReason,
    },
};
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;

use crate::{
    state::{World, WorldReadOnly},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn payer() -> KeyPair {
    KeyPair::from_seed(vec![0x78; 32], Algorithm::Ed25519)
}

fn recipient() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![0x79; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn account() -> AccountId {
    AccountId::new(payer().public_key().clone())
}

fn principal() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("payment", "universal").unwrap(),
        "principal".parse().unwrap(),
    )
}

fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}

fn config() -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::one();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = fee_asset().clone();
    nexus.fees.fee_sink_account_id =
        AccountId::new(config.genesis_key.public_key().clone()).clone();
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            nexus
                .fees
                .clone()
                .into_custom_parameter()
                .expect("original signed Global fee policy"),
        ));
    config.nexus = Some(nexus);
    config.genesis_instructions = vec![
        Register::account(Account::new(account())).into(),
        Register::account(Account::new(recipient())).into(),
        Register::domain(Domain::new(
            DomainId::try_new("payment", "universal").unwrap(),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            principal(),
            "Payment principal",
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "Payment fees",
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Mint::asset_quantity(1_000_000_u32, AssetId::of(principal(), account())).into(),
        Mint::asset_quantity(100_u32, AssetId::of(fee_asset(), account())).into(),
        Mint::asset_quantity(100_u32, AssetId::of(fee_asset(), recipient())).into(),
    ];
    config
}

fn intent(chain: &CertifiedTestChain, reference: &str) -> SettleAtomic {
    SettleAtomic::new(
        chain.network_id(),
        SettlementId::new(account(), reference.parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::of(principal(), account()),
            recipient: recipient(),
            quantity: 250_000_u32.into(),
        }])
        .unwrap(),
        AtomicSettlementEscrows::empty(),
        NonZeroU64::new(2).unwrap(),
        Metadata::default(),
    )
}

fn signed(
    chain: &CertifiedTestChain,
    instructions: Vec<InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    signed_by(chain, &payer(), instructions, created_ms)
}

fn signed_by(
    chain: &CertifiedTestChain,
    key: &KeyPair,
    instructions: Vec<InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                Quantity::one(),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(created_ms));
    builder
        .with_instructions(instructions)
        .sign(key.private_key())
}

fn balance(chain: &CertifiedTestChain, asset: AssetDefinitionId, owner: AccountId) -> Quantity {
    chain
        .state()
        .view()
        .world()
        .assets()
        .get(&AssetId::of(asset, owner))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}

fn assert_replay(
    chain: &CertifiedTestChain,
    index: u32,
    payment: &SettleAtomic,
    disposition: SettlementReplayDispositionV1,
) {
    let committed = chain.committed(chain.height());
    let (_, output) = committed.block().network_output_at(index).unwrap();
    let Err(TransactionRejectionReason::Validation(ValidationFail::SettlementReplay(replay))) =
        output.result.as_ref()
    else {
        panic!("expected typed uncharged retry, got {:?}", output.result);
    };
    assert_eq!(replay.settlement_id, payment.settlement_id);
    assert_eq!(replay.disposition, disposition);
    assert_eq!(replay.committed_block_height, 2);
    assert_eq!(
        replay.committed_block_hash,
        chain.committed(2).block().hash()
    );
    assert!(output.result.nexus_fee_receipt().is_none());
}

#[test]
fn direct_payment_replay_two_carriers_charge_once_and_recover_after_certified_restart() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let payment = intent(&chain, "customer-250000");
    // Independent gateways retain different exact carriers for one authorized business intent.
    let first = signed(&chain, vec![payment.clone().into()], 1_001);
    let second = signed(&chain, vec![payment.clone().into()], 1_002);
    assert_ne!(first.hash(), second.hash());
    assert_eq!(chain.commit(vec![first, second]), vec![true, false]);
    assert_eq!(
        balance(&chain, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&chain, principal(), account()), 750_000_u32.into());
    assert_eq!(
        balance(&chain, fee_asset(), account()),
        99_u32.into(),
        "same direct payment identity charges one execution fee across distinct carriers",
    );
    assert_replay(
        &chain,
        1,
        &payment,
        SettlementReplayDispositionV1::AlreadySettled,
    );
    let receipt = chain
        .state()
        .view()
        .world()
        .settlement_receipts()
        .get(&payment.settlement_id)
        .unwrap()
        .clone();

    let mut restored = CertifiedTestChain::start(config()).unwrap();
    restored.replay_from(&chain).unwrap();
    let retry = signed(&restored, vec![payment.clone().into()], 1_003);
    // Original payment expiry has passed; recovering the successful original does not re-execute it.
    assert_eq!(restored.commit(vec![retry]), vec![false]);
    assert_replay(
        &restored,
        0,
        &payment,
        SettlementReplayDispositionV1::AlreadySettled,
    );
    assert_eq!(
        balance(&restored, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&restored, fee_asset(), account()), 99_u32.into());
    assert_eq!(
        restored
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id),
        Some(&receipt)
    );
}

#[test]
fn direct_payment_replay_changed_terms_conflict_and_distinct_reference_pays_normally() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let payment = intent(&chain, "first-payment");
    let first = signed(&chain, vec![payment.clone().into()], 1_001);
    assert_eq!(chain.commit(vec![first]), vec![true]);
    let mut changed = payment.clone();
    changed.expires_at_height = NonZeroU64::new(20).unwrap();
    let conflict = signed(&chain, vec![changed.into()], 1_002);
    assert_eq!(chain.commit(vec![conflict]), vec![false]);
    assert_replay(
        &chain,
        0,
        &payment,
        SettlementReplayDispositionV1::ConflictingIntent,
    );
    assert_eq!(balance(&chain, fee_asset(), account()), 99_u32.into());
    let mut distinct = intent(&chain, "second-payment");
    distinct.expires_at_height = NonZeroU64::new(20).unwrap();
    let second = signed(&chain, vec![distinct.into()], 1_003);
    assert_eq!(chain.commit(vec![second]), vec![true]);
    assert_eq!(
        balance(&chain, principal(), recipient()),
        500_000_u32.into()
    );
    assert_eq!(balance(&chain, fee_asset(), account()), 98_u32.into());
}

#[test]
fn direct_payment_replay_does_not_exempt_composite_business_failures() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let payment = intent(&chain, "composite-control");
    let first = signed(&chain, vec![payment.clone().into()], 1_001);
    assert_eq!(chain.commit(vec![first]), vec![true]);
    let composite = signed(
        &chain,
        vec![
            payment.into(),
            iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "not a direct payment".into(),
            )
            .into(),
        ],
        1_002,
    );
    assert_eq!(chain.commit(vec![composite]), vec![false]);
    let committed = chain.committed(chain.height());
    let (_, output) = committed.block().network_output_at(0).unwrap();
    assert!(!matches!(
        output.result.as_ref(),
        Err(TransactionRejectionReason::Validation(
            ValidationFail::SettlementReplay(_)
        ))
    ));
    assert_eq!(
        balance(&chain, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&chain, fee_asset(), account()), 98_u32.into());
}

#[test]
fn direct_payment_replay_boxed_intent_recovers_but_wrong_network_or_authority_does_not() {
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{NetworkId, isi::SettlementInstructionBox};

    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let payment = intent(&chain, "exact-owner-control");
    let first = signed(&chain, vec![payment.clone().into()], 1_001);
    assert_eq!(chain.commit(vec![first]), vec![true]);
    let boxed = signed(
        &chain,
        vec![SettlementInstructionBox::Atomic(payment.clone()).into()],
        1_002,
    );
    assert_eq!(chain.commit(vec![boxed]), vec![false]);
    assert_replay(
        &chain,
        0,
        &payment,
        SettlementReplayDispositionV1::AlreadySettled,
    );
    assert_eq!(balance(&chain, fee_asset(), account()), 99_u32.into());

    let mut foreign = payment.clone();
    foreign.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"wrong payment network",
    )));
    let foreign = signed(&chain, vec![foreign.into()], 1_003);
    assert_eq!(chain.commit(vec![foreign]), vec![false]);
    let foreign_key = KeyPair::from_seed(vec![0x79; 32], Algorithm::Ed25519);
    let unauthorized = signed_by(&chain, &foreign_key, vec![payment.into()], 1_004);
    assert_eq!(chain.commit(vec![unauthorized]), vec![false]);
    for height in [4, 5] {
        let committed = chain.committed(height);
        let (_, output) = committed.block().network_output_at(0).unwrap();
        assert!(!matches!(
            output.result.as_ref(),
            Err(TransactionRejectionReason::Validation(
                ValidationFail::SettlementReplay(_)
            ))
        ));
    }
    assert_eq!(
        balance(&chain, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&chain, fee_asset(), account()), 98_u32.into());
    assert_eq!(balance(&chain, fee_asset(), recipient()), 99_u32.into());
}

#[test]
fn committed_fraud_permission_preserves_actual_payment_fees_and_certified_restart_across_transport()
{
    use iroha_data_model::{
        fraud::{FraudAdmissionPolicyV1, FraudRiskBandV1},
        parameter::Parameter,
    };
    for permitted in [false, true] {
        let committed = FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Low),
            missing_assessment_permitted: permitted,
            ..FraudAdmissionPolicyV1::protocol_default()
        };
        let configured = |transport: u64| {
            let mut configured = config();
            configured
                .genesis_parameters
                .push(Parameter::Custom(committed.clone().into_custom_parameter()));
            configured.fraud_monitoring = iroha_config::parameters::actual::FraudMonitoring::new(
                vec![
                    format!("https://unavailable-{transport}.invalid/assessment")
                        .parse()
                        .unwrap(),
                ],
                Duration::from_millis(transport + 1),
                Duration::from_millis(transport + 2),
            );
            configured
        };
        let mut original = CertifiedTestChain::start(configured(0)).unwrap();
        let original_genesis = original.committed(1).block().hash();
        let payment = intent(&original, "fraud-policy-exact-payment");
        let transaction = signed(&original, vec![payment.clone().into()], 1_001);
        assert_eq!(original.commit(vec![transaction.clone()]), vec![permitted]);
        let original_carrier = original.committed(2);
        let (_, output) = original_carrier.block().network_output_at(0).unwrap();
        if permitted {
            assert!(output.result.is_ok());
            assert!(output.result.nexus_fee_receipt().is_some());
        } else {
            assert!(
                matches!(output.result.as_ref(), Err(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted(reason)
            )) if reason == "fraud monitoring requires an attached assessment")
            );
            assert!(
                output.result.nexus_fee_receipt().is_none(),
                "fraud admission refuses before fee charging"
            );
        }
        let expected_principal = if permitted { 250_000_u32 } else { 0 };
        let expected_fee_balance = if permitted { 99_u32 } else { 100 };
        assert_eq!(
            balance(&original, principal(), recipient()),
            expected_principal.into()
        );
        assert_eq!(
            balance(&original, fee_asset(), account()),
            expected_fee_balance.into()
        );
        let receipt = original
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id)
            .cloned();
        assert_eq!(receipt.is_some(), permitted);
        for transport in [10, 1_000] {
            let mut independent = CertifiedTestChain::start(configured(transport)).unwrap();
            assert_eq!(
                independent.committed(1).block().hash(),
                original_genesis,
                "transport cannot choose signed-genesis identity"
            );
            assert_eq!(
                independent.commit(vec![transaction.clone()]),
                vec![permitted]
            );
            let carrier = independent.committed(2);
            assert_eq!(
                carrier.result(),
                original_carrier.result(),
                "same certified execution result"
            );
            assert_eq!(
                carrier.block().hash(),
                original_carrier.block().hash(),
                "same canonical carrier"
            );
            assert_eq!(
                balance(&independent, principal(), recipient()),
                expected_principal.into()
            );
            assert_eq!(
                balance(&independent, fee_asset(), account()),
                expected_fee_balance.into()
            );
            assert_eq!(
                independent
                    .state()
                    .view()
                    .world()
                    .settlement_receipts()
                    .get(&payment.settlement_id),
                receipt.as_ref()
            );

            let mut restored = CertifiedTestChain::start(configured(transport + 1)).unwrap();
            restored.replay_from(&original).unwrap();
            assert_eq!(
                restored.height(),
                2,
                "restart needs no filler transaction or successor block"
            );
            assert_eq!(restored.committed(2).result(), original_carrier.result());
            assert_eq!(
                balance(&restored, principal(), recipient()),
                expected_principal.into()
            );
            assert_eq!(
                balance(&restored, fee_asset(), account()),
                expected_fee_balance.into()
            );
            assert_eq!(
                restored
                    .state()
                    .view()
                    .world()
                    .settlement_receipts()
                    .get(&payment.settlement_id),
                receipt.as_ref()
            );
        }
    }
}

fn global_fee_policy_payment(signed_limit: u32) {
    let mut original = CertifiedTestChain::start(config()).unwrap();
    let payment = intent(&original, "global-committed-fee-authority");
    let mut builder = TransactionBuilder::new(
        original.network_id(),
        account(),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                signed_limit.into(),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(1_001));
    let transaction = builder
        .with_instructions([payment.clone()])
        .sign(payer().private_key());
    assert_eq!(original.commit(vec![transaction.clone()]), vec![true]);
    let committed = original.committed(2);
    let (_, output) = committed.block().network_output_at(0).unwrap();
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual successful monetary charge");
    assert_eq!(receipt.fee_amount, Quantity::one());
    assert_eq!(receipt.schedule.base_fee, Quantity::one());
    assert_eq!(balance(&original, fee_asset(), account()), 99_u32.into());
    assert_eq!(
        balance(&original, principal(), recipient()),
        250_000_u32.into()
    );
    let settlement = original
        .state()
        .view()
        .world()
        .settlement_receipts()
        .get(&payment.settlement_id)
        .unwrap()
        .clone();

    let mut independent = CertifiedTestChain::start(config()).unwrap();
    assert_eq!(independent.genesis().hash(), original.genesis().hash());
    // Change only the process-local copy after the identical original H1 has committed.
    // At limit 1 the old owner rejects; at limit 2 it burns 2 instead of 1.
    independent.state().nexus.write().fees.base_fee = 2_u32.into();
    assert_eq!(
        independent.commit(vec![transaction.clone()]),
        vec![true],
        "a node-local schedule cannot reject the same authorized payment"
    );
    let other = independent.committed(2);
    let (_, output) = other.block().network_output_at(0).unwrap();
    assert_eq!(
        output.result.nexus_fee_receipt(),
        Some(receipt),
        "the exact same input must publish the same monetary receipt"
    );
    assert_eq!(
        other.result(),
        committed.result(),
        "same committed complete State result"
    );
    assert_eq!(other.block().hash(), committed.block().hash());
    assert_eq!(balance(&independent, fee_asset(), account()), 99_u32.into());
    assert_eq!(
        balance(&independent, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(
        independent
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id),
        Some(&settlement)
    );

    let mut restored = CertifiedTestChain::start(config()).unwrap();
    restored.state().nexus.write().fees.base_fee = 7_u32.into();
    restored.replay_from(&original).unwrap();
    assert_eq!(
        restored.height(),
        2,
        "recovery requires no successor traffic"
    );
    assert_eq!(restored.committed(2).result(), committed.result());
    assert_eq!(balance(&restored, fee_asset(), account()), 99_u32.into());
    assert_eq!(
        restored
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id),
        Some(&settlement)
    );
}

#[test]
fn committed_global_fee_policy_prevents_local_schedule_rejecting_payment() {
    global_fee_policy_payment(1);
}

#[test]
fn committed_global_fee_policy_prevents_local_schedule_changing_paid_receipt() {
    global_fee_policy_payment(2);
}

fn fee_update_config() -> TestChainConfig {
    let mut config = config();
    config.genesis_instructions.push(
        iroha_data_model::isi::Grant::account_permission(
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            account(),
        )
        .into(),
    );
    config
}

#[test]
fn committed_fee_update_uses_predecessor_for_entire_block_and_survives_replay() {
    use crate::state::StateReadOnly as _;
    use iroha_data_model::{isi::SetParameter, parameter::Parameter};
    let mut chain = CertifiedTestChain::start(fee_update_config()).unwrap();
    let before = chain.state().view().nexus().fees.clone();
    let mut next = before.clone();
    next.base_fee = 2_u32.into();
    next.fee_sink_account_id = recipient();
    let update = signed(
        &chain,
        vec![
            SetParameter::new(Parameter::Custom(
                next.clone().into_custom_parameter().unwrap(),
            ))
            .into(),
        ],
        1001,
    );
    let payment = intent(&chain, "same-block-root-fee-update");
    let paid = signed(&chain, vec![payment.clone().into()], 1002);
    assert_eq!(
        chain.commit(vec![update, paid]),
        vec![true, true],
        "every transaction in the policy-update block must use predecessor fees"
    );
    let original = chain.committed(2);
    for index in 0..2 {
        let receipt = original
            .block()
            .network_output_at(index)
            .unwrap()
            .1
            .result
            .nexus_fee_receipt()
            .expect("actual successful debit");
        assert_eq!(receipt.fee_amount, Quantity::one());
        assert_eq!(receipt.schedule.base_fee, Quantity::one());
    }
    assert_eq!(balance(&chain, fee_asset(), account()), 98_u32.into());
    assert_eq!(
        balance(&chain, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(chain.state().view().nexus().fees, next);
    let second = intent(&chain, "successor-root-fee-update");
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        account(),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                2_u32.into(),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(2001));
    let second = builder
        .with_instructions([second])
        .sign(payer().private_key());
    assert_eq!(chain.commit(vec![second]), vec![true]);
    let last = chain.committed(3);
    let receipt = last
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .nexus_fee_receipt()
        .unwrap();
    assert_eq!(receipt.fee_amount, 2_u32.into());
    assert_eq!(receipt.schedule.base_fee, 2_u32.into());
    assert_eq!(balance(&chain, fee_asset(), account()), 96_u32.into());
    assert_eq!(
        balance(&chain, principal(), recipient()),
        500_000_u32.into()
    );
    let mut replay = CertifiedTestChain::start(fee_update_config()).unwrap();
    replay.state().nexus.write().fees.base_fee = 999_u32.into();
    replay.replay_from(&chain).unwrap();
    assert_eq!(
        replay.height(),
        3,
        "final policy/payment recovery needs no later traffic"
    );
    assert_eq!(replay.committed(2).result(), original.result());
    assert_eq!(replay.committed(3).result(), last.result());
    assert_eq!(replay.state().view().nexus().fees, next);
    assert_eq!(balance(&replay, fee_asset(), account()), 96_u32.into());
    assert_eq!(
        balance(&replay, principal(), recipient()),
        500_000_u32.into()
    );
}

#[test]
fn paid_root_fee_identity_updates_are_rejected_without_replacing_committed_custody() {
    use crate::state::StateReadOnly as _;
    use iroha_data_model::{isi::SetParameter, parameter::Parameter};
    for change_currency in [true, false] {
        let mut chain = CertifiedTestChain::start(fee_update_config()).unwrap();
        let before = chain.state().view().nexus().fees.clone();
        let mut invalid = before.clone();
        if change_currency {
            invalid.fee_asset_id = principal();
        } else {
            invalid.sponsor_vault_custody_account_id = recipient();
        }
        // Both replacements name registered objects. Refusal must come from the
        // immutable monetary identity rule, not missing currency/account validation.
        let update = signed(
            &chain,
            vec![
                SetParameter::new(Parameter::Custom(invalid.into_custom_parameter().unwrap()))
                    .into(),
            ],
            1001,
        );
        assert_eq!(
            chain.commit(vec![update]),
            vec![false],
            "paid policy update must retain immutable currency and sponsor custody"
        );
        let original = chain.committed(2);
        let output = &original.block().network_output_at(0).unwrap().1.result;
        let rejection = output.as_ref().expect_err("identity update must reject");
        assert!(
            matches!(
                rejection,
                TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(_))
            ),
            "{rejection}"
        );
        assert!(
            rejection
                .to_string()
                .contains("root fee currency and sponsor custody are immutable after genesis"),
            "{rejection}"
        );
        let receipt = output
            .nexus_fee_receipt()
            .expect("actual rejected execution retains its fee");
        assert_eq!(receipt.fee_amount, Quantity::one());
        assert_eq!(receipt.schedule.base_fee, Quantity::one());
        assert_eq!(chain.state().view().nexus().fees, before);
        assert_eq!(balance(&chain, fee_asset(), account()), 99_u32.into());
        assert_eq!(
            balance(&chain, principal(), account()),
            1_000_000_u32.into()
        );
        assert_eq!(balance(&chain, principal(), recipient()), Quantity::zero());

        let mut replay = CertifiedTestChain::start(fee_update_config()).unwrap();
        replay.state().nexus.write().fees.base_fee = 999_u32.into();
        replay.replay_from(&chain).unwrap();
        assert_eq!(
            replay.height(),
            2,
            "rejected update recovery requires no later traffic"
        );
        assert_eq!(replay.committed(2).result(), original.result());
        assert_eq!(replay.state().view().nexus().fees, before);
        assert_eq!(balance(&replay, fee_asset(), account()), 99_u32.into());
        assert_eq!(
            balance(&replay, principal(), account()),
            1_000_000_u32.into()
        );
        assert_eq!(balance(&replay, principal(), recipient()), Quantity::zero());
    }
}
