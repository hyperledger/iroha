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
        AtomicSettlementMovement, AtomicSettlementMovements, InstructionBox, Mint, Register,
        SettleAtomic, SettlementId,
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
    nexus.fees.fee_asset_id = fee_asset().canonical_address();
    nexus.fees.fee_sink_account_id =
        AccountId::new(config.genesis_key.public_key().clone()).to_string();
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
