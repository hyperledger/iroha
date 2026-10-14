//! Actual native payment execution joined to independent SDK verification and bank credit.
//! Four fixture validators certify Core execution; this is not process/network qualification.

use std::{num::NonZeroU64, sync::Arc, time::Duration};

use iroha::{
    client::{
        NativePaymentFullReturnRequest, PaymentCreditStatus, PaymentInbox,
        PaymentReceiptVerificationError, VerifiedPaymentReceipt,
    },
    workflow::FileWorkflowStorage,
};
use iroha_core::{
    state::{StorageReadOnly, World, WorldReadOnly},
    sumeragi::{
        finality::build_proof,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
    block::SignedBlock,
    domain::Domain,
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovement, AtomicSettlementMovements, Mint,
        Register, SettleAtomic, SettlementId,
    },
    parameter::system::ConsensusMode,
    query::CommittedTransaction,
    sumeragi_finality::{
        SignedGenesisPinsV1, SumeragiFinalityVerifier, authenticate_signed_genesis_v1,
    },
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
    },
};
use iroha_model_base::{domain::DomainId, metadata::Metadata, name::Name};
use iroha_primitives::numeric::Quantity;
use sha2::{Digest as _, Sha256};

fn payer_key() -> KeyPair {
    KeyPair::from_seed(vec![0x78; 32], Algorithm::Ed25519)
}

fn payer() -> AccountId {
    AccountId::new(payer_key().public_key().clone())
}

fn recipient() -> AccountId {
    AccountId::new(recipient_key().public_key().clone())
}

fn recipient_key() -> KeyPair {
    KeyPair::from_seed(vec![0x79; 32], Algorithm::Ed25519)
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
        Register::account(Account::new(payer())).into(),
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
        Mint::asset_quantity(1_000_000_u32, AssetId::of(principal(), payer())).into(),
        Mint::asset_quantity(100_u32, AssetId::of(fee_asset(), payer())).into(),
        Mint::asset_quantity(100_u32, AssetId::of(fee_asset(), recipient())).into(),
    ];
    config
}

fn intent(chain: &CertifiedTestChain) -> SettleAtomic {
    SettleAtomic::new(
        chain.network_id(),
        SettlementId::new(payer(), "customer-250000".parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::of(principal(), payer()),
            recipient: recipient(),
            quantity: 250_000_u32.into(),
        }])
        .unwrap(),
        AtomicSettlementEscrows::empty(),
        NonZeroU64::new(2).unwrap(),
        Metadata::default(),
    )
}

fn signed(chain: &CertifiedTestChain, payment: &SettleAtomic, time_ms: u64) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        payer(),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                Quantity::one(),
            )],
            None,
        ),
    )
    .with_instructions([payment.clone()]);
    builder.set_creation_time(Duration::from_millis(time_ms));
    builder.sign(payer_key().private_key())
}

fn balance(
    chain: &CertifiedTestChain,
    definition: AssetDefinitionId,
    owner: AccountId,
) -> Quantity {
    chain
        .state()
        .view()
        .world()
        .assets()
        .get(&AssetId::of(definition, owner))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}

fn evidence(block: &SignedBlock, input: u32) -> CommittedTransaction {
    let entrypoint = block
        .network_entrypoint_at(usize::try_from(input).unwrap())
        .unwrap()
        .clone();
    let (index, _) = block.network_output_at(input).unwrap();
    let output = block.execution_outputs()[index as usize].clone();
    CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(input).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(index).unwrap(),
        output,
    }
}

fn pinned_genesis(chain: &CertifiedTestChain) -> (Vec<u8>, SignedGenesisPinsV1) {
    // The test operator selects the original local genesis before receipt delivery.
    // A remote response cannot supply or replace these installation pins.
    let wire = chain.genesis().encode_wire().unwrap();
    let configuration = config();
    let pins = SignedGenesisPinsV1 {
        chain_id: configuration.chain_id.to_string(),
        network_id: chain.network_id(),
        genesis_hash: chain.genesis().hash(),
        signed_genesis_sha256: Sha256::digest(&wire).into(),
        genesis_public_key: configuration.genesis_key.public_key().clone(),
        roster: chain
            .validators()
            .iter()
            .map(|(peer, _)| peer.clone())
            .collect(),
        mode: ConsensusMode::Permissioned,
    };
    (wire, pins)
}

fn verifier(wire: &[u8], pins: &SignedGenesisPinsV1) -> SumeragiFinalityVerifier {
    let authenticated = authenticate_signed_genesis_v1(wire, pins).unwrap();
    SumeragiFinalityVerifier::new(
        authenticated.block(),
        &pins.chain_id,
        authenticated.validators().to_vec(),
    )
    .unwrap()
}

#[test]
fn executed_payment_at_final_tip_credits_once_across_carriers_and_restart() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    assert_eq!(chain.validators().len(), 4);
    let (genesis_wire, pins) = pinned_genesis(&chain);
    let payment = intent(&chain);
    let first = signed(&chain, &payment, 1_001);
    let first_hash = first.hash();
    let second = signed(&chain, &payment, 1_002);
    let second_hash = second.hash();
    assert_ne!(first_hash, second_hash);
    assert_eq!(chain.commit(vec![first, second]), vec![true, false]);
    assert_eq!(chain.height(), 2, "no successor or unrelated transaction");
    assert_eq!(
        balance(&chain, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&chain, principal(), payer()), 750_000_u32.into());
    assert_eq!(balance(&chain, fee_asset(), payer()), 99_u32.into());

    let genesis_proof = build_proof(&chain.state().view(), 1).unwrap();
    let payment_proof = build_proof(&chain.state().view(), 2).unwrap();
    let mut independent = verifier(&genesis_wire, &pins);
    independent.verify(&genesis_proof).unwrap();
    let verified_block = independent.verify(&payment_proof).unwrap();
    let original_evidence = evidence(verified_block.block(), 0);
    let receipt = VerifiedPaymentReceipt::verify(
        &verified_block,
        pins.network_id,
        first_hash,
        &payment,
        original_evidence.clone(),
    )
    .unwrap();
    assert_eq!(
        receipt.nexus_fee_receipt().unwrap().fee_amount,
        Quantity::one()
    );
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id),
        Some(receipt.settlement()),
        "SDK projection equals the actual executed receipt",
    );
    assert!(
        VerifiedPaymentReceipt::verify(
            &verified_block,
            pins.network_id,
            second_hash,
            &payment,
            evidence(verified_block.block(), 1)
        )
        .is_err(),
        "included rejected retry cannot become a successful receipt"
    );

    let root = tempfile::tempdir().unwrap();
    let customer: Name = "customer-250000".parse().unwrap();
    let destination = AssetId::of(principal(), recipient());
    let inbox = PaymentInbox::new(Arc::new(
        FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
    ))
    .unwrap();
    assert_eq!(
        inbox.credit(&receipt, &customer, &destination).unwrap(),
        PaymentCreditStatus::Recorded
    );
    let notification = inbox
        .pending_notification(&receipt, &customer, &destination)
        .unwrap()
        .unwrap();
    assert_eq!(notification.quantity, 250_000_u32.into());
    assert_eq!(notification.transaction_hash, first_hash);

    // Persist only ordinary evidence. A new process must authenticate every byte again.
    let retained =
        norito::encode_canonical(&(genesis_proof, payment_proof, original_evidence)).unwrap();
    drop(inbox);
    drop(receipt);
    drop(verified_block);
    drop(independent);
    let mut restored = CertifiedTestChain::start(config()).unwrap();
    restored.replay_from(&chain).unwrap();
    drop(chain);
    assert_eq!(
        restored.height(),
        2,
        "restart and credit recovery author no block"
    );
    let (genesis_proof, payment_proof, original_evidence): (
        iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
        iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
        CommittedTransaction,
    ) = norito::decode_canonical(&retained).unwrap();
    let mut independent = verifier(&genesis_wire, &pins);
    independent.verify(&genesis_proof).unwrap();
    let verified_block = independent.verify(&payment_proof).unwrap();
    let recovered = VerifiedPaymentReceipt::verify_recovered(
        &verified_block,
        pins.network_id,
        &payment,
        original_evidence,
    )
    .unwrap();
    let inbox = PaymentInbox::new(Arc::new(
        FileWorkflowStorage::open_or_create(root.path().join("inbox")).unwrap(),
    ))
    .unwrap();
    assert_eq!(
        inbox.credit(&recovered, &customer, &destination).unwrap(),
        PaymentCreditStatus::AlreadyRecorded {
            notification_pending: true
        }
    );
    assert_eq!(
        inbox
            .pending_notification(&recovered, &customer, &destination)
            .unwrap(),
        Some(notification)
    );
    inbox
        .acknowledge_notification(&recovered, &customer, &destination)
        .unwrap();
    inbox
        .acknowledge_notification(&recovered, &customer, &destination)
        .unwrap();
    assert_eq!(
        inbox.credit(&recovered, &customer, &destination).unwrap(),
        PaymentCreditStatus::AlreadyRecorded {
            notification_pending: false
        }
    );
    assert_eq!(
        balance(&restored, principal(), recipient()),
        250_000_u32.into()
    );
    assert_eq!(balance(&restored, fee_asset(), payer()), 99_u32.into());
}

#[test]
fn insufficient_funds_payment_is_included_but_cannot_authorize_customer_credit() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let (genesis_wire, pins) = pinned_genesis(&chain);
    let payment = SettleAtomic::new(
        chain.network_id(),
        SettlementId::new(payer(), "insufficient-principal".parse().unwrap()),
        AtomicSettlementMovements::try_from(vec![AtomicSettlementMovement {
            source: AssetId::of(principal(), payer()),
            recipient: recipient(),
            quantity: 2_000_000_u32.into(),
        }])
        .unwrap(),
        AtomicSettlementEscrows::empty(),
        NonZeroU64::new(2).unwrap(),
        Metadata::default(),
    );
    let transaction = signed(&chain, &payment, 1_001);
    let transaction_hash = transaction.hash();
    assert_eq!(chain.commit(vec![transaction]), vec![false]);
    assert_eq!(chain.height(), 2);
    assert_eq!(balance(&chain, principal(), payer()), 1_000_000_u32.into());
    assert_eq!(balance(&chain, principal(), recipient()), Quantity::zero());
    assert_eq!(balance(&chain, fee_asset(), payer()), 99_u32.into());
    assert!(
        chain
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id)
            .is_none()
    );

    let mut independent = verifier(&genesis_wire, &pins);
    independent
        .verify(&build_proof(&chain.state().view(), 1).unwrap())
        .unwrap();
    let block = independent
        .verify(&build_proof(&chain.state().view(), 2).unwrap())
        .unwrap();
    let included = evidence(block.block(), 0);
    assert!(included.result().is_err());
    assert!(matches!(
        VerifiedPaymentReceipt::verify(
            &block,
            pins.network_id,
            transaction_hash,
            &payment,
            included.clone()
        ),
        Err(PaymentReceiptVerificationError::Finality(_)),
    ));
    assert!(matches!(
        VerifiedPaymentReceipt::verify_recovered(&block, pins.network_id, &payment, included),
        Err(PaymentReceiptVerificationError::Finality(_)),
    ));
}

#[test]
fn full_return_is_a_separate_once_only_payment_and_preserves_original_after_restart() {
    let mut chain = CertifiedTestChain::start(config()).unwrap();
    let (genesis_wire, pins) = pinned_genesis(&chain);
    let payment = intent(&chain);
    let original = signed(&chain, &payment, 1_001);
    let original_hash = original.hash();
    assert_eq!(chain.commit(vec![original]), vec![true]);
    let mut independent = verifier(&genesis_wire, &pins);
    independent
        .verify(&build_proof(&chain.state().view(), 1).unwrap())
        .unwrap();
    let original_block = independent
        .verify(&build_proof(&chain.state().view(), 2).unwrap())
        .unwrap();
    let original = VerifiedPaymentReceipt::verify(
        &original_block,
        pins.network_id,
        original_hash,
        &payment,
        evidence(original_block.block(), 0),
    )
    .unwrap();
    let original_receipt = original.settlement().clone();
    let return_fee = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            Quantity::one(),
        )],
        None,
    );
    let first_gateway = NativePaymentFullReturnRequest::new(
        original.clone(),
        NonZeroU64::new(3).unwrap(),
        return_fee.clone(),
    )
    .unwrap();
    let second_gateway = NativePaymentFullReturnRequest::new(
        original,
        NonZeroU64::new(3).unwrap(),
        return_fee.clone(),
    )
    .unwrap();
    assert_eq!(
        first_gateway.settlement_id(),
        second_gateway.settlement_id()
    );
    assert_eq!(first_gateway.settlement_id().owner(), &recipient());
    assert_ne!(first_gateway.settlement_id(), &payment.settlement_id);
    let mut carriers = Vec::new();
    for (gateway, creation_time) in [(&first_gateway, 1_002), (&second_gateway, 1_003)] {
        let mut builder = TransactionBuilder::new(pins.network_id, recipient(), return_fee.clone())
            .with_instructions([gateway.payment().intent().clone()]);
        builder.set_creation_time(Duration::from_millis(creation_time));
        carriers.push(builder.sign(recipient_key().private_key()));
    }
    let reverse_hash = carriers[0].hash();
    let rejected_hash = carriers[1].hash();
    assert_ne!(reverse_hash, rejected_hash);
    assert_eq!(chain.commit(carriers), vec![true, false]);
    assert_eq!(chain.height(), 3, "the reverse payment needs no successor");
    assert_eq!(balance(&chain, principal(), payer()), 1_000_000_u32.into());
    assert_eq!(balance(&chain, principal(), recipient()), Quantity::zero());
    assert_eq!(balance(&chain, fee_asset(), payer()), 99_u32.into());
    assert_eq!(balance(&chain, fee_asset(), recipient()), 99_u32.into());
    let reverse_block = independent
        .verify(&build_proof(&chain.state().view(), 3).unwrap())
        .unwrap();
    let reverse = VerifiedPaymentReceipt::verify(
        &reverse_block,
        pins.network_id,
        reverse_hash,
        first_gateway.payment().intent(),
        evidence(reverse_block.block(), 0),
    )
    .unwrap();
    let linked = first_gateway.verify_return(reverse).unwrap();
    assert_eq!(linked.original().settlement(), &original_receipt);
    assert_eq!(linked.reverse().transaction_hash(), reverse_hash);
    assert_eq!(
        linked.reverse().nexus_fee_receipt().unwrap().fee_amount,
        Quantity::one()
    );
    assert!(
        VerifiedPaymentReceipt::verify(
            &reverse_block,
            pins.network_id,
            rejected_hash,
            second_gateway.payment().intent(),
            evidence(reverse_block.block(), 1),
        )
        .is_err()
    );
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .settlement_receipts()
            .get(&payment.settlement_id),
        Some(&original_receipt),
        "return execution never rewrites the original successful receipt",
    );

    let mut restored = CertifiedTestChain::start(config()).unwrap();
    restored.replay_from(&chain).unwrap();
    drop(chain);
    let mut fresh = verifier(&genesis_wire, &pins);
    fresh
        .verify(&build_proof(&restored.state().view(), 1).unwrap())
        .unwrap();
    let original_block = fresh
        .verify(&build_proof(&restored.state().view(), 2).unwrap())
        .unwrap();
    let original = VerifiedPaymentReceipt::verify_recovered(
        &original_block,
        pins.network_id,
        &payment,
        evidence(original_block.block(), 0),
    )
    .unwrap();
    let request =
        NativePaymentFullReturnRequest::new(original, NonZeroU64::new(3).unwrap(), return_fee)
            .unwrap();
    assert_eq!(request.settlement_id(), first_gateway.settlement_id());
    let reverse_block = fresh
        .verify(&build_proof(&restored.state().view(), 3).unwrap())
        .unwrap();
    let reverse = VerifiedPaymentReceipt::verify_recovered(
        &reverse_block,
        pins.network_id,
        request.payment().intent(),
        evidence(reverse_block.block(), 0),
    )
    .unwrap();
    let recovered = request.verify_return(reverse).unwrap();
    assert_eq!(recovered.original().settlement(), &original_receipt);
    assert_eq!(
        recovered.reverse().settlement(),
        linked.reverse().settlement()
    );
    assert_eq!(restored.height(), 3);
    assert_eq!(balance(&restored, fee_asset(), recipient()), 99_u32.into());
}
