//! Settlement legs are sorted by native key order and hashed exactly as Core checks.
//!
//! Core authorizes atomic settlements and repos with `CanExecuteSettlement` consents
//! bound to `SettleAtomic::intent_hash` (`iroha_core::smartcontracts::isi::settlement::atomic`)
//! and `RepoIsi::{initiation,maturity}_intent_hash` (`iroha_core::smartcontracts::isi::repo`).
//! These tests drive the JavaScript JSON helpers and require the same hashes.
use super::*;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address::ChainDiscriminantGuard},
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    block::BlockHeader,
    escrow::{
        ConditionalEscrowCondition, ConditionalEscrowOracleCondition, ConditionalEscrowPredicate,
        ConditionalEscrowValue, ConditionalEscrowWithinCondition, EscrowId,
    },
    isi::{
        AtomicSettlementEscrows, AtomicSettlementMovements, SettleAtomic, SettlementId,
        repo::{RepoInstructionBox, RepoIsi},
    },
    repo::{RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use iroha_primitives::numeric::Quantity;
use std::num::{NonZeroU32, NonZeroU64};

const PREFIX: u16 = 369;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture key")
            .public_key()
            .clone(),
    )
}

fn definition(name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("bondpoc", "universal").expect("domain"),
        name.parse().expect("name"),
    )
}

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"bond-poc",
    )))
}

fn movement(asset: &str, from: u8, to: u8, quantity: u32) -> AtomicSettlementMovement {
    AtomicSettlementMovement {
        source: AssetId::with_scope(definition(asset), account(from), AssetBalanceScope::Global),
        recipient: account(to),
        quantity: Quantity::from(quantity),
    }
}

fn escrow(asset: &str, from: u8, to: u8, label: &str, amount: u32) -> AtomicSettlementEscrow {
    AtomicSettlementEscrow {
        source: AssetId::new(definition(asset), account(from)),
        escrow_id: EscrowId::new(Hash::new(format!("bond-escrow:{label}"))),
        beneficiary: account(to),
        amount: Quantity::from(amount),
        conditions: vec![
            ConditionalEscrowCondition::Oracle(ConditionalEscrowOracleCondition {
                id: "coupon_paid".parse().expect("condition id"),
                attestor: account(0xA7),
                predicate: ConditionalEscrowPredicate::Equals(ConditionalEscrowValue::Bool(true)),
                sequence: NonZeroU32::new(1).expect("sequence"),
            }),
            ConditionalEscrowCondition::Within(ConditionalEscrowWithinCondition {
                id: "window".parse().expect("window id"),
                duration_ms: NonZeroU64::new(86_400_000).expect("duration"),
            }),
        ],
        expires_at_ms: 1_900_000_000_000,
        evidence_hashes: vec![Hash::new(b"bond-term-sheet")],
    }
}

/// The settlement namespace owner: the smallest debited source account, so the
/// identifier does not depend on the (possibly unsorted) leg order.
fn settlement_id(
    movements: &[AtomicSettlementMovement],
    escrows: &[AtomicSettlementEscrow],
) -> SettlementId {
    let owner = movements
        .iter()
        .map(|movement| movement.source.account())
        .chain(escrows.iter().map(|escrow| escrow.source.account()))
        .min()
        .cloned()
        .unwrap_or_else(|| account(0xEE));
    SettlementId::new(owner, "dvp_bond_1".parse().expect("settlement reference"))
}

fn atomic_value(
    movements: &[AtomicSettlementMovement],
    escrows: &[AtomicSettlementEscrow],
) -> Value {
    atomic_value_with_id(movements, escrows, &settlement_id(movements, escrows))
}

fn atomic_value_with_id(
    movements: &[AtomicSettlementMovement],
    escrows: &[AtomicSettlementEscrow],
    settlement_id: &SettlementId,
) -> Value {
    let mut payload = json::Map::new();
    payload.insert(
        "network_id".into(),
        json::to_value(&network()).expect("network id"),
    );
    payload.insert(
        "settlement_id".into(),
        json::to_value(settlement_id).expect("settlement id"),
    );
    let render = |items: Vec<Value>| Value::Array(items);
    payload.insert(
        "movements".into(),
        render(
            movements
                .iter()
                .map(|movement| json::to_value(movement).expect("movement"))
                .collect(),
        ),
    );
    payload.insert(
        "escrows".into(),
        render(
            escrows
                .iter()
                .map(|escrow| json::to_value(escrow).expect("escrow"))
                .collect(),
        ),
    );
    payload.insert("expires_at_height".into(), Value::from(500_u64));
    payload.insert("metadata".into(), Value::Object(json::Map::new()));
    let mut variants = json::Map::new();
    variants.insert("Atomic".into(), Value::Object(payload));
    crate::instruction_envelope("Settlement", Value::Object(variants))
}

fn native(
    mut movements: Vec<AtomicSettlementMovement>,
    mut escrows: Vec<AtomicSettlementEscrow>,
) -> (
    SettleAtomic,
    Vec<AtomicSettlementMovement>,
    Vec<AtomicSettlementEscrow>,
) {
    movements.sort_by(|left, right| {
        (&left.source, &left.recipient).cmp(&(&right.source, &right.recipient))
    });
    escrows.sort_by_key(|escrow| escrow.escrow_id);
    let settlement = SettleAtomic::new(
        network(),
        settlement_id(&movements, &escrows),
        AtomicSettlementMovements::try_from(movements.clone()).expect("canonical movements"),
        AtomicSettlementEscrows::try_from(escrows.clone()).expect("canonical escrows"),
        NonZeroU64::new(500).expect("expiry"),
        Metadata::default(),
    );
    (settlement, movements, escrows)
}

#[test]
fn canonical_ordering_uses_native_keys_and_hashes_the_consented_intent() {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    let movements = vec![
        movement("cash", 10, 11, 5),
        movement("bond", 11, 10, 7),
        movement("cash", 12, 10, 9),
    ];
    let (expected, sorted, _) = native(movements.clone(), Vec::new());
    let mut unsorted = sorted.clone();
    unsorted.reverse();
    let input = atomic_value(&unsorted, &[]);
    assert!(crate::value_to_instruction(input.clone()).is_err());
    assert!(atomic_settlement_intent_hash(input.clone()).is_err());

    let canonical = canonical_atomic_settlement_json(input).expect("canonical ordering");
    assert_eq!(canonical, atomic_value(&sorted, &[]));
    assert_eq!(
        canonical_atomic_settlement_json(canonical.clone()).expect("idempotent"),
        canonical
    );
    assert_eq!(
        atomic_settlement_intent_hash(canonical).expect("intent hash"),
        expected.intent_hash().expect("Core intent hash")
    );
}

/// Bond issuance with two issuer-owned bond deliveries and four escrow legs, including a
/// foreign-source escrow, hashes exactly as Core authorizes it.
#[test]
fn four_escrow_legs_and_two_issuer_bond_legs_hash_exactly_as_core_checks() {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    let issuer = 0xB2;
    let movements = vec![
        movement("bond", issuer, 0xB1, 10),
        movement("bond", issuer, 0xB4, 5),
    ];
    let escrows = vec![
        escrow("cash", 0xB1, issuer, "retention-b1", 1_000),
        escrow("cash", 0xB4, issuer, "retention-b4", 500),
        escrow("bond", issuer, 0xB1, "coupon-b1", 1),
        escrow("cash", issuer, 0xB4, "refund-b4", 25),
    ];
    let (expected, sorted_movements, sorted_escrows) = native(movements.clone(), escrows.clone());
    let mut shuffled_escrows = sorted_escrows.clone();
    shuffled_escrows.rotate_left(1);
    let mut shuffled_movements = sorted_movements.clone();
    shuffled_movements.reverse();
    let input = atomic_value(&shuffled_movements, &shuffled_escrows);
    assert!(
        crate::value_to_instruction(input.clone()).is_err(),
        "the strict codec never sorts"
    );

    let canonical = canonical_atomic_settlement_json(input).expect("canonical ordering");
    assert_eq!(canonical, atomic_value(&sorted_movements, &sorted_escrows));
    let core_hash = expected.intent_hash().expect("Core intent hash");
    assert_eq!(
        atomic_settlement_intent_hash(canonical.clone()).expect("JS intent hash"),
        core_hash
    );
    // Every escrow term is part of the consented intent.
    let mut changed_escrows = sorted_escrows;
    changed_escrows[0].amount = Quantity::from(1_001_u32);
    assert_ne!(
        atomic_settlement_intent_hash(atomic_value(&sorted_movements, &changed_escrows))
            .expect("changed intent hash"),
        core_hash
    );
}

#[test]
fn canonical_ordering_never_coalesces_or_admits_other_envelopes() {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    let duplicate = atomic_value(
        &[movement("cash", 10, 11, 5), movement("cash", 10, 11, 6)],
        &[],
    );
    assert!(canonical_atomic_settlement_json(duplicate).is_err());
    // One ordinary payment is a complete intent; an intent without any leg is not.
    let single = atomic_value(&[movement("cash", 10, 11, 5)], &[]);
    assert_eq!(
        canonical_atomic_settlement_json(single.clone()).expect("single payment"),
        single
    );
    assert!(canonical_atomic_settlement_json(atomic_value(&[], &[])).is_err());
    // The settlement namespace owner must debit one of the legs.
    let foreign_owner = atomic_value_with_id(
        &[movement("cash", 10, 11, 5)],
        &[],
        &SettlementId::new(account(11), "dvp_bond_1".parse().expect("reference")),
    );
    assert!(canonical_atomic_settlement_json(foreign_owner.clone()).is_err());
    assert!(atomic_settlement_intent_hash(foreign_owner).is_err());
    // A bare reference is not a settlement identifier.
    let mut bare = atomic_value(&[movement("cash", 10, 11, 5)], &[]);
    bare.as_object_mut()
        .and_then(|envelope| envelope.get_mut("Settlement"))
        .and_then(Value::as_object_mut)
        .and_then(|variants| variants.get_mut("Atomic"))
        .and_then(Value::as_object_mut)
        .expect("atomic payload")
        .insert("settlement_id".into(), Value::String("dvp_bond_1".into()));
    assert!(canonical_atomic_settlement_json(bare).is_err());
    let duplicate_escrow = atomic_value(
        &[],
        &[
            escrow("cash", 10, 11, "same", 1),
            escrow("cash", 12, 11, "same", 2),
        ],
    );
    assert!(canonical_atomic_settlement_json(duplicate_escrow).is_err());
    let mut extra = atomic_value(
        &[movement("cash", 10, 11, 5), movement("bond", 11, 10, 7)],
        &[],
    );
    extra
        .as_object_mut()
        .expect("envelope")
        .insert("Log".into(), Value::Null);
    assert!(canonical_atomic_settlement_json(extra).is_err());
    let dvp: Value = json::from_str(r#"{"Settlement":{"Dvp":{}}}"#).expect("JSON");
    assert!(canonical_atomic_settlement_json(dvp.clone()).is_err());
    assert!(atomic_settlement_intent_hash(dvp).is_err());
}

#[test]
fn repo_intent_hashes_match_the_core_consent_methods() {
    let _network = ChainDiscriminantGuard::enter(PREFIX);
    let repo = |allow_early_repayment| {
        RepoIsi::new(
            "repo_si_2026".parse().expect("agreement id"),
            account(7),
            account(8),
            None,
            RepoCashLeg::new(definition("cash"), Quantity::from(1_000_u32)),
            RepoCollateralLeg::new(definition("bond"), Quantity::from(1_100_u32)),
            250,
            1_900_000_000_000,
            RepoGovernance::new(1_500, 0, allow_early_repayment),
        )
    };
    for allow in [false, true] {
        let initiate = repo(allow);
        let value = crate::instruction_to_json_value(&InstructionBox::from(
            RepoInstructionBox::from(initiate.clone()),
        ))
        .expect("render repo");
        let hashes = repo_intent_hashes(value).expect("repo hashes");
        assert_eq!(hashes.initiation, initiate.initiation_intent_hash());
        assert_eq!(hashes.maturity, initiate.maturity_intent_hash());
        assert_ne!(hashes.initiation, hashes.maturity);
    }
    assert_ne!(
        repo(false).initiation_intent_hash(),
        repo(true).initiation_intent_hash()
    );
    let reverse: Value =
        json::from_str(r#"{"Repo":{"Reverse":{"agreement_id":"repo_si_2026"}}}"#).expect("JSON");
    assert!(repo_intent_hashes(reverse).is_err());
}

/// The JavaScript SDK identifier helpers (`assetDefinitionIdFromSeed`, `newEscrowId`)
/// assert these same literals, pinning their derivations to the native rules.
#[test]
fn sdk_identifier_vectors_match_native_derivations() {
    let derived = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain"),
        "usd".parse().expect("name"),
    );
    assert_eq!(derived.to_string(), "4eaant86faGEgeH21U4qTTfpvwSb");
    assert_eq!(
        json::to_value(&EscrowId::new(Hash::new(b"bond-escrow"))).expect("escrow id JSON"),
        Value::String(
            "hash:7C485F0A8D12CE1522C64CEBE02CE693A4F6DE697C6F7DFE857EEBDB129065C3#F398".into()
        )
    );
}
