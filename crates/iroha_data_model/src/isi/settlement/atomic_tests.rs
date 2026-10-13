//! Model boundary tests for complete atomic intent and typed receipts.

use super::*;
use crate::{
    asset::{AssetBalanceScope, AssetDefinitionId},
    block::BlockHeader,
    isi::{
        SettlementDetails, SettlementInstructionBox, SettlementReceipt,
        test_support::{assert_registry_decodes, assert_slice_roundtrip},
    },
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_model_base::topology::DataSpaceId;

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("deterministic fixture key")
            .public_key()
            .clone(),
    )
}
fn asset() -> AssetDefinitionId {
    AssetDefinitionId::from_uuid_bytes([
        1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
    ])
    .expect("fixture UUIDv4")
}
fn instruction(count: usize) -> SettleAtomic {
    let from = account(1);
    let to = account(2);
    let values = (0..count)
        .map(|index| AtomicSettlementMovement {
            source: AssetId::with_scope(
                asset(),
                from.clone(),
                AssetBalanceScope::Dataspace(DataSpaceId::new(index as u64 + 1)),
            ),
            recipient: to.clone(),
            quantity: Quantity::from(index as u64 + 42),
        })
        .collect::<Vec<_>>();
    SettleAtomic {
        network_id: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"atomic-network"),
        )),
        settlement_id: SettlementId::new(
            from,
            "atomic_fixture".parse().expect("business reference"),
        ),
        movements: AtomicSettlementMovements::try_from(values).expect("canonical movements"),
        escrows: AtomicSettlementEscrows::empty(),
        expires_at_height: NonZeroU64::new(500).expect("nonzero expiry"),
        metadata: Metadata::default(),
    }
}

#[test]
#[ignore = "explicit current typed capture of the owner-qualified atomic settlement"]
fn print_scoped_settlement_atomic_fixture_rows() {
    let value = instruction(3);
    let record = crate::isi::generated_record_identity_tests::capture(value.clone());
    let boxed = crate::isi::generated_box_identity_tests::case(
        "Atomic",
        SettlementInstructionBox::Atomic(value),
    );
    println!(
        "SCOPED_SETTLEMENT_RECORD={}",
        json::to_json(&record).unwrap()
    );
    println!(
        "SCOPED_SETTLEMENT_BOX_CASE={}",
        json::to_json(&boxed).unwrap()
    );
}

#[test]
fn atomic_settlement_canonical_roundtrips_minimum_and_maximum() {
    for count in [1, 2, 3, 255] {
        let value = instruction(count);
        let frame = norito::encode_canonical(&value).expect("canonical frame");
        let decoded: SettleAtomic = norito::decode_canonical(&frame).expect("canonical decode");
        assert_eq!(decoded, value);
        assert_eq!(norito::encode_canonical(&decoded).expect("reencode"), frame);
        assert_slice_roundtrip(value.clone());
        assert_slice_roundtrip(SettlementInstructionBox::Atomic(value.clone()));
        let json = json::to_json(&value).expect("JSON");
        assert_eq!(
            json::from_str::<SettleAtomic>(&json).expect("JSON decode"),
            value
        );
    }
}

#[test]
fn atomic_settlement_rejects_namespace_owner_outside_its_debits() {
    for count in [1, 3] {
        let mut value = instruction(count);
        value.settlement_id.owner = account(3);
        assert!(
            value
                .validate()
                .unwrap_err()
                .contains("settlement id owner")
        );
        assert!(value.intent_hash().is_err());
        let frame = norito::encode_canonical(&value).unwrap();
        assert!(norito::decode_canonical::<SettleAtomic>(&frame).is_err());
        let json = json::to_json(&value).unwrap();
        // Derived JSON captures structure; consensus/SDK must apply the shared static check.
        assert!(
            json::from_str::<SettleAtomic>(&json)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[test]
fn atomic_settlement_intent_binds_the_explicit_participating_namespace_owner() {
    let mut value = instruction(2);
    let mut movements = value.movements.as_slice().to_vec();
    movements[1].source.account = account(4);
    movements.sort_by(|left, right| {
        (&left.source, &left.recipient).cmp(&(&right.source, &right.recipient))
    });
    value.movements = AtomicSettlementMovements::try_from(movements).unwrap();
    let original = value.intent_hash().unwrap();
    value.settlement_id.owner = account(4);
    assert_ne!(value.intent_hash().unwrap(), original);
}

#[test]
fn atomic_settlement_rejects_noncanonical_keys_and_invalid_movements() {
    #[derive(Encode)]
    struct Forged(Vec<AtomicSettlementMovement>);
    let valid = instruction(3).movements.as_slice().to_vec();
    // Empty movement lists are bounded by the containing intent's leg rule
    // (covered by `atomic_settlement_requires_one_leg_and_a_participating_owner`).
    let mut cases = vec![vec![valid[0].clone(); 256]];
    let mut reversed = valid.clone();
    reversed.swap(0, 1);
    cases.push(reversed);
    let mut duplicate = valid.clone();
    duplicate[1] = duplicate[0].clone();
    cases.push(duplicate);
    let mut quantity_duplicate = valid.clone();
    quantity_duplicate[1] = quantity_duplicate[0].clone();
    quantity_duplicate[1].quantity = Quantity::from(7_u32);
    cases.push(quantity_duplicate);
    let mut zero = valid.clone();
    zero[1].quantity = Quantity::from(0_u32);
    cases.push(vec![zero[1].clone()]);
    cases.push(zero);
    let mut self_payment = valid.clone();
    self_payment[1].recipient = self_payment[1].source.account().clone();
    cases.push(vec![self_payment[1].clone()]);
    cases.push(self_payment);
    for values in cases {
        assert!(AtomicSettlementMovements::try_from(values.clone()).is_err());
        let json = json::to_json(&values).expect("untrusted JSON");
        assert!(json::from_str::<AtomicSettlementMovements>(&json).is_err());
        let payload = Forged(values).encode();
        assert!(AtomicSettlementMovements::decode_from_slice(&payload).is_err());
        let frame = ncore::frame_bare_with_header_flags::<AtomicSettlementMovements>(
            &payload,
            ncore::default_encode_flags(),
        )
        .expect("forged frame");
        assert!(norito::decode_from_bytes::<AtomicSettlementMovements>(&frame).is_err());
    }
}

#[test]
fn atomic_settlement_decoders_reject_oversized_count_before_elements() {
    // An oversized declaration with no element body must fail on the count,
    // before Vec's element planner or allocation is reached. An empty movement
    // list is bounded by the containing intent's leg rule instead.
    for count in [256_u64, 65_536] {
        let field = count.to_le_bytes();
        let mut payload = vec![8_u8]; // compact V1 byte length of the sole Vec field
        payload.extend_from_slice(&field);
        let flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        let error =
            AtomicSettlementMovements::decode_from_slice(&payload).expect_err("reject count");
        let receipt_error = ResolvedSettlementMovements::decode_from_slice(&payload)
            .expect_err("reject receipt count");
        drop(flags);
        assert!(
            matches!(error, ncore::Error::Message(ref text) if text == "atomic movement count outside 0..=255")
        );
        assert!(
            matches!(receipt_error, ncore::Error::Message(ref text) if text == "atomic movement count outside 0..=255")
        );
    }
}

#[test]
fn atomic_settlement_containing_decoders_enforce_movement_validation() {
    #[derive(Encode)]
    struct ForgedMovements(Vec<AtomicSettlementMovement>);
    #[derive(Encode)]
    struct ForgedInstruction {
        network_id: NetworkId,
        settlement_id: SettlementId,
        movements: ForgedMovements,
        escrows: AtomicSettlementEscrows,
        expires_at_height: NonZeroU64,
        metadata: Metadata,
    }
    let value = instruction(3);
    let mut values = value.movements.as_slice().to_vec();
    values[1].quantity = Quantity::from(0_u32);
    let forged = ForgedInstruction {
        network_id: value.network_id,
        settlement_id: value.settlement_id,
        movements: ForgedMovements(values),
        escrows: value.escrows,
        expires_at_height: value.expires_at_height,
        metadata: value.metadata,
    }
    .encode();
    assert!(SettleAtomic::decode_from_slice(&forged).is_err());
    let frame =
        ncore::frame_bare_with_header_flags::<SettleAtomic>(&forged, ncore::default_encode_flags())
            .expect("correctly framed invalid instruction");
    assert!(norito::decode_from_bytes::<SettleAtomic>(&frame).is_err());
}

#[test]
fn atomic_settlement_rejects_omitted_binary_asset_scopes() {
    #[derive(Encode)]
    struct UnscopedSource {
        account: AccountId,
        definition: AssetDefinitionId,
    }
    #[derive(Encode)]
    struct UnscopedMovement {
        source: UnscopedSource,
        recipient: AccountId,
        quantity: Quantity,
    }
    #[derive(Encode)]
    struct UnscopedMovements(Vec<UnscopedMovement>);
    let mut values = vec![(account(1), account(2)), (account(3), account(4))];
    values.sort();
    let payload = UnscopedMovements(
        values
            .into_iter()
            .map(|(source, recipient)| UnscopedMovement {
                source: UnscopedSource {
                    account: source,
                    definition: asset(),
                },
                recipient,
                quantity: Quantity::from(42_u32),
            })
            .collect(),
    )
    .encode();
    assert!(
        AtomicSettlementMovements::decode_from_slice(&payload).is_err(),
        "omitted scope cannot default into an atomic consent preimage"
    );
}

#[test]
fn atomic_settlement_rejects_truncation_trailing_fields_and_unknown_json() {
    let value = instruction(3);
    let payload = value.encode();
    for length in 0..payload.len() {
        assert!(
            SettleAtomic::decode_from_slice(&payload[..length]).is_err(),
            "truncated at {length}"
        );
    }
    let mut trailing = payload;
    trailing.push(0);
    assert!(SettleAtomic::decode_from_slice(&trailing).is_err());
    let text = json::to_json(&value).expect("JSON");
    for malformed in [
        text.replacen('{', "{\"unknown\":0,", 1),
        text.replacen("\"expires_at_height\":500", "\"expires_at_height\":0", 1),
        text.replacen("\"quantity\":\"42\"", "\"quantity\":42", 1),
        text.replacen("\"quantity\":\"42\"", "\"quantity\":\"042\"", 1),
        text.replacen("\"quantity\":\"42\"", "\"quantity\":\"-1\"", 1),
        text.replacen("\"recipient\":", "\"unknown\":0,\"recipient\":", 1),
        text.replacen(
            "\"expires_at_height\":500",
            "\"expires_at_height\":500,\"expires_at_height\":500",
            1,
        ),
    ] {
        assert_ne!(malformed, text, "negative fixture changes a real field");
        assert!(json::from_str::<SettleAtomic>(&malformed).is_err());
    }
}

#[test]
fn atomic_settlement_intent_binds_every_authorized_field() {
    let value = instruction(3);
    let original = value.intent_hash().expect("intent");
    let mut variants = Vec::new();
    let mut changed = value.clone();
    changed.network_id = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"another-genesis")),
    );
    variants.push(changed);
    let mut changed = value.clone();
    changed.settlement_id.reference = "another_business_id".parse().expect("reference");
    variants.push(changed);
    let mut changed = value.clone();
    changed.expires_at_height = NonZeroU64::new(501).expect("expiry");
    variants.push(changed);
    let mut changed = value.clone();
    changed.metadata.insert(
        "reference".parse().expect("key"),
        iroha_primitives::json::Json::new("other"),
    );
    variants.push(changed);
    for index in 0..3 {
        for field in 0..5 {
            let mut values = value.movements.as_slice().to_vec();
            match field {
                0 => values[index].quantity = Quantity::from(99_u32),
                1 => values[index].recipient = account(3),
                2 => values[index].source.account = account(4),
                3 => {
                    values[index].source.definition = AssetDefinitionId::from_uuid_bytes([
                        2, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
                    ])
                    .expect("other asset")
                }
                4 => {
                    values[index].source.scope =
                        AssetBalanceScope::Dataspace(DataSpaceId::new(100 + index as u64))
                }
                _ => unreachable!(),
            }
            values.sort_by(|a, b| (&a.source, &a.recipient).cmp(&(&b.source, &b.recipient)));
            let mut changed = value.clone();
            changed.movements =
                AtomicSettlementMovements::try_from(values).expect("changed canonical vector");
            variants.push(changed);
        }
    }
    for changed in variants {
        assert_ne!(changed.intent_hash().expect("changed intent"), original);
    }
    let frame = norito::encode_canonical(&value).expect("canonical frame");
    assert_eq!(
        original,
        Hash::new_from_chunks(&[SettleAtomic::INTENT_HASH_DOMAIN, &frame])
    );
    assert_ne!(original, Hash::new(&frame));
}

#[test]
fn atomic_settlement_resolves_exact_scopes_and_rejects_inconsistent_receipts() {
    let value = instruction(3);
    let resolved = value.movements.resolve().expect("resolved vector");
    for (signed, committed) in value.movements.as_slice().iter().zip(resolved.as_slice()) {
        assert_eq!(signed.source, committed.source);
        assert_eq!(signed.destination(), committed.destination);
        assert_eq!(signed.quantity, committed.quantity);
    }
    for field in 0..6 {
        let mut changed = resolved.as_slice().to_vec();
        match field {
            0 => changed[1].destination.scope = AssetBalanceScope::Global,
            1 => {
                changed[1].destination.definition = AssetDefinitionId::from_uuid_bytes([
                    2, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
                ])
                .expect("other asset")
            }
            2 => changed[1].destination.account = changed[1].source.account().clone(),
            3 => changed[1].quantity = Quantity::from(0_u32),
            4 => changed.swap(0, 1),
            5 => {
                changed[1].metadata.insert(
                    "unexpected".parse().expect("key"),
                    iroha_primitives::json::Json::new(1),
                );
            }
            _ => unreachable!(),
        }
        assert!(ResolvedSettlementMovements::try_from(changed.clone()).is_err());
        assert!(
            json::from_str::<ResolvedSettlementMovements>(
                &json::to_json(&changed).expect("untrusted JSON")
            )
            .is_err()
        );
    }
}

#[test]
fn atomic_settlement_receipt_requires_one_typed_complete_outcome() {
    for count in [1, 3, 255] {
        let value = instruction(count);
        let receipt = SettlementReceipt {
            authority: account(9),
            metadata: value.metadata.clone(),
            block_height: 7,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"committing-block",
            )),
            executed_at_ms: 11,
            details: SettlementDetails::Atomic(crate::isi::AtomicSettlementDetails {
                movements: value.movements.resolve().expect("resolved"),
                intent_hash: value.intent_hash().expect("intent"),
                escrow_ids: Vec::new(),
            }),
        };
        let bytes = norito::encode_canonical(&receipt).expect("receipt frame");
        assert_eq!(
            norito::decode_canonical::<SettlementReceipt>(&bytes).expect("receipt decode"),
            receipt
        );
        let text = json::to_json(&receipt).expect("receipt JSON");
        assert_eq!(receipt.details.movements().count(), count);
        assert_eq!(
            json::from_str::<SettlementReceipt>(&text).expect("receipt JSON decode"),
            receipt
        );
        for malformed in [
            text.replacen('{', "{\"plan\":null,", 1),
            text.replacen("\"Atomic\"", "\"Unknown\"", 1),
        ] {
            assert_ne!(malformed, text);
            assert!(json::from_str::<SettlementReceipt>(&malformed).is_err());
        }
    }
}

#[test]
fn typed_receipt_iterator_retains_bilateral_and_all_atomic_references() {
    let resolved = instruction(255).movements.resolve().expect("resolved");
    let first = resolved.as_slice()[0].clone();
    let last = resolved.as_slice()[254].clone();
    for details in [
        SettlementDetails::Dvp(crate::isi::DvpSettlementDetails {
            delivery: first.clone(),
            payment: last.clone(),
            order: crate::isi::SettlementExecutionOrder::DeliveryThenPayment,
        }),
        SettlementDetails::Pvp(crate::isi::PvpSettlementDetails {
            primary: first.clone(),
            counter: last.clone(),
            order: crate::isi::SettlementExecutionOrder::PaymentThenDelivery,
        }),
        SettlementDetails::Atomic(crate::isi::AtomicSettlementDetails {
            movements: resolved,
            intent_hash: Hash::new(b"fixture-intent"),
            escrow_ids: Vec::new(),
        }),
    ] {
        let frame = norito::encode_canonical(&details).expect("typed receipt frame");
        let decoded = norito::decode_canonical::<SettlementDetails>(&frame)
            .expect("typed receipt canonical decode");
        assert_eq!(decoded, details);
        assert_eq!(norito::encode_canonical(&decoded).expect("reencode"), frame);
        let json = json::to_json(&details).expect("typed receipt JSON");
        assert_eq!(
            json::from_str::<SettlementDetails>(&json).expect("typed receipt JSON decode"),
            details
        );
        let movements = details.movements().collect::<Vec<_>>();
        assert_eq!(movements.first().copied(), Some(&first));
        assert_eq!(movements.last().copied(), Some(&last));
        assert_eq!(
            movements.len(),
            if matches!(
                details,
                SettlementDetails::Atomic(crate::isi::AtomicSettlementDetails { .. })
            ) {
                255
            } else {
                2
            }
        );
    }
}

#[test]
fn atomic_receipt_rejects_missing_commitment_and_duplicate_kind() {
    let details = SettlementDetails::Atomic(crate::isi::AtomicSettlementDetails {
        movements: instruction(3).movements.resolve().expect("resolved"),
        intent_hash: Hash::new(b"fixture-intent"),
        escrow_ids: Vec::new(),
    });
    let text = json::to_json(&details).expect("typed details JSON");
    // Generate the omission through the actual JSON value rather than assuming
    // whether the hash leaf is represented by a string or a byte array.
    let mut value: json::Value = json::from_str(&text).expect("JSON value");
    let json::Value::Object(ref mut outer) = value else {
        panic!("tagged object");
    };
    let json::Value::Object(inner) = outer.get_mut("value").expect("variant content") else {
        panic!("variant object");
    };
    assert!(inner.remove("intent_hash").is_some());
    assert!(
        json::from_str::<SettlementDetails>(&json::to_json(&value).expect("missing field JSON"))
            .is_err()
    );
    let duplicate = text.replacen(
        "\"kind\":\"Atomic\"",
        "\"kind\":\"Atomic\",\"kind\":\"Atomic\"",
        1,
    );
    assert_ne!(duplicate, text);
    assert!(json::from_str::<SettlementDetails>(&duplicate).is_err());
}

#[test]
fn fx_receipt_requires_context_and_rejects_retired_duplicate_movement_fields() {
    let movements = instruction(2)
        .movements
        .resolve()
        .expect("resolved codec fixture");
    let context = crate::isi::FxCorridorPricingContext {
        policy_id: "fx_fixture".parse().expect("policy id"),
        policy_revision: 1,
        oracle_evidence: crate::isi::FxCorridorOracleEvidence {
            feed_id: "fx_feed".parse().expect("feed id"),
            feed_config_version: crate::oracle::FeedConfigVersion(1),
            slot: 42,
            request_hash: Hash::new(b"codec-fixture-request"),
            event_hash: HashOf::from_untyped_unchecked(Hash::new(b"codec-fixture-event")),
        },
        oracle_recorded_at_ms: 11,
        oracle_rate: crate::oracle::ObservationValue::new(76, 0),
    };
    let context_json = json::to_json(&context).expect("context JSON");
    let retired_field = context_json.replacen('{', "{\"source_amount\":\"42\",", 1);
    assert!(json::from_str::<crate::isi::FxCorridorPricingContext>(&retired_field).is_err());
    let details = SettlementDetails::FxCorridor(crate::isi::FxCorridorSettlementDetails {
        source: movements.as_slice()[0].clone(),
        destination: movements.as_slice()[1].clone(),
        context,
    });
    assert_eq!(details.movements().count(), 2);
    let frame = norito::encode_canonical(&details).expect("FX detail frame");
    assert_eq!(
        norito::decode_canonical::<SettlementDetails>(&frame).expect("FX detail decode"),
        details
    );
    let text = json::to_json(&details).expect("FX details JSON");
    assert_eq!(
        json::from_str::<SettlementDetails>(&text).expect("FX details decode"),
        details
    );
    let mut value: json::Value = json::from_str(&text).expect("JSON value");
    let json::Value::Object(ref mut outer) = value else {
        panic!("tagged object");
    };
    let json::Value::Object(inner) = outer.get_mut("value").expect("variant content") else {
        panic!("variant object");
    };
    assert!(inner.remove("context").is_some());
    assert!(
        json::from_str::<SettlementDetails>(&json::to_json(&value).expect("missing context JSON"))
            .is_err()
    );
}

#[test]
fn atomic_settlement_is_unconditionally_registered_under_the_settlement_box() {
    let registry = crate::isi::registry::default();
    let value = SettlementInstructionBox::Atomic(instruction(3));
    assert_registry_decodes(&registry, SettlementInstructionBox::WIRE_ID, value);
    assert!(!registry.contains(SettleAtomic::WIRE_ID));
    assert!(!registry.contains(std::any::type_name::<SettleAtomic>()));
}

#[test]
fn atomic_settlement_generated_identity_has_root_and_container_roundtrips() {
    let value = instruction(3);
    assert_eq!(
        <SettleAtomic as norito::NoritoSchema>::nominal_name(),
        "iroha_data_model::isi::settlement::SettleAtomic"
    );
    let values = vec![Some(value)];
    let bytes = norito::encode_canonical(&values).expect("container frame");
    assert_eq!(
        norito::decode_canonical::<Vec<Option<SettleAtomic>>>(&bytes).expect("container decode"),
        values
    );
}

fn escrow(label: &str, amount: u32) -> AtomicSettlementEscrow {
    AtomicSettlementEscrow {
        source: AssetId::new(asset(), account(1)),
        escrow_id: crate::escrow::EscrowId::new(Hash::new(label.as_bytes())),
        beneficiary: account(2),
        amount: Quantity::from(amount),
        conditions: vec![crate::escrow::ConditionalEscrowCondition::Oracle(
            crate::escrow::ConditionalEscrowOracleCondition {
                id: "coupon_paid".parse().expect("condition id"),
                attestor: account(5),
                predicate: crate::escrow::ConditionalEscrowPredicate::Equals(
                    crate::escrow::ConditionalEscrowValue::Bool(true),
                ),
                sequence: core::num::NonZeroU32::new(1).expect("sequence"),
            },
        )],
        expires_at_ms: 1_800_000_000_000,
        evidence_hashes: vec![Hash::new(b"term-sheet")],
    }
}

fn sorted_escrows(mut values: Vec<AtomicSettlementEscrow>) -> AtomicSettlementEscrows {
    values.sort_by_key(|value| value.escrow_id);
    AtomicSettlementEscrows::try_from(values).expect("canonical escrows")
}

fn instruction_with_escrows(count: usize) -> SettleAtomic {
    let mut value = instruction(3);
    value.escrows = sorted_escrows(
        (0..count)
            .map(|index| escrow(&format!("escrow-{index}"), 10 + index as u32))
            .collect(),
    );
    value
}

#[test]
fn atomic_settlement_escrows_roundtrip_and_bind_the_intent() {
    for count in [0, 1, 16] {
        let value = instruction_with_escrows(count);
        let frame = norito::encode_canonical(&value).expect("canonical frame");
        let decoded: SettleAtomic = norito::decode_canonical(&frame).expect("canonical decode");
        assert_eq!(decoded, value);
        assert_slice_roundtrip(value.clone());
        assert_slice_roundtrip(SettlementInstructionBox::Atomic(value.clone()));
        let json = json::to_json(&value).expect("JSON");
        assert_eq!(
            json::from_str::<SettleAtomic>(&json).expect("JSON decode"),
            value
        );
        assert_eq!(value.escrows.escrow_ids().len(), count);
    }
    let value = instruction_with_escrows(2);
    let original = value.intent_hash().expect("intent");
    assert_ne!(
        instruction(3).intent_hash().expect("no escrows"),
        original,
        "adding an escrow leg changes the consented intent"
    );
    let mut variants = Vec::new();
    for field in 0..7 {
        let mut values = value.escrows.as_slice().to_vec();
        match field {
            0 => values[1].source = AssetId::new(asset(), account(7)),
            1 => values[1].escrow_id = crate::escrow::EscrowId::new(Hash::new(b"another-escrow")),
            2 => values[1].beneficiary = account(8),
            3 => values[1].amount = Quantity::from(99_u32),
            4 => values[1]
                .conditions
                .push(crate::escrow::ConditionalEscrowCondition::Within(
                    crate::escrow::ConditionalEscrowWithinCondition {
                        id: "window".parse().expect("condition id"),
                        duration_ms: NonZeroU64::new(60_000).expect("duration"),
                    },
                )),
            5 => values[1].expires_at_ms += 1,
            6 => values[1].evidence_hashes.clear(),
            _ => unreachable!(),
        }
        let mut changed = value.clone();
        changed.escrows = sorted_escrows(values);
        variants.push(changed);
    }
    let mut removed = value.clone();
    removed.escrows = sorted_escrows(value.escrows.as_slice()[..1].to_vec());
    variants.push(removed);
    for changed in variants {
        assert_ne!(changed.intent_hash().expect("changed intent"), original);
    }
}

#[test]
fn atomic_settlement_escrows_enforce_bounds_order_and_terms() {
    #[derive(Encode)]
    struct Forged(Vec<AtomicSettlementEscrow>);
    let valid = instruction_with_escrows(3).escrows.as_slice().to_vec();
    let mut cases = Vec::new();
    cases.push(
        (0..17)
            .map(|index| escrow(&format!("bound-{index}"), 1))
            .collect::<Vec<_>>(),
    );
    let mut reversed = valid.clone();
    reversed.swap(0, 1);
    cases.push(reversed);
    let mut duplicate = valid.clone();
    duplicate[1].escrow_id = duplicate[0].escrow_id;
    cases.push(duplicate);
    let mut zero = valid.clone();
    zero[1].amount = Quantity::from(0_u32);
    cases.push(zero);
    let mut scoped = valid.clone();
    scoped[1].source = AssetId::with_scope(
        asset(),
        account(1),
        AssetBalanceScope::Dataspace(DataSpaceId::new(4)),
    );
    cases.push(scoped);
    for (index, values) in cases.into_iter().enumerate() {
        let mut values = values;
        if index == 0 {
            values.sort_by_key(|value| value.escrow_id);
        }
        assert!(AtomicSettlementEscrows::try_from(values.clone()).is_err());
        let text = json::to_json(&values).expect("untrusted JSON");
        assert!(json::from_str::<AtomicSettlementEscrows>(&text).is_err());
        let payload = Forged(values.clone()).encode();
        let flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        assert!(AtomicSettlementEscrows::decode_from_slice(&payload).is_err());
        drop(flags);
        let mut instruction = instruction(3);
        instruction.escrows = AtomicSettlementEscrows::empty();
        assert!(instruction.validate().is_ok());
        let mut forged = instruction.clone();
        forged.escrows = AtomicSettlementEscrows(values);
        assert!(forged.validate().is_err());
        assert!(forged.intent_hash().is_err());
        assert!(norito::encode_canonical(&forged).is_err());
    }
}

#[test]
fn atomic_settlement_escrow_json_requires_every_field() {
    let value = instruction_with_escrows(1);
    let text = json::to_json(&value).expect("JSON");
    let missing_escrows = text.replacen(
        &format!(
            ",\"escrows\":{}",
            json::to_json(&value.escrows).expect("escrows JSON")
        ),
        "",
        1,
    );
    assert_ne!(missing_escrows, text);
    assert!(json::from_str::<SettleAtomic>(&missing_escrows).is_err());
    for malformed in [
        text.replacen(
            "\"evidence_hashes\":",
            "\"unknown\":0,\"evidence_hashes\":",
            1,
        ),
        text.replacen("\"expires_at_ms\":1800000000000,", "", 1),
        text.replacen("\"amount\":\"10\"", "\"amount\":10", 1),
    ] {
        assert_ne!(malformed, text);
        assert!(json::from_str::<SettleAtomic>(&malformed).is_err());
    }
}

#[test]
fn atomic_settlement_requires_one_leg_and_a_participating_owner() {
    let one_movement = |count: usize| -> AtomicSettlementMovements {
        AtomicSettlementMovements::try_from(instruction(3).movements.as_slice()[..count].to_vec())
            .expect("bounded movement list")
    };
    let escrows = |count: usize| {
        sorted_escrows(
            (0..count)
                .map(|index| escrow(&format!("leg-{index}"), 1 + index as u32))
                .collect(),
        )
    };
    // A subscription carries one fee movement plus four escrow legs, a pure
    // escrow exchange carries no movement at all, and one ordinary payment or
    // one escrow leg is a complete intent. The settlement ID owner must debit
    // at least one movement or escrow leg.
    let escrow_only_owner = account(6);
    for (movements, escrow_count, owner, accepted) in [
        (1, 4, account(1), true),
        (0, 2, account(1), true),
        (1, 1, account(1), true),
        (2, 0, account(1), true),
        (1, 0, account(1), true),
        (0, 1, account(1), true),
        (0, 0, account(1), false),
        (0, 2, account(3), false),
        (1, 0, account(3), false),
        (1, 1, escrow_only_owner.clone(), true),
    ] {
        let mut value = instruction(3);
        value.movements = one_movement(movements);
        value.escrows = escrows(escrow_count);
        if owner == escrow_only_owner {
            let mut legs = value.escrows.as_slice().to_vec();
            legs[0].source = AssetId::new(asset(), escrow_only_owner.clone());
            value.escrows = sorted_escrows(legs);
        }
        value.settlement_id.owner = owner.clone();
        assert_eq!(
            value.validate().is_ok(),
            accepted,
            "{movements} movements and {escrow_count} escrows owned by {owner}"
        );
        let payload = value.encode();
        let flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        let decoded = SettleAtomic::decode_from_slice(&payload).is_ok();
        drop(flags);
        assert_eq!(
            decoded, accepted,
            "the hand-written decoder enforces the leg and owner rules"
        );
        assert_eq!(value.intent_hash().is_ok(), accepted);
        if accepted {
            let frame = norito::encode_canonical(&value).expect("frame");
            assert_eq!(
                norito::decode_canonical::<SettleAtomic>(&frame).expect("decode"),
                value
            );
            assert_slice_roundtrip(value.clone());
            let json = json::to_json(&value).expect("JSON");
            assert_eq!(
                json::from_str::<SettleAtomic>(&json).expect("JSON decode"),
                value
            );
        }
    }
}
