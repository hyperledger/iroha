//! Consensus model shape, ownership and exact codec contracts.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_primitives::numeric::{Numeric, Quantity};
use norito::core::DecodeFromSlice;
use std::num::NonZeroU64;
fn checked_random_keypair_with_algorithm(algorithm: Algorithm) -> KeyPair {
    KeyPair::try_random_with_algorithm(algorithm)
        .expect("generate checked consensus fixture keypair")
}

include!("consensus/wire_schema_tests.rs");
#[derive(Encode)]
struct ForgedNexusFeeScheduleInputs {
    tx_bytes_len: u64,
    instruction_count: u64,
    gas_used: u64,
    base_fee: Numeric,
    per_byte_fee: Numeric,
    per_instruction_fee: Numeric,
    per_gas_unit_fee: Numeric,
}
#[derive(Encode)]
struct ForgedNexusFeeReceipt {
    version: u16,
    source_id: [u8; 32],
    dataspace_id: DataSpaceId,
    lane_id: LaneId,
    block_height: u64,
    debit_source: FeeDebitSource,
    fee_asset_id: AssetDefinitionId,
    program_revision: Option<u64>,
    lease_id: Option<Hash>,
    fee_amount: Numeric,
    settlement: NexusFeeSettlementV1,
    schedule: NexusFeeScheduleInputs,
}
#[derive(Encode)]
struct ForgedNposGenesisParams {
    epoch_length_blocks: NonZeroU64,
    epoch_seed: [u8; 32],
    max_validators: u32,
    min_self_bond: Numeric,
    min_nomination_bond: Numeric,
    finality_margin_blocks: u64,
    evidence_horizon_blocks: u64,
    activation_lag_blocks: u64,
    slashing_delay_blocks: u64,
}
fn sample_nexus_fee_receipt(source_id: [u8; 32]) -> NexusFeeReceipt {
    NexusFeeReceipt {
        version: NexusFeeReceipt::VERSION,
        source_id,
        dataspace_id: DataSpaceId::new(7),
        lane_id: LaneId::new(1),
        block_height: 42,
        debit_source: FeeDebitSource::Account(crate::account::AccountId::new(
            checked_random_keypair_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        )),
        fee_asset_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
            .parse()
            .expect("canonical asset definition id"),
        program_revision: None,
        lease_id: None,
        fee_amount: "0.001".parse().expect("quantity"),
        settlement: NexusFeeSettlementV1::Burn,
        schedule: NexusFeeScheduleInputs {
            tx_bytes_len: 100,
            instruction_count: 1,
            gas_used: 0,
            base_fee: Quantity::zero(),
            per_byte_fee: Quantity::zero(),
            per_instruction_fee: "0.001".parse().expect("quantity"),
            per_gas_unit_fee: Quantity::zero(),
        },
    }
}
#[test]
fn negative_numeric_payloads_cannot_decode_as_nexus_fees() {
    let forged_schedule = ForgedNexusFeeScheduleInputs {
        tx_bytes_len: 1,
        instruction_count: 1,
        gas_used: 1,
        base_fee: Numeric::new(-1_i32, 0),
        per_byte_fee: Numeric::zero(),
        per_instruction_fee: Numeric::zero(),
        per_gas_unit_fee: Numeric::zero(),
    };
    let encoded = forged_schedule.encode();
    assert!(
        NexusFeeScheduleInputs::decode(&mut encoded.as_slice()).is_err(),
        "a negative signed payload must not decode as a fee schedule component"
    );
    let valid = sample_nexus_fee_receipt([0xA5; 32]);
    let forged_receipt = ForgedNexusFeeReceipt {
        version: valid.version,
        source_id: valid.source_id,
        dataspace_id: valid.dataspace_id,
        lane_id: valid.lane_id,
        block_height: valid.block_height,
        debit_source: valid.debit_source,
        fee_asset_id: valid.fee_asset_id,
        program_revision: valid.program_revision,
        lease_id: valid.lease_id,
        fee_amount: Numeric::new(-1_i32, 0),
        settlement: valid.settlement,
        schedule: valid.schedule,
    };
    let encoded = forged_receipt.encode();
    assert!(
        NexusFeeReceipt::decode(&mut encoded.as_slice()).is_err(),
        "a negative signed payload must not decode as a fee receipt amount"
    );
}
#[test]
fn sponsored_nexus_fee_receipt_roundtrips_typed_source_and_asset() {
    let mut receipt = sample_nexus_fee_receipt([0x5A; 32]);
    receipt.debit_source = FeeDebitSource::SponsorProgram(crate::nexus::FeeSponsorProgramId::new(
        crate::account::AccountId::new(
            checked_random_keypair_with_algorithm(Algorithm::Ed25519)
                .public_key()
                .clone(),
        ),
        "retail".parse().expect("program name"),
    ));
    receipt.program_revision = Some(4);
    receipt.lease_id = Some(Hash::new(b"receipt-spend-lease"));
    let bytes = receipt.encode();
    assert_eq!(
        NexusFeeReceipt::decode(&mut bytes.as_slice()).expect("decode sponsored receipt"),
        receipt
    );
    let json = norito::json::to_json(&receipt).expect("serialize sponsored receipt");
    assert_eq!(
        norito::json::from_str::<NexusFeeReceipt>(&json).expect("deserialize sponsored receipt"),
        receipt
    );
}

#[test]
fn nexus_fee_receipt_rejects_pre_release_layout_without_nullable_bindings() {
    #[derive(Encode)]
    struct PreReleaseNexusFeeReceipt {
        version: u16,
        source_id: [u8; 32],
        dataspace_id: DataSpaceId,
        lane_id: LaneId,
        block_height: u64,
        debit_source: FeeDebitSource,
        fee_asset_id: crate::asset::AssetDefinitionId,
        fee_amount: Quantity,
        schedule: NexusFeeScheduleInputs,
    }

    let receipt = sample_nexus_fee_receipt([0x5C; 32]);
    let bytes = PreReleaseNexusFeeReceipt {
        version: receipt.version,
        source_id: receipt.source_id,
        dataspace_id: receipt.dataspace_id,
        lane_id: receipt.lane_id,
        block_height: receipt.block_height,
        debit_source: receipt.debit_source,
        fee_asset_id: receipt.fee_asset_id,
        fee_amount: receipt.fee_amount,
        schedule: receipt.schedule,
    }
    .encode();
    assert!(
        NexusFeeReceipt::decode_all(&mut bytes.as_slice()).is_err(),
        "the first-release fee receipt must reject the layout without revision and lease slots"
    );
}

#[test]
fn nexus_fee_receipt_json_requires_nullable_bindings_and_closed_nested_schedule() {
    let receipt = sample_nexus_fee_receipt([0x5D; 32]);
    for field in ["program_revision", "lease_id"] {
        let mut value = norito::json::to_value(&receipt).expect("serialize Nexus fee receipt");
        assert!(
            value
                .as_object_mut()
                .expect("Nexus fee receipt JSON object")
                .remove(field)
                .is_some(),
            "fixture must contain nullable field {field}"
        );
        assert!(
            norito::json::from_value::<NexusFeeReceipt>(value).is_err(),
            "the first-release Nexus fee receipt must require {field}"
        );
    }

    let mut unknown = norito::json::to_value(&receipt).expect("serialize Nexus fee receipt");
    unknown
        .as_object_mut()
        .expect("Nexus fee receipt JSON object")
        .insert("pre_release_field".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<NexusFeeReceipt>(unknown).is_err(),
        "the first-release Nexus fee receipt must reject unknown fields"
    );

    let mut unknown_schedule =
        norito::json::to_value(&receipt.schedule).expect("serialize Nexus fee schedule");
    unknown_schedule
        .as_object_mut()
        .expect("Nexus fee schedule JSON object")
        .insert("pre_release_field".to_owned(), norito::json::Value::Null);
    assert!(
        norito::json::from_value::<NexusFeeScheduleInputs>(unknown_schedule).is_err(),
        "the first-release Nexus fee schedule must reject unknown fields"
    );
}

#[test]
fn negative_numeric_payloads_cannot_decode_as_npos_bonds() {
    let forged = ForgedNposGenesisParams {
        epoch_length_blocks: NonZeroU64::new(10).expect("nonzero epoch"),
        epoch_seed: [1; 32],
        max_validators: 4,
        min_self_bond: Numeric::new(-1_i32, 0),
        min_nomination_bond: Numeric::one(),
        finality_margin_blocks: 1,
        evidence_horizon_blocks: 10,
        activation_lag_blocks: 1,
        slashing_delay_blocks: 1,
    };
    let encoded = forged.encode();
    assert!(
        NposGenesisParams::decode(&mut encoded.as_slice()).is_err(),
        "a negative signed payload must not decode as an NPoS minimum bond"
    );
}

#[test]
fn exec_witness_roundtrip_codec() {
    let w = ExecWitness {
        reads: vec![ExecKv {
            key: b"key:read".to_vec(),
            value: b"value-pre".to_vec(),
        }],
        writes: vec![ExecKv {
            key: b"key:write".to_vec(),
            value: b"value-post".to_vec(),
        }],
        fastpq_transcripts: Vec::new(),
        fastpq_batches: Vec::new(),
    };
    let bytes = w.encode();
    let dec = ExecWitness::decode(&mut &bytes[..]).expect("decode witness");
    assert_eq!(w, dec);
}
#[test]
fn lane_settlement_receipt_decode_from_slice_requires_canonical_bare_prefix() {
    let receipt = LaneSettlementReceipt {
        source_id: [0xA5; 32],
        local_amount: "1.25".parse().expect("quantity"),
        xor_due: "2.5".parse().expect("quantity"),
        xor_after_haircut: "2.0".parse().expect("quantity"),
        xor_variance: "0.5".parse().expect("quantity"),
        timestamp_ms: 1_689_000,
    };
    let canonical = receipt.encode();
    let mut followed_by_next_field = canonical.clone();
    followed_by_next_field.extend_from_slice(b"next-field");
    let (decoded, used) = LaneSettlementReceipt::decode_from_slice(&followed_by_next_field)
        .expect("decode canonical lane settlement receipt prefix");
    assert_eq!(decoded, receipt);
    assert_eq!(used, canonical.len());
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate = {
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::codec::encode_with_header_flags(&receipt).0
    };
    assert_ne!(
        alternate, canonical,
        "alternate layout must differ for the canonicality probe"
    );
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    let (decoded, used) = LaneSettlementReceipt::decode_from_slice(&followed_by_next_field)
        .expect("canonical receipt prefix must ignore the ambient layout");
    assert_eq!(decoded, receipt);
    assert_eq!(used, canonical.len());
    LaneSettlementReceipt::decode_from_slice(&alternate)
        .expect_err("alternate bare layout must be rejected");
}
include!("consensus/runtime_diagnostics_tests.rs");
include!("consensus/npos_diagnostics_tests.rs");

#[test]
fn borrowed_native_evidence_frame_preserves_original_parser_refusal() {
    use super::Evidence;
    for bytes in [Vec::new(), vec![1], vec![0; 32]] {
        let original = Evidence { native: bytes };
        let owned = original
            .decode_native()
            .expect_err("malformed native proof");
        let borrowed = Evidence::decode_native_frame(original.native_frame())
            .expect_err("the original borrowed frame has the same malformed proof");
        assert_eq!(borrowed.to_string(), owned.to_string());
    }
}
