//! Exact field/array parity, original allocation ownership and refusal controls.

use super::*;
use crate::amx_prepare_streaming_allocations::{PhysicalObservation, with_exact_allocation_denial};
use iroha_crypto::{Algorithm, KeyPair};
use norito::core::{DecodeBudgetContext, DecodeLimits};

// Captured derive relations are test oracles only. Both production destinations
// use the shared kernels; neither can fall back to these ordinary allocations.
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CapturedStaking {
    min_validator_stake: Quantity,
    max_stake_shares_per_validator: NonZeroU32,
    max_pending_unbonds_per_share: NonZeroU32,
    unbonding_delay_ms: u64,
    max_slash_bps: u16,
    stake_asset_id: AssetDefinitionId,
    stake_escrow_account_id: AccountId,
    slash_sink_account_id: AccountId,
}
impl From<CapturedStaking> for PublicLaneStakingPolicy {
    fn from(v: CapturedStaking) -> Self {
        Self {
            min_validator_stake: v.min_validator_stake,
            max_stake_shares_per_validator: v.max_stake_shares_per_validator,
            max_pending_unbonds_per_share: v.max_pending_unbonds_per_share,
            unbonding_delay_ms: v.unbonding_delay_ms,
            max_slash_bps: v.max_slash_bps,
            stake_asset_id: v.stake_asset_id,
            stake_escrow_account_id: v.stake_escrow_account_id,
            slash_sink_account_id: v.slash_sink_account_id,
        }
    }
}
struct CapturedExemptions(RootFeeExemptions);
impl JsonDeserialize for CapturedExemptions {
    fn json_deserialize(p: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        RootFeeExemptions::from_sorted(Vec::<AccountId>::json_deserialize(p)?)
            .map(Self)
            .map_err(json::Error::from_decode_resource)
    }
}
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CapturedFees {
    fee_asset_id: AssetDefinitionId,
    fee_sink_account_id: AccountId,
    sponsor_vault_custody_account_id: AccountId,
    successful_claim_fee_exempt_authorities: CapturedExemptions,
    base_fee: Quantity,
    per_byte_fee: Quantity,
    per_instruction_fee: Quantity,
    per_gas_unit_fee: Quantity,
}
impl From<CapturedFees> for RootFeePolicy {
    fn from(v: CapturedFees) -> Self {
        Self {
            fee_asset_id: v.fee_asset_id,
            fee_sink_account_id: v.fee_sink_account_id,
            sponsor_vault_custody_account_id: v.sponsor_vault_custody_account_id,
            successful_claim_fee_exempt_authorities: v.successful_claim_fee_exempt_authorities.0,
            base_fee: v.base_fee,
            per_byte_fee: v.per_byte_fee,
            per_instruction_fee: v.per_instruction_fee,
            per_gas_unit_fee: v.per_gas_unit_fee,
        }
    }
}
fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
fn staking() -> PublicLaneStakingPolicy {
    PublicLaneStakingPolicy {
        min_validator_stake: "123456789012345678901234567890.125".parse().unwrap(),
        max_stake_shares_per_validator: NonZeroU32::new(17).unwrap(),
        max_pending_unbonds_per_share: NonZeroU32::new(5).unwrap(),
        unbonding_delay_ms: 43_210,
        max_slash_bps: 1_001,
        stake_asset_id: crate::parameter::system::SumeragiNposParameters::default()
            .xor_asset_definition_id,
        stake_escrow_account_id: account(11),
        slash_sink_account_id: account(12),
    }
}
fn fees() -> RootFeePolicy {
    RootFeePolicy {
        fee_asset_id: staking().stake_asset_id,
        fee_sink_account_id: account(21),
        sponsor_vault_custody_account_id: account(22),
        successful_claim_fee_exempt_authorities: RootFeeExemptions::try_from_iter([
            account(23),
            account(24),
        ])
        .unwrap(),
        base_fee: "12345678901234567890.1".parse().unwrap(),
        per_byte_fee: "0.003".parse().unwrap(),
        per_instruction_fee: "45.678".parse().unwrap(),
        per_gas_unit_fee: "0.000009".parse().unwrap(),
    }
}
fn document<T>(
    source: &str,
    parse: impl FnOnce(&mut json::Parser<'_>) -> Result<T, MonetaryJsonAdmissionError>,
) -> Result<T, MonetaryJsonAdmissionError> {
    let mut p = json::Parser::new(source);
    p.preflight_document()?;
    p.skip_ws();
    let value = parse(&mut p)?;
    p.finish_document()?;
    Ok(value)
}
fn decode_staking_source(
    source: &str,
    budget: &AllocationBudget,
) -> Result<AdmittedPublicLaneStakingPolicy, MonetaryJsonAdmissionError> {
    document(source, |p| {
        AdmittedPublicLaneStakingPolicy::try_decode_json(p, budget)
    })
}
fn decode_fee_source(
    source: &str,
    budget: &AllocationBudget,
) -> Result<AdmittedRootFeePolicy, MonetaryJsonAdmissionError> {
    document(source, |p| {
        AdmittedRootFeePolicy::try_decode_json(p, budget)
    })
}
fn json_error(error: MonetaryJsonAdmissionError) -> json::Error {
    match error {
        MonetaryJsonAdmissionError::Json(error) => error,
        other => panic!("ample original pool must preserve JSON refusal: {other}"),
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn monetary_staking_ordinary_and_admitted_preserve_captured_field_order_and_errors() {
    let source = json::to_json(&staking()).unwrap();
    let body = &source[..source.len() - 1];
    let source_account = json::to_json(&staking().stake_escrow_account_id).unwrap();
    let source_quantity = json::to_json(&staking().min_validator_stake).unwrap();
    for input in [
        "{}".to_owned(),
        "{\"unbonding_delay_ms\":2}".to_owned(),
        format!("{body},\"min_validator_stake\":false}}"),
        format!("{body},\"unknown\":false}}"),
        format!("{body},}}"),
        source.replacen(&source_account, "\"merchant@bank.example\"", 1),
        source.replacen(&source_quantity, "\"1.0\"", 1),
        source.replace(
            "\"max_stake_shares_per_validator\":17",
            "\"max_stake_shares_per_validator\":0",
        ),
        source.replace(
            "\"max_pending_unbonds_per_share\":5",
            "\"max_pending_unbonds_per_share\":-1",
        ),
        source.replace("\"max_slash_bps\":1001", "\"max_slash_bps\":65536"),
        "{\"\\uD800\":1}".to_owned(),
    ] {
        assert_ne!(input, source);
        let captured = json::from_str::<CapturedStaking>(&input)
            .err()
            .expect("invalid captured source");
        let ordinary = json::from_str::<PublicLaneStakingPolicy>(&input).unwrap_err();
        let budget = AllocationBudget::new(1 << 20);
        let admitted = json_error(decode_staking_source(&input, &budget).unwrap_err());
        assert_eq!(format!("{ordinary:?}"), format!("{captured:?}"), "{input}");
        assert_eq!(format!("{admitted:?}"), format!("{captured:?}"), "{input}");
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn monetary_fee_ordinary_and_admitted_preserve_captured_field_order_and_errors() {
    let source = json::to_json(&fees()).unwrap();
    let body = &source[..source.len() - 1];
    let source_account = json::to_json(&fees().sponsor_vault_custody_account_id).unwrap();
    let source_quantity = json::to_json(&fees().base_fee).unwrap();
    for input in [
        "{}".to_owned(),
        "{\"base_fee\":\"1\"}".to_owned(),
        format!("{body},\"fee_asset_id\":false}}"),
        format!("{body},\"unknown\":false}}"),
        format!("{body},}}"),
        source.replacen(&source_account, "\"not-an-account\"", 1),
        source.replacen(&source_quantity, "\"-1\"", 1),
        source.replace("\"per_byte_fee\":\"0.003\"", "\"per_byte_fee\":null"),
        "{\"\\uD800\":1}".to_owned(),
    ] {
        assert_ne!(input, source);
        let captured = json::from_str::<CapturedFees>(&input)
            .err()
            .expect("invalid captured source");
        let ordinary = json::from_str::<RootFeePolicy>(&input).unwrap_err();
        let budget = AllocationBudget::new(1 << 20);
        let admitted = json_error(decode_fee_source(&input, &budget).unwrap_err());
        assert_eq!(format!("{ordinary:?}"), format!("{captured:?}"), "{input}");
        assert_eq!(format!("{admitted:?}"), format!("{captured:?}"), "{input}");
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn monetary_exemptions_preserve_strict_order_and_later_malformed_leaf_precedence() {
    let values = fees().successful_claim_fee_exempt_authorities;
    let first = json::to_json(values.iter().next().unwrap()).unwrap();
    let second = json::to_json(values.iter().nth(1).unwrap()).unwrap();
    for input in [
        format!("[{first},{first}]"),
        format!("[{second},{first}]"),
        format!("[{first},{first},\"invalid\"]"),
        format!("[{first},]"),
        format!("[{first}, \n ]"),
        format!("[{first},{first},]"),
        format!("[{second},{first},]"),
        format!("[{first} {second}]"),
        format!("[,{first}]"),
        "[,]".to_owned(),
        "[false]".to_owned(),
    ] {
        let captured = json::from_str::<CapturedExemptions>(&input)
            .err()
            .expect("invalid captured array");
        let ordinary = json::from_str::<RootFeeExemptions>(&input).unwrap_err();
        let budget = AllocationBudget::new(1 << 20);
        let admitted = document(&input, |p| {
            decode_exemptions(p, &mut AdmittedDestination { budget: &budget })
        })
        .err()
        .expect("invalid admitted array");
        assert_eq!(format!("{ordinary:?}"), format!("{captured:?}"), "{input}");
        assert_eq!(
            format!("{:?}", json_error(admitted)),
            format!("{captured:?}"),
            "{input}"
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let budget = AllocationBudget::new(0);
    let empty = document("[]", |p| {
        decode_exemptions(p, &mut AdmittedDestination { budget: &budget })
    })
    .unwrap();
    assert!(empty.value.is_empty());
    assert!(empty.custody.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn monetary_staking_keeps_all_values_exact_original_custody_and_codec_identity() {
    for minimum in [Quantity::zero(), staking().min_validator_stake] {
        let mut expected = staking();
        expected.min_validator_stake = minimum;
        let source = json::to_json(&expected)
            .unwrap()
            .replace("\"min_validator_stake\"", "\"min_validator_\\u0073take\"");
        let captured: PublicLaneStakingPolicy =
            json::from_str::<CapturedStaking>(&source).unwrap().into();
        let budget = AllocationBudget::new(1 << 20);
        let foreign = AllocationBudget::new(1 << 20);
        let owner = decode_staking_source(&source, &budget).unwrap();
        assert_eq!(owner.get(), &captured);
        assert_eq!(owner.get(), &expected);
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        let custody = &owner.custody;
        let exact = custody.minimum.layout().size()
            + custody.escrow.bytes().unwrap()
            + custody.sink.bytes().unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            exact,
            "no shell or temporary text remains retained"
        );
        assert_eq!(
            norito::encode_canonical(owner.get()).unwrap(),
            norito::encode_canonical(&expected).unwrap()
        );
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn monetary_fees_keep_all_rates_exact_array_ledger_and_original_custody() {
    for empty in [false, true] {
        let mut expected = fees();
        if empty {
            expected.successful_claim_fee_exempt_authorities.clear();
            expected.base_fee = Quantity::zero();
        }
        let source = json::to_json(&expected).unwrap();
        let captured: RootFeePolicy = json::from_str::<CapturedFees>(&source).unwrap().into();
        let budget = AllocationBudget::new(1 << 20);
        let foreign = AllocationBudget::new(1 << 20);
        let owner = decode_fee_source(&source, &budget).unwrap();
        assert_eq!(owner.get(), &captured);
        assert_eq!(owner.get(), &expected);
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        let custody = &owner.custody;
        let exact = custody.sink.bytes().unwrap()
            + custody.sponsor.bytes().unwrap()
            + custody
                .rates
                .iter()
                .map(|charge| charge.layout().size())
                .sum::<usize>()
            + custody.exemptions.accounts.layout().size()
            + Layout::array::<ControllerCustody>(custody.exemptions.identities.capacity())
                .unwrap()
                .size()
            + custody
                .exemptions
                .identities
                .as_slice()
                .iter()
                .map(|charge| charge.bytes().unwrap())
                .sum::<usize>();
        assert_eq!(
            budget.reserved_bytes(),
            exact,
            "all retained bytes have their actual original ledger"
        );
        assert_eq!(
            norito::encode_canonical(owner.get()).unwrap(),
            norito::encode_canonical(&expected).unwrap()
        );
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn monetary_original_peak_refusal_retries_same_source_and_refunds_partial_graph() {
    let staking_source = json::to_json(&staking()).unwrap();
    let fees_source = json::to_json(&fees()).unwrap();
    for fees_case in [false, true] {
        let source = if fees_case {
            &fees_source
        } else {
            &staking_source
        };
        let original = AllocationBudget::new(1 << 20);
        if fees_case {
            drop(decode_fee_source(source, &original).unwrap());
        } else {
            drop(decode_staking_source(source, &original).unwrap());
        }
        assert_eq!(original.reserved_bytes(), 0);
        let peak = original.peak_reserved_bytes();
        assert!(peak > 0);
        let short = AllocationBudget::new(peak - 1);
        let error = if fees_case {
            decode_fee_source(source, &short).unwrap_err()
        } else {
            decode_staking_source(source, &short).unwrap_err()
        };
        assert!(
            matches!(
                error,
                MonetaryJsonAdmissionError::Allocation(ChargedBufferError::Admission(_))
            ),
            "{error}"
        );
        assert_eq!(short.reserved_bytes(), 0);
        let exact = AllocationBudget::new(peak);
        if fees_case {
            drop(decode_fee_source(source, &exact).unwrap());
        } else {
            drop(decode_staking_source(source, &exact).unwrap());
        }
        assert_eq!(exact.peak_reserved_bytes(), peak);
        assert_eq!(exact.reserved_bytes(), 0);
    }
}

#[test]
fn monetary_exemption_array_and_ledger_physical_refusals_keep_typed_allocator_error() {
    let source = json::to_json(&fees().successful_claim_fee_exempt_authorities).unwrap();
    for layout in [
        Layout::array::<AccountId>(2).unwrap(),
        Layout::array::<ControllerCustody>(2).unwrap(),
    ] {
        let budget = AllocationBudget::new(1 << 20);
        let (result, denied) = with_exact_allocation_denial(layout, || {
            document(&source, |p| {
                decode_exemptions(p, &mut AdmittedDestination { budget: &budget })
            })
        });
        assert!(denied, "requested original array/ledger is exercised");
        assert!(
            matches!(result, Err(MonetaryJsonAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == layout.size())
        );
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            document(&source, |p| decode_exemptions(
                p,
                &mut AdmittedDestination { budget: &budget }
            ))
            .unwrap()
            .value
            .len(),
            2
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
#[allow(unsafe_code)]
fn monetary_move_parts_retain_exact_exemption_pointer_without_new_allocation_or_early_refund() {
    let source = json::to_json(&fees()).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let owner = decode_fee_source(&source, &budget).unwrap();
    let original = owner
        .value
        .successful_claim_fee_exempt_authorities
        .iter()
        .as_slice()
        .as_ptr();
    let reserved = budget.reserved_bytes();
    struct Closed {
        value: RootFeePolicy,
        custody: RootFeePolicyCustody,
    }
    let observation = PhysicalObservation::start();
    // SAFETY: the same fields are immediately placed in one immutable value-first owner.
    let (value, custody) = unsafe { owner.into_allocation_parts() };
    let moved = Closed { value, custody };
    assert_eq!(observation.snapshot().requests(), [0; 3]);
    assert_eq!(
        moved
            .value
            .successful_claim_fee_exempt_authorities
            .iter()
            .as_slice()
            .as_ptr(),
        original
    );
    assert_eq!(observation.snapshot().retirements(original as usize), 0);
    assert_eq!(budget.reserved_bytes(), reserved);
    assert!(moved.custody.belongs_to(&budget));
    drop(moved);
    assert_eq!(observation.snapshot().retirements(original as usize), 1);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn monetary_staking_move_parts_are_allocation_free_and_keep_the_exact_pool() {
    let source = json::to_json(&staking()).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let owner = decode_staking_source(&source, &budget).unwrap();
    let reserved = budget.reserved_bytes();
    struct Closed {
        value: PublicLaneStakingPolicy,
        custody: PublicLaneStakingPolicyCustody,
    }
    let observation = PhysicalObservation::start();
    // SAFETY: no backing can change between extraction and this value-first owner.
    let (value, custody) = unsafe { owner.into_allocation_parts() };
    let moved = Closed { value, custody };
    assert_eq!(observation.snapshot().requests(), [0; 3]);
    assert_eq!(moved.value.max_slash_bps, 1_001);
    assert!(moved.custody.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(moved);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn monetary_cumulative_decoder_refusal_and_document_tail_keep_original_json_failure() {
    let source = json::to_json(&fees()).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    for fees_case in [false, true] {
        let input = if fees_case {
            source.clone()
        } else {
            json::to_json(&staking()).unwrap()
        };
        let context = DecodeBudgetContext::new(limits(0));
        let mut original_scope = None;
        let attempt = context
            .with(|| {
                norito::core::classify_decode_attempt(|| {
                    let result = if fees_case {
                        decode_fee_source(&input, &budget).map(drop)
                    } else {
                        decode_staking_source(&input, &budget).map(drop)
                    };
                    result.map_err(|error| {
                        let MonetaryJsonAdmissionError::Json(error) = error else {
                            panic!("original cumulative decoder is the cause");
                        };
                        let error = error.into_core_error();
                        let norito::Error::ScopedDecodeResource(scope) = &error else {
                            panic!("original field decoder must preserve scope: {error:?}");
                        };
                        original_scope = Some(scope.clone());
                        error
                    })
                })
            })
            .unwrap_err();
        assert_eq!(
            attempt.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(budget.reserved_bytes(), 0);
        let retained = attempt.into_local_refusal().unwrap().into_error();
        let norito::Error::ScopedDecodeResource(scope) = &retained else {
            panic!("retained exact original decoder identity");
        };
        assert_eq!(scope, &original_scope.unwrap());
        let replay = norito::core::classify_decode_attempt::<()>(|| Err(retained)).unwrap_err();
        assert_eq!(replay.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
        assert!(
            replay.local_refusal().is_none(),
            "old refusal cannot acquire a new local attempt"
        );
        if fees_case {
            drop(decode_fee_source(&input, &budget).unwrap());
        } else {
            drop(decode_staking_source(&input, &budget).unwrap());
        }
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let tail = format!("{source} false");
    let expected = json::from_str::<RootFeePolicy>(&tail).unwrap_err();
    let actual = json_error(decode_fee_source(&tail, &budget).unwrap_err());
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    assert_eq!(budget.reserved_bytes(), 0);
    drop(decode_fee_source(&source, &budget).unwrap());
    assert_eq!(budget.reserved_bytes(), 0);
}
