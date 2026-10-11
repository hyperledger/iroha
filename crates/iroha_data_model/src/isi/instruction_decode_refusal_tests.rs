//! Original instruction decoder refusal, bounded scratch, and same-input retry controls.

use super::*;
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeFromSlice, DecodeResourceError,
    DeserializePayload, classify_decode_attempt,
};

fn allocation_limits(bytes: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn fixture() -> InstructionBox {
    InstructionBox::from(Log::new(
        Level::INFO,
        "original instruction refusal".repeat(4),
    ))
}

fn assert_original_refusal_and_retry(decode: impl Fn() -> Result<InstructionBox, norito::Error>) {
    let (baseline, usage) =
        norito::core::with_decode_limits_measured(allocation_limits(usize::MAX), &decode);
    let expected = baseline.unwrap();
    let demand = usage.total_allocated_bytes();
    assert!(demand > 1);
    for limit in [0, 1, demand - 1] {
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let original = DecodeBudgetContext::try_new_owned(
            allocation_limits(demand.checked_mul(4).unwrap()),
            &pool,
        )
        .unwrap();
        let retained = pool.reserved_bytes();
        let mut observed = None;
        let refusal = original
            .with(|| {
                norito::with_decode_limits_scope(allocation_limits(limit), || {
                    classify_decode_attempt(|| {
                        let error = decode().expect_err("original instruction decode must refuse");
                        let norito::Error::ScopedDecodeResource(origin) = &error else {
                            panic!("instruction decoder erased original scoped refusal: {error:?}");
                        };
                        observed = Some(origin.clone());
                        Err::<(), _>(error)
                    })
                })
            })
            .unwrap_err();
        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let refusal = refusal.into_error();
        let Some(DecodeResourceError::TotalAllocationExceeded {
            attempted,
            limit: actual,
        }) = refusal.decode_resource_error()
        else {
            panic!("instruction decoder lost allocation fields: {refusal:?}");
        };
        assert_eq!(actual, u64::try_from(limit).unwrap());
        assert!(attempted > actual);
        let norito::Error::ScopedDecodeResource(returned) = refusal else {
            panic!("instruction decoder lost original observer");
        };
        assert_eq!(returned, observed.unwrap());
        drop(returned);
        let before_retry = original.consumed_allocated_bytes();
        assert_eq!(original.with(&decode).unwrap(), expected);
        assert_eq!(
            original.consumed_allocated_bytes() - before_retry,
            u64::try_from(demand).unwrap()
        );
        assert_eq!(pool.reserved_bytes(), retained);
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn archived_instruction_refusal_stops_without_allocating_an_owned_pair_retry() {
    let expected = fixture();
    let framed = norito::core::to_bytes(&expected).unwrap();
    let archived = norito::core::from_bytes::<InstructionBox>(&framed).unwrap();
    let bytes = norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast()).unwrap();
    let borrowed = || decode_instruction_from_borrowed_pair(bytes).map(|(value, _)| value);
    let archived_decode = || InstructionBox::try_deserialize(archived);
    let (_, usage) =
        norito::core::with_decode_limits_measured(allocation_limits(usize::MAX), borrowed);
    let demand = usage.total_allocated_bytes();
    for limit in [0, 1, demand - 1] {
        let (original, original_usage) =
            norito::core::with_decode_limits_measured(allocation_limits(limit), borrowed);
        let (actual, actual_usage) =
            norito::core::with_decode_limits_measured(allocation_limits(limit), archived_decode);
        assert_eq!(
            actual.unwrap_err().decode_resource_error(),
            original.unwrap_err().decode_resource_error(),
            "archived instruction must return its first borrowed decode refusal"
        );
        assert_eq!(
            actual_usage.total_allocated_bytes(),
            original_usage.total_allocated_bytes(),
            "refused instruction must not allocate or retry an owned pair"
        );
    }
    assert_original_refusal_and_retry(archived_decode);
}

#[test]
fn instruction_slice_retains_original_scoped_refusal_and_retry() {
    let mut bytes = Vec::new();
    norito::core::serialize_to_buffer(&fixture(), &mut bytes).unwrap();
    let pointer = bytes.as_ptr();
    assert_original_refusal_and_retry(|| {
        InstructionBox::decode_from_slice(&bytes).map(|(value, used)| {
            assert_eq!(used, bytes.len());
            value
        })
    });
    assert_eq!(bytes.as_ptr(), pointer);
}

#[test]
fn instruction_json_retains_original_scoped_refusal_and_retry() {
    let source = norito::json::to_json(&fixture()).unwrap();
    let pointer = source.as_ptr();
    assert_original_refusal_and_retry(|| {
        norito::json::from_json::<InstructionBox>(&source)
            .map_err(norito::json::Error::into_core_error)
    });
    assert_eq!(source.as_ptr(), pointer);
}

#[test]
fn instruction_base64_scratch_is_admitted_before_decode_and_retries_original_input() {
    let framed = norito::encode_canonical(&fixture()).unwrap();
    let encoded = STANDARD.encode(&framed);
    let scratch = base64::decoded_len_estimate(encoded.len());
    let (result, _) =
        norito::core::with_decode_limits_measured(allocation_limits(scratch - 1), || {
            instruction_box_from_base64_literal(&encoded)
        });
    let error = result
        .expect_err("base64 scratch must be admitted before allocation")
        .into_core_error();
    assert_eq!(
        error.decode_resource_error(),
        Some(DecodeResourceError::TotalAllocationExceeded {
            attempted: u64::try_from(scratch).unwrap(),
            limit: u64::try_from(scratch - 1).unwrap(),
        }),
        "instruction base64 must refuse its original scratch reservation"
    );
    assert_original_refusal_and_retry(|| {
        instruction_box_from_base64_literal(&encoded).map_err(norito::json::Error::into_core_error)
    });
    let malformed = instruction_box_from_base64_literal("%not-base64").unwrap_err();
    assert!(!malformed.is_decode_resource_limit());
}

#[test]
fn structured_asset_instructions_preserve_original_account_refusal_and_retry() {
    use crate::asset::{AssetTransferAvailability, AssetTransferControlWindow, AssetTransferLimit};
    use crate::isi::asset_transfer_control::{
        SetAssetHoldingLimit, SetAssetTransferAvailability, SetAssetTransferBlacklist,
        SetAssetTransferControl,
    };
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0xA7; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let account = AccountId::new(key.public_key().clone());
    let asset = crate::asset::AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").unwrap(),
        "rose".parse().unwrap(),
    );
    let cases: [(&str, &str, InstructionBox); 4] = [
        (
            "SetAssetTransferAvailability",
            r#""expected_revision":7,"incoming":"Disabled","outgoing":"Enabled","reason":"review""#,
            SetAssetTransferAvailability::new(
                account.clone(),
                asset.clone(),
                7,
                AssetTransferAvailability::Disabled,
                AssetTransferAvailability::Enabled,
                Some("review".into()),
            )
            .into(),
        ),
        (
            "SetAssetHoldingLimit",
            r#""holding_limit":"9""#,
            SetAssetHoldingLimit::new(account.clone(), asset.clone(), Some(9_u32.into())).into(),
        ),
        (
            "SetAssetTransferBlacklist",
            r#""blacklisted":true"#,
            SetAssetTransferBlacklist::new(account.clone(), asset.clone(), true).into(),
        ),
        (
            "SetAssetTransferControl",
            r#""limits":[{"window":"DAY","cap_amount":"9"}]"#,
            SetAssetTransferControl::new(
                account.clone(),
                asset.clone(),
                vec![AssetTransferLimit {
                    window: AssetTransferControlWindow::Day,
                    cap_amount: Some(9_u32.into()),
                }],
            )
            .into(),
        ),
    ];
    for (name, fields, expected) in cases {
        let source = format!(
            r#"{{"name":"{name}","params":{{"account_id":"{account}","asset_definition_id":"{asset}",{fields}}}}}"#
        );
        assert_eq!(
            norito::json::from_json::<InstructionBox>(&source).unwrap(),
            expected
        );
        let pointer = source.as_ptr();
        assert_original_refusal_and_retry(|| {
            norito::json::from_json::<InstructionBox>(&source)
                .map_err(norito::json::Error::into_core_error)
        });
        assert_eq!(source.as_ptr(), pointer);
        for bad in ["not-an-account".to_owned(), format!(" {account}")] {
            let invalid = source.replacen(&account.to_string(), &bad, 1);
            let error = norito::json::from_json::<InstructionBox>(&invalid).unwrap_err();
            assert!(
                !error.is_decode_resource_limit(),
                "malformed account remains terminal"
            );
        }
    }
}
