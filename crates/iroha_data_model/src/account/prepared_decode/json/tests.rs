//! Original controller custody, exact native refusals and observer provenance.

use super::*;
use crate::amx_prepare_streaming_allocations::{
    PhysicalObservation, measured, with_nth_exact_allocation_denial,
};
use iroha_crypto::KeyPair;
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, classify_decode_attempt,
};

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    )
}
fn multi() -> AccountId {
    let members = [0x35, 0x36]
        .into_iter()
        .map(|seed| MultisigMember::new(account(seed).try_signatory().unwrap().clone(), 1).unwrap())
        .collect();
    AccountId::new_multisig(MultisigPolicy::new(2, members).unwrap())
}
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<ChargedAccount, AccountJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let result = ChargedAccount::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(result)
}
fn expect_failure(
    result: Result<ChargedAccount, AccountJsonAdmissionError>,
) -> AccountJsonAdmissionError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected actual decode refusal"),
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn direct_json_preserves_single_multisig_and_foreign_pool_boundaries() {
    for chain in [0, 369, 753, 1, 42, 65535] {
        let _chain = address::ChainDiscriminantGuard::enter(chain);
        for expected in [account(0x33), multi()] {
            let wire = json::to_json(&expected).unwrap();
            let pool = AllocationBudget::new(1 << 20);
            let foreign = AllocationBudget::new(1 << 20);
            let owner = decode(&wire, &pool).unwrap();
            assert_eq!(owner.get(), &expected);
            assert!(owner.belongs_to(&pool));
            assert!(!owner.belongs_to(&foreign));
            assert_eq!(pool.reserved_bytes(), owner.custody.bytes().unwrap());
            assert_eq!(json::from_str::<AccountId>(&wire).unwrap(), expected);
            drop(owner);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn escaped_json_text_uses_original_string_kernel_without_alternate_identity() {
    use std::fmt::Write as _;
    let _chain = address::ChainDiscriminantGuard::enter(753);
    let expected = account(0x34);
    let literal = expected.canonical_i105().unwrap();
    let mut escaped = String::from("\"");
    for ch in literal.chars() {
        if ch.is_ascii() {
            write!(&mut escaped, "\\u{:04x}", u32::from(ch)).unwrap();
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('"');
    let pool = AllocationBudget::new(1 << 20);
    let owner = decode(&escaped, &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(json::from_str::<AccountId>(&escaped).unwrap(), expected);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
    for source in [
        format!("{escaped} false"),
        "null".into(),
        "[]".into(),
        "\"\\uD800\"".into(),
    ] {
        assert!(decode(&source, &pool).is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn every_finite_pool_prefix_refunds_before_retry_and_never_changes_source() {
    let _chain = address::ChainDiscriminantGuard::enter(753);
    let expected = multi();
    let source = json::to_json(&expected).unwrap();
    let original = source.clone();
    let pool = AllocationBudget::new(0);
    let (zero, requests) = measured(|| decode(&source, &pool));
    assert!(matches!(
        zero,
        Err(AccountJsonAdmissionError::Allocation(
            ChargedBufferError::Admission(_)
        ))
    ));
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(pool.reserved_bytes(), 0);
    let mut failures = 0;
    let mut succeeded = false;
    for capacity in (1..8192).step_by(23) {
        pool.set_limit_bytes(capacity);
        match decode(&source, &pool) {
            Err(AccountJsonAdmissionError::Allocation(ChargedBufferError::Admission(_))) => {
                failures += 1
            }
            Err(error) => panic!("valid literal must only meet the actual finite pool: {error:?}"),
            Ok(owner) => {
                assert_eq!(owner.get(), &expected);
                drop(owner);
                succeeded = true;
                break;
            }
        }
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(source, original);
    }
    assert!(failures > 3 && succeeded);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(1 << 20);
    drop(decode(&source, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn each_actual_single_decode_allocation_fails_fallibly_and_refunds() {
    let _chain = address::ChainDiscriminantGuard::enter(753);
    let expected = account(0x38);
    let literal = expected.canonical_i105().unwrap();
    let wire = json::to_json(&expected).unwrap();
    let canonical = expected
        .to_account_address()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let digits = literal.strip_prefix("sora").unwrap().chars().count();
    let layouts = [
        Layout::array::<u8>(literal.len()).unwrap(),
        Layout::array::<u8>(digits).unwrap(),
        Layout::array::<u64>(((digits - 6) * 7).div_ceil(64)).unwrap(),
        Layout::array::<u8>(canonical.len()).unwrap(),
        expected
            .try_signatory()
            .unwrap()
            .retained_allocation_layout(),
        Layout::array::<u64>(canonical.len().div_ceil(8)).unwrap(),
        Layout::array::<u8>((canonical.len() * 8 + 5) / 6).unwrap(),
    ];
    let pool = AllocationBudget::new(1 << 20);
    let (owner, requests) = measured(|| decode(&wire, &pool));
    assert_eq!(
        requests,
        [7, 0, 0],
        "all actual scratch and retained allocations are enumerated"
    );
    drop(owner.unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
    for (index, layout) in layouts.into_iter().enumerate() {
        let skip = layouts[..index]
            .iter()
            .filter(|earlier| **earlier == layout)
            .count();
        let (result, denied) =
            with_nth_exact_allocation_denial(layout, skip, || decode(&wire, &pool));
        assert!(denied, "actual allocation {index} reached");
        assert!(
            matches!(result,Err(AccountJsonAdmissionError::Allocation(ChargedBufferError::Allocator{requested_bytes})) if requested_bytes==layout.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(decode(&wire, &pool).unwrap().get(), &expected);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn sibling_and_unwind_keep_actual_key_lifetime_bound_to_its_original_credit() {
    let _chain = address::ChainDiscriminantGuard::enter(753);
    let expected = account(0x39);
    let source = json::to_json(&expected).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let observation = PhysicalObservation::start();
    let owner = decode(&source, &pool).unwrap();
    let layout = expected
        .try_signatory()
        .unwrap()
        .retained_allocation_layout();
    let pointer = observation.snapshot().single_live_pointer(layout).unwrap();
    // Earlier scratch may have used the same native address. Retain its history
    // while observing this key's distinct still-live generation.
    let retired_before = observation.snapshot().retirements(pointer);
    pool.set_limit_bytes(pool.reserved_bytes());
    assert!(decode(&source, &pool).is_err());
    assert_eq!(owner.get(), &expected);
    assert!(owner.belongs_to(&pool));
    assert_eq!(
        observation.snapshot().single_live_pointer(layout),
        Some(pointer)
    );
    assert_eq!(observation.snapshot().retirements(pointer), retired_before);
    assert_eq!(pool.reserved_bytes(), layout.size());
    drop(owner);
    assert_eq!(observation.snapshot().single_live_pointer(layout), None);
    assert_eq!(
        observation.snapshot().retirements(pointer),
        retired_before + 1
    );
    assert_eq!(pool.reserved_bytes(), 0);
    drop(observation);
    pool.set_limit_bytes(1 << 20);
    let owner = decode(&source, &pool).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _retained = owner;
        panic!("abandoned account destination");
    }));
    assert!(result.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn direct_refusal_preserves_same_attempt_identity_and_replay_stays_invalid() {
    let _chain = address::ChainDiscriminantGuard::enter(753);
    let expected = account(0x40);
    let source = json::to_json(&expected).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let (result, usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(&source, &pool));
    drop(result.unwrap());
    let demand = usage.total_allocated_bytes();
    assert_eq!(pool.reserved_bytes(), 0);
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let mut seen = None;
    let attempt = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let error = expect_failure(decode(&source, &pool));
                    let AccountJsonAdmissionError::Json(json::Error::ScopedDecodeResource(origin)) =
                        error
                    else {
                        panic!("original observer lost: {error:?}")
                    };
                    seen = Some(origin.clone());
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original cause lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let _ = expect_failure(decode(&source, &pool));
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert_eq!(pool.reserved_bytes(), 0);
    let before = context.consumed_allocated_bytes();
    drop(context.with(|| decode(&source, &pool)).unwrap());
    assert_eq!(
        context.consumed_allocated_bytes() - before,
        u64::try_from(demand).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}
