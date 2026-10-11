//! Retained account output borrows canonical keys without spending inbound decoder capacity.

use super::*;
use iroha_crypto::KeyPair;

fn key(seed: u8) -> PublicKey {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
        .expect("checked deterministic key")
        .into_parts()
        .0
}

fn multisig() -> AccountId {
    AccountId::new_multisig(
        MultisigPolicy::new(
            3,
            vec![
                MultisigMember::new(key(21), 2).expect("first retained member"),
                MultisigMember::new(key(22), 1).expect("second retained member"),
            ],
        )
        .expect("canonical retained policy"),
    )
}

fn zero_budget() -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX)
}

fn assert_retained_output(account: &AccountId) {
    let expected = account
        .canonical_i105()
        .expect("canonical output before scope");
    let expected_hex = account
        .to_canonical_hex()
        .expect("canonical hex before scope");
    let (actual, usage) = norito::core::with_decode_limits_measured(zero_budget(), || {
        assert_eq!(
            account.to_canonical_hex().expect("retained canonical hex"),
            expected_hex
        );
        let actual = account.to_string();
        assert_eq!(
            account.canonical_i105().expect("retained canonical output"),
            actual
        );
        assert_eq!(
            account
                .to_i105_for_discriminant(chain_discriminant())
                .expect("retained explicit discriminant"),
            actual
        );
        actual
    });
    assert_eq!(actual, expected);
    assert_eq!(usage.total_allocated_bytes(), 0);
}

fn assert_owned_parity_and_roundtrip(account: &AccountId) {
    let reference = AccountAddress::from_account_id(account).expect("original owned address");
    let canonical = reference
        .canonical_bytes()
        .expect("original canonical bytes");
    for discriminant in [CHAIN_DISCRIMINANT_SORA, CHAIN_DISCRIMINANT_TEST, 42] {
        let literal = account
            .to_i105_for_discriminant(discriminant)
            .expect("retained account output");
        assert_eq!(
            literal,
            reference
                .to_i105_for_discriminant(discriminant)
                .expect("original owned output")
        );
        let decoded = AccountAddress::from_i105_for_discriminant(&literal, Some(discriminant))
            .expect("original canonical decoder");
        assert_eq!(
            decoded.canonical_bytes().expect("decoded canonical bytes"),
            canonical
        );
        assert_eq!(
            decoded.to_account_id().expect("decoded controller"),
            *account
        );
    }
}

#[test]
fn retained_single_account_formatting_survives_zero_decode_allocation() {
    assert_retained_output(&AccountId::new(key(20)));
}

#[test]
fn retained_multisig_account_formatting_survives_zero_decode_allocation() {
    assert_retained_output(&multisig());
}

#[test]
fn retained_single_output_preserves_owned_bytes_and_roundtrip() {
    assert_owned_parity_and_roundtrip(&AccountId::new(key(20)));
}

#[test]
fn retained_multisig_output_preserves_owned_bytes_and_roundtrip() {
    assert_owned_parity_and_roundtrip(&multisig());
}

#[test]
fn inbound_controller_decode_and_admission_clone_still_require_capacity() {
    let public_key = key(20);
    let account = AccountId::new(public_key.clone());
    let canonical = AccountAddress::from_account_id(&account)
        .expect("owned original address")
        .canonical_bytes()
        .expect("canonical input");
    norito::with_decode_limits_scope(zero_budget(), || {
        assert!(matches!(
            AccountAddress::from_canonical_bytes(&canonical),
            Err(AccountAddressError::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. }
            ))
        ));
        assert!(public_key.try_clone_for_admission().is_err());
    });
    assert_eq!(
        AccountAddress::from_canonical_bytes(&canonical)
            .expect("original decoder retries with capacity")
            .to_account_id()
            .expect("original controller"),
        account
    );
}
