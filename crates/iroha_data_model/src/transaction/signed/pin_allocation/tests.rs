//! Exact graph ownership tests over synthetic envelopes, without native execution claims.

use super::*;
use iroha_crypto::KeyPair;
use iroha_primitives::{numeric::Quantity, time::TimeSource};
use std::time::Duration;

use super::super::wire_v1_test_support as support;

fn paid(signed: &SignedTransaction) -> SignedTransaction {
    let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
    let mut payload = signed.payload().clone();
    let mut uuid = [7; 16];
    uuid[6] = 0x47;
    uuid[8] = 0x87;
    payload.fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            crate::asset::AssetDefinitionId::from_uuid_bytes(uuid).unwrap(),
            "0.003".parse::<Quantity>().unwrap(),
        )],
        None,
    );
    super::super::TransactionBuilder::from_payload(payload)
        .unwrap()
        .sign(key.private_key())
}
fn pin(bytes: usize) -> SignedTransaction {
    let original = support::signed("advance");
    let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
    // Arbitrary manifest bytes test allocation geometry only; the ordinary native validator
    // remains responsible for semantic manifest and paid-publication admission.
    let value = super::super::TransactionBuilder::new_with_time_source(
        original.network_id().copied().unwrap(),
        original.authority().clone(),
        &TimeSource::new_fixed(Duration::from_millis(42_001)),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([RegisterPinManifest::new(vec![0x6b; bytes], None, None)])
    .sign(key.private_key());
    paid(&value)
}

#[test]
fn every_closed_profile_keeps_full_wire_and_exact_physical_charge_until_graph_drop() {
    for signed in [
        paid(&support::signed("advance")),
        paid(&support::signed("check")),
        paid(&support::signed("check-present")),
        pin(16 * 1024),
    ] {
        let original = signed.encode_wire_v1().unwrap();
        let demand = Source::new(&signed).unwrap().demand().unwrap().bytes;
        let budget = AllocationBudget::new(demand);
        let funded = AllocatedPinTransactionV1::copy_from(&signed, &budget).unwrap();
        assert!(funded.belongs_to(&budget));
        assert!(!funded.belongs_to(&AllocationBudget::new(demand)));
        assert_eq!(funded.allocation_bytes(), Some(demand));
        assert_eq!(budget.reserved_bytes(), demand);
        assert_eq!(funded.signed(), &signed);
        assert_eq!(funded.signed().encode_wire_v1().unwrap(), original);
        assert_eq!(
            funded.entrypoint().encode_wire_v1().unwrap(),
            TransactionEntrypoint::External(signed.clone())
                .encode_wire_v1()
                .unwrap()
        );
        assert_ne!(
            funded.signed().signature().0.payload().as_ptr(),
            signed.signature().0.payload().as_ptr()
        );
        drop(signed);
        assert_eq!(funded.signed().encode_wire_v1().unwrap(), original);
        assert_eq!(budget.reserved_bytes(), demand);
        drop(funded);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn pool_and_inherited_cumulative_refusals_keep_source_and_refund_partial_backings() {
    let signed = paid(&support::signed("check-present"));
    let original = signed.encode_wire_v1().unwrap();
    let demand = Source::new(&signed).unwrap().demand().unwrap().bytes;
    let short = AllocationBudget::new(demand - 1);
    assert!(matches!(
        AllocatedPinTransactionV1::copy_from(&signed, &short),
        Err(Error::Admission(_))
    ));
    assert_eq!(short.reserved_bytes(), 0);
    let budget = AllocationBudget::new(demand * 2);
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64);
    norito::core::with_decode_limits_scope(limits(0), || {
        assert!(matches!(
            AllocatedPinTransactionV1::copy_from(&signed, &budget),
            Err(Error::Codec(_))
        ));
    });
    assert_eq!(budget.reserved_bytes(), 0);
    // Permit the exact ledger and some fields, then refuse a later field. No partially copied
    // allocation or original-pool credit escapes the failed copy.
    norito::core::with_decode_limits_scope(limits(demand - 1), || {
        assert!(matches!(
            AllocatedPinTransactionV1::copy_from(&signed, &budget),
            Err(Error::Codec(_))
        ));
    });
    assert_eq!(budget.reserved_bytes(), 0);
    norito::core::with_decode_limits_scope(limits(demand), || {
        let first = AllocatedPinTransactionV1::copy_from(&signed, &budget).unwrap();
        assert!(matches!(
            AllocatedPinTransactionV1::copy_from(&signed, &budget),
            Err(Error::Codec(_))
        ));
        assert_eq!(budget.reserved_bytes(), demand);
        drop(first);
        assert_eq!(budget.reserved_bytes(), 0);
        // Physical release does not renew the original cumulative codec allowance.
        assert!(matches!(
            AllocatedPinTransactionV1::copy_from(&signed, &budget),
            Err(Error::Codec(_))
        ));
    });
    assert_eq!(signed.encode_wire_v1().unwrap(), original);
}

#[test]
fn unsupported_graphs_refuse_before_any_pool_allocation_without_reencoding_authority() {
    for signed in [
        support::signed("check-metadata"),
        support::signed("large"),
        support::signed("multisig-a"),
        pin(MAX_FRAME),
    ] {
        let budget = AllocationBudget::new(usize::MAX);
        assert!(matches!(
            AllocatedPinTransactionV1::copy_from(&signed, &budget),
            Err(Error::Profile)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let mut signed = paid(&support::signed("advance"));
    let FeePaymentIntent::Authority(fees) = &mut signed.payload.fee_payment else {
        unreachable!()
    };
    fees.gas_limit = std::num::NonZeroU64::new(3);
    let budget = AllocationBudget::new(usize::MAX);
    assert!(matches!(
        AllocatedPinTransactionV1::copy_from(&signed, &budget),
        Err(Error::Profile)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}
