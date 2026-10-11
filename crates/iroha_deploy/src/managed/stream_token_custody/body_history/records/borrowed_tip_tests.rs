//! Genuine generated World carriers preserve read-only authentication, scope and inclusion gates.

use super::*;
use crate::{
    managed::{
        LocalnetPorts,
        native_operation::{
            test_support::native_fixture::{NativeFixture, quote_instructions},
            verify_carrier,
        },
    },
    verify::finality::FinalityError,
};
use iroha_data_model::isi::{InstructionBox, Log};

#[test]
fn borrowed_original_gates_keep_cold_refusal_retry_scope_and_exact_executed_inclusion() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "borrowed-original-gates",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut owner = ManagedStreamTokenCustody::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let signed = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "original executed borrowed carrier".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    // Independent fresh native observations leave distinct, not-yet-imported tip owners.
    let scope = native.observe(&owner.authority);
    let carrier = native.observe(&owner.authority);
    let original_scope = checkpoint_bytes(&scope).unwrap();
    let original_carrier = checkpoint_bytes(&carrier).unwrap();
    let original_signed = signed.encode_wire_v1().unwrap();
    let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    for _ in 0..2 {
        let error = norito::with_decode_limits_scope(no_allocation, || {
            UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope)
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsigned enrollment checkpoint invalid")
        );
        let error =
            norito::with_decode_limits_scope(no_allocation, || verify_carrier(&carrier, &signed))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid original native operation carrier")
        );
        for verifier in [&scope, &carrier] {
            assert!(matches!(
                norito::with_decode_limits_scope(no_allocation, || verifier.verified_tip_ref()),
                Err(FinalityError::DecodeResource(_))
            ));
        }
    }
    // Retry goes through the identical canonical native authentication and real paid carrier.
    UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope).unwrap();
    let executed = verify_carrier(&carrier, &signed).unwrap();
    assert_eq!(executed.transaction_hash, signed.hash());
    assert_eq!(executed.height, 2);
    assert_eq!(
        executed.block_hash,
        carrier.checkpoint().tip().block_header.hash()
    );
    let original_tip = carrier.verified_tip_ref().unwrap();
    assert!(!std::ptr::eq(
        original_tip,
        scope.verified_tip_ref().unwrap()
    ));
    norito::with_decode_limits_scope(no_allocation, || {
        UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope).unwrap();
        // A warm tip does not admit the original transaction's canonical wire allocation.
        let wire_error = signed.encode_wire_v1().unwrap_err();
        assert!(norito::core::decode_error_matches_active_limits(
            &wire_error
        ));
        assert!(matches!(
            wire_error.decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted,
                limit: 0,
            }) if attempted > 0
        ));
        let error = verify_carrier(&carrier, &signed).unwrap_err();
        assert!(matches!(
            error,
            crate::managed::Error::Invalid(message)
                if message == "invalid original native operation wire"
        ));
        assert!(std::ptr::eq(
            original_tip,
            carrier.verified_tip_ref().unwrap()
        ));
    });
    // The same original paid transaction and retained carrier retry outside the refused scope.
    assert_eq!(verify_carrier(&carrier, &signed).unwrap(), executed);

    // The cached immutable historical tip cannot replace the caller's explicit Global scope.
    let network = owner.authority.config.network_id;
    owner.authority.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign Global scope"),
        ));
    assert!(
        UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope)
            .unwrap_err()
            .to_string()
            .contains("unsigned enrollment checkpoint changed Global scope")
    );
    owner.authority.config.network_id = network;
    let chain = owner.authority.config.chain.clone();
    owner.authority.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    assert_ne!(owner.authority.config.chain, chain);
    assert!(
        UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope)
            .unwrap_err()
            .to_string()
            .contains("unsigned enrollment checkpoint changed Global scope")
    );
    owner.authority.config.chain = chain;
    UnsignedEnrollment::validate_checkpoint_scope(&owner, &scope).unwrap();

    // A valid separately signed, quoted original absent from that exact block still refuses.
    let absent = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "different original never committed".into(),
        ))],
    );
    absent.verify_signature().unwrap();
    assert_ne!(absent.hash(), signed.hash());
    assert!(
        verify_carrier(&carrier, &absent)
            .unwrap_err()
            .to_string()
            .contains("transaction absent from certified carrier")
    );
    assert_eq!(checkpoint_bytes(&scope).unwrap(), original_scope);
    assert_eq!(checkpoint_bytes(&carrier).unwrap(), original_carrier);
    assert_eq!(signed.encode_wire_v1().unwrap(), original_signed);
    assert_eq!(native.chain.height(), 2);
    assert!(std::ptr::eq(
        original_tip,
        carrier.verified_tip_ref().unwrap()
    ));
    owner.authority.validate_profile().unwrap();
    drop(ports);
}
