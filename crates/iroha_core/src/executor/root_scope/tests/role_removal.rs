//! Role deletion has root-local scope without granting role or permission authority.

use super::*;
use iroha_data_model::{
    isi::{Grant, Register, Revoke, Unregister, UnregisterBox},
    role::Role,
};

#[test]
fn private_role_removal_scope_accepts_only_canonical_boxed_deletion() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let role = "bank_service_read".parse().unwrap();
    let removal = Unregister::role(role);
    let registry = iroha_data_model::isi::InstructionRegistry::new()
        .register_with_id::<Unregister<Role>>("iroha.test.role_removal.v1");
    let (payload, flags) = norito::codec::encode_with_header_flags(&removal);
    let frame =
        norito::core::frame_bare_with_header_flags::<Unregister<Role>>(&payload, flags).unwrap();
    let concrete = registry
        .decode("iroha.test.role_removal.v1", &frame)
        .unwrap()
        .unwrap();
    assert!(concrete.as_any().is::<Unregister<Role>>());
    let boxed: InstructionBox = UnregisterBox::Role(removal).into();
    // The default instruction registry excludes direct grouped variants. A custom
    // registry cannot give that retired representation a reviewed scope owner.
    let error = ensure_instruction_scope(&concrete, &mut tx).unwrap_err();
    assert!(
        matches!(error, ValidationFail::NotPermitted(ref cause)
        if cause == "instruction has no reviewed private-root scope owner"),
        "{error}"
    );
    assert!(
        ensure_instruction_scope(&boxed, &mut tx).is_ok(),
        "canonical role deletion must reach ordinary current management authorization"
    );
    let error = Executor::Initial
        .execute_borrowed_overlay_instruction(&mut tx, &ALICE_ID, &boxed, None)
        .unwrap_err();
    assert!(
        matches!(error, ValidationFail::NotPermitted(ref cause)
        if cause == "Can't unregister role"),
        "{error}"
    );
    let broad = iroha_executor_data_model::permission::query::CanReadAllLedgerData;
    let role = "bank_service_read".parse().unwrap();
    let denied: [InstructionBox; 6] = [
        Register::role(Role::new(role, ALICE_ID.clone()).add_permission(broad)).into(),
        Grant::account_role("bank_service_read".parse().unwrap(), ALICE_ID.clone()).into(),
        Revoke::account_role("bank_service_read".parse().unwrap(), ALICE_ID.clone()).into(),
        Grant::account_permission(broad, ALICE_ID.clone()).into(),
        Revoke::account_permission(broad, ALICE_ID.clone()).into(),
        Unregister::account(ALICE_ID.clone()).into(),
    ];
    for instruction in denied {
        assert!(ensure_instruction_scope(&instruction, &mut tx).is_err());
        assert!(!tx.is_execution_deferred());
    }
    tx.current_dataspace_id = Some(DataSpaceId::new(ds.as_u64() + 1));
    assert!(ensure_instruction_scope(&boxed, &mut tx).is_err());
}
