//! Protected registry and original permission decoding must complete before delegation mutates.
#[path = "trigger_permission_guard_tests.rs"]
mod trigger_permission_guard_tests;
use super::*;
use crate::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    state::{State, World},
};
use iroha_data_model::{
    isi::error::InstructionExecutionError,
    parameter::{CustomParameter, Parameter},
    permission::Permission,
};
use iroha_primitives::json::Json;

fn with_permission_state(test: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &AccountId)) {
    let owner = account(201);
    let recipient = account(202);
    let state = State::new_for_testing(
        World::with(
            [],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(recipient.clone()).build(&owner),
            ],
            [],
        ),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1_000,
        0,
    ));
    let mut stx = block.transaction();
    test(&mut stx, &owner, &recipient);
}

fn transfer_permission(owner: &AccountId) -> Permission {
    iroha_executor_data_model::permission::asset::CanTransferAsset {
        asset: AssetId::new(fee_asset(), owner.clone()),
    }
    .into()
}

fn runtime_permissions() -> [Permission; 2] {
    [
        transfer_permission(&account(201)),
        iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
            contract: test_contract_address(),
            permission: "Payout".parse().unwrap(),
        }
        .into(),
    ]
}

fn malformed_registry(stx: &mut StateTransaction<'_, '_>) -> CustomParameter {
    let original =
        CustomParameter::new(ValidationFeePolicyRegistryV1::parameter_id(), Json::new(()));
    stx.world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(original.clone()));
    original
}

fn assert_registry_unchanged(stx: &StateTransaction<'_, '_>, original: &CustomParameter) {
    assert_eq!(
        stx.world.parameters().custom().get(original.id()),
        Some(original)
    );
}

fn assert_registry_rejection(error: &InstructionExecutionError) {
    assert!(
        matches!(error, InstructionExecutionError::InvariantViolation(_)),
        "malformed protected DATA is a completed instruction rejection: {error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("malformed protected policy registry")
    );
}

#[test]
fn malformed_protected_registry_rejects_account_grant_before_permission_mutation() {
    with_permission_state(|stx, owner, recipient| {
        let permission = transfer_permission(owner);
        let original = malformed_registry(stx);
        let error = Grant::account_permission(permission.clone(), recipient.clone())
            .execute(owner, stx)
            .expect_err("a malformed protected registry cannot remove the Grant guard");
        assert_registry_rejection(&error);
        assert!(
            !stx.world
                .account_contains_inherent_permission(recipient, &permission)
        );
        assert!(stx.world.take_external_events().is_empty());
        assert_eq!(stx.execution_deferral(), None);
        assert_registry_unchanged(stx, &original);
    });
}

#[test]
fn malformed_protected_registry_rejects_account_revoke_before_permission_mutation() {
    with_permission_state(|stx, owner, recipient| {
        let permission = transfer_permission(owner);
        Grant::account_permission(permission.clone(), recipient.clone())
            .execute(owner, stx)
            .unwrap();
        stx.world.take_external_events();
        let original = malformed_registry(stx);
        let error = Revoke::account_permission(permission.clone(), recipient.clone())
            .execute(owner, stx)
            .expect_err("a malformed protected registry cannot remove the Revoke guard");
        assert_registry_rejection(&error);
        assert!(
            stx.world
                .account_contains_inherent_permission(recipient, &permission)
        );
        assert!(stx.world.take_external_events().is_empty());
        assert_eq!(stx.execution_deferral(), None);
        assert_registry_unchanged(stx, &original);
    });
}

#[test]
fn malformed_protected_registry_rejects_role_registration_before_permission_mutation() {
    with_permission_state(|stx, owner, recipient| {
        let permission = transfer_permission(owner);
        let role_id: RoleId = "PROTECTED_REGISTRY_ROLE".parse().unwrap();
        let original = malformed_registry(stx);
        let role = Role::new(role_id.clone(), recipient.clone()).add_permission(permission);
        let error = Register::role(role)
            .execute(owner, stx)
            .expect_err("a malformed protected registry cannot authorize a new delegation role");
        assert_registry_rejection(&error);
        assert!(stx.world.roles.get(&role_id).is_none());
        assert!(stx.world.account_roles.iter().next().is_none());
        assert!(stx.world.take_external_events().is_empty());
        assert_registry_unchanged(stx, &original);
    });
}

#[test]
fn malformed_protected_registry_rejects_role_grant_before_permission_mutation() {
    with_permission_state(|stx, owner, recipient| {
        let permission = transfer_permission(owner);
        let role_id: RoleId = "PROTECTED_REGISTRY_ROLE".parse().unwrap();
        Register::role(Role::new(role_id.clone(), recipient.clone()))
            .execute(owner, stx)
            .unwrap();
        stx.world.take_external_events();
        let original = malformed_registry(stx);
        let error = Grant::role_permission(permission, role_id.clone())
            .execute(owner, stx)
            .expect_err("a malformed protected registry cannot authorize role delegation");
        assert_registry_rejection(&error);
        assert!(
            stx.world
                .roles
                .get(&role_id)
                .unwrap()
                .permissions()
                .next()
                .is_none()
        );
        assert!(stx.world.take_external_events().is_empty());
        assert_registry_unchanged(stx, &original);
    });
}

#[test]
fn recognized_payout_runtime_permission_malformed_payload_rejects_before_grant() {
    for canonical in runtime_permissions() {
        with_permission_state(|stx, owner, recipient| {
            let malformed = Permission::new(canonical.name.clone(), Json::new(()));
            let error = Grant::account_permission(malformed.clone(), recipient.clone())
                .execute(owner, stx)
                .expect_err(
                    "recognized malformed permission DATA cannot become an unrelated token",
                );
            assert!(matches!(
                error,
                InstructionExecutionError::InvariantViolation(_)
            ));
            assert!(error.to_string().contains("payout runtime permission"));
            assert!(
                !stx.world
                    .account_contains_inherent_permission(recipient, &malformed)
            );
            assert_eq!(stx.execution_deferral(), None);
            assert!(stx.world.take_external_events().is_empty());
        });
    }
}

#[test]
fn recognized_payout_runtime_permission_original_decode_refusal_defers_without_grant() {
    for permission in runtime_permissions() {
        let original_payload = permission.payload().clone();
        with_permission_state(|stx, owner, recipient| {
            let grant = Grant::account_permission(permission.clone(), recipient.clone());
            let error = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || grant.execute(owner, stx),
            )
            .expect_err("recognized original decoder refusal cannot authorize delegation");
            assert!(
                error
                    .to_string()
                    .contains("local execution attempt did not complete")
            );
            assert_eq!(
                stx.execution_deferral().unwrap().reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity
            );
            assert!(
                !stx.world
                    .account_contains_inherent_permission(recipient, &permission)
            );
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(permission.payload(), &original_payload);
        });
        // Retry exact original DATA in a fresh attempt after the refused overlay is dropped.
        with_permission_state(|stx, owner, recipient| {
            Grant::account_permission(permission.clone(), recipient.clone())
                .execute(owner, stx)
                .expect("the same valid permission retries when original local capacity returns");
            assert!(
                stx.world
                    .account_contains_inherent_permission(recipient, &permission)
            );
            assert_eq!(permission.payload(), &original_payload);
            assert_eq!(stx.execution_deferral(), None);
        });
    }
}

#[test]
fn unrelated_permission_name_remains_unrestricted_without_original_payload_decode() {
    with_permission_state(|stx, owner, recipient| {
        let permission: Permission =
            iroha_executor_data_model::permission::governance::CanManageRuntimeUpgrades.into();
        let original = malformed_registry(stx);
        let grant = Grant::account_permission(permission.clone(), recipient.clone());
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || grant.execute(owner, stx),
        )
        .expect(
            "unrelated permission names do not decode the protected runtime payload or registry",
        );
        assert!(
            stx.world
                .account_contains_inherent_permission(recipient, &permission)
        );
        assert_eq!(stx.execution_deferral(), None);
        assert_registry_unchanged(stx, &original);
    });
}

#[test]
fn absent_registry_and_valid_unprotected_runtime_permissions_keep_original_grant_contract() {
    for permission in runtime_permissions() {
        with_permission_state(|stx, owner, recipient| {
            assert!(
                stx.world
                    .parameters()
                    .custom()
                    .get(&ValidationFeePolicyRegistryV1::parameter_id())
                    .is_none()
            );
            Grant::account_permission(permission.clone(), recipient.clone())
                .execute(owner, stx)
                .unwrap();
            assert!(
                stx.world
                    .account_contains_inherent_permission(recipient, &permission)
            );
            Revoke::account_permission(permission.clone(), recipient.clone())
                .execute(owner, stx)
                .unwrap();
            assert!(
                !stx.world
                    .account_contains_inherent_permission(recipient, &permission)
            );
            assert_eq!(stx.execution_deferral(), None);
        });
    }
}
