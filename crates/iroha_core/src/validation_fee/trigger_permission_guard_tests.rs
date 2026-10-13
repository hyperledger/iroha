//! Recognized trigger permission decoding owns rejection or refusal before delegation mutates.
use super::*;
use iroha_data_model::trigger::TriggerId;

#[derive(Clone, Copy)]
enum TriggerDelegation {
    AccountGrant,
    RoleRegister,
    RoleGrant,
}

fn trigger_permissions(trigger: &TriggerId) -> [Permission; 4] {
    use iroha_executor_data_model::permission::trigger::{
        CanExecuteTrigger, CanModifyTrigger, CanModifyTriggerMetadata, CanUnregisterTrigger,
    };
    [
        CanUnregisterTrigger {
            trigger: trigger.clone(),
        }
        .into(),
        CanModifyTrigger {
            trigger: trigger.clone(),
        }
        .into(),
        CanExecuteTrigger {
            trigger: trigger.clone(),
        }
        .into(),
        CanModifyTriggerMetadata {
            trigger: trigger.clone(),
        }
        .into(),
    ]
}

// Exercise the actual native handlers as a component; generic genesis dispatch owns a
// separately authenticated source and is not authorized by this isolated overlay.
enum PreparedTriggerDelegation {
    AccountGrant(Grant<Permission, Account>),
    RoleRegister(Register<Role>),
    RoleGrant(Grant<Permission, Role>),
}

impl PreparedTriggerDelegation {
    fn execute(
        self,
        owner: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError> {
        match self {
            Self::AccountGrant(instruction) => instruction.execute(owner, stx),
            Self::RoleRegister(instruction) => instruction.execute(owner, stx),
            Self::RoleGrant(instruction) => instruction.execute(owner, stx),
        }
    }
}

fn trigger_delegation_instruction(
    kind: TriggerDelegation,
    stx: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    recipient: &AccountId,
    permission: Permission,
) -> PreparedTriggerDelegation {
    let role_id: RoleId = "TRIGGER_PERMISSION_GUARD_ROLE".parse().unwrap();
    match kind {
        TriggerDelegation::AccountGrant => PreparedTriggerDelegation::AccountGrant(
            Grant::account_permission(permission, recipient.clone()),
        ),
        TriggerDelegation::RoleRegister => PreparedTriggerDelegation::RoleRegister(Register::role(
            Role::new(role_id, recipient.clone()).add_permission(permission),
        )),
        TriggerDelegation::RoleGrant => {
            if stx.world.roles.get(&role_id).is_none() {
                Register::role(Role::new(role_id.clone(), recipient.clone()))
                    .execute(owner, stx)
                    .unwrap();
            }
            PreparedTriggerDelegation::RoleGrant(Grant::role_permission(permission, role_id))
        }
    }
}

fn trigger_delegation_bytes(stx: &StateTransaction<'_, '_>) -> Vec<u8> {
    norito::to_bytes(&(
        stx.world
            .account_permissions
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        stx.world
            .roles
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        stx.world
            .account_roles
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect::<Vec<_>>(),
    ))
    .unwrap()
}

fn assert_trigger_delegation_decode_boundary(kind: TriggerDelegation, refuse: bool) {
    let trigger: TriggerId = "external_trigger_guard_target".parse().unwrap();
    for valid in trigger_permissions(&trigger) {
        let permission = if refuse {
            valid
        } else {
            Permission::new(valid.name.clone(), Json::new(()))
        };
        let original_payload = permission.payload().clone();
        with_permission_state(|stx, owner, recipient| {
            let instruction =
                trigger_delegation_instruction(kind, stx, owner, recipient, permission.clone());
            let before = trigger_delegation_bytes(stx);
            stx.world.take_external_events();
            let attempt = || instruction.execute(owner, stx);
            let error = if refuse {
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                    attempt,
                )
            } else {
                attempt()
            }
            .expect_err("recognized trigger decoder failure cannot authorize delegation");
            if refuse {
                assert!(
                    error
                        .to_string()
                        .contains("local execution attempt did not complete")
                );
                assert_eq!(
                    stx.borrow_execution_deferral().unwrap().reason(),
                    ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                );
            } else {
                assert!(
                    matches!(&error, InstructionExecutionError::InvariantViolation(message) if message.contains(permission.name.as_str()))
                );
                assert!(!stx.is_execution_deferred());
            }
            assert_eq!(trigger_delegation_bytes(stx), before);
            assert!(stx.world.take_external_events().is_empty());
            assert_eq!(permission.payload(), &original_payload);
        });
        if refuse {
            with_permission_state(|stx, owner, recipient| {
                let instruction =
                    trigger_delegation_instruction(kind, stx, owner, recipient, permission.clone());
                instruction.execute(owner, stx).expect("exact original valid trigger permission retries after original capacity returns");
                assert!(!stx.is_execution_deferred());
                assert_eq!(permission.payload(), &original_payload);
            });
        }
    }
}

#[test]
fn malformed_trigger_permission_rejects_account_grant_before_mutation() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::AccountGrant, false);
}
#[test]
fn malformed_trigger_permission_rejects_role_registration_before_mutation() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::RoleRegister, false);
}
#[test]
fn malformed_trigger_permission_rejects_role_grant_before_mutation() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::RoleGrant, false);
}
#[test]
fn original_trigger_permission_decode_refusal_defers_account_grant() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::AccountGrant, true);
}
#[test]
fn original_trigger_permission_decode_refusal_defers_role_registration() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::RoleRegister, true);
}
#[test]
fn original_trigger_permission_decode_refusal_defers_role_grant() {
    assert_trigger_delegation_decode_boundary(TriggerDelegation::RoleGrant, true);
}
#[test]
fn valid_external_trigger_permission_delegation_remains_allowed() {
    let trigger: TriggerId = "external_trigger_guard_target".parse().unwrap();
    for permission in trigger_permissions(&trigger) {
        for kind in [
            TriggerDelegation::AccountGrant,
            TriggerDelegation::RoleRegister,
            TriggerDelegation::RoleGrant,
        ] {
            with_permission_state(|stx, owner, recipient| {
                let instruction =
                    trigger_delegation_instruction(kind, stx, owner, recipient, permission.clone());
                instruction.execute(owner, stx).expect(
                    "valid external trigger permissions retain original delegation behavior",
                );
                assert!(!stx.is_execution_deferred());
            });
        }
    }
}
#[test]
fn unrelated_permission_name_never_decodes_trigger_payload() {
    let permission = Permission::new("ExternalTriggerCapability".to_owned(), Json::new(()));
    for kind in [
        TriggerDelegation::AccountGrant,
        TriggerDelegation::RoleRegister,
        TriggerDelegation::RoleGrant,
    ] {
        with_permission_state(|stx, owner, recipient| {
            let instruction =
                trigger_delegation_instruction(kind, stx, owner, recipient, permission.clone());
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || instruction.execute(owner, stx),
            )
            .expect("unrelated names do not decode a trigger permission payload");
            assert!(!stx.is_execution_deferred());
        });
    }
}

#[test]
fn enacted_payout_trigger_still_rejects_exact_control_delegation() {
    with_validation_fee_payout_state_at_height(21, |stx, deployer, code, code_hash| {
        let trigger: TriggerId = "typed_guard_enacted_payout".parse().unwrap();
        let binding = activate_bound_payout_runtime(
            stx,
            deployer,
            code,
            code_hash,
            94,
            fee_asset(),
            "typed_guard_enacted_payout",
        )
        .binding;
        install_policy_registry_fixture(&policy_registry(&[], &[binding]), stx);
        let recipient = account(2);
        for permission in trigger_permissions(&trigger) {
            for kind in [
                TriggerDelegation::AccountGrant,
                TriggerDelegation::RoleRegister,
                TriggerDelegation::RoleGrant,
            ] {
                let instruction = trigger_delegation_instruction(
                    kind,
                    stx,
                    deployer,
                    &recipient,
                    permission.clone(),
                );
                let before = trigger_delegation_bytes(stx);
                stx.world.take_external_events();
                let error = instruction
                    .execute(deployer, stx)
                    .expect_err("enacted trigger authority cannot be delegated");
                assert!(
                    matches!(&error, InstructionExecutionError::InvariantViolation(message) if message.contains("forbids") && message.contains("trigger"))
                );
                assert_eq!(trigger_delegation_bytes(stx), before);
                assert!(!stx.is_execution_deferred());
                assert!(stx.world.take_external_events().is_empty());
            }
        }
    });
}
