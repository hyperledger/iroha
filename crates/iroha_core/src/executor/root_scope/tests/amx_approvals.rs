//! Exact direct debit consent has a private-root owner before ordinary authorization.

use super::*;
use iroha_data_model::{
    asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    isi::{Grant, Revoke},
    permission::Permission,
    sumeragi_amx::AmxDebitApprovalV1,
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::json::Json;

fn approval(tx: &mut StateTransaction<'_, '_>) -> AmxDebitApprovalV1 {
    let scope = execution_root_scope(tx).unwrap();
    let SumeragiRootScope::Dataspace {
        parent_network_id,
        dataspace_id,
    } = scope
    else {
        panic!("private fixture");
    };
    let instance = scope
        .instance_id(
            &crate::sumeragi::crypto::BlsCrypto::new(),
            *tx.network_id(),
            tx.chain_id().as_str(),
        )
        .unwrap();
    AmxDebitApprovalV1 {
        global_network: parent_network_id,
        participant_network: *tx.network_id(),
        participant_instance: instance.0,
        dataspace: dataspace_id,
        transaction_id: [8; 32],
        debited_asset: AssetId::with_scope(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("bank", "universal").unwrap(),
                "cash".parse().unwrap(),
            ),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(dataspace_id),
        ),
    }
}

fn direct_instructions(permission: Permission) -> [InstructionBox; 2] {
    [
        Grant::account_permission(permission.clone(), ALICE_ID.clone()).into(),
        Revoke::account_permission(permission, ALICE_ID.clone()).into(),
    ]
}

#[test]
fn direct_amx_consent_wrappers_require_exact_immutable_private_root() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let exact = approval(&mut tx);
    for instruction in direct_instructions(exact.permission().unwrap()) {
        assert!(
            ensure_instruction_scope(&instruction, &mut tx).is_ok(),
            "exact direct consent must reach debit-owner authorization on its bank root"
        );
    }
    for field in 0..5 {
        let mut foreign = exact.clone();
        match field {
            0 => {
                foreign.global_network = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"another parent")),
                )
            }
            1 => {
                foreign.participant_network = NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::new(b"another bank")),
                )
            }
            2 => foreign.participant_instance[0] ^= 1,
            3 => {
                foreign.dataspace = DataSpaceId::new(17);
                foreign.debited_asset = AssetId::with_scope(
                    exact.debited_asset.definition().clone(),
                    ALICE_ID.clone(),
                    AssetBalanceScope::Dataspace(foreign.dataspace),
                );
            }
            4 => foreign.transaction_id = [0; 32],
            _ => unreachable!(),
        }
        // A malformed fingerprint cannot even be projected by the normal builder;
        // construct that negative wire value through the typed executor wrapper.
        let permission: Permission =
            iroha_executor_data_model::permission::amx::CanPrepareAmx { approval: foreign }.into();
        for instruction in direct_instructions(permission) {
            assert!(ensure_instruction_scope(&instruction, &mut tx).is_err());
            assert!(tx.execution_deferral().is_none());
        }
    }
}

#[test]
fn amx_consent_scope_does_not_whitelist_roles_unrelated_or_inexact_permissions() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let permission = approval(&mut tx).permission().unwrap();
    let role = "amx-relay-role".parse().unwrap();
    let roles: [InstructionBox; 2] = [
        Grant::role_permission(permission.clone(), role).into(),
        Revoke::role_permission(permission.clone(), "amx-relay-role".parse().unwrap()).into(),
    ];
    for instruction in roles {
        assert!(ensure_instruction_scope(&instruction, &mut tx).is_err());
    }
    let mut value: norito::json::Value = permission.payload().try_into_any().unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), norito::json::Value::Bool(true));
    for permission in [
        Permission::new("CanPrepareAmx".into(), Json::try_new(value).unwrap()),
        Permission::new("UnreviewedPermission".into(), permission.payload().clone()),
        Permission::new("CanPrepareAmx".into(), "null".parse::<Json>().unwrap()),
    ] {
        for instruction in direct_instructions(permission) {
            assert!(ensure_instruction_scope(&instruction, &mut tx).is_err());
            assert!(tx.execution_deferral().is_none());
        }
    }
}

#[test]
fn amx_consent_scope_decode_refusal_retains_retryable_execution() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let exact = approval(&mut tx);
    let scope = execution_root_scope(&mut tx).unwrap();
    let [instruction, _] = direct_instructions(exact.permission().unwrap());
    let result = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || is_exact_local_amx_approval(&instruction, &mut tx, scope),
    );
    assert!(result.is_err());
    assert!(
        tx.execution_deferral().is_some(),
        "a local approval decode refusal must not commit a scope rejection"
    );
}
