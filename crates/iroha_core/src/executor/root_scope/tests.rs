//! Actual owned, borrowed and nested private instruction boundaries.

mod amx_roles;

use super::*;
use crate::{
    executor::Executor,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    state::{State, World},
    sumeragi::lanes::routing::test_support,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId, Registrable,
    account::Account,
    block::BlockHeader,
    isi::{CustomInstruction, RegisterPeerWithPop, SetParameter},
    nexus::{DataSpaceCatalog, DataSpaceMetadata},
    smart_contract::ContractAddress,
    transaction::{Executable, IvmBytecode, IvmProved},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_test_samples::ALICE_ID;

fn private_state() -> (State, DataSpaceId) {
    let ds = DataSpaceId::new((1_u64 << 40) + 17);
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"parent",
        ))),
        dataspace_id: ds,
    };
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let mut parameters = world.parameters.block();
    parameters.set_parameter(test_support::metadata(scope));
    parameters.commit();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: ds,
            alias: "private-scope-test".into(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .unwrap();
    (
        State::new_with_nexus_for_testing(world, nexus, LiveQueryStore::start_test()),
        ds,
    )
}

fn bind_scope(tx: &mut StateTransaction<'_, '_>, ds: DataSpaceId) {
    tx.current_dataspace_id = Some(ds);
    tx.world.current_dataspace_id = Some(ds);
}

fn header(height: u64) -> BlockHeader {
    BlockHeader::new(height.try_into().unwrap(), None, None, 1_000, 0)
}

#[test]
fn owned_borrowed_and_native_boxed_paths_reject_private_global_control_before_effects() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let control: InstructionBox =
        SetParameter::new(test_support::metadata(SumeragiRootScope::Global)).into();
    assert!(
        Executor::Initial
            .execute_instruction(&mut tx, &ALICE_ID, control.clone())
            .is_err()
    );
    assert!(
        Executor::Initial
            .execute_borrowed_overlay_instruction(&mut tx, &ALICE_ID, &control, None)
            .is_err()
    );
    assert!(control.execute(&ALICE_ID, &mut tx).is_err());
    assert!(
        matches!(execution_root_scope(&mut tx).unwrap(), SumeragiRootScope::Dataspace { dataspace_id, .. } if dataspace_id == ds)
    );
    let log: InstructionBox = Log::new(iroha_data_model::Level::INFO, "root-local".into()).into();
    Executor::Initial
        .execute_instruction(&mut tx, &ALICE_ID, log.clone())
        .unwrap();
    Executor::Initial
        .execute_borrowed_overlay_instruction(&mut tx, &ALICE_ID, &log, None)
        .unwrap();
    log.execute(&ALICE_ID, &mut tx).unwrap();
}

#[test]
fn parameter_control_cannot_hide_in_deferred_multisig_or_an_unknown_local_target() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    let propose = iroha_executor_data_model::isi::multisig::MultisigPropose {
        account: ALICE_ID.clone(),
        instructions: vec![
            SetParameter::new(test_support::metadata(SumeragiRootScope::Global)).into(),
        ],
        transaction_ttl_ms: None,
    };
    let instruction = InstructionBox::from(MultisigInstructionBox::Propose(propose));
    assert!(ensure_instruction_scope(&instruction, &mut tx).is_err());
    let no_scope: InstructionBox =
        CustomInstruction::new("unreviewed private-root operation").into();
    let peer_key =
        iroha_crypto::KeyPair::from_seed(vec![71; 32], iroha_crypto::Algorithm::BlsNormal);
    let register_peer: InstructionBox = RegisterPeerWithPop::new(
        iroha_model_base::peer::PeerId::new(peer_key.public_key().clone()),
        iroha_crypto::bls_normal_pop_prove(peer_key.private_key()).expect("fixture PoP"),
    )
    .into();
    let register_account: InstructionBox =
        iroha_data_model::isi::Register::account(Account::new(ALICE_ID.clone())).into();
    for unreviewed in [no_scope, register_peer, register_account] {
        assert!(
            matches!(ensure_instruction_scope(&unreviewed, &mut tx), Err(ValidationFail::NotPermitted(reason)) if reason.contains("reviewed private-root scope owner"))
        );
    }
}

#[test]
fn private_contract_calls_require_exact_scope_and_raw_overlays_remain_closed() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    for (target, allowed) in [
        (ds, true),
        (DataSpaceId::new(17), false),
        (DataSpaceId::UNIVERSAL, false),
    ] {
        let address = ContractAddress::derive(&tx.network_id, &ALICE_ID, 0, target).unwrap();
        assert_eq!(ensure_contract_scope(&mut tx, &address).is_ok(), allowed);
        assert_eq!(
            ensure_committed_contract_scope(&tx.world, &address).is_ok(),
            allowed
        );
    }
    let bytecode = IvmBytecode::from_compiled(vec![1]);
    assert!(ensure_executable_scope(&mut tx, &Executable::Ivm(bytecode.clone())).is_err());
    assert!(
        ensure_executable_scope(
            &mut tx,
            &Executable::IvmProved(IvmProved {
                bytecode,
                overlay: Vec::new().into(),
                events_commitment: Hash::new(b"events"),
                gas_policy_commitment: Hash::new(b"gas"),
            })
        )
        .is_err()
    );
    tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let address = ContractAddress::derive(&tx.network_id, &ALICE_ID, 0, ds).unwrap();
    assert!(ensure_contract_scope(&mut tx, &address).is_err());
}

#[test]
fn height_one_without_authenticated_genesis_capability_has_no_instruction_authority() {
    for world in [World::new(), test_support::world(SumeragiRootScope::Global)] {
        let state = State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(header(1));
        let mut tx = block.transaction();
        let log: InstructionBox =
            Log::new(iroha_data_model::Level::INFO, "forged bootstrap".into()).into();
        assert!(execution_root_scope(&mut tx).is_err());
        assert!(
            Executor::Initial
                .execute_instruction(&mut tx, &ALICE_ID, log.clone())
                .is_err()
        );
        assert!(log.execute(&ALICE_ID, &mut tx).is_err());
    }
}

#[test]
fn artifact_lookup_requires_both_captured_namespaces_and_preserves_full_width() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let hash = Hash::new(b"artifact");
    assert!(captured_artifact_id(&mut tx, hash).is_err());
    bind_scope(&mut tx, ds);
    let artifact = captured_artifact_id(&mut tx, hash).unwrap();
    assert_eq!(artifact.dataspace_id, ds);
    assert_eq!(artifact.code_hash, hash);
    tx.world.current_dataspace_id = Some(DataSpaceId::new(17));
    assert!(captured_artifact_id(&mut tx, hash).is_err());
    bind_scope(&mut tx, DataSpaceId::new(17));
    assert!(captured_artifact_id(&mut tx, hash).is_err());
}

#[test]
fn durable_authorization_rejects_foreign_contract_before_registry_or_permission_lookup() {
    let (state, _) = private_state();
    let mut block = state.block(header(2));
    let tx = block.transaction();
    let foreign =
        ContractAddress::derive(&tx.network_id, &ALICE_ID, 0, DataSpaceId::UNIVERSAL).unwrap();
    let authorization = crate::executor::ContractEntrypointAuthorizationSnapshot {
        authority: ALICE_ID.clone(),
        entrypoint: "write".into(),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
        contract_address: foreign,
        contract_alias: None,
        contract_alias_binding: None,
        code_hash: Hash::new(b"foreign-artifact"),
        lifecycle_revision: 1,
        parent: None,
    };
    let error = authorization.validate(&tx.world).unwrap_err();
    assert!(error.to_string().contains("foreign contract dataspace"));
}

#[test]
fn artifact_registry_reads_require_immutable_scope_and_exact_private_owner() {
    use iroha_data_model::smart_contract::ContractArtifactId;
    let (state, own) = private_state();
    let view = state.view();
    let hash = Hash::new(b"shared artifact bytes");
    let local = ContractArtifactId::new(own, hash);
    assert!(ensure_committed_artifact_scope(view.world(), &local).is_ok());
    for ds in [DataSpaceId::UNIVERSAL, DataSpaceId::new(17)] {
        assert!(
            ensure_committed_artifact_scope(view.world(), &ContractArtifactId::new(ds, hash))
                .is_err()
        );
    }
    assert!(ensure_committed_artifact_scope(&World::new().view(), &local).is_err());
    let global = test_support::world(SumeragiRootScope::Global);
    assert!(ensure_committed_artifact_scope(&global.view(), &local).is_ok());
}

#[test]
fn private_roots_cannot_register_or_anchor_children_in_the_parent_registry() {
    use iroha_data_model::isi::private_dataspace::{
        AnchorPrivateDataspace, RegisterPrivateDataspace,
    };
    let (state, own) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, own);
    let operations: Vec<InstructionBox> = vec![
        RegisterPrivateDataspace {
            alias: "child".into(),
            expected_ownership_generation: 0,
            registration: vec![],
        }
        .into(),
        AnchorPrivateDataspace {
            dataspace_id: own,
            anchor: vec![],
        }
        .into(),
    ];
    for instruction in operations {
        let target = crate::queue::native_instruction_execution_target(
            &*instruction,
            &tx.nexus.dataspace_catalog,
            &tx.world,
            0,
        )
        .unwrap();
        assert_eq!(target.dataspace, Some(DataSpaceId::UNIVERSAL));
        assert!(target.global);
        let error = Executor::Initial
            .execute_instruction(&mut tx, &ALICE_ID, instruction)
            .unwrap_err();
        assert!(error.to_string().contains("global-control"));
    }
}

#[test]
fn malformed_root_metadata_is_terminal_and_cannot_acquire_retry_authority() {
    use iroha_data_model::parameter::{
        Parameter, custom::CustomParameter, system::consensus_metadata::handshake_meta_id,
    };
    for payload in ["null", "{}", "false", "\"global\""] {
        let (state, ds) = private_state();
        let mut block = state.block(header(2));
        let mut tx = block.transaction();
        bind_scope(&mut tx, ds);
        tx.world
            .parameters
            .set_parameter(Parameter::Custom(CustomParameter::new(
                handshake_meta_id(),
                payload.parse::<iroha_primitives::json::Json>().unwrap(),
            )));
        assert!(matches!(
            execution_root_scope(&mut tx),
            Err(ValidationFail::NotPermitted(reason))
                if reason == "instruction execution requires immutable root scope"
        ));
        assert!(tx.require_storage_admission().is_ok());
        assert!(tx.execution_deferral().is_none());
    }
}

#[test]
fn readonly_manifest_query_preserves_malformed_and_foreign_rejections() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::smartcontracts::ValidSingularQuery as _;
    use iroha_data_model::{
        parameter::{
            Parameter, custom::CustomParameter, system::consensus_metadata::handshake_meta_id,
        },
        query::{error::QueryExecutionFail, smart_contract::FindContractManifestByArtifactId},
        smart_contract::ContractArtifactId,
    };
    let (state, own) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, own);
    let hash = Hash::new(b"scope query negative control");
    let local = FindContractManifestByArtifactId::new(ContractArtifactId::new(own, hash));
    let foreign = FindContractManifestByArtifactId::new(ContractArtifactId::new(
        DataSpaceId::UNIVERSAL,
        hash,
    ));
    assert!(matches!(
        foreign.execute(&tx),
        Err(ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message)))
            if message.contains("private root cannot access a foreign artifact dataspace")
    ));
    for payload in ["null", "{}", "false", "\"global\""] {
        tx.world
            .parameters
            .set_parameter(Parameter::Custom(CustomParameter::new(
                handshake_meta_id(),
                payload.parse::<iroha_primitives::json::Json>().unwrap(),
            )));
        assert!(matches!(
            local.execute(&tx),
            Err(ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message)))
                if message.contains("artifact access requires immutable root scope")
        ));
        assert!(tx.require_storage_admission().is_ok());
        assert!(tx.execution_deferral().is_none());
    }
}

#[test]
fn native_global_read_permission_borrows_exact_direct_and_role_grants_under_refusal() {
    use iroha_data_model::{
        permission::Permission,
        role::{Role, RoleId},
    };
    use std::collections::{BTreeMap, BTreeSet};
    let (state, _) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    let role_id: RoleId = "borrowed_global_reader".parse().unwrap();
    for through_role in [false, true] {
        for payload in ["null", "\"null\"", "false", "{}", "{\"null\":null}"] {
            let permission = Permission::new(
                "CanReadAllLedgerData".to_owned(),
                payload.parse::<iroha_primitives::json::Json>().unwrap(),
            );
            tx.world
                .account_permissions
                .insert(ALICE_ID.clone(), BTreeSet::new());
            tx.world.roles.insert(
                role_id.clone(),
                Role {
                    id: role_id.clone(),
                    permissions: if through_role {
                        BTreeSet::from([permission.clone()])
                    } else {
                        BTreeSet::new()
                    },
                    permission_epochs: BTreeMap::new(),
                },
            );
            if through_role {
                tx.world.account_roles.insert(
                    crate::role::RoleIdWithOwner::new(ALICE_ID.clone(), role_id.clone()),
                    (),
                );
            } else {
                tx.world
                    .account_permissions
                    .insert(ALICE_ID.clone(), BTreeSet::from([permission]));
            }
            let allowed = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
                || super::super::authority_has_native_global_read_permission(&tx.world, &ALICE_ID),
            )
            .unwrap();
            assert_eq!(allowed, payload == "null");
        }
    }
}

#[test]
fn original_private_instruction_routing_refusal_latches_before_scope_verdict() {
    use crate::state::WorldReadOnly as _;
    use iroha_data_model::{
        account::AccountAddress,
        domain::Domain,
        isi::Register,
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_model_base::metadata::Metadata;
    use mv::storage::StorageReadOnly as _;
    use norito::codec::Encode as _;

    let selector = crate::sns::selector_for_dataspace_alias("alpha").unwrap();
    let address = AccountAddress::from_account_id(&ALICE_ID).unwrap();
    let record = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    let key = crate::sns::record_storage_key(&selector);
    let original = record.encode();
    let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    world
        .smart_contract_state_mut_for_testing()
        .insert(key.clone(), original.clone());
    let state = State::new_for_testing(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let ds = crate::sns::dataspace_id_for_sns_alias("alpha").unwrap();
    let instruction: InstructionBox = Register::domain(Domain::new(
        iroha_model_base::domain::DomainId::try_new("bank", "alpha").unwrap(),
    ))
    .into();
    let mut block = state.block(header(2));
    {
        let mut tx = block.transaction();
        bind_scope(&mut tx, ds);
        assert!(ensure_private_instruction(&instruction, &mut tx, ds, 0).is_ok());
        assert!(tx.execution_deferral().is_none());
        norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32),
            || assert!(ensure_private_instruction(&instruction, &mut tx, ds, 0).is_err()),
        );
        assert_eq!(
            tx.execution_deferral().unwrap().reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert_eq!(tx.world.smart_contract_state().get(&key), Some(&original));
    }
    let mut retry = block.transaction();
    bind_scope(&mut retry, ds);
    assert!(ensure_private_instruction(&instruction, &mut retry, ds, 0).is_ok());
    assert!(retry.execution_deferral().is_none());
}
