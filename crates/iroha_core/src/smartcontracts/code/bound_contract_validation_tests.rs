//! Live-query host validation preserves eager registry errors without owning payloads.

use super::{
    tests::{default_header, minimal_contract_artifact, test_state},
    *,
};
use iroha_model_base::topology::DataSpaceId;

fn insert_contract(
    transaction: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    index: u64,
    dataspace_id: DataSpaceId,
    byte_count: usize,
) -> (ContractAddress, ContractArtifactId) {
    let network = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
        .parse()
        .expect("fixture network");
    let address = ContractAddress::derive(&network, authority, index, dataspace_id)
        .expect("fixture contract address");
    let (_, mut manifest) = minimal_contract_artifact(1);
    // Registry reads intentionally do not re-verify admitted images. Distinct
    // synthetic large images isolate copying from compiler and admission costs.
    let bytes = vec![u8::try_from(index % 256).expect("byte"); byte_count];
    let code_hash = Hash::new(&bytes);
    let artifact_id = ContractArtifactId::new(dataspace_id, code_hash);
    manifest.code_hash = Some(code_hash);
    transaction
        .world
        .bind_active_contract_subject_for_testing(address.clone(), code_hash);
    transaction.world.contract_code.insert(artifact_id, bytes);
    transaction
        .world
        .contract_manifests
        .insert(artifact_id, manifest);
    (address, artifact_id)
}

/// Independent reference retaining the original eager lookup's ordered reads.
fn eager_record(
    state: &impl StateReadOnly,
    contract_address: &ContractAddress,
) -> Result<Option<BoundContractRecord>, ExecutionAttemptError<ValidationFail>> {
    let Some(code_hash) = fetch_instance_binding(state, contract_address)? else {
        return Ok(None);
    };
    let Some(contract_subject) =
        borrow_bound_contract_subject_from_world(state.world(), contract_address)
    else {
        return Ok(None);
    };
    let Ok(artifact_id) = ContractArtifactId::for_address(contract_address, code_hash) else {
        return Ok(None);
    };
    let Some(manifest) = fetch_manifest(state, &artifact_id)? else {
        return Ok(None);
    };
    let Some(code_bytes) = fetch_code_bytes(state, &artifact_id)? else {
        return Ok(None);
    };
    let contract_alias_binding = state
        .world()
        .contract_alias_bindings()
        .get(contract_address)
        .cloned();
    let contract_alias = contract_alias_binding
        .as_ref()
        .map(|binding| binding.alias.clone());
    if let Some(alias) = contract_alias.as_ref()
        && state.world().contract_aliases().get(alias) != Some(contract_address)
    {
        return Ok(None);
    }
    Ok(Some(BoundContractRecord {
        lifecycle_revision: state
            .world()
            .contract_subject_bindings()
            .get(contract_address)
            .expect("validated binding")
            .lifecycle
            .revision,
        contract_address: contract_address.clone(),
        contract_subject: contract_subject.clone(),
        contract_alias,
        contract_alias_binding,
        code_hash,
        manifest,
        code_bytes,
    }))
}

fn eager_snapshot(
    state: &impl StateReadOnly,
) -> Result<BTreeMap<AccountId, BoundContractRecord>, ExecutionAttemptError<ValidationFail>> {
    let mut records = BTreeMap::new();
    for (address, _) in state.world().contract_instances().iter() {
        if let Some(record) = eager_record(state, address)? {
            records.insert(record.contract_subject.clone(), record);
        }
    }
    Ok(records)
}

fn outcome<T>(result: Result<T, ExecutionAttemptError<ValidationFail>>) -> Result<T, String> {
    result.map_err(|error| format!("{error:?}"))
}

#[test]
fn bound_contract_validation_preserves_incomplete_and_malformed_binding_absence() {
    for defect in 0..9 {
        let (state, authority, _) = test_state();
        let mut block = state.block(default_header(1));
        let mut transaction = block.transaction();
        let (address, artifact) =
            insert_contract(&mut transaction, &authority, 1, DataSpaceId::UNIVERSAL, 128);
        match defect {
            0 => {
                transaction
                    .world
                    .contract_subject_bindings
                    .remove(address.clone());
            }
            1 => {
                transaction
                    .world
                    .contract_subject_bindings
                    .get_mut(&address)
                    .expect("binding")
                    .subject = authority.clone();
            }
            2 => {
                transaction
                    .world
                    .contract_subject_bindings
                    .get_mut(&address)
                    .expect("binding")
                    .lifecycle
                    .revision = 0;
            }
            3 => {
                let binding = transaction
                    .world
                    .contract_subject_bindings
                    .get_mut(&address)
                    .expect("binding");
                binding.lifecycle.active_code_hash = None;
            }
            4 => {
                transaction.world.accounts.remove(address.subject_id());
            }
            5 => {
                transaction.world.contract_manifests.remove(artifact);
            }
            6 => {
                transaction.world.contract_code.remove(artifact);
            }
            7 => {
                let alias =
                    ContractAlias::from_components("validation", Some("wonderland"), "universal")
                        .expect("fixture alias");
                transaction
                    .world
                    .bind_contract_alias(&address, alias.clone(), None, None, 0)
                    .expect("bind alias");
                transaction.world.contract_aliases.remove(alias);
            }
            8 => {
                transaction.world.contract_instances.remove(address.clone());
            }
            _ => unreachable!(),
        }
        let expected =
            outcome(eager_snapshot(&transaction)).expect("incomplete records are absent");
        assert!(expected.is_empty(), "defect {defect}");
        assert_eq!(
            outcome(snapshot_bound_contract_records_by_subject(&transaction)),
            Ok(expected)
        );
        assert_eq!(
            outcome(validate_bound_contract_records_by_subject(&transaction)),
            Ok(())
        );
    }
}

#[test]
fn bound_contract_validation_borrows_exact_stored_payloads_and_preserves_owned_records() {
    let (state, authority, _) = test_state();
    let mut block = state.block(default_header(1));
    let mut transaction = block.transaction();
    for index in 0..16 {
        let (address, artifact) = insert_contract(
            &mut transaction,
            &authority,
            index,
            DataSpaceId::UNIVERSAL,
            64 * 1024,
        );
        let alias = ContractAlias::from_components(
            &format!("validation{index}"),
            Some("wonderland"),
            "universal",
        )
        .expect("fixture alias");
        transaction
            .world
            .bind_contract_alias(&address, alias, None, None, 0)
            .expect("bind alias");
        let borrowed = borrow_bound_contract_record(&transaction, &address)
            .expect("registry read")
            .expect("complete binding");
        assert!(std::ptr::eq(
            borrowed.manifest,
            transaction
                .world
                .contract_manifests
                .get(&artifact)
                .expect("stored manifest"),
        ));
        assert!(std::ptr::eq(
            borrowed.code_bytes.as_ptr(),
            transaction
                .world
                .contract_code
                .get(&artifact)
                .expect("stored bytes")
                .as_ptr(),
        ));
        assert!(std::ptr::eq(
            borrowed.contract_subject,
            &transaction
                .world
                .contract_subject_bindings
                .get(&address)
                .expect("binding")
                .subject,
        ));
        assert!(std::ptr::eq(
            borrowed.contract_alias_binding.expect("borrowed alias"),
            transaction
                .world
                .contract_alias_bindings
                .get(&address)
                .expect("stored alias"),
        ));
    }
    assert_eq!(
        outcome(validate_bound_contract_records_by_subject(&transaction)),
        Ok(())
    );
    let expected = outcome(eager_snapshot(&transaction)).expect("eager snapshot");
    assert_eq!(expected.len(), 16);
    assert_eq!(
        outcome(snapshot_bound_contract_records_by_subject(&transaction)),
        Ok(expected)
    );
}

#[test]
fn bound_contract_validation_retains_scope_error_before_incomplete_binding() {
    let (state, authority, _) = test_state();
    let mut block = state.block(default_header(1));
    let mut transaction = block.transaction();
    let (address, _) =
        insert_contract(&mut transaction, &authority, 1, DataSpaceId::UNIVERSAL, 128);
    transaction.world.contract_subject_bindings.remove(address);
    transaction
        .world
        .parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                parent_network_id: state.network_id,
                dataspace_id: DataSpaceId::new(7),
            },
        ))
        .expect("private scope metadata");
    let expected = outcome(eager_snapshot(&transaction)).map(|_| ());
    assert!(
        expected
            .as_ref()
            .unwrap_err()
            .contains("foreign artifact dataspace")
    );
    assert_eq!(
        outcome(validate_bound_contract_records_by_subject(&transaction)),
        expected
    );
    assert_eq!(
        outcome(snapshot_bound_contract_records_by_subject(&transaction)).map(|_| ()),
        expected
    );
}

#[test]
fn bound_contract_validation_preserves_malformed_scope_rejections() {
    use iroha_data_model::parameter::{
        Parameter, custom::CustomParameter, system::consensus_metadata::handshake_meta_id,
    };
    let (state, authority, _) = test_state();
    let mut block = state.block(default_header(1));
    let mut transaction = block.transaction();
    insert_contract(&mut transaction, &authority, 1, DataSpaceId::UNIVERSAL, 128);
    for payload in ["null", "{}", "false", "\"global\""] {
        transaction
            .world
            .parameters
            .set_parameter(Parameter::Custom(CustomParameter::new(
                handshake_meta_id(),
                payload
                    .parse::<iroha_primitives::json::Json>()
                    .expect("valid JSON"),
            )))
            .expect("fixture metadata");
        let expected = outcome(eager_snapshot(&transaction)).map(|_| ());
        assert!(
            expected
                .as_ref()
                .unwrap_err()
                .contains("artifact access requires immutable root scope")
        );
        assert_eq!(
            outcome(validate_bound_contract_records_by_subject(&transaction)),
            expected
        );
    }
}

#[test]
fn bound_contract_validation_retains_local_decode_refusal() {
    let (state, authority, _) = test_state();
    let mut block = state.block(default_header(1));
    let mut transaction = block.transaction();
    insert_contract(&mut transaction, &authority, 1, DataSpaceId::UNIVERSAL, 128);
    let limits = || norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let eager = norito::core::with_decode_limits_scope(limits(), || eager_snapshot(&transaction));
    let validation = norito::core::with_decode_limits_scope(limits(), || {
        validate_bound_contract_records_by_subject(&transaction)
    });
    let Err(ExecutionAttemptError::Deferred(eager)) = eager else {
        panic!("eager lookup must retain its local decode refusal");
    };
    let Err(ExecutionAttemptError::Deferred(validation)) = validation else {
        panic!("borrowed validation must retain its local decode refusal");
    };
    assert_eq!(
        eager.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert_eq!(validation.reason(), eager.reason());
    let eager_owner = eager.decode_refusal().expect("original eager decode owner");
    let validation_owner = validation
        .decode_refusal()
        .expect("original borrowed validation decode owner");
    assert_eq!(
        eager_owner.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert_eq!(validation_owner.kind(), eager_owner.kind());
    assert_eq!(
        validation_owner.resource_error(),
        eager_owner.resource_error()
    );
    assert_ne!(
        validation_owner, eager_owner,
        "independent decode attempts retain distinct opaque scope identities"
    );
    assert!(eager.allocation_refusal().is_none());
    assert!(validation.allocation_refusal().is_none());
}

#[test]
fn bound_contract_validation_empty_registry_needs_no_scope_decode() {
    let (state, _, _) = test_state();
    let view = state.view();
    norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || {
            assert_eq!(outcome(eager_snapshot(&view)).map(|_| ()), Ok(()));
            assert_eq!(
                outcome(validate_bound_contract_records_by_subject(&view)),
                Ok(())
            );
        },
    );
}

#[test]
#[ignore = "diagnostic benchmark for host setup with many deployed contracts"]
fn bound_contract_validation_many_contracts_diagnostic() {
    const CONTRACTS: u64 = 256;
    const BYTES: usize = 64 * 1024;
    const ROUNDS: usize = 8;
    let (state, authority, _) = test_state();
    let mut block = state.block(default_header(1));
    let mut transaction = block.transaction();
    for index in 0..CONTRACTS {
        insert_contract(
            &mut transaction,
            &authority,
            index,
            DataSpaceId::UNIVERSAL,
            BYTES,
        );
    }
    let started = std::time::Instant::now();
    for _ in 0..ROUNDS {
        let snapshot = eager_snapshot(std::hint::black_box(&transaction)).expect("eager snapshot");
        assert_eq!(snapshot.len(), CONTRACTS as usize);
        std::hint::black_box(snapshot);
    }
    let eager_elapsed = started.elapsed();
    let started = std::time::Instant::now();
    for _ in 0..ROUNDS {
        validate_bound_contract_records_by_subject(std::hint::black_box(&transaction))
            .expect("borrowed validation");
    }
    eprintln!(
        "bound contract setup: {CONTRACTS} contracts x {BYTES} bytes x {ROUNDS} rounds; eager={eager_elapsed:?}, validation={:?}; eliminated {} copied bytecode bytes per invocation",
        started.elapsed(),
        CONTRACTS as usize * BYTES,
    );
}

#[test]
#[ignore = "combined invocation timing diagnostic; run with --ignored --nocapture"]
fn bound_contract_validation_and_elections_invocation_diagnostic() {
    use crate::smartcontracts::ivm::host::{CoreHostImpl, vrf_epoch_length_from_state};
    use std::sync::Arc;

    const CONTRACTS: u64 = 256;
    const BYTES: usize = 64 * 1024;
    const ELECTIONS: u32 = 4_096;
    const ROUNDS: u32 = 8;
    const GAS_LIMIT: u64 = 1_000_000;
    let (state, authority, _) = test_state();
    {
        let mut setup = state.block(default_header(1));
        let mut transaction = setup.transaction();
        for index in 0..CONTRACTS {
            insert_contract(
                &mut transaction,
                &authority,
                index,
                DataSpaceId::UNIVERSAL,
                BYTES,
            );
        }
        for index in 0..ELECTIONS {
            transaction.world.elections.insert(
                format!("election-{index}"),
                crate::state::ElectionState {
                    options: 2,
                    finalized: true,
                    tally: vec![u128::from(index), 1],
                    ..crate::state::ElectionState::default()
                },
            );
        }
        transaction.apply();
        setup
            .commit_world_overlay_for_testing()
            .expect("commit diagnostic registry fixture");
    }
    let mut block = state.block(default_header(2));
    let transaction = block.transaction();
    let mut program = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1_000,
        abi_version: 1,
    }
    .encode();
    program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    let mut vm = ivm::IVM::new(GAS_LIMIT);
    vm.load_program(&program).expect("load no-op guest");
    // A reused VM models the existing runtime checkout; each invocation still
    // creates and hydrates a fresh host against the same pinned transaction.
    let mut invoke = |cached: bool| {
        vm.reset().expect("reset runtime");
        vm.set_gas_limit(GAS_LIMIT);
        let records = if cached {
            validate_bound_contract_records_by_subject(&transaction)
                .expect("validate live registry reads");
            None
        } else {
            Some(eager_snapshot(&transaction).expect("eager registry snapshot"))
        };
        let mut host =
            CoreHostImpl::with_accounts(authority.clone(), transaction.accounts_snapshot());
        host.set_output_limits_from_parameters(transaction.world.parameters.get().smart_contract());
        host.set_generic_execution();
        host.set_crypto_config(Arc::clone(&transaction.crypto));
        host.set_zk_config(transaction.zk());
        host.set_public_inputs_from_parameters(transaction.world.parameters.get());
        let epoch_length = vrf_epoch_length_from_state(&transaction).expect("VRF parameters");
        host.set_query_state_with_vrf_epoch_seeds(&transaction, epoch_length);
        host.set_chain_id(transaction.chain_id());
        if let Some(records) = records {
            host.set_bound_contract_records_by_subject_snapshot(records);
            host.set_zk_snapshots_from_world(transaction.world(), transaction.zk())
                .expect("uncached ZK hydration");
        } else {
            host.set_zk_snapshots_from_state(&transaction)
                .expect("cached ZK hydration");
        }
        vm.run_with_host(&mut host).expect("run no-op guest");
        std::hint::black_box(vm.remaining_gas())
    };
    let expected_gas = invoke(false);
    let cold_started = std::time::Instant::now();
    assert_eq!(invoke(true), expected_gas);
    let cold_elapsed = cold_started.elapsed();
    let eager_started = std::time::Instant::now();
    for _ in 0..ROUNDS {
        assert_eq!(invoke(false), expected_gas);
    }
    let eager_elapsed = eager_started.elapsed();
    let cached_started = std::time::Instant::now();
    for _ in 0..ROUNDS {
        assert_eq!(invoke(true), expected_gas);
    }
    let cached_elapsed = cached_started.elapsed();
    eprintln!(
        "fresh-host no-op invocation: {CONTRACTS} contracts x {BYTES} bytes, {ELECTIONS} elections, {ROUNDS} warmed rounds; old total={eager_elapsed:?}, cached total={cached_elapsed:?}, first cached invocation={cold_elapsed:?}; guest gas={} on both paths",
        GAS_LIMIT - expected_gas,
    );
}
