// Production typed nested-call funding, completed-work metering, and rollback controls.

fn nested_return_funding_fixture() -> (State, AccountId, ContractAddress, ContractAddress) {
    let authority = fixture_account("alice");
    let state = contract_test_state(&authority);
    let caller = install_contract(
        &state,
        &authority,
        r"
seiyaku Caller {
  error enum CalleeError { ForcedFailure = 1 }
  kotoage fn main() authorize(anyone) -> int { return 0; }
}
",
        0,
    );
    let target_contract = install_contract(
        &state,
        &authority,
        r"
seiyaku Callee { permission AssetOps;
  error enum CalleeError { ForcedFailure = 1 }
  state int counter;
  hajimari() { counter = 0; }
  kotoage fn write() authorize(AssetOps) -> int {
    counter = 9;
    return counter;
  }
  kotoage fn fail_after_write() authorize(AssetOps) -> int {
    counter = 9;
    require(false, CalleeError::ForcedFailure);
    return 0;
  }
}
",
        1,
    );
    grant_asset_ops_to_account(&state, &authority, caller.subject_id());
    (state, authority, caller, target_contract)
}

#[test]
fn nested_call_funding_refuses_without_effects_then_retries() {
    let (state, authority, caller, target_contract) = nested_return_funding_fixture();
    let budget = iroha_allocation::AllocationBudget::new(0);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let (refused, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &target_contract,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let error = refused.expect_err("cold nested execution cannot fit a zero pool");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::AllocationDeferred(_)
    ));
    assert!(error.execution_deferral().is_some());
    assert_eq!(error.metered_gas(), None);
    assert_eq!(vm.remaining_gas(), 1_000_000);
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        target_contract.as_ref().as_bytes()
    );
    assert!(effects.is_empty());
    assert_eq!(
        cache.stats().runtime_misses,
        0,
        "reserve before child checkout"
    );
    assert_eq!(cache.stats().runtime_prepared_loads, 0);
    assert_eq!(budget.reserved_bytes(), 0);

    budget.set_limit_bytes(128 * 1024 * 1024);
    let (success, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &target_contract,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let cold_gas = success.expect("same invocation retries after local capacity returns");
    assert!(
        !effects.is_empty(),
        "only successful retry publishes the child write"
    );
    assert_eq!(
        render_nested_result(
            &vm,
            iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Int,
        ),
        norito::json!("9")
    );
    let after_success = cache.stats();
    let idle_bytes = budget.reserved_bytes();
    // Concurrent aggregate-cache pressure may evict idle storage. Zero still refuses the next
    // nested allocation without depending on whether that optional retention survived.
    budget.set_limit_bytes(0);
    let (refused, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &target_contract,
        "write",
        Json::new(()),
        cache.clone(),
    );
    let error = refused.expect_err("zero pool refuses original nested allocation custody");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::AllocationDeferred(_)
    ));
    assert!(error.execution_deferral().is_some());
    assert_eq!(error.metered_gas(), None);
    // An idle cached child may survive optional cache pressure. Its empty input
    // installation charges 32 + one eight-byte result word before allocation
    // refuses. If it was evicted, checkout refuses before this work begins.
    let input_installation_gas = 32 + core::mem::size_of::<u64>() as u64;
    let installation_spent = 1_000_000 - vm.remaining_gas();
    let after_refusal = cache.stats();
    if installation_spent == 0 {
        assert_eq!(after_refusal.runtime_hits, after_success.runtime_hits);
        assert!(
            after_refusal.runtime_misses == after_success.runtime_misses
                || after_refusal.runtime_misses == after_success.runtime_misses + 1,
            "eviction refuses either artifact preparation or the single cold checkout"
        );
    } else {
        assert_eq!(installation_spent, input_installation_gas);
        assert_eq!(
            after_refusal.runtime_hits,
            after_success.runtime_hits + 1,
            "reusing an idle VM is counted before its input installation can refuse"
        );
        assert_eq!(after_refusal.runtime_misses, after_success.runtime_misses);
    }
    assert_eq!(
        after_refusal.runtime_prepared_loads, after_success.runtime_prepared_loads,
        "zero capacity never loads another runtime"
    );
    assert_eq!(
        after_refusal.runtime_template_builds, after_success.runtime_template_builds,
        "zero capacity never admits a fresh runtime baseline"
    );
    // The shared dispatcher also asserts all six input descriptors are unchanged.
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        target_contract.as_ref().as_bytes()
    );
    assert!(effects.is_empty());
    assert!(budget.reserved_bytes() <= idle_bytes);

    budget.set_limit_bytes(128 * 1024 * 1024);
    let (retry, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &target_contract,
        "write",
        Json::new(()),
        cache.clone(),
    );
    assert_eq!(
        retry.expect("retry after capacity returns"),
        cold_gas,
        "funding never changes gas"
    );
    assert!(!effects.is_empty());
    assert_eq!(
        render_nested_result(
            &vm,
            iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1::Int,
        ),
        norito::json!("9")
    );
    drop(cache);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "all nested owners were reclaimed"
    );
}

#[test]
fn prepaid_nested_return_is_released_when_child_effects_roll_back() {
    let (state, authority, caller, target_contract) = nested_return_funding_fixture();
    let budget = iroha_allocation::AllocationBudget::new(128 * 1024 * 1024);
    let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
    let (result, vm, effects) = call_contract_syscall_with_prepared_cache(
        &state,
        &authority,
        &caller,
        &target_contract,
        "fail_after_write",
        Json::new(()),
        cache.clone(),
    );
    let error = result.expect_err("callee aborts after staging its write");
    assert!(matches!(
        error.as_unmetered(),
        ivm::VMError::ContractAbort { code: 1, .. }
    ));
    assert!(
        error.metered_gas().is_some(),
        "contract faults remain metered"
    );
    assert!(
        vm.remaining_gas() < 1_000_000,
        "child execution still spends its gas"
    );
    assert!(effects.is_empty(), "failed child write is rolled back");
    assert_eq!(
        vm.validate_tlv(vm.register(10)).unwrap().payload,
        target_contract.as_ref().as_bytes()
    );
    drop(cache);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "unused return credit cannot leak on child failure"
    );
}

// These phase boundaries retire genesis/compiler and funding frames before the
// large transaction or Host/IVM slots are entered on the ordinary test stack.
// Keep the original State on the heap; do not clone its World or increase stacks.
const IMPORTED_RETURN_GAS: u64 = 4_000_000;

type ImportedReturnSnapshot = (
    Vec<(AssetId, Quantity)>,
    Vec<(StatePath, Vec<u8>)>,
    Vec<(
        (iroha_model_base::topology::LaneId, AccountId),
        (AssetId, Quantity),
    )>,
    Vec<(AssetId, Quantity)>,
);

struct ImportedReturnFixture {
    state: Box<State>,
    authority: AccountId,
    caller: ContractAddress,
    child: ContractAddress,
    principal: AssetId,
    caller_asset: AssetId,
    child_asset: AssetId,
}

#[inline(never)]
fn prepare_imported_return_fixture(
    authority: &AccountId,
    produced_type: &str,
    produced_expression: &str,
    claimed_kind: iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1,
) -> ImportedReturnFixture {
    // This is the current genesis-pinned Global XOR definition at scale nine,
    // not a separately named fixture currency. The fixture's signed genesis
    // authenticates its World before any instance or ordinary call exists.
    let world = crate::validation_fee::tests::validation_fee_payout_world(authority);
    let state = Box::new(contract_test_state_with_world(authority, world));
    assert!(state.committed_height() >= 1);
    let xor = state
        .view()
        .world()
        .sumeragi_npos_parameters()
        .unwrap()
        .unwrap()
        .xor_asset_definition_id;
    crate::state::validate_network_xor_asset(state.view().world(), &xor).unwrap();
    let child_source = format!(
        r#"
seiyaku ReturnChild {{ permission AssetOps;
  state StateMap<int, int> Values;
  kotoage fn write_then_return(quantity amount) authorize(AssetOps) -> {produced_type} {{
    Values[1] = 9;
    ledger::asset::transfer(source: context::authority(), destination: context::seiyaku_subject(), asset_definition: AssetDefinitionId::parse("{xor}"), amount: amount, dataspace: DataSpaceId::parse("0"));
    return {produced_expression};
  }}
}}
"#
    );
    let child = install_contract_with_interface(&state, authority, &child_source, 1, |interface| {
        let entry = interface
            .entrypoints
            .iter_mut()
            .find(|entry| entry.name == "write_then_return")
            .unwrap();
        let original = entry.return_schema.clone().unwrap();
        assert_eq!(
            original.canonical_type_name().as_deref(),
            Some(produced_type)
        );
        let claimed = exact_return_type(claimed_kind);
        entry.return_type = claimed.canonical_type_name();
        entry.return_schema = Some(claimed.clone());
        let callable = interface
            .callables
            .iter_mut()
            .find(|callable| callable.entry_pc == entry.entry_pc)
            .unwrap();
        assert!(callable.results.matches_entrypoint_type(&original));
        callable.results = ivm::call::CallSchemaV1::from_entrypoint_type(&claimed).unwrap();
        assert!(callable.results.matches_entrypoint_type(&claimed));
    });
    let claimed_type = exact_return_type(claimed_kind)
        .canonical_type_name()
        .unwrap();
    let root_source = format!(
        r#"
seiyaku ReturnRoot {{
  import seiyaku "child.to" as Child;
  state StateMap<int, int> RootValues;
  kotoage fn main(quantity amount) authorize(anyone) -> {claimed_type} {{
    RootValues[1] = 5;
    ledger::asset::transfer(source: context::authority(), destination: context::seiyaku_subject(), asset_definition: AssetDefinitionId::parse("{xor}"), amount: amount, dataspace: DataSpaceId::parse("0"));
    let child = Child::at(address: b"{child}");
    return child.write_then_return(amount: amount);
  }}
}}
"#
    );
    let root_artifact = compile_bound_contract_import(&state, &child, "child.to", &root_source);
    let caller = install_contract_artifact_with_interface_and_lifecycle(
        &state,
        authority,
        root_artifact,
        0,
        false,
        |_| {},
    );
    grant_contract_entrypoint_to_account(
        &state,
        authority,
        caller.subject_id(),
        &child,
        "write_then_return",
    );
    let principal = AssetId::new(xor.clone(), authority.clone());
    let caller_asset = AssetId::new(xor.clone(), caller.subject_id());
    let child_asset = AssetId::new(xor.clone(), child.subject_id());
    grant_test_asset_transfer(&state, caller.subject_id(), principal.clone());
    grant_test_asset_transfer(&state, child.subject_id(), caller_asset.clone());

    ImportedReturnFixture {
        state,
        authority: authority.clone(),
        caller,
        child,
        principal,
        caller_asset,
        child_asset,
    }
}

#[inline(never)]
fn fund_imported_return_fixture(fixture: &ImportedReturnFixture) {
    use iroha_data_model::nexus::{
        PublicLaneStakeShare, PublicLaneValidatorRecord, PublicLaneValidatorStatus,
    };
    use iroha_model_base::topology::LaneId;
    let state = &fixture.state;
    let authority = &fixture.authority;
    let principal = &fixture.principal;
    let caller_asset = &fixture.caller_asset;
    // Fund exact original custody through the native quantity instruction.
    // Both spendable transfer legs are separate from three retained XOR of
    // principal. No reward distribution, inflation or fee-payment leg is
    // invented by this return-boundary qualification component.
    let height = u64::try_from(state.view().height() + 1)
        .unwrap()
        .try_into()
        .unwrap();
    let mut funding = state.block(BlockHeader::new(
        height,
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    {
        let mut tx = funding.transaction();
        Mint::asset_quantity(Quantity::from(5_u32), principal.clone())
            .execute(authority, &mut tx)
            .unwrap();
        Mint::asset_quantity(Quantity::from(2_u32), caller_asset.clone())
            .execute(authority, &mut tx)
            .unwrap();
        let held = Quantity::from(3_u32);
        crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
            &tx.world,
            LaneId::SINGLE,
            authority,
            principal,
            &held,
            &Quantity::from(5_u32),
        )
        .unwrap()
        .apply(&mut tx.world);
        tx.world.public_lane_validators.insert(
            (LaneId::SINGLE, authority.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: authority.clone(),
                peer_id: iroha_model_base::peer::PeerId::new(
                    authority.expect_single_signatory().clone(),
                ),
                stake_account: authority.clone(),
                total_stake: held.clone(),
                self_stake: held.clone(),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
        tx.world.public_lane_stake_shares.insert(
            (LaneId::SINGLE, authority.clone(), authority.clone()),
            PublicLaneStakeShare {
                lane_id: LaneId::SINGLE,
                validator: authority.clone(),
                staker: authority.clone(),
                bonded: held,
                pending_unbonds: BTreeMap::new(),
                metadata: Metadata::default(),
            },
        );
        crate::state::validate_public_lane_stake_reserves(&tx.world).unwrap();
        tx.apply();
    }
    funding.commit_world_overlay_for_testing().unwrap();
}

#[inline(never)]
fn snapshot_imported_return_fixture(fixture: &ImportedReturnFixture) -> ImportedReturnSnapshot {
    let state = &fixture.state;
    let before = {
        let view = state.view();
        (
            view.world()
                .assets()
                .iter()
                .map(|(id, value)| (id.clone(), value.as_ref().clone()))
                .collect::<Vec<_>>(),
            view.world()
                .smart_contract_state()
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect::<Vec<_>>(),
            view.world()
                .public_lane_stake_custody()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            view.world()
                .public_lane_stake_reserves()
                .iter()
                .map(|(id, value)| (id.clone(), value.clone()))
                .collect::<Vec<_>>(),
        )
    };

    before
}

#[inline(never)]
fn sign_imported_return_call(
    fixture: &ImportedReturnFixture,
) -> (iroha_data_model::transaction::SignedTransaction, Hash, u32) {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointArgumentRecordV1, entrypoint_argument_schema_hash_v1,
    };
    let state = &fixture.state;
    let authority = &fixture.authority;
    let caller = &fixture.caller;
    let child = &fixture.child;
    let invocation = contract_invocation_from_json(
        state,
        caller.clone(),
        "main",
        &Json::from(norito::json!({"amount":"1"})),
    );
    let argument_pointer = invocation.arguments.as_ref().unwrap().as_bytes().as_ptr();
    let original_arguments = invocation.arguments.as_ref().unwrap().as_bytes().to_vec();
    let input_hash = Hash::new(&original_arguments);
    let input_record: EntrypointArgumentRecordV1 =
        norito::decode_canonical(&original_arguments).unwrap();
    let (root_schema, child_hash, child_ordinal) = {
        let view = state.view();
        let root_key =
            ContractArtifactId::for_address(caller, invocation.expected_code_hash).unwrap();
        let root_entry = view
            .world()
            .contract_manifests()
            .get(&root_key)
            .unwrap()
            .entrypoints
            .as_ref()
            .unwrap()
            .iter()
            .find(|entry| entry.name == "main")
            .unwrap();
        let hash = *view.world().contract_instances().get(child).unwrap();
        let key = ContractArtifactId::for_address(child, hash).unwrap();
        let ordinal = view
            .world()
            .contract_manifests()
            .get(&key)
            .unwrap()
            .entrypoints
            .as_ref()
            .unwrap()
            .iter()
            .position(|entry| entry.name == "write_then_return")
            .unwrap();
        (
            root_entry.argument_schema.clone().unwrap(),
            hash,
            u32::try_from(ordinal).unwrap(),
        )
    };
    assert_eq!(
        input_record.schema_hash,
        entrypoint_argument_schema_hash_v1(&norito::encode_canonical(&root_schema).unwrap())
    );
    let signed = TransactionBuilder::new(
        state.network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(
            Vec::new(),
            core::num::NonZeroU64::new(IMPORTED_RETURN_GAS),
        ),
    )
    .with_executable(Executable::ContractCall(invocation))
    .sign(fixture_signing_keypair(authority).private_key());
    signed
        .verify_signature()
        .expect("the actual root source is signed");
    let Executable::ContractCall(signed_invocation) = signed.instructions() else {
        unreachable!()
    };
    let signed_record = signed_invocation.arguments.as_ref().unwrap();
    assert_eq!(
        signed_record.as_bytes().as_ptr(),
        argument_pointer,
        "building/signing moves the original canonical record without replacing its backing"
    );
    assert_eq!(signed_record.as_bytes(), original_arguments.as_slice());
    assert_eq!(Hash::new(signed_record.as_bytes()), input_hash);

    (signed, child_hash, child_ordinal)
}

#[inline(never)]
fn execute_imported_return_call(
    fixture: &ImportedReturnFixture,
    before: &ImportedReturnSnapshot,
    label: &str,
    valid: bool,
    signed: iroha_data_model::transaction::SignedTransaction,
    child_hash: Hash,
    child_ordinal: u32,
    cache: &mut crate::smartcontracts::ivm::cache::IvmCache,
) {
    use iroha_data_model::executor::fault::{
        IvmFaultKindV1, IvmFaultPositionV1, IvmInvocationSelectorV1,
    };
    let state = &fixture.state;
    let authority = &fixture.authority;
    let principal = &fixture.principal;
    let caller_asset = &fixture.caller_asset;
    let child_asset = &fixture.child_asset;
    let next_height = u64::try_from(state.view().height() + 1)
        .unwrap()
        .try_into()
        .unwrap();
    let mut block = state.block(BlockHeader::new(
        next_height,
        state.view().latest_block_hash(),
        None,
        0,
        0,
    ));
    assert_eq!(block.gas_limit_per_block, IMPORTED_RETURN_GAS);
    {
        let source_call = Hash::from(signed.hash_as_entrypoint());
        let mut tx = block.transaction_for_fastpq_testing(source_call);
        tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let result = crate::executor::Executor::Initial
            .execute_transaction(&mut tx, authority, &signed, cache);
        assert!(
            tx.last_tx_gas_used > 0 && tx.last_tx_gas_used < IMPORTED_RETURN_GAS,
            "{label}: actual root/child work must be metered below the unchanged policy"
        );
        if valid {
            result.expect("the complete canonical quantity return commits both actual effects");
            assert_eq!(
                tx.world.assets.get(principal).unwrap().as_ref(),
                &Quantity::from(4_u32)
            );
            assert_eq!(
                tx.world.assets.get(caller_asset).unwrap().as_ref(),
                &Quantity::from(2_u32)
            );
            assert_eq!(
                tx.world.assets.get(child_asset).unwrap().as_ref(),
                &Quantity::from(1_u32)
            );
            assert_eq!(
                tx.world.smart_contract_state.len(),
                before.1.len() + 2,
                "the valid control executes both actual scoped writes"
            );
            assert_eq!(
                tx.world.public_lane_stake_reserves.get(principal),
                Some(&Quantity::from(3_u32))
            );
            crate::state::validate_public_lane_stake_reserves(&tx.world).unwrap();
            tx.apply();
        } else {
            let rejection =
                crate::execution_attempt::expect_completed_rejection(result.expect_err(
                    "typed child result must be rejected after its actual write/transfer",
                ));
            let ValidationFail::IvmFault(fault) = rejection else {
                panic!("{label}: expected protected typed-return fault, got {rejection:?}")
            };
            assert!(
                matches!(
                    fault.kind,
                    IvmFaultKindV1::DecodeError | IvmFaultKindV1::NoritoInvalid
                ),
                "{label}: {fault:?}"
            );
            assert_eq!(
                fault.site.code_hash, child_hash,
                "failure retains the actual child artifact rather than relabeling the root"
            );
            assert_eq!(
                fault.site.selector,
                IvmInvocationSelectorV1::Entrypoint(child_ordinal)
            );
            assert!(
                matches!(fault.site.position, IvmFaultPositionV1::Execute { pc_offset } if pc_offset > 0)
                    || matches!(fault.site.position, IvmFaultPositionV1::ReturnValidation),
                "{label}: reject at the executed child's return, not before argument installation"
            );
            // Dropping this actual rejected transaction is the rollback,
            // including the root's staged transfer and durable write.
        }
    }
    if !valid {
        // Reopen the same still-live StateBlock after dropping the rejected
        // StateTransaction. A later block drop must not hide any leaked
        // partial transaction, root transfer, child write or reserve update.
        let reopened = block.transaction();
        let same_live_block = (
            reopened
                .world
                .assets()
                .iter()
                .map(|(id, value)| (id.clone(), value.as_ref().clone()))
                .collect::<Vec<_>>(),
            reopened
                .world
                .smart_contract_state()
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect::<Vec<_>>(),
            reopened
                .world
                .public_lane_stake_custody()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>(),
            reopened
                .world
                .public_lane_stake_reserves()
                .iter()
                .map(|(id, value)| (id.clone(), value.clone()))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            &same_live_block, before,
            "{label}: rejected transaction cannot leak any of the four complete snapshots into its still-live block"
        );
        crate::state::validate_public_lane_stake_reserves(&reopened.world).unwrap();
        drop(reopened);
    }
    if valid {
        block.commit_world_overlay_for_testing().unwrap();
    } else {
        drop(block);
    }
}

#[inline(never)]
fn assert_committed_imported_return_fixture(
    fixture: &ImportedReturnFixture,
    before: &ImportedReturnSnapshot,
    label: &str,
    valid: bool,
) {
    let state = &fixture.state;
    let view = state.view();
    let after = (
        view.world()
            .assets()
            .iter()
            .map(|(id, value)| (id.clone(), value.as_ref().clone()))
            .collect::<Vec<_>>(),
        view.world()
            .smart_contract_state()
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect::<Vec<_>>(),
        view.world()
            .public_lane_stake_custody()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>(),
        view.world()
            .public_lane_stake_reserves()
            .iter()
            .map(|(id, value)| (id.clone(), value.clone()))
            .collect::<Vec<_>>(),
    );
    if valid {
        assert_ne!(after.0, before.0);
        assert_ne!(after.1, before.1);
        assert_eq!(after.2, before.2);
        assert_eq!(after.3, before.3);
    } else {
        assert_eq!(
            &after, before,
            "{label}: actual transaction rollback preserves all balances, both scoped writes, pinned custody and principal reserves"
        );
    }
    crate::state::validate_public_lane_stake_reserves(view.world()).unwrap();
    drop(view);
}

#[inline(never)]
fn probe_canonical_imported_return(
    fixture: &ImportedReturnFixture,
    prepared: &PreparedContractCache,
    original_pool: &iroha_allocation::AllocationBudget,
) {
    use iroha_data_model::smart_contract::entrypoint::{
        EntrypointReturnRecordV1, EntrypointValueKindV1 as Kind, entrypoint_return_schema_hash_v1,
    };
    let state = &fixture.state;
    let authority = &fixture.authority;
    let caller = &fixture.caller;
    let child = &fixture.child;
    let principal = &fixture.principal;
    let child_asset = &fixture.child_asset;
    // Capture the successful actual A9 table into the sole canonical
    // return record and prove its exact schema hash and numeric value.
    // This separate host attempt is never applied to the ledger.
    let view = state.view();
    let mut host = CoreHostImpl::new(authority.clone());
    host.set_prepared_contract_cache(prepared.clone());
    host.set_query_state(&view);
    host.set_durable_state_snapshot_from_world(view.world());
    let mut vm = IVM::try_new_with_memory_budget(IMPORTED_RETURN_GAS, original_pool).unwrap();
    bind_nested_caller(&mut host, &mut vm, &view, authority, caller);
    let registers = store_typed_contract_call(
        &mut vm,
        state,
        child,
        "write_then_return",
        &Json::from(norito::json!({"amount":"1"})),
    );
    assert!(
        host.syscall(ivm_sys::SYSCALL_CALL_CONTRACT, &mut vm)
            .unwrap()
            > 0
    );
    assert_eq!(
        (10..16).map(|index| vm.register(index)).collect::<Vec<_>>(),
        registers
    );
    let schema = exact_return_type(Kind::Quantity);
    let record = captured_nested_result(&vm, &schema);
    let bytes = norito::encode_canonical(&record).unwrap();
    assert_eq!(
        norito::decode_canonical::<EntrypointReturnRecordV1>(&bytes).unwrap(),
        record
    );
    assert_eq!(
        record.schema_hash,
        entrypoint_return_schema_hash_v1(&norito::encode_canonical(&schema).unwrap())
    );
    assert_eq!(
        ivm::value_record::render_entrypoint_return_record(&schema, &record).unwrap(),
        norito::json!("1")
    );
    let context = host.current_contract_runtime_context.clone().unwrap();
    let artifacts = host.into_execution_artifacts(Some(context)).unwrap();
    let effects = artifacts.queued_instructions_with_authority();
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].0, child.subject_id());
    assert_eq!(
        view.world().assets().get(principal).unwrap().as_ref(),
        &Quantity::from(4_u32)
    );
    assert_eq!(
        view.world().assets().get(child_asset).unwrap().as_ref(),
        &Quantity::from(1_u32)
    );
    assert_eq!(
        view.world().public_lane_stake_reserves().get(principal),
        Some(&Quantity::from(3_u32))
    );
    drop(artifacts);
    drop(vm);
    drop(view);
}

// Exercise the signed root and its actual generic imported child at the normal
// four-million gas policy. Bad public/callable metadata is itself admitted and
// signed consistently, so each rejection must come from the child's protected
// return after it has staged its durable write and real XOR transfer.
#[test]
fn signed_imported_wrong_returns_roll_back_child_root_and_real_xor_principal() {
    use iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1 as Kind;
    let authority = fixture_account("alice");
    for (label, produced_type, produced_expression, claimed_kind, valid) in [
        ("valid", "quantity", "amount", Kind::Quantity, true),
        ("wrong schema", "bytes", r#"b"\xff""#, Kind::String, false),
        ("wrong atom", "quantity", "amount", Kind::Bool, false),
        ("wrong numeric pointer", "int", "9", Kind::Quantity, false),
    ] {
        let fixture = prepare_imported_return_fixture(
            &authority,
            produced_type,
            produced_expression,
            claimed_kind,
        );
        fund_imported_return_fixture(&fixture);
        let before = snapshot_imported_return_fixture(&fixture);
        let (signed, child_hash, child_ordinal) = sign_imported_return_call(&fixture);
        let original_pool = iroha_allocation::AllocationBudget::new(128 * 1024 * 1024);
        let prepared = PreparedContractCache::with_execution_budget(4, original_pool.clone());
        let mut cache = crate::smartcontracts::ivm::cache::IvmCache::with_prepared_contract_cache(
            4,
            prepared.clone(),
        );
        execute_imported_return_call(
            &fixture,
            &before,
            label,
            valid,
            signed,
            child_hash,
            child_ordinal,
            &mut cache,
        );
        assert_committed_imported_return_fixture(&fixture, &before, label, valid);
        if valid {
            probe_canonical_imported_return(&fixture, &prepared, &original_pool);
        }
        drop(cache);
        drop(prepared);
        assert_eq!(
            original_pool.reserved_bytes(),
            0,
            "{label}: last actual runtime/cache reader refunds the original finite pool"
        );
    }
}
