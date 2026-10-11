//! Original signed work retains inherited root-metadata refusal outside publication.

use super::*;
use crate::{
    executor::Executor,
    smartcontracts::ivm::cache::IvmCache,
    sumeragi::test_chain::{CertifiedTestChain, PreparedTestChainConfig, Signers},
};

fn certified_root() -> (DataspaceChain, CertifiedTestChain) {
    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let root = DataspaceChain::new(parent, DataSpaceId::new((1_u64 << 40) + 92));
    certify_private_root(root)
}

fn certify_private_root(root: DataspaceChain) -> (DataspaceChain, CertifiedTestChain) {
    let (state, kura) = root.state(None);
    let original = iroha_genesis::validate_prepared_genesis_bundle(
        &root.chain.genesis.encode_wire().unwrap(),
        &root.manifest,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key(),
        root.chain.genesis.hash(),
    )
    .unwrap();
    let chain = CertifiedTestChain::from_prepared(PreparedTestChainConfig {
        genesis: original,
        manifest: root.manifest.clone(),
        state,
        kura,
        validator_keys: root.chain.keys.clone(),
        pasta_seeds: (0..4)
            .map(|index| zeroize::Zeroizing::new([0xA0 + index; 32]))
            .collect(),
        clock: ALICE_KEYPAIR.clone(),
        lane_blocks: Arc::new(super::super::super::super::lanes::merge::NoLanes),
    })
    .unwrap();
    (root, chain)
}

#[test]
fn signed_private_work_keeps_scope_decode_refusal_local_and_retries_original_carrier() {
    let (root, mut chain) = certified_root();
    let signed = root.signed_work("retry original scope authority");
    let accepted = AcceptedTransaction::accept(
        signed.clone(),
        chain.state().network_id_ref(),
        Duration::from_secs(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
    )
    .unwrap();
    assert_eq!(accepted.hash_as_entrypoint(), signed.hash_as_entrypoint());
    let state = Arc::clone(chain.state());
    let before = state.world.state_accumulator.view().get().root();
    // Read the same committed metadata once to identify a late refusal without guessing
    // its graph size. A failing over-limit reservation observes usage without charging it.
    let view = state.view();
    let capacity = 1 << 20;
    let usage = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, capacity, 32),
        || {
            assert_eq!(
                crate::sumeragi::lanes::routing::read_committed_root_scope(&view.world).unwrap(),
                Some(root.scope),
            );
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(capacity + 1).unwrap_err()
            else {
                panic!("expected exact allocation observation");
            };
            assert_eq!(limit, u64::try_from(capacity).unwrap());
            usize::try_from(attempted).unwrap() - capacity - 1
        },
    );
    drop(view);
    assert!(usage > 1);
    for allocation_limit in [0, usage - 1] {
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            2_u64.try_into().unwrap(),
            Some(root.chain.genesis.hash()),
            None,
            2_000,
            0,
        ));
        let mut transaction =
            block.transaction_for_fastpq_testing(Hash::from(signed.hash_as_entrypoint()));
        let limits = norito::DecodeLimits::new(96, usize::MAX, usize::MAX, allocation_limit, 32);
        let error = norito::with_decode_limits_scope(limits, || {
            Executor::Initial.execute_transaction(
                &mut transaction,
                &ALICE_ID,
                signed.clone(),
                &mut IvmCache::new(),
            )
        })
        .unwrap_err();
        let refusal = transaction.require_storage_admission();
        assert!(
            refusal.is_err(),
            "metadata refusal became a completed signed-input verdict: {error:?}"
        );
        let refusal = refusal.unwrap_err();
        assert_eq!(
            refusal,
            crate::state::StateStorageAdmissionError::RootScopeDecode(
                crate::state::RootScopeDecodeRefusal::Budget,
            ),
        );
        assert!(matches!(
            error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
                if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                    && reason.allocation_refusal().is_none()
        ));
        assert!(refusal.release_wait().is_none());
        // Even a caller which catches the inner instruction error cannot publish the attempt.
        transaction.apply();
        assert_eq!(block.require_storage_admission(), Err(refusal.clone()));
        assert!(matches!(
            block.commit_world_overlay_for_testing(),
            Err(crate::state::storage_transactions::TransactionsBlockError::LocalStateStorage(actual))
                if actual == refusal
        ));
        assert_eq!(state.view().height(), 1);
        assert_eq!(chain.kura().blocks_count(), 1);
        assert_eq!(state.world.state_accumulator.view().get().root(), before);
        assert!(!state.has_committed_entrypoint(signed.hash_as_entrypoint()));
    }
    // Retry through the real native executor with its original captured route and fee owner.
    let proposal = chain.proposal(None, vec![signed.clone()]);
    let committed = chain.commit_proposal(
        proposal,
        Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::empty(),
    );
    assert!(
        committed
            .block()
            .execution_outputs()
            .iter()
            .all(|output| output.result().is_ok())
    );
    assert!(state.has_committed_entrypoint(signed.hash_as_entrypoint()));
    assert_eq!(state.view().height(), 2);
    let fee = work_fee("retry original scope authority");
    let view = state.view();
    for (account, expected) in [
        (ALICE_ID.clone(), 10_000 - fee),
        (SAMPLE_GENESIS_ACCOUNT_ID.clone(), 0),
    ] {
        assert_eq!(
            view.world()
                .assets()
                .get(&AssetId::with_scope(
                    root.fee_asset.clone(),
                    account,
                    AssetBalanceScope::Dataspace(root.scope.dataspace_id()),
                ))
                .map_or_else(Quantity::zero, |value| value.as_ref().clone()),
            Quantity::from(expected)
        );
    }
    assert_eq!(
        view.world()
            .asset_definition(&root.fee_asset)
            .unwrap()
            .total_quantity(),
        &Quantity::from(10_000 - fee),
        "retry burns the original root's exact paid fee"
    );
}

#[test]
fn signed_private_manifest_query_does_not_turn_scope_refusal_into_permanent_error() {
    use crate::smartcontracts::ValidSingularQuery as _;
    use iroha_data_model::{
        query::{error::QueryExecutionFail, smart_contract::FindContractManifestByArtifactId},
        smart_contract::ContractArtifactId,
    };
    let (root, chain) = certified_root();
    let view = chain.state().view();
    let query = FindContractManifestByArtifactId::new(ContractArtifactId::new(
        root.scope.dataspace_id(),
        Hash::new(b"absent artifact in original private root"),
    ));
    assert!(matches!(
        query.execute(&view),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::NotFound
        ))
    ));
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || query.execute(&view),
    )
    .unwrap_err();
    assert!(
        matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(ref reason)
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "scope decoder refusal became a permanent query result: {error:?}",
    );
    assert!(matches!(
        query.execute(&view),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            QueryExecutionFail::NotFound
        ))
    ));
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}

#[test]
fn signed_private_host_query_keeps_scope_refusal_out_of_completed_vm_errors() {
    use crate::smartcontracts::ivm::host::{QueryStateExecute as _, QueryStateRef};
    use iroha_data_model::{
        query::{QueryRequest, smart_contract::FindContractManifestByArtifactId},
        smart_contract::ContractArtifactId,
    };
    let (root, chain) = certified_root();
    let view = chain.state().view();
    let request = || {
        QueryRequest::Singular(
            FindContractManifestByArtifactId::new(ContractArtifactId::new(
                root.scope.dataspace_id(),
                Hash::new(b"absent original artifact for host query"),
            ))
            .into(),
        )
    };
    assert!(
        QueryStateRef::View(&view)
            .execute_optional_singular_query(&ALICE_ID, request(), None)
            .unwrap()
            .0
            .is_none()
    );
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || QueryStateRef::View(&view).execute_optional_singular_query(&ALICE_ID, request(), None),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            ivm::VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        ),
        "local scope refusal became a completed VM error: {error:?}",
    );
    assert!(
        QueryStateRef::View(&view)
            .execute_optional_singular_query(&ALICE_ID, request(), None)
            .unwrap()
            .0
            .is_none()
    );
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}

#[test]
fn signed_private_contract_lookup_does_not_turn_scope_refusal_into_vm_permission_denial() {
    use crate::smartcontracts::ivm::host::{QueryStateRef, QueryStateRefOps as _};
    use iroha_data_model::smart_contract::ContractAddress;
    let (root, chain) = certified_root();
    let view = chain.state().view();
    let address = ContractAddress::derive(
        chain.state().network_id_ref(),
        &ALICE_ID,
        0,
        root.scope.dataspace_id(),
    )
    .unwrap();
    assert!(matches!(
        QueryStateRef::View(&view).contract_instance_by_address(&address),
        Err(ivm::VMError::DecodeError)
    ));
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || QueryStateRef::View(&view).contract_instance_by_address(&address),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            ivm::VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        ),
        "scope read refusal became completed contract authorization: {error:?}"
    );
    assert!(matches!(
        QueryStateRef::View(&view).contract_instance_by_address(&address),
        Err(ivm::VMError::DecodeError)
    ));
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}

#[test]
fn signed_private_registry_lookup_does_not_publish_refusal_as_absence() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    use iroha_data_model::{
        isi::smart_contract_code::{RegisterSmartContractBytes, RegisterSmartContractCode},
        smart_contract::ContractArtifactId,
    };
    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let dataspace = DataSpaceId::new((1_u64 << 40) + 93);
    let (bytes, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku OriginalRegistry {
  hajimari() {}
  kotoage fn main() authorize("CanReadRegistry") {}
}
"#,
        )
        .unwrap();
    let artifact = ContractArtifactId::new(dataspace, manifest.code_hash.unwrap());
    let root = DataspaceChain::with_genesis_instructions(
        parent,
        dataspace,
        vec![
            RegisterSmartContractBytes {
                artifact_id: artifact,
                code: bytes.clone(),
            }
            .into(),
            RegisterSmartContractCode {
                artifact_id: artifact,
                manifest: manifest
                    .try_signed(
                        manifest_signing.context(),
                        manifest_signing.max_frame_bytes(),
                        &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
                    )
                    .expect("sign bounded fixture manifest"),
            }
            .into(),
        ],
    )
    .unwrap();
    let (_, chain) = certify_private_root(root);
    let view = chain.state().view();
    assert_eq!(
        crate::smartcontracts::code::fetch_code_bytes(&view, &artifact),
        Ok(Some(bytes.clone()))
    );
    let called = std::cell::Cell::new(false);
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || crate::smartcontracts::code::with_code_bytes(&view, &artifact, |_| called.set(true)),
    );
    assert!(
        !called.get(),
        "no bytecode consumer may run on an incomplete scope read"
    );
    assert!(
        matches!(refused, Err(crate::execution_attempt::ExecutionAttemptError::Deferred(ref reason)) if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "local refusal was returned as completed registry absence"
    );
    assert_eq!(
        crate::smartcontracts::code::fetch_code_bytes(&view, &artifact),
        Ok(Some(bytes))
    );
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}

#[test]
fn signed_private_snapshot_query_projects_local_refusal_only_at_transport_boundary() {
    use crate::{
        query::snapshot::{CursorMode, SnapshotQueryError, run_on_snapshot_with_mode},
        smartcontracts::isi::query::QueryLimits,
    };
    use iroha_data_model::{
        query::{
            QueryRequest, error::QueryExecutionFail,
            smart_contract::FindContractManifestByArtifactId,
        },
        smart_contract::ContractArtifactId,
    };
    let (root, chain) = certified_root();
    let request = || {
        QueryRequest::Singular(
            FindContractManifestByArtifactId::new(ContractArtifactId::new(
                root.scope.dataspace_id(),
                Hash::new(b"snapshot original missing artifact"),
            ))
            .into(),
        )
    };
    let run = || {
        run_on_snapshot_with_mode(
            chain.state(),
            &chain.state().query_handle,
            &ALICE_ID,
            request(),
            CursorMode::Ephemeral,
            QueryLimits::default(),
        )
    };
    assert!(matches!(
        run(),
        Err(SnapshotQueryError::Execution(QueryExecutionFail::NotFound))
    ));
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        run,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            SnapshotQueryError::Execution(QueryExecutionFail::GasBudgetExceeded)
        ),
        "local refusal did not reach the operational query boundary: {error:?}"
    );
    assert!(matches!(
        run(),
        Err(SnapshotQueryError::Execution(QueryExecutionFail::NotFound))
    ));
    assert_eq!(chain.state().view().height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}

#[test]
fn signed_private_account_permission_read_defers_without_constructing_a_json_token() {
    use iroha_data_model::query::{QueryRequest, account::prelude::FindAccountById};
    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let exact: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::query::CanReadAccountData {
            account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        }
        .into();
    let root = DataspaceChain::with_genesis_instructions(
        parent,
        DataSpaceId::new((1_u64 << 40) + 94),
        vec![iroha_data_model::isi::Grant::account_permission(exact, ALICE_ID.clone()).into()],
    )
    .unwrap();
    let (_, chain) = certify_private_root(root);
    let view = chain.state().view();
    let request =
        QueryRequest::Singular(FindAccountById::new(SAMPLE_GENESIS_ACCOUNT_ID.clone()).into());
    let run = || {
        Executor::Initial.validate_query_with_world_parts(
            view.world(),
            Some(chain.genesis().header()),
            &ALICE_ID,
            &request,
            &view.execution_budget(),
        )
    };
    run().expect("the exact original signed genesis grant authorizes the foreign account");
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        run,
    )
    .expect_err("an incomplete permission-payload read must remain local");
    assert!(
        matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(ref reason)
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "permission-payload refusal became a completed authorization: {error:?}",
    );
    run().expect("the same original signed permission retries without changing authority");
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
}
