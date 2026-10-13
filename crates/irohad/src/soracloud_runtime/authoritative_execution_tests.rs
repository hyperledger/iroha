// Authoritative SoraCloud execution-result regression.
use iroha_data_model::soracloud::SoraAgentRuntimeStatusV1;

fn push_committed_test_block_hash(state: &mut Arc<State>, height: u64) -> Result<()> {
    let view = state.view();
    let next_height = committed_height(&view)
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("test consensus height overflow"))?;
    eyre::ensure!(
        height == next_height,
        "test block height must advance consecutively: expected {next_height}, got {height}"
    );
    let header = BlockHeader::new(
        NonZeroU64::new(height).ok_or_else(|| eyre::eyre!("block height must be non-zero"))?,
        view.latest_block_hash(),
        None,
        0,
        0,
    );
    drop(view);
    Arc::get_mut(state)
        .ok_or_else(|| eyre::eyre!("test state must be uniquely owned while advancing height"))?
        .push_block_hash_for_testing(header.hash());
    Ok(())
}

#[test]
fn execute_apartment_returns_authoritative_status_and_commitment() -> Result<()> {
    let mut state = test_state();
    let apartment = sample_agent_record()?;
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        world.soracloud_agent_apartments_mut_for_testing().insert(
            apartment.manifest.apartment_name.to_string(),
            apartment.clone(),
        );
    }
    push_committed_test_block_hash(&mut state, 1)?;
    let temp_dir = tempfile::tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(canonical_test_runtime_state_dir(&temp_dir)?),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let result = handle
        .execute_apartment(SoracloudApartmentExecutionRequest {
            observed_height: 1,
            observed_block_hash: committed_block_hash(&state.view()),
            apartment_name: apartment.manifest.apartment_name.to_string(),
            process_generation: apartment.process_generation,
            operation: "checkpoint".to_owned(),
            request_commitment: Hash::new(b"checkpoint-request"),
        })
        .map_err(|error| eyre::eyre!("{error:?}"))?;
    assert_eq!(result.status, apartment.runtime_status_at_current_height(1));
    assert!(result.checkpoint_artifact_hash.is_none());
    assert!(result.journal_artifact_hash.is_none());
    assert_ne!(result.result_commitment, Hash::new(b"checkpoint-request"));
    Ok(())
}

#[test]
fn apartment_execution_fails_closed_at_committed_lease_expiry_height() -> Result<()> {
    let mut state = test_state();
    let mut apartment = sample_agent_record()?;
    apartment.lease_expires_height = 2;
    let apartment_name = apartment.manifest.apartment_name.to_string();
    {
        let world = &mut Arc::get_mut(&mut state).expect("unique test state").world;
        world
            .soracloud_agent_apartments_mut_for_testing()
            .insert(apartment_name.clone(), apartment.clone());
    }

    push_committed_test_block_hash(&mut state, 1)?;
    let temp_dir = tempfile::tempdir()?;
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(canonical_test_runtime_state_dir(&temp_dir)?),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let active_request = SoracloudApartmentExecutionRequest {
        observed_height: 1,
        observed_block_hash: committed_block_hash(&state.view()),
        apartment_name: apartment_name.clone(),
        process_generation: apartment.process_generation,
        operation: "checkpoint".to_owned(),
        request_commitment: Hash::new(b"active-apartment-request"),
    };
    let active = handle
        .execute_apartment(active_request)
        .map_err(|error| eyre::eyre!(error))?;
    assert_eq!(active.status, SoraAgentRuntimeStatusV1::Running);

    drop(handle);
    drop(manager);
    push_committed_test_block_hash(&mut state, 2)?;
    assert_eq!(
        committed_height(&state.view()),
        apartment.lease_expires_height
    );
    assert_eq!(
        state
            .view()
            .world()
            .soracloud_agent_apartments()
            .get(&apartment_name)
            .expect("apartment remains authoritative")
            .runtime_status_at_current_height(apartment.lease_expires_height),
        SoraAgentRuntimeStatusV1::LeaseExpired,
        "authoritative row status must be derived at the committed height boundary"
    );
    let manager = SoracloudRuntimeManager::new(
        test_runtime_manager_config(canonical_test_runtime_state_dir(&temp_dir)?),
        Arc::clone(&state),
    );
    manager.reconcile_once()?;
    let handle = test_runtime_handle(&manager, Arc::clone(&state));
    let snapshot = handle.snapshot();
    assert_eq!(
        snapshot
            .apartments
            .get(&apartment_name)
            .expect("expired apartment remains projected")
            .status,
        SoraAgentRuntimeStatusV1::LeaseExpired
    );

    let error = handle
        .execute_apartment(SoracloudApartmentExecutionRequest {
            observed_height: apartment.lease_expires_height,
            observed_block_hash: committed_block_hash(&state.view()),
            apartment_name,
            process_generation: apartment.process_generation,
            operation: "checkpoint".to_owned(),
            request_commitment: Hash::new(b"expired-apartment-request"),
        })
        .expect_err("an apartment at its lease-expiry height must not execute");
    assert_eq!(error.kind, SoracloudRuntimeExecutionErrorKind::Unavailable);
    assert!(
        error
            .message
            .contains("lease expired at consensus height 2")
    );
    Ok(())
}
