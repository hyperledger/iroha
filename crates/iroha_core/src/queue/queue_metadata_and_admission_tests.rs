#[test]
fn queue_metadata_cleared_on_commit_and_clear_all() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push tx");
    let _ = queue.gossip_batch(1, &state.view());
    let removed = queue.remove_committed_hashes(std::iter::once(hash), None);
    assert_eq!(removed, 1);
    assert!(queue.tx_encoded_len.is_empty());
    assert!(queue.tx_gas_cost.is_empty());
    let tx = accepted_tx_by_someone(&time_source);
    queue.push(tx, state.view()).expect("push tx");
    assert!(!queue.tx_encoded_len.is_empty());
    let _ = queue.gossip_batch(1, &state.view());
    queue.clear_all();
    assert!(queue.tx_encoded_len.is_empty());
    assert!(queue.tx_gas_cost.is_empty());
}
#[test]
fn queue_reuses_gossip_payload_without_side_cache() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    // Gossip admission uses network time. Anchor the signed fixture to that
    // clock, with room for another test to update its offset concurrently.
    let network_now = crate::time::admission_snapshot()
        .status
        .now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("network admission time follows the Unix epoch");
    let (_clock, time_source) =
        TimeSource::new_mock(network_now.saturating_sub(Duration::from_secs(10)));
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let entrypoint = tx.entrypoint().clone();
    let entrypoint_hash = tx.hash_as_entrypoint();
    let payload = tx.entrypoint_bytes();
    let default_limits = TransactionParameters::default();
    let tx_limits = TransactionParameters::with_max_signatures(
        nonzero!(16_u64),
        nonzero!(4096_u64),
        nonzero!(1024_u64),
        default_limits.max_tx_bytes(),
        default_limits.max_decompressed_bytes(),
        default_limits.max_metadata_depth(),
    );
    let crypto_cfg = iroha_config::parameters::actual::Crypto::default();
    let tx = AcceptedTransaction::accept_gossip_entrypoint_with_payload(
        entrypoint,
        Arc::clone(&payload),
        entrypoint_hash,
        &queue_test_network_id(),
        Duration::from_millis(10),
        tx_limits,
        &crypto_cfg,
    )
    .expect("accept gossip entrypoint with cached payload");
    let hash = tx.hash_as_entrypoint();
    assert!(
        Arc::ptr_eq(&tx.entrypoint_bytes(), &payload),
        "accepted gossip transaction should reuse inbound entrypoint bytes"
    );
    queue.push(tx, state.view()).expect("push tx with payload");
    let encoded_len = queue
        .tx_encoded_len
        .get(&hash)
        .map(|entry| *entry.value())
        .expect("encoded len stored");
    assert_eq!(encoded_len, payload.len());
    let batch = queue.gossip_batch_with_state(1, &state);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload.as_slice(), payload.as_slice());
    assert!(
        Arc::ptr_eq(&batch[0].payload, &payload),
        "gossip should reuse inbound entrypoint bytes"
    );
}
#[test]
fn queue_reuses_gossip_payload_without_side_cache_in_shared_view() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let payload = tx.entrypoint_bytes();
    let state_view = state.view();
    queue
        .push_in_view(tx, &state_view)
        .expect("push tx with payload through shared view");
    let batch = queue.gossip_batch(1, &state_view);
    assert_eq!(batch.len(), 1);
    assert!(Arc::ptr_eq(&batch[0].payload, &payload));
}
#[test]
fn queue_reuses_gossip_payload_without_side_cache_with_state() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let payload = tx.entrypoint_bytes();
    queue
        .push_with_lane_with_state(tx, &state)
        .expect("push tx with payload through state");
    let batch = queue.gossip_batch_with_state(1, &state);
    assert_eq!(batch.len(), 1);
    assert!(Arc::ptr_eq(&batch[0].payload, &payload));
}
#[test]
fn queue_generated_gossip_payload_uses_framed_entrypoint_wire() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let cached_payload = tx.entrypoint_bytes();
    let expected_payload = ncore::to_bytes(tx.entrypoint()).expect("encode transaction entrypoint");
    queue.push(tx, state.view()).expect("push tx");
    let batch = queue.gossip_batch(1, &state.view());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload.as_slice(), expected_payload.as_slice());
    assert!(
        Arc::ptr_eq(&batch[0].payload, &cached_payload),
        "queue gossip should reuse accepted transaction entrypoint bytes"
    );
}
#[test]
fn sealed_commitment_uses_local_queue_residence_ttl() {
    let (time_handle, time_source) = TimeSource::new_mock(Duration::from_secs(3600));
    let queue = Queue::test(
        Config {
            transaction_time_to_live: Duration::from_secs(1),
            expired_cull_interval: Duration::from_secs(1),
            ..config_factory()
        },
        &time_source,
    );
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let network_id = state.network_id;
    let (authority, keypair) = gen_account_in("wonderland");
    register_test_authority(&state, &authority);
    let inner_tx = TransactionBuilder::new_with_time_source(
        network_id,
        authority.clone(),
        &time_source,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "sealed queue expiry inner".to_owned(),
    )])
    .sign(keypair.private_key());
    let salt = [0xD4; 32];
    let reveal_deadline_height = 10;
    let commitment_hash =
        compute_sealed_transaction_commitment(&network_id, &inner_tx, salt, reveal_deadline_height);
    let payload = SealedTransactionCommitmentPayload::new(
        network_id,
        authority,
        commitment_hash,
        2,
        reveal_deadline_height,
        None,
    );
    let commitment = SignedSealedTransactionCommitment::sign(payload, keypair.private_key());
    let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Owned(
        TransactionEntrypoint::SealedCommitment(commitment),
    ));
    assert!(
        !queue.is_expired(&accepted),
        "a commitment has no queue residence before admission"
    );
    queue
        .push(accepted, state.view())
        .expect("sealed commitment admission");
    time_handle.advance(Duration::from_secs(2));
    assert_eq!(
        queue.cull_expired_entries_if_due(),
        1,
        "a commitment that never reaches a block must not become a permanent queue entry"
    );
    assert_eq!(queue.active_len(), 0);
}
#[test]
fn push_in_view_accepts_multiple_transactions_with_shared_snapshot() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let state_view = state.view();
    queue
        .push_in_view(accepted_tx_by_someone(&time_source), &state_view)
        .expect("first push");
    queue
        .push_in_view(accepted_tx_by_someone(&time_source), &state_view)
        .expect("second push");
    assert_eq!(queue.queued_len(), 2);
}
#[test]
fn push_with_lane_with_state_accepts_multiple_transactions() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    queue
        .push_with_lane_with_state(accepted_tx_by_someone(&time_source), &state)
        .expect("first push");
    queue
        .push_with_lane_with_state(accepted_tx_by_someone(&time_source), &state)
        .expect("second push");
    assert_eq!(queue.queued_len(), 2);
}
#[test]
fn push_with_lane_with_state_rejects_committed_transaction() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    let tx_hash = tx.hash_as_entrypoint();
    {
        let mut transactions = state.transactions.block();
        transactions.insert_block_with_single_tx(tx_hash, nonzero!(1_usize));
        transactions
            .commit()
            .expect("transactions block should commit");
    }
    let err = queue
        .push_with_lane_with_state(tx, &state)
        .expect_err("committed transaction must be rejected");
    assert!(matches!(err.err, Error::InBlockchain));
    assert_eq!(err.tx.as_ref().hash_as_entrypoint(), tx_hash);
}
#[test]
fn push_with_lane_with_state_rejects_unresolved_route() {
    struct UnresolvedRouter;
    impl LaneRouter for UnresolvedRouter {
        fn try_route(
            &self,
            _tx: &dyn TransactionRoutingView,
        ) -> Result<RoutingDecision, RoutingResolveError> {
            Ok(RoutingDecision::new(LaneId::new(99), DataSpaceId::new(77)))
        }
    }
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test_with_router(config_factory(), &time_source, Arc::new(UnresolvedRouter));
    let tx = accepted_tx_by_someone(&time_source);
    let err = queue
        .push_with_lane_with_state(tx, &state)
        .expect_err("unresolved route must be rejected");
    assert!(matches!(err.err, Error::UnresolvedRoute { .. }));
    if let Error::UnresolvedRoute { reason } = &err.err {
        assert!(
            reason.contains("lane"),
            "route rejection reason should include lane lookup failure"
        );
    }
}
#[test]
fn contains_pending_hash_ignores_committed_entries() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    register_accepted_tx_authority_for_queue_test(&mut state, &tx);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push tx");
    assert!(queue.contains_pending_hash(hash, &state));
    {
        let mut transactions = state.transactions.block();
        transactions.insert_block_with_single_tx(hash, nonzero!(1_usize));
        transactions
            .commit()
            .expect("transactions block should commit");
    }
    assert!(!queue.contains_pending_hash(hash, &state));
}
#[test]
fn contains_pending_hash_waiting_for_state_does_not_pin_queue_removal() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    register_accepted_tx_authority_for_queue_test(&mut state, &tx);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push tx");
    assert!(queue.contains_pending_hash(hash, &state));
    let generation = state.state_view_generation();
    let original_hashes = state
        .view()
        .block_hashes
        .iter()
        .copied()
        .collect::<Vec<_>>();

    // The real publication writer blocks State::view at its first hash read. Its
    // original journal is aborted after the concurrency cut; nothing is published.
    let hashes = state.block_hashes.block().detach();
    let writer = hashes
        .try_prepare_publication(&state.block_hashes, |_, _| {
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap_or_else(|(_, error, _)| panic!("prepare original hash writer: {error:?}"));
    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
    *queue.pending_hash_state_view_handoff.lock() = Some(reached_tx);
    let (lookup_tx, lookup_rx) = std::sync::mpsc::sync_channel(1);
    let (removed_tx, removed_rx) = std::sync::mpsc::sync_channel(1);
    let timeout = Duration::from_secs(5);
    let (reached, removed_while_held, lookup_while_held, lookup, removal) =
        std::thread::scope(|scope| {
            let lookup = scope.spawn(|| {
                let pending = queue.contains_pending_hash(hash, &state);
                let _ = lookup_tx.send(pending);
                pending
            });
            let reached = reached_rx.recv_timeout(timeout);
            let removal = scope.spawn(|| {
                let removed = queue.remove_committed_hashes([hash], None);
                let _ = removed_tx.send(removed);
                removed
            });
            let removed_while_held = removed_rx.recv_timeout(timeout);
            let lookup_while_held = lookup_rx.try_recv();

            // Release the physical blocker before assertions or joins even if a
            // regressed lookup pins the shard and removal cannot finish. Buffered
            // notifications and closed receivers cannot strand either worker.
            drop(writer.abort());
            drop(reached_rx);
            drop(removed_rx);
            drop(lookup_rx);
            let lookup = lookup.join();
            let removal = removal.join();
            (
                reached,
                removed_while_held,
                lookup_while_held,
                lookup,
                removal,
            )
        });

    assert_eq!(
        reached,
        Ok(()),
        "lookup reached its actual State view boundary"
    );
    assert_eq!(
        removed_while_held,
        Ok(1),
        "Queue removal must complete while the original State hash writer is held"
    );
    assert!(matches!(
        lookup_while_held,
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(!lookup.expect("pending lookup thread"));
    assert_eq!(removal.expect("queue removal thread"), 1);
    assert!(!queue.contains_entrypoint_hash(hash));
    assert!(!queue.contains_pending_hash(hash, &state));
    assert_eq!(queue.active_len(), 0);
    assert!(!queue.admission_faulted());
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(
        state
            .view()
            .block_hashes
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        original_hashes
    );
    assert!(!state.view().has_entrypoint(hash));
}
#[test]
fn gossip_batch_with_state_removes_committed_entries() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let tx = accepted_tx_by_someone(&time_source);
    register_accepted_tx_authority_for_queue_test(&mut state, &tx);
    let hash = tx.hash_as_entrypoint();
    queue.push(tx, state.view()).expect("push tx");
    {
        let mut transactions = state.transactions.block();
        transactions.insert_block_with_single_tx(hash, nonzero!(1_usize));
        transactions
            .commit()
            .expect("transactions block should commit");
    }
    let batch = queue.gossip_batch_with_state(1, &state);
    assert!(
        batch.is_empty(),
        "committed transaction must not be selected for gossip"
    );
    assert_eq!(queue.active_len(), 0);
    assert_eq!(queue.queued_len(), 0);
    assert!(!queue.current_backpressure().is_saturated());
}
#[tokio::test]
async fn push_rejects_without_governance_manifest() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    #[cfg(feature = "telemetry")]
    let metrics = Arc::new(Metrics::default());
    #[cfg(feature = "telemetry")]
    let state = Arc::new(State::with_telemetry(
        world_with_test_domains(),
        kura.clone(),
        query_handle.clone(),
        StateTelemetry::new(metrics.clone(), true),
    ));
    #[cfg(not(feature = "telemetry"))]
    let state = State::new(world_with_test_domains(), kura, query_handle);
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let mut statuses = BTreeMap::new();
    statuses.insert(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "default".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_string()),
            manifest_path: None,
            governance_rules: None,
            privacy_commitments: Vec::new(),
        },
    );
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.install_lane_manifests_for_testing(&manifests);
    let result = queue.push(accepted_tx_by_someone(&time_source), state.view());
    assert!(matches!(
        result,
        Err(Failure {
            err: Error::Governance(_),
            ..
        })
    ));
    #[cfg(feature = "telemetry")]
    assert_eq!(
        metrics
            .governance_manifest_admission_total
            .with_label_values(&["missing_manifest"])
            .get(),
        1
    );
}
/// Preserve the signed operation while targeting the fixture's actual configured dataspace.
fn accepted_uaid_dataspace_tx(
    state: &State,
    dataspace: DataSpaceId,
    account: &AccountId,
    key_pair: &KeyPair,
    time_source: &TimeSource,
) -> AcceptedTransaction<'static> {
    let nexus = state.nexus_snapshot();
    let alias = &nexus
        .dataspace_catalog
        .by_id(dataspace)
        .expect("fixture target dataspace exists")
        .alias;
    let target = DomainId::try_new(&unique_test_domain_name("uaid"), alias)
        .expect("domain in the actual configured target dataspace");
    let tx = accepted_tx_with(
        account.clone(),
        key_pair,
        time_source,
        vec![Unregister::domain(target).into()],
        Metadata::default(),
    );
    let plan = ConfigLaneRouter::new(
        nexus.routing_policy,
        nexus.dataspace_catalog,
        nexus.lane_catalog,
    )
    .try_route_plan_with_view(&tx, &state.view())
    .expect("signed instruction must resolve before UAID compliance is tested");
    assert_eq!(
        plan,
        RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, dataspace)),
        "the actual instruction and the fixture router must name the same route"
    );
    tx
}

#[tokio::test]
async fn uaid_without_dataspace_binding_is_rejected() {
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::missing-binding"));
    let dataspace = DataSpaceId::new(7);
    let (world, account_id, key_pair) = world_with_uaid_account(uaid, dataspace, false);
    let nexus = test_nexus_for_routes(&[(LaneId::SINGLE, dataspace)]);
    let query_handle = LiveQueryStore::start_test();
    #[cfg(feature = "telemetry")]
    let metrics = Arc::new(Metrics::default());
    #[cfg(feature = "telemetry")]
    let state = Arc::new(new_queue_test_state_with_telemetry(
        world,
        nexus,
        query_handle,
        StateTelemetry::new(metrics.clone(), true),
    ));
    #[cfg(not(feature = "telemetry"))]
    let state = Arc::new(State::new_with_nexus_for_testing(
        world,
        nexus,
        query_handle,
    ));
    #[cfg(feature = "telemetry")]
    assert!(std::ptr::eq(
        state.metrics().metrics_ref(),
        metrics.as_ref()
    ));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let router: Arc<dyn LaneRouter> = Arc::new(StaticRouter {
        lane: LaneId::SINGLE,
        dataspace,
    });
    let queue = Arc::new(Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        router.clone(),
        &[(LaneId::SINGLE, dataspace)],
    ));
    let mut statuses = BTreeMap::new();
    statuses.insert(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "uaid-enforcement".to_string(),
            dataspace,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: None,
            manifest_path: None,
            governance_rules: None,
            privacy_commitments: Vec::new(),
        },
    );
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.install_lane_manifests_for_testing(&manifests);
    let result = queue.push(
        accepted_uaid_dataspace_tx(&state, dataspace, &account_id, &key_pair, &time_source),
        state.view(),
    );
    match result {
        Err(Failure {
            err: Error::LaneComplianceDenied { reason, .. },
            ..
        }) => assert!(
            reason.contains("not bound to dataspace"),
            "expected missing dataspace binding rejection, got {reason}"
        ),
        other => panic!("expected missing dataspace binding rejection, got {other:?}"),
    }
}
#[tokio::test]
async fn space_directory_manifest_publish_bypasses_uaid_binding_admission() {
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::manifest-publish"));
    let manifest_dataspace = DataSpaceId::new(10);
    let (world, account_id, key_pair) = world_with_uaid_account(uaid, manifest_dataspace, false);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world, kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: LaneId::SINGLE,
            dataspace: DataSpaceId::UNIVERSAL,
        }),
    );
    let manifest = AssetPermissionManifest {
        version: ManifestVersion::default(),
        uaid,
        dataspace: manifest_dataspace,
        issued_ms: 1,
        activation_epoch: 0,
        expiry_epoch: None,
        entries: Vec::new(),
    };
    let tx = accepted_tx_with(
        account_id,
        &key_pair,
        &time_source,
        vec![
            iroha_data_model::isi::space_directory::PublishSpaceDirectoryManifest { manifest }
                .into(),
        ],
        Metadata::default(),
    );
    queue
        .push(tx, state.view())
        .expect("manifest publication creates the UAID dataspace binding");
}
#[tokio::test]
async fn uaid_binding_allows_lane_identity_extraction() {
    let dataspace = DataSpaceId::new(11);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::bound"));
    let (world, account_id, key_pair) = world_with_uaid_account(uaid, dataspace, true);
    let nexus = test_nexus_for_routes(&[(LaneId::SINGLE, dataspace)]);
    let query_handle = LiveQueryStore::start_test();
    #[cfg(feature = "telemetry")]
    let metrics = Arc::new(Metrics::default());
    #[cfg(feature = "telemetry")]
    let state = Arc::new(new_queue_test_state_with_telemetry(
        world,
        nexus,
        query_handle,
        StateTelemetry::new(metrics.clone(), true),
    ));
    #[cfg(not(feature = "telemetry"))]
    let state = Arc::new(State::new_with_nexus_for_testing(
        world,
        nexus,
        query_handle,
    ));
    #[cfg(feature = "telemetry")]
    assert!(std::ptr::eq(
        state.metrics().metrics_ref(),
        metrics.as_ref()
    ));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let router: Arc<dyn LaneRouter> = Arc::new(StaticRouter {
        lane: LaneId::SINGLE,
        dataspace,
    });
    let queue = Arc::new(Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        router.clone(),
        &[(LaneId::SINGLE, dataspace)],
    ));
    let mut statuses = BTreeMap::new();
    statuses.insert(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "uaid-binding".to_string(),
            dataspace,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: None,
            manifest_path: None,
            governance_rules: None,
            privacy_commitments: Vec::new(),
        },
    );
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.install_lane_manifests_for_testing(&manifests);
    queue
        .push(
            accepted_uaid_dataspace_tx(&state, dataspace, &account_id, &key_pair, &time_source),
            state.view(),
        )
        .expect("UAID with active dataspace binding should be admitted");
}
#[tokio::test]
async fn uaid_routing_rejects_foreign_dataspace_without_binding() {
    let bound = DataSpaceId::new(42);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::rebind"));
    let (world, account_id, key_pair) = world_with_uaid_account(uaid, bound, true);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = Arc::new(State::new(world, kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let target = DataSpaceId::UNIVERSAL;
    let queue = Queue::test_with_router(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: LaneId::SINGLE,
            dataspace: target,
        }),
    );
    let result = queue.push(
        accepted_tx_by(account_id.clone(), &key_pair, &time_source),
        state.view(),
    );
    match result {
        Err(Failure {
            err: Error::LaneComplianceDenied { reason, .. },
            ..
        }) => assert!(
            reason.contains("not bound to dataspace"),
            "expected missing dataspace binding rejection, got {reason}"
        ),
        other => panic!("expected missing dataspace binding rejection, got {other:?}"),
    }
}
#[tokio::test]
async fn uaid_binding_allows_matching_dataspace() {
    let dataspace = DataSpaceId::new(24);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::aligned"));
    let (world, account_id, key_pair) = world_with_uaid_account(uaid, dataspace, true);
    let state = Arc::new(State::new_with_nexus_for_testing(
        world,
        test_nexus_for_routes(&[(LaneId::SINGLE, dataspace)]),
        LiveQueryStore::start_test(),
    ));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: LaneId::SINGLE,
            dataspace,
        }),
        &[(LaneId::SINGLE, dataspace)],
    );
    queue
        .push(
            accepted_uaid_dataspace_tx(&state, dataspace, &account_id, &key_pair, &time_source),
            state.view(),
        )
        .expect("UAID bound to dataspace should be admitted");
}
#[tokio::test]
async fn uaid_with_inactive_target_dataspace_manifest_is_rejected() {
    let dataspace = DataSpaceId::new(24);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"uaid::inactive-manifest"));
    let (mut world, account_id, key_pair) = world_with_uaid_account(uaid, dataspace, true);
    let mut set = world
        .space_directory_manifests
        .view()
        .get(&uaid)
        .cloned()
        .expect("manifest set must exist");
    let record = set
        .get(&dataspace)
        .cloned()
        .expect("manifest record must exist");
    let mut inactive = record;
    inactive.lifecycle.mark_expired(2);
    set.upsert(inactive);
    world.space_directory_manifests.insert(uaid, set);
    let state = Arc::new(State::new_with_nexus_for_testing(
        world,
        test_nexus_for_routes(&[(LaneId::SINGLE, dataspace)]),
        LiveQueryStore::start_test(),
    ));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test_with_router_for_routes(
        config_factory(),
        &time_source,
        Arc::new(StaticRouter {
            lane: LaneId::SINGLE,
            dataspace,
        }),
        &[(LaneId::SINGLE, dataspace)],
    );
    let result = queue.push(
        accepted_uaid_dataspace_tx(&state, dataspace, &account_id, &key_pair, &time_source),
        state.view(),
    );
    match result {
        Err(Failure {
            err: Error::LaneComplianceDenied { .. },
            ..
        }) => {}
        other => panic!("expected inactive manifest rejection, got {other:?}"),
    }
}
