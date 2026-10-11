//! Catalog and recovery assertions on the fixture's real beacon-custody network.
//!
//! The caller owns daemon startup/restart and signed-snapshot observation. This
//! module retains the exact four-peer execution proofs and permissions across
//! those phase boundaries, using the parent module's native finality cache and
//! fixed canonical result-bearing carrier reader.
use super::*;
use iroha::client::Client;
use iroha_genesis::ValidatedGenesisBundle;
use std::path::PathBuf;

pub(crate) struct CatalogPeer {
    pub client: Client,
    pub peer_id: PeerId,
    pub kura_store: PathBuf,
}

pub(crate) struct CatalogFixture {
    pub peers: [CatalogPeer; 4],
    pub writer: Client,
    pub genesis: ValidatedGenesisBundle,
    /// Independently selected chain label from the validated genesis manifest.
    pub chain_id: String,
    /// Exact immutable configured dataspace catalog, before runtime additions.
    pub baseline_dataspaces: DataSpaceCatalog,
    /// Exact expected effective lane catalog at the beginning of this scenario.
    pub baseline_lanes: Vec<LaneConfig>,
    /// Independently expected earlier runtime additions, if another scenario ran first.
    pub previous_runtime: Option<NexusRuntimeCatalogV1>,
    pub old_route: (LaneId, DataSpaceId),
    pub added_lane: LaneId,
    pub added_dataspace: DataSpaceId,
    pub delegator: AccountId,
    pub grantee: AccountId,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    FullReplay,
    SnapshotRestore,
    Complete,
}

pub(crate) struct CatalogScenario {
    fixture: CatalogFixture,
    finality: FixtureFinality,
    before: LaneLifecycleStatusV1,
    after: LaneLifecycleStatusV1,
    runtime: NexusRuntimeCatalogV1,
    history: Vec<AppliedEvidence>,
    committee: Vec<PeerId>,
    phase: Phase,
}

pub(crate) fn delegation_role(delegator: AccountId, dataspace: DataSpaceId) -> InstructionBox {
    Register::role(
        Role::new(
            "runtime_catalog_resolution_delegate"
                .parse()
                .expect("role id"),
            delegator,
        )
        .add_permission(delegation_permission(dataspace)),
    )
    .into()
}

fn delegation_permission(dataspace: DataSpaceId) -> Permission {
    CanDelegateAccountAliasResolution {
        scope: AccountAliasPermissionScope::Dataspace(dataspace),
    }
    .into()
}

fn permission(dataspace: DataSpaceId) -> Permission {
    CanResolveAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(dataspace),
    }
    .into()
}

fn finality_from_genesis(fixture: &CatalogFixture) -> Result<FixtureFinality> {
    let genesis_hash = fixture.genesis.expected_hash();
    let network_id = NetworkId::from_genesis_hash(genesis_hash);
    let validators: BTreeMap<_, _> = fixture
        .genesis
        .validator_pops()
        .iter()
        .map(|(key, pop)| (PeerId::new(key.clone()), pop.clone()))
        .collect();
    let actual: BTreeSet<_> = fixture
        .peers
        .iter()
        .map(|peer| peer.peer_id.clone())
        .collect();
    ensure!(
        validators.len() == 4
            && actual.len() == 4
            && validators.keys().cloned().collect::<BTreeSet<_>>() == actual
            && validators.values().all(|pop| !pop.is_empty()),
        "catalog readers differ from the exact four validators and PoPs in signed genesis"
    );
    ensure!(
        fixture.writer.account_client()?.network_id() == &network_id
            && fixture.writer.account_client()?.authority() == &fixture.delegator,
        "catalog clients do not bind the exact genesis network and delegator"
    );
    for peer in &fixture.peers {
        ensure!(
            peer.client.account_client()?.network_id() == &network_id,
            "catalog reader belongs to a different genesis network"
        );
    }
    let peers = fixture
        .peers
        .iter()
        .map(|peer| {
            (
                peer.peer_id.clone(),
                Arc::new(Mutex::new(VerifiedPeerFinality {
                    network_id,
                    genesis_hash,
                    peer: peer.peer_id.clone(),
                    verifier: None,
                    verified: BTreeMap::new(),
                })),
            )
        })
        .collect();
    ensure!(
        fixture.genesis.consensus_metadata().mode
            == iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
        "catalog fixture requires signed NPoS genesis authority"
    );
    let validators = validators
        .into_iter()
        .map(|(peer, proof_of_possession)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession,
        })
        .collect();
    Ok(FixtureFinality {
        network_id,
        genesis_hash,
        trusted_genesis: fixture.genesis.block().clone(),
        chain_id: fixture.chain_id.clone(),
        validators,
        peers,
    })
}

async fn lifecycle_and_runtime(
    peer: &CatalogPeer,
) -> Result<(LaneLifecycleStatusV1, Option<NexusRuntimeCatalogV1>)> {
    let client = peer.client.clone();
    read_on_dedicated_thread(move || {
        let status = client.get_lane_lifecycle_status()?;
        status.validate()?;
        let parameters = client.get_parameters()?;
        let runtime = parameters
            .custom()
            .get(&NexusRuntimeCatalogV1::parameter_id())
            .map(NexusRuntimeCatalogV1::from_custom_parameter)
            .transpose()?
            .flatten();
        ensure!(
            status.runtime_catalog_hash
                == runtime
                    .as_ref()
                    .map(NexusRuntimeCatalogV1::canonical_hash)
                    .transpose()?,
            "lifecycle runtime catalog hash differs from authenticated overlay"
        );
        Ok((status, runtime))
    })
    .await
}

async fn current_manifest(
    fixture: &CatalogFixture,
) -> Result<(RuntimeLaneManifestV1, Vec<PeerId>)> {
    let client = fixture.peers[0].client.clone();
    let roster =
        read_on_dedicated_thread(move || client.get_public_lane_validators(LaneId::new(0))).await?;
    let items = roster
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("live lane-0 roster omitted items"))?;
    ensure!(
        items.len() == 4,
        "manifest must bind exactly the four live validators"
    );
    let mut bindings = Vec::new();
    let mut validators = BTreeSet::new();
    let mut peers = BTreeSet::new();
    for item in items {
        ensure!(
            item.get("status")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("Active"),
            "manifest source contains an inactive validator"
        );
        let validator = item
            .get("validator")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("live roster omitted validator account"))?;
        let peer = item
            .get("peer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("live roster omitted consensus peer"))?;
        let parsed_peer: PeerId = peer.parse()?;
        ensure!(
            validators.insert(validator.to_owned()) && peers.insert(parsed_peer),
            "live roster repeats an identity"
        );
        bindings.push(norito::json!({"validator": validator, "peer_id": peer}));
    }
    let expected_peers: BTreeSet<_> = fixture
        .peers
        .iter()
        .map(|peer| peer.peer_id.clone())
        .collect();
    ensure!(
        peers == expected_peers,
        "manifest peers differ from the actual running cohort"
    );
    Ok((
        RuntimeLaneManifestV1 {
            lane_id: fixture.added_lane,
            manifest: Json::from_norito_value_ref(&norito::json!({
                "lane": "runtime-committee", "version": 1, "validators": bindings, "quorum": 3,
            }))?,
        },
        peers.into_iter().collect(),
    ))
}

async fn exact_applied_height(
    fixture: &CatalogFixture,
    transaction: &SignedTransaction,
) -> Result<u64> {
    let hash = transaction.hash();
    let expected_hex = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let deadline = Instant::now() + FUNCTIONAL_FINALITY_TIMEOUT;
    timeout_at(deadline, async {
        loop {
            let observations = try_join_all(fixture.peers.iter().map(|peer| async move {
                let client = peer.client.clone();
                let status = validator_status_until(&client, deadline).await?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                ensure!(
                    !remaining.is_zero(),
                    "catalog transaction observation exceeded its deadline"
                );
                let mut builder = client.to_builder();
                builder.torii_request_timeout =
                    iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT.min(remaining);
                let client = builder.build()?;
                let local = read_on_dedicated_thread(move || {
                    client.get_transaction_status_response_local(hash)
                })
                .await?;
                Ok::<_, eyre::Report>((status.blocks, local))
            }))
            .await?;
            let heights = observations
                .iter()
                .map(|(tip, response)| {
                    response
                        .as_ref()
                        .filter(|response| {
                            response.hash == expected_hex
                                && response.scope == "local"
                                && response.resolved_from == "state"
                                && response.status.kind == "Applied"
                        })
                        .and_then(|response| response.status.block_height)
                        .filter(|height| *height > 1 && *tip >= *height)
                })
                .collect::<Option<Vec<_>>>();
            if let Some(heights) = heights {
                ensure!(
                    heights.iter().all(|height| *height == heights[0]),
                    "four peers disagree on the applied height"
                );
                return Ok(heights[0]);
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .wrap_err("four-peer catalog transaction did not reach exact local Applied")?
}

async fn canonical_execution(
    finality: &FixtureFinality,
    peer: &CatalogPeer,
    transaction: &SignedTransaction,
    height: u64,
    lane: LaneId,
    dataspace: DataSpaceId,
    expected_committee: Option<&[PeerId]>,
) -> Result<Vec<u8>> {
    // One absolute deadline covers the complete authenticated history read.
    // Bridge finality proofs consume Torii's heavy-query burst and may return
    // Retry-After; the client retries that backpressure only with a deadline.
    let client = peer
        .client
        .with_request_deadline(std::time::Instant::now() + FUNCTIONAL_FINALITY_TIMEOUT);
    let finality = finality.clone();
    let peer = CatalogPeer {
        client,
        peer_id: peer.peer_id.clone(),
        kura_store: peer.kura_store.clone(),
    };
    let transaction = transaction.clone();
    let expected_committee = expected_committee.map(<[PeerId]>::to_vec);
    read_on_dedicated_thread(move || {
        authenticated_native_execution(
            &finality,
            &peer,
            &transaction,
            height,
            RoutingDecision::new(lane, dataspace),
            expected_committee.as_deref(),
        )
    })
    .await
}

async fn submit_on_route(
    fixture: &CatalogFixture,
    finality: &FixtureFinality,
    instructions: Vec<InstructionBox>,
    lane: LaneId,
    dataspace: DataSpaceId,
    committee: Option<&[PeerId]>,
) -> Result<AppliedEvidence> {
    let mut builder = fixture.writer.to_builder();
    builder.transaction_status_timeout = FUNCTIONAL_FINALITY_TIMEOUT;
    let client = builder.build()?;
    let account = client.account_client()?;
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions,
        FeePaymentIntent::authority(Vec::new(), None),
        Metadata::default(),
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    let transaction = account.sign_transaction(payload)?;
    ensure!(
        account.submit_transaction_and_wait(&transaction).await? == transaction.hash(),
        "submission changed transaction identity"
    );
    let height = exact_applied_height(fixture, &transaction).await?;
    let wires = try_join_all(fixture.peers.iter().map(|peer| {
        canonical_execution(
            finality,
            peer,
            &transaction,
            height,
            lane,
            dataspace,
            committee,
        )
    }))
    .await?;
    ensure!(
        wires.iter().all(|wire| *wire == wires[0]),
        "peers disagree on the exact executed block wire"
    );
    Ok(AppliedEvidence {
        transaction,
        height,
        lane,
        dataspace,
        canonical_block: wires[0].clone(),
    })
}

async fn assert_resolution_delegation(fixture: &CatalogFixture) -> Result<()> {
    try_join_all(fixture.peers.iter().map(|peer| async move {
        let client = peer.client.clone();
        let delegator = fixture.delegator.clone();
        let permissions =
            read_on_dedicated_thread(move || effective_permissions(&client, &delegator)).await?;
        ensure!(
            permissions.contains(&delegation_permission(fixture.added_dataspace)),
            "peer lost the delegator's exact dataspace alias-resolution delegation"
        );
        Ok::<(), eyre::Report>(())
    }))
    .await?;
    Ok(())
}

async fn assert_catalog_and_history(
    scenario: &CatalogScenario,
    permission_present: bool,
) -> Result<()> {
    let CatalogScenario {
        fixture,
        finality,
        before,
        after,
        runtime: expected_runtime,
        history,
        committee,
        ..
    } = scenario;
    assert_resolution_delegation(fixture).await?;
    try_join_all(fixture.peers.iter().map(|peer| async move {
        let (status, runtime) = lifecycle_and_runtime(peer).await?;
        ensure!(
            status == *after && runtime.as_ref() == Some(expected_runtime),
            "peer lost committed topology or inline manifests"
        );
        ensure!(
            before.lanes.iter().all(|lane| status.lanes.contains(lane))
                && before
                    .incarnations
                    .iter()
                    .all(|incarnation| status.incarnations.contains(incarnation)),
            "catalog expansion changed an old lane or incarnation"
        );
        let client = peer.client.clone();
        let grantee = fixture.grantee.clone();
        let permissions =
            read_on_dedicated_thread(move || effective_permissions(&client, &grantee)).await?;
        ensure!(
            permissions.contains(&permission(fixture.added_dataspace)) == permission_present,
            "replayed permission state differs from committed history"
        );
        for applied in history {
            let current = canonical_execution(
                finality,
                peer,
                &applied.transaction,
                applied.height,
                applied.lane,
                applied.dataspace,
                (applied.lane == fixture.added_lane).then_some(committee),
            )
            .await?;
            ensure!(
                current == applied.canonical_block,
                "recovery changed a historical executed block"
            );
        }
        Ok::<(), eyre::Report>(())
    }))
    .await?;
    Ok(())
}

pub(crate) fn replayed_complete_history(logs: &[PathBuf], minimum_height: u64) -> Result<bool> {
    for path in logs {
        for line in BufReader::new(fs::File::open(path)?).lines() {
            let line = line?;
            if !line.contains("Replaying authenticated complete Kura prefix") {
                continue;
            }
            let record: Value = json::from_str(&line)?;
            let fields = record.get("fields").unwrap_or(&record);
            if fields.get("start_height").and_then(Value::as_u64) == Some(1)
                && fields
                    .get("generic_replay_height")
                    .and_then(Value::as_u64)
                    .is_some_and(|height| height >= minimum_height)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

impl CatalogScenario {
    /// Commit an expansion and the first new-lane permission grant. All inputs
    /// describe the already running real-custody fixture; no daemon is started here.
    pub(crate) async fn begin(fixture: CatalogFixture) -> Result<Self> {
        let finality = finality_from_genesis(&fixture)?;
        ensure!(
            fixture.delegator != fixture.grantee
                && fixture
                    .baseline_lanes
                    .iter()
                    .any(|lane| (lane.id, lane.dataspace_id) == fixture.old_route)
                && fixture
                    .baseline_lanes
                    .iter()
                    .all(|lane| lane.id != fixture.added_lane
                        && lane.dataspace_id != fixture.added_dataspace)
                && fixture
                    .baseline_dataspaces
                    .entries()
                    .iter()
                    .all(|entry| entry.id != fixture.added_dataspace),
            "catalog fixture must preserve an existing route and add unused identities"
        );
        if let Some(runtime) = &fixture.previous_runtime {
            runtime.canonical_hash()?;
            ensure!(
                runtime.baseline_dataspaces_hash
                    == dataspace_catalog_hash(&fixture.baseline_dataspaces)
                    && runtime
                        .dataspaces
                        .iter()
                        .all(|entry| entry.descriptor.id != fixture.added_dataspace)
                    && runtime
                        .manifests
                        .iter()
                        .all(|entry| entry.lane_id != fixture.added_lane),
                "earlier runtime overlay conflicts with the configured baseline or new identities"
            );
        }
        let role = delegation_role(fixture.delegator.clone(), fixture.added_dataspace);
        ensure!(
            fixture.genesis.block().has_results()
                && fixture
                    .genesis
                    .block()
                    .external_transactions()
                    .filter_map(|transaction| match transaction.instructions() {
                        Executable::Instructions(instructions) => Some(instructions),
                        _ => None,
                    })
                    .flat_map(|instructions| instructions.iter())
                    .filter(|instruction| *instruction == &role)
                    .count()
                    == 1,
            "prepared genesis must execute exactly one complete delegation role registration"
        );
        assert_resolution_delegation(&fixture).await?;
        let (before, previous_runtime) = lifecycle_and_runtime(&fixture.peers[0]).await?;
        ensure!(
            before.lanes == fixture.baseline_lanes && previous_runtime == fixture.previous_runtime,
            "initial committed catalog differs from the exact native fixture baseline"
        );
        try_join_all(fixture.peers.iter().map(|peer| async {
            let (status, runtime) = lifecycle_and_runtime(peer).await?;
            ensure!(
                status == before && runtime == fixture.previous_runtime,
                "four peers disagree on the exact catalog before expansion"
            );
            let client = peer.client.clone();
            let grantee = fixture.grantee.clone();
            let permissions =
                read_on_dedicated_thread(move || effective_permissions(&client, &grantee)).await?;
            ensure!(
                !permissions.contains(&permission(fixture.added_dataspace)),
                "grantee already has the future dataspace permission"
            );
            Ok::<(), eyre::Report>(())
        }))
        .await?;
        let old = submit_on_route(
            &fixture,
            &finality,
            vec![
                Log::new(
                    Level::INFO,
                    "old dataspace before catalog transition".into(),
                )
                .into(),
            ],
            fixture.old_route.0,
            fixture.old_route.1,
            None,
        )
        .await?;
        let (manifest, committee) = current_manifest(&fixture).await?;
        let lane = LaneConfig {
            id: fixture.added_lane,
            dataspace_id: fixture.added_dataspace,
            alias: "runtime-committee".into(),
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        };
        let mut manifest_hash = [0_u8; 32];
        manifest_hash[..8].copy_from_slice(&fixture.added_dataspace.as_u64().to_le_bytes());
        let dataspace = RuntimeDataSpaceAdditionV1 {
            descriptor: DataSpaceMetadata {
                id: fixture.added_dataspace,
                alias: "runtime-ds".into(),
                description: Some("committed runtime dataspace".into()),
                fault_tolerance: 1,
            },
            manifest_hash,
        };
        let transition = NexusCatalogTransitionV1 {
            version: NexusCatalogTransitionV1::VERSION,
            expected_catalog_hash: before.catalog_hash,
            expected_incarnation_root: before.incarnation_root,
            expected_runtime_catalog_hash: before.runtime_catalog_hash,
            dataspace_additions: vec![dataspace.clone()],
            lane_additions: vec![lane.clone()],
            manifest_additions: vec![manifest.clone()],
        };
        let changed = submit_on_route(
            &fixture,
            &finality,
            vec![SetParameter::new(Parameter::Custom(transition.into_custom_parameter()?)).into()],
            fixture.old_route.0,
            fixture.old_route.1,
            None,
        )
        .await?;
        ensure!(
            changed.height > old.height,
            "catalog transition must follow existing committed history"
        );
        let (after, runtime) = lifecycle_and_runtime(&fixture.peers[0]).await?;
        let runtime =
            runtime.ok_or_else(|| eyre!("transition did not publish protected runtime catalog"))?;
        let mut expected_lanes = fixture.baseline_lanes.clone();
        expected_lanes.push(lane);
        expected_lanes.sort_by_key(|lane| lane.id);
        let mut expected_dataspaces = fixture
            .previous_runtime
            .as_ref()
            .map(|runtime| runtime.dataspaces.clone())
            .unwrap_or_default();
        expected_dataspaces.push(dataspace);
        expected_dataspaces.sort_by_key(|entry| entry.descriptor.id);
        let mut expected_manifests = fixture
            .previous_runtime
            .as_ref()
            .map(|runtime| runtime.manifests.clone())
            .unwrap_or_default();
        expected_manifests.push(manifest);
        expected_manifests.sort_by_key(|entry| entry.lane_id);
        ensure!(
            after.lanes == expected_lanes
                && runtime.dataspaces == expected_dataspaces
                && runtime.manifests == expected_manifests
                && runtime.baseline_dataspaces_hash
                    == dataspace_catalog_hash(&fixture.baseline_dataspaces)
                && fixture
                    .previous_runtime
                    .as_ref()
                    .is_none_or(|previous| runtime.version == previous.version
                        && runtime.baseline_manifests_hash == previous.baseline_manifests_hash),
            "committed catalog did not preserve exact baseline and additive descriptors"
        );
        runtime.canonical_hash()?;
        assert_resolution_delegation(&fixture).await?;
        let granted = submit_on_route(
            &fixture,
            &finality,
            vec![
                Grant::account_permission(
                    permission(fixture.added_dataspace),
                    fixture.grantee.clone(),
                )
                .into(),
            ],
            fixture.added_lane,
            fixture.added_dataspace,
            Some(&committee),
        )
        .await?;
        ensure!(
            granted.height > changed.height,
            "new-lane transaction must follow catalog activation"
        );
        let scenario = Self {
            fixture,
            finality,
            before,
            after,
            runtime,
            history: vec![old, changed, granted],
            committee,
            phase: Phase::FullReplay,
        };
        scenario.assert_history(true).await?;
        Ok(scenario)
    }

    /// Minimum height that every peer must prove it fully replayed from Kura.
    /// The caller must also reject any signed snapshot before this restart.
    pub(crate) fn replay_height(&self) -> u64 {
        self.history
            .last()
            .expect("nonempty catalog history")
            .height
    }

    async fn assert_history(&self, permission_present: bool) -> Result<()> {
        assert_catalog_and_history(self, permission_present).await
    }

    /// Call only after all four fresh processes prove complete Kura replay from
    /// height one and regain admission. The retained verifier caches are reused.
    /// Return the exact Applied height required for signed snapshot recovery.
    pub(crate) async fn after_full_replay(&mut self) -> Result<u64> {
        ensure!(
            self.phase == Phase::FullReplay,
            "catalog full replay phase repeated or out of order"
        );
        self.assert_history(true).await?;
        let revoked = submit_on_route(
            &self.fixture,
            &self.finality,
            vec![
                Revoke::account_permission(
                    permission(self.fixture.added_dataspace),
                    self.fixture.grantee.clone(),
                )
                .into(),
            ],
            self.fixture.added_lane,
            self.fixture.added_dataspace,
            Some(&self.committee),
        )
        .await?;
        ensure!(
            revoked.height > self.replay_height(),
            "retained replay did not resume new-lane finality"
        );
        self.history.push(revoked);
        self.assert_history(false).await?;
        self.phase = Phase::SnapshotRestore;
        Ok(self.replay_height())
    }

    /// Call only after a fresh process loads the complete native signed snapshot
    /// at or above the returned revocation height and regains admission.
    pub(crate) async fn after_snapshot_restore(&mut self) -> Result<()> {
        ensure!(
            self.phase == Phase::SnapshotRestore,
            "catalog snapshot phase repeated or out of order"
        );
        self.assert_history(false).await?;
        let resumed = submit_on_route(
            &self.fixture,
            &self.finality,
            vec![
                Grant::account_permission(
                    permission(self.fixture.added_dataspace),
                    self.fixture.grantee.clone(),
                )
                .into(),
            ],
            self.fixture.added_lane,
            self.fixture.added_dataspace,
            Some(&self.committee),
        )
        .await?;
        ensure!(
            resumed.height > self.replay_height(),
            "signed-snapshot recovery did not resume new-lane finality"
        );
        self.history.push(resumed);
        let old_resumed = submit_on_route(
            &self.fixture,
            &self.finality,
            vec![Log::new(Level::INFO, "old dataspace after catalog recovery".into()).into()],
            self.fixture.old_route.0,
            self.fixture.old_route.1,
            None,
        )
        .await?;
        ensure!(
            old_resumed.height > self.replay_height(),
            "old dataspace stopped progressing after expansion"
        );
        self.history.push(old_resumed);
        self.assert_history(true).await?;
        self.phase = Phase::Complete;
        Ok(())
    }
}
