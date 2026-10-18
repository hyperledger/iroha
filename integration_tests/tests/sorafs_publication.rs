//! Real four-validator publication, native replication, retrieval, restart and corruption repair.
//!
//! Signed genesis establishes provider admission. Owner-funded reserve, capacity, publication
//! assertions and repair transitions execute through the production queue. The three providers
//! use explicit software custody and bounded authenticated source transport, without State writes.

use super::{
    sorafs_network::{bounded_storage, submit_instruction},
    sorafs_publication_authority::PublicationAuthorityFixture,
    sorafs_publication_compliance::PublicationComplianceFixture,
    sorafs_publication_config::{ProviderFixture, set},
    sorafs_publication_http as wire,
};
use eyre::{Result, WrapErr as _, ensure, eyre};
use futures_util::future::try_join_all;
use integration_tests::sandbox;
use iroha::{blocking::Client, crypto::KeyPair};
use iroha_data_model::{
    isi::sorafs::{
        DecideSorafsReserveMovement, RegisterCapacityDeclaration, RegisterPinManifest,
        RegisterSorafsReserveAccount, RequestSorafsReserveMovement, SetSorafsReservePolicy,
        SubmitSorafsRepairTask, UpsertProviderCredit,
    },
    prelude::*,
    query::sorafs::prelude::FindSorafsRepairTask,
    sorafs::{
        moderation_ledger::RepairLedgerTerminalKindV1,
        pin_registry::{ManifestDigest, StorageClass},
        pricing::ProviderCreditRecord,
        reserve::{
            RESERVE_AUTHORITY_POLICY_VERSION_V1, ReserveAuthorityPolicyV1, ReserveDuration,
            ReserveMovementKindV1, ReservePolicyV1, ReserveProviderTermsV1, ReserveTier,
        },
    },
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, SumeragiFinalityVerifier,
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanOperateSorafsRepair, CanSetSorafsReservePolicy, CanUpsertSorafsProviderCredit,
};
use iroha_model_base::{domain::DomainId, metadata::Metadata};
use iroha_primitives::numeric::Quantity;
use iroha_test_network::{
    Network, NetworkBuilder, init_instruction_registry, read_on_dedicated_thread,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID};
use sorafs_car::{CarBuildPlan, CarWriter, FileEntry};
use sorafs_manifest::{
    DagCodecId, ManifestBuilder, ManifestV1, PinPolicy,
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityDeclarationV1, CapacityMetadataEntry,
        ChunkerCommitmentV1,
    },
    provider_advert::StakePointer,
    repair::{
        REPAIR_EVIDENCE_VERSION_V1, REPAIR_REPORT_VERSION_V1, RepairCauseV1, RepairEvidenceV1,
        RepairManualCauseV1, RepairReportV1, RepairTicketId,
    },
};
use std::{
    borrow::Cow,
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{Duration, Instant, timeout, timeout_at};

const TICKET: &str = "REP-PUBLICATION-NATIVE-1";

pub struct PublishedNetwork {
    pub network: sandbox::SerializedNetwork,
    pub authority: PublicationAuthorityFixture,
    pub providers: Vec<ProviderFixture>,
    pub layers: Vec<toml::Table>,
    pub http: reqwest::Client,
    pub manifest: ManifestV1,
    pub floor: SumeragiFinalityCheckpoint,
    pub payload: Vec<u8>,
    cli_binary: PathBuf,
    runtime_directory: tempfile::TempDir,
}

pub fn client(network: &Network, peer: usize, key: &KeyPair) -> Client {
    let client = network.peers()[peer].client_for(
        &AccountId::new(key.public_key().clone()),
        key.private_key().clone(),
    );
    integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = wire::DEADLINE;
        client.torii_request_timeout = Duration::from_secs(10);
        client.transaction_ttl = Some(Duration::from_secs(300));
        client.add_transaction_nonce = true;
    })
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn merge(target: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (target.get_mut(&key), value) {
            (Some(toml::Value::Table(existing)), toml::Value::Table(next)) => merge(existing, next),
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

async fn fund_and_declare(
    network: &Network,
    providers: &[ProviderFixture],
    asset: AssetDefinitionId,
) -> Result<()> {
    let governor = client(network, 0, &ALICE_KEYPAIR);
    // NPoS genesis funds the test-network bootstrap accounts, not caller-registered workers.
    // Fund every separate production custody account through ordinary signed transfers.
    let native_fee_asset =
        iroha_genesis::signed_genesis_root_fee_policy(&network.genesis().0)?.fee_asset_id;
    for provider in providers {
        ensure!(
            provider.owner() != provider.completion_signer(),
            "dedicated completion account required"
        );
        for account in [provider.owner(), provider.completion_signer()]
            .into_iter()
            .chain(
                provider
                    .role_keys
                    .iter()
                    .map(|key| AccountId::new(key.public_key().clone())),
            )
        {
            submit_instruction(
                &governor,
                Transfer::asset_quantity(
                    AssetId::of(native_fee_asset.clone(), ALICE_ID.clone()),
                    10_000_u32,
                    account,
                ),
            )
            .await?;
        }
    }
    let policy = ReserveAuthorityPolicyV1 {
        version: RESERVE_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        economics: ReservePolicyV1::default(),
        asset_definition: asset,
        custody_account: BOB_ID.clone(),
        treasury_account: ALICE_ID.clone(),
        operations_authority: ALICE_ID.clone(),
        decision_authority: ALICE_ID.clone(),
        grace_period_days: 7,
        default_after_days: 30,
        max_provider_debt: "1000".parse()?,
        max_pending_movements_per_provider: 4,
        max_open_appeals_per_provider: 2,
    };
    let policy_digest = policy.digest()?;
    submit_instruction(&governor, SetSorafsReservePolicy::new(policy)).await?;
    for (index, provider) in providers.iter().enumerate() {
        let owner = client(network, 0, &provider.owner_key);
        submit_instruction(&owner, provider.completion_authority()).await?;
        submit_instruction(
            &governor,
            RegisterSorafsReserveAccount::new(
                ReserveProviderTermsV1 {
                    provider_id: provider.id,
                    provider_account: provider.owner(),
                    tier: ReserveTier::TierA,
                    storage_class: StorageClass::Hot,
                    duration: ReserveDuration::Monthly,
                    capacity_gib: 2,
                },
                policy_digest,
            ),
        )
        .await?;
        let movement = [0xB0 + u8::try_from(index).expect("fixture provider index fits u8"); 32];
        submit_instruction(
            &owner,
            RequestSorafsReserveMovement::new(
                movement,
                provider.id,
                ReserveMovementKindV1::TopUp,
                "100".parse()?,
                1,
                policy_digest,
            ),
        )
        .await?;
        submit_instruction(
            &governor,
            DecideSorafsReserveMovement::new(
                movement,
                2,
                policy_digest,
                true,
                "owner-funded publication reserve".into(),
            ),
        )
        .await?;
        let instant = now()?;
        submit_instruction(
            &governor,
            UpsertProviderCredit {
                expected_current: None,
                record: ProviderCreditRecord::new(
                    provider.id,
                    Quantity::from(100_u32),
                    Quantity::from(100_u32),
                    Quantity::from(1_u32),
                    Quantity::zero(),
                    instant,
                    instant,
                    Metadata::default(),
                ),
            },
        )
        .await?;
        let declaration = CapacityDeclarationV1 {
            version: CAPACITY_DECLARATION_VERSION_V1,
            provider_id: *provider.id.as_bytes(),
            stake: StakePointer {
                pool_id: [0xC0 + u8::try_from(index).expect("fixture provider index fits u8"); 32],
                stake_amount: "1".parse()?,
            },
            committed_capacity_gib: 2,
            chunker_commitments: vec![ChunkerCommitmentV1 {
                profile_id: "sorafs.sf1@1.0.0".into(),
                profile_aliases: None,
                committed_gib: 2,
                capability_refs: Vec::new(),
            }],
            lane_commitments: Vec::new(),
            pricing: None,
            valid_from: instant - 120,
            valid_until: instant + 86400,
            metadata: vec![
                CapacityMetadataEntry {
                    key: "sorafs.owner_account_id".into(),
                    value: provider.owner().to_string(),
                },
                CapacityMetadataEntry {
                    key: "sorafs.storage_class".into(),
                    value: "hot".into(),
                },
            ],
        };
        declaration.validate()?;
        submit_instruction(
            &owner,
            RegisterCapacityDeclaration::new(norito::encode_canonical(&declaration)?),
        )
        .await?;
    }
    Ok(())
}

pub async fn refresh_adverts(published: &PublishedNetwork) -> Result<()> {
    refresh_network_adverts(&published.http, &published.network, &published.authority).await
}
async fn refresh_network_adverts(
    http: &reqwest::Client,
    network: &Network,
    authority: &PublicationAuthorityFixture,
) -> Result<()> {
    timeout(wire::DEADLINE, async {
        for provider in 0..3 {
            let advert = authority.advert(provider, network.network_id(), now()?)?;
            for peer in network.peers().iter().take(3) {
                let response = http
                    .post(format!(
                        "{}/v1/sorafs/provider/advert",
                        peer.torii_url().trim_end_matches('/')
                    ))
                    .header("Content-Type", "application/x-norito")
                    .body(norito::encode_canonical(&advert)?)
                    .send()
                    .await?;
                ensure!(
                    response.status().is_success(),
                    "actual signed provider advert rejected: {}",
                    response.status()
                );
            }
        }
        Ok::<_, eyre::Report>(())
    })
    .await?
}

/// Build an actual network and return only after all three production workers finalize completion.
/// A caller may add the genuine Parliament corridor before genesis for subsequent revocation tests.
pub async fn create_and_publish(
    transform: impl FnOnce(NetworkBuilder) -> NetworkBuilder,
) -> Result<PublishedNetwork> {
    init_instruction_registry();
    let cli_binary = std::env::var_os("TEST_NETWORK_BIN_SORAFS_CLI")
        .map(PathBuf::from)
        .ok_or_else(|| eyre!("prebuild the same-source sorafs_cli with cli-orchestrator and set TEST_NETWORK_BIN_SORAFS_CLI; publication qualification must execute the CLI"))?;
    ensure!(
        cli_binary.is_absolute() && cli_binary.is_file(),
        "TEST_NETWORK_BIN_SORAFS_CLI must be an existing absolute same-source artifact"
    );
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target");
    fs::create_dir_all(&target)?;
    let runtime_directory = tempfile::Builder::new()
        .prefix("sorafs-publication-")
        .tempdir_in(target.canonicalize()?)?;
    let providers = (0..3)
        .map(|index| ProviderFixture::new(runtime_directory.path(), index))
        .collect::<Result<Vec<_>>>()?;
    let authority = PublicationAuthorityFixture::new(
        &providers
            .iter()
            .map(|provider| *provider.id.as_bytes())
            .collect::<Vec<_>>(),
        &providers
            .iter()
            .map(ProviderFixture::owner)
            .collect::<Vec<_>>(),
    )?;
    let compliance = PublicationComplianceFixture::new(runtime_directory.path(), 3)?;
    let domain = DomainId::try_new("sorafspublication", "universal")?;
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "xor".parse()?);
    let fee_asset = asset.to_string();
    let treasury = BOB_ID.to_string();
    let mut builder = bounded_storage(
        NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers()
            .with_block_cadence(Duration::from_secs(1))
            .with_npos_consensus(),
    )
    .with_config_layer(move |layer| {
        layer
            .write(["sorafs", "storage", "enabled"], false)
            .write(["governance", "sorafs_pin_fee_asset_id"], fee_asset.clone())
            .write(
                ["governance", "sorafs_pin_fee_treasury_account"],
                treasury.clone(),
            );
    })
    .with_genesis_instruction(Register::domain(Domain::new(domain)))
    .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
        asset.clone(),
        "Publication reserve",
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanSetSorafsReservePolicy),
        ALICE_ID.clone(),
    ))
    .with_genesis_instruction(Grant::account_permission(
        Permission::from(CanUpsertSorafsProviderCredit),
        ALICE_ID.clone(),
    ));
    for provider in &providers {
        for instruction in provider.genesis_accounts() {
            builder = builder.with_genesis_instruction(instruction);
        }
        builder = builder
            .with_genesis_instruction(Mint::asset_quantity(
                1000_u32,
                AssetId::of(asset.clone(), provider.owner()),
            ))
            .with_genesis_instruction(Grant::account_permission(
                Permission::from(CanOperateSorafsRepair {
                    provider_id: provider.id,
                }),
                ALICE_ID.clone(),
            ));
    }
    builder = builder.with_genesis_instruction(Mint::asset_quantity(
        1000_u32,
        AssetId::of(asset.clone(), ALICE_ID.clone()),
    ));
    for instruction in authority.genesis_instructions()?.into_iter().chain(
        PublicationComplianceFixture::genesis_instructions(&ALICE_ID)?,
    ) {
        builder = builder.with_genesis_instruction(instruction);
    }
    let context = "four_peer_native_publication_and_storage_lifecycle";
    let network = sandbox::build_network_or_skip(transform(builder), context);
    let network = sandbox::enforce_network_start_requirement(network, context)?
        .ok_or_else(|| eyre!("publication qualification requires an actual four-validator network; startup was unavailable"))?;
    ensure!(
        network.peers().len() == 4,
        "publication requires exactly four validators"
    );
    let origins = providers
        .iter()
        .zip(network.peers())
        .map(|(provider, peer)| (provider.id, peer.torii_url()))
        .collect::<Vec<_>>();
    let mut layers = Vec::new();
    for (index, provider) in providers.iter().enumerate() {
        let mut layer = provider.config(&origins)?;
        merge(&mut layer, compliance.config(index)?);
        layers.push(layer);
    }
    let mut validator_layer = toml::Table::new();
    set(
        &mut validator_layer,
        &["sorafs", "storage", "enabled"],
        false,
    );
    layers.push(validator_layer);
    let genesis = network.genesis();
    timeout(
        wire::DEADLINE,
        try_join_all(network.peers().iter().zip(&layers).map(|(peer, layer)| {
            peer.start_checked(
                network
                    .config_layers_for_peer(peer)
                    .chain(std::iter::once(Cow::Borrowed(layer))),
                Some(&genesis),
            )
        })),
    )
    .await??;
    network.ensure_blocks(1).await?;
    let http = wire::http()?;
    let checkpoint = wire::genesis_checkpoint(&http, &network).await?;
    for (index, peer) in network.peers().iter().take(3).enumerate() {
        compliance
            .install(
                &http,
                &network.network_id(),
                &peer.torii_url(),
                &ALICE_KEYPAIR,
                index,
            )
            .await?;
    }
    fund_and_declare(&network, &providers, asset).await?;
    refresh_network_adverts(&http, &network, &authority).await?;
    let data = (0..128 * 1024)
        .map(|index| {
            u8::try_from((index * 17 + index / 251) % 251).expect("fixture residue is below 251")
        })
        .collect::<Vec<_>>();
    let (plan, payload) = CarBuildPlan::from_files(vec![FileEntry {
        path: vec!["payload.bin".into()],
        data,
    }])?;
    let car = CarWriter::new(&plan, &payload)?.write_to(std::io::sink())?;
    let manifest = ManifestBuilder::new()
        .root_cid(car.root_cids[0].clone())
        .dag_codec(DagCodecId(car.dag_codec))
        .chunking_from_profile(
            plan.chunk_profile,
            sorafs_manifest::BLAKE3_256_MULTIHASH_CODE,
        )
        .chunk_digest_sha3_256(sorafs_car::compute_chunk_plan_digest_sha3(&plan.chunks))
        .por_root(sorafs_car::compute_por_root(&payload, &plan)?)
        .content_length(plan.content_length)
        .car_digest(*car.car_archive_digest.as_bytes())
        .car_size(car.car_size)
        .pin_policy(PinPolicy {
            min_replicas: 3,
            retention_epoch: now()? + 86400,
            storage_class: sorafs_manifest::StorageClass::Hot,
        })
        .build()?;
    let digest = ManifestDigest::from_manifest(&manifest)?;
    let publisher = client(&network, 0, &ALICE_KEYPAIR);
    submit_instruction(
        &publisher,
        RegisterPinManifest::new(norito::encode_canonical(&manifest)?, None, None),
    )
    .await?;
    let base = network.peers()[0].torii_url();
    let row = wire::preparation(
        &http,
        &network.network_id(),
        &base,
        &ALICE_KEYPAIR,
        digest,
        false,
    )
    .await?;
    let assigned_floor = wire::prove(
        &http,
        &publisher,
        &base,
        &ALICE_KEYPAIR,
        &row,
        &checkpoint,
        false,
    )
    .await?;
    let source_request = iroha_data_model::sorafs::publication::SorafsAssignedSourceRequestV1 {
        target_provider: *providers[1].id.as_bytes(),
        source_provider: *providers[0].id.as_bytes(),
        order_id: *row.order.order_id.as_bytes(),
        assignment_revision: row.order.assignment_revision,
        manifest_digest: *digest.as_bytes(),
        chunk_index: None,
        floor_height: assigned_floor.height(),
        floor_block_hash: *assigned_floor.block_hash().as_ref(),
    };
    for (key, request) in [
        (&*ALICE_KEYPAIR, source_request),
        (&providers[1].owner_key, source_request),
        (
            &providers[1].completion_key,
            iroha_data_model::sorafs::publication::SorafsAssignedSourceRequestV1 {
                assignment_revision: source_request.assignment_revision + 1,
                ..source_request
            },
        ),
    ] {
        let response = wire::post(
            &http,
            &network.network_id(),
            &base,
            key,
            "v1/sorafs/provider/source",
            norito::encode_canonical(&request)?,
        )
        .await?;
        ensure!(
            response.status() == reqwest::StatusCode::FORBIDDEN,
            "unowned or stale source request was not refused by native authority: {}",
            response.status()
        );
    }
    // Seed just one provider. The other assigned production workers must obtain authenticated
    // chunk bytes from that provider and submit their own exact native completion transactions.
    wire::stage(
        &http,
        &network.network_id(),
        &base,
        &ALICE_KEYPAIR,
        *providers[0].id.as_bytes(),
        &row,
        (&manifest, &plan, &payload),
    )
    .await?;
    let complete = wire::preparation(
        &http,
        &network.network_id(),
        &base,
        &ALICE_KEYPAIR,
        digest,
        true,
    )
    .await?;
    ensure!(
        complete.order.provider_completions.len() == 3,
        "all three independent native completions required"
    );
    for completion in &complete.order.provider_completions {
        let provider = providers
            .iter()
            .find(|provider| provider.id == completion.provider_id)
            .ok_or_else(|| eyre!("completion provider must belong to the test network"))?;
        ensure!(
            completion.completed_by == provider.completion_signer(),
            "native completion must retain the dedicated signer"
        );
        ensure!(
            completion.completion_authority.provider_owner == provider.owner(),
            "native completion must retain the independent owner"
        );
        ensure!(
            completion.completion_authority.completion_signer == completion.completed_by,
            "full completion authority must bind the signer"
        );
    }
    let floor = wire::prove(
        &http,
        &publisher,
        &base,
        &ALICE_KEYPAIR,
        &complete,
        &assigned_floor,
        true,
    )
    .await?;
    Ok(PublishedNetwork {
        network,
        authority,
        providers,
        layers,
        http,
        manifest,
        floor,
        payload,
        cli_binary,
        runtime_directory,
    })
}

pub fn cid(bytes: &[u8]) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::from("b");
    let (mut accumulator, mut bits) = (0_u32, 0_u32);
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            output.push(char::from(
                alphabet[((accumulator >> (bits - 5)) & 31) as usize],
            ));
            bits -= 5;
        }
    }
    if bits != 0 {
        output.push(char::from(
            alphabet[((accumulator << (5 - bits)) & 31) as usize],
        ));
    }
    output
}

pub async fn retrieve(published: &PublishedNetwork, peer: usize) -> Result<reqwest::Response> {
    Ok(published
        .http
        .get(format!(
            "{}/sorafs/cid/{}/payload.bin",
            published.network.peers()[peer]
                .torii_url()
                .trim_end_matches('/'),
            cid(&published.manifest.root_cid)
        ))
        .header("Accept-Encoding", "identity")
        .send()
        .await?)
}

async fn check_payload(published: &PublishedNetwork, peer: usize) -> Result<()> {
    let response = retrieve(published, peer).await?;
    ensure!(
        response.status().is_success(),
        "public CID retrieval from provider {peer} failed: {}",
        response.status()
    );
    ensure!(
        wire::bytes(response, published.payload.len()).await? == published.payload,
        "verified public CID bytes changed"
    );
    Ok(())
}

pub async fn restart(published: &PublishedNetwork, peer: usize) -> Result<()> {
    let node = &published.network.peers()[peer];
    node.shutdown().await;
    timeout(
        wire::DEADLINE,
        node.start_checked(
            published
                .network
                .config_layers_for_peer(node)
                .chain(std::iter::once(Cow::Borrowed(&published.layers[peer]))),
            None,
        ),
    )
    .await??;
    Ok(())
}

pub async fn qualify_storage_lifecycle(published: &PublishedNetwork) -> Result<()> {
    for peer in 0..3 {
        check_payload(published, peer).await?;
    }
    restart(published, 1).await?;
    check_payload(published, 1).await?;
    published.network.peers()[0].shutdown().await;
    let digest = ManifestDigest::from_manifest(&published.manifest)?;
    let chunk_dir = published.providers[0]
        .storage_dir
        .join("manifests")
        .join(hex::encode(digest.as_bytes()))
        .join("chunks");
    let mut chunks = fs::read_dir(&chunk_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    chunks.sort();
    let path = chunks
        .first()
        .ok_or_else(|| eyre!("native producer created no chunk files"))?;
    let chunk_length = fs::metadata(path)?.len();
    ensure!(
        chunk_length > 0 && chunk_length <= u64::from(sorafs_car::CHUNK_STORE_MAX_CHUNK_BYTES),
        "corruption fixture must modify exactly one bounded persisted chunk"
    );
    let mut corrupted = fs::read(path)?;
    ensure!(corrupted.len() as u64 == chunk_length);
    let expected_digest = blake3::hash(&corrupted);
    // Keep unrelated healthy manifests available, but rule out every local copy of the
    // missing content. Completion must exercise the authenticated remote repair source.
    for manifest in fs::read_dir(published.providers[0].storage_dir.join("manifests"))? {
        for candidate in fs::read_dir(manifest?.path().join("chunks"))? {
            let candidate = candidate?.path();
            if candidate == *path || fs::metadata(&candidate)?.len() != chunk_length {
                continue;
            }
            let bytes = fs::read(&candidate)?;
            ensure!(bytes.len() as u64 == chunk_length);
            ensure!(
                blake3::hash(&bytes) != expected_digest,
                "remote repair qualification must not have a valid local source for the corrupted chunk"
            );
        }
    }
    corrupted[0] ^= 0x80;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(&corrupted)?;
    file.sync_all()?;
    drop(file);
    let node = &published.network.peers()[0];
    timeout(
        wire::DEADLINE,
        node.start_checked(
            published
                .network
                .config_layers_for_peer(node)
                .chain(std::iter::once(Cow::Borrowed(&published.layers[0]))),
            None,
        ),
    )
    .await??;
    let unavailable = retrieve(published, 0).await?;
    ensure!(
        unavailable.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "corrupt payload must remain unavailable after restart, got {}",
        unavailable.status()
    );
    let unavailable_body = wire::bytes(unavailable, 65536).await?;
    ensure!(
        String::from_utf8(unavailable_body)?
            .contains("manifest payload is quarantined pending verified repair"),
        "an unrelated restart or finality error cannot establish payload quarantine"
    );
    // An unaffected replica remains available before any repair task can be claimed.
    check_payload(published, 1).await?;
    refresh_adverts(published).await?;
    let report = RepairReportV1 {
        version: REPAIR_REPORT_VERSION_V1,
        ticket_id: RepairTicketId(TICKET.into()),
        auditor_account: ALICE_ID.to_string(),
        submitted_at_unix: now()?,
        evidence: RepairEvidenceV1 {
            version: REPAIR_EVIDENCE_VERSION_V1,
            manifest_digest: *digest.as_bytes(),
            provider_id: *published.providers[0].id.as_bytes(),
            por_history_id: None,
            cause: RepairCauseV1::Manual(RepairManualCauseV1 {
                reason: "real restart corruption qualification".into(),
            }),
            evidence_json: None,
            notes: None,
        },
        notes: None,
    };
    let operator = client(&published.network, 1, &ALICE_KEYPAIR);
    let canonical_report = norito::encode_canonical(&report)?;
    submit_instruction(
        &operator,
        SubmitSorafsRepairTask::new([0xD7; 32], canonical_report.clone()),
    )
    .await?;
    let completed = timeout_at(Instant::now() + wire::DEADLINE, async {
        loop {
            let reader = client(&published.network, 1, &ALICE_KEYPAIR);
            let snapshot = read_on_dedicated_thread(move || {
                Ok(reader
                    .client()
                    .query_single(FindSorafsRepairTask::new(TICKET.into(), None))?)
            })
            .await?;
            let task = &snapshot.task;
            ensure!(
                task.ticket_id == TICKET
                    && task.canonical_report == canonical_report
                    && task.manifest_digest == *digest.as_bytes()
                    && task.provider_id == *published.providers[0].id.as_bytes()
                    && task.source_identity == [0xD7; 32]
                    && task.submitted_by == *ALICE_ID,
                "repair query substituted the admitted publication task"
            );
            if let Some(terminal) = &task.terminal_outcome {
                let RepairLedgerTerminalKindV1::Completed(completion) = &terminal.kind else {
                    return Err(eyre!(
                        "production repair did not complete: {:?}",
                        terminal.kind
                    ));
                };
                ensure!(
                    completion.evidence_digest != [0; 32]
                        && terminal.lease_generation > 0
                        && terminal.finalized_by
                            == AccountId::new(
                                published.providers[0].role_keys[1].public_key().clone()
                            )
                        && terminal.finalized_at_unix_ms >= task.submitted_at_unix_ms
                        && snapshot.finalized_cursor.height > 0
                        && snapshot.finalized_cursor.block_hash != [0; 32],
                    "completion did not bind the assigned native repair worker and finalized task"
                );
                break Ok::<_, eyre::Report>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await??;
    // Query actual applied State on every validator, not only a local worker's completion.
    timeout_at(Instant::now() + wire::DEADLINE, async {
        for peer in 0..4 {
            loop {
                let reader = client(&published.network, peer, &ALICE_KEYPAIR);
                let snapshot = read_on_dedicated_thread(move || {
                    Ok(reader
                        .client()
                        .query_single(FindSorafsRepairTask::new(TICKET.into(), None))?)
                })
                .await?;
                if snapshot.finalized_cursor.height >= completed.finalized_cursor.height {
                    ensure!(
                        snapshot.task == completed.task,
                        "validator {peer} did not apply the exact terminal native repair task"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        Ok::<_, eyre::Report>(())
    })
    .await??;
    check_payload(published, 0).await?;
    restart(published, 0).await?;
    check_payload(published, 0).await?;
    qualify_cli_deploy(published).await?;
    Ok(())
}

async fn qualify_cli_deploy(published: &PublishedNetwork) -> Result<()> {
    let root = published.runtime_directory.path().join("cli");
    fs::create_dir(&root)?;
    let payload = root.join("payload");
    fs::create_dir(&payload)?;
    fs::write(
        payload.join("hello.txt"),
        b"actual same-source SoraFS CLI publication\n",
    )?;
    let deploy_client = client(&published.network, 0, &ALICE_KEYPAIR);
    let mut config = toml::Table::new();
    set(
        &mut config,
        &["network_id"],
        published.network.network_id().to_string(),
    );
    set(
        &mut config,
        &["chain"],
        published.network.chain_id().to_string(),
    );
    set(
        &mut config,
        &["torii_url"],
        published.network.peers()[0].torii_url(),
    );
    set(
        &mut config,
        &["account", "public_key"],
        ALICE_KEYPAIR.public_key().to_string(),
    );
    set(
        &mut config,
        &["account", "private_key"],
        iroha_crypto::ExposedPrivateKey(ALICE_KEYPAIR.private_key().clone())
            .try_to_multihash_string()?,
    );
    set(
        &mut config,
        &["account", "chain_discriminant"],
        i64::from(deploy_client.client().account_chain_discriminant()),
    );
    let config_path = root.join("client.toml");
    let mut config_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&config_path)?;
    config_file.write_all(toml::to_string(&config)?.as_bytes())?;
    config_file.sync_all()?;
    let checkpoint = root.join("trusted-finality.to");
    fs::write(&checkpoint, published.floor.encode_canonical()?)?;
    let out_dir = root.join("output");
    let receipt = root.join("receipt.json");
    let log = root.join("cli.log");
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log)?;
    let mut command = tokio::process::Command::new(&published.cli_binary);
    command
        .arg("deploy")
        .arg(format!("--payload={}", payload.display()))
        .arg(format!("--client-config={}", config_path.display()))
        .arg(format!("--finality-checkpoint={}", checkpoint.display()))
        .arg(format!("--out-dir={}", out_dir.display()))
        .arg(format!("--summary-out={}", receipt.display()))
        .arg(format!(
            "--gateway-base-url={}",
            published.network.peers()[0].torii_url()
        ))
        .arg("--name=native-cli")
        .arg("--no-peer-discovery")
        .stdout(output.try_clone()?)
        .stderr(output)
        .kill_on_drop(true);
    for peer in published.network.peers().iter().take(3) {
        command.arg(format!("--provider-url={}", peer.torii_url()));
    }
    let mut child = command.spawn()?;
    let status = match timeout(Duration::from_secs(620), child.wait()).await {
        Ok(status) => status?,
        Err(error) => {
            // Reap our own test child before its private runtime directory is removed.
            child
                .kill()
                .await
                .wrap_err("terminate and reap timed-out publication CLI")?;
            return Err(error).wrap_err("same-source publication CLI exceeded its deadline");
        }
    };
    ensure!(
        status.success(),
        "same-source sorafs_cli deploy failed; runtime log: {}",
        log.display()
    );
    ensure!(
        fs::metadata(&receipt)?.len() <= 1024 * 1024,
        "CLI receipt exceeded bound"
    );
    let receipt: norito::json::Value = norito::json::from_slice(&fs::read(receipt)?)?;
    ensure!(
        receipt["success"].as_bool() == Some(true)
            && receipt["publication_verified"].as_bool() == Some(true)
            && receipt["gateway_verification"]["success"].as_bool() == Some(true),
        "CLI failed native finality or asset verification"
    );
    let successor_path = out_dir.join("publication.finality.to");
    let successor_metadata = fs::metadata(&successor_path)?;
    ensure!(
        successor_metadata.len() <= MAX_FINALITY_CHECKPOINT_BYTES as u64,
        "CLI finality checkpoint exceeded bound"
    );
    ensure!(
        successor_metadata.permissions().mode() & 0o777 == 0o600,
        "CLI finality checkpoint must be owner-only"
    );
    let successor = SumeragiFinalityCheckpoint::decode_canonical(&fs::read(successor_path)?)?;
    SumeragiFinalityVerifier::from_trusted_checkpoint(
        &successor,
        &published.network.network_id(),
        published.network.chain_id().as_ref(),
    )?;
    ensure!(
        successor.height() > published.floor.height(),
        "CLI did not persist authenticated publication progress"
    );
    ensure!(fs::metadata(out_dir.join("native-cli.manifest.to"))?.len() <= 4 * 1024 * 1024);
    let manifest: ManifestV1 = wire::decode(
        &fs::read(out_dir.join("native-cli.manifest.to"))?,
        4 * 1024 * 1024,
    )?;
    let row = wire::preparation(
        &published.http,
        &published.network.network_id(),
        &published.network.peers()[0].torii_url(),
        &ALICE_KEYPAIR,
        ManifestDigest::from_manifest(&manifest)?,
        true,
    )
    .await?;
    wire::prove(
        &published.http,
        &deploy_client,
        &published.network.peers()[0].torii_url(),
        &ALICE_KEYPAIR,
        &row,
        &published.floor,
        true,
    )
    .await?;
    Ok(())
}

#[test]
fn four_peer_publication_replication_retrieval_restart_and_native_repair() -> Result<()> {
    super::sorafs_network::run("sorafs-publication", || async {
        let published = create_and_publish(|builder| builder).await?;
        qualify_storage_lifecycle(&published)
            .await
            .wrap_err("actual native publication lifecycle")?;
        Ok(())
    })
}

#[test]
fn cid_encoding_uses_canonical_multibase_bits() {
    assert_eq!(cid(&[0, 255]), "bad7q");
}
