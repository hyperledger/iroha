//! Stock discovery and TLS seed ingress over actual generated signed genesis and paid custody.
//!
//! The certified chain executes native transactions and signs exact four-seat quorum evidence;
//! it does not run four independent validators. Seed staging is not completed replication,
//! provider Serving, full managed bootstrap, or cold-package release qualification.

use super::*;
use iroha_config::node_config::{NodeConfigOptions, NodeFile, open_node_config};
use iroha_core::{
    query::stream_token_custody::read_stream_token_custody_control_at_v1,
    queue::Queue,
    state::StateReadOnly as _,
    sumeragi::{
        lanes::merge::NoLanes,
        test_chain::{CertifiedTestChain, PreparedTestChainConfig},
    },
};
use iroha_crypto::{Hash, KeyPair, Signature};
use iroha_data_model::{
    account::AccountId,
    isi::{InstructionBox, Log, sorafs::MutateSorafsStreamTokenCustody},
    sorafs::stream_token_custody::{
        SorafsStreamTokenCustodyActionV1, SorafsStreamTokenCustodyRevocationV1,
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_deploy::{
    genesis::staging::{
        configured_initial_genesis_state, ensure_peer_config_matches_manifest,
        staged_genesis_chain_discriminant,
    },
    localnet::service_authorities::StreamTokenAuthorityRole as Role,
    managed::{LocalnetPorts, PreparedLocalnet},
};
use iroha_fs::PrivateDirectory;
use iroha_genesis::{GenesisBlock, RawGenesisTransaction};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use iroha_musubi_service::{
    AuthenticatedMusubiPublicationRuntimeClientV1, MusubiSeedIngressCarPlanV1,
    MusubiSeedIngressStageRequestV1, MusubiSeedStagingBackendV1,
    SoftwareMusubiPublicationRuntimeAuthorizationSignerV1,
};
use sorafs_manifest::signer::{
    custody::{
        SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyAuthorityV1,
        SignerCustodyBindingV1, SignerCustodyRecordV1, SignerCustodyStatementV1,
    },
    custody_control::SignerCustodyPolicyV1,
    protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
};
use std::{
    io::Cursor,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

struct Generated {
    prepared: PreparedLocalnet,
    manager_key: KeyPair,
    manager_account: AccountId,
    chain: CertifiedTestChain,
    storage_root: std::path::PathBuf,
    // Reclaim native State/Kura and custody owners before removing their original directory.
    _directory: tempfile::TempDir,
}
impl Generated {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix(".stock-positive-")
            .tempdir_in(std::env::temp_dir())
            .unwrap();
        let ports = LocalnetPorts::reserve().unwrap();
        let prepared = iroha_deploy::localnet::prepare_localnet(
            "stock-positive",
            &directory.path().join("generation"),
            &ports,
        )
        .unwrap();
        let manager = prepared.context.load_client_config().unwrap();
        let root =
            PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
        let bytes = root
            .read(
                "genesis.json",
                iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
            )
            .unwrap();
        iroha_genesis::validate_genesis_manifest_json(&bytes).unwrap();
        let manifest = RawGenesisTransaction::from_json_slice_at_path(
            &bytes,
            root.path().join("genesis.json"),
        )
        .unwrap();
        let _address = staged_genesis_chain_discriminant(&manifest);
        let signed = root
            .read(
                "genesis.signed.nrt",
                iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
            )
            .unwrap();
        let mut custody = Vec::new();
        let mut first = None;
        for peer in &prepared.peers {
            let reader = open_node_config(
                NodeFile::Path(peer.config_path.clone()),
                NodeConfigOptions::default(),
            )
            .unwrap();
            let (user, _) = reader.read().unwrap();
            let config = user.parse().unwrap();
            ensure_peer_config_matches_manifest(&config, &manifest).unwrap();
            custody.push(config.common.key_pair.clone());
            if first.is_none() {
                first = Some(config);
            }
        }
        custody.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let config = first.unwrap();
        assert_eq!(
            config.pipeline.ivm_execution_max_bytes,
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES
        );
        let storage_root = config.torii.sorafs_storage.data_dir.clone();
        let genesis = iroha_genesis::validate_prepared_genesis_bundle(
            &signed,
            &manifest,
            &config.genesis.public_key,
            config.genesis.expected_hash,
        )
        .unwrap();
        assert_eq!(genesis.canonical_wire(), signed.as_slice());
        let (state, kura, _) = configured_initial_genesis_state(
            &manifest,
            Some(&config),
            &GenesisBlock(genesis.block().clone()),
        )
        .unwrap();
        let chain = CertifiedTestChain::from_prepared(PreparedTestChainConfig {
            genesis,
            manifest,
            state: Arc::new(state),
            kura,
            validator_keys: custody,
            clock: manager.key_pair.clone(),
            lane_blocks: Arc::new(NoLanes),
        })
        .unwrap();
        assert_eq!(chain.network_id(), manager.network_id);
        assert_eq!(
            chain.state().ivm_execution_budget().limit_bytes(),
            iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES
        );
        assert_eq!(
            chain.state().ivm_execution_budget().limit_bytes(),
            1024 * 1024 * 1024
        );
        drop(ports);
        Self {
            _directory: directory,
            prepared,
            manager_key: manager.key_pair,
            manager_account: manager.account,
            chain,
            storage_root,
        }
    }

    fn paid(&mut self, instruction: InstructionBox) {
        let mut builder = TransactionBuilder::new(
            self.chain.network_id(),
            self.manager_account.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(now_ms()));
        builder.set_ttl(Duration::from_secs(600));
        let builder = builder.with_instructions([instruction]);
        let draft = builder.clone().sign(self.manager_key.private_key());
        let header = self.chain.state().latest_block_header_fast().unwrap();
        let view = self.chain.state().view();
        let quote = iroha_core::executor::quote_nexus_fee_admission_draft(
            view.world(),
            view.nexus(),
            view.pipeline(),
            &view.zk().gas,
            draft.payload(),
            header.creation_time_ms,
            iroha_core::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .expect("original native quote time"),
            header.height().get() + 1,
            Some(DataSpaceId::UNIVERSAL),
        )
        .unwrap();
        assert!(
            !quote.quote.charges.is_empty(),
            "generated native work must pay the original Nexus fees"
        );
        let transaction = builder
            .with_fee_payment_intent(quote.recommended_intent)
            .sign(self.manager_key.private_key());
        drop(view);
        assert_eq!(self.chain.commit(vec![transaction]), vec![true]);
    }

    fn key(&self, slot: u8, role: Role) -> KeyPair {
        let manifest = self.prepared.stream_token_authorities().unwrap().unwrap();
        let provider = &manifest.providers[usize::from(slot)];
        let account = &provider.authority(role).unwrap().account;
        let public = account.try_signatory().unwrap();
        load_bound_software_key_v1(
            &self
                .prepared
                .context
                .client_config
                .parent()
                .unwrap()
                .join("runtime")
                .join("stream-token-authorities")
                .join("providers")
                .join(slot.to_string())
                .join(role.credential_filename()),
            public,
        )
        .unwrap()
    }

    fn enroll(&mut self, slot: u8) -> SignerCustodyPolicyV1 {
        let plans = self.prepared.provider_service_plans().unwrap().unwrap();
        let plan = &plans[usize::from(slot)];
        let provider = plan.provider_id();
        let token = self.key(slot, Role::TokenSigner);
        let attester = self.key(slot, Role::CustodyAttester);
        // This is an ordinary explicit test policy, not a reconstruction of private generated
        // bootstrap policies. Every account/key and native permission comes from original genesis.
        let policy = SignerCustodyPolicyV1 {
            binding: SignerCustodyBindingV1 {
                chain_id: self.chain.state().chain_id_ref().to_string(),
                network_id: *self.chain.network_id().as_bytes(),
                runtime_handle: "software://stock-positive/runtime".into(),
                key_handle: "software://stock-positive/token".into(),
                service_id: "stock-positive-stream-token".into(),
                administrator_id: "stock-positive-custodian".into(),
                role: SignerRoleV1::StreamToken,
                purpose: SignerPurposeBindingV1::StreamToken {
                    provider_id: *provider.as_bytes(),
                },
                algorithm: SignerKeyAlgorithmV1::Ed25519,
                public_key: token.public_key().clone(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: *Hash::new([slot, 1]).as_ref(),
            },
            attester_authority: SignerCustodyAuthorityV1 {
                service_id: "stock-positive-attester".into(),
                administrator_id: "stock-positive-independent-custodian".into(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: *Hash::new([slot, 2]).as_ref(),
            },
            attester_public_key: attester.public_key().clone(),
            active_from_unix_ms: plan.admission_material().issued_at * 1000,
            active_until_unix_ms: plan.admission_material().retention_epoch * 1000,
            max_validity_ms: 600_000,
            max_anchor_age_ms: 300_000,
        };
        policy.validate().unwrap();
        self.paid(
            MutateSorafsStreamTokenCustody {
                provider_id: provider,
                expected_revision: 0,
                expected_digest: [0; 32],
                action: SorafsStreamTokenCustodyActionV1::Configure(
                    norito::encode_canonical(&policy).unwrap(),
                ),
            }
            .into(),
        );
        let current = read_stream_token_custody_control_at_v1(
            &self.chain.state().view(),
            &policy.binding,
            self.chain.height(),
        )
        .unwrap()
        .unwrap();
        let issued = now_ms().max(
            self.chain
                .committed(self.chain.height())
                .block()
                .header()
                .creation_time_ms,
        );
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: policy.binding.clone(),
            authority: policy.attester_authority.clone(),
            anchor: current.anchor,
            sequence: current.state.next_sequence,
            predecessor_digest: current.state.predecessor_digest,
            issued_at_unix_ms: issued,
            expires_at_unix_ms: issued + 600_000,
            evidence_digest: *Hash::new([slot, 3]).as_ref(),
            revoked: false,
        };
        let signature = Signature::try_new(
            attester.private_key(),
            &statement.signing_payload().unwrap(),
        )
        .unwrap();
        let record = SignerCustodyRecordV1 {
            statement,
            attestation: signature.payload().try_into().unwrap(),
        };
        self.paid(
            MutateSorafsStreamTokenCustody {
                provider_id: provider,
                expected_revision: 1,
                expected_digest: current.anchor.state_digest,
                action: SorafsStreamTokenCustodyActionV1::Enroll(
                    norito::encode_canonical(&record).unwrap(),
                ),
            }
            .into(),
        );
        policy
    }

    fn refresh_adverts(&self, cache: &Cache) {
        let now = now_ms() / 1000;
        let plans = self.prepared.provider_service_plans().unwrap().unwrap();
        for plan in &plans {
            let advert = self
                .prepared
                .provider_advert(plan.provider_id(), now)
                .unwrap();
            let policy = cache.blocking_read().validation_policy();
            let prepared = policy.prepare(advert, now).unwrap();
            cache
                .blocking_write()
                .commit_prepared(prepared, now)
                .unwrap();
        }
    }

    fn wait_for_real_clock(&self) {
        let until = Instant::now() + Duration::from_secs(30);
        let native = self
            .chain
            .committed(self.chain.height())
            .block()
            .header()
            .creation_time_ms;
        while now_ms() < native {
            assert!(
                Instant::now() < until,
                "fixture native cut remains in the future"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn generated_stock_callback_and_tls_seed_ingress_use_original_native_owners() {
    let mut fixture = Generated::new();
    fixture.paid(
        Log::new(
            iroha_data_model::Level::INFO,
            "stock discovery paid prerequisite".into(),
        )
        .into(),
    );
    let policies = [fixture.enroll(0), fixture.enroll(1), fixture.enroll(2)];
    assert_eq!(fixture.chain.height(), 8);
    fixture.wait_for_real_clock();
    let state = Arc::clone(fixture.chain.state());
    let budget = state.ivm_execution_budget();
    let plans = fixture.prepared.provider_service_plans().unwrap().unwrap();
    let provider_listeners = plans.each_ref().map(|plan| {
        let url: reqwest::Url = plan.https_origin().parse().unwrap();
        let listener = std::net::TcpListener::bind((
            Ipv4Addr::LOCALHOST,
            url.port_or_known_default().unwrap(),
        ))
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    });
    let originals = plans.each_ref().map(|plan| {
        GeneratedLocalProviderTransportV1::select(
            plan.network_id(),
            fixture.chain.state().chain_id_ref().as_str(),
            plan.provider_id(),
            &plan.reserve_terms().provider_account,
            plan.admission_material(),
        )
        .unwrap()
    });
    let capabilities = plans
        .iter()
        .flat_map(|plan| {
            plan.admission_material()
                .proposal
                .capabilities
                .iter()
                .map(|cap| cap.cap_type)
        })
        .collect::<Vec<_>>();
    let mut adverts = iroha_torii::sorafs::ProviderAdvertCache::new(
        capabilities,
        Arc::new(iroha_torii::sorafs::AdmissionRegistry::from_state(
            Arc::clone(&state),
        )),
    );
    let observed = now_ms() / 1000;
    for plan in &plans {
        let advert = fixture
            .prepared
            .provider_advert(plan.provider_id(), observed)
            .unwrap();
        let prepared = adverts
            .validation_policy()
            .prepare(advert, observed)
            .unwrap();
        adverts.commit_prepared(prepared, observed).unwrap();
    }
    let cache = Arc::new(tokio::sync::RwLock::new(adverts));
    // The test retains the same conservative original-graph allowance as stock selection.
    let retained_bytes = plans
        .iter()
        .map(|plan| {
            norito::canonical_decode_limits(
                norito::canonical_frame_len(plan.admission_material()).unwrap(),
            )
            .max_total_allocated_bytes()
                + norito::canonical_frame_len(&plan.reserve_terms().provider_account).unwrap()
        })
        .sum::<usize>()
        * 2;
    let layout = Layout::array::<u8>(retained_bytes).unwrap();
    let charge = budget
        .try_reserve(layout)
        .unwrap()
        .try_split(layout)
        .unwrap();
    let discovery = discovery::prepare(
        Arc::clone(&state),
        Arc::clone(&cache),
        originals.clone(),
        Duration::from_secs(30),
        charge,
    )
    .unwrap();
    assert!(discovery(ProviderId::new([0; 32])).is_err());
    for (index, plan) in plans.iter().enumerate() {
        fixture.refresh_adverts(&cache);
        let current = discovery(plan.provider_id()).expect(
            "stock current callback must fit the original 1 GiB pool and verify native authority",
        );
        originals[index].authenticate_current(&current).unwrap();
        assert_eq!(
            current.token_public_key(),
            &policies[index].binding.public_key
        );
        assert_eq!(current.token_key_revision(), 1);
        assert_eq!(budget.limit_bytes(), 1024 * 1024 * 1024);
    }
    // A fresh native revocation must invalidate the old candidate and cached finality cursor.
    for listener in &provider_listeners {
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "native callback does not contact provider data endpoints"
        );
    }
    let policy = &policies[2];
    let control = read_stream_token_custody_control_at_v1(
        &state.view(),
        &policy.binding,
        fixture.chain.height(),
    )
    .unwrap()
    .unwrap();
    fixture.paid(
        MutateSorafsStreamTokenCustody {
            provider_id: plans[2].provider_id(),
            expected_revision: 2,
            expected_digest: control.anchor.state_digest,
            action: SorafsStreamTokenCustodyActionV1::Revoke(
                SorafsStreamTokenCustodyRevocationV1 {
                    signer: true,
                    attester: false,
                },
            ),
        }
        .into(),
    );
    fixture.wait_for_real_clock();
    fixture.refresh_adverts(&cache);
    assert!(discovery(plans[2].provider_id()).is_err());
    assert!(discovery(plans[0].provider_id()).is_ok());
    let retained = budget.reserved_bytes();
    drop(discovery);
    assert!(
        retained - budget.reserved_bytes() >= retained_bytes + 3 * 16 * 1024 * 1024,
        "callback-owned original and result reservations are released"
    );

    let publication = fixture
        .prepared
        .publication_service_plan()
        .unwrap()
        .unwrap();
    let config = publication.installation_config();
    let (events, _) = tokio::sync::broadcast::channel(16);
    let queue = Arc::new(Queue::from_config(
        iroha_config::parameters::actual::Queue::default(),
        events,
    ));
    let node = sorafs_node::NodeHandle::try_new(
        sorafs_node::config::StorageConfig::builder()
            .enabled(true)
            .provider_id(Some(publication.seed_provider()))
            .data_dir(fixture.storage_root.clone())
            .build(),
    )
    .unwrap();
    let context = MusubiPublicationPrivateServiceContextV1::new(
        fixture.chain.network_id(),
        Arc::clone(&state),
        queue,
        node,
    );
    let factory = select_factory(&config, Some(&context), Some(cache), None, false)
        .unwrap()
        .unwrap();
    let deployment = factory
        .build(context)
        .expect("stock opens all original generated publication owners");
    let signer = SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(
        fixture.manager_account.clone(),
        fixture.manager_key.clone(),
    )
    .unwrap();
    let client =
        AuthenticatedMusubiPublicationRuntimeClientV1::from_generated_local_authorization_signer(
            fixture.chain.network_id(),
            fixture.manager_account.clone(),
            Arc::new(signer),
            publication.publication_transport().unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
    let base = client.generated_local_base_url().unwrap();
    let (mut binding, commitment, plan, car) = iroha_musubi_service::seed_test_support::fixture();
    binding.network_id = fixture.chain.network_id();
    binding.publisher = fixture.manager_account.clone();
    binding.ingress_broker = publication.ingress_broker().clone();
    binding.seed_provider = publication.seed_provider();
    let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(&plan, &commitment).unwrap();
    let request = MusubiSeedIngressStageRequestV1 {
        version: 1,
        operation_id: [0x59; 32],
        binding: binding.clone(),
        commitment: commitment.clone(),
        plan_digest: witness.canonical_digest().unwrap(),
        plan_length: witness.canonical_len().unwrap(),
    };
    // All fallible fixture/client/request preparation finishes before owning a live listener.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let (shutdown, mut task) = runtime.block_on(async move {
        let mut supervisor = iroha_futures::supervisor::Supervisor::new();
        let shutdown = supervisor.shutdown_signal();
        supervisor.monitor(deployment.start(shutdown.clone()));
        (shutdown, tokio::spawn(supervisor.start()))
    });
    let receipt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.stage_seed_ingress(base, &request, &plan, &mut Cursor::new(&car))
    }));
    // A request refusal or panic must still signal and join this test's owned listener.
    shutdown.send();
    let joined = runtime.block_on(async {
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(15), &mut task).await {
            Some(result)
        } else {
            // Only this test's supervisor is cancelled. Its cancellation guard withdraws
            // and cancels its own children; no process or unrelated task is signalled.
            task.abort();
            let _terminated = task.await;
            None
        }
    });
    joined
        .expect("owned TLS shutdown completed within its bound")
        .unwrap()
        .unwrap();
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let receipt = receipt.expect("actual TLS seed ingress returns a verified broker receipt");
    receipt.verify(&binding, now_ms()).unwrap();
    let seed = MusubiSeedStagingBackendV1::open(
        &config.custody_root.join("seed"),
        publication.seed_provider(),
        config.max_seed_records,
        config.max_seed_bytes,
    )
    .unwrap();
    let (retained_plan, retained_car) = seed.read_staged_car(&receipt, &commitment).unwrap();
    assert_eq!(retained_plan, plan);
    assert_eq!(retained_car, car);
    assert_eq!(budget.limit_bytes(), 1024 * 1024 * 1024);
}
