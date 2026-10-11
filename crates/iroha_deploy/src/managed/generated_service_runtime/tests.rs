//! Genuine original-profile renderer controls; no worker, native admission or Serving claim.
use super::*;
use crate::{
    localnet::service_authorities::{
        NetworkServiceAuthorityRole as NetworkRole, StreamTokenAuthorityRole as Role,
    },
    managed::{
        ManagedInitialGatewaySetup, ManagedInitialProviderIngestAuthority,
        ManagedInitialReputationPolicy, ManagedInitialReservePolicy,
        ManagedReserveAccountRegistration,
        native_operation::test_support::native_fixture::{NativeFixture, quote_instructions},
        provider_funding::{ProviderFundingBootstrap, ProviderFundingProgress},
    },
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::{InstructionBox, Log},
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{collections::BTreeMap, io, net::TcpListener, time::Duration};

fn fixture(name: &str) -> (tempfile::TempDir, PreparedLocalnet, Vec<TcpListener>) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        name,
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    drop(ports);
    let peers = prepared
        .peers
        .iter()
        .map(|peer| {
            let url: url::Url = peer.torii_url.parse().unwrap();
            let listener = TcpListener::bind(("127.0.0.1", url.port().unwrap())).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .collect();
    (temporary, prepared, peers)
}
fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            AssetDefinitionId::parse_address_literal(
                crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
            )
            .unwrap(),
            Quantity::from(1_000u64),
        )]),
        deadline: Instant::now() + Duration::from_secs(300),
    }
}
fn select(prepared: &PreparedLocalnet) -> GeneratedServicePolicies {
    let mut parent = ManagedServiceBootstrap::open(prepared).unwrap();
    parent.authorize_test_startup(&options()).unwrap().unwrap();
    parent.selected_policies().unwrap()
}
fn no_http(peers: &[TcpListener]) {
    for peer in peers {
        assert_eq!(peer.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
}
fn actual(
    revision: &GeneratedServiceRuntimeRevision,
    index: usize,
) -> iroha_config::parameters::actual::Root {
    let peer = revision.peer(index).unwrap();
    let bytes = iroha_fs::read_private(peer.path(), MAX_CONFIG_BYTES).unwrap();
    let table = crate::secret_toml::parse_table(
        std::str::from_utf8(&bytes).unwrap(),
        "test derived config",
    )
    .unwrap();
    config::parse(table, peer.path(), true).unwrap()
}

/// The fixture commits ordinary wallet transactions through the certified native test chain.
/// It proves actual child history only; it does not claim running peers or service readiness.
struct Genuine {
    _temporary: tempfile::TempDir,
    prepared: PreparedLocalnet,
    owner: GeneratedServiceRuntime,
    native: NativeFixture,
    selection: RuntimeSelection,
    components: [Arc<ProviderComponent>; 3],
    carriers: Vec<ManagedTransactionFinality>,
    options: BoundedTransactionOptions,
    catalog: GeneratedServiceRuntimeRevision,
}
impl Genuine {
    fn new(name: &str, full_parent: bool, short_initial: bool) -> Self {
        Self::with_material_preflight(name, full_parent, short_initial, false)
    }
    fn with_material_preflight(
        name: &str,
        full_parent: bool,
        short_initial: bool,
        retain_before_first_render: bool,
    ) -> Self {
        assert!(!full_parent || !short_initial);
        assert!(!retain_before_first_render || full_parent);
        let (temporary, prepared, peers) = fixture(name);
        // Native wallet readers own these original loopback ports during preparation.
        drop(peers);
        let mut options = options();
        options.deadline = Instant::now() + Duration::from_secs(600);
        let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
        let authorization = parent.authorize_test_startup(&options).unwrap().unwrap();
        let utc = authorization.test_terms().signing_deadline_unix_ms;
        drop(parent);
        let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
        let mut selection = RuntimeSelection::read(&owner.authority).unwrap();
        let catalog = owner.prepare_catalog(options.deadline).unwrap();
        let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
        let log = quote_instructions(
            &native,
            &owner.authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "runtime component prerequisites".into(),
            ))],
        );
        native.bootstrap_commit(&owner.authority, &log);
        let mut carriers = Vec::new();
        if full_parent {
            let mut reserve = ManagedInitialReservePolicy::open(&prepared).unwrap();
            carriers.push(
                reserve
                    .bootstrap_native(
                        &mut native,
                        &selection.policies.network.reserve,
                        utc,
                        &options,
                    )
                    .finalized
                    .unwrap(),
            );
        }
        for index in 0..3 {
            let selected = &selection.policies.providers[index];
            let provider = selected.provider_id;
            let mut custody = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
            carriers.push(
                custody
                    .bootstrap_native_configure(&mut native, &selected.custody, utc, &options)
                    .finalized
                    .unwrap(),
            );
            let initial = if short_initial {
                // A genuine shorter native enrollment under the unchanged generated policy.
                // This component-only fixture intentionally does not claim parent completion:
                // its deliberately short interval differs from the generated day-long selection.
                let now = now_ms().unwrap();
                ManagedCustodyEnrollmentInterval {
                    issued_at_unix_ms: now,
                    expires_at_unix_ms: now + if index == 1 { 120_000 } else { 30_000 },
                    deadline_unix_ms: now + 20_000,
                }
            } else {
                selected.initial_enrollment(now_ms().unwrap(), utc).unwrap()
            };
            selection.initial[index] = Some(initial);
            carriers.push(
                custody
                    .bootstrap_native_enroll(
                        &mut native,
                        &selected.custody,
                        selection.initial(index).unwrap(),
                        &options,
                    )
                    .finalized
                    .unwrap(),
            );
            drop(custody);
            if full_parent {
                let mut account =
                    ManagedReserveAccountRegistration::open(&prepared, provider).unwrap();
                carriers.push(
                    account
                        .bootstrap_native(
                            &mut native,
                            &selection.policies.network.reserve,
                            selection.plans[index].reserve_terms(),
                            utc,
                            &options,
                        )
                        .finalized
                        .unwrap(),
                );
                drop(account);
                let mut funding = ProviderFundingBootstrap::open(&prepared, provider).unwrap();
                let ProviderFundingProgress::Complete {
                    request,
                    approval,
                    credit,
                    capacity,
                } = funding.bootstrap_native(
                    &mut native,
                    &selection.policies.network.reserve,
                    utc,
                    &options,
                )
                else {
                    panic!("actual funding owners must retain complete history")
                };
                let request = request.unwrap();
                let approval = approval.unwrap();
                assert_eq!(request.movement_id(), approval.request().movement_id());
                carriers.extend([*request.original(), *approval.original(), credit, capacity]);
                drop(funding);
                let mut ingest =
                    ManagedInitialProviderIngestAuthority::open(&prepared, provider).unwrap();
                carriers.push(
                    ingest
                        .bootstrap_native(&mut native, &selected.provider_ingest, utc, &options)
                        .finalized
                        .unwrap(),
                );
                drop(ingest);
                let mut gateway = ManagedInitialGatewaySetup::open(&prepared, provider).unwrap();
                carriers.push(
                    gateway
                        .bootstrap_native(&mut native, &selected.gateway, utc, &options)
                        .finalized
                        .unwrap(),
                );
            }
        }
        if full_parent {
            let mut reputation = ManagedInitialReputationPolicy::open(&prepared).unwrap();
            carriers.push(
                reputation
                    .bootstrap_native(
                        &mut native,
                        &selection.policies.gateway_labels(),
                        &selection.policies.network.reputation,
                        utc,
                        &options,
                    )
                    .finalized
                    .unwrap(),
            );
            drop(reputation);
            let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
            let ServiceBootstrapProgress::Complete(history) =
                parent.recover(options.deadline).unwrap()
            else {
                panic!("all original native children must be recoverable")
            };
            assert_eq!(history.ordered_carriers().unwrap(), carriers);
            assert_eq!(carriers.len(), 29);
            assert_eq!(
                carriers.iter().map(|c| c.height).collect::<Vec<_>>(),
                (3..=31).collect::<Vec<_>>()
            );
        }
        let enrollments = std::array::from_fn(|index| {
            let provider = selection.plans[index].provider_id();
            let custody = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
            custody
                .retained_initial_enrollment(
                    &selection.policies.providers[index].custody,
                    selection.initial(index).unwrap(),
                    options.deadline,
                )
                .unwrap()
        });
        let components = if retain_before_first_render {
            assert!(!owner.authority.directory.path().join("providers").exists());
            let before = owner.authority.directory.entries(8).unwrap();
            let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
            let ServiceBootstrapProgress::Complete(history) =
                parent.recover(options.deadline).unwrap()
            else {
                panic!("material preflight requires exact complete native history")
            };
            drop(parent);
            // Use the shared post-selection material owner with actual historical originals.
            // This does not emulate native discovery or claim current HTTP eligibility.
            let (_, components, required) = owner
                .retain_selected_components(
                    RuntimeSelection::read(&owner.authority).unwrap(),
                    &history,
                    enrollments,
                    options.deadline,
                )
                .unwrap();
            assert_eq!(required.originals(), carriers);
            let mut expected = before;
            expected.push("providers".into());
            expected.sort();
            assert_eq!(owner.authority.directory.entries(8).unwrap(), expected);
            components
        } else {
            enrollments
                .into_iter()
                .enumerate()
                .map(|(index, enrollment)| {
                    ProviderComponent::retain(
                        &owner.authority.directory,
                        selection.identity(&owner.authority, index).unwrap(),
                        enrollment,
                        None,
                        Retention::PublishCurrent,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or_else(|_| panic!("exactly three original provider components"))
        };
        Self {
            _temporary: temporary,
            prepared,
            owner,
            native,
            selection,
            components,
            carriers,
            options,
            catalog,
        }
    }
    fn peers(&self) -> Vec<TcpListener> {
        self.prepared
            .peers
            .iter()
            .map(|peer| {
                let url: url::Url = peer.torii_url.parse().unwrap();
                let listener = TcpListener::bind(("127.0.0.1", url.port().unwrap())).unwrap();
                listener.set_nonblocking(true).unwrap();
                listener
            })
            .collect()
    }
    fn initial(&self, index: usize) -> RetainedCustodyEnrollment {
        let custody = ManagedStreamTokenCustody::open(
            &self.prepared,
            self.selection.plans[index].provider_id(),
        )
        .unwrap();
        custody
            .retained_initial_enrollment(
                &self.selection.policies.providers[index].custody,
                self.selection.initial(index).unwrap(),
                self.options.deadline,
            )
            .unwrap()
    }
    fn renew(&mut self, index: usize) -> Arc<ProviderComponent> {
        let old = self.components[index].selection();
        let midpoint =
            old.issued_at_unix_ms + (old.expires_at_unix_ms - old.issued_at_unix_ms).div_ceil(2);
        let limit = Instant::now() + Duration::from_secs(30);
        while now_ms().unwrap() < midpoint {
            assert!(
                Instant::now() < limit,
                "real native renewal midpoint did not arrive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut custody = ManagedStreamTokenCustody::open(
            &self.prepared,
            self.selection.plans[index].provider_id(),
        )
        .unwrap();
        let enrollment = custody.bootstrap_native_renew(
            &mut self.native,
            &self.selection.policies.providers[index].custody,
            old.sequence + 1,
            now_ms().unwrap() + 60_000,
            &self.options,
        );
        let component = ProviderComponent::retain(
            &self.owner.authority.directory,
            self.selection
                .identity(&self.owner.authority, index)
                .unwrap(),
            enrollment,
            Some(&self.components[index]),
            Retention::PublishCurrent,
        )
        .unwrap();
        self.carriers.push(component.finalized());
        component
    }
    fn intent(&self, components: &[Arc<ProviderComponent>; 3]) -> Intent {
        let mut intent = self.catalog.manifest.intent.clone();
        intent.stage = GeneratedRuntimeStage::StreamTokens;
        intent.components = Some(std::array::from_fn(|index| components[index].digest()));
        intent.required = RequiredTransactions::from_originals(self.carriers.clone())
            .unwrap()
            .identities()
            .to_vec();
        intent
    }
    fn render(&self, index: usize, components: &[Arc<ProviderComponent>; 3]) -> (String, PathBuf) {
        let root = PrivateDirectory::open_exact(generation_path(&self.prepared).unwrap()).unwrap();
        let original = root
            .read(format!("peer{index}.toml"), MAX_CONFIG_BYTES)
            .unwrap();
        let destination = root
            .path()
            .join(format!("peer{index}.projection-only.toml"));
        let text = config::render(
            &self.owner.authority,
            &self.selection,
            &self.intent(components),
            Some(components),
            index,
            &original,
            &destination,
            &self.owner.authority.directory,
            components.get(index).map(|c| c.directory()),
        )
        .unwrap();
        assert!(!destination.exists());
        (text.to_string(), destination)
    }
}

#[test]
fn catalog_first_launch_retains_exact_siblings_roles_topology_and_originals_without_http() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-catalog");
    let originals: Vec<_> = prepared
        .peers
        .iter()
        .map(|peer| {
            iroha_fs::read_private(&peer.config_path, MAX_CONFIG_BYTES)
                .unwrap()
                .to_vec()
        })
        .collect();
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    assert!(GeneratedServiceRuntime::open(&prepared).is_err());
    let expected_publication = prepared.publication_service_plan().unwrap().unwrap();
    let (selection, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            RuntimeSelection::read(&owner.authority).unwrap()
        });
    // The bootstrap owner and three custody owners independently authenticate their profiles.
    // Reading original provider/compliance/publication plans on this live owner adds no parse.
    assert_eq!(parses, 4);
    assert_eq!(
        selection.publication.configuration_table().unwrap(),
        expected_publication.configuration_table().unwrap()
    );
    assert!(selection.initial.iter().all(Option::is_none));
    let revision = owner.prepare_catalog(options().deadline).unwrap();
    assert_eq!(revision.stage(), GeneratedRuntimeStage::Catalog);
    assert!(revision.required_transactions().is_empty());
    assert!(revision.observation_floor().is_err());
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    assert_eq!(
        revision.provider_ids(),
        manifest.providers.each_ref().map(|p| p.provider_id)
    );
    for provider in revision.provider_ids() {
        assert!(revision.selected_enrollment(provider).unwrap().is_none());
    }
    assert!(
        revision
            .selected_enrollment(ProviderId::new([0; 32]))
            .is_err()
    );
    for index in 0..4 {
        assert_eq!(
            iroha_fs::read_private(&prepared.peers[index].config_path, MAX_CONFIG_BYTES)
                .unwrap()
                .as_slice(),
            originals[index]
        );
        assert_eq!(
            revision.peer(index).unwrap().path().parent().unwrap(),
            prepared.peers[index].config_path.parent().unwrap()
        );
        assert_eq!(
            revision.cwd(),
            prepared.context.client_config.parent().unwrap()
        );
        let config = actual(&revision, index);
        assert!(config.torii.sorafs_discovery.discovery_enabled);
        assert!(config.torii.sorafs_discovery.admission.is_some());
        assert!(config.musubi_publication.installation.is_none());
        assert_eq!(config.nexus.lane_catalog.lane_count().get(), 1);
        assert_eq!(config.torii.sorafs_storage.enabled, index < 3);
        assert!(!config.torii.sorafs_storage.stream_tokens.enabled);
        assert!(
            config
                .torii
                .sorafs_storage
                .provider_ingest_runtime
                .is_none()
        );
        assert!(config.torii.sorafs_storage.stream_tokens.signer.is_none());
        assert!(!config.torii.sorafs_repair.enabled);
        assert!(!config.torii.sorafs_por.enabled);
        assert!(!config.torii.sorafs_storage.reserve_worker.enabled);
        assert!(!config.torii.sorafs_storage.orderbook_worker.enabled);
        let signers = &config.torii.sorafs_storage.native_transaction_signers;
        if index < 3 {
            let inventory = &manifest.providers[index];
            for (binding, role) in [
                (signers.proof_outcome.as_ref().unwrap(), Role::ProofOutcome),
                (signers.repair.as_ref().unwrap(), Role::Repair),
                (signers.orderbook.as_ref().unwrap(), Role::OrderbookMatcher),
            ] {
                assert_eq!(
                    binding.authority,
                    inventory.authority(role).unwrap().account
                );
                assert_eq!(
                    binding
                        .software_credential
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .unwrap(),
                    role.credential_filename()
                );
                assert_eq!(
                    &binding.public_key,
                    inventory
                        .authority(role)
                        .unwrap()
                        .account
                        .try_signatory()
                        .unwrap()
                );
                assert_ne!(binding.policy_digest, [0; 32]);
            }
            let reserve = signers.reserve.as_ref().unwrap();
            let account = &manifest
                .network
                .authority(NetworkRole::ReserveOperations)
                .unwrap()
                .account;
            assert_eq!(&reserve.authority, account);
            assert_eq!(&reserve.public_key, account.try_signatory().unwrap());
            assert_eq!(
                reserve
                    .software_credential
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .unwrap(),
                NetworkRole::ReserveOperations.credential_filename()
            );
            assert_ne!(reserve.policy_digest, [0; 32]);
            let compliance = config.torii.sorafs_gateway.compliance.unwrap();
            let plan = prepared
                .gateway_compliance_plan(inventory.provider_id)
                .unwrap()
                .unwrap();
            assert_eq!(compliance.policy_id, plan.trust_policy().policy_id);
            assert_eq!(
                compliance.gateway_id,
                policies
                    .provider(inventory.provider_id)
                    .unwrap()
                    .gateway
                    .compliance_gateway_id
            );
            assert_eq!(compliance.catalog_threshold, 2);
            assert_eq!(compliance.gateway_ack_threshold, 1);
            assert!(compliance.feeds.is_empty());
            assert_eq!(
                compliance.max_catalog_validity.as_secs(),
                plan.catalog_validity_seconds()
            );
            assert!(config.torii.transport.https.is_some());
        } else {
            assert_eq!(
                *signers,
                iroha_config::parameters::actual::SorafsNativeTransactionSignerBindings::default()
            );
            assert!(config.torii.sorafs_gateway.compliance.is_none());
            assert!(config.torii.transport.https.is_none());
        }
    }
    owner.validate(&revision).unwrap();
    owner.validate_for(&prepared, &revision).unwrap();
    let mut foreign = prepared.clone();
    foreign.context.name.push_str("-other");
    assert!(owner.validate_for(&foreign, &revision).is_err());
    assert!(owner.prepare_catalog(Instant::now()).is_err());

    assert!(revision.peer(4).is_err());
    no_http(&peers);
}

#[test]
fn exact_publication_reopens_and_changed_config_or_manifest_is_never_overwritten() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-reopen");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let first = owner.prepare_catalog(options().deadline).unwrap();
    let name = first.manifest_name.clone();
    let original_manifest = owner
        .authority
        .directory
        .read(&name, MAX_MANIFEST_BYTES)
        .unwrap()
        .to_vec();
    let first_path = first.peer(0).unwrap().path().to_owned();
    let bytes = iroha_fs::read_private(&first_path, MAX_CONFIG_BYTES)
        .unwrap()
        .to_vec();
    drop(owner);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let second = owner.prepare_catalog(options().deadline).unwrap();
    assert_eq!(first_path, second.peer(0).unwrap().path());
    assert_eq!(
        first.peer(0).unwrap().blake3(),
        second.peer(0).unwrap().blake3()
    );
    assert_eq!(
        owner
            .authority
            .directory
            .read(&name, MAX_MANIFEST_BYTES)
            .unwrap()
            .as_slice(),
        original_manifest
    );
    let root = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let held_config = first_path.with_extension("held");
    std::fs::rename(&first_path, &held_config).unwrap();
    assert!(owner.prepare_catalog(options().deadline).is_err());
    assert!(
        !first_path.exists(),
        "committed config must never be recreated"
    );
    assert_eq!(std::fs::read(&held_config).unwrap(), bytes);
    let mut changed_manifest: Manifest = norito::decode_canonical(&original_manifest).unwrap();
    changed_manifest.launch_digests[3][0] ^= 1;
    owner
        .authority
        .directory
        .write_atomic(
            &name,
            &encode(&changed_manifest, MAX_MANIFEST_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(owner.prepare_catalog(options().deadline).is_err());
    assert!(
        !first_path.exists(),
        "changed aggregate must fail before config publication"
    );
    owner
        .authority
        .directory
        .write_atomic(&name, &original_manifest, PublishMode::Replace)
        .unwrap();
    std::fs::rename(&held_config, &first_path).unwrap();
    root.write_atomic(
        first_path.file_name().unwrap(),
        b"modified = true\n",
        PublishMode::Replace,
    )
    .unwrap();
    assert!(owner.validate(&second).is_err());
    assert!(owner.prepare_catalog(options().deadline).is_err());
    assert_eq!(
        iroha_fs::read_private(&first_path, MAX_CONFIG_BYTES)
            .unwrap()
            .as_slice(),
        b"modified = true\n"
    );
    root.write_atomic(
        first_path.file_name().unwrap(),
        &bytes,
        PublishMode::Replace,
    )
    .unwrap();
    owner
        .authority
        .directory
        .write_atomic(&name, b"not a manifest", PublishMode::Replace)
        .unwrap();
    assert!(owner.validate(&second).is_err());
    assert!(owner.prepare_catalog(options().deadline).is_err());
    assert_eq!(
        owner
            .authority
            .directory
            .read(&name, MAX_MANIFEST_BYTES)
            .unwrap()
            .as_slice(),
        b"not a manifest"
    );
    no_http(&peers);
}

#[test]
fn absent_parent_and_unprepared_native_children_cannot_publish_token_revision() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-unprepared");
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    assert!(owner.prepare_catalog(options().deadline).is_err());
    assert!(
        owner
            .prepare_current_stream_tokens(options().deadline)
            .is_err()
    );
    assert_eq!(owner.authority.directory.entries(16).unwrap().len(), 1); // operation.lock only
    select(&prepared);
    assert!(
        owner
            .prepare_current_stream_tokens(options().deadline)
            .is_err()
    );
    assert_eq!(owner.authority.directory.entries(16).unwrap().len(), 1);
    no_http(&peers);
}

#[test]
fn token_projection_uses_exact_policies_credentials_and_fee_intent_without_claiming_native_evidence()
 {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-token-projection", false, false);
    let peers = fixture.peers();
    for index in 0..3 {
        let policies = &fixture.selection.policies.providers[index];
        let inventory = &fixture.owner.authority.manifest.providers[index];
        let (text, destination) = fixture.render(index, &fixture.components);
        let actual = config::parse(
            crate::secret_toml::parse_table(&text, "projection only").unwrap(),
            &destination,
            true,
        )
        .unwrap();
        let tokens = actual.torii.sorafs_storage.stream_tokens;
        let signer = tokens.signer.unwrap();
        assert_eq!(signer.policy_digest, policies.custody.binding.policy_digest);
        assert_eq!(
            signer.attester.authority.policy_digest,
            policies.custody.attester_authority.policy_digest
        );
        assert_eq!(
            signer.observer.authority.policy_digest,
            policies.observer_authority.policy_digest
        );
        let native = signer.native.unwrap();
        assert_eq!(
            native.fee_payment,
            fixture.selection.policies.network.runtime_fee_payment
        );
        assert_eq!(
            native.operator,
            inventory.authority(Role::IssuerOperator).unwrap().account
        );
        assert_ne!(
            native.operator,
            fixture
                .selection
                .policies
                .network
                .reserve
                .operations_authority
        );
        assert_eq!(
            native.custody_record,
            fixture.components[index]
                .directory()
                .path()
                .join(custody_name(
                    fixture.components[index].selection().bytes_digest
                ))
        );
        assert_eq!(
            native.receipt_journal,
            fixture.components[index]
                .directory()
                .path()
                .join("stream-token-receipts")
        );
        let gateway = tokens.admission_native.unwrap();
        assert_eq!(
            gateway.fee_payment,
            fixture.selection.policies.network.runtime_fee_payment
        );
        assert!(policies.gateway.operators.contains(&gateway.operator));
        assert!(policies.gateway.observers.contains(&gateway.observer));
        assert_eq!(
            gateway.reputation_recorder,
            fixture
                .selection
                .policies
                .network
                .reputation
                .token_recorder_authority
        );
        assert_eq!(
            tokens.admission_provider_policy_digest,
            Some(policies.gateway.qualification.policy_digest)
        );
        assert!(!destination.exists());
    }
    no_http(&peers);
}

#[test]
fn private_publication_bounds_and_changed_bytes_fail_without_partial_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let root = PrivateDirectory::open_or_create(temporary.path().join("runtime")).unwrap();
    assert!(retain_exact(&root, "bound", &[7; 5], 4).is_err());
    assert!(retain_exact(&root, "bound", &[], 4).is_err());
    assert!(root.entries(8).unwrap().is_empty());
    retain_exact(&root, "bound", &[7; 4], 4).unwrap();
    retain_exact(&root, "bound", &[7; 4], 4).unwrap();
    assert!(retain_exact(&root, "bound", &[8; 4], 4).is_err());
    assert_eq!(root.read("bound", 4).unwrap().as_slice(), &[7; 4]);
}

#[test]
fn committed_receipt_custody_is_required_and_never_recreated() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("runtime")).unwrap();
    // Filesystem ownership control only, not a fabricated token revision or enrollment proof.
    assert!(retain_receipt_custody(&directory, true).is_err());
    assert!(!directory.path().join("stream-token-receipts").exists());
    retain_receipt_custody(&directory, false).unwrap();
    let receipts = directory.open_child("stream-token-receipts").unwrap();
    receipts
        .write_atomic("original-receipt", b"retained", PublishMode::CreateNew)
        .unwrap();
    drop(receipts);
    retain_receipt_custody(&directory, true).unwrap();
    assert_eq!(
        directory
            .open_child("stream-token-receipts")
            .unwrap()
            .read("original-receipt", 16)
            .unwrap()
            .as_slice(),
        b"retained"
    );
    std::fs::rename(
        directory.path().join("stream-token-receipts"),
        directory.path().join("lost-receipts"),
    )
    .unwrap();
    assert!(retain_receipt_custody(&directory, true).is_err());
    assert!(!directory.path().join("stream-token-receipts").exists());
    assert_eq!(
        directory
            .open_child("lost-receipts")
            .unwrap()
            .read("original-receipt", 16)
            .unwrap()
            .as_slice(),
        b"retained"
    );
}

#[test]
fn ingest_projection_retains_original_signer_policy_paths_and_all_four_execution_policies() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-ingest-projection", false, false);
    let peers = fixture.peers();
    let root = PrivateDirectory::open_exact(generation_path(&fixture.prepared).unwrap()).unwrap();
    for index in 0..4 {
        let original = root
            .read(format!("peer{index}.toml"), MAX_CONFIG_BYTES)
            .unwrap();
        let original_table = crate::secret_toml::parse_table(
            std::str::from_utf8(&original).unwrap(),
            "original config",
        )
        .unwrap();
        let before = config::parse(
            original_table,
            &fixture.prepared.peers[index].config_path,
            false,
        )
        .unwrap();
        let destination = root
            .path()
            .join(format!("peer{index}.ingest-projection-only.toml"));
        let (rendered, actual_destination) = fixture.render(index, &fixture.components);
        assert_eq!(actual_destination.parent(), destination.parent());
        let table = crate::secret_toml::parse_table(&rendered, "ingest projection").unwrap();
        let after = config::parse(table, &destination, true).unwrap();
        assert_eq!(before.nexus.lane_catalog, after.nexus.lane_catalog);
        assert_eq!(
            before.nexus.dataspace_catalog,
            after.nexus.dataspace_catalog
        );
        assert_eq!(
            crate::localnet::service_authorities::configured_execution_policy(&before).unwrap(),
            crate::localnet::service_authorities::configured_execution_policy(&after).unwrap()
        );
        assert_eq!(before.genesis.expected_hash, after.genesis.expected_hash);
        assert_eq!(
            before.common.key_pair.public_key(),
            after.common.key_pair.public_key()
        );
        assert_eq!(
            before.kura.store_dir.resolve_relative_path(),
            after.kura.store_dir.resolve_relative_path()
        );
        assert_eq!(
            before.torii.sorafs_storage.data_dir,
            after.torii.sorafs_storage.data_dir
        );
        assert!(!destination.exists());
        let ingest = after.torii.sorafs_storage.provider_ingest_runtime.as_ref();
        assert_eq!(ingest.is_some(), index < 3);
        if let Some(ingest) = ingest {
            let policies = &fixture.selection.policies.providers[index];
            let plan = &fixture.selection.plans[index];
            let inventory = &fixture.owner.authority.manifest.providers[index];
            let signer = &inventory.authority(Role::ProviderIngest).unwrap().account;
            let provider_owner = &inventory.authority(Role::IssuerOperator).unwrap().account;
            assert_ne!(signer, provider_owner);
            assert_eq!(&policies.provider_ingest.provider_owner, provider_owner);
            assert_eq!(&policies.provider_ingest.completion_signer, signer);
            let credential = root.path().join(format!(
                "runtime/stream-token-authorities/providers/{index}/provider-ingest.key"
            ));
            let bytes = iroha_fs::read_private(&credential, 16 * 1024 + 256).unwrap();
            let private: iroha_crypto::ExposedPrivateKey =
                std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap())
                    .unwrap()
                    .parse()
                    .unwrap();
            let key = iroha_crypto::KeyPair::from_private_key(private.0).unwrap();
            assert_eq!(Some(key.public_key()), signer.try_signatory());
            assert_eq!(
                ingest.native_completion_credential.as_ref(),
                Some(&credential)
            );
            assert_eq!(&ingest.completion_signer_public_key, key.public_key());
            assert_eq!(
                ingest.completion_signer_algorithm,
                iroha_crypto::Algorithm::Ed25519
            );
            assert_eq!(
                ingest.completion_signer_policy,
                policies.provider_ingest.signer_policy
            );
            assert_eq!(ingest.completion_signer_adapter_revision, 1);
            assert_eq!(
                ingest.completion_signer_handle,
                "software://managed/provider-ingest/completion"
            );
            for (handle, revision, digest) in [
                (
                    &ingest.authenticated_source_fetch_handle,
                    ingest.authenticated_source_fetch_revision,
                    ingest.authenticated_source_fetch_policy_digest,
                ),
                (
                    &ingest.completion_signer_resolver_handle,
                    ingest.completion_signer_resolver_revision,
                    ingest.completion_signer_resolver_policy_digest,
                ),
                (
                    &ingest.checkpoint_store_handle,
                    ingest.checkpoint_store_revision,
                    ingest.checkpoint_store_policy_digest,
                ),
            ] {
                assert!(handle.starts_with("software://managed/provider-ingest/"));
                assert_eq!(revision, 1);
                assert_ne!(digest, [0; 32]);
            }
            assert_ne!(
                ingest.authenticated_source_fetch_policy_digest,
                ingest.completion_signer_resolver_policy_digest
            );
            assert_ne!(
                ingest.completion_signer_resolver_policy_digest,
                ingest.checkpoint_store_policy_digest
            );
            assert_eq!(ingest.native_source_origins.len(), 2);
            for other in &fixture.selection.plans {
                let origin = ingest
                    .native_source_origins
                    .get(&hex::encode(other.provider_id().as_bytes()));
                if other.provider_id() == plan.provider_id() {
                    assert!(origin.is_none());
                } else {
                    assert_eq!(
                        origin.unwrap().as_str(),
                        fixture.prepared.peers[other.peer_index()].torii_url
                    );
                }
            }
            assert_eq!(
                ingest.finalized_archive.relative_root,
                PathBuf::from("provider-ingest-finalized-archive-v1")
            );
            assert!(ingest.finalized_archive.retention_authority.is_none());
            let journal = ingest.provider_attestation_journal.as_ref().unwrap();
            let expected = plan.attestation_journal_policy();
            assert_eq!(journal.clock.handle, sorafs_node::provider_attestation_native::NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1);
            assert_eq!(journal.clock.policy_digest, expected.digest().unwrap());
            assert_eq!(journal.inventory.handle, sorafs_node::provider_attestation_native::NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1);
            assert_eq!(journal.inventory.policy_digest, expected.digest().unwrap());
            assert_eq!(journal.approval_signer.handle, sorafs_node::provider_attestation_native::NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1);
            assert_eq!(journal.approval_signer.policy_digest, sorafs_node::provider_attestation_journal::musubi_provider_attestation_controller_policy_digest_v1(signer).unwrap());
            assert_eq!(
                (
                    journal.clock.revision,
                    journal.inventory.revision,
                    journal.approval_signer.revision
                ),
                (1, 1, 1)
            );
            assert_eq!(journal.max_entries, expected.max_entries);
            assert_eq!(journal.checkpoint_max_bytes, expected.checkpoint_max_bytes);
            assert_eq!(journal.max_attempts, expected.max_attempts);
            assert_eq!(journal.lease_ttl_ms, expected.lease_ttl_ms);
            assert_eq!(journal.approval_timeout_ms, expected.approval_timeout_ms);
            assert_eq!(journal.handoff_timeout_ms, expected.handoff_timeout_ms);
            assert_eq!(journal.retry_delay_ms, expected.retry_delay_ms);
            assert_eq!(journal.max_cas_retries, expected.max_cas_retries);
            assert!(ingest.outbox.max_active_entries > 0);
            assert!(ingest.outbox.checkpoint_max_bytes.0 > 0);
            assert!(
                !after
                    .torii
                    .sorafs_storage
                    .data_dir
                    .join("provider-ingest-native-authority")
                    .exists()
            );
            let token_signer = after
                .torii
                .sorafs_storage
                .stream_tokens
                .signer
                .as_ref()
                .unwrap();
            assert_eq!(
                token_signer.native.as_ref().unwrap().fee_payment,
                fixture.selection.policies.network.runtime_fee_payment
            );
        }
        assert_eq!(
            root.read(format!("peer{index}.toml"), MAX_CONFIG_BYTES)
                .unwrap()
                .as_slice(),
            original.as_slice()
        );
    }
    no_http(&peers);
}

#[test]
fn ingest_projection_rejects_policy_substitution_and_wrong_fixed_owner_or_signer() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-ingest-substitution", false, false);
    let peers = fixture.peers();
    let root = PrivateDirectory::open_exact(generation_path(&fixture.prepared).unwrap()).unwrap();
    let original = root.read("peer0.toml", MAX_CONFIG_BYTES).unwrap();
    let destination = root.path().join("peer0.invalid-ingest-projection.toml");
    let intent = fixture.intent(&fixture.components);
    for change in 0..5 {
        let mut selection = RuntimeSelection::read(&fixture.owner.authority).unwrap();
        let selected = &mut selection.policies.providers[0].provider_ingest;
        let inventory = &fixture.owner.authority.manifest.providers[0];
        match change {
            0 => selected.completion_signer = selected.provider_owner.clone(),
            1 => {
                selected.provider_owner = inventory
                    .authority(Role::GatewayOperator)
                    .unwrap()
                    .account
                    .clone()
            }
            2 => {
                selected.completion_signer = inventory
                    .authority(Role::ProofOutcome)
                    .unwrap()
                    .account
                    .clone()
            }
            3 => selected.signer_policy.policy_digest = [0; 32],
            _ => {
                selected.completion_signer = fixture.owner.authority.manifest.providers[1]
                    .authority(Role::ProviderIngest)
                    .unwrap()
                    .account
                    .clone()
            }
        }
        let render = |selected_intent| {
            config::render(
                &fixture.owner.authority,
                &selection,
                selected_intent,
                Some(&fixture.components),
                0,
                &original,
                &destination,
                &fixture.owner.authority.directory,
                Some(fixture.components[0].directory()),
            )
        };
        assert!(render(&intent).is_err());
        // Recomputing the public hash cannot substitute another role or another provider.
        let mut changed = intent.clone();
        changed.policies =
            *Hash::new(encode(&selection.policies, MAX_POLICY_BYTES).unwrap()).as_ref();
        assert!(render(&changed).is_err());
    }
    let mut substituted = fixture.components.clone();
    substituted.swap(0, 1);
    assert!(
        config::render(
            &fixture.owner.authority,
            &fixture.selection,
            &intent,
            Some(&substituted),
            0,
            &original,
            &destination,
            &fixture.owner.authority.directory,
            Some(fixture.components[0].directory())
        )
        .is_err()
    );
    assert!(!destination.exists());
    no_http(&peers);
}

#[test]
fn renewal_rejects_catalog_and_foreign_predecessors_before_http_or_publication() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-renewal-predecessor");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let catalog = owner.prepare_catalog(options().deadline).unwrap();
    let names = owner.authority.directory.entries(32).unwrap();
    for sequence in [0, 1, 2, 3, 65, u64::MAX] {
        assert!(
            owner
                .prepare_renewed_stream_tokens(
                    &catalog,
                    catalog.provider_ids()[0],
                    sequence,
                    options().deadline
                )
                .is_err()
        );
    }
    assert_eq!(owner.authority.directory.entries(32).unwrap(), names);
    assert!(
        !owner
            .authority
            .directory
            .path()
            .join("stream-token-receipts")
            .exists()
    );
    let (_other, prepared_other, peers_other) = fixture("runtime-renewal-foreign");
    select(&prepared_other);
    let foreign = GeneratedServiceRuntime::open(&prepared_other).unwrap();
    assert!(
        foreign
            .prepare_renewed_stream_tokens(
                &catalog,
                catalog.provider_ids()[0],
                2,
                options().deadline
            )
            .is_err()
    );
    assert_eq!(foreign.authority.directory.entries(16).unwrap().len(), 1);
    no_http(&peers);
    no_http(&peers_other);
}

#[test]
fn independent_provider_renewals_preserve_exact_ancestry_out_of_slot_order() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Genuine::new("runtime-renewal-claims", false, true);
    let initial = fixture.components.clone();
    let mut selected = initial.clone();
    selected[2] = fixture.renew(2);
    assert_eq!(
        selected.each_ref().map(|c| c.selection().sequence),
        [1, 1, 2]
    );
    assert_eq!(selected[0].digest(), initial[0].digest());
    assert_eq!(selected[1].digest(), initial[1].digest());
    selected[0] = fixture.renew(0);
    assert_eq!(
        selected.each_ref().map(|c| c.selection().sequence),
        [2, 1, 2]
    );
    assert!(selected[0].finalized().height > selected[2].finalized().height);
    assert_eq!(selected[1].digest(), initial[1].digest());
    let peers = fixture.peers();
    for index in [2, 0] {
        let provider = fixture.selection.plans[index].provider_id();
        let custody = ManagedStreamTokenCustody::open(&fixture.prepared, provider).unwrap();
        let next = || {
            custody
                .retained_renewed_enrollment(
                    2,
                    &fixture.selection.policies.providers[index].custody,
                    fixture.options.deadline,
                )
                .unwrap()
        };
        let identity = fixture
            .selection
            .identity(&fixture.owner.authority, index)
            .unwrap();
        assert_eq!(
            next().statement().predecessor_digest,
            initial[index].selection().record_digest
        );
        assert!(
            selected[index].selection().expires_at_unix_ms
                > initial[index].selection().expires_at_unix_ms
        );
        // Skipping the actual predecessor, reusing a successor as its own predecessor, or
        // substituting another provider never creates a new successful component.
        let names = selected[index].directory().entries(32).unwrap();
        assert!(
            ProviderComponent::retain(
                &fixture.owner.authority.directory,
                identity,
                next(),
                None,
                Retention::PublishCurrent
            )
            .is_err()
        );
        assert!(
            ProviderComponent::retain(
                &fixture.owner.authority.directory,
                identity,
                next(),
                Some(&selected[index]),
                Retention::PublishCurrent
            )
            .is_err()
        );
        assert!(
            ProviderComponent::retain(
                &fixture.owner.authority.directory,
                identity,
                next(),
                Some(&initial[1]),
                Retention::PublishCurrent
            )
            .is_err()
        );
        let restored = ProviderComponent::retain(
            &fixture.owner.authority.directory,
            identity,
            next(),
            Some(&initial[index]),
            Retention::ExistingMaterial,
        )
        .unwrap();
        assert_eq!(restored.digest(), selected[index].digest());
        assert_eq!(restored.finalized(), selected[index].finalized());
        assert_eq!(selected[index].directory().entries(32).unwrap(), names);
    }
    assert!(
        ProviderComponent::retain(
            &fixture.owner.authority.directory,
            fixture
                .selection
                .identity(&fixture.owner.authority, 0)
                .unwrap(),
            fixture.initial(1),
            None,
            Retention::PublishCurrent
        )
        .is_err()
    );
    no_http(&peers);
}

#[test]
fn selected_native_intervals_never_extend_original_provider_policy_or_replace_initial_selection() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-selected-interval", false, false);
    let peers = fixture.peers();
    fixture
        .selection
        .validate_interval(Some(&fixture.components))
        .unwrap();
    for index in 0..3 {
        for change in 0..4 {
            let mut selection = RuntimeSelection::read(&fixture.owner.authority).unwrap();
            match change {
                0 => selection.initial[index].as_mut().unwrap().issued_at_unix_ms += 1,
                1 => {
                    selection.initial[index]
                        .as_mut()
                        .unwrap()
                        .expires_at_unix_ms -= 1
                }
                2 => {
                    selection.policies.providers[index]
                        .custody
                        .active_from_unix_ms = now_ms().unwrap() + 60_000
                }
                _ => {
                    selection.policies.providers[index]
                        .custody
                        .active_until_unix_ms =
                        fixture.components[index].selection().expires_at_unix_ms - 1
                }
            }
            assert!(
                selection
                    .validate_interval(Some(&fixture.components))
                    .is_err()
            );
        }
    }
    no_http(&peers);
}

#[test]
fn renewal_projection_keeps_receipt_namespace_and_original_fees_after_refused_partial_write() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Genuine::new("runtime-renewal-projection", false, true);
    let original_components = fixture.components.clone();
    let mut renewed_components = original_components.clone();
    renewed_components[0] = fixture.renew(0);
    let peers = fixture.peers();
    let (first, destination) = fixture.render(0, &original_components);
    let (renewed, _) = fixture.render(0, &renewed_components);
    let parse = |text: &str| {
        config::parse(
            crate::secret_toml::parse_table(text, "renewal projection").unwrap(),
            &destination,
            true,
        )
        .unwrap()
        .torii
        .sorafs_storage
        .stream_tokens
        .signer
        .unwrap()
        .native
        .unwrap()
    };
    let publication = |text: &str| {
        config::parse(
            crate::secret_toml::parse_table(text, "renewal publication projection").unwrap(),
            &destination,
            true,
        )
        .unwrap()
        .musubi_publication
    };
    assert_eq!(
        publication(&first),
        fixture.selection.publication.installation_config()
    );
    assert_eq!(publication(&first), publication(&renewed));
    let original_binding = parse(&first);
    let renewed_binding = parse(&renewed);
    assert_ne!(
        original_binding.custody_record,
        renewed_binding.custody_record
    );
    assert_eq!(
        original_binding.receipt_journal,
        renewed_binding.receipt_journal
    );
    assert_eq!(original_binding.fee_payment, renewed_binding.fee_payment);
    assert_eq!(
        renewed_binding.fee_payment,
        fixture.selection.policies.network.runtime_fee_payment
    );
    assert_eq!(
        original_binding.signer_credential,
        renewed_binding.signer_credential
    );
    assert!(!destination.exists());
    for index in 1..3 {
        let (before, _) = fixture.render(index, &original_components);
        let (after, _) = fixture.render(index, &renewed_components);
        assert_eq!(
            before, after,
            "other provider projection must retain its exact bytes"
        );
    }
    let root = PrivateDirectory::open_exact(generation_path(&fixture.prepared).unwrap()).unwrap();
    retain_exact(
        &root,
        "partial-revision-control",
        renewed.as_bytes(),
        MAX_CONFIG_BYTES,
    )
    .unwrap();
    assert!(
        retain_exact(
            &root,
            "partial-revision-control",
            first.as_bytes(),
            MAX_CONFIG_BYTES
        )
        .is_err()
    );
    retain_exact(
        &root,
        "partial-revision-control",
        renewed.as_bytes(),
        MAX_CONFIG_BYTES,
    )
    .unwrap();
    assert_eq!(
        root.read("partial-revision-control", MAX_CONFIG_BYTES)
            .unwrap()
            .as_slice(),
        renewed.as_bytes()
    );
    let receipts = renewed_components[0]
        .directory()
        .path()
        .join("stream-token-receipts");
    std::fs::rename(&receipts, receipts.with_extension("held")).unwrap();
    assert!(renewed_components[0].validate().is_err());
    assert!(retain_receipt_custody(renewed_components[0].directory(), true).is_err());
    assert!(!receipts.exists());
    no_http(&peers);
}

#[test]
fn existing_component_recovery_matches_exact_files_and_never_repairs_missing_ancestors() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-material-recovery", false, false);
    let peers = fixture.peers();
    for index in 0..3 {
        let component = &fixture.components[index];
        let recover = || {
            ProviderComponent::retain(
                &fixture.owner.authority.directory,
                fixture
                    .selection
                    .identity(&fixture.owner.authority, index)
                    .unwrap(),
                fixture.initial(index),
                None,
                Retention::ExistingMaterial,
            )
        };
        let restored = recover().unwrap();
        assert_eq!(component.digest(), restored.digest());
        assert_eq!(
            component.enrollment().bytes(),
            restored.enrollment().bytes()
        );
        assert_eq!(component.finalized(), restored.finalized());
        let directory = component.directory();
        let custody = directory
            .path()
            .join(custody_name(component.selection().bytes_digest));
        let held = custody.with_extension("held");
        let bytes = std::fs::read(&custody).unwrap();
        std::fs::rename(&custody, &held).unwrap();
        assert!(recover().is_err());
        assert!(!custody.exists());
        assert_eq!(std::fs::read(&held).unwrap(), bytes);
        std::fs::rename(&held, &custody).unwrap();
        directory
            .write_atomic(
                custody.file_name().unwrap(),
                b"changed ancestor",
                PublishMode::Replace,
            )
            .unwrap();
        assert!(recover().is_err());
        assert_eq!(std::fs::read(&custody).unwrap(), b"changed ancestor");
        directory
            .write_atomic(custody.file_name().unwrap(), &bytes, PublishMode::Replace)
            .unwrap();
        let manifest = directory
            .path()
            .join(format!("component-{}.nrt", hex::encode(component.digest())));
        let held_manifest = manifest.with_extension("held");
        std::fs::rename(&manifest, &held_manifest).unwrap();
        assert!(recover().is_err());
        assert!(!manifest.exists());
        std::fs::rename(&held_manifest, &manifest).unwrap();
        recover().unwrap().validate().unwrap();
        let original_manifest = std::fs::read(&manifest).unwrap();
        std::fs::rename(&custody, &held).unwrap();
        directory
            .write_atomic(
                manifest.file_name().unwrap(),
                b"changed component",
                PublishMode::Replace,
            )
            .unwrap();
        let publish = || {
            ProviderComponent::retain(
                &fixture.owner.authority.directory,
                fixture
                    .selection
                    .identity(&fixture.owner.authority, index)
                    .unwrap(),
                fixture.initial(index),
                None,
                Retention::PublishCurrent,
            )
        };
        let before = directory.entries(32).unwrap();
        assert!(publish().is_err());
        assert!(
            !custody.exists(),
            "changed component must fail before body publication"
        );
        assert_eq!(directory.entries(32).unwrap(), before);
        directory
            .write_atomic(
                manifest.file_name().unwrap(),
                &original_manifest,
                PublishMode::Replace,
            )
            .unwrap();
        assert!(publish().is_err());
        assert!(
            !custody.exists(),
            "committed component body must never be repaired"
        );
        std::fs::rename(&held, &custody).unwrap();
        publish().unwrap().validate().unwrap();
        let receipts = directory.path().join("stream-token-receipts");
        std::fs::rename(&receipts, receipts.with_extension("held")).unwrap();
        assert!(recover().is_err());
        assert!(!receipts.exists());
        std::fs::rename(receipts.with_extension("held"), &receipts).unwrap();
        recover().unwrap().validate().unwrap();
    }
    no_http(&peers);
}

#[test]
fn runtime_restart_refuses_decoy_revisions_without_original_native_children() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-decoy-recovery");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let catalog = owner.prepare_catalog(options().deadline).unwrap();
    // A copied real Catalog manifest under a later-looking name remains only inert bytes.
    let bytes = owner
        .authority
        .directory
        .read(&catalog.manifest_name, MAX_MANIFEST_BYTES)
        .unwrap();
    owner
        .authority
        .directory
        .write_atomic("revision-ffffffff.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    let before = owner.authority.directory.entries(32).unwrap();
    assert!(
        owner
            .prepare_current_stream_tokens(options().deadline)
            .is_err()
    );
    assert_eq!(owner.authority.directory.entries(32).unwrap(), before);
    assert!(
        !owner
            .authority
            .directory
            .path()
            .join("stream-token-receipts")
            .exists()
    );
    assert!(owner.validate(&catalog).is_ok());
    no_http(&peers);
}

#[test]
fn runtime_retains_all_twenty_nine_original_transactions_and_same_block_distinct_transactions() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Genuine::new("runtime-all-native-carriers", true, false);
    let required = || {
        RequiredTransactions::from_originals(
            fixture
                .carriers
                .iter()
                .copied()
                .chain(fixture.components.iter().map(|c| c.finalized())),
        )
        .unwrap()
    };
    let selected = required();
    assert_eq!(selected.originals(), fixture.carriers);
    assert_eq!(selected.identities().len(), 29);
    assert_eq!(
        selected.observation_floor().unwrap(),
        *fixture.carriers.last().unwrap()
    );
    // The renderer's private publication is exercised with genuine complete original history.
    // Current native HTTP eligibility and the worker all-peer barrier remain separate gates.
    let revision = fixture
        .owner
        .publish(
            &fixture.selection,
            Some(fixture.components.clone()),
            Some(required()),
            fixture.options.deadline,
        )
        .unwrap();
    assert_eq!(revision.required_transactions(), fixture.carriers);
    assert_eq!(
        revision.observation_floor().unwrap(),
        *fixture.carriers.last().unwrap()
    );
    fixture.owner.validate(&revision).unwrap();
    for index in 0..3 {
        let provider = fixture.selection.plans[index].provider_id();
        let original = revision.selected_enrollment(provider).unwrap().unwrap();
        assert_eq!(
            original.bytes(),
            fixture.components[index].enrollment().bytes()
        );
        assert_eq!(
            original.finalized(),
            fixture.components[index].enrollment().finalized()
        );
    }
    let unknown = ProviderId::new([0; 32]);
    assert!(revision.selected_enrollment(unknown).is_err());
    // Losing selected material cannot turn an already committed aggregate into a fresh
    // publication. Use the same two-phase preparation/preflight owner as restart recovery.
    for index in 0..3 {
        let component = &fixture.components[index];
        let directory = component.directory();
        let body = directory
            .path()
            .join(custody_name(component.selection().bytes_digest));
        let manifest = directory
            .path()
            .join(format!("component-{}.nrt", hex::encode(component.digest())));
        let held_body = body.with_extension("held");
        let held_manifest = manifest.with_extension("held");
        std::fs::rename(&body, &held_body).unwrap();
        std::fs::rename(&manifest, &held_manifest).unwrap();
        let prepared = ProviderComponent::prepare(
            fixture
                .selection
                .identity(&fixture.owner.authority, index)
                .unwrap(),
            fixture.initial(index),
            None,
        )
        .unwrap();
        let digests = std::array::from_fn(|slot| {
            if slot == index {
                prepared.digest()
            } else {
                fixture.components[slot].digest()
            }
        });
        let retention = fixture
            .owner
            .component_retentions(&fixture.selection, digests, &required())
            .unwrap();
        assert!(
            retention
                .iter()
                .all(|value| *value == Retention::ExistingMaterial)
        );
        let names = directory.entries(32).unwrap();
        assert!(
            prepared
                .retain(&fixture.owner.authority.directory, retention[index])
                .is_err()
        );
        assert!(!body.exists() && !manifest.exists());
        assert_eq!(directory.entries(32).unwrap(), names);
        std::fs::rename(&held_body, &body).unwrap();
        std::fs::rename(&held_manifest, &manifest).unwrap();
        fixture.owner.validate(&revision).unwrap();
    }
    let first = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "first actual same-block transaction".into(),
        ))],
    );
    let second = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "second actual same-block transaction".into(),
        ))],
    );
    assert_eq!(
        fixture
            .native
            .chain
            .commit(vec![first.clone(), second.clone()]),
        vec![true, true]
    );
    let verifier = fixture.native.observe(&fixture.owner.authority);
    let first = crate::managed::native_operation::verify_carrier(&verifier, &first).unwrap();
    let second = crate::managed::native_operation::verify_carrier(&verifier, &second).unwrap();
    assert_eq!(first.height, second.height);
    assert_eq!(first.block_hash, second.block_hash);
    assert_ne!(first.transaction_hash, second.transaction_hash);
    let mut all = fixture.carriers.clone();
    all.extend([first, second, first]);
    let selected = RequiredTransactions::from_originals(all.clone()).unwrap();
    assert_eq!(selected.originals().len(), 31);
    assert_eq!(&selected.originals()[29..], &[first, second]);
    assert!(selected.originals().starts_with(&fixture.carriers));
    assert_eq!(selected.observation_floor().unwrap().height, first.height);
    assert!(RequiredTransactions::from_originals(all.into_iter().chain([first])).is_err());
    // Mutating actual coordinates is a refusal control, never a fabricated successful proof.
    for changed in [
        ManagedTransactionFinality {
            block_time_ms: first.block_time_ms + 1,
            ..first
        },
        ManagedTransactionFinality {
            block_hash: fixture.carriers[0].block_hash,
            ..first
        },
        ManagedTransactionFinality { height: 1, ..first },
        ManagedTransactionFinality {
            height: first.height + 1,
            ..first
        },
    ] {
        assert!(RequiredTransactions::from_originals([first, changed]).is_err());
    }
    let peers = fixture.peers();
    no_http(&peers);
}

#[test]
fn readonly_runtime_retention_refuses_absence_without_creating_files_or_receipt_namespace() {
    let temporary = tempfile::tempdir().unwrap();
    let private = PrivateDirectory::open_or_create(temporary.path().join("runtime")).unwrap();
    let directory = PrivateDirectory::open_exact(private.path()).unwrap();
    assert!(
        retain_revision_file(
            &directory,
            "missing.nrt",
            b"original",
            64,
            Retention::ExistingMaterial
        )
        .is_err()
    );
    assert!(directory.entries(4).unwrap().is_empty());
    assert!(retain_receipt_custody(&directory, true).is_err());
    assert!(directory.entries(4).unwrap().is_empty());
    retain_revision_file(
        &directory,
        "current.nrt",
        b"original",
        64,
        Retention::PublishCurrent,
    )
    .unwrap();
    retain_revision_file(
        &directory,
        "current.nrt",
        b"original",
        64,
        Retention::ExistingMaterial,
    )
    .unwrap();
    assert!(
        retain_revision_file(
            &directory,
            "current.nrt",
            b"replacement",
            64,
            Retention::ExistingMaterial
        )
        .is_err()
    );
    assert_eq!(
        directory.read("current.nrt", 64).unwrap().as_slice(),
        b"original"
    );
}

#[test]
fn prior_aggregate_prevents_mixed_successor_repair_and_reference_audit_is_bounded() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Genuine::new("runtime-mixed-aggregate", false, true);
    // Genuine custody history exercises only the renderer reference journal. The shorter
    // initial intervals do not match parent intent and cannot establish parent completion.
    let mut previous = fixture.components.clone();
    previous[0] = fixture.renew(0);
    // Inert reference-audit input, not a successful publication or launch revision. Its
    // component digests and transaction coordinates come from the actual native owners;
    // launch digests are copied from the real Catalog solely to satisfy structural bounds.
    // The reference can only strengthen readonly custody requirements. The parent would
    // correctly refuse these shorter initial intervals for an operational revision.
    let prior = Manifest {
        intent: fixture.intent(&previous),
        launch_digests: fixture.catalog.manifest.launch_digests,
    };
    let (prior_name, retained) = fixture.owner.retained_manifest(&prior.intent).unwrap();
    assert!(retained.is_none());
    fixture
        .owner
        .authority
        .directory
        .write_atomic(
            &prior_name,
            &encode(&prior, MAX_MANIFEST_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    assert_eq!(
        previous.each_ref().map(|c| c.selection().sequence),
        [2, 1, 1]
    );
    let mut current = previous.clone();
    current[2] = fixture.renew(2);
    assert_eq!(
        current.each_ref().map(|c| c.selection().sequence),
        [2, 1, 2]
    );
    let peers = fixture.peers();
    let required = RequiredTransactions::from_originals(fixture.carriers.clone()).unwrap();
    let digests = current.each_ref().map(|c| c.digest());
    let (_, exact) = fixture
        .owner
        .retained_manifest(&fixture.intent(&current))
        .unwrap();
    assert!(
        exact.is_none(),
        "the selected mixed aggregate has never been published"
    );
    let audit = || {
        fixture
            .owner
            .component_retentions(&fixture.selection, digests, &required)
    };
    let retention = audit().unwrap();
    assert!(retention[0] == Retention::ExistingMaterial);
    assert!(retention[1] == Retention::ExistingMaterial);
    assert!(retention[2] == Retention::PublishCurrent);
    let component = &current[0];
    let directory = component.directory();
    let body = directory
        .path()
        .join(custody_name(component.selection().bytes_digest));
    let manifest = directory
        .path()
        .join(format!("component-{}.nrt", hex::encode(component.digest())));
    let held_body = body.with_extension("held");
    let held_manifest = manifest.with_extension("held");
    std::fs::rename(&body, &held_body).unwrap();
    std::fs::rename(&manifest, &held_manifest).unwrap();
    let custody = ManagedStreamTokenCustody::open(
        &fixture.prepared,
        fixture.selection.plans[0].provider_id(),
    )
    .unwrap();
    let enrollment = custody
        .retained_renewed_enrollment(
            2,
            &fixture.selection.policies.providers[0].custody,
            fixture.options.deadline,
        )
        .unwrap();
    drop(custody);
    let selected = ProviderComponent::prepare(
        fixture
            .selection
            .identity(&fixture.owner.authority, 0)
            .unwrap(),
        enrollment,
        Some(&fixture.components[0]),
    )
    .unwrap();
    let names = directory.entries(32).unwrap();
    assert!(
        selected
            .retain(&fixture.owner.authority.directory, audit().unwrap()[0])
            .is_err()
    );
    assert!(!body.exists() && !manifest.exists());
    assert_eq!(directory.entries(32).unwrap(), names);
    std::fs::rename(&held_body, &body).unwrap();
    std::fs::rename(&held_manifest, &manifest).unwrap();
    component.validate().unwrap();

    let runtime = &fixture.owner.authority.directory;
    let original = runtime.read(&prior_name, MAX_MANIFEST_BYTES).unwrap();
    runtime
        .write_atomic(&prior_name, b"malformed reference", PublishMode::Replace)
        .unwrap();
    let before = runtime.entries(MAX_RUNTIME_ENTRIES).unwrap();
    assert!(audit().is_err());
    assert_eq!(runtime.entries(MAX_RUNTIME_ENTRIES).unwrap(), before);
    runtime
        .write_atomic(&prior_name, &original, PublishMode::Replace)
        .unwrap();
    // A canonical hash-shaped name does not make a foreign original profile acceptable.
    let mut foreign = prior.clone();
    foreign.intent.genesis[0] ^= 1;
    let foreign_name = format!(
        "revision-{}.nrt",
        hex::encode(Hash::new(encode(&foreign.intent, MAX_MANIFEST_BYTES).unwrap()).as_ref())
    );
    runtime
        .write_atomic(
            &foreign_name,
            &encode(&foreign, MAX_MANIFEST_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let before = runtime.entries(MAX_RUNTIME_ENTRIES).unwrap();
    assert!(audit().is_err());
    assert_eq!(runtime.entries(MAX_RUNTIME_ENTRIES).unwrap(), before);
    std::fs::remove_file(runtime.path().join(&foreign_name)).unwrap();
    audit().unwrap();
    // Extra inert files exercise the directory allocation bound, not invented native history.
    for index in 0..MAX_RUNTIME_ENTRIES {
        runtime
            .write_atomic(
                format!("inert-{index:04}"),
                b"input",
                PublishMode::CreateNew,
            )
            .unwrap();
    }
    assert!(runtime.entries(MAX_RUNTIME_ENTRIES).is_err());
    assert!(audit().is_err());
    assert_eq!(
        runtime.read(&prior_name, MAX_MANIFEST_BYTES).unwrap(),
        original
    );
    no_http(&peers);
}

#[test]
fn publication_projection_installs_exact_original_only_on_ready_seed_peer_and_preserves_custody() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::new("runtime-publication-projection", false, false);
    let peers = fixture.peers();
    let plan = &fixture.selection.publication;
    let expected = plan.installation_config();
    let root = PrivateDirectory::open_exact(&expected.custody_root).unwrap();
    let before = root.entries(8).unwrap();
    for index in 0..4 {
        let (text, destination) = fixture.render(index, &fixture.components);
        let actual = config::parse(
            crate::secret_toml::parse_table(&text, "publication projection").unwrap(),
            &destination,
            true,
        )
        .unwrap();
        if index == 0 {
            assert_eq!(actual.musubi_publication, expected);
            let selected = actual.musubi_publication.installation.as_ref().unwrap();
            assert_eq!(
                selected.seed_provider,
                fixture.selection.plans[0].provider_id()
            );
            assert_eq!(
                selected.ingress_broker,
                fixture
                    .owner
                    .authority
                    .provider_inventory(fixture.selection.plans[0].provider_id())
                    .unwrap()
                    .authority(Role::IssuerOperator)
                    .unwrap()
                    .account
            );
            assert_eq!(selected.pin_session, plan.session_id());
            assert_eq!(
                &actual
                    .musubi_publication
                    .paid_pin_policy(&selected.ingress_broker)
                    .transaction_authority,
                plan.pin_authority()
            );
            assert_ne!(&selected.ingress_broker, plan.pin_authority());
        } else {
            assert!(actual.musubi_publication.installation.is_none());
        }
        assert!(!destination.exists());
    }
    assert_eq!(root.entries(8).unwrap(), before);
    let original =
        iroha_fs::read_private(&fixture.prepared.peers[0].config_path, MAX_CONFIG_BYTES).unwrap();
    let mut changed = crate::secret_toml::parse_table(
        std::str::from_utf8(&original).unwrap(),
        "refused original installation",
    )
    .unwrap();
    changed.insert(
        "musubi_publication".into(),
        toml::Value::Table(plan.configuration_table().unwrap()),
    );
    let changed = zeroize::Zeroizing::new(toml::to_string(&changed).unwrap());
    let destination = fixture.prepared.peers[0]
        .config_path
        .with_file_name("refused-publication-projection.toml");
    assert!(
        config::render(
            &fixture.owner.authority,
            &fixture.selection,
            &fixture.intent(&fixture.components),
            Some(&fixture.components),
            0,
            changed.as_bytes(),
            &destination,
            &fixture.owner.authority.directory,
            Some(fixture.components[0].directory()),
        )
        .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(root.entries(8).unwrap(), before);
    let originals = fixture.prepared.peers.iter().map(|peer| {
        let bytes = iroha_fs::read_private(&peer.config_path, MAX_CONFIG_BYTES).unwrap();
        config::parse(
            crate::secret_toml::parse_table(
                std::str::from_utf8(&bytes).unwrap(),
                "original publication absence",
            )
            .unwrap(),
            &peer.config_path,
            false,
        )
        .unwrap()
    });
    for original in originals {
        assert!(original.musubi_publication.installation.is_none());
    }
    no_http(&peers);
}

#[test]
fn catalog_material_preflight_preserves_original_heads_before_first_stream_render() {
    let _guard = crate::managed::native_test_guard();
    let fixture =
        Genuine::with_material_preflight("runtime-pre-first-render-material", true, false, true);
    let peers = fixture.peers();
    assert_eq!(fixture.carriers.len(), 29);
    assert_eq!(fixture.catalog.stage(), GeneratedRuntimeStage::Catalog);
    assert!(fixture.catalog.required_transactions().is_empty());
    fixture.owner.validate(&fixture.catalog).unwrap();
    let before = fixture.owner.authority.directory.entries(8).unwrap();
    let retained = std::array::from_fn::<_, 3, _>(|index| {
        let component = &fixture.components[index];
        assert_eq!(component.selection().sequence, 1);
        assert_eq!(
            component.enrollment().bytes(),
            fixture.initial(index).bytes()
        );
        let directory = component.directory();
        (
            directory.identity().unwrap(),
            directory.entries(8).unwrap(),
            directory
                .open_child("stream-token-receipts")
                .unwrap()
                .identity()
                .unwrap(),
            directory
                .read(
                    format!("component-{}.nrt", hex::encode(component.digest())),
                    MAX_MANIFEST_BYTES,
                )
                .unwrap()
                .to_vec(),
        )
    });
    let recover_material = || {
        let mut parent = ManagedServiceBootstrap::open(&fixture.prepared).unwrap();
        let ServiceBootstrapProgress::Complete(history) =
            parent.recover(fixture.options.deadline).unwrap()
        else {
            panic!("all twenty-nine original native carriers remain required")
        };
        drop(parent);
        fixture.owner.retain_selected_components(
            RuntimeSelection::read(&fixture.owner.authority).unwrap(),
            &history,
            std::array::from_fn(|index| fixture.initial(index)),
            fixture.options.deadline,
        )
    };
    let (_, recovered, required) = recover_material().unwrap();
    assert_eq!(required.originals(), fixture.carriers);
    assert_eq!(
        required.observation_floor().unwrap(),
        *fixture.carriers.last().unwrap()
    );
    for (index, component) in recovered.iter().enumerate() {
        let directory = component.directory();
        assert_eq!(component.digest(), fixture.components[index].digest());
        assert_eq!(directory.identity().unwrap(), retained[index].0);
        assert_eq!(directory.entries(8).unwrap(), retained[index].1);
        assert_eq!(
            directory
                .open_child("stream-token-receipts")
                .unwrap()
                .identity()
                .unwrap(),
            retained[index].2
        );
        assert_eq!(
            directory
                .read(
                    format!("component-{}.nrt", hex::encode(component.digest())),
                    MAX_MANIFEST_BYTES,
                )
                .unwrap()
                .as_slice(),
            retained[index].3
        );
    }
    assert_eq!(
        fixture.owner.authority.directory.entries(8).unwrap(),
        before
    );
    no_http(&peers);

    // Even before a StreamTokens aggregate exists, committed component custody is not repairable.
    let component = &fixture.components[1];
    for name in [
        "stream-token-receipts".to_owned(),
        custody_name(component.selection().bytes_digest),
    ] {
        let original = component.directory().path().join(name);
        let held = original.with_extension("held");
        std::fs::rename(&original, &held).unwrap();
        let names = component.directory().entries(8).unwrap();
        assert!(matches!(
            recover_material(),
            Err(crate::managed::Error::Bootstrap(
                crate::managed::ManagedBootstrapFailure::RetainedMaterial
            ))
        ));
        assert!(!original.exists());
        assert_eq!(component.directory().entries(8).unwrap(), names);
        assert_eq!(
            fixture.owner.authority.directory.entries(8).unwrap(),
            before
        );
        no_http(&peers);
        std::fs::rename(&held, &original).unwrap();
    }
    component.validate().unwrap();
    fixture.owner.validate(&fixture.catalog).unwrap();
    // A material-only result never bypasses current-use qualification or yields a launch revision.
    assert!(
        fixture
            .owner
            .prepare_current_stream_tokens(Instant::now())
            .is_err()
    );
    assert_eq!(
        fixture.owner.authority.directory.entries(8).unwrap(),
        before
    );
    no_http(&peers);
}
