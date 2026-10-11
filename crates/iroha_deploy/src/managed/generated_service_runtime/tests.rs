//! Genuine original-profile renderer controls; no worker, native admission or Serving claim.
use super::*;
use crate::{
    localnet::service_authorities::{
        NetworkServiceAuthorityRole as NetworkRole, StreamTokenAuthorityRole as Role,
    },
    managed::{
        ManagedHistoricalReserveTopUp, ManagedHistoricalReserveTopUpApproval,
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
#[cfg(unix)]
thread_local! {
    static BOOTSTRAP_REOPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(unix)]
pub(super) fn before_bootstrap_reopen() {
    // Release the RefCell borrow before running the one-shot native mutation.
    let action = BOOTSTRAP_REOPEN_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

#[cfg(unix)]
struct BootstrapReopenHook;
#[cfg(unix)]
impl BootstrapReopenHook {
    fn install(action: impl FnOnce() + 'static) -> Self {
        BOOTSTRAP_REOPEN_HOOK.with(|hook| {
            assert!(hook.borrow_mut().replace(Box::new(action)).is_none());
        });
        Self
    }
}
#[cfg(unix)]
impl Drop for BootstrapReopenHook {
    fn drop(&mut self) {
        BOOTSTRAP_REOPEN_HOOK.with(|hook| *hook.borrow_mut() = None);
    }
}

#[cfg(unix)]
fn bootstrap_loss_after_selection(owner: &GeneratedServiceRuntime, call: impl FnOnce()) {
    let path = owner
        .authority
        .directory
        .path()
        .parent()
        .unwrap()
        .join("service-bootstrap");
    let displaced = path.with_file_name("held-recovery-service-bootstrap");
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let directory_identity = directory.identity().unwrap();
    let lock_identity =
        iroha_fs::FileIdentity::of(&directory.open_existing_lock("operation.lock").unwrap())
            .unwrap();
    let lock_bytes = directory
        .read("operation.lock", MAX_MANIFEST_BYTES)
        .unwrap();
    let initial = directory.open_child("initial").unwrap();
    let original = initial.read("original.nrt", MAX_POLICY_BYTES).unwrap();
    let names = initial.entries(32).unwrap();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = std::rc::Rc::clone(&reached);
    let removed_path = path.clone();
    let saved_path = displaced.clone();
    let hook = BootstrapReopenHook::install(move || {
        std::fs::rename(&removed_path, &saved_path).unwrap();
        observed.set(true);
    });
    call();
    assert!(
        reached.get(),
        "the successful selection reached its second open"
    );
    assert!(BOOTSTRAP_REOPEN_HOOK.with(|hook| hook.borrow().is_none()));
    assert!(
        !path.exists(),
        "recovery must not recreate the lost purpose or lock"
    );
    assert!(displaced.join("operation.lock").exists());
    drop(hook);
    std::fs::rename(&displaced, &path).unwrap();
    assert_eq!(directory.identity().unwrap(), directory_identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&directory.open_existing_lock("operation.lock").unwrap())
            .unwrap(),
        lock_identity
    );
    assert_eq!(
        directory
            .read("operation.lock", MAX_MANIFEST_BYTES)
            .unwrap()
            .as_slice(),
        lock_bytes.as_slice()
    );
    assert_eq!(
        initial
            .read("original.nrt", MAX_POLICY_BYTES)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    assert_eq!(initial.entries(32).unwrap(), names);
    directory.revalidate().unwrap();
    owner.authority.validate_profile().unwrap();
}

// Catalog creates the exact empty material skeleton needed by its derived configs.
// This is not a token component, receipt journal or native enrollment publication.
fn catalog_material_skeleton(
    owner: &GeneratedServiceRuntime,
) -> (iroha_fs::FileIdentity, [iroha_fs::FileIdentity; 3]) {
    let providers = owner.authority.directory.open_child("providers").unwrap();
    assert_eq!(
        providers.entries(3).unwrap(),
        (0..3)
            .map(|index| std::ffi::OsString::from(index.to_string()))
            .collect::<Vec<_>>()
    );
    let slots = std::array::from_fn(|index| {
        let slot = providers.open_child(index.to_string()).unwrap();
        assert!(slot.entries(1).unwrap().is_empty());
        slot.identity().unwrap()
    });
    (providers.identity().unwrap(), slots)
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
// Each genuine native stage returns before the next owner's scratch is live. The setup
// borrows the same fixture, original selection and carrier list; no proof, current-time or
// transaction operation is replaced by fixture bookkeeping.
struct GenuineNativeSetup<'a> {
    prepared: &'a PreparedLocalnet,
    native: &'a mut NativeFixture,
    selection: &'a mut RuntimeSelection,
    carriers: &'a mut Vec<ManagedTransactionFinality>,
    utc: u64,
    options: &'a BoundedTransactionOptions,
}
impl GenuineNativeSetup<'_> {
    #[inline(never)]
    fn run(&mut self, full_parent: bool, short_initial: bool) {
        if full_parent {
            self.reserve();
        }
        for index in 0..3 {
            self.custody(index, short_initial);
            if full_parent {
                self.account(index);
                // These original historical owners stay alive through the later children,
                // just as in the sequential setup before its scratch was separated.
                let (_request, _approval) = self.funding(index);
                self.ingest(index);
                self.gateway(index);
            }
        }
        if full_parent {
            self.reputation();
            self.parent();
        }
    }
    #[inline(never)]
    fn reserve(&mut self) {
        let mut reserve = ManagedInitialReservePolicy::open(self.prepared).unwrap();
        self.carriers.push(
            reserve
                .bootstrap_native(
                    self.native,
                    &self.selection.policies.network.reserve,
                    self.utc,
                    self.options,
                )
                .finalized
                .unwrap(),
        );
    }

    #[inline(never)]
    fn custody(&mut self, index: usize, short_initial: bool) {
        let selected = &self.selection.policies.providers[index];
        let provider = selected.provider_id;
        let mut custody = ManagedStreamTokenCustody::open(self.prepared, provider).unwrap();
        self.carriers.push(
            custody
                .bootstrap_native_configure(self.native, &selected.custody, self.utc, self.options)
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
            selected
                .initial_enrollment(now_ms().unwrap(), self.utc)
                .unwrap()
        };
        self.selection.initial[index] = Some(initial);
        self.carriers.push(
            custody
                .bootstrap_native_enroll(
                    self.native,
                    &selected.custody,
                    self.selection.initial(index).unwrap(),
                    self.options,
                )
                .finalized
                .unwrap(),
        );
        drop(custody);
    }

    #[inline(never)]
    fn account(&mut self, index: usize) {
        let selected = &self.selection.policies.providers[index];
        let provider = selected.provider_id;
        let mut account = ManagedReserveAccountRegistration::open(self.prepared, provider).unwrap();
        self.carriers.push(
            account
                .bootstrap_native(
                    self.native,
                    &self.selection.policies.network.reserve,
                    self.selection.plans[index].reserve_terms(),
                    self.utc,
                    self.options,
                )
                .finalized
                .unwrap(),
        );
        drop(account);
    }

    #[inline(never)]
    fn funding(
        &mut self,
        index: usize,
    ) -> (
        ManagedHistoricalReserveTopUp,
        ManagedHistoricalReserveTopUpApproval,
    ) {
        let provider = self.selection.policies.providers[index].provider_id;
        let mut funding = ProviderFundingBootstrap::open(self.prepared, provider).unwrap();
        let ProviderFundingProgress::Complete {
            request,
            approval,
            credit,
            capacity,
        } = funding.bootstrap_native(
            self.native,
            &self.selection.policies.network.reserve,
            self.utc,
            self.options,
        )
        else {
            panic!("actual funding owners must retain complete history")
        };
        let request = request.unwrap();
        let approval = approval.unwrap();
        assert_eq!(request.movement_id(), approval.request().movement_id());
        self.carriers
            .extend([*request.original(), *approval.original(), credit, capacity]);
        drop(funding);
        (request, approval)
    }

    #[inline(never)]
    fn ingest(&mut self, index: usize) {
        let selected = &self.selection.policies.providers[index];
        let provider = selected.provider_id;
        let mut ingest =
            ManagedInitialProviderIngestAuthority::open(self.prepared, provider).unwrap();
        self.carriers.push(
            ingest
                .bootstrap_native(
                    self.native,
                    &selected.provider_ingest,
                    self.utc,
                    self.options,
                )
                .finalized
                .unwrap(),
        );
        drop(ingest);
    }

    #[inline(never)]
    fn gateway(&mut self, index: usize) {
        let selected = &self.selection.policies.providers[index];
        let provider = selected.provider_id;
        let mut gateway = ManagedInitialGatewaySetup::open(self.prepared, provider).unwrap();
        self.carriers.push(
            gateway
                .bootstrap_native(self.native, &selected.gateway, self.utc, self.options)
                .finalized
                .unwrap(),
        );
    }

    #[inline(never)]
    fn reputation(&mut self) {
        let mut reputation = ManagedInitialReputationPolicy::open(self.prepared).unwrap();
        self.carriers.push(
            reputation
                .bootstrap_native(
                    self.native,
                    &self.selection.policies.gateway_labels(),
                    &self.selection.policies.network.reputation,
                    self.utc,
                    self.options,
                )
                .finalized
                .unwrap(),
        );
        drop(reputation);
    }

    #[inline(never)]
    fn parent(&mut self) {
        let mut parent = ManagedServiceBootstrap::open(self.prepared).unwrap();
        let ServiceBootstrapProgress::Complete(history) =
            parent.recover(self.options.deadline).unwrap()
        else {
            panic!("all original native children must be recoverable")
        };
        assert_eq!(history.ordered_carriers().unwrap(), *self.carriers);
        assert_eq!(self.carriers.len(), 29);
        assert_eq!(
            self.carriers.iter().map(|c| c.height).collect::<Vec<_>>(),
            (3..=31).collect::<Vec<_>>()
        );
    }
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
        // Authenticate the real Catalog skeleton before the expensive native setup begins.
        // Only Copy identities cross that setup; no extra directory handles are retained.
        let catalog_material =
            retain_before_first_render.then(|| catalog_material_skeleton(&owner));
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
        GenuineNativeSetup {
            prepared: &prepared,
            native: &mut native,
            selection: &mut selection,
            carriers: &mut carriers,
            utc,
            options: &options,
        }
        .run(full_parent, short_initial);
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
            let catalog_material = catalog_material.unwrap();
            assert_eq!(catalog_material_skeleton(&owner), catalog_material);
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
            assert_eq!(owner.authority.directory.entries(8).unwrap(), before);
            let providers = owner.authority.directory.open_child("providers").unwrap();
            assert_eq!(providers.identity().unwrap(), catalog_material.0);
            for (index, component) in components.iter().enumerate() {
                assert_eq!(
                    component.directory().identity().unwrap(),
                    catalog_material.1[index]
                );
            }
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
    // Bootstrap and custody owners borrow the immutable original bundle while retaining
    // their independent fresh profile, native directory and purpose lock checks.
    assert_eq!(parses, 0);
    assert_eq!(
        selection.publication.configuration_table().unwrap(),
        expected_publication.configuration_table().unwrap()
    );
    assert!(selection.initial.iter().all(Option::is_none));
    let revision = owner.prepare_catalog(options().deadline).unwrap();
    catalog_material_skeleton(&owner);
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
#[cfg(unix)]
fn material_recovery_refuses_bootstrap_loss_after_selection_without_repair() {
    use crate::localnet::service_authorities::count_profile_validations;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-recovery-bootstrap-race");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let selected = RuntimeSelection::read(&owner.authority).unwrap();
    let before = owner.authority.directory.entries(32).unwrap();
    let ((), captures) = count_profile_validations(|| {
        bootstrap_loss_after_selection(&owner, || {
            assert!(matches!(
                owner.retain_current_custody_material(options().deadline),
                Err(crate::managed::Error::Invalid(message))
                    if message == "original service bootstrap purpose is absent"
            ));
        });
    });
    assert_eq!(
        captures, 0,
        "selection and existing reopen borrow immutable originals"
    );
    let retried = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(
        encode(&retried.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&selected.policies, MAX_POLICY_BYTES).unwrap()
    );
    // Restored ordinary history is still incomplete; no failed recovery publishes material.
    assert!(matches!(
        owner.retain_current_custody_material(options().deadline),
        Err(crate::managed::Error::Invalid(message))
            if message == "generated bootstrap has incomplete original execution"
    ));
    assert_eq!(owner.authority.directory.entries(32).unwrap(), before);
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
    #[cfg(unix)]
    {
        let peers = fixture.peers();
        let names = fixture.owner.authority.directory.entries(32).unwrap();
        let provider = fixture.selection.plans[0].provider_id();
        bootstrap_loss_after_selection(&fixture.owner, || {
            assert!(matches!(
                fixture.owner.prepare_renewed_stream_tokens(
                    &revision,
                    provider,
                    2,
                    fixture.options.deadline,
                ),
                Err(crate::managed::Error::Invalid(message))
                    if message == "original service bootstrap purpose is absent"
            ));
        });
        // Restore the same original parent and leave every real carrier/component unchanged.
        fixture.owner.validate(&revision).unwrap();
        assert_eq!(revision.required_transactions(), fixture.carriers);
        assert_eq!(
            fixture.owner.authority.directory.entries(32).unwrap(),
            names
        );
        no_http(&peers);
    }
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

fn standalone_custody_initials(
    authority: &ServiceAuthority,
    policies: &GeneratedServicePolicies,
) -> [Option<ManagedCustodyEnrollmentInterval>; 3] {
    std::array::from_fn(|index| {
        let provider = policies.providers[index].provider_id;
        ManagedStreamTokenCustody::open_existing(&authority.prepared, provider)
            .unwrap()
            .and_then(|custody| {
                custody
                    .inspect_local_initial_interval_if_present(&policies.providers[index].custody)
                    .unwrap()
            })
    })
}

#[test]
fn runtime_selection_borrows_custody_originals_without_reparse() {
    use crate::localnet::service_authorities::count_profile_validations;
    use crate::managed::service_authority::ProviderPurpose;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-borrowed-selection");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let (absent, parses) = count_profile_validations(|| RuntimeSelection::read(&owner.authority));
    let absent = absent.unwrap();
    assert_eq!(parses, 0);
    assert!(absent.initial.iter().all(Option::is_none));

    // Actual empty custody owners exercise the present constructor, without fabricating bodies.
    let originals: Vec<_> = policies
        .providers
        .iter()
        .map(|selected| {
            let custody = ServiceAuthority::open_provider(
                &prepared,
                selected.provider_id,
                ProviderPurpose::Custody,
            )
            .unwrap();
            (
                custody.directory.identity().unwrap(),
                iroha_fs::FileIdentity::of(&custody._lock).unwrap(),
            )
        })
        .collect();
    let (expected, parses) =
        count_profile_validations(|| standalone_custody_initials(&owner.authority, &policies));
    assert_eq!(parses, 3, "the real standalone owners each recapture once");
    let (selection, parses) =
        count_profile_validations(|| RuntimeSelection::read(&owner.authority));
    let selection = selection.unwrap();
    assert_eq!(parses, 0, "all four owners borrow the original profile");
    assert_eq!(selection.initial, expected);
    assert_eq!(
        encode(&selection.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&policies, MAX_POLICY_BYTES).unwrap()
    );
    for (index, selected) in policies.providers.iter().enumerate() {
        assert!(
            selection.identity(&owner.authority, index).unwrap()
                == absent.identity(&owner.authority, index).unwrap()
        );
        let custody = ServiceAuthority::open_provider_existing(
            &prepared,
            selected.provider_id,
            ProviderPurpose::Custody,
        )
        .unwrap()
        .unwrap();
        assert_eq!(custody.directory.identity().unwrap(), originals[index].0);
        assert_eq!(
            iroha_fs::FileIdentity::of(&custody._lock).unwrap(),
            originals[index].1
        );
    }
    let (revision, parses) =
        count_profile_validations(|| owner.prepare_catalog(options().deadline));
    let revision = revision.unwrap();
    assert_eq!(
        parses, 0,
        "both independent selection reads keep fresh checks without recapture"
    );
    assert_eq!(revision.stage(), GeneratedRuntimeStage::Catalog);
    assert!(revision.required_transactions().is_empty());
    for index in 0..3 {
        assert!(
            revision.manifest.intent.providers[index]
                == selection.identity(&owner.authority, index).unwrap()
        );
    }
    no_http(&peers);
}

#[test]
fn runtime_selection_borrowed_custody_refuses_changed_sources_and_lock_with_retry() {
    use crate::managed::service_authority::ProviderPurpose;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-borrowed-refusal");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    // The bootstrap purpose retains its own independent exclusive lock.
    let bootstrap =
        ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
            .unwrap()
            .unwrap();
    let bootstrap_identity = bootstrap.directory.identity().unwrap();
    let bootstrap_lock = iroha_fs::FileIdentity::of(&bootstrap._lock).unwrap();
    assert!(RuntimeSelection::read(&owner.authority).is_err());
    no_http(&peers);
    drop(bootstrap);
    let retried = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(retried.initial, expected.initial);
    let bootstrap =
        ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
            .unwrap()
            .unwrap();
    assert_eq!(bootstrap.directory.identity().unwrap(), bootstrap_identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&bootstrap._lock).unwrap(),
        bootstrap_lock
    );
    drop(bootstrap);
    for selected in &policies.providers {
        let custody = ServiceAuthority::open_provider(
            &prepared,
            selected.provider_id,
            ProviderPurpose::Custody,
        )
        .unwrap();
        let directory = custody.directory.identity().unwrap();
        let lock = iroha_fs::FileIdentity::of(&custody._lock).unwrap();
        assert!(RuntimeSelection::read(&owner.authority).is_err());
        no_http(&peers);
        drop(custody);
        let retried = RuntimeSelection::read(&owner.authority).unwrap();
        assert_eq!(retried.initial, expected.initial);
        let original = ServiceAuthority::open_provider_existing(
            &prepared,
            selected.provider_id,
            ProviderPurpose::Custody,
        )
        .unwrap()
        .unwrap();
        assert_eq!(original.directory.identity().unwrap(), directory);
        assert_eq!(iroha_fs::FileIdentity::of(&original._lock).unwrap(), lock);
    }
    let root = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let original = root.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = Zeroizing::new(original.to_vec());
    changed.extend_from_slice(b"\n# changed original byte custody\n");
    crate::secret_toml::parse_table(std::str::from_utf8(&changed).unwrap(), "changed peer")
        .unwrap();
    root.write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(RuntimeSelection::read(&owner.authority).is_err());
    assert_eq!(
        root.read("peer3.toml", MAX_CONFIG_BYTES)
            .unwrap()
            .as_slice(),
        changed.as_slice()
    );
    no_http(&peers);
    root.write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let restored = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(restored.initial, expected.initial);
    assert_eq!(
        encode(&restored.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&expected.policies, MAX_POLICY_BYTES).unwrap()
    );
    let generation_identity = root.identity().unwrap();
    let saved = _temporary.path().join("saved-runtime-selection-generation");
    #[cfg(unix)]
    {
        std::fs::rename(root.path(), &saved).unwrap();
        assert!(RuntimeSelection::read(&owner.authority).is_err());
        let replacement = PrivateDirectory::open_or_create(root.path()).unwrap();
        assert!(RuntimeSelection::read(&owner.authority).is_err());
        assert!(replacement.entries(8).unwrap().is_empty());
        no_http(&peers);
        drop(replacement);
        std::fs::remove_dir(root.path()).unwrap();
        std::fs::rename(&saved, root.path()).unwrap();
    }
    #[cfg(windows)]
    {
        // Native sharing forbids moving this retained generation on Windows.
        assert!(std::fs::rename(root.path(), &saved).is_err());
    }
    assert_eq!(root.identity().unwrap(), generation_identity);
    let retried = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(retried.initial, expected.initial);
    assert_eq!(
        encode(&retried.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&expected.policies, MAX_POLICY_BYTES).unwrap()
    );
    owner.authority.validate_profile().unwrap();
    no_http(&peers);
}

#[test]
fn runtime_selection_active_and_owned_custody_keeps_full_admission() {
    use crate::localnet::service_authorities::count_profile_validations;
    use norito::core::DecodeBudgetContext;
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-borrowed-admission");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (selection, parses) =
        count_profile_validations(|| baseline.with(|| RuntimeSelection::read(&owner.authority)));
    let selection = selection.unwrap();
    assert_eq!(parses, 4, "active admission keeps all four full captures");
    assert_eq!(selection.initial, expected.initial);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (selection, parses) =
        count_profile_validations(|| exact.with(|| RuntimeSelection::read(&owner.authority)));
    let selection = selection.unwrap();
    assert_eq!(parses, 4);
    assert_eq!(exact.consumed_allocated_bytes(), charge as u64);
    assert_eq!(
        encode(&selection.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&expected.policies, MAX_POLICY_BYTES).unwrap()
    );
    for allocated in [0, charge - 1] {
        let first = DecodeBudgetContext::new(limits(allocated));
        let expected_error = first
            .with(|| RuntimeSelection::read(&owner.authority))
            .err()
            .unwrap();
        let retry = DecodeBudgetContext::new(limits(allocated));
        let refused = retry
            .with(|| RuntimeSelection::read(&owner.authority))
            .err()
            .unwrap();
        assert_eq!(refused.to_string(), expected_error.to_string());
        assert_eq!(
            retry.consumed_allocated_bytes(),
            first.consumed_allocated_bytes()
        );
    }
    drop(owner);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owned = caller
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    let (selection, parses) =
        count_profile_validations(|| RuntimeSelection::read(&owned.authority));
    let selection = selection.unwrap();
    assert_eq!(
        parses, 4,
        "an Owned parent outside its old scope still fully recaptures"
    );
    assert_eq!(selection.initial, expected.initial);
    assert_eq!(
        encode(&selection.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&expected.policies, MAX_POLICY_BYTES).unwrap()
    );
    owned.authority.validate_profile().unwrap();
    no_http(&peers);
}

#[test]
fn runtime_selection_missing_bootstrap_refuses_without_creating_purpose_state() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-missing-bootstrap");
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let network =
        PrivateDirectory::open_exact(owner.authority.directory.path().parent().unwrap()).unwrap();
    let before = network.entries(8).unwrap();
    assert!(
        network
            .open_child_optional("service-bootstrap")
            .unwrap()
            .is_none()
    );
    assert!(RuntimeSelection::read(&owner.authority).is_err());
    assert!(
        network
            .open_child_optional("service-bootstrap")
            .unwrap()
            .is_none()
    );
    assert_eq!(network.entries(8).unwrap(), before);
    no_http(&peers);

    // Only the explicit startup producer may create and authorize the missing purpose.
    let policies = select(&prepared);
    let selection = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(
        encode(&selection.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&policies, MAX_POLICY_BYTES).unwrap()
    );
    assert!(selection.initial.iter().all(Option::is_none));
    owner.authority.validate_profile().unwrap();
    no_http(&peers);
}

#[test]
#[cfg(unix)]
fn runtime_selection_missing_original_bootstrap_keeps_absence_and_same_original_retry() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-lost-bootstrap");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    let (path, identity, lock, names, initial_identity, original, initial_names) = {
        let bootstrap =
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
                .unwrap()
                .unwrap();
        let initial = bootstrap.directory.open_child("initial").unwrap();
        (
            bootstrap.directory.path().to_path_buf(),
            bootstrap.directory.identity().unwrap(),
            iroha_fs::FileIdentity::of(&bootstrap._lock).unwrap(),
            bootstrap.directory.entries(8).unwrap(),
            initial.identity().unwrap(),
            initial.read("original.nrt", 512 * 1024).unwrap(),
            initial.entries(8).unwrap(),
        )
    };
    let network = PrivateDirectory::open_exact(path.parent().unwrap()).unwrap();
    let saved = network.path().join("saved-original-service-bootstrap");
    std::fs::rename(&path, &saved).unwrap();
    let displaced_names = network.entries(8).unwrap();
    assert!(RuntimeSelection::read(&owner.authority).is_err());
    assert!(
        !path.exists(),
        "a selection read must not recreate the original purpose"
    );
    assert_eq!(network.entries(8).unwrap(), displaced_names);
    no_http(&peers);

    // Restore the same native directory, lock and original bytes, rather than new equivalents.
    std::fs::rename(&saved, &path).unwrap();
    let restored = RuntimeSelection::read(&owner.authority).unwrap();
    assert_eq!(restored.initial, expected.initial);
    assert_eq!(
        encode(&restored.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&policies, MAX_POLICY_BYTES).unwrap()
    );
    let bootstrap =
        ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
            .unwrap()
            .unwrap();
    assert_eq!(bootstrap.directory.identity().unwrap(), identity);
    assert_eq!(iroha_fs::FileIdentity::of(&bootstrap._lock).unwrap(), lock);
    assert_eq!(bootstrap.directory.entries(8).unwrap(), names);
    let initial = bootstrap.directory.open_child("initial").unwrap();
    assert_eq!(initial.identity().unwrap(), initial_identity);
    assert_eq!(initial.read("original.nrt", 512 * 1024).unwrap(), original);
    assert_eq!(initial.entries(8).unwrap(), initial_names);
    owner.authority.validate_profile().unwrap();
    no_http(&peers);
}

thread_local! {
    static SELECTION_FINISH_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub(super) fn before_selection_finish() {
    let action = SELECTION_FINISH_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

struct SelectionFinishHook;
impl SelectionFinishHook {
    fn install(action: impl FnOnce() + 'static) -> Self {
        SELECTION_FINISH_HOOK.with(|hook| {
            assert!(hook.borrow_mut().replace(Box::new(action)).is_none());
        });
        Self
    }
}
impl Drop for SelectionFinishHook {
    fn drop(&mut self) {
        SELECTION_FINISH_HOOK.with(|hook| *hook.borrow_mut() = None);
    }
}

fn assert_same_runtime_selection(
    authority: &ServiceAuthority,
    actual: &RuntimeSelection,
    expected: &RuntimeSelection,
) {
    assert_eq!(
        encode(&actual.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&expected.policies, MAX_POLICY_BYTES).unwrap()
    );
    assert_eq!(actual.initial, expected.initial);
    assert_eq!(
        actual.publication.configuration_table().unwrap(),
        expected.publication.configuration_table().unwrap()
    );
    for index in 0..3 {
        assert!(
            actual.identity(authority, index).unwrap()
                == expected.identity(authority, index).unwrap()
        );
    }
}

#[test]
fn runtime_selection_immutable_projection_keeps_original_values_and_bounded_full_checks() {
    use crate::managed::service_authority::profile_validation_test_support;

    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-projection-checks");
    let policies = select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected_plans = owner.authority.provider_plans().unwrap().clone();
    let expected_publication = owner.authority.publication_plan().unwrap();
    let expected_compliance: [_; 3] = std::array::from_fn(|index| {
        owner
            .authority
            .gateway_compliance_plan(expected_plans[index].provider_id())
            .unwrap()
    });
    let expected_initial = standalone_custody_initials(&owner.authority, &policies);
    let (actual, checks) =
        profile_validation_test_support::count(|| RuntimeSelection::read(&owner.authority));
    let actual = actual.unwrap();
    // Existing child locks, mutable reads and the unconditional image exit remain; the
    // constructor and bootstrap policy projections share this exact original image.
    assert_eq!(checks, 2);
    assert_eq!(actual.initial, expected_initial);
    assert_eq!(
        encode(&actual.policies, MAX_POLICY_BYTES).unwrap(),
        encode(&policies, MAX_POLICY_BYTES).unwrap()
    );
    assert_eq!(
        actual.publication.configuration_table().unwrap(),
        expected_publication.configuration_table().unwrap()
    );
    for index in 0..3 {
        assert_eq!(
            actual.plans[index].original_profile_commitment(),
            expected_plans[index].original_profile_commitment()
        );
        assert_eq!(
            actual.plans[index].provider_id(),
            expected_plans[index].provider_id()
        );
        assert_eq!(
            actual.plans[index].peer_index(),
            expected_plans[index].peer_index()
        );
        assert_eq!(actual.plans[index].slot(), expected_plans[index].slot());
        assert_eq!(
            actual.compliance[index].original_commitment(),
            expected_compliance[index].original_commitment()
        );
    }
    no_http(&peers);
}

#[test]
fn runtime_selection_projection_refuses_source_changes_at_entry_and_exit_then_retries() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-projection-custody");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    let generation = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let original = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = original.to_vec();
    changed.extend_from_slice(b"\n# changed source image, same parsed configuration\n");
    let names = owner
        .authority
        .directory
        .entries(MAX_RUNTIME_ENTRIES)
        .unwrap();

    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(RuntimeSelection::read(&owner.authority).is_err());
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let restored = RuntimeSelection::read(&owner.authority).unwrap();
    assert_same_runtime_selection(&owner.authority, &restored, &expected);

    let source = generation.retain().unwrap();
    let hook = SelectionFinishHook::install(move || {
        source
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
    });
    let error = RuntimeSelection::read(&owner.authority).err().unwrap();
    assert!(SELECTION_FINISH_HOOK.with(|value| value.borrow().is_none()));
    drop(hook);
    assert!(
        matches!(error, crate::managed::Error::Invalid(message) if message == "retained service profile input custody differs")
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let restored = RuntimeSelection::read(&owner.authority).unwrap();
    assert_same_runtime_selection(&owner.authority, &restored, &expected);
    assert_eq!(
        owner
            .authority
            .directory
            .entries(MAX_RUNTIME_ENTRIES)
            .unwrap(),
        names
    );
    no_http(&peers);
}

#[test]
fn runtime_selection_projection_closes_original_custody_after_child_read_error() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, peers) = fixture("runtime-projection-error-exit");
    select(&prepared);
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    let expected = RuntimeSelection::read(&owner.authority).unwrap();
    let generation = PrivateDirectory::open_exact(generation_path(&prepared).unwrap()).unwrap();
    let profile = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let bootstrap = PrivateDirectory::open_exact(
        owner
            .authority
            .directory
            .path()
            .parent()
            .unwrap()
            .join("service-bootstrap"),
    )
    .unwrap();
    let initial = bootstrap.open_child("initial").unwrap();
    let original = initial.read("original.nrt", MAX_POLICY_BYTES).unwrap();
    let names = initial.entries(32).unwrap();
    initial
        .write_atomic(
            "original.nrt",
            b"malformed bootstrap original",
            PublishMode::Replace,
        )
        .unwrap();
    let ordinary = RuntimeSelection::read(&owner.authority).err().unwrap();
    assert!(
        matches!(ordinary, crate::managed::Error::Invalid(message) if message == "invalid original service bootstrap intent")
    );

    let source = generation.retain().unwrap();
    let mut changed = profile.to_vec();
    changed.extend_from_slice(b"\n# changed source after an ordinary child refusal\n");
    let hook = SelectionFinishHook::install(move || {
        source
            .write_atomic("peer3.toml", &changed, PublishMode::Replace)
            .unwrap();
    });
    let error = RuntimeSelection::read(&owner.authority).err().unwrap();
    assert!(SELECTION_FINISH_HOOK.with(|value| value.borrow().is_none()));
    drop(hook);
    assert!(
        matches!(error, crate::managed::Error::Invalid(message) if message == "retained service profile input custody differs")
    );
    generation
        .write_atomic("peer3.toml", &profile, PublishMode::Replace)
        .unwrap();
    initial
        .write_atomic("original.nrt", &original, PublishMode::Replace)
        .unwrap();
    let restored = RuntimeSelection::read(&owner.authority).unwrap();
    assert_same_runtime_selection(&owner.authority, &restored, &expected);
    assert_eq!(initial.entries(32).unwrap(), names);
    no_http(&peers);
}

#[test]
fn renewal_operation_releases_original_custody_before_catalog_validation() {
    use crate::managed::{
        ManagedBootstrapFailure, native_operation::Fees, runtime::test_with_renewal_custody,
        stream_token_custody::renewal::GeneratedRenewalTurn,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::with_material_preflight("runtime-renewal-lock", true, false, true);
    let peers = fixture.peers();
    assert_eq!(fixture.carriers.len(), 29);
    assert_eq!(fixture.catalog.stage(), GeneratedRuntimeStage::Catalog);
    let provider = fixture.selection.plans[0].provider_id();
    let options = BoundedTransactionOptions {
        fee_payment: fixture
            .selection
            .policies
            .network
            .runtime_fee_payment
            .clone(),
        max_total_fees: BTreeMap::from([(
            fixture
                .selection
                .policies
                .network
                .reserve
                .asset_definition
                .clone(),
            Quantity::from(1_u64),
        )]),
        deadline: fixture.options.deadline,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let require_overlap_refusal = || {
        assert!(matches!(
            fixture.owner.validate(&fixture.catalog),
            Err(crate::managed::Error::Invalid(message))
                if message == "another managed native operation holds this generation"
        ));
    };
    fixture.owner.validate(&fixture.catalog).unwrap();
    let mut turn = test_with_renewal_custody(&fixture.prepared, provider, |custody| {
        require_overlap_refusal();
        GeneratedRenewalTurn::begin(
            custody,
            &fixture.selection.policies.providers[0].custody,
            Fees::from_options(&options)?,
            *fixture.carriers.last().unwrap(),
            options.deadline,
            Arc::clone(&cancelled),
        )
    })
    .unwrap();
    // The genuine native configuration and carrier created this exact owned turn. The
    // production scope must release its operation lock before the renderer can reopen it.
    fixture.owner.validate(&fixture.catalog).unwrap();
    let original_turn = std::ptr::addr_of!(turn);
    let result = test_with_renewal_custody(&fixture.prepared, provider, |custody| {
        require_overlap_refusal();
        custody.reconcile_generated_renewal(&mut turn, Instant::now())
    });
    assert!(matches!(result, Err(crate::managed::Error::NativeDeadline)));
    assert_eq!(std::ptr::addr_of!(turn), original_turn);
    fixture.owner.validate(&fixture.catalog).unwrap();

    // Reopening custody cannot replace the turn's original cancellation capability. Both
    // ordinary failures close the actual native lock before the complete renderer check.
    cancelled.store(true, Ordering::Release);
    let result = test_with_renewal_custody(&fixture.prepared, provider, |custody| {
        require_overlap_refusal();
        custody.reconcile_generated_renewal(&mut turn, options.deadline)
    });
    assert!(matches!(
        result,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    assert_eq!(std::ptr::addr_of!(turn), original_turn);
    fixture.owner.validate(&fixture.catalog).unwrap();
    assert!(cancelled.load(Ordering::Acquire));
    no_http(&peers);
}

#[test]
fn fresh_catalog_round_preserves_original_census_and_expired_current_proof_refusal() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Genuine::with_material_preflight("runtime-catalog-round", true, false, true);
    let peers = fixture.peers();
    assert_eq!(fixture.carriers.len(), 29);
    assert!(fixture.owner.fresh_catalog_round().unwrap());
    let finite = 64 * 1024 * 1024;
    let active = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        finite, finite, finite, 0, 64,
    ));
    assert!(
        !active.with(|| fixture.owner.fresh_catalog_round()).unwrap(),
        "active limits skip even the scheduling census"
    );
    let required = RequiredTransactions::from_originals(fixture.carriers.iter().copied()).unwrap();
    let before = fixture.owner.authority.directory.entries(32).unwrap();
    let floor = required.observation_floor().unwrap();
    // This is the production three-owner loop with real independent finality/challenge and
    // native custody producers. It never fabricates a checkpoint, proof or retained enrollment.
    for wrong_provider in [false, true, false] {
        let challenges: [_; 3] = std::array::from_fn(|_| std::sync::Mutex::new(Vec::new()));
        let result = fixture.owner.current_provider_round(
            &fixture.selection,
            fixture.options.deadline,
            true,
            |slot, custody| {
                let policy = &fixture.selection.policies.providers[slot].custody;
                let current = custody.test_native_current(
                    &fixture.native,
                    policy,
                    fixture.options.deadline,
                    &challenges[slot],
                )?;
                let selected = if wrong_provider && slot == 1 { 0 } else { slot };
                custody.verify_enrollment_at(
                    fixture.components[selected].enrollment(),
                    policy,
                    floor.height,
                    *floor.block_hash.as_ref(),
                    &current,
                    now_ms()?,
                    fixture.options.deadline,
                )?;
                Ok(fixture.components[slot].enrollment().record_digest())
            },
        );
        assert_eq!(
            result.is_err(),
            wrong_provider,
            "fresh native provider round: wrong_provider={wrong_provider}; result={result:?}; remaining_ms={}",
            fixture
                .options
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        );
        if let Ok(digests) = result {
            assert_eq!(
                digests,
                fixture
                    .components
                    .each_ref()
                    .map(|component| component.enrollment().record_digest())
            );
        }
        let challenges = challenges.map(|values| values.into_inner().unwrap());
        for values in &challenges {
            assert_eq!(values.len(), 4);
            assert!(values.iter().all(|value| *value == values[0]));
            assert_ne!(values[0], [0; 32]);
        }
        assert_ne!(challenges[0][0], challenges[1][0]);
        assert_ne!(challenges[0][0], challenges[2][0]);
        assert_ne!(challenges[1][0], challenges[2][0]);
        // Even the failed aggregate joined and released every actual provider purpose lock.
        for plan in &fixture.selection.plans {
            drop(ManagedStreamTokenCustody::open(&fixture.prepared, plan.provider_id()).unwrap());
        }
    }
    for parallel in [false, true] {
        assert!(matches!(
            fixture.owner.verify_current_components(
                &fixture.selection,
                &fixture.components,
                &required,
                Instant::now(),
                parallel,
            ),
            Err(crate::managed::Error::NativeDeadline)
        ));
    }
    assert_eq!(
        fixture.owner.authority.directory.entries(32).unwrap(),
        before
    );
    fixture.owner.validate(&fixture.catalog).unwrap();
    // An actual retained provider-purpose owner selects original serial recovery, including
    // the empty pre-catalog prefix. This name confers no catalog or native admission result.
    let provider = fixture.selection.plans[1].provider_id();
    let publisher = crate::managed::gateway_compliance::ManagedGatewayCompliance::open(
        &fixture.prepared,
        provider,
    )
    .unwrap();
    assert!(!fixture.owner.fresh_catalog_round().unwrap());
    drop(publisher);
    assert!(!fixture.owner.fresh_catalog_round().unwrap());
    no_http(&peers);
}

#[path = "import_scope_tests.rs"]
pub(super) mod import_scope_tests;

#[path = "policy_projection_tests.rs"]
mod policy_projection_tests;

#[path = "runtime_original_tests.rs"]
mod runtime_original_tests;
