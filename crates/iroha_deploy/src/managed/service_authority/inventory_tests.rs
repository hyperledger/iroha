//! Real generated private-custody controls for parent absence and present-child originals.

use super::*;
use iroha_fs::PublishMode;

fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "inventory-fast-path",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let owner =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    (temporary, owner)
}

#[test]
fn all_absent_child_purposes_preserve_names_without_reconstructing_authorities() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let providers = parent
        .manifest
        .providers
        .each_ref()
        .map(|value| value.provider_id);
    let before = parent.directory.entries(4).unwrap();
    let (result, opens) = ServiceChildInventory::test_count_authority_opens(|| -> Result<()> {
        let inventory = ServiceChildInventory::begin(&parent)?;
        assert!(
            inventory
                .open_network(NetworkPurpose::InitialReservePolicy)?
                .is_none()
        );
        assert!(
            inventory
                .open_network(NetworkPurpose::InitialReputationPolicy)?
                .is_none()
        );
        for provider in providers {
            for purpose in [
                ProviderPurpose::Custody,
                ProviderPurpose::Custody,
                ProviderPurpose::ReserveAccountRegistration,
                ProviderPurpose::ProviderFundingBootstrap,
                ProviderPurpose::ReserveTopUpRequest,
                ProviderPurpose::ReserveTopUpApproval,
                ProviderPurpose::InitialProviderCredit,
                ProviderPurpose::ProviderCapacityDeclaration,
                ProviderPurpose::InitialProviderIngestAuthority,
                ProviderPurpose::InitialGatewaySetup,
            ] {
                assert!(inventory.open_provider(provider, purpose)?.is_none());
            }
        }
        assert!(
            inventory
                .open_provider(ProviderId::new([0x71; 32]), ProviderPurpose::Custody)
                .is_err()
        );
        inventory.finish()
    });
    result.unwrap();
    assert_eq!(opens, 0);
    assert_eq!(parent.directory.entries(4).unwrap(), before);
    assert!(
        !parent
            .directory
            .path()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("providers")
            .exists()
    );
}

#[test]
fn present_child_preserves_native_lock_empty_prefix_and_dirty_loss_rules() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let provider = parent.manifest.providers[1].provider_id;
    let child =
        ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
            .unwrap();
    let retained = child.directory.retain().unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let (locked, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    assert!(locked.is_err());
    assert_eq!(opens, 1);
    drop(child);
    let (reopened, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    let reopened = reopened.unwrap().unwrap();
    assert_eq!(opens, 1);
    assert_eq!(
        reopened.directory.identity().unwrap(),
        retained.identity().unwrap()
    );
    assert_eq!(reopened.config.network_id, parent.config.network_id);
    drop(reopened);
    std::fs::remove_file(retained.path().join("operation.lock")).unwrap();
    let (empty, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    assert!(empty.unwrap().is_none());
    assert_eq!(opens, 1);
    assert!(retained.entries(1).unwrap().is_empty());
    super::super::super::native_operation::require_empty(&retained).unwrap();
    retained
        .write_atomic("unknown.nrt", b"presence only", PublishMode::CreateNew)
        .unwrap();
    // The exact snapshot must also be empty if material arrives after the initial empty check.
    assert!(Branch::capture_empty(retained.retain().unwrap()).is_err());
    let (changed, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    assert!(changed.is_err());
    assert_eq!(opens, 0);
    assert!(inventory.finish().is_err());
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let (dirty, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    assert!(dirty.is_err());
    assert_eq!(opens, 1);
    assert!(!retained.path().join("operation.lock").exists());
    assert_eq!(
        retained.read("unknown.nrt", 32).unwrap().as_slice(),
        b"presence only"
    );
    inventory.finish().unwrap();
}

#[test]
fn new_earlier_namespace_and_replaced_parent_lock_refuse_before_child_open() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(
        inventory
            .open_provider(provider, ProviderPurpose::Custody)
            .unwrap()
            .is_none()
    );
    // The same parent-native ancestry now has material where the previous probe observed absence.
    let operations = &inventory.branches[1].directory;
    operations.ensure_child("providers").unwrap();
    let (changed, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.open_network(NetworkPurpose::InitialReservePolicy)
    });
    assert!(changed.is_err());
    assert_eq!(opens, 0);
    assert!(inventory.finish().is_err());
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    #[cfg(unix)]
    {
        parent
            .directory
            .write_atomic("operation.lock", b"", PublishMode::Replace)
            .unwrap();
        let (changed, opens) = ServiceChildInventory::test_count_authority_opens(|| {
            inventory.open_provider(provider, ProviderPurpose::Custody)
        });
        assert!(changed.is_err());
        assert_eq!(opens, 0);
        assert!(inventory.finish().is_err());
    }
    #[cfg(windows)]
    {
        // The retained native lock denies deletion/replacement before its identity can change.
        let original = iroha_fs::FileIdentity::of(&parent._lock).unwrap();
        assert!(
            parent
                .directory
                .write_atomic("operation.lock", b"", PublishMode::Replace)
                .is_err()
        );
        assert_eq!(iroha_fs::FileIdentity::of(&parent._lock).unwrap(), original);
        assert_eq!(
            iroha_fs::FileIdentity::of(&parent.directory.open_read("operation.lock").unwrap())
                .unwrap(),
            original
        );
        let (unchanged, opens) = ServiceChildInventory::test_count_authority_opens(|| {
            inventory.open_provider(provider, ProviderPurpose::Custody)
        });
        assert!(unchanged.unwrap().is_none());
        assert_eq!(opens, 0);
        inventory.finish().unwrap();
    }
}

#[test]
fn whole_profile_is_authenticated_before_and_after_the_absence_census() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let peer = &parent.prepared.peers[0].config_path;
    let directory = PrivateDirectory::open_exact(peer.parent().unwrap()).unwrap();
    let original = directory
        .read(peer.file_name().unwrap(), 1024 * 1024)
        .unwrap();
    directory
        .write_atomic(
            peer.file_name().unwrap(),
            b"invalid = [",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(inventory.finish().is_err());
    assert!(ServiceChildInventory::begin(&parent).is_err());
    // Ordinary standalone absence callers keep their full original authentication contract.
    assert!(
        ServiceAuthority::open_network_existing(
            &parent.prepared,
            NetworkPurpose::InitialReservePolicy
        )
        .is_err()
    );
    directory
        .write_atomic(peer.file_name().unwrap(), &original, PublishMode::Replace)
        .unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(
        inventory
            .open_network(NetworkPurpose::InitialReservePolicy)
            .unwrap()
            .is_none()
    );
    inventory.finish().unwrap();
}

#[test]
fn first_reserve_name_probe_refuses_appeared_names_and_retries_fresh_without_child_opens() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let (missing, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        ServiceChildInventory::begin(&parent)?.initial_reserve_policy_absent()
    });
    assert!(missing.unwrap());
    assert_eq!(opens, 0);
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let network = inventory.branches[inventory.network]
        .directory
        .retain()
        .unwrap();
    let purpose = network
        .ensure_child(NetworkPurpose::InitialReservePolicy.directory_name())
        .unwrap();
    let (refused, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        inventory.initial_reserve_policy_absent()
    });
    assert!(refused.is_err());
    assert_eq!(opens, 0);
    let (present, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        ServiceChildInventory::begin(&parent)?.initial_reserve_policy_absent()
    });
    assert!(!present.unwrap());
    assert_eq!(opens, 0, "presence observation must not lock a child");
    assert!(purpose.entries(1).unwrap().is_empty());
    std::fs::remove_dir(purpose.path()).unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let appeared = network.ensure_child("appeared-purpose").unwrap();
    assert!(inventory.initial_reserve_policy_absent().is_err());
    std::fs::remove_dir(appeared.path()).unwrap();
    assert!(
        ServiceChildInventory::begin(&parent)
            .unwrap()
            .initial_reserve_policy_absent()
            .unwrap()
    );
}

#[test]
fn first_reserve_name_probe_checks_original_profile_at_entry_and_exit_then_retries() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let peer = &parent.prepared.peers[0].config_path;
    let generation = PrivateDirectory::open_exact(peer.parent().unwrap()).unwrap();
    let name = peer.file_name().unwrap();
    let original = generation.read(name, 1024 * 1024).unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    generation
        .write_atomic(name, b"invalid = [", PublishMode::Replace)
        .unwrap();
    let ((entry, exit), opens) = ServiceChildInventory::test_count_authority_opens(|| {
        (
            ServiceChildInventory::begin(&parent).is_err(),
            inventory.initial_reserve_policy_absent().is_err(),
        )
    });
    assert!(entry && exit);
    assert_eq!(opens, 0);
    generation
        .write_atomic(name, &original, PublishMode::Replace)
        .unwrap();
    let (retried, opens) = ServiceChildInventory::test_count_authority_opens(|| {
        ServiceChildInventory::begin(&parent)?.initial_reserve_policy_absent()
    });
    assert!(retried.unwrap());
    assert_eq!(opens, 0);
    assert_eq!(generation.read(name, 1024 * 1024).unwrap(), original);
}

#[test]
fn first_reserve_name_probe_retains_parent_lock_and_native_ancestors_before_retry() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let lock_identity = iroha_fs::FileIdentity::of(&parent._lock).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let lock_path = parent.directory.path().join("operation.lock");
        let original_path = parent.directory.path().join("original-operation.lock");
        std::fs::rename(&lock_path, &original_path).unwrap();
        parent
            .directory
            .write_atomic("operation.lock", b"", PublishMode::CreateNew)
            .unwrap();
        assert!(inventory.initial_reserve_policy_absent().is_err());
        assert!(ServiceChildInventory::begin(&parent).is_err());
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::rename(&original_path, &lock_path).unwrap();
        assert_eq!(
            iroha_fs::FileIdentity::of(&parent.directory.open_read("operation.lock").unwrap())
                .unwrap(),
            lock_identity
        );
        assert!(
            ServiceChildInventory::begin(&parent)
                .unwrap()
                .initial_reserve_policy_absent()
                .unwrap()
        );

        let inventory = ServiceChildInventory::begin(&parent).unwrap();
        let network_path = parent.directory.path().parent().unwrap();
        let original_mode = std::fs::metadata(network_path).unwrap().permissions();
        std::fs::set_permissions(network_path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(inventory.initial_reserve_policy_absent().is_err());
        std::fs::set_permissions(network_path, original_mode).unwrap();
        assert!(
            ServiceChildInventory::begin(&parent)
                .unwrap()
                .initial_reserve_policy_absent()
                .unwrap()
        );

        let inventory = ServiceChildInventory::begin(&parent).unwrap();
        let operations = PrivateDirectory::open_exact(network_path.parent().unwrap()).unwrap();
        let saved_network = operations.path().join("original-network");
        std::fs::rename(network_path, &saved_network).unwrap();
        let replaced = operations.ensure_child("network").unwrap();
        assert!(inventory.initial_reserve_policy_absent().is_err());
        std::fs::remove_dir(replaced.path()).unwrap();
        std::fs::rename(&saved_network, network_path).unwrap();
        assert!(
            ServiceChildInventory::begin(&parent)
                .unwrap()
                .initial_reserve_policy_absent()
                .unwrap()
        );
    }
    #[cfg(windows)]
    {
        // Retained native lock denies replacement; no successful mutation is fabricated.
        assert!(
            parent
                .directory
                .write_atomic("operation.lock", b"", PublishMode::Replace)
                .is_err()
        );
        assert_eq!(
            iroha_fs::FileIdentity::of(&parent._lock).unwrap(),
            lock_identity
        );
        assert!(inventory.initial_reserve_policy_absent().unwrap());
    }
    assert_eq!(
        iroha_fs::FileIdentity::of(&parent._lock).unwrap(),
        lock_identity
    );
    assert!(
        ServiceChildInventory::begin(&parent)
            .unwrap()
            .initial_reserve_policy_absent()
            .unwrap()
    );
}

struct OriginalChildProjection {
    config: Config,
    genesis: GenesisAnchor,
    manifest: StreamTokenAuthorityManifest,
    peers: Vec<PeerId>,
    plan: RetainedProviderServicePlan,
    directory: iroha_fs::FileIdentity,
    lock: iroha_fs::FileIdentity,
}
impl OriginalChildProjection {
    fn capture(authority: &ServiceAuthority) -> Self {
        Self {
            config: authority.config.clone(),
            genesis: authority.genesis.clone(),
            manifest: authority.manifest.clone(),
            peers: authority.peers.iter().map(|(id, _)| id.clone()).collect(),
            plan: authority.provider_plan().unwrap(),
            directory: authority.directory.identity().unwrap(),
            lock: iroha_fs::FileIdentity::of(&authority._lock).unwrap(),
        }
    }
    fn require_same(&self, actual: &ServiceAuthority) {
        assert_eq!(actual.config.network_id, self.config.network_id);
        assert_eq!(actual.config.chain, self.config.chain);
        assert_eq!(actual.config.account, self.config.account);
        assert_eq!(
            actual.config.account_chain_discriminant,
            self.config.account_chain_discriminant
        );
        assert_eq!(
            actual.config.key_pair.public_key(),
            self.config.key_pair.public_key()
        );
        assert_eq!(actual.config.torii_api_url, self.config.torii_api_url);
        assert_eq!(actual.genesis, self.genesis);
        assert_eq!(actual.manifest, self.manifest);
        assert_eq!(
            actual.peers.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            self.peers.iter().collect::<Vec<_>>()
        );
        assert_eq!(actual.directory.identity().unwrap(), self.directory);
        assert_eq!(
            iroha_fs::FileIdentity::of(&actual._lock).unwrap(),
            self.lock
        );
        let actual = actual.provider_plan().unwrap();
        assert_eq!(
            actual.original_profile_commitment(),
            self.plan.original_profile_commitment()
        );
        assert_eq!(actual.admission_material(), self.plan.admission_material());
        assert_eq!(actual.reserve_terms(), self.plan.reserve_terms());
        assert_eq!(actual.declaration(), self.plan.declaration());
        assert_eq!(actual.pricing(), self.plan.pricing());
    }
}

#[test]
fn present_census_shares_original_bundle_without_mutable_parent_projection_leakage() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    drop(
        ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
            .unwrap(),
    );
    let (expected, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            ServiceAuthority::open_provider_existing(
                &parent.prepared,
                provider,
                ProviderPurpose::Custody,
            )
            .unwrap()
            .unwrap()
        });
    assert_eq!(parses, 1);
    let expected_projection = OriginalChildProjection::capture(&expected);
    drop(expected); // Both paths must acquire the same genuine exclusive child lock in turn.
    let parent_config = parent.config.clone();
    let parent_genesis = parent.genesis.clone();
    parent.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    parent.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"mutable census projection"),
        ));
    parent.config.account_chain_discriminant ^= 1;
    parent.genesis.chain_id.push_str("-mutable-projection");
    parent.peers.reverse();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        inventory
            .open_provider(provider, ProviderPurpose::Custody)
            .unwrap()
            .unwrap()
    });
    assert_eq!(parses, 0);
    let (AuthorityProfile::Shared(parent_bundle), AuthorityProfile::Shared(child_bundle)) =
        (&parent.profile, &child.profile)
    else {
        panic!("outside active admission both share validated originals")
    };
    assert!(Arc::ptr_eq(parent_bundle, child_bundle));
    expected_projection.require_same(&child);
    assert_eq!(child.test_checkpoint_import_attempts(), 0);
    child.validate_profile().unwrap();
    drop(child);
    inventory.finish().unwrap();
    parent.config = parent_config;
    parent.genesis = parent_genesis;
    parent.peers.reverse();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    let child = child.unwrap().unwrap();
    assert_eq!(parses, 0);
    expected_projection.require_same(&child);
    drop(child);
    inventory.finish().unwrap();
    let expected = ServiceAuthority::open_provider_existing(
        &parent.prepared,
        provider,
        ProviderPurpose::Custody,
    )
    .unwrap()
    .unwrap();
    expected_projection.require_same(&expected);
}

#[test]
fn present_census_rechecks_complete_profile_and_native_parent_then_restores_original() {
    let _guard = crate::managed::native_test_guard();
    let (temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    let child =
        ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
            .unwrap();
    let child_identity = child.directory.identity().unwrap();
    let lock_identity = iroha_fs::FileIdentity::of(&child._lock).unwrap();
    drop(child);
    let generation =
        PrivateDirectory::open_exact(parent.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let runtime = generation.open_child("runtime").unwrap();
    let authorities = runtime.open_child("stream-token-authorities").unwrap();
    for (directory, name, maximum) in [
        (&generation, "peer3.toml", 1024 * 1024),
        (
            &generation,
            "genesis.signed.nrt",
            iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
        ),
        (&runtime, "onboarding-signer.key", 4096),
        (&authorities, "authorities.json", 512 * 1024),
    ] {
        let original = directory.read(name, maximum).unwrap();
        let inventory = ServiceChildInventory::begin(&parent).unwrap();
        let mut changed = original.to_vec();
        changed.push(0);
        directory
            .write_atomic(name, &changed, PublishMode::Replace)
            .unwrap();
        let (refused, parses) =
            crate::localnet::service_authorities::count_profile_validations(|| {
                inventory.open_provider(provider, ProviderPurpose::Custody)
            });
        assert!(refused.is_err());
        assert_eq!(
            parses, 0,
            "fresh byte admission must refuse without semantic reuse"
        );
        assert!(inventory.finish().is_err());
        directory
            .write_atomic(name, &original, PublishMode::Replace)
            .unwrap();
        let inventory = ServiceChildInventory::begin(&parent).unwrap();
        let child = inventory
            .open_provider(provider, ProviderPurpose::Custody)
            .unwrap()
            .unwrap();
        assert_eq!(child.directory.identity().unwrap(), child_identity);
        assert_eq!(
            iroha_fs::FileIdentity::of(&child._lock).unwrap(),
            lock_identity
        );
        child.validate_profile().unwrap();
        drop(child);
        inventory.finish().unwrap();
        assert_eq!(directory.read(name, maximum).unwrap(), original);
    }
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let saved = temporary.path().join("saved-generation");
    #[cfg(unix)]
    {
        std::fs::rename(generation.path(), &saved).unwrap();
        let replacement = PrivateDirectory::open_or_create(generation.path()).unwrap();
        assert!(
            inventory
                .open_provider(provider, ProviderPurpose::Custody)
                .is_err()
        );
        assert!(inventory.finish().is_err());
        std::fs::remove_dir(replacement.path()).unwrap();
        std::fs::rename(&saved, generation.path()).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(generation.path(), &saved).is_err());
        let child = inventory
            .open_provider(provider, ProviderPurpose::Custody)
            .unwrap()
            .unwrap();
        assert_eq!(child.directory.identity().unwrap(), child_identity);
        drop(child);
        inventory.finish().unwrap();
    }
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let child = inventory
        .open_provider(provider, ProviderPurpose::Custody)
        .unwrap()
        .unwrap();
    assert_eq!(child.directory.identity().unwrap(), child_identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&child._lock).unwrap(),
        lock_identity
    );
    drop(child);
    inventory.finish().unwrap();
}

#[test]
fn present_census_preserves_full_active_decode_and_owned_parent_fallback() {
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    use norito::core::DecodeBudgetContext;
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    drop(
        ServiceAuthority::open_provider(&parent.prepared, provider, ProviderPurpose::Custody)
            .unwrap(),
    );
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, parses) =
        crate::localnet::service_authorities::count_profile_validations(|| {
            baseline.with(|| {
                ServiceAuthority::open_provider_existing(
                    &parent.prepared,
                    provider,
                    ProviderPurpose::Custody,
                )
            })
        });
    let expected = expected.unwrap().unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&expected.profile, AuthorityProfile::Owned(_)));
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    drop(expected);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        exact.with(|| {
            ServiceAuthority::open_existing_from_original(
                &parent,
                Some(provider),
                ProviderPurpose::Custody.directory_name(),
                None,
            )
        })
    });
    let child = child.unwrap().unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&child.profile, AuthorityProfile::Owned(_)));
    assert_eq!(exact.consumed_allocated_bytes(), charge as u64);
    drop(child);
    for allocated in [0, charge - 1] {
        let ordinary = DecodeBudgetContext::new(limits(allocated));
        let expected = ordinary
            .with(|| {
                ServiceAuthority::open_provider_existing(
                    &parent.prepared,
                    provider,
                    ProviderPurpose::Custody,
                )
            })
            .err()
            .unwrap();
        let borrowed = DecodeBudgetContext::new(limits(allocated));
        let refused = borrowed
            .with(|| {
                ServiceAuthority::open_existing_from_original(
                    &parent,
                    Some(provider),
                    ProviderPurpose::Custody.directory_name(),
                    None,
                )
            })
            .err()
            .unwrap();
        assert_eq!(refused.to_string(), expected.to_string());
        assert_eq!(
            borrowed.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
    }
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let retry = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        retry.with(|| inventory.open_provider(provider, ProviderPurpose::Custody))
    });
    let child = child.unwrap().unwrap();
    assert_eq!(parses, 1);
    assert!(matches!(&child.profile, AuthorityProfile::Owned(_)));
    assert!(child.checkpoint_import_scope().is_none());
    child.validate_profile().unwrap();
    drop(child);
    inventory.finish().unwrap();
    let entry = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let inventory = entry
        .with(|| ServiceChildInventory::begin(&parent))
        .unwrap();
    assert!(inventory.checkpoint_import_scope.is_none());
    inventory.finish().unwrap();
    let prepared = parent.prepared.clone();
    drop(parent);
    let caller = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let parent = caller
        .with(|| {
            ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::ServiceBootstrap)
        })
        .unwrap()
        .unwrap();
    assert!(matches!(&parent.profile, AuthorityProfile::Owned(_)));
    assert!(!norito::core::decode_limits_active());
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(inventory.checkpoint_import_scope.is_none());
    let (child, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
        inventory.open_provider(provider, ProviderPurpose::Custody)
    });
    let child = child.unwrap().unwrap();
    assert_eq!(
        parses, 1,
        "an Owned parent outside its old scope still needs a full fresh capture"
    );
    assert!(matches!(&child.profile, AuthorityProfile::Shared(_)));
    assert!(child.checkpoint_import_scope().is_none());
    child.validate_profile().unwrap();
    drop(child);
    inventory.finish().unwrap();
}

#[test]
fn census_import_scope_reuses_only_immutable_imports_and_ends_cold() {
    use crate::managed::native_operation::{
        checkpoint_bytes, decode_checkpoint,
        test_support::native_fixture::{NativeFixture, quote_instructions},
    };
    use iroha_data_model::isi::{InstructionBox, Log};
    use norito::core::DecodeBudgetContext;

    fn limits(allocation: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocation, 64)
    }

    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let provider = parent.manifest.providers[0].provider_id;
    let mut native = NativeFixture::from_generated(&parent.prepared, &parent);
    let signed = quote_instructions(
        &native,
        &parent.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "census immutable checkpoint".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed]), vec![true]);
    let original = native.observe(&parent);
    let bytes = checkpoint_bytes(&original).unwrap();
    for purpose in [
        ProviderPurpose::Custody,
        ProviderPurpose::ReserveAccountRegistration,
    ] {
        let child = ServiceAuthority::open_provider(&parent.prepared, provider, purpose).unwrap();
        child
            .directory
            .write_atomic("current-checkpoint.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
    }

    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    assert!(inventory.checkpoint_import_scope.is_some());
    let _imports = ServiceAuthority::test_begin_graph_import_counts();
    let mut escaped = None;
    let mut custody_identity = None;
    // Both Custody stages still construct and authenticate independent live owners in order.
    for purpose in [
        ProviderPurpose::Custody,
        ProviderPurpose::Custody,
        ProviderPurpose::ReserveAccountRegistration,
    ] {
        let is_custody = matches!(purpose, ProviderPurpose::Custody);
        let child = inventory.open_provider(provider, purpose).unwrap().unwrap();
        assert!(child.checkpoint_import_scope().is_some());
        if is_custody {
            let identity = (
                child.directory.identity().unwrap(),
                iroha_fs::FileIdentity::of(&child._lock).unwrap(),
            );
            if let Some(expected) = custody_identity {
                assert_eq!(identity, expected);
            }
            custody_identity = Some(identity);
        }
        let fresh = super::super::super::native_operation::read_optional(
            &child.directory,
            "current-checkpoint.nrt",
            super::super::super::native_operation::MAX_CHECKPOINT_BYTES,
        )
        .unwrap()
        .unwrap();
        assert_eq!(fresh, bytes);
        let imported = child.decode_checkpoint(&fresh).unwrap();
        assert_eq!(imported, original);
        assert_eq!(child.test_checkpoint_import_attempts(), 1);
        escaped = Some(imported);
        child.validate_profile().unwrap();
    }
    assert_eq!(ServiceAuthority::test_graph_import_snapshot(), Some(1));
    assert_eq!(parent.test_checkpoint_import_attempts(), 0);

    let child = inventory
        .open_provider(provider, ProviderPurpose::Custody)
        .unwrap()
        .unwrap();
    // A warmed import is not fresh source admission: missing/corrupt bytes remain independent.
    std::fs::remove_file(child.directory.path().join("current-checkpoint.nrt")).unwrap();
    assert!(
        super::super::super::native_operation::read_optional(
            &child.directory,
            "current-checkpoint.nrt",
            super::super::super::native_operation::MAX_CHECKPOINT_BYTES
        )
        .unwrap()
        .is_none()
    );
    child
        .directory
        .write_atomic("current-checkpoint.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    let mut changed = bytes.clone();
    changed.push(0);
    child
        .directory
        .write_atomic("current-checkpoint.nrt", &changed, PublishMode::Replace)
        .unwrap();
    let fresh = super::super::super::native_operation::read_optional(
        &child.directory,
        "current-checkpoint.nrt",
        super::super::super::native_operation::MAX_CHECKPOINT_BYTES,
    )
    .unwrap()
    .unwrap();
    assert!(child.decode_checkpoint(&fresh).is_err());
    child
        .directory
        .write_atomic("current-checkpoint.nrt", &bytes, PublishMode::Replace)
        .unwrap();
    let fresh = super::super::super::native_operation::read_optional(
        &child.directory,
        "current-checkpoint.nrt",
        super::super::super::native_operation::MAX_CHECKPOINT_BYTES,
    )
    .unwrap()
    .unwrap();
    assert_eq!(child.decode_checkpoint(&fresh).unwrap(), original);
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    baseline
        .with(|| decode_checkpoint(&bytes, child.config.network_id, child.config.chain.as_str()))
        .unwrap();
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 1);
    for cap in [0, 1, charge] {
        child.decode_checkpoint(&bytes).unwrap();
        let ordinary = DecodeBudgetContext::new(limits(cap));
        let expected = ordinary.with(|| {
            decode_checkpoint(&bytes, child.config.network_id, child.config.chain.as_str())
        });
        let before = child.test_checkpoint_import_attempts();
        let active = DecodeBudgetContext::new(limits(cap));
        let actual = active.with(|| child.decode_checkpoint(&bytes));
        assert_eq!(
            active.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
            (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
            other => panic!("active import must keep the canonical result: {other:?}"),
        }
        assert_eq!(child.test_checkpoint_import_attempts(), before + 1);
        child.decode_checkpoint(&bytes).unwrap();
        assert_eq!(
            child.test_checkpoint_import_attempts(),
            before + 2,
            "active admission clears the selected census memo and never stores its result"
        );
    }
    drop(child);
    inventory.finish().unwrap();
    let inventory = ServiceChildInventory::begin(&parent).unwrap();
    let child = inventory
        .open_provider(provider, ProviderPurpose::Custody)
        .unwrap()
        .unwrap();
    assert_eq!(child.test_checkpoint_import_attempts(), 0);
    let cold = child.decode_checkpoint(&bytes).unwrap();
    assert_eq!(cold, original);
    assert_eq!(child.test_checkpoint_import_attempts(), 1);
    assert!(!std::ptr::eq(
        cold.checkpoint(),
        escaped.as_ref().unwrap().checkpoint()
    ));
    drop(child);
    inventory.finish().unwrap();
}

#[test]
fn catalog_scheduling_requires_all_original_purpose_names_absent() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    assert!(
        ServiceChildInventory::begin(&parent)
            .unwrap()
            .gateway_catalog_purposes_absent()
            .unwrap()
    );
    let operations = parent
        .profile
        .runtime()
        .open_child("service-operations")
        .unwrap();
    let providers = operations.ensure_child("providers").unwrap();
    for slot in 0..3 {
        let provider = providers.ensure_child(slot.to_string()).unwrap();
        let inventory = ServiceChildInventory::begin(&parent).unwrap();
        let purpose = provider
            .ensure_child(ProviderPurpose::GatewayCompliance.directory_name())
            .unwrap();
        assert!(
            inventory.gateway_catalog_purposes_absent().is_err(),
            "appeared name closes original census"
        );
        assert!(
            !ServiceChildInventory::begin(&parent)
                .unwrap()
                .gateway_catalog_purposes_absent()
                .unwrap(),
            "even empty purpose selects recovery"
        );
        assert!(purpose.entries(1).unwrap().is_empty());
        let path = purpose.path().to_path_buf();
        drop(purpose);
        std::fs::remove_dir(path).unwrap();
        assert!(
            ServiceChildInventory::begin(&parent)
                .unwrap()
                .gateway_catalog_purposes_absent()
                .unwrap()
        );
    }
}
