//! Closed generated issuer signing retains the original manager, peers and whole profile.

use super::*;
use iroha_fs::PublishMode;
use std::time::Duration;

fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "service-operator",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority = ServiceAuthority::open_provider(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        ProviderPurpose::Custody,
    )
    .unwrap();
    (temporary, authority)
}

fn credentials(authority: &ServiceAuthority) -> PrivateDirectory {
    PrivateDirectory::open_exact(
        authority
            .prepared
            .context
            .client_config
            .parent()
            .unwrap()
            .join("runtime")
            .join("stream-token-authorities")
            .join("providers")
            .join(
                authority
                    .provider_inventory(authority.provider_id().unwrap())
                    .unwrap()
                    .slot
                    .to_string(),
            ),
    )
    .unwrap()
}

fn peer_identities(authority: &ServiceAuthority) -> Vec<(PeerId, AccountId, NetworkId, String)> {
    authority
        .peers
        .iter()
        .map(|(peer, client)| {
            let account = client.account_client().unwrap();
            (
                peer.clone(),
                account.authority().clone(),
                *account.network_id(),
                account.endpoint().to_string(),
            )
        })
        .collect()
}

fn assert_only_signer_may_differ(original: &Config, selected: &Config) {
    // Exhaustive destructuring intentionally fails compilation if Config gains another field.
    let Config {
        chain,
        network_id,
        account: _,
        account_chain_discriminant,
        key_pair: _,
        basic_auth,
        api_token,
        torii_api_url,
        torii_request_timeout,
        transaction_ttl,
        transaction_status_timeout,
        transaction_add_nonce,
        sorafs_alias_cache,
        sorafs_anonymity_policy,
        sorafs_rollout_phase,
    } = selected;
    assert_eq!(*chain, original.chain);
    assert_eq!(*network_id, original.network_id);
    assert_eq!(
        *account_chain_discriminant,
        original.account_chain_discriminant
    );
    assert_eq!(*torii_api_url, original.torii_api_url);
    assert_eq!(*torii_request_timeout, original.torii_request_timeout);
    assert_eq!(*transaction_ttl, original.transaction_ttl);
    assert_eq!(
        *transaction_status_timeout,
        original.transaction_status_timeout
    );
    assert_eq!(*transaction_add_nonce, original.transaction_add_nonce);
    assert_eq!(*sorafs_anonymity_policy, original.sorafs_anonymity_policy);
    assert_eq!(*sorafs_rollout_phase, original.sorafs_rollout_phase);
    // Never use assertion formatting on secret values.
    match (basic_auth.as_ref(), original.basic_auth.as_ref()) {
        (Some(selected), Some(original)) => {
            assert!(selected.web_login.as_str() == original.web_login.as_str());
            assert!(selected.password.expose_secret() == original.password.expose_secret());
        }
        (None, None) => {}
        _ => panic!("HTTP authentication selection changed"),
    }
    assert!(
        api_token
            .as_ref()
            .map(iroha::secrecy::SecretString::expose_secret)
            == original
                .api_token
                .as_ref()
                .map(iroha::secrecy::SecretString::expose_secret)
    );
    let cache = &original.sorafs_alias_cache;
    assert_eq!(sorafs_alias_cache.positive_ttl(), cache.positive_ttl());
    assert_eq!(sorafs_alias_cache.refresh_window(), cache.refresh_window());
    assert_eq!(sorafs_alias_cache.hard_expiry(), cache.hard_expiry());
    assert_eq!(sorafs_alias_cache.negative_ttl(), cache.negative_ttl());
    assert_eq!(sorafs_alias_cache.revocation_ttl(), cache.revocation_ttl());
    assert_eq!(
        sorafs_alias_cache.rotation_max_age(),
        cache.rotation_max_age()
    );
    assert_eq!(
        sorafs_alias_cache.successor_grace(),
        cache.successor_grace()
    );
    assert_eq!(
        sorafs_alias_cache.governance_grace(),
        cache.governance_grace()
    );
}

fn assert_profile_refusal(authority: &ServiceAuthority) {
    match authority.issuer_operator_config().unwrap_err() {
        super::super::Error::Invalid(message) => {
            assert_eq!(message, "invalid original issuer-operator profile")
        }
        _ => panic!("issuer selection must redact the original profile error"),
    }
}

#[test]
fn issuer_operator_config_changes_only_signer_and_preserves_manager_peers() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, mut authority) = fixture();
    // Exercise the clone's non-default local client options without changing native identity.
    authority.config.basic_auth = Some(iroha::config::BasicAuth {
        web_login: "fixture-login".parse().unwrap(),
        password: iroha::secrecy::SecretString::new("fixture-password".into()),
    });
    authority.config.api_token = Some(iroha::secrecy::SecretString::new("fixture-token".into()));
    authority.config.torii_request_timeout = Duration::from_secs(23);
    authority.config.transaction_ttl = Duration::from_secs(71);
    authority.config.transaction_status_timeout = Duration::from_secs(19);
    authority.config.transaction_add_nonce = !authority.config.transaction_add_nonce;
    authority.config.sorafs_alias_cache = sorafs_manifest::alias_cache::AliasCachePolicy::new(
        Duration::from_secs(31),
        Duration::from_secs(7),
        Duration::from_secs(61),
        Duration::from_secs(5),
        Duration::from_secs(13),
        Duration::from_secs(37),
        Duration::from_secs(11),
        Duration::from_secs(17),
    );
    let original = authority.config.clone();
    let peers = peer_identities(&authority);
    let files = credentials(&authority);
    let retained = files
        .read(
            StreamTokenAuthorityRole::IssuerOperator.credential_filename(),
            256,
        )
        .unwrap();
    let config = authority.issuer_operator_config().unwrap();
    assert_only_signer_may_differ(&original, &config);
    assert_eq!(
        &config.account,
        authority
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .unwrap()
    );
    assert_eq!(
        config.account.try_signatory(),
        Some(config.key_pair.public_key())
    );
    assert_ne!(config.account, original.account);
    assert!(config.key_pair != original.key_pair);
    assert_only_signer_may_differ(&original, &authority.config);
    assert_eq!(authority.config.account, original.account);
    assert!(authority.config.key_pair == original.key_pair);
    assert_eq!(peer_identities(&authority), peers);
    assert!(
        retained.as_slice()
            == files
                .read(
                    StreamTokenAuthorityRole::IssuerOperator.credential_filename(),
                    256
                )
                .unwrap()
                .as_slice()
    );
    assert_eq!(
        authority.directory.entries(2).unwrap(),
        [std::ffi::OsString::from("operation.lock")]
    );
    let attester = crate::localnet::service_authorities::custody_attester_key(
        &authority.prepared,
        &authority.manifest,
        authority.provider_id().unwrap(),
    )
    .unwrap();
    assert_eq!(
        Some(attester.public_key()),
        authority
            .provider_role(StreamTokenAuthorityRole::CustodyAttester)
            .unwrap()
            .try_signatory()
    );
    assert_ne!(attester.public_key(), config.key_pair.public_key());
}

#[test]
fn issuer_operator_revalidates_every_role_before_returning_any_config() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, authority) = fixture();
    let files = credentials(&authority);
    let peers = peer_identities(&authority);
    let manager = authority.config.clone();
    let operator = StreamTokenAuthorityRole::IssuerOperator.credential_filename();
    let observer = StreamTokenAuthorityRole::IssuerObserver.credential_filename();
    let attester = StreamTokenAuthorityRole::CustodyAttester.credential_filename();
    let original_operator = files.read(operator, 256).unwrap();
    let original_observer = files.read(observer, 256).unwrap();
    let original_attester = files.read(attester, 256).unwrap();
    // A well-formed credential for a different genuine role cannot replace the selected signer.
    files
        .write_atomic(operator, &original_observer, PublishMode::Replace)
        .unwrap();
    assert_profile_refusal(&authority);
    files
        .write_atomic(operator, &original_operator, PublishMode::Replace)
        .unwrap();
    // Corrupt an unrelated role: reading only the operator would miss this profile substitution.
    files
        .write_atomic(
            observer,
            b"secret-unrelated-role-substitution\n",
            PublishMode::Replace,
        )
        .unwrap();
    assert_profile_refusal(&authority);
    files
        .write_atomic(observer, &original_observer, PublishMode::Replace)
        .unwrap();
    // Both selected purposes share exact LF/canonical multihash admission.
    files
        .write_atomic(
            attester,
            &original_attester[..original_attester.len() - 1],
            PublishMode::Replace,
        )
        .unwrap();
    assert_profile_refusal(&authority);
    assert!(
        crate::localnet::service_authorities::custody_attester_key(
            &authority.prepared,
            &authority.manifest,
            authority.provider_id().unwrap(),
        )
        .is_err()
    );
    files
        .write_atomic(attester, &original_attester, PublishMode::Replace)
        .unwrap();
    authority.issuer_operator_config().unwrap();
    assert_only_signer_may_differ(&manager, &authority.config);
    assert_eq!(authority.config.account, manager.account);
    assert!(authority.config.key_pair == manager.key_pair);
    assert_eq!(peer_identities(&authority), peers);
}

#[test]
fn issuer_operator_refuses_replaced_operation_lock_before_credential_use() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, authority) = fixture();
    let manager = authority.config.clone();
    let peers = peer_identities(&authority);
    // Native private publication replaces the lock's inode while the original remains held.
    authority
        .directory
        .write_atomic("operation.lock", b"", PublishMode::Replace)
        .unwrap();
    assert_profile_refusal(&authority);
    assert_eq!(authority.config.account, manager.account);
    assert!(authority.config.key_pair == manager.key_pair);
    assert_eq!(peer_identities(&authority), peers);
}

#[test]
fn exact_network_and_provider_scopes_have_independent_locks_and_distinct_reserve_signer() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, first) = fixture();
    let prepared = first.prepared.clone();
    let ids = first
        .manifest
        .providers
        .each_ref()
        .map(|provider| provider.provider_id);
    let network =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).unwrap();
    let second =
        ServiceAuthority::open_provider(&prepared, ids[1], ProviderPurpose::Custody).unwrap();
    let third =
        ServiceAuthority::open_provider(&prepared, ids[2], ProviderPurpose::Custody).unwrap();
    assert!(
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).is_err()
    );
    assert!(network.provider_id().is_err());
    assert!(
        network
            .provider_role(StreamTokenAuthorityRole::IssuerOperator)
            .is_err()
    );
    assert!(network.issuer_operator_config().is_err());
    let operator = network.reserve_operations_config().unwrap();
    assert_only_signer_may_differ(&network.config, &operator);
    assert_ne!(operator.account, network.config.account);
    for (index, owner) in [&first, &second, &third].into_iter().enumerate() {
        assert_eq!(owner.provider_id().unwrap(), ids[index]);
        assert_eq!(owner.provider_plan().unwrap().provider_id(), ids[index]);
        assert!(
            ServiceAuthority::open_provider(&prepared, ids[index], ProviderPurpose::Custody)
                .is_err()
        );
        assert!(owner.provider_inventory(ids[(index + 1) % 3]).is_err());
        assert_eq!(
            network.provider_inventory(ids[index]).unwrap().provider_id,
            ids[index]
        );
        let issuer = owner.issuer_operator_config().unwrap();
        let reserve = owner.reserve_operations_config().unwrap();
        assert_ne!(issuer.account, reserve.account);
        assert_eq!(reserve.account, operator.account);
        assert_eq!(
            reserve.key_pair.public_key(),
            operator.key_pair.public_key()
        );
        assert_only_signer_may_differ(&owner.config, &reserve);
        assert_eq!(owner.config.account, network.config.account);
        assert_ne!(owner.directory.path(), network.directory.path());
    }
    assert_ne!(first.directory.path(), second.directory.path());
    assert_ne!(second.directory.path(), third.directory.path());
}

#[test]
fn unknown_provider_is_rejected_before_operation_directory_creation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, owner) = fixture();
    let root = PrivateDirectory::open_exact(owner.prepared.context.client_config.parent().unwrap())
        .unwrap();
    let providers = root
        .open_child("runtime")
        .unwrap()
        .open_child("service-operations")
        .unwrap()
        .open_child("providers")
        .unwrap();
    let before = providers.entries(8).unwrap();
    let unknown = ProviderId::new([0xA7; 32]);
    assert!(owner.manifest.provider(unknown).is_err());
    assert!(
        ServiceAuthority::open_provider(&owner.prepared, unknown, ProviderPurpose::Custody)
            .is_err()
    );
    assert_eq!(providers.entries(8).unwrap(), before);
}

#[test]
fn existing_authorities_do_not_create_scopes_locks_or_repair_dirty_missing_locks() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, first) = fixture();
    let prepared = first.prepared.clone();
    let ids = first
        .manifest
        .providers
        .each_ref()
        .map(|provider| provider.provider_id);
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let operations = generation
        .open_child("runtime")
        .unwrap()
        .open_child("service-operations")
        .unwrap();
    let providers = operations.open_child("providers").unwrap();
    let before = providers.entries(8).unwrap();
    assert!(
        ServiceAuthority::open_provider_existing(&prepared, ids[1], ProviderPurpose::Custody)
            .unwrap()
            .is_none()
    );
    assert_eq!(providers.entries(8).unwrap(), before);
    assert!(
        ServiceAuthority::open_network_existing(&prepared, NetworkPurpose::InitialReservePolicy)
            .unwrap()
            .is_none()
    );
    assert!(
        !operations
            .path()
            .join("network/initial-reserve-policy")
            .exists()
    );
    assert!(
        ServiceAuthority::open_provider_existing(&prepared, ids[0], ProviderPurpose::Custody)
            .is_err()
    );
    let path = first.directory.path().to_owned();
    drop(first);
    let reopened =
        ServiceAuthority::open_provider_existing(&prepared, ids[0], ProviderPurpose::Custody)
            .unwrap()
            .unwrap();
    assert_eq!(reopened.directory.path(), path);
    assert_eq!(
        reopened.directory.entries(2).unwrap(),
        [std::ffi::OsString::from("operation.lock")]
    );
    drop(reopened);
    std::fs::remove_file(path.join("operation.lock")).unwrap();
    assert!(
        ServiceAuthority::open_provider_existing(&prepared, ids[0], ProviderPurpose::Custody)
            .unwrap()
            .is_none()
    );
    assert!(!path.join("operation.lock").exists());
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    directory
        .write_atomic("unknown.nrt", b"dirty", PublishMode::CreateNew)
        .unwrap();
    assert!(
        ServiceAuthority::open_provider_existing(&prepared, ids[0], ProviderPurpose::Custody)
            .is_err()
    );
    assert!(!path.join("operation.lock").exists());
    assert_eq!(
        directory.read("unknown.nrt", 5).unwrap().as_slice(),
        b"dirty"
    );
}
