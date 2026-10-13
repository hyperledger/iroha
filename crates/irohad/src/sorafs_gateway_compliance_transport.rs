//! Config-selected assembly of the existing bounded, pinned compliance HTTPS transport.
//!
//! This module supplies bytes transport only. The gateway controller retains governed catalog
//! signatures, acknowledgement quorum, freshness, promotion and durable checkpoint authority.
use iroha_config::parameters::actual::{
    SorafsGatewayComplianceFeed, SorafsGatewayRuntimeProviderBinding,
};
use iroha_config::parameters::defaults::sorafs::gateway::compliance::{
    GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1, GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
};
use iroha_torii::sorafs::gateway::{
    GatewayComplianceFeedTransport, ProductionGatewayComplianceFeedTransport,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Select the exact built-in transport or require the independently configured external provider.
/// Native construction performs no DNS or feed reads and invents no catalog authority.
pub fn resolve(
    binding: &SorafsGatewayRuntimeProviderBinding,
    feeds: &[SorafsGatewayComplianceFeed],
    injected: Option<Arc<dyn GatewayComplianceFeedTransport>>,
) -> Result<Arc<dyn GatewayComplianceFeedTransport>, &'static str> {
    if binding.provider_handle != GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1 {
        return injected.ok_or("configured external compliance feed transport is absent");
    }
    if injected.is_some() {
        return Err("built-in compliance transport conflicts with an injected provider");
    }
    if binding.revision != GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1 {
        return Err("built-in compliance transport revision does not match configuration");
    }
    let mut pins = BTreeMap::<String, BTreeSet<[u8; 32]>>::new();
    for host in feeds.iter().flat_map(|feed| &feed.hosts) {
        let accepted = host
            .accepted_spki_sha256
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if accepted.len() != host.accepted_spki_sha256.len()
            || pins
                .insert(host.hostname.clone(), accepted.clone())
                .is_some_and(|previous| previous != accepted)
        {
            return Err("compliance hostname has a noncanonical or conflicting trust inventory");
        }
    }
    let transport = ProductionGatewayComplianceFeedTransport::try_new(pins)
        .map_err(|_| "configured compliance HTTPS transport could not be constructed")?;
    let first = transport
        .qualification()
        .map_err(|_| "compliance transport qualification unavailable")?;
    let second = transport
        .qualification()
        .map_err(|_| "compliance transport qualification unavailable")?;
    if first != second
        || first.test_marked
        || first.provider_handle != binding.provider_handle
        || first.revision != binding.revision
        || first.policy_digest != binding.policy_digest
    {
        return Err("compliance transport does not match its configured public binding");
    }
    Ok(Arc::new(transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::SorafsGatewayComplianceFeedHost;
    use sorafs_manifest::gateway_compliance::gateway_compliance_feed_transport_policy_digest;
    fn fixture() -> (
        SorafsGatewayRuntimeProviderBinding,
        Vec<SorafsGatewayComplianceFeed>,
    ) {
        let pins = BTreeMap::from([("feed.example".to_owned(), BTreeSet::from([[7; 32]]))]);
        let binding = SorafsGatewayRuntimeProviderBinding {
            provider_handle: GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.into(),
            revision: GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            policy_digest: gateway_compliance_feed_transport_policy_digest(&pins).unwrap(),
        };
        let feeds = vec![SorafsGatewayComplianceFeed {
            feed_id: "regional".into(),
            url: "https://feed.example/catalog".into(),
            required: false,
            hosts: vec![SorafsGatewayComplianceFeedHost {
                hostname: "feed.example".into(),
                accepted_spki_sha256: vec![[7; 32]],
            }],
        }];
        (binding, feeds)
    }
    #[test]
    fn exact_native_binding_constructs_without_network_io_or_catalog_authority() {
        let (binding, feeds) = fixture();
        let transport = resolve(&binding, &feeds, None).unwrap();
        let identity = transport.qualification().unwrap();
        assert_eq!(identity.provider_handle, binding.provider_handle);
        assert_eq!(identity.revision, binding.revision);
        assert_eq!(identity.policy_digest, binding.policy_digest);
        assert!(!identity.test_marked);
    }
    #[test]
    fn native_selection_rejects_external_injection_and_configuration_mismatch() {
        let (mut binding, feeds) = fixture();
        let injected = resolve(&binding, &feeds, None).unwrap();
        assert!(resolve(&binding, &feeds, Some(injected)).is_err());
        binding.revision += 1;
        assert!(resolve(&binding, &feeds, None).is_err());
        binding.revision -= 1;
        binding.policy_digest[0] ^= 1;
        assert!(resolve(&binding, &feeds, None).is_err());
    }
    #[test]
    fn native_selection_preserves_public_dns_and_exact_pin_policy() {
        let (binding, mut feeds) = fixture();
        // The original nonempty binding must not silently become an empty inventory.
        assert!(resolve(&binding, &[], None).is_err());
        feeds[0].hosts[0].hostname = "127.0.0.1".into();
        assert!(resolve(&binding, &feeds, None).is_err());
        feeds[0].hosts[0].hostname = "feed.example".into();
        feeds[0].hosts[0].accepted_spki_sha256.push([7; 32]);
        assert!(resolve(&binding, &feeds, None).is_err());
        feeds[0].hosts[0].accepted_spki_sha256.pop();
        let mut other = feeds[0].clone();
        other.feed_id = "second".into();
        other.hosts[0].accepted_spki_sha256 = vec![[8; 32]];
        feeds.push(other);
        assert!(resolve(&binding, &feeds, None).is_err());
    }
    #[test]
    fn external_selection_requires_explicit_provider_and_preserves_identity_for_controller() {
        let (mut binding, feeds) = fixture();
        let injected = resolve(&binding, &feeds, None).unwrap();
        binding.provider_handle = "provider://sorafs/compliance/custom".into();
        assert!(resolve(&binding, &feeds, None).is_err());
        let resolved = resolve(&binding, &feeds, Some(Arc::clone(&injected))).unwrap();
        assert!(Arc::ptr_eq(&resolved, &injected));
        // The unchanged controller independently rejects a provider whose actual identity does
        // not match this external binding. Assembly does not relabel an injected provider.
    }
    #[test]
    fn explicit_empty_native_inventory_qualifies_and_denies_every_external_host() {
        let pins = BTreeMap::new();
        let binding = SorafsGatewayRuntimeProviderBinding {
            provider_handle: GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.into(),
            revision: GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            policy_digest: gateway_compliance_feed_transport_policy_digest(&pins).unwrap(),
        };
        let transport = resolve(&binding, &[], None).unwrap();
        let identity = transport.qualification().unwrap();
        assert!(!identity.test_marked);
        assert_eq!(identity.policy_digest, binding.policy_digest);
        assert!(matches!(
            transport.resolve("not-configured.example", std::time::Duration::from_secs(1)),
            Err(iroha_torii::sorafs::gateway::GatewayComplianceError::TrustPinMismatch)
        ));
        let (_, feeds) = fixture();
        assert!(resolve(&binding, &feeds, None).is_err());
    }
}
