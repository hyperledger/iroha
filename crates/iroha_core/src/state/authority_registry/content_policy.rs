//! Deterministic content-bundle admission fields of the State-owned policy.
//!
//! `PublishContentBundle` reads these fields to accept an archive and form its
//! canonical record. Gateway quotas, response objectives and fetch PoW do not
//! change ledger execution. The account allow-list is a set for admission, so
//! its incidental configuration order and repeated identities are excluded.

use iroha_config::parameters::actual::Content;
use iroha_data_model::{account::AccountId, content::ContentAuthMode};
use norito::{Decode, Encode, NoritoSchema};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:content-stripe-layout:v1")]
struct ContentStripeLayoutV1 {
    total_stripes: u32,
    shards_per_stripe: u32,
    row_parity_stripes: u16,
}

/// Canonical first-release content policy borrowed from the active State config.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:content:v1")]
pub(super) struct ContentAdmissionPolicyV1 {
    max_bundle_bytes: u64,
    max_files: u32,
    max_path_len: u32,
    max_retention_blocks: u64,
    chunk_size_bytes: u32,
    publish_allow_accounts: Vec<AccountId>,
    default_cache_max_age_secs: u32,
    max_cache_max_age_secs: u32,
    immutable_bundles: bool,
    default_auth_mode: ContentAuthMode,
    stripe_layout: ContentStripeLayoutV1,
}

impl ContentAdmissionPolicyV1 {
    /// Project exactly the fields read by deterministic bundle admission.
    pub(super) fn from_actual(config: &Content) -> Self {
        let mut publish_allow_accounts = config.publish_allow_accounts.clone();
        publish_allow_accounts.sort_unstable();
        publish_allow_accounts.dedup();
        Self {
            max_bundle_bytes: config.max_bundle_bytes,
            max_files: config.max_files,
            max_path_len: config.max_path_len,
            max_retention_blocks: config.max_retention_blocks,
            chunk_size_bytes: config.chunk_size_bytes,
            publish_allow_accounts,
            default_cache_max_age_secs: config.default_cache_max_age_secs,
            max_cache_max_age_secs: config.max_cache_max_age_secs,
            immutable_bundles: config.immutable_bundles,
            default_auth_mode: config.default_auth_mode.clone(),
            stripe_layout: ContentStripeLayoutV1 {
                total_stripes: config.stripe_layout.total_stripes,
                shards_per_stripe: config.stripe_layout.shards_per_stripe,
                row_parity_stripes: config.stripe_layout.row_parity_stripes,
            },
        }
    }
}

/// Borrow the complete policy and fund the account set's canonical ordering.
pub(super) struct BorrowedContentPolicy<'a> {
    config: &'a Content,
    accounts: super::policy_borrowed::SortedRefs<'a, AccountId>,
}
impl<'a> BorrowedContentPolicy<'a> {
    pub(super) fn new(
        config: &'a Content,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, super::policy_borrowed::OrderError> {
        Ok(Self {
            config,
            accounts: super::policy_borrowed::SortedRefs::new_by(
                &config.publish_allow_accounts,
                budget,
                Ord::cmp,
            )?,
        })
    }
}
impl norito::SerializePayload for BorrowedContentPolicy<'_> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
        use super::policy_borrowed::{Ref, Seq, record};
        let config = self.config;
        record!(
            config.max_bundle_bytes,
            config.max_files,
            config.max_path_len,
            config.max_retention_blocks,
            config.chunk_size_bytes,
            Seq(self.accounts.unique()),
            config.default_cache_max_age_secs,
            config.max_cache_max_age_secs,
            config.immutable_bundles,
            Ref(&config.default_auth_mode),
            record!(
                config.stripe_layout.total_stripes,
                config.stripe_layout.shards_per_stripe,
                config.stripe_layout.row_parity_stripes
            )
        )
        .serialize(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::{ContentLimits, ContentPow, ContentSlo};
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::da::prelude::DaStripeLayout;
    use iroha_data_model::role::RoleId;
    use std::num::{NonZeroU32, NonZeroU64};

    fn account(seed: &[u8]) -> AccountId {
        AccountId::new(
            KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519)
                .public_key()
                .clone(),
        )
    }

    fn policy() -> Content {
        Content {
            max_bundle_bytes: 10_000,
            max_files: 8,
            max_path_len: 120,
            max_retention_blocks: 1_000,
            chunk_size_bytes: 512,
            publish_allow_accounts: vec![account(b"content-allow-a"), account(b"content-allow-b")],
            limits: ContentLimits {
                max_requests_per_second: NonZeroU32::new(10).unwrap(),
                request_burst: NonZeroU32::new(20).unwrap(),
                max_egress_bytes_per_second: NonZeroU64::new(100_000).unwrap(),
                egress_burst_bytes: NonZeroU64::new(200_000).unwrap(),
            },
            default_cache_max_age_secs: 60,
            max_cache_max_age_secs: 120,
            immutable_bundles: false,
            default_auth_mode: ContentAuthMode::Public,
            slo: ContentSlo {
                target_p50_latency_ms: NonZeroU32::new(10).unwrap(),
                target_p99_latency_ms: NonZeroU32::new(100).unwrap(),
                target_availability_bps: NonZeroU32::new(9_900).unwrap(),
            },
            pow: ContentPow {
                difficulty_bits: 0,
                header_name: "x-content-pow".to_owned(),
            },
            stripe_layout: DaStripeLayout {
                total_stripes: 4,
                shards_per_stripe: 16,
                row_parity_stripes: 1,
            },
        }
    }

    fn frame(policy: &Content) -> Vec<u8> {
        super::super::policy_borrowed::assert_same_payload(
            &BorrowedContentPolicy::new(policy, &iroha_allocation::AllocationBudget::new(1 << 20))
                .unwrap(),
            &ContentAdmissionPolicyV1::from_actual(policy),
        );
        norito::encode_canonical(&ContentAdmissionPolicyV1::from_actual(policy)).unwrap()
    }

    #[test]
    fn content_admission_policy_has_explicit_v1_roundtrip_and_ambient_invariance() {
        let projected = ContentAdmissionPolicyV1::from_actual(&policy());
        assert_eq!(
            ContentAdmissionPolicyV1::nominal_name(),
            "iroha:state:content:v1"
        );
        let encoded = norito::encode_canonical(&projected).unwrap();
        assert_eq!(
            norito::decode_canonical::<ContentAdmissionPolicyV1>(&encoded).unwrap(),
            projected
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projected).unwrap(), encoded);
    }

    #[test]
    fn every_content_admission_input_changes_the_projection() {
        let baseline = policy();
        let expected = frame(&baseline);
        let mut changed = baseline.clone();
        changed.max_bundle_bytes += 1;
        assert_ne!(frame(&changed), expected, "max bundle bytes");
        let mut changed = baseline.clone();
        changed.max_files += 1;
        assert_ne!(frame(&changed), expected, "max files");
        let mut changed = baseline.clone();
        changed.max_path_len += 1;
        assert_ne!(frame(&changed), expected, "max path length");
        let mut changed = baseline.clone();
        changed.max_retention_blocks += 1;
        assert_ne!(frame(&changed), expected, "retention window");
        let mut changed = baseline.clone();
        changed.chunk_size_bytes += 1;
        assert_ne!(frame(&changed), expected, "chunk size");
        let mut changed = baseline.clone();
        changed
            .publish_allow_accounts
            .push(account(b"content-allow-c"));
        assert_ne!(frame(&changed), expected, "publisher allow-list");
        let mut changed = baseline.clone();
        changed.default_cache_max_age_secs += 1;
        assert_ne!(frame(&changed), expected, "default cache age");
        let mut changed = baseline.clone();
        changed.max_cache_max_age_secs += 1;
        assert_ne!(frame(&changed), expected, "max cache age");
        let mut changed = baseline.clone();
        changed.immutable_bundles = true;
        assert_ne!(frame(&changed), expected, "immutable default");
        let mut changed = baseline.clone();
        changed.default_auth_mode =
            ContentAuthMode::RoleGate(RoleId::new("reader".parse().unwrap()));
        assert_ne!(frame(&changed), expected, "read authorization default");
        let mut changed = baseline.clone();
        changed.stripe_layout.total_stripes += 1;
        assert_ne!(frame(&changed), expected, "DA stripe count");
        let mut changed = baseline.clone();
        changed.stripe_layout.shards_per_stripe += 1;
        assert_ne!(frame(&changed), expected, "DA shard count");
        let mut changed = baseline;
        changed.stripe_layout.row_parity_stripes += 1;
        assert_ne!(frame(&changed), expected, "DA row parity count");
    }

    #[test]
    fn content_allow_list_is_a_set_and_gateway_controls_are_local() {
        let baseline = policy();
        let expected = frame(&baseline);
        let mut changed = baseline.clone();
        changed.publish_allow_accounts.reverse();
        changed
            .publish_allow_accounts
            .push(changed.publish_allow_accounts[0].clone());
        assert_eq!(frame(&changed), expected);

        let mut local = baseline;
        local.limits.max_requests_per_second = NonZeroU32::new(11).unwrap();
        local.limits.request_burst = NonZeroU32::new(21).unwrap();
        local.limits.max_egress_bytes_per_second = NonZeroU64::new(100_001).unwrap();
        local.limits.egress_burst_bytes = NonZeroU64::new(200_001).unwrap();
        local.slo.target_p50_latency_ms = NonZeroU32::new(11).unwrap();
        local.slo.target_p99_latency_ms = NonZeroU32::new(101).unwrap();
        local.slo.target_availability_bps = NonZeroU32::new(9_901).unwrap();
        local.pow.difficulty_bits = 1;
        local.pow.header_name = "x-other-pow".to_owned();
        assert_eq!(frame(&local), expected);
    }
}
