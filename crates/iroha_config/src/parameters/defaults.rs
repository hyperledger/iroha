//! Parameters default values
#![allow(
    clippy::doc_markdown,
    clippy::doc_link_with_quotes,
    clippy::assertions_on_constants
)]
use iroha_crypto::Algorithm;
use iroha_data_model::{
    account::{AccountId, curve::CurveId},
    asset::prelude::AssetDefinitionId,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use nonzero_ext::nonzero;
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
fn canonical_asset_definition_id(domain: &str, name: &str) -> AssetDefinitionId {
    let domain_id =
        DomainId::parse_fully_qualified(domain).expect("default asset definition domain");
    let asset_name = Name::from_str(name).expect("default asset definition name");
    AssetDefinitionId::derive_from_components(domain_id, asset_name)
}
fn canonical_asset_definition_literal(domain: &str, name: &str) -> String {
    canonical_asset_definition_id(domain, name).to_string()
}
/// Cryptography configuration defaults.
pub mod crypto {
    use super::*;
    /// Preview toggle for OpenSSL-backed SM helpers.
    pub const ENABLE_SM_OPENSSL_PREVIEW: bool = false;
    /// Default SM intrinsic dispatch policy.
    pub const SM_INTRINSICS_POLICY: &str = "auto";
    /// Default hash algorithm identifier used when none is supplied.
    pub const DEFAULT_HASH: &str = "blake2b-256";
    /// Default signing algorithms permitted on the network.
    pub const ALLOWED_SIGNING: &[Algorithm] = &[Algorithm::Ed25519, Algorithm::Secp256k1];
    /// Default distinguishing identifier for SM2 signatures.
    pub const SM2_DISTID_DEFAULT: &str = "1234567812345678";
    /// Default set of curve identifiers permitted for account controllers.
    pub const ALLOWED_CURVE_IDS: &[u8] = &[CurveId::ED25519.as_u8(), CurveId::SECP256K1.as_u8()];
    /// Default hash algorithm identifier used when none is supplied.
    pub fn default_hash() -> String {
        DEFAULT_HASH.to_string()
    }
    /// Whether optional OpenSSL SM3/SM4 helpers are enabled by default; SM2 is unaffected.
    pub fn enable_sm_openssl_preview() -> bool {
        ENABLE_SM_OPENSSL_PREVIEW
    }
    /// Default SM intrinsic dispatch policy.
    pub fn sm_intrinsics_policy() -> String {
        SM_INTRINSICS_POLICY.to_owned()
    }
    /// Default set of signing algorithms permitted on the network.
    pub fn allowed_signing() -> Vec<Algorithm> {
        ALLOWED_SIGNING.to_vec()
    }
    /// Default set of signing algorithms expressed as strings (for env overrides).
    pub fn allowed_signing_env() -> Vec<String> {
        ALLOWED_SIGNING.iter().map(Algorithm::to_string).collect()
    }
    /// Default distinguishing identifier for SM2 signatures.
    pub fn sm2_distid_default() -> String {
        SM2_DISTID_DEFAULT.to_string()
    }
    /// Derive the curve capability list from the supplied signing algorithms.
    pub fn derive_curve_ids_from_algorithms(algorithms: &[Algorithm]) -> Vec<u8> {
        let mut ids: Vec<u8> = algorithms
            .iter()
            .filter_map(|algo| CurveId::try_from_algorithm(*algo).ok())
            .map(CurveId::as_u8)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
    /// Default set of curve identifiers permitted on the network.
    pub fn allowed_curve_ids() -> Vec<u8> {
        derive_curve_ids_from_algorithms(ALLOWED_SIGNING)
    }
}
/// Common configuration defaults shared across components.
pub mod common {
    /// Default chain discriminant / I105 network prefix (Sora Nexus global).
    pub const CHAIN_DISCRIMINANT: u16 = 0x02F1;
    /// Chain discriminant applied when configuration omits an override.
    pub const fn chain_discriminant() -> u16 {
        CHAIN_DISCRIMINANT
    }
}
/// Public endpoint used by the stock runtime-provider broker.
pub mod runtime_provider_broker {
    use super::{NonZeroUsize, PathBuf};
    use std::time::Duration;

    /// Maximum and default admitted observer-operation duration, including dispatch and reply.
    pub const OBSERVER_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

    /// Finite aggregate public-transcript memory for one credential registry (64 MiB).
    pub const CREDENTIAL_MAX_MEMORY_BYTES: NonZeroUsize = nonzero_ext::nonzero!(67_108_864usize);

    /// Default Unix socket path for the local runtime-provider broker.
    #[cfg(target_os = "macos")]
    pub const ENDPOINT_PATH: &str = "/private/var/iroha/run/runtime-provider-broker-v1.sock";
    /// Default Unix socket path for the local runtime-provider broker.
    #[cfg(not(target_os = "macos"))]
    pub const ENDPOINT_PATH: &str =
        "/run/iroha-runtime-provider-broker-v1/runtime-provider-broker-v1.sock";

    /// Return the public default endpoint path.
    pub fn endpoint_path() -> PathBuf {
        PathBuf::from(ENDPOINT_PATH)
    }
}
/// Fixed layout under a node's `data_dir`.
///
/// When `data_dir` is set, every state path listed in [`data_dir::STATE_PATHS`] that the
/// configuration does not set explicitly defaults to `<data_dir>/state/<relative>`, and every
/// secret file defaults to `<data_dir>/secrets/<name>`. Explicit per-path values still win.
pub mod data_dir {
    /// Path of the loader-owned configuration source that carries the resolved absolute
    /// `data_dir` and the paths completed from it (`iroha_config::node_config`). The parser
    /// accepts `data_dir` only from this source, so a configuration that sets `data_dir` but was
    /// read without the loader is rejected instead of silently keeping default paths.
    pub const LAYOUT_SOURCE: &str = "<data_dir layout>";
    /// Subdirectory of `data_dir` holding every derived state path.
    pub const STATE_DIR: &str = "state";
    /// Subdirectory of `data_dir` holding owner-only secret files.
    pub const SECRETS_DIR: &str = "secrets";
    /// Derived state paths: configuration key and path relative to [`STATE_DIR`].
    ///
    /// TODO: the SoraFS provider sub-states (`sorafs.storage.pop_credentials.*`,
    /// moderation, reputation, reserve-transparency, hedging-billing and evidence-viewer
    /// checkpoints) and `torii.privacy_bootle_lantern_issuer.state_dir` still default to
    /// `./storage/...`; they are only used when the embedded SoraFS provider or the
    /// Bootle/Lantern issuer is enabled, which no compiled profile does.
    pub const STATE_PATHS: &[(&[&str], &str)] = &[
        (&["kura", "store_dir"], "kura"),
        (&["snapshot", "store_dir"], "snapshot"),
        (&["tiered_state", "cold_store_root"], "tiered_state"),
        (&["tiered_state", "da_store_root"], "da_wsv_snapshots"),
        (&["streaming", "session_store_dir"], "streaming"),
        (&["soracloud_runtime", "state_dir"], "soracloud_runtime"),
        (
            &[
                "network",
                "soranet_handshake",
                "pow",
                "revocation_store_path",
            ],
            "soranet/ticket_revocations.norito",
        ),
        (&["torii", "data_dir"], "torii"),
        (
            &["torii", "da_ingest", "replay_cache_store_dir"],
            "torii/da_replay",
        ),
        (
            &["torii", "da_ingest", "manifest_store_dir"],
            "torii/da_manifests",
        ),
        (&["sorafs", "storage", "data_dir"], "sorafs"),
        (&["sorafs", "por", "state_dir"], "sorafs/por"),
    ];
    /// Validator BLS private key (`private_key_file`).
    pub const VALIDATOR_KEY: &str = "validator.key";
    /// SoraNet transport Ed25519 private key (`soranet_transport_private_key_file`).
    pub const TRANSPORT_KEY: &str = "transport.key";
    /// Streaming identity Ed25519 private key (`streaming.identity_private_key_file`).
    pub const STREAMING_KEY: &str = "streaming.key";
    /// Soracloud runtime mutation-signer private key.
    pub const RUNTIME_SIGNER_KEY: &str = "runtime_signer.key";
    /// Global beacon partial-signer credential.
    pub const BEACON_CREDENTIAL: &str = "beacon.cred";
    /// Faucet authority private key (`torii.faucet.private_key_file`).
    pub const FAUCET_AUTHORITY_KEY: &str = "authority/faucet.key";
    /// Onboarding authority private key (`torii.account_onboarding.private_key_file`).
    pub const ONBOARDING_AUTHORITY_KEY: &str = "authority/onboarding.key";
    /// SoraFS council authority private key.
    pub const SORAFS_COUNCIL_AUTHORITY_KEY: &str = "authority/sorafs_council.key";
}
/// Node process lifecycle defaults.
pub mod lifecycle {
    /// The daemon keeps running when its standard input closes.
    pub const EXIT_ON_STDIN_CLOSE: bool = false;
}
/// Canonical first-release Taira deployment policy shared by generators and launchers.
pub mod taira {
    /// Canonical first-release Inrou canary guest CPU allocation.
    pub const INROU_CANARY_CPU_MILLIS: u32 = 750;
    /// Canonical first-release Inrou canary guest RAM.
    pub const INROU_CANARY_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
    /// Canary temporary filesystem; its sole durable state is separately bounded.
    pub const INROU_CANARY_EPHEMERAL_STORAGE_BYTES: u64 = 16 * 1024 * 1024;
    /// Exact normalized Debian ext4 size produced by the verified asset helper.
    pub const INROU_CANARY_ROOT_VOLUME_BYTES: u64 = 1536 * 1024 * 1024;
    /// Ext4 app-data volume for the at-most-1024-byte canonical state plus journal.
    pub const INROU_CANARY_SHARED_VOLUME_BYTES: u64 = 64 * 1024 * 1024;
    /// Exact per-replica root and temporary storage admission.
    pub const INROU_CANARY_HOST_STORAGE_BYTES: u64 =
        INROU_CANARY_ROOT_VOLUME_BYTES + INROU_CANARY_EPHEMERAL_STORAGE_BYTES;
    const _: () = assert!(
        iroha_data_model::soracloud::SORA_INROU_VMM_CPU_OVERHEAD_MILLIS_V1 <= u32::MAX as u64
    );
    /// Host CPU ceiling includes one canonical canary plus mandatory VMM overhead.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the source constant is compile-time bounded to u32 above"
    )]
    pub const INROU_MAX_CPU_MILLIS: u32 = INROU_CANARY_CPU_MILLIS
        + iroha_data_model::soracloud::SORA_INROU_VMM_CPU_OVERHEAD_MILLIS_V1 as u32;
    /// Host RAM ceiling includes one canonical canary plus mandatory VMM overhead.
    pub const INROU_MAX_MEMORY_BYTES: u64 = INROU_CANARY_MEMORY_BYTES
        + iroha_data_model::soracloud::SORA_INROU_VMM_MEMORY_OVERHEAD_BYTES_V1;
    /// Full writable allowance, including the declared app-data volume.
    pub const INROU_MAX_STORAGE_BYTES: u64 =
        INROU_CANARY_HOST_STORAGE_BYTES + INROU_CANARY_SHARED_VOLUME_BYTES;
    /// Normalized 1536 MiB rootfs plus pinned kernel/initrd fit within 1600 MiB.
    /// Exact prepared material is still checked by staging and runtime admission.
    pub const INROU_GUEST_IMAGE_MAX_BYTES: u64 = 1600 * 1024 * 1024;
    /// One bounded hydration worker per first-release validator.
    pub const HYDRATION_CONCURRENCY: usize = 1;
    /// One retained prepared runtime per first-release validator.
    pub const PREPARED_RUNTIME_CACHE_CAPACITY: usize = 1;
    /// Whole-validator CPU bound for the signed service unit, outside its Inrou worker.
    pub const VALIDATOR_CPU_MILLIS: u64 = 1000;
    /// Whole-validator RAM bound for the signed service unit, outside its Inrou worker.
    pub const VALIDATOR_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    /// Explicit guest-system CPU outside the four validators and their workers.
    pub const SYSTEM_CPU_RESERVE_MILLIS: u64 = 1000;
    /// Explicit guest-system memory outside the four validators and their workers.
    pub const SYSTEM_MEMORY_RESERVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    /// Encoded WSV budget inside the whole-validator memory bound.
    pub const NEXUS_MAX_WSV_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
    /// Denominator used by the Nexus storage weight fields.
    pub const STORAGE_WEIGHT_BASIS_POINTS: u16 = 10_000;
    /// Aggregate Nexus disk budget for one validator.
    pub const NEXUS_STORAGE_BUDGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    /// Kura share of the Nexus disk budget, in basis points.
    pub const NEXUS_KURA_BLOCKS_BPS: u16 = 2_500;
    /// WSV snapshot share of the Nexus disk budget, in basis points.
    pub const NEXUS_WSV_SNAPSHOTS_BPS: u16 = 1_250;
    /// SoraFS share of the Nexus disk budget, in basis points.
    pub const NEXUS_SORAFS_BPS: u16 = 6_250;
    /// Effective SoraFS component cap derived from the aggregate budget.
    pub const SORAFS_STORAGE_CAP_BYTES: u64 =
        NEXUS_STORAGE_BUDGET_BYTES * NEXUS_SORAFS_BPS as u64 / STORAGE_WEIGHT_BASIS_POINTS as u64;
    /// Inrou egress request budget per minute.
    pub const INROU_EGRESS_RATE_PER_MINUTE: u32 = 600;
    /// Inrou egress byte budget per minute.
    pub const INROU_EGRESS_MAX_BYTES_PER_MINUTE: u64 = 100 * 1024 * 1024;

    const _: () = assert!(
        NEXUS_KURA_BLOCKS_BPS + NEXUS_WSV_SNAPSHOTS_BPS + NEXUS_SORAFS_BPS
            == STORAGE_WEIGHT_BASIS_POINTS
    );
    // Preseed stores the admitted guest and bundle together. Keep at least 64 MiB
    // beyond both payload ceilings for discovery, manifests and storage metadata.
    const _: () = assert!(
        SORAFS_STORAGE_CAP_BYTES
            >= INROU_GUEST_IMAGE_MAX_BYTES
                + super::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT
                + 64 * 1024 * 1024
    );
    #[cfg(test)]
    mod compact_tests {
        use super::*;
        #[test]
        fn four_validators_and_required_workloads_fit_nine_cpus_and_sixteen_gib() {
            assert_eq!(
                4 * (VALIDATOR_CPU_MILLIS + u64::from(INROU_MAX_CPU_MILLIS))
                    + SYSTEM_CPU_RESERVE_MILLIS,
                9_000
            );
            let memory =
                4 * (VALIDATOR_MEMORY_BYTES + INROU_MAX_MEMORY_BYTES) + SYSTEM_MEMORY_RESERVE_BYTES;
            assert_eq!(memory, 13 * 1024 * 1024 * 1024);
            assert!(memory < 16 * 1024 * 1024 * 1024);
            assert!(NEXUS_MAX_WSV_MEMORY_BYTES < VALIDATOR_MEMORY_BYTES);
        }
        #[test]
        fn nexus_storage_contains_the_complete_admitted_preseed() {
            let mib = 1024 * 1024;
            assert_eq!(NEXUS_STORAGE_BUDGET_BYTES, 4096 * mib);
            for (weight, expected_mib) in [
                (NEXUS_KURA_BLOCKS_BPS, 1024),
                (NEXUS_WSV_SNAPSHOTS_BPS, 512),
                (NEXUS_SORAFS_BPS, 2560),
            ] {
                assert_eq!(
                    NEXUS_STORAGE_BUDGET_BYTES * u64::from(weight)
                        / u64::from(STORAGE_WEIGHT_BASIS_POINTS),
                    expected_mib * mib
                );
            }
            let payload_ceiling = INROU_GUEST_IMAGE_MAX_BYTES
                + super::super::soracloud_runtime::INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT;
            assert_eq!(SORAFS_STORAGE_CAP_BYTES - payload_ceiling, 448 * mib);
        }
        #[test]
        fn normalized_debian_geometry_and_complete_canary_storage_fit_the_profile() {
            let upstream_root = 3_085_959_168_u64;
            let root = 1536 * 1024 * 1024;
            let kernel = 27_236_288_u64;
            let initrd = 13_923_072_u64;
            assert!(upstream_root > INROU_CANARY_ROOT_VOLUME_BYTES);
            assert_eq!(root, INROU_CANARY_ROOT_VOLUME_BYTES);
            assert_eq!(INROU_GUEST_IMAGE_MAX_BYTES, 1600 * 1024 * 1024);
            assert!(root + kernel + initrd <= INROU_GUEST_IMAGE_MAX_BYTES);
            assert_eq!(
                INROU_MAX_STORAGE_BYTES,
                INROU_CANARY_ROOT_VOLUME_BYTES
                    + INROU_CANARY_EPHEMERAL_STORAGE_BYTES
                    + INROU_CANARY_SHARED_VOLUME_BYTES
            );
            assert_eq!(INROU_MAX_CPU_MILLIS, 1000);
            assert_eq!(INROU_MAX_MEMORY_BYTES, 768 * 1024 * 1024);
        }
    }
}
/// IVM- and banner-related defaults.
pub mod ivm {
    /// Startup banner settings.
    pub mod banner {
        /// Show startup banners by default.
        pub const SHOW: bool = true;
        /// Play the startup beep by default (when built with the `beep` feature).
        pub const BEEP: bool = true;
        /// Whether the banner is shown by default.
        pub const fn show() -> bool {
            SHOW
        }
        /// Whether the startup beep is enabled by default.
        pub const fn beep() -> bool {
            BEEP
        }
    }
}
/// Non-secret private Musubi publication custody defaults.
pub mod musubi_publication {
    /// Private root containing the independent journal, seed and clock owners.
    pub const CUSTODY_ROOT: &str = "./storage/musubi-publication";
    /// Loopback-only listener until an operator injects a qualified private TLS deployment.
    pub const PRIVATE_TLS_BIND: &str = "127.0.0.1:18495";
    /// Bound on concurrent private TLS requests and their admitted body reservations.
    pub const MAX_INFLIGHT_REQUESTS: u16 = 2;
    /// Lifetime operation capacity of the durable publication journal.
    pub const JOURNAL_MAX_OPERATIONS: u32 = 1_024;
    /// Unexpired authorization capacity of the durable publication journal.
    pub const JOURNAL_MAX_AUTHORIZATIONS: u32 = 4_096;
    /// Total durable response bytes, including in-flight terminal reservations.
    pub const JOURNAL_MAX_TOTAL_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
    /// Maximum complete canonical journal snapshot size.
    pub const JOURNAL_MAX_SNAPSHOT_BYTES: u64 = 40 * 1024 * 1024;
    /// Maximum number of exact CAR seed records retained in local custody.
    pub const MAX_SEED_RECORDS: u32 = 16;
    /// Maximum total bytes of exact CAR seed records retained in local custody.
    pub const MAX_SEED_BYTES: u64 = 256 * 1024 * 1024;
    /// Maximum publisher-clock lead accepted by publication authorization.
    pub const MAX_FUTURE_CLOCK_SKEW_MS: u64 = 2_000;
    /// Lifetime assigned to a broker-signed seed-ingress receipt.
    pub const RECEIPT_LIFETIME_MS: u64 = 60_000;
    /// Paid-pin storage tier used by the publication coordinator.
    pub const PIN_STORAGE_CLASS: &str = "hot";
    /// Paid-pin lifetime beyond submission, long enough for the SoraFS ingest deadline.
    pub const PIN_RETENTION_HORIZON_SECS: u64 = 30 * 24 * 60 * 60;
    /// Operator ceiling for one paid-pin retention request.
    pub const MAX_PIN_RETENTION_HORIZON_SECS: u64 = 365 * 24 * 60 * 60;
    /// Finite budget for each fresh native provider discovery during publication readback.
    pub const READBACK_REQUEST_TIMEOUT_MS: u64 = 30_000;
    /// Maximum independent native discovery budget, matching the account-read transport bound.
    pub const MAX_READBACK_REQUEST_TIMEOUT_MS: u64 = 120_000;
    /// Resolve the exact paid-pin transaction account from the qualified ingress broker.
    pub const PIN_TRANSACTION_AUTHORITY: &str = "ingress_broker";

    /// Parse the fixed default private TLS bind address.
    #[must_use]
    pub fn private_tls_bind() -> std::net::SocketAddr {
        PRIVATE_TLS_BIND
            .parse()
            .expect("literal private TLS bind address")
    }
}
/// Embedded Soracloud runtime-manager defaults.
pub mod soracloud_runtime {
    use super::*;
    /// Enable Soracloud production posture checks.
    pub const PRODUCTION_MODE: bool = false;
    /// Default root directory for Soracloud runtime-manager state.
    pub const STATE_DIR: &str = "./storage/soracloud_runtime";
    /// Default reconciliation cadence in milliseconds.
    pub const RECONCILE_INTERVAL_MS: u64 = 5_000;
    /// Default number of concurrent artifact hydration workers.
    ///
    /// This pool is independent of prepared IVM caching and Inrou guest concurrency.
    pub const HYDRATION_CONCURRENCY: NonZeroUsize = nonzero!(4_usize);
    /// Hard V1 ceiling for concurrent artifact hydration workers.
    ///
    /// A remote worker may buffer up to 256 MiB, so V1 limits the pool to 2 GiB of
    /// concurrent remote payload buffers before protocol and allocator overhead.
    pub const HYDRATION_CONCURRENCY_MAX: usize = 8;
    /// Default number of idle prepared IVM runtimes retained across requests.
    ///
    /// This cache is independent of artifact hydration and Inrou guest concurrency.
    pub const PREPARED_RUNTIME_CACHE_CAPACITY: NonZeroUsize = nonzero!(4_usize);
    /// Hard V1 ceiling for idle prepared IVM runtimes.
    pub const PREPARED_RUNTIME_CACHE_CAPACITY_MAX: usize = 64;
    /// Default bundle cache budget in bytes.
    pub const BUNDLE_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(512_u64 * 1024 * 1024);
    /// Default static-asset cache budget in bytes.
    pub const STATIC_ASSET_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(512_u64 * 1024 * 1024);
    /// Default journal cache budget in bytes.
    pub const JOURNAL_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(512_u64 * 1024 * 1024);
    /// Default checkpoint cache budget in bytes.
    pub const CHECKPOINT_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(512_u64 * 1024 * 1024);
    /// Default model-artifact cache budget in bytes.
    pub const MODEL_ARTIFACT_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(1_024_u64 * 1024 * 1024);
    /// Default model-weight cache budget in bytes.
    pub const MODEL_WEIGHT_CACHE_BUDGET_BYTES: NonZeroU64 = nonzero!(4_096_u64 * 1024 * 1024);
    /// Whether this node advertises local Inrou hosting by default.
    pub const INROU_ENABLED: bool = false;
    /// First uid/gid in the canonical four-slot PortableVM identity reservation.
    pub const INROU_PORTABLE_VM_ID_BASE: u32 = 70_000;
    /// Number of canonical PortableVM identities that may coexist on one host.
    pub const INROU_PORTABLE_VM_ID_SLOT_COUNT: u32 = 4;
    /// Exclusive upper bound of the canonical PortableVM identity reservation.
    pub const INROU_PORTABLE_VM_ID_MAX_EXCLUSIVE: u32 =
        INROU_PORTABLE_VM_ID_BASE + INROU_PORTABLE_VM_ID_SLOT_COUNT;
    /// Return the canonical PortableVM identity slot for an exact uid/gid pair.
    #[must_use]
    pub const fn inrou_portable_vm_identity_slot(uid: u32, gid: u32) -> Option<u32> {
        if uid != gid
            || uid < INROU_PORTABLE_VM_ID_BASE
            || uid >= INROU_PORTABLE_VM_ID_MAX_EXCLUSIVE
        {
            None
        } else {
            Some(uid - INROU_PORTABLE_VM_ID_BASE)
        }
    }
    /// Dedicated QEMU uid. `None` keeps PortableVM hosting fail-closed until configured.
    pub const INROU_PORTABLE_VM_UID: Option<NonZeroU32> = None;
    /// Dedicated QEMU primary gid. `None` keeps PortableVM hosting fail-closed until configured.
    pub const INROU_PORTABLE_VM_GID: Option<NonZeroU32> = None;
    /// Disabled-profile fallback aggregate physical CPU ceiling, including VMM overhead.
    pub const INROU_MAX_CPU_MILLIS: NonZeroU32 = nonzero!(8_000_u32);
    /// Disabled-profile fallback aggregate physical memory ceiling, including VMM overhead.
    pub const INROU_MAX_MEMORY_BYTES: NonZeroU64 = nonzero!(8_u64 * 1024 * 1024 * 1024);
    /// Disabled-profile fallback aggregate writable-storage ceiling in bytes.
    pub const INROU_MAX_STORAGE_BYTES: NonZeroU64 = nonzero!(64_u64 * 1024 * 1024 * 1024);
    /// Maximum immutable operator-preseeded guest-image bytes materialized for one host ISA.
    pub const INROU_GUEST_IMAGE_MAX_BYTES: NonZeroU64 = nonzero!(4_u64 * 1024 * 1024 * 1024);
    /// Hard production ceiling for one immutable Inrou guest-image artifact.
    pub const INROU_GUEST_IMAGE_MAX_BYTES_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
    /// Maximum compressed size accepted for one Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES: NonZeroU64 =
        nonzero!(512_u64 * 1024 * 1024);
    /// Hard production ceiling for compressed Inrou bundle archives.
    pub const INROU_BUNDLE_ARCHIVE_MAX_COMPRESSED_BYTES_LIMIT: u64 = 512 * 1024 * 1024;
    /// Maximum decoded size accepted for one Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES: NonZeroU64 =
        nonzero!(3_u64 * 1024 * 1024 * 1024);
    /// Hard production ceiling for decoded Inrou bundle archives.
    pub const INROU_BUNDLE_ARCHIVE_MAX_DECODED_BYTES_LIMIT: u64 = 3 * 1024 * 1024 * 1024;
    /// Maximum number of entries accepted from one Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_ENTRIES: NonZeroU32 = nonzero!(4_096_u32);
    /// Hard protocol ceiling for entries in one Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_ENTRIES_LIMIT: u32 = 65_536;
    /// Maximum decoded size accepted for one file in an Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES: NonZeroU64 = nonzero!(512_u64 * 1024 * 1024);
    /// Hard production ceiling for one decoded Inrou bundle file.
    pub const INROU_BUNDLE_ARCHIVE_MAX_FILE_BYTES_LIMIT: u64 = 512 * 1024 * 1024;
    /// Maximum aggregate decoded file size accepted from one Inrou bundle archive.
    pub const INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES: NonZeroU64 =
        nonzero!(2_u64 * 1024 * 1024 * 1024);
    /// Hard production ceiling for aggregate decoded Inrou bundle file bytes.
    pub const INROU_BUNDLE_ARCHIVE_MAX_TOTAL_FILE_BYTES_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
    /// Default startup grace window in milliseconds for Inrou microVMs.
    pub const INROU_START_GRACE_MS: u64 = 30_000;
    /// Default shutdown grace window in milliseconds for Inrou microVMs.
    pub const INROU_STOP_GRACE_MS: u64 = 10_000;
    /// Minimum operator lifecycle grace accepted for Inrou microVMs.
    pub const INROU_LIFECYCLE_GRACE_MIN_MS: u64 = 100;
    /// Maximum operator lifecycle grace, matching
    /// [`iroha_data_model::soracloud::SORA_INROU_LIFECYCLE_GRACE_MAX_SECS_V1`].
    pub const INROU_LIFECYCLE_GRACE_MAX_MS: u64 = 600_000;
    /// Default outbound egress posture for the embedded runtime manager.
    pub const EGRESS_DEFAULT_ALLOW: bool = false;
    /// Default outbound request-rate cap per service/minute. `None` means quota is unset.
    pub const EGRESS_RATE_PER_MINUTE: Option<u32> = None;
    /// Default outbound byte budget per service/minute. `None` means budget is unset.
    pub const EGRESS_MAX_BYTES_PER_MINUTE: Option<u64> = None;
    /// Default root directory for Soracloud runtime-manager state.
    pub fn state_dir() -> PathBuf {
        PathBuf::from(STATE_DIR)
    }
    /// Default allowlist for outbound runtime egress destinations.
    pub fn egress_allowed_hosts() -> Vec<String> {
        Vec::new()
    }
}
/// Pending-transaction queue defaults used by consensus and Torii.
pub mod queue {
    use super::*;
    /// Maximum number of transactions the global queue holds concurrently.
    pub const CAPACITY: NonZeroUsize = nonzero!(4_usize * 2_usize.pow(16));
    /// Maximum number of transactions accepted per authority (prevents one authority from
    /// exhausting the retained-byte budget before other registered authorities can make progress).
    pub const CAPACITY_PER_USER: NonZeroUsize = nonzero!(2_usize.pow(14));
    /// Estimated maximum retained queue memory budget in bytes.
    pub const MAX_RETAINED_BYTES: NonZeroU64 = nonzero!(128_u64 * 1024 * 1024);
    /// Time-to-live for queued transactions before automatic eviction.
    pub const TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(24 * 60 * 60);
    /// Minimum interval between expired-transaction sweeps.
    pub const EXPIRED_CULL_INTERVAL: Duration = Duration::from_secs(1);
    /// Maximum number of entries scanned per expired-transaction sweep.
    pub const EXPIRED_CULL_BATCH: NonZeroUsize = nonzero!(256_usize);
}
/// Transaction admission defaults enforced at pipeline ingress.
pub mod transaction {
    use super::*;
    /// Maximum signatures accepted on a transaction payload.
    pub const fn max_signatures() -> NonZeroU64 {
        nonzero!(16_u64)
    }
    /// Maximum instructions allowed in a transaction payload.
    pub const fn max_instructions() -> NonZeroU64 {
        // `v1/contracts/call` wrapper transactions for Nexus contract flows can exceed 59k
        // decoded IVM instructions (for example local DLMM pool bootstrap), so keep a wider
        // margin above currently observed payloads.
        nonzero!(100_000_u64)
    }
    /// Maximum Kotodama bytecode length (bytes) allowed during admission.
    pub const fn ivm_bytecode_size() -> NonZeroU64 {
        nonzero!(4 * 2_u64.pow(20))
    }
}
/// Compute lane defaults.
pub mod compute {
    use super::*;
    use iroha_config_base::util::Bytes;
    use iroha_data_model::compute::{
        ComputeAuthPolicy, ComputeFeeSplit, ComputePriceAmplifiers, ComputePriceDeltaBounds,
        ComputePriceRiskClass, ComputePriceWeights, ComputeRandomnessPolicy, ComputeResourceBudget,
        ComputeSandboxRules, ComputeSponsorPolicy, ComputeStorageAccess,
    };
    use iroha_model_base::name::Name;
    use std::str::FromStr;
    /// Whether the compute lane is enabled by default.
    pub const ENABLED: bool = false;
    /// Default TTL (slots) applied to compute calls.
    pub const fn default_ttl_slots() -> NonZeroU64 {
        nonzero!(32_u64)
    }
    /// Maximum TTL (slots) accepted for compute calls.
    pub const fn max_ttl_slots() -> NonZeroU64 {
        nonzero!(512_u64)
    }
    /// Maximum request payload size (bytes).
    pub const MAX_REQUEST_BYTES: Bytes = Bytes(512 * 1024);
    /// Maximum response payload size (bytes).
    pub const MAX_RESPONSE_BYTES: Bytes = Bytes(512 * 1024);
    /// Default per-call gas limit.
    pub const fn max_gas_per_call() -> NonZeroU64 {
        nonzero!(5_000_000_u64)
    }
    /// Maximum compute units that may be charged per call.
    pub const fn max_cu_per_call() -> NonZeroU64 {
        nonzero!(100_000_u64)
    }
    /// Maximum amplification ratio (response/ingress) permitted for compute calls.
    pub const fn max_amplification_ratio() -> NonZeroU32 {
        nonzero!(16_u32)
    }
    /// Maximum concurrent in-flight calls per route used by the gateway.
    pub const fn max_inflight_per_route() -> NonZeroUsize {
        nonzero!(32_usize)
    }
    /// Maximum queued requests per route (beyond in-flight).
    pub const fn queue_depth_per_route() -> NonZeroUsize {
        nonzero!(512_usize)
    }
    /// Maximum allowed requests per second (token-bucket rate limit).
    pub const fn max_requests_per_second() -> NonZeroU32 {
        nonzero!(super::torii::DEFAULT_REQUEST_RATE_PER_SEC)
    }
    /// Target p50 latency budget in milliseconds for compute calls.
    pub const fn target_p50_latency_ms() -> NonZeroU64 {
        nonzero!(25_u64)
    }
    /// Target p95 latency budget in milliseconds for compute calls.
    pub const fn target_p95_latency_ms() -> NonZeroU64 {
        nonzero!(75_u64)
    }
    /// Target p99 latency budget in milliseconds for compute calls.
    pub const fn target_p99_latency_ms() -> NonZeroU64 {
        nonzero!(120_u64)
    }
    fn name(value: &str) -> Name {
        Name::from_str(value).expect("default compute name")
    }
    /// Default namespace allowlist.
    pub fn default_namespaces() -> Vec<Name> {
        vec![name("compute")]
    }
    /// Default resource profile name.
    pub fn default_resource_profile() -> Name {
        name("cpu-small")
    }
    /// Default price family identifier.
    pub fn default_price_family() -> Name {
        name("default")
    }
    /// Default resource profiles shipped with the node.
    pub fn resource_profiles() -> BTreeMap<Name, ComputeResourceBudget> {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            default_resource_profile(),
            ComputeResourceBudget {
                max_cycles: nonzero!(5_000_000_u64),
                max_memory_bytes: nonzero!(128 * 1024 * 1024_u64),
                max_stack_bytes: nonzero!(2 * 1024 * 1024_u64),
                max_io_bytes: nonzero!(16 * 1024 * 1024_u64),
                max_egress_bytes: nonzero!(8 * 1024 * 1024_u64),
                allow_gpu_hints: false,
            },
        );
        profiles.insert(
            name("cpu-balanced"),
            ComputeResourceBudget {
                max_cycles: nonzero!(10_000_000_u64),
                max_memory_bytes: nonzero!(256 * 1024 * 1024_u64),
                max_stack_bytes: nonzero!(4 * 1024 * 1024_u64),
                max_io_bytes: nonzero!(24 * 1024 * 1024_u64),
                max_egress_bytes: nonzero!(12 * 1024 * 1024_u64),
                allow_gpu_hints: true,
            },
        );
        profiles
    }
    /// Default price families mapping cycles + egress into compute units.
    pub fn price_families() -> BTreeMap<Name, ComputePriceWeights> {
        let mut families = BTreeMap::new();
        families.insert(
            default_price_family(),
            ComputePriceWeights {
                cycles_per_unit: nonzero!(1_000_000_u64),
                egress_bytes_per_unit: nonzero!(1024_u64),
                unit_label: "cu".to_string(),
            },
        );
        families
    }
    /// Default risk class mapping for price families.
    pub fn price_risk_classes() -> BTreeMap<Name, ComputePriceRiskClass> {
        let mut classes = BTreeMap::new();
        classes.insert(default_price_family(), ComputePriceRiskClass::Balanced);
        classes
    }
    /// Default delta bounds applied per risk class (basis points).
    pub fn price_bounds() -> BTreeMap<ComputePriceRiskClass, ComputePriceDeltaBounds> {
        let mut bounds = BTreeMap::new();
        bounds.insert(
            ComputePriceRiskClass::Low,
            ComputePriceDeltaBounds {
                max_cycles_delta_bps: nonzero!(500_u16),
                max_egress_delta_bps: nonzero!(500_u16),
            },
        );
        bounds.insert(
            ComputePriceRiskClass::Balanced,
            ComputePriceDeltaBounds {
                max_cycles_delta_bps: nonzero!(1_500_u16),
                max_egress_delta_bps: nonzero!(1_500_u16),
            },
        );
        bounds.insert(
            ComputePriceRiskClass::High,
            ComputePriceDeltaBounds {
                max_cycles_delta_bps: nonzero!(3_000_u16),
                max_egress_delta_bps: nonzero!(3_000_u16),
            },
        );
        bounds
    }
    /// Default fee split applied to compute unit charges (basis points).
    pub fn fee_split() -> ComputeFeeSplit {
        ComputeFeeSplit {
            burn_bps: 2_000,
            validators_bps: 6_000,
            providers_bps: 2_000,
        }
    }
    /// Default sponsor policy caps for subsidised compute requests.
    pub fn sponsor_policy() -> ComputeSponsorPolicy {
        ComputeSponsorPolicy {
            max_cu_per_call: nonzero!(10_000_u64),
            max_daily_cu: nonzero!(100_000_u64),
        }
    }
    /// Price amplifiers applied for GPU/TEE/best-effort execution.
    pub fn price_amplifiers() -> ComputePriceAmplifiers {
        ComputePriceAmplifiers::default()
    }
    /// Default sandbox rules for compute execution.
    pub fn sandbox_rules() -> ComputeSandboxRules {
        ComputeSandboxRules {
            randomness: ComputeRandomnessPolicy::SeededFromRequest,
            storage: ComputeStorageAccess::ReadOnly,
            deny_nondeterministic_syscalls: true,
            allow_gpu_hints: false,
            allow_tee_hints: false,
        }
    }
    /// Default authentication policy for compute routes.
    pub const fn default_auth_policy() -> ComputeAuthPolicy {
        ComputeAuthPolicy::Either
    }
}
/// Content lane defaults.
pub mod content {
    use iroha_data_model::da::prelude::DaStripeLayout;
    /// Maximum tarball size accepted for a single content bundle (bytes).
    pub const MAX_BUNDLE_BYTES: u64 = 1_048_576;
    /// Maximum number of files in a bundle.
    pub const MAX_FILES: u32 = 128;
    /// Maximum allowed path length per file.
    pub const MAX_PATH_LEN: u32 = 256;
    /// Maximum retention window (blocks) for an expiring bundle.
    pub const MAX_RETENTION_BLOCKS: u64 = 10_000;
    /// Chunk size (bytes) used when ingesting tarballs.
    pub const CHUNK_SIZE_BYTES: u32 = 64 * 1024;
    /// Default Cache-Control max-age for content bundles (seconds).
    pub const DEFAULT_CACHE_MAX_AGE_SECS: u32 = 300;
    /// Ceiling for Cache-Control max-age (seconds).
    pub const MAX_CACHE_MAX_AGE_SECS: u32 = 86_400;
    /// Force immutable cache-control by default.
    pub const IMMUTABLE_BUNDLES: bool = true;
    /// Maximum served requests per second for the content gateway.
    pub const MAX_REQUESTS_PER_SECOND: u32 = super::torii::DEFAULT_REQUEST_RATE_PER_SEC;
    /// Maximum served egress bytes per second for the content gateway.
    pub const MAX_EGRESS_BYTES_PER_SECOND: u32 = 256 * 1024 * 1024;
    /// Target p50 latency (milliseconds) for content responses.
    pub const TARGET_P50_LATENCY_MS: u32 = 50;
    /// Target p99 latency (milliseconds) for content responses.
    pub const TARGET_P99_LATENCY_MS: u32 = 250;
    /// Burst size for the content request token bucket.
    pub const REQUEST_BURST: u32 = super::torii::DEFAULT_REQUEST_BURST;
    /// Burst size for the egress token bucket.
    pub const EGRESS_BURST_BYTES: u64 = 1024 * 1024 * 1024;
    /// Target availability in basis points (10000 = 100%).
    pub const TARGET_AVAILABILITY_BPS: u32 = 9_990;
    /// Default PoW difficulty (leading zero bits) when enabled for content fetches.
    pub const POW_DIFFICULTY_BITS: u8 = 0;
    /// Default header name carrying PoW nonces.
    pub fn default_pow_header() -> String {
        "x-iroha-pow".to_string()
    }
    /// Default DA stripe layout used for content bundles.
    pub const fn default_stripe_layout() -> DaStripeLayout {
        DaStripeLayout {
            total_stripes: 1,
            shards_per_stripe: 1,
            row_parity_stripes: 0,
        }
    }
    /// Default auth mode string for content lane ("public" | "role:<role>" | "sponsor:<uaid>").
    pub fn default_auth_mode() -> String {
        "public".to_string()
    }
}
/// Oracle pipeline defaults.
pub mod oracle {
    use super::*;
    use iroha_model_base::name::Name;
    /// Public-only custody identity for the oracle reward pool.
    ///
    /// The compressed point is the first canonical prime-order Ed25519 point
    /// produced by `SHA-256("iroha:oracle:reward-pool:v1" || counter_le_u32)`
    /// for counters starting at zero (counter 12). It is constructed directly
    /// as a point, not by multiplying a known private scalar. Protocol
    /// instructions move funds from this account; no signing key is required.
    pub const REWARD_POOL_PUBLIC_KEY: &str =
        "ed01202F616CC1D79D5638D1078788B2A4C3B0C404530B447E565517FBAB4F49E47CDB";
    /// Public-only sink identity for oracle penalties.
    ///
    /// The compressed point is the first canonical prime-order Ed25519 point
    /// produced by `SHA-256("iroha:oracle:slash-receiver:v1" || counter_le_u32)`
    /// for counters starting at zero (counter 0). It is constructed directly
    /// as a point, not by multiplying a known private scalar.
    pub const SLASH_RECEIVER_PUBLIC_KEY: &str =
        "ed0120A05C4A4595ECE6697D86BD4957572BA94DF6C6441D96B781EBEA87A38A934DF1";
    fn protocol_custody_account(public_key: &str) -> AccountId {
        let public_key: iroha_crypto::PublicKey = public_key
            .parse()
            .expect("default oracle custody public key");
        AccountId::new(public_key)
    }
    /// Fixed reward amount for an inlier observation.
    pub fn reward_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle reward amount")
    }
    /// Maximum retained feed-history entries per oracle feed.
    pub const fn history_depth() -> NonZeroUsize {
        nonzero!(2_048usize)
    }
    /// Asset credited to providers when observations are accepted.
    pub fn reward_asset() -> AssetDefinitionId {
        super::canonical_asset_definition_id("sora.universal", "xor")
    }
    /// Account debited to fund oracle provider rewards.
    pub fn reward_pool() -> AccountId {
        protocol_custody_account(REWARD_POOL_PUBLIC_KEY)
    }
    /// Asset debited when slashing oracle providers.
    pub fn slash_asset() -> AssetDefinitionId {
        super::canonical_asset_definition_id("sora.universal", "xor")
    }
    /// Account credited when penalties are collected.
    pub fn slash_receiver() -> AccountId {
        protocol_custody_account(SLASH_RECEIVER_PUBLIC_KEY)
    }
    /// Penalty applied to outlier observations.
    pub fn slash_outlier_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle outlier penalty")
    }
    /// Penalty applied to explicit error observations.
    pub fn slash_error_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle error penalty")
    }
    /// Penalty applied when a provider misses a slot.
    pub fn slash_no_show_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle no-show penalty")
    }
    /// Bond asset required when opening a dispute.
    pub fn dispute_bond_asset() -> AssetDefinitionId {
        super::canonical_asset_definition_id("sora.universal", "xor")
    }
    /// Bond amount required to open a dispute.
    pub fn dispute_bond_amount() -> Quantity {
        Quantity::from_str("2").expect("default oracle dispute bond amount")
    }
    /// Reward paid to a successful challenger.
    pub fn dispute_reward_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle dispute reward")
    }
    /// Penalty charged for frivolous disputes.
    pub fn frivolous_slash_amount() -> Quantity {
        Quantity::from_str("1").expect("default oracle frivolous penalty")
    }
    /// SLA (blocks) for intake stage.
    pub const fn intake_sla_blocks() -> u64 {
        12
    }
    /// SLA (blocks) for rules committee stage.
    pub const fn rules_sla_blocks() -> u64 {
        24
    }
    /// SLA (blocks) for COP review stage.
    pub const fn cop_sla_blocks() -> u64 {
        36
    }
    /// SLA (blocks) for technical audit stage.
    pub const fn technical_sla_blocks() -> u64 {
        36
    }
    /// SLA (blocks) for policy jury stage.
    pub const fn policy_jury_sla_blocks() -> u64 {
        48
    }
    /// SLA (blocks) for enactment stage.
    pub const fn enact_sla_blocks() -> u64 {
        48
    }
    /// Intake approvals required.
    pub const fn intake_min_votes() -> NonZeroUsize {
        nonzero!(1_usize)
    }
    /// Rules committee approvals required.
    pub const fn rules_min_votes() -> NonZeroUsize {
        nonzero!(1_usize)
    }
    /// COP approvals required for low-class changes.
    pub const fn cop_low_votes() -> NonZeroUsize {
        nonzero!(1_usize)
    }
    /// COP approvals required for medium-class changes.
    pub const fn cop_medium_votes() -> NonZeroUsize {
        nonzero!(2_usize)
    }
    /// COP approvals required for high-class changes.
    pub const fn cop_high_votes() -> NonZeroUsize {
        nonzero!(3_usize)
    }
    /// Technical audit approvals required.
    pub const fn technical_min_votes() -> NonZeroUsize {
        nonzero!(2_usize)
    }
    /// Policy jury approvals required for low-class changes.
    pub const fn policy_jury_low_votes() -> NonZeroUsize {
        nonzero!(2_usize)
    }
    /// Policy jury approvals required for medium-class changes.
    pub const fn policy_jury_medium_votes() -> NonZeroUsize {
        nonzero!(3_usize)
    }
    /// Policy jury approvals required for high-class changes.
    pub const fn policy_jury_high_votes() -> NonZeroUsize {
        nonzero!(4_usize)
    }
    /// Feed identifier expected for twitter follow attestations.
    pub fn twitter_binding_feed_id() -> Name {
        Name::from_str(iroha_data_model::oracle::TWITTER_FOLLOW_FEED_ID)
            .expect("default twitter binding feed id")
    }
    /// Pepper identifier used for keyed twitter hashes.
    pub fn twitter_binding_pepper_id() -> String {
        "pepper-social-v1".to_string()
    }
    /// Maximum TTL (milliseconds) accepted for twitter binding attestations.
    pub const fn twitter_binding_max_ttl_ms() -> u64 {
        86_400_000 // 24h
    }
    /// Minimum TTL (milliseconds) accepted for twitter binding attestations.
    pub const fn twitter_binding_min_ttl_ms() -> u64 {
        300_000 // 5 minutes
    }
    /// Minimum spacing (milliseconds) between attestations for the same binding hash.
    pub const fn twitter_binding_min_update_spacing_ms() -> u64 {
        30_000 // 30s
    }
}
/// Kura block-store defaults.
pub mod kura {
    use crate::{
        kura::FsyncMode,
        parameters::actual::{KuraFastpqArtifactPolicy, KuraMembershipStoragePolicy},
    };
    use iroha_config_base::util::Bytes;
    use nonzero_ext::nonzero;
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        time::Duration,
    };
    /// Directory for Kura storage relative to the node working directory.
    pub const STORE_DIR: &str = "./storage";
    /// Full context values remain separate from the compact R proof (16 MiB per carrier).
    pub const NATIVE_CONTEXT_ARCHIVE_MAX_BYTES: NonZeroUsize = nonzero!(16_usize * 1024 * 1024);
    /// Number of blocks cached in memory to accelerate lookups.
    pub const BLOCKS_IN_MEMORY: NonZeroUsize = nonzero!(1024_usize);
    /// Total fixed native checkpoint slots, split between recent and sparse recency caches.
    pub const HISTORY_CHECKPOINT_CACHE_CAPACITY: NonZeroUsize = nonzero!(8192_usize);
    /// Maximum explicitly configured node-local native checkpoint slots.
    pub const MAX_HISTORY_CHECKPOINT_CACHE_CAPACITY: usize = 65_536;
    /// Requested allocation bytes retained by State's block-hash generations.
    pub const BLOCK_HASH_HISTORY_BYTES: Bytes = Bytes(256 * 1024 * 1024);
    /// Requested allocation bytes retained by State's transaction-membership generations.
    pub const TRANSACTION_HISTORY_BYTES: Bytes = Bytes(256 * 1024 * 1024);
    /// Finite extent retained by the initial membership segment (256 MiB).
    pub const MEMBERSHIP_STORAGE_MAX_BYTES: NonZeroU64 = nonzero!(256_u64 * 1024 * 1024);
    /// Membership controls and original append workspaces (64 MiB).
    pub const MEMBERSHIP_STORAGE_MEMORY_BYTES: NonZeroUsize = nonzero!(64_usize * 1024 * 1024);
    /// Initial single-generation limits; these do not provide indefinite history retention.
    pub const MEMBERSHIP_STORAGE_POLICY: KuraMembershipStoragePolicy =
        KuraMembershipStoragePolicy {
            max_bytes: MEMBERSHIP_STORAGE_MAX_BYTES,
            memory_bytes: MEMBERSHIP_STORAGE_MEMORY_BYTES,
        };
    /// Maximum complete stored FASTPQ artifact bytes, matching the proof-sidecar default.
    pub const FASTPQ_ARTIFACT_MAX_BYTES: NonZeroUsize =
        nonzero!(fastpq_isi::resource_limits::FASTPQ_DEFAULT_MAX_PROOF_FRAME_BYTES_V1);
    /// Maximum stable FASTPQ content records retained before storage refuses new content.
    pub const FASTPQ_ARTIFACT_MAX_COUNT: NonZeroUsize = nonzero!(1024_usize);
    /// Maximum stable plus temporary FASTPQ artifact bytes (256 MiB).
    pub const FASTPQ_ARTIFACT_MAX_TOTAL_BYTES: NonZeroU64 = nonzero!(256_u64 * 1024 * 1024);
    /// Complete configured default FASTPQ artifact storage policy.
    pub const FASTPQ_ARTIFACT_POLICY: KuraFastpqArtifactPolicy = KuraFastpqArtifactPolicy {
        max_artifact_bytes: FASTPQ_ARTIFACT_MAX_BYTES,
        max_artifacts: FASTPQ_ARTIFACT_MAX_COUNT,
        max_total_bytes: FASTPQ_ARTIFACT_MAX_TOTAL_BYTES,
    };
    /// Default fsync policy for block persistence.
    pub const FSYNC_MODE: FsyncMode = FsyncMode::Batched;
    /// Default batching interval for fsync operations.
    pub const FSYNC_INTERVAL: Duration = Duration::from_millis(50);
    /// Maximum on-disk footprint allowed for Kura (0 = unlimited).
    pub const MAX_DISK_USAGE_BYTES: Bytes = Bytes(0);
}
/// P2P networking defaults covering gossip, framing, and socket behavior.
pub mod network {
    use super::*;
    /// Default lane profile applied to networking presets.
    pub mod lane_profile {
        /// Default lane profile label for datacenter/validator deployments.
        pub const DEFAULT: &str = "core";
        /// Default lane profile label as owned string for config defaults.
        pub fn default_label() -> String {
            DEFAULT.to_string()
        }
        /// Core profile scheduler tick (milliseconds) for shaping calculations.
        pub const CORE_TICK_MS: u16 = 5;
        /// Core profile recommended MTU (bytes) for p2p traffic.
        pub const CORE_MTU_BYTES: u16 = 1500;
        /// Core profile target uplink budget (bits per second) used when deriving per-peer caps.
        pub const CORE_UPLINK_BPS: u64 = 1_200_000_000;
        /// Core profile constant-rate neighbor budget.
        pub const CORE_CONSTANT_NEIGHBORS: usize = 48;
        /// Core profile soft cap for total connections.
        ///
        /// The shared fallback also serves Kagami's 8,192-command profile; 97
        /// reply sources keep its complete height-local lifecycle inventory at
        /// 65,432 records, while 98 would exceed the 65,536-slot namespace.
        pub const CORE_MAX_TOTAL_CONNECTIONS: usize = 97;
        /// Core profile soft cap for inbound connections.
        pub const CORE_MAX_INCOMING: usize = 48;
        /// Home profile scheduler tick (milliseconds) for shaping calculations.
        pub const HOME_TICK_MS: u16 = 10;
        /// Home profile recommended MTU (bytes) for p2p traffic.
        pub const HOME_MTU_BYTES: u16 = 1400;
        /// Home profile target uplink budget (bits per second) used when deriving per-peer caps.
        pub const HOME_UPLINK_BPS: u64 = 120_000_000;
        /// Home profile constant-rate neighbor budget.
        pub const HOME_CONSTANT_NEIGHBORS: usize = 12;
        /// Home profile soft cap for total connections.
        pub const HOME_MAX_TOTAL_CONNECTIONS: usize = 32;
        /// Home profile soft cap for inbound connections.
        pub const HOME_MAX_INCOMING: usize = 12;
    }
    /// Interval between transaction gossip batches.
    pub const TRANSACTION_GOSSIP_PERIOD: Duration = Duration::from_secs(1);
    /// Number of gossip ticks to wait before re-sending the same transactions.
    pub const TRANSACTION_GOSSIP_RESEND_TICKS: NonZeroU32 = nonzero!(3u32);
    /// Canonical wire maximum for transactions and aligned metadata in one gossip batch.
    pub const TRANSACTION_GOSSIP_MAX_SIZE: NonZeroU32 = nonzero!(512u32);
    /// Default maximum number of transactions sent or accepted in one gossip batch.
    pub const TRANSACTION_GOSSIP_SIZE: NonZeroU32 = nonzero!(500u32);
    /// Drop transaction gossip for dataspaces that are missing from the lane catalog instead of
    /// falling back to restricted targeting.
    pub const TX_GOSSIP_DROP_UNKNOWN_DATASPACE: bool = false;
    /// Optional cap on restricted-dataspace gossip targets (None = all authorized native lane validators).
    pub const TX_GOSSIP_RESTRICTED_TARGET_CAP: Option<NonZeroUsize> = None;
    /// Optional cap on public-dataspace gossip targets (None = broadcast; default = 16).
    pub const TX_GOSSIP_PUBLIC_TARGET_CAP: Option<NonZeroUsize> = Some(nonzero!(16_usize));
    /// Interval between reshuffles of public gossip target selection.
    pub const TX_GOSSIP_PUBLIC_TARGET_RESHUFFLE: Duration = TRANSACTION_GOSSIP_PERIOD;
    /// Interval between reshuffles of restricted gossip target selection.
    pub const TX_GOSSIP_RESTRICTED_TARGET_RESHUFFLE: Duration = TRANSACTION_GOSSIP_PERIOD;
    /// Interval between peer gossip batches.
    pub const PEER_GOSSIP_PERIOD: Duration = Duration::from_secs(1);
    /// Maximum interval between peer gossip batches (change-driven gossip backs off toward this).
    pub const PEER_GOSSIP_MAX_PERIOD: Duration = Duration::from_secs(30);
    /// Interval between block gossip batches.
    pub const BLOCK_GOSSIP_PERIOD: Duration = Duration::from_secs(10);
    /// Maximum interval between block gossip batches (idle backoff ceiling).
    pub const BLOCK_GOSSIP_MAX_PERIOD: Duration = Duration::from_secs(30);
    /// Number of blocks gossiped per batch.
    pub const BLOCK_GOSSIP_SIZE: NonZeroU32 = nonzero!(4u32);
    /// Trust decay half-life applied to gossip scores.
    pub const TRUST_DECAY_HALF_LIFE: Duration = Duration::from_secs(300);
    /// Whether trust gossip capability is advertised/enabled by default.
    pub const TRUST_GOSSIP: bool = true;
    /// Penalty applied for invalid/bad gossip (absolute score delta).
    pub const TRUST_PENALTY_BAD_GOSSIP: i32 = 5;
    /// Penalty applied when peers gossip about unknown/invalid peers.
    pub const TRUST_PENALTY_UNKNOWN_PEER: i32 = 3;
    /// Minimum trust score allowed before gossip is ignored.
    pub const TRUST_MIN_SCORE: i32 = -20;
    /// Idle timeout before disconnecting an inactive peer.
    ///
    /// Keep this comfortably above the typical integration-test runtime so peers do not churn
    /// before they exchange their first gossip/status messages.
    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    /// Maximum total tenure for an accepted transport to authenticate.
    pub const PREAUTH_TIMEOUT: Duration = Duration::from_secs(30);
    /// Maximum concurrent pre-authentication transports admitted from one source IP.
    pub const PREAUTH_MAX_CONNECTIONS_PER_IP: NonZeroUsize = nonzero!(8_usize);
    /// Base deadline for an exact reply to remain owned by one peer writer without a flush.
    pub const REPLY_WRITER_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);
    /// Delay outbound peer dials after startup.
    pub const CONNECT_STARTUP_DELAY: Duration = Duration::from_millis(0);
    /// Timeout applied to an individual outbound dial attempt (TCP/TLS/QUIC/WS).
    pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    /// Maximum age for deferred outbound frames queued while peer session is missing.
    pub const DEFERRED_SEND_TTL_MS: u64 = 1_500;
    /// Maximum deferred outbound frames retained per peer while session is missing.
    pub const DEFERRED_SEND_MAX_PER_PEER: usize = 256;
    /// Maximum stream-wire bytes retained per peer by deferred outbound frames.
    pub const DEFERRED_SEND_MAX_BYTES_PER_PEER: usize = 32 * 1024 * 1024;
    /// Maximum stream-wire bytes retained by all deferred outbound peer queues together.
    pub const DEFERRED_SEND_MAX_BYTES_TOTAL: usize = 128 * 1024 * 1024;
    /// Idle timeout before expiring accept throttle buckets.
    pub const ACCEPT_BUCKET_IDLE: Duration = Duration::from_secs(10 * 60);
    /// Maximum number of accept throttle buckets to retain.
    pub const MAX_ACCEPT_BUCKETS: NonZeroUsize = nonzero!(4096_usize);
    /// Prefix length used for IPv4 accept prefix buckets.
    pub const ACCEPT_PREFIX_V4_BITS: u8 = 24;
    /// Prefix length used for IPv6 accept prefix buckets.
    pub const ACCEPT_PREFIX_V6_BITS: u8 = 64;
    /// Default stagger between parallel dial attempts for multiple addresses (Happy Eyeballs)
    pub const HAPPY_EYEBALLS_STAGGER: Duration = Duration::from_millis(100);
    // QUIC datagram settings (best-effort gossip/health delivery).
    /// Whether QUIC DATAGRAM support is enabled when QUIC transport is in use.
    ///
    /// This remains `false` until quinn-proto 0.11.18 or later is locked and
    /// requalified. Reliable streams carry best-effort topics meanwhile.
    pub const QUIC_DATAGRAMS_ENABLED: bool = false;
    /// Upper bound (bytes) for a single QUIC datagram payload.
    ///
    /// Chosen conservatively to avoid IP fragmentation on typical Internet paths.
    pub const QUIC_DATAGRAM_MAX_PAYLOAD_BYTES: NonZeroUsize = nonzero!(1200_usize);
    /// Receive buffer reserved for QUIC datagrams per active QUIC connection (bytes).
    ///
    /// This stays near the datagram payload scale because the reserve multiplies
    /// by the configured total-connection cap and can otherwise dominate RSS.
    pub const QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES: NonZeroUsize = nonzero!(1024 * 1024_usize);
    /// Send buffer reserved for QUIC datagrams per active QUIC connection (bytes).
    ///
    /// Operators can raise this together with the receive buffer, accounting
    /// for both reserves once per configured active connection.
    pub const QUIC_DATAGRAM_SEND_BUFFER_BYTES: NonZeroUsize = nonzero!(1024 * 1024_usize);
    // P2P bounded queue capacities (always enforced)
    // Defaults tuned for ~20,000 TPS environments: prioritize headroom for gossip/low-priority
    // traffic while keeping consensus/control queues responsive.
    /// Capacity for priority queues fed by high-importance messages.
    pub const P2P_QUEUE_CAP_HIGH: NonZeroUsize = nonzero!(8192_usize);
    /// Capacity for lower-importance queues (e.g., gossip bursts).
    pub const P2P_QUEUE_CAP_LOW: NonZeroUsize = nonzero!(32768_usize);
    /// Capacity for post-queue tasks (per topic).
    pub const P2P_POST_QUEUE_CAP: NonZeroUsize = nonzero!(2048_usize);
    /// Maximum high-priority stream wire bytes (prefix plus AEAD body) retained per peer and
    /// ordinary-high actor subcap. The inbound transport mirrors this as both its process-wide
    /// ordinary source-byte pool and its process-wide alignment-scratch pool; authenticated
    /// decryption itself reuses the source allocation. The actor adds one maximum control-frame
    /// safety charge and one maximum route-qualified semantic-progress frame charge as disjoint
    /// reserves; each authenticated peer separately gets one such progress charge bounded by the
    /// connection cap.
    pub const P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES: NonZeroUsize =
        nonzero!(128 * 1024 * 1024_usize);
    /// Maximum low-priority stream wire bytes retained per peer, including frame prefixes; the
    /// inbound transport mirrors this as separate process-wide source and alignment-scratch pools.
    /// This funds plaintext and encryption copies for both 17 MiB BlockSync and gossip
    /// classes, plus their bounded envelopes, without sharing either class's reservation.
    pub const P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES: NonZeroUsize =
        nonzero!(72 * 1024 * 1024_usize);
    /// Maximum encrypted high-priority outbound frames retained per peer.
    pub const P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES: NonZeroUsize = nonzero!(8192_usize);
    /// Maximum encrypted low-priority outbound frames retained per peer.
    pub const P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES: NonZeroUsize = nonzero!(4096_usize);
    /// Capacity for the inbound P2P subscriber queue feeding the node relay.
    pub const P2P_SUBSCRIBER_QUEUE_CAP: NonZeroUsize = nonzero!(8192_usize);
    /// Optional per-peer consensus ingress rate (msgs/sec). When None, consensus ingress limiting is disabled.
    ///
    /// Defaults tuned for liveness-sensitive traffic without allowing abusive bursts.
    pub const CONSENSUS_INGRESS_RATE_PER_SEC: Option<NonZeroU32> = Some(nonzero!(300_u32));
    /// Optional burst for consensus ingress rate limiting (msgs). Defaults to `rate` when None.
    pub const CONSENSUS_INGRESS_BURST: Option<NonZeroU32> = Some(nonzero!(300_u32));
    /// Optional per-peer consensus ingress bytes/sec budget. When None, bytes limiting is disabled.
    pub const CONSENSUS_INGRESS_BYTES_PER_SEC: Option<NonZeroU32> = Some(nonzero!(67_108_864_u32)); // 64 MiB/s
    /// Optional burst size in bytes for consensus ingress limiting. Defaults to `bytes_per_sec` when None.
    pub const CONSENSUS_INGRESS_BYTES_BURST: Option<NonZeroU32> = Some(nonzero!(134_217_728_u32)); // 128 MiB
    /// Optional per-peer critical consensus ingress rate (msgs/sec). When None, critical limiting is disabled.
    ///
    /// Critical traffic is liveness-sensitive (votes, certificates, and certified body transfer)
    /// and uses a dedicated cap.
    pub const CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC: Option<NonZeroU32> = Some(nonzero!(300_u32));
    /// Optional burst for critical consensus ingress rate limiting (msgs). Defaults to `rate` when None.
    pub const CONSENSUS_INGRESS_CRITICAL_BURST: Option<NonZeroU32> = Some(nonzero!(300_u32));
    /// Optional per-peer critical consensus ingress bytes/sec budget. When None, bytes limiting is disabled.
    pub const CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC: Option<NonZeroU32> =
        Some(nonzero!(134_217_728_u32)); // 128 MiB/s
    /// Optional burst size in bytes for critical consensus ingress limiting. Defaults to `bytes_per_sec` when None.
    pub const CONSENSUS_INGRESS_CRITICAL_BYTES_BURST: Option<NonZeroU32> =
        Some(nonzero!(268_435_456_u32)); // 256 MiB
    /// Drop threshold (per window) before temporarily suppressing consensus ingress.
    pub const CONSENSUS_INGRESS_PENALTY_THRESHOLD: u32 = 32;
    /// Window size (ms) for consensus ingress penalty tracking.
    pub const CONSENSUS_INGRESS_PENALTY_WINDOW_MS: u64 = 5_000;
    /// Cooldown (ms) applied after consensus ingress penalties trigger.
    pub const CONSENSUS_INGRESS_PENALTY_COOLDOWN_MS: u64 = 10_000;
    // Optional DNS hostname refresh interval (None disables). Default 5 minutes.
    /// Interval between DNS resolution refreshes for peer hostnames.
    pub const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
    // Disconnect peers when their per-topic bounded post channel overflows
    /// Whether to disconnect peers that overflow their per-topic queues.
    pub const DISCONNECT_ON_POST_OVERFLOW: bool = true;
    /// Default hop limit for relayed frames.
    pub const RELAY_TTL: u8 = 8;
    /// Complete plaintext P2P frame ceiling used by the largest topic classes.
    pub const MAX_PLAINTEXT_FRAME_BYTES: NonZeroUsize = nonzero!(17 * 1024 * 1024_usize); // 17 MiB
    /// Nonce and authentication-tag bytes added by the first-release
    /// ChaCha20-Poly1305 transport.
    pub const DEFAULT_AEAD_FRAME_OVERHEAD_BYTES: usize = 12 + 16;
    // Maximum allowed encrypted frame size for peer messages (bytes).
    /// Maximum encrypted frame size for peer messages in bytes.
    ///
    /// The cap was sized for a maximal certified-body response of 16,844,237 bytes
    /// before the P2P relay/data wrapper and AEAD nonce/tag.
    /// Rounding the cap up to 17 MiB leaves just under 1 MiB for those bounded
    /// layers while keeping every retained frame allocation finite.
    /// The encrypted ceiling includes AEAD expansion in addition to the full
    /// 17 MiB plaintext topic cap; keeping these as distinct constants avoids
    /// making the default geometry invalid by exactly one nonce and tag.
    // TODO(S4): re-derive the 16,844,237-byte sizing from the current Sumeragi full-body
    // transport message; it was measured on the retired certified-body response.
    pub const MAX_FRAME_BYTES: NonZeroUsize =
        nonzero!(17 * 1024 * 1024_usize + DEFAULT_AEAD_FRAME_OVERHEAD_BYTES);
    // Per-topic caps describe complete canonical plaintext frames.
    /// Maximum frame size for consensus control traffic.
    ///
    /// Consensus certificates and READY bundles can scale with validator set size, so keep
    /// this aligned with the global plaintext ceiling to avoid dropping liveness-critical
    /// frames. The encrypted global cap additionally includes nonce/tag expansion.
    pub const MAX_FRAME_BYTES_CONSENSUS: NonZeroUsize = MAX_PLAINTEXT_FRAME_BYTES;
    /// Maximum frame size for control-plane messages.
    ///
    /// Consensus-safety proposals and timeout certificates use this topic. A
    /// 2 MiB cap carries the reviewed 1,106,267-byte maximal proposal ceiling
    /// plus the bounded P2P envelope overhead.
    pub const MAX_FRAME_BYTES_CONTROL: NonZeroUsize = nonzero!(2 * 1024 * 1024_usize);
    /// Maximum frame size for block sync / consensus payload traffic.
    pub const MAX_FRAME_BYTES_BLOCK_SYNC: NonZeroUsize = MAX_PLAINTEXT_FRAME_BYTES;
    /// Maximum complete transaction-gossip frame, including signed relay metadata.
    /// This carries the maximum committed transaction under the global plaintext ceiling.
    pub const MAX_FRAME_BYTES_TX_GOSSIP: NonZeroUsize = MAX_PLAINTEXT_FRAME_BYTES;
    /// Maximum frame size for peer gossip.
    pub const MAX_FRAME_BYTES_PEER_GOSSIP: NonZeroUsize = nonzero!(65_536_usize); // 64 KiB
    /// Maximum frame size for health-check channel messages.
    pub const MAX_FRAME_BYTES_HEALTH: NonZeroUsize = nonzero!(32_768_usize); // 32 KiB
    /// Maximum Connect relay envelope, separate from health/diagnostic traffic.
    pub const MAX_FRAME_BYTES_CONNECT: NonZeroUsize = nonzero!(131_072_usize); // 128 KiB
    /// Maximum frame size for other miscellaneous topics.
    pub const MAX_FRAME_BYTES_OTHER: NonZeroUsize = nonzero!(131_072_usize); // 128 KiB
    // TCP options
    /// Whether to enable TCP_NODELAY for reduced latency.
    pub const TCP_NODELAY: bool = true;
    /// Default TCP keepalive (recommended for long-lived P2P sockets)
    pub const TCP_KEEPALIVE: Duration = Duration::from_secs(60);
    /// Require peers to advertise matching SM helper availability (`sm_enabled`) during handshake.
    pub const REQUIRE_SM_HANDSHAKE_MATCH: bool = true;
    /// Require peers to match the OpenSSL preview toggle (`sm_openssl_preview`) during handshake.
    pub const REQUIRE_SM_OPENSSL_PREVIEW_MATCH: bool = true;
    /// Default relay mode for P2P (disabled).
    pub const RELAY_MODE: &str = "disabled";
}
/// Snapshotting defaults for archival state dumps.
pub mod snapshot {
    use super::*;
    /// Directory for snapshot files relative to node root.
    pub const STORE_DIR: &str = "./storage/snapshot";
    // 10 mins
    /// Interval between automatic snapshot creation tasks.
    pub const CREATE_EVERY: Duration = Duration::from_secs(10 * 60);
    /// Chunk size used for snapshot Merkle metadata (default: 1 MiB).
    pub const MERKLE_CHUNK_SIZE_BYTES: NonZeroUsize = nonzero!(1_048_576_usize);
    /// Maximum snapshot payload buffered during startup (default: 1 GiB).
    ///
    /// JSON restoration uses additional transient memory; operators should size this below
    /// available restore headroom for their representative world state.
    pub const MAX_PAYLOAD_BYTES: NonZeroUsize = nonzero!(1_073_741_824_usize);
    /// Aggregate requested bytes held by authenticated snapshot payload read buffers.
    /// One maximum-sized payload fits; typed restore and writer output are separate.
    pub const MAX_READ_BUFFER_BYTES: NonZeroUsize = MAX_PAYLOAD_BYTES;
    /// Maximum typed-decoder nesting depth for one snapshot payload.
    ///
    /// Keep the default tied to the codec's structural ceiling so a default
    /// configuration can never advertise a depth that Norito rejects.
    pub const MAX_DECODE_DEPTH: NonZeroUsize = nonzero!(::norito::core::MAX_VALUE_NESTING_DEPTH);
    /// Maximum aggregate collection items decoded from one snapshot payload.
    pub const MAX_DECODE_ITEMS: NonZeroUsize = nonzero!(10_000_000_usize);
    /// Maximum UTF-8 bytes accepted for any individual snapshot string.
    pub const MAX_STRING_BYTES: NonZeroUsize = nonzero!(1_048_576_usize);
    /// Maximum bytes accepted for any individual snapshot blob.
    pub const MAX_BLOB_BYTES: NonZeroUsize = nonzero!(67_108_864_usize);
    /// Maximum transient allocation budget during typed snapshot restoration.
    pub const MAX_TRANSIENT_BYTES: NonZeroUsize = nonzero!(2_147_483_648_usize);
}
/// Norito streaming control-plane defaults.
pub mod streaming {
    use norito::streaming::CapabilityFlags;
    /// Directory for persisted streaming session snapshots relative to the node root.
    pub const SESSION_STORE_DIR: &str = "./storage/streaming";
    /// Feature bitmask advertised during capability negotiation (baseline feedback + privacy provider + bundled entropy).
    pub const FEATURE_BITS: u32 = 0b11 | CapabilityFlags::FEATURE_ENTROPY_BUNDLED;
    /// Defaults applied to the streaming audio/video sync enforcement gate.
    pub mod sync {
        /// Enable sync enforcement in observe-only mode by default.
        pub const ENABLED: bool = true;
        /// Observe-only mode keeps logging metrics without rejecting segments.
        pub const OBSERVE_ONLY: bool = true;
        /// Minimum rolling window (milliseconds) required before enforcement.
        pub const MIN_WINDOW_MS: u16 = 5_000;
        /// Sustained EWMA drift threshold (milliseconds) that triggers rejection.
        pub const EWMA_THRESHOLD_MS: u16 = 10;
        /// Hard cap for any single frame drift (milliseconds).
        pub const HARD_CAP_MS: u16 = 12;
    }
    /// Codec gating defaults.
    pub mod codec {
        use std::path::PathBuf;
        /// Default CABAC runtime mode (`disabled`).
        pub const CABAC_MODE: &str = "disabled";
        /// Bundled entropy mode advertised by all supported builds (requires `ENABLE_RANS_BUNDLES=1`).
        pub const BUNDLED_ENTROPY_MODE: &str = "rans_bundled";
        /// Default bundle width used by the bundled-rANS encoder.
        pub const BUNDLE_WIDTH: u8 = 2;
        /// Default acceleration backend for bundle processing.
        pub const BUNDLE_ACCEL: &str = "none";
        /// Default trellis block sizes (empty until claim-avoidance ships).
        pub fn trellis_blocks() -> Vec<u16> {
            Vec::new()
        }
        /// Default deterministic rANS table artefact.
        pub fn rans_tables_path() -> PathBuf {
            PathBuf::from("codec/rans/tables/rans_seed0.toml")
        }
        /// Default entropy mode string (bundled rANS only).
        pub fn entropy_mode() -> String {
            assert!(
                norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
                "Bundled rANS is mandatory; rebuild with ENABLE_RANS_BUNDLES=1"
            );
            BUNDLED_ENTROPY_MODE.to_string()
        }
        /// Default bundle width for bundled rANS encoders.
        pub const fn bundle_width() -> u8 {
            BUNDLE_WIDTH
        }
        /// Default acceleration backend string for bundle execution.
        pub fn bundle_accel() -> String {
            BUNDLE_ACCEL.to_string()
        }
    }
}
/// SoraNet-specific defaults.
/// SoraFS storage defaults.
pub mod sorafs {
    /// Defaults governing the embedded SoraFS storage worker.
    pub mod storage {
        use iroha_config_base::util::Bytes;
        use std::path::PathBuf;
        /// Feature toggle for the embedded SoraFS storage worker.
        pub const ENABLED: bool = false;
        /// Default root directory for pinned chunks and manifest metadata.
        pub fn data_dir() -> PathBuf {
            PathBuf::from("./storage/sorafs")
        }
        /// Maximum on-disk capacity allocated to SoraFS (bytes).
        pub const MAX_CAPACITY_BYTES: Bytes = Bytes(100 * 1024 * 1024 * 1024);
        /// Maximum concurrent fetch operations served by the gateway.
        pub const MAX_PARALLEL_FETCHES: usize = 32;
        /// Shared private signer-journal inventory resident-credit ceiling (bytes).
        pub const SIGNER_JOURNAL_INVENTORY_RESIDENT_BYTES: Bytes = Bytes(16 * 1024 * 1024);
        /// Concurrent logical directory/metadata probe credits across every signer purpose.
        pub const SIGNER_JOURNAL_INVENTORY_METADATA_PROBES: u64 = 1_000_000;
        /// Concurrent pinned path, receipt and scan descriptors across every signer purpose.
        pub const SIGNER_JOURNAL_INVENTORY_OPEN_HANDLES: u32 = 1_024;
        /// Maximum number of manifests pinned before the node applies back-pressure.
        pub const MAX_PINS: usize = 10_000;
        /// Background Proof-of-Retrievability sampling cadence (seconds).
        pub const POR_SAMPLE_INTERVAL_SECS: u64 = 600;
        /// Maximum PDP segments that one governed challenge may sample.
        pub const PDP_SAMPLE_WINDOW: u16 = 64;
        /// Protocol ceiling for configured PDP segment samples.
        pub const PDP_SAMPLE_WINDOW_MAX: u16 = 500;
        /// Aggregate in-memory budget for canonical PDP tree indexes.
        pub const PDP_TREE_MEMORY_LIMIT_BYTES: Bytes = Bytes(512 * 1024 * 1024);
        /// Authenticated AI-screening admission is opt-in until a governed
        /// authority bundle and its reviewed digest are configured.
        pub const MODERATION_SCREENING_ENABLED: bool = false;
        /// Proof-of-personhood credential services require explicit governed
        /// policy plus runtime-injected signing, key-custody, and authentication
        /// providers.
        pub mod pop_credentials {
            use std::path::PathBuf;
            /// PoP service routes and workers are disabled by default.
            pub const ENABLED: bool = false;
            /// Required dual-control quorum when the service is enabled.
            pub const APPROVAL_QUORUM: u8 = 2;
            /// Maximum pending encrypted enrollments.
            pub const MAX_PENDING_ENROLLMENTS: u32 = 4_096;
            /// Maximum durable ledger submission outbox entries.
            pub const MAX_OUTBOX_ENTRIES: u32 = 4_096;
            /// Maximum durable terminal dead letters.
            pub const MAX_DEAD_LETTERS: u32 = 4_096;
            /// Maximum consumed proof nullifiers retained for replay defense.
            pub const MAX_SEEN_NULLIFIERS: u32 = 65_536;
            /// Submission attempts before an unconfirmed operation is dead-lettered.
            pub const MAX_SUBMISSION_ATTEMPTS: u16 = 8;
            /// Registry submission/reconciliation worker cadence.
            pub const WORKER_INTERVAL_MS: u64 = 1_000;
            /// Maximum absolute skew between finalized and runtime clock time.
            pub const MAX_FINALIZED_TIME_SKEW_SECS: u64 = 30;
            /// Default issuer checkpoint directory.
            pub fn issuer_state_dir() -> PathBuf {
                PathBuf::from("./storage/sorafs/pop/issuer")
            }
            /// Default encrypted wallet-vault directory.
            pub fn wallet_state_dir() -> PathBuf {
                PathBuf::from("./storage/sorafs/pop/wallet")
            }
        }
        /// Finalized-chain moderation orchestrator defaults.
        pub mod moderation_orchestrator {
            use iroha_config_base::util::Bytes;
            use std::path::PathBuf;
            /// Native moderation orchestration is disabled until every
            /// runtime-only signer, reader, and terminal sink is injected.
            pub const ENABLED: bool = false;
            /// Maximum appeals and activated cases in one complete snapshot.
            pub const MAX_CASES: u32 =
                iroha_data_model::sorafs::moderation_ledger::MODERATION_QUERY_MAX_CASES_V1;
            /// Maximum finalized typed events retained in one snapshot.
            pub const MAX_EVENTS: u32 =
                iroha_data_model::sorafs::moderation_ledger::MODERATION_QUERY_MAX_EVENTS_V1;
            /// Maximum pending native transactions.
            pub const MAX_OUTBOX_ENTRIES: u32 = 4_096;
            /// Maximum durable operation identities and dead letters.
            pub const MAX_IDEMPOTENCY_RECORDS: u32 = 65_536;
            /// Maximum settlement/publication handoff identities.
            pub const MAX_HANDOFFS: u32 = 65_536;
            /// Safe attempts under one unchanged operation identity.
            pub const MAX_SUBMIT_ATTEMPTS: u16 = 8;
            /// Maximum canonical checkpoint size.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(32 * 1024 * 1024);
            /// Maximum checkpoint-plus-minimal-terminal-wrapper archive artifact size.
            pub const PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES: Bytes = Bytes(40 * 1024 * 1024);
            /// Minimum canonical archive artifact size admitted by V1.
            pub const PANEL_NOTIFICATION_ARCHIVE_MIN_BYTES_V1: u64 = 1024 * 1024;
            /// Hard canonical archive artifact ceiling admitted by V1.
            pub const PANEL_NOTIFICATION_ARCHIVE_MAX_BYTES_LIMIT_V1: u64 = 64 * 1024 * 1024;
            /// Finalized reconciliation and deadline-maintenance cadence.
            pub const WORKER_INTERVAL_MS: u64 = 1_000;
            /// Maximum native maintenance actions emitted in one scan.
            pub const MAINTENANCE_BATCH_LIMIT: u32 = 128;
            /// Default checkpoint path used only while the service is disabled.
            pub fn checkpoint_path() -> PathBuf {
                PathBuf::from("./storage/sorafs/moderation/orchestrator.norito")
            }
        }
        /// Authenticated finalized-PoR replay archive defaults.
        pub mod por_replay_archive {
            /// Compaction is opt-in until a deployment-owned immutable archive
            /// and external Ed25519 signer are injected.
            pub const ENABLED: bool = false;
            /// Supervised reconciliation and bounded compaction cadence.
            pub const POLL_INTERVAL_MS: u64 = 1_000;
            /// Maximum acknowledged records reconciled and compacted per tick.
            pub const MAX_RECORDS_PER_TICK: u32 = 64;
            /// Maximum signed successor receipts accepted in one inclusion proof.
            pub const MAX_SUCCESSOR_RECEIPTS: u32 = 1_024;
            /// Maximum canonical bytes accepted for one successor-receipt proof.
            pub const MAX_SUCCESSOR_PROOF_BYTES: u64 = 1_048_576;
            /// Minimum supported supervised cadence.
            pub const POLL_INTERVAL_MIN_MS: u64 = 100;
            /// Maximum supported supervised cadence.
            pub const POLL_INTERVAL_MAX_MS: u64 = 60_000;
            /// Hard per-tick work ceiling.
            pub const MAX_RECORDS_PER_TICK_LIMIT: u32 = 1_024;
            /// Hard ceiling for a configured successor-receipt count bound.
            pub const MAX_SUCCESSOR_RECEIPTS_LIMIT: u32 = 65_536;
            /// Hard ceiling for a configured canonical successor-proof byte bound.
            pub const MAX_SUCCESSOR_PROOF_BYTES_LIMIT: u64 = 16_777_216;
        }
        /// Finalized-ledger reputation projector and external publication defaults.
        pub mod reputation_runtime {
            use iroha_config_base::util::Bytes;
            use std::path::PathBuf;
            /// The committed projector is opt-in until every runtime-only
            /// finalized-query, sealed journal-checkpoint, threshold-signer,
            /// Governance DAG, and native journal-transaction dependency is
            /// supplied.
            pub const ENABLED: bool = false;
            /// Exact-anchor reconciliation cadence.
            pub const POLL_INTERVAL_MS: u64 = 1_000;
            /// Maximum items requested from one native finalized query page.
            pub const PAGE_ITEMS: u32 = 64;
            /// Maximum native pages accepted in one coherent ingest batch.
            pub const MAX_PAGES_PER_BATCH: u32 = 4_096;
            /// Maximum provider accumulators retained by the V1 projector.
            pub const MAX_PROVIDERS: u32 = 65_536;
            /// Maximum typed events staged in one atomic projector batch.
            pub const MAX_PENDING_EVENTS: u32 = 65_536;
            /// Maximum exact-replay receipts retained.
            pub const MAX_REPLAY_RECEIPTS: u32 = 262_144;
            /// Maximum external-delivery failure receipts retained.
            pub const MAX_MATERIAL_DELIVERY_FAILURES: u32 = 64;
            /// Maximum canonical projector checkpoint size.
            pub const INGEST_CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
            /// Maximum canonical publication checkpoint size.
            pub const PUBLICATION_CHECKPOINT_MAX_BYTES: Bytes = Bytes(32 * 1024 * 1024);
            /// Maximum bytes accepted for one canonical finalized archive record.
            pub const FINALIZED_ARCHIVE_MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
            /// Maximum immutable records admitted in each finalized archive namespace.
            pub const FINALIZED_ARCHIVE_MAX_ENTRIES: usize = 1_000_000;
            /// Maximum aggregate canonical anchor and policy bytes admitted.
            pub const FINALIZED_ARCHIVE_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
            /// Maximum admitted lag between the Kura tip and the archive head.
            pub const FINALIZED_ARCHIVE_MAX_KURA_TIP_LAG_BLOCKS: u64 = 2;
            /// Hard ceiling for admitted archive lag behind the Kura tip.
            pub const FINALIZED_ARCHIVE_MAX_KURA_TIP_LAG_BLOCKS_LIMIT: u64 = 10_000;
            /// Sealed monotonic finalized-archive retention is opt-in.
            pub const FINALIZED_ARCHIVE_RETENTION_ENABLED: bool = false;
            /// Deterministic private finalized archive directory below `state_dir`.
            pub const FINALIZED_ARCHIVE_DIRECTORY_NAME: &str = "finalized-reputation-archive-v1";
            /// Governed default PoR-success weight.
            pub const POR_SUCCESS_BPS: u16 = 2_200;
            /// Governed default PDP-success weight.
            pub const PDP_SUCCESS_BPS: u16 = 2_000;
            /// Governed default PoTR-success weight.
            pub const POTR_SUCCESS_BPS: u16 = 1_800;
            /// Governed default latency-health weight.
            pub const LATENCY_BPS: u16 = 1_500;
            /// Governed default upheld-dispute penalty weight.
            pub const DISPUTE_BPS: u16 = 1_000;
            /// Governed default stream-token violation penalty weight.
            pub const TOKEN_VIOLATION_BPS: u16 = 500;
            /// Governed default unresolved-repair penalty weight.
            pub const REPAIR_BREACH_BPS: u16 = 1_000;
            /// Default private state root used only while the runtime is disabled.
            pub fn state_dir() -> PathBuf {
                PathBuf::from("./storage/sorafs/reputation")
            }
        }
        /// Finalized reserve-event transparency scanner defaults.
        pub mod reserve_transparency_runtime {
            use iroha_config_base::util::Bytes;
            use std::path::PathBuf;
            /// The scanner is opt-in with the committed reputation archive.
            pub const ENABLED: bool = false;
            /// Normal exact-anchor scan cadence.
            pub const POLL_INTERVAL_MS: u64 = 1_000;
            /// Maximum bounded retry delay after transient unavailability.
            pub const RETRY_MAX_INTERVAL_MS: u64 = 30_000;
            /// Maximum reserve events requested from one immutable page.
            pub const PAGE_ITEMS: u32 = 64;
            /// Maximum immutable pages consumed by one scanner tick.
            pub const MAX_PAGES_PER_TICK: u32 = 64;
            /// Maximum canonical scanner checkpoint bytes.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024);
            /// Default private state root used only while the scanner is disabled.
            pub fn state_dir() -> PathBuf {
                PathBuf::from("./storage/sorafs/reserve-transparency")
            }
        }
        /// Finalized-ledger hedging/billing supervisor defaults.
        pub mod hedging_billing_runtime {
            use std::path::PathBuf;
            /// Disabled until all identity-pinned runtime-only adapters and
            /// reviewed public policy artifacts are supplied.
            pub const ENABLED: bool = false;
            /// Finalized reconciliation and delivery cadence.
            pub const POLL_INTERVAL_MS: u64 = 1_000;
            /// Maximum finalized journal pages consumed in one worker tick.
            pub const MAX_PAGES_PER_TICK: u32 = 256;
            /// Maximum finalized period closes consumed in one worker tick.
            pub const MAX_PERIOD_CLOSES_PER_TICK: u32 = 32;
            /// Maximum signer/publication/reconciliation operations in one tick.
            pub const MAX_DELIVERY_OPERATIONS_PER_TICK: u32 = 256;
            /// Maximum admitted distance between the authenticated finalized
            /// head and the durable billing projector cursor.
            pub const MAX_FINALIZED_LAG_BLOCKS: u64 = 2;
            /// Default private state root used only while the runtime is disabled.
            pub fn state_dir() -> PathBuf {
                PathBuf::from("./storage/sorafs/hedging-billing")
            }
        }
        /// Supervised finalized-ledger provider-ingest defaults.
        pub mod provider_ingest_runtime {
            /// Provider ingest is opt-in until its source, signer, and sealed
            /// checkpoint providers are registered by the daemon.
            pub const ENABLED: bool = false;
            /// Delay between finalized assignment scans.
            pub const SCAN_INTERVAL_MS: u64 = 1_000;
            /// Maximum finalized assignment rows requested in one page.
            pub const MAX_PAGE_ROWS: usize = 64;
            /// Maximum finalized pages reconciled in one tick.
            pub const MAX_PAGES_PER_TICK: usize = 4;
            /// Maximum source jobs performed in one tick.
            pub const MAX_SOURCE_JOBS_PER_TICK: usize = 16;
            /// Maximum governed source providers considered for one assignment.
            pub const MAX_SOURCE_PROVIDERS: usize = 1_024;
            /// Hard deadline ceiling for one authenticated source operation.
            pub const SOURCE_OPERATION_TIMEOUT_MS_LIMIT_V1: u64 = 24 * 60 * 60 * 1_000;
            /// Timeout for authenticated source fetch, verification, and storage.
            pub const SOURCE_OPERATION_TIMEOUT_MS: u64 = 5 * 60_000;
            /// Durable source-lease renewal cadence.
            pub const SOURCE_LEASE_RENEW_INTERVAL_MS: u64 = 15_000;
            /// Timeout for completion payload construction and external signing.
            pub const SIGNER_TIMEOUT_MS: u64 = 30_000;
            /// Timeout for transaction preflight, submission, and observation.
            pub const INGRESS_TIMEOUT_MS: u64 = 30_000;
            /// Time-to-live assigned to one completion transaction.
            pub const COMPLETION_TRANSACTION_TTL_MS: u64 = 5 * 60_000;
            /// Default-off Musubi provider-attestation journal bounds.
            ///
            /// The clock-seal, approval-signer, and inventory binding triplets
            /// intentionally have no defaults and must be supplied together for
            /// an activation request.
            pub mod provider_attestation_journal {
                use iroha_config_base::util::Bytes;
                /// Request native completed-bundle capture activation with exact credential
                /// bindings and explicitly initialized retained journal custody.
                pub const ENABLED: bool = false;
                /// Maximum retained active and terminal entries, independently of
                /// the checkpoint byte cap.
                pub const MAX_ENTRIES: usize = 1_024;
                /// Hard upper bound on retained entries.
                pub const MAX_ENTRIES_LIMIT: usize = 4_096;
                /// Maximum approval or inventory-handoff attempts per stage.
                pub const MAX_ATTEMPTS: u32 = 8;
                /// Hard upper bound on attempts per stage.
                pub const MAX_ATTEMPTS_LIMIT: u32 = 64;
                /// Lease duration for approval and inventory-handoff claims.
                pub const LEASE_TTL_MS: u64 = 60_000;
                /// Hard upper bound on one claim lease.
                pub const LEASE_TTL_MAX_MS: u64 = 24 * 60 * 60 * 1_000;
                /// Maximum external approval-signer operation duration.
                pub const APPROVAL_TIMEOUT_MS: u64 = 30_000;
                /// Maximum external coordinator-inventory operation duration.
                pub const HANDOFF_TIMEOUT_MS: u64 = 30_000;
                /// Hard upper bound on one external stage operation.
                pub const EXTERNAL_TIMEOUT_MAX_MS: u64 = 5 * 60 * 1_000;
                /// Delay before retrying a transient stage failure.
                pub const RETRY_DELAY_MS: u64 = 1_000;
                /// Hard upper bound on a retry delay.
                pub const RETRY_DELAY_MAX_MS: u64 = 24 * 60 * 60 * 1_000;
                /// Canonical checkpoint framing reserved independently of entries.
                pub const CHECKPOINT_HEADER_FOOTPRINT_BYTES_V1: usize = 64 * 1024;
                /// Canonical state and framing reserved around one active entry.
                pub const ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1: usize = 64 * 1024;
                /// Conservative canonical reserve for one stored approval intent.
                ///
                /// This covers the two Musubi account identities bounded at 8 KiB each,
                /// the 255-byte chain identifier, immutable digests, cursors, signer
                /// policy, attestation key, sequence, and Norito framing.
                pub const STORED_APPROVAL_INTENT_CANONICAL_RESERVE_BYTES_V1: usize = 64 * 1024;
                /// Schema-derived reserve for one active intent through its worst-case
                /// provider-attestation state transition.
                pub const SINGLE_ACTIVE_ENTRY_RESERVE_BYTES_V1: usize =
                    CHECKPOINT_HEADER_FOOTPRINT_BYTES_V1
                    + STORED_APPROVAL_INTENT_CANONICAL_RESERVE_BYTES_V1
                    + iroha_data_model::musubi::MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1
                    + ACTIVE_ENTRY_WRAPPER_MARGIN_BYTES_V1;
                /// Smallest useful checkpoint policy.
                ///
                /// Four times the public complete-attestation ceiling is deliberately
                /// conservative: it exceeds [`SINGLE_ACTIVE_ENTRY_RESERVE_BYTES_V1`]
                /// while leaving headroom for canonical framing evolution within V1.
                pub const CHECKPOINT_MIN_BYTES: usize = 4
                    * iroha_data_model::musubi::MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1;
                /// Maximum canonical checkpoint size, independently of the entry cap.
                pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
                /// Physical and decoder ceiling for one canonical checkpoint.
                pub const CHECKPOINT_MAX_BYTES_LIMIT: usize = 128 * 1024 * 1024;
                /// Maximum CAS conflicts retried by one journal operation.
                pub const MAX_CAS_RETRIES: u32 = 16;
                /// Hard upper bound on CAS conflicts retried by one operation.
                pub const MAX_CAS_RETRIES_LIMIT: u32 = 64;
            }
            /// Daemon-owned immutable finalized-assignment archive defaults.
            pub mod finalized_archive {
                use iroha_config_base::util::Bytes;
                /// Relative archive namespace below the resolved Kura root.
                pub const RELATIVE_ROOT: &str = "provider-ingest-finalized-archive-v1";
                /// Maximum canonical bytes admitted for one immutable anchor record.
                pub const MAX_RECORD_BYTES: Bytes = Bytes(128 * 1024 * 1024);
                /// Maximum immutable anchor records admitted by one namespace.
                pub const MAX_ARCHIVE_ENTRIES: usize = 1_000_000;
                /// Maximum aggregate canonical bytes admitted by one namespace.
                pub const MAX_TOTAL_BYTES: Bytes = Bytes(64 * 1024 * 1024 * 1024);
                /// Maximum provider projections admitted at one anchor.
                pub const MAX_PROVIDERS_PER_ANCHOR: usize = 1_024;
                /// Maximum assigned orders admitted for one provider at one anchor.
                pub const MAX_ORDERS_PER_PROVIDER: usize = 256;
                /// Maximum aggregate provider/order rows admitted at one anchor.
                pub const MAX_TOTAL_ORDERS_PER_ANCHOR: usize = 256;
                /// Maximum rows returned by one provider-indexed archive page.
                pub const MAX_PAGE_ROWS: usize = 64;
                /// Maximum authenticated lag between the Kura and archive tips.
                pub const MAX_KURA_TIP_LAG_BLOCKS: u64 = 2;
                /// Keep archive retention manual unless an external sealed
                /// monotonic authority is explicitly configured.
                pub const RETENTION_ENABLED: bool = false;
            }
            /// Durable provider-ingest completion-outbox defaults.
            pub mod outbox {
                use iroha_config_base::util::Bytes;
                /// Maximum non-terminal ingest jobs.
                pub const MAX_ACTIVE_ENTRIES: usize = 128;
                /// Maximum retained terminal tombstones.
                pub const MAX_TERMINAL_ENTRIES: usize = 4_096;
                /// Maximum retry attempts under one semantic job identity.
                pub const MAX_ATTEMPTS: u32 = 8;
                /// Hard production ceiling for one canonical outbox checkpoint.
                pub const CHECKPOINT_MAX_BYTES_LIMIT: u64 = 192 * 1024 * 1024;
                /// Maximum canonical outbox checkpoint size.
                pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(192 * 1024 * 1024);
                /// Deadline for one external sealed-checkpoint operation.
                pub const CHECKPOINT_OPERATION_TIMEOUT_MS: u64 = 30_000;
                /// Source-claim lease duration.
                pub const SOURCE_LEASE_TTL_MS: u64 = 60_000;
                /// Initial retry delay.
                pub const RETRY_BASE_DELAY_MS: u64 = 1_000;
                /// Maximum exponential retry delay.
                pub const RETRY_MAX_DELAY_MS: u64 = 5 * 60_000;
                /// Maximum finalized-block age of a terminal tombstone.
                pub const TERMINAL_RETENTION_BLOCKS: u64 = 100_000;
                /// Canonical checkpoint framing reserved independently of entries.
                pub const CHECKPOINT_CANONICAL_OVERHEAD_BYTES_V1: u64 = 4 * 1024;
                /// Canonical non-payload bytes reserved for one active entry.
                ///
                /// This covers three separately retained, canonically bounded
                /// account identities, the bounded chain identifier, immutable
                /// authorization text, state/cursor material, and Norito framing.
                /// The unsigned payload and signed transaction are counted
                /// separately by [`worst_case_checkpoint_bytes_v1`].
                pub const ACTIVE_ENTRY_CANONICAL_OVERHEAD_BYTES_V1: u64 = 64 * 1024;
                /// Maximum canonical bytes for each retained completion account identity.
                pub const COMPLETION_ACCOUNT_ID_MAX_CANONICAL_BYTES_V1: u64 =
                    iroha_data_model::musubi::MUSUBI_MAX_ACCOUNT_ID_CANONICAL_BYTES_V1 as u64;
                /// Canonical reserve for one immutable finalized authorization.
                ///
                /// The provider-ingest runtime validates the largest variable
                /// fields at 256 bytes for the manifest CID and 128 bytes for
                /// the chunker handle. This reserve also covers the fixed job,
                /// cursor, provider, order, manifest, chunk-plan, PoR, and
                /// content-length fields.
                pub const TERMINAL_AUTHORIZATION_CANONICAL_RESERVE_BYTES_V1: u64 = 4 * 1024;
                /// Canonical reserve for terminal evidence other than `completed_by`.
                ///
                /// This includes the bounded manifest identifier, completion
                /// epoch, committed hash, finalized cursor, enum tag, the
                /// bounded pre-completion Musubi verification receipt, and
                /// length framing for the largest `FinalizedCompleted` variant.
                pub const TERMINAL_OUTCOME_FIXED_CANONICAL_RESERVE_BYTES_V1: u64 = 12 * 1024;
                /// Canonical entry/container framing reserved around terminal fields.
                pub const TERMINAL_ENTRY_CANONICAL_FRAMING_RESERVE_BYTES_V1: u64 = 2 * 1024;
                /// Canonical bytes reserved for one payload-free terminal entry.
                ///
                /// The bound is derived from the immutable authorization, one
                /// explicitly bounded completion account, the largest terminal
                /// outcome, and entry/container framing. A canonical fixture
                /// maximizes the authorization fields and outcome variant,
                /// while explicit account validation enforces the remaining
                /// identity reserve.
                pub const TERMINAL_ENTRY_CANONICAL_OVERHEAD_BYTES_V1: u64 =
                    TERMINAL_AUTHORIZATION_CANONICAL_RESERVE_BYTES_V1
                        + COMPLETION_ACCOUNT_ID_MAX_CANONICAL_BYTES_V1
                        + TERMINAL_OUTCOME_FIXED_CANONICAL_RESERVE_BYTES_V1
                        + TERMINAL_ENTRY_CANONICAL_FRAMING_RESERVE_BYTES_V1;
                /// Canonical envelope headroom reserved after encoding the unsigned
                /// completion transaction.
                pub const SIGNED_TRANSACTION_ENVELOPE_RESERVE_BYTES_V1: u64 = 4 * 1024;
                /// Production floor for one canonical signed completion transaction.
                ///
                /// The daemon's canonical completion-payload fixture is encoded,
                /// signed, round-tripped, and checked against this floor. Keeping
                /// 64 KiB available avoids a syntactically valid but operationally
                /// unusable configuration while remaining well below the default.
                pub const MAX_SIGNED_TRANSACTION_BYTES_MIN: u64 = 64 * 1024;
                /// Hard production ceiling for one canonical signed completion transaction.
                ///
                /// Two retained copies plus structural state still fit beneath
                /// the 192 MiB checkpoint ceiling at this 64 MiB limit.
                pub const MAX_SIGNED_TRANSACTION_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
                /// Maximum canonical signed completion transaction size.
                pub const MAX_SIGNED_TRANSACTION_BYTES: Bytes = Bytes(256 * 1024);
                /// Maximum payload-free rows returned by one status page.
                pub const MAX_STATUS_PAGE_SIZE: usize = 256;
                /// Conservatively bound a full canonical outbox checkpoint.
                ///
                /// Each active entry can retain both an unsigned
                /// `expected_payload` and the complete `signed_transaction`.
                /// Every conversion and addition is checked so impossible
                /// deployment policies fail closed instead of wrapping.
                #[must_use]
                pub fn worst_case_checkpoint_bytes_v1(
                    max_active_entries: usize,
                    max_terminal_entries: usize,
                    max_signed_transaction_bytes: u64,
                ) -> Option<u64> {
                    let active_entries = u64::try_from(max_active_entries).ok()?;
                    let terminal_entries = u64::try_from(max_terminal_entries).ok()?;
                    let retained_active_payload_bytes =
                        max_signed_transaction_bytes.checked_mul(2)?;
                    let active_entry_bytes = retained_active_payload_bytes
                        .checked_add(ACTIVE_ENTRY_CANONICAL_OVERHEAD_BYTES_V1)?;
                    let active_bytes = active_entries.checked_mul(active_entry_bytes)?;
                    let terminal_bytes =
                        terminal_entries.checked_mul(TERMINAL_ENTRY_CANONICAL_OVERHEAD_BYTES_V1)?;
                    CHECKPOINT_CANONICAL_OVERHEAD_BYTES_V1
                        .checked_add(active_bytes)?
                        .checked_add(terminal_bytes)
                }
            }
        }
        /// Defaults for the durable admission-bound PDP provider protocol.
        pub mod pdp_provider {
            use iroha_config_base::util::Bytes;
            /// Maximum pending challenges retained by one provider runtime.
            pub const MAX_PENDING_RECORDS: u32 = 4_096;
            /// Maximum compact terminal replay records retained by one provider runtime.
            pub const MAX_TERMINAL_RECORDS: u32 = 65_536;
            /// Maximum canonical durable checkpoint size.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(128 * 1024 * 1024);
            /// Maximum canonical challenge payload size.
            pub const CHALLENGE_MAX_BYTES: Bytes = Bytes(512 * 1024);
            /// Maximum canonical proof payload size.
            pub const PROOF_MAX_BYTES: Bytes = Bytes(16 * 1024 * 1024);
            /// Minimum governed response window in seconds.
            pub const MIN_RESPONSE_WINDOW_SECS: u64 = 4 * 60;
            /// Maximum governed response window in seconds.
            pub const MAX_RESPONSE_WINDOW_SECS: u64 = 10 * 60;
            /// Maximum provider timestamp skew ahead of server time in seconds.
            pub const MAX_FUTURE_SKEW_SECS: u64 = 5;
            /// Minimum compact terminal replay retention in seconds.
            pub const TERMINAL_RETENTION_SECS: u64 = 24 * 60 * 60;
        }
        /// Maximum replay events retained for each embedded runtime event stream.
        pub const RUNTIME_EVENT_HISTORY_LIMIT: usize = 4_096;
        /// Maximum entries retained in each auxiliary runtime state index.
        pub const RUNTIME_STATE_ENTRY_LIMIT: usize = 65_536;
        /// First-release hard ceiling shared by node and Torii PoR projections.
        pub const RUNTIME_STATE_ENTRY_LIMIT_MAX: usize = 65_536;
        /// Maximum encoded size accepted for one auxiliary runtime checkpoint.
        pub const RUNTIME_CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
        /// Finalized reconciliation cadence for durable proof-outcome delivery.
        pub const RUNTIME_PROOF_OUTCOME_FORWARDER_INTERVAL_MS: std::num::NonZeroU64 =
            nonzero_ext::nonzero!(1_000_u64);
        /// Submission attempts allowed for one exact proof-outcome transaction.
        pub const RUNTIME_PROOF_OUTCOME_MAX_ATTEMPTS: std::num::NonZeroU32 =
            nonzero_ext::nonzero!(8_u32);
        /// Default telemetry alias advertised by the node.
        pub fn alias() -> Option<String> {
            None
        }
        /// Default SoraFS availability tier string.
        pub fn advert_availability() -> String {
            "hot".to_string()
        }
        /// Default upper bound on retrieval latency advertised in telemetry (milliseconds).
        pub const ADVERT_MAX_LATENCY_MS: u32 = 500;
        /// Default rendezvous topics advertised when none are provided.
        pub fn advert_topics() -> Vec<String> {
            vec!["sorafs.sf1.primary:universal".to_string()]
        }
        /// Default filesystem directory for governance artefacts.
        pub fn governance_dir() -> Option<PathBuf> {
            None
        }
        /// Default Governance DAG publisher peer identifier.
        pub fn governance_publisher_peer_id() -> Option<String> {
            None
        }
        /// Always-on Governance DAG public publisher defaults.
        pub mod governance_dag_service {
            use iroha_config_base::util::Bytes;
            use std::path::PathBuf;
            /// The public publisher is opt-in until endpoints and secret paths are configured.
            pub const ENABLED: bool = false;
            /// Head publication mode (`signed_http` or `ipns`).
            pub const HEAD_MODE: &str = "signed_http";
            /// Poll interval for filesystem feed reconciliation.
            pub const POLL_INTERVAL_SECS: u64 = 5;
            /// Endpoint TCP/TLS connection timeout.
            pub const CONNECT_TIMEOUT_MS: u64 = 3_000;
            /// End-to-end HTTP request timeout.
            pub const REQUEST_TIMEOUT_MS: u64 = 15_000;
            /// DNS lookup timeout before a client is built with pinned addresses.
            pub const DNS_TIMEOUT_MS: u64 = 2_000;
            /// Maximum accepted remote response body.
            pub const MAX_RESPONSE_BYTES: Bytes = Bytes(4 * 1024 * 1024);
            /// Maximum local block, head, CAR, or block-prefix archive request.
            ///
            /// Covers the canonical block ceiling (128 MiB plus a 64 KiB
            /// signature allowance), the 1 MiB archive wrapper, and 64 KiB
            /// of deterministic multipart framing.
            pub const MAX_REQUEST_BYTES: Bytes = Bytes((129 * 1024 * 1024) + (128 * 1024));
            /// Maximum future clock skew accepted for blocks and heads.
            pub const MAX_FUTURE_SKEW_SECS: u64 = 60;
            /// Maximum lifetime accepted for one signed outbound request envelope.
            pub const REQUEST_AUTH_MAX_ENVELOPE_LIFETIME_SECS: u64 = 30;
            /// Maximum future clock skew accepted for an outbound request envelope.
            pub const REQUEST_AUTH_MAX_FUTURE_SKEW_SECS: u64 = 5;
            /// Hard upper bound for a configured outbound request-envelope lifetime.
            pub const REQUEST_AUTH_MAX_ENVELOPE_LIFETIME_LIMIT_SECS: u64 = 300;
            /// Hard upper bound for configured outbound request future clock skew.
            pub const REQUEST_AUTH_MAX_FUTURE_SKEW_LIMIT_SECS: u64 = 60;
            /// HTTPS is required by default.
            pub const ALLOW_INSECURE_HTTP: bool = false;
            /// Publicly routable IPFS API addresses are required by default.
            pub const ALLOW_PRIVATE_IPFS_ENDPOINT: bool = false;
            /// Publicly routable signed-head addresses are required by default.
            pub const ALLOW_PRIVATE_HEAD_ENDPOINT: bool = false;
            /// Existing public state must be resolved unless initial bootstrap is explicit.
            pub const ALLOW_HEAD_BOOTSTRAP: bool = false;
            /// Default loopback status/query listener.
            pub const LISTEN_ADDR: &str = "127.0.0.1:9094";
            /// Optional service state directory.
            pub fn state_dir() -> Option<PathBuf> {
                None
            }
        }
        /// Durable native orderbook transaction worker defaults.
        pub mod orderbook_worker {
            use iroha_config_base::util::Bytes;
            use nonzero_ext::nonzero;
            use std::num::{NonZeroU32, NonZeroU64};
            /// New work generation is opt-in; storage enablement still activates durable drain.
            pub const ENABLED: bool = false;
            /// Finalized-state scan cadence.
            pub const SCAN_INTERVAL_MS: NonZeroU64 = nonzero!(1_000_u64);
            /// Maximum fills requested by one native match transaction.
            pub const MATCH_BATCH_LIMIT: NonZeroU32 = nonzero!(64_u32);
            /// Maximum expiries/closures requested by one native maintenance transaction.
            pub const MAINTENANCE_BATCH_LIMIT: NonZeroU32 = nonzero!(128_u32);
            /// Maximum pending semantic operations retained durably.
            pub const MAX_PENDING: NonZeroU32 = nonzero!(4_096_u32);
            /// Maximum finalized idempotency tombstones retained durably.
            pub const MAX_COMPLETED: NonZeroU32 = nonzero!(65_536_u32);
            /// Maximum terminal dead letters retained durably.
            pub const MAX_DEAD_LETTERS: NonZeroU32 = nonzero!(4_096_u32);
            /// Maximum signing/submission attempts for one semantic operation.
            pub const MAX_ATTEMPTS: NonZeroU32 = nonzero!(8_u32);
            /// Maximum canonical durable checkpoint size.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
            /// Minimum supported finalized-state scan cadence.
            pub const SCAN_INTERVAL_MIN_MS: u64 = 100;
            /// Maximum supported finalized-state scan cadence.
            pub const SCAN_INTERVAL_MAX_MS: u64 = 60_000;
            /// Hard ceiling for pending semantic operations.
            pub const MAX_PENDING_LIMIT: u32 = 65_536;
            /// Hard ceiling for finalized idempotency tombstones.
            pub const MAX_COMPLETED_LIMIT: u32 = 262_144;
            /// Hard ceiling for terminal dead letters.
            pub const MAX_DEAD_LETTERS_LIMIT: u32 = 65_536;
            /// Hard ceiling for attempts under one semantic identity.
            pub const MAX_ATTEMPTS_LIMIT: u32 = 64;
            /// Smallest checkpoint able to retain one maximum V1 transaction plus metadata.
            pub const CHECKPOINT_MIN_BYTES: u64 = 4 * 1024 * 1024;
            /// Hard ceiling for one canonical durable checkpoint.
            pub const CHECKPOINT_MAX_BYTES_LIMIT: u64 = 512 * 1024 * 1024;
        }
        /// Durable native reserve/rent transaction worker defaults.
        pub mod reserve_worker {
            use iroha_config_base::util::Bytes;
            use nonzero_ext::nonzero;
            use std::num::{NonZeroU32, NonZeroU64};
            /// New work generation is opt-in; storage enablement still activates durable drain.
            pub const ENABLED: bool = false;
            /// Finalized-state scan cadence.
            pub const SCAN_INTERVAL_MS: NonZeroU64 = nonzero!(1_000_u64);
            /// Maximum durable operations inspected in one fair scan.
            pub const SCAN_BATCH_LIMIT: NonZeroU32 = nonzero!(128_u32);
            /// Maximum pending semantic operations retained durably.
            pub const MAX_PENDING: NonZeroU32 = nonzero!(4_096_u32);
            /// Maximum finalized idempotency tombstones retained durably.
            pub const MAX_COMPLETED: NonZeroU32 = nonzero!(65_536_u32);
            /// Maximum terminal dead letters retained durably.
            pub const MAX_DEAD_LETTERS: NonZeroU32 = nonzero!(4_096_u32);
            /// Maximum signing/submission attempts for one semantic operation.
            pub const MAX_ATTEMPTS: NonZeroU32 = nonzero!(8_u32);
            /// Maximum canonical durable checkpoint size.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
            /// Minimum supported finalized-state scan cadence.
            pub const SCAN_INTERVAL_MIN_MS: u64 = 100;
            /// Maximum supported finalized-state scan cadence.
            pub const SCAN_INTERVAL_MAX_MS: u64 = 60_000;
            /// Hard ceiling for operations inspected in one scan.
            pub const SCAN_BATCH_LIMIT_MAX: u32 = 1_000;
            /// Hard ceiling for pending semantic operations.
            pub const MAX_PENDING_LIMIT: u32 = 65_536;
            /// Hard ceiling for finalized idempotency tombstones.
            pub const MAX_COMPLETED_LIMIT: u32 = 262_144;
            /// Hard ceiling for terminal dead letters.
            pub const MAX_DEAD_LETTERS_LIMIT: u32 = 65_536;
            /// Hard ceiling for attempts under one semantic identity.
            pub const MAX_ATTEMPTS_LIMIT: u32 = 64;
            /// Smallest checkpoint able to retain one maximum V1 transaction plus metadata.
            pub const CHECKPOINT_MIN_BYTES: u64 = 4 * 1024 * 1024;
            /// Hard ceiling for one canonical durable checkpoint.
            pub const CHECKPOINT_MAX_BYTES_LIMIT: u64 = 512 * 1024 * 1024;
        }
        /// Privacy aggregate scheduler defaults.
        pub mod privacy_aggregates {
            /// Enable config-backed SFM-4c privacy aggregate scheduling.
            pub const ENABLED: bool = false;
            /// Default privacy aggregate cycle width (seconds).
            pub const CYCLE_SECONDS: u64 = 7 * 24 * 60 * 60;
            /// Governed first cycle start. Disabled by default; production must
            /// set a nonzero cycle-aligned Unix timestamp before enabling.
            pub const FIRST_CYCLE_START_UNIX: u64 = 0;
            /// Default delay after a cycle closes before publication (seconds).
            pub const PUBLISH_DELAY_SECONDS: u64 = 60 * 60;
            /// Public aggregate identifier prefix.
            pub const AGGREGATE_ID_PREFIX: &str = "sfm4c-cycle";
            /// Governed V1 privacy mode.
            pub const PRIVACY_MODE: &str = "differential_privacy_with_suppression";
            /// Reduced governed epsilon numerator.
            pub const EPSILON_NUMERATOR: u64 = 4;
            /// Reduced governed epsilon denominator.
            pub const EPSILON_DENOMINATOR: u64 = 5;
            /// Maximum contribution from one private subject to one metric.
            pub const PER_SUBJECT_METRIC_CAP: u64 = 1;
            /// Minimum distinct-subject count required for publication.
            pub const SUPPRESSION_THRESHOLD: u64 = 25;
            /// Reduced numerator of the durable composed-epsilon budget.
            pub const COMPOSITION_BUDGET_EPSILON_NUMERATOR: u64 = 12;
            /// Reduced denominator of the durable composed-epsilon budget.
            pub const COMPOSITION_BUDGET_EPSILON_DENOMINATOR: u64 = 1;
            /// Maximum publications retained under one composition-budget policy.
            pub const COMPOSITION_BUDGET_MAX_PUBLICATIONS: u64 = 52;
            /// Stable governed query identity. Production enables the
            /// scheduler only after setting a reviewed nonzero digest.
            pub fn query_id_hex() -> Option<String> {
                None
            }
            /// Governed privacy-policy digest. Production enables the scheduler
            /// only after setting this to a reviewed 32-byte lowercase hex value.
            pub fn policy_digest_hex() -> Option<String> {
                None
            }
            /// Deployment-owned fused privacy publisher handle.
            ///
            /// Production must set this together with the exact provider
            /// revision and public-policy digest before enabling the scheduler.
            pub fn fenced_privacy_publisher_handle() -> Option<String> {
                None
            }
            /// Deployment-owned fused privacy publisher revision.
            pub const fn fenced_privacy_publisher_revision() -> Option<u64> {
                None
            }
            /// Deployment-owned fused privacy publisher public-policy digest.
            pub fn fenced_privacy_publisher_policy_digest_hex() -> Option<String> {
                None
            }
        }
        /// Production SFM-4b3 evidence-viewer defaults.
        pub mod evidence_viewer {
            use iroha_config_base::util::Bytes;
            use std::path::PathBuf;
            /// Evidence viewing is disabled until every runtime security
            /// boundary and governed identity is injected.
            pub const ENABLED: bool = false;
            /// Maximum session lifetime in milliseconds.
            pub const SESSION_TTL_MS: u64 = 5 * 60 * 1_000;
            /// Rotating bearer-grant lifetime in milliseconds.
            pub const GRANT_TTL_MS: u64 = 60 * 1_000;
            /// WebAuthn challenge lifetime in milliseconds.
            pub const CHALLENGE_TTL_MS: u64 = 2 * 60 * 1_000;
            /// Maximum authenticated plaintext bytes per range request.
            pub const MAX_RANGE_BYTES: Bytes = Bytes(4 * 1024 * 1024);
            /// Maximum retained single-use challenges.
            pub const MAX_CHALLENGES: u32 = 65_536;
            /// Maximum retained case-bound sessions and hold/erasure records.
            pub const MAX_SESSIONS: u32 = 65_536;
            /// Maximum retained signed hash-chain receipts.
            pub const MAX_RECEIPTS: u32 = 1_000_000;
            /// Maximum retained idempotency tombstones.
            pub const MAX_IDEMPOTENCY_RECORDS: u32 = 1_000_000;
            /// Maximum canonical checkpoint size.
            pub const CHECKPOINT_MAX_BYTES: Bytes = Bytes(64 * 1024 * 1024);
            /// Retention interval after the last session expires.
            pub const RETENTION_AFTER_EXPIRY_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
            /// Cadence for the supervised immutable-archive compaction worker.
            pub const COMPACTION_INTERVAL_MS: u64 = 60 * 1_000;
            /// Maximum expired records archived by one compaction tick.
            pub const COMPACTION_MAX_RECORDS: u32 = 256;
            /// Default local checkpoint cache used only while the service is disabled.
            pub fn checkpoint_path() -> PathBuf {
                PathBuf::from("./storage/sorafs/moderation/evidence-viewer.norito")
            }
        }
        /// Evidence-viewer audit-report scheduler defaults.
        pub mod evidence_viewer_audits {
            /// Enable config-backed SFM-4b3 evidence-viewer audit-report scheduling.
            pub const ENABLED: bool = false;
            /// Default evidence-viewer audit-report cycle width (seconds).
            pub const CYCLE_SECONDS: u64 = 24 * 60 * 60;
            /// Default delay after a cycle closes before publication (seconds).
            pub const PUBLISH_DELAY_SECONDS: u64 = 60 * 60;
        }
        /// Stream token issuance defaults.
        pub mod tokens {
            /// Complete native stream-token transaction observation timeout.
            pub const NATIVE_TRANSACTION_TIMEOUT_MS: u64 = 30_000;
            /// Software host-clock uncertainty checked at both eligibility endpoints.
            pub const CLOCK_UNCERTAINTY_MS: u64 = 250;
            /// Enable gateway-issued stream tokens.
            pub const ENABLED: bool = false;
            /// Default TTL applied to issued tokens (seconds).
            pub const DEFAULT_TTL_SECS: u64 = 900; // 15 minutes
            /// Default maximum concurrent streams permitted per token.
            pub const DEFAULT_MAX_STREAMS: u16 = 4;
            /// Default sustained throughput budget (bytes per second).
            pub const DEFAULT_RATE_LIMIT_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB/s
            /// Default allowed requests per minute for token refresh.
            pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 120;
            /// Durable callback row and local queued/reserved cleanup ticket ceiling.
            pub const ADMISSION_MAX_PENDING: u32 = 65_536;
            /// Maximum active token quota windows admitted by native consensus.
            pub const ADMISSION_MAX_TRACKED_TOKENS: u32 = 65_536;
            /// Maximum ordered callback rows replayed by one reconciliation tick.
            pub const ADMISSION_RECONCILE_MAX_ITEMS: u32 = 256;
            /// Absolute native gateway admission and callback/Serving operation budget.
            pub const ADMISSION_OPERATION_TIMEOUT_MS: u64 = 30_000;
            /// Supervised native callback reconciliation cadence in milliseconds.
            pub const ADMISSION_RECONCILE_INTERVAL_MS: u64 = 1_000;
            /// Maximum lifetime of one consensus-owned concurrency lease.
            pub const ADMISSION_LEASE_TTL_MS: u64 = 120_000;
        }
    }
    /// Defaults for native SoraFS repair workers and transaction forwarding.
    pub mod repair {
        /// Maximum total authenticated remote repair duration in milliseconds.
        pub const SOURCE_TIMEOUT_MS: u64 = 60_000;
        /// Enable native repair processing (disabled by default).
        pub const ENABLED: bool = false;
        /// Default native claim lease duration (seconds).
        pub const CLAIM_TTL_SECS: u64 = 15 * 60;
        /// Native claim renewal lead time (seconds).
        pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;
        /// Maximum transaction forwarding attempts before dead-lettering.
        pub const MAX_ATTEMPTS: u32 = 3;
        /// Hard ceiling for transaction forwarding attempts under one repair operation.
        pub const MAX_ATTEMPTS_LIMIT: u32 = 64;
        /// Concurrent native repair executions per node.
        pub const WORKER_CONCURRENCY: usize = 4;
        /// Hard ceiling for concurrent native repair executions per node.
        pub const WORKER_CONCURRENCY_LIMIT: usize = 64;
    }
    /// Defaults for the SoraFS GC scheduler configuration.
    pub mod gc {
        use std::path::PathBuf;
        /// Enable the GC worker (disabled by default).
        pub const ENABLED: bool = false;
        /// Optional directory for durable GC state.
        pub fn state_dir() -> Option<PathBuf> {
            None
        }
        /// GC cadence (seconds).
        pub const INTERVAL_SECS: u64 = 15 * 60;
        /// Maximum deletions per GC run.
        pub const MAX_DELETIONS_PER_RUN: u32 = 500;
        /// Grace window for retention expiry (seconds).
        pub const RETENTION_GRACE_SECS: u64 = 24 * 60 * 60;
    }
    /// Defaults for the Proof-of-Retrievability coordinator runtime.
    pub mod por {
        use std::path::PathBuf;
        /// Enable the PoR coordinator runtime.
        ///
        pub const ENABLED: bool = false;
        /// Length of a PoR epoch (seconds).
        pub const EPOCH_INTERVAL_SECS: u64 = 60 * 60;
        /// Response window allowed for proofs (seconds).
        pub const RESPONSE_WINDOW_SECS: u64 = 15 * 60;
        /// Minimum number of trusted operator/auditor signatures on a verdict.
        pub const AUDITOR_SIGNATURE_THRESHOLD: u16 = 1;
        /// Required strict-majority drand endpoint agreement.
        pub const DRAND_QUORUM: u16 = 2;
        /// Maximum configured drand endpoint count.
        pub const DRAND_MAX_ENDPOINTS: usize = 8;
        /// Drand connection timeout in milliseconds.
        pub const DRAND_CONNECT_TIMEOUT_MS: u64 = 3_000;
        /// Drand request timeout in milliseconds.
        pub const DRAND_REQUEST_TIMEOUT_MS: u64 = 5_000;
        /// Maximum accepted drand response body size.
        pub const DRAND_MAX_BODY_BYTES: usize = 4 * 1024;
        /// Maximum age of a verified drand beacon.
        pub const DRAND_MAX_BEACON_AGE_SECS: u64 = 30;
        /// Maximum tolerated local-clock future skew.
        pub const DRAND_MAX_FUTURE_SKEW_SECS: u64 = 3;
        /// Deadline within an epoch for authenticated provider VRF submissions.
        pub const VRF_SUBMISSION_DEADLINE_SECS: u64 = 5 * 60;
        /// Maximum durable VRF submission count.
        pub const VRF_MAX_ENTRIES: usize = 65_536;
        /// Number of epochs for which accepted VRFs/replay state remain live.
        pub const VRF_RETENTION_EPOCHS: u64 = 7 * 24;
        /// Maximum accepted clock skew for signed VRF submissions.
        pub const VRF_MAX_CLOCK_SKEW_SECS: u64 = 60;
        /// Canonical PoR coordinator snapshot filename.
        pub const COORDINATOR_STATE_FILE: &str = "por-coordinator.to";
        /// Canonical verified drand high-water filename.
        pub const DRAND_STATE_FILE: &str = "drand-high-water.to";
        /// Canonical authenticated provider VRF state filename.
        pub const VRF_STATE_FILE: &str = "provider-vrf-state.to";
        /// Default private directory for PoR coordinator, drand, and VRF state.
        pub fn state_dir() -> PathBuf {
            PathBuf::from("./storage/sorafs/por")
        }
        /// Durable PoR coordinator snapshot path.
        pub fn coordinator_state_path() -> PathBuf {
            state_dir().join(COORDINATOR_STATE_FILE)
        }
        /// Durable verified drand high-water state path.
        pub fn drand_state_path() -> PathBuf {
            state_dir().join(DRAND_STATE_FILE)
        }
        /// Durable authenticated provider VRF state path.
        pub fn vrf_state_path() -> PathBuf {
            state_dir().join(VRF_STATE_FILE)
        }
    }
    /// Defaults for the SoraFS gateway policy and automation surface.
    pub mod gateway {
        /// Require clients to attach the manifest envelope before serving data.
        pub const REQUIRE_MANIFEST_ENVELOPE: bool = true;
        /// Enforce admission registry membership by default.
        pub const ENFORCE_ADMISSION: bool = true;
        /// Enforce advertised capabilities (e.g., chunk-range fetch) before serving data.
        pub const ENFORCE_CAPABILITIES: bool = true;
        /// Enable per-CID untrusted host routing.
        pub const UNTRUSTED_HOSTING_ENABLED: bool = false;
        /// Redirect browser path-gateway requests to the canonical CID host.
        pub const PATH_GATEWAY_REDIRECT: bool = true;
        /// Limit canonical redirects to browser HTML navigations.
        pub const REDIRECT_HTML_ONLY: bool = true;
        /// Static-site host binding file defaults.
        pub mod site_bindings {
            use iroha_config_base::util::Bytes;
            use nonzero_ext::nonzero;
            use std::{num::NonZeroUsize, path::PathBuf};
            /// Optional JSON binding document loaded and validated when Torii starts.
            #[must_use]
            pub fn path() -> Option<PathBuf> {
                None
            }
            /// Maximum encoded binding-document size accepted at startup.
            pub const MAX_BYTES: Bytes = Bytes(1024 * 1024);
            /// Maximum number of named host bindings accepted at startup.
            pub const MAX_SITES: NonZeroUsize = nonzero!(1024usize);
        }
        /// Rate-limiting defaults applied to gateway clients.
        pub mod rate_limit {
            use std::time::Duration;
            /// Maximum burst and tokens replenished per window.
            pub const MAX_REQUESTS: Option<u32> =
                Some(crate::parameters::defaults::torii::DEFAULT_REQUEST_RATE_PER_MINUTE);
            /// Time required to replenish the complete token budget.
            pub const WINDOW: Duration = Duration::from_secs(60);
            /// Temporary ban duration applied after repeated violations.
            pub const BAN: Option<Duration> = Some(Duration::from_secs(30));
        }
        /// Default staged anonymity policy applied to SoraNet transports.
        pub const DEFAULT_ANONYMITY_POLICY: &str = "anon-guard-pq";
        /// Default rollout phase label for the staged PQ activation.
        pub const DEFAULT_ROLLOUT_PHASE: &str = "canary";
        /// Returns the default rollout phase label.
        #[must_use]
        pub fn rollout_phase() -> String {
            DEFAULT_ROLLOUT_PHASE.to_string()
        }
        /// Returns the default staged anonymity policy label.
        #[must_use]
        #[allow(clippy::unnecessary_wraps)]
        pub fn anonymity_policy() -> Option<String> {
            Some(DEFAULT_ANONYMITY_POLICY.to_string())
        }
        /// Untrusted-hosting defaults for per-CID browser origins.
        pub mod untrusted_hosting {
            /// Canonical live CID-host suffix.
            pub const LIVE_CID_HOST_SUFFIX: &str = "sorafs.sora.org";
            /// Canonical Taira CID-host suffix.
            pub const TAIRA_CID_HOST_SUFFIX: &str = "sorafs.taira.sora.org";
            /// Return the default live CID-host suffix.
            #[must_use]
            pub fn live_cid_host_suffix() -> String {
                LIVE_CID_HOST_SUFFIX.to_string()
            }
            /// Return the default Taira CID-host suffix.
            #[must_use]
            pub fn taira_cid_host_suffix() -> String {
                TAIRA_CID_HOST_SUFFIX.to_string()
            }
        }
        /// ACME automation defaults.
        pub mod acme {
            use std::time::Duration;
            /// Enable ACME automation for TLS certificates.
            pub const ENABLED: bool = false;
            /// Default account email (unset by default).
            pub fn account_email() -> Option<String> {
                None
            }
            /// Default ACME directory URL (Let’s Encrypt production).
            pub fn directory_url() -> String {
                "https://acme-v02.api.letsencrypt.org/directory".to_string()
            }
            /// Default hostnames covered by the automation (empty list).
            pub fn hostnames() -> Vec<String> {
                Vec::new()
            }
            /// Optional DNS provider plug-in identifier.
            pub fn dns_provider_id() -> Option<String> {
                None
            }
            /// Renewal window applied before certificate expiry (seconds).
            pub const RENEWAL_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
            /// Backoff applied after automation failures (seconds).
            pub const RETRY_BACKOFF: Duration = Duration::from_secs(30 * 60);
            /// Maximum jitter applied to retry scheduling (seconds).
            pub const RETRY_JITTER: Duration = Duration::from_secs(5 * 60);
            /// Solve DNS-01 challenges by default.
            pub const DNS01: bool = true;
            /// Solve TLS-ALPN-01 challenges by default.
            pub const TLS_ALPN_01: bool = true;
            /// Initial ECH enabled state reported via telemetry.
            pub const ECH_ENABLED: bool = false;
        }
        /// Governed compliance-controller defaults.
        pub mod compliance {
            use iroha_config_base::util::Bytes;
            use std::time::Duration;
            /// Stable runtime handle required from the V1 authenticated feed transport.
            pub const GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1: &str =
                "sorafs.gateway.compliance.feed-https.v1";
            /// Exact V1 runtime adapter revision.
            pub const GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1: u64 = 1;
            /// Keep the signed compliance controller disabled until governance
            /// identities, feeds, storage, and a runtime transport are provisioned.
            pub const ENABLED: bool = false;
            /// Maximum encoded feed response.
            pub const MAX_ENCODED_BYTES: Bytes = Bytes(4 * 1024 * 1024);
            /// Maximum normalized/decompressed feed response.
            pub const MAX_DECODED_BYTES: Bytes = Bytes(16 * 1024 * 1024);
            /// Maximum admitted redirect count.
            pub const MAX_REDIRECTS: u8 = 3;
            /// Maximum distinct public DNS answers.
            pub const MAX_DNS_ADDRESSES: usize = 8;
            /// Per-connection feed timeout.
            pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
            /// Total feed operation timeout.
            pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
            /// Maximum accepted timestamp skew.
            pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(
                sorafs_manifest::gateway_compliance::DEFAULT_GATEWAY_COMPLIANCE_MAX_CLOCK_SKEW_SECS,
            );
            /// Maximum age of one source feed at catalog construction.
            pub const MAX_FEED_AGE: Duration = Duration::from_secs(60 * 60);
            /// Maximum signed catalog validity interval.
            pub const MAX_CATALOG_VALIDITY: Duration = Duration::from_secs(2 * 60 * 60);
            /// Maximum durable promotion/rollback history.
            pub const MAX_HISTORY_ENTRIES: usize = 256;
        }
    }
}
/// Torii API defaults (HTTP + query service).
pub mod torii {
    use iroha_config_base::util::Bytes;
    use iroha_data_model::{
        da::types::{BlobClass, GovernanceTag, RetentionPolicy},
        sorafs::pin_registry::StorageClass as SorafsStorageClass,
    };
    use iroha_primitives::numeric::XorQuantity;
    use nonzero_ext::nonzero;
    use std::{
        num::{NonZeroU32, NonZeroUsize},
        path::PathBuf,
        time::Duration,
        vec::Vec,
    };
    /// Maximum inner body carried by the first-release Torii proxy protocol.
    pub const TORII_PROXY_MAX_INNER_BODY_BYTES_V1: u64 = 64_000_000;
    /// Maximum request payload size accepted by Torii (bytes).
    pub const MAX_CONTENT_LEN: Bytes = Bytes(TORII_PROXY_MAX_INNER_BODY_BYTES_V1);
    /// Maximum concurrent physical transaction-ingress compute jobs.
    pub const TRANSACTION_INGRESS_MAX_CONCURRENT_COMPUTE_JOBS: NonZeroUsize = nonzero!(4usize);
    /// Maximum signed transactions accepted by one HTTP batch submission.
    pub const TRANSACTION_INGRESS_MAX_BATCH_TRANSACTIONS: NonZeroUsize = nonzero!(512usize);
    /// Maximum concurrent verified-source compiler working sets.
    pub const VERIFIED_SOURCE_MAX_CONCURRENT_COMPILES: NonZeroUsize = nonzero!(1usize);
    /// First-release upper bound for configured verified-source compiler concurrency.
    pub const VERIFIED_SOURCE_MAX_CONCURRENT_COMPILES_V1: usize = 4;
    /// Absolute deadline for reading one admitted verified-source request body.
    pub const VERIFIED_SOURCE_BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
    /// Idle time before closing unused query subscriptions.
    pub const QUERY_IDLE_TIME: Duration = Duration::from_secs(10);
    /// Capacity of in-memory query result cache for all authorities.
    pub const QUERY_STORE_CAPACITY: NonZeroUsize = nonzero!(128usize);
    /// Per-authority allocation within the query result cache.
    pub const QUERY_STORE_CAPACITY_PER_USER: NonZeroUsize = nonzero!(128usize);
    /// Maximum concurrent query executions admitted by Torii.
    pub const QUERY_MAX_INFLIGHT: NonZeroUsize = nonzero!(256usize);
    /// Maximum concurrent heavy query executions admitted by Torii.
    pub const QUERY_HEAVY_MAX_INFLIGHT: NonZeroUsize = nonzero!(64usize);
    /// Aggregate bytes split between bounded signed-query ingress and fanout working sets.
    pub const QUERY_FANOUT_MAX_RETAINED_BYTES: Bytes = Bytes(512_000_000);
    /// Maximum complete working set owned by one query, independent of aggregate concurrency.
    pub const QUERY_FANOUT_MAX_WORKING_SET_BYTES: Bytes = Bytes(48_000_000);
    /// Persistent SCCP history-node backing, independent of transient query leases.
    pub const SCCP_HISTORY_CACHE_MAX_BYTES: Bytes = Bytes(8_000_000);
    /// Minimum aggregate V1 query-memory pool for four ingress slots plus one fanout.
    pub const QUERY_FANOUT_MIN_POOL_BYTES_V1: u64 = 20_000_000;
    /// Source-derived route/catalogue/key/candidate bytes in one V1 fanout.
    pub const QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1: u64 = 9_562_690;
    /// Variable-size units retained by the conservative V1 pre-body envelope.
    pub const QUERY_FANOUT_PREBODY_UNITS_V1: u64 = 15;
    /// Divisor reserving one quarter of aggregate query memory for ingress.
    pub const QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1: u64 = 4;
    /// Independently admitted signed-query ingress bodies.
    pub const QUERY_MEMORY_INGRESS_SLOTS_V1: u64 = 4;
    /// Source-derived routing catalogue and key-validation scratch for one ingress body.
    pub const QUERY_INGRESS_FIXED_OVERHEAD_BYTES_V1: u64 = 1_122_370;
    /// Simultaneously retained variable-size ingress representations.
    pub const QUERY_INGRESS_PHASE_UNITS_V1: u64 = 5;
    /// Source-proven maximum bytes exposed to Hyper by one socket read.
    pub const HTTP_READ_CHUNK_BYTES_V1: u64 = 8 * 1024;
    /// Reserved address-space headroom for fixed internal proxy decode state.
    pub const TORII_PROXY_HTTP_FIXED_MEMORY_HEADROOM_V1: u64 = 64 * 1024 * 1024;
    /// Variable-size representations in the internal proxy HTTP memory envelope.
    pub const TORII_PROXY_HTTP_MEMORY_PHASE_UNITS_V1: u64 = 4;
    /// Maximum time a query waits for execution capacity before Torii rejects it.
    /// A solo proof burst can occupy all heavy-query permits for more than one
    /// second; keep a finite queue deadline below the outer HTTP route timeout.
    pub const QUERY_QUEUE_TIMEOUT_MS: u64 = 30_000;
    /// Absolute deadline for one admitted App routed-read body.
    pub const APP_API_ROUTED_READ_BODY_READ_TIMEOUT_MS: u64 = 10_000;
    /// Derive one complete V1 query working set without increasing its configured ceiling.
    #[must_use]
    pub fn query_fanout_working_set_bytes(
        aggregate_bytes: u64,
        max_working_set_bytes: u64,
        max_content_bytes: u64,
    ) -> Option<u64> {
        let ingress_pool = aggregate_bytes / QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1;
        let fanout_pool = aggregate_bytes.checked_sub(ingress_pool)?;
        let desired = max_content_bytes
            .checked_mul(QUERY_FANOUT_PREBODY_UNITS_V1)?
            .checked_add(QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1)?;
        let working_set = desired.min(max_working_set_bytes).min(fanout_pool);
        (working_set > QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1).then_some(working_set)
    }
    /// Derive the V1 routed-read route-body phase during configuration parsing.
    #[must_use]
    pub fn app_api_routed_read_route_body_phase_bytes(
        aggregate_bytes: u64,
        max_working_set_bytes: u64,
        max_content_bytes: u64,
    ) -> Option<u64> {
        query_fanout_working_set_bytes(aggregate_bytes, max_working_set_bytes, max_content_bytes)?
            .checked_sub(QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1)
            .map(|remaining| remaining / QUERY_FANOUT_PREBODY_UNITS_V1)
            .filter(|phase| *phase > 1)
    }
    /// Derive the complete independently reserved V1 ingress phase.
    #[must_use]
    pub fn query_ingress_body_phase_bytes(
        aggregate_bytes: u64,
        max_working_set_bytes: u64,
        max_content_bytes: u64,
    ) -> Option<u64> {
        let fanout_phase = app_api_routed_read_route_body_phase_bytes(
            aggregate_bytes,
            max_working_set_bytes,
            max_content_bytes,
        )?;
        let ingress_slot_bytes =
            aggregate_bytes / QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1 / QUERY_MEMORY_INGRESS_SLOTS_V1;
        ingress_slot_bytes
            .checked_sub(QUERY_INGRESS_FIXED_OVERHEAD_BYTES_V1)
            .map(|remaining| {
                (remaining / QUERY_INGRESS_PHASE_UNITS_V1)
                    .min(max_content_bytes)
                    .min(fanout_phase)
            })
            .filter(|phase| *phase > 0)
    }
    // Request-rate budgets accommodate sustained application traffic and large
    // deployment/proof walks. Actual work is bounded separately by admission,
    // memory, payload and execution limits.
    /// Shared steady-state HTTP request budget; rate tokens do not reserve memory.
    pub const DEFAULT_REQUEST_RATE_PER_SEC: u32 = 1_000_000;
    /// Minute-based form of the shared HTTP request budget.
    pub const DEFAULT_REQUEST_RATE_PER_MINUTE: u32 = 60 * DEFAULT_REQUEST_RATE_PER_SEC;
    /// Shared HTTP burst budget for clients, wallets and tooling behind one origin.
    pub const DEFAULT_REQUEST_BURST: u32 = 10_000_000;
    /// Default steady-state query rate tokens issued per authority every second.
    pub const QUERY_RATE_PER_AUTHORITY_PER_SEC: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Maximum burst tokens accumulated per authority.
    pub const QUERY_BURST_PER_AUTHORITY: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Default steady-state transaction submission rate tokens per authority every second.
    pub const TX_RATE_PER_AUTHORITY_PER_SEC: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Default transaction submission burst tokens per authority.
    pub const TX_BURST_PER_AUTHORITY: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Default steady-state deploy rate tokens issued per origin every second.
    pub const DEPLOY_RATE_PER_ORIGIN_PER_SEC: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Maximum burst tokens accumulated per origin for deploy endpoints.
    pub const DEPLOY_BURST_PER_ORIGIN: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Default public Soracloud local-read rate per remote IP every second.
    pub const SORACLOUD_PUBLIC_RATE_PER_IP_PER_SEC: Option<u32> =
        Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Default public Soracloud local-read burst capacity per remote IP.
    pub const SORACLOUD_PUBLIC_BURST_PER_IP: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Default maximum number of concurrent public Soracloud local-read executions.
    pub const SORACLOUD_PUBLIC_MAX_INFLIGHT: NonZeroUsize = nonzero!(32usize);
    /// Maximum hosted Soracloud response body buffered for P2P proxy forwarding.
    pub const SORACLOUD_PUBLIC_MAX_RESPONSE_BYTES: Bytes = Bytes(64 * 1024 * 1024);
    /// Default signed Soracloud mutation rate per account+origin every second.
    pub const SORACLOUD_MUTATION_RATE_PER_ACCOUNT_ORIGIN_PER_SEC: Option<u32> =
        Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Default signed Soracloud mutation burst per account+origin.
    pub const SORACLOUD_MUTATION_BURST_PER_ACCOUNT_ORIGIN: Option<u32> =
        Some(DEFAULT_REQUEST_BURST);
    /// Default maximum number of concurrent signed Soracloud mutation executions.
    pub const SORACLOUD_MUTATION_MAX_INFLIGHT: NonZeroUsize = nonzero!(64usize);
    /// Maximum body size for signed Soracloud control-plane mutations before signature verification.
    pub const SORACLOUD_MUTATION_MAX_BODY_BYTES: Bytes = Bytes(8 * 1024 * 1024);
    /// Steady-state proof endpoint rate (requests per minute). None disables.
    pub const PROOF_RATE_PER_MIN: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_MINUTE);
    /// Burst tokens for proof endpoints (requests).
    pub const PROOF_BURST: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Maximum proof request payload size (bytes).
    pub const PROOF_MAX_BODY_BYTES: Bytes = Bytes(8 * 1024 * 1024); // 8 MiB
    /// Maximum proof-bearing request bodies buffered concurrently before handler admission.
    pub const PROOF_BODY_MAX_INFLIGHT: NonZeroUsize = nonzero!(8usize);
    /// Absolute deadline for reading one admitted proof-bearing request body.
    pub const PROOF_BODY_READ_TIMEOUT_MS: u64 = 15_000;
    /// Steady-state egress budget for proof responses (bytes/sec). None disables.
    pub const PROOF_EGRESS_BYTES_PER_SEC: Option<u64> = Some(256 * 1024 * 1024); // 256 MiB/s
    /// Burst egress budget for proof responses (bytes).
    ///
    /// Allows long finality walks and large proof responses without an artificial
    /// per-client bandwidth bottleneck. This is a token budget, not an allocation.
    pub const PROOF_EGRESS_BURST_BYTES: Option<u64> = Some(1024 * 1024 * 1024); // 1 GiB
    /// Maximum page size accepted by proof listing endpoints.
    pub const PROOF_MAX_LIST_LIMIT: u32 = 200;
    /// Wall-clock timeout applied to proof list/count handlers (milliseconds).
    pub const PROOF_REQUEST_TIMEOUT_MS: u64 = 1_000;
    /// Cache lifetime advertised for proof lookups (seconds).
    pub const PROOF_CACHE_MAX_AGE_SECS: u64 = 30;
    /// Retry hint advertised when proof endpoints are throttled (seconds).
    pub const PROOF_RETRY_AFTER_SECS: u64 = 1;
    /// Default global pre-auth connection cap (pre-RLIMIT clamp).
    pub const PREAUTH_MAX_CONNECTIONS: Option<NonZeroUsize> = Some(nonzero!(1024usize));
    /// Default per-IP pre-auth connection cap, including bounded query waiters.
    /// A solo client's next heavy-query wave must reach the execution queue.
    pub const PREAUTH_MAX_CONNECTIONS_PER_IP: Option<NonZeroUsize> = Some(nonzero!(256usize));
    /// SoraNet privacy ingestion defaults (disabled until explicitly configured).
    pub mod soranet_privacy_ingest {
        use super::*;
        /// Require an explicit allow-list before accepting signed privacy telemetry.
        pub const ENABLED: bool = false;
        /// Requests per second budget for privacy ingest (None disables).
        pub const RATE_PER_SEC: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_SEC);
        /// Burst budget for privacy ingest (tokens).
        pub const BURST: Option<u32> = Some(DEFAULT_REQUEST_BURST);
        /// CIDR allow-list for privacy ingest (empty => deny).
        pub fn allow_cidrs() -> Vec<String> {
            Vec::new()
        }
    }
    /// Native Bootle/Lantern blind-issuance service defaults.
    pub mod privacy_bootle_lantern_issuer {
        use iroha_config_base::util::Bytes;
        use std::path::PathBuf;
        /// Issuance is opt-in and fails closed without its runtime provider registry.
        pub const ENABLED: bool = false;
        /// Default durable one-shot authorization store directory.
        pub fn state_dir() -> PathBuf {
            PathBuf::from("./storage/privacy_bootle_lantern_issuer")
        }
        /// Default validity window for one authenticated issuance authorization.
        pub const AUTHORIZATION_LIFETIME_BLOCKS: u64 = 300;
        /// Default maximum retained authorization count.
        pub const MAX_RECORDS: usize = 4_096;
        /// Exact worst-case ILS1 reservation for every default authorization slot.
        pub const MAX_TOTAL_BYTES: Bytes = Bytes(3_310 * MAX_RECORDS as u64);
        /// Default terminal-record retention after its authoritative horizon.
        pub const TERMINAL_RETENTION_BLOCKS: u64 = 4_096;
        /// First-release concurrent native-issuance hard ceiling.
        ///
        /// There is deliberately no operational default: an enabled issuer
        /// must choose its deployment-specific bound explicitly.
        pub const MAX_INFLIGHT_HARD: usize = 64;
        /// First-release authorization lifetime hard ceiling.
        pub const AUTHORIZATION_LIFETIME_BLOCKS_MAX: u64 = 4_096;
        /// First-release durable store record-count hard ceiling.
        pub const MAX_RECORDS_HARD: usize = 1_000_000;
        /// Largest canonical ILS1 record, including one exact ILR1 response.
        pub const MAX_RECORD_BYTES: u64 = 3_310;
        /// First-release durable store byte hard ceiling.
        pub const MAX_TOTAL_BYTES_HARD: u64 = MAX_RECORD_BYTES * MAX_RECORDS_HARD as u64;
        /// First-release terminal-retention hard ceiling.
        pub const TERMINAL_RETENTION_BLOCKS_MAX: u64 = u32::MAX as u64;
    }
    /// Peer-telemetry geo lookup defaults (disabled unless explicitly enabled).
    pub mod peer_geo {
        use url::Url;
        /// Master enable switch for peer geo lookups.
        pub const ENABLED: bool = false;
        /// Optional geo endpoint (ip-api compatible). `None` uses the built-in default when enabled.
        pub fn endpoint() -> Option<Url> {
            None
        }
    }
    /// Local limits only; no default issuer, bank, policy, signer or worker is selected.
    pub mod kagemusha_enrollment {
        /// Complete fresh bank observation timeout in milliseconds.
        pub const REQUEST_TIMEOUT_MS: u64 = 5_000;
        /// Complete private platform verification exchange timeout.
        pub const WORKER_EXCHANGE_TIMEOUT_MS: u64 = 60_000;
        /// Maximum concurrent authenticated service requests.
        pub const MAX_INFLIGHT: usize = 16;
    }

    /// Retail recipient lookup defaults (disabled unless routes are configured).
    pub mod recipient_lookup {
        /// HTTP request timeout applied to configured bank Core API lookups.
        pub const REQUEST_TIMEOUT_MS: u64 = 4_000;
        /// Governed FX corridor policy used to authorize retail recipient reads.
        pub const POLICY_ID: &str = "cbuae_aed_sbp_pkr";
        /// Maximum retail recipient route/lookup requests accepted per signer each minute.
        pub const REQUESTS_PER_MINUTE: u32 = super::DEFAULT_REQUEST_RATE_PER_MINUTE;
    }
    /// Operator request-signature defaults for Torii operator endpoints.
    pub mod operator_signatures {
        /// Master enable switch for operator signature authentication.
        pub const ENABLED: bool = true;
        /// Allow the node identity key (from `[common]`) to sign operator requests.
        pub const ALLOW_NODE_KEY: bool = true;
        /// Absolute deadline for collecting one request body before signature verification.
        pub const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        /// Maximum allowed clock skew for signed operator requests (seconds).
        pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
        /// TTL for operator nonces retained for replay detection (seconds).
        pub const NONCE_TTL_SECS: u64 = 300;
        /// Maximum number of nonces held in memory for replay detection.
        pub const REPLAY_CACHE_CAPACITY: usize = 10_000;
        /// Additional operator public keys allowed to sign requests (empty by default).
        pub fn allowed_public_keys() -> Vec<iroha_crypto::PublicKey> {
            Vec::new()
        }
    }
    /// Operator authentication defaults for Torii operator endpoints.
    pub mod operator_auth {
        /// Master enable switch for operator authentication.
        pub const ENABLED: bool = false;
        /// Require mTLS at the ingress tier before allowing operator endpoints.
        pub const REQUIRE_MTLS: bool = false;
        /// Explicit trusted proxy hosts that may assert the forwarded client certificate header.
        pub fn mtls_trusted_proxy_cidrs() -> Vec<String> {
            vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()]
        }
        /// Operator-token allow-list for first-credential bootstrap (empty => none).
        pub fn tokens() -> Vec<String> {
            Vec::new()
        }
        /// Auth attempt rate (per minute). None disables.
        pub const RATE_PER_MIN: Option<u32> = Some(super::DEFAULT_REQUEST_RATE_PER_MINUTE);
        /// Burst budget for auth attempts (tokens).
        pub const BURST: Option<u32> = Some(super::DEFAULT_REQUEST_BURST);
        /// Per-kind capacity for expiry-bound challenges, sessions, and lockout identities.
        pub const EPHEMERAL_STATE_CAPACITY: usize = 4_096;
        /// Maximum accepted per-kind ephemeral-state capacity.
        pub const MAX_EPHEMERAL_STATE_CAPACITY: usize = 65_536;
        /// Maximum number of persisted operator WebAuthn credentials.
        pub const CREDENTIAL_CAPACITY: usize = 64;
        /// Maximum accepted persisted credential capacity.
        pub const MAX_CREDENTIAL_CAPACITY: usize = 1_024;
        /// Maximum number of configured first-credential bootstrap tokens.
        pub const MAX_BOOTSTRAP_TOKENS: usize = 16;
        /// Minimum byte length of a first-credential bootstrap token.
        pub const BOOTSTRAP_TOKEN_MIN_BYTES: usize = 32;
        /// Maximum byte length of a first-credential bootstrap token.
        pub const BOOTSTRAP_TOKEN_MAX_BYTES: usize = 256;
        /// Failures before applying a temporary lockout.
        pub const LOCKOUT_FAILURES: u32 = 5;
        /// Sliding window for lockout failure counts (seconds).
        pub const LOCKOUT_WINDOW_SECS: u64 = 300;
        /// Lockout duration once triggered (seconds).
        pub const LOCKOUT_DURATION_SECS: u64 = 900;
        /// WebAuthn configuration defaults.
        pub mod webauthn {
            /// Master enable switch for WebAuthn.
            pub const ENABLED: bool = true;
            /// Require user verification during assertions.
            pub const REQUIRE_USER_VERIFICATION: bool = true;
            /// Challenge TTL for WebAuthn ceremonies (seconds).
            pub const CHALLENGE_TTL_SECS: u64 = 120;
            /// Session token TTL after successful WebAuthn assertion (seconds).
            pub const SESSION_TTL_SECS: u64 = 900;
            /// Default RP name used in WebAuthn options.
            pub fn rp_name() -> String {
                "Iroha Operator".to_string()
            }
            /// Default user id encoded into WebAuthn options.
            pub fn user_id() -> String {
                "operator".to_string()
            }
            /// Default user name encoded into WebAuthn options.
            pub fn user_name() -> String {
                "operator".to_string()
            }
            /// Default user display name encoded into WebAuthn options.
            pub fn user_display_name() -> String {
                "Iroha Operator".to_string()
            }
            /// Allowed WebAuthn origins (empty => must be configured).
            pub fn origins() -> Vec<String> {
                Vec::new()
            }
            /// Allowed WebAuthn algorithms (COSE labels).
            pub fn allowed_algorithms() -> Vec<String> {
                vec!["es256".to_string(), "ed25519".to_string()]
            }
        }
    }
    /// Webhook destination security defaults for app-facing webhooks.
    pub mod webhook_security {
        /// Master enable switch for webhook destination guard rails.
        pub const ENABLED: bool = true;
        /// CIDR allow-list for webhook destinations (empty => only public IPs are allowed).
        pub fn allow_cidrs() -> Vec<String> {
            Vec::new()
        }
    }
    /// Capacity of the broadcast channel used for Torii events/SSE/webhooks.
    pub const EVENTS_BUFFER_CAPACITY: usize = 10_000;
    /// WebSocket message timeout for Torii event/block streams (milliseconds).
    pub const WS_MESSAGE_TIMEOUT_MS: u64 = 10_000;
    /// Default page size for app-facing list/query endpoints.
    pub const APP_API_DEFAULT_LIST_LIMIT: u32 = 100;
    /// Maximum page size accepted by app-facing list/query endpoints.
    pub const APP_API_MAX_LIST_LIMIT: u32 = 500;
    /// Maximum fetch size accepted by app-facing iterable queries.
    pub const APP_API_MAX_FETCH_SIZE: u32 = 500;
    /// Rate-limiter cost per default-sized page, rounding partial pages up.
    pub const APP_API_RATE_LIMIT_COST_PER_PAGE: u32 = 1;
    /// Canonical request freshness defaults for app-facing signed HTTP requests.
    pub mod app_auth {
        /// Maximum allowed clock skew for signed app requests (seconds).
        pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
        /// TTL for app request nonces retained for replay detection (seconds).
        pub const NONCE_TTL_SECS: u64 = 300;
        /// Maximum number of app request nonces held in memory for replay detection.
        pub const REPLAY_CACHE_CAPACITY: usize = 10_000;
    }
    /// Maximum pending webhook deliveries persisted on disk.
    pub const WEBHOOK_QUEUE_CAPACITY: usize = 10_000;
    /// Maximum delivery attempts before a payload is dropped.
    pub const WEBHOOK_MAX_ATTEMPTS: u32 = 12;
    /// Initial backoff delay (milliseconds) applied to webhook retries.
    pub const WEBHOOK_BACKOFF_INITIAL_MS: u64 = 1_000;
    /// Maximum backoff delay (milliseconds) applied to webhook retries.
    pub const WEBHOOK_BACKOFF_MAX_MS: u64 = 60_000;
    /// HTTP connect timeout (milliseconds) for webhook delivery.
    pub const WEBHOOK_CONNECT_TIMEOUT_MS: u64 = 10_000;
    /// HTTP write timeout (milliseconds) for webhook delivery.
    pub const WEBHOOK_WRITE_TIMEOUT_MS: u64 = 10_000;
    /// HTTP read timeout (milliseconds) for webhook delivery.
    pub const WEBHOOK_READ_TIMEOUT_MS: u64 = 10_000;
    /// Capacity helper for Torii events buffer.
    pub const fn events_buffer_capacity() -> NonZeroUsize {
        nonzero!(EVENTS_BUFFER_CAPACITY)
    }
    /// Queue capacity helper for webhook delivery worker.
    pub const fn webhook_queue_capacity() -> NonZeroUsize {
        nonzero!(WEBHOOK_QUEUE_CAPACITY)
    }
    /// Attempt cap helper for webhook delivery worker.
    pub const fn webhook_max_attempts() -> NonZeroU32 {
        nonzero!(WEBHOOK_MAX_ATTEMPTS)
    }
    /// Enable the push bridge (FCM/APNS). Disabled by default.
    pub const PUSH_ENABLED: bool = false;
    /// Enable push-notification rate limiting.
    pub const PUSH_RATE_LIMIT_ENABLED: bool = true;
    /// Steady-state rate (requests per minute) for push notifications.
    pub const PUSH_RATE_PER_MINUTE: NonZeroU32 = nonzero!(DEFAULT_REQUEST_RATE_PER_MINUTE);
    /// Burst tokens for push notifications.
    pub const PUSH_BURST: NonZeroU32 = nonzero!(DEFAULT_REQUEST_BURST);
    /// HTTP connect timeout (milliseconds) for push delivery.
    pub const PUSH_CONNECT_TIMEOUT_MS: u64 = 5_000;
    /// HTTP request timeout (milliseconds) for push delivery.
    pub const PUSH_REQUEST_TIMEOUT_MS: u64 = 10_000;
    /// Maximum topics recorded per registered device.
    pub const PUSH_MAX_TOPICS_PER_DEVICE: NonZeroUsize = nonzero!(32_usize);
    /// First-release hard ceiling for topics recorded per registered device.
    pub const PUSH_MAX_TOPICS_PER_DEVICE_V1: usize = 256;
    /// Default APNs environment for provider-token delivery.
    pub const PUSH_APNS_ENVIRONMENT: &str = "sandbox";
    /// Base directory for Torii persistence (attachments, webhooks, DA queues).
    pub fn data_dir() -> PathBuf {
        PathBuf::from("./storage/torii")
    }
    // API tokens are disabled by default.
    /// Whether Torii requires API tokens for authentication.
    pub const REQUIRE_API_TOKEN: bool = false;
    /// Maximum number of listener-wide API tokens admitted by first-release configuration.
    pub const API_TOKEN_MAX_COUNT_V1: usize = 256;
    /// Minimum byte length of a listener-wide API token.
    pub const API_TOKEN_MIN_BYTES_V1: usize = 32;
    /// Maximum byte length of a listener-wide API token.
    pub const API_TOKEN_MAX_BYTES_V1: usize = 256;
    /// Faucet defaults.
    pub mod faucet {
        use super::*;
        use std::num::NonZeroU64;
        /// Leading-zero-bit difficulty for faucet proof-of-work.
        ///
        /// Eighteen bits is the fail-safe default for an explicitly enabled
        /// faucet. Operators may select a lower non-zero value for bounded
        /// testnet and local-development deployments.
        pub const POW_DIFFICULTY_BITS: u8 = 18;
        /// Scrypt `log2(N)` cost parameter for faucet proof-of-work.
        pub const POW_SCRYPT_LOG_N: u8 = 13;
        /// Scrypt block size parameter for faucet proof-of-work.
        pub const POW_SCRYPT_R: u32 = 8;
        /// Scrypt parallelization parameter for faucet proof-of-work.
        pub const POW_SCRYPT_P: u32 = 1;
        /// Maximum committed-block age for accepted faucet PoW anchors.
        pub const POW_MAX_ANCHOR_AGE_BLOCKS: NonZeroU64 = nonzero!(6u64);
        /// Number of recent committed blocks to scan for prior faucet claims when adapting difficulty.
        pub const POW_ADAPTIVE_LOOKBACK_BLOCKS: u64 = 0;
        /// Number of recent faucet claims required to add one extra difficulty bit.
        pub const POW_ADAPTIVE_CLAIMS_PER_EXTRA_BIT: u64 = 0;
        /// Maximum number of adaptive difficulty bits added on top of the base difficulty.
        pub const POW_ADAPTIVE_MAX_EXTRA_BITS: u8 = 0;
        /// Whether verified finalized global-beacon seeds are mixed into faucet challenges.
        pub const POW_BEACON_SEED_ENABLED: bool = false;
    }
    // The pre-auth gate charges every external HTTP request. Its default must
    // accommodate the downstream application budgets, including multiple tools
    // or wallets sharing one external IP.
    /// Steady-state rate for pre-authorization attempts per IP.
    pub const PREAUTH_RATE_PER_IP_PER_SEC: Option<u32> = Some(DEFAULT_REQUEST_RATE_PER_SEC);
    /// Burst tokens allowed for pre-authorization attempts per IP.
    pub const PREAUTH_BURST_PER_IP: Option<u32> = Some(DEFAULT_REQUEST_BURST);
    /// Optional extra cooldown after pre-auth rate exhaustion; disabled by default.
    pub const PREAUTH_BAN_DURATION: Duration = Duration::ZERO;
    /// Maximum number of temporary pre-auth bans retained in memory.
    pub const PREAUTH_BAN_CAPACITY: NonZeroUsize = nonzero!(4096usize);
    /// Exact transport source hosts trusted for internal Torii reads and privileged routing.
    pub fn internal_api_trusted_cidrs() -> Vec<String> {
        vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()]
    }
    /// Enable app-facing webhook routes and workers.
    pub const WEBHOOKS_ENABLED: bool = true;
    /// Enable app-facing ZK attachment routes and workers.
    pub const ZK_ATTACHMENTS_ENABLED: bool = true;
    /// Default TTL for app API ZK attachments (seconds)
    pub const ATTACHMENTS_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
    /// Default maximum size per ZK attachment (bytes)
    pub const ATTACHMENTS_MAX_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB
    /// Default maximum number of ZK attachments stored per tenant (0 = unlimited).
    pub const ATTACHMENTS_PER_TENANT_MAX_COUNT: u64 = 128;
    /// Default aggregate attachment bytes per tenant (0 = unlimited).
    pub const ATTACHMENTS_PER_TENANT_MAX_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
    /// Default maximum number of ZK attachments retained by one node.
    pub const ATTACHMENTS_GLOBAL_MAX_COUNT: u64 = 4_096;
    /// Maximum supported node-global attachment count.
    ///
    /// Torii bounds each filesystem-backed quota scan to this many attachment
    /// metadata records and root tenant-directory entries.
    pub const ATTACHMENTS_GLOBAL_MAX_COUNT_MAX: u64 = 20_000;
    /// Default aggregate ZK attachment bytes retained by one node.
    pub const ATTACHMENTS_GLOBAL_MAX_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
    /// Default allowed MIME types for attachment payloads (post-sniff).
    #[must_use]
    pub fn attachments_allowed_mime_types() -> Vec<String> {
        vec![
            "application/x-norito".to_string(),
            "application/json".to_string(),
            "application/x-zk1".to_string(),
        ]
    }
    /// Default maximum expanded bytes when decompressing attachments.
    pub const ATTACHMENTS_MAX_EXPANDED_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
    /// Default maximum archive depth when expanding attachments.
    pub const ATTACHMENTS_MAX_ARCHIVE_DEPTH: u32 = 2;
    /// Default attachment sanitization timeout (milliseconds).
    pub const ATTACHMENTS_SANITIZE_TIMEOUT_MS: u64 = 1_000;
    /// Attachment sanitizer execution mode (`subprocess` or `in_process`).
    pub const ATTACHMENTS_SANITIZER_MODE: &str = "subprocess";
    /// Background ZK prover worker enable flag.
    pub const ZK_PROVER_ENABLED: bool = true;
    /// Background ZK prover scan period (seconds)
    pub const ZK_PROVER_SCAN_PERIOD_SECS: u64 = 30;
    /// Background ZK prover reports retention TTL (seconds)
    pub const ZK_PROVER_REPORTS_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
    /// Maximum number of prover reports retained on disk.
    pub const ZK_PROVER_REPORTS_MAX_COUNT: u64 = 4_096;
    /// Maximum aggregate bytes retained by prover report bodies and summary shards.
    pub const ZK_PROVER_REPORTS_MAX_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB
    /// Maximum bytes in one persisted first-release prover report.
    pub const ZK_PROVER_REPORT_MAX_BYTES_V1: u64 = 8 * 1024 * 1024; // 8 MiB
    /// Maximum bytes in one persisted first-release prover summary shard.
    pub const ZK_PROVER_REPORT_SUMMARY_MAX_BYTES_V1: u64 = 64 * 1024; // 64 KiB
    /// Maximum number of attachments the background prover processes concurrently.
    pub const ZK_PROVER_MAX_INFLIGHT: usize = 2;
    /// Maximum raw body bytes admitted by the first-release prover worker.
    pub const ZK_PROVER_ATTACHMENT_BODY_MAX_BYTES_V1: u64 = 8 * 1024 * 1024; // 8 MiB
    /// Maximum aggregate attachment bytes processed per scan cycle.
    pub const ZK_PROVER_MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
    /// Maximum wall-clock time (milliseconds) spent in a single scan cycle.
    pub const ZK_PROVER_MAX_SCAN_MILLIS: u64 = 2_000;
    /// Directory containing verifying key bytes for the background prover worker.
    #[must_use]
    pub fn zk_prover_keys_dir() -> PathBuf {
        data_dir().join("zk_prover").join("keys")
    }
    /// Maximum concurrent IVM contract simulation and view workers.
    pub const IVM_TOOLING_MAX_INFLIGHT: usize = 1;
    /// Wall-clock timeout for synchronous IVM simulation and view tooling.
    pub const IVM_TOOLING_TIMEOUT_MS: u64 = 60_000;
    /// Allowlisted backend prefixes for the background prover worker.
    #[must_use]
    pub fn zk_prover_allowed_backends() -> Vec<String> {
        vec!["pipa-r/pasta".to_string()]
    }
    /// Allowlisted circuit identifiers for the background prover worker.
    /// Empty list means "allow all circuits".
    #[must_use]
    pub fn zk_prover_allowed_circuits() -> Vec<String> {
        Vec::new()
    }
    /// Emit Torii filter debug traces (developer diagnostics only).
    pub const DEBUG_MATCH_FILTERS: bool = false;
    /// Replay cache capacity per `(lane, epoch)` window.
    pub const DA_REPLAY_CACHE_CAPACITY: NonZeroUsize = nonzero!(4096usize);
    /// Maximum number of distinct `(lane, epoch)` replay windows retained globally.
    pub const DA_REPLAY_CACHE_MAX_LANE_EPOCHS: NonZeroUsize = nonzero!(1024usize);
    /// Replay cache TTL (seconds) applied to observed manifests.
    pub const DA_REPLAY_CACHE_TTL_SECS: u64 = 15 * 60;
    /// Maximum sequence lag tolerated before rejecting manifests.
    pub const DA_REPLAY_CACHE_MAX_SEQUENCE_LAG: u64 = 4_096;
    /// Maximum number of concurrent CPU-intensive DA ingest jobs.
    pub const DA_MAX_CONCURRENT_COMPUTE_JOBS: NonZeroUsize = nonzero!(1usize);
    /// Maximum number of DA spool batches queued for async disk persistence.
    pub const DA_SPOOL_QUEUE_CAPACITY: NonZeroUsize = nonzero!(1024usize);
    /// Maximum number of DA spool batches flushed by one worker write pass.
    pub const DA_SPOOL_BATCH_MAX: NonZeroUsize = nonzero!(32usize);
    /// Default directory for persisted DA replay cursors.
    pub fn da_replay_cache_store_dir() -> PathBuf {
        PathBuf::from("./storage/da_replay")
    }
    /// Default directory for queued DA manifests awaiting SoraFS orchestration.
    pub fn da_manifest_store_dir() -> PathBuf {
        PathBuf::from("./storage/da_manifests")
    }
    /// Governance metadata encryption disabled by default.
    pub fn da_governance_metadata_key() -> Option<[u8; 32]> {
        None
    }
    /// Default governance metadata key label (unused when encryption disabled).
    pub fn da_governance_metadata_key_label() -> Option<String> {
        None
    }
    /// Default replication/retention policy applied to DA blobs.
    pub fn da_replication_default_policy() -> RetentionPolicy {
        RetentionPolicy {
            hot_retention_secs: 6 * 60 * 60,
            cold_retention_secs: 30 * 24 * 60 * 60,
            required_replicas: 3,
            storage_class: SorafsStorageClass::Warm,
            governance_tag: GovernanceTag::new("da.default"),
        }
    }
    /// Per-class overrides layered on top of the default DA replication policy.
    pub fn da_replication_overrides() -> Vec<(BlobClass, RetentionPolicy)> {
        vec![
            (
                BlobClass::TaikaiSegment,
                RetentionPolicy {
                    hot_retention_secs: 24 * 60 * 60,
                    cold_retention_secs: 14 * 24 * 60 * 60,
                    required_replicas: 5,
                    storage_class: SorafsStorageClass::Hot,
                    governance_tag: GovernanceTag::new("da.taikai.live"),
                },
            ),
            (
                BlobClass::NexusLaneSidecar,
                RetentionPolicy {
                    hot_retention_secs: 6 * 60 * 60,
                    cold_retention_secs: 7 * 24 * 60 * 60,
                    required_replicas: 4,
                    storage_class: SorafsStorageClass::Warm,
                    governance_tag: GovernanceTag::new("da.sidecar"),
                },
            ),
            (
                BlobClass::GovernanceArtifact,
                RetentionPolicy {
                    hot_retention_secs: 12 * 60 * 60,
                    cold_retention_secs: 180 * 24 * 60 * 60,
                    required_replicas: 3,
                    storage_class: SorafsStorageClass::Cold,
                    governance_tag: GovernanceTag::new("da.governance"),
                },
            ),
        ]
    }
    /// Availability-class overrides layered on top of the Taikai policy.
    pub fn taikai_availability_overrides() -> Vec<(
        iroha_data_model::taikai::TaikaiAvailabilityClass,
        RetentionPolicy,
    )> {
        vec![
            (
                iroha_data_model::taikai::TaikaiAvailabilityClass::Hot,
                RetentionPolicy {
                    hot_retention_secs: 24 * 60 * 60,
                    cold_retention_secs: 14 * 24 * 60 * 60,
                    required_replicas: 5,
                    storage_class: SorafsStorageClass::Hot,
                    governance_tag: GovernanceTag::new("da.taikai.live"),
                },
            ),
            (
                iroha_data_model::taikai::TaikaiAvailabilityClass::Warm,
                RetentionPolicy {
                    hot_retention_secs: 6 * 60 * 60,
                    cold_retention_secs: 30 * 24 * 60 * 60,
                    required_replicas: 4,
                    storage_class: SorafsStorageClass::Warm,
                    governance_tag: GovernanceTag::new("da.taikai.warm"),
                },
            ),
            (
                iroha_data_model::taikai::TaikaiAvailabilityClass::Cold,
                RetentionPolicy {
                    hot_retention_secs: 60 * 60,
                    cold_retention_secs: 180 * 24 * 60 * 60,
                    required_replicas: 3,
                    storage_class: SorafsStorageClass::Cold,
                    governance_tag: GovernanceTag::new("da.taikai.archive"),
                },
            ),
        ]
    }
    /// Default rent base rate per GiB-month in XOR.
    pub fn da_rent_base_rate_per_gib_month() -> XorQuantity {
        "0.25".parse().expect("default is canonical")
    }
    /// Default protocol reserve share in basis points.
    pub const DA_RENT_PROTOCOL_RESERVE_BPS: u16 = 2_000;
    /// Default PDP bonus share in basis points.
    pub const DA_RENT_PDP_BONUS_BPS: u16 = 500;
    /// Default PoTR bonus share in basis points.
    pub const DA_RENT_POTR_BONUS_BPS: u16 = 250;
    /// Default egress credit per GiB in XOR.
    pub fn da_rent_egress_credit_per_gib() -> XorQuantity {
        "0.0015".parse().expect("default is canonical")
    }
    /// Transport-specific defaults (Norito-RPC, future streaming surfaces, etc.).
    pub mod transport {
        use iroha_config_base::util::Bytes;
        use nonzero_ext::nonzero;
        use std::num::NonZeroUsize;
        /// Explicit trusted proxy hosts whose appended `X-Forwarded-For` chain
        /// is used to derive the canonical remote IP.
        pub fn trusted_proxy_cidrs() -> Vec<String> {
            Vec::new()
        }
        /// HTTP/1 server socket and parser limits.
        pub mod http {
            use super::*;
            /// Maximum accepted TCP connections retained by Torii.
            pub const MAX_CONNECTIONS: NonZeroUsize = nonzero!(1024usize);
            /// Maximum accepted TCP connections retained for one source IP.
            pub const MAX_CONNECTIONS_PER_IP: NonZeroUsize = nonzero!(64usize);
            /// Absolute deadline for reading one HTTP/1 request head.
            pub const HEADER_READ_TIMEOUT_MS: u64 = 10_000;
            /// Maximum duration without socket write progress and graceful connection-drain deadline.
            pub const WRITE_TIMEOUT_MS: u64 = 30_000;
            /// Maximum number of HTTP/1 headers accepted in one request.
            pub const MAX_HEADERS: NonZeroUsize = nonzero!(100usize);
            /// Maximum HTTP/1 parser buffer, including the request head.
            pub const MAX_HEADER_BYTES: Bytes = Bytes(64 * 1024);
        }
        /// Optional HTTPS listener identity and handshake bounds.
        pub mod https {
            /// Absolute TLS handshake deadline; HTTPS itself is disabled by default.
            pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
            /// Maximum configured TLS handshake deadline.
            pub const MAX_HANDSHAKE_TIMEOUT_MS: u64 = 120_000;
            /// Maximum DER certificates in the configured leaf-first chain.
            pub const MAX_CERTIFICATES: usize = 4;
            /// Maximum bytes in each DER certificate or private key file.
            pub const MAX_DER_BYTES: usize = 16 * 1024;
        }
        /// Norito-RPC transport defaults surfaced via `torii.transport.norito_rpc`.
        pub mod norito_rpc {
            /// Enable the production Norito-RPC transport by default.
            pub const ENABLED: bool = true;
            /// Require the forwarded client certificate header from a trusted ingress proxy.
            pub const REQUIRE_MTLS: bool = false;
            /// Explicit trusted proxy hosts that may assert the forwarded client certificate header.
            pub fn mtls_trusted_proxy_cidrs() -> Vec<String> {
                vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()]
            }
            /// Default rollout stage label for Norito-RPC.
            pub const STAGE: &str = "ga";
            /// Default allowlist of clients permitted to use Norito-RPC (empty = unrestricted).
            #[must_use]
            pub fn allowed_clients() -> Vec<String> {
                Vec::new()
            }
        }
    }
    /// MCP endpoint defaults surfaced via `torii.mcp`.
    pub mod mcp {
        /// Enable the bounded read-only native Torii MCP server.
        pub const ENABLED: bool = true;
        /// Maximum accepted MCP request payload size (bytes).
        pub const MAX_REQUEST_BYTES: usize = 1_048_576; // 1 MiB
        /// Maximum number of tools returned per `tools/list` response page.
        pub const MAX_TOOLS_PER_LIST: usize = 500;
        /// Maximum number of MCP tool dispatches executing concurrently.
        pub const MAX_INFLIGHT_DISPATCHES: usize = 32;
        /// Default MCP tool profile (`read_only`, `writer`, `operator`).
        pub const PROFILE: &str = "read_only";
        /// Expose operator-only routes in the MCP registry.
        pub const EXPOSE_OPERATOR_ROUTES: bool = false;
        /// Extra allow-list prefixes for MCP tool names (empty => profile-only).
        #[must_use]
        pub fn allow_tool_prefixes() -> Vec<String> {
            Vec::new()
        }
        /// Extra deny-list prefixes for MCP tool names.
        #[must_use]
        pub fn deny_tool_prefixes() -> Vec<String> {
            Vec::new()
        }
        // Each tool dispatch consumes a token, including tools in batches.
        // Match the HTTP application budget; dispatch concurrency and payload
        // limits bound actual work independently.
        /// Optional steady-state MCP request budget (requests/minute). None disables.
        pub const RATE_PER_MINUTE: Option<u32> = Some(super::DEFAULT_REQUEST_RATE_PER_MINUTE);
        /// Optional MCP request burst budget.
        pub const BURST: Option<u32> = Some(super::DEFAULT_REQUEST_BURST);
    }
    /// Account-onboarding defaults surfaced via `torii.account_onboarding`.
    pub mod account_onboarding {
        /// Default alias lease acquisition term.
        pub const LEASE_TERM_YEARS: u8 = 1;
    }
    /// CORS defaults surfaced via `torii.cors`.
    pub mod cors {
        /// Enable CORS response headers.
        pub const ENABLED: bool = false;
        /// Default maximum preflight cache age in seconds.
        pub const MAX_AGE_SECS: u64 = 3_600;
        /// Origins allowed to make browser cross-origin requests.
        #[must_use]
        pub fn allowed_origins() -> Vec<String> {
            Vec::new()
        }
        /// HTTP methods allowed in CORS preflight responses.
        #[must_use]
        pub fn allowed_methods() -> Vec<String> {
            Vec::new()
        }
        /// Request headers allowed in CORS preflight responses.
        #[must_use]
        pub fn allowed_headers() -> Vec<String> {
            Vec::new()
        }
        /// Response headers exposed to browser clients.
        #[must_use]
        pub fn exposed_headers() -> Vec<String> {
            Vec::new()
        }
    }
    /// Default poll interval (seconds) for Taikai anchor uploads.
    pub const DA_TAIKAI_ANCHOR_POLL_INTERVAL_SECS: u64 = 30;
    /// Absolute deadline for one Taikai anchor upload and signed receipt.
    pub const DA_TAIKAI_ANCHOR_REQUEST_TIMEOUT_SECS: u64 = 15;
    /// ISO 20022 bridge disabled by default.
    pub const ISO_BRIDGE_ENABLED: bool = false;
    /// Maximum request body accepted by an ISO 20022 submission endpoint.
    pub const ISO_BRIDGE_MAX_BODY_BYTES: Bytes = Bytes(1024 * 1024);
    /// ISO 20022 dedupe TTL (seconds).
    pub const ISO_BRIDGE_DEDUPE_TTL_SECS: u64 = 5 * 60; // 5 minutes
    /// ISO 20022 default rail profile.
    pub const ISO_BRIDGE_DEFAULT_PROFILE: &str = "generic-iso20022";
    /// ISO 20022 default structured-address validation mode.
    pub const ISO_BRIDGE_STRUCTURED_ADDRESS_MODE: &str = "permissive";
    /// ISO 20022 reference data refresh cadence (seconds).
    pub const ISO_BRIDGE_REFERENCE_REFRESH_SECS: u64 = 24 * 60 * 60; // 24 hours
    /// ISO 20022 durable store age retention (seconds); zero keeps records by age.
    pub const ISO_BRIDGE_STORE_RETENTION_SECS: u64 = 0;
    /// ISO 20022 durable store default maximum record count.
    pub const ISO_BRIDGE_STORE_MAX_RECORDS: u64 = 256;
    /// Absolute first-release maximum for ISO 20022 durable records retained in memory.
    pub const ISO_BRIDGE_STORE_MAX_RECORDS_HARD_LIMIT_V1: u64 = 1_024;
    /// Return the default ISO 20022 submission body limit.
    #[must_use]
    pub const fn iso_bridge_max_body_bytes() -> Bytes {
        ISO_BRIDGE_MAX_BODY_BYTES
    }
    /// Return the default ISO 20022 durable-store record limit.
    #[must_use]
    pub const fn iso_bridge_store_max_records() -> u64 {
        ISO_BRIDGE_STORE_MAX_RECORDS
    }
    /// Return the default ISO 20022 bridge rail profile identifier.
    #[must_use]
    pub fn iso_bridge_default_profile() -> String {
        ISO_BRIDGE_DEFAULT_PROFILE.to_owned()
    }
    /// Return the default ISO 20022 structured-address validation mode.
    #[must_use]
    pub fn iso_bridge_structured_address_mode() -> String {
        ISO_BRIDGE_STRUCTURED_ADDRESS_MODE.to_owned()
    }
    /// SoraFS discovery disabled by default.
    pub const SORAFS_DISCOVERY_ENABLED: bool = false;
    /// Maximum number of admitted provider replay high-water marks persisted by Torii.
    pub const SORAFS_DISCOVERY_REPLAY_MAX_ENTRIES: NonZeroUsize = nonzero!(65_536usize);
    /// Default path for the durable SoraFS provider advert replay checkpoint.
    pub fn sorafs_discovery_replay_checkpoint_path() -> PathBuf {
        PathBuf::from("sorafs_discovery/provider_advert_replay.to")
    }
    /// Maximum SoraFS capacity declarations per provider per hour.
    pub const SORAFS_QUOTA_DECLARATION_MAX_EVENTS: Option<u32> = Some(4);
    /// Rolling window (seconds) for SoraFS capacity declarations.
    pub const SORAFS_QUOTA_DECLARATION_WINDOW_SECS: u64 = 60 * 60;
    /// Maximum SoraFS capacity telemetry reports per provider per hour.
    pub const SORAFS_QUOTA_TELEMETRY_MAX_EVENTS: Option<u32> = Some(12);
    /// Rolling window (seconds) for SoraFS capacity telemetry.
    pub const SORAFS_QUOTA_TELEMETRY_WINDOW_SECS: u64 = 60 * 60;
    /// Maximum SoraFS disputes per provider per day.
    pub const SORAFS_QUOTA_DISPUTE_MAX_EVENTS: Option<u32> = Some(2);
    /// Rolling window (seconds) for SoraFS disputes.
    pub const SORAFS_QUOTA_DISPUTE_WINDOW_SECS: u64 = 24 * 60 * 60;
    /// Maximum SoraFS PoR submissions per provider per hour.
    pub const SORAFS_QUOTA_POR_MAX_EVENTS: Option<u32> = Some(60);
    /// Rolling window (seconds) for SoraFS PoR submissions.
    pub const SORAFS_QUOTA_POR_WINDOW_SECS: u64 = 60 * 60;
    /// Default appeal-finance settlement worker reconciliation scan interval (milliseconds).
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_SCAN_INTERVAL_MS: u64 = 30_000;
    /// Default maximum appeal-finance settlement worker queue attempts per unchanged ledger state.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_RETRY_ATTEMPTS: u32 = 3;
    /// Default maximum durable pending appeal-finance operations.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_PENDING: usize = 4_096;
    /// Default maximum durable finalized appeal-finance tombstones.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_COMPLETED: usize = 16_384;
    /// Default maximum durable appeal-finance dead letters.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_MAX_DEAD_LETTERS: usize = 1_024;
    /// Default maximum canonical appeal-finance checkpoint size.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES: u64 = 64 * 1024 * 1024;
    /// Minimum canonical appeal-finance checkpoint size admitted by V1.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MIN_BYTES_V1: u64 = 4 * 1024;
    /// Hard canonical appeal-finance checkpoint ceiling admitted by V1.
    pub const SORAFS_APPEAL_FINANCE_SETTLEMENT_WORKER_CHECKPOINT_MAX_BYTES_LIMIT_V1: u64 =
        512 * 1024 * 1024;
    /// Canonical first-release appeal-finance asset and policy defaults.
    pub mod sorafs_appeal_finance {
        use iroha_data_model::asset::prelude::AssetDefinitionId;
        use iroha_primitives::numeric::{Numeric, XOR_QUANTITY_SCALE, XorQuantity};
        use std::str::FromStr;
        /// Canonical first-release asset scale for XOR-denominated appeal finance.
        pub const ASSET_SCALE: u32 = XOR_QUANTITY_SCALE;
        /// Version shared by the baseline pricing and settlement policies.
        pub const BASELINE_POLICY_VERSION: &str = "baseline-v1";
        /// Quote validity window in seconds.
        pub const PRICING_QUOTE_TTL_SECS: u64 = 15 * 60;
        /// Default panel size shared by pricing and settlement.
        pub const DEFAULT_PANEL_SIZE: u32 = 7;
        /// Normal-urgency price multiplier.
        pub const PRICING_URGENCY_NORMAL_MULTIPLIER: &str = "1";
        /// High-urgency price multiplier.
        pub const PRICING_URGENCY_HIGH_MULTIPLIER: &str = "1.2";
        /// Content appeal base rate.
        pub const PRICING_CONTENT_BASE_RATE_XOR: &str = "150";
        /// Content appeal backlog target.
        pub const PRICING_CONTENT_BACKLOG_TARGET: u32 = 50;
        /// Content appeal backlog multiplier cap.
        pub const PRICING_CONTENT_BACKLOG_CAP: &str = "1";
        /// Content appeal evidence-size divisor in MiB.
        pub const PRICING_CONTENT_SIZE_DIVISOR_MB: &str = "100";
        /// Content appeal evidence-size multiplier cap.
        pub const PRICING_CONTENT_SIZE_CAP: &str = "2";
        /// Content appeal minimum deposit.
        pub const PRICING_CONTENT_MIN_DEPOSIT_XOR: &str = "100";
        /// Content appeal maximum deposit.
        pub const PRICING_CONTENT_MAX_DEPOSIT_XOR: &str = "2500";
        /// Access appeal base rate.
        pub const PRICING_ACCESS_BASE_RATE_XOR: &str = "200";
        /// Access appeal backlog target.
        pub const PRICING_ACCESS_BACKLOG_TARGET: u32 = 30;
        /// Access appeal backlog multiplier cap.
        pub const PRICING_ACCESS_BACKLOG_CAP: &str = "1";
        /// Access appeal evidence-size divisor in MiB.
        pub const PRICING_ACCESS_SIZE_DIVISOR_MB: &str = "50";
        /// Access appeal evidence-size multiplier cap.
        pub const PRICING_ACCESS_SIZE_CAP: &str = "2";
        /// Access appeal minimum deposit.
        pub const PRICING_ACCESS_MIN_DEPOSIT_XOR: &str = "100";
        /// Access appeal maximum deposit.
        pub const PRICING_ACCESS_MAX_DEPOSIT_XOR: &str = "2500";
        /// Fraud appeal base rate.
        pub const PRICING_FRAUD_BASE_RATE_XOR: &str = "500";
        /// Fraud appeal backlog target.
        pub const PRICING_FRAUD_BACKLOG_TARGET: u32 = 20;
        /// Fraud appeal backlog multiplier cap.
        pub const PRICING_FRAUD_BACKLOG_CAP: &str = "1";
        /// Fraud appeal evidence-size divisor in MiB.
        pub const PRICING_FRAUD_SIZE_DIVISOR_MB: &str = "50";
        /// Fraud appeal evidence-size multiplier cap.
        pub const PRICING_FRAUD_SIZE_CAP: &str = "2";
        /// Fraud appeal minimum deposit.
        pub const PRICING_FRAUD_MIN_DEPOSIT_XOR: &str = "100";
        /// Fraud appeal maximum deposit.
        pub const PRICING_FRAUD_MAX_DEPOSIT_XOR: &str = "5000";
        /// Other appeal base rate.
        pub const PRICING_OTHER_BASE_RATE_XOR: &str = "120";
        /// Other appeal backlog target.
        pub const PRICING_OTHER_BACKLOG_TARGET: u32 = 40;
        /// Other appeal backlog multiplier cap.
        pub const PRICING_OTHER_BACKLOG_CAP: &str = "1";
        /// Other appeal evidence-size divisor in MiB.
        pub const PRICING_OTHER_SIZE_DIVISOR_MB: &str = "100";
        /// Other appeal evidence-size multiplier cap.
        pub const PRICING_OTHER_SIZE_CAP: &str = "2";
        /// Other appeal minimum deposit.
        pub const PRICING_OTHER_MIN_DEPOSIT_XOR: &str = "100";
        /// Other appeal maximum deposit.
        pub const PRICING_OTHER_MAX_DEPOSIT_XOR: &str = "2500";
        /// Baseline class-level surge multiplier.
        pub const PRICING_SURGE_MULTIPLIER: &str = "1";
        /// Baseline stipend paid to each juror.
        pub const SETTLEMENT_STIPEND_PER_JUROR_XOR: &str = "25";
        /// Baseline per-case juror bonus pool.
        pub const SETTLEMENT_CASE_BONUS_XOR: &str = "10";
        /// Refund rate for an upheld decision.
        pub const SETTLEMENT_UPHOLD_REFUND_RATE: &str = "0";
        /// Treasury rate for an upheld decision.
        pub const SETTLEMENT_UPHOLD_TREASURY_RATE: &str = "1";
        /// Refund rate for an overturned decision.
        pub const SETTLEMENT_OVERTURN_REFUND_RATE: &str = "1";
        /// Treasury rate for an overturned decision.
        pub const SETTLEMENT_OVERTURN_TREASURY_RATE: &str = "0";
        /// Refund rate for a modified decision.
        pub const SETTLEMENT_MODIFY_REFUND_RATE: &str = "1";
        /// Treasury rate for a modified decision.
        pub const SETTLEMENT_MODIFY_TREASURY_RATE: &str = "0";
        /// Refund rate when an appeal is withdrawn before panel activation.
        pub const SETTLEMENT_WITHDRAWN_BEFORE_PANEL_REFUND_RATE: &str = "0.9";
        /// Treasury rate when an appeal is withdrawn before panel activation.
        pub const SETTLEMENT_WITHDRAWN_BEFORE_PANEL_TREASURY_RATE: &str = "0";
        /// Refund rate when an appeal is withdrawn after panel activation.
        pub const SETTLEMENT_WITHDRAWN_AFTER_PANEL_REFUND_RATE: &str = "0";
        /// Treasury rate when an appeal is withdrawn after panel activation.
        pub const SETTLEMENT_WITHDRAWN_AFTER_PANEL_TREASURY_RATE: &str = "1";
        /// Refund rate for a frivolous appeal.
        pub const SETTLEMENT_FRIVOLOUS_REFUND_RATE: &str = "0.5";
        /// Treasury rate for a frivolous appeal.
        pub const SETTLEMENT_FRIVOLOUS_TREASURY_RATE: &str = "0.5";
        /// Refund rate while an appeal remains escalated.
        pub const SETTLEMENT_ESCALATED_REFUND_RATE: &str = "0";
        /// Treasury rate while an appeal remains escalated.
        pub const SETTLEMENT_ESCALATED_TREASURY_RATE: &str = "0";
        /// Canonical governed asset definition used for appeal finance.
        #[must_use]
        pub fn asset_definition_id() -> AssetDefinitionId {
            super::super::canonical_asset_definition_id("sora.universal", "xor")
        }
        /// Parse one hard-coded canonical decimal policy value.
        #[must_use]
        pub fn numeric(value: &str) -> Numeric {
            Numeric::from_str(value).expect("canonical appeal-finance numeric default")
        }
        /// Parse one hard-coded canonical XOR-denominated policy value.
        #[must_use]
        pub fn xor_quantity(value: &str) -> XorQuantity {
            XorQuantity::from_str(value).expect("canonical appeal-finance XOR quantity default")
        }
    }
    /// Default set of capability names recognised by Torii's discovery cache.
    pub fn sorafs_known_capabilities() -> Vec<String> {
        vec![
            "torii_gateway".to_string(),
            "chunk_range_fetch".to_string(),
            "potr_mldsa".to_string(),
            "registered_account_read".to_string(),
        ]
    }
}
/// Nexus lane/data-space defaults.
pub mod nexus {
    use super::*;
    /// AXT policy and runtime defaults.
    pub mod axt {
        /// Default slot length (in milliseconds) used when deriving AXT expiry slots from block timestamps.
        pub const SLOT_LENGTH_MS: u64 = 1;
        /// Minimum allowable slot length to keep expiry math meaningful.
        pub const MIN_SLOT_LENGTH_MS: u64 = 1;
        /// Maximum allowable slot length to avoid disabling expiry enforcement entirely.
        pub const MAX_SLOT_LENGTH_MS: u64 = 600_000;
        /// Default maximum tolerated clock skew (milliseconds) applied to expiry checks.
        pub const CLOCK_SKEW_MS_DEFAULT: u64 = 0;
        /// Upper bound on tolerated clock skew to prevent unbounded expiry extensions.
        pub const CLOCK_SKEW_MS_MAX: u64 = 60_000;
        /// Default number of slots to retain cached proofs (accepted or rejected).
        pub const PROOF_CACHE_TTL_SLOTS: u64 = 1;
        /// Maximum allowed proof cache TTL (slots) to bound replay surface.
        pub const PROOF_CACHE_TTL_SLOTS_MAX: u64 = 64;
        /// Default number of slots to retain handle usage for replay protection.
        pub const REPLAY_RETENTION_SLOTS: u64 = 128;
        /// Maximum allowed replay retention window (slots) to bound in-memory state.
        pub const REPLAY_RETENTION_SLOTS_MAX: u64 = 4_096;
    }
    /// Atomic private cross-dataspace settlement defaults.
    pub mod atomic_private_settlement {
        /// The production path is governed and disabled until explicitly activated.
        pub const ENABLED: bool = false;
        /// Minimum governance notice before an activation height becomes effective.
        pub const MINIMUM_ACTIVATION_NOTICE_BLOCKS: u64 = 7_200;
        /// Audited fixed-shape private-note proof profile version.
        pub const PROOF_PROFILE_VERSION: u16 = 1;
        /// Maximum dataspace legs admitted in one private atomic bundle.
        pub const MAX_PARTICIPANTS: u16 = 255;
        /// Protocol minimum dataspace legs in one private atomic bundle.
        pub const MIN_PARTICIPANTS: u16 = 2;
        /// Protocol maximum dataspace legs in one private atomic bundle.
        pub const MAX_PARTICIPANTS_LIMIT: u16 = 255;
        /// Maximum distance between admission and bundle expiry, in blocks.
        pub const MAX_EXPIRY_BLOCKS: u64 = 7_200;
        /// Maximum time allowed to collect auditor approvals, in blocks.
        pub const AUDIT_TIMEOUT_BLOCKS: u64 = 1_200;
        /// Maximum time allowed to collect all Prepare QCs, in blocks.
        pub const PREPARE_TIMEOUT_BLOCKS: u64 = 1_200;
        /// Maximum time allowed to collect all Commit QCs, in blocks.
        pub const COMMIT_TIMEOUT_BLOCKS: u64 = 1_200;
        /// Canonical padded capsule plaintext classes, in bytes.
        ///
        /// XChaCha20-Poly1305 adds a 16-byte authentication tag on the wire.
        pub const CAPSULE_PADDING_CLASSES_BYTES: [u32; 4] = [4_096, 16_384, 65_536, 262_144];
        /// Return the default padding classes as an owned configuration value.
        #[must_use]
        pub fn capsule_padding_classes_bytes() -> Vec<u32> {
            CAPSULE_PADDING_CLASSES_BYTES.to_vec()
        }
        /// Maximum proof sidecar size admitted for one leg.
        pub const MAX_PROOF_BYTES: u64 = 8 * 1024 * 1024;
        /// Hard proof-size ceiling implemented by the V1 data model.
        pub const MAX_PROOF_BYTES_LIMIT: u64 = 8 * 1024 * 1024;
        /// Maximum encrypted audit capsule size admitted for one leg.
        pub const MAX_CAPSULE_BYTES: u64 = 1024 * 1024;
        /// Hard encrypted-capsule ceiling for the V1 path.
        pub const MAX_CAPSULE_BYTES_LIMIT: u64 = 16 * 1024 * 1024;
        /// Maximum canonical sponsor-signed direct carrier transaction size.
        /// Protocol carrier limit. The worst-case 255-leg V1 fixture is below 1 MiB.
        pub const MAX_CARRIER_BYTES: u64 = 4 * 1024 * 1024;
        /// Hard global-carrier ceiling for the V1 path.
        /// V1 cannot admit a carrier larger than its Norito receipt bound.
        pub const MAX_CARRIER_BYTES_LIMIT: u64 = 4 * 1024 * 1024;
        /// Minimum durable sidecar retention after admission, in blocks.
        pub const SIDECAR_RETENTION_BLOCKS: u64 = 1_000_000;
        /// Maximum encrypted settlement records retained by one local sidecar store.
        pub const SIDECAR_MAX_RECORDS: u32 = 256;
        /// Hard record-count ceiling implemented by the V1 sidecar store.
        pub const SIDECAR_MAX_RECORDS_LIMIT: u32 = 4_096;
        /// Maximum canonical bytes retained by one local sidecar store.
        pub const SIDECAR_MAX_TOTAL_BYTES: u64 = 12 * 1024 * 1024 * SIDECAR_MAX_RECORDS as u64;
        /// Hard byte ceiling implemented by the V1 sidecar store.
        pub const SIDECAR_MAX_TOTAL_BYTES_LIMIT: u64 =
            12 * 1024 * 1024 * SIDECAR_MAX_RECORDS_LIMIT as u64;
        /// Governed minimum online auditor threshold accepted for new policies.
        pub const DEFAULT_MIN_AUDITOR_APPROVALS: u16 = 1;
        /// Audit-policy schema versions accepted by default.
        pub const PERMITTED_POLICY_VERSIONS: [u16; 1] = [1];
        /// Return the default policy versions as an owned configuration value.
        #[must_use]
        pub fn permitted_policy_versions() -> Vec<u16> {
            PERMITTED_POLICY_VERSIONS.to_vec()
        }
    }
    /// Storage budget defaults for Nexus nodes.
    pub mod storage {
        use iroha_config_base::util::Bytes;
        /// Filesystem capacity reserved as runtime storage headroom (basis points).
        pub const AUTO_STORAGE_HEADROOM_BPS: u16 = 2_000;
        /// Block interval between disk budget enforcement scans (0 = every block).
        pub const BUDGET_ENFORCE_INTERVAL_BLOCKS: u64 = 10;
        /// WSV hot-tier deterministic encoded-key plus measured-value budget (bytes).
        pub const MAX_WSV_MEMORY_BYTES: Bytes = Bytes(8 * 1024 * 1024 * 1024);
        /// Shared retained carrier shell/effects/descriptor allowance, not total RAM.
        pub const RETAINED_CARRIER_SHELL_BYTES: usize = 256 * 1024 * 1024;
        /// Exact backing for one maximum-size committed-evidence prune-key plan.
        pub const CONSENSUS_EVIDENCE_PRUNE_PLAN_BYTES: usize =
            4 * 31 * core::mem::size_of::<iroha_crypto::Hash>();
        /// Exact in-memory shape of one pending penalty metadata entry.
        /// Each optional peer's compact bytes hold a separate original charge.
        pub type ConsensusPenaltyPendingEntry = (
            iroha_crypto::Hash,
            iroha_data_model::block::consensus::EvidenceScope,
            u64,
            u64,
            [u8; 32],
            Option<(
                iroha_data_model::block::consensus::ValidatorIndex,
                iroha_model_base::peer::PeerId,
                Option<iroha_data_model::sumeragi_lanes::SumeragiLaneStakeBinding>,
                iroha_allocation::AllocationCharge,
            )>,
        );
        /// Exact fixed backing for the maximum retained pending penalty plan.
        pub const CONSENSUS_EVIDENCE_PENDING_PLAN_BYTES: usize = 4
            * 31
            * iroha_data_model::sumeragi_lanes::MAX_LANE_CUSTODY_SIGNERS
            * core::mem::size_of::<ConsensusPenaltyPendingEntry>();
        /// Sole native BLS-normal compact signer owner: one algorithm tag and 48 key bytes.
        /// Core validates this exact geometry before retaining a pending signer.
        pub const CONSENSUS_EVIDENCE_PENDING_PEER_KEY_BYTES: usize = 1 + 48;
        /// Maximum native peer-key backing in one pending plan, including fixed lane committees.
        pub const CONSENSUS_EVIDENCE_PENDING_PEER_KEYS_MAX_BYTES: usize = 4
            * 31
            * iroha_data_model::sumeragi_lanes::MAX_LANE_CUSTODY_SIGNERS
            * CONSENSUS_EVIDENCE_PENDING_PEER_KEY_BYTES;
        /// Minimum pool able to retain one maximum prune plan and one pending plan.
        pub const CONSENSUS_EVIDENCE_ONE_PLAN_BYTES: usize = CONSENSUS_EVIDENCE_PRUNE_PLAN_BYTES
            + CONSENSUS_EVIDENCE_PENDING_PLAN_BYTES
            + CONSENSUS_EVIDENCE_PENDING_PEER_KEYS_MAX_BYTES;
        /// Simultaneously retained proposal, validation, application and replay plans.
        pub const CONSENSUS_EVIDENCE_PREPARATION_CONCURRENT_PLANS: usize = 8;
        /// Finite pool for eight maximum prune/pending plans, original peer keys,
        /// and the bounded local observation pool (8 MiB frames plus descriptors).
        /// TODO(S8): decoded native proof/history graphs need original funded owners.
        pub const CONSENSUS_EVIDENCE_PREPARATION_BYTES: usize = CONSENSUS_EVIDENCE_ONE_PLAN_BYTES
            * CONSENSUS_EVIDENCE_PREPARATION_CONCURRENT_PLANS
            + 9 * 1024 * 1024;
        /// Minimum original-owner backing for one public-lane stake-share key,
        /// one validator group, three cloned Ed25519 account identifiers, and
        /// four aggregate charge descriptors with three nonzero magnitudes.
        /// The Core group is a transparent wrapper around this exact tuple
        /// layout. Larger keys, multisig controllers and exact final quantity
        /// magnitudes are measured against the configured finite pool.
        pub const CONSENSUS_STAKE_INDEX_MIN_BYTES: usize = core::mem::size_of::<(
            iroha_model_base::topology::LaneId,
            iroha_data_model::account::AccountId,
            iroha_data_model::account::AccountId,
        )>() + core::mem::size_of::<(
            iroha_model_base::topology::LaneId,
            iroha_data_model::account::AccountId,
            core::ops::Range<usize>,
            iroha_primitives::numeric::Quantity,
            iroha_primitives::numeric::Quantity,
            iroha_primitives::numeric::Quantity,
            Option<iroha_primitives::numeric::Quantity>,
        )>() + 3
            * (1 + 32 + core::mem::size_of::<iroha_allocation::AllocationCharge>())
            + 4 * core::mem::size_of::<iroha_allocation::AllocationCharge>()
            + 3 * core::mem::size_of::<usize>();
        /// Finite process-local pool for stake-index backings, keys and aggregate magnitudes.
        pub const CONSENSUS_STAKE_INDEX_BYTES: usize = 64 * 1024 * 1024;
        /// Budget share for Kura block storage (basis points).
        pub const KURA_BLOCKS_BPS: u16 = 3_500;
        /// Budget share for tiered-state cold snapshots (basis points).
        pub const WSV_SNAPSHOTS_BPS: u16 = 2_000;
        /// Budget share for SoraFS storage (basis points).
        pub const SORAFS_BPS: u16 = 4_500;
        /// Total basis points for storage budgeting.
        pub const BPS_TOTAL: u16 = 10_000;
    }
    /// Default number of execution lanes when no explicit lane catalog is configured.
    pub const LANE_COUNT: NonZeroU32 = nonzero!(1u32);
    /// Default alias assigned to the primary lane when no catalog entries are provided.
    pub const DEFAULT_LANE_ALIAS: &str = "default";
    /// Default alias assigned to the universal dataspace when no catalog entries are provided.
    pub const DEFAULT_DATASPACE_ALIAS: &str = "universal";
    /// Default lane index used when routing policy omits an explicit value.
    pub const DEFAULT_ROUTING_LANE_INDEX: u32 = 0;
    /// Dataspace consensus defaults.
    pub mod dataspace {
        /// Default fault tolerance value (f) used to size per-dataspace committees (3f + 1).
        pub const FAULT_TOLERANCE: u32 = 1;
    }
    /// Lane registry defaults.
    pub mod registry {
        use std::time::Duration;
        /// Poll interval for refreshing manifests and governance bundles.
        pub const POLL_INTERVAL: Duration = Duration::from_secs(60);
    }
    /// Shared Hugging Face lease defaults.
    pub mod hf_shared_leases {
        /// Drain grace window after the last member leaves a shared HF lease pool (milliseconds).
        pub const DRAIN_GRACE_MS: u64 = 5_000;
    }
    /// Encrypted uploaded-model registry admission defaults.
    pub mod uploaded_models {
        /// Maximum plaintext bytes admitted for one uploaded model.
        pub const MAX_PLAINTEXT_BYTES_PER_MODEL: u64 = 64 * 1024 * 1024 * 1024;
        /// Maximum encrypted chunk count admitted for one uploaded model.
        pub const MAX_CHUNK_COUNT_PER_MODEL: u32 = 16_384;
    }
    /// Lane compliance configuration defaults.
    pub mod compliance {
        /// Compliance disabled by default.
        pub const ENABLED: bool = false;
        /// Audit-only mode enabled by default to allow dry-runs.
        pub const AUDIT_ONLY: bool = true;
    }
    /// Lane-fusion defaults governing low-load consolidation.
    pub mod fusion {
        /// TEU floor below which adjacent lanes should fuse after the observation window.
        pub const FLOOR_TEU: u32 = 4_000;
        /// TEU threshold that forces fused lanes to split back into independent pipelines.
        pub const EXIT_TEU: u32 = 6_000;
        /// Consecutive low-load slots required before fusion activates.
        pub const OBSERVATION_SLOTS: u16 = 2;
        /// Maximum number of slots a fused window may persist without re-evaluating load.
        pub const MAX_WINDOW_SLOTS: u16 = 16;
    }
    /// Deterministic lane autoscaling defaults.
    pub mod autoscale {
        /// Whether consensus-driven lane autoscaling is enabled.
        pub const ENABLED: bool = false;
        /// Inclusive lower lane-id bound reserved for autoscale-managed elastic lanes.
        pub const MIN_LANE_ID: u32 = 1;
        /// Exclusive upper lane-id bound reserved for autoscale-managed elastic lanes.
        pub const MAX_LANE_ID_EXCLUSIVE: u32 = 8;
        /// Target block interval used by the autoscaler (milliseconds).
        pub const TARGET_BLOCK_MS: u64 = 1_000;
        /// Scale-out latency ratio threshold versus target block interval.
        pub const SCALE_OUT_LATENCY_RATIO: f64 = 1.20;
        /// Scale-in latency ratio threshold versus target block interval.
        pub const SCALE_IN_LATENCY_RATIO: f64 = 0.80;
        /// Scale-out utilization ratio threshold.
        pub const SCALE_OUT_UTILIZATION_RATIO: f64 = 0.85;
        /// Scale-in utilization ratio threshold.
        pub const SCALE_IN_UTILIZATION_RATIO: f64 = 0.40;
        /// Number of recent blocks used for scale-out decisions.
        pub const SCALE_OUT_WINDOW_BLOCKS: u16 = 32;
        /// Number of recent blocks used for scale-in decisions.
        pub const SCALE_IN_WINDOW_BLOCKS: u16 = 96;
        /// Cooldown period in blocks after every transition.
        pub const COOLDOWN_BLOCKS: u16 = 64;
        /// Per-lane target throughput used to compute utilization (tx/s).
        pub const PER_LANE_TARGET_TPS: u32 = 50;
    }
    /// Commit & proof deadline defaults (Δ window).
    pub mod commit {
        /// Slot-bound deadline for proofs/DA bundles to arrive before a transaction aborts.
        pub const WINDOW_SLOTS: u16 = 2;
    }
    /// Public-lane staking defaults.
    pub mod staking {
        use super::super::{NonZeroU32, Quantity};
        use nonzero_ext::nonzero;
        use std::time::Duration;
        /// Minimum bonded stake required to register a validator (asset base units).
        pub fn min_validator_stake() -> Quantity {
            Quantity::from(1_u64)
        }
        /// Maximum number of validators allowed per lane.
        pub const MAX_VALIDATORS: NonZeroU32 = nonzero!(32_u32);
        /// Maximum number of stake-share rows retained for one validator.
        pub const MAX_STAKE_SHARES_PER_VALIDATOR: NonZeroU32 = nonzero!(256_u32);
        /// Maximum number of pending unbond requests retained in one stake share.
        pub const MAX_PENDING_UNBONDS_PER_SHARE: NonZeroU32 = nonzero!(8_u32);
        /// Minimum delay between scheduling and finalising unbonds.
        pub const UNBONDING_DELAY: Duration = Duration::from_secs(0);
        /// Maximum slash ratio (basis points, 10_000 = 100%).
        pub const MAX_SLASH_BPS: u16 = 10_000;
        /// Escrow account that custodies bonded stake.
        pub const STAKE_ESCROW_ACCOUNT_ID: &str = super::fees::FEE_SINK_ACCOUNT_ID;
        /// Account that receives slashed stake (treasury/burn sink).
        pub const SLASH_SINK_ACCOUNT_ID: &str = super::fees::FEE_SINK_ACCOUNT_ID;
        /// Canonical XOR asset used by both staking and Nexus fees.
        pub fn stake_asset_id() -> String {
            super::fees::fee_asset_id()
        }
        /// Escrow account that custodies bonded stake.
        pub fn stake_escrow_account_id() -> String {
            STAKE_ESCROW_ACCOUNT_ID.to_string()
        }
        /// Account that receives slashed stake (treasury/burn sink).
        pub fn slash_sink_account_id() -> String {
            SLASH_SINK_ACCOUNT_ID.to_string()
        }
    }
    /// Universal fee schedule defaults.
    pub mod fees {
        use iroha_data_model::account::AccountId;
        use iroha_primitives::numeric::Quantity;
        /// Account that receives collected fees (string form).
        pub const FEE_SINK_ACCOUNT_ID: &str = super::pipeline::GAS_TECH_ACCOUNT_ID;
        /// Protocol account that physically custodies isolated sponsor-program vault assets.
        pub const SPONSOR_VAULT_CUSTODY_ACCOUNT_ID: &str =
            "sorauﾛ1NｱｻｸYSafﾇｷヰc5ﾇﾄVxﾏ9jLZヱﾋzsKqurﾊﾘ9ｸ3eｴAｶD54TDT";
        /// Base fee charged per transaction.
        pub fn base_fee() -> Quantity {
            Quantity::zero()
        }
        /// Additional fee charged per serialized transaction byte.
        pub fn per_byte_fee() -> Quantity {
            Quantity::zero()
        }
        /// Additional fee charged per instruction.
        pub fn per_instruction_fee() -> Quantity {
            "0.001".parse().expect("canonical fee quantity")
        }
        /// Additional fee charged per gas unit.
        pub fn per_gas_unit_fee() -> Quantity {
            "0.00005".parse().expect("canonical fee quantity")
        }
        /// Default Nexus fee settlement mode.
        pub const SETTLEMENT_MODE: &str = "direct";
        /// Sponsor vault custody account parsed under the default Sora chain discriminant.
        pub fn sponsor_vault_custody_account_id() -> AccountId {
            let _default_chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                super::super::common::chain_discriminant(),
            );
            AccountId::parse_encoded(SPONSOR_VAULT_CUSTODY_ACCOUNT_ID)
                .expect("default sponsor vault custody account must be canonical I105")
        }
        /// Fee asset definition identifier (string form).
        pub fn fee_asset_id() -> String {
            super::super::canonical_asset_definition_literal("universal.universal", "xor")
        }
    }
    /// Asynchronous Nexus lane-relay worker defaults.
    pub mod relay_worker {
        /// Protocol relay worker is disabled until rollout config activates it.
        pub const ENABLED: bool = false;
        /// Optional relayer account override; by default the node account signs worker transactions.
        pub const AUTHORITY_ACCOUNT_ID: Option<&str> = None;
        /// Hard per-kind cap for durable relay/allocation work and relay announcement history.
        pub const MAX_PENDING_RELAYS: usize = 1024;
        /// Worker retry cadence in milliseconds.
        pub const RETRY_BACKOFF_MS: u64 = 5_000;
        /// Maximum proof/submission attempts before marking local worker state rejected.
        pub const MAX_RETRY_ATTEMPTS: u32 = 10;
    }
    /// Domain endorsement defaults.
    pub mod endorsement {
        /// Quorum required (committee signatures) to accept an endorsement (0 disables enforcement).
        pub const QUORUM: u16 = 0;
        /// Committee member key identifiers allowed to sign endorsements.
        pub fn committee_keys() -> Vec<String> {
            Vec::new()
        }
    }
    /// Data-availability sampling defaults.
    pub mod da {
        /// Total in-slot DA signatures budget per lane.
        pub const Q_IN_SLOT_TOTAL: u32 = 2_048;
        /// Minimum in-slot DA signatures per dataspace.
        pub const Q_IN_SLOT_PER_DS_MIN: u16 = 8;
        /// Baseline attester sample size (S) for VRF draws.
        pub const SAMPLE_SIZE_BASE: u16 = 64;
        /// Maximum attester sample size when adaptive scaling increases coverage.
        pub const SAMPLE_SIZE_MAX: u16 = 96;
        /// Threshold `T` (Ed25519 signatures) required off-path for DA certificates.
        pub const THRESHOLD_BASE: u16 = 43;
        /// Number of shards each attester must verify per slot.
        pub const PER_ATTESTER_SHARDS: u16 = 25;
        /// Number of consecutive block heights in one deterministic ingest quota window.
        pub const INGEST_QUOTA_WINDOW_BLOCKS: u64 = 100;
        /// Maximum accepted DA ingests per account in one quota window.
        pub const INGEST_QUOTA_MAX_COUNT_PER_ACCOUNT: u64 = 1_024;
        /// Maximum canonical DA payload bytes per account in one quota window (64 GiB).
        pub const INGEST_QUOTA_MAX_BYTES_PER_ACCOUNT: u64 = 64 << 30;
        /// Rolling audit defaults ensuring long-term coverage.
        pub mod audit {
            use std::time::Duration;
            /// Signatures verified per audit window.
            pub const SAMPLE_SIZE: u16 = 32;
            /// Number of audit windows tracked before slashing for insufficient coverage.
            pub const WINDOW_COUNT: u16 = 20;
            /// Interval between audit windows.
            pub const INTERVAL: Duration = Duration::from_secs(10 * 60);
        }
        /// Recovery deadline defaults for missing DA proofs.
        pub mod recovery {
            use std::time::Duration;
            /// Deadline for supplying recovery proofs once requested.
            pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
        }
        /// Temporal diversity defaults for attester rotation.
        pub mod rotation {
            /// Maximum appearances of an attester within the rolling window.
            pub const MAX_HITS_PER_WINDOW: u16 = 4;
            /// Slot-width of the rolling window enforcing temporal diversity.
            pub const WINDOW_SLOTS: u16 = 64;
            /// Domain-separation tag used when deriving deterministic rotation seeds.
            pub const SEED_TAG: &str = "iroha:da:rotate:v1\0";
            /// Exponential decay applied to latency bias weights (0-1 inclusive).
            pub const LATENCY_DECAY: f64 = 0.25;
        }
    }
}
/// Iroha Connect defaults.
pub mod connect {
    use std::time::Duration;
    /// Enable Iroha Connect WS + P2P relay.
    pub const ENABLED: bool = true;
    /// Max concurrent WS sessions across roles.
    pub const WS_MAX_SESSIONS: usize = 10_000;
    /// Max concurrent WS sessions per remote IP.
    pub const WS_PER_IP_MAX_SESSIONS: usize = 10;
    /// Per-IP WS handshake rate (requests per minute).
    pub const WS_RATE_PER_IP_PER_MIN: u32 = super::torii::DEFAULT_REQUEST_RATE_PER_MINUTE;
    /// Session inactivity TTL (milliseconds).
    pub const SESSION_TTL: Duration = Duration::from_millis(300_000); // 5 minutes
    /// Maximum WS frame size accepted for Connect frames (bytes).
    pub const FRAME_MAX_BYTES: usize = 64_000;
    /// Maximum buffered payload per session (bytes) for pending delivery.
    pub const SESSION_BUFFER_MAX_BYTES: usize = 262_144; // 256 KiB
    /// Heartbeat ping interval (milliseconds).
    pub const PING_INTERVAL: Duration = Duration::from_millis(30_000);
    /// Minimum heartbeat interval allowed for browser transports (milliseconds).
    pub const PING_MIN_INTERVAL: Duration = Duration::from_millis(15_000);
    /// Number of consecutive missed heartbeats tolerated before disconnect.
    pub const PING_MISS_TOLERANCE: u32 = 3;
    /// Dedupe cache TTL (milliseconds) for (sid,dir,seq).
    pub const DEDUPE_TTL: Duration = Duration::from_millis(120_000); // 2 minutes
    /// Dedupe cache capacity (entries).
    pub const DEDUPE_CAP: usize = 8_192;
    /// Enable P2P re-broadcast relay.
    pub const RELAY_ENABLED: bool = true;
    /// Relay strategy string: "broadcast" or "local_only".
    pub const RELAY_STRATEGY: &str = "broadcast";
    /// Default hop TTL for Connect relay envelopes (0 disables cross-node rebroadcast).
    pub const P2P_TTL_HOPS: u8 = 8;
}
/// External fraud-risk monitoring defaults.
pub mod fraud_monitoring {
    use std::time::Duration;
    /// Enable outbound fraud-monitoring requests.
    pub const ENABLED: bool = false;
    /// HTTP connect timeout for fraud-monitoring requests.
    pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
    /// Request timeout for fraud-monitoring calls.
    pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(1_500);
    /// Maximum grace period to tolerate missing fraud assessments (seconds).
    pub const MISSING_ASSESSMENT_GRACE_SECS: u64 = 0;
}
/// Telemetry export defaults.
pub mod telemetry {
    use std::time::Duration;
    /// Default minimal retry period
    pub const MIN_RETRY_PERIOD: Duration = Duration::from_secs(1);
    /// Default maximum exponent for the retry delay
    pub const MAX_RETRY_DELAY_EXPONENT: u8 = 4;
    /// Panic on duplicate metric registration (developer diagnostics only).
    pub const PANIC_ON_DUPLICATE_METRICS: bool = false;
    /// Telemetry integrity defaults.
    pub mod integrity {
        /// Enable hash-chained telemetry exports by default.
        pub const ENABLED: bool = true;
    }
}
/// Network Time Service (NTS) defaults.
pub mod time {
    use std::time::Duration;
    /// Sampling interval for peer time probes.
    pub const NTS_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
    /// Maximum peers to sample per round.
    pub const NTS_SAMPLE_CAP_PER_ROUND: usize = 8;
    /// Maximum acceptable round-trip time (milliseconds) for samples.
    pub const NTS_MAX_RTT_MS: u64 = 500;
    /// Trim percent for median aggregation (10% from each side).
    pub const NTS_TRIM_PERCENT: u8 = 10;
    /// Per-peer ring buffer capacity for samples.
    pub const NTS_PER_PEER_BUFFER: usize = 16;
    /// Enable EMA smoothing of network offset.
    pub const NTS_SMOOTHING_ENABLED: bool = false;
    /// EMA alpha in [0,1]; higher means more responsive.
    pub const NTS_SMOOTHING_ALPHA: f64 = 0.2;
    /// Maximum allowed adjustment per minute (ms) when smoothing.
    pub const NTS_MAX_ADJUST_MS_PER_MIN: u64 = 50;
    /// Minimum number of peer samples required for healthy NTS.
    pub const NTS_MIN_SAMPLES: usize = 3;
    /// Maximum absolute offset (ms) permitted before NTS is considered unhealthy (0 disables).
    pub const NTS_MAX_OFFSET_MS: u64 = 1_000;
    /// Maximum confidence (MAD) in ms permitted before NTS is considered unhealthy (0 disables).
    pub const NTS_MAX_CONFIDENCE_MS: u64 = 500;
    /// Enforcement mode for unhealthy NTS ("warn" or "reject").
    pub const NTS_ENFORCEMENT_MODE: &str = "warn";
}
/// Execution pipeline defaults (scheduler, overlay, batching).
pub mod pipeline {
    use nonzero_ext::nonzero;
    use std::num::NonZeroU64;
    /// Enable dynamic prepass (IVM read-only run to derive access sets).
    pub const DYNAMIC_PREPASS: bool = true;
    /// Cache derived access sets by code hash/entrypoint for diagnostics.
    pub const ACCESS_SET_CACHE_ENABLED: bool = true;
    /// Enable parallel overlay construction.
    pub const PARALLEL_OVERLAY: bool = true;
    /// Number of worker threads for stateless/overlay pipeline stages (0 = bounded auto).
    pub const WORKERS: usize = 0;
    /// Capacity for the stateless validation cache (0 = disabled).
    pub const STATELESS_CACHE_CAP: usize = 4_096;
    /// Enable per-layer parallel application of overlays.
    pub const PARALLEL_APPLY: bool = true;
    /// Use a binary-heap ready queue in the scheduler instead of stable sort.
    pub const READY_QUEUE_HEAP: bool = false;
    /// Enable GPU key bucketing for scheduler prepass when hardware is available.
    pub const GPU_KEY_BUCKET: bool = false;
    /// Emit scheduler input/output traces for deterministic tie-break debugging.
    pub const DEBUG_TRACE_SCHEDULER_INPUTS: bool = false;
    /// Emit transaction evaluation traces during overlay application (dev diagnostics).
    pub const DEBUG_TRACE_TX_EVAL: bool = false;
    /// Maximum instructions per overlayed transaction (0 = unlimited).
    pub const OVERLAY_MAX_INSTRUCTIONS: usize = 0;
    /// Maximum serialized overlay bytes per transaction (0 = unlimited).
    pub const OVERLAY_MAX_BYTES: u64 = 0;
    /// Instructions processed per overlay chunk during application.
    pub const OVERLAY_CHUNK_INSTRUCTIONS: usize = 256;
    /// IVM pre-decode cache size (number of decoded streams cached).
    pub const CACHE_SIZE: usize = 128;
    /// Maximum decoded instructions retained per cached entry (0 = unlimited).
    pub const IVM_CACHE_MAX_DECODED_OPS: usize = 8_000_000;
    /// Aggregate IVM preparation/runtime allocation retention budget (0 disables).
    pub const IVM_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
    /// Finite requested allocation credits for active IVM execution (zero denies allocation).
    pub const IVM_EXECUTION_MAX_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB
    /// Rayon worker cap for prover/trace verification (0 = number of physical cores).
    pub const IVM_PROVER_THREADS: usize = 0;
    /// Ed25519-specific batch size (0 disables batching).
    pub const SIGNATURE_BATCH_MAX_ED25519: usize = 64;
    /// Secp256k1-specific batch size (0 disables batching).
    pub const SIGNATURE_BATCH_MAX_SECP256K1: usize = 16;
    /// PQC-specific batch size (0 disables batching).
    pub const SIGNATURE_BATCH_MAX_PQC: usize = 8;
    /// BLS-specific batch size (0 disables batching).
    pub const SIGNATURE_BATCH_MAX_BLS: usize = 16;
    /// Default gas-collection technical account identifier (encoded-only literal).
    pub const GAS_TECH_ACCOUNT_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    /// Admission-time upper bound for `max_cycles` embedded in IVM bytecode headers.
    pub const IVM_MAX_CYCLES_UPPER_BOUND: NonZeroU64 = nonzero!(1_000_000_u64);
    /// Maximum decoded Kotodama instructions accepted during admission (0 = unlimited).
    pub const IVM_MAX_DECODED_INSTRUCTIONS: u64 = 1_048_576;
    /// Maximum decoded byte length after Kotodama instruction expansion (0 = unlimited).
    pub const IVM_MAX_DECODED_BYTES: u64 = 4 * 1024 * 1024;
    /// Default cursor mode for query endpoints ("ephemeral" or "stored").
    pub const QUERY_DEFAULT_CURSOR_MODE: &str = "ephemeral";
    /// Maximum fetch size for iterable queries executed inside the IVM.
    pub const QUERY_MAX_FETCH_SIZE: u64 = super::torii::APP_API_MAX_FETCH_SIZE as u64;
    /// Maximum number of transactions allowed in the quarantine lane per block (0 = disabled).
    pub const QUARANTINE_MAX_TXS_PER_BLOCK: usize = 0;
    /// Per-transaction cycle cap enforced for the quarantine lane (0 = unlimited).
    pub const QUARANTINE_TX_MAX_CYCLES: u64 = 0;
    /// Minimum gas units required before stored cursor mode can be used (0 = disabled).
    pub const QUERY_STORED_MIN_GAS_UNITS: u64 = 0;
    /// AMX per-dataspace execution budget in milliseconds.
    pub const AMX_PER_DATASPACE_BUDGET_MS: u64 = 30;
    /// AMX group execution budget across dataspaces in milliseconds.
    pub const AMX_GROUP_BUDGET_MS: u64 = 140;
    /// Estimated nanoseconds per instruction used for AMX budgeting.
    pub const AMX_PER_INSTRUCTION_NS: u64 = 50;
    /// Estimated nanoseconds per memory access used for AMX budgeting.
    pub const AMX_PER_MEMORY_ACCESS_NS: u64 = 80;
    /// Estimated nanoseconds per syscall used for AMX budgeting.
    pub const AMX_PER_SYSCALL_NS: u64 = 120;
}
/// Tiered state backend defaults.
pub mod tiered_state {
    use iroha_config_base::util::Bytes;
    /// Disable tiered snapshots by default.
    pub const ENABLED: bool = false;
    /// Keep all keys hot unless explicitly configured.
    pub const HOT_RETAINED_KEYS: usize = 0;
    /// Hot-tier budget using canonical encoded-key bytes plus measured value bytes.
    pub const HOT_RETAINED_BYTES: Bytes = Bytes(0);
    /// Minimum snapshots to retain newly hot entries before demotion (0 = disabled).
    pub const HOT_RETAINED_GRACE_SNAPSHOTS: u64 = 1;
    /// Optional cold-tier byte budget across snapshots (0 = unlimited).
    pub const MAX_COLD_BYTES: Bytes = Bytes(0);
    /// Default on-disk root for tiered state snapshots.
    pub const DEFAULT_COLD_STORE_ROOT: &str = "./storage/tiered_state";
    /// Default on-disk root for DA-backed tiered state snapshots.
    pub const DEFAULT_DA_STORE_ROOT: &str = "./storage/da_wsv_snapshots";
    /// Retain the latest two snapshots when enabled.
    pub const MAX_SNAPSHOTS: usize = 2;
}
/// Concurrency defaults for thread pools and global Rayon.
pub mod concurrency {
    /// Minimum scheduler worker threads (0 = auto/physical cores)
    pub const SCHEDULER_MIN: usize = 0;
    /// Maximum scheduler worker threads (0 = auto/physical cores)
    pub const SCHEDULER_MAX: usize = 0;
    /// Global Rayon thread pool size (0 = auto/physical cores)
    pub const RAYON_GLOBAL: usize = 0;
    /// Default stack size (bytes) for Tokio runtime and blocking threads.
    pub const TOKIO_STACK_BYTES: usize = 8 * 1024 * 1024;
    /// Minimum allowed Tokio runtime and blocking-thread stack size.
    pub const TOKIO_STACK_BYTES_MIN: usize = 8 * 1024 * 1024;
    /// Maximum allowed Tokio runtime and blocking-thread stack size.
    pub const TOKIO_STACK_BYTES_MAX: usize = 64 * 1024 * 1024;
    /// Default stack size (bytes) for scheduler worker threads.
    pub const SCHEDULER_STACK_BYTES: usize = 32 * 1024 * 1024;
    /// Default stack size (bytes) for prover worker threads.
    pub const PROVER_STACK_BYTES: usize = 32 * 1024 * 1024;
    /// Default stack size (bytes) for Sumeragi helper threads.
    pub const SUMERAGI_STACK_BYTES: usize = 64 * 1024 * 1024;
    /// Minimum allowed Sumeragi helper-thread stack size.
    pub const SUMERAGI_STACK_BYTES_MIN: usize = 64 * 1024 * 1024;
    /// Maximum allowed Sumeragi helper-thread stack size.
    pub const SUMERAGI_STACK_BYTES_MAX: usize = 64 * 1024 * 1024;
}
/// Norito codec defaults.
pub mod norito {
    /// Allow GPU compression offload when compiled and available.
    pub const ALLOW_GPU_COMPRESSION: bool = true;
    /// Hard upper bound on Norito archive length after decompression (bytes).
    ///
    /// This limit is enforced before allocations to reject decompression bombs
    /// and other adversarial inputs that advertise extreme lengths. The default
    /// leaves headroom for the canonical maximum block and chunk-store payloads.
    pub const MAX_ARCHIVE_LEN: u64 = 1024 * 1024 * 1024; // 1 GiB
}
/// Hardware acceleration defaults (Metal/CUDA usage in IVM and helpers).
pub mod accel {
    /// Complete default process attempt envelope; State execution memory is separate.
    pub const RESOURCE_LIMITS: iroha_accel::RegistryLimits = iroha_accel::RegistryLimits::STANDARD;
    /// Enable SIMD acceleration (NEON/AVX/SSE) when available.
    pub const ENABLE_SIMD: bool = true;
    /// Enable CUDA backend when compiled and available.
    pub const ENABLE_CUDA: bool = true;
    /// Enable Metal backend on macOS when compiled and available.
    pub const ENABLE_METAL: bool = true;
    /// Optional IVM device-selection cap; Some(0) explicitly opts out.
    pub const MAX_GPUS: Option<usize> = None;
    /// Heuristic: minimum number of leaves to use GPU for Merkle leaves hashing.
    pub const MERKLE_MIN_LEAVES_GPU: usize = 8192;
    // Separate process attempt envelope, independent of State destination funding.
    /// Aggregate ordinary host backing bytes. Zero denies admission of this resource; no profile is required to supply the default.
    pub const HOST_BYTES: usize = RESOURCE_LIMITS.work.host_bytes;
    /// Aggregate pinned host backing bytes. Zero denies admission of this resource; no profile is required to supply the default.
    pub const PINNED_BYTES: usize = RESOURCE_LIMITS.work.pinned_bytes;
    /// Aggregate requested device backing bytes. Zero denies admission of this resource; no profile is required to supply the default.
    pub const DEVICE_BYTES: usize = RESOURCE_LIMITS.work.device_bytes;
    /// Concurrently retained complete work aggregates. Zero denies admission of this resource; no profile is required to supply the default.
    pub const IN_FLIGHT: usize = RESOURCE_LIMITS.work.in_flight;
    /// Variable shared Rust control and policy metadata bytes. Zero denies admission of this resource; no profile is required to supply the default.
    pub const METADATA_BYTES: usize = RESOURCE_LIMITS.metadata_bytes;
    /// Lifetime-observed physical device records, including quarantine. Zero denies admission of this resource; no profile is required to supply the default.
    pub const OBSERVED_DEVICES: usize = RESOURCE_LIMITS.devices;
    /// Ordinal probes per discovery pass. Zero denies admission of this resource; no profile is required to supply the default.
    pub const DISCOVERY_ORDINALS: u32 = RESOURCE_LIMITS.discovery_ordinals;
    /// Retained native module owners. Zero denies admission of this resource; no profile is required to supply the default.
    pub const MODULES: usize = RESOURCE_LIMITS.modules;
    /// Retained native stream owners. Zero denies admission of this resource; no profile is required to supply the default.
    pub const STREAMS: usize = RESOURCE_LIMITS.streams;
    /// Immutable artifact bytes admitted per module. Zero denies admission of this resource; no profile is required to supply the default.
    pub const ARTIFACT_BYTES: usize = RESOURCE_LIMITS.artifact_bytes;
}
/// Zero-knowledge subsystem defaults used by Torii and the host runtime.
// The proof-size, circuit-size and SCCP limits below are the protocol default of the committed
// `zk_validity_policy_v1` parameter (`iroha_data_model::zk_validity_policy`): a chain that
// commits no policy runs under them, and the node configuration schema has no key for them
// (`specs/zk_resource_contract.json`, bounds `proof.config_*`).
pub mod zk {
    /// SCCP proof-admission and deterministic verifier-work defaults.
    pub mod sccp {
        use nonzero_ext::nonzero;
        use std::num::{NonZeroU32, NonZeroU64};
        /// Maximum closed SCCP proofs in one transaction.
        pub const MAX_PROOFS_PER_TRANSACTION: NonZeroU32 = nonzero!(1_u32);
        /// Maximum closed SCCP proofs committed in one block.
        pub const MAX_PROOFS_PER_BLOCK: NonZeroU32 = nonzero!(4_u32);
        /// Maximum canonical bytes retained for one closed SCCP bridge proof.
        ///
        /// This stays below the first-release 10 MiB transaction wire ceiling and leaves room for
        /// the transaction envelope, signatures, and a same-transaction settlement receipt.
        pub const MAX_PROOF_BYTES_PER_PROOF: NonZeroU64 = nonzero!(8_u64 * 1024 * 1024);
        /// Maximum aggregate SCCP proof bytes in one transaction.
        pub const MAX_PROOF_BYTES_PER_TRANSACTION: NonZeroU64 = MAX_PROOF_BYTES_PER_PROOF;
        /// Maximum aggregate SCCP proof bytes committed in one block.
        pub const MAX_PROOF_BYTES_PER_BLOCK: NonZeroU64 = nonzero!(32_u64 * 1024 * 1024);
        /// Maximum native-finality continuation headers in one transaction.
        ///
        /// A full BSC advance carries 16 steps of at most 256 headers apiece.
        pub const MAX_NATIVE_HEADERS_PER_TRANSACTION: NonZeroU32 = nonzero!(4_096_u32);
        /// Maximum native-finality continuation headers committed in one block.
        pub const MAX_NATIVE_HEADERS_PER_BLOCK: NonZeroU32 = nonzero!(16_384_u32);
        /// Maximum Ethereum light-client updates in one transaction.
        pub const MAX_ETHEREUM_LIGHT_CLIENT_UPDATES_PER_TRANSACTION: NonZeroU32 = nonzero!(128_u32);
        /// Maximum Ethereum light-client updates committed in one block.
        pub const MAX_ETHEREUM_LIGHT_CLIENT_UPDATES_PER_BLOCK: NonZeroU32 = nonzero!(512_u32);
        /// Maximum framed native-finality header bytes in one transaction.
        pub const MAX_NATIVE_HEADER_BYTES_PER_TRANSACTION: NonZeroU64 =
            nonzero!(8_u64 * 1024 * 1024);
        /// Maximum framed native-finality header bytes committed in one block.
        pub const MAX_NATIVE_HEADER_BYTES_PER_BLOCK: NonZeroU64 = nonzero!(32_u64 * 1024 * 1024);
        /// Maximum Ed25519 signature checks in one transaction.
        ///
        /// A full TON advance carries 16 key-block hops signed by at most 1,024 validators
        /// apiece; the bound leaves room for evidence and proof anchors.
        pub const MAX_ED25519_SIGNATURE_CHECKS_PER_TRANSACTION: NonZeroU32 = nonzero!(65_536_u32);
        /// Maximum Ed25519 signature checks committed in one block.
        pub const MAX_ED25519_SIGNATURE_CHECKS_PER_BLOCK: NonZeroU32 = nonzero!(262_144_u32);
        /// Maximum BSC fast-finality vote attestations (fast-aggregate BLS checks) in one
        /// transaction.
        ///
        /// A full BSC advance carries 16 attestations, one per step.
        pub const MAX_BLS_VOTE_ATTESTATIONS_PER_TRANSACTION: NonZeroU32 = nonzero!(64_u32);
        /// Maximum BSC fast-finality vote attestations (fast-aggregate BLS checks) committed in
        /// one block.
        pub const MAX_BLS_VOTE_ATTESTATIONS_PER_BLOCK: NonZeroU32 = nonzero!(256_u32);
    }
    /// FASTPQ prover defaults.
    pub mod fastpq {
        use iroha_config_base::util::Bytes;
        use nonzero_ext::nonzero;
        use std::num::NonZeroUsize;
        /// Default execution mode for the FASTPQ prover (`cpu` or `gpu`).
        pub const EXECUTION_MODE: &str = "cpu";
        /// Default Poseidon pipeline mode (`cpu` or `gpu`).
        pub const POSEIDON_MODE: &str = "cpu";
        /// Maximum queued FASTPQ proof sidecar attachments.
        pub const PROOF_SIDECAR_QUEUE_CAP: NonZeroUsize = nonzero!(1024_usize);
        /// Maximum encoded FASTPQ proof snapshot accepted for sidecar persistence.
        pub const PROOF_SIDECAR_MAX_BYTES: Bytes =
            Bytes(fastpq_isi::resource_limits::FASTPQ_DEFAULT_MAX_PROOF_FRAME_BYTES_V1 as u64);
        /// Maximum attempts to merge a FASTPQ proof snapshot into a pending pipeline sidecar.
        pub const PROOF_SIDECAR_MAX_RETRIES: NonZeroUsize = nonzero!(16_usize);
        /// Optional override for the Metal command-buffer cap (None = derive automatically).
        pub const METAL_MAX_IN_FLIGHT: Option<usize> = None;
        /// Optional override for Metal threadgroup width (None = derive automatically).
        pub const METAL_THREADGROUP_WIDTH: Option<u64> = None;
        /// Whether to emit per-dispatch Metal kernel traces (off by default).
        pub const METAL_TRACE: bool = false;
        /// Whether to log Metal device enumeration details (off by default).
        pub const METAL_DEBUG_ENUM: bool = false;
    }
    /// Native PIPA-R verifier limits for the compiled circuit registry.
    pub mod pipa_r {
        /// Native PIPA-R verification is available by default.
        pub const ENABLED: bool = true;
        /// Maximum outer envelope size, shared with stateless pre-verification.
        pub const MAX_ENVELOPE_BYTES: usize = super::preverify::MAX_BYTES;
        /// Maximum canonical proof-payload size.
        pub const MAX_PROOF_BYTES: usize = 192 * 1024;
    }
    /// Maximum proofs accepted by one host batch-verification syscall.
    pub const MAX_VERIFY_BATCH: u32 = 16;
    /// Bounds for the local diagnostic polynomial-opening endpoint.
    pub mod ipa_commitment {
        /// Maximum domain exponent for diagnostic polynomial openings.
        pub const MAX_K: u32 = 16;
        /// Maximum diagnostic transcript-label length in bytes.
        pub const MAX_TRANSCRIPT_LABEL_LEN: usize = 64;
        /// Maximum encoded diagnostic polynomial-opening envelope size.
        pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
        /// Require ASCII diagnostic transcript labels.
        pub const ENFORCE_TRANSCRIPT_LABEL_ASCII: bool = true;
    }
    /// Optional local diagnostic trace worker defaults.
    pub mod trace {
        /// Enable optional local diagnostic trace checking.
        pub const ENABLED: bool = true;
        /// Maximum diagnostic tasks dispatched in one worker batch.
        pub const MAX_BATCH: u32 = 16;
        /// Diagnostic worker threads (0 selects the bounded automatic count).
        pub const WORKER_THREADS: usize = 0;
        /// Diagnostic ingress capacity (0 derives a bounded capacity).
        pub const QUEUE_CAP: usize = 0;
        /// Maximum diagnostic enqueue wait in milliseconds.
        pub const ENQUEUE_WAIT_MS: u64 = 25;
        /// Capacity of the important diagnostic-task retry ring.
        pub const RETRY_RING_CAP: usize = 2048;
        /// Maximum retry rounds for an important diagnostic task.
        pub const RETRY_MAX_ATTEMPTS: u32 = 3;
        /// Diagnostic retry scheduler interval in milliseconds.
        pub const RETRY_TICK_MS: u64 = 5;
    }
    /// Native STARK/FRI verifier configuration defaults.
    pub mod stark {
        /// Runtime toggle for STARK verification in hosts.
        ///
        /// Acceptance still requires binaries built with `zk-stark`.
        pub const ENABLED: bool = true;
        /// Maximum accepted outer STARK OpenVerifyEnvelope length (bytes).
        pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024; // 1 MiB
        /// Maximum accepted proof payload length (bytes).
        ///
        /// The native `stark/fri/*` verifier enforces additional structural caps
        /// during decoding; this limit is an early, coarse safeguard.
        pub const MAX_PROOF_BYTES: usize = 1024 * 1024; // 1 MiB
    }
    /// Stateless pre-verification defaults.
    pub mod preverify {
        /// Maximum accepted proof size (bytes) for pre-verification.
        /// Larger proofs are rejected with `ProofTooBig` before any further checks.
        pub const MAX_BYTES: usize = 1024 * 1024; // 1 MiB
        /// Soft byte-budget for pre-verification work (0 = unlimited).
        /// If non-zero and the proof size exceeds this budget, `PreverifyBudgetExceeded` is returned.
        pub const BUDGET_BYTES: u64 = 0;
    }
    /// ZK voting/election defaults.
    pub mod vote {
        /// Maximum number of recent ballot ciphertexts to keep per election.
        pub const BALLOT_HISTORY_CAP: usize = 1024;
    }
    /// Proof registry defaults.
    pub mod proof {
        /// Maximum number of recent proof records to retain per backend (0 = unlimited).
        pub const RECORD_HISTORY_CAP: usize = 4096;
        /// Grace window (in blocks) to keep proof records even if over capacity.
        pub const RETENTION_GRACE_BLOCKS: u64 = 256;
        /// Maximum number of proof records pruned in a single enforcement pass (0 = unlimited).
        pub const PRUNE_BATCH_SIZE: usize = 512;
        /// Maximum length of a bridge proof range (`end_height - start_height + 1`, 0 = unlimited).
        pub const BRIDGE_MAX_RANGE_LEN: u64 = 4096;
        /// Maximum age (in blocks) a bridge proof's end height may trail the current block (0 = unlimited).
        pub const BRIDGE_MAX_PAST_AGE_BLOCKS: u64 = 0;
        /// Maximum future drift (in blocks) a bridge proof's end height may lead the current block (0 = unlimited).
        pub const BRIDGE_MAX_FUTURE_DRIFT_BLOCKS: u64 = 0;
    }
}
/// Sumeragi (consensus) defaults
pub mod sumeragi {
    use iroha_crypto::Algorithm;
    /// Consensus wire/state-machine protocol version required by this release.
    pub const PROTOCOL_VERSION: u32 = iroha_data_model::sumeragi::PROTOCOL_VERSION as u32;
    /// Fresh-network target block cadence selected by genesis.
    pub const BLOCK_CADENCE_MS: u64 = 1_000;
    /// The view-zero round deadline is ten signed block-cadence intervals.
    pub const ROUND_TIMEOUT_CADENCE_MULTIPLIER: u32 = 10;
    /// Minimum lead time between publishing and activating a consensus key.
    pub const KEY_ACTIVATION_LEAD_BLOCKS: u64 = 1;
    /// Dual-key overlap window during rotation.
    pub const KEY_OVERLAP_GRACE_BLOCKS: u64 = 8;
    /// Grace window after declared consensus-key expiry.
    pub const KEY_EXPIRY_GRACE_BLOCKS: u64 = 0;
    /// Allowed consensus signing algorithms.
    pub const KEY_ALLOWED_ALGOS: &[Algorithm] = &[Algorithm::BlsNormal];
    /// Default list of allowed consensus signing algorithms.
    pub fn key_allowed_algorithms() -> Vec<Algorithm> {
        KEY_ALLOWED_ALGOS.to_vec()
    }
    /// Suffix of the default safety-record directory, a sibling of the Kura store directory
    /// (`specs/sumeragi.md` §7.4: records are never backed up or restored with the store).
    pub const RECORDS_DIR_SUFFIX: &str = "-sumeragi-records";
    /// Suffix of the default key installation log, a sibling of the Kura store directory and
    /// outside the record directory (§7.4).
    pub const INSTALLATION_LOG_SUFFIX: &str = "-sumeragi-installation.log";
    /// NPoS epoch, randomness, election, and reconfiguration defaults.
    pub mod npos {
        /// Epoch length in blocks.
        pub const EPOCH_LENGTH_BLOCKS: u64 = 3_600;
        /// Exact bounded `3f + 1` ceiling for an epoch committee.
        pub const MAX_VALIDATORS: u32 = 31;
        /// Minimum validator self-bond.
        pub const MIN_SELF_BOND: u64 = 1_000;
        /// Minimum nomination bond.
        pub const MIN_NOMINATION_BOND: u64 = 1;
        /// Maximum contribution from one nominator, in percent.
        pub const MAX_NOMINATOR_CONCENTRATION_PCT: u8 = 25;
        /// Permitted seat-allocation variance, in percent.
        pub const SEAT_BAND_PCT: u8 = 5;
        /// Maximum correlated ownership, in percent.
        pub const MAX_ENTITY_CORRELATION_PCT: u8 = 25;
        /// Evidence-retention horizon for epoch reconfiguration.
        pub const RECONFIG_EVIDENCE_HORIZON_BLOCKS: u64 = 7_200;
        /// Delay between finalized election and roster activation.
        pub const RECONFIG_ACTIVATION_LAG_BLOCKS: u64 = 1;
        /// Delay before finalized slashing evidence is applied.
        pub const SLASHING_DELAY_BLOCKS: u64 = 3_600;
        /// Finality margin before a new epoch roster activates.
        pub const FINALITY_MARGIN_BLOCKS: u64 = 8;
    }
}
/// Governance defaults (voting & parliament).
pub mod governance {
    use super::*;
    /// Enable standalone plain-ballot governance alongside ZK voting.
    pub const PLAIN_VOTING_ENABLED: bool = true;
    /// Default public key used for governance escrow account derivation.
    pub const BOND_ESCROW_PUBLIC_KEY: &str =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
    /// Default citizenship bond requirement (smallest units).
    pub const CITIZENSHIP_BOND_AMOUNT: u128 = 150;
    /// Default asset definition used for governance voting and bonds.
    pub fn voting_asset_id() -> String {
        super::canonical_asset_definition_literal("sora.universal", "xor")
    }
    fn account_id_from_public_key(public_key: &str) -> AccountId {
        let public_key = public_key.parse().expect("default governance public key");
        AccountId::new(public_key)
    }
    fn account_literal_from_account_id(account_id: &AccountId) -> String {
        // Config defaults must stay stable regardless of any ambient thread-local
        // chain override active while deserializing `UserConfig`.
        account_id
            .to_i105_for_discriminant(super::common::chain_discriminant())
            .expect("default governance account literal")
    }
    fn default_governance_account_id() -> AccountId {
        account_id_from_public_key(BOND_ESCROW_PUBLIC_KEY)
    }
    fn default_governance_account_literal() -> String {
        account_literal_from_account_id(&default_governance_account_id())
    }
    /// Default escrow account that custodies governance bonds.
    pub fn bond_escrow_account_id() -> AccountId {
        default_governance_account_id()
    }
    /// Default escrow account literal that custodies governance bonds.
    pub fn bond_escrow_account() -> String {
        default_governance_account_literal()
    }
    /// Default asset definition used for citizenship bonding.
    pub fn citizenship_asset_id() -> String {
        voting_asset_id()
    }
    /// Default escrow account that holds citizenship bonds.
    pub fn citizenship_escrow_account_id() -> AccountId {
        default_governance_account_id()
    }
    /// Default escrow account literal that holds citizenship bonds.
    pub fn citizenship_escrow_account() -> String {
        default_governance_account_literal()
    }
    /// Default receiver for slashed governance bonds.
    pub fn slash_receiver_account_id() -> AccountId {
        default_governance_account_id()
    }
    /// Default literal receiver for slashed governance bonds.
    pub fn slash_receiver_account() -> String {
        default_governance_account_literal()
    }
    /// Default exact citizenship bond requirement.
    pub fn citizenship_bond_amount() -> Quantity {
        Quantity::from(CITIZENSHIP_BOND_AMOUNT)
    }
    /// Default exact minimum governance voting bond.
    pub fn min_bond_amount() -> Quantity {
        Quantity::from(150_u64)
    }
    /// Emit alias frontier telemetry by default.
    pub const ALIAS_FRONTIER_TELEMETRY: bool = true;
    /// Emit governance pipeline trace logs.
    pub const DEBUG_TRACE_PIPELINE: bool = false;
    /// Maximum number of non-closed governance referenda retained at once.
    pub const MAX_ACTIVE_REFERENDA: NonZeroU32 = nonzero!(64_u32);
    /// Maximum distinct governance-lock owners retained for one referendum.
    pub const MAX_LOCK_OWNERS_PER_REFERENDUM: NonZeroU32 = nonzero!(1_000_u32);
    /// Default JDG signature schemes accepted during attestation validation.
    pub const JDG_SIGNATURE_SCHEMES: &[&str] = &["simple_threshold"];
    /// Default runtime-upgrade provenance enforcement mode.
    pub const RUNTIME_UPGRADE_PROVENANCE_MODE: &str = "optional";
    /// Require SBOM digests for runtime-upgrade provenance.
    pub const RUNTIME_UPGRADE_PROVENANCE_REQUIRE_SBOM: bool = false;
    /// Require SLSA attestation bytes for runtime-upgrade provenance.
    pub const RUNTIME_UPGRADE_PROVENANCE_REQUIRE_SLSA: bool = false;
    /// Default signature threshold for runtime-upgrade provenance.
    pub const RUNTIME_UPGRADE_PROVENANCE_SIGNATURE_THRESHOLD: usize = 0;
    /// Default exact TEU balance required for alias admission.
    pub fn alias_teu_minimum() -> Quantity {
        Quantity::zero()
    }
    /// Default toggle for emitting alias frontier telemetry.
    pub const fn alias_frontier_telemetry() -> bool {
        ALIAS_FRONTIER_TELEMETRY
    }
    /// Default JDG signature scheme allow-list.
    pub fn jdg_signature_schemes() -> Vec<String> {
        JDG_SIGNATURE_SCHEMES
            .iter()
            .copied()
            .map(str::to_string)
            .collect()
    }
    /// Default alternates retained for each attempt-local Parliament body draw.
    pub const PARLIAMENT_ALTERNATE_SIZE: usize = 21;
    /// Exact number of blocks between a Parliament sortition request and its beacon pulse.
    pub const PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS: u64 = 4;
    /// Consensus block-height span during which selected primaries and alternates may respond.
    pub const PARLIAMENT_INVITATION_PHASE_BLOCKS: u64 = 3_600;
    /// Consensus block-height span for public-finding endorsements after Reflection begins.
    pub const PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS: u64 = 3_600;
    /// Default Rules Committee size.
    pub const PARLIAMENT_RULES_COMMITTEE_SIZE: usize = 50;
    /// Default Agenda Council size.
    pub const PARLIAMENT_AGENDA_COUNCIL_SIZE: usize = 150;
    /// Default Interest Panel size.
    pub const PARLIAMENT_INTEREST_PANEL_SIZE: usize = 12;
    /// Default Review Panel size.
    pub const PARLIAMENT_REVIEW_PANEL_SIZE: usize = 150;
    /// Default Coordination Council size.
    pub const PARLIAMENT_COORDINATION_COUNCIL_SIZE: usize = 150;
    /// Default Policy Jury size (hidden timed-OVN bodies require the V1 anonymity floor).
    pub const PARLIAMENT_POLICY_JURY_SIZE: usize = 500;
    /// Configured Confirmation Jury target/cap (hidden timed-OVN bodies require the V1 anonymity floor).
    pub const PARLIAMENT_CONFIRMATION_JURY_SIZE: usize = 1_000;
    /// Default Oversight Committee size.
    pub const PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE: usize = 50;
    /// Default MPC Committee size.
    pub const PARLIAMENT_MPC_COMMITTEE_SIZE: usize = 50;
    /// Default FMA Committee size.
    pub const PARLIAMENT_FMA_COMMITTEE_SIZE: usize = 50;
    /// Timed-OVN deterministic block-height defaults and first-release resource ceilings.
    pub mod parliament_timed_ovn {
        /// Consensus block-height span allotted to proof-validated registration submissions.
        pub const REGISTRATION_PHASE_BLOCKS: u64 = 3_600;
        /// Consensus block-height span allotted to freezing pre-ballot dropouts and survivors.
        ///
        /// The default reserves at least one block for every entry in the maximum corpus. This
        /// remains safe under the standard genesis gas limit, where a worst-case dropout
        /// transition may consume most of one block after replaying the bounded cache.
        pub const SURVIVOR_FREEZE_PHASE_BLOCKS: u64 = 1_000;
        /// Consensus block-height span allotted to the exact masked-ballot commitment corpus.
        pub const COMMITMENT_PHASE_BLOCKS: u64 = 3_600;
        /// Consensus block-height span between commitment close and the earliest timed release.
        pub const RELEASE_DELAY_BLOCKS: u64 = 600;
        /// Consensus block-height grace window for aggregate opening after release begins.
        pub const OPENING_PHASE_BLOCKS: u64 = 600;
        /// Retry attempts permitted after the initial private ballot attempt (hard cap: 16).
        pub const MAX_BALLOT_RETRIES: u32 = 3;
        /// Hard first-release ceiling preventing retry-driven state/time amplification.
        pub const MAX_BALLOT_RETRIES_LIMIT: u32 = 16;
        /// Maximum entries retained in any registration, survivor, or ballot corpus (cap: 1,000).
        pub const MAX_CORPUS_ENTRIES: u32 = 1_000;
        /// Hard first-release corpus ceiling, matching the bounded timed-OVN decoder.
        pub const MAX_CORPUS_ENTRIES_LIMIT: u32 = 1_000;
    }
    /// Adaptive-corruption bounds for one finalized Parliament TLE key session.
    pub mod parliament_tle_key_lifecycle {
        /// Inclusive new-ballot lifetime after the mandatory `H + 1` activation.
        ///
        /// This matches the default maximum four-attempt timed-OVN lifecycle.
        /// Ballots committed before expiry retain their session through their
        /// independently committed inclusive opening deadline.
        pub const SESSION_LIFETIME_BLOCKS: u64 = 37_600;
        /// Conservative V1 ceiling: every fresh ballot requires a fresh DKG key.
        pub const MAX_FRESH_BALLOTS_PER_SESSION: u32 = 1;
    }
    /// Default per-binding reward amount ("1" XOR).
    pub const VIRAL_FOLLOW_REWARD_AMOUNT: &str = "1";
    /// Default sender bonus amount ("0.1" XOR).
    pub const VIRAL_SENDER_BONUS_AMOUNT: &str = "0.1";
    /// Default maximum rewards a UAID may claim per day.
    pub const VIRAL_MAX_DAILY_CLAIMS_PER_UAID: u32 = 1;
    /// Default maximum rewards per binding (lifetime).
    pub const VIRAL_MAX_CLAIMS_PER_BINDING: u32 = 1;
    /// Default daily budget for viral rewards (in reward asset units).
    pub const VIRAL_DAILY_BUDGET: &str = "1000";
    /// Default incentive pool account identifier.
    pub fn viral_incentive_pool_account() -> String {
        slash_receiver_account()
    }
    /// Default escrow account identifier.
    pub fn viral_escrow_account() -> String {
        slash_receiver_account()
    }
    /// Default viral reward asset definition identifier.
    pub fn viral_reward_asset_id() -> String {
        voting_asset_id()
    }
    /// Default viral follow reward amount.
    pub fn viral_follow_reward_amount() -> Quantity {
        Quantity::from_str(VIRAL_FOLLOW_REWARD_AMOUNT).expect("default viral follow reward amount")
    }
    /// Default sender bonus amount for first delivery.
    pub fn viral_sender_bonus_amount() -> Quantity {
        Quantity::from_str(VIRAL_SENDER_BONUS_AMOUNT).expect("default viral sender bonus amount")
    }
    /// Default daily viral reward budget.
    pub fn viral_daily_budget() -> Quantity {
        Quantity::from_str(VIRAL_DAILY_BUDGET).expect("default viral daily budget")
    }
    /// Optional promotion start timestamp (ms since Unix epoch).
    pub fn viral_promo_start_ms() -> Option<u64> {
        None
    }
    /// Optional promotion end timestamp (ms since Unix epoch).
    pub fn viral_promo_end_ms() -> Option<u64> {
        None
    }
    /// Aggregate campaign cap across the promo window (0 = unlimited).
    pub fn viral_campaign_cap() -> Quantity {
        Quantity::zero()
    }
    /// Default SoraFS pin policy constraints enforced by governance.
    pub mod sorafs_pin_policy {
        /// Minimum replicas floor required for approved manifests.
        pub const MIN_REPLICAS_FLOOR: u16 = 1;
        /// Maximum replicas ceiling allowed for approved manifests (inclusive).
        pub const MAX_REPLICAS_CEILING: Option<u16> = Some(5);
        /// Optional maximum retention epoch (inclusive); `None` disables the cap.
        pub const MAX_RETENTION_EPOCH: Option<u64> = None;
        /// Permissionless public pins do not require council signatures by default.
        pub const REQUIRE_COUNCIL_SIGNATURES: bool = false;
        /// Default distinct trusted approval-signature quorum.
        pub const APPROVAL_QUORUM: u16 = 1;
        /// Hard ceiling for governed SoraFS pin-approval signers.
        pub const MAX_APPROVAL_SIGNERS: usize = 64;
        /// Maximum number of retained pin-manifest records in consensus state.
        pub const MAX_GLOBAL_MANIFESTS: u64 = 1_000_000;
        /// Maximum aggregate content bytes represented by live pin manifests.
        pub const MAX_GLOBAL_BYTES: u64 = 1 << 50;
        /// Maximum number of retained pin-manifest records submitted by one account.
        pub const MAX_MANIFESTS_PER_AUTHORITY: u64 = 10_000;
        /// Maximum aggregate content bytes represented by one account's live pins.
        pub const MAX_BYTES_PER_AUTHORITY: u64 = 1 << 40;
        /// Maximum predecessor depth admitted for a manifest lineage.
        pub const MAX_LINEAGE_DEPTH: u32 = 64;
        /// Maximum number of retained direct successors admitted for one manifest.
        pub const MAX_SUCCESSOR_FANOUT: u32 = 32;
    }
    /// Default SoraFS public pin fee configuration.
    pub mod sorafs_pin_fee {
        use iroha_data_model::account::AccountId;
        /// XOR asset definition used to collect public pin fees.
        pub fn asset_id() -> String {
            super::super::nexus::fees::fee_asset_id()
        }
        /// Treasury account that receives public pin fees.
        pub fn treasury_account() -> String {
            super::super::nexus::fees::FEE_SINK_ACCOUNT_ID.to_string()
        }
        /// Treasury account parsed under the default Sora chain discriminant.
        pub fn treasury_account_id() -> AccountId {
            let _default_chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                super::super::common::chain_discriminant(),
            );
            AccountId::parse_encoded(&treasury_account())
                .expect("default SoraFS pin fee treasury account")
        }
    }
    /// Default SoraFS under-delivery penalty policy thresholds.
    pub mod sorafs_penalty {
        /// Minimum utilisation ratio (basis points) required before counting a strike.
        pub const UTILISATION_FLOOR_BPS: u16 = 7_500;
        /// Minimum uptime success rate (basis points) before counting a strike.
        pub const UPTIME_FLOOR_BPS: u16 = 9_500;
        /// Minimum PoR success rate (basis points) before counting a strike.
        pub const POR_SUCCESS_FLOOR_BPS: u16 = 9_700;
        /// Number of consecutive strikes required before issuing a slash.
        pub const STRIKE_THRESHOLD: u32 = 3;
        /// Percentage of bonded collateral slashed when penalties trigger (basis points).
        pub const PENALTY_BOND_BPS: u16 = 2_500;
        /// Cooldown window count (in settlement windows) before another penalty may trigger.
        pub const COOLDOWN_WINDOWS: u32 = 2;
        /// Maximum PDP failures tolerated within a telemetry window before forcing a strike (0 = none).
        pub const MAX_PDP_FAILURES: u32 = 0;
        /// Maximum PoTR SLA breaches tolerated within a telemetry window before forcing a strike (0 = none).
        pub const MAX_POTR_BREACHES: u32 = 0;
    }
    /// Default authentication and validation policy for SoraFS telemetry.
    pub mod sorafs_telemetry {
        /// Require telemetry submissions to originate from an authorised submitter list.
        pub const REQUIRE_SUBMITTER: bool = false;
        /// Require telemetry windows to carry a nonce for replay protection.
        /// Windows without a nonce are accepted only when this is false, but provided nonces
        /// are still checked for replay regardless.
        pub const REQUIRE_NONCE: bool = true;
        /// Maximum tolerated gap between accepted telemetry windows (seconds).
        pub const MAX_WINDOW_GAP_SECS: u64 = 6 * 60 * 60;
        /// Reject telemetry that reports zero capacity to avoid zero-fee windows.
        pub const REJECT_ZERO_CAPACITY: bool = true;
        /// Default authorised submitter accounts. The default policy is self-service, so the
        /// allow-list starts empty unless operators opt back into `require_submitter = true`.
        pub fn submitters() -> Vec<String> {
            Vec::new()
        }
    }
    /// Default governance bond slashing policy.
    pub mod slash_policy {
        /// Percentage of the locked bond slashed when a double-vote is detected (basis points).
        pub const DOUBLE_VOTE_BPS: u16 = 2_500;
        /// Percentage of the locked bond slashed for ineligible proofs (basis points).
        pub const INELIGIBLE_PROOF_BPS: u16 = 1_500;
        /// Percentage of the locked bond slashed for misconduct (basis points).
        pub const MISCONDUCT_BPS: u16 = 5_000;
        /// Appeal window (in blocks) after which restitution requests should be rejected by default.
        pub const RESTITUTION_WINDOW_BLOCKS: u64 = 7_200;
    }
}
/// Confidential asset/verifier defaults.
pub mod confidential {
    use super::*;
    /// Enable confidential verification; validators require this capability.
    pub const ENABLED: bool = true;
    /// Observer-only assume-valid disabled by default.
    pub const ASSUME_VALID: bool = false;
    /// Default verifier backend identifier.
    pub const VERIFIER_BACKEND: &str = "pipa-r/pasta";
    /// Maximum confidential proof size (bytes).
    pub const MAX_PROOF_SIZE_BYTES: u32 = 1_048_576;
    /// Maximum nullifiers per transaction.
    pub const MAX_NULLIFIERS_PER_TX: u32 = 8;
    /// Maximum commitments per transaction.
    pub const MAX_COMMITMENTS_PER_TX: u32 = 8;
    /// Maximum confidential ops per block.
    pub const MAX_CONFIDENTIAL_OPS_PER_BLOCK: u32 = 256;
    /// Verifier timeout duration.
    pub const VERIFY_TIMEOUT: Duration = Duration::from_millis(750);
    /// Maximum anchor age in blocks.
    pub const MAX_ANCHOR_AGE_BLOCKS: u64 = 10_000;
    /// Maximum proof bytes per block.
    pub const MAX_PROOF_BYTES_BLOCK: u64 = 1_048_576;
    /// Maximum verification calls per transaction. One Soracloud BFV full-bootstrap
    /// execution can verify one proof per registered identifier slot, so the default
    /// must admit at least one complete production-shaped execution proof batch.
    pub const MAX_VERIFY_CALLS_PER_TX: u32 = 128;
    /// Maximum verification calls per block.
    pub const MAX_VERIFY_CALLS_PER_BLOCK: u32 = 128;
    /// Maximum public inputs per proof.
    pub const MAX_PUBLIC_INPUTS: u32 = 32;
    /// Reorg depth bound (must exceed anchor age).
    pub const REORG_DEPTH_BOUND: u64 = 10_000;
    /// Minimum delay between policy change request and activation.
    pub const POLICY_TRANSITION_DELAY_BLOCKS: u64 = 100;
    /// Grace window around policy activation for conversions.
    pub const POLICY_TRANSITION_WINDOW_BLOCKS: u64 = 200;
    /// Maximum confidential-policy transitions that may share one effective height.
    pub const POLICY_TRANSITION_MAX_PER_HEIGHT: NonZeroU32 = nonzero!(256_u32);
    /// Non-zero commitment tree root history length retained.
    pub const TREE_ROOTS_HISTORY_LEN: NonZeroUsize = nonzero!(10_000_usize);
    /// Commitment tree frontier checkpoint interval.
    pub const TREE_FRONTIER_CHECKPOINT_INTERVAL: u64 = 100;
    /// Maximum verifier entries in registry.
    pub const REGISTRY_MAX_VK_ENTRIES: u32 = 64;
    /// Maximum parameter entries in registry.
    pub const REGISTRY_MAX_PARAMS_ENTRIES: u32 = 32;
    /// Maximum registry mutations per block.
    pub const REGISTRY_MAX_DELTA_PER_BLOCK: u32 = 4;
    /// Confidential verification gas schedule defaults.
    pub mod gas {
        /// Base verify cost for a confidential proof.
        pub const PROOF_BASE: u64 = 250_000;
        /// Cost per public input field element.
        pub const PER_PUBLIC_INPUT: u64 = 2_000;
        /// Cost per proof byte.
        pub const PER_PROOF_BYTE: u64 = 5;
        /// Cost per nullifier.
        pub const PER_NULLIFIER: u64 = 300;
        /// Cost per commitment.
        pub const PER_COMMITMENT: u64 = 500;
    }
    /// Default Poseidon parameter set identifier (if any) for confidential policies.
    pub const POSEIDON_PARAMS_ID: Option<u32> = None;
    /// Default Pedersen parameter set identifier (if any) for confidential policies.
    pub const PEDERSEN_PARAMS_ID: Option<u32> = None;
    /// Confidential ruleset version advertised during handshake.
    pub const RULES_VERSION: u32 = iroha_data_model::confidential::CONFIDENTIAL_RULES_VERSION;
}
/// SoraNet privacy telemetry defaults shared by relay runtimes.
pub mod soranet {
    /// Configuration defaults for privacy bucket aggregation.
    pub mod privacy {
        /// Width of each aggregation bucket (seconds).
        pub const BUCKET_SECS: u64 = 60;
        /// Minimum handshakes required before emitting counters.
        pub const MIN_HANDSHAKES: u64 = 12;
        /// Completed bucket delay before attempting a flush.
        pub const FLUSH_DELAY_BUCKETS: u64 = 1;
        /// Maximum bucket age before forcing a suppressed emit.
        pub const FORCE_FLUSH_BUCKETS: u64 = 6;
        /// Number of completed buckets retained for scraping.
        pub const MAX_COMPLETED_BUCKETS: usize = 120;
        /// Expected Prio shares required before combining contributions.
        pub const EXPECTED_SHARES: u16 = 2;
        /// Maximum bucket lag tolerated for collector shares before suppression.
        pub const MAX_SHARE_LAG_BUCKETS: u64 = 12;
        /// Capacity of the in-memory privacy event buffer.
        pub const EVENT_BUFFER_CAPACITY: usize = 4_096;
    }
    /// Defaults for the SoraNet VPN control plane and scheduler.
    pub mod vpn {
        use std::time::Duration;
        /// Enable the VPN tunnel by default.
        pub const ENABLED: bool = false;
        /// Fixed cell size (bytes).
        pub const CELL_SIZE_BYTES: u16 = 1_024;
        /// Flow label width (bits).
        pub const FLOW_LABEL_BITS: u8 = 24;
        /// Cover-to-data ratio expressed in permille.
        pub const COVER_TO_DATA_PER_MILLE: u16 = 250;
        /// Maximum burst of consecutive cover cells.
        pub const MAX_COVER_BURST: u16 = 3;
        /// Heartbeat cadence for keepalives (milliseconds).
        pub const HEARTBEAT_MS: u16 = 500;
        /// Maximum jitter applied to cover/keepalive slots (milliseconds).
        pub const JITTER_MS: u16 = 10;
        /// Padding budget advertised in headers (milliseconds).
        pub const PADDING_BUDGET_MS: u16 = 15;
        /// Guard/exit refresh cadence (seconds).
        pub const GUARD_REFRESH_SECS: Duration = Duration::from_secs(60 * 60);
        /// Control-plane lease duration (seconds).
        pub const LEASE_SECS: Duration = Duration::from_secs(10 * 60);
        /// DNS push interval (seconds).
        pub const DNS_PUSH_INTERVAL_SECS: Duration = Duration::from_secs(90);
        /// Default exit class label for billing/telemetry.
        pub const EXIT_CLASS: &str = "standard";
        /// Default meter family identifier.
        pub const METER_FAMILY: &str = "soranet.vpn.standard";
        /// Default full-tunnel IPv4 route pushed to clients.
        pub const DEFAULT_IPV4_ROUTE: &str = "0.0.0.0/0";
        /// Default full-tunnel IPv6 route pushed to clients.
        pub const DEFAULT_IPV6_ROUTE: &str = "::/0";
        /// Default DNS server pushed to clients.
        pub const DEFAULT_DNS_SERVER: &str = "1.1.1.1";
        /// Default prepaid XOR lease fee.
        pub fn lease_fee() -> iroha_primitives::numeric::Quantity {
            "0.001".parse().expect("default SoraNet VPN lease fee")
        }
        /// Default settlement grace after disconnect before escrow is refundable.
        pub const SETTLEMENT_GRACE_SECS: u64 = 60;
        /// Default operator account for the disabled profile.
        ///
        /// Enabling VPN requires a dedicated Ed25519 private key that matches
        /// this single-key account, or an explicit account/key override.
        pub fn operator_account_id() -> String {
            super::super::governance::bond_escrow_account()
        }
        /// Default client routes.
        pub fn route_pushes() -> Vec<String> {
            vec![
                DEFAULT_IPV4_ROUTE.to_string(),
                DEFAULT_IPV6_ROUTE.to_string(),
            ]
        }
        /// Default routes excluded from the tunnel.
        pub fn excluded_routes() -> Vec<String> {
            Vec::new()
        }
        /// Default DNS servers.
        pub fn dns_servers() -> Vec<String> {
            vec![DEFAULT_DNS_SERVER.to_string()]
        }
        /// Returns the default guard refresh cadence.
        #[must_use]
        pub const fn guard_refresh_secs() -> Duration {
            GUARD_REFRESH_SECS
        }
        /// Returns the default lease duration.
        #[must_use]
        pub const fn lease_secs() -> Duration {
            LEASE_SECS
        }
        /// Returns the default DNS push interval.
        #[must_use]
        pub const fn dns_push_interval_secs() -> Duration {
            DNS_PUSH_INTERVAL_SECS
        }
        /// Helper returning the guard refresh cadence in seconds.
        #[must_use]
        pub fn guard_refresh_secs_u64() -> u64 {
            GUARD_REFRESH_SECS.as_secs()
        }
        /// Helper returning the lease duration in seconds.
        #[must_use]
        pub fn lease_secs_u64() -> u64 {
            LEASE_SECS.as_secs()
        }
        /// Helper returning the DNS push interval in seconds.
        #[must_use]
        pub fn dns_push_interval_secs_u64() -> u64 {
            DNS_PUSH_INTERVAL_SECS.as_secs()
        }
    }
}
/// Settlement defaults.
pub mod settlement {
    /// Router defaults (shadow price, guard rails).
    pub mod router {
        /// Default TWAP window used for conversion quotes (seconds).
        pub const TWAP_WINDOW_SECS: u64 = 60;
        /// Base epsilon margin applied to every quote (basis points).
        pub const EPSILON_BPS: u16 = 25;
        /// Default buffer coverage horizon (hours).
        pub const BUFFER_HORIZON_HOURS: u16 = 72;
        /// Alert threshold percentage for remaining buffer.
        pub const ALERT_PCT: u8 = 75;
        /// Throttle threshold percentage for remaining buffer.
        pub const THROTTLE_PCT: u8 = 25;
        /// XOR-only threshold percentage.
        pub const XOR_ONLY_PCT: u8 = 10;
        /// Halt threshold percentage.
        pub const HALT_PCT: u8 = 2;
    }
}
/// Node-local SCCP defaults for `[sccp.keeper]` and `[sccp.light_client_keeper]`
/// (`specs/sccp.md` §4.13.4). Every value works without operator input.
pub mod sccp {
    /// `[sccp.keeper]` defaults.
    pub mod keeper {
        /// The keeper runs by default.
        pub const ENABLED: bool = true;
        /// Keeper-key directory below `kura.store_dir`, used while `key_dir` is empty.
        pub const KEY_DIR_UNDER_KURA_STORE: &str = "sccp/keeper-key";
        /// Submit due keepalives (§4.7.4).
        pub const KEEPALIVE: bool = true;
        /// Keepalive stagger per canonical committee index.
        pub const KEEPALIVE_STAGGER_MS: u64 = 15_000;
        /// Watch the registered destinations for certificates that Taira did not produce.
        pub const WATCH: bool = true;
    }
    /// `[sccp.light_client_keeper]` defaults.
    pub mod light_client_keeper {
        /// The keeper advances stale light clients by default.
        pub const ENABLED: bool = true;
        /// `0` advances once `ws_bound_ms / 4` of each light client has elapsed without progress.
        pub const ADVANCE_AFTER_MS: u64 = 0;
        /// Per-network cadence of checking local light-client state.
        pub const POLL_INTERVAL_MS: u64 = 60_000;
        /// Total wall-clock time of one RPC attempt before failing over to the next endpoint.
        pub const REQUEST_TIMEOUT_MS: u64 = 10_000;
        /// Wall-clock budget of one network's poll: every RPC request of one advance build.
        pub const POLL_BUDGET_MS: u64 = 120_000;
        /// Largest encoded advance the keeper submits.
        pub const MAX_ADVANCE_BYTES: usize = 262_144;
        /// Longest accepted endpoint list per chain.
        pub const MAX_ENDPOINTS_PER_LIST: usize = 64;
        /// Most accepted `[[sccp.light_client_keeper.secret_headers]]` entries.
        pub const MAX_SECRET_HEADERS: usize = 64;
    }
    /// Compiled free public endpoints (no API key), used when a configured list is empty
    /// and reused by `iroha_sccp_rpc` and `iroha_sccp_wallet`.
    // TODO(ws70): verify terms of use and route coverage of every compiled endpoint (spec §13 item 10).
    pub mod endpoints {
        /// Ethereum mainnet execution-layer JSON-RPC endpoints.
        pub const ETHEREUM_EXECUTION: &[&str] = &[
            "https://ethereum-rpc.publicnode.com",
            "https://eth.llamarpc.com",
            "https://cloudflare-eth.com",
        ];
        /// Ethereum mainnet beacon API endpoints serving the light-client routes.
        pub const ETHEREUM_BEACON: &[&str] = &[
            "https://ethereum-beacon-api.publicnode.com",
            "https://lodestar-mainnet.chainsafe.io",
        ];
        /// BNB Smart Chain mainnet JSON-RPC endpoints.
        pub const BSC: &[&str] = &[
            "https://bsc-dataseed.bnbchain.org",
            "https://bsc-rpc.publicnode.com",
        ];
        /// TON mainnet liteservers as `<ipv4>:<port>:<base64 ed25519 public key>`, copied from
        /// the `liteservers` array of `https://ton.org/global-config.json` (signed-integer IP
        /// converted to dotted form).
        // TODO(ws70): re-check these entries against the live global config before release;
        // the published liteserver set rotates over time.
        pub const TON_LITESERVERS: &[&str] = &[
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.15:48014:3XO67K/qi+gu3T9v8G2hx1yNmWZhccL3O7SoosFo8G0=",
            "135.181.177.59:53312:aF91CuUHuuOv9rm2W5+O/4h38M3sRm40DtSdRxQhmtQ=",
            "135.181.140.212:13206:K0t3+IWLOXHYMvMcrGZDPs+pn58a17LFbnXoQkKc2xw=",
            "135.181.140.221:46995:wQE0MVhXNWUXpWiW5Bk8cAirIh5NNG3cZM1/fSVKIts=",
            "65.21.141.233:30131:wrQaeIFispPfHndEBc0s0fx7GSp8UFFvebnytQQfc6A=",
            "65.21.141.198:47160:vOe1Xqt/1AQ2Z56Pr+1Rnw+f0NmAA7rNCZFIHeChB7o=",
            "65.21.141.231:17728:BYSVpL7aPk0kU5CtlsIae/8mf2B/NrBi7DKmepcjX6Q=",
            "65.21.141.197:13570:iVQH71cymoNgnrhOT35tl/Y7k86X5iVuu5Vf68KmifQ=",
            "164.68.101.206:52995:QnGFe9kihW+TKacEvvxFWqVXeRxCB6ChjjhNTrL7+/k=",
            "164.68.99.144:20334:gyLh12v4hBRtyBygvvbbO2HqEtgl+ojpeRJKt4gkMq0=",
            "188.68.216.239:19925:ucho5bEkufbKN1JR1BGHpkObq602whJn3Q3UwhtgSo4=",
            "51.195.189.59:19434:J5CwYXuCZWVPgiFPW+NY2roBwDWpRRtANHSTYTRSVtI=",
            "51.195.189.140:23067:vX8d0i31zB0prVuZK8fBkt37WnEpuEHrb7PElk4FJ1o=",
            "135.181.132.198:53560:NlYhh/xf4uQpE+7EzgorPHqIaqildznrpajJTRRH2HU=",
            "135.181.132.253:46529:jLO6yoooqUQqg4/1QXflpv2qGCoXmzZCR+bOsYJ2hxw=",
            "54.39.158.156:51565:TDg+ILLlRugRB4Kpg3wXjPcoc+d+Eeb7kuVe16CS9z8=",
            "185.86.79.9:4701:G6cNAr6wXBBByWDzddEWP5xMFsAcp6y13fXA8Q7EJlM=",
        ];
    }
}
#[cfg(test)]
#[path = "defaults_tests.rs"]
mod tests;
