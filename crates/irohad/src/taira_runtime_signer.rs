//! Fixed-descriptor runtime signer custody for the Taira daemon launcher.
//!
//! Taira keeps each validator's Soracloud runtime key in its deployment
//! supervisor.  The supervisor opens the owner-only regular file and passes it
//! to the daemon as inherited descriptor 198.  No path, key, or alternate
//! descriptor is accepted through arguments, configuration, or environment.
//! Optional global-beacon custody consumes descriptor 200 only when the exact
//! public provider binding is configured; the canonical credential is bound to
//! the expected genesis network.

use crate::{
    IrohaRuntimeDeps, IrohaRuntimeProviderBindingV1, IrohaRuntimeProviderBindingsV1,
    IrohaRuntimeProviderRegistryErrorV1, IrohaRuntimeProviderRegistryV1,
    IrohaRuntimeProviderSlotV1, node_secrets,
    soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1,
};
use iroha_config::parameters::{
    actual::{NexusStorageWeights, Root as Config, SoracloudRuntime},
    defaults::{
        soracloud_runtime as soracloud_runtime_defaults,
        taira::{
            INROU_EGRESS_MAX_BYTES_PER_MINUTE as TAIRA_INROU_EGRESS_MAX_BYTES_PER_MINUTE_V1,
            INROU_EGRESS_RATE_PER_MINUTE as TAIRA_INROU_EGRESS_RATE_PER_MINUTE_V1,
            NEXUS_KURA_BLOCKS_BPS as TAIRA_NEXUS_KURA_BLOCKS_BPS_V1,
            NEXUS_SORAFS_BPS as TAIRA_NEXUS_SORAFS_BPS_V1,
            NEXUS_STORAGE_BUDGET_BYTES as TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1,
            NEXUS_WSV_SNAPSHOTS_BPS as TAIRA_NEXUS_WSV_SNAPSHOTS_BPS_V1,
            SORAFS_STORAGE_CAP_BYTES as TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
        },
    },
};
use iroha_crypto::KeyPair;
use iroha_data_model::NetworkId;
use std::{
    ffi::OsStr,
    fmt,
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, Write as _},
    num::{NonZeroU32, NonZeroU64},
    os::{
        fd::{FromRawFd as _, RawFd},
        unix::fs::MetadataExt as _,
    },
    sync::Arc,
    time::Duration,
};

use zeroize::Zeroizing;

#[cfg(any(test, feature = "test-network-disposable-broker"))]
mod disposable_broker;
#[cfg(feature = "test-network-disposable-broker")]
pub use disposable_broker::load_disposable_runtime_provider_broker_v1;

fn invocation_does_not_start_a_node(argument: &OsStr) -> bool {
    matches!(
        argument.to_str(),
        Some("--check-config" | "--help" | "-h" | "--version" | "-V")
    )
}

/// Fixed inherited descriptor containing the Taira runtime signer key.
pub const TAIRA_RUNTIME_SIGNER_FD_V1: RawFd = 198;
/// Fixed inherited descriptor containing the configured global-beacon credential.
pub const TAIRA_GLOBAL_BEACON_CREDENTIAL_FD_V1: RawFd = 200;
/// Exact adapter/public-policy revision of the first-release Taira signer.
pub const TAIRA_RUNTIME_SIGNER_REVISION_V1: u64 = 1;
/// Exact byte length of one canonical Ed25519 private multihash plus newline.
pub const TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1: u64 = 71;
/// Canonical public Taira chain identity accepted by this launcher.
pub const TAIRA_CHAIN_ID_V1: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
/// Canonical I105 address discriminant accepted by this launcher.
pub const TAIRA_CHAIN_DISCRIMINANT_V1: u16 = 369;
/// Exact first-release Taira validator count.
pub const TAIRA_VALIDATOR_COUNT_V1: usize = 4;
/// Exact aggregate Inrou CPU ceiling for one first-release Taira validator.
pub const TAIRA_INROU_MAX_CPU_MILLIS_V1: u32 =
    iroha_config::parameters::defaults::taira::INROU_MAX_CPU_MILLIS;
/// Exact aggregate Inrou memory ceiling for one first-release Taira validator.
pub const TAIRA_INROU_MAX_MEMORY_BYTES_V1: u64 =
    iroha_config::parameters::defaults::taira::INROU_MAX_MEMORY_BYTES;
/// Exact aggregate Inrou writable-storage ceiling for one first-release Taira validator.
pub const TAIRA_INROU_MAX_STORAGE_BYTES_V1: u64 =
    iroha_config::parameters::defaults::taira::INROU_MAX_STORAGE_BYTES;
/// Exact immutable Inrou guest-image ceiling for one first-release Taira validator.
pub const TAIRA_INROU_GUEST_IMAGE_MAX_BYTES_V1: u64 =
    iroha_config::parameters::defaults::taira::INROU_GUEST_IMAGE_MAX_BYTES;
/// Exact Inrou startup grace for one first-release Taira validator.
pub const TAIRA_INROU_START_GRACE_MS_V1: u64 = 30_000;
/// Exact Inrou shutdown grace for one first-release Taira validator.
pub const TAIRA_INROU_STOP_GRACE_MS_V1: u64 = 10_000;

const TAIRA_RUNTIME_SIGNER_HANDLE_PREFIX_V1: &str = "software://taira/inrou/";
const TAIRA_RUNTIME_SIGNER_POLICY_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.taira.runtime-signer.compiled-policy.digest.v1\0";
const TAIRA_RUNTIME_SIGNER_COMPILED_POLICY_V1: &[u8] = b"algorithm=ed25519;credential=inherited-fd-198-consumed-after-load;descriptor=stable-owner-euid-regular-mode-0600-nlink-1-size-71;key=canonical-private-multihash-plus-newline;handle=software://taira/inrou/<lowercase-raw-public-key-hex>;authority=account-id(public-key);transactions=exact-authority-payload;provenance=canonical-soracloud-v1-domain-version-purpose-preimage;qualification=active-nontest;";

fn taira_runtime_signer_policy_digest_v1() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TAIRA_RUNTIME_SIGNER_POLICY_DIGEST_DOMAIN_V1);
    hasher.update(&TAIRA_RUNTIME_SIGNER_REVISION_V1.to_be_bytes());
    hasher.update(
        &u64::try_from(TAIRA_RUNTIME_SIGNER_COMPILED_POLICY_V1.len())
            .expect("compiled Taira signer policy length fits u64")
            .to_be_bytes(),
    );
    hasher.update(TAIRA_RUNTIME_SIGNER_COMPILED_POLICY_V1);
    *hasher.finalize().as_bytes()
}

fn validate_taira_launcher_profile_v1(
    chain_id: &str,
    chain_discriminant: u16,
    trusted_peer_count: usize,
    validator_roster_len: usize,
    runtime: &SoracloudRuntime,
) -> Result<(), String> {
    if chain_id != TAIRA_CHAIN_ID_V1 {
        return Err(format!(
            "Taira launcher requires canonical chain id {TAIRA_CHAIN_ID_V1}"
        ));
    }
    if chain_discriminant != TAIRA_CHAIN_DISCRIMINANT_V1 {
        return Err(format!(
            "Taira launcher requires chain discriminant {TAIRA_CHAIN_DISCRIMINANT_V1}"
        ));
    }
    if trusted_peer_count != TAIRA_VALIDATOR_COUNT_V1
        || validator_roster_len != TAIRA_VALIDATOR_COUNT_V1
    {
        return Err(format!(
            "Taira launcher requires exactly {TAIRA_VALIDATOR_COUNT_V1} trusted validator peers"
        ));
    }
    if !runtime.production_mode {
        return Err("Taira launcher requires Soracloud production mode".to_owned());
    }
    if runtime.hydration_concurrency
        != std::num::NonZeroUsize::new(
            iroha_config::parameters::defaults::taira::HYDRATION_CONCURRENCY,
        )
        .expect("nonzero Taira worker capacity")
        || runtime.prepared_runtime_cache_capacity
            != std::num::NonZeroUsize::new(
                iroha_config::parameters::defaults::taira::PREPARED_RUNTIME_CACHE_CAPACITY,
            )
            .expect("nonzero Taira worker capacity")
    {
        return Err(
            "Taira launcher requires the exact V1 hydration-worker and prepared-runtime capacities"
                .to_owned(),
        );
    }
    let inrou = &runtime.inrou;
    if !inrou.enabled {
        if inrou.portable_vm_uid.is_some()
            || inrou.portable_vm_gid.is_some()
            || inrou.trusted_guest_artifact.is_some()
        {
            return Err(
                "disabled Taira Inrou hosting cannot retain a PortableVM identity or trusted guest artifact"
                    .to_owned(),
            );
        }
    } else {
        let uid = inrou
            .portable_vm_uid
            .ok_or_else(|| "enabled Taira Inrou hosting requires portable_vm_uid".to_owned())?
            .get();
        let gid = inrou
            .portable_vm_gid
            .ok_or_else(|| "enabled Taira Inrou hosting requires portable_vm_gid".to_owned())?
            .get();
        if soracloud_runtime_defaults::inrou_portable_vm_identity_slot(uid, gid).is_none() {
            return Err(format!(
                "Taira Inrou uid/gid must be one equal canonical slot pair in {}..{} (upper bound exclusive)",
                soracloud_runtime_defaults::INROU_PORTABLE_VM_ID_BASE,
                soracloud_runtime_defaults::INROU_PORTABLE_VM_ID_MAX_EXCLUSIVE,
            ));
        }
        if inrou.guest_image_max_bytes.get() != TAIRA_INROU_GUEST_IMAGE_MAX_BYTES_V1
            || inrou.max_cpu_millis.get() != TAIRA_INROU_MAX_CPU_MILLIS_V1
            || inrou.max_memory_bytes.get() != TAIRA_INROU_MAX_MEMORY_BYTES_V1
            || inrou.max_storage_bytes.get() != TAIRA_INROU_MAX_STORAGE_BYTES_V1
        {
            return Err("Taira launcher requires the exact V1 Inrou resource ceilings".to_owned());
        }
        if inrou.start_grace != Duration::from_millis(TAIRA_INROU_START_GRACE_MS_V1)
            || inrou.stop_grace != Duration::from_millis(TAIRA_INROU_STOP_GRACE_MS_V1)
        {
            return Err("Taira launcher requires the exact V1 Inrou lifecycle graces".to_owned());
        }
    }
    let egress = &runtime.egress;
    if egress.default_allow
        || !egress.allowed_hosts.is_empty()
        || egress.rate_per_minute.map(NonZeroU32::get)
            != Some(TAIRA_INROU_EGRESS_RATE_PER_MINUTE_V1)
        || egress.max_bytes_per_minute.map(NonZeroU64::get)
            != Some(TAIRA_INROU_EGRESS_MAX_BYTES_PER_MINUTE_V1)
    {
        return Err(
            "Taira launcher requires the exact deny-by-default V1 Inrou egress profile".to_owned(),
        );
    }
    Ok(())
}

fn validate_taira_storage_profile_v1(
    local_budget_bytes: Option<u64>,
    effective_budget_bytes: Option<u64>,
    weights: NexusStorageWeights,
    configured_sorafs_capacity_bytes: Option<u64>,
    sorafs_provider_enabled: bool,
    sorafs_capacity_bytes: u64,
) -> Result<(), String> {
    if local_budget_bytes != Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1)
        || effective_budget_bytes != Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1)
    {
        return Err(format!(
            "Taira launcher requires the exact {TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1}-byte Nexus storage budget"
        ));
    }
    if weights.kura_blocks_bps != TAIRA_NEXUS_KURA_BLOCKS_BPS_V1
        || weights.wsv_snapshots_bps != TAIRA_NEXUS_WSV_SNAPSHOTS_BPS_V1
        || weights.sorafs_bps != TAIRA_NEXUS_SORAFS_BPS_V1
    {
        return Err("Taira launcher requires the exact V1 Nexus storage weights".to_owned());
    }
    if configured_sorafs_capacity_bytes != Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1) {
        return Err(format!(
            "Taira launcher requires an explicit {TAIRA_SORAFS_STORAGE_CAP_BYTES_V1}-byte SoraFS storage cap before Nexus clamping"
        ));
    }
    if sorafs_provider_enabled {
        return Err(
            "Taira launcher requires embedded SoraFS provider storage to be disabled".to_owned(),
        );
    }
    if sorafs_capacity_bytes != TAIRA_SORAFS_STORAGE_CAP_BYTES_V1 {
        return Err(format!(
            "Taira launcher requires the exact {TAIRA_SORAFS_STORAGE_CAP_BYTES_V1}-byte effective SoraFS storage cap"
        ));
    }
    Ok(())
}

fn validate_taira_launcher_config_v1(config: &Config) -> Result<(), String> {
    if config.nexus.storage.max_wsv_memory_bytes.get()
        != iroha_config::parameters::defaults::taira::NEXUS_MAX_WSV_MEMORY_BYTES
    {
        return Err("Taira launcher requires the exact bounded WSV memory budget".to_owned());
    }
    let trusted_peers = config.common.trusted_peers.value();
    validate_taira_launcher_profile_v1(
        config.common.chain.as_ref(),
        *config.common.chain_discriminant.value(),
        trusted_peers.others.len().saturating_add(1),
        trusted_peers.validator_roster_len(),
        &config.soracloud_runtime,
    )?;
    validate_taira_storage_profile_v1(
        config
            .nexus
            .storage
            .local_budget_bytes
            .map(|bytes| bytes.get()),
        config
            .nexus
            .storage
            .effective_local_budget_bytes
            .map(|bytes| bytes.get()),
        config.nexus.storage.disk_budget_weights,
        config
            .nexus
            .storage
            .configured_sorafs_max_capacity_bytes()
            .map(|bytes| bytes.get()),
        config.torii.sorafs_storage.enabled,
        config.torii.sorafs_storage.max_capacity_bytes.get(),
    )
}

/// Fixed-descriptor signer startup failure with payload-free display.
#[derive(Debug)]
pub enum TairaRuntimeSignerErrorV1 {
    /// Original local decoder failure, retained until the registry boundary.
    CredentialDecode(norito::core::DecodeAttemptError),
    /// Original local session admission or construction failure until the registry boundary.
    CredentialSession(iroha_core::beacon::GlobalThresholdBeaconSessionError),
    /// Exact original credential producer refusal; never invalid key material.
    CredentialOutput(iroha_core::beacon::credential::GlobalBeaconCredentialEncodeErrorV1),
    /// The credential is locally unavailable without a more specific original cause.
    CredentialUnavailable,
    /// A fixed runtime descriptor is absent or unreadable.
    DescriptorUnavailable,
    /// The descriptor does not identify one stable owner-only regular file.
    UntrustedDescriptor,
    /// The file does not contain exactly one canonical Ed25519 key record.
    InvalidKey,
}

impl fmt::Display for TairaRuntimeSignerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DescriptorUnavailable => "Taira runtime signer descriptor is unavailable",
            Self::CredentialUnavailable => "Taira beacon credential memory is unavailable",
            Self::CredentialDecode(_) => "Taira beacon credential decoder is unavailable",
            Self::CredentialSession(_) => "Taira beacon credential session is unavailable",
            Self::CredentialOutput(_) => "Taira beacon credential output is unavailable",
            Self::UntrustedDescriptor => "Taira runtime signer descriptor is not trusted",
            Self::InvalidKey => "Taira runtime signer key record is invalid",
        })
    }
}

impl std::error::Error for TairaRuntimeSignerErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CredentialDecode(error) => Some(error),
            Self::CredentialSession(error) => Some(error),
            Self::CredentialOutput(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorIdentityV1 {
    device: u64,
    inode: u64,
    length: u64,
    owner: u32,
    mode: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl DescriptorIdentityV1 {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            owner: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    /// Whether `metadata` of the erased descriptor still describes the checked file: the same
    /// regular inode with the same owner and mode, now empty. A launcher removes the one-shot
    /// pathname once it observes the empty file, which may precede this check, so the link
    /// count is either unchanged or zero; any other count (such as a new hard link) is
    /// rejected.
    fn same_security_identity_after_consumption(&self, metadata: &std::fs::Metadata) -> bool {
        metadata.is_file()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.owner
            && metadata.mode() == self.mode
            && (metadata.nlink() == self.links || metadata.nlink() == 0)
            && metadata.len() == 0
    }
}

/// Erase the loaded record from its one-shot file, then confirm that the descriptor still
/// identifies the checked file.
fn consume_trusted_key_file(
    file: &mut File,
    identity: &DescriptorIdentityV1,
    zeroed_key_record: &[u8],
) -> Result<(), TairaRuntimeSignerErrorV1> {
    erase_trusted_key_file(file, zeroed_key_record)?;
    verify_consumed_key_file(file, identity)
}

/// Overwrite the record with zeroes and truncate the file. Launchers treat the empty file as
/// consumed and may remove its one-shot pathname from then on.
fn erase_trusted_key_file(
    file: &mut File,
    zeroed_key_record: &[u8],
) -> Result<(), TairaRuntimeSignerErrorV1> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    file.write_all(zeroed_key_record)
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    file.sync_data()
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    file.set_len(0)
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    file.sync_data()
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)
}

/// Confirm that the erased descriptor still identifies the checked, now empty file.
fn verify_consumed_key_file(
    file: &File,
    identity: &DescriptorIdentityV1,
) -> Result<(), TairaRuntimeSignerErrorV1> {
    let consumed = file
        .metadata()
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    if !identity.same_security_identity_after_consumption(&consumed) {
        return Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor);
    }
    Ok(())
}

pub(crate) fn load_private_record_from_file<T>(
    mut file: File,
    record_bytes: u64,
    parse: impl FnOnce(&[u8]) -> Result<T, TairaRuntimeSignerErrorV1>,
) -> Result<T, TairaRuntimeSignerErrorV1> {
    let before_metadata = file
        .metadata()
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    let before = DescriptorIdentityV1::from_metadata(&before_metadata);
    let effective_uid = rustix::process::geteuid().as_raw();
    if !before_metadata.is_file()
        || before.owner != effective_uid
        || before.mode & 0o7777 != 0o600
        || before.links != 1
        || before.length != record_bytes
    {
        return Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor);
    }
    let capacity =
        usize::try_from(record_bytes).map_err(|_| TairaRuntimeSignerErrorV1::InvalidKey)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity + 1));
    std::io::Read::by_ref(&mut file)
        .take(record_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    let after = DescriptorIdentityV1::from_metadata(
        &file
            .metadata()
            .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?,
    );
    if after != before || bytes.len() != capacity {
        return Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor);
    }
    let parsed = parse(&bytes);
    if matches!(
        &parsed,
        Err(TairaRuntimeSignerErrorV1::CredentialUnavailable
            | TairaRuntimeSignerErrorV1::CredentialDecode(_)
            | TairaRuntimeSignerErrorV1::CredentialSession(_)
            | TairaRuntimeSignerErrorV1::CredentialOutput(_))
    ) {
        // A host-local refusal is retryable; it must not consume the original credential.
        return parsed;
    }
    bytes.fill(0);
    consume_trusted_key_file(&mut file, &before, &bytes)?;
    parsed
}

fn load_key_pair_from_file(file: File) -> Result<KeyPair, TairaRuntimeSignerErrorV1> {
    load_private_record_from_file(file, TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1, |bytes| {
        node_secrets::parse_ed25519_signer_record_v1(bytes)
            .ok_or(TairaRuntimeSignerErrorV1::InvalidKey)
    })
}

#[allow(
    unsafe_code,
    reason = "the daemon launcher transfers unique ownership of fixed inherited descriptors"
)]
pub(crate) fn take_inherited_private_file(
    descriptor: RawFd,
) -> Result<File, TairaRuntimeSignerErrorV1> {
    if !matches!(
        descriptor,
        TAIRA_RUNTIME_SIGNER_FD_V1 | TAIRA_GLOBAL_BEACON_CREDENTIAL_FD_V1
    ) {
        return Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let descriptor_path = format!("/proc/self/fd/{descriptor}");
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let descriptor_path = format!("/dev/fd/{descriptor}");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(descriptor_path)
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?;
    // SAFETY: the deployment supervisor transfers each fixed descriptor to this launcher as
    // its only owner. Opening its kernel descriptor path proves it is live before ownership
    // is constructed. Drop closes the inherited descriptor; the owned duplicate is consumed.
    let inherited = unsafe { File::from_raw_fd(descriptor) };
    drop(inherited);
    Ok(file)
}

fn load_global_beacon_signer_from_file(
    file: File,
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
    TairaRuntimeSignerErrorV1,
> {
    let length = file
        .metadata()
        .map_err(|_| TairaRuntimeSignerErrorV1::DescriptorUnavailable)?
        .len();
    let maximum =
        u64::try_from(iroha_core::beacon::credential::MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1)
            .map_err(|_| TairaRuntimeSignerErrorV1::InvalidKey)?;
    if length == 0 || length > maximum {
        return Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor);
    }
    load_private_record_from_file(file, length, |bytes| {
        crate::external_software_signer::decode_global_beacon_runtime_signer_v1(
            bytes, network_id, configured, budget,
        )
        .map_err(|error| match error {
            crate::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::DecodeResource(error) => TairaRuntimeSignerErrorV1::CredentialDecode(error),
            crate::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::Session(error) => TairaRuntimeSignerErrorV1::CredentialSession(error),
            crate::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::Output(error) => TairaRuntimeSignerErrorV1::CredentialOutput(error),
            crate::external_software_signer::RuntimeConsensusThresholdSignerCredentialErrorV1::Unavailable => TairaRuntimeSignerErrorV1::CredentialUnavailable,
            _ => TairaRuntimeSignerErrorV1::InvalidKey,
        })
    })
}

fn load_inherited_global_beacon_signer(
    network_id: &NetworkId,
    configured: &IrohaRuntimeProviderBindingV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<
    Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
    TairaRuntimeSignerErrorV1,
> {
    load_global_beacon_signer_from_file(
        take_inherited_private_file(TAIRA_GLOBAL_BEACON_CREDENTIAL_FD_V1)?,
        network_id,
        configured,
        budget,
    )
}

fn load_inherited_key_pair() -> Result<KeyPair, TairaRuntimeSignerErrorV1> {
    load_key_pair_from_file(take_inherited_private_file(TAIRA_RUNTIME_SIGNER_FD_V1)?)
}

/// Compiled public binding of the inherited-descriptor Taira signer.
const TAIRA_RUNTIME_SIGNER_POLICY_V1: node_secrets::RuntimeSignerPolicyV1 =
    node_secrets::RuntimeSignerPolicyV1 {
        handle_prefix: TAIRA_RUNTIME_SIGNER_HANDLE_PREFIX_V1,
        revision: TAIRA_RUNTIME_SIGNER_REVISION_V1,
        policy_digest: taira_runtime_signer_policy_digest_v1,
    };

/// The shared file-backed signer under the Taira policy.
fn taira_runtime_signer(
    key_pair: KeyPair,
) -> Result<node_secrets::FileRuntimeSignerV1, TairaRuntimeSignerErrorV1> {
    node_secrets::FileRuntimeSignerV1::new(TAIRA_RUNTIME_SIGNER_POLICY_V1, key_pair)
        .ok_or(TairaRuntimeSignerErrorV1::InvalidKey)
}

struct TairaRuntimeProviderRegistryV1 {
    credential_budget: std::sync::OnceLock<iroha_allocation::AllocationBudget>,
    signer: Arc<node_secrets::FileRuntimeSignerV1>,
}

impl TairaRuntimeProviderRegistryV1 {
    fn from_inherited_descriptor() -> Result<Self, TairaRuntimeSignerErrorV1> {
        Ok(Self {
            credential_budget: std::sync::OnceLock::new(),
            signer: Arc::new(taira_runtime_signer(load_inherited_key_pair()?)?),
        })
    }
}

fn select_taira_provider_bindings<'a>(
    bindings: impl IntoIterator<Item = &'a IrohaRuntimeProviderBindingV1>,
) -> Result<
    (
        &'a IrohaRuntimeProviderBindingV1,
        Option<&'a IrohaRuntimeProviderBindingV1>,
    ),
    IrohaRuntimeProviderRegistryErrorV1,
> {
    let mut soracloud = None;
    let mut beacon = None;
    for binding in bindings {
        let previous = match binding.slot() {
            IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner => {
                soracloud.replace(binding)
            }
            IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner => beacon.replace(binding),
            _ => return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution),
        };
        if previous.is_some() {
            return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
        }
    }
    Ok((
        soracloud.ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?,
        beacon,
    ))
}

impl TairaRuntimeProviderRegistryV1 {
    fn resolve_with_beacon_loader(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
        load_beacon: impl FnOnce(
            &NetworkId,
            &IrohaRuntimeProviderBindingV1,
            &iroha_allocation::AllocationBudget,
        ) -> Result<
            Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
            TairaRuntimeSignerErrorV1,
        >,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
        let (requested, beacon) = select_taira_provider_bindings(bindings.iter())?;
        let credential_budget = self
            .credential_budget
            .get_or_init(|| bindings.new_credential_registry_budget_v1());
        if credential_budget.limit_bytes() != bindings.credential_max_memory_bytes() {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        let exact = requested
            .soracloud_runtime_signer_binding()
            .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        let qualification = self
            .signer
            .qualification()
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::Unavailable)?;
        if exact.handle() != self.signer.handle()
            || exact.authority() != &self.signer.authority()
            || exact.public_key() != self.signer.signer_public_key()
            || exact.qualification() != qualification
        {
            return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
        }
        let signer: Arc<dyn SoracloudRuntimeMutationSignerV1> = self.signer.clone();
        let mut dependencies =
            IrohaRuntimeDeps::default().with_soracloud_runtime_mutation_signer(signer);
        if let Some(beacon) = beacon {
            let signer =
                load_beacon(bindings.network_id(), beacon, credential_budget).map_err(|error| {
                    match error {
                        TairaRuntimeSignerErrorV1::DescriptorUnavailable
                        | TairaRuntimeSignerErrorV1::CredentialUnavailable
                        | TairaRuntimeSignerErrorV1::CredentialDecode(_)
                        | TairaRuntimeSignerErrorV1::CredentialSession(_)
                        | TairaRuntimeSignerErrorV1::CredentialOutput(_) => {
                            IrohaRuntimeProviderRegistryErrorV1::Unavailable
                        }
                        TairaRuntimeSignerErrorV1::UntrustedDescriptor
                        | TairaRuntimeSignerErrorV1::InvalidKey => {
                            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
                        }
                    }
                })?;
            dependencies = dependencies.with_sumeragi_global_beacon_partial_signer(signer);
        }
        Ok(dependencies)
    }
}

impl IrohaRuntimeProviderRegistryV1 for TairaRuntimeProviderRegistryV1 {
    fn resolve(
        &self,
        bindings: &IrohaRuntimeProviderBindingsV1,
    ) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
        self.resolve_with_beacon_loader(bindings, load_inherited_global_beacon_signer)
    }
}

/// Run Taira with consumed signer descriptor 198 and optional beacon credential 200.
///
/// Config validation, help, and version introspection remain offline and do not
/// read the descriptors. Every node-starting invocation resolves exactly the
/// Soracloud signer and any explicitly configured global-beacon signer through [`crate::run_with_runtime_provider_registry`].
pub fn main_entry(build: iroha_core::release_identity::CompiledBuildMetadata) {
    if crate::external_software_signer::dispatch_beacon_custody_preparation_if_requested() {
        return;
    }
    if crate::beacon_bootstrap::dispatch_if_requested() {
        return;
    }
    crate::soracloud_runtime::dispatch_inrou_internal_launcher_if_requested();
    if std::env::args_os().any(|argument| invocation_does_not_start_a_node(&argument)) {
        if let Err(report) = crate::run_with_config_guard(build, validate_taira_launcher_config_v1)
        {
            eprintln!("{report:?}");
            std::process::exit(1);
        }
        return;
    }
    let registry = match TairaRuntimeProviderRegistryV1::from_inherited_descriptor() {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    if let Err(report) = crate::run_with_runtime_provider_registry_and_config_guard(
        build,
        &registry,
        validate_taira_launcher_config_v1,
    ) {
        eprintln!("{report:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    fn beacon_test_budget() -> iroha_allocation::AllocationBudget {
        iroha_allocation::AllocationBudget::new(64 * 1024 * 1024)
    }
    use super::*;
    use crate::soracloud_runtime_signer::SoracloudRuntimeSigningErrorV1;
    use iroha_crypto::{Algorithm, ExposedPrivateKey};
    use iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1;
    use iroha_data_model::{
        NetworkId,
        block::BlockHeader,
        soracloud::encode_soracloud_runtime_provenance_preimage_v1,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use std::{
        fs,
        num::{NonZeroU32, NonZeroUsize},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    };

    fn canonical_runtime_profile() -> SoracloudRuntime {
        let mut runtime = SoracloudRuntime::default();
        runtime.production_mode = true;
        runtime.hydration_concurrency = std::num::NonZeroUsize::new(
            iroha_config::parameters::defaults::taira::HYDRATION_CONCURRENCY,
        )
        .expect("nonzero Taira worker capacity");
        runtime.prepared_runtime_cache_capacity = std::num::NonZeroUsize::new(
            iroha_config::parameters::defaults::taira::PREPARED_RUNTIME_CACHE_CAPACITY,
        )
        .expect("nonzero Taira worker capacity");
        runtime.inrou.enabled = true;
        runtime.inrou.portable_vm_uid = NonZeroU32::new(70_000);
        runtime.inrou.portable_vm_gid = NonZeroU32::new(70_000);
        runtime.inrou.guest_image_max_bytes = NonZeroU64::new(TAIRA_INROU_GUEST_IMAGE_MAX_BYTES_V1)
            .expect("nonzero guest-image budget");
        runtime.inrou.max_cpu_millis =
            NonZeroU32::new(TAIRA_INROU_MAX_CPU_MILLIS_V1).expect("nonzero CPU budget");
        runtime.inrou.max_memory_bytes =
            NonZeroU64::new(TAIRA_INROU_MAX_MEMORY_BYTES_V1).expect("nonzero memory budget");
        runtime.inrou.max_storage_bytes =
            NonZeroU64::new(TAIRA_INROU_MAX_STORAGE_BYTES_V1).expect("nonzero storage budget");
        runtime.inrou.start_grace = Duration::from_millis(TAIRA_INROU_START_GRACE_MS_V1);
        runtime.inrou.stop_grace = Duration::from_millis(TAIRA_INROU_STOP_GRACE_MS_V1);
        runtime.egress.default_allow = false;
        runtime.egress.allowed_hosts.clear();
        runtime.egress.rate_per_minute = NonZeroU32::new(TAIRA_INROU_EGRESS_RATE_PER_MINUTE_V1);
        runtime.egress.max_bytes_per_minute =
            NonZeroU64::new(TAIRA_INROU_EGRESS_MAX_BYTES_PER_MINUTE_V1);
        runtime
    }

    fn canonical_core_runtime_profile() -> SoracloudRuntime {
        let mut runtime = canonical_runtime_profile();
        // Core testnet has no Inrou table; its disabled limits use the typed defaults.
        runtime.inrou = Default::default();
        runtime
    }

    #[test]
    fn offline_introspection_never_requires_the_runtime_signer() {
        for argument in ["--check-config", "--help", "-h", "--version", "-V"] {
            assert!(invocation_does_not_start_a_node(OsStr::new(argument)));
        }
        for argument in ["--config", "--sora", "--genesis-manifest-json"] {
            assert!(!invocation_does_not_start_a_node(OsStr::new(argument)));
        }
    }

    #[test]
    fn launcher_profile_is_exact_and_has_no_generic_network_fallback() {
        let runtime = canonical_runtime_profile();
        validate_taira_launcher_profile_v1(
            TAIRA_CHAIN_ID_V1,
            TAIRA_CHAIN_DISCRIMINANT_V1,
            TAIRA_VALIDATOR_COUNT_V1,
            TAIRA_VALIDATOR_COUNT_V1,
            &runtime,
        )
        .expect("canonical Taira profile");
        assert!(
            validate_taira_launcher_profile_v1(
                "iroha3-taira",
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                &runtime,
            )
            .is_err()
        );
        assert!(
            validate_taira_launcher_profile_v1(
                TAIRA_CHAIN_ID_V1,
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1 - 1,
                TAIRA_VALIDATOR_COUNT_V1,
                &runtime,
            )
            .is_err()
        );
        validate_taira_launcher_profile_v1(
            TAIRA_CHAIN_ID_V1,
            TAIRA_CHAIN_DISCRIMINANT_V1,
            TAIRA_VALIDATOR_COUNT_V1,
            TAIRA_VALIDATOR_COUNT_V1,
            &canonical_core_runtime_profile(),
        )
        .expect("canonical Core-only Taira profile");
        let mut exact_inrou = runtime.clone();
        for slot in 0..soracloud_runtime_defaults::INROU_PORTABLE_VM_ID_SLOT_COUNT {
            let id = soracloud_runtime_defaults::INROU_PORTABLE_VM_ID_BASE + slot;
            exact_inrou.inrou.portable_vm_uid = NonZeroU32::new(id);
            exact_inrou.inrou.portable_vm_gid = NonZeroU32::new(id);
            validate_taira_launcher_profile_v1(
                TAIRA_CHAIN_ID_V1,
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                &exact_inrou,
            )
            .expect("Taira accepts every canonical same-host PortableVM identity slot");
        }
        exact_inrou.inrou.portable_vm_uid = NonZeroU32::new(70_000);
        exact_inrou.inrou.portable_vm_gid = NonZeroU32::new(70_001);
        assert!(
            validate_taira_launcher_profile_v1(
                TAIRA_CHAIN_ID_V1,
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                &exact_inrou,
            )
            .is_err(),
            "Taira must reject mismatched Inrou uid/gid slots"
        );
        let mut configured_identity = runtime;
        configured_identity.inrou.portable_vm_gid = None;
        assert!(
            validate_taira_launcher_profile_v1(
                TAIRA_CHAIN_ID_V1,
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                &configured_identity,
            )
            .is_err()
        );
    }

    #[test]
    fn launcher_core_profile_rejects_stale_inrou_custody() {
        let runtime = canonical_core_runtime_profile();
        let assert_rejected = |runtime: &SoracloudRuntime| {
            let error = validate_taira_launcher_profile_v1(
                TAIRA_CHAIN_ID_V1,
                TAIRA_CHAIN_DISCRIMINANT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                TAIRA_VALIDATOR_COUNT_V1,
                runtime,
            )
            .expect_err("disabled Inrou cannot retain guest custody");
            assert!(error.contains("disabled Taira Inrou hosting"), "{error}");
        };

        let mut stale_uid = runtime.clone();
        stale_uid.inrou.portable_vm_uid = NonZeroU32::new(70_000);
        assert_rejected(&stale_uid);

        let mut stale_gid = runtime.clone();
        stale_gid.inrou.portable_vm_gid = NonZeroU32::new(70_000);
        assert_rejected(&stale_gid);

        let mut stale_guest = runtime;
        stale_guest.inrou.trusted_guest_artifact = Some(
            iroha_data_model::soracloud::SoraPublishedInrouGuestImageArtifactV1 {
                manifest_digest_hex: String::new(),
                content_cid: String::new(),
            },
        );
        assert_rejected(&stale_guest);
    }

    #[test]
    fn launcher_profile_rejects_noncanonical_inrou_resources_and_egress() {
        let runtime = canonical_runtime_profile();
        let assert_rejected = |runtime: &SoracloudRuntime| {
            assert!(
                validate_taira_launcher_profile_v1(
                    TAIRA_CHAIN_ID_V1,
                    TAIRA_CHAIN_DISCRIMINANT_V1,
                    TAIRA_VALIDATOR_COUNT_V1,
                    TAIRA_VALIDATOR_COUNT_V1,
                    runtime,
                )
                .is_err()
            );
        };

        let mut changed = runtime.clone();
        changed.hydration_concurrency = NonZeroUsize::new(
            std::num::NonZeroUsize::new(
                iroha_config::parameters::defaults::taira::HYDRATION_CONCURRENCY,
            )
            .expect("nonzero Taira worker capacity")
            .get()
                + 1,
        )
        .expect("changed hydration-worker count is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.prepared_runtime_cache_capacity = NonZeroUsize::new(
            std::num::NonZeroUsize::new(
                iroha_config::parameters::defaults::taira::PREPARED_RUNTIME_CACHE_CAPACITY,
            )
            .expect("nonzero Taira worker capacity")
            .get()
                + 1,
        )
        .expect("changed prepared-runtime capacity is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.guest_image_max_bytes =
            NonZeroU64::new(TAIRA_INROU_GUEST_IMAGE_MAX_BYTES_V1 + 1)
                .expect("changed guest-image budget is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.max_cpu_millis = NonZeroU32::new(TAIRA_INROU_MAX_CPU_MILLIS_V1 + 1)
            .expect("changed CPU budget is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.max_memory_bytes = NonZeroU64::new(TAIRA_INROU_MAX_MEMORY_BYTES_V1 + 1)
            .expect("changed memory budget is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.max_storage_bytes = NonZeroU64::new(TAIRA_INROU_MAX_STORAGE_BYTES_V1 + 1)
            .expect("changed storage budget is nonzero");
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.start_grace = Duration::from_millis(TAIRA_INROU_START_GRACE_MS_V1 + 1);
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.inrou.stop_grace = Duration::from_millis(TAIRA_INROU_STOP_GRACE_MS_V1 + 1);
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.egress.default_allow = true;
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed
            .egress
            .allowed_hosts
            .push("example.invalid".to_owned());
        assert_rejected(&changed);

        let mut changed = runtime.clone();
        changed.egress.rate_per_minute = NonZeroU32::new(TAIRA_INROU_EGRESS_RATE_PER_MINUTE_V1 + 1);
        assert_rejected(&changed);

        let mut changed = runtime;
        changed.egress.max_bytes_per_minute =
            NonZeroU64::new(TAIRA_INROU_EGRESS_MAX_BYTES_PER_MINUTE_V1 + 1);
        assert_rejected(&changed);
    }

    fn canonical_storage_weights() -> NexusStorageWeights {
        NexusStorageWeights {
            kura_blocks_bps: TAIRA_NEXUS_KURA_BLOCKS_BPS_V1,
            wsv_snapshots_bps: TAIRA_NEXUS_WSV_SNAPSHOTS_BPS_V1,
            sorafs_bps: TAIRA_NEXUS_SORAFS_BPS_V1,
        }
    }

    #[test]
    fn launcher_storage_profile_rejects_noncanonical_budgets_caps_and_provider() {
        assert_eq!(
            u64::try_from(
                u128::from(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1)
                    * u128::from(TAIRA_NEXUS_SORAFS_BPS_V1)
                    / 10_000,
            )
            .expect("Taira SoraFS cap fits u64"),
            TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            "the compiled cap must be the exact floor of the canonical weighted budget"
        );
        let canonical = || {
            validate_taira_storage_profile_v1(
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                canonical_storage_weights(),
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                false,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            )
        };
        canonical().expect("canonical Taira storage profile");
        assert_eq!(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1, 4 * 1024 * 1024 * 1024);
        assert_eq!(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1, 2560 * 1024 * 1024);
        assert!(
            validate_taira_storage_profile_v1(
                Some(1024 * 1024 * 1024),
                Some(1024 * 1024 * 1024),
                NexusStorageWeights {
                    kura_blocks_bps: 6_000,
                    wsv_snapshots_bps: 2_000,
                    sorafs_bps: 2_000,
                },
                Some(214_748_364),
                false,
                214_748_364,
            )
            .is_err(),
            "the undersized profile cannot admit the first-release guest"
        );

        assert!(
            validate_taira_storage_profile_v1(
                None,
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                canonical_storage_weights(),
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                false,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            )
            .is_err()
        );
        assert!(
            validate_taira_storage_profile_v1(
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1 - 1),
                canonical_storage_weights(),
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                false,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            )
            .is_err()
        );

        let mut wrong_weights = canonical_storage_weights();
        wrong_weights.kura_blocks_bps -= 1;
        wrong_weights.sorafs_bps += 1;
        assert!(
            validate_taira_storage_profile_v1(
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                wrong_weights,
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                false,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            )
            .is_err()
        );
        assert!(
            validate_taira_storage_profile_v1(
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                canonical_storage_weights(),
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                true,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
            )
            .is_err()
        );
        assert!(
            validate_taira_storage_profile_v1(
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                canonical_storage_weights(),
                Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1),
                false,
                TAIRA_SORAFS_STORAGE_CAP_BYTES_V1 - 1,
            )
            .is_err()
        );

        for configured_cap in [
            None,
            Some(0),
            Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1 - 1),
            Some(TAIRA_SORAFS_STORAGE_CAP_BYTES_V1 + 1),
            Some(iroha_config::parameters::defaults::sorafs::storage::MAX_CAPACITY_BYTES.get()),
        ] {
            assert!(
                validate_taira_storage_profile_v1(
                    Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                    Some(TAIRA_NEXUS_STORAGE_BUDGET_BYTES_V1),
                    canonical_storage_weights(),
                    configured_cap,
                    false,
                    TAIRA_SORAFS_STORAGE_CAP_BYTES_V1,
                )
                .is_err(),
                "normalized noncanonical source cap {configured_cap:?} must be rejected"
            );
        }
    }

    fn key_file(key_pair: &KeyPair) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("temporary signer directory");
        let path = directory.path().join("runtime.private_key");
        let literal = ExposedPrivateKey(key_pair.private_key().clone())
            .try_to_multihash_string()
            .expect("canonical private key");
        assert_eq!(
            literal.len() + 1,
            usize::try_from(TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1)
                .expect("fixed Taira key length fits usize")
        );
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        writeln!(options.open(&path).expect("create signer key"), "{literal}")
            .expect("write signer key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect signer key");
        (directory, path)
    }

    fn open_consumable_key_file(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open consumable signer key")
    }

    #[test]
    fn descriptor_loader_accepts_only_canonical_owner_only_ed25519() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x31; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let (_directory, path) = key_file(&key_pair);
        let loaded =
            load_key_pair_from_file(open_consumable_key_file(&path)).expect("load signer key");
        assert_eq!(loaded.public_key(), key_pair.public_key());
        assert_eq!(fs::metadata(path).expect("consumed key metadata").len(), 0);
    }

    #[test]
    fn consumption_preserves_restart_source_and_starves_child_descriptor() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x36; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let (directory, source_path) = key_file(&key_pair);
        let launch_path = directory.path().join("runtime.fd198");
        fs::copy(&source_path, &launch_path).expect("stage consumable launch key");
        fs::set_permissions(&launch_path, fs::Permissions::from_mode(0o600))
            .expect("protect launch key");
        let child_descriptor = File::open(&launch_path).expect("open child descriptor probe");

        load_key_pair_from_file(open_consumable_key_file(&launch_path))
            .expect("consume staged launch key");
        assert_eq!(
            fs::metadata(&source_path)
                .expect("persistent restart source metadata")
                .len(),
            TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1
        );
        assert_eq!(
            fs::metadata(&launch_path)
                .expect("consumed launch metadata")
                .len(),
            0
        );
        let output = std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::from(child_descriptor))
            .output()
            .expect("spawn child descriptor probe");
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn descriptor_loader_rejects_mode_and_link_substitution() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let (directory, path) = key_file(&key_pair);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weaken mode");
        assert!(matches!(
            load_key_pair_from_file(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
        fs::hard_link(&path, directory.path().join("linked.private_key"))
            .expect("create hard link");
        assert!(matches!(
            load_key_pair_from_file(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));
    }

    /// A consumable owner-only launch copy of `key_pair`'s record beside its retained source.
    fn staged_launch_key(
        key_pair: &KeyPair,
        name: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let (directory, source) = key_file(key_pair);
        let launch = directory.path().join(name);
        fs::copy(&source, &launch).expect("stage consumable launch key");
        fs::set_permissions(&launch, fs::Permissions::from_mode(0o600))
            .expect("protect launch key");
        (directory, launch)
    }

    #[test]
    fn consumption_accepts_the_launcher_removing_its_path_before_or_after_the_final_check() {
        use std::os::unix::fs::MetadataExt as _;

        let key_pair =
            KeyPair::try_from_seed(vec![0x37; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        // The launcher removes the one-shot pathname after the daemon's final check.
        let (_directory, launch) = staged_launch_key(&key_pair, "after.fd198");
        let loaded = load_key_pair_from_file(open_consumable_key_file(&launch))
            .expect("consume while the launch path exists");
        assert_eq!(loaded.public_key(), key_pair.public_key());
        assert_eq!(fs::metadata(&launch).expect("consumed launch").len(), 0);
        fs::remove_file(&launch).expect("launcher removes the consumed path");

        // The launcher removes it as soon as it sees the empty file, before the final check.
        let (_directory, launch) = staged_launch_key(&key_pair, "before.fd198");
        let mut file = open_consumable_key_file(&launch);
        let identity =
            DescriptorIdentityV1::from_metadata(&file.metadata().expect("launch metadata"));
        erase_trusted_key_file(&mut file, &[0; 71]).expect("erase launch record");
        fs::remove_file(&launch).expect("launcher removes the consumed path");
        assert_eq!(file.metadata().expect("unlinked metadata").nlink(), 0);
        verify_consumed_key_file(&file, &identity)
            .expect("an erased file keeps its identity after its path is removed");
    }

    #[test]
    fn consumption_rejects_a_link_or_mode_change_after_erasure() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x38; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let (directory, launch) = staged_launch_key(&key_pair, "linked.fd198");
        let mut file = open_consumable_key_file(&launch);
        let identity =
            DescriptorIdentityV1::from_metadata(&file.metadata().expect("launch metadata"));
        erase_trusted_key_file(&mut file, &[0; 71]).expect("erase launch record");
        fs::hard_link(&launch, directory.path().join("alias.fd198")).expect("add a link");
        assert!(matches!(
            verify_consumed_key_file(&file, &identity),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));

        let (_directory, launch) = staged_launch_key(&key_pair, "chmod.fd198");
        let mut file = open_consumable_key_file(&launch);
        let identity =
            DescriptorIdentityV1::from_metadata(&file.metadata().expect("launch metadata"));
        erase_trusted_key_file(&mut file, &[0; 71]).expect("erase launch record");
        fs::set_permissions(&launch, fs::Permissions::from_mode(0o644)).expect("weaken mode");
        fs::remove_file(&launch).expect("launcher removes the consumed path");
        assert!(matches!(
            verify_consumed_key_file(&file, &identity),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));
    }

    #[test]
    fn key_consumption_races_a_launcher_that_removes_the_emptied_path() {
        // Like the localnet launcher, this launcher watches its own descriptor of the one-shot
        // file and removes the pathname as soon as the daemon's truncation empties it, racing
        // the daemon's post-consumption check.
        let key_pair =
            KeyPair::try_from_seed(vec![0x64; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        for round in 0..16 {
            let (_directory, launch) =
                staged_launch_key(&key_pair, &format!("launch-{round}.fd198"));
            let observer = File::open(&launch).expect("launcher descriptor");
            let path = launch.clone();
            let launcher = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while observer.metadata().expect("launcher fstat").len() != 0 {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the daemon never consumed the launch file"
                    );
                    std::thread::yield_now();
                }
                fs::remove_file(&path).expect("launcher removes the consumed path");
            });
            let loaded = load_key_pair_from_file(open_consumable_key_file(&launch));
            launcher.join().expect("launcher thread");
            assert_eq!(
                loaded
                    .expect("consumption tolerates the removed launch path")
                    .public_key(),
                key_pair.public_key()
            );
            assert!(!launch.exists());
        }
    }

    #[test]
    fn descriptor_loader_rejects_noncanonical_or_wrong_algorithm_records() {
        let key_pair =
            KeyPair::try_from_seed(vec![0xAB; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let (_directory, path) = key_file(&key_pair);
        let mut bytes = fs::read(&path).expect("read canonical key");
        let letter = bytes
            .iter_mut()
            .find(|byte| byte.is_ascii_hexdigit() && byte.is_ascii_alphabetic())
            .expect("canonical private key contains a hex letter");
        if letter.is_ascii_lowercase() {
            letter.make_ascii_uppercase();
        } else {
            letter.make_ascii_lowercase();
        }
        fs::write(&path, bytes).expect("replace key casing");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect key");
        assert!(matches!(
            load_key_pair_from_file(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::InvalidKey)
        ));
        assert_eq!(fs::metadata(path).expect("consumed key metadata").len(), 0);

        let wrong_algorithm = KeyPair::try_from_seed(vec![0xBC; 32], Algorithm::Secp256k1)
            .expect("non-Ed25519 fixture key");
        let (_directory, path) = key_file(&wrong_algorithm);
        assert_eq!(
            fs::metadata(&path).expect("wrong algorithm metadata").len(),
            TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1
        );
        assert!(matches!(
            load_key_pair_from_file(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::InvalidKey)
        ));
        assert_eq!(
            fs::metadata(path)
                .expect("consumed wrong algorithm metadata")
                .len(),
            0
        );
    }

    #[test]
    fn signer_binds_handle_authority_and_exact_payload() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x34; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let signer = taira_runtime_signer(key_pair).expect("Taira signer");
        assert!(
            signer
                .handle()
                .starts_with(TAIRA_RUNTIME_SIGNER_HANDLE_PREFIX_V1)
        );
        let payload = TransactionBuilder::new(
            NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed([0x51; iroha_crypto::Hash::LENGTH]),
                ),
            ),
            signer.authority(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .into_payload()
        .expect("transaction payload");
        let signed_transaction = signer
            .sign_transaction(payload.clone())
            .expect("sign exact transaction");
        assert_eq!(signed_transaction.payload(), &payload);
        signed_transaction
            .verify_signature()
            .expect("valid signature");
    }

    #[test]
    fn signer_policy_digest_binds_the_compiled_policy() {
        let digest = taira_runtime_signer_policy_digest_v1();
        assert_ne!(digest, [0; 32]);
        let mut altered = TAIRA_RUNTIME_SIGNER_COMPILED_POLICY_V1.to_vec();
        altered.push(b'!');
        let mut hasher = blake3::Hasher::new();
        hasher.update(TAIRA_RUNTIME_SIGNER_POLICY_DIGEST_DOMAIN_V1);
        hasher.update(&TAIRA_RUNTIME_SIGNER_REVISION_V1.to_be_bytes());
        hasher.update(
            &u64::try_from(altered.len())
                .expect("altered policy length fits u64")
                .to_be_bytes(),
        );
        hasher.update(&altered);
        assert_ne!(digest, *hasher.finalize().as_bytes());
    }

    #[test]
    fn signer_rejects_cross_purpose_provenance() {
        let key_pair =
            KeyPair::try_from_seed(vec![0x35; 32], Algorithm::Ed25519).expect("Ed25519 key pair");
        let signer = taira_runtime_signer(key_pair).expect("Taira signer");
        let withdrawal = encode_soracloud_runtime_provenance_preimage_v1(
            SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw,
            b"canonical-withdrawal-payload",
        )
        .expect("encode withdrawal preimage");
        let signature = signer
            .sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw,
                &withdrawal,
            )
            .expect("sign matching purpose");
        signature
            .verify(signer.signer_public_key(), &withdrawal)
            .expect("matching-purpose signature verifies");
        assert!(matches!(
            signer.sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
                &withdrawal,
            ),
            Err(SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage)
        ));
        assert!(matches!(
            signer.sign_provenance(
                SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw,
                b"bare-account-id-payload",
            ),
            Err(SoracloudRuntimeSigningErrorV1::InvalidProvenancePreimage)
        ));
    }

    fn beacon_file(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("temporary beacon credential directory");
        let path = directory.path().join("beacon.fd200");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create consumable synthetic beacon credential");
        file.write_all(bytes)
            .expect("write synthetic beacon credential");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect credential");
        (directory, path)
    }

    fn beacon_config(
        registry: &TairaRuntimeProviderRegistryV1,
        network_id: NetworkId,
        beacon: Option<&IrohaRuntimeProviderBindingV1>,
    ) -> Config {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/kagami/iroha3-dev/peer0.toml");
        let source = fs::read_to_string(path).expect("read checked-in default config only");
        let mut table: toml::Table = toml::from_str(&source).expect("parse checked-in default");
        let genesis = table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("default genesis table");
        assert_eq!(
            genesis.remove("expected_hash_file"),
            Some(toml::Value::String("genesis.expected_hash".to_owned()))
        );
        assert!(
            genesis
                .insert(
                    "expected_hash".to_owned(),
                    toml::Value::String(network_id.to_string())
                )
                .is_none()
        );
        let mut config =
            Config::from_toml_source(iroha_config_base::toml::TomlSource::inline(table))
                .expect("parse public fixture trust without runtime identity files");
        let signer = &registry.signer;
        config.soracloud_runtime.submission.signer = Some(
            iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding {
                handle: signer.handle().to_owned(),
                authority: signer.authority(),
                algorithm: Algorithm::Ed25519,
                public_key: signer.signer_public_key().clone(),
                revision: TAIRA_RUNTIME_SIGNER_REVISION_V1,
                policy_digest: taira_runtime_signer_policy_digest_v1(),
            },
        );
        config.sumeragi.global_beacon_partial_signer_provider_handle =
            beacon.map(|b| b.handle().to_owned());
        config
            .sumeragi
            .global_beacon_partial_signer_provider_revision = beacon.and_then(|b| b.revision());
        config
            .sumeragi
            .global_beacon_partial_signer_provider_policy_digest =
            beacon.and_then(|b| b.policy_digest());
        config
    }

    fn fixture_key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x37; 32], Algorithm::Ed25519).expect("fixture Soracloud key")
    }

    fn fixture_registry() -> TairaRuntimeProviderRegistryV1 {
        TairaRuntimeProviderRegistryV1 {
            credential_budget: std::sync::OnceLock::new(),
            signer: Arc::new(
                taira_runtime_signer(fixture_key_pair()).expect("fixture Soracloud signer"),
            ),
        }
    }

    fn disposable_broker_policy() -> iroha_config::parameters::actual::RuntimeProviderBroker {
        iroha_config::parameters::actual::RuntimeProviderBroker::from_toml_source(
            iroha_config_base::toml::TomlSource::inline(
                "".parse().expect("empty public broker policy table"),
            ),
        )
        .expect("validated default broker policy")
    }

    #[test]
    fn disposable_broker_policy_mismatch_precedes_credential_reads_and_signer_loading() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        for supplied in [1, fixture.catalog.credential_max_memory_bytes() + 1] {
            let mut policy = disposable_broker_policy();
            policy.credential_max_memory_bytes =
                std::num::NonZeroUsize::new(supplied).expect("nonzero test policy");
            let mut reader = std::io::Cursor::new([0xA5; 32]);
            assert!(matches!(
                disposable_broker::load_with_signer(&fixture.catalog, &policy, &mut reader, || {
                    panic!("policy mismatch must not consume unrelated signer custody")
                }),
                Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
            ));
            assert_eq!(reader.position(), 0);
        }
    }

    #[test]
    fn disposable_broker_composes_exact_soracloud_and_threshold_catalogs() {
        use crate::{
            RuntimeProviderBrokerBackendRegistryV1 as _,
            external_software_signer::encode_consensus_threshold_credential_bundle_v1,
        };

        let beacon =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let signer = fixture_registry();
        for (with_soracloud, with_beacon) in [(true, false), (false, true), (true, true)] {
            let catalog = if with_soracloud {
                IrohaRuntimeProviderBindingsV1::try_from_config(&beacon_config(
                    &signer,
                    *beacon.catalog.network_id(),
                    with_beacon.then(|| beacon.catalog.iter().next().unwrap()),
                ))
                .unwrap()
            } else {
                beacon.catalog.clone()
            };
            let bundle = encode_consensus_threshold_credential_bundle_v1(
                with_beacon.then_some(beacon.credential.as_slice()),
                None,
            )
            .unwrap();
            let (_directory, path) = key_file(&fixture_key_pair());
            let mut loaded_signer = false;
            let registry = disposable_broker::load_with_signer(
                &catalog,
                &disposable_broker_policy(),
                &mut bundle.as_slice(),
                || {
                    loaded_signer = true;
                    Ok(Arc::new(taira_runtime_signer(load_key_pair_from_file(
                        open_consumable_key_file(&path),
                    )?)?))
                },
            )
            .expect("complete exact broker custody");
            assert_eq!(loaded_signer, with_soracloud);
            assert_eq!(
                fs::metadata(path).unwrap().len(),
                if with_soracloud {
                    0
                } else {
                    TAIRA_RUNTIME_SIGNER_KEY_FILE_BYTES_V1
                }
            );
            registry.resolve(&catalog).expect("complete backend set");
            let substituted =
                catalog
                    .clone()
                    .with_network_id_for_test(NetworkId::from_genesis_hash(
                        iroha_crypto::HashOf::from_untyped_unchecked(
                            iroha_crypto::Hash::prehashed([0xD8; 32]),
                        ),
                    ));
            assert!(matches!(
                registry.resolve(&substituted),
                Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
            ));
        }
    }

    #[test]
    fn disposable_broker_rejects_catalog_and_credential_substitution() {
        use crate::external_software_signer::encode_consensus_threshold_credential_bundle_v1;

        let beacon =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let signer = fixture_registry();
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&beacon_config(
            &signer,
            *beacon.catalog.network_id(),
            beacon.catalog.iter().next(),
        ))
        .unwrap();
        let complete =
            encode_consensus_threshold_credential_bundle_v1(Some(&beacon.credential), None)
                .unwrap();
        let empty = encode_consensus_threshold_credential_bundle_v1(None, None).unwrap();
        assert!(
            disposable_broker::load_with_signer(
                &catalog,
                &disposable_broker_policy(),
                &mut empty.as_slice(),
                || { panic!("missing beacon custody must fail before consuming signer custody") }
            )
            .is_err()
        );
        let wrong = KeyPair::from_seed(vec![0x38; 32], Algorithm::Ed25519);
        assert!(matches!(
            disposable_broker::load_with_signer(
                &catalog,
                &disposable_broker_policy(),
                &mut complete.as_slice(),
                || { Ok(Arc::new(taira_runtime_signer(wrong)?)) }
            ),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        assert!(matches!(
            disposable_broker::load_with_signer(
                &catalog,
                &disposable_broker_policy(),
                &mut complete.as_slice(),
                || { Err(TairaRuntimeSignerErrorV1::DescriptorUnavailable) }
            ),
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
    }

    #[test]
    fn disposable_broker_rejects_unsupported_slots_before_reading_credentials() {
        let unsupported = IrohaRuntimeProviderBindingsV1::qualified_for_test(
            "disposable-catalog-test",
            IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider,
            "software://private/prf",
            1,
            [0x91; 32],
        );
        let mut input = std::io::Cursor::new([0xA5; 32]);
        assert!(matches!(
            disposable_broker::load_with_signer(
                &unsupported,
                &disposable_broker_policy(),
                &mut input,
                || { panic!("unrequested signer credential must remain untouched") }
            ),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn beacon_loader_consumes_exact_credential_and_verifies_native_signature() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let binding = fixture
            .catalog
            .iter()
            .next()
            .expect("one exact beacon provider");
        let (directory, source) = beacon_file(&fixture.credential);
        let launch = directory.path().join("launch.fd200");
        fs::copy(&source, &launch).expect("stage launch credential");
        let mut child = File::open(&launch).expect("child descriptor probe");
        let signer = load_global_beacon_signer_from_file(
            open_consumable_key_file(&launch),
            fixture.catalog.network_id(),
            binding,
            &beacon_test_budget(),
        )
        .expect("load exact native beacon credential");
        assert_eq!(
            fs::metadata(&source).expect("restart source").len(),
            u64::try_from(fixture.credential.len()).expect("credential length")
        );
        assert_eq!(fs::metadata(&launch).expect("consumed descriptor").len(), 0);
        assert_eq!(child.read(&mut [0_u8; 1]).expect("consumed child inode"), 0);
        let digest =
            iroha_core::beacon::credential::global_beacon_partial_signer_public_inventory_digest_v1(
                *fixture.catalog.network_id(),
                &[(fixture.session.record(), 1)],
            )
            .expect("derive public inventory without private components");
        assert_eq!(binding.policy_digest(), Some(digest));
        let anchor = iroha_data_model::consensus::GlobalThresholdBeaconChainAnchorV1 {
            height: 40,
            block_hash: iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0x91; 32]),
            ),
        };
        let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
            fixture.session.clone(),
            41,
            anchor,
            iroha_core::beacon::pulse_context_fixture_v1(),
        )
        .expect("canonical pulse payload");
        let partial = signer
            .sign_partial(&fixture.session, verifier.payload())
            .expect("native custody signs exact pulse");
        assert!(
            verifier
                .accept_partial(partial)
                .expect("native cryptographic partial verification")
        );
    }

    #[test]
    fn beacon_loader_rejects_wrong_network_qualification_and_corruption() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let exact = fixture.catalog.iter().next().expect("exact provider");
        let foreign_network = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xD7; 32]),
            ),
        );
        assert_ne!(foreign_network, *fixture.catalog.network_id());
        let (_directory, path) = beacon_file(&fixture.credential);
        assert!(matches!(
            load_global_beacon_signer_from_file(
                open_consumable_key_file(&path),
                &foreign_network,
                exact,
                &beacon_test_budget(),
            ),
            Err(TairaRuntimeSignerErrorV1::InvalidKey)
        ));
        assert_eq!(
            fs::metadata(path)
                .expect("consumed foreign credential")
                .len(),
            0
        );
        for (handle, revision, digest) in [
            (
                "software://different-beacon-owner",
                exact.revision().expect("revision"),
                exact.policy_digest().expect("digest"),
            ),
            (
                exact.handle(),
                exact.revision().expect("revision") + 1,
                exact.policy_digest().expect("digest"),
            ),
            (
                exact.handle(),
                exact.revision().expect("revision"),
                [0xD8; 32],
            ),
        ] {
            let wrong = IrohaRuntimeProviderBindingsV1::qualified_for_test(
                "bound-credential-fixture",
                IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner,
                handle,
                revision,
                digest,
            )
            .with_network_id_for_test(*fixture.catalog.network_id());
            let (_directory, path) = beacon_file(&fixture.credential);
            assert!(matches!(
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    fixture.catalog.network_id(),
                    wrong.iter().next().expect("substituted provider"),
                    &beacon_test_budget(),
                ),
                Err(TairaRuntimeSignerErrorV1::InvalidKey)
            ));
            assert_eq!(
                fs::metadata(path)
                    .expect("consumed substituted credential")
                    .len(),
                0
            );
        }
        let mut corrupt = Zeroizing::new(fixture.credential.to_vec());
        corrupt[0] ^= 1;
        let (_directory, path) = beacon_file(&corrupt);
        assert!(matches!(
            load_global_beacon_signer_from_file(
                open_consumable_key_file(&path),
                fixture.catalog.network_id(),
                exact,
                &beacon_test_budget(),
            ),
            Err(TairaRuntimeSignerErrorV1::InvalidKey)
        ));
        assert_eq!(
            fs::metadata(path)
                .expect("consumed malformed credential")
                .len(),
            0
        );
    }

    #[test]
    fn beacon_loader_rejects_untrusted_descriptor_and_size() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let binding = fixture.catalog.iter().next().expect("exact provider");
        let load = |file| {
            load_global_beacon_signer_from_file(
                file,
                fixture.catalog.network_id(),
                binding,
                &beacon_test_budget(),
            )
        };
        for size in [
            0,
            u64::try_from(
                iroha_core::beacon::credential::MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1,
            )
            .expect("max size")
                + 1,
        ] {
            let (_directory, path) = beacon_file(&[]);
            open_consumable_key_file(&path)
                .set_len(size)
                .expect("set bounded size fixture");
            assert!(matches!(
                load(open_consumable_key_file(&path)),
                Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
            ));
        }
        let (directory, path) = beacon_file(&fixture.credential);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weaken credential");
        assert!(matches!(
            load(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore credential");
        let alias = directory.path().join("alias");
        fs::hard_link(&path, &alias).expect("create alias");
        assert!(matches!(
            load(open_consumable_key_file(&path)),
            Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
        ));
        fs::remove_file(alias).expect("remove alias");
        assert!(matches!(
            load(File::open(&path).expect("read-only credential")),
            Err(TairaRuntimeSignerErrorV1::DescriptorUnavailable)
        ));
        assert_ne!(
            fs::metadata(path).expect("unconsumable credential").len(),
            0
        );
        for fd in [-1, 0, 197, 201] {
            assert!(matches!(
                take_inherited_private_file(fd),
                Err(TairaRuntimeSignerErrorV1::UntrustedDescriptor)
            ));
        }
    }

    #[test]
    fn registry_allows_bootstrap_without_beacon_and_rejects_extra_or_duplicate_slots() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let registry = fixture_registry();
        let config = beacon_config(&registry, *fixture.catalog.network_id(), None);
        let bindings =
            IrohaRuntimeProviderBindingsV1::try_from_config(&config).expect("bootstrap catalog");
        let dependencies = registry
            .resolve_with_beacon_loader(&bindings, |_, _, _| {
                panic!("bootstrap must not access FD200")
            })
            .expect("bootstrap Soracloud signer only");
        assert!(dependencies.soracloud_runtime_mutation_signer.is_some());
        assert!(dependencies.sumeragi_global_beacon_partial_signer.is_none());
        let soracloud = bindings.iter().next().expect("Soracloud binding");
        let beacon = fixture.catalog.iter().next().expect("beacon binding");
        for duplicated in [
            vec![soracloud, soracloud],
            vec![soracloud, beacon, beacon],
            vec![beacon],
        ] {
            assert!(matches!(
                select_taira_provider_bindings(duplicated),
                Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
            ));
        }
        let mut extra = config.clone();
        extra
            .gov
            .parliament_tle_partial_release_signer_provider_handle =
            Some("software://unexpected-tle".to_owned());
        extra
            .gov
            .parliament_tle_partial_release_signer_provider_revision = Some(1);
        extra
            .gov
            .parliament_tle_partial_release_signer_provider_policy_digest = Some([0xD3; 32]);
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&extra)
            .expect("valid but unsupported public provider");
        assert!(matches!(
            registry.resolve_with_beacon_loader(&bindings, |_, _, _| panic!(
                "extra provider rejected before FD200"
            )),
            Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)
        ));
    }

    #[test]
    fn registry_resolves_exact_configured_beacon_and_preserves_soracloud_binding() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let registry = fixture_registry();
        let beacon = fixture.catalog.iter().next().expect("beacon provider");
        let config = beacon_config(&registry, *fixture.catalog.network_id(), Some(beacon));
        let bindings =
            IrohaRuntimeProviderBindingsV1::try_from_config(&config).expect("two exact providers");
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings.network_id(), fixture.catalog.network_id());
        let (_directory, path) = beacon_file(&fixture.credential);
        let dependencies = registry
            .resolve_with_beacon_loader(&bindings, |network_id, configured, budget| {
                assert_eq!(network_id, fixture.catalog.network_id());
                assert_eq!(configured, beacon);
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    network_id,
                    configured,
                    budget,
                )
            })
            .expect("resolve both exact native signers");
        assert!(dependencies.soracloud_runtime_mutation_signer.is_some());
        assert!(dependencies.sumeragi_global_beacon_partial_signer.is_some());
        assert_eq!(
            fs::metadata(path).expect("credential consumed once").len(),
            0
        );
        assert!(matches!(
            registry.resolve_with_beacon_loader(&bindings, |_, _, _| Err(
                TairaRuntimeSignerErrorV1::DescriptorUnavailable
            )),
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
        let mut wrong = config;
        wrong
            .soracloud_runtime
            .submission
            .signer
            .as_mut()
            .expect("configured Soracloud")
            .policy_digest[0] ^= 1;
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&wrong)
            .expect("qualified substituted Soracloud binding");
        assert!(matches!(
            registry.resolve_with_beacon_loader(&bindings, |_, _, _| panic!(
                "Soracloud mismatch rejected before FD200"
            )),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
    }
    #[test]
    fn beacon_memory_refusal_preserves_consumable_descriptor_and_uses_original_retry_pool() {
        use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
        use std::task::{Context, Waker};

        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let binding = fixture.catalog.iter().next().unwrap();
        let (_directory, path) = beacon_file(&fixture.credential);
        let budget = beacon_test_budget();
        let floor = ReleaseRegistration::allocation_layout().size();
        let mut prepaid = budget.try_reserve_bytes(floor).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - floor)
            .unwrap();
        let failed = load_global_beacon_signer_from_file(
            open_consumable_key_file(&path),
            fixture.catalog.network_id(),
            binding,
            &budget,
        )
        .err()
        .expect("actual original session admission refusal");
        assert_eq!(
            failed.to_string(),
            "Taira beacon credential session is unavailable"
        );
        assert!(std::error::Error::source(&failed).is_some());
        let TairaRuntimeSignerErrorV1::CredentialSession(
            iroha_core::beacon::GlobalThresholdBeaconSessionError::Admission(original),
        ) = failed
        else {
            panic!("the original session refusal must survive until the actual registry boundary");
        };
        let AllocationRefusal::Capacity {
            requested_bytes,
            ref release,
            ..
        } = original
        else {
            panic!("the retained original graph is blocked by its actual pool");
        };
        assert_eq!(
            original,
            budget.try_reserve_bytes(requested_bytes).unwrap_err()
        );
        let mut context = Context::from_waker(Waker::noop());
        assert!(registration.poll_wait(release, &mut context).is_pending());
        let foreign_pool = iroha_allocation::AllocationBudget::new(1);
        drop(foreign_pool.try_reserve_bytes(1).unwrap());
        assert!(
            registration.poll_wait(release, &mut context).is_pending(),
            "foreign release cannot authorize original custody retry"
        );
        assert_eq!(
            fs::read(&path).unwrap().as_slice(),
            fixture.credential.as_slice()
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        assert!(registration.poll_wait(release, &mut context).is_ready());
        registration.cancel();
        let signer = load_global_beacon_signer_from_file(
            open_consumable_key_file(&path),
            fixture.catalog.network_id(),
            binding,
            &budget,
        )
        .unwrap();
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        let retained = budget.reserved_bytes();
        assert!(retained > floor);
        let last_reader = signer.clone();
        drop(signer);
        assert_eq!(budget.reserved_bytes(), retained);
        drop(last_reader);
        assert_eq!(budget.reserved_bytes(), floor);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn registry_reuses_one_configured_pool_and_rejects_bound_changes_before_loading() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let registry = fixture_registry();
        let binding = fixture.catalog.iter().next().unwrap();
        let mut config = beacon_config(&registry, *fixture.catalog.network_id(), Some(binding));
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&config).unwrap();
        let (_directory, path) = beacon_file(&fixture.credential);
        let dependencies = registry
            .resolve_with_beacon_loader(&catalog, |network, binding, budget| {
                assert_eq!(budget.limit_bytes(), catalog.credential_max_memory_bytes());
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    network,
                    binding,
                    budget,
                )
            })
            .unwrap();
        let original = registry.credential_budget.get().unwrap();
        let retained = original.reserved_bytes();
        assert!(retained > 0);
        let blocker = original
            .try_reserve_bytes(original.limit_bytes() - retained)
            .unwrap();
        let (_directory_two, path_two) = beacon_file(&fixture.credential);
        assert!(matches!(
            registry.resolve_with_beacon_loader(&catalog, |network, binding, budget| {
                assert!(budget.same_pool(original));
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path_two),
                    network,
                    binding,
                    budget,
                )
            }),
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
        assert_eq!(original.reserved_bytes(), original.limit_bytes());
        assert_eq!(
            fs::read(&path_two).unwrap().as_slice(),
            fixture.credential.as_slice()
        );
        config.runtime_provider_broker.credential_max_memory_bytes =
            std::num::NonZeroUsize::new(original.limit_bytes() + 1).unwrap();
        let substituted = IrohaRuntimeProviderBindingsV1::try_from_config(&config).unwrap();
        assert!(matches!(
            registry.resolve_with_beacon_loader(&substituted, |_, _, _| panic!(
                "changed bound must fail before loading"
            )),
            Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)
        ));
        drop(blocker);
        assert_eq!(original.reserved_bytes(), retained);
        drop(dependencies);
        assert_eq!(original.reserved_bytes(), 0);
    }

    #[test]
    fn beacon_decode_refusal_preserves_consumable_descriptor_and_original_cause_until_retry() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let binding = fixture.catalog.iter().next().unwrap();
        let (_directory, path) = beacon_file(&fixture.credential);
        let budget = beacon_test_budget();
        let failed = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || {
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    fixture.catalog.network_id(),
                    binding,
                    &budget,
                )
            },
        )
        .err()
        .expect("actual original credential decode refusal");
        assert_eq!(
            failed.to_string(),
            "Taira beacon credential decoder is unavailable"
        );
        assert!(std::error::Error::source(&failed).is_some());
        let TairaRuntimeSignerErrorV1::CredentialDecode(error) = failed else {
            panic!("local pressure must retain the consumable credential");
        };
        assert_eq!(
            error.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(matches!(
            error.into_error(),
            norito::Error::ScopedDecodeResource(_)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            fs::read(&path).unwrap().as_slice(),
            fixture.credential.as_slice()
        );
        let signer = load_global_beacon_signer_from_file(
            open_consumable_key_file(&path),
            fixture.catalog.network_id(),
            binding,
            &budget,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().len(),
            0,
            "successful import still consumes the trusted launch descriptor"
        );
        drop(signer);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn inherited_decode_failure_is_unavailable_at_both_runtime_registry_boundaries() {
        let fixture =
            crate::external_software_signer::consensus_threshold_beacon_broker_test_fixture_v1();
        let registry = fixture_registry();
        let binding = fixture.catalog.iter().next().unwrap();
        let config = beacon_config(&registry, *fixture.catalog.network_id(), Some(binding));
        let catalog = IrohaRuntimeProviderBindingsV1::try_from_config(&config).unwrap();
        let (_directory, path) = beacon_file(&fixture.credential);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        // The local loader finishes its scope before the registry classifies its original error.
        let failed = registry.resolve_with_beacon_loader(&catalog, |network, binding, budget| {
            norito::with_decode_limits_scope(limits, || {
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    network,
                    binding,
                    budget,
                )
            })
        });
        assert!(matches!(
            failed,
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
        assert_eq!(
            fs::read(&path).unwrap().as_slice(),
            fixture.credential.as_slice()
        );
        assert_eq!(
            registry.credential_budget.get().unwrap().reserved_bytes(),
            0
        );
        let dependencies = registry
            .resolve_with_beacon_loader(&catalog, |network, binding, budget| {
                load_global_beacon_signer_from_file(
                    open_consumable_key_file(&path),
                    network,
                    binding,
                    budget,
                )
            })
            .unwrap();
        drop(dependencies);
        assert_eq!(
            registry.credential_budget.get().unwrap().reserved_bytes(),
            0
        );

        let bundle =
            crate::external_software_signer::encode_consensus_threshold_credential_bundle_v1(
                Some(&fixture.credential),
                None,
            )
            .unwrap();
        let original = iroha_crypto::Hash::new(bundle.as_slice());
        let failed = norito::with_decode_limits_scope(limits, || {
            disposable_broker::load_with_signer(
                &fixture.catalog,
                &disposable_broker_policy(),
                &mut bundle.as_slice(),
                || panic!("threshold-only catalog never loads unrelated signer"),
            )
        });
        assert!(matches!(
            failed,
            Err(IrohaRuntimeProviderRegistryErrorV1::Unavailable)
        ));
        let loaded = disposable_broker::load_with_signer(
            &fixture.catalog,
            &disposable_broker_policy(),
            &mut bundle.as_slice(),
            || panic!("threshold-only catalog never loads unrelated signer"),
        )
        .unwrap();
        assert_eq!(iroha_crypto::Hash::new(bundle.as_slice()), original);
        drop(loaded);
    }
}
