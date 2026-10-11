//! Embedded Soracloud runtime-manager reconciliation for `irohad`.
//!
//! This subsystem continuously projects authoritative Soracloud world state
//! into a node-local materialization plan and now serves deterministic local
//! reads/apartment observations directly from the committed snapshot plus the
//! hydrated artifact cache. Soracloud runtime v1 runs IVM handlers directly
//! and supervises hosted HTTP revisions (`Inrou`) as loopback services.
//! PortableVM release workers run as an explicitly configured non-root Linux
//! identity inside private mount, network, IPC, UTS, PID, and cgroup namespaces.
//! The authenticated minimal root exposes only the fixed QEMU closure, KVM,
//! descriptor-bound read-only inputs and writable disks; QEMU has no host
//! `/run`, `/sys`, external network interface, or unrelated supervisor descriptor.
//! The supervisor retains the public listener and enters the attested private
//! network namespace only in a one-shot connector thread after re-attesting the
//! cgroup, namespace, mount, root, and anonymous-QMP state. Root-owned
//! `iptables` owner barriers protect the supervisor listener from local bypass.
//! An acknowledged anonymous pipe holds the namespace launcher until it is
//! placed in a unique cgroup-v2 worker subtree with finite CPU, memory, swap,
//! process, and backing-device IO limits. The generated guest app unit
//! separately enforces the admitted open-file, task, and ephemeral-storage
//! limits exactly.
//!
//! Ordered mailbox execution and public query local reads now run admitted IVM
//! bundles directly through the Soracloud host surface while asset local reads
//! still resolve from the committed snapshot plus hydrated artifact cache.
//! The Soracloud host has no ledger world-state snapshot, so it rejects the
//! complete state-backed AXT syscall family instead of delegating it to the
//! standalone core-host shim.
use eyre::WrapErr;
use iroha_core::soracloud_runtime::{
    SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_FILE_V1, SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1,
    SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1, SoracloudApartmentExecutionRequest,
    SoracloudApartmentExecutionResult, SoracloudHostedHttpReplicaRuntimeStateV1,
    SoracloudHostedHttpRuntimeStateV1, SoracloudLocalReadRequest, SoracloudLocalReadResponse,
    SoracloudOrderedMailboxExecutionRequest, SoracloudOrderedMailboxExecutionResult,
    SoracloudRuntime, SoracloudRuntimeApartmentPlan, SoracloudRuntimeArtifactPlan,
    SoracloudRuntimeExecutionError, SoracloudRuntimeExecutionErrorKind, SoracloudRuntimeInrouPlan,
    SoracloudRuntimeLeaseVolumePlan, SoracloudRuntimeMailboxPlan, SoracloudRuntimeReadHandle,
    SoracloudRuntimeReplicaPlan, SoracloudRuntimeRevisionRole, SoracloudRuntimeServicePlan,
    SoracloudRuntimeSnapshot,
};
use iroha_core::state::{State, StateView, WorldReadOnly};
use iroha_core::{
    executor::quote_nexus_fee_admission_draft, queue::Queue, tx::AcceptedTransaction,
};
use iroha_crypto::Hash;
#[cfg(test)]
use iroha_crypto::KeyPair;
#[cfg(test)]
use iroha_data_model::nexus::PublicLaneValidatorStatus;
#[cfg(test)]
use iroha_data_model::soracloud::SoraNetworkAllowlistEntryV1;
#[cfg(any(target_os = "linux", test))]
use iroha_data_model::soracloud::{
    SORA_INROU_DATA_VOLUME_MOUNT_ROOT_V1, SORA_INROU_MAX_VCPUS_V1, SoraResourceLimitsV1,
    sora_inrou_data_volume_mount_path_v1,
};
#[cfg(test)]
use iroha_data_model::soracloud::{
    SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1, SoraInrouReplicaHostAvailabilityV1,
};
#[cfg(test)]
use iroha_data_model::transaction::SignedTransaction;
use iroha_data_model::{
    Encode,
    account::AccountId,
    isi::{self, InstructionBox},
    smart_contract::{
        entrypoint::{
            EntrypointArgumentRecordV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
            entrypoint_argument_schema_hash_v1,
        },
        manifest::ManifestProvenance,
    },
    soracloud::{
        SORA_HTTP_SERVICE_REPLICA_MAX_V1, SORA_INROU_GUEST_IMAGE_MAX_MEMBERS_V1,
        SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1, SORA_INROU_HOSTED_REPLICA_CAPACITY_V1,
        SORA_INROU_PORTABLE_PATH_MAX_COMPONENTS_V1, SORA_INROU_REPLICA_RUNTIME_STATE_VERSION_V1,
        SORA_RUNTIME_RECEIPT_VERSION_V1, SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1,
        SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1, SORACLOUD_HOST_RESPONSE_VERSION_V1,
        SoraAgentApartmentRecordV1, SoraArtifactKindV1, SoraCertifiedResponsePolicyV1,
        SoraConfigExportTargetV1, SoraContainerRuntimeV1, SoraDeploymentBundleV1,
        SoraInrouGuestIsaV1, SoraInrouHostCapabilityRecordV1, SoraInrouReplicaPlacementV1,
        SoraInrouReplicaRuntimeStateV1, SoraLeaseVolumeKindV1, SoraNetworkPolicyV1,
        SoraPublishedInrouGuestImageArtifactV1, SoraRolloutStageV1, SoraRouteVisibilityV1,
        SoraRuntimeReceiptV1, SoraServiceDeploymentStateV1, SoraServiceExecutionPlaneV1,
        SoraServiceHandlerClassV1, SoraServiceHandlerV1, SoraServiceHealthStatusV1,
        SoraServiceLeaseStatusV1, SoraServiceLifecycleActionV1, SoraServiceMailboxMessageV1,
        SoraServiceRuntimeStateV1, SoraServiceStateEntryV1, SoraStateBindingV1,
        SoraStateMutationOperationV1, SoracloudAppendJournalResponseV1,
        SoracloudEmitMailboxMessageRequestV1, SoracloudEmitMailboxMessageResponseV1,
        SoracloudEmitStateMutationRequestV1, SoracloudEmitStateMutationResponseV1,
        SoracloudHostOperationV1, SoracloudHostRequestEnvelopeV1, SoracloudHostRequestPayloadV1,
        SoracloudHostResponseEnvelopeV1, SoracloudHostResponsePayloadV1,
        SoracloudPublishCheckpointResponseV1, SoracloudReadCommittedStateResponseV1,
        SoracloudReadConfigResponseV1, SoracloudReadSecretEnvelopeResponseV1,
        derive_soracloud_local_read_receipt_id_v1, derive_soracloud_mailbox_message_id_v1,
        encode_inrou_host_advertise_provenance_payload,
        encode_inrou_host_withdraw_provenance_payload,
    },
    sorafs::pin_registry::ManifestDigest,
    transaction::{TransactionBuilder, TransactionPayload},
};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal};
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
#[cfg(test)]
use iroha_torii::sorafs::api::StorageStoredFileDto;
use iroha_torii::sorafs::{
    EndpointKind, ProviderAdvertCache, ReplicationOrderV1, TransportProtocol,
    api::StorageManifestResponseDto,
    site::{decode_content_cid, encode_content_cid},
};
use ivm::{
    CoreHost, IVM, IVMHost, Memory, PointerType, PreparedArgumentRecord, PreparedContract,
    RuntimeTemplate, VMError, prepare_contract,
    syscalls::{
        self as ivm_syscalls, SYSCALL_SORACLOUD_APPEND_JOURNAL,
        SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE, SYSCALL_SORACLOUD_EMIT_STATE_MUTATION,
        SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT, SYSCALL_SORACLOUD_READ_COMMITTED_STATE,
        SYSCALL_SORACLOUD_READ_CONFIG, SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE,
    },
};
use mv::storage::StorageReadOnly;
use parking_lot::{Mutex, RwLock};
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
#[cfg(any(target_os = "linux", test))]
use sorafs_car::bundle_archive::{
    BundleArchiveEntry, BundleArchiveEntryKind, BundleArchiveLimits, visit_gzip_ustar,
};
use sorafs_car::{
    CarBuildPlan, CarChunk, CarWriter, FilePlan, compute_chunk_plan_digest_sha3, compute_por_root,
};
use sorafs_node::store::{StorageBackend, StoredManifest};
#[cfg(target_os = "linux")]
use std::io::BufRead as _;
#[cfg(any(target_os = "linux", test))]
use std::net::{Shutdown, TcpListener};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
#[cfg(all(unix, any(target_os = "linux", test)))]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileTypeExt as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(all(test, unix))]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;
#[cfg(any(target_os = "linux", test))]
use std::process::{Command, Stdio};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read as _, Seek as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs as _},
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
        mpsc,
    },
    thread,
    time::Duration,
};
use tokio::{sync::RwLock as AsyncRwLock, task::JoinHandle};
#[cfg(target_os = "linux")]
#[path = "soracloud_runtime/inrou_cgroup.rs"]
mod inrou_cgroup;
// Exercise the same portable sysfs resolver on developer hosts without compiling
// Linux-only cgroup and namespace syscalls into their daemon.
#[cfg(all(test, not(target_os = "linux")))]
#[path = "soracloud_runtime/inrou_cgroup/io_device.rs"]
mod inrou_cgroup_io_device_tests;
#[cfg(target_os = "linux")]
#[path = "soracloud_runtime/inrou_namespace.rs"]
mod inrou_namespace;
#[path = "soracloud_runtime/remote_stream_token_auth.rs"]
mod remote_stream_token_auth;

#[cfg(target_os = "linux")]
static INROU_SELF_EXEC_DISPATCH_ARMED: AtomicBool = AtomicBool::new(false);

/// Dispatch the exact post-exec Inrou namespace helper before daemon startup.
#[cfg(target_os = "linux")]
pub(crate) fn dispatch_inrou_internal_launcher_if_requested() {
    let stock_launcher = inrou_stock_self_executable_is_admitted();
    INROU_SELF_EXEC_DISPATCH_ARMED.store(stock_launcher, AtomicOrdering::Release);
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(inrou_cgroup::INROU_INTERNAL_LAUNCHER_ARG_V1))
    {
        return;
    }
    if !stock_launcher {
        eprintln!(
            "Inrou internal launcher failed: executable is not a root-custodied stock iroha3d launcher"
        );
        std::process::exit(126);
    }
    let arguments = arguments
        .take(inrou_cgroup::INROU_INTERNAL_LAUNCHER_MAX_ARGUMENTS + 1)
        .collect::<Vec<_>>();
    match inrou_cgroup::run_inrou_internal_launcher_v1(arguments) {
        Ok(status) => std::process::exit(status.code().unwrap_or(126)),
        Err(error) => {
            eprintln!("Inrou internal launcher failed: {error:#}");
            std::process::exit(126);
        }
    }
}

#[cfg(target_os = "linux")]
fn inrou_stock_self_executable_is_admitted() -> bool {
    let Ok(target) = fs::read_link("/proc/self/exe") else {
        return false;
    };
    fs::metadata("/proc/self/exe").ok().is_some_and(|metadata| {
        inrou_stock_self_executable_custody_is_admitted(
            &target,
            metadata.is_file(),
            metadata.uid(),
            metadata.nlink(),
            metadata.mode(),
        )
    })
}

#[cfg(target_os = "linux")]
fn inrou_stock_self_executable_custody_is_admitted(
    target: &Path,
    is_regular_file: bool,
    owner_uid: u32,
    link_count: u64,
    mode: u32,
) -> bool {
    target.is_absolute()
        && matches!(
            target.file_name().and_then(OsStr::to_str),
            Some("iroha3d" | "iroha3d_taira")
        )
        && is_regular_file
        && owner_uid == 0
        && link_count == 1
        && mode & 0o111 != 0
        && mode & 0o022 == 0
}

/// No Inrou internal launcher exists off Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) fn dispatch_inrou_internal_launcher_if_requested() {}

const INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS: u64 = 10_000;
const INROU_HOST_HEARTBEAT_TTL_FLOOR_MS: u64 = 300_000;
// Avoid rewriting authoritative adverts just to push the same heartbeat expiry forward.
const INROU_HOST_HEARTBEAT_REFRESH_MARGIN_FLOOR_MS: u64 = 60_000;
const INROU_PLACEMENT_RECONCILE_ATTEMPT_COOLDOWN_MS: u64 = 10_000;
const SORACLOUD_LOCAL_READ_MAX_SNAPSHOT_LAG_BLOCKS: u64 = 64;
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_BUNDLE_BLOCK_MEMBER: &str = "inrou_bundle.raw";
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_BUNDLE_DEVICE_SERIAL: &str = "sora_bundle";
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_BLOCK_SECTOR_BYTES: usize = 512;
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_BUNDLE_GUEST_ROOT: &str = "/var/lib/soracloud/materialization/bundle";
#[cfg(any(target_os = "linux", test))]
const INROU_GUEST_HARDENING_MARKER_PATH: &str =
    "/var/lib/soracloud/materialization/.inrou-guest-hardening-v1";
#[cfg(any(target_os = "linux", test))]
const INROU_GUEST_HARDENING_MARKER_BODY: &str = "inrou-guest-hardening-v1\n\
root-password-locked=1\n\
root-shell-nologin=1\n\
ssh-units-masked=1\n";
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_VOLUME_FILESYSTEM: &str = "ext4";
#[cfg(any(target_os = "linux", test))]
const INROU_PORTABLE_VOLUME_MOUNT_OPTIONS: &str =
    "rw,nosuid,nodev,noexec,nosymfollow,errors=remount-ro";
/// Largest variable response body a Soracloud syscall may materialize.
///
/// Host-produced TLVs spill from INPUT into HEAP. Accepting a body larger than
/// the maximum spill region could never succeed and would make pre-syscall gas
/// reservation unbounded.
const SORACLOUD_HOST_VARIABLE_RESPONSE_MAX_BYTES: usize = Memory::HEAP_MAX_SIZE as usize;
/// Largest HTTP content-type value copied into an IVM egress response.
const SORACLOUD_HTTP_RESPONSE_READ_BUFFER_BYTES: usize = 64 * 1024;
const SORACLOUD_HTTP_RESPONSE_INITIAL_ALLOCATION_BYTES: usize = 8 * 1024;
const SORACLOUD_REMOTE_MANIFEST_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const SORACLOUD_REMOTE_HYDRATION_PLAN_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const SORACLOUD_REMOTE_STREAM_TOKEN_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const SORACLOUD_REMOTE_CHUNK_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT: usize = 500;
const SORACLOUD_REMOTE_HYDRATION_MAX_SOURCES: usize = 4_096;
const SORACLOUD_REMOTE_HYDRATION_MAX_PROVIDERS_PER_SOURCE: usize = 128;
const SORACLOUD_REMOTE_HYDRATION_MAX_IN_MEMORY_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
const SORACLOUD_LOCAL_HYDRATION_STREAM_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
const SORACLOUD_OPERATOR_PRESEED_MAX_MANIFEST_SCAN_V1: usize = 10_000;
const SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_MAX_MESSAGE_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_MAX_MESSAGES_PER_COMMAND: usize = 32;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_ATTEST_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_POWERDOWN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_PROC_STATUS_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN: &str = "IROHA_INROU_V1";
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_CHAINS: [&str; 4] = [
    "IROHA_INROU_S0_V1",
    "IROHA_INROU_S1_V1",
    "IROHA_INROU_S2_V1",
    "IROHA_INROU_S3_V1",
];
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_CHAIN_MARKERS: [&str; 4] = [
    "iroha-inrou-owned-v1-slot-0",
    "iroha-inrou-owned-v1-slot-1",
    "iroha-inrou-owned-v1-slot-2",
    "iroha-inrou-owned-v1-slot-3",
];
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_LOCK_PATHS: [&str; 4] = [
    "/run/iroha-inrou-firewall-v1-slot-0.lock",
    "/run/iroha-inrou-firewall-v1-slot-1.lock",
    "/run/iroha-inrou-firewall-v1-slot-2.lock",
    "/run/iroha-inrou-firewall-v1-slot-3.lock",
];
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_MAX_OWNED_JUMPS: usize = 4;
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_BRIDGE_MAX_CONNECTIONS: usize = 256;
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_BRIDGE_SESSION_STACK_BYTES: usize = 256 * 1024;
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_BRIDGE_IO_POLL: Duration = Duration::from_millis(250);
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_BRIDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", test))]
// Each response direction durably prepays at most one 16-KiB window before a
// socket write. With the 256-session cap, a crash can overcharge at most 4 MiB
// per hosted replica, while it can never expose unaccounted response bytes.
const SORACLOUD_INROU_EGRESS_RESERVATION_BYTES: usize = 16 * 1024;
const SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR: &str = "inrou_egress_checkpoints";
const SORACLOUD_INROU_EGRESS_CHECKPOINT_MAGIC_V1: &[u8; 8] = b"INREGV1\0";
const SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1: usize = 80;
const SORACLOUD_INROU_EGRESS_CHECKPOINT_MAX_FILES_V1: usize = 65_536;
const SORACLOUD_INROU_LEASE_USAGE_RETRY_MS: u64 = 10_000;
const SORACLOUD_INROU_RUNTIME_STATE_RETRY_MS: u64 = SORACLOUD_INROU_LEASE_USAGE_RETRY_MS;
const SORACLOUD_EGRESS_DNS_MAX_ADDRESSES_V1: usize = 32;
const SORACLOUD_EGRESS_DNS_MAX_IN_FLIGHT_V1: usize = 4;
const SORACLOUD_EGRESS_DNS_TIMEOUT_V1: Duration = Duration::from_secs(5);
static SORACLOUD_EGRESS_DNS_IN_FLIGHT_V1: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_IO_POLL: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QMP_SESSION_ATTEST_TIMEOUT: Duration = Duration::from_secs(2);
const SORACLOUD_INROU_CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const SORACLOUD_INROU_ID_BASE: u32 =
    iroha_config::parameters::defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_BASE;
const SORACLOUD_INROU_ID_MAX_EXCLUSIVE: u32 =
    iroha_config::parameters::defaults::soracloud_runtime::INROU_PORTABLE_VM_ID_MAX_EXCLUSIVE;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_SERVICE_IDENTITY_PREFIX: &str = "iroha-inrou-";
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_SERVICE_HOME: &str = "/nonexistent";
#[cfg(any(target_os = "linux", test))]
// Linux misc-device major 10, KVM minor 232 in the kernel dev_t encoding.
const SORACLOUD_INROU_KVM_DEVICE_RDEV: u64 = (10_u64 << 8) | 232_u64;
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_QEMU_SANDBOX_POLICY: &str =
    "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny";
#[cfg(any(target_os = "linux", test))]
const SORACLOUD_INROU_LOG_TRUNCATION_MARKER: &[u8] =
    b"\n[Inrou runtime log truncated at the configured safety limit]\n";
const SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_MAX_REPLICAS: usize = 4_096;
const SORACLOUD_RUNTIME_STATE_MAX_STRING_BYTES: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const SORACLOUD_RUNTIME_STDERR_TAIL_BYTES: u64 = 64 * 1024;
const SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES: usize = 65_536;
const SORACLOUD_HYDRATION_MAX_REQUIRED_ARTIFACTS: usize = 65_536;
const SORACLOUD_RUNTIME_ARTIFACT_PATH_MAX_BYTES: usize = 4 * 1024;
fn build_remote_hydration_http_client(
    base_url: &reqwest::Url,
) -> eyre::Result<reqwest::blocking::Client> {
    let host = base_url
        .host_str()
        .ok_or_else(|| eyre::eyre!("remote Soracloud hydration origin has no host"))?;
    let resolved_addresses = resolve_soracloud_egress_socket_addrs(base_url).ok_or_else(|| {
        eyre::eyre!(
            "remote Soracloud hydration origin `{base_url}` did not resolve exclusively to bounded public addresses"
        )
    })?;
    build_soracloud_direct_http_client(
        host,
        &resolved_addresses,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .wrap_err("build DNS-pinned Soracloud remote hydration HTTP client")
}
fn read_soracloud_http_response_body_bounded(
    reader: &mut impl io::Read,
    declared_length: Option<u64>,
    maximum_bytes: u64,
) -> eyre::Result<Vec<u8>> {
    if maximum_bytes == 0 {
        eyre::bail!("Soracloud HTTP response byte limit must be positive");
    }
    if let Some(length) = declared_length
        && length > maximum_bytes
    {
        eyre::bail!(
            "Soracloud HTTP response Content-Length {length} exceeds the {maximum_bytes}-byte limit"
        );
    }
    let maximum = usize::try_from(maximum_bytes)
        .wrap_err("Soracloud HTTP response byte limit does not fit this host")?;
    let initial_capacity = declared_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(SORACLOUD_HTTP_RESPONSE_INITIAL_ALLOCATION_BYTES)
        .min(SORACLOUD_HTTP_RESPONSE_INITIAL_ALLOCATION_BYTES)
        .min(maximum);
    let mut body = Vec::new();
    body.try_reserve_exact(initial_capacity)
        .wrap_err("reserve initial Soracloud HTTP response buffer")?;
    let mut buffer = [0_u8; SORACLOUD_HTTP_RESPONSE_READ_BUFFER_BYTES];
    loop {
        let remaining = maximum
            .checked_sub(body.len())
            .ok_or_else(|| eyre::eyre!("Soracloud HTTP response body length overflow"))?;
        let read_capacity = remaining.min(buffer.len());
        if read_capacity == 0 {
            let read = read_soracloud_http_response_chunk(reader, &mut buffer[..1])?;
            if read == 0 {
                break;
            }
            eyre::bail!("Soracloud HTTP response body exceeds the {maximum_bytes}-byte limit");
        }
        let read = read_soracloud_http_response_chunk(reader, &mut buffer[..read_capacity])?;
        if read == 0 {
            break;
        }
        let required_len = body
            .len()
            .checked_add(read)
            .ok_or_else(|| eyre::eyre!("Soracloud HTTP response body length overflow"))?;
        reserve_soracloud_http_response_capacity(&mut body, required_len, maximum)?;
        body.extend_from_slice(&buffer[..read]);
    }
    let actual_length = u64::try_from(body.len()).unwrap_or(u64::MAX);
    if let Some(length) = declared_length
        && length != actual_length
    {
        eyre::bail!(
            "Soracloud HTTP response body length {actual_length} does not match Content-Length {length}"
        );
    }
    Ok(body)
}
fn reserve_soracloud_http_response_capacity(
    body: &mut Vec<u8>,
    required_len: usize,
    maximum: usize,
) -> eyre::Result<()> {
    if required_len > maximum {
        eyre::bail!("Soracloud HTTP response reservation exceeds its byte limit");
    }
    if body.capacity() >= required_len {
        return Ok(());
    }
    let growth_target = body
        .capacity()
        .max(1)
        .saturating_mul(2)
        .max(required_len)
        .min(maximum);
    body.try_reserve_exact(growth_target.saturating_sub(body.len()))
        .wrap_err("reserve Soracloud HTTP response buffer")
}
fn read_soracloud_http_response_chunk(
    reader: &mut impl io::Read,
    buffer: &mut [u8],
) -> eyre::Result<usize> {
    loop {
        match reader.read(buffer) {
            Ok(read) if read <= buffer.len() => return Ok(read),
            Ok(read) => {
                eyre::bail!(
                    "Soracloud HTTP response reader reported {read} bytes for a {}-byte buffer",
                    buffer.len()
                );
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).wrap_err("read Soracloud HTTP response body"),
        }
    }
}
fn read_soracloud_http_response_bounded(
    mut response: reqwest::blocking::Response,
    maximum_bytes: u64,
    label: &str,
) -> eyre::Result<Vec<u8>> {
    let declared_length = response.content_length();
    read_soracloud_http_response_body_bounded(&mut response, declared_length, maximum_bytes)
        .wrap_err_with(|| format!("read bounded {label} response"))
}
fn open_soracloud_regular_file_no_follow(
    path: &Path,
    label: &str,
) -> io::Result<(fs::File, fs::Metadata)> {
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() || !named.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} must be a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    if named.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} {} must have exactly one hard link, found {}",
                path.display(),
                named.nlink()
            ),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !same_soracloud_regular_file(&named, &opened) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} changed while it was opened", path.display()),
        ));
    }
    Ok((file, opened))
}
fn same_soracloud_regular_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if !left.is_file() || !right.is_file() || left.len() != right.len() {
        return false;
    }
    #[cfg(unix)]
    {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.nlink() == right.nlink()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.modified().ok() == right.modified().ok()
    }
}
fn read_soracloud_regular_file_bounded(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> io::Result<Vec<u8>> {
    if maximum_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} byte limit must be positive"),
        ));
    }
    let (mut file, fingerprint) = open_soracloud_regular_file_no_follow(path, label)?;
    if fingerprint.len() > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} {} requires {} bytes, exceeding the {maximum_bytes}-byte limit",
                path.display(),
                fingerprint.len()
            ),
        ));
    }
    let capacity = usize::try_from(fingerprint.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} is too large to address", path.display()),
        )
    })?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(capacity).map_err(|error| {
        io::Error::other(format!(
            "reserve {label} {} bounded buffer: {error}",
            path.display()
        ))
    })?;
    std::io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut payload)?;
    let observed = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if observed > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} {} exceeds the {maximum_bytes}-byte limit",
                path.display()
            ),
        ));
    }
    let opened_after = file.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    if observed != fingerprint.len()
        || !same_soracloud_regular_file(&fingerprint, &opened_after)
        || !same_soracloud_regular_file(&opened_after, &named_after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} changed while it was read", path.display()),
        ));
    }
    Ok(payload)
}
#[cfg(target_os = "linux")]
fn read_soracloud_regular_text_bounded(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> io::Result<String> {
    String::from_utf8(read_soracloud_regular_file_bounded(
        path,
        maximum_bytes,
        label,
    )?)
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
/// Runtime-manager configuration derived from the explicit Soracloud runtime settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SoracloudRuntimeManagerConfig {
    /// Whether runtime production posture checks are enabled.
    pub production_mode: bool,
    /// Root directory for local runtime materialization state.
    pub state_dir: PathBuf,
    /// Reconciliation cadence against authoritative state.
    pub reconcile_interval: Duration,
    /// Maximum concurrent artifact hydration workers, independent of Inrou guest concurrency.
    pub hydration_concurrency: NonZeroUsize,
    /// Maximum idle prepared IVM runtimes retained independently of hydration workers.
    pub prepared_runtime_cache_capacity: NonZeroUsize,
    /// Configured artifact-cache budgets for the embedded runtime manager.
    pub cache_budgets: iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets,
    /// Mutable `Inrou` microVM hosting limits.
    pub inrou: iroha_config::parameters::actual::SoracloudRuntimeInrou,
    /// Runtime-originated transaction submission settings.
    pub submission: iroha_config::parameters::actual::SoracloudRuntimeSubmission,
    /// Outbound egress policy for embedded runtimes.
    pub egress: iroha_config::parameters::actual::SoracloudRuntimeEgress,
    /// Local validator account used to enforce authoritative Inrou placement assignments.
    pub local_validator_account_id: Option<AccountId>,
    /// Local peer identifier used to confirm authoritative Inrou placement assignments.
    pub local_peer_id: Option<String>,
}
/// Internal sink used by the runtime manager to enqueue authoritative Soracloud mutations.
pub(crate) trait SoracloudRuntimeMutationSink: Send + Sync {
    /// Revalidate the production signer boundary before manager startup.
    ///
    /// Non-production recording and test sinks deliberately fail this check.
    fn ensure_production_qualified(&self) -> eyre::Result<()> {
        eyre::bail!("mutation sink is not backed by a qualified production signer")
    }
    /// Submit one authoritative Soracloud instruction through the normal transaction pipeline.
    fn submit_instruction(
        &self,
        instruction: InstructionBox,
        endpoint: &'static str,
    ) -> eyre::Result<()>;
    /// Submit or refresh the authoritative Inrou host advert using the sink's configured validator authority.
    fn submit_inrou_host_capability(
        &self,
        capability: &SoraInrouHostCapabilityRecordV1,
    ) -> eyre::Result<()>;
    /// Withdraw this sink's authoritative Inrou host advert.
    fn submit_inrou_host_withdrawal(&self, _validator_account_id: &AccountId) -> eyre::Result<()> {
        eyre::bail!("mutation sink does not support Inrou host withdrawal")
    }
    /// Submit an authoritative Inrou placement reconciliation request.
    fn submit_inrou_placement_reconcile(&self) -> eyre::Result<()> {
        self.submit_instruction(
            InstructionBox::from(isi::soracloud::ReconcileSoracloudInrouPlacements),
            "/internal/soracloud/runtime/inrou-placement-reconcile",
        )
    }
}
/// Queue-backed mutation sink used by `irohad` to report runtime-originated Soracloud health events.
#[derive(Clone)]
pub(crate) struct QueuedSoracloudRuntimeMutationSink {
    queue: Arc<Queue>,
    state: Arc<State>,
    authority: AccountId,
    binding: crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1,
    signer: Arc<dyn crate::soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1>,
    submission: iroha_config::parameters::actual::SoracloudRuntimeSubmission,
}
impl QueuedSoracloudRuntimeMutationSink {
    /// Construct a queue-backed sink using the exact configured external authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the public binding is missing or invalid, or when
    /// the injected provider is unavailable, substituted, stale, revoked, or
    /// test-marked.
    pub(crate) fn new(
        queue: Arc<Queue>,
        state: Arc<State>,
        signer: Arc<dyn crate::soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1>,
        submission: iroha_config::parameters::actual::SoracloudRuntimeSubmission,
    ) -> eyre::Result<Self> {
        let configured = submission.signer.as_ref().ok_or_else(|| {
            eyre::eyre!("queue-backed mutation sink requires a configured signer binding")
        })?;
        let binding =
            crate::soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_from_config(
                configured,
            )
            .map_err(|error| eyre::eyre!("invalid configured signer binding: {error:?}"))?;
        let signer = crate::soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
            binding.clone(),
            signer,
        )
        .map_err(|error| eyre::eyre!("runtime signer qualification failed: {error:?}"))?;
        let authority = binding.authority().clone();
        Ok(Self {
            queue,
            state,
            authority,
            binding,
            signer,
            submission,
        })
    }
}
impl SoracloudRuntimeMutationSink for QueuedSoracloudRuntimeMutationSink {
    fn ensure_production_qualified(&self) -> eyre::Result<()> {
        crate::soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
            self.binding.clone(),
            Arc::clone(&self.signer),
        )
        .map(|_| ())
        .map_err(|error| eyre::eyre!("runtime signer is no longer production-qualified: {error:?}"))
    }
    fn submit_instruction(
        &self,
        instruction: InstructionBox,
        endpoint: &'static str,
    ) -> eyre::Result<()> {
        let mut payload = build_soracloud_runtime_submission_payload(
            *self.state.network_id_ref(),
            self.authority.clone(),
            instruction,
            self.submission.fee_payment_intent(),
            endpoint,
        )?;
        let route = self
            .queue
            .route_payload_plan_with_state(&payload, self.state.as_ref())
            .wrap_err_with(|| {
                format!("route internal Soracloud runtime mutation at `{endpoint}`")
            })?;
        let iroha_core::queue::RoutingPlan::Single(route) = route else {
            eyre::bail!("Soracloud runtime submission requires one resolved route");
        };
        let latest_header = self.state.latest_block_header_fast();
        let observation_time_ms = latest_header
            .as_ref()
            .map_or(0, |header| header.creation_time_ms);
        let next_block_height = latest_header
            .as_ref()
            .map_or(1, |header| header.height().get().saturating_add(1));
        let nexus = self.state.nexus_snapshot();
        let pipeline = self.state.pipeline_snapshot();
        let quote = {
            let world = self.state.world_view();
            quote_nexus_fee_admission_draft(
                &world,
                &nexus,
                &pipeline,
                &payload,
                observation_time_ms,
                next_block_height,
                Some(route.route.dataspace_id),
            )
        }
        .map_err(|error| {
            eyre::eyre!("quote internal Soracloud runtime mutation at `{endpoint}`: {error:?}")
        })?;
        payload.fee_payment = quote.recommended_intent;
        let tx = self
            .signer
            .sign_transaction(payload)
            .map_err(|error| {
                eyre::eyre!(
                    "external signer refused internal Soracloud runtime mutation at `{endpoint}`: {error:?}"
                )
            })?;
        let (max_clock_drift, transaction_params, crypto) = {
            let world = self.state.world_view();
            let params = world.parameters();
            (
                params.sumeragi().max_clock_drift(),
                params.transaction(),
                self.state.crypto(),
            )
        };
        let accepted = AcceptedTransaction::accept(
            tx,
            self.state.network_id_ref(),
            max_clock_drift,
            transaction_params,
            crypto.as_ref(),
        )
        .wrap_err_with(|| format!("accept internal Soracloud runtime mutation at `{endpoint}`"))?;
        self.queue
            .push_with_lane_with_state(accepted, self.state.as_ref())
            .map(|_| ())
            .map_err(|failure| {
                eyre::eyre!(
                    "enqueue internal Soracloud runtime mutation at `{endpoint}`: {}",
                    failure.err
                )
            })
    }
    fn submit_inrou_host_capability(
        &self,
        capability: &SoraInrouHostCapabilityRecordV1,
    ) -> eyre::Result<()> {
        if capability.validator_account_id != self.authority {
            eyre::bail!(
                "runtime Inrou host advert validator `{}` does not match sink authority `{}`",
                capability.validator_account_id,
                self.authority
            );
        }
        let provenance_preimage = encode_inrou_host_advertise_provenance_payload(capability)
            .wrap_err("encode runtime Inrou host advert provenance payload")?;
        let instruction = InstructionBox::from(isi::soracloud::AdvertiseSoracloudInrouHost {
            capability: capability.clone(),
            provenance: ManifestProvenance {
                signer: self
                    .signer
                    .public_key()
                    .map_err(|error| eyre::eyre!("probe runtime signer key: {error:?}"))?,
                signature: self
                    .signer
                    .sign_provenance(
                        iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostAdvert,
                        &provenance_preimage,
                    )
                    .map_err(|error| {
                        eyre::eyre!(
                            "external signer refused Inrou host-advert provenance: {error:?}"
                        )
                    })?,
            },
        });
        self.submit_instruction(instruction, "/internal/soracloud/runtime/inrou-host-advert")
    }
    fn submit_inrou_host_withdrawal(&self, validator_account_id: &AccountId) -> eyre::Result<()> {
        if *validator_account_id != self.authority {
            eyre::bail!(
                "runtime Inrou host withdrawal validator `{validator_account_id}` does not match sink authority `{}`",
                self.authority
            );
        }
        let provenance_preimage =
            encode_inrou_host_withdraw_provenance_payload(validator_account_id)
                .wrap_err("encode runtime Inrou host withdrawal provenance payload")?;
        let instruction = InstructionBox::from(isi::soracloud::WithdrawSoracloudInrouHost {
            validator_account_id: validator_account_id.clone(),
            provenance: ManifestProvenance {
                signer: self
                    .signer
                    .public_key()
                    .map_err(|error| eyre::eyre!("probe runtime signer key: {error:?}"))?,
                signature: self
                    .signer
                    .sign_provenance(
                        iroha_data_model::soracloud::SoracloudRuntimeProvenancePurposeV1::InrouHostWithdraw,
                        &provenance_preimage,
                    )
                    .map_err(|error| {
                        eyre::eyre!(
                            "external signer refused Inrou host-withdrawal provenance: {error:?}"
                        )
                    })?,
            },
        });
        self.submit_instruction(
            instruction,
            "/internal/soracloud/runtime/inrou-host-withdraw",
        )
    }
}
fn build_soracloud_runtime_submission_payload(
    network_id: iroha_data_model::NetworkId,
    authority: AccountId,
    instruction: InstructionBox,
    fee_payment: iroha_data_model::transaction::FeePaymentIntent,
    endpoint: &'static str,
) -> eyre::Result<TransactionPayload> {
    TransactionBuilder::new(network_id, authority, fee_payment)
        .with_instructions([instruction])
        .into_payload()
        .wrap_err_with(|| format!("build internal Soracloud runtime mutation at `{endpoint}`"))
}
#[cfg(test)]
fn sign_soracloud_runtime_submission_payload(
    payload: TransactionPayload,
    key_pair: &KeyPair,
    endpoint: &'static str,
) -> eyre::Result<SignedTransaction> {
    TransactionBuilder::from_payload(payload)
        .wrap_err_with(|| {
            format!("rebuild quoted internal Soracloud runtime mutation at `{endpoint}`")
        })?
        .try_sign(key_pair.private_key())
        .wrap_err_with(|| format!("sign internal Soracloud runtime mutation at `{endpoint}`"))
}
#[cfg(test)]
fn sign_soracloud_runtime_provenance(
    key_pair: &KeyPair,
    payload: &[u8],
    context: &'static str,
) -> eyre::Result<iroha_crypto::Signature> {
    iroha_crypto::Signature::try_new(key_pair.private_key(), payload).wrap_err(context)
}
fn current_host_inrou_guest_isa() -> Option<SoraInrouGuestIsaV1> {
    #[cfg(target_arch = "x86_64")]
    {
        return Some(SoraInrouGuestIsaV1::X8664);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Some(SoraInrouGuestIsaV1::Aarch64);
    }
    #[allow(unreachable_code)]
    None
}
#[cfg(any(target_os = "linux", test))]
fn portable_vm_guest_machine_profile(
    guest_isa: SoraInrouGuestIsaV1,
) -> PortableVmGuestMachineProfile {
    match guest_isa {
        SoraInrouGuestIsaV1::X8664 => PortableVmGuestMachineProfile {
            machine_type: "q35",
            root_label: "rootfs-x86_64",
            block_device: "virtio-blk-pci",
            #[cfg(target_os = "linux")]
            net_device: "virtio-net-pci",
        },
        SoraInrouGuestIsaV1::Aarch64 => PortableVmGuestMachineProfile {
            machine_type: "virt",
            root_label: "rootfs-aarch64",
            block_device: "virtio-blk-device",
            #[cfg(target_os = "linux")]
            net_device: "virtio-net-device",
        },
    }
}
#[cfg(not(target_os = "linux"))]
fn ensure_portable_vm_backend_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    let _ = config;
    eyre::bail!(
        "Inrou PortableVM V1 hosting requires Linux KVM, private mount/network/IPC/UTS/PID/cgroup namespaces, an authenticated minimal runtime closure, exact cgroup-v2 limits, locked-identity procfs attestation, anonymous QMP, and QEMU seccomp"
    )
}
#[cfg(not(target_os = "linux"))]
fn ensure_portable_vm_backend_statically_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    ensure_portable_vm_backend_available(config)
}
#[cfg(target_os = "linux")]
struct PortableVmBackendPreflight {
    child_identity: PortableVmChildIdentity,
    qemu_img: PathBuf,
    namespace_tools: inrou_namespace::InrouNamespaceTools,
}
#[cfg(any(target_os = "linux", test))]
fn inrou_startup_probe_shape(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<iroha_config::parameters::inrou_startup_probe::InrouStartupProbeShapeV1> {
    iroha_config::parameters::inrou_startup_probe::InrouStartupProbeShapeV1::from_host_envelope(
        u64::from(config.max_cpu_millis.get()),
        config.max_memory_bytes.get(),
    )
    .map_err(|message| eyre::eyre!(message))
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InrouWorkerTeardownAttestations {
    direct_child_exited: bool,
    cgroup_empty: bool,
}
#[cfg(any(target_os = "linux", test))]
impl InrouWorkerTeardownAttestations {
    const fn release_authorized(self) -> bool {
        self.direct_child_exited && self.cgroup_empty
    }
}
#[cfg(target_os = "linux")]
fn terminate_inrou_confined_child_bounded(
    child: &mut std::process::Child,
    worker_cgroup: &mut inrou_cgroup::InrouWorkerCgroup,
    firewall: &mut Option<InrouLoopbackOwnerFirewall>,
    label: &str,
) -> eyre::Result<std::process::ExitStatus> {
    // Revoke the complete lifetime before waiting for the watchdog. Killing
    // only the direct helper would remove the owner during namespace setup.
    let cgroup_empty = worker_cgroup.kill_and_attest_empty_bounded();
    let termination = if cgroup_empty.is_ok() {
        terminate_inrou_child_bounded(child)
    } else {
        child.try_wait().map_err(Into::into).and_then(|status| {
            status.ok_or_else(|| eyre::eyre!("retaining the live Inrou watchdog because complete cgroup termination is unproven"))
        })
    };
    let attestations = InrouWorkerTeardownAttestations {
        direct_child_exited: termination.is_ok(),
        cgroup_empty: cgroup_empty.is_ok(),
    };
    match (termination, cgroup_empty) {
        (Ok(status), Ok(empty)) => {
            debug_assert!(attestations.release_authorized());
            if let Err(error) = worker_cgroup.release_attested_empty(empty) {
                if let Some(firewall) = firewall.take() {
                    std::mem::forget(firewall);
                }
                return Err(error).wrap_err_with(|| {
                    format!(
                        "{label} child exited with {status} and its cgroup was proved empty, but the confined cgroup could not be released"
                    )
                });
            }
            Ok(status)
        }
        (termination, cgroup_empty) => {
            debug_assert!(!attestations.release_authorized());
            if let Some(firewall) = firewall.take() {
                // Neither a direct-child termination error nor an uncleared
                // worker cgroup is enough proof that every QEMU descendant is
                // gone. Retain both the owner barrier and its slot lock until
                // supervisor exit instead of exposing either loopback port.
                std::mem::forget(firewall);
            }
            match (termination, cgroup_empty) {
                (Err(termination), Ok(_)) => Err(termination).wrap_err(format!(
                    "{label} cgroup is empty, but direct-child termination is unproven; retaining the cgroup"
                )),
                (Ok(status), Err(cgroup_empty)) => Err(cgroup_empty).wrap_err_with(|| {
                    format!(
                        "{label} child exited with {status}, but its cgroup could not be proved empty"
                    )
                }),
                (Err(termination), Err(cgroup_empty)) => Err(termination).wrap_err_with(|| {
                    format!(
                        "{label} direct-child termination and empty-cgroup attestation both failed: {cgroup_empty}"
                    )
                }),
                (Ok(_), Ok(_)) => unreachable!("successful teardown returned above"),
            }
        }
    }
}
#[cfg(target_os = "linux")]
fn terminate_inrou_startup_probe_bounded(
    child: &mut std::process::Child,
    worker_cgroup: &mut inrou_cgroup::InrouWorkerCgroup,
    firewall: &mut Option<InrouLoopbackOwnerFirewall>,
) -> eyre::Result<std::process::ExitStatus> {
    terminate_inrou_confined_child_bounded(child, worker_cgroup, firewall, "Inrou startup probe")
}
#[cfg(target_os = "linux")]
fn portable_vm_backend_static_preflight(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<PortableVmBackendPreflight> {
    require_inrou_self_exec_dispatch_armed()?;
    current_host_inrou_guest_isa().ok_or_else(|| {
        eyre::eyre!("Inrou PortableVM V1 supports only x86_64 and aarch64 Linux hosts")
    })?;
    inrou_cgroup::ensure_inrou_cgroup_v2_available()
        .wrap_err("require root-custodied cgroup-v2 controllers for Inrou PortableVM")?;
    let child_identity = portable_vm_child_identity(config)?;
    ensure_portable_vm_identity_reserved(&child_identity)
        .wrap_err("validate the locked local Inrou QEMU service identity")?;
    resolve_inrou_iptables_executable().ok_or_else(|| {
        eyre::eyre!(
            "configured Inrou PortableVM backend requires a root-owned iptables executable at a standard system path"
        )
    })?;
    let qemu_img = resolve_inrou_qemu_img_executable()
        .ok_or_else(|| eyre::eyre!("configured Inrou PortableVM backend requires qemu-img"))?;
    let namespace_tools = inrou_namespace::InrouNamespaceTools::resolve_exact()
        .wrap_err("resolve the fixed root-custodied Inrou namespace launcher")?;
    inrou_namespace::InrouNamespacePlan::preflight(namespace_tools.clone())
        .wrap_err("authenticate the immutable Inrou V1 runtime closure")?;
    Ok(PortableVmBackendPreflight {
        child_identity,
        qemu_img,
        namespace_tools,
    })
}
#[cfg(target_os = "linux")]
fn ensure_portable_vm_backend_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    let preflight = portable_vm_backend_static_preflight(config)?;
    let owner_slot = inrou_cgroup::InrouCgroupOwnerSlot::from_identity(
        preflight.child_identity.uid,
        preflight.child_identity.gid,
    )?;
    let slot_lock =
        acquire_inrou_iptables_lock(inrou_firewall_identity_slot(&preflight.child_identity)?)?;
    inrou_cgroup::attest_inrou_worker_absence(owner_slot).wrap_err(
        "require no retained workers for this canonical Inrou owner under its exclusive slot lock",
    )?;
    run_inrou_portable_vm_startup_probe(config, preflight, slot_lock)
        .wrap_err("exercise the authenticated Inrou QEMU/KVM startup boundary")
}
#[cfg(target_os = "linux")]
fn run_inrou_portable_vm_startup_probe(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
    preflight: PortableVmBackendPreflight,
    slot_lock: InrouOwnerSlotLock,
) -> eyre::Result<()> {
    const PROBE_GUEST_PORT: u16 = 9;
    let probe = inrou_startup_probe_shape(config)?;
    let PortableVmBackendPreflight {
        child_identity,
        qemu_img: _,
        namespace_tools,
    } = preflight;
    let guest_isa = current_host_inrou_guest_isa()
        .ok_or_else(|| eyre::eyre!("Inrou startup probe requires x86_64 or aarch64"))?;
    ensure_portable_vm_identity_reserved(&child_identity)
        .wrap_err("recheck the locked Inrou QEMU service identity before startup qualification")?;
    ensure_no_process_with_inrou_identity(&child_identity)
        .wrap_err("require an exclusive Inrou QEMU identity before startup qualification")?;
    let namespace_plan =
        inrou_namespace::InrouNamespacePlan::prepare_startup_probe(namespace_tools)
            .wrap_err("prepare the artifact-free Inrou startup-probe namespace")?;
    let io_backing_paths = namespace_plan.io_backing_paths()?;
    let io_backing_path_refs = io_backing_paths
        .iter()
        .map(PathBuf::as_path)
        .collect::<Vec<_>>();
    let slot = inrou_firewall_identity_slot(&child_identity)?;
    let mut worker_cgroup = inrou_cgroup::InrouWorkerCgroup::prepare(
        inrou_cgroup::InrouCgroupWorkerKey {
            owner_slot: inrou_cgroup::InrouCgroupOwnerSlot::from_identity(
                child_identity.uid,
                child_identity.gid,
            )?,
            service_name: "startup-probe",
            service_version: "v1",
            replica_slot: u16::try_from(slot).expect("canonical Inrou slot fits u16"),
            process_generation: 0,
            bundle_hash: "inrou-startup-probe-v1",
        },
        &probe.resources(),
        &io_backing_path_refs,
    )
    .wrap_err("prepare exact cgroup-v2 limits for the Inrou startup probe")?;
    let mut launch_barrier = inrou_cgroup::InrouLaunchBarrier::create()
        .wrap_err("create the Inrou startup-probe cgroup launch barrier")?;
    let PortableVmNetworkPlan {
        netdev,
        listen_base_url: _,
        public_listener,
        backend_reservation,
        expected_backend,
    } = build_portable_vm_network_plan(PROBE_GUEST_PORT)
        .wrap_err("prepare the Inrou startup-probe user-mode network")?;
    let mut loopback_firewall = Some(
        InrouLoopbackOwnerFirewall::install_with_lock(&public_listener, &child_identity, slot_lock)
            .wrap_err("exercise the canonical-slot Inrou loopback firewall")?,
    );
    ensure_portable_vm_identity_reserved(&child_identity)
        .wrap_err("recheck the locked Inrou QEMU identity under the startup-probe firewall")?;
    ensure_no_process_with_inrou_identity(&child_identity)
        .wrap_err("recheck the exclusive Inrou QEMU identity under the startup-probe firewall")?;
    let mut command = build_inrou_portable_vm_command(
        &namespace_plan,
        &child_identity,
        &launch_barrier,
        worker_cgroup.attestation().expected_proc_path(),
    )?;
    append_inrou_startup_probe_qemu_args(&mut command, guest_isa, &netdev, probe);
    let (stderr_reader, stderr_writer) = UnixStream::pair()
        .wrap_err("create the anonymous Inrou startup-probe stderr socketpair")?;
    let stderr_cancellation = stderr_reader
        .try_clone()
        .wrap_err("retain the Inrou startup-probe stderr cancellation handle")?;
    command.stderr(Stdio::from(OwnedFd::from(stderr_writer)));
    let qmp_stream = configure_inrou_qmp_stdio(&mut command)
        .wrap_err("create the Inrou startup-probe QMP socketpair")?;
    ensure_no_process_with_inrou_identity(&child_identity)
        .wrap_err("finalize the exclusive Inrou identity before the startup-probe spawn")?;
    drop(backend_reservation);
    let mut child = command.spawn().wrap_err_with(|| {
        format!(
            "spawn artifact-free Inrou QEMU/KVM probe via {}",
            namespace_plan.launcher().display()
        )
    })?;
    drop(command);
    launch_barrier.child_spawned();
    let stderr_drain = match thread::Builder::new()
        .name("inrou-startup-probe-stderr".to_owned())
        .spawn(move || drain_host_command_stdout_bounded(stderr_reader, 16 * 1024))
    {
        Ok(drain) => drain,
        Err(error) => {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "start bounded Inrou startup-probe stderr capture{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
    };
    // Capture only the artifact-free helper/QEMU probe's diagnostics. Its
    // environment is cleared, and no workload, signing, or secret inputs exist.
    // Drain concurrently even after the retained bound to avoid pipe deadlock.
    let result: eyre::Result<()> = (|| {
        if let Err(error) = worker_cgroup.place_launcher(child.id()) {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "place and attest the Inrou startup-probe launcher{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        if let Err(error) = launch_barrier.release() {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "release the Inrou startup probe after cgroup placement{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        let (forward, mut qmp_control, namespace_attestation) = match query_inrou_qmp_host_forward(
            &mut child,
            qmp_stream,
            &namespace_plan,
            &child_identity,
            worker_cgroup.attestation(),
            PROBE_GUEST_PORT,
        ) {
            Ok(attested) => attested,
            Err(error) => {
                let termination = terminate_inrou_startup_probe_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                );
                return Err(error).wrap_err_with(|| {
                    format!(
                        "attest the artifact-free Inrou QEMU/KVM probe{}",
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        if forward != expected_backend {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            eyre::bail!(
                "Inrou startup probe published host forward {forward} instead of {expected_backend}{}",
                inrou_termination_error_suffix(&termination)
            );
        }
        match namespace_attestation.connect_private_loopback(worker_cgroup.attestation(), forward) {
            Ok(stream) => drop(stream),
            Err(error) => {
                let termination = terminate_inrou_startup_probe_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                );
                return Err(error).wrap_err_with(|| {
                    format!(
                        "exercise the attested Inrou private-network connector{}",
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        }
        if let Err(error) = namespace_attestation.attest_live(worker_cgroup.attestation()) {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "re-attest the live Inrou startup probe before shutdown{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        if let Err(error) = request_inrou_qmp_quit(
            &mut qmp_control,
            SORACLOUD_INROU_QMP_POWERDOWN_REQUEST_TIMEOUT,
        ) {
            let termination = terminate_inrou_startup_probe_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "shut down the Inrou startup probe over QMP{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        let status =
            match wait_for_inrou_child_exit_bounded(&mut child, SORACLOUD_INROU_CHILD_STOP_TIMEOUT)
            {
                Ok(Some(status)) => status,
                Ok(None) => {
                    let termination = terminate_inrou_startup_probe_bounded(
                        &mut child,
                        &mut worker_cgroup,
                        &mut loopback_firewall,
                    );
                    eyre::bail!(
                        "Inrou startup probe ignored its QMP quit request{}",
                        inrou_termination_error_suffix(&termination)
                    );
                }
                Err(error) => {
                    let termination = terminate_inrou_startup_probe_bounded(
                        &mut child,
                        &mut worker_cgroup,
                        &mut loopback_firewall,
                    );
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "attest bounded Inrou startup-probe shutdown{}",
                            inrou_termination_error_suffix(&termination)
                        )
                    });
                }
            };
        let empty_cgroup = match worker_cgroup.kill_and_attest_empty_bounded() {
            Ok(empty_cgroup) => empty_cgroup,
            Err(error) => {
                if let Some(firewall) = loopback_firewall.take() {
                    // QMP quit reaped the direct child, but an uncleared cgroup
                    // leaves descendant termination unproven. Keep the barrier
                    // fail-closed.
                    std::mem::forget(firewall);
                }
                return Err(error)
                    .wrap_err("prove the QMP-stopped Inrou startup-probe cgroup is empty");
            }
        };
        if let Err(error) = worker_cgroup.release_attested_empty(empty_cgroup) {
            if let Some(firewall) = loopback_firewall.take() {
                std::mem::forget(firewall);
            }
            return Err(error).wrap_err(
                "release the empty Inrou startup-probe cgroup after direct-child exit attestation",
            );
        }
        if !status.success() {
            eyre::bail!("Inrou startup probe exited with non-success status {status}");
        }
        loopback_firewall
            .as_mut()
            .expect("startup-probe firewall remains installed")
            .cleanup()
            .wrap_err("remove the Inrou startup-probe firewall")?;
        ensure_no_process_with_inrou_identity(&child_identity)
            .wrap_err("prove the dedicated Inrou identity is vacant after startup qualification")?;
        Ok(())
    })();
    let diagnostics = finish_inrou_startup_probe_stderr_bounded(stderr_drain, &stderr_cancellation);
    match result {
        Ok(()) => diagnostics
            .map(|_| ())
            .wrap_err("finish Inrou startup-probe stderr capture"),
        Err(error) => Err(error).wrap_err(inrou_startup_probe_stderr_context(&diagnostics)),
    }
}
#[cfg(target_os = "linux")]
fn ensure_portable_vm_backend_statically_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    portable_vm_backend_static_preflight(config).map(|_| ())
}
fn validate_inrou_portable_vm_v1_config(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    if config.guest_image_max_bytes.get()
        > iroha_config::parameters::defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT
    {
        eyre::bail!(
            "Inrou guest_image_max_bytes exceeds its {}-byte hard ceiling",
            iroha_config::parameters::defaults::soracloud_runtime::INROU_GUEST_IMAGE_MAX_BYTES_LIMIT
        );
    }
    let lifecycle_grace_minimum = Duration::from_millis(
        iroha_config::parameters::defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MIN_MS,
    );
    let lifecycle_grace_maximum = Duration::from_millis(
        iroha_config::parameters::defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS,
    );
    for (field, value) in [
        ("start_grace", config.start_grace),
        ("stop_grace", config.stop_grace),
    ] {
        if !(lifecycle_grace_minimum..=lifecycle_grace_maximum).contains(&value) {
            eyre::bail!(
                "Inrou PortableVM V1 {field} must be between {} and {} milliseconds inclusive",
                iroha_config::parameters::defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MIN_MS,
                iroha_config::parameters::defaults::soracloud_runtime::INROU_LIFECYCLE_GRACE_MAX_MS,
            );
        }
    }
    if !config.enabled {
        if config.portable_vm_uid.is_some()
            || config.portable_vm_gid.is_some()
            || config.trusted_guest_artifact.is_some()
        {
            eyre::bail!(
                "disabled Inrou hosting must not retain a PortableVM identity or trusted guest artifact"
            );
        }
        return Ok(());
    }
    let uid = config
        .portable_vm_uid
        .ok_or_else(|| eyre::eyre!("enabled Inrou PortableVM V1 requires portable_vm_uid"))?
        .get();
    let gid = config
        .portable_vm_gid
        .ok_or_else(|| eyre::eyre!("enabled Inrou PortableVM V1 requires portable_vm_gid"))?
        .get();
    if iroha_config::parameters::defaults::soracloud_runtime::inrou_portable_vm_identity_slot(
        uid, gid,
    )
    .is_none()
    {
        eyre::bail!(
            "Inrou PortableVM V1 uid/gid must be one equal canonical slot pair in {}..{} (upper bound exclusive)",
            SORACLOUD_INROU_ID_BASE,
            SORACLOUD_INROU_ID_MAX_EXCLUSIVE,
        );
    }
    config
        .trusted_guest_artifact
        .as_ref()
        .ok_or_else(|| {
            eyre::eyre!("enabled Inrou PortableVM V1 requires a trusted guest artifact")
        })?
        .validate()
        .map_err(|error| eyre::eyre!("invalid trusted Inrou guest artifact: {error}"))?;
    let minimum_host_cpu = u64::from(iroha_data_model::soracloud::SORA_INROU_MIN_CPU_MILLIS_V1)
        + iroha_data_model::soracloud::SORA_INROU_VMM_CPU_OVERHEAD_MILLIS_V1;
    if u64::from(config.max_cpu_millis.get()) < minimum_host_cpu {
        eyre::bail!(
            "Inrou host CPU capacity must cover at least {minimum_host_cpu} millicores of workload and VMM cost"
        );
    }
    let minimum_host_memory = iroha_data_model::soracloud::SORA_INROU_MIN_MEMORY_BYTES_V1
        + iroha_data_model::soracloud::SORA_INROU_VMM_MEMORY_OVERHEAD_BYTES_V1;
    if config.max_memory_bytes.get() < minimum_host_memory {
        eyre::bail!(
            "Inrou host memory capacity must cover at least {minimum_host_memory} bytes of guest and VMM cost"
        );
    }
    if config.max_storage_bytes.get()
        < iroha_data_model::soracloud::SORA_INROU_EPHEMERAL_STORAGE_ALIGNMENT_BYTES_V1
    {
        eyre::bail!("Inrou host storage capacity must be at least 4096 bytes");
    }
    Ok(())
}
fn validate_soracloud_runtime_manager_posture(
    config: &SoracloudRuntimeManagerConfig,
) -> eyre::Result<()> {
    if config.hydration_concurrency.get()
        > iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX
    {
        eyre::bail!(
            "Soracloud artifact hydration worker count exceeds the first-release limit of {}",
            iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX
        );
    }
    if config.prepared_runtime_cache_capacity.get()
        > iroha_config::parameters::defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX
    {
        eyre::bail!(
            "Soracloud prepared-runtime cache capacity exceeds the first-release limit of {}",
            iroha_config::parameters::defaults::soracloud_runtime::PREPARED_RUNTIME_CACHE_CAPACITY_MAX
        );
    }
    validate_inrou_portable_vm_v1_config(&config.inrou)?;
    if config.inrou.enabled && !config.production_mode {
        eyre::bail!(
            "enabled Inrou PortableVM V1 requires Soracloud runtime production_mode = true"
        );
    }
    if config.production_mode {
        if config.egress.default_allow {
            eyre::bail!("production Soracloud runtime requires fail-closed default egress");
        }
        if config.egress.rate_per_minute.is_none() || config.egress.max_bytes_per_minute.is_none() {
            eyre::bail!(
                "production Soracloud runtime requires explicit request-rate and byte-rate egress limits"
            );
        }
        if config.submission.signer.is_none() {
            eyre::bail!(
                "production Soracloud runtime requires an explicit mutation-signer binding"
            );
        }
    }
    Ok(())
}
fn ensure_inrou_portable_vm_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    validate_inrou_portable_vm_v1_config(config)?;
    if config.enabled {
        ensure_portable_vm_backend_available(config)
            .wrap_err("preflight mandatory Inrou PortableVM V1 runtime")?;
    }
    Ok(())
}
fn ensure_inrou_portable_vm_statically_available(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<()> {
    validate_inrou_portable_vm_v1_config(config)?;
    if config.enabled {
        ensure_portable_vm_backend_statically_available(config)
            .wrap_err("statically revalidate mandatory Inrou PortableVM V1 runtime")?;
    }
    Ok(())
}
impl SoracloudRuntimeManagerConfig {
    /// Build a runtime-manager configuration from the parsed Soracloud runtime settings.
    #[must_use]
    pub fn from_runtime_config(
        config: &iroha_config::parameters::actual::SoracloudRuntime,
    ) -> Self {
        config.assert_runtime_posture();
        Self {
            production_mode: config.production_mode,
            state_dir: config.state_dir.clone(),
            reconcile_interval: config.reconcile_interval,
            hydration_concurrency: config.hydration_concurrency,
            prepared_runtime_cache_capacity: config.prepared_runtime_cache_capacity,
            cache_budgets: config.cache_budgets.clone(),
            inrou: config.inrou.clone(),
            submission: config.submission.clone(),
            egress: config.egress.clone(),
            local_validator_account_id: None,
            local_peer_id: None,
        }
    }
    /// Attach the local validator and peer identity used for Inrou host reconciliation.
    #[must_use]
    pub fn with_local_host_identity(
        mut self,
        validator_account_id: AccountId,
        peer_id: impl Into<String>,
    ) -> Self {
        self.local_validator_account_id = Some(validator_account_id);
        self.local_peer_id = Some(peer_id.into());
        self
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SoracloudArtifactFileFingerprint {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    modified_nanoseconds: Option<u128>,
}
impl SoracloudArtifactFileFingerprint {
    fn from_metadata(
        metadata: &fs::Metadata,
        cache_path: &Path,
    ) -> Result<Self, SoracloudRuntimeExecutionError> {
        if !metadata.is_file() {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "hydrated Soracloud artifact cache {} is not a regular file",
                    cache_path.display()
                ),
            ));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "hydrated Soracloud artifact cache {} must have exactly one hard link, found {}",
                    cache_path.display(),
                    metadata.nlink()
                ),
            ));
        }
        Ok(Self {
            bytes: metadata.len(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
            #[cfg(not(unix))]
            modified_nanoseconds: metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })
    }
}
fn open_soracloud_artifact_for_validation(
    cache_path: &Path,
) -> Result<(fs::File, SoracloudArtifactFileFingerprint), SoracloudRuntimeExecutionError> {
    let named_metadata = fs::symlink_metadata(cache_path).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "inspect hydrated Soracloud artifact cache {} before opening: {error}",
                cache_path.display()
            ),
        )
    })?;
    let named_fingerprint =
        SoracloudArtifactFileFingerprint::from_metadata(&named_metadata, cache_path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(cache_path).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "open hydrated Soracloud artifact cache {} without following links: {error}",
                cache_path.display()
            ),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "inspect hydrated Soracloud artifact cache {}: {error}",
                cache_path.display()
            ),
        )
    })?;
    let fingerprint = SoracloudArtifactFileFingerprint::from_metadata(&metadata, cache_path)?;
    if fingerprint != named_fingerprint {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "hydrated Soracloud artifact cache {} changed identity while it was opened",
                cache_path.display()
            ),
        ));
    }
    Ok((file, fingerprint))
}
fn validate_opened_soracloud_artifact_after_read(
    file: &fs::File,
    cache_path: &Path,
    expected_fingerprint: &SoracloudArtifactFileFingerprint,
    observed_bytes: u64,
) -> Result<(), SoracloudRuntimeExecutionError> {
    let opened_metadata = file.metadata().map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "reinspect opened hydrated Soracloud artifact cache {}: {error}",
                cache_path.display()
            ),
        )
    })?;
    let named_metadata = fs::symlink_metadata(cache_path).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "reinspect named hydrated Soracloud artifact cache {}: {error}",
                cache_path.display()
            ),
        )
    })?;
    let opened_fingerprint =
        SoracloudArtifactFileFingerprint::from_metadata(&opened_metadata, cache_path)?;
    let named_fingerprint =
        SoracloudArtifactFileFingerprint::from_metadata(&named_metadata, cache_path)?;
    if &opened_fingerprint != expected_fingerprint
        || named_fingerprint != opened_fingerprint
        || opened_fingerprint.bytes != observed_bytes
    {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "hydrated Soracloud artifact cache {} changed while it was being read",
                cache_path.display()
            ),
        ));
    }
    Ok(())
}
fn read_opened_soracloud_artifact_bounded(
    mut file: fs::File,
    cache_path: &Path,
    fingerprint: &SoracloudArtifactFileFingerprint,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SoracloudRuntimeExecutionError> {
    if fingerprint.bytes > maximum_bytes {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} requires {} bytes, exceeding the configured {maximum_bytes}-byte limit",
                cache_path.display(),
                fingerprint.bytes
            ),
        ));
    }
    let capacity = usize::try_from(fingerprint.bytes).map_err(|_| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} is too large to address",
                cache_path.display()
            ),
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                format!(
                    "read hydrated Soracloud artifact cache {}: {error}",
                    cache_path.display()
                ),
            )
        })?;
    let observed_bytes = u64::try_from(bytes.len()).map_err(|_| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} byte count does not fit u64",
                cache_path.display()
            ),
        )
    })?;
    if observed_bytes > maximum_bytes {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} exceeds the configured {maximum_bytes}-byte limit",
                cache_path.display()
            ),
        ));
    }
    validate_opened_soracloud_artifact_after_read(&file, cache_path, fingerprint, observed_bytes)?;
    Ok(bytes)
}
fn verify_cached_soracloud_artifact(
    cache_path: &Path,
    expected_hash: Hash,
    maximum_bytes: u64,
) -> Result<SoracloudArtifactFileFingerprint, SoracloudRuntimeExecutionError> {
    let (_file, fingerprint) =
        open_verified_cached_soracloud_artifact(cache_path, expected_hash, maximum_bytes)?;
    Ok(fingerprint)
}
fn open_verified_cached_soracloud_artifact(
    cache_path: &Path,
    expected_hash: Hash,
    maximum_bytes: u64,
) -> Result<(fs::File, SoracloudArtifactFileFingerprint), SoracloudRuntimeExecutionError> {
    let (mut file, fingerprint) = open_soracloud_artifact_for_validation(cache_path)?;
    if fingerprint.bytes > maximum_bytes {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} requires {} bytes, exceeding the configured {maximum_bytes}-byte limit",
                cache_path.display(),
                fingerprint.bytes
            ),
        ));
    }
    let (actual_hash, observed_bytes) = Hash::new_from_reader_bounded(&mut file, maximum_bytes)
        .map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                format!(
                    "hash hydrated Soracloud artifact cache {}: {error}",
                    cache_path.display()
                ),
            )
        })?;
    validate_opened_soracloud_artifact_after_read(&file, cache_path, &fingerprint, observed_bytes)?;
    if actual_hash != expected_hash {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} failed hash verification: expected {}, found {}",
                cache_path.display(),
                expected_hash,
                actual_hash
            ),
        ));
    }
    file.rewind().map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "rewind verified Soracloud artifact cache {}: {error}",
                cache_path.display()
            ),
        )
    })?;
    Ok((file, fingerprint))
}
#[derive(Default)]
struct SoracloudPreparedRuntimeCounters {
    metadata_validations: AtomicU64,
    artifact_reads: AtomicU64,
    artifact_hashes: AtomicU64,
    contract_preparations: AtomicU64,
    runtime_allocations: AtomicU64,
    prepared_loads: AtomicU64,
    template_builds: AtomicU64,
    runtime_reuses: AtomicU64,
    dirty_resets: AtomicU64,
    runtime_returns: AtomicU64,
    invalidations: AtomicU64,
    evictions: AtomicU64,
}
impl SoracloudPreparedRuntimeCounters {
    fn increment(counter: &AtomicU64) {
        let _ = counter.fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }
}
struct PooledSoracloudIvm {
    vm: IVM,
    template: RuntimeTemplate,
    previously_used: bool,
}
struct SoracloudPreparedContractEntry {
    cache_path: PathBuf,
    fingerprint: SoracloudArtifactFileFingerprint,
    prepared: PreparedContract,
    idle_runtimes: Vec<PooledSoracloudIvm>,
    artifact_bytes: u64,
    generation: u64,
    last_used: u64,
}
#[derive(Clone)]
struct CachedSoracloudPreparedContract {
    key: Hash,
    generation: u64,
    prepared: PreparedContract,
}
#[derive(Default)]
struct SoracloudPreparedRuntimeCacheState {
    entries: BTreeMap<Hash, SoracloudPreparedContractEntry>,
    retained_artifact_bytes: u64,
    idle_runtimes: usize,
    clock: u64,
    next_generation: u64,
}
impl SoracloudPreparedRuntimeCacheState {
    fn next_tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }
    fn next_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }
    fn remove_entry(&mut self, key: &Hash) -> bool {
        let Some(entry) = self.entries.remove(key) else {
            return false;
        };
        self.retained_artifact_bytes = self
            .retained_artifact_bytes
            .saturating_sub(entry.artifact_bytes);
        self.idle_runtimes = self.idle_runtimes.saturating_sub(entry.idle_runtimes.len());
        true
    }
    fn least_recently_used_entry(&self, excluding: Option<Hash>) -> Option<Hash> {
        self.entries
            .iter()
            .filter(|(key, _)| excluding.as_ref().is_none_or(|excluded| *key != excluded))
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| *key)
    }
    fn least_recently_used_idle_runtime_entry(&self) -> Option<Hash> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.idle_runtimes.is_empty())
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| *key)
    }
}
struct SoracloudPreparedRuntimeCache {
    state: Mutex<SoracloudPreparedRuntimeCacheState>,
    max_prepared_artifact_bytes: u64,
    max_idle_runtimes: usize,
    counters: SoracloudPreparedRuntimeCounters,
}
impl SoracloudPreparedRuntimeCache {
    fn new(max_prepared_artifact_bytes: u64, max_idle_runtimes: NonZeroUsize) -> Self {
        Self {
            state: Mutex::new(SoracloudPreparedRuntimeCacheState::default()),
            max_prepared_artifact_bytes,
            max_idle_runtimes: max_idle_runtimes.get(),
            counters: SoracloudPreparedRuntimeCounters::default(),
        }
    }
    fn from_config(config: &SoracloudRuntimeManagerConfig) -> Self {
        Self::new(
            config.cache_budgets.bundle_bytes.get(),
            config.prepared_runtime_cache_capacity,
        )
    }
    fn invalidate(&self, key: Hash) {
        if self.state.lock().remove_entry(&key) {
            SoracloudPreparedRuntimeCounters::increment(&self.counters.invalidations);
        }
    }
    fn enforce_idle_runtime_limit(&self, state: &mut SoracloudPreparedRuntimeCacheState) {
        while state.idle_runtimes > self.max_idle_runtimes {
            let Some(key) = state.least_recently_used_idle_runtime_entry() else {
                break;
            };
            let Some(entry) = state.entries.get_mut(&key) else {
                break;
            };
            if entry.idle_runtimes.pop().is_some() {
                state.idle_runtimes = state.idle_runtimes.saturating_sub(1);
                SoracloudPreparedRuntimeCounters::increment(&self.counters.evictions);
            }
        }
    }
    fn cached_handle(
        key: Hash,
        entry: &SoracloudPreparedContractEntry,
    ) -> CachedSoracloudPreparedContract {
        CachedSoracloudPreparedContract {
            key,
            generation: entry.generation,
            prepared: entry.prepared.clone(),
        }
    }
    fn prepare(
        &self,
        cache_path: &Path,
        expected_hash: Hash,
    ) -> Result<CachedSoracloudPreparedContract, SoracloudRuntimeExecutionError> {
        SoracloudPreparedRuntimeCounters::increment(&self.counters.metadata_validations);
        let (file, fingerprint) = match open_soracloud_artifact_for_validation(cache_path) {
            Ok(opened) => opened,
            Err(error) => {
                self.invalidate(expected_hash);
                return Err(error);
            }
        };
        if fingerprint.bytes > self.max_prepared_artifact_bytes {
            self.invalidate(expected_hash);
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "hydrated Soracloud artifact cache {} requires {} bytes, exceeding the configured {}-byte prepared-contract budget",
                    cache_path.display(),
                    fingerprint.bytes,
                    self.max_prepared_artifact_bytes
                ),
            ));
        }
        {
            let mut state = self.state.lock();
            let is_hit = state.entries.get(&expected_hash).is_some_and(|entry| {
                entry.cache_path == cache_path && entry.fingerprint == fingerprint
            });
            if is_hit {
                let tick = state.next_tick();
                let entry = state
                    .entries
                    .get_mut(&expected_hash)
                    .expect("matching prepared entry must exist");
                entry.last_used = tick;
                return Ok(Self::cached_handle(expected_hash, entry));
            }
            if state.remove_entry(&expected_hash) {
                SoracloudPreparedRuntimeCounters::increment(&self.counters.invalidations);
            }
        }
        SoracloudPreparedRuntimeCounters::increment(&self.counters.artifact_reads);
        let artifact = read_opened_soracloud_artifact_bounded(
            file,
            cache_path,
            &fingerprint,
            self.max_prepared_artifact_bytes,
        )?;
        SoracloudPreparedRuntimeCounters::increment(&self.counters.artifact_hashes);
        let actual_hash = Hash::new(&artifact);
        if actual_hash != expected_hash {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "hydrated Soracloud artifact cache {} failed hash verification: expected {}, found {}",
                    cache_path.display(),
                    expected_hash,
                    actual_hash
                ),
            ));
        }
        let artifact_bytes = fingerprint.bytes;
        let prepared =
            prepare_contract(Arc::<[u8]>::from(artifact.into_boxed_slice())).map_err(|error| {
                SoracloudRuntimeExecutionError::new(
                    SoracloudRuntimeExecutionErrorKind::Internal,
                    format!(
                        "verify and prepare Soracloud contract artifact {}: {error}",
                        cache_path.display()
                    ),
                )
            })?;
        SoracloudPreparedRuntimeCounters::increment(&self.counters.contract_preparations);
        let mut vm = IVM::try_new(u64::MAX).map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                vm_error_kind(&error),
                format!(
                    "allocate Soracloud prepared runtime: {}",
                    vm_error_label(&error)
                ),
            )
        })?;
        // SoraCloud execution is not a proof-production boundary. Formal trace
        // collection must be explicitly enabled only by a proof owner because
        // witness logs can retain private register and memory values.
        vm.set_zk_trace_enabled(false);
        SoracloudPreparedRuntimeCounters::increment(&self.counters.runtime_allocations);
        vm.load_prepared(&prepared).map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                vm_error_kind(&error),
                format!(
                    "load prepared Soracloud contract artifact {}: {}",
                    cache_path.display(),
                    vm_error_label(&error)
                ),
            )
        })?;
        SoracloudPreparedRuntimeCounters::increment(&self.counters.prepared_loads);
        let template = vm.try_runtime_template().map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                vm_error_kind(&error),
                format!(
                    "capture Soracloud prepared runtime: {}",
                    vm_error_label(&error)
                ),
            )
        })?;
        SoracloudPreparedRuntimeCounters::increment(&self.counters.template_builds);
        // The descriptor used for the read must still name the file that was
        // hashed. A replacement between read and insertion is invalidated and
        // retried by the caller on its next request.
        SoracloudPreparedRuntimeCounters::increment(&self.counters.metadata_validations);
        let (_, current_fingerprint) = open_soracloud_artifact_for_validation(cache_path)?;
        if current_fingerprint != fingerprint {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                format!(
                    "hydrated Soracloud artifact cache {} changed while it was being prepared",
                    cache_path.display()
                ),
            ));
        }
        let mut state = self.state.lock();
        if state.remove_entry(&expected_hash) {
            SoracloudPreparedRuntimeCounters::increment(&self.counters.invalidations);
        }
        while state.retained_artifact_bytes.saturating_add(artifact_bytes)
            > self.max_prepared_artifact_bytes
        {
            let Some(evicted) = state.least_recently_used_entry(Some(expected_hash)) else {
                break;
            };
            if state.remove_entry(&evicted) {
                SoracloudPreparedRuntimeCounters::increment(&self.counters.evictions);
            }
        }
        let generation = state.next_generation();
        let last_used = state.next_tick();
        state.retained_artifact_bytes =
            state.retained_artifact_bytes.saturating_add(artifact_bytes);
        state.idle_runtimes = state.idle_runtimes.saturating_add(1);
        state.entries.insert(
            expected_hash,
            SoracloudPreparedContractEntry {
                cache_path: cache_path.to_path_buf(),
                fingerprint,
                prepared: prepared.clone(),
                idle_runtimes: vec![PooledSoracloudIvm {
                    vm,
                    template,
                    previously_used: false,
                }],
                artifact_bytes,
                generation,
                last_used,
            },
        );
        self.enforce_idle_runtime_limit(&mut state);
        let entry = state
            .entries
            .get(&expected_hash)
            .expect("new prepared entry must remain within its own byte budget");
        Ok(Self::cached_handle(expected_hash, entry))
    }
    fn checkout<'cache>(
        &'cache self,
        prepared: &CachedSoracloudPreparedContract,
    ) -> Result<SoracloudIvmRuntimeLease<'cache>, SoracloudRuntimeExecutionError> {
        let pooled = {
            let mut state = self.state.lock();
            let tick = state.next_tick();
            let pooled = state
                .entries
                .get_mut(&prepared.key)
                .filter(|entry| entry.generation == prepared.generation)
                .and_then(|entry| {
                    entry.last_used = tick;
                    entry.idle_runtimes.pop()
                });
            if pooled.is_some() {
                state.idle_runtimes = state.idle_runtimes.saturating_sub(1);
            }
            pooled
        };
        let (vm, template) = if let Some(pooled) = pooled {
            if pooled.previously_used {
                SoracloudPreparedRuntimeCounters::increment(&self.counters.runtime_reuses);
            }
            (pooled.vm, pooled.template)
        } else {
            let mut vm = IVM::try_new(u64::MAX).map_err(|error| {
                SoracloudRuntimeExecutionError::new(
                    vm_error_kind(&error),
                    format!(
                        "allocate cached Soracloud runtime: {}",
                        vm_error_label(&error)
                    ),
                )
            })?;
            SoracloudPreparedRuntimeCounters::increment(&self.counters.runtime_allocations);
            vm.load_prepared(&prepared.prepared).map_err(|error| {
                SoracloudRuntimeExecutionError::new(
                    vm_error_kind(&error),
                    format!(
                        "load cached prepared Soracloud contract: {}",
                        vm_error_label(&error)
                    ),
                )
            })?;
            SoracloudPreparedRuntimeCounters::increment(&self.counters.prepared_loads);
            let template = vm.try_runtime_template().map_err(|error| {
                SoracloudRuntimeExecutionError::new(
                    vm_error_kind(&error),
                    format!(
                        "capture cached Soracloud runtime: {}",
                        vm_error_label(&error)
                    ),
                )
            })?;
            SoracloudPreparedRuntimeCounters::increment(&self.counters.template_builds);
            (vm, template)
        };
        Ok(SoracloudIvmRuntimeLease {
            cache: self,
            key: prepared.key,
            generation: prepared.generation,
            template,
            vm: Some(vm),
        })
    }
    fn return_runtime(&self, key: Hash, generation: u64, template: RuntimeTemplate, vm: IVM) {
        let mut state = self.state.lock();
        let tick = state.next_tick();
        let Some(entry) = state
            .entries
            .get_mut(&key)
            .filter(|entry| entry.generation == generation)
        else {
            SoracloudPreparedRuntimeCounters::increment(&self.counters.evictions);
            return;
        };
        entry.last_used = tick;
        entry.idle_runtimes.push(PooledSoracloudIvm {
            vm,
            template,
            previously_used: true,
        });
        state.idle_runtimes = state.idle_runtimes.saturating_add(1);
        SoracloudPreparedRuntimeCounters::increment(&self.counters.runtime_returns);
        self.enforce_idle_runtime_limit(&mut state);
    }
    #[cfg(test)]
    fn stats(&self) -> SoracloudPreparedRuntimeStats {
        let state = self.state.lock();
        SoracloudPreparedRuntimeStats {
            metadata_validations: self
                .counters
                .metadata_validations
                .load(AtomicOrdering::Relaxed),
            artifact_reads: self.counters.artifact_reads.load(AtomicOrdering::Relaxed),
            artifact_hashes: self.counters.artifact_hashes.load(AtomicOrdering::Relaxed),
            contract_preparations: self
                .counters
                .contract_preparations
                .load(AtomicOrdering::Relaxed),
            runtime_allocations: self
                .counters
                .runtime_allocations
                .load(AtomicOrdering::Relaxed),
            prepared_loads: self.counters.prepared_loads.load(AtomicOrdering::Relaxed),
            template_builds: self.counters.template_builds.load(AtomicOrdering::Relaxed),
            runtime_reuses: self.counters.runtime_reuses.load(AtomicOrdering::Relaxed),
            dirty_resets: self.counters.dirty_resets.load(AtomicOrdering::Relaxed),
            runtime_returns: self.counters.runtime_returns.load(AtomicOrdering::Relaxed),
            invalidations: self.counters.invalidations.load(AtomicOrdering::Relaxed),
            evictions: self.counters.evictions.load(AtomicOrdering::Relaxed),
            prepared_entries: state.entries.len(),
            retained_artifact_bytes: state.retained_artifact_bytes,
            idle_runtimes: state.idle_runtimes,
        }
    }
}
struct SoracloudIvmRuntimeLease<'cache> {
    cache: &'cache SoracloudPreparedRuntimeCache,
    key: Hash,
    generation: u64,
    template: RuntimeTemplate,
    vm: Option<IVM>,
}
impl Deref for SoracloudIvmRuntimeLease<'_> {
    type Target = IVM;
    fn deref(&self) -> &Self::Target {
        self.vm.as_ref().expect("runtime lease must own an IVM")
    }
}
impl DerefMut for SoracloudIvmRuntimeLease<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vm.as_mut().expect("runtime lease must own an IVM")
    }
}
impl Drop for SoracloudIvmRuntimeLease<'_> {
    fn drop(&mut self) {
        let Some(mut vm) = self.vm.take() else {
            return;
        };
        if vm.reset_from_runtime_template(&self.template).is_err() {
            return;
        }
        SoracloudPreparedRuntimeCounters::increment(&self.cache.counters.dirty_resets);
        self.cache
            .return_runtime(self.key, self.generation, self.template.clone(), vm);
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SoracloudPreparedRuntimeStats {
    metadata_validations: u64,
    artifact_reads: u64,
    artifact_hashes: u64,
    contract_preparations: u64,
    runtime_allocations: u64,
    prepared_loads: u64,
    template_builds: u64,
    runtime_reuses: u64,
    dirty_resets: u64,
    runtime_returns: u64,
    invalidations: u64,
    evictions: u64,
    prepared_entries: usize,
    retained_artifact_bytes: u64,
    idle_runtimes: usize,
}
/// Executable handle to the embedded Soracloud runtime manager.
#[derive(Clone)]
pub struct SoracloudRuntimeManagerHandle {
    snapshot: Arc<RwLock<SoracloudRuntimeSnapshot>>,
    config: Arc<SoracloudRuntimeManagerConfig>,
    state_dir: Arc<PathBuf>,
    state: Arc<State>,
    ivm_runtime_cache: Arc<SoracloudPreparedRuntimeCache>,
}
impl SoracloudRuntimeManagerHandle {
    /// Return the latest materialization snapshot.
    #[must_use]
    pub fn snapshot(&self) -> SoracloudRuntimeSnapshot {
        self.snapshot.read().clone()
    }
    /// Return the runtime-manager state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.state_dir.as_ref().clone()
    }
    #[cfg(test)]
    fn ivm_runtime_cache_stats(&self) -> SoracloudPreparedRuntimeStats {
        self.ivm_runtime_cache.stats()
    }
}
impl SoracloudRuntimeReadHandle for SoracloudRuntimeManagerHandle {
    fn snapshot(&self) -> SoracloudRuntimeSnapshot {
        SoracloudRuntimeManagerHandle::snapshot(self)
    }
    fn state_dir(&self) -> PathBuf {
        SoracloudRuntimeManagerHandle::state_dir(self)
    }
    fn local_peer_id(&self) -> Option<String> {
        self.config.local_peer_id.clone()
    }
}
impl SoracloudRuntime for SoracloudRuntimeManagerHandle {
    fn execute_local_read(
        &self,
        request: SoracloudLocalReadRequest,
    ) -> Result<SoracloudLocalReadResponse, SoracloudRuntimeExecutionError> {
        let view = self.state.view();
        let snapshot = self.snapshot();
        validate_local_runtime_snapshot(&view, &snapshot, &request)?;
        let context = resolve_local_read_context(&view, &request)?;
        match request.handler_class {
            iroha_core::soracloud_runtime::SoracloudLocalReadKind::Asset => {
                execute_asset_local_read(
                    &request,
                    &context,
                    self.state_dir.as_ref(),
                    self.config.cache_budgets.static_asset_bytes.get(),
                )
            }
            iroha_core::soracloud_runtime::SoracloudLocalReadKind::Query => {
                execute_query_local_read(
                    &view,
                    &request,
                    &context,
                    self.state_dir.as_ref(),
                    self.ivm_runtime_cache.as_ref(),
                )
            }
        }
    }
    fn execute_ordered_mailbox(
        &self,
        request: SoracloudOrderedMailboxExecutionRequest,
    ) -> Result<SoracloudOrderedMailboxExecutionResult, SoracloudRuntimeExecutionError> {
        validate_authoritative_mailbox_runtime_state(&request)?;
        if request.handler.is_none() {
            return Ok(deterministic_mailbox_failure_result(
                request,
                "missing_handler",
                SoraServiceHealthStatusV1::Degraded,
            ));
        }
        if let Err(message) = ensure_ivm_runtime(
            request.bundle.service.execution_plane,
            request.bundle.container.runtime,
            request.deployment.service_name.as_ref(),
            &request.deployment.current_service_version,
        ) {
            return Ok(deterministic_mailbox_failure_result_with_message(
                request,
                "invalid_runtime",
                message,
                SoraServiceHealthStatusV1::Degraded,
            ));
        }
        let bundle_cache_path = self
            .state_dir
            .join("artifacts")
            .join(hash_cache_name(request.bundle.container.bundle_hash));
        let prepared = match self
            .ivm_runtime_cache
            .prepare(&bundle_cache_path, request.bundle.container.bundle_hash)
        {
            Ok(prepared) => prepared,
            Err(error) => {
                if error.kind == SoracloudRuntimeExecutionErrorKind::Unavailable {
                    return Err(error);
                }
                return Ok(deterministic_mailbox_failure_result_with_message(
                    request,
                    "invalid_bundle",
                    error.message,
                    SoraServiceHealthStatusV1::Degraded,
                ));
            }
        };
        let entrypoint_name = request
            .handler
            .as_ref()
            .expect("handler presence checked above")
            .entrypoint
            .clone();
        if prepared
            .prepared
            .entrypoint_descriptor(&entrypoint_name)
            .is_none()
        {
            return Ok(deterministic_mailbox_failure_result(
                request,
                "missing_entrypoint",
                SoraServiceHealthStatusV1::Degraded,
            ));
        }
        let mut vm = match self.ivm_runtime_cache.checkout(&prepared) {
            Ok(vm) => vm,
            Err(error) => {
                if error.kind == SoracloudRuntimeExecutionErrorKind::Unavailable {
                    return Err(error);
                }
                return Ok(deterministic_mailbox_failure_result_with_message(
                    request,
                    "invalid_bundle",
                    error.message,
                    SoraServiceHealthStatusV1::Degraded,
                ));
            }
        };
        let mailbox_payload_tlv =
            match mailbox_payload_tlv_bytes(&request.mailbox_message.payload_bytes) {
                Ok(tlv_bytes) => tlv_bytes,
                Err(error) => return ordered_mailbox_vm_failure(request, &error),
            };
        let public_inputs = match ordered_mailbox_public_inputs(
            &mailbox_payload_tlv,
            request.observed_sequence,
            request.observed_height,
        ) {
            Ok(public_inputs) => public_inputs,
            Err(error) => return ordered_mailbox_vm_failure(request, &error),
        };
        let (arguments, output_kind) = match prepare_soracloud_invocation(
            &mut vm,
            &prepared.prepared,
            &entrypoint_name,
            SoracloudInvocationInput {
                body_tlv: &mailbox_payload_tlv,
                metadata_tlv: None,
                execution_sequence: Some(request.observed_sequence),
                observed_height: request.observed_height,
            },
        ) {
            Ok(invocation) => invocation,
            Err(error) => return ordered_mailbox_vm_failure(request, &error),
        };
        let committed_entries = collect_committed_service_state_entries(
            &self.state.view(),
            request.deployment.service_name.as_ref(),
        );
        let host = SoracloudIvmHost::new(request.clone(), self.state_dir(), committed_entries)
            .with_public_inputs(public_inputs)
            .with_prepared_arguments(arguments);
        vm.set_host(host);
        if let Err(error) = vm.run() {
            return ordered_mailbox_vm_failure(request, &error);
        }
        let (response_bytes, content_type) =
            match decode_ordered_mailbox_vm_output(&vm, output_kind, &request) {
                Ok(response) => response,
                Err(error) => return ordered_mailbox_output_failure(request, error),
            };
        let Some(host) = vm
            .host_mut_any()
            .and_then(|host| host.downcast_mut::<SoracloudIvmHost>())
        else {
            return Ok(deterministic_mailbox_failure_result(
                request,
                "host_unavailable",
                SoraServiceHealthStatusV1::Degraded,
            ));
        };
        match std::mem::replace(
            host,
            SoracloudIvmHost::new(request.clone(), self.state_dir(), BTreeMap::new()),
        )
        .into_execution_result(response_bytes, content_type)
        {
            Ok(result) => Ok(result),
            Err(error) => Ok(deterministic_mailbox_failure_result_with_message(
                request,
                "materialization_failure",
                error.message,
                SoraServiceHealthStatusV1::Degraded,
            )),
        }
    }
    fn execute_apartment(
        &self,
        request: SoracloudApartmentExecutionRequest,
    ) -> Result<SoracloudApartmentExecutionResult, SoracloudRuntimeExecutionError> {
        let view = self.state.view();
        let snapshot = self.snapshot();
        validate_apartment_snapshot(&view, &snapshot, &request)?;
        let Some(record) = view
            .world()
            .soracloud_agent_apartments()
            .get(&request.apartment_name)
        else {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::InvalidRequest,
                format!("unknown Soracloud apartment `{}`", request.apartment_name),
            ));
        };
        if record.process_generation != request.process_generation {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                format!(
                    "apartment `{}` process generation {} does not match committed generation {}",
                    request.apartment_name, request.process_generation, record.process_generation
                ),
            ));
        }
        let runtime_status = record.runtime_status_at_current_height(committed_height(&view));
        if runtime_status == iroha_data_model::soracloud::SoraAgentRuntimeStatusV1::LeaseExpired {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Unavailable,
                format!(
                    "apartment `{}` lease expired at consensus height {}; renew before execution",
                    request.apartment_name, record.lease_expires_height
                ),
            ));
        }
        Ok(SoracloudApartmentExecutionResult {
            status: runtime_status,
            checkpoint_artifact_hash: None,
            journal_artifact_hash: None,
            result_commitment: apartment_result_commitment(
                &request.apartment_name,
                request.process_generation,
                &request.operation,
                request.request_commitment,
                runtime_status,
            ),
        })
    }
}
#[derive(Clone, Debug)]
struct StagedRuntimeArtifact {
    artifact_path: String,
    bytes: Vec<u8>,
    artifact_hash: Hash,
}
#[derive(Clone, Copy)]
enum SoracloudResponseShape<'a> {
    ReadCommittedState(Option<&'a SoraServiceStateEntryV1>),
    SingleHash,
    HashPair,
    FoundPayload { payload_bytes: usize },
    SecretEnvelope(Option<&'a iroha_data_model::soracloud::SecretEnvelopeV1>),
}
fn exact_norito_encoded_len<T: norito::core::NoritoSerialize + ?Sized>(value: &T) -> Option<usize> {
    norito::core::SerializePayload::encoded_len_exact(value)
}
fn norito_len_prefixed_encoded_len(payload_bytes: usize) -> Option<usize> {
    norito::core::len_prefix_len_with_flags(payload_bytes, norito::core::default_encode_flags())
        .checked_add(payload_bytes)
}
fn norito_struct_encoded_len<const N: usize>(field_bytes: [usize; N]) -> Option<usize> {
    field_bytes.into_iter().try_fold(0usize, |total, field| {
        total.checked_add(norito_len_prefixed_encoded_len(field)?)
    })
}
fn norito_option_encoded_len(inner_bytes: Option<usize>) -> Option<usize> {
    match inner_bytes {
        Some(inner_bytes) => 1usize.checked_add(norito_len_prefixed_encoded_len(inner_bytes)?),
        None => Some(1),
    }
}
fn norito_enum_newtype_encoded_len(inner_bytes: usize) -> Option<usize> {
    exact_norito_encoded_len(&0u32)?.checked_add(norito_len_prefixed_encoded_len(inner_bytes)?)
}
fn norito_byte_vec_encoded_len(value_bytes: usize) -> Option<usize> {
    exact_norito_encoded_len(&0u64)?.checked_add(value_bytes)
}
fn soracloud_state_entry_encoded_len(entry: &SoraServiceStateEntryV1) -> Option<usize> {
    norito_struct_encoded_len([
        exact_norito_encoded_len(&entry.schema_version)?,
        exact_norito_encoded_len(&entry.service_name)?,
        exact_norito_encoded_len(&entry.service_version)?,
        exact_norito_encoded_len(&entry.binding_name)?,
        exact_norito_encoded_len(&entry.state_key)?,
        exact_norito_encoded_len(&entry.encryption)?,
        norito_byte_vec_encoded_len(entry.payload.len())?,
        exact_norito_encoded_len(&entry.payload_bytes)?,
        Hash::LENGTH,
        norito_option_encoded_len(entry.fhe_public_key_digest.map(|_| Hash::LENGTH))?,
        exact_norito_encoded_len(&entry.fhe_residual_multiple_bound)?,
        exact_norito_encoded_len(&entry.fhe_bound_mode)?,
        exact_norito_encoded_len(&entry.last_update_sequence)?,
        Hash::LENGTH,
        exact_norito_encoded_len(&entry.source_action)?,
    ])
}
fn soracloud_secret_envelope_encoded_len(
    envelope: &iroha_data_model::soracloud::SecretEnvelopeV1,
) -> Option<usize> {
    norito_struct_encoded_len([
        exact_norito_encoded_len(&envelope.schema_version)?,
        exact_norito_encoded_len(&envelope.encryption)?,
        exact_norito_encoded_len(&envelope.key_id)?,
        exact_norito_encoded_len(&envelope.key_version)?,
        norito_byte_vec_encoded_len(envelope.nonce.len())?,
        norito_byte_vec_encoded_len(envelope.ciphertext.len())?,
        Hash::LENGTH,
        norito_option_encoded_len(envelope.aad_digest.map(|_| Hash::LENGTH))?,
    ])
}
fn soracloud_response_encoded_len_bound(
    operation: SoracloudHostOperationV1,
    shape: SoracloudResponseShape<'_>,
) -> Option<usize> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let response_fields = match shape {
        SoracloudResponseShape::ReadCommittedState(entry) => {
            let entry_bytes = match entry {
                Some(entry) => Some(soracloud_state_entry_encoded_len(entry)?),
                None => None,
            };
            norito_struct_encoded_len([norito_option_encoded_len(entry_bytes)?])?
        }
        SoracloudResponseShape::SingleHash => norito_struct_encoded_len([Hash::LENGTH])?,
        SoracloudResponseShape::HashPair => {
            norito_struct_encoded_len([Hash::LENGTH, Hash::LENGTH])?
        }
        SoracloudResponseShape::FoundPayload { payload_bytes } => norito_struct_encoded_len([
            exact_norito_encoded_len(&false)?,
            norito_byte_vec_encoded_len(payload_bytes)?,
        ])?,
        SoracloudResponseShape::SecretEnvelope(envelope) => {
            let envelope_bytes = match envelope {
                Some(envelope) => Some(soracloud_secret_envelope_encoded_len(envelope)?),
                None => None,
            };
            norito_struct_encoded_len([norito_option_encoded_len(envelope_bytes)?])?
        }
    };
    let response_payload = norito_enum_newtype_encoded_len(response_fields)?;
    // Gas covers the complete frame written by Norito, including its header
    // and the response type's archived payload alignment padding.
    let framing = norito::core::Header::SIZE.checked_next_multiple_of(
        norito::core::archived_payload_align::<SoracloudHostResponseEnvelopeV1>(),
    )?;
    framing.checked_add(norito_struct_encoded_len([
        exact_norito_encoded_len(&SORACLOUD_HOST_RESPONSE_VERSION_V1)?,
        exact_norito_encoded_len(&operation)?,
        response_payload,
    ])?)
}
struct SoracloudIvmHost {
    request: SoracloudOrderedMailboxExecutionRequest,
    state_dir: PathBuf,
    core_host: CoreHost,
    public_inputs: BTreeMap<Name, Vec<u8>>,
    prepared_arguments: Option<PreparedArgumentRecord>,
    committed_entries: BTreeMap<(String, String), SoraServiceStateEntryV1>,
    binding_totals: BTreeMap<String, u64>,
    observed_local_read_bindings:
        BTreeMap<(String, String), iroha_core::soracloud_runtime::SoracloudLocalReadBinding>,
    staged_state_mutations: Vec<iroha_core::soracloud_runtime::SoracloudDeterministicStateMutation>,
    staged_outbound_mailbox_messages: Vec<SoraServiceMailboxMessageV1>,
    staged_journal: Option<StagedRuntimeArtifact>,
    staged_checkpoint: Option<StagedRuntimeArtifact>,
    #[cfg(test)]
    metering_queries: AtomicU64,
    #[cfg(test)]
    metering_allocations: AtomicU64,
}
impl SoracloudIvmHost {
    fn ensure_syscall_available(number: u32) -> Result<(), VMError> {
        if ivm_syscalls::is_axt_syscall(number) {
            return Err(VMError::UnknownSyscall(number));
        }
        Ok(())
    }
    fn new(
        request: SoracloudOrderedMailboxExecutionRequest,
        state_dir: PathBuf,
        committed_entries: BTreeMap<(String, String), SoraServiceStateEntryV1>,
    ) -> Self {
        let mut binding_totals = BTreeMap::new();
        for entry in committed_entries.values() {
            let total = binding_totals
                .entry(entry.binding_name.to_string())
                .or_insert(0u64);
            *total = total.saturating_add(entry.payload_bytes.get());
        }
        Self {
            request,
            state_dir,
            core_host: CoreHost::new(),
            public_inputs: BTreeMap::new(),
            prepared_arguments: None,
            committed_entries,
            binding_totals,
            observed_local_read_bindings: BTreeMap::new(),
            staged_state_mutations: Vec::new(),
            staged_outbound_mailbox_messages: Vec::new(),
            staged_journal: None,
            staged_checkpoint: None,
            #[cfg(test)]
            metering_queries: AtomicU64::new(0),
            #[cfg(test)]
            metering_allocations: AtomicU64::new(0),
        }
    }
    fn with_public_inputs(mut self, public_inputs: BTreeMap<Name, Vec<u8>>) -> Self {
        self.public_inputs = public_inputs;
        self
    }
    fn with_prepared_arguments(mut self, arguments: Option<PreparedArgumentRecord>) -> Self {
        self.prepared_arguments = arguments;
        self
    }
    fn handler_class(&self) -> SoraServiceHandlerClassV1 {
        self.request
            .handler
            .as_ref()
            .map(|handler| handler.class)
            .unwrap_or(SoraServiceHandlerClassV1::Update)
    }
    fn service_name(&self) -> &Name {
        &self.request.deployment.service_name
    }
    fn service_version(&self) -> &str {
        &self.request.deployment.current_service_version
    }
    fn require_mutating_runtime(&self, _syscall: u32) -> Result<(), VMError> {
        if self.handler_class() == SoraServiceHandlerClassV1::Update {
            Ok(())
        } else {
            Err(VMError::metered(
                ivm::gas::G_SORACLOUD,
                VMError::PermissionDenied,
            ))
        }
    }
    fn record_metering_query(&self) {
        #[cfg(test)]
        SoracloudPreparedRuntimeCounters::increment(&self.metering_queries);
    }
    fn record_metering_allocation(&self) {
        #[cfg(test)]
        SoracloudPreparedRuntimeCounters::increment(&self.metering_allocations);
    }
    #[cfg(test)]
    fn metering_query_count(&self) -> u64 {
        self.metering_queries.load(AtomicOrdering::Relaxed)
    }
    #[cfg(test)]
    fn metering_allocation_count(&self) -> u64 {
        self.metering_allocations.load(AtomicOrdering::Relaxed)
    }
    fn quoted_request_payload_len(vm: &IVM, expected: PointerType) -> Result<usize, VMError> {
        let (actual, request_bytes) = ivm::host::quote_any_tlv_at(vm, vm.register(10))
            .map_err(|error| VMError::metered(ivm::gas::G_SORACLOUD, error))?;
        let request_gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        if actual != expected {
            return Err(VMError::metered(
                request_gas,
                VMError::AbiTypeNotAllowed {
                    abi: vm.abi_version(),
                    type_id: actual as u16,
                },
            ));
        }
        Ok(request_bytes)
    }
    fn fixed_response_len(number: u32) -> Option<usize> {
        let (operation, shape) = match number {
            SYSCALL_SORACLOUD_EMIT_STATE_MUTATION => (
                SoracloudHostOperationV1::EmitStateMutation,
                SoracloudResponseShape::SingleHash,
            ),
            SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE => (
                SoracloudHostOperationV1::EmitMailboxMessage,
                SoracloudResponseShape::HashPair,
            ),
            SYSCALL_SORACLOUD_APPEND_JOURNAL => (
                SoracloudHostOperationV1::AppendJournal,
                SoracloudResponseShape::SingleHash,
            ),
            SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT => (
                SoracloudHostOperationV1::PublishCheckpoint,
                SoracloudResponseShape::SingleHash,
            ),
            _ => return None,
        };
        soracloud_response_encoded_len_bound(operation, shape)
    }
    fn state_dependent_gas_quote(vm: &IVM, request_bytes: usize) -> Result<u64, VMError> {
        let minimum = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        let available = ivm::host::reserve_available_syscall_gas(vm)?;
        if available < minimum {
            return Err(VMError::metered(available, VMError::OutOfGas));
        }
        Ok(available)
    }
    fn preflight_response_shape(
        vm: &IVM,
        request_bytes: usize,
        operation: SoracloudHostOperationV1,
        shape: SoracloudResponseShape<'_>,
    ) -> Result<(), VMError> {
        let request_gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        let response_bytes = soracloud_response_encoded_len_bound(operation, shape)
            .ok_or_else(|| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        let gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, response_bytes);
        ivm::host::preflight_reserved_syscall_gas(vm, gas)
    }
    fn read_request_payload(
        &self,
        vm: &IVM,
        expected_operation: SoracloudHostOperationV1,
        syscall: u32,
    ) -> Result<(SoracloudHostRequestPayloadV1, usize), VMError> {
        let tlv = vm
            .validate_tlv(vm.register(10))
            .map_err(|err| VMError::metered(ivm::gas::G_SORACLOUD, err))?;
        let request_bytes = tlv.payload.len();
        let request_gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        if tlv.type_id != PointerType::SoracloudRequest {
            return Err(VMError::metered(
                request_gas,
                VMError::AbiTypeNotAllowed {
                    abi: vm.abi_version(),
                    type_id: tlv.type_id_raw(),
                },
            ));
        }
        let envelope = norito::decode_from_bytes::<SoracloudHostRequestEnvelopeV1>(tlv.payload)
            .map_err(|_| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        envelope
            .validate()
            .map_err(|_| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        if envelope.operation != expected_operation {
            return Err(VMError::metered_not_implemented(request_gas, syscall));
        }
        Ok((envelope.payload, request_bytes))
    }
    fn write_response(
        &self,
        vm: &mut IVM,
        operation: SoracloudHostOperationV1,
        payload: SoracloudHostResponsePayloadV1,
        request_bytes: usize,
    ) -> Result<u64, VMError> {
        let envelope = SoracloudHostResponseEnvelopeV1 {
            schema_version: SORACLOUD_HOST_RESPONSE_VERSION_V1,
            operation,
            payload,
        };
        let request_gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        envelope
            .validate()
            .map_err(|_| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        let payload_bytes = norito::to_bytes(&envelope)
            .map_err(|_| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        let gas =
            ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, payload_bytes.len());
        ivm::host::preflight_reserved_syscall_gas(vm, gas)?;
        let tlv = make_pointer_tlv(PointerType::SoracloudResponse, &payload_bytes);
        self.record_metering_allocation();
        let ptr = vm
            .alloc_host_tlv(&tlv)
            .map_err(|err| VMError::metered(gas, err))?;
        vm.set_register(10, ptr);
        Ok(gas)
    }
    fn binding(&self, binding_name: &Name) -> Result<&SoraStateBindingV1, VMError> {
        self.request
            .bundle
            .service
            .state_bindings
            .iter()
            .find(|binding| binding.binding_name == *binding_name)
            .ok_or(VMError::PermissionDenied)
    }
    fn state_entry_key(binding_name: &Name, state_key: &str) -> (String, String) {
        (binding_name.to_string(), state_key.to_owned())
    }
    fn current_entry_size(&self, binding_name: &Name, state_key: &str) -> u64 {
        let key = Self::state_entry_key(binding_name, state_key);
        self.committed_entries
            .get(&key)
            .map(|entry| entry.payload_bytes.get())
            .unwrap_or(0)
    }
    fn stage_state_mutation(
        &mut self,
        request: SoracloudEmitStateMutationRequestV1,
    ) -> Result<SoracloudEmitStateMutationResponseV1, VMError> {
        self.record_metering_query();
        self.require_mutating_runtime(SYSCALL_SORACLOUD_EMIT_STATE_MUTATION)?;
        if !self
            .request
            .bundle
            .container
            .capabilities
            .allow_state_writes
        {
            return Err(VMError::PermissionDenied);
        }
        if request.state_key.trim().is_empty() || !request.state_key.starts_with('/') {
            return Err(VMError::PermissionDenied);
        }
        let binding = self.binding(&request.binding_name)?.clone();
        if !request.state_key.starts_with(&binding.key_prefix) {
            return Err(VMError::PermissionDenied);
        }
        if binding.encryption != request.encryption {
            return Err(VMError::PermissionDenied);
        }
        let binding_name = request.binding_name.to_string();
        let current_size = self.current_entry_size(&request.binding_name, &request.state_key);
        match request.operation {
            SoraStateMutationOperationV1::Upsert => {
                let Some(payload) = request.payload.as_ref() else {
                    return Err(VMError::NoritoInvalid);
                };
                let payload_bytes =
                    u64::try_from(payload.len()).map_err(|_| VMError::NoritoInvalid)?;
                if payload_bytes == 0 {
                    return Err(VMError::NoritoInvalid);
                }
                if request
                    .payload_bytes
                    .is_some_and(|declared| declared != payload_bytes)
                {
                    return Err(VMError::NoritoInvalid);
                }
                let payload_commitment = Hash::new(payload);
                if request
                    .payload_commitment
                    .is_some_and(|declared| declared != payload_commitment)
                {
                    return Err(VMError::NoritoInvalid);
                }
                if payload_bytes > binding.max_item_bytes.get() {
                    return Err(VMError::PermissionDenied);
                }
                if !matches!(
                    binding.mutability,
                    iroha_data_model::soracloud::SoraStateMutabilityV1::AppendOnly
                        | iroha_data_model::soracloud::SoraStateMutabilityV1::ReadWrite
                ) {
                    return Err(VMError::PermissionDenied);
                }
                if binding.mutability
                    == iroha_data_model::soracloud::SoraStateMutabilityV1::AppendOnly
                    && current_size > 0
                {
                    return Err(VMError::PermissionDenied);
                }
                let current_total = self.binding_totals.get(&binding_name).copied().unwrap_or(0);
                let next_total = current_total
                    .saturating_sub(current_size)
                    .saturating_add(payload_bytes);
                if next_total > binding.max_total_bytes.get() {
                    return Err(VMError::PermissionDenied);
                }
                self.binding_totals.insert(binding_name.clone(), next_total);
                self.committed_entries.insert(
                    Self::state_entry_key(&request.binding_name, &request.state_key),
                    SoraServiceStateEntryV1 {
                        schema_version:
                            iroha_data_model::soracloud::SORA_SERVICE_STATE_ENTRY_VERSION_V1,
                        service_name: self.request.deployment.service_name.clone(),
                        service_version: self.request.deployment.current_service_version.clone(),
                        binding_name: request.binding_name.clone(),
                        state_key: request.state_key.clone(),
                        encryption: request.encryption,
                        payload: payload.clone(),
                        payload_bytes: std::num::NonZeroU64::new(payload_bytes)
                            .ok_or(VMError::NoritoInvalid)?,
                        payload_commitment,
                        fhe_public_key_digest: None,
                        fhe_residual_multiple_bound: None,
                        fhe_bound_mode: None,
                        last_update_sequence: self.request.observed_sequence,
                        governance_tx_hash: self.request.mailbox_message.payload_commitment,
                        source_action: SoraServiceLifecycleActionV1::StateMutation,
                    },
                );
            }
            SoraStateMutationOperationV1::Delete => {
                if request.payload_bytes.is_some()
                    || request.payload.is_some()
                    || request.payload_commitment.is_some()
                {
                    return Err(VMError::NoritoInvalid);
                }
                if binding.mutability
                    != iroha_data_model::soracloud::SoraStateMutabilityV1::ReadWrite
                {
                    return Err(VMError::PermissionDenied);
                }
                let current_total = self.binding_totals.get(&binding_name).copied().unwrap_or(0);
                self.binding_totals.insert(
                    binding_name.clone(),
                    current_total.saturating_sub(current_size),
                );
                self.committed_entries.remove(&Self::state_entry_key(
                    &request.binding_name,
                    &request.state_key,
                ));
            }
        }
        let mutation_payload_bytes = request
            .payload
            .as_ref()
            .and_then(|payload| u64::try_from(payload.len()).ok());
        let mutation_payload_commitment = request.payload.as_ref().map(Hash::new);
        let mutation = iroha_core::soracloud_runtime::SoracloudDeterministicStateMutation {
            binding_name,
            state_key: request.state_key.clone(),
            operation: request.operation,
            encryption: request.encryption,
            payload_bytes: mutation_payload_bytes,
            payload: request.payload.clone(),
            payload_commitment: mutation_payload_commitment,
        };
        let mutation_commitment = Hash::new(Encode::encode(&(
            "soracloud.host.state-mutation.v1",
            self.request.mailbox_message.message_id,
            mutation.binding_name.as_str(),
            mutation.state_key.as_str(),
            mutation.operation,
            mutation.encryption,
            mutation.payload_bytes,
            mutation.payload_commitment,
            u64::try_from(self.staged_state_mutations.len()).unwrap_or(u64::MAX),
        )));
        self.staged_state_mutations.push(mutation);
        Ok(SoracloudEmitStateMutationResponseV1 {
            mutation_commitment,
        })
    }
    fn stage_outbound_mailbox_message(
        &mut self,
        request: SoracloudEmitMailboxMessageRequestV1,
    ) -> Result<SoracloudEmitMailboxMessageResponseV1, VMError> {
        self.require_mutating_runtime(SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE)?;
        let payload_commitment = Hash::new(&request.payload_bytes);
        let staged_message_id = Hash::new(Encode::encode(&(
            "soracloud.host.mailbox.v1",
            self.request.mailbox_message.message_id,
            self.request.deployment.service_name.as_ref(),
            self.request.mailbox_message.to_handler.as_ref(),
            request.to_service.as_ref(),
            request.to_handler.as_ref(),
            payload_commitment,
            request.delivery_delay_blocks,
            u64::try_from(self.staged_outbound_mailbox_messages.len()).unwrap_or(u64::MAX),
        )));
        self.staged_outbound_mailbox_messages
            .push(SoraServiceMailboxMessageV1 {
                schema_version: SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
                message_id: Hash::prehashed([0; Hash::LENGTH]),
                from_service: self.request.deployment.service_name.clone(),
                from_service_version: String::new(),
                from_handler: self.request.mailbox_message.to_handler.clone(),
                to_service: request.to_service,
                to_service_version: String::new(),
                to_handler: request.to_handler,
                payload_bytes: request.payload_bytes,
                payload_commitment,
                delivery_delay_blocks: request.delivery_delay_blocks,
                enqueue_sequence: 0,
                enqueue_height: 0,
                available_after_height: 0,
                expires_at_height: 0,
            });
        Ok(SoracloudEmitMailboxMessageResponseV1 {
            message_id: staged_message_id,
            payload_commitment,
        })
    }
    fn stage_artifact(
        slot: &mut Option<StagedRuntimeArtifact>,
        request: String,
        bytes: Vec<u8>,
    ) -> Hash {
        let artifact_hash = Hash::new(&bytes);
        *slot = Some(StagedRuntimeArtifact {
            artifact_path: request,
            bytes,
            artifact_hash,
        });
        artifact_hash
    }
    fn read_config_material(&self, key: &str) -> Result<Option<Vec<u8>>, VMError> {
        self.record_metering_query();
        if let Some(config) = self.request.deployment.service_configs.get(key) {
            let bytes = config.value_json.get().as_bytes();
            if bytes.len() > SORACLOUD_HOST_VARIABLE_RESPONSE_MAX_BYTES {
                return Err(VMError::PermissionDenied);
            }
            return Ok(Some(bytes.to_vec()));
        }
        let relative = sanitized_relative_material_path(key)?;
        let path = self
            .state_dir
            .join("configs")
            .join(storage_path_component(self.service_name().as_ref()))
            .join(storage_path_component(self.service_version()))
            .join(relative);
        match read_soracloud_regular_file_bounded(
            &path,
            u64::try_from(SORACLOUD_HOST_VARIABLE_RESPONSE_MAX_BYTES).unwrap_or(u64::MAX),
            "Soracloud service material",
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(VMError::PermissionDenied),
        }
    }
    fn read_service_config(
        &self,
        config_name: &str,
    ) -> Result<SoracloudReadConfigResponseV1, VMError> {
        let payload_bytes = self.read_config_material(config_name)?;
        Ok(SoracloudReadConfigResponseV1 {
            found: payload_bytes.is_some(),
            payload_bytes: payload_bytes.unwrap_or_default(),
        })
    }
    fn read_service_secret_envelope(
        &self,
        secret_name: &str,
    ) -> SoracloudReadSecretEnvelopeResponseV1 {
        self.record_metering_query();
        SoracloudReadSecretEnvelopeResponseV1 {
            envelope: self
                .request
                .deployment
                .service_secrets
                .get(secret_name)
                .map(|entry| entry.envelope.clone()),
        }
    }
    fn read_public_input(&self, vm: &mut IVM) -> Result<u64, VMError> {
        let ptr = vm.register(10);
        let tlv = vm
            .validate_tlv(ptr)
            .map_err(|error| VMError::metered(ivm::gas::G_SORACLOUD, error))?;
        let request_bytes = tlv.payload.len();
        let request_gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0);
        if tlv.type_id != PointerType::Name {
            return Err(VMError::metered(request_gas, VMError::NoritoInvalid));
        }
        let name: Name = norito::decode_from_bytes(tlv.payload)
            .map_err(|_| VMError::metered(request_gas, VMError::NoritoInvalid))?;
        self.record_metering_query();
        let Some(bytes) = self.public_inputs.get(&name) else {
            return Err(VMError::metered(request_gas, VMError::PermissionDenied));
        };
        let gas = ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, bytes.len());
        ivm::host::preflight_reserved_syscall_gas(vm, gas)?;
        self.record_metering_allocation();
        let dst = vm
            .alloc_host_tlv(bytes)
            .map_err(|error| VMError::metered(gas, error))?;
        vm.set_register(10, dst);
        Ok(gas)
    }
    fn into_execution_result(
        self,
        response_bytes: Vec<u8>,
        content_type: Option<String>,
    ) -> Result<SoracloudOrderedMailboxExecutionResult, SoracloudRuntimeExecutionError> {
        let handler_class = self.handler_class();
        let journal_artifact_hash = persist_staged_runtime_artifact(
            self.state_dir.join("journals"),
            self.staged_journal.as_ref(),
        )?;
        let checkpoint_artifact_hash = persist_staged_runtime_artifact(
            self.state_dir.join("checkpoints"),
            self.staged_checkpoint.as_ref(),
        )?;
        let runtime_state = updated_runtime_state(
            self.request.runtime_state.clone(),
            SoraServiceHealthStatusV1::Healthy,
        );
        let result_commitment = authoritative_mailbox_result_commitment(
            &self.request,
            &self.staged_state_mutations,
            &self.staged_outbound_mailbox_messages,
            &response_bytes,
            content_type.as_deref(),
            &runtime_state,
            journal_artifact_hash,
            checkpoint_artifact_hash,
        );
        let mut runtime_receipt = SoraRuntimeReceiptV1 {
            schema_version: SORA_RUNTIME_RECEIPT_VERSION_V1,
            receipt_id: Hash::prehashed([0; Hash::LENGTH]),
            service_name: self.request.deployment.service_name.clone(),
            service_version: self.request.deployment.current_service_version.clone(),
            handler_name: self.request.mailbox_message.to_handler.clone(),
            handler_class,
            request_commitment: self.request.mailbox_message.payload_commitment,
            result_commitment,
            certified_by: SoraCertifiedResponsePolicyV1::None,
            emitted_sequence: 0,
            execution_host: None,
            mailbox_message_id: Some(self.request.mailbox_message.message_id),
            journal_artifact_hash,
            checkpoint_artifact_hash,
        };
        runtime_receipt.receipt_id =
            iroha_core::soracloud_runtime::ordered_mailbox_runtime_receipt_id(&runtime_receipt)
                .expect("ordered mailbox runtime receipt carries its source message");
        Ok(SoracloudOrderedMailboxExecutionResult {
            state_mutations: self.staged_state_mutations,
            outbound_mailbox_messages: self.staged_outbound_mailbox_messages,
            response_bytes,
            content_type,
            runtime_state: Some(runtime_state),
            runtime_receipt,
        })
    }
    fn local_read_bindings(&self) -> Vec<iroha_core::soracloud_runtime::SoracloudLocalReadBinding> {
        self.observed_local_read_bindings
            .values()
            .cloned()
            .collect::<Vec<_>>()
    }
    fn has_local_read_side_effects(&self) -> bool {
        !self.staged_state_mutations.is_empty()
            || !self.staged_outbound_mailbox_messages.is_empty()
            || self.staged_journal.is_some()
            || self.staged_checkpoint.is_some()
    }
}
impl IVMHost for SoracloudIvmHost {
    fn prepared_entrypoint_arguments(&self) -> Option<PreparedArgumentRecord> {
        self.prepared_arguments.clone()
    }
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        Self::ensure_syscall_available(number)?;
        if number == ivm_syscalls::SYSCALL_GET_PUBLIC_INPUT {
            let request_bytes = Self::quoted_request_payload_len(vm, PointerType::Name)?;
            return Self::state_dependent_gas_quote(vm, request_bytes);
        }
        match number {
            SYSCALL_SORACLOUD_READ_COMMITTED_STATE
            | SYSCALL_SORACLOUD_EMIT_STATE_MUTATION
            | SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE
            | SYSCALL_SORACLOUD_APPEND_JOURNAL
            | SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT
            | SYSCALL_SORACLOUD_READ_CONFIG
            | SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE => {}
            _ => return self.core_host.prepare_syscall(number, vm),
        }
        let request_bytes = Self::quoted_request_payload_len(vm, PointerType::SoracloudRequest)?;
        if let Some(response_bytes) = Self::fixed_response_len(number) {
            Ok(ivm::gas::syscall_byte_gas(
                ivm::gas::G_SORACLOUD,
                request_bytes,
                response_bytes,
            ))
        } else {
            Self::state_dependent_gas_quote(vm, request_bytes)
        }
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        Self::ensure_syscall_available(number)?;
        match number {
            ivm_syscalls::SYSCALL_GET_PUBLIC_INPUT => self.read_public_input(vm),
            SYSCALL_SORACLOUD_READ_COMMITTED_STATE => {
                let (payload, request_bytes) = self.read_request_payload(
                    vm,
                    SoracloudHostOperationV1::ReadCommittedState,
                    number,
                )?;
                let SoracloudHostRequestPayloadV1::ReadCommittedState(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                self.record_metering_query();
                let entry = self
                    .committed_entries
                    .get(&Self::state_entry_key(
                        &request.binding_name,
                        &request.state_key,
                    ))
                    .cloned();
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::ReadCommittedState,
                    SoracloudResponseShape::ReadCommittedState(entry.as_ref()),
                )?;
                if let Some(entry) = entry.as_ref() {
                    self.observed_local_read_bindings.insert(
                        Self::state_entry_key(&request.binding_name, &request.state_key),
                        state_entry_binding(entry),
                    );
                }
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::ReadCommittedState,
                    SoracloudHostResponsePayloadV1::ReadCommittedState(
                        SoracloudReadCommittedStateResponseV1 { entry },
                    ),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_EMIT_STATE_MUTATION => {
                let (payload, request_bytes) = self.read_request_payload(
                    vm,
                    SoracloudHostOperationV1::EmitStateMutation,
                    number,
                )?;
                let SoracloudHostRequestPayloadV1::EmitStateMutation(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::EmitStateMutation,
                    SoracloudResponseShape::SingleHash,
                )?;
                let response = self.stage_state_mutation(request).map_err(|err| {
                    VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        err.into_unmetered(),
                    )
                })?;
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::EmitStateMutation,
                    SoracloudHostResponsePayloadV1::EmitStateMutation(response),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE => {
                let (payload, request_bytes) = self.read_request_payload(
                    vm,
                    SoracloudHostOperationV1::EmitMailboxMessage,
                    number,
                )?;
                let SoracloudHostRequestPayloadV1::EmitMailboxMessage(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::EmitMailboxMessage,
                    SoracloudResponseShape::HashPair,
                )?;
                let response = self
                    .stage_outbound_mailbox_message(request)
                    .map_err(|err| {
                        VMError::metered(
                            ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                            err.into_unmetered(),
                        )
                    })?;
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::EmitMailboxMessage,
                    SoracloudHostResponsePayloadV1::EmitMailboxMessage(response),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_APPEND_JOURNAL => {
                let (payload, request_bytes) =
                    self.read_request_payload(vm, SoracloudHostOperationV1::AppendJournal, number)?;
                let SoracloudHostRequestPayloadV1::AppendJournal(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                self.require_mutating_runtime(number).map_err(|err| {
                    VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        err,
                    )
                })?;
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::AppendJournal,
                    SoracloudResponseShape::SingleHash,
                )?;
                let artifact_hash = Self::stage_artifact(
                    &mut self.staged_journal,
                    request.artifact_path,
                    request.payload_bytes,
                );
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::AppendJournal,
                    SoracloudHostResponsePayloadV1::AppendJournal(
                        SoracloudAppendJournalResponseV1 { artifact_hash },
                    ),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT => {
                let (payload, request_bytes) = self.read_request_payload(
                    vm,
                    SoracloudHostOperationV1::PublishCheckpoint,
                    number,
                )?;
                let SoracloudHostRequestPayloadV1::PublishCheckpoint(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                self.require_mutating_runtime(number).map_err(|err| {
                    VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        err,
                    )
                })?;
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::PublishCheckpoint,
                    SoracloudResponseShape::SingleHash,
                )?;
                let artifact_hash = Self::stage_artifact(
                    &mut self.staged_checkpoint,
                    request.artifact_path,
                    request.payload_bytes,
                );
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::PublishCheckpoint,
                    SoracloudHostResponsePayloadV1::PublishCheckpoint(
                        SoracloudPublishCheckpointResponseV1 { artifact_hash },
                    ),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_READ_CONFIG => {
                let (payload, request_bytes) =
                    self.read_request_payload(vm, SoracloudHostOperationV1::ReadConfig, number)?;
                let SoracloudHostRequestPayloadV1::ReadConfig(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                let response = self
                    .read_service_config(&request.config_name)
                    .map_err(|err| {
                        VMError::metered(
                            ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                            err,
                        )
                    })?;
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::ReadConfig,
                    SoracloudResponseShape::FoundPayload {
                        payload_bytes: response.payload_bytes.len(),
                    },
                )?;
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::ReadConfig,
                    SoracloudHostResponsePayloadV1::ReadConfig(response),
                    request_bytes,
                )
            }
            SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE => {
                let (payload, request_bytes) = self.read_request_payload(
                    vm,
                    SoracloudHostOperationV1::ReadSecretEnvelope,
                    number,
                )?;
                let SoracloudHostRequestPayloadV1::ReadSecretEnvelope(request) = payload else {
                    return Err(VMError::metered(
                        ivm::gas::syscall_byte_gas(ivm::gas::G_SORACLOUD, request_bytes, 0),
                        VMError::NoritoInvalid,
                    ));
                };
                let response = self.read_service_secret_envelope(&request.secret_name);
                Self::preflight_response_shape(
                    vm,
                    request_bytes,
                    SoracloudHostOperationV1::ReadSecretEnvelope,
                    SoracloudResponseShape::SecretEnvelope(response.envelope.as_ref()),
                )?;
                self.write_response(
                    vm,
                    SoracloudHostOperationV1::ReadSecretEnvelope,
                    SoracloudHostResponsePayloadV1::ReadSecretEnvelope(response),
                    request_bytes,
                )
            }
            _ => self.core_host.syscall(number, vm),
        }
    }
    fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
        !ivm_syscalls::is_axt_syscall(number) && self.core_host.allows_syscall(policy, number)
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any
    where
        Self: 'static,
    {
        self
    }
}
#[derive(Clone)]
struct ResolvedLocalReadContext {
    deployment: SoraServiceDeploymentStateV1,
    bundle: SoraDeploymentBundleV1,
    handler: SoraServiceHandlerV1,
}
type HostedHttpReporterKey = (String, String, u64, u64, u16, String);
type HostedHttpReplicaStateKey = (String, String, u16, String);
type HostedHttpRevisionKey = (String, String, u64, u64);
type SharedHostedHttpWorkers =
    Arc<Mutex<BTreeMap<HostedHttpReporterKey, Arc<Mutex<HostedHttpWorker>>>>>;
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostedHttpWorkerCacheKey {
    runtime: SoraContainerRuntimeV1,
    guest_isa: Option<SoraInrouGuestIsaV1>,
    service_name: String,
    service_version: String,
    replica_slot: u16,
    lease_started_height: u64,
    placement_incarnation: String,
    validator_account_id: String,
    peer_id: String,
    bundle_hash: String,
    bundle_path: String,
    entrypoint: String,
    process_generation: u64,
    args: Vec<String>,
    effective_env: BTreeMap<String, String>,
    healthcheck_path: Option<String>,
    service_data_dir: PathBuf,
}
struct HostedHttpWorker {
    cache_key: HostedHttpWorkerCacheKey,
    child: std::process::Child,
    log_drains: Vec<thread::JoinHandle<()>>,
    listen_base_url: String,
    egress_accounting: PortableVmReplicaEgressAccounting,
    stderr_log_path: PathBuf,
    /// Effective shutdown grace: max(operator minimum, workload minimum).
    stop_grace: Duration,
    port_forward: Option<PortableVmLoopbackBridge>,
    qmp_control: Option<Arc<Mutex<PortableVmQmpControl>>>,
    #[cfg(target_os = "linux")]
    loopback_firewall: Option<InrouLoopbackOwnerFirewall>,
    #[cfg(target_os = "linux")]
    cgroup: Option<inrou_cgroup::InrouWorkerCgroup>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedHttpLeaseUsageSubmissionAttempt {
    accounted_egress_bytes: u64,
    finalize_reporter: bool,
    attempted_at_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedHttpRuntimeStateSubmissionAttempt {
    commitment: Hash,
    attempted_at_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedHttpReporterCheckpointState {
    lease_started_height: u64,
    reporting_epoch: u64,
    accounted_egress_bytes: u64,
    finalize_reporter: bool,
}
fn hosted_http_reporter_checkpoint_is_current_open(
    authoritative: Option<HostedHttpReporterCheckpointState>,
    lease_started_height: u64,
    reporting_epoch: u64,
    local_accounted_egress_bytes: u64,
) -> bool {
    authoritative
        == Some(HostedHttpReporterCheckpointState {
            lease_started_height,
            reporting_epoch,
            accounted_egress_bytes: local_accounted_egress_bytes,
            finalize_reporter: false,
        })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostedHttpTerminalReporterAction {
    Retire,
    Submit,
}
fn hosted_http_terminal_reporter_action(
    authoritative: Option<HostedHttpReporterCheckpointState>,
    local_accounted_egress_bytes: u64,
) -> io::Result<HostedHttpTerminalReporterAction> {
    match authoritative {
        Some(checkpoint)
            if checkpoint.finalize_reporter
                && checkpoint.accounted_egress_bytes == local_accounted_egress_bytes =>
        {
            Ok(HostedHttpTerminalReporterAction::Retire)
        }
        Some(checkpoint) if checkpoint.finalize_reporter => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "finalized authoritative reporter checkpoint at {} bytes does not match the durable local counter at {local_accounted_egress_bytes} bytes",
                checkpoint.accounted_egress_bytes
            ),
        )),
        Some(checkpoint) if checkpoint.accounted_egress_bytes > local_accounted_egress_bytes => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authoritative terminal checkpoint exceeds the durable local reporter counter",
            ))
        }
        Some(_) => Ok(HostedHttpTerminalReporterAction::Submit),
        None if local_accounted_egress_bytes == 0 => Ok(HostedHttpTerminalReporterAction::Retire),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a nonzero stopped reporter has no admitted on-chain checkpoint to finalize",
        )),
    }
}
/// Embedded `irohad` Soracloud runtime-manager actor.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InrouStartupCapabilitySnapshot {
    supported_guest_isas: BTreeSet<SoraInrouGuestIsaV1>,
    trusted_guest_artifact: SoraPublishedInrouGuestImageArtifactV1,
}
impl InrouStartupCapabilitySnapshot {
    fn from_validated_config(config: &SoracloudRuntimeManagerConfig) -> Option<Self> {
        if !config.inrou.enabled {
            return None;
        }
        let guest_isa = current_host_inrou_guest_isa()?;
        let trusted_guest_artifact = config.inrou.trusted_guest_artifact.clone()?;
        Some(Self {
            supported_guest_isas: BTreeSet::from([guest_isa]),
            trusted_guest_artifact,
        })
    }

    fn qualify(config: &SoracloudRuntimeManagerConfig) -> eyre::Result<Option<Self>> {
        validate_soracloud_runtime_manager_posture(config)?;
        ensure_inrou_portable_vm_available(&config.inrou)?;
        Ok(Self::from_validated_config(config))
    }

    // Record-format tests need the structurally exact projection without
    // conferring launch authority; shipping builds do not compile this path.
    #[cfg(test)]
    fn for_capability_record_unit_test(
        config: &SoracloudRuntimeManagerConfig,
    ) -> eyre::Result<Option<Self>> {
        validate_inrou_portable_vm_v1_config(&config.inrou)?;
        Ok(Self::from_validated_config(config))
    }
}
pub(crate) struct SoracloudRuntimeManager {
    config: SoracloudRuntimeManagerConfig,
    state: Arc<State>,
    snapshot: Arc<RwLock<SoracloudRuntimeSnapshot>>,
    hosted_http_workers: SharedHostedHttpWorkers,
    mutation_sink: Option<Arc<dyn SoracloudRuntimeMutationSink>>,
    last_inrou_host_advert_attempt_ms: Mutex<Option<u64>>,
    pending_inrou_host_capability_advert: Mutex<Option<SoraInrouHostCapabilityRecordV1>>,
    inrou_startup_capability: Option<InrouStartupCapabilitySnapshot>,
    inrou_startup_qualified_config: Option<SoracloudRuntimeManagerConfig>,
    last_inrou_host_withdraw_attempt_ms: Mutex<Option<u64>>,
    last_inrou_placement_reconcile_attempt_ms: Mutex<Option<u64>>,
    last_runtime_state_submission_commitments:
        Mutex<BTreeMap<HostedHttpReplicaStateKey, HostedHttpRuntimeStateSubmissionAttempt>>,
    last_service_lease_usage_submission_bytes:
        Mutex<BTreeMap<HostedHttpReporterKey, HostedHttpLeaseUsageSubmissionAttempt>>,
    inrou_revision_egress_accounting:
        Mutex<BTreeMap<HostedHttpRevisionKey, PortableVmEgressAccounting>>,
    inrou_replica_egress_accounting:
        Mutex<BTreeMap<HostedHttpReporterKey, PortableVmEgressAccounting>>,
    sorafs_node: Option<sorafs_node::NodeHandle>,
    operator_preseed_store: Option<QualifiedOperatorPreseedStore>,
    sorafs_provider_cache: Option<Arc<AsyncRwLock<ProviderAdvertCache>>>,
    remote_hydration_provider_gates: Mutex<BTreeMap<[u8; 32], Arc<RemoteHydrationProviderGate>>>,
    remote_stream_token_operator: Option<remote_stream_token_auth::RemoteStreamTokenOperator>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QualifiedOperatorPreseedManifest {
    payload_digest: [u8; 32],
    content_length: u64,
}
struct QualifiedOperatorPreseedStore {
    backend: Arc<StorageBackend>,
    manifests: BTreeMap<[u8; 32], QualifiedOperatorPreseedManifest>,
}
impl QualifiedOperatorPreseedStore {
    fn from_validated_digests(
        backend: Arc<StorageBackend>,
        qualified_manifest_digests: BTreeSet<[u8; 32]>,
    ) -> eyre::Result<Self> {
        if qualified_manifest_digests.is_empty() {
            eyre::bail!(
                "operator-preseed attachment requires at least one current qualified manifest"
            );
        }
        if qualified_manifest_digests.len() > SORACLOUD_OPERATOR_PRESEED_MAX_MANIFEST_SCAN_V1 {
            eyre::bail!(
                "operator-preseed qualification contains {} manifests, exceeding the V1 hydration limit of {}",
                qualified_manifest_digests.len(),
                SORACLOUD_OPERATOR_PRESEED_MAX_MANIFEST_SCAN_V1
            );
        }
        let mut manifests = BTreeMap::new();
        for digest in qualified_manifest_digests {
            let manifest = backend.manifest_by_digest(&digest).ok_or_else(|| {
                eyre::eyre!(
                    "current operator-preseed qualification references missing manifest {}",
                    hex::encode(digest)
                )
            })?;
            if manifest.content_length() == 0 {
                eyre::bail!(
                    "current operator-preseed qualification references empty manifest {}",
                    hex::encode(digest)
                );
            }
            manifests.insert(
                digest,
                QualifiedOperatorPreseedManifest {
                    payload_digest: *manifest.payload_digest(),
                    content_length: manifest.content_length(),
                },
            );
        }
        Ok(Self { backend, manifests })
    }

    fn manifest_by_digest(&self, digest: &[u8; 32]) -> eyre::Result<Option<StoredManifest>> {
        let Some(qualified) = self.manifests.get(digest) else {
            return Ok(None);
        };
        let manifest = self.backend.manifest_by_digest(digest).ok_or_else(|| {
            eyre::eyre!(
                "qualified operator-preseed manifest {} disappeared after startup validation",
                hex::encode(digest)
            )
        })?;
        if manifest.payload_digest() != &qualified.payload_digest
            || manifest.content_length() != qualified.content_length
        {
            eyre::bail!(
                "qualified operator-preseed manifest {} changed payload identity after startup validation",
                hex::encode(digest)
            );
        }
        Ok(Some(manifest))
    }
}
fn validate_operator_preseed_provider_boundary(
    inrou_enabled: bool,
    operator_preseed_attached: bool,
    provider_storage_enabled: bool,
) -> eyre::Result<()> {
    if operator_preseed_attached && !inrou_enabled {
        eyre::bail!("operator-preseed storage is valid only while Inrou hosting is enabled");
    }
    if inrou_enabled && provider_storage_enabled {
        eyre::bail!("Inrou V1 hosting requires embedded SoraFS provider storage to be disabled");
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationSource {
    manifest_digest_hex: String,
    manifest_cid_hex: String,
    chunker_handle: Option<String>,
    provider_ids: Vec<[u8; 32]>,
}
#[derive(Debug)]
struct RequiredArtifactHydration {
    cache_path: PathBuf,
    artifact_hash: Hash,
    artifact_path: String,
    maximum_bytes: u64,
    operator_preseed_required: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationProviderTarget {
    base_url: reqwest::Url,
    advert_issued_at: u64,
    maximum_concurrent_streams: NonZeroUsize,
}
#[derive(Debug)]
struct RemoteHydrationProviderGate {
    state: Mutex<RemoteHydrationProviderGateState>,
    available: parking_lot::Condvar,
}
#[derive(Clone, Copy, Debug)]
struct RemoteHydrationProviderGateState {
    in_flight: usize,
    advert_issued_at: u64,
    maximum_concurrent_streams: NonZeroUsize,
}
impl RemoteHydrationProviderGate {
    fn new(advert_issued_at: u64, maximum_concurrent_streams: NonZeroUsize) -> Self {
        Self {
            state: Mutex::new(RemoteHydrationProviderGateState {
                in_flight: 0,
                advert_issued_at,
                maximum_concurrent_streams,
            }),
            available: parking_lot::Condvar::new(),
        }
    }

    fn acquire(
        self: &Arc<Self>,
        advert_issued_at: u64,
        advertised_maximum: NonZeroUsize,
    ) -> Option<RemoteHydrationProviderPermit> {
        let mut state = self.state.lock();
        if advert_issued_at > state.advert_issued_at {
            state.advert_issued_at = advert_issued_at;
            state.maximum_concurrent_streams = advertised_maximum;
            self.available.notify_all();
        } else if advert_issued_at == state.advert_issued_at
            && advertised_maximum < state.maximum_concurrent_streams
        {
            state.maximum_concurrent_streams = advertised_maximum;
            self.available.notify_all();
        }
        loop {
            if advert_issued_at < state.advert_issued_at {
                return None;
            }
            if state.in_flight < state.maximum_concurrent_streams.get() {
                state.in_flight += 1;
                drop(state);
                return Some(RemoteHydrationProviderPermit {
                    gate: Arc::clone(self),
                });
            }
            self.available.wait(&mut state);
        }
    }
}
struct RemoteHydrationProviderPermit {
    gate: Arc<RemoteHydrationProviderGate>,
}
impl Drop for RemoteHydrationProviderPermit {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.in_flight = state
            .in_flight
            .checked_sub(1)
            .expect("a provider permit increments the in-flight count before construction");
        self.gate.available.notify_one();
    }
}
struct RemoteHydrationProviderSession {
    target: RemoteHydrationProviderTarget,
    _permit: RemoteHydrationProviderPermit,
}

fn run_bounded_hydration_tasks<T, F>(
    tasks: &[T],
    maximum_workers: NonZeroUsize,
    operation: F,
) -> eyre::Result<()>
where
    T: Sync,
    F: Fn(&T) -> eyre::Result<()> + Sync,
{
    if maximum_workers.get()
        > iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX
    {
        eyre::bail!(
            "Soracloud artifact hydration worker count exceeds the first-release limit of {}",
            iroha_config::parameters::defaults::soracloud_runtime::HYDRATION_CONCURRENCY_MAX
        );
    }
    if tasks.is_empty() {
        return Ok(());
    }
    let worker_count = maximum_workers.get().min(tasks.len());
    thread::scope(|scope| {
        let operation = &operation;
        let mut task_senders = Vec::with_capacity(worker_count);
        let mut result_receivers = Vec::with_capacity(worker_count);
        let mut workers = Vec::with_capacity(worker_count);
        let mut spawn_error = None;
        for worker_index in 0..worker_count {
            let (task_sender, task_receiver) = mpsc::sync_channel::<Option<usize>>(1);
            let (result_sender, result_receiver) =
                mpsc::sync_channel::<(usize, eyre::Result<()>)>(1);
            match thread::Builder::new()
                .name(format!("soracloud-hydration-{worker_index}"))
                .spawn_scoped(scope, move || {
                    while let Ok(Some(task_index)) = task_receiver.recv() {
                        let result = operation(&tasks[task_index]);
                        if result_sender.send((task_index, result)).is_err() {
                            break;
                        }
                    }
                }) {
                Ok(worker) => {
                    task_senders.push(task_sender);
                    result_receivers.push(result_receiver);
                    workers.push(worker);
                }
                Err(error) => {
                    spawn_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = spawn_error {
            for sender in &task_senders {
                let _ = sender.send(None);
            }
            for worker in workers {
                let _ = worker.join();
            }
            return Err(error).wrap_err("spawn Soracloud artifact hydration worker");
        }

        let mut outcome = Ok(());
        let mut wave_start = 0;
        while wave_start < tasks.len() {
            let wave_size = worker_count.min(tasks.len() - wave_start);
            for (worker_index, sender) in task_senders.iter().take(wave_size).enumerate() {
                let task_index = wave_start + worker_index;
                if sender.send(Some(task_index)).is_err() {
                    outcome = Err(eyre::eyre!(
                        "Soracloud artifact hydration worker {worker_index} terminated before accepting task {task_index}"
                    ));
                    break;
                }
            }
            if outcome.is_err() {
                break;
            }

            let mut wave_error = None;
            for (worker_index, receiver) in result_receivers.iter().take(wave_size).enumerate() {
                let expected_task_index = wave_start + worker_index;
                match receiver.recv() {
                    Ok((task_index, result)) => {
                        if task_index != expected_task_index && wave_error.is_none() {
                            wave_error = Some(eyre::eyre!(
                                "Soracloud artifact hydration worker {worker_index} returned task {task_index}, expected {expected_task_index}"
                            ));
                        }
                        if let Err(error) = result
                            && wave_error.is_none()
                        {
                            wave_error = Some(error);
                        }
                    }
                    Err(_) if wave_error.is_none() => {
                        wave_error = Some(eyre::eyre!(
                            "Soracloud artifact hydration worker {worker_index} panicked while running task {expected_task_index}"
                        ));
                    }
                    Err(_) => {}
                }
            }
            if let Some(error) = wave_error {
                outcome = Err(error);
                break;
            }
            wave_start += wave_size;
        }

        for sender in &task_senders {
            let _ = sender.send(None);
        }
        let mut worker_panicked = false;
        for worker in workers {
            worker_panicked |= worker.join().is_err();
        }
        if outcome.is_ok() && worker_panicked {
            return Err(eyre::eyre!("Soracloud artifact hydration worker panicked"));
        }
        outcome
    })
}
const SORAFS_REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1: usize = 256 * 1024;
const SORAFS_REPLICATION_ORDER_DECODE_LIMITS_V1: norito::DecodeLimits = norito::DecodeLimits::new(
    sorafs_manifest::capacity::MAX_CAPACITY_METADATA_VALUE_BYTES,
    SORAFS_REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1,
    131_072,
    SORAFS_REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1 * 4,
    32,
);
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationPlan {
    manifest_id_hex: String,
    chunker_handle: String,
    content_length: u64,
    payload_digest: [u8; 32],
    chunks: Vec<RemoteHydrationChunk>,
    files: Vec<RemoteHydrationFile>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationChunk {
    index: usize,
    offset: u64,
    length: u32,
    digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationFile {
    path: Vec<String>,
    offset: u64,
    size: u64,
    first_chunk: usize,
    chunk_count: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteHydrationPlanPage {
    chunker_handle: String,
    content_length: u64,
    payload_digest: [u8; 32],
    chunk_count: usize,
    file_count: usize,
    offset: usize,
    limit: usize,
    truncated_chunks: bool,
    truncated_files: bool,
    chunks: Vec<RemoteHydrationChunk>,
    files: Vec<RemoteHydrationFile>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedRemoteManifest {
    manifest: sorafs_manifest::ManifestV1,
    manifest_id_hex: String,
    manifest_digest: [u8; 32],
    payload_digest: [u8; 32],
    chunk_count: usize,
    chunker_handle: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SorafsHydratedFileLayout {
    path: Vec<String>,
    offset: u64,
    size: u64,
}
fn stable_inrou_runtime_state_submission_view(
    state: &SoraInrouReplicaRuntimeStateV1,
) -> SoraInrouReplicaRuntimeStateV1 {
    let mut stable_state = state.clone();
    stable_state.updated_at_ms = 0;
    stable_state
}
fn inrou_runtime_state_submission_commitment(state: &SoraInrouReplicaRuntimeStateV1) -> Hash {
    Hash::new(Encode::encode(&stable_inrou_runtime_state_submission_view(
        state,
    )))
}
fn inrou_runtime_state_matches_authoritative_snapshot(
    authoritative: &SoraInrouReplicaRuntimeStateV1,
    desired: &SoraInrouReplicaRuntimeStateV1,
) -> bool {
    stable_inrou_runtime_state_submission_view(authoritative)
        == stable_inrou_runtime_state_submission_view(desired)
}
fn write_verified_sorafs_manifest_payload_to_cache(
    manifest: &StoredManifest,
    expected_hash: Hash,
    cache_path: &Path,
    maximum_bytes: u64,
    mut read_payload_range: impl FnMut(&str, u64, usize) -> Result<Vec<u8>, String>,
) -> io::Result<()> {
    let content_length = manifest.content_length();
    let manifest_id = manifest.manifest_id();
    let expected_payload_digest = *manifest.payload_digest();
    write_atomic_file(cache_path, |file| {
        let mut payload_hasher = blake3::Hasher::new();
        let mut cursor = 0_u64;
        while cursor < content_length {
            let remaining = content_length - cursor;
            let read_len =
                usize::try_from(remaining.min(SORACLOUD_LOCAL_HYDRATION_STREAM_CHUNK_BYTES))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "local SoraFS hydration chunk length does not fit this host",
                        )
                    })?;
            let chunk = read_payload_range(manifest_id, cursor, read_len).map_err(|error| {
                io::Error::other(format!(
                    "read local SoraFS hydration chunk at {cursor}: {error}"
                ))
            })?;
            if chunk.len() != read_len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "local SoraFS hydration chunk was truncated",
                ));
            }
            payload_hasher.update(&chunk);
            file.write_all(&chunk)?;
            cursor = cursor
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "local SoraFS hydration byte count does not fit u64",
                    )
                })?)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "local SoraFS hydration byte count overflow",
                    )
                })?;
        }
        if payload_hasher.finalize().as_bytes() != &expected_payload_digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local SoraFS hydration payload digest mismatch",
            ));
        }
        file.rewind()?;
        let (actual_hash, hashed_bytes) = Hash::new_from_reader_bounded(&mut *file, maximum_bytes)?;
        if hashed_bytes != content_length || actual_hash != expected_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local SoraFS hydration artifact hash mismatch",
            ));
        }
        Ok(((), content_length))
    })
}
impl SoracloudRuntimeManager {
    /// Construct the runtime manager for the supplied node state.
    #[must_use]
    pub fn new(config: SoracloudRuntimeManagerConfig, state: Arc<State>) -> Self {
        Self {
            config,
            state,
            snapshot: Arc::new(RwLock::new(SoracloudRuntimeSnapshot::default())),
            hosted_http_workers: Arc::new(Mutex::new(BTreeMap::new())),
            mutation_sink: None,
            last_inrou_host_advert_attempt_ms: Mutex::new(None),
            pending_inrou_host_capability_advert: Mutex::new(None),
            inrou_startup_capability: None,
            inrou_startup_qualified_config: None,
            last_inrou_host_withdraw_attempt_ms: Mutex::new(None),
            last_inrou_placement_reconcile_attempt_ms: Mutex::new(None),
            last_runtime_state_submission_commitments: Mutex::new(BTreeMap::new()),
            last_service_lease_usage_submission_bytes: Mutex::new(BTreeMap::new()),
            inrou_revision_egress_accounting: Mutex::new(BTreeMap::new()),
            inrou_replica_egress_accounting: Mutex::new(BTreeMap::new()),
            sorafs_node: None,
            operator_preseed_store: None,
            sorafs_provider_cache: None,
            remote_stream_token_operator: None,
            remote_hydration_provider_gates: Mutex::new(BTreeMap::new()),
        }
    }
    fn qualify_inrou_startup_capability(&mut self) -> eyre::Result<()> {
        if let Some(qualified) = self.inrou_startup_qualified_config.as_ref() {
            if qualified != &self.config {
                eyre::bail!("Soracloud configuration changed after startup qualification");
            }
            return Ok(());
        }
        self.inrou_startup_capability = InrouStartupCapabilitySnapshot::qualify(&self.config)?;
        self.inrou_startup_qualified_config = Some(self.config.clone());
        Ok(())
    }
    /// Exercise mandatory host prerequisites before consensus can emit durable work.
    /// The same manager carries the exact configuration and qualification into start.
    pub(crate) fn preflight_startup(mut self) -> eyre::Result<Self> {
        self.qualify_inrou_startup_capability()?;
        Ok(self)
    }
    /// Attach the authoritative mutation sink used for runtime-originated Soracloud health reports.
    #[must_use]
    pub(crate) fn with_mutation_sink(
        mut self,
        mutation_sink: Arc<dyn SoracloudRuntimeMutationSink>,
    ) -> Self {
        self.mutation_sink = Some(mutation_sink);
        self
    }
    /// Attach the embedded SoraFS storage handle used for authoritative hydration.
    #[must_use]
    pub fn with_sorafs_node(mut self, sorafs_node: sorafs_node::NodeHandle) -> Self {
        self.sorafs_node = Some(sorafs_node);
        self
    }
    /// Attach the deployment-owned, read-only hydration view over an operator-preseeded store.
    ///
    /// This store is intentionally separate from the embedded provider node: it exposes no
    /// routes or workers and is admitted only while provider storage is disabled. The manifest
    /// allowlist must be the exact result of durable current-peer/current-capacity receipt
    /// validation.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized allowlist, a missing manifest, or an empty qualified payload.
    pub(crate) fn with_operator_preseed_store(
        mut self,
        store: Arc<StorageBackend>,
        qualified_manifest_digests: BTreeSet<[u8; 32]>,
    ) -> eyre::Result<Self> {
        self.operator_preseed_store = Some(QualifiedOperatorPreseedStore::from_validated_digests(
            store,
            qualified_manifest_digests,
        )?);
        Ok(self)
    }
    /// Attach the shared SoraFS provider-discovery cache used for remote hydration.
    #[must_use]
    pub fn with_sorafs_provider_cache(
        mut self,
        sorafs_provider_cache: Arc<AsyncRwLock<ProviderAdvertCache>>,
    ) -> Self {
        self.sorafs_provider_cache = Some(sorafs_provider_cache);
        self
    }
    /// Start the background reconciliation loop.
    ///
    /// # Errors
    ///
    /// Returns an error before producing a runtime handle or background child
    /// when a production signer boundary is absent or no longer qualified, an
    /// enabled remote-hydration cache lacks an exact-network operator identity,
    /// persisted state cannot be restored, or initial reconciliation fails.
    pub fn start(
        mut self,
        shutdown_signal: ShutdownSignal,
    ) -> eyre::Result<(SoracloudRuntimeManagerHandle, Child)> {
        validate_soracloud_runtime_manager_posture(&self.config)
            .wrap_err("validate Soracloud runtime-manager PortableVM V1 posture")?;
        validate_operator_preseed_provider_boundary(
            self.config.inrou.enabled,
            self.operator_preseed_store.is_some(),
            self.sorafs_node
                .as_ref()
                .is_some_and(sorafs_node::NodeHandle::is_enabled),
        )?;
        self.ensure_trusted_inrou_guest_artifact_preseeded()
            .wrap_err("verify the exact operator-approved Inrou guest artifact preseed")?;
        self.qualify_inrou_startup_capability()
            .wrap_err("qualify the immutable Inrou PortableVM V1 startup capability")?;
        remote_stream_token_auth::ensure_startup_binding(
            self.remote_stream_token_operator.as_ref(),
            self.state.network_id_ref(),
            self.sorafs_provider_cache.is_some(),
        )?;
        if self.config.production_mode {
            self.mutation_sink
                .as_ref()
                .ok_or_else(|| {
                    eyre::eyre!(
                        "production Soracloud runtime manager requires a qualified mutation sink"
                    )
                })?
                .ensure_production_qualified()
                .wrap_err("revalidate production Soracloud runtime mutation sink")?;
        }
        let manager = Arc::new(self);
        manager.initialize_for_startup()?;
        let handle = SoracloudRuntimeManagerHandle {
            snapshot: Arc::clone(&manager.snapshot),
            config: Arc::new(manager.config.clone()),
            state_dir: Arc::new(manager.config.state_dir.clone()),
            state: Arc::clone(&manager.state),
            ivm_runtime_cache: Arc::new(SoracloudPreparedRuntimeCache::from_config(
                &manager.config,
            )),
        };
        let task = Arc::clone(&manager).spawn_reconcile_task(shutdown_signal);
        Ok((
            handle,
            Child::new(task, OnShutdown::Wait(Duration::from_secs(1))),
        ))
    }
    fn initialize_for_startup(self: &Arc<Self>) -> eyre::Result<()> {
        self.restore_persisted_snapshot().wrap_err_with(|| {
            format!(
                "restore persisted Soracloud runtime-manager snapshot from {}",
                self.config.state_dir.display()
            )
        })?;
        Arc::clone(self).run_startup_reconcile().wrap_err_with(|| {
            format!(
                "complete initial Soracloud runtime-manager reconciliation under {}",
                self.config.state_dir.display()
            )
        })
    }
    fn run_startup_reconcile(self: Arc<Self>) -> eyre::Result<()> {
        let manager = Arc::clone(&self);
        let thread = crate::panic_recovery::spawn_thread_recoverable(
            std::thread::Builder::new().name("soracloud-runtime-startup-reconcile".to_owned()),
            move || manager.reconcile_once(),
        )
        .wrap_err("spawn Soracloud startup reconcile thread")?;
        match crate::panic_recovery::join_thread_recoverable(thread) {
            Ok(result) => result,
            Err(_panic) => {
                self.quarantine_local_inrou_runtime();
                Err(eyre::eyre!("Soracloud startup reconcile thread panicked"))
            }
        }
    }
    fn spawn_reconcile_task(self: Arc<Self>, shutdown_signal: ShutdownSignal) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(self.config.reconcile_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let manager = Arc::clone(&self);
                        match crate::panic_recovery::join_recoverable(
                            crate::panic_recovery::spawn_blocking_recoverable(move || {
                                manager.reconcile_once()
                            }),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                iroha_logger::warn!(
                                    ?error,
                                    state_dir = %self.config.state_dir.display(),
                                    "Soracloud runtime-manager reconciliation failed"
                                );
                            }
                            Err(_panic) => {
                                self.quarantine_local_inrou_runtime();
                                iroha_logger::warn!(
                                    state_dir = %self.config.state_dir.display(),
                                    "Soracloud runtime-manager reconciliation task panicked"
                                );
                            }
                        }
                    }
                    () = shutdown_signal.receive() => {
                        iroha_logger::debug!("Soracloud runtime manager is being shut down.");
                        break;
                    }
                    else => break,
                }
            }
        })
    }
    /// Reconcile the node-local materialization plan against authoritative state once.
    pub(crate) fn reconcile_once(&self) -> eyre::Result<()> {
        let result = self.reconcile_once_inner();
        if result.is_err() {
            self.quarantine_local_inrou_runtime();
        }
        result
    }
    fn quarantine_local_inrou_runtime(&self) {
        let workers = {
            let mut workers = self.hosted_http_workers.lock();
            std::mem::take(&mut *workers)
        };
        for worker in workers.into_values() {
            worker.lock().stop();
        }
        let scrubbed_snapshot = {
            let mut snapshot = self.snapshot.write();
            strip_inrou_runtime_plans(&mut snapshot).then(|| snapshot.clone())
        };
        if let Some(snapshot) = scrubbed_snapshot
            && let Err(error) = write_json_atomic_bounded(
                &self.runtime_snapshot_path(),
                &snapshot,
                SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
                "Soracloud runtime snapshot",
            )
        {
            iroha_logger::warn!(
                ?error,
                state_dir = %self.config.state_dir.display(),
                "failed to durably scrub quarantined Inrou plans from the runtime snapshot"
            );
        }
    }
    fn reconcile_once_inner(&self) -> eyre::Result<()> {
        validate_soracloud_runtime_manager_posture(&self.config)
            .wrap_err("validate Soracloud runtime-manager PortableVM V1 posture")?;
        fs::create_dir_all(self.services_root())
            .wrap_err_with(|| format!("create {}", self.services_root().display()))?;
        fs::create_dir_all(self.apartments_root())
            .wrap_err_with(|| format!("create {}", self.apartments_root().display()))?;
        fs::create_dir_all(self.artifacts_root())
            .wrap_err_with(|| format!("create {}", self.artifacts_root().display()))?;
        fs::create_dir_all(self.journals_root())
            .wrap_err_with(|| format!("create {}", self.journals_root().display()))?;
        fs::create_dir_all(self.checkpoints_root())
            .wrap_err_with(|| format!("create {}", self.checkpoints_root().display()))?;
        fs::create_dir_all(self.credentials_root())
            .wrap_err_with(|| format!("create {}", self.credentials_root().display()))?;
        fs::create_dir_all(self.service_data_root())
            .wrap_err_with(|| format!("create {}", self.service_data_root().display()))?;
        let inrou_hosting_available = self.inrou_startup_capability.is_some()
            && match ensure_inrou_portable_vm_statically_available(&self.config.inrou) {
                Ok(()) => self.config.inrou.enabled,
                Err(error) => {
                    iroha_logger::warn!(
                        ?error,
                        "Inrou PortableVM V1 is unavailable; withdrawing host and stopping local replicas"
                    );
                    false
                }
            };
        if !inrou_hosting_available {
            let view = self.state.view();
            self.withdraw_local_inrou_host_if_needed(&view);
        }
        let (
            bundle_registry,
            initial_snapshot,
            inrou_host_capability_refresh,
            inrou_placement_reconcile_needed,
        ) = {
            let view = self.state.view();
            let bundle_registry = collect_service_revision_registry(&view);
            let inrou_host_capability_refresh = inrou_hosting_available
                .then(|| self.local_inrou_host_capability_refresh_candidate(&view))
                .flatten();
            let inrou_placement_reconcile_needed = self
                .inrou_placement_reconcile_needed(&view, &bundle_registry)
                .wrap_err("calculate whether Inrou placement reconciliation is needed")?;
            let initial_snapshot = build_runtime_snapshot(
                &view,
                &bundle_registry,
                &self.config.state_dir,
                self.artifacts_root(),
                &self.config.cache_budgets,
                self.config.local_validator_account_id.as_ref(),
                self.config.local_peer_id.as_deref(),
                inrou_hosting_available,
            )?;
            (
                bundle_registry,
                initial_snapshot,
                inrou_host_capability_refresh,
                inrou_placement_reconcile_needed,
            )
        };
        self.refresh_local_inrou_host_capability_if_needed(inrou_host_capability_refresh);
        self.request_inrou_placement_reconcile_if_needed(inrou_placement_reconcile_needed);
        {
            let view = self.state.view();
            self.write_service_materializations(&initial_snapshot, &bundle_registry, &view)?;
            self.write_apartment_materializations(&initial_snapshot, &view)?;
        }
        self.prune_stale_service_materializations(&initial_snapshot)?;
        self.prune_stale_apartment_materializations(&initial_snapshot)?;
        {
            let view = self.state.view();
            self.hydrate_missing_artifacts(&view, &initial_snapshot)?;
        }
        {
            let view = self.state.view();
            self.reconcile_inrou_egress_checkpoint_files(&view)
                .wrap_err("reconcile durable Inrou egress checkpoint files")?;
            self.reconcile_hosted_http_workers(&view, &initial_snapshot)?;
        }
        {
            let view = self.state.view();
            self.enforce_cache_budgets(&view, &initial_snapshot)?;
        }
        let snapshot = {
            let view = self.state.view();
            build_runtime_snapshot(
                &view,
                &bundle_registry,
                &self.config.state_dir,
                self.artifacts_root(),
                &self.config.cache_budgets,
                self.config.local_validator_account_id.as_ref(),
                self.config.local_peer_id.as_deref(),
                inrou_hosting_available,
            )?
        };
        {
            let view = self.state.view();
            self.submit_http_service_runtime_state_updates(&view, &snapshot)?;
        }
        write_json_atomic_bounded(
            &self.config.state_dir.join("runtime_snapshot.json"),
            &snapshot,
            SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
            "Soracloud runtime snapshot",
        )?;
        *self.snapshot.write() = snapshot;
        Ok(())
    }
    fn submit_http_service_runtime_state_updates(
        &self,
        view: &StateView<'_>,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let inrou_plans = collect_authoritative_single_revision_inrou_runtime_plans(
            view,
            snapshot,
            self.config.local_validator_account_id.as_ref(),
            self.config.local_peer_id.as_deref(),
        )?;
        let Some(mutation_sink) = self.mutation_sink.as_ref() else {
            return Ok(());
        };
        let desired_keys = inrou_plans
            .iter()
            .flat_map(|(service_name, service_version, plan)| {
                plan.local_replicas.iter().map(|replica| {
                    (
                        (*service_name).clone(),
                        (*service_version).clone(),
                        replica.replica_slot,
                        replica.placement_incarnation.clone(),
                    )
                })
            })
            .collect::<BTreeSet<_>>();
        let clearable_keys = match (
            self.config.local_validator_account_id.as_ref(),
            self.config.local_peer_id.as_deref(),
        ) {
            (Some(local_validator_account_id), Some(local_peer_id)) => view
                .world()
                .soracloud_inrou_replica_runtime()
                .iter()
                .filter_map(|((service_name, service_version, replica_slot), state)| {
                    if &state.validator_account_id != local_validator_account_id
                        || state.peer_id != local_peer_id
                    {
                        return None;
                    }
                    let replica_slot = replica_slot.parse::<u16>().ok()?;
                    let key = (
                        service_name.clone(),
                        service_version.clone(),
                        replica_slot,
                        state.placement_incarnation.to_string(),
                    );
                    (!desired_keys.contains(&key)).then_some(key)
                })
                .collect::<BTreeSet<_>>(),
            _ => BTreeSet::new(),
        };
        self.last_runtime_state_submission_commitments
            .lock()
            .retain(|key, _commitment| desired_keys.contains(key));
        for (service_name, service_version, replica_slot, placement_incarnation) in clearable_keys {
            let service_name_id = match Name::from_str(&service_name) {
                Ok(name) => name,
                Err(error) => {
                    iroha_logger::warn!(
                        ?error,
                        service_name = %service_name,
                        service_version = %service_version,
                        replica_slot,
                        "failed to parse Soracloud service name while clearing authoritative Inrou replica runtime state"
                    );
                    continue;
                }
            };
            let expected_placement_incarnation = match Hash::from_str(&placement_incarnation) {
                Ok(incarnation) => incarnation,
                Err(error) => {
                    iroha_logger::warn!(
                        ?error,
                        service_name = %service_name,
                        service_version = %service_version,
                        replica_slot,
                        "failed to parse the persisted Inrou runtime placement incarnation"
                    );
                    continue;
                }
            };
            let instruction =
                InstructionBox::from(isi::soracloud::ClearSoracloudInrouReplicaRuntimeState {
                    service_name: service_name_id,
                    service_version: service_version.clone(),
                    replica_slot,
                    expected_placement_incarnation,
                });
            if let Err(error) = mutation_sink.submit_instruction(
                instruction,
                "/internal/soracloud/runtime/inrou-replica-runtime-state-clear",
            ) {
                iroha_logger::warn!(
                    ?error,
                    service_name = %service_name,
                    service_version = %service_version,
                    replica_slot,
                    "failed to clear authoritative Inrou replica runtime state from embedded runtime manager"
                );
                continue;
            }
        }
        for (service_name, service_version, plan) in inrou_plans {
            if plan.local_replicas.is_empty() {
                continue;
            }
            let Some(bundle) = view
                .world()
                .soracloud_service_revisions()
                .get(&(service_name.clone(), service_version.clone()))
            else {
                continue;
            };
            let service_name_id = match Name::from_str(service_name) {
                Ok(name) => name,
                Err(error) => {
                    iroha_logger::warn!(
                        ?error,
                        service_name = %service_name,
                        service_version = %service_version,
                        "failed to parse Soracloud service name while submitting authoritative Inrou replica runtime state"
                    );
                    continue;
                }
            };
            let Some((lease_started_height, reporting_epoch)) =
                self.authoritative_service_lease_identity(view, service_name)
            else {
                continue;
            };
            for replica in &plan.local_replicas {
                let Some(assignment) = view
                    .world()
                    .soracloud_inrou_service_placements()
                    .get(&(service_name.clone(), service_version.clone()))
                    .and_then(|record| {
                        record
                            .placements
                            .iter()
                            .find(|placement| placement.replica_slot == replica.replica_slot)
                    })
                else {
                    continue;
                };
                if !assignment.host_availability.is_available()
                    || assignment.lease_started_height != lease_started_height
                    || replica.placement_incarnation != assignment.placement_incarnation.to_string()
                    || replica.lease_started_height != assignment.lease_started_height
                    || self.config.local_validator_account_id.as_ref()
                        != Some(&assignment.validator_account_id)
                    || self.config.local_peer_id.as_deref() != Some(assignment.peer_id.as_str())
                {
                    continue;
                }
                let Some(reporter_target_epoch) = self
                    .authoritative_service_lease_reporter_target_epoch(
                        view,
                        service_name,
                        lease_started_height,
                        service_version,
                        replica.replica_slot,
                        assignment.placement_incarnation,
                    )
                else {
                    continue;
                };
                let authoritative_state = view.world().soracloud_inrou_replica_runtime().get(&(
                    service_name.clone(),
                    service_version.clone(),
                    replica.replica_slot.to_string(),
                ));
                let reporter_accounted_egress_bytes = if reporter_target_epoch == reporting_epoch {
                    self.inrou_replica_egress_accounting
                        .lock()
                        .get(&(
                            service_name.clone(),
                            service_version.clone(),
                            lease_started_height,
                            reporter_target_epoch,
                            replica.replica_slot,
                            replica.placement_incarnation.clone(),
                        ))
                        .map_or_else(
                            || {
                                self.authoritative_service_lease_reporter_checkpoint(
                                    view,
                                    service_name,
                                    lease_started_height,
                                    reporter_target_epoch,
                                    service_version,
                                    replica.replica_slot,
                                    assignment.placement_incarnation,
                                )
                                .map_or(0, |checkpoint| checkpoint.accounted_egress_bytes)
                            },
                            PortableVmEgressAccounting::accounted_egress_bytes,
                        )
                } else {
                    0
                };
                let desired_state = SoraInrouReplicaRuntimeStateV1 {
                    schema_version: SORA_INROU_REPLICA_RUNTIME_STATE_VERSION_V1,
                    service_name: service_name_id.clone(),
                    service_version: service_version.clone(),
                    replica_slot: replica.replica_slot,
                    placement_incarnation: assignment.placement_incarnation,
                    validator_account_id: assignment.validator_account_id.clone(),
                    peer_id: assignment.peer_id.clone(),
                    selected_guest_isa: assignment.selected_guest_isa,
                    health_status: replica.health_status,
                    load_factor_bps: plan.load_factor_bps,
                    materialized_bundle_hash: bundle.container.bundle_hash,
                    reporting_epoch,
                    accounted_egress_bytes: reporter_accounted_egress_bytes,
                    updated_at_ms: soracloud_runtime_observed_at_ms(),
                    last_error: replica.last_error.clone(),
                };
                if authoritative_state.is_some_and(|state| {
                    inrou_runtime_state_matches_authoritative_snapshot(state, &desired_state)
                }) {
                    self.last_runtime_state_submission_commitments
                        .lock()
                        .remove(&(
                            service_name.clone(),
                            service_version.clone(),
                            replica.replica_slot,
                            replica.placement_incarnation.clone(),
                        ));
                    continue;
                }
                let commitment = inrou_runtime_state_submission_commitment(&desired_state);
                let attempted_at_ms = desired_state.updated_at_ms;
                let key = (
                    service_name.clone(),
                    service_version.clone(),
                    replica.replica_slot,
                    replica.placement_incarnation.clone(),
                );
                if self
                    .last_runtime_state_submission_commitments
                    .lock()
                    .get(&key)
                    .is_some_and(|previous| {
                        previous.commitment == commitment
                            && attempted_at_ms >= previous.attempted_at_ms
                            && attempted_at_ms - previous.attempted_at_ms
                                < SORACLOUD_INROU_RUNTIME_STATE_RETRY_MS
                    })
                {
                    continue;
                }
                let instruction =
                    InstructionBox::from(isi::soracloud::SetSoracloudInrouReplicaRuntimeState {
                        state: desired_state,
                    });
                if let Err(error) = mutation_sink.submit_instruction(
                    instruction,
                    "/internal/soracloud/runtime/inrou-replica-runtime-state",
                ) {
                    iroha_logger::warn!(
                        ?error,
                        service_name = %service_name,
                        service_version = %service_version,
                        replica_slot = replica.replica_slot,
                        "failed to submit authoritative Inrou replica runtime state update from embedded runtime manager"
                    );
                    continue;
                }
                self.last_runtime_state_submission_commitments
                    .lock()
                    .insert(
                        key,
                        HostedHttpRuntimeStateSubmissionAttempt {
                            commitment,
                            attempted_at_ms,
                        },
                    );
            }
        }
        Ok(())
    }
    fn authoritative_service_reporting_epoch_egress_bytes(
        &self,
        view: &StateView<'_>,
        service_name: &str,
        service_version: &str,
        lease_started_height: u64,
        reporting_epoch: u64,
    ) -> eyre::Result<u64> {
        let service_name_id = Name::from_str(service_name).wrap_err_with(|| {
            format!("parse authoritative Soracloud service name `{service_name}`")
        })?;
        let deployment = view
            .world()
            .soracloud_service_deployments()
            .get(&service_name_id)
            .ok_or_else(|| {
                eyre::eyre!(
                    "service `{service_name}` revision `{service_version}` has no authoritative deployment"
                )
            })?;
        if deployment.active_rollout.is_some() {
            eyre::bail!(
                "service `{service_name}` carries an unsupported active Inrou canary; first-release host-local lease disks require one active revision"
            );
        }
        let lease = deployment
            .service_lease
            .as_ref()
            .filter(|_| deployment.current_service_version == service_version)
            .filter(|lease| {
                lease.lease_started_height == lease_started_height
                    && lease.reporting_epoch == reporting_epoch
            })
            .ok_or_else(|| {
                eyre::eyre!(
                    "service `{service_name}` revision `{service_version}` has no authoritative lease egress for reporting epoch `{reporting_epoch}`"
                )
            })?;
        // Reporter checkpoints remain authoritative after placement retirement
        // until reporting-epoch rollover settles and clears them. Seed the
        // shared revision/epoch counter from every same-revision checkpoint,
        // not only identities still present in the current placement record.
        lease
            .egress_reporter_checkpoints
            .iter()
            .filter(|checkpoint| {
                checkpoint.reporting_epoch == reporting_epoch
                    && checkpoint.assignment.placement.lease_started_height
                        == lease_started_height
                    && checkpoint.assignment.service_version == service_version
            })
            .try_fold(0_u64, |total, checkpoint| {
                total.checked_add(checkpoint.accounted_egress_bytes)
            })
            .ok_or_else(|| {
                eyre::eyre!(
                    "service `{service_name}` revision `{service_version}` reporting epoch `{reporting_epoch}` exceeds the local u64 revision counter"
                )
            })
    }
    fn authoritative_service_lease_identity(
        &self,
        view: &StateView<'_>,
        service_name: &str,
    ) -> Option<(u64, u64)> {
        let service_name = Name::from_str(service_name).ok()?;
        view.world()
            .soracloud_service_deployments()
            .get(&service_name)
            .and_then(|deployment| deployment.service_lease.as_ref())
            .map(|lease| (lease.lease_started_height, lease.reporting_epoch))
    }
    fn authoritative_service_lease_reporter_target_epoch(
        &self,
        view: &StateView<'_>,
        service_name: &str,
        lease_started_height: u64,
        service_version: &str,
        replica_slot: u16,
        placement_incarnation: Hash,
    ) -> Option<u64> {
        let validator_account_id = self.config.local_validator_account_id.as_ref()?;
        let service_name = Name::from_str(service_name).ok()?;
        let lease = view
            .world()
            .soracloud_service_deployments()
            .get(&service_name)
            .and_then(|deployment| deployment.service_lease.as_ref())
            .filter(|lease| lease.lease_started_height == lease_started_height)?;
        let current_identity_is_admitted =
            lease.egress_reporter_checkpoints.iter().any(|checkpoint| {
                checkpoint.reporting_epoch == lease.reporting_epoch
                    && checkpoint.assignment.placement.lease_started_height == lease_started_height
                    && checkpoint.assignment.service_version == service_version
                    && checkpoint.assignment.placement.replica_slot == replica_slot
                    && checkpoint.assignment.placement.placement_incarnation
                        == placement_incarnation
                    && checkpoint.assignment.placement.validator_account_id == *validator_account_id
            });
        if current_identity_is_admitted
            || lease.egress_reporter_checkpoints.len()
                != SORA_SERVICE_LEASE_MAX_EGRESS_REPORTER_CHECKPOINTS_V1
        {
            Some(lease.reporting_epoch)
        } else {
            lease.reporting_epoch.checked_add(1)
        }
    }
    fn authoritative_service_lease_reporter_checkpoint(
        &self,
        view: &StateView<'_>,
        service_name: &str,
        lease_started_height: u64,
        reporting_epoch: u64,
        service_version: &str,
        replica_slot: u16,
        placement_incarnation: Hash,
    ) -> Option<HostedHttpReporterCheckpointState> {
        let validator_account_id = self.config.local_validator_account_id.as_ref()?;
        let service_name = Name::from_str(service_name).ok()?;
        view.world()
            .soracloud_service_deployments()
            .get(&service_name)
            .and_then(|deployment| deployment.service_lease.as_ref())
            .filter(|lease| {
                lease.lease_started_height == lease_started_height
                    && lease.reporting_epoch == reporting_epoch
            })
            .and_then(|lease| {
                lease.egress_reporter_checkpoints.iter().find(|checkpoint| {
                    checkpoint.reporting_epoch == reporting_epoch
                        && checkpoint.assignment.placement.lease_started_height
                            == lease_started_height
                        && checkpoint.assignment.service_version == service_version
                        && checkpoint.assignment.placement.replica_slot == replica_slot
                        && checkpoint.assignment.placement.placement_incarnation
                            == placement_incarnation
                        && checkpoint.assignment.placement.validator_account_id
                            == *validator_account_id
                })
            })
            .map(|checkpoint| HostedHttpReporterCheckpointState {
                lease_started_height: checkpoint.assignment.placement.lease_started_height,
                reporting_epoch: checkpoint.reporting_epoch,
                accounted_egress_bytes: checkpoint.accounted_egress_bytes,
                finalize_reporter: checkpoint.finalize_reporter,
            })
    }
    fn reconcile_inrou_egress_checkpoint_files(&self, view: &StateView<'_>) -> io::Result<()> {
        let mut retained_digests = BTreeSet::new();
        for (service_name, deployment) in view.world().soracloud_service_deployments().iter() {
            let current_revision_key = (
                service_name.to_string(),
                deployment.current_service_version.clone(),
            );
            let current_revision_is_inrou = view
                .world()
                .soracloud_service_revisions()
                .get(&current_revision_key)
                .is_some_and(|bundle| bundle.container.runtime == SoraContainerRuntimeV1::Inrou);
            if current_revision_is_inrou && deployment.active_rollout.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "service `{service_name}` carries an unsupported active Inrou canary; first-release host-local lease disks require one active revision"
                    ),
                ));
            }
            let Some(lease) = deployment.service_lease.as_ref() else {
                continue;
            };
            for checkpoint in &lease.egress_reporter_checkpoints {
                if checkpoint.reporting_epoch != lease.reporting_epoch
                    || checkpoint.assignment.placement.lease_started_height
                        != lease.lease_started_height
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "service `{service_name}` contains an Inrou reporter checkpoint from another lease incarnation or reporting epoch"
                        ),
                    ));
                }
                if checkpoint.assignment.service_version != deployment.current_service_version {
                    continue;
                }
                retained_digests.insert(inrou_egress_reporter_key_digest(
                    service_name.as_ref(),
                    lease.lease_started_height,
                    checkpoint.reporting_epoch,
                    &checkpoint.assignment.service_version,
                    checkpoint.assignment.placement.replica_slot,
                    &checkpoint.assignment.placement.placement_incarnation,
                    &checkpoint.assignment.placement.validator_account_id,
                )?);
            }
        }
        // A crash may occur after the durable counter is precharged but before
        // the reporter's initial/open checkpoint reaches WSV. Retain every
        // exact placement assigned to this host so GC cannot erase the only
        // crash-recovery floor before worker reconciliation loads it.
        if let (Some(validator_account_id), Some(local_peer_id)) = (
            self.config.local_validator_account_id.as_ref(),
            self.config.local_peer_id.as_deref(),
        ) {
            for ((service_name, service_version), record) in
                view.world().soracloud_inrou_service_placements().iter()
            {
                let Some(deployment) = Name::from_str(service_name)
                    .ok()
                    .and_then(|name| view.world().soracloud_service_deployments().get(&name))
                else {
                    continue;
                };
                if deployment.active_rollout.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "service `{service_name}` carries an unsupported active Inrou canary; first-release host-local lease disks require one active revision"
                        ),
                    ));
                }
                if deployment.current_service_version != *service_version {
                    continue;
                }
                let Some(lease_started_height) = deployment
                    .service_lease
                    .as_ref()
                    .map(|lease| lease.lease_started_height)
                else {
                    continue;
                };
                for placement in record.placements.iter().filter(|placement| {
                    placement.lease_started_height == lease_started_height
                        && &placement.validator_account_id == validator_account_id
                        && placement.peer_id == local_peer_id
                }) {
                    let Some(reporting_epoch) = self
                        .authoritative_service_lease_reporter_target_epoch(
                            view,
                            service_name,
                            lease_started_height,
                            service_version,
                            placement.replica_slot,
                            placement.placement_incarnation,
                        )
                    else {
                        continue;
                    };
                    retained_digests.insert(inrou_egress_reporter_key_digest(
                        service_name,
                        lease_started_height,
                        reporting_epoch,
                        service_version,
                        placement.replica_slot,
                        &placement.placement_incarnation,
                        validator_account_id,
                    )?);
                }
            }
        }
        let mut retained_local_keys = self
            .inrou_replica_egress_accounting
            .lock()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        retained_local_keys.extend(self.hosted_http_workers.lock().keys().cloned());
        if !retained_local_keys.is_empty() {
            let validator_account_id =
                self.config
                    .local_validator_account_id
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "local Inrou accounting exists without a validator reporter identity",
                        )
                    })?;
            for (
                service_name,
                service_version,
                lease_started_height,
                reporting_epoch,
                replica_slot,
                placement_incarnation,
            ) in retained_local_keys
            {
                let placement_incarnation =
                    Hash::from_str(&placement_incarnation).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid local Inrou placement incarnation: {error}"),
                        )
                    })?;
                retained_digests.insert(inrou_egress_reporter_key_digest(
                    &service_name,
                    lease_started_height,
                    reporting_epoch,
                    &service_version,
                    replica_slot,
                    &placement_incarnation,
                    validator_account_id,
                )?);
            }
        }
        reconcile_inrou_egress_checkpoint_directory(
            &self.config.state_dir,
            &retained_digests,
            SORACLOUD_INROU_EGRESS_CHECKPOINT_MAX_FILES_V1,
        )?;
        Ok(())
    }
    fn submit_http_service_lease_usage_update(
        &self,
        view: &StateView<'_>,
        service_name: &str,
        lease_started_height: u64,
        reporting_epoch: u64,
        service_version: &str,
        replica_slot: u16,
        placement_incarnation: Hash,
        replica_accounted_egress_bytes: u64,
        finalize_reporter: bool,
    ) {
        let Some(mutation_sink) = self.mutation_sink.as_ref() else {
            return;
        };
        let key = (
            service_name.to_owned(),
            service_version.to_owned(),
            lease_started_height,
            reporting_epoch,
            replica_slot,
            placement_incarnation.to_string(),
        );
        let authoritative_checkpoint = self.authoritative_service_lease_reporter_checkpoint(
            view,
            service_name,
            lease_started_height,
            reporting_epoch,
            service_version,
            replica_slot,
            placement_incarnation,
        );
        // The consensus instruction admits a new reporter identity only at
        // zero. If a crash left a durable non-zero counter before that opening
        // reached WSV, open at zero first and report the preserved durable
        // value on the next authoritative view.
        let submitted_accounted_egress_bytes =
            if authoritative_checkpoint.is_none() && !finalize_reporter {
                0
            } else {
                replica_accounted_egress_bytes
            };
        let submitted_checkpoint = HostedHttpReporterCheckpointState {
            lease_started_height,
            reporting_epoch,
            accounted_egress_bytes: submitted_accounted_egress_bytes,
            finalize_reporter,
        };
        if authoritative_checkpoint == Some(submitted_checkpoint) {
            self.last_service_lease_usage_submission_bytes
                .lock()
                .remove(&key);
            return;
        }
        let attempted_at_ms = soracloud_runtime_observed_at_ms();
        if self
            .last_service_lease_usage_submission_bytes
            .lock()
            .get(&key)
            .is_some_and(|previous| {
                previous.accounted_egress_bytes == submitted_accounted_egress_bytes
                    && previous.finalize_reporter == finalize_reporter
                    && attempted_at_ms >= previous.attempted_at_ms
                    && attempted_at_ms - previous.attempted_at_ms
                        < SORACLOUD_INROU_LEASE_USAGE_RETRY_MS
            })
        {
            return;
        }
        let service_name_id = match Name::from_str(service_name) {
            Ok(name) => name,
            Err(error) => {
                iroha_logger::warn!(
                    ?error,
                    service_name = %service_name,
                    service_version = %service_version,
                    "failed to parse Soracloud service name while submitting authoritative lease usage"
                );
                return;
            }
        };
        let lease_identity_matches = view
            .world()
            .soracloud_service_deployments()
            .get(&service_name_id)
            .and_then(|deployment| deployment.service_lease.as_ref())
            .is_some_and(|lease| {
                lease.lease_started_height == lease_started_height
                    && (lease.reporting_epoch == reporting_epoch
                        || (lease.reporting_epoch.checked_add(1) == Some(reporting_epoch)
                            && submitted_accounted_egress_bytes == 0
                            && !finalize_reporter))
            });
        if !lease_identity_matches {
            iroha_logger::warn!(
                service_name = %service_name,
                service_version = %service_version,
                lease_started_height,
                reporting_epoch,
                "refusing to submit Soracloud lease usage for a stale lease or invalid reporting-epoch transition"
            );
            return;
        }
        let instruction = InstructionBox::from(isi::soracloud::ReportSoracloudServiceLeaseUsage {
            service_name: service_name_id,
            lease_started_height,
            reporting_epoch,
            active_service_version: service_version.to_owned(),
            replica_slot,
            placement_incarnation,
            replica_accounted_egress_bytes: submitted_accounted_egress_bytes,
            finalize_reporter,
        });
        if let Err(error) = mutation_sink.submit_instruction(
            instruction,
            "/internal/soracloud/runtime/service-lease-usage",
        ) {
            iroha_logger::warn!(
                ?error,
                service_name = %service_name,
                service_version = %service_version,
                reporting_epoch,
                replica_slot,
                replica_accounted_egress_bytes = submitted_accounted_egress_bytes,
                finalize_reporter,
                "failed to submit authoritative Soracloud service lease usage update from embedded runtime manager"
            );
            return;
        }
        self.last_service_lease_usage_submission_bytes
            .lock()
            .insert(
                key,
                HostedHttpLeaseUsageSubmissionAttempt {
                    accounted_egress_bytes: submitted_accounted_egress_bytes,
                    finalize_reporter,
                    attempted_at_ms,
                },
            );
    }
    fn build_local_inrou_host_capability_record(
        &self,
        now_ms: u64,
    ) -> Option<SoraInrouHostCapabilityRecordV1> {
        let startup_capability = self.inrou_startup_capability.as_ref()?;
        let validator_account_id = self.config.local_validator_account_id.as_ref()?;
        let peer_id = self.config.local_peer_id.as_deref()?;
        let desired_expiry_ms = desired_inrou_host_heartbeat_expiry_ms(now_ms, &self.config);
        Some(SoraInrouHostCapabilityRecordV1 {
            schema_version: SORA_INROU_HOST_CAPABILITY_RECORD_VERSION_V1,
            validator_account_id: validator_account_id.clone(),
            peer_id: peer_id.to_owned(),
            supported_guest_isas: startup_capability.supported_guest_isas.clone(),
            trusted_guest_artifact: startup_capability.trusted_guest_artifact.clone(),
            max_hosted_replica_capacity: SORA_INROU_HOSTED_REPLICA_CAPACITY_V1,
            max_cpu_millis: self.config.inrou.max_cpu_millis.get(),
            max_memory_bytes: self.config.inrou.max_memory_bytes.get(),
            max_storage_bytes: self.config.inrou.max_storage_bytes.get(),
            advertised_at_ms: now_ms,
            heartbeat_expires_at_ms: desired_expiry_ms,
        })
    }
    fn local_inrou_host_advert_attempt_allowed(&self, now_ms: u64) -> bool {
        let mut last_attempt_ms = self.last_inrou_host_advert_attempt_ms.lock();
        if let Some(previous_attempt_ms) = *last_attempt_ms
            && now_ms.saturating_sub(previous_attempt_ms) < INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS
        {
            return false;
        }
        *last_attempt_ms = Some(now_ms);
        true
    }
    fn local_inrou_host_withdraw_attempt_allowed(&self, now_ms: u64) -> bool {
        let mut last_attempt_ms = self.last_inrou_host_withdraw_attempt_ms.lock();
        if let Some(previous_attempt_ms) = *last_attempt_ms
            && now_ms.saturating_sub(previous_attempt_ms) < INROU_HOST_ADVERT_ATTEMPT_COOLDOWN_MS
        {
            return false;
        }
        *last_attempt_ms = Some(now_ms);
        true
    }
    fn pending_inrou_host_capability_advert_suppresses(
        &self,
        desired: &SoraInrouHostCapabilityRecordV1,
        now_ms: u64,
    ) -> bool {
        self.pending_inrou_host_capability_advert
            .lock()
            .as_ref()
            .is_some_and(|pending| {
                inrou_host_capability_matches(pending, desired)
                    && pending.is_active_at(now_ms)
                    && !inrou_host_heartbeat_refresh_due(pending, now_ms, &self.config)
            })
    }
    fn remember_pending_inrou_host_capability_advert(
        &self,
        desired: &SoraInrouHostCapabilityRecordV1,
    ) {
        *self.pending_inrou_host_capability_advert.lock() = Some(desired.clone());
    }
    fn clear_pending_inrou_host_capability_advert(&self) {
        *self.pending_inrou_host_capability_advert.lock() = None;
    }
    fn local_inrou_placement_reconcile_attempt_allowed(&self, now_ms: u64) -> bool {
        let mut last_attempt_ms = self.last_inrou_placement_reconcile_attempt_ms.lock();
        if let Some(previous_attempt_ms) = *last_attempt_ms
            && now_ms.saturating_sub(previous_attempt_ms)
                < INROU_PLACEMENT_RECONCILE_ATTEMPT_COOLDOWN_MS
        {
            return false;
        }
        *last_attempt_ms = Some(now_ms);
        true
    }
    fn local_inrou_host_capability_refresh_candidate(
        &self,
        view: &StateView<'_>,
    ) -> Option<SoraInrouHostCapabilityRecordV1> {
        let now_ms = soracloud_runtime_observed_at_ms();
        let Some(desired) = self.build_local_inrou_host_capability_record(now_ms) else {
            return None;
        };
        let authoritative = view
            .world()
            .soracloud_inrou_host_capabilities()
            .get(&desired.validator_account_id);
        let needs_refresh =
            inrou_host_capability_refresh_needed(authoritative, &desired, now_ms, &self.config);
        if !needs_refresh {
            self.clear_pending_inrou_host_capability_advert();
            return None;
        }
        Some(desired)
    }
    fn refresh_local_inrou_host_capability_if_needed(
        &self,
        refresh: Option<SoraInrouHostCapabilityRecordV1>,
    ) {
        let Some(mutation_sink) = self.mutation_sink.as_ref() else {
            return;
        };
        let Some(desired) = refresh else {
            return;
        };
        let now_ms = soracloud_runtime_observed_at_ms();
        if self.pending_inrou_host_capability_advert_suppresses(&desired, now_ms) {
            return;
        }
        if !self.local_inrou_host_advert_attempt_allowed(now_ms) {
            return;
        }
        if let Err(error) = mutation_sink.submit_inrou_host_capability(&desired) {
            iroha_logger::warn!(
                ?error,
                validator_account_id = %desired.validator_account_id,
                peer_id = %desired.peer_id,
                "failed to submit authoritative Inrou host capability advert from embedded runtime manager"
            );
            return;
        }
        self.remember_pending_inrou_host_capability_advert(&desired);
    }
    fn withdraw_local_inrou_host_if_needed(&self, view: &StateView<'_>) {
        let Some(validator_account_id) = self.config.local_validator_account_id.as_ref() else {
            return;
        };
        if view
            .world()
            .soracloud_inrou_host_capabilities()
            .get(validator_account_id)
            .is_none()
        {
            self.clear_pending_inrou_host_capability_advert();
            return;
        }
        let Some(mutation_sink) = self.mutation_sink.as_ref() else {
            return;
        };
        let now_ms = soracloud_runtime_observed_at_ms();
        if !self.local_inrou_host_withdraw_attempt_allowed(now_ms) {
            return;
        }
        if let Err(error) = mutation_sink.submit_inrou_host_withdrawal(validator_account_id) {
            iroha_logger::warn!(
                ?error,
                validator_account_id = %validator_account_id,
                "failed to withdraw unavailable local Inrou host advert"
            );
            return;
        }
        self.clear_pending_inrou_host_capability_advert();
        if let Err(error) = mutation_sink.submit_inrou_placement_reconcile() {
            iroha_logger::warn!(
                ?error,
                validator_account_id = %validator_account_id,
                "failed to request Inrou placement reconciliation after host withdrawal"
            );
        }
    }
    fn inrou_placement_reconcile_needed(
        &self,
        view: &StateView<'_>,
        bundle_registry: &BTreeMap<(String, String), SoraDeploymentBundleV1>,
    ) -> eyre::Result<bool> {
        let world = view.world();
        let current_height = committed_height(view);
        let now_ms = soracloud_runtime_observed_at_ms();
        let mut desired_records = BTreeMap::<(String, String), u16>::new();
        #[derive(Clone, Copy, Default)]
        struct RetainedUsage {
            hosted_replicas: u16,
            cpu_millis: u64,
            memory_bytes: u64,
            storage_bytes: u64,
        }
        let mut retained_usage_by_validator = BTreeMap::<AccountId, RetainedUsage>::new();
        let mut retained_placements = Vec::<(
            SoraInrouReplicaPlacementV1,
            Option<SoraPublishedInrouGuestImageArtifactV1>,
        )>::new();
        for (service_name, deployment) in world.soracloud_service_deployments().iter() {
            if !deployment.hosted_service_lease_active_at(current_height)? {
                continue;
            }
            let lease_started_height = deployment
                .service_lease
                .as_ref()
                .ok_or_else(|| {
                    eyre::eyre!(
                        "active Inrou service `{service_name}` has no authoritative lease incarnation"
                    )
                })?
                .lease_started_height;
            let service_version = deployment.current_service_version.clone();
            let Some(bundle) =
                bundle_registry.get(&(service_name.as_ref().to_owned(), service_version.clone()))
            else {
                continue;
            };
            if bundle.container.runtime != SoraContainerRuntimeV1::Inrou
                || bundle.service.execution_plane
                    != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
            {
                continue;
            }
            if deployment.active_rollout.is_some() {
                eyre::bail!(
                    "service `{service_name}` carries an unsupported active Inrou canary; first-release host-local lease disks require one active revision"
                );
            }
            let key = (service_name.as_ref().to_owned(), service_version.clone());
            desired_records.insert(key.clone(), bundle.service.replicas.get());
            let Some(record) = world.soracloud_inrou_service_placements().get(&key) else {
                return Ok(true);
            };
            if record.service_name != *service_name
                || record.service_version != service_version
                || record.desired_replica_count != bundle.service.replicas.get()
                || record.placements.len() > usize::from(record.desired_replica_count)
            {
                return Ok(true);
            }
            let required_storage_bytes = bundle
                    .service
                    .lease_volumes
                    .iter()
                    .filter(|volume| volume.kind.is_per_replica())
                    .try_fold(
                        bundle.container.resources.ephemeral_storage_bytes.get(),
                        |total, volume| total.checked_add(volume.max_total_bytes.get()),
                    )
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "Inrou service `{service_name}` revision `{service_version}` per-replica storage exceeds u64"
                        )
                    })?;
            for placement in &record.placements {
                if placement.lease_started_height != lease_started_height {
                    return Ok(true);
                }
                let current = retained_usage_by_validator
                    .get(&placement.validator_account_id)
                    .copied()
                    .unwrap_or_default();
                let next = RetainedUsage {
                    hosted_replicas: current.hosted_replicas.checked_add(1).ok_or_else(|| {
                        eyre::eyre!("aggregate retained Inrou replica count exceeds u16")
                    })?,
                    cpu_millis: current
                        .cpu_millis
                        .checked_add(
                            bundle
                                .container
                                .resources
                                .checked_inrou_host_cpu_millis()
                                .ok_or_else(|| {
                                    eyre::eyre!("Inrou physical CPU reservation exceeds u64")
                                })?,
                        )
                        .ok_or_else(|| eyre::eyre!("aggregate retained Inrou CPU exceeds u64"))?,
                    memory_bytes: current
                        .memory_bytes
                        .checked_add(
                            bundle
                                .container
                                .resources
                                .checked_inrou_host_memory_bytes()
                                .ok_or_else(|| {
                                    eyre::eyre!("Inrou physical memory reservation exceeds u64")
                                })?,
                        )
                        .ok_or_else(|| {
                            eyre::eyre!("aggregate retained Inrou memory exceeds u64")
                        })?,
                    storage_bytes: current
                        .storage_bytes
                        .checked_add(required_storage_bytes)
                        .ok_or_else(|| {
                            eyre::eyre!("aggregate retained Inrou storage exceeds u64")
                        })?,
                };
                retained_usage_by_validator.insert(placement.validator_account_id.clone(), next);
                let selected_image_artifact = bundle
                    .container
                    .inrou
                    .as_ref()
                    .and_then(|inrou| inrou.guest_images.get(&placement.selected_guest_isa))
                    .map(|image| image.published_artifact.clone());
                retained_placements.push((placement.clone(), selected_image_artifact));
            }
        }
        for (placement, selected_image_artifact) in retained_placements {
            let exact_host_is_eligible = retained_usage_by_validator
                .get(&placement.validator_account_id)
                .and_then(|usage| {
                    world
                        .soracloud_inrou_host_capabilities()
                        .get(&placement.validator_account_id)
                        .map(|capability| (usage, capability))
                })
                .is_some_and(|(usage, capability)| {
                    capability.can_host_replicas_at(now_ms)
                        && capability.peer_id == placement.peer_id
                        && capability
                            .supported_guest_isas
                            .contains(&placement.selected_guest_isa)
                        && selected_image_artifact
                            .as_ref()
                            .is_some_and(|artifact| artifact == &capability.trusted_guest_artifact)
                        && usage.hosted_replicas <= capability.max_hosted_replica_capacity
                        && usage.cpu_millis <= u64::from(capability.max_cpu_millis)
                        && usage.memory_bytes <= capability.max_memory_bytes
                        && usage.storage_bytes <= capability.max_storage_bytes
                        && iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
                            world,
                            &placement.validator_account_id,
                            &placement.peer_id,
                            current_height,
                            |lane_id| view.is_lane_active_for_authority(lane_id),
                        )
                });
            if placement.host_availability.is_available() != exact_host_is_eligible {
                return Ok(true);
            }
        }
        Ok(world
            .soracloud_inrou_service_placements()
            .iter()
            .any(|(key, record)| {
                desired_records
                    .get(key)
                    .is_none_or(|desired_replica_count| {
                        *desired_replica_count != record.desired_replica_count
                    })
            }))
    }
    fn request_inrou_placement_reconcile_if_needed(&self, needed: bool) {
        let Some(mutation_sink) = self.mutation_sink.as_ref() else {
            return;
        };
        if !needed {
            return;
        }
        let now_ms = soracloud_runtime_observed_at_ms();
        if !self.local_inrou_placement_reconcile_attempt_allowed(now_ms) {
            return;
        }
        if let Err(error) = mutation_sink.submit_inrou_placement_reconcile() {
            iroha_logger::warn!(
                ?error,
                "failed to submit authoritative Inrou placement reconciliation request from embedded runtime manager"
            );
        }
    }
    fn runtime_snapshot_path(&self) -> PathBuf {
        self.config.state_dir.join("runtime_snapshot.json")
    }
    fn restore_persisted_snapshot(&self) -> eyre::Result<bool> {
        let path = self.runtime_snapshot_path();
        let Some(mut snapshot) = read_json_optional::<SoracloudRuntimeSnapshot>(
            &path,
            SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
            "Soracloud runtime snapshot",
        )
        .wrap_err_with(|| format!("read {}", path.display()))?
        else {
            return Ok(false);
        };
        if snapshot.schema_version != SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1 {
            eyre::bail!(
                "unsupported Soracloud runtime snapshot schema version {}; expected {}",
                snapshot.schema_version,
                SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1
            );
        }
        let validation_error = {
            let view = self.state.view();
            collect_authoritative_single_revision_inrou_runtime_plans(
                &view,
                &snapshot,
                self.config.local_validator_account_id.as_ref(),
                self.config.local_peer_id.as_deref(),
            )
            .err()
        };
        if let Some(error) = validation_error {
            // This V1 file is derived node-local state, never rollout authority. A parsed but
            // non-current Inrou plan must disappear durably before startup reconciliation; only
            // the exact schema remains accepted, and authoritative WSV rebuilds the sole revision.
            if !strip_inrou_runtime_plans(&mut snapshot) {
                return Err(error).wrap_err("validate first-release Inrou runtime snapshot");
            }
            write_json_atomic_bounded(
                &path,
                &snapshot,
                SORACLOUD_RUNTIME_SNAPSHOT_MAX_BYTES,
                "Soracloud runtime snapshot",
            )
            .wrap_err_with(|| {
                format!(
                    "durably scrub non-authoritative Inrou plans from {}",
                    path.display()
                )
            })?;
            iroha_logger::warn!(
                ?error,
                snapshot_path = %path.display(),
                "discarded non-authoritative persisted Inrou runtime plans before reconciliation"
            );
        }
        *self.snapshot.write() = snapshot;
        Ok(true)
    }
    fn desired_hosted_http_worker_keys(
        &self,
        view: &StateView<'_>,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<BTreeSet<HostedHttpReporterKey>> {
        let mut desired = BTreeSet::new();
        for (service_name, service_version, plan) in
            collect_authoritative_single_revision_inrou_runtime_plans(
                view,
                snapshot,
                self.config.local_validator_account_id.as_ref(),
                self.config.local_peer_id.as_deref(),
            )?
        {
            if plan.process_generation.is_none() {
                continue;
            }
            for replica in &plan.local_replicas {
                let Ok(placement_incarnation) = Hash::from_str(&replica.placement_incarnation)
                else {
                    continue;
                };
                let Some(reporting_epoch) = self.authoritative_service_lease_reporter_target_epoch(
                    view,
                    service_name,
                    replica.lease_started_height,
                    service_version,
                    replica.replica_slot,
                    placement_incarnation,
                ) else {
                    continue;
                };
                desired.insert((
                    service_name.clone(),
                    service_version.clone(),
                    replica.lease_started_height,
                    reporting_epoch,
                    replica.replica_slot,
                    replica.placement_incarnation.clone(),
                ));
            }
        }
        Ok(desired)
    }
    fn reconcile_hosted_http_workers(
        &self,
        view: &StateView<'_>,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let desired_keys = self.desired_hosted_http_worker_keys(view, snapshot)?;
        let desired_revision_keys = desired_keys
            .iter()
            .map(
                |(
                    service_name,
                    service_version,
                    lease_started_height,
                    reporting_epoch,
                    _replica_slot,
                    _placement_incarnation,
                )| {
                    (
                        service_name.clone(),
                        service_version.clone(),
                        *lease_started_height,
                        *reporting_epoch,
                    )
                },
            )
            .collect::<BTreeSet<_>>();
        let stale_workers = {
            let mut workers = self.hosted_http_workers.lock();
            let (stale, kept): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut *workers)
                .into_iter()
                .partition(|(key, _)| !desired_keys.contains(key));
            *workers = kept;
            stale
        };
        for (
            (
                service_name,
                service_version,
                lease_started_height,
                reporting_epoch,
                replica_slot,
                placement_incarnation,
            ),
            worker,
        ) in stale_workers
        {
            let placement_incarnation_hash = Hash::from_str(&placement_incarnation)
                .wrap_err("parse stale Inrou worker placement incarnation")?;
            let final_accounted_egress_bytes = {
                let mut worker = worker.lock();
                worker.stop();
                worker.accounted_egress_bytes().ok_or_else(|| {
                    eyre::eyre!(
                        "stale hosted worker `{service_name}` revision `{service_version}` replica {replica_slot} has no reporter accounting"
                    )
                })?
            };
            self.submit_http_service_lease_usage_update(
                view,
                &service_name,
                lease_started_height,
                reporting_epoch,
                &service_version,
                replica_slot,
                placement_incarnation_hash,
                final_accounted_egress_bytes,
                true,
            );
        }
        let pending_terminal_reporters = self
            .inrou_replica_egress_accounting
            .lock()
            .iter()
            .filter(|(key, _accounting)| !desired_keys.contains(*key))
            .map(|(key, accounting)| (key.clone(), accounting.clone()))
            .collect::<Vec<_>>();
        let mut finalized_reporters = Vec::new();
        for (
            (
                service_name,
                service_version,
                lease_started_height,
                reporting_epoch,
                replica_slot,
                placement_incarnation,
            ),
            accounting,
        ) in pending_terminal_reporters
        {
            let lease_identity_is_current = self
                .authoritative_service_lease_identity(view, &service_name)
                .is_some_and(|(current_lease_started_height, current_reporting_epoch)| {
                    current_lease_started_height == lease_started_height
                        && (current_reporting_epoch == reporting_epoch
                            || current_reporting_epoch.checked_add(1) == Some(reporting_epoch))
                });
            if !lease_identity_is_current {
                finalized_reporters.push((
                    service_name,
                    service_version,
                    lease_started_height,
                    reporting_epoch,
                    replica_slot,
                    placement_incarnation,
                ));
                continue;
            }
            let placement_incarnation_hash = Hash::from_str(&placement_incarnation)
                .wrap_err("parse terminal Inrou reporter placement incarnation")?;
            let local_accounted_egress_bytes = accounting.accounted_egress_bytes();
            let authoritative = self.authoritative_service_lease_reporter_checkpoint(
                view,
                &service_name,
                lease_started_height,
                reporting_epoch,
                &service_version,
                replica_slot,
                placement_incarnation_hash,
            );
            match hosted_http_terminal_reporter_action(
                authoritative,
                local_accounted_egress_bytes,
            )
            .wrap_err_with(|| {
                format!(
                    "validate terminal Inrou reporter `{service_name}` revision `{service_version}` replica {replica_slot}"
                )
            })? {
                HostedHttpTerminalReporterAction::Retire => {
                    finalized_reporters.push((
                        service_name,
                        service_version,
                        lease_started_height,
                        reporting_epoch,
                        replica_slot,
                        placement_incarnation.clone(),
                    ));
                }
                HostedHttpTerminalReporterAction::Submit => self
                    .submit_http_service_lease_usage_update(
                    view,
                    &service_name,
                    lease_started_height,
                    reporting_epoch,
                    &service_version,
                    replica_slot,
                    placement_incarnation_hash,
                    local_accounted_egress_bytes,
                    true,
                ),
            }
        }
        if !finalized_reporters.is_empty() {
            let finalized_reporters = finalized_reporters.into_iter().collect::<BTreeSet<_>>();
            self.inrou_replica_egress_accounting
                .lock()
                .retain(|key, _accounting| !finalized_reporters.contains(key));
            self.last_service_lease_usage_submission_bytes
                .lock()
                .retain(|key, _attempt| !finalized_reporters.contains(key));
        }
        self.inrou_revision_egress_accounting
            .lock()
            .retain(|key, _accounting| desired_revision_keys.contains(key));
        let retained_reporter_keys = self
            .inrou_replica_egress_accounting
            .lock()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.last_service_lease_usage_submission_bytes
            .lock()
            .retain(|key, _attempt| {
                desired_keys.contains(key) || retained_reporter_keys.contains(key)
            });
        let max_inrou_instances = self.hosted_http_concurrency_limit();
        let mut running_processes = {
            let workers = self.hosted_http_workers.lock();
            workers.len()
        };
        for (service_name, service_version, plan) in
            collect_authoritative_single_revision_inrou_runtime_plans(
                view,
                snapshot,
                self.config.local_validator_account_id.as_ref(),
                self.config.local_peer_id.as_deref(),
            )?
        {
            if plan.process_generation.is_none() {
                continue;
            }
            let Some(bundle) = view
                .world()
                .soracloud_service_revisions()
                .get(&(service_name.clone(), service_version.clone()))
            else {
                continue;
            };
            let runtime_label = "inrou";
            let (lease_started_height, reporting_epoch) = self
                    .authoritative_service_lease_identity(view, service_name)
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "local Inrou service `{service_name}` revision `{service_version}` has no authoritative reporting epoch"
                        )
                    })?;
            let process_generation = plan.process_generation.ok_or_else(|| {
                    eyre::eyre!(
                        "local Inrou service `{service_name}` revision `{service_version}` has no canonical process generation"
                    )
                })?;
            let service_data_dir =
                build_native_service_data_dir(&self.config.state_dir, service_name);
            let authoritative_reporting_epoch_egress_bytes = self
                .authoritative_service_reporting_epoch_egress_bytes(
                    view,
                    service_name,
                    service_version,
                    lease_started_height,
                    reporting_epoch,
                )?;
            let revision_reporting_epoch_accounting_offset_bytes =
                authoritative_reporting_epoch_egress_bytes;
            let revision_egress_accounting = {
                let mut accounting = self.inrou_revision_egress_accounting.lock();
                accounting
                    .entry((
                        service_name.clone(),
                        service_version.clone(),
                        lease_started_height,
                        reporting_epoch,
                    ))
                    .or_insert_with(|| {
                        PortableVmEgressAccounting::new(
                            revision_reporting_epoch_accounting_offset_bytes,
                        )
                    })
                    .clone()
            };
            revision_egress_accounting
                    .advance_floor(revision_reporting_epoch_accounting_offset_bytes)
                    .wrap_err_with(|| {
                        format!(
                            "advance shared Inrou egress accounting floor for service `{service_name}` revision `{service_version}`"
                        )
                    })?;
            let mut replica_runtime_states = Vec::with_capacity(plan.local_replica_slots.len());
            for replica_slot in plan.local_replica_slots.iter().copied() {
                let replica_plan = project_hosted_http_replica_plan(plan, replica_slot)?;
                let placement = exact_inrou_replica_placement(&replica_plan)?;
                if placement.lease_started_height != lease_started_height {
                    eyre::bail!(
                        "local Inrou replica `{service_name}` revision `{service_version}` replica {replica_slot} belongs to lease height {} instead of authoritative height {lease_started_height}",
                        placement.lease_started_height
                    );
                }
                let placement_incarnation =
                        Hash::from_str(&placement.placement_incarnation).wrap_err_with(|| {
                            format!(
                                "parse Inrou placement incarnation for service `{service_name}` revision `{service_version}` replica {replica_slot}"
                            )
                        })?;
                let target_reporting_epoch = self
                        .authoritative_service_lease_reporter_target_epoch(
                            view,
                            service_name,
                            lease_started_height,
                            service_version,
                            replica_slot,
                            placement_incarnation,
                        )
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "local Inrou replica `{service_name}` revision `{service_version}` replica {replica_slot} has no authoritative reporter epoch"
                            )
                        })?;
                let reporter_revision_egress_accounting =
                    if target_reporting_epoch == reporting_epoch {
                        revision_egress_accounting.clone()
                    } else {
                        let mut accounting = self.inrou_revision_egress_accounting.lock();
                        accounting
                            .entry((
                                service_name.clone(),
                                service_version.clone(),
                                lease_started_height,
                                target_reporting_epoch,
                            ))
                            .or_insert_with(|| PortableVmEgressAccounting::new(0))
                            .clone()
                    };
                let key = (
                    service_name.clone(),
                    service_version.clone(),
                    lease_started_height,
                    target_reporting_epoch,
                    replica_slot,
                    placement.placement_incarnation.clone(),
                );
                let authoritative_reporter_checkpoint = self
                    .authoritative_service_lease_reporter_checkpoint(
                        view,
                        service_name,
                        lease_started_height,
                        target_reporting_epoch,
                        service_version,
                        replica_slot,
                        placement_incarnation,
                    );
                let authoritative_reporter_accounted_egress_bytes =
                    authoritative_reporter_checkpoint
                        .map_or(0, |checkpoint| checkpoint.accounted_egress_bytes);
                let reporter_egress_accounting = if let Some(accounting) = self
                    .inrou_replica_egress_accounting
                    .lock()
                    .get(&key)
                    .cloned()
                {
                    accounting
                } else {
                    let validator_account_id = self
                            .config
                            .local_validator_account_id
                            .as_ref()
                            .ok_or_else(|| {
                                eyre::eyre!(
                                    "local Inrou replica `{service_name}` revision `{service_version}` replica {replica_slot} has no validator reporter identity"
                                )
                            })?;
                    let durable_checkpoint = InrouDurableEgressCheckpoint::load_or_create(
                            &self.config.state_dir,
                            service_name,
                            lease_started_height,
                            target_reporting_epoch,
                            service_version,
                            replica_slot,
                            &placement_incarnation,
                            validator_account_id,
                            authoritative_reporter_checkpoint,
                        )
                        .wrap_err_with(|| {
                            format!(
                                "recover durable Inrou egress checkpoint for service `{service_name}` revision `{service_version}` replica {replica_slot}"
                            )
                        })?;
                    let recovered_accounted_egress_bytes =
                        durable_checkpoint.accounted_egress_bytes();
                    let accounting = PortableVmEgressAccounting::new_durable_with_gate(
                        recovered_accounted_egress_bytes,
                        Arc::clone(&reporter_revision_egress_accounting.update_gate),
                        durable_checkpoint,
                    )?;
                    self.inrou_replica_egress_accounting
                        .lock()
                        .insert(key.clone(), accounting.clone());
                    accounting
                };
                reporter_egress_accounting
                        .advance_floor(authoritative_reporter_accounted_egress_bytes)
                        .wrap_err_with(|| {
                            format!(
                                "advance Inrou reporter egress accounting floor for service `{service_name}` revision `{service_version}` replica {replica_slot}"
                            )
                        })?;
                let replica_egress_accounting = PortableVmReplicaEgressAccounting::from_shared(
                    reporter_revision_egress_accounting,
                    reporter_egress_accounting.clone(),
                )
                .wrap_err("bind Inrou revision and reporter egress accounting")?;
                let submit_replica_usage = || {
                    self.submit_http_service_lease_usage_update(
                        view,
                        service_name,
                        lease_started_height,
                        target_reporting_epoch,
                        service_version,
                        replica_slot,
                        placement_incarnation,
                        reporter_egress_accounting.accounted_egress_bytes(),
                        false,
                    );
                };
                if self
                    .last_service_lease_usage_submission_bytes
                    .lock()
                    .get(&key)
                    .is_some_and(|attempt| {
                        attempt.accounted_egress_bytes
                            > reporter_egress_accounting.accounted_egress_bytes()
                    })
                {
                    return Err(eyre::eyre!(
                        "last submitted Inrou checkpoint for `{service_name}` revision `{service_version}` replica {replica_slot} exceeds its durable local counter"
                    ));
                }
                submit_replica_usage();
                let local_reporter_accounted_egress_bytes =
                    reporter_egress_accounting.accounted_egress_bytes();
                let reporter_checkpoint_is_open = authoritative_reporter_checkpoint
                    .is_some_and(|checkpoint| !checkpoint.finalize_reporter);
                let reporter_checkpoint_is_current =
                    hosted_http_reporter_checkpoint_is_current_open(
                        authoritative_reporter_checkpoint,
                        lease_started_height,
                        target_reporting_epoch,
                        local_reporter_accounted_egress_bytes,
                    );
                let existing_worker_is_running = self.hosted_http_workers.lock().contains_key(&key);
                if !reporter_checkpoint_is_open
                    || (!reporter_checkpoint_is_current && !existing_worker_is_running)
                {
                    if let Some(worker) = self.hosted_http_workers.lock().remove(&key) {
                        worker.lock().stop();
                        running_processes = running_processes.saturating_sub(1);
                    }
                    let accounted_egress_bytes =
                        reporter_egress_accounting.accounted_egress_bytes();
                    replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                        &PathBuf::from(&replica_plan.materialization_dir),
                        service_name,
                        service_version,
                        process_generation,
                        replica_slot,
                        &placement.placement_incarnation,
                        SoraServiceHealthStatusV1::Hydrating,
                        None,
                        None,
                        accounted_egress_bytes,
                        Some(
                            "awaiting authoritative Inrou egress reporter checkpoint catch-up"
                                .to_owned(),
                        ),
                    )?);
                    continue;
                }
                let cache_key = HostedHttpWorkerCacheKey {
                    runtime: bundle.container.runtime,
                    guest_isa: plan.inrou.as_ref().map(|inrou| inrou.selected_guest_isa),
                    service_name: service_name.clone(),
                    service_version: service_version.clone(),
                    replica_slot,
                    lease_started_height: placement.lease_started_height,
                    placement_incarnation: placement.placement_incarnation.clone(),
                    validator_account_id: placement.validator_account_id.clone(),
                    peer_id: placement.peer_id.clone(),
                    bundle_hash: plan.bundle_hash.clone(),
                    bundle_path: plan.bundle_path.clone(),
                    entrypoint: plan.entrypoint.clone(),
                    process_generation,
                    args: bundle.container.args.clone(),
                    effective_env: replica_plan.effective_env.clone(),
                    healthcheck_path: bundle.container.lifecycle.healthcheck_path.clone(),
                    service_data_dir: service_data_dir.clone(),
                };
                let existing_worker = {
                    let workers = self.hosted_http_workers.lock();
                    workers.get(&key).cloned()
                };
                if let Some(worker) = existing_worker {
                    let mut guard = worker.lock();
                    let current_accounted_egress_bytes = guard.accounted_egress_bytes();
                    let exited = match guard.try_wait() {
                        Ok(Some(status)) => {
                            Some(format!("{runtime_label} exited with status {status}"))
                        }
                        Ok(None) => None,
                        Err(error) => {
                            Some(format!("failed to poll {runtime_label} status: {error}"))
                        }
                    };
                    let same_cache_key = guard.cache_key == cache_key;
                    if exited.is_none() && same_cache_key {
                        let health = probe_hosted_http_health(
                            &guard.listen_base_url,
                            guard.cache_key.healthcheck_path.as_deref(),
                        );
                        let (health_status, last_error) = match health {
                            Ok(()) => (SoraServiceHealthStatusV1::Healthy, None),
                            Err(error) => (
                                SoraServiceHealthStatusV1::Degraded,
                                Some(runtime_error_summary(&error)),
                            ),
                        };
                        let accounted_egress_bytes = current_accounted_egress_bytes
                            .unwrap_or_else(|| reporter_egress_accounting.accounted_egress_bytes());
                        replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                            &PathBuf::from(&replica_plan.materialization_dir),
                            service_name,
                            service_version,
                            process_generation,
                            replica_slot,
                            &placement.placement_incarnation,
                            health_status,
                            Some(&guard.listen_base_url),
                            guard.pid(),
                            accounted_egress_bytes,
                            last_error,
                        )?);
                        submit_replica_usage();
                        continue;
                    }
                    guard.stop();
                    let accounted_egress_bytes = guard
                        .accounted_egress_bytes()
                        .unwrap_or_else(|| reporter_egress_accounting.accounted_egress_bytes());
                    drop(guard);
                    let removed = self.hosted_http_workers.lock().remove(&key);
                    if removed.is_some() && running_processes > 0 {
                        running_processes = running_processes.saturating_sub(1);
                    }
                    if !replica_plan.bundle_available_locally {
                        replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                            &PathBuf::from(&replica_plan.materialization_dir),
                            service_name,
                            service_version,
                            process_generation,
                            replica_slot,
                            &placement.placement_incarnation,
                            SoraServiceHealthStatusV1::Hydrating,
                            None,
                            None,
                            accounted_egress_bytes,
                            Some(format!("{runtime_label} bundle is still hydrating")),
                        )?);
                        submit_replica_usage();
                        continue;
                    }
                    if running_processes >= max_inrou_instances {
                        replica_runtime_states.push(
                                persist_hosted_http_replica_runtime_state(
                                    &PathBuf::from(&replica_plan.materialization_dir),
                                    service_name,
                                    service_version,
                                    process_generation,
                                    replica_slot,
                                    &placement.placement_incarnation,
                                    SoraServiceHealthStatusV1::Degraded,
                                    None,
                                    None,
                                    accounted_egress_bytes,
                                    Some(format!(
                                        "{runtime_label} concurrency limit {max_inrou_instances} is already exhausted"
                                    )),
                                )?,
                            );
                        submit_replica_usage();
                        continue;
                    }
                } else if !replica_plan.bundle_available_locally {
                    replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                        &PathBuf::from(&replica_plan.materialization_dir),
                        service_name,
                        service_version,
                        process_generation,
                        replica_slot,
                        &placement.placement_incarnation,
                        SoraServiceHealthStatusV1::Hydrating,
                        None,
                        None,
                        reporter_egress_accounting.accounted_egress_bytes(),
                        Some(format!("{runtime_label} bundle is still hydrating")),
                    )?);
                    submit_replica_usage();
                    continue;
                } else if running_processes >= max_inrou_instances {
                    replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                            &PathBuf::from(&replica_plan.materialization_dir),
                            service_name,
                            service_version,
                            process_generation,
                            replica_slot,
                            &placement.placement_incarnation,
                            SoraServiceHealthStatusV1::Degraded,
                            None,
                            None,
                            reporter_egress_accounting.accounted_egress_bytes(),
                            Some(format!(
                                "{runtime_label} concurrency limit {max_inrou_instances} is already exhausted"
                            )),
                        )?);
                    submit_replica_usage();
                    continue;
                }
                let worker = match self
                        .start_hosted_http_worker(
                            &replica_plan,
                            bundle,
                            cache_key.clone(),
                            replica_egress_accounting.clone(),
                        )
                        .wrap_err_with(|| {
                            format!(
                                "start {runtime_label} Soracloud service `{service_name}` revision `{service_version}` replica {replica_slot}"
                            )
                        }) {
                        Ok(worker) => worker,
                        Err(error) => {
                            iroha_logger::warn!(
                                ?error,
                                service_name = %service_name,
                                service_version = %service_version,
                                replica_slot,
                                runtime = runtime_label,
                                "failed to start hosted Soracloud HTTP service replica"
                            );
                            replica_runtime_states.push(
                                persist_hosted_http_replica_runtime_state(
                                    &PathBuf::from(&replica_plan.materialization_dir),
                                    service_name,
                                    service_version,
                                    process_generation,
                                    replica_slot,
                                    &placement.placement_incarnation,
                                    SoraServiceHealthStatusV1::Degraded,
                                    None,
                                    None,
                                    reporter_egress_accounting.accounted_egress_bytes(),
                                    Some(runtime_error_summary(&error)),
                                )?,
                            );
                            submit_replica_usage();
                            continue;
                        }
                    };
                let accounted_egress_bytes = worker
                    .accounted_egress_bytes()
                    .unwrap_or_else(|| reporter_egress_accounting.accounted_egress_bytes());
                replica_runtime_states.push(persist_hosted_http_replica_runtime_state(
                    &PathBuf::from(&replica_plan.materialization_dir),
                    service_name,
                    service_version,
                    process_generation,
                    replica_slot,
                    &placement.placement_incarnation,
                    SoraServiceHealthStatusV1::Healthy,
                    Some(&worker.listen_base_url),
                    worker.pid(),
                    accounted_egress_bytes,
                    None,
                )?);
                self.hosted_http_workers
                    .lock()
                    .insert(key, Arc::new(Mutex::new(worker)));
                running_processes = running_processes.saturating_add(1);
                submit_replica_usage();
            }
            let accounted_egress_bytes = revision_egress_accounting.accounted_egress_bytes();
            let revision_listen_base_url =
                aggregate_hosted_http_revision_listener(&replica_runtime_states)
                    .map(ToOwned::to_owned);
            let revision_pid = aggregate_hosted_http_revision_pid(&replica_runtime_states);
            let revision_last_error =
                aggregate_hosted_http_revision_last_error(&replica_runtime_states);
            write_hosted_http_runtime_state(
                &PathBuf::from(&plan.materialization_dir),
                service_name,
                service_version,
                process_generation,
                aggregate_hosted_http_revision_health_status(&replica_runtime_states),
                revision_listen_base_url.as_deref(),
                revision_pid,
                accounted_egress_bytes,
                revision_last_error,
                replica_runtime_states,
            )?;
        }
        Ok(())
    }
    fn start_hosted_http_worker(
        &self,
        plan: &SoracloudRuntimeServicePlan,
        bundle: &SoraDeploymentBundleV1,
        cache_key: HostedHttpWorkerCacheKey,
        egress_accounting: PortableVmReplicaEgressAccounting,
    ) -> eyre::Result<HostedHttpWorker> {
        if cache_key.runtime != SoraContainerRuntimeV1::Inrou {
            eyre::bail!(
                "unsupported hosted HTTP runtime {:?}; Soracloud hosted HTTP services must use `Inrou`",
                cache_key.runtime
            );
        }
        self.start_inrou_worker(plan, bundle, cache_key, egress_accounting)
    }
    fn start_inrou_worker(
        &self,
        plan: &SoracloudRuntimeServicePlan,
        bundle: &SoraDeploymentBundleV1,
        cache_key: HostedHttpWorkerCacheKey,
        egress_accounting: PortableVmReplicaEgressAccounting,
    ) -> eyre::Result<HostedHttpWorker> {
        validate_soracloud_runtime_manager_posture(&self.config)
            .wrap_err("enforce canonical Inrou PortableVM V1 admission before worker launch")?;
        plan.inrou
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Inrou runtime requires a local runtime Inrou plan"))?;
        self.start_inrou_worker_portable(plan, bundle, cache_key, egress_accounting)
    }
    #[cfg(not(target_os = "linux"))]
    fn start_inrou_worker_portable(
        &self,
        _plan: &SoracloudRuntimeServicePlan,
        _bundle: &SoraDeploymentBundleV1,
        _cache_key: HostedHttpWorkerCacheKey,
        _egress_accounting: PortableVmReplicaEgressAccounting,
    ) -> eyre::Result<HostedHttpWorker> {
        eyre::bail!(
            "Inrou PortableVM release hosting requires Linux procfs identity attestation, anonymous QMP capabilities, and QEMU seccomp"
        )
    }
    #[cfg(target_os = "linux")]
    fn start_inrou_worker_portable(
        &self,
        plan: &SoracloudRuntimeServicePlan,
        bundle: &SoraDeploymentBundleV1,
        cache_key: HostedHttpWorkerCacheKey,
        egress_accounting: PortableVmReplicaEgressAccounting,
    ) -> eyre::Result<HostedHttpWorker> {
        validate_inrou_v1_network_policy(&bundle.container.capabilities.network)?;
        let placement = exact_inrou_replica_placement(plan)?;
        let local_validator_account_id = self
            .config
            .local_validator_account_id
            .as_ref()
            .ok_or_else(|| {
                eyre::eyre!("Inrou worker launch requires a local validator identity")
            })?;
        let local_peer_id = self
            .config
            .local_peer_id
            .as_deref()
            .ok_or_else(|| eyre::eyre!("Inrou worker launch requires a local peer identity"))?;
        if placement.validator_account_id != local_validator_account_id.to_string()
            || placement.peer_id != local_peer_id
        {
            eyre::bail!(
                "Inrou replica {} placement is assigned to validator `{}` peer `{}`, not this validator `{local_validator_account_id}` peer `{local_peer_id}`",
                placement.replica_slot,
                placement.validator_account_id,
                placement.peer_id,
            );
        }
        if cache_key.replica_slot != placement.replica_slot
            || cache_key.lease_started_height != placement.lease_started_height
            || cache_key.placement_incarnation != placement.placement_incarnation
            || cache_key.validator_account_id != placement.validator_account_id
            || cache_key.peer_id != placement.peer_id
        {
            eyre::bail!(
                "Inrou worker cache identity does not match replica {} placement {}",
                placement.replica_slot,
                placement.placement_incarnation,
            );
        }
        if plan
            .lease_volumes
            .iter()
            .any(|volume| volume.lease_started_height != placement.lease_started_height)
        {
            eyre::bail!(
                "Inrou replica {} placement {} does not match every projected lease-volume incarnation",
                placement.replica_slot,
                placement.placement_incarnation,
            );
        }
        if !placement.host_availability.is_available() {
            eyre::bail!(
                "Inrou replica {} placement {} cannot start because its sticky assigned host is unavailable",
                placement.replica_slot,
                placement.placement_incarnation,
            );
        }
        let inrou = plan
            .inrou
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Inrou runtime requires a local runtime Inrou plan"))?;
        let host_guest_isa = current_host_inrou_guest_isa().ok_or_else(|| {
            eyre::eyre!("Inrou PortableVM V1 supports only x86_64 and aarch64 Linux hosts")
        })?;
        if inrou.selected_guest_isa != host_guest_isa {
            eyre::bail!(
                "KVM-only Inrou V1 requires guest ISA `{}` to equal this host ISA `{}`",
                inrou.selected_guest_isa.as_str(),
                host_guest_isa.as_str(),
            );
        }
        let profile = portable_vm_guest_machine_profile(inrou.selected_guest_isa);
        let preflight = portable_vm_backend_static_preflight(&self.config.inrou)
            .wrap_err("revalidate the sealed Inrou PortableVM launcher")?;
        let PortableVmBackendPreflight {
            child_identity,
            qemu_img,
            namespace_tools,
        } = preflight;
        ensure_no_process_with_inrou_identity(&child_identity)
            .wrap_err("require an unused dedicated Inrou QEMU identity before disk delegation")?;
        let materialization_dir =
            ensure_secure_inrou_disk_directory(Path::new(&plan.materialization_dir))
                .wrap_err("secure and canonicalize Inrou PortableVm materialization directory")?;
        // Reconciliation kills and waits for a tracked previous worker before
        // reaching this launch. A daemon crash is covered by QEMU's
        // exit-with-parent policy; after revoking path access, reclaim still
        // scans procfs and fails closed if that old identity retains an fd.
        for volume in &plan.lease_volumes {
            let file_name = if volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume {
                "rootfs.ext4"
            } else {
                "lease.raw"
            };
            let volume_dir =
                ensure_secure_inrou_disk_directory(Path::new(&volume.local_materialization_dir))
                    .wrap_err_with(|| {
                        format!(
                            "secure and canonicalize Inrou volume `{}`",
                            volume.volume_name
                        )
                    })?;
            reclaim_inrou_qemu_file_if_present(
                &volume_dir,
                OsStr::new(file_name),
                &child_identity,
            )?;
        }
        let archive_limits = inrou_bundle_archive_limits(
            &self.config.inrou,
            self.config.cache_budgets.bundle_bytes.get(),
        );
        let bundle_root = ensure_native_bundle_extracted(
            &PathBuf::from(&plan.bundle_cache_path),
            bundle.container.bundle_hash,
            &materialization_dir,
            OsStr::new("inrou_bundle"),
            &bundle.container.entrypoint,
            archive_limits,
        )?;
        self.hydrate_published_inrou_guest_image_artifact(&bundle_root, bundle, inrou)?;
        ensure_inrou_entrypoint_present_at(&bundle_root, &bundle.container.entrypoint)?;
        let kernel_image_path =
            resolve_inrou_bundle_member_path(bundle_root.path(), &inrou.kernel_image_path)?;
        let base_rootfs_image_path =
            resolve_inrou_bundle_member_path(bundle_root.path(), &inrou.rootfs_image_path)?;
        let initrd_image_path = inrou
            .initrd_image_path
            .as_ref()
            .map(|path| resolve_inrou_bundle_member_path(bundle_root.path(), path))
            .transpose()?;
        let guest_port = bundle
            .service
            .route
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Inrou service requires a route"))?
            .service_port
            .get();
        let stderr_log_name = OsStr::new("inrou.stderr.log");
        let stderr_log_path = materialization_dir.path().join(stderr_log_name);
        let stderr_log =
            open_inrou_runtime_log(&materialization_dir, stderr_log_name, "Inrou stderr log")
                .wrap_err_with(|| format!("open {}", stderr_log_path.display()))?;
        let (prepared_root_disk, root_disk_format) = match plan
            .lease_volumes
            .iter()
            .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
        {
            Some(root_volume) => {
                let root_disk_binding = inrou_root_disk_binding(bundle, plan, inrou, root_volume)?;
                (
                    ensure_inrou_portable_root_disk(
                        &base_rootfs_image_path,
                        root_volume,
                        root_disk_binding,
                    )
                    .wrap_err("prepare Inrou mutable PortableVm root disk")?,
                    "raw",
                )
            }
            None => eyre::bail!("Inrou runtime requires one PersistentRootLeaseVolume"),
        };
        let root_disk_path = prepared_root_disk.image_path.clone();
        let root_disk_exact_bytes = prepared_root_disk.exact_bytes;
        let lease_disks = ensure_inrou_portable_lease_disks(&qemu_img, plan)
            .wrap_err("prepare PortableVm lease disks")?;
        let data_volume_mounts = build_inrou_portable_data_volume_mounts(&lease_disks);
        let PortableVmNetworkPlan {
            netdev,
            listen_base_url,
            public_listener,
            backend_reservation,
            expected_backend,
        } = build_portable_vm_network_plan(guest_port)
            .wrap_err("prepare PortableVm user-mode networking")?;
        let mut loopback_firewall = Some(
            InrouLoopbackOwnerFirewall::install(&public_listener, &child_identity)
                .wrap_err("isolate Inrou loopback listeners by supervisor socket owner")?,
        );
        ensure_portable_vm_identity_reserved(&child_identity)
            .wrap_err("recheck the locked Inrou QEMU service identity under the firewall lock")?;
        ensure_no_process_with_inrou_identity(&child_identity).wrap_err(
            "recheck the exclusive Inrou QEMU identity under the firewall lock before delegation",
        )?;
        let network_config = build_inrou_portable_network_config();
        let portable_bundle_max_bytes = archive_limits.max_compressed_bytes;
        let (portable_bundle_path, portable_bundle_exact_bytes) =
            stage_portable_vm_bundle_block_device(
                &materialization_dir,
                &PathBuf::from(&plan.bundle_cache_path),
                bundle.container.bundle_hash,
                portable_bundle_max_bytes,
            )
            .wrap_err("stage verified PortableVm app-bundle block device")?;
        let portable_bundle = PortableVmBundleBinding {
            expected_hash: bundle.container.bundle_hash,
            exact_bytes: portable_bundle_exact_bytes,
            maximum_bytes: portable_bundle_max_bytes,
        };
        let startup_grace = effective_inrou_lifecycle_grace(
            self.config.inrou.start_grace,
            bundle.container.lifecycle.start_grace_secs.get(),
        );
        let stop_grace = effective_inrou_lifecycle_grace(
            self.config.inrou.stop_grace,
            bundle.container.lifecycle.stop_grace_secs.get(),
        );
        let user_data = build_inrou_user_data(
            plan,
            &cache_key,
            guest_port,
            &bundle.container.resources,
            &data_volume_mounts,
            stop_grace,
            None,
            Some(portable_bundle),
        )?;
        let cloud_init_root = write_inrou_cloud_init_documents(
            &materialization_dir,
            &cache_key,
            &network_config,
            &user_data,
        )
        .wrap_err("write PortableVm cloud-init documents")?;
        ensure_no_process_with_inrou_identity(&child_identity)
            .wrap_err("recheck the exclusive Inrou QEMU identity before file delegation")?;
        let runtime_root = &self.config.state_dir;
        let delegated_kernel_file = prepare_inrou_qemu_file_access(
            runtime_root,
            &kernel_image_path,
            &child_identity,
            false,
        )?;
        let delegated_initrd_file = initrd_image_path
            .as_ref()
            .map(|initrd_image_path| {
                prepare_inrou_qemu_file_access(
                    runtime_root,
                    initrd_image_path,
                    &child_identity,
                    false,
                )
            })
            .transpose()?;
        let delegated_root_disk =
            prepare_inrou_qemu_file_access(runtime_root, &root_disk_path, &child_identity, true)?;
        let delegated_portable_bundle_file = prepare_inrou_qemu_file_access(
            runtime_root,
            &portable_bundle_path,
            &child_identity,
            false,
        )?;
        let delegated_lease_disk_files = lease_disks
            .iter()
            .map(|disk| {
                prepare_inrou_qemu_file_access(
                    runtime_root,
                    &disk.image_path,
                    &child_identity,
                    true,
                )
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let delegated_cloud_init_files = ["meta-data", "network-config", "user-data"]
            .into_iter()
            .map(|document| {
                let path = cloud_init_root.path().join(document);
                let file =
                    prepare_inrou_qemu_file_access(runtime_root, &path, &child_identity, false)?;
                Ok((document, path, file))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let mut namespace_bindings = vec![
            inrou_namespace::InrouNamespaceBindingRequest {
                host_path: kernel_image_path.clone(),
                host_file: delegated_kernel_file,
                sandbox_path: PathBuf::from(inrou_namespace::INROU_NAMESPACE_KERNEL_PATH),
                writable: false,
            },
            inrou_namespace::InrouNamespaceBindingRequest {
                host_path: portable_bundle_path.clone(),
                host_file: delegated_portable_bundle_file,
                sandbox_path: PathBuf::from(inrou_namespace::INROU_NAMESPACE_BUNDLE_PATH),
                writable: false,
            },
            inrou_namespace::InrouNamespaceBindingRequest {
                host_path: root_disk_path.clone(),
                host_file: delegated_root_disk
                    .try_clone()
                    .wrap_err("retain exact Inrou root-disk descriptor for namespace launch")?,
                sandbox_path: PathBuf::from(inrou_namespace::INROU_NAMESPACE_ROOT_DISK_PATH),
                writable: true,
            },
        ];
        if let (Some(initrd_image_path), Some(delegated_initrd_file)) =
            (initrd_image_path.as_ref(), delegated_initrd_file)
        {
            namespace_bindings.push(inrou_namespace::InrouNamespaceBindingRequest {
                host_path: initrd_image_path.clone(),
                host_file: delegated_initrd_file,
                sandbox_path: PathBuf::from(inrou_namespace::INROU_NAMESPACE_INITRD_PATH),
                writable: false,
            });
        }
        for (document, host_path, host_file) in delegated_cloud_init_files {
            namespace_bindings.push(inrou_namespace::InrouNamespaceBindingRequest {
                host_path,
                host_file,
                sandbox_path: Path::new(inrou_namespace::INROU_NAMESPACE_CLOUD_INIT_ROOT)
                    .join(document),
                writable: false,
            });
        }
        for (index, (disk, delegated_disk)) in lease_disks
            .iter()
            .zip(&delegated_lease_disk_files)
            .enumerate()
        {
            if index >= inrou_namespace::INROU_NAMESPACE_MAX_LEASE_DISKS {
                eyre::bail!("Inrou PortableVM exceeds its fixed lease-disk limit");
            }
            namespace_bindings.push(inrou_namespace::InrouNamespaceBindingRequest {
                host_path: disk.image_path.clone(),
                host_file: delegated_disk.try_clone().wrap_err_with(|| {
                    format!("retain exact Inrou lease-disk descriptor {index} for namespace launch")
                })?,
                sandbox_path: PathBuf::from(format!("/inrou/disk/lease{index}")),
                writable: true,
            });
        }
        let namespace_plan = inrou_namespace::InrouNamespacePlan::prepare(
            namespace_tools,
            child_identity.gid,
            namespace_bindings,
        )
        .wrap_err("prepare the authenticated Inrou minimal-root namespace plan")?;
        let memory_mib = portable_vm_memory_mib(&bundle.container.resources);
        let machine_arg = format!("{},accel=kvm,memory-backend=vmmem", profile.machine_type);
        let io_backing_paths = namespace_plan.io_backing_paths()?;
        let io_backing_path_refs = io_backing_paths
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        let mut worker_cgroup = inrou_cgroup::InrouWorkerCgroup::prepare(
            inrou_cgroup::InrouCgroupWorkerKey {
                owner_slot: inrou_cgroup::InrouCgroupOwnerSlot::from_identity(
                    child_identity.uid,
                    child_identity.gid,
                )?,
                service_name: &cache_key.service_name,
                service_version: &cache_key.service_version,
                replica_slot: cache_key.replica_slot,
                process_generation: cache_key.process_generation,
                bundle_hash: &cache_key.bundle_hash,
            },
            &bundle.container.resources,
            &io_backing_path_refs,
        )
        .wrap_err("prepare finite cgroup-v2 confinement for Inrou PortableVM")?;
        let mut launch_barrier = inrou_cgroup::InrouLaunchBarrier::create()
            .wrap_err("create the anonymous Inrou cgroup launch barrier")?;
        let mut command = build_inrou_portable_vm_command(
            &namespace_plan,
            &child_identity,
            &launch_barrier,
            worker_cgroup.attestation().expected_proc_path(),
        )?;
        command
            .arg("-object")
            .arg(format!(
                "memory-backend-ram,id=vmmem,size={}M,share=on",
                memory_mib
            ))
            .arg("-machine")
            .arg(machine_arg)
            .arg("-cpu")
            .arg("host")
            .arg("-smp")
            .arg(portable_vm_vcpu_count(&bundle.container.resources)?.to_string())
            .arg("-kernel")
            .arg(inrou_namespace::INROU_NAMESPACE_KERNEL_PATH);
        if initrd_image_path.is_some() {
            command
                .arg("-initrd")
                .arg(inrou_namespace::INROU_NAMESPACE_INITRD_PATH);
        }
        command
            .arg("-append")
            .arg(portable_vm_kernel_cmdline(profile))
            .arg("-nodefaults")
            .arg("-no-reboot")
            .arg("-display")
            .arg("none")
            .arg("-monitor")
            .arg("none")
            .arg("-netdev")
            .arg(&netdev)
            .arg("-device")
            .arg(format!("{},netdev=net0", profile.net_device))
            .stderr(Stdio::piped());
        let qmp_stream = configure_inrou_qmp_stdio(&mut command)
            .wrap_err("create capability-bound Inrou QMP socketpair")?;
        append_portable_vm_drive(
            &mut command,
            profile,
            "rootfs",
            Path::new(inrou_namespace::INROU_NAMESPACE_ROOT_DISK_PATH),
            root_disk_format,
            false,
            true,
        )
        .wrap_err("attach PortableVm mutable root disk")?;
        append_portable_vm_vvfat_drive(
            &mut command,
            profile,
            Path::new(inrou_namespace::INROU_NAMESPACE_CLOUD_INIT_ROOT),
        )
        .wrap_err("attach read-only PortableVm cloud-init seed")?;
        append_portable_vm_drive_with_serial(
            &mut command,
            profile,
            "bundle",
            Path::new(inrou_namespace::INROU_NAMESPACE_BUNDLE_PATH),
            "raw",
            true,
            false,
            Some(INROU_PORTABLE_BUNDLE_DEVICE_SERIAL),
        )
        .wrap_err("attach read-only PortableVm app-bundle block device")?;
        for (index, disk) in lease_disks.iter().enumerate() {
            append_portable_vm_drive_with_serial(
                &mut command,
                profile,
                &format!("lease{index}"),
                Path::new(&format!("/inrou/disk/lease{index}")),
                disk.image_format,
                false,
                true,
                Some(&disk.device_serial),
            )
            .wrap_err_with(|| format!("attach PortableVm lease disk {index}"))?;
        }
        ensure_no_process_with_inrou_identity(&child_identity)
            .wrap_err("finalize the exclusive Inrou QEMU identity immediately before spawn")?;
        ensure_portable_vm_identity_reserved(&child_identity)
            .wrap_err("finalize the locked Inrou QEMU service identity before spawn")?;
        // The reservation selects a non-privileged port. QEMU binds that number
        // in its fresh private network namespace, so host processes cannot race
        // or impersonate the resulting endpoint.
        drop(backend_reservation);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "spawn Inrou PortableVM via {}",
                        namespace_plan.launcher().display()
                    )
                });
            }
        };
        drop(command);
        launch_barrier.child_spawned();
        if let Err(error) = worker_cgroup.place_launcher(child.id()) {
            let termination = terminate_inrou_confined_child_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
                "Inrou PortableVM",
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "place and attest Inrou launcher before QEMU exec{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        if let Err(error) = launch_barrier.release() {
            let termination = terminate_inrou_confined_child_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
                "Inrou PortableVM",
            );
            return Err(error).wrap_err_with(|| {
                format!(
                    "release Inrou QEMU only after cgroup placement{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
        let mut log_drains = match attach_inrou_runtime_log_drains(&mut child, stderr_log) {
            Ok(log_drains) => log_drains,
            Err(error) => {
                let termination = terminate_inrou_confined_child_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                    "Inrou PortableVM",
                );
                return Err(error).wrap_err_with(|| {
                    format!(
                        "attach bounded Inrou PortableVm log drains{}",
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        let (qemu_forward, qmp_control, namespace_attestation) = match query_inrou_qmp_host_forward(
            &mut child,
            qmp_stream,
            &namespace_plan,
            &child_identity,
            worker_cgroup.attestation(),
            guest_port,
        ) {
            Ok(qemu_forward) => qemu_forward,
            Err(error) => {
                let termination = terminate_inrou_confined_child_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                    "Inrou PortableVM",
                );
                join_inrou_log_drains_bounded(&mut log_drains);
                return Err(error).wrap_err_with(|| {
                    format!(
                        "attest QEMU-owned Inrou host forwarding over QMP{}",
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        if qemu_forward != expected_backend {
            let termination = terminate_inrou_confined_child_bounded(
                &mut child,
                &mut worker_cgroup,
                &mut loopback_firewall,
                "Inrou PortableVM",
            );
            join_inrou_log_drains_bounded(&mut log_drains);
            eyre::bail!(
                "QEMU published Inrou host forward {qemu_forward} instead of the reserved private-network endpoint {expected_backend}{}",
                inrou_termination_error_suffix(&termination)
            );
        }
        let qmp_control = Arc::new(Mutex::new(qmp_control));
        let mut port_forward = match PortableVmLoopbackBridge::start(
            public_listener,
            qemu_forward,
            egress_accounting.clone(),
            Arc::clone(&qmp_control),
            namespace_attestation,
            worker_cgroup.attestation().clone(),
            guest_port,
        ) {
            Ok(port_forward) => port_forward,
            Err(error) => {
                let termination = terminate_inrou_confined_child_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                    "Inrou PortableVM",
                );
                join_inrou_log_drains_bounded(&mut log_drains);
                return Err(error).wrap_err_with(|| {
                    format!(
                        "start supervisor-owned Inrou loopback bridge{}",
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        let started_at = std::time::Instant::now();
        loop {
            let child_status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    port_forward.stop();
                    let termination = terminate_inrou_confined_child_bounded(
                        &mut child,
                        &mut worker_cgroup,
                        &mut loopback_firewall,
                        "Inrou PortableVM",
                    );
                    join_inrou_log_drains_bounded(&mut log_drains);
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "poll Inrou PortableVm process during startup{}",
                            inrou_termination_error_suffix(&termination)
                        )
                    });
                }
            };
            if let Some(status) = child_status {
                port_forward.stop();
                let termination = terminate_inrou_confined_child_bounded(
                    &mut child,
                    &mut worker_cgroup,
                    &mut loopback_firewall,
                    "Inrou PortableVM",
                );
                join_inrou_log_drains_bounded(&mut log_drains);
                let stderr = stderr_log_excerpt(&stderr_log_path);
                eyre::bail!(
                    "Inrou PortableVm process exited during startup with status {status}{}{}",
                    if stderr.is_empty() {
                        String::new()
                    } else {
                        format!(": {stderr}")
                    },
                    inrou_termination_error_suffix(&termination),
                );
            }
            match probe_hosted_http_health(
                &listen_base_url,
                bundle.container.lifecycle.healthcheck_path.as_deref(),
            ) {
                Ok(()) => {
                    let delegated_disk_custody = InrouDiskCustody {
                        uid: 0,
                        gid: child_identity.gid,
                        mode: 0o660,
                    };
                    let disk_commit = (|| -> eyre::Result<()> {
                        validate_inrou_disk_under_exact_custody_at(
                            &prepared_root_disk.directory,
                            &prepared_root_disk.image_name,
                            &delegated_root_disk,
                            root_disk_exact_bytes,
                            delegated_disk_custody,
                        )?;
                        mark_inrou_portable_lease_disks_initialized(
                            &lease_disks,
                            &delegated_lease_disk_files,
                            delegated_disk_custody,
                        )
                    })();
                    if let Err(error) = disk_commit {
                        port_forward.stop();
                        let termination = terminate_inrou_confined_child_bounded(
                            &mut child,
                            &mut worker_cgroup,
                            &mut loopback_firewall,
                            "Inrou PortableVM",
                        );
                        join_inrou_log_drains_bounded(&mut log_drains);
                        return Err(error).wrap_err_with(|| {
                            format!(
                                "validate the authenticated Inrou root disk and commit lease-disk initialization after guest health{}",
                                inrou_termination_error_suffix(&termination)
                            )
                        });
                    }
                    return Ok(HostedHttpWorker::new(
                        cache_key,
                        child,
                        log_drains,
                        listen_base_url,
                        egress_accounting,
                        stderr_log_path,
                        stop_grace,
                        port_forward,
                        qmp_control,
                        loopback_firewall
                            .take()
                            .expect("installed Inrou loopback firewall"),
                        worker_cgroup,
                    ));
                }
                Err(error) if started_at.elapsed() < startup_grace => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(250));
                }
                Err(error) => {
                    port_forward.stop();
                    let termination = terminate_inrou_confined_child_bounded(
                        &mut child,
                        &mut worker_cgroup,
                        &mut loopback_firewall,
                        "Inrou PortableVM",
                    );
                    join_inrou_log_drains_bounded(&mut log_drains);
                    let stderr = stderr_log_excerpt(&stderr_log_path);
                    eyre::bail!(
                        "Inrou PortableVm failed healthcheck during startup: {}{}{}",
                        error,
                        if stderr.is_empty() {
                            String::new()
                        } else {
                            format!(": {stderr}")
                        },
                        inrou_termination_error_suffix(&termination),
                    );
                }
            }
        }
    }
    fn services_root(&self) -> PathBuf {
        self.config.state_dir.join("services")
    }
    fn apartments_root(&self) -> PathBuf {
        self.config.state_dir.join("apartments")
    }
    fn hosted_http_concurrency_limit(&self) -> usize {
        if !self.config.inrou.enabled || self.inrou_startup_capability.is_none() {
            0
        } else {
            usize::from(SORA_INROU_HOSTED_REPLICA_CAPACITY_V1)
        }
    }
    fn artifacts_root(&self) -> PathBuf {
        self.config.state_dir.join("artifacts")
    }
    fn journals_root(&self) -> PathBuf {
        self.config.state_dir.join("journals")
    }
    fn checkpoints_root(&self) -> PathBuf {
        self.config.state_dir.join("checkpoints")
    }
    fn credentials_root(&self) -> PathBuf {
        self.config.state_dir.join("credentials")
    }
    fn service_data_root(&self) -> PathBuf {
        self.config.state_dir.join("service_data")
    }
    fn write_service_materializations(
        &self,
        snapshot: &SoracloudRuntimeSnapshot,
        bundle_registry: &BTreeMap<(String, String), SoraDeploymentBundleV1>,
        view: &StateView<'_>,
    ) -> eyre::Result<()> {
        for (service_name, versions) in &snapshot.services {
            let service_dir_name = storage_path_component(service_name);
            let service_root = self.services_root().join(service_dir_name);
            fs::create_dir_all(&service_root)
                .wrap_err_with(|| format!("create {}", service_root.display()))?;
            for (service_version, plan) in versions {
                let version_dir = service_root.join(storage_path_component(service_version));
                fs::create_dir_all(&version_dir)
                    .wrap_err_with(|| format!("create {}", version_dir.display()))?;
                write_json_atomic(&version_dir.join("runtime_plan.json"), plan)?;
                for replica_slot in &plan.local_replica_slots {
                    let replica_plan = project_hosted_http_replica_plan(plan, *replica_slot)?;
                    let replica_dir = PathBuf::from(&replica_plan.materialization_dir);
                    fs::create_dir_all(&replica_dir)
                        .wrap_err_with(|| format!("create {}", replica_dir.display()))?;
                    write_json_atomic(&replica_dir.join("runtime_plan.json"), &replica_plan)?;
                }
                let bundle = bundle_registry
                    .get(&(service_name.clone(), service_version.clone()))
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "runtime snapshot references missing admitted bundle for service `{service_name}` revision `{service_version}`"
                        )
                    })?;
                write_json_atomic(&version_dir.join("deployment_bundle.json"), bundle)?;
                let deployment = view
                    .world()
                    .soracloud_service_deployments()
                    .get(&bundle.service.service_name)
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "runtime snapshot references missing deployment state for service `{}`",
                            bundle.service.service_name
                        )
                    })?;
                write_service_config_materializations(
                    &version_dir,
                    &PathBuf::from(&plan.config_materialization_dir),
                    &PathBuf::from(&plan.config_exports_materialization_dir),
                    &PathBuf::from(&plan.effective_env_materialization_path),
                    plan,
                    deployment,
                )?;
                write_service_secret_materializations(
                    &version_dir,
                    &PathBuf::from(&plan.secret_envelopes_materialization_dir),
                    deployment,
                )?;
            }
        }
        Ok(())
    }
    fn write_apartment_materializations(
        &self,
        snapshot: &SoracloudRuntimeSnapshot,
        view: &StateView<'_>,
    ) -> eyre::Result<()> {
        for (apartment_name, plan) in &snapshot.apartments {
            let apartment_root = self
                .apartments_root()
                .join(storage_path_component(apartment_name));
            fs::create_dir_all(&apartment_root)
                .wrap_err_with(|| format!("create {}", apartment_root.display()))?;
            write_json_atomic(&apartment_root.join("runtime_plan.json"), plan)?;
            if let Some(record) = view
                .world()
                .soracloud_agent_apartments()
                .get(apartment_name)
            {
                write_json_atomic(
                    &apartment_root.join("apartment_manifest.json"),
                    &record.manifest,
                )?;
            }
        }
        Ok(())
    }
    fn prune_stale_service_materializations(
        &self,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let desired: BTreeMap<String, BTreeSet<String>> = snapshot
            .services
            .iter()
            .map(|(service_name, versions)| {
                let desired_versions = versions
                    .keys()
                    .map(|version| storage_path_component(version))
                    .collect();
                (storage_path_component(service_name), desired_versions)
            })
            .collect();
        prune_nested_directory_tree(self.services_root().as_path(), &desired)?;
        Ok(())
    }
    fn prune_stale_apartment_materializations(
        &self,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let desired: BTreeSet<String> = snapshot
            .apartments
            .keys()
            .map(|name| storage_path_component(name))
            .collect();
        prune_flat_directory_tree(self.apartments_root().as_path(), &desired)?;
        Ok(())
    }
    fn hydrate_missing_artifacts(
        &self,
        view: &StateView<'_>,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let remote_sources = collect_remote_hydration_sources(view, &self.state)?;
        let mut required = BTreeMap::<String, (Hash, String, u64, bool)>::new();
        for versions in snapshot.services.values() {
            for plan in versions.values() {
                let operator_preseed_required = plan.runtime == SoraContainerRuntimeV1::Inrou
                    && !plan.local_replica_slots.is_empty();
                for artifact in &plan.artifacts {
                    if artifact.local_cache_path.len() > SORACLOUD_RUNTIME_ARTIFACT_PATH_MAX_BYTES
                        || artifact.artifact_path.len() > SORACLOUD_RUNTIME_ARTIFACT_PATH_MAX_BYTES
                    {
                        eyre::bail!(
                            "Soracloud runtime artifact path exceeds the {}-byte hydration limit",
                            SORACLOUD_RUNTIME_ARTIFACT_PATH_MAX_BYTES
                        );
                    }
                    let artifact_hash =
                        Hash::from_str(&artifact.artifact_hash).wrap_err_with(|| {
                            format!("parse Soracloud artifact hash `{}`", artifact.artifact_hash)
                        })?;
                    let maximum_bytes =
                        runtime_cache_budget_for_kind(artifact.kind, &self.config.cache_budgets);
                    match required.entry(artifact.local_cache_path.clone()) {
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            let existing = entry.get_mut();
                            if existing.0 != artifact_hash || existing.1 != artifact.artifact_path {
                                eyre::bail!(
                                    "Soracloud runtime snapshot maps cache path `{}` to conflicting artifact identities",
                                    artifact.local_cache_path
                                );
                            }
                            existing.2 = existing.2.min(maximum_bytes);
                            existing.3 |= operator_preseed_required;
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert((
                                artifact_hash,
                                artifact.artifact_path.clone(),
                                maximum_bytes,
                                operator_preseed_required,
                            ));
                        }
                    }
                    if required.len() > SORACLOUD_HYDRATION_MAX_REQUIRED_ARTIFACTS {
                        eyre::bail!(
                            "Soracloud runtime snapshot requires more than {} distinct hydrated artifacts",
                            SORACLOUD_HYDRATION_MAX_REQUIRED_ARTIFACTS
                        );
                    }
                }
            }
        }
        let tasks = required
            .into_iter()
            .filter_map(
                |(
                    local_cache_path,
                    (artifact_hash, artifact_path, maximum_bytes, operator_preseed_required),
                )| {
                    let cache_path = PathBuf::from(local_cache_path);
                    (operator_preseed_required
                        || verify_cached_soracloud_artifact(
                            &cache_path,
                            artifact_hash,
                            maximum_bytes,
                        )
                        .is_err())
                    .then_some(RequiredArtifactHydration {
                        cache_path,
                        artifact_hash,
                        artifact_path,
                        maximum_bytes,
                        operator_preseed_required,
                    })
                },
            )
            .collect::<Vec<_>>();
        run_bounded_hydration_tasks(&tasks, self.config.hydration_concurrency, |task| {
            self.hydrate_required_artifact(&remote_sources, task)
        })
    }
    fn hydrate_required_artifact(
        &self,
        remote_sources: &[RemoteHydrationSource],
        task: &RequiredArtifactHydration,
    ) -> eyre::Result<()> {
        if task.operator_preseed_required {
            if self.cached_artifact_has_operator_preseed_qualification(
                &task.cache_path,
                task.artifact_hash,
                task.maximum_bytes,
            )? {
                return Ok(());
            }
            if self.hydrate_operator_preseed_payload_to_cache(
                task.artifact_hash,
                &task.cache_path,
                task.maximum_bytes,
            )? {
                verify_cached_soracloud_artifact(
                    &task.cache_path,
                    task.artifact_hash,
                    task.maximum_bytes,
                )
                .map_err(|error| {
                    eyre::eyre!(
                        "verify qualified operator-preseed artifact `{}` at {}: {}",
                        task.artifact_path,
                        task.cache_path.display(),
                        error.message
                    )
                })?;
                return Ok(());
            }
            eyre::bail!(
                "locally assigned Inrou artifact `{}` has no exact current operator-preseed qualification; remote hydration fallback is forbidden",
                task.artifact_path
            );
        }
        if verify_cached_soracloud_artifact(
            &task.cache_path,
            task.artifact_hash,
            task.maximum_bytes,
        )
        .is_ok()
        {
            return Ok(());
        }
        if self.hydrate_local_sorafs_payload_to_cache(
            remote_sources,
            task.artifact_hash,
            &task.cache_path,
            task.maximum_bytes,
        )? {
            verify_cached_soracloud_artifact(
                &task.cache_path,
                task.artifact_hash,
                task.maximum_bytes,
            )
            .map_err(|error| {
                eyre::eyre!(
                    "verify streamed local Soracloud artifact `{}` at {}: {}",
                    task.artifact_path,
                    task.cache_path.display(),
                    error.message
                )
            })?;
            return Ok(());
        }
        let payload =
            self.read_committed_remote_sorafs_payload(remote_sources, task.artifact_hash)?;
        let Some(payload) = payload else {
            return Ok(());
        };
        if u64::try_from(payload.len()).unwrap_or(u64::MAX) > task.maximum_bytes {
            return Err(eyre::eyre!(
                "hydrated Soracloud artifact `{}` requires {} bytes, exceeding its configured {}-byte cache limit",
                task.artifact_path,
                payload.len(),
                task.maximum_bytes
            ));
        }
        write_bytes_atomic(&task.cache_path, &payload).wrap_err_with(|| {
            format!(
                "persist hydrated Soracloud artifact `{}` at {}",
                task.artifact_path,
                task.cache_path.display()
            )
        })?;
        verify_cached_soracloud_artifact(&task.cache_path, task.artifact_hash, task.maximum_bytes)
            .map_err(|error| {
                eyre::eyre!(
                    "verify hydrated Soracloud artifact `{}` at {} after persistence: {}",
                    task.artifact_path,
                    task.cache_path.display(),
                    error.message
                )
            })?;
        Ok(())
    }
    fn hydrate_local_sorafs_payload_to_cache(
        &self,
        remote_sources: &[RemoteHydrationSource],
        expected_hash: Hash,
        cache_path: &Path,
        maximum_bytes: u64,
    ) -> eyre::Result<bool> {
        if self.hydrate_operator_preseed_payload_to_cache(
            expected_hash,
            cache_path,
            maximum_bytes,
        )? {
            return Ok(true);
        }
        let Some(sorafs_node) = self.sorafs_node.as_ref() else {
            return Ok(false);
        };
        if !sorafs_node.is_enabled() {
            return Ok(false);
        }
        for source in remote_sources {
            let Ok(manifest_digest) = parse_sorafs_manifest_digest_hex(&source.manifest_digest_hex)
            else {
                continue;
            };
            let Ok(manifest) = sorafs_node.manifest_metadata_by_digest(&manifest_digest) else {
                continue;
            };
            let Ok(manifest_cid) = hex::decode(&source.manifest_cid_hex) else {
                continue;
            };
            if manifest.manifest_cid() != manifest_cid.as_slice()
                || manifest.content_length() == 0
                || manifest.content_length() > maximum_bytes
            {
                continue;
            }
            let manifest_id = manifest.manifest_id().to_owned();
            let write_result = write_verified_sorafs_manifest_payload_to_cache(
                &manifest,
                expected_hash,
                cache_path,
                maximum_bytes,
                |manifest_id, offset, len| {
                    sorafs_node
                        .read_payload_range(manifest_id, offset, len)
                        .map_err(|error| error.to_string())
                },
            );
            match write_result {
                Ok(()) => return Ok(true),
                Err(error) => {
                    iroha_logger::debug!(
                        ?error,
                        manifest_id = %manifest_id,
                        "local committed SoraFS payload did not match the requested Soracloud artifact"
                    );
                }
            }
        }
        Ok(false)
    }
    fn cached_artifact_has_operator_preseed_qualification(
        &self,
        cache_path: &Path,
        expected_hash: Hash,
        maximum_bytes: u64,
    ) -> eyre::Result<bool> {
        let Some(store) = self.operator_preseed_store.as_ref() else {
            return Ok(false);
        };
        let (mut file, fingerprint) =
            match open_verified_cached_soracloud_artifact(cache_path, expected_hash, maximum_bytes)
            {
                Ok(opened) => opened,
                Err(_) => return Ok(false),
            };
        if !store
            .manifests
            .values()
            .any(|qualified| qualified.content_length == fingerprint.bytes)
        {
            return Ok(false);
        }
        let mut payload_hasher = blake3::Hasher::new();
        let mut observed_bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).wrap_err_with(|| {
                format!(
                    "hash cached Soracloud artifact {} against operator-preseed qualification",
                    cache_path.display()
                )
            })?;
            if read == 0 {
                break;
            }
            observed_bytes = observed_bytes
                .checked_add(u64::try_from(read).expect("read length fits u64"))
                .ok_or_else(|| eyre::eyre!("cached operator-preseed byte count overflow"))?;
            if observed_bytes > maximum_bytes {
                eyre::bail!(
                    "cached Soracloud artifact {} exceeds its configured {}-byte limit while checking operator-preseed qualification",
                    cache_path.display(),
                    maximum_bytes
                );
            }
            payload_hasher.update(&buffer[..read]);
        }
        validate_opened_soracloud_artifact_after_read(
            &file,
            cache_path,
            &fingerprint,
            observed_bytes,
        )
        .map_err(|error| eyre::eyre!(error.message))?;
        let payload_digest = *payload_hasher.finalize().as_bytes();
        for (manifest_digest, qualified) in &store.manifests {
            if qualified.content_length == observed_bytes
                && qualified.payload_digest == payload_digest
            {
                store
                    .manifest_by_digest(manifest_digest)?
                    .expect("qualified manifest keys are present in the qualification map");
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn hydrate_operator_preseed_payload_to_cache(
        &self,
        expected_hash: Hash,
        cache_path: &Path,
        maximum_bytes: u64,
    ) -> eyre::Result<bool> {
        let Some(store) = self.operator_preseed_store.as_ref() else {
            return Ok(false);
        };
        for manifest_digest in store.manifests.keys() {
            let manifest = store
                .manifest_by_digest(manifest_digest)?
                .expect("qualified manifest keys are present in the qualification map");
            if manifest.content_length() == 0 || manifest.content_length() > maximum_bytes {
                continue;
            }
            let manifest_id = manifest.manifest_id().to_owned();
            let write_result = write_verified_sorafs_manifest_payload_to_cache(
                &manifest,
                expected_hash,
                cache_path,
                maximum_bytes,
                |manifest_id, offset, len| {
                    store
                        .backend
                        .read_payload_range(manifest_id, offset, len)
                        .map_err(|error| error.to_string())
                },
            );
            match write_result {
                Ok(()) => return Ok(true),
                Err(error) => {
                    iroha_logger::debug!(
                        ?error,
                        manifest_id = %manifest_id,
                        "operator-preseed SoraFS payload did not match the requested Soracloud artifact"
                    );
                }
            }
        }
        Ok(false)
    }
    fn read_committed_remote_sorafs_payload(
        &self,
        remote_sources: &[RemoteHydrationSource],
        expected_hash: Hash,
    ) -> eyre::Result<Option<Vec<u8>>> {
        let Some(_cache) = self.sorafs_provider_cache.as_ref() else {
            return Ok(None);
        };
        if remote_sources.is_empty() {
            return Ok(None);
        }
        for source in remote_sources {
            for provider_id in &source.provider_ids {
                let Some(provider) = self.acquire_remote_hydration_provider_session(provider_id)
                else {
                    continue;
                };
                let base_url = &provider.target.base_url;
                let client = match build_remote_hydration_http_client(base_url) {
                    Ok(client) => client,
                    Err(error) => {
                        iroha_logger::warn!(
                            ?error,
                            provider_id_hex = %hex::encode(provider_id),
                            base_url = %base_url,
                            "rejecting remote Soracloud hydration provider with unsafe or unpinnable DNS"
                        );
                        continue;
                    }
                };
                let Some(manifest) =
                    self.fetch_remote_manifest_metadata(&client, &base_url, source)
                else {
                    continue;
                };
                if let Some(expected_chunker) = source.chunker_handle.as_ref()
                    && manifest.chunker_handle.as_str() != expected_chunker.as_str()
                {
                    continue;
                }
                let Some(plan) = self.fetch_remote_hydration_plan(&client, &base_url, &manifest)
                else {
                    continue;
                };
                if plan.chunker_handle != manifest.chunker_handle {
                    continue;
                }
                let client_id = "soracloud-runtime-hydration";
                let nonce =
                    remote_hydration_nonce(&source.manifest_cid_hex, provider_id, expected_hash);
                let Some(stream_token) = self.fetch_remote_stream_token(
                    &client,
                    &base_url,
                    &source.manifest_cid_hex,
                    provider_id,
                    &plan,
                    client_id,
                    &nonce,
                ) else {
                    continue;
                };
                let Ok(capacity) = usize::try_from(plan.content_length) else {
                    iroha_logger::warn!(
                        manifest_digest = %source.manifest_digest_hex,
                        manifest_cid = %source.manifest_cid_hex,
                        provider_id_hex = %hex::encode(provider_id),
                        content_length = plan.content_length,
                        "skipping remote Soracloud hydration candidate with oversized payload"
                    );
                    continue;
                };
                let mut payload = Vec::new();
                if payload.try_reserve_exact(capacity).is_err() {
                    continue;
                }
                let mut cursor = 0_u64;
                let mut fetch_failed = false;
                for chunk in &plan.chunks {
                    if chunk.offset != cursor {
                        fetch_failed = true;
                        break;
                    }
                    let Some(bytes) = self.fetch_remote_chunk(
                        &client,
                        &base_url,
                        &plan,
                        chunk,
                        &stream_token,
                        client_id,
                        &nonce,
                    ) else {
                        fetch_failed = true;
                        break;
                    };
                    if bytes.len() != usize::try_from(chunk.length).unwrap_or(usize::MAX) {
                        fetch_failed = true;
                        break;
                    }
                    if blake3::hash(&bytes).as_bytes() != &chunk.digest {
                        fetch_failed = true;
                        break;
                    }
                    let Ok(bytes_len) = u64::try_from(bytes.len()) else {
                        fetch_failed = true;
                        break;
                    };
                    let Some(next_cursor) = cursor.checked_add(bytes_len) else {
                        fetch_failed = true;
                        break;
                    };
                    cursor = next_cursor;
                    payload.extend_from_slice(&bytes);
                }
                if fetch_failed || cursor != plan.content_length {
                    continue;
                }
                if verify_remote_hydration_payload(&payload, &plan, &manifest).is_err() {
                    continue;
                }
                if Hash::new(&payload) == expected_hash {
                    return Ok(Some(payload));
                }
            }
        }
        Ok(None)
    }
    #[cfg(test)]
    fn read_committed_remote_sorafs_directory_payload(
        &self,
        remote_sources: &[RemoteHydrationSource],
        manifest_digest_hex: &str,
        expected_manifest_cid: &[u8],
    ) -> eyre::Result<Option<(Vec<u8>, Vec<SorafsHydratedFileLayout>)>> {
        let Some(_cache) = self.sorafs_provider_cache.as_ref() else {
            return Ok(None);
        };
        if remote_sources.is_empty() {
            return Ok(None);
        }
        for source in remote_sources {
            if source.manifest_digest_hex.as_str() != manifest_digest_hex
                || source.manifest_cid_hex != hex::encode(expected_manifest_cid)
            {
                continue;
            }
            for provider_id in &source.provider_ids {
                let Some(provider) = self.acquire_remote_hydration_provider_session(provider_id)
                else {
                    continue;
                };
                let base_url = &provider.target.base_url;
                let client = match build_remote_hydration_http_client(base_url) {
                    Ok(client) => client,
                    Err(error) => {
                        iroha_logger::warn!(
                            ?error,
                            provider_id_hex = %hex::encode(provider_id),
                            base_url = %base_url,
                            "rejecting remote Soracloud directory hydration provider with unsafe or unpinnable DNS"
                        );
                        continue;
                    }
                };
                let Some(manifest) =
                    self.fetch_remote_manifest_metadata(&client, &base_url, source)
                else {
                    continue;
                };
                if let Some(expected_chunker) = source.chunker_handle.as_ref()
                    && manifest.chunker_handle.as_str() != expected_chunker.as_str()
                {
                    continue;
                }
                let Some(plan) = self.fetch_remote_hydration_plan(&client, &base_url, &manifest)
                else {
                    continue;
                };
                if plan.chunker_handle != manifest.chunker_handle {
                    continue;
                }
                let client_id = "soracloud-runtime-directory-hydration";
                let nonce = remote_hydration_nonce(
                    &source.manifest_cid_hex,
                    provider_id,
                    Hash::new(&manifest.manifest_digest),
                );
                let Some(stream_token) = self.fetch_remote_stream_token(
                    &client,
                    &base_url,
                    &source.manifest_cid_hex,
                    provider_id,
                    &plan,
                    client_id,
                    &nonce,
                ) else {
                    continue;
                };
                let Ok(capacity) = usize::try_from(plan.content_length) else {
                    continue;
                };
                let mut payload = Vec::new();
                if payload.try_reserve_exact(capacity).is_err() {
                    continue;
                }
                let mut cursor = 0_u64;
                let mut fetch_failed = false;
                for chunk in &plan.chunks {
                    if chunk.offset != cursor {
                        fetch_failed = true;
                        break;
                    }
                    let Some(bytes) = self.fetch_remote_chunk(
                        &client,
                        &base_url,
                        &plan,
                        chunk,
                        &stream_token,
                        client_id,
                        &nonce,
                    ) else {
                        fetch_failed = true;
                        break;
                    };
                    if bytes.len() != usize::try_from(chunk.length).unwrap_or(usize::MAX) {
                        fetch_failed = true;
                        break;
                    }
                    if blake3::hash(&bytes).as_bytes() != &chunk.digest {
                        fetch_failed = true;
                        break;
                    }
                    let Ok(bytes_len) = u64::try_from(bytes.len()) else {
                        fetch_failed = true;
                        break;
                    };
                    let Some(next_cursor) = cursor.checked_add(bytes_len) else {
                        fetch_failed = true;
                        break;
                    };
                    cursor = next_cursor;
                    payload.extend_from_slice(&bytes);
                }
                if fetch_failed || cursor != plan.content_length {
                    continue;
                }
                if verify_remote_hydration_payload(&payload, &plan, &manifest).is_err() {
                    continue;
                }
                let car_plan = remote_hydration_car_plan(&plan, &manifest)?;
                let files = canonical_remote_hydration_file_layouts(&plan, &car_plan)?;
                return Ok(Some((payload, files)));
            }
        }
        Ok(None)
    }
    #[cfg(unix)]
    #[cfg(any(target_os = "linux", test))]
    fn hydrate_operator_preseed_inrou_guest_image_artifact(
        &self,
        bundle_root: &PinnedInrouDirectory,
        plan: &SoracloudRuntimeInrouPlan,
        manifest_digest: [u8; 32],
        expected_manifest_cid: &[u8],
    ) -> eyre::Result<bool> {
        let Some(store) = self.operator_preseed_store.as_ref() else {
            return Ok(false);
        };
        let Some(manifest) = store.manifest_by_digest(&manifest_digest)? else {
            return Ok(false);
        };
        if manifest.manifest_cid() != expected_manifest_cid {
            eyre::bail!(
                "operator-preseed SoraFS manifest CID does not match the signed Inrou artifact reference"
            );
        }
        let files = manifest
            .files()
            .iter()
            .map(|file| SorafsHydratedFileLayout {
                path: file.path.clone(),
                offset: file.offset,
                size: file.size,
            })
            .collect::<Vec<_>>();
        validate_published_inrou_guest_image_files(plan, &files)?;
        let inrou_root = reset_inrou_child_directory(bundle_root, OsStr::new("inrou"), 0o700)
            .wrap_err("reset pinned Inrou guest-image materialization root")?;
        materialize_operator_preseed_sorafs_files(
            store.backend.as_ref(),
            &manifest,
            &files,
            &inrou_root,
            SORA_INROU_GUEST_IMAGE_MAX_MEMBERS_V1,
            self.config.inrou.guest_image_max_bytes.get(),
        )
        .wrap_err_with(|| {
            format!(
                "stream operator-preseed Inrou guest-image manifest {} into {}",
                hex::encode(manifest_digest),
                inrou_root.path().display()
            )
        })?;
        Ok(true)
    }
    fn ensure_trusted_inrou_guest_artifact_preseeded(&self) -> eyre::Result<()> {
        if !self.config.inrou.enabled {
            return Ok(());
        }
        let artifact = self
            .config
            .inrou
            .trusted_guest_artifact
            .as_ref()
            .ok_or_else(|| {
                eyre::eyre!("enabled Inrou hosting has no exact operator-approved guest artifact")
            })?;
        artifact
            .validate()
            .map_err(|error| eyre::eyre!("invalid trusted Inrou guest artifact: {error}"))?;
        let store = self.operator_preseed_store.as_ref().ok_or_else(|| {
            eyre::eyre!(
                "enabled Inrou hosting requires a disabled-provider operator-preseed SoraFS store"
            )
        })?;
        let manifest_digest = parse_sorafs_manifest_digest_hex(&artifact.manifest_digest_hex)?;
        let expected_manifest_cid = parse_canonical_sorafs_content_cid(&artifact.content_cid)?;
        let manifest = store.manifest_by_digest(&manifest_digest)?.ok_or_else(|| {
            eyre::eyre!(
                "operator-preseed store is missing or does not currently qualify trusted Inrou guest manifest {}",
                artifact.manifest_digest_hex
            )
        })?;
        if manifest.manifest_cid() != expected_manifest_cid {
            eyre::bail!(
                "operator-preseed trusted Inrou guest manifest CID does not match configured content CID"
            );
        }
        let guest_isa = current_host_inrou_guest_isa().ok_or_else(|| {
            eyre::eyre!("enabled Inrou hosting requires an x86_64 or AArch64 host")
        })?;
        let files = manifest
            .files()
            .iter()
            .map(|file| SorafsHydratedFileLayout {
                path: file.path.clone(),
                offset: file.offset,
                size: file.size,
            })
            .collect::<Vec<_>>();
        let initrd_member = vec![guest_isa.as_str().to_owned(), "initrd.img".to_owned()];
        let initrd_image_path = files
            .iter()
            .any(|file| file.path == initrd_member)
            .then(|| format!("/inrou/{}/initrd.img", guest_isa.as_str()));
        let host_plan = SoracloudRuntimeInrouPlan {
            selected_guest_isa: guest_isa,
            kernel_image_path: format!("/inrou/{}/vmlinux", guest_isa.as_str()),
            rootfs_image_path: format!("/inrou/{}/rootfs.ext4", guest_isa.as_str()),
            initrd_image_path,
            root_volume_name: "root_disk".to_owned(),
        };
        validate_published_inrou_guest_image_files(&host_plan, &files).wrap_err_with(|| {
            format!(
                "validate trusted Inrou guest artifact for host ISA `{}`",
                guest_isa.as_str()
            )
        })?;
        plan_operator_preseed_sorafs_files(
            &files,
            Path::new("/inrou"),
            manifest.content_length(),
            SORA_INROU_GUEST_IMAGE_MAX_MEMBERS_V1,
            self.config.inrou.guest_image_max_bytes.get(),
        )
        .wrap_err("validate trusted Inrou guest artifact physical layout")?;
        Ok(())
    }
    #[cfg(any(target_os = "linux", test))]
    #[cfg(unix)]
    fn hydrate_published_inrou_guest_image_artifact(
        &self,
        bundle_root: &PinnedInrouDirectory,
        bundle: &SoraDeploymentBundleV1,
        plan: &SoracloudRuntimeInrouPlan,
    ) -> eyre::Result<()> {
        let inrou =
            bundle.container.inrou.as_ref().ok_or_else(|| {
                eyre::eyre!("signed Inrou deployment bundle is missing its manifest")
            })?;
        let image = inrou
            .guest_images
            .get(&plan.selected_guest_isa)
            .ok_or_else(|| {
                eyre::eyre!(
                    "signed Inrou deployment bundle is missing selected guest ISA `{}`",
                    plan.selected_guest_isa.as_str()
                )
            })?;
        if image.kernel_image_path != plan.kernel_image_path
            || image.rootfs_image_path != plan.rootfs_image_path
            || image.initrd_image_path != plan.initrd_image_path
        {
            eyre::bail!(
                "selected Inrou runtime plan guest-image members do not match the signed deployment bundle"
            );
        }
        let artifact = &image.published_artifact;
        let trusted_artifact = self
            .config
            .inrou
            .trusted_guest_artifact
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Inrou host has no configured trusted guest artifact"))?;
        if artifact != trusted_artifact {
            eyre::bail!(
                "selected Inrou guest artifact does not match the operator-approved host artifact"
            );
        }
        let manifest_digest = parse_sorafs_manifest_digest_hex(&artifact.manifest_digest_hex)?;
        let manifest_cid = parse_canonical_sorafs_content_cid(&artifact.content_cid)?;
        if self.hydrate_operator_preseed_inrou_guest_image_artifact(
            bundle_root,
            plan,
            manifest_digest,
            &manifest_cid,
        )? {
            return Ok(());
        }
        Err(eyre::eyre!(
            "operator-preseed store is missing configured Inrou guest-image artifact {} for {}",
            artifact.manifest_digest_hex,
            plan.selected_guest_isa.as_str()
        ))
    }
    fn remote_hydration_provider_target(
        &self,
        provider_id: &[u8; 32],
    ) -> Option<RemoteHydrationProviderTarget> {
        let cache = self.sorafs_provider_cache.as_ref()?;
        let guard = cache.try_read().ok()?;
        let record = guard.record_by_provider(provider_id)?;
        let advert = record.advert();
        let now = current_unix_time_secs()?;
        if !provider_advert_is_fresh(advert, now) {
            return None;
        }
        let supports_torii_http_range = advert.body.transport_hints.as_ref().is_some_and(|hints| {
            hints
                .iter()
                .any(|hint| hint.protocol == TransportProtocol::ToriiHttpRange)
        });
        if !supports_torii_http_range {
            return None;
        }
        let endpoint = advert
            .body
            .endpoints
            .iter()
            .find(|endpoint| endpoint.kind == EndpointKind::Torii)?;
        let stream_budget = advert.body.stream_budget?;
        let maximum_concurrent_streams = advert
            .body
            .qos
            .max_concurrent_streams
            .min(stream_budget.max_in_flight);
        Some(RemoteHydrationProviderTarget {
            base_url: normalize_remote_provider_base_url(&endpoint.host_pattern)?,
            advert_issued_at: advert.issued_at,
            maximum_concurrent_streams: NonZeroUsize::new(usize::from(maximum_concurrent_streams))?,
        })
    }
    fn acquire_remote_hydration_provider_permit(
        &self,
        provider_id: &[u8; 32],
        advert_issued_at: u64,
        maximum_concurrent_streams: NonZeroUsize,
    ) -> Option<RemoteHydrationProviderPermit> {
        let gate = {
            let mut gates = self.remote_hydration_provider_gates.lock();
            if let Some(gate) = gates.get(provider_id) {
                Arc::clone(gate)
            } else {
                // Provider churn must not make this registry append-only.
                // Active permits and waiters own another `Arc`; idle entries
                // are reconstructed from the currently admitted advert.
                gates.retain(|_, gate| Arc::strong_count(gate) > 1);
                let gate = Arc::new(RemoteHydrationProviderGate::new(
                    advert_issued_at,
                    maximum_concurrent_streams,
                ));
                gates.insert(*provider_id, Arc::clone(&gate));
                gate
            }
        };
        gate.acquire(advert_issued_at, maximum_concurrent_streams)
    }
    fn acquire_remote_hydration_provider_session(
        &self,
        provider_id: &[u8; 32],
    ) -> Option<RemoteHydrationProviderSession> {
        self.acquire_remote_hydration_provider_session_inner(provider_id, |_, _| {})
    }
    fn acquire_remote_hydration_provider_session_inner<F>(
        &self,
        provider_id: &[u8; 32],
        mut after_resolve: F,
    ) -> Option<RemoteHydrationProviderSession>
    where
        F: FnMut(usize, &RemoteHydrationProviderTarget),
    {
        for attempt in 0..2 {
            let target = self.remote_hydration_provider_target(provider_id)?;
            after_resolve(attempt, &target);
            let Some(permit) = self.acquire_remote_hydration_provider_permit(
                provider_id,
                target.advert_issued_at,
                target.maximum_concurrent_streams,
            ) else {
                continue;
            };
            if self.remote_hydration_provider_target(provider_id).as_ref() == Some(&target) {
                return Some(RemoteHydrationProviderSession {
                    target,
                    _permit: permit,
                });
            }
        }
        None
    }
    fn remote_hydration_payload_limit(&self) -> u64 {
        [
            self.config.cache_budgets.bundle_bytes.get(),
            self.config.cache_budgets.static_asset_bytes.get(),
            self.config.cache_budgets.journal_bytes.get(),
            self.config.cache_budgets.checkpoint_bytes.get(),
            self.config.cache_budgets.model_artifact_bytes.get(),
            self.config.cache_budgets.model_weight_bytes.get(),
        ]
        .into_iter()
        .max()
        .expect("Soracloud runtime cache budgets are nonempty")
    }
    fn in_memory_hydration_payload_limit(&self) -> u64 {
        self.remote_hydration_payload_limit()
            .min(SORACLOUD_REMOTE_HYDRATION_MAX_IN_MEMORY_PAYLOAD_BYTES)
    }
    fn fetch_remote_manifest_metadata(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        source: &RemoteHydrationSource,
    ) -> Option<VerifiedRemoteManifest> {
        let mut url = match base_url.join(&format!(
            "v1/sorafs/storage/manifest/{}",
            source.manifest_cid_hex
        )) {
            Ok(url) => url,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    base_url = %base_url,
                    manifest_cid = %source.manifest_cid_hex,
                    "failed to build remote Soracloud hydration manifest URL"
                );
                return None;
            }
        };
        url.query_pairs_mut().append_pair("limit", "1");
        let response = match client.get(url.clone()).send() {
            Ok(response) => response,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "remote Soracloud hydration manifest request failed"
                );
                return None;
            }
        };
        if !response.status().is_success() {
            return None;
        }
        let body = match read_soracloud_http_response_bounded(
            response,
            SORACLOUD_REMOTE_MANIFEST_MAX_RESPONSE_BYTES,
            "remote Soracloud hydration manifest",
        ) {
            Ok(body) => body,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to read remote Soracloud hydration manifest body"
                );
                return None;
            }
        };
        match norito::json::from_slice::<StorageManifestResponseDto>(&body) {
            Ok(dto) => validate_remote_manifest_response(
                source,
                dto,
                self.in_memory_hydration_payload_limit(),
            )
            .inspect_err(|error| {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "remote Soracloud hydration manifest failed canonical validation"
                );
            })
            .ok(),
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to decode remote Soracloud hydration manifest response"
                );
                None
            }
        }
    }
    fn fetch_remote_hydration_plan(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        manifest: &VerifiedRemoteManifest,
    ) -> Option<RemoteHydrationPlan> {
        fetch_remote_hydration_plan_pages(
            client,
            base_url,
            manifest,
            SORA_INROU_GUEST_IMAGE_MAX_MEMBERS_V1,
        )
        .inspect_err(|error| {
            iroha_logger::debug!(
                ?error,
                base_url = %base_url,
                manifest_id = %manifest.manifest_id_hex,
                "failed to fetch complete remote Soracloud hydration plan"
            );
        })
        .ok()
    }
    fn fetch_remote_stream_token(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        manifest_id_hex: &str,
        provider_id: &[u8; 32],
        plan: &RemoteHydrationPlan,
        client_id: &str,
        nonce: &str,
    ) -> Option<String> {
        let url = match base_url.join("v1/sorafs/storage/token") {
            Ok(url) => url,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    base_url = %base_url,
                    "failed to build remote Soracloud hydration token URL"
                );
                return None;
            }
        };
        let max_chunk_len = plan
            .chunks
            .iter()
            .map(|chunk| u64::from(chunk.length))
            .max()
            .unwrap_or(0);
        let request = match remote_stream_token_auth::build_request(
            client,
            self.remote_stream_token_operator.as_ref(),
            url.clone(),
            manifest_id_hex,
            provider_id,
            max_chunk_len,
            plan.chunks.len(),
            client_id,
            nonce,
        ) {
            Ok(request) => request,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to build authenticated remote Soracloud hydration token request"
                );
                return None;
            }
        };
        let response = match client.execute(request) {
            Ok(response) => response,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "remote Soracloud hydration token request failed"
                );
                return None;
            }
        };
        if !response.status().is_success() {
            return None;
        }
        let body = match read_soracloud_http_response_bounded(
            response,
            SORACLOUD_REMOTE_STREAM_TOKEN_MAX_RESPONSE_BYTES,
            "remote Soracloud hydration token",
        ) {
            Ok(body) => body,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to read remote Soracloud hydration token body"
                );
                return None;
            }
        };
        let value: norito::json::Value = match norito::json::from_slice(&body) {
            Ok(value) => value,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to decode remote Soracloud hydration token response"
                );
                return None;
            }
        };
        value
            .get("token_base64")
            .and_then(norito::json::Value::as_str)
            .map(ToOwned::to_owned)
    }
    fn fetch_remote_chunk(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        plan: &RemoteHydrationPlan,
        chunk: &RemoteHydrationChunk,
        stream_token: &str,
        client_id: &str,
        nonce: &str,
    ) -> Option<Vec<u8>> {
        let expected_length = u64::from(chunk.length);
        if expected_length == 0 || expected_length > SORACLOUD_REMOTE_CHUNK_MAX_RESPONSE_BYTES {
            iroha_logger::debug!(
                chunk_length = expected_length,
                maximum = SORACLOUD_REMOTE_CHUNK_MAX_RESPONSE_BYTES,
                "remote Soracloud hydration chunk length is outside the supported range"
            );
            return None;
        }
        let chunk_digest_hex = hex::encode(chunk.digest);
        let url = match base_url.join(&format!(
            "v1/sorafs/storage/chunk/{}/{}",
            plan.manifest_id_hex, chunk_digest_hex
        )) {
            Ok(url) => url,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    base_url = %base_url,
                    manifest_id = %plan.manifest_id_hex,
                    chunk_digest = %chunk_digest_hex,
                    "failed to build remote Soracloud hydration chunk URL"
                );
                return None;
            }
        };
        let response = match client
            .get(url.clone())
            .header("X-SoraFS-Stream-Token", stream_token)
            .header("X-SoraFS-Chunker", &plan.chunker_handle)
            .header("X-SoraFS-Client", client_id)
            .header("X-SoraFS-Nonce", nonce)
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "remote Soracloud hydration chunk request failed"
                );
                return None;
            }
        };
        if !response.status().is_success() {
            return None;
        }
        match read_soracloud_http_response_bounded(
            response,
            expected_length,
            "remote Soracloud hydration chunk",
        ) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                iroha_logger::debug!(
                    ?error,
                    url = %url,
                    "failed to read remote Soracloud hydration chunk body"
                );
                None
            }
        }
    }
    fn enforce_cache_budgets(
        &self,
        view: &StateView<'_>,
        snapshot: &SoracloudRuntimeSnapshot,
    ) -> eyre::Result<()> {
        let artifact_observations = collect_artifact_cache_observations(view, snapshot)?;
        let artifact_candidates = collect_artifact_cache_candidates(
            self.artifacts_root().as_path(),
            &artifact_observations,
        )?;
        let journal_sequences = collect_runtime_receipt_artifact_sequences(view, |receipt| {
            receipt.journal_artifact_hash
        })?;
        let checkpoint_sequences = collect_runtime_receipt_artifact_sequences(view, |receipt| {
            receipt.checkpoint_artifact_hash
        })?;
        prune_cache_bucket(
            artifact_candidates.bundle,
            self.config.cache_budgets.bundle_bytes.get(),
        )?;
        prune_cache_bucket(
            artifact_candidates.static_asset,
            self.config.cache_budgets.static_asset_bytes.get(),
        )?;
        let mut journal_candidates = artifact_candidates.journal;
        journal_candidates.extend(collect_fixed_bucket_candidates(
            self.journals_root().as_path(),
            "journals",
            &journal_sequences,
        )?);
        prune_cache_bucket(
            journal_candidates,
            self.config.cache_budgets.journal_bytes.get(),
        )?;
        let mut checkpoint_candidates = artifact_candidates.checkpoint;
        checkpoint_candidates.extend(collect_fixed_bucket_candidates(
            self.checkpoints_root().as_path(),
            "checkpoints",
            &checkpoint_sequences,
        )?);
        prune_cache_bucket(
            checkpoint_candidates,
            self.config.cache_budgets.checkpoint_bytes.get(),
        )?;
        prune_cache_bucket(
            artifact_candidates.model_artifact,
            self.config.cache_budgets.model_artifact_bytes.get(),
        )?;
        prune_cache_bucket(
            artifact_candidates.model_weight,
            self.config.cache_budgets.model_weight_bytes.get(),
        )?;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheObservationMetadata {
    bucket: RuntimeCacheBucket,
    observation_sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RuntimeCacheBucket {
    Bundle,
    StaticAsset,
    Journal,
    Checkpoint,
    ModelArtifact,
    ModelWeight,
}
impl RuntimeCacheBucket {
    const fn priority(self) -> u8 {
        match self {
            Self::Bundle => 5,
            Self::ModelWeight => 4,
            Self::ModelArtifact => 3,
            Self::Journal => 2,
            Self::Checkpoint => 2,
            Self::StaticAsset => 1,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct CachePruneCandidate {
    path: PathBuf,
    stable_key: String,
    bytes: u64,
    observation_sequence: u64,
}
#[derive(Default)]
struct ArtifactCacheCandidates {
    bundle: Vec<CachePruneCandidate>,
    static_asset: Vec<CachePruneCandidate>,
    journal: Vec<CachePruneCandidate>,
    checkpoint: Vec<CachePruneCandidate>,
    model_artifact: Vec<CachePruneCandidate>,
    model_weight: Vec<CachePruneCandidate>,
}
impl ArtifactCacheCandidates {
    fn bucket_mut(&mut self, bucket: RuntimeCacheBucket) -> &mut Vec<CachePruneCandidate> {
        match bucket {
            RuntimeCacheBucket::Bundle => &mut self.bundle,
            RuntimeCacheBucket::StaticAsset => &mut self.static_asset,
            RuntimeCacheBucket::Journal => &mut self.journal,
            RuntimeCacheBucket::Checkpoint => &mut self.checkpoint,
            RuntimeCacheBucket::ModelArtifact => &mut self.model_artifact,
            RuntimeCacheBucket::ModelWeight => &mut self.model_weight,
        }
    }
}
fn collect_artifact_cache_observations(
    view: &StateView<'_>,
    snapshot: &SoracloudRuntimeSnapshot,
) -> eyre::Result<BTreeMap<String, CacheObservationMetadata>> {
    let world = view.world();
    let mut observations = BTreeMap::new();
    for (service_name, deployment) in world.soracloud_service_deployments().iter() {
        let service_name = service_name.to_string();
        let Some(versions) = snapshot.services.get(&service_name) else {
            continue;
        };
        for (_service_version, plan) in versions {
            let observation_sequence = match plan.role {
                SoracloudRuntimeRevisionRole::Active => deployment.process_started_sequence,
                SoracloudRuntimeRevisionRole::CanaryCandidate => deployment
                    .active_rollout
                    .as_ref()
                    .map_or(deployment.process_started_sequence, |rollout| {
                        rollout.updated_sequence
                    }),
            };
            for artifact in &plan.artifacts {
                upsert_cache_observation(
                    &mut observations,
                    sanitize_path_component(&artifact.artifact_hash),
                    runtime_cache_bucket_for_kind(artifact.kind),
                    observation_sequence,
                )?;
            }
        }
    }
    for (_, record) in world.soracloud_model_weight_versions().iter() {
        upsert_cache_observation(
            &mut observations,
            hash_cache_name(record.weight_artifact_hash),
            RuntimeCacheBucket::ModelWeight,
            record
                .promoted_sequence
                .unwrap_or(record.registered_sequence),
        )?;
    }
    for (_, record) in world.soracloud_model_artifacts().iter() {
        upsert_cache_observation(
            &mut observations,
            hash_cache_name(record.weight_artifact_hash),
            RuntimeCacheBucket::ModelArtifact,
            record.registered_sequence,
        )?;
    }
    Ok(observations)
}
fn runtime_cache_bucket_for_kind(kind: SoraArtifactKindV1) -> RuntimeCacheBucket {
    match kind {
        SoraArtifactKindV1::Bundle => RuntimeCacheBucket::Bundle,
        SoraArtifactKindV1::StaticAsset => RuntimeCacheBucket::StaticAsset,
        SoraArtifactKindV1::Journal => RuntimeCacheBucket::Journal,
        SoraArtifactKindV1::Checkpoint => RuntimeCacheBucket::Checkpoint,
        SoraArtifactKindV1::ModelArtifact => RuntimeCacheBucket::ModelArtifact,
        SoraArtifactKindV1::ModelWeights => RuntimeCacheBucket::ModelWeight,
    }
}
fn upsert_cache_observation(
    observations: &mut BTreeMap<String, CacheObservationMetadata>,
    key: String,
    bucket: RuntimeCacheBucket,
    observation_sequence: u64,
) -> eyre::Result<()> {
    if !observations.contains_key(&key)
        && observations.len() >= SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
    {
        eyre::bail!(
            "Soracloud artifact observations exceed the {}-entry reconciliation limit",
            SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
        );
    }
    match observations.entry(key) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let existing = entry.get_mut();
            existing.observation_sequence = existing.observation_sequence.max(observation_sequence);
            if bucket.priority() > existing.bucket.priority() {
                existing.bucket = bucket;
            }
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(CacheObservationMetadata {
                bucket,
                observation_sequence,
            });
        }
    }
    Ok(())
}
fn collect_artifact_cache_candidates(
    root: &Path,
    observations: &BTreeMap<String, CacheObservationMetadata>,
) -> eyre::Result<ArtifactCacheCandidates> {
    let mut candidates = ArtifactCacheCandidates::default();
    if !root.exists() {
        return Ok(candidates);
    }
    let mut scanned_entries = 0_usize;
    for entry in fs::read_dir(root).wrap_err_with(|| format!("read {}", root.display()))? {
        let entry = entry?;
        scanned_entries = scanned_entries.saturating_add(1);
        if scanned_entries > SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES {
            eyre::bail!(
                "Soracloud artifact cache {} exceeds the {}-entry reconciliation limit",
                root.display(),
                SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
            );
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let observation =
            observations
                .get(&file_name)
                .copied()
                .unwrap_or(CacheObservationMetadata {
                    bucket: RuntimeCacheBucket::StaticAsset,
                    observation_sequence: 0,
                });
        candidates
            .bucket_mut(observation.bucket)
            .push(CachePruneCandidate {
                path: entry.path(),
                stable_key: format!("artifacts/{file_name}"),
                bytes: entry.metadata()?.len(),
                observation_sequence: observation.observation_sequence,
            });
    }
    Ok(candidates)
}
fn collect_runtime_receipt_artifact_sequences(
    view: &StateView<'_>,
    select_hash: impl Fn(&SoraRuntimeReceiptV1) -> Option<Hash>,
) -> eyre::Result<BTreeMap<String, u64>> {
    let mut sequences = BTreeMap::new();
    for (_, receipt) in view.world().soracloud_runtime_receipts().iter() {
        let Some(hash) = select_hash(receipt) else {
            continue;
        };
        let key = hash_cache_name(hash);
        if !sequences.contains_key(&key)
            && sequences.len() >= SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
        {
            eyre::bail!(
                "Soracloud runtime receipt artifact observations exceed the {}-entry reconciliation limit",
                SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
            );
        }
        sequences
            .entry(key)
            .and_modify(|sequence: &mut u64| {
                *sequence = (*sequence).max(receipt.emitted_sequence);
            })
            .or_insert(receipt.emitted_sequence);
    }
    Ok(sequences)
}
fn collect_fixed_bucket_candidates(
    root: &Path,
    bucket_name: &str,
    observation_sequences: &BTreeMap<String, u64>,
) -> eyre::Result<Vec<CachePruneCandidate>> {
    let mut candidates = Vec::new();
    if !root.exists() {
        return Ok(candidates);
    }
    for (index, entry) in fs::read_dir(root)
        .wrap_err_with(|| format!("read {}", root.display()))?
        .enumerate()
    {
        if index >= SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES {
            eyre::bail!(
                "Soracloud {bucket_name} cache {} exceeds the {}-entry reconciliation limit",
                root.display(),
                SORACLOUD_ARTIFACT_CACHE_MAX_DIRECTORY_ENTRIES
            );
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        candidates.push(CachePruneCandidate {
            path: entry.path(),
            stable_key: format!("{bucket_name}/{file_name}"),
            bytes: entry.metadata()?.len(),
            observation_sequence: observation_sequences.get(&file_name).copied().unwrap_or(0),
        });
    }
    Ok(candidates)
}
fn prune_cache_bucket(
    mut candidates: Vec<CachePruneCandidate>,
    budget_bytes: u64,
) -> eyre::Result<()> {
    let mut retained_bytes = candidates.iter().fold(0u64, |total, candidate| {
        total.saturating_add(candidate.bytes)
    });
    if retained_bytes <= budget_bytes {
        return Ok(());
    }
    candidates.sort_by(|left, right| {
        left.observation_sequence
            .cmp(&right.observation_sequence)
            .then_with(|| left.stable_key.cmp(&right.stable_key))
    });
    for candidate in candidates {
        if retained_bytes <= budget_bytes {
            break;
        }
        fs::remove_file(&candidate.path).wrap_err_with(|| {
            format!("prune Soracloud runtime cache {}", candidate.path.display())
        })?;
        retained_bytes = retained_bytes.saturating_sub(candidate.bytes);
    }
    Ok(())
}
fn execute_asset_local_read(
    request: &SoracloudLocalReadRequest,
    context: &ResolvedLocalReadContext,
    state_dir: &Path,
    maximum_artifact_bytes: u64,
) -> Result<SoracloudLocalReadResponse, SoracloudRuntimeExecutionError> {
    let Some(artifact) =
        resolve_asset_artifact(&context.bundle, &context.handler, &request.handler_path)
    else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "asset handler `{}` on service `{}` cannot resolve request path `{}`",
                context.handler.handler_name, request.service_name, request.handler_path
            ),
        ));
    };
    let cache_path = state_dir
        .join("artifacts")
        .join(hash_cache_name(artifact.artifact_hash));
    let response_bytes = read_and_verify_cached_artifact(
        &cache_path,
        artifact.artifact_hash,
        maximum_artifact_bytes,
    )?;
    let result_commitment = asset_result_commitment(artifact.artifact_hash, &response_bytes);
    let runtime_receipt = match context.handler.certified_response {
        SoraCertifiedResponsePolicyV1::AuditReceipt => Some(local_read_receipt(
            request,
            &context.deployment,
            &context.handler,
            result_commitment,
            context.handler.certified_response,
            None,
        )),
        SoraCertifiedResponsePolicyV1::StateCommitment => None,
        SoraCertifiedResponsePolicyV1::None => {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::InvalidRequest,
                format!(
                    "asset handler `{}` cannot serve an uncertified fast-path response",
                    context.handler.handler_name
                ),
            ));
        }
    };
    Ok(SoracloudLocalReadResponse {
        response_bytes,
        content_type: Some(content_type_for_path(&artifact.artifact_path).to_owned()),
        content_encoding: None,
        cache_control: Some("public, max-age=60".to_owned()),
        bindings: vec![iroha_core::soracloud_runtime::SoracloudLocalReadBinding {
            binding_name: None,
            state_key: None,
            payload_commitment: None,
            artifact_hash: Some(artifact.artifact_hash),
        }],
        result_commitment,
        certified_by: context.handler.certified_response,
        runtime_receipt,
    })
}
fn execute_query_local_read(
    view: &StateView<'_>,
    request: &SoracloudLocalReadRequest,
    context: &ResolvedLocalReadContext,
    state_dir: &Path,
    ivm_runtime_cache: &SoracloudPreparedRuntimeCache,
) -> Result<SoracloudLocalReadResponse, SoracloudRuntimeExecutionError> {
    let bundle_cache_path = state_dir
        .join("artifacts")
        .join(hash_cache_name(context.bundle.container.bundle_hash));
    let prepared = ivm_runtime_cache
        .prepare(&bundle_cache_path, context.bundle.container.bundle_hash)
        .map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                error.kind,
                format!(
                    "prepare Soracloud query bundle for service `{}` revision `{}`: {}",
                    request.service_name, request.service_version, error.message,
                ),
            )
        })?;
    if prepared
        .prepared
        .entrypoint_descriptor(context.handler.entrypoint.as_ref())
        .is_none()
    {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "query handler `{}` on service `{}` revision `{}` is missing entrypoint `{}`",
                context.handler.handler_name,
                request.service_name,
                request.service_version,
                context.handler.entrypoint,
            ),
        ));
    }
    let mut vm = ivm_runtime_cache.checkout(&prepared).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            error.kind,
            format!(
                "checkout Soracloud query runtime for service `{}` revision `{}`: {}",
                request.service_name, request.service_version, error.message,
            ),
        )
    })?;
    let body_tlv = local_read_request_body_tlv_bytes(request).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "encode Soracloud query body for service `{}` handler `{}`: {}",
                request.service_name,
                request.handler_name,
                vm_error_label(&error),
            ),
        )
    })?;
    let metadata_tlv = local_read_request_metadata_tlv_bytes(request)?;
    let public_inputs = local_read_public_inputs(&body_tlv, &metadata_tlv, request.observed_height)
        .map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                vm_error_kind(&error),
                format!(
                    "prepare Soracloud query public inputs for service `{}` handler `{}`: {}",
                    request.service_name,
                    request.handler_name,
                    vm_error_label(&error),
                ),
            )
        })?;
    let (arguments, output_kind) = prepare_soracloud_invocation(
        &mut vm,
        &prepared.prepared,
        context.handler.entrypoint.as_ref(),
        SoracloudInvocationInput {
            body_tlv: &body_tlv,
            metadata_tlv: Some(&metadata_tlv),
            execution_sequence: None,
            observed_height: request.observed_height,
        },
    )
    .map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "prepare Soracloud query arguments for service `{}` handler `{}`: {}",
                request.service_name,
                request.handler_name,
                vm_error_label(&error),
            ),
        )
    })?;
    let committed_entries =
        collect_committed_service_state_entries(view, request.service_name.as_str());
    let host = SoracloudIvmHost::new(
        local_read_execution_request(view, request, context),
        state_dir.to_path_buf(),
        committed_entries,
    )
    .with_public_inputs(public_inputs)
    .with_prepared_arguments(arguments);
    vm.set_host(host);
    vm.run().map_err(|error| {
        let error_label = vm_error_label(&error);
        let error_detail = vm
            .last_diagnostic()
            .and_then(|diagnostic| diagnostic.context.syscall)
            .map_or_else(
                || error_label.to_owned(),
                |syscall| format!("{error_label}(0x{syscall:02x})"),
            );
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "execute Soracloud query handler `{}` on service `{}` revision `{}`: {}",
                context.handler.handler_name,
                request.service_name,
                request.service_version,
                error_detail,
            ),
        )
    })?;
    let (response_bytes, content_type) =
        decode_local_read_vm_output(&vm, output_kind, request, context)?;
    let Some(host) = vm
        .host_mut_any()
        .and_then(|host| host.downcast_mut::<SoracloudIvmHost>())
    else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "local Soracloud query host for service `{}` handler `{}` is unavailable after execution",
                request.service_name, request.handler_name
            ),
        ));
    };
    if host.has_local_read_side_effects() {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "query handler `{}` on service `{}` attempted to mutate Soracloud runtime state during a public local read",
                context.handler.handler_name, request.service_name
            ),
        ));
    }
    let bindings = host.local_read_bindings();
    let result_commitment = Hash::new(&response_bytes);
    let runtime_receipt = match context.handler.certified_response {
        SoraCertifiedResponsePolicyV1::AuditReceipt => Some(local_read_receipt(
            request,
            &context.deployment,
            &context.handler,
            result_commitment,
            context.handler.certified_response,
            None,
        )),
        SoraCertifiedResponsePolicyV1::StateCommitment => None,
        SoraCertifiedResponsePolicyV1::None => {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::InvalidRequest,
                format!(
                    "query handler `{}` cannot serve an uncertified fast-path response",
                    context.handler.handler_name
                ),
            ));
        }
    };
    Ok(SoracloudLocalReadResponse {
        response_bytes,
        content_type,
        content_encoding: None,
        cache_control: Some("no-store".to_owned()),
        bindings,
        result_commitment,
        certified_by: context.handler.certified_response,
        runtime_receipt,
    })
}
fn local_read_execution_request(
    view: &StateView<'_>,
    request: &SoracloudLocalReadRequest,
    context: &ResolvedLocalReadContext,
) -> SoracloudOrderedMailboxExecutionRequest {
    let observed_sequence =
        iroha_core::soracloud_runtime::authoritative_soracloud_sequence(view.world());
    let mut mailbox_message = SoraServiceMailboxMessageV1 {
        schema_version: SORA_SERVICE_MAILBOX_MESSAGE_VERSION_V1,
        message_id: Hash::prehashed([0; Hash::LENGTH]),
        from_service: context.deployment.service_name.clone(),
        from_service_version: context.deployment.current_service_version.clone(),
        from_handler: context.handler.handler_name.clone(),
        to_service: context.deployment.service_name.clone(),
        to_service_version: context.deployment.current_service_version.clone(),
        to_handler: context.handler.handler_name.clone(),
        payload_bytes: request.request_body.clone(),
        payload_commitment: request.request_commitment,
        delivery_delay_blocks: 0,
        enqueue_sequence: observed_sequence,
        enqueue_height: request.observed_height,
        available_after_height: request.observed_height,
        expires_at_height: request.observed_height.saturating_add(1),
    };
    mailbox_message.message_id = derive_soracloud_mailbox_message_id_v1(&mailbox_message);
    SoracloudOrderedMailboxExecutionRequest {
        observed_height: request.observed_height,
        observed_block_hash: request.observed_block_hash,
        observed_sequence,
        deployment: context.deployment.clone(),
        bundle: context.bundle.clone(),
        handler: Some(context.handler.clone()),
        mailbox_message,
        runtime_state: None,
        authoritative_pending_mailbox_messages: 0,
    }
}
fn local_read_request_body_tlv_bytes(
    request: &SoracloudLocalReadRequest,
) -> Result<Vec<u8>, VMError> {
    mailbox_payload_tlv_bytes(&request.request_body)
}
fn local_read_request_metadata_tlv_bytes(
    request: &SoracloudLocalReadRequest,
) -> Result<Vec<u8>, SoracloudRuntimeExecutionError> {
    let request_headers = request
        .request_headers
        .iter()
        .map(|(key, value)| (key.clone(), norito::json::Value::from(value.clone())))
        .collect::<norito::json::Map>();
    let mut metadata = norito::json::Map::new();
    metadata.insert(
        "schema_version".to_owned(),
        norito::json::Value::from(u64::from(1_u16)),
    );
    metadata.insert(
        "observed_height".to_owned(),
        norito::json::Value::from(request.observed_height),
    );
    metadata.insert(
        "observed_block_hash".to_owned(),
        request
            .observed_block_hash
            .map(|hash| norito::json::Value::from(hash.to_string()))
            .unwrap_or(norito::json::Value::Null),
    );
    metadata.insert(
        "service_name".to_owned(),
        norito::json::Value::from(request.service_name.clone()),
    );
    metadata.insert(
        "service_version".to_owned(),
        norito::json::Value::from(request.service_version.clone()),
    );
    metadata.insert(
        "handler_name".to_owned(),
        norito::json::Value::from(request.handler_name.clone()),
    );
    metadata.insert(
        "request_method".to_owned(),
        norito::json::Value::from(request.request_method.clone()),
    );
    metadata.insert(
        "request_path".to_owned(),
        norito::json::Value::from(request.request_path.clone()),
    );
    metadata.insert(
        "handler_path".to_owned(),
        norito::json::Value::from(request.handler_path.clone()),
    );
    metadata.insert(
        "request_query".to_owned(),
        request
            .request_query
            .clone()
            .map(norito::json::Value::from)
            .unwrap_or(norito::json::Value::Null),
    );
    metadata.insert(
        "request_headers".to_owned(),
        norito::json::Value::Object(request_headers),
    );
    metadata.insert(
        "request_commitment".to_owned(),
        norito::json::Value::from(request.request_commitment.to_string()),
    );
    metadata.insert(
        "request_body_bytes".to_owned(),
        norito::json::Value::from(u64::try_from(request.request_body.len()).unwrap_or(u64::MAX)),
    );
    metadata.insert(
        "request_body_is_tlv".to_owned(),
        norito::json::Value::from(
            ivm::pointer_abi::validate_tlv_bytes(&request.request_body).is_ok(),
        ),
    );
    let metadata_value = norito::json::Value::Object(metadata);
    let metadata_json = soracloud_codec_attempt(|| Json::from_norito_value_ref(&metadata_value));
    let metadata_json = metadata_json.map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "serialize Soracloud query metadata JSON for service `{}` handler `{}`: {error}",
                request.service_name, request.handler_name
            ),
        )
    })?;
    let metadata_bytes = soracloud_canonical_frame(
        &metadata_json,
        iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES,
    )
    .map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "serialize Soracloud query metadata for service `{}` handler `{}`: {error}",
                request.service_name, request.handler_name
            ),
        )
    })?;
    ivm::pointer_abi::encode_tlv(PointerType::Json, &metadata_bytes).map_err(|error| {
        SoracloudRuntimeExecutionError::new(vm_error_kind(&error), vm_error_label(&error))
    })
}
fn public_input_name(name: &str) -> Result<Name, VMError> {
    Name::from_str(name).map_err(|_| VMError::NoritoInvalid)
}
fn public_input_int_tlv(value: u64) -> Result<Vec<u8>, VMError> {
    let ivm::EntrypointValueAtomV1::Pointer(bytes) = soracloud_integer_atom(value)? else {
        return Err(VMError::DecodeError);
    };
    Ok(bytes)
}
fn insert_public_input(
    inputs: &mut BTreeMap<Name, Vec<u8>>,
    name: &str,
    value: Vec<u8>,
) -> Result<(), VMError> {
    inputs.insert(public_input_name(name)?, value);
    Ok(())
}
fn pointer_tlv_payload(tlv_bytes: &[u8]) -> &[u8] {
    ivm::pointer_abi::validate_tlv_bytes(tlv_bytes)
        .map(|tlv| tlv.payload)
        .unwrap_or(tlv_bytes)
}
fn json_value_from_tlv(tlv_bytes: &[u8]) -> Result<norito::json::Value, VMError> {
    let tlv = ivm::pointer_abi::validate_tlv_bytes(tlv_bytes).map_err(|_| VMError::DecodeError)?;
    if tlv.type_id != PointerType::Json {
        return Err(VMError::DecodeError);
    }
    let json = soracloud_codec_attempt(|| norito::decode_canonical::<Json>(tlv.payload))?;
    soracloud_codec_attempt(|| json.try_into_any_norito::<norito::json::Value>())
}
fn json_pointer_response_payload(payload: &[u8]) -> Result<Vec<u8>, VMError> {
    let json = soracloud_codec_attempt(|| norito::decode_canonical::<Json>(payload))?;
    soracloud_copy_bytes(json.get().as_bytes())
}
fn trigger_event_json_tlv(fields: norito::json::Map) -> Result<Vec<u8>, VMError> {
    let value = norito::json::Value::Object(fields);
    let json = soracloud_codec_attempt(|| Json::from_norito_value_ref(&value))?;
    let bytes = soracloud_canonical_frame(
        &json,
        iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES,
    )?;
    ivm::pointer_abi::encode_tlv(PointerType::Json, &bytes)
}
fn local_read_public_inputs(
    body_tlv: &[u8],
    metadata_tlv: &[u8],
    observed_height: u64,
) -> Result<BTreeMap<Name, Vec<u8>>, VMError> {
    let mut inputs = BTreeMap::new();
    let mut trigger_event = norito::json::Map::new();
    trigger_event.insert(
        "_request_body".to_owned(),
        norito::json::Value::from(hex::encode(pointer_tlv_payload(body_tlv))),
    );
    trigger_event.insert(
        "_request_meta".to_owned(),
        json_value_from_tlv(metadata_tlv)?,
    );
    trigger_event.insert(
        "observed_height".to_owned(),
        norito::json::Value::from(observed_height),
    );
    let trigger_event_tlv = trigger_event_json_tlv(trigger_event)?;
    insert_public_input(&mut inputs, "trigger_event_json", trigger_event_tlv)?;
    insert_public_input(
        &mut inputs,
        "_request_body",
        soracloud_copy_bytes(body_tlv)?,
    )?;
    insert_public_input(
        &mut inputs,
        "_request_meta",
        soracloud_copy_bytes(metadata_tlv)?,
    )?;
    let observed_height_tlv = public_input_int_tlv(observed_height)?;
    insert_public_input(&mut inputs, "observed_height", observed_height_tlv)?;
    Ok(inputs)
}
fn ordered_mailbox_public_inputs(
    payload_tlv: &[u8],
    observed_sequence: u64,
    observed_height: u64,
) -> Result<BTreeMap<Name, Vec<u8>>, VMError> {
    let mut inputs = BTreeMap::new();
    let mut trigger_event = norito::json::Map::new();
    trigger_event.insert(
        "_request_body".to_owned(),
        norito::json::Value::from(hex::encode(pointer_tlv_payload(payload_tlv))),
    );
    trigger_event.insert(
        "observed_sequence".to_owned(),
        norito::json::Value::from(observed_sequence),
    );
    trigger_event.insert(
        "observed_height".to_owned(),
        norito::json::Value::from(observed_height),
    );
    let trigger_event_tlv = trigger_event_json_tlv(trigger_event)?;
    insert_public_input(&mut inputs, "trigger_event_json", trigger_event_tlv)?;
    insert_public_input(
        &mut inputs,
        "_request_body",
        soracloud_copy_bytes(payload_tlv)?,
    )?;
    let observed_sequence_tlv = public_input_int_tlv(observed_sequence)?;
    insert_public_input(&mut inputs, "observed_sequence", observed_sequence_tlv)?;
    let observed_height_tlv = public_input_int_tlv(observed_height)?;
    insert_public_input(&mut inputs, "observed_height", observed_height_tlv)?;
    Ok(inputs)
}
// Native refusal stays local even when it occurs after guest execution. The
// observer owns the original decoder scope; no wider scope or new pool is used.
fn soracloud_codec_attempt<T>(
    operation: impl FnOnce() -> Result<T, norito::Error>,
) -> Result<T, VMError> {
    norito::core::classify_decode_attempt(operation).map_err(|error| match error.kind() {
        norito::core::DecodeAttemptErrorKind::Allocator => {
            VMError::ExecutionDeferred(ivm::ExecutionDeferral::AllocationUnavailable)
        }
        norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
            VMError::ExecutionDeferred(ivm::ExecutionDeferral::ActiveMemoryCapacity)
        }
        norito::core::DecodeAttemptErrorKind::Invalid => VMError::DecodeError,
    })
}
fn soracloud_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, VMError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| VMError::ExecutionDeferred(ivm::ExecutionDeferral::AllocationUnavailable))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
fn soracloud_canonical_frame<T: norito::NoritoSerialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, VMError> {
    let size = soracloud_codec_attempt(|| norito::canonical_frame_len(value))?;
    if size > maximum {
        return Err(VMError::DecodeError);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| VMError::ExecutionDeferred(ivm::ExecutionDeferral::AllocationUnavailable))?;
    bytes.resize(size, 0);
    let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
    soracloud_codec_attempt(|| norito::core::write_canonical_to_writer(value, &mut writer))?;
    if writer.position() != size as u64 {
        return Err(VMError::DecodeError);
    }
    Ok(bytes)
}
// Soracloud handlers use the same authenticated public call tables as every
// Kotodama entrypoint. These are the context fields emitted by the CLI templates;
// named public-input syscalls remain an independent host surface.
struct SoracloudInvocationInput<'a> {
    body_tlv: &'a [u8],
    metadata_tlv: Option<&'a [u8]>,
    execution_sequence: Option<u64>,
    observed_height: u64,
}
#[derive(Clone, Copy)]
enum SoracloudOutputKind {
    Unit,
    Json,
    Blob,
}
fn soracloud_output_kind(
    schema: Option<&ivm::EntrypointValueTypeV1>,
) -> Result<SoracloudOutputKind, VMError> {
    match schema.map(|schema| schema.nodes.as_slice()) {
        Some([EntrypointValueTypeNodeV1::Unit]) => Ok(SoracloudOutputKind::Unit),
        Some([EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json)]) => {
            Ok(SoracloudOutputKind::Json)
        }
        Some([EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Blob)]) => {
            Ok(SoracloudOutputKind::Blob)
        }
        _ => Err(VMError::DecodeError),
    }
}
fn soracloud_integer_atom(value: u64) -> Result<ivm::EntrypointValueAtomV1, VMError> {
    let integer = iroha_primitives::bigint::BigInt::from(value);
    let frame = iroha_primitives::numeric_abi::IntValueV1::prepare_frame(&integer)
        .map_err(VMError::from)?
        .encode_frame()
        .map_err(VMError::from)?;
    Ok(ivm::EntrypointValueAtomV1::Pointer(
        ivm::pointer_abi::encode_tlv(PointerType::Int, &frame)?,
    ))
}
fn prepare_soracloud_invocation(
    vm: &mut IVM,
    contract: &PreparedContract,
    entrypoint_name: &str,
    input: SoracloudInvocationInput<'_>,
) -> Result<(Option<PreparedArgumentRecord>, SoracloudOutputKind), VMError> {
    let entrypoint = contract
        .entrypoint_descriptor(entrypoint_name)
        .ok_or(VMError::PermissionDenied)?;
    let output_kind = soracloud_output_kind(entrypoint.return_schema.as_ref())?;
    vm.select_entrypoint(entrypoint_name)?;
    let Some(schema) = entrypoint.argument_schema.as_ref() else {
        return Ok((None, output_kind));
    };
    if !schema.validate() || schema.fields.len() > 4 {
        return Err(VMError::DecodeError);
    }
    let mut atoms = Vec::new();
    atoms
        .try_reserve_exact(schema.fields.len())
        .map_err(|_| VMError::ExecutionDeferred(ivm::ExecutionDeferral::AllocationUnavailable))?;
    for field in &schema.fields {
        let atom = match (field.name.as_str(), field.ty.nodes.as_slice()) {
            ("_request_body", [EntrypointValueTypeNodeV1::Leaf(kind)]) => {
                let body = ivm::pointer_abi::validate_tlv_bytes(input.body_tlv)
                    .map_err(|_| VMError::DecodeError)?;
                if input.body_tlv.len()
                    > iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES
                {
                    return Err(VMError::DecodeError);
                }
                let bytes = match kind {
                    EntrypointValueKindV1::Blob if body.type_id == PointerType::Blob => {
                        soracloud_copy_bytes(input.body_tlv)?
                    }
                    EntrypointValueKindV1::Blob => {
                        ivm::pointer_abi::encode_tlv(PointerType::Blob, body.payload)?
                    }
                    EntrypointValueKindV1::Json if body.type_id == PointerType::Json => {
                        soracloud_copy_bytes(input.body_tlv)?
                    }
                    _ => return Err(VMError::DecodeError),
                };
                ivm::EntrypointValueAtomV1::Pointer(bytes)
            }
            ("_request_meta", [EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json)]) => {
                let metadata = input.metadata_tlv.ok_or(VMError::DecodeError)?;
                if metadata.len()
                    > iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES
                {
                    return Err(VMError::DecodeError);
                }
                ivm::EntrypointValueAtomV1::Pointer(soracloud_copy_bytes(metadata)?)
            }
            (
                "execution_sequence",
                [EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
            ) => soracloud_integer_atom(input.execution_sequence.ok_or(VMError::DecodeError)?)?,
            ("observed_height", [EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)]) => {
                soracloud_integer_atom(input.observed_height)?
            }
            _ => return Err(VMError::DecodeError),
        };
        atoms.push(atom);
    }
    let schema_bytes = soracloud_canonical_frame(
        schema,
        iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES,
    )?;
    let record = EntrypointArgumentRecordV1 {
        schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
        atoms,
    };
    let canonical = soracloud_canonical_frame(
        &record,
        iroha_data_model::smart_contract::entrypoint::MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES,
    )?;
    // TODO: The canonical preparation owner still has unadmitted native Arc/plan
    // backing. Soracloud's cache has no execution AllocationBudget today; this
    // migration does not invent one or claim full host-graph funding.
    let arguments = ivm::prepare_argument_record_with_gas_limit(
        schema,
        Arc::from(canonical),
        vm.remaining_gas(),
    )?;
    arguments.precharge_vm(vm)?;
    Ok((Some(arguments), output_kind))
}
fn decode_local_read_vm_output(
    vm: &IVM,
    output_kind: SoracloudOutputKind,
    request: &SoracloudLocalReadRequest,
    context: &ResolvedLocalReadContext,
) -> Result<(Vec<u8>, Option<String>), SoracloudRuntimeExecutionError> {
    decode_vm_output(
        vm,
        output_kind,
        "query",
        context.handler.handler_name.as_ref(),
        request.service_name.as_str(),
        request.service_version.as_str(),
    )
}
fn decode_ordered_mailbox_vm_output(
    vm: &IVM,
    output_kind: SoracloudOutputKind,
    request: &SoracloudOrderedMailboxExecutionRequest,
) -> Result<(Vec<u8>, Option<String>), SoracloudRuntimeExecutionError> {
    let handler_name = request
        .handler
        .as_ref()
        .map(|handler| handler.handler_name.as_ref())
        .unwrap_or_else(|| request.mailbox_message.to_handler.as_ref());
    let execution_kind = match request
        .handler
        .as_ref()
        .map(|handler| handler.class)
        .unwrap_or(SoraServiceHandlerClassV1::Update)
    {
        SoraServiceHandlerClassV1::Update => "update",
        SoraServiceHandlerClassV1::Query => "query",
        SoraServiceHandlerClassV1::Asset => "asset",
    };
    decode_vm_output(
        vm,
        output_kind,
        execution_kind,
        handler_name,
        request.deployment.service_name.as_ref(),
        request.deployment.current_service_version.as_str(),
    )
}
fn decode_vm_output(
    vm: &IVM,
    output_kind: SoracloudOutputKind,
    execution_kind: &str,
    handler_name: &str,
    service_name: &str,
    service_version: &str,
) -> Result<(Vec<u8>, Option<String>), SoracloudRuntimeExecutionError> {
    let invalid_table = |error: &VMError| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(error),
            format!(
                "{execution_kind} handler `{handler_name}` on service `{service_name}` revision `{service_version}` returned an invalid completed result table: {}",
                vm_error_label(error),
            ),
        )
    };
    if vm
        .call_result_word_count()
        .map_err(|error| invalid_table(&error))?
        != 1
    {
        return Err(invalid_table(&VMError::DecodeError));
    }
    let response_ptr = vm
        .public_call_result_word(0)
        .map_err(|error| invalid_table(&error))?;
    if matches!(output_kind, SoracloudOutputKind::Unit) {
        return if response_ptr == 0 {
            Ok((Vec::new(), None))
        } else {
            Err(invalid_table(&VMError::DecodeError))
        };
    }
    let tlv = vm.validate_tlv(response_ptr).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            vm_error_kind(&error),
            format!(
                "{execution_kind} handler `{handler_name}` on service `{service_name}` revision `{service_version}` returned an invalid pointer: {}",
                vm_error_label(&error),
            ),
        )
    })?;
    let (response_bytes, content_type) = match (output_kind, tlv.type_id) {
        (SoracloudOutputKind::Json, PointerType::Json) => (
            json_pointer_response_payload(tlv.payload).map_err(|error| {
                SoracloudRuntimeExecutionError::new(
                    vm_error_kind(&error),
                    format!(
                        "{execution_kind} handler `{handler_name}` on service `{service_name}` revision `{service_version}` returned a JSON pointer without canonical Norito JSON framing: {}",
                        vm_error_label(&error),
                    ),
                )
            })?,
            Some("application/json".to_owned()),
        ),
        (SoracloudOutputKind::Blob, PointerType::Blob) => (
            soracloud_copy_bytes(tlv.payload).map_err(|error| invalid_table(&error))?,
            Some("application/octet-stream".to_owned()),
        ),
        (_, other) => {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "{execution_kind} handler `{handler_name}` on service `{service_name}` revision `{service_version}` returned unsupported pointer type {:?}",
                    other,
                ),
            ));
        }
    };
    Ok((response_bytes, content_type))
}
fn validate_local_runtime_snapshot(
    view: &StateView<'_>,
    snapshot: &SoracloudRuntimeSnapshot,
    request: &SoracloudLocalReadRequest,
) -> Result<(), SoracloudRuntimeExecutionError> {
    let committed_height = committed_height(view);
    let committed_block_hash = committed_block_hash(view);
    if request.observed_height != committed_height
        || request.observed_block_hash != committed_block_hash
    {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "local read snapshot is stale: request observed height/hash {:?}/{:?}, committed {:?}/{:?}",
                request.observed_height,
                request.observed_block_hash,
                committed_height,
                committed_block_hash
            ),
        ));
    }
    let snapshot_block_hash = parse_snapshot_hash(snapshot.observed_block_hash.as_deref())?;
    if !local_read_snapshot_covers_committed_state(
        snapshot.observed_height,
        snapshot_block_hash,
        committed_height,
        committed_block_hash,
    ) {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "runtime-manager hydration is behind committed state for service `{}`",
                request.service_name
            ),
        ));
    }
    let Some(service_versions) = snapshot.services.get(&request.service_name) else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "service `{}` is not materialized in the node-local runtime snapshot",
                request.service_name
            ),
        ));
    };
    let Some(plan) = service_versions.get(&request.service_version) else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "service `{}` revision `{}` is not materialized locally",
                request.service_name, request.service_version
            ),
        ));
    };
    if !plan.bundle_available_locally {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "service `{}` revision `{}` is not hydrated locally",
                request.service_name, request.service_version
            ),
        ));
    }
    Ok(())
}
fn local_read_snapshot_covers_committed_state(
    snapshot_height: u64,
    snapshot_block_hash: Option<Hash>,
    committed_height: u64,
    committed_block_hash: Option<Hash>,
) -> bool {
    if snapshot_height == committed_height {
        return snapshot_block_hash == committed_block_hash;
    }
    if snapshot_height > committed_height {
        return false;
    }
    committed_height.saturating_sub(snapshot_height) <= SORACLOUD_LOCAL_READ_MAX_SNAPSHOT_LAG_BLOCKS
}
fn validate_apartment_snapshot(
    view: &StateView<'_>,
    snapshot: &SoracloudRuntimeSnapshot,
    request: &SoracloudApartmentExecutionRequest,
) -> Result<(), SoracloudRuntimeExecutionError> {
    let committed_height = committed_height(view);
    let committed_block_hash = committed_block_hash(view);
    if request.observed_height != committed_height
        || request.observed_block_hash != committed_block_hash
    {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "apartment execution snapshot is stale: request observed height/hash {:?}/{:?}, committed {:?}/{:?}",
                request.observed_height,
                request.observed_block_hash,
                committed_height,
                committed_block_hash
            ),
        ));
    }
    if snapshot.observed_height != committed_height
        || parse_snapshot_hash(snapshot.observed_block_hash.as_deref())? != committed_block_hash
    {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "runtime-manager apartment snapshot is behind committed state for `{}`",
                request.apartment_name
            ),
        ));
    }
    if !snapshot.apartments.contains_key(&request.apartment_name) {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "apartment `{}` is not materialized in the node-local runtime snapshot",
                request.apartment_name
            ),
        ));
    }
    Ok(())
}
fn resolve_local_read_context(
    view: &StateView<'_>,
    request: &SoracloudLocalReadRequest,
) -> Result<ResolvedLocalReadContext, SoracloudRuntimeExecutionError> {
    let service_id: Name = request.service_name.parse().map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "invalid Soracloud service name `{}`: {error}",
                request.service_name
            ),
        )
    })?;
    let Some(deployment) = view
        .world()
        .soracloud_service_deployments()
        .get(&service_id)
        .cloned()
    else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!("unknown Soracloud service `{}`", request.service_name),
        ));
    };
    if deployment.current_service_version != request.service_version {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "service `{}` active version `{}` does not match requested local-read version `{}`",
                request.service_name, deployment.current_service_version, request.service_version
            ),
        ));
    }
    let Some(bundle) = view
        .world()
        .soracloud_service_revisions()
        .get(&(
            request.service_name.clone(),
            request.service_version.clone(),
        ))
        .cloned()
    else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "missing admitted Soracloud revision `{}` for service `{}`",
                request.service_version, request.service_name
            ),
        ));
    };
    ensure_ivm_runtime(
        bundle.service.execution_plane,
        bundle.container.runtime,
        request.service_name.as_str(),
        request.service_version.as_str(),
    )
    .map_err(|message| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            message,
        )
    })?;
    let route = bundle.service.route.as_ref().ok_or_else(|| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "service `{}` revision `{}` does not expose a public local-read route",
                request.service_name, request.service_version
            ),
        )
    })?;
    if route.visibility != SoraRouteVisibilityV1::Public {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "service `{}` revision `{}` local-read route is not public",
                request.service_name, request.service_version
            ),
        ));
    }
    let Some(handler) = bundle
        .service
        .handlers
        .iter()
        .find(|handler| {
            handler.handler_name.as_ref() == request.handler_name
                && handler.class == request.handler_class.handler_class()
        })
        .cloned()
    else {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "service `{}` revision `{}` does not expose handler `{}` for {:?}",
                request.service_name,
                request.service_version,
                request.handler_name,
                request.handler_class
            ),
        ));
    };
    if !matches!(
        handler.class,
        SoraServiceHandlerClassV1::Asset | SoraServiceHandlerClassV1::Query
    ) {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::InvalidRequest,
            format!(
                "service `{}` revision `{}` handler `{}` is not publicly routable",
                request.service_name, request.service_version, request.handler_name
            ),
        ));
    }
    Ok(ResolvedLocalReadContext {
        deployment,
        bundle,
        handler,
    })
}
fn resolve_asset_artifact<'a>(
    bundle: &'a SoraDeploymentBundleV1,
    handler: &SoraServiceHandlerV1,
    handler_path: &str,
) -> Option<&'a iroha_data_model::soracloud::SoraArtifactRefV1> {
    let normalized_handler_path = if handler_path.is_empty() {
        "/"
    } else {
        handler_path
    };
    let mut candidates = bundle
        .service
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind == SoraArtifactKindV1::StaticAsset
                && artifact
                    .handler_name
                    .as_ref()
                    .is_some_and(|name| name == &handler.handler_name)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.artifact_path.cmp(&right.artifact_path));
    if normalized_handler_path == "/" {
        return candidates
            .iter()
            .copied()
            .find(|artifact| artifact.artifact_path.ends_with("/index.html"))
            .or_else(|| candidates.into_iter().next());
    }
    candidates
        .iter()
        .copied()
        .find(|artifact| artifact.artifact_path == normalized_handler_path)
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|artifact| artifact.artifact_path.ends_with(normalized_handler_path))
        })
}
fn read_and_verify_cached_artifact(
    cache_path: &Path,
    expected_hash: Hash,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SoracloudRuntimeExecutionError> {
    let (file, fingerprint) = open_soracloud_artifact_for_validation(cache_path)?;
    let response_bytes =
        read_opened_soracloud_artifact_bounded(file, cache_path, &fingerprint, maximum_bytes)?;
    let actual_hash = Hash::new(&response_bytes);
    if actual_hash != expected_hash {
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "hydrated Soracloud artifact cache {} failed hash verification: expected {}, found {}",
                cache_path.display(),
                expected_hash,
                actual_hash
            ),
        ));
    }
    Ok(response_bytes)
}
fn asset_result_commitment(artifact_hash: Hash, response_bytes: &[u8]) -> Hash {
    let mut payload = Vec::with_capacity(Hash::LENGTH + response_bytes.len());
    payload.extend_from_slice(artifact_hash.as_ref());
    payload.extend_from_slice(response_bytes);
    Hash::new(payload)
}
fn state_entry_binding(
    entry: &SoraServiceStateEntryV1,
) -> iroha_core::soracloud_runtime::SoracloudLocalReadBinding {
    iroha_core::soracloud_runtime::SoracloudLocalReadBinding {
        binding_name: Some(entry.binding_name.to_string()),
        state_key: Some(entry.state_key.clone()),
        payload_commitment: Some(entry.payload_commitment),
        artifact_hash: None,
    }
}
fn local_read_receipt(
    request: &SoracloudLocalReadRequest,
    deployment: &SoraServiceDeploymentStateV1,
    handler: &SoraServiceHandlerV1,
    result_commitment: Hash,
    certified_by: SoraCertifiedResponsePolicyV1,
    mailbox_message_id: Option<Hash>,
) -> SoraRuntimeReceiptV1 {
    let mut receipt = SoraRuntimeReceiptV1 {
        schema_version: iroha_data_model::soracloud::SORA_RUNTIME_RECEIPT_VERSION_V1,
        receipt_id: Hash::new(b"soracloud:local-read-receipt:pending"),
        service_name: deployment.service_name.clone(),
        service_version: deployment.current_service_version.clone(),
        handler_name: handler.handler_name.clone(),
        handler_class: handler.class,
        request_commitment: request.request_commitment,
        result_commitment,
        certified_by,
        emitted_sequence: 0,
        execution_host: None,
        mailbox_message_id,
        journal_artifact_hash: None,
        checkpoint_artifact_hash: None,
    };
    receipt.receipt_id = derive_soracloud_local_read_receipt_id_v1(&receipt);
    receipt
}
fn soracloud_runtime_observed_at_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(1)
        .max(1)
}
fn desired_inrou_host_heartbeat_expiry_ms(
    now_ms: u64,
    config: &SoracloudRuntimeManagerConfig,
) -> u64 {
    now_ms.saturating_add(inrou_host_heartbeat_ttl_ms(config))
}
fn inrou_host_heartbeat_ttl_ms(config: &SoracloudRuntimeManagerConfig) -> u64 {
    let interval_ms = u64::try_from(config.reconcile_interval.as_millis()).unwrap_or(u64::MAX);
    interval_ms
        .saturating_mul(4)
        .max(INROU_HOST_HEARTBEAT_TTL_FLOOR_MS)
}
fn inrou_host_heartbeat_refresh_margin_ms(config: &SoracloudRuntimeManagerConfig) -> u64 {
    let interval_ms = u64::try_from(config.reconcile_interval.as_millis()).unwrap_or(u64::MAX);
    inrou_host_heartbeat_ttl_ms(config).min(
        interval_ms
            .saturating_mul(2)
            .max(INROU_HOST_HEARTBEAT_REFRESH_MARGIN_FLOOR_MS),
    )
}
fn inrou_host_heartbeat_refresh_due(
    existing: &SoraInrouHostCapabilityRecordV1,
    now_ms: u64,
    config: &SoracloudRuntimeManagerConfig,
) -> bool {
    existing.heartbeat_expires_at_ms
        <= now_ms.saturating_add(inrou_host_heartbeat_refresh_margin_ms(config))
}
fn inrou_host_capability_matches(
    existing: &SoraInrouHostCapabilityRecordV1,
    desired: &SoraInrouHostCapabilityRecordV1,
) -> bool {
    existing.validator_account_id == desired.validator_account_id
        && existing.peer_id == desired.peer_id
        && existing.supported_guest_isas == desired.supported_guest_isas
        && existing.trusted_guest_artifact == desired.trusted_guest_artifact
        && existing.max_hosted_replica_capacity == desired.max_hosted_replica_capacity
        && existing.max_cpu_millis == desired.max_cpu_millis
        && existing.max_memory_bytes == desired.max_memory_bytes
        && existing.max_storage_bytes == desired.max_storage_bytes
}
fn inrou_host_capability_refresh_needed(
    existing: Option<&SoraInrouHostCapabilityRecordV1>,
    desired: &SoraInrouHostCapabilityRecordV1,
    now_ms: u64,
    config: &SoracloudRuntimeManagerConfig,
) -> bool {
    existing.is_none_or(|existing| {
        !inrou_host_capability_matches(existing, desired)
            || !existing.is_active_at(now_ms)
            || inrou_host_heartbeat_refresh_due(existing, now_ms, config)
    })
}
fn apartment_result_commitment(
    apartment_name: &str,
    process_generation: u64,
    operation: &str,
    request_commitment: Hash,
    status: iroha_data_model::soracloud::SoraAgentRuntimeStatusV1,
) -> Hash {
    Hash::new(Encode::encode(&(
        "soracloud:apartment",
        apartment_name,
        process_generation,
        operation,
        request_commitment,
        status,
    )))
}
fn committed_height(view: &StateView<'_>) -> u64 {
    u64::try_from(view.height()).unwrap_or(u64::MAX)
}
fn committed_block_hash(view: &StateView<'_>) -> Option<Hash> {
    view.latest_block_hash().map(Hash::from)
}
fn parse_snapshot_hash(
    snapshot_hash: Option<&str>,
) -> Result<Option<Hash>, SoracloudRuntimeExecutionError> {
    snapshot_hash
        .map(Hash::from_str)
        .transpose()
        .map_err(|error| {
            SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!("invalid Soracloud runtime snapshot block hash: {error}"),
            )
        })
}
fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("css") => "text/css; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("mjs") => "application/javascript; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}
#[cfg(test)]
fn deployment_lifecycle_sequence_lower_bound(deployment: &SoraServiceDeploymentStateV1) -> u64 {
    let mut lower_bound = deployment.process_started_sequence;
    for entry in deployment.service_configs.values() {
        lower_bound = lower_bound.max(entry.last_update_sequence);
    }
    for entry in deployment.service_secrets.values() {
        lower_bound = lower_bound.max(entry.last_update_sequence);
    }
    for rollout in [
        deployment.active_rollout.as_ref(),
        deployment.last_rollout.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        lower_bound = lower_bound
            .max(rollout.created_sequence)
            .max(rollout.updated_sequence);
    }
    lower_bound
}
#[cfg(test)]
fn observe_soracloud_audit_sequence(audit_head: &mut Option<u64>, sequence: u64) {
    let next = (*audit_head).map_or(sequence, |head| head.max(sequence));
    *audit_head = Some(next);
}
#[cfg(test)]
fn observe_keyed_soracloud_audit_sequence(
    audit_head: &mut Option<u64>,
    store: &str,
    stored_sequence: u64,
    embedded_sequence: u64,
) -> eyre::Result<()> {
    if stored_sequence != embedded_sequence {
        eyre::bail!(
            "Soracloud {store} key `{stored_sequence}` does not match embedded sequence `{embedded_sequence}`"
        );
    }
    observe_soracloud_audit_sequence(audit_head, embedded_sequence);
    Ok(())
}
#[cfg(test)]
fn current_soracloud_audit_sequence(world: &impl WorldReadOnly) -> eyre::Result<u64> {
    let mut audit_head = None::<u64>;
    for (stored_sequence, event) in world.soracloud_service_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "service audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_app_infra_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "app-infra audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_training_job_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "training-job audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_model_weight_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "model-weight audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_model_artifact_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "model-artifact audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_hf_shared_lease_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "HF shared-lease audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (stored_sequence, event) in world.soracloud_agent_apartment_audit_events().iter() {
        observe_keyed_soracloud_audit_sequence(
            &mut audit_head,
            "agent-apartment audit",
            *stored_sequence,
            event.sequence,
        )?;
    }
    for (_, receipt) in world.soracloud_runtime_receipts().iter() {
        observe_soracloud_audit_sequence(&mut audit_head, receipt.emitted_sequence);
    }
    let mut deployments = world.soracloud_service_deployments().iter().peekable();
    if deployments.peek().is_none() {
        return Ok(audit_head.unwrap_or(0));
    }
    let audit_head = audit_head
        .ok_or_else(|| eyre::eyre!("Soracloud audit history is empty while deployments exist"))?;
    for (stored_service_name, deployment) in deployments {
        if stored_service_name != &deployment.service_name {
            eyre::bail!(
                "Soracloud deployment key `{stored_service_name}` does not match embedded service `{}`",
                deployment.service_name
            );
        }
        let lower_bound = deployment_lifecycle_sequence_lower_bound(deployment);
        if audit_head < lower_bound {
            eyre::bail!(
                "Soracloud audit head `{audit_head}` is behind lifecycle lower bound `{lower_bound}` for service `{stored_service_name}`"
            );
        }
    }
    Ok(audit_head)
}
fn build_lease_volume_plans(
    bundle: &SoraDeploymentBundleV1,
    deployment: &SoraServiceDeploymentStateV1,
    state_dir: &Path,
    service_name: &str,
    service_version: &str,
) -> eyre::Result<Vec<SoracloudRuntimeLeaseVolumePlan>> {
    deployment
        .validate_against_active_bundle(bundle)
        .wrap_err_with(|| {
            format!(
                "validate active bundle binding for service `{service_name}` revision `{service_version}`"
            )
        })?;
    if bundle.service.execution_plane
        == iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
    {
        let lease = deployment.service_lease.as_ref().ok_or_else(|| {
            eyre::eyre!(
                "hosted service `{service_name}` revision `{service_version}` has no authoritative economic lease"
            )
        })?;
        if lease.replica_count != bundle.service.replicas {
            eyre::bail!(
                "hosted service `{service_name}` revision `{service_version}` lease replica_count {} does not match admitted replica count {}",
                lease.replica_count,
                bundle.service.replicas,
            );
        }
    }
    let mut declared_names = BTreeSet::new();
    for volume in &bundle.service.lease_volumes {
        if !declared_names.insert(volume.volume_name.clone()) {
            eyre::bail!(
                "service `{service_name}` revision `{service_version}` declares duplicate lease volume `{}`",
                volume.volume_name
            );
        }
    }
    let mut authoritative_names = BTreeSet::new();
    for state in &deployment.lease_volume_states {
        state.validate().wrap_err_with(|| {
            format!(
                "validate authoritative lease volume `{}` for service `{service_name}` revision `{service_version}`",
                state.volume_name
            )
        })?;
        if !authoritative_names.insert(state.volume_name.clone()) {
            eyre::bail!(
                "service `{service_name}` revision `{service_version}` has duplicate authoritative lease volume state `{}`",
                state.volume_name
            );
        }
    }
    if declared_names != authoritative_names {
        let missing = declared_names
            .difference(&authoritative_names)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let unexpected = authoritative_names
            .difference(&declared_names)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        eyre::bail!(
            "service `{service_name}` revision `{service_version}` requires exact 1:1 authoritative lease volume state; missing {missing:?}, unexpected {unexpected:?}"
        );
    }
    bundle
        .service
        .lease_volumes
        .iter()
        .map(|volume| {
            let authoritative = deployment
                .lease_volume_states
                .iter()
                .find(|state| state.volume_name == volume.volume_name)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "service `{service_name}` revision `{service_version}` has no authoritative state for lease volume `{}`",
                        volume.volume_name
                    )
                })?;
            for (field, matches) in [
                ("kind", authoritative.kind == volume.kind),
                (
                    "storage_class",
                    authoritative.storage_class == volume.storage_class,
                ),
                ("mount_path", authoritative.mount_path == volume.mount_path),
                (
                    "max_total_bytes",
                    authoritative.max_total_bytes == volume.max_total_bytes.get(),
                ),
            ] {
                if !matches {
                    eyre::bail!(
                        "authoritative lease volume `{}` field `{field}` does not match service `{service_name}` revision `{service_version}`",
                        volume.volume_name
                    );
                }
            }
            let local_materialization_dir = build_hosted_http_service_volume_dir(
                state_dir,
                service_name,
                service_version,
                authoritative.lease_started_height,
                volume.volume_name.as_ref(),
            );
            Ok(SoracloudRuntimeLeaseVolumePlan {
                volume_name: volume.volume_name.to_string(),
                kind: authoritative.kind,
                storage_class: authoritative.storage_class,
                mount_path: authoritative.mount_path.clone(),
                max_total_bytes: authoritative.max_total_bytes,
                lease_started_height: authoritative.lease_started_height,
                lease_expires_height: authoritative.lease_expires_height,
                authoritative_generation: authoritative.authoritative_generation,
                local_materialization_dir: local_materialization_dir.display().to_string(),
            })
        })
        .collect()
}
fn local_inrou_replica_placements(
    world: &impl WorldReadOnly,
    service_name: &str,
    service_version: &str,
    local_validator_account_id: Option<&AccountId>,
    local_peer_id: Option<&str>,
    current_height: u64,
    lane_is_active_for_authority: impl Fn(iroha_model_base::topology::LaneId) -> bool,
) -> Vec<SoraInrouReplicaPlacementV1> {
    let Some(local_validator_account_id) = local_validator_account_id else {
        return Vec::new();
    };
    let Some(local_peer_id) = local_peer_id else {
        return Vec::new();
    };
    let has_active_peer_binding =
        iroha_core::soracloud_runtime::soracloud_validator_has_active_peer_binding(
            world,
            local_validator_account_id,
            local_peer_id,
            current_height,
            lane_is_active_for_authority,
        );
    if !has_active_peer_binding {
        return Vec::new();
    }
    let Some(record) = world
        .soracloud_inrou_service_placements()
        .get(&(service_name.to_owned(), service_version.to_owned()))
    else {
        return Vec::new();
    };
    let mut placements = record
        .placements
        .iter()
        .filter(|placement| {
            placement.host_availability.is_available()
                && &placement.validator_account_id == local_validator_account_id
                && placement.peer_id == local_peer_id
        })
        .cloned()
        .collect::<Vec<_>>();
    placements.sort_by_key(|placement| placement.replica_slot);
    placements
}
fn build_inrou_runtime_plan(
    bundle: &SoraDeploymentBundleV1,
    local_assignment: Option<&SoraInrouReplicaPlacementV1>,
) -> Option<SoracloudRuntimeInrouPlan> {
    let inrou = bundle.container.inrou.as_ref()?;
    let root_volume = bundle
        .service
        .lease_volumes
        .iter()
        .find(|volume| volume.kind == SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)?;
    let selected_guest_isa = local_assignment?.selected_guest_isa;
    let guest_image = inrou.guest_images.get(&selected_guest_isa)?;
    Some(SoracloudRuntimeInrouPlan {
        selected_guest_isa,
        kernel_image_path: guest_image.kernel_image_path.clone(),
        rootfs_image_path: guest_image.rootfs_image_path.clone(),
        initrd_image_path: guest_image.initrd_image_path.clone(),
        root_volume_name: root_volume.volume_name.to_string(),
    })
}
fn build_runtime_snapshot(
    view: &StateView<'_>,
    bundle_registry: &BTreeMap<(String, String), SoraDeploymentBundleV1>,
    state_dir: &Path,
    artifacts_root: PathBuf,
    cache_budgets: &iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets,
    local_validator_account_id: Option<&AccountId>,
    local_peer_id: Option<&str>,
    local_inrou_hosting_enabled: bool,
) -> eyre::Result<SoracloudRuntimeSnapshot> {
    let mut services = BTreeMap::new();
    let world = view.world();
    let current_height = committed_height(view);
    for (service_name, deployment) in world.soracloud_service_deployments().iter() {
        let service_name_key = service_name.clone();
        let service_name = service_name_key.to_string();
        let versions = collect_active_versions(deployment)?;
        let current_bundle = bundle_registry
            .get(&(service_name.clone(), deployment.current_service_version.clone()))
            .ok_or_else(|| eyre::eyre!(
                "deployment for service `{service_name}` references missing current admitted revision `{}`",
                deployment.current_service_version
            ))?;
        if deployment.active_rollout.is_some()
            && current_bundle.container.runtime == SoraContainerRuntimeV1::Inrou
        {
            eyre::bail!(
                "deployment for Inrou service `{service_name}` carries an unsupported active canary; first-release host-local lease disks require one active revision"
            );
        }
        let current_lease_volumes = build_lease_volume_plans(
            current_bundle,
            deployment,
            state_dir,
            &service_name,
            &deployment.current_service_version,
        )?;
        let runtime_state = world.soracloud_service_runtime().get(&service_name_key);
        let authoritative_pending = authoritative_mailbox_counts(
            world.soracloud_mailbox_messages(),
            world.soracloud_runtime_receipts(),
        );
        let mut version_plans = BTreeMap::new();
        for (service_version, role, traffic_percent) in versions {
            let bundle = bundle_registry
                .get(&(service_name.clone(), service_version.clone()))
                .ok_or_else(|| {
                    eyre::eyre!(
                        "deployment for service `{service_name}` references missing admitted revision `{service_version}`"
                    )
                })?;
            if bundle.service.service_name != service_name_key
                || bundle.service.service_version != service_version
            {
                eyre::bail!(
                    "service revision registry key does not match admitted revision identity"
                );
            }
            if deployment.active_rollout.is_some()
                && bundle.container.runtime == SoraContainerRuntimeV1::Inrou
            {
                eyre::bail!(
                    "deployment for Inrou service `{service_name}` carries an unsupported active canary; first-release host-local lease disks require one active revision"
                );
            }
            validate_inrou_runtime_topology(bundle, &service_name, &service_version)?;
            let is_runtime_active = runtime_state
                .as_ref()
                .is_some_and(|state| state.active_service_version == service_version);
            let service_dir = state_dir
                .join("services")
                .join(storage_path_component(&service_name))
                .join(storage_path_component(&service_version));
            let config_dir = service_dir.join("configs");
            let config_exports_dir = service_dir.join("config_exports");
            let effective_env_path = service_dir.join("effective_env.json");
            let secret_envelopes_dir = service_dir.join("secret_envelopes");
            let service_data_dir = build_native_service_data_dir(state_dir, &service_name);
            let bundle_cache_path =
                artifacts_root.join(hash_cache_name(bundle.container.bundle_hash));
            let active_runtime_state = runtime_state
                .as_ref()
                .filter(|state| state.active_service_version == service_version);
            let artifact_plans = build_artifact_plans(bundle, &artifacts_root, cache_budgets);
            let bundle_available_locally = artifact_plans.first().is_some_and(|artifact| {
                artifact.kind == SoraArtifactKindV1::Bundle && artifact.available_locally
            });
            let hydration_complete = artifact_plans
                .iter()
                .all(|artifact| artifact.available_locally);
            // A deterministic canary keeps its admitted baseline executable,
            // while economic authority belongs to the current candidate.
            // Hosted lease volumes can never be projected onto an older revision.
            bundle.validate_for_admission()?;
            let lease_volumes = if service_version == deployment.current_service_version {
                current_lease_volumes.clone()
            } else {
                if bundle.service.execution_plane
                    != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::DeterministicService
                    || current_bundle.service.execution_plane
                        != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::DeterministicService
                {
                    eyre::bail!("service `{service_name}` canary revisions must both use deterministic execution");
                }
                Vec::new()
            };
            let service_lease_status = deployment.hosted_service_lease_status_at(current_height)?;
            let remaining_runtime_balance =
                deployment.hosted_service_remaining_balance(current_height)?;
            let hosted_http_lease_active = bundle.service.execution_plane
                != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
                || (service_lease_status == Some(SoraServiceLeaseStatusV1::Active)
                    && lease_volumes
                        .iter()
                        .all(|volume| current_height < volume.lease_expires_height));
            let local_inrou_assignments = if local_inrou_hosting_enabled
                && bundle.container.runtime == SoraContainerRuntimeV1::Inrou
            {
                local_inrou_replica_placements(
                    world,
                    &service_name,
                    &service_version,
                    local_validator_account_id,
                    local_peer_id,
                    current_height,
                    |lane_id| view.is_lane_active_for_authority(lane_id),
                )
            } else {
                Vec::new()
            };
            let hosted_http_runtime_state = if bundle.container.runtime
                == SoraContainerRuntimeV1::Inrou
                && !local_inrou_assignments.is_empty()
            {
                read_hosted_http_runtime_state(&service_dir).wrap_err_with(|| {
                    format!(
                        "read hosted-HTTP runtime state for service `{service_name}` revision `{service_version}`"
                    )
                })?
            } else {
                None
            };
            let mut effective_env = build_effective_service_environment(bundle, deployment)?;
            if bundle.container.runtime == SoraContainerRuntimeV1::Inrou {
                effective_env.insert(
                    "SORACLOUD_SERVICE_DATA_DIR".to_owned(),
                    "/var/lib/soracloud/service".to_owned(),
                );
                effective_env.insert(
                    "SORACLOUD_SERVICE_MATERIALIZATION_DIR".to_owned(),
                    "/var/lib/soracloud/materialization".to_owned(),
                );
            } else {
                effective_env.insert(
                    "SORACLOUD_SERVICE_DATA_DIR".to_owned(),
                    service_data_dir.display().to_string(),
                );
                effective_env.insert(
                    "SORACLOUD_SERVICE_MATERIALIZATION_DIR".to_owned(),
                    service_dir.display().to_string(),
                );
            }
            if let Some(lease) = deployment.service_lease.as_ref() {
                effective_env.insert(
                    "SORACLOUD_SERVICE_LEASE_EXPIRES_HEIGHT".to_owned(),
                    lease.lease_expires_height.to_string(),
                );
                effective_env.insert(
                    "SORACLOUD_SERVICE_PREPAID_BALANCE".to_owned(),
                    lease.prepaid_runtime_balance.to_string(),
                );
                effective_env.insert(
                    "SORACLOUD_SERVICE_QUOTA_CLASS".to_owned(),
                    lease.quota_class.clone(),
                );
                effective_env.insert(
                    "SORACLOUD_SERVICE_REMAINING_BALANCE".to_owned(),
                    remaining_runtime_balance
                        .as_ref()
                        .map_or_else(|| "0".to_owned(), ToString::to_string),
                );
            }
            for volume in &lease_volumes {
                let env_suffix = sanitize_env_var_component(&volume.volume_name);
                effective_env.insert(
                    format!("SORACLOUD_LEASE_VOLUME_{env_suffix}_DIR"),
                    if bundle.container.runtime == SoraContainerRuntimeV1::Inrou {
                        volume.mount_path.clone()
                    } else {
                        volume.local_materialization_dir.clone()
                    },
                );
                effective_env.insert(
                    format!("SORACLOUD_LEASE_VOLUME_{env_suffix}_MOUNT_PATH"),
                    volume.mount_path.clone(),
                );
            }
            let local_replicas = if bundle.container.runtime == SoraContainerRuntimeV1::Inrou {
                build_hosted_http_local_replica_plans(
                    &service_dir,
                    &local_inrou_assignments,
                    hosted_http_runtime_state.as_ref(),
                    hydration_complete,
                    hosted_http_lease_active,
                )
            } else {
                Vec::new()
            };
            let hosts_inrou_locally =
                hosted_http_lease_active && !local_inrou_assignments.is_empty();
            let plan = SoracloudRuntimeServicePlan {
                service_name: service_name.clone(),
                service_version: service_version.clone(),
                role,
                traffic_percent,
                runtime: bundle.container.runtime,
                execution_plane: bundle.service.execution_plane,
                bundle_hash: bundle.container.bundle_hash.to_string(),
                bundle_path: bundle.container.bundle_path.clone(),
                entrypoint: bundle.container.entrypoint.clone(),
                inrou: build_inrou_runtime_plan(bundle, local_inrou_assignments.first()),
                bundle_cache_path: bundle_cache_path.display().to_string(),
                bundle_available_locally,
                process_generation: match bundle.container.runtime {
                    iroha_data_model::soracloud::SoraContainerRuntimeV1::Ivm => {
                        is_runtime_active.then_some(deployment.process_generation)
                    }
                    SoraContainerRuntimeV1::Inrou => {
                        hosts_inrou_locally.then_some(deployment.process_generation)
                    }
                },
                desired_replica_count: bundle.service.replicas.get(),
                local_replica_slots: local_replicas
                    .iter()
                    .map(|replica| replica.replica_slot)
                    .collect(),
                local_replicas,
                health_status: if !hydration_complete {
                    SoraServiceHealthStatusV1::Hydrating
                } else {
                    match bundle.container.runtime {
                        iroha_data_model::soracloud::SoraContainerRuntimeV1::Ivm => {
                            hydrated_ivm_service_health_status(
                                active_runtime_state.copied(),
                                bundle.service.execution_plane,
                                bundle.container.runtime,
                                &service_name,
                                &service_version,
                            )
                        }
                        SoraContainerRuntimeV1::Inrou => {
                            if !hosted_http_lease_active {
                                SoraServiceHealthStatusV1::Degraded
                            } else if !hosts_inrou_locally {
                                SoraServiceHealthStatusV1::Unavailable
                            } else {
                                hosted_http_runtime_state
                                    .as_ref()
                                    .filter(|state| {
                                        state.process_generation == deployment.process_generation
                                    })
                                    .map_or(SoraServiceHealthStatusV1::Degraded, |state| {
                                        state.health_status
                                    })
                            }
                        }
                    }
                },
                load_factor_bps: active_runtime_state.map_or(0, |state| state.load_factor_bps),
                authoritative_pending_mailbox_messages: authoritative_pending
                    .get(&service_name)
                    .copied()
                    .unwrap_or_default(),
                rollout_handle: deployment
                    .active_rollout
                    .as_ref()
                    .map(|rollout| rollout.rollout_handle.clone()),
                config_generation: deployment.config_generation,
                secret_generation: deployment.secret_generation,
                quota_class: deployment
                    .service_lease
                    .as_ref()
                    .map(|lease| lease.quota_class.clone()),
                service_lease_status,
                lease_expires_height: deployment
                    .service_lease
                    .as_ref()
                    .map(|lease| lease.lease_expires_height),
                remaining_runtime_balance,
                config_entry_count: u32::try_from(deployment.service_configs.len())
                    .unwrap_or(u32::MAX),
                secret_entry_count: u32::try_from(deployment.service_secrets.len())
                    .unwrap_or(u32::MAX),
                config_exports: bundle.container.config_exports.clone(),
                supports_host_read_config: true,
                supports_host_read_secret_envelope: true,
                materialization_dir: service_dir.display().to_string(),
                config_materialization_dir: config_dir.display().to_string(),
                effective_env,
                effective_env_materialization_path: effective_env_path.display().to_string(),
                config_exports_materialization_dir: config_exports_dir.display().to_string(),
                secret_envelopes_materialization_dir: secret_envelopes_dir.display().to_string(),
                lease_volumes,
                mailboxes: bundle
                    .service
                    .handlers
                    .iter()
                    .filter_map(|handler| {
                        handler
                            .mailbox
                            .as_ref()
                            .map(|mailbox| SoracloudRuntimeMailboxPlan {
                                handler_name: handler.handler_name.to_string(),
                                queue_name: mailbox.queue_name.to_string(),
                                max_pending_messages: mailbox.max_pending_messages.get(),
                                max_message_bytes: mailbox.max_message_bytes.get(),
                                retention_blocks: mailbox.retention_blocks.get(),
                            })
                    })
                    .collect(),
                artifacts: artifact_plans,
            };
            version_plans.insert(service_version, plan);
        }
        services.insert(service_name, version_plans);
    }
    let apartments = world
        .soracloud_agent_apartments()
        .iter()
        .map(|(apartment_name, record)| {
            (
                apartment_name.clone(),
                build_apartment_plan(apartment_name, record, committed_height(view), state_dir),
            )
        })
        .collect();
    Ok(SoracloudRuntimeSnapshot {
        schema_version: SoracloudRuntimeSnapshot::default().schema_version,
        observed_height: u64::try_from(view.height()).unwrap_or(u64::MAX),
        observed_block_hash: view.latest_block_hash().map(|hash| hash.to_string()),
        local_peer_id: local_peer_id.map(ToOwned::to_owned),
        services,
        apartments,
    })
}
fn build_apartment_plan(
    apartment_name: &str,
    record: &SoraAgentApartmentRecordV1,
    current_height: u64,
    state_dir: &Path,
) -> SoracloudRuntimeApartmentPlan {
    let apartment_root = state_dir
        .join("apartments")
        .join(storage_path_component(apartment_name));
    SoracloudRuntimeApartmentPlan {
        apartment_name: apartment_name.to_string(),
        manifest_hash: record.manifest_hash.to_string(),
        status: record.runtime_status_at_current_height(current_height),
        process_generation: record.process_generation,
        lease_expires_height: record.lease_expires_height,
        last_active_sequence: record.last_active_sequence,
        materialization_dir: apartment_root.display().to_string(),
        pending_wallet_request_count: u32::try_from(record.pending_wallet_requests.len())
            .unwrap_or(u32::MAX),
        pending_mailbox_message_count: u32::try_from(record.mailbox_queue.len())
            .unwrap_or(u32::MAX),
        autonomy_budget_remaining_units: record.autonomy_budget_remaining_units,
        approved_artifact_count: u32::try_from(record.artifact_allowlist.len()).unwrap_or(u32::MAX),
        autonomy_run_count: u32::try_from(record.autonomy_run_history.len()).unwrap_or(u32::MAX),
        revoked_policy_capability_count: u32::try_from(record.revoked_policy_capabilities.len())
            .unwrap_or(u32::MAX),
    }
}
fn build_artifact_plans(
    bundle: &SoraDeploymentBundleV1,
    artifacts_root: &Path,
    cache_budgets: &iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets,
) -> Vec<SoracloudRuntimeArtifactPlan> {
    let mut artifacts = Vec::with_capacity(bundle.service.artifacts.len().saturating_add(1));
    let bundle_cache_path = artifacts_root.join(hash_cache_name(bundle.container.bundle_hash));
    artifacts.push(SoracloudRuntimeArtifactPlan {
        kind: SoraArtifactKindV1::Bundle,
        artifact_hash: bundle.container.bundle_hash.to_string(),
        artifact_path: bundle.container.bundle_path.clone(),
        handler_name: None,
        local_cache_path: bundle_cache_path.display().to_string(),
        available_locally: verify_cached_soracloud_artifact(
            &bundle_cache_path,
            bundle.container.bundle_hash,
            runtime_cache_budget_for_kind(SoraArtifactKindV1::Bundle, cache_budgets),
        )
        .is_ok(),
    });
    artifacts.extend(bundle.service.artifacts.iter().map(|artifact| {
        let cache_path = artifacts_root.join(hash_cache_name(artifact.artifact_hash));
        SoracloudRuntimeArtifactPlan {
            kind: artifact.kind,
            artifact_hash: artifact.artifact_hash.to_string(),
            artifact_path: artifact.artifact_path.clone(),
            handler_name: artifact.handler_name.as_ref().map(ToString::to_string),
            local_cache_path: cache_path.display().to_string(),
            available_locally: verify_cached_soracloud_artifact(
                &cache_path,
                artifact.artifact_hash,
                runtime_cache_budget_for_kind(artifact.kind, cache_budgets),
            )
            .is_ok(),
        }
    }));
    artifacts
}
fn runtime_cache_budget_for_kind(
    kind: SoraArtifactKindV1,
    cache_budgets: &iroha_config::parameters::actual::SoracloudRuntimeCacheBudgets,
) -> u64 {
    match kind {
        SoraArtifactKindV1::Bundle => cache_budgets.bundle_bytes.get(),
        SoraArtifactKindV1::StaticAsset => cache_budgets.static_asset_bytes.get(),
        SoraArtifactKindV1::Journal => cache_budgets.journal_bytes.get(),
        SoraArtifactKindV1::Checkpoint => cache_budgets.checkpoint_bytes.get(),
        SoraArtifactKindV1::ModelArtifact => cache_budgets.model_artifact_bytes.get(),
        SoraArtifactKindV1::ModelWeights => cache_budgets.model_weight_bytes.get(),
    }
}
fn collect_service_revision_registry(
    view: &StateView<'_>,
) -> BTreeMap<(String, String), SoraDeploymentBundleV1> {
    view.world()
        .soracloud_service_revisions()
        .iter()
        .map(|((service_name, service_version), bundle)| {
            (
                (service_name.clone(), service_version.clone()),
                bundle.clone(),
            )
        })
        .collect()
}
fn strip_inrou_runtime_plans(snapshot: &mut SoracloudRuntimeSnapshot) -> bool {
    let mut removed = false;
    for versions in snapshot.services.values_mut() {
        let previous_len = versions.len();
        versions.retain(|_, plan| !has_inrou_runtime_shape(plan));
        removed |= versions.len() != previous_len;
    }
    snapshot.services.retain(|_, versions| !versions.is_empty());
    removed
}
fn has_inrou_runtime_shape(plan: &SoracloudRuntimeServicePlan) -> bool {
    plan.runtime == SoraContainerRuntimeV1::Inrou
        || plan.execution_plane == SoraServiceExecutionPlaneV1::HttpService
        || plan.inrou.is_some()
        || !plan.local_replica_slots.is_empty()
        || !plan.local_replicas.is_empty()
}
fn collect_single_revision_inrou_runtime_plans(
    snapshot: &SoracloudRuntimeSnapshot,
) -> eyre::Result<Vec<(&String, &String, &SoracloudRuntimeServicePlan)>> {
    let mut plans = Vec::new();
    for (service_name, versions) in &snapshot.services {
        let mut inrou_versions = versions
            .iter()
            .filter(|(_, plan)| has_inrou_runtime_shape(plan));
        let Some((service_version, plan)) = inrou_versions.next() else {
            continue;
        };
        if versions.len() != 1 || inrou_versions.next().is_some() {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` must contain exactly one revision"
            );
        }
        if plan.role != SoracloudRuntimeRevisionRole::Active || plan.traffic_percent != 100 {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` must be the sole active revision with 100 percent traffic"
            );
        }
        if plan.service_name != *service_name || plan.service_version != *service_version {
            eyre::bail!(
                "runtime snapshot key `{service_name}`/`{service_version}` does not match embedded Inrou plan `{}`/`{}`",
                plan.service_name,
                plan.service_version
            );
        }
        plans.push((service_name, service_version, plan));
    }
    Ok(plans)
}
fn collect_authoritative_single_revision_inrou_runtime_plans<'snapshot>(
    view: &StateView<'_>,
    snapshot: &'snapshot SoracloudRuntimeSnapshot,
    local_validator_account_id: Option<&AccountId>,
    local_peer_id: Option<&str>,
) -> eyre::Result<
    Vec<(
        &'snapshot String,
        &'snapshot String,
        &'snapshot SoracloudRuntimeServicePlan,
    )>,
> {
    let plans = collect_single_revision_inrou_runtime_plans(snapshot)?;
    if plans.is_empty() {
        return Ok(plans);
    }
    let world = view.world();
    let current_height = committed_height(view);
    let current_block_hash = view.latest_block_hash().map(|hash| hash.to_string());
    if snapshot.observed_height != current_height
        || snapshot.observed_block_hash != current_block_hash
    {
        eyre::bail!(
            "Inrou runtime snapshot belongs to height {} block {:?}, not authoritative height {current_height} block {current_block_hash:?}",
            snapshot.observed_height,
            snapshot.observed_block_hash
        );
    }
    if snapshot.local_peer_id.as_deref() != local_peer_id {
        eyre::bail!(
            "Inrou runtime snapshot peer identity {:?} does not match this runtime host {:?}",
            snapshot.local_peer_id,
            local_peer_id
        );
    }
    for (service_name, service_version, plan) in &plans {
        let service_name_id = Name::from_str(service_name.as_str()).wrap_err_with(|| {
            format!("parse Inrou runtime snapshot service name `{service_name}`")
        })?;
        let deployment = world
            .soracloud_service_deployments()
            .get(&service_name_id)
            .ok_or_else(|| {
                eyre::eyre!(
                    "runtime snapshot for Inrou service `{service_name}` has no authoritative deployment"
                )
            })?;
        if deployment.current_service_version.as_str() != service_version.as_str() {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` is not the authoritative current revision `{}`",
                deployment.current_service_version
            );
        }
        let bundle = world
            .soracloud_service_revisions()
            .get(&((*service_name).clone(), (*service_version).clone()))
            .ok_or_else(|| {
                eyre::eyre!(
                    "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` has no admitted bundle"
                )
            })?;
        deployment
            .validate_against_active_bundle(bundle)
            .map_err(|error| eyre::eyre!(error.to_string()))
            .wrap_err_with(|| {
                format!(
                    "validate authoritative Inrou deployment `{service_name}` revision `{service_version}`"
                )
            })?;
        if plan.runtime != SoraContainerRuntimeV1::Inrou
            || bundle.container.runtime != SoraContainerRuntimeV1::Inrou
            || bundle.service.execution_plane
                != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
            || plan.execution_plane != bundle.service.execution_plane
            || plan.bundle_hash != bundle.container.bundle_hash.to_string()
            || plan.bundle_path != bundle.container.bundle_path
            || plan.entrypoint != bundle.container.entrypoint
            || plan.desired_replica_count != bundle.service.replicas.get()
        {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` does not match its admitted bundle"
            );
        }
        let active_placement =
            iroha_core::soracloud_runtime::resolve_active_inrou_placement_record(
                world,
                service_name,
                service_version,
                current_height,
            )
            .map_err(eyre::Report::msg)?;
        let local_assignments = if active_placement.is_some() {
            local_inrou_replica_placements(
                world,
                service_name,
                service_version,
                local_validator_account_id,
                local_peer_id,
                current_height,
                |lane_id| view.is_lane_active_for_authority(lane_id),
            )
        } else {
            Vec::new()
        };
        let expected_process_generation =
            (!local_assignments.is_empty()).then_some(deployment.process_generation);
        if plan.process_generation != expected_process_generation
            || plan.config_generation != deployment.config_generation
            || plan.secret_generation != deployment.secret_generation
            || plan.rollout_handle.is_some()
        {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` does not match the authoritative process and material generations"
            );
        }
        let mut projected_slots = plan
            .local_replicas
            .iter()
            .map(|replica| replica.replica_slot)
            .collect::<Vec<_>>();
        projected_slots.sort_unstable();
        if projected_slots != plan.local_replica_slots {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` carries inconsistent local replica slots"
            );
        }
        let expected_slots = local_assignments
            .iter()
            .map(|assignment| assignment.replica_slot)
            .collect::<Vec<_>>();
        if plan.local_replica_slots != expected_slots
            || plan.local_replicas.len() != local_assignments.len()
        {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` does not contain the exact local authoritative replica set"
            );
        }
        let expected_inrou_plan = build_inrou_runtime_plan(bundle, local_assignments.first());
        if plan.inrou.as_ref() != expected_inrou_plan.as_ref() {
            eyre::bail!(
                "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` does not match the signed local guest plan"
            );
        }
        for replica in &plan.local_replicas {
            let assignment = local_assignments
                .iter()
                .find(|assignment| assignment.replica_slot == replica.replica_slot)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` replica {} has no active authoritative assignment",
                        replica.replica_slot
                    )
                })?;
            if replica.lease_started_height != assignment.lease_started_height
                || replica.placement_incarnation != assignment.placement_incarnation.to_string()
                || replica.host_availability != assignment.host_availability
                || replica.validator_account_id != assignment.validator_account_id.to_string()
                || replica.peer_id != assignment.peer_id
                || plan.inrou.as_ref().map(|inrou| inrou.selected_guest_isa)
                    != Some(assignment.selected_guest_isa)
            {
                eyre::bail!(
                    "runtime snapshot for Inrou service `{service_name}` revision `{service_version}` replica {} does not match its active authoritative assignment",
                    replica.replica_slot
                );
            }
        }
    }
    Ok(plans)
}
fn collect_active_versions(
    deployment: &SoraServiceDeploymentStateV1,
) -> eyre::Result<Vec<(String, SoracloudRuntimeRevisionRole, u8)>> {
    let mut versions = Vec::new();
    if let Some(rollout) = deployment.active_rollout.as_ref() {
        let traffic_percent = rollout.traffic_percent;
        if !(1..100).contains(&traffic_percent) {
            eyre::bail!(
                "deployment for service `{}` carries invalid active rollout traffic_percent {}; expected 1..=99",
                deployment.service_name,
                traffic_percent
            );
        }
        if rollout.stage != SoraRolloutStageV1::Canary {
            eyre::bail!(
                "deployment for service `{}` carries non-canary active rollout stage {:?}",
                deployment.service_name,
                rollout.stage
            );
        }
        if rollout.candidate_version != deployment.current_service_version {
            eyre::bail!(
                "deployment for service `{}` carries active rollout candidate `{}` but current revision is `{}`",
                deployment.service_name,
                rollout.candidate_version,
                deployment.current_service_version
            );
        }
        let baseline_version = &rollout.baseline_version;
        if baseline_version == &rollout.candidate_version {
            eyre::bail!(
                "deployment for service `{}` carries identical active rollout baseline and candidate revision `{}`",
                deployment.service_name,
                baseline_version
            );
        }
        let baseline_percent = 100 - traffic_percent;
        versions.push((
            baseline_version.clone(),
            SoracloudRuntimeRevisionRole::Active,
            baseline_percent,
        ));
        versions.push((
            rollout.candidate_version.clone(),
            SoracloudRuntimeRevisionRole::CanaryCandidate,
            traffic_percent,
        ));
    } else {
        versions.push((
            deployment.current_service_version.clone(),
            SoracloudRuntimeRevisionRole::Active,
            100,
        ));
    }
    Ok(versions)
}
fn hydrated_ivm_service_health_status(
    runtime_state: Option<&SoraServiceRuntimeStateV1>,
    execution_plane: iroha_data_model::soracloud::SoraServiceExecutionPlaneV1,
    runtime: iroha_data_model::soracloud::SoraContainerRuntimeV1,
    service_name: &str,
    service_version: &str,
) -> SoraServiceHealthStatusV1 {
    if let Some(state) = runtime_state {
        return state.health_status;
    }
    if ensure_ivm_runtime(execution_plane, runtime, service_name, service_version).is_ok() {
        SoraServiceHealthStatusV1::Healthy
    } else {
        SoraServiceHealthStatusV1::Degraded
    }
}
fn authoritative_mailbox_counts(
    messages: &impl StorageReadOnly<Hash, SoraServiceMailboxMessageV1>,
    receipts: &impl StorageReadOnly<Hash, SoraRuntimeReceiptV1>,
) -> BTreeMap<String, u32> {
    let consumed: BTreeSet<Hash> = receipts
        .iter()
        .filter_map(|(_receipt_id, receipt)| receipt.mailbox_message_id)
        .collect();
    let mut counts = BTreeMap::new();
    for (_, message) in messages.iter() {
        if consumed.contains(&message.message_id) {
            continue;
        }
        let entry = counts.entry(message.to_service.to_string()).or_insert(0u32);
        *entry = entry.saturating_add(1);
    }
    counts
}
fn collect_committed_service_state_entries(
    view: &StateView<'_>,
    service_name: &str,
) -> BTreeMap<(String, String), SoraServiceStateEntryV1> {
    view.world()
        .soracloud_service_state_entries()
        .iter()
        .filter(|((_service, _binding, _key), entry)| entry.service_name.as_ref() == service_name)
        .map(|((_service, binding, key), entry)| ((binding.clone(), key.clone()), entry.clone()))
        .collect()
}
fn ordered_mailbox_vm_failure(
    request: SoracloudOrderedMailboxExecutionRequest,
    error: &VMError,
) -> Result<SoracloudOrderedMailboxExecutionResult, SoracloudRuntimeExecutionError> {
    if vm_error_kind(error) == SoracloudRuntimeExecutionErrorKind::Unavailable {
        // Resource admission is local. It cannot create a committed degraded
        // runtime receipt or change the message's protocol validity.
        return Err(SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            vm_error_label(error),
        ));
    }
    Ok(deterministic_mailbox_failure_result(
        request,
        vm_error_label(error),
        SoraServiceHealthStatusV1::Degraded,
    ))
}
fn ordered_mailbox_output_failure(
    request: SoracloudOrderedMailboxExecutionRequest,
    error: SoracloudRuntimeExecutionError,
) -> Result<SoracloudOrderedMailboxExecutionResult, SoracloudRuntimeExecutionError> {
    if error.kind == SoracloudRuntimeExecutionErrorKind::Unavailable {
        return Err(error);
    }
    Ok(deterministic_mailbox_failure_result_with_message(
        request,
        "invalid_response",
        error.message,
        SoraServiceHealthStatusV1::Degraded,
    ))
}
fn deterministic_mailbox_failure_result(
    request: SoracloudOrderedMailboxExecutionRequest,
    outcome_label: &str,
    health_status: SoraServiceHealthStatusV1,
) -> SoracloudOrderedMailboxExecutionResult {
    deterministic_mailbox_failure_result_with_message(
        request,
        outcome_label,
        outcome_label.to_owned(),
        health_status,
    )
}
fn deterministic_mailbox_failure_result_with_message(
    request: SoracloudOrderedMailboxExecutionRequest,
    outcome_label: &str,
    detail: String,
    health_status: SoraServiceHealthStatusV1,
) -> SoracloudOrderedMailboxExecutionResult {
    let result_commitment = Hash::new(Encode::encode(&(
        "soracloud:runtime-failure:v1",
        request.mailbox_message.message_id,
        request.deployment.service_name.as_ref(),
        request.deployment.current_service_version.as_str(),
        request.mailbox_message.to_handler.as_ref(),
        request.observed_sequence,
        outcome_label,
        detail,
    )));
    let mut runtime_receipt = SoraRuntimeReceiptV1 {
        schema_version: SORA_RUNTIME_RECEIPT_VERSION_V1,
        receipt_id: Hash::prehashed([0; Hash::LENGTH]),
        service_name: request.deployment.service_name.clone(),
        service_version: request.deployment.current_service_version.clone(),
        handler_name: request.mailbox_message.to_handler.clone(),
        handler_class: request
            .handler
            .as_ref()
            .map(|handler| handler.class)
            .unwrap_or(SoraServiceHandlerClassV1::Update),
        request_commitment: request.mailbox_message.payload_commitment,
        result_commitment,
        certified_by: SoraCertifiedResponsePolicyV1::None,
        emitted_sequence: 0,
        execution_host: None,
        mailbox_message_id: Some(request.mailbox_message.message_id),
        journal_artifact_hash: None,
        checkpoint_artifact_hash: None,
    };
    runtime_receipt.receipt_id =
        iroha_core::soracloud_runtime::ordered_mailbox_runtime_receipt_id(&runtime_receipt)
            .expect("ordered mailbox runtime receipt carries its source message");
    SoracloudOrderedMailboxExecutionResult {
        state_mutations: Vec::new(),
        outbound_mailbox_messages: Vec::new(),
        response_bytes: Vec::new(),
        content_type: None,
        runtime_state: Some(updated_runtime_state(
            request.runtime_state.clone(),
            health_status,
        )),
        runtime_receipt,
    }
}
fn validate_authoritative_mailbox_runtime_state(
    request: &SoracloudOrderedMailboxExecutionRequest,
) -> Result<(), SoracloudRuntimeExecutionError> {
    let state = request.runtime_state.as_ref().ok_or_else(|| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Unavailable,
            format!(
                "service `{}` has no authoritative runtime state for ordered mailbox execution",
                request.deployment.service_name
            ),
        )
    })?;
    state.validate().map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "service `{}` carries invalid authoritative runtime state: {error}",
                request.deployment.service_name
            ),
        )
    })?;
    for (field, matches) in [
        (
            "service_name",
            state.service_name == request.deployment.service_name,
        ),
        (
            "active_service_version",
            state.active_service_version == request.deployment.current_service_version,
        ),
        (
            "materialized_bundle_hash",
            state.materialized_bundle_hash == request.bundle.container.bundle_hash,
        ),
    ] {
        if !matches {
            return Err(SoracloudRuntimeExecutionError::new(
                SoracloudRuntimeExecutionErrorKind::Internal,
                format!(
                    "service `{}` authoritative runtime-state field `{field}` does not match the admitted mailbox execution context",
                    request.deployment.service_name
                ),
            ));
        }
    }
    Ok(())
}
fn updated_runtime_state(
    runtime_state: Option<iroha_data_model::soracloud::SoraServiceRuntimeStateV1>,
    health_status: SoraServiceHealthStatusV1,
) -> iroha_data_model::soracloud::SoraServiceRuntimeStateV1 {
    let mut runtime_state = runtime_state
        .expect("ordered mailbox runtime state must be validated before result construction");
    runtime_state.health_status = health_status;
    runtime_state
}
fn ensure_ivm_runtime(
    execution_plane: iroha_data_model::soracloud::SoraServiceExecutionPlaneV1,
    runtime: iroha_data_model::soracloud::SoraContainerRuntimeV1,
    service_name: &str,
    service_version: &str,
) -> Result<(), String> {
    if execution_plane
        != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::DeterministicService
    {
        return Err(format!(
            "service `{service_name}` revision `{service_version}` targets unsupported Soracloud execution plane `{:?}`; deterministic local reads and mailbox execution require `DeterministicService`",
            execution_plane
        ));
    }
    match runtime {
        iroha_data_model::soracloud::SoraContainerRuntimeV1::Ivm => Ok(()),
        other => Err(format!(
            "service `{service_name}` revision `{service_version}` targets unsupported Soracloud runtime `{:?}`; deterministic local reads and mailbox execution require `Ivm`",
            other
        )),
    }
}
fn authoritative_mailbox_result_commitment(
    request: &SoracloudOrderedMailboxExecutionRequest,
    state_mutations: &[iroha_core::soracloud_runtime::SoracloudDeterministicStateMutation],
    outbound_mailbox_messages: &[SoraServiceMailboxMessageV1],
    response_bytes: &[u8],
    content_type: Option<&str>,
    runtime_state: &SoraServiceRuntimeStateV1,
    journal_artifact_hash: Option<Hash>,
    checkpoint_artifact_hash: Option<Hash>,
) -> Hash {
    let mutation_fingerprints = state_mutations
        .iter()
        .map(|mutation| {
            (
                mutation.binding_name.as_str(),
                mutation.state_key.as_str(),
                mutation.operation,
                mutation.encryption,
                mutation.payload_bytes,
                mutation.payload_commitment,
            )
        })
        .collect::<Vec<_>>();
    let outbound_fingerprints = outbound_mailbox_messages
        .iter()
        .map(|message| {
            (
                message.message_id,
                message.from_service.as_ref(),
                message.from_handler.as_ref(),
                message.to_service.as_ref(),
                message.to_handler.as_ref(),
                message.payload_commitment,
                message.delivery_delay_blocks,
                message.available_after_height,
                message.expires_at_height,
            )
        })
        .collect::<Vec<_>>();
    let response_fingerprint = (
        content_type,
        Hash::new(response_bytes),
        runtime_state.clone(),
        journal_artifact_hash,
        checkpoint_artifact_hash,
    );
    Hash::new(Encode::encode(&(
        "soracloud:runtime-result:v1",
        request.mailbox_message.message_id,
        request.deployment.service_name.as_ref(),
        request.deployment.current_service_version.as_str(),
        request.mailbox_message.to_handler.as_ref(),
        request.observed_sequence,
        mutation_fingerprints,
        outbound_fingerprints,
        response_fingerprint,
    )))
}
fn mailbox_payload_tlv_bytes(payload_bytes: &[u8]) -> Result<Vec<u8>, VMError> {
    if payload_bytes.is_empty() {
        return ivm::pointer_abi::encode_tlv(PointerType::Blob, &[]);
    }
    if ivm::pointer_abi::validate_tlv_bytes(payload_bytes).is_ok() {
        return soracloud_copy_bytes(payload_bytes);
    }
    ivm::pointer_abi::encode_tlv(PointerType::Blob, payload_bytes)
}
fn make_pointer_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(u32::try_from(payload.len()).unwrap_or(u32::MAX)).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn vm_error_label(error: &VMError) -> &'static str {
    match error.as_unmetered() {
        VMError::ExecutionDeferred(_) => "execution_deferred",
        VMError::AllocationDeferred(_) => "allocation_deferred",
        VMError::OutOfGas => "out_of_gas",
        VMError::OutOfMemory => "out_of_memory",
        VMError::MemoryAccessViolation { .. } => "memory_access_violation",
        VMError::MisalignedAccess { .. } => "misaligned_access",
        VMError::MemoryOutOfBounds => "memory_out_of_bounds",
        VMError::DecodeError => "decode_error",
        VMError::InvalidOpcode(_) => "invalid_opcode",
        VMError::UnknownSyscall(_) => "unknown_syscall",
        VMError::HostUnavailable => "host_unavailable",
        VMError::NotImplemented { .. } => "not_implemented",
        VMError::SyscallGasQuoteExceeded { .. } => "syscall_gas_quote_exceeded",
        VMError::SyscallMeteringModeMismatch { .. } => "syscall_metering_mode_mismatch",
        VMError::GasCostOverflow => "gas_cost_overflow",
        VMError::SyscallOutOfGas { .. } => "syscall_out_of_gas",
        VMError::NumericFault(_) => "numeric_fault",
        VMError::PointerAbiFault(_) => "pointer_abi_fault",
        VMError::AssertionFailed => "assertion_failed",
        VMError::ContractAbort { .. } => "contract_abort",
        VMError::ExceededMaxCycles => "exceeded_max_cycles",
        VMError::InvalidMetadata => "invalid_metadata",
        VMError::UnsupportedProgramVersion { .. } => "unsupported_program_version",
        VMError::UnsupportedProgramFeatureBits { .. } => "unsupported_program_feature_bits",
        VMError::UnsupportedProgramAbiVersion { .. } => "unsupported_program_abi_version",
        VMError::ProgramVectorLengthTooLarge { .. } => "program_vector_length_too_large",
        VMError::ArtifactAbiHashMismatch { .. } => "artifact_abi_hash_mismatch",
        VMError::GenericSyscallNotAllowed { .. } => "generic_syscall_not_allowed",
        VMError::InvalidVectorLength { .. } => "invalid_vector_length",
        VMError::MissingHalt => "missing_halt",
        VMError::VectorExtensionDisabled => "vector_disabled",
        VMError::ZkExtensionDisabled => "zk_disabled",
        VMError::NullifierAlreadyUsed => "nullifier_used",
        VMError::PermissionDenied => "permission_denied",
        VMError::PrivacyViolation => "privacy_violation",
        VMError::ReentrantCall => "reentrant_call",
        VMError::CallDepthExceeded => "call_depth_exceeded",
        VMError::RegisterOutOfBounds => "register_out_of_bounds",
        VMError::NoritoInvalid => "norito_invalid",
        VMError::AbiTypeNotAllowed { .. } => "abi_type_not_allowed",
        VMError::HostOutputBudgetExceeded { .. } => "host_output_budget_exceeded",
        VMError::AmxBudgetExceeded { .. } => "amx_budget_exceeded",
        VMError::Metered { .. } => unreachable!("as_unmetered peels metered wrappers"),
    }
}
fn vm_error_kind(error: &VMError) -> SoracloudRuntimeExecutionErrorKind {
    match error.as_unmetered() {
        VMError::ExecutionDeferred(_) | VMError::AllocationDeferred(_) => {
            SoracloudRuntimeExecutionErrorKind::Unavailable
        }
        _ => SoracloudRuntimeExecutionErrorKind::Internal,
    }
}
fn persist_staged_runtime_artifact(
    root: PathBuf,
    artifact: Option<&StagedRuntimeArtifact>,
) -> Result<Option<Hash>, SoracloudRuntimeExecutionError> {
    let Some(artifact) = artifact else {
        return Ok(None);
    };
    fs::create_dir_all(&root).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "create Soracloud runtime artifact root {}: {error}",
                root.display()
            ),
        )
    })?;
    let path = root.join(hash_cache_name(artifact.artifact_hash));
    fs::write(&path, &artifact.bytes).map_err(|error| {
        SoracloudRuntimeExecutionError::new(
            SoracloudRuntimeExecutionErrorKind::Internal,
            format!(
                "persist Soracloud runtime artifact `{}` at {}: {error}",
                artifact.artifact_path,
                path.display()
            ),
        )
    })?;
    Ok(Some(artifact.artifact_hash))
}
fn sanitized_relative_material_path(key: &str) -> Result<PathBuf, VMError> {
    if key.trim().is_empty() {
        return Err(VMError::PermissionDenied);
    }
    let mut path = PathBuf::new();
    for component in key.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(VMError::PermissionDenied);
        }
        path.push(storage_path_component(component));
    }
    Ok(path)
}
#[cfg(test)]
fn parse_soracloud_egress_url(raw: &str) -> Option<reqwest::Url> {
    if raw.is_empty()
        || raw.trim() != raw
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return None;
    }
    let parsed = reqwest::Url::parse(raw).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
    {
        return None;
    }
    let authority = raw.split_once("://")?.1.split(['/', '?', '#']).next()?;
    if authority.contains('@') || parsed.host_str()?.is_empty() {
        return None;
    }
    Some(parsed)
}
fn soracloud_egress_ip_is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_unspecified()
                && !address.is_multicast()
                && first != 0
                && !(first == 100 && (64..=127).contains(&second))
                && !(first == 192 && second == 0 && third == 0)
                && !(first == 192 && second == 88 && third == 99)
                && !(first == 198 && (18..=19).contains(&second))
                && first < 240
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return soracloud_egress_ip_is_public(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            let global_unicast = segments[0] & 0xe000 == 0x2000;
            let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
            let special_purpose = segments[0] == 0x2001 && segments[1] <= 0x01ff;
            let six_to_four = segments[0] == 0x2002;
            global_unicast
                && !documentation
                && !special_purpose
                && !six_to_four
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
        }
    }
}
fn validate_soracloud_egress_socket_addrs(
    mut addresses: Vec<SocketAddr>,
    expected_port: u16,
    allow_test_loopback: bool,
) -> Option<Vec<SocketAddr>> {
    if addresses.is_empty()
        || addresses.len() > SORACLOUD_EGRESS_DNS_MAX_ADDRESSES_V1
        || addresses.iter().any(|address| {
            address.port() != expected_port
                || (!soracloud_egress_ip_is_public(address.ip())
                    && !(allow_test_loopback && address.ip().is_loopback()))
        })
    {
        return None;
    }
    addresses.sort_unstable();
    addresses.dedup();
    Some(addresses)
}
struct SoracloudEgressDnsReservation;
impl SoracloudEgressDnsReservation {
    fn acquire() -> Option<Self> {
        SORACLOUD_EGRESS_DNS_IN_FLIGHT_V1
            .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Acquire, |current| {
                (current < SORACLOUD_EGRESS_DNS_MAX_IN_FLIGHT_V1).then(|| current.saturating_add(1))
            })
            .ok()?;
        Some(Self)
    }
}
impl Drop for SoracloudEgressDnsReservation {
    fn drop(&mut self) {
        SORACLOUD_EGRESS_DNS_IN_FLIGHT_V1.fetch_sub(1, AtomicOrdering::AcqRel);
    }
}
fn resolve_soracloud_egress_dns_bounded(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let reservation = SoracloudEgressDnsReservation::acquire()?;
    let host = host.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    let resolver = thread::Builder::new()
        .name("soracloud-egress-dns".to_owned())
        .spawn(move || {
            let _reservation = reservation;
            let resolved = (host.as_str(), port)
                .to_socket_addrs()
                .ok()
                .and_then(|addresses| {
                    let mut bounded = Vec::with_capacity(SORACLOUD_EGRESS_DNS_MAX_ADDRESSES_V1);
                    for address in addresses {
                        if bounded.len() == SORACLOUD_EGRESS_DNS_MAX_ADDRESSES_V1 {
                            return None;
                        }
                        bounded.push(address);
                    }
                    (!bounded.is_empty()).then_some(bounded)
                });
            let _ = sender.send(resolved);
        })
        .ok()?;
    let resolved = receiver
        .recv_timeout(SORACLOUD_EGRESS_DNS_TIMEOUT_V1)
        .ok()?;
    resolver.join().ok()?;
    resolved
}
fn resolve_soracloud_egress_socket_addrs(url: &reqwest::Url) -> Option<Vec<SocketAddr>> {
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    let addresses = if let Some(address) = parse_url_host_ip_literal(host) {
        vec![SocketAddr::new(address, port)]
    } else {
        resolve_soracloud_egress_dns_bounded(host, port)?
    };
    // Unit HTTP fixtures are necessarily loopback-only. Production builds do
    // not compile this exception; mixed public/special-use DNS answers remain
    // rejected even in tests.
    #[cfg(test)]
    let allow_test_loopback =
        !addresses.is_empty() && addresses.iter().all(|address| address.ip().is_loopback());
    #[cfg(not(test))]
    let allow_test_loopback = false;
    validate_soracloud_egress_socket_addrs(addresses, port, allow_test_loopback)
}
fn build_soracloud_direct_http_client(
    host: &str,
    resolved_addresses: &[SocketAddr],
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::blocking::Client, reqwest::Error> {
    let builder = reqwest::blocking::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        // Soracloud policy names the direct destination. Ambient proxy routing
        // would bypass both that decision and the pinned DNS result.
        .no_proxy();
    let builder = if parse_url_host_ip_literal(host).is_some() {
        builder
    } else {
        builder.resolve_to_addrs(host, resolved_addresses)
    };
    builder.build()
}
fn hash_cache_name(hash: Hash) -> String {
    sanitize_path_component(&hash.to_string())
}
fn parse_url_host_ip_literal(host: &str) -> Option<IpAddr> {
    // `Url::host_str` retains the brackets around IPv6 literals. Normalize
    // those brackets before applying the same IP policy to IPv4 and IPv6.
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    literal.parse().ok()
}
fn normalize_provider_base_url(raw: &str) -> Option<reqwest::Url> {
    normalize_provider_origin_url(raw, false)
}
#[cfg(not(test))]
fn normalize_remote_provider_base_url(raw: &str) -> Option<reqwest::Url> {
    normalize_provider_base_url(raw)
}
#[cfg(test)]
fn normalize_remote_provider_base_url(raw: &str) -> Option<reqwest::Url> {
    normalize_provider_origin_url(raw, true)
}
fn normalize_provider_origin_url(
    raw: &str,
    allow_test_loopback_http: bool,
) -> Option<reqwest::Url> {
    if raw.is_empty()
        || raw.trim() != raw
        || raw.contains('*')
        || raw.contains('@')
        || raw.contains('\\')
        || raw.contains('%')
        || raw.chars().any(char::is_control)
    {
        return None;
    }
    let with_scheme = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = reqwest::Url::parse(&with_scheme).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
    {
        return None;
    }
    let authority_start = raw.find("://").map_or(0, |offset| offset + 3);
    if let Some(path_start) = raw[authority_start..].find('/') {
        let path_start = authority_start.checked_add(path_start)?;
        if &raw[path_start..] != "/" {
            return None;
        }
    }
    let host = url.host_str()?;
    let host_without_root_dot = host.strip_suffix('.').unwrap_or(host);
    if host_without_root_dot.eq_ignore_ascii_case("localhost")
        || host_without_root_dot
            .to_ascii_lowercase()
            .ends_with(".localhost")
    {
        return None;
    }
    let ip_literal = parse_url_host_ip_literal(host);
    if ip_literal.is_none() && url.domain().is_none() {
        // A URL host must classify as either a domain or an IP literal. Keep
        // that parser invariant explicit so a future representation change
        // cannot silently route a non-domain literal through DNS policy.
        return None;
    }
    match url.scheme() {
        "https" => {
            if ip_literal.is_some_and(|address| !soracloud_egress_ip_is_public(address)) {
                return None;
            }
        }
        "http"
            if allow_test_loopback_http
                && ip_literal.is_some_and(|address| address.is_loopback()) => {}
        _ => return None,
    }
    Some(url)
}
fn current_unix_time_secs() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
fn provider_advert_is_fresh(advert: &sorafs_manifest::ProviderAdvertV1, now: u64) -> bool {
    now < advert.expires_at
        && advert.validate_with_body(now).is_ok()
        && advert.verify_signature().is_ok()
}
#[cfg(any(target_os = "linux", test))]
fn open_inrou_runtime_log(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    label: &str,
) -> io::Result<fs::File> {
    validate_inrou_single_component(name)?;
    let path = directory.path().join(name);
    let named = match rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => Some(metadata),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(io::Error::from(error)),
    };
    if let Some(metadata) = named.as_ref()
        && (rustix::fs::FileType::from_raw_mode(metadata.st_mode)
            != rustix::fs::FileType::RegularFile
            || metadata.st_nlink as u64 != 1
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || u32::from(metadata.st_mode) & 0o077 != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{label} {} must be owner-private, runtime-owned, and singly linked",
                path.display()
            ),
        ));
    }
    let flags = rustix::fs::OFlags::WRONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
        | if named.is_none() {
            rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL
        } else {
            rustix::fs::OFlags::empty()
        };
    let file = fs::File::from(
        rustix::fs::openat(
            &directory.directory,
            name,
            flags,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(io::Error::from)?,
    );
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} did not open as a regular file", path.display()),
        ));
    }
    if let Some(named) = named.as_ref()
        && !inrou_stat_matches_metadata(named, &opened)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} changed while it was opened", path.display()),
        ));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if opened.nlink() != 1 || opened.uid() != effective_uid || opened.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{label} {} did not retain private runtime custody",
                path.display()
            ),
        ));
    }
    file.set_len(0)?;
    let named_after = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if !inrou_stat_matches_metadata(&named_after, &file.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {} changed during truncation", path.display()),
        ));
    }
    Ok(file)
}
#[cfg(any(target_os = "linux", test))]
fn drain_inrou_runtime_log_bounded(mut reader: impl io::Read, mut log: fs::File) -> io::Result<()> {
    let payload_limit = SORACLOUD_INROU_LOG_MAX_BYTES
        .saturating_sub(SORACLOUD_INROU_LOG_TRUNCATION_MARKER.len() as u64);
    let mut payload_written = 0_u64;
    let mut marked_truncated = false;
    let mut log_writable = true;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let remaining = payload_limit.saturating_sub(payload_written);
        let to_write = usize::try_from(remaining.min(read as u64)).unwrap_or(0);
        if log_writable && to_write != 0 {
            if let Err(error) = log.write_all(&buffer[..to_write]) {
                iroha_logger::warn!(?error, "failed to append bounded Inrou runtime log");
                log_writable = false;
            } else {
                payload_written = payload_written.saturating_add(to_write as u64);
            }
        }
        if read > to_write && !marked_truncated {
            if log_writable && let Err(error) = log.write_all(SORACLOUD_INROU_LOG_TRUNCATION_MARKER)
            {
                iroha_logger::warn!(?error, "failed to mark truncated Inrou runtime log");
                log_writable = false;
            }
            marked_truncated = true;
        }
    }
    if log_writable {
        log.flush()?;
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn spawn_inrou_runtime_log_drain(
    reader: impl io::Read + Send + 'static,
    log: fs::File,
    thread_name: &'static str,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            if let Err(error) = drain_inrou_runtime_log_bounded(reader, log) {
                iroha_logger::warn!(?error, %thread_name, "Inrou runtime log drain failed");
            }
        })
}
#[cfg(target_os = "linux")]
fn attach_inrou_runtime_log_drains(
    child: &mut std::process::Child,
    stderr_log: fs::File,
) -> eyre::Result<Vec<thread::JoinHandle<()>>> {
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => eyre::bail!("Inrou runtime stderr pipe was not configured"),
    };
    let stderr_drain = spawn_inrou_runtime_log_drain(stderr, stderr_log, "inrou-runtime-stderr")
        .wrap_err("spawn Inrou stderr drain")?;
    Ok(vec![stderr_drain])
}
fn terminate_inrou_child_bounded(
    child: &mut std::process::Child,
) -> eyre::Result<std::process::ExitStatus> {
    let initial_poll_error = match child.try_wait() {
        Ok(Some(status)) => return Ok(status),
        Ok(None) => None,
        Err(error) => Some(error),
    };
    let kill_error = child.kill().err();
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_CHILD_STOP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                eyre::bail!(
                    "Inrou child pid {} did not exit within {:?} after SIGKILL{}",
                    child.id(),
                    SORACLOUD_INROU_CHILD_STOP_TIMEOUT,
                    format_inrou_child_stop_errors(
                        initial_poll_error.as_ref(),
                        kill_error.as_ref()
                    ),
                );
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "poll Inrou child pid {} after SIGKILL{}",
                        child.id(),
                        format_inrou_child_stop_errors(
                            initial_poll_error.as_ref(),
                            kill_error.as_ref()
                        ),
                    )
                });
            }
        }
    }
}
fn wait_for_inrou_child_exit_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> eyre::Result<Option<std::process::ExitStatus>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!(
                        "poll Inrou child pid {} during its graceful shutdown window",
                        child.id()
                    )
                });
            }
        }
    }
}
fn format_inrou_child_stop_errors(
    initial_poll_error: Option<&io::Error>,
    kill_error: Option<&io::Error>,
) -> String {
    let mut suffix = String::new();
    if let Some(error) = initial_poll_error {
        suffix.push_str(&format!("; initial status poll failed: {error}"));
    }
    if let Some(error) = kill_error {
        suffix.push_str(&format!("; sending SIGKILL failed: {error}"));
    }
    suffix
}
#[cfg(any(target_os = "linux", test))]
fn inrou_termination_error_suffix(termination: &eyre::Result<std::process::ExitStatus>) -> String {
    termination
        .as_ref()
        .err()
        .map_or_else(String::new, |error| {
            format!("; bounded child termination also failed: {error}")
        })
}
fn join_inrou_log_drains_bounded(log_drains: &mut Vec<thread::JoinHandle<()>>) {
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT;
    while log_drains.iter().any(|drain| !drain.is_finished())
        && std::time::Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(10));
    }
    for drain in log_drains.drain(..) {
        if drain.is_finished() {
            let _ = drain.join();
        } else {
            iroha_logger::warn!(
                timeout_ms = SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT.as_millis(),
                "detaching an Inrou log drain that did not stop before its deadline"
            );
        }
    }
}
#[cfg(target_os = "linux")]
fn stderr_log_excerpt(path: &Path) -> String {
    let Ok((mut file, metadata)) =
        open_soracloud_regular_file_no_follow(path, "runtime stderr log")
    else {
        return String::new();
    };
    let start = metadata
        .len()
        .saturating_sub(SORACLOUD_RUNTIME_STDERR_TAIL_BYTES);
    if file.seek(io::SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    if file
        .take(SORACLOUD_RUNTIME_STDERR_TAIL_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return String::new();
    }
    let tail_start = if start == 0 {
        0
    } else {
        bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| index.saturating_add(1))
    };
    let contents = String::from_utf8_lossy(&bytes[tail_start..]);
    let mut tail = contents
        .lines()
        .rev()
        .take(6)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if tail.is_empty() {
        return String::new();
    }
    tail.reverse();
    tail.join(" | ")
}
#[cfg(any(target_os = "linux", test))]
fn effective_inrou_lifecycle_grace(
    operator_minimum: Duration,
    workload_minimum_secs: u32,
) -> Duration {
    operator_minimum.max(Duration::from_secs(u64::from(workload_minimum_secs)))
}
impl HostedHttpWorker {
    #[cfg(target_os = "linux")]
    fn new(
        cache_key: HostedHttpWorkerCacheKey,
        child: std::process::Child,
        log_drains: Vec<thread::JoinHandle<()>>,
        listen_base_url: String,
        egress_accounting: PortableVmReplicaEgressAccounting,
        stderr_log_path: PathBuf,
        stop_grace: Duration,
        port_forward: PortableVmLoopbackBridge,
        qmp_control: Arc<Mutex<PortableVmQmpControl>>,
        #[cfg(target_os = "linux")] loopback_firewall: InrouLoopbackOwnerFirewall,
        #[cfg(target_os = "linux")] cgroup: inrou_cgroup::InrouWorkerCgroup,
    ) -> Self {
        Self {
            cache_key,
            child,
            log_drains,
            listen_base_url,
            egress_accounting,
            stderr_log_path,
            stop_grace,
            port_forward: Some(port_forward),
            qmp_control: Some(qmp_control),
            #[cfg(target_os = "linux")]
            loopback_firewall: Some(loopback_firewall),
            #[cfg(target_os = "linux")]
            cgroup: Some(cgroup),
        }
    }
    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }
    fn accounted_egress_bytes(&self) -> Option<u64> {
        if self.cache_key.runtime != SoraContainerRuntimeV1::Inrou {
            return None;
        }
        Some(self.egress_accounting.reporter_accounted_egress_bytes())
    }
    fn force_stop_child(&mut self) -> eyre::Result<std::process::ExitStatus> {
        #[cfg(target_os = "linux")]
        self.cgroup
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Inrou worker lost its lifetime cgroup"))?
            .kill_and_attest_empty_bounded()
            .wrap_err("terminate the complete Inrou lifetime before reaping its watchdog")?;
        terminate_inrou_child_bounded(&mut self.child)
    }
    fn stop(&mut self) {
        let _ = &self.stderr_log_path;
        if let Some(mut port_forward) = self.port_forward.take() {
            port_forward.stop();
        }
        let termination = match self.child.try_wait() {
            Ok(Some(status)) => Ok(status),
            Ok(None) => {
                #[cfg(target_os = "linux")]
                let graceful_request = self.qmp_control.as_ref().map_or_else(
                    || Err(eyre::eyre!("Inrou worker lost its QMP control channel")),
                    |qmp_control| {
                        request_inrou_qmp_system_powerdown(
                            &mut qmp_control.lock(),
                            self.stop_grace
                                .min(SORACLOUD_INROU_QMP_POWERDOWN_REQUEST_TIMEOUT),
                        )
                    },
                );
                #[cfg(not(target_os = "linux"))]
                let graceful_request: eyre::Result<()> = Err(eyre::eyre!(
                    "Inrou PortableVM graceful shutdown requires Linux QMP"
                ));

                match graceful_request {
                    Ok(()) => {
                        match wait_for_inrou_child_exit_bounded(&mut self.child, self.stop_grace) {
                            Ok(Some(status)) => Ok(status),
                            Ok(None) => {
                                iroha_logger::warn!(
                                    pid = self.child.id(),
                                    stop_grace_ms = self.stop_grace.as_millis(),
                                    "Inrou PortableVM exceeded its effective graceful shutdown window; forcing bounded SIGKILL"
                                );
                                self.force_stop_child()
                            }
                            Err(error) => {
                                iroha_logger::error!(
                                    ?error,
                                    pid = self.child.id(),
                                    "failed to attest Inrou PortableVM exit during graceful shutdown; forcing bounded SIGKILL"
                                );
                                self.force_stop_child()
                            }
                        }
                    }
                    Err(error) => {
                        iroha_logger::error!(
                            ?error,
                            pid = self.child.id(),
                            "Inrou QMP system_powerdown request failed; forcing bounded SIGKILL"
                        );
                        self.force_stop_child()
                    }
                }
            }
            Err(error) => {
                iroha_logger::error!(
                    ?error,
                    pid = self.child.id(),
                    "failed to poll Inrou PortableVM before graceful shutdown; forcing bounded SIGKILL"
                );
                self.force_stop_child()
            }
        };
        #[cfg(target_os = "linux")]
        let cgroup_cleanup = self.cgroup.take().map(|mut cgroup| {
            let cgroup_empty = cgroup.kill_and_attest_empty_bounded();
            let result: eyre::Result<()> = match (&termination, cgroup_empty) {
                (Ok(status), Ok(empty)) => cgroup.release_attested_empty(empty).wrap_err_with(|| {
                    format!(
                        "release the empty Inrou worker cgroup after direct child exited with {status}"
                    )
                }),
                (Err(termination), Ok(_)) => Err(eyre::eyre!(
                    "Inrou worker cgroup is empty, but direct-child termination is unproven: {termination}"
                )),
                (Ok(status), Err(cgroup_empty)) => Err(cgroup_empty).wrap_err_with(|| {
                    format!(
                        "Inrou direct child exited with {status}, but its cgroup could not be proved empty"
                    )
                }),
                (Err(termination), Err(cgroup_empty)) => {
                    Err(cgroup_empty).wrap_err_with(|| {
                        format!(
                            "Inrou direct-child termination and empty-cgroup attestation both failed: {termination}"
                        )
                    })
                }
            };
            if result.is_err() {
                // Retain the live object and its deterministic path. A
                // subsequent launch with this worker identity must fail
                // rather than silently escape its stale confined group.
                std::mem::forget(cgroup);
            }
            result
        });
        #[cfg(target_os = "linux")]
        if termination.is_err()
            || cgroup_cleanup
                .as_ref()
                .is_some_and(|cleanup| cleanup.is_err())
        {
            if let Some(firewall) = self.loopback_firewall.take() {
                // A worker or descendant whose bounded cleanup failed must
                // not outlive the owner firewall.
                std::mem::forget(firewall);
            }
        }
        if let Err(error) = termination {
            iroha_logger::warn!(
                ?error,
                pid = self.child.id(),
                "Inrou PortableVM child did not stop before its deadline; retaining the owner firewall"
            );
        }
        #[cfg(target_os = "linux")]
        if let Some(Err(error)) = cgroup_cleanup {
            iroha_logger::error!(
                ?error,
                pid = self.child.id(),
                "Inrou cgroup did not become empty before its deadline; retaining the cgroup and owner firewall"
            );
        }
        join_inrou_log_drains_bounded(&mut self.log_drains);
        let _ = self.qmp_control.take();
        #[cfg(target_os = "linux")]
        let _ = self.loopback_firewall.take();
    }
}
impl Drop for HostedHttpWorker {
    fn drop(&mut self) {
        self.stop();
    }
}
fn hosted_http_runtime_state_path(materialization_dir: &Path) -> PathBuf {
    materialization_dir.join(SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_FILE_V1)
}
fn write_hosted_http_runtime_state(
    materialization_dir: &Path,
    service_name: &str,
    service_version: &str,
    process_generation: u64,
    health_status: SoraServiceHealthStatusV1,
    listen_base_url: Option<&str>,
    pid: Option<u32>,
    accounted_egress_bytes: u64,
    last_error: Option<String>,
    replicas: Vec<SoracloudHostedHttpReplicaRuntimeStateV1>,
) -> eyre::Result<()> {
    let runtime_state = SoracloudHostedHttpRuntimeStateV1 {
        schema_version: SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1,
        service_name: service_name.to_owned(),
        service_version: service_version.to_owned(),
        process_generation,
        health_status,
        listen_base_url: listen_base_url.map(ToOwned::to_owned),
        pid,
        accounted_egress_bytes,
        replicas,
        last_error,
        updated_at_ms: soracloud_runtime_observed_at_ms(),
    };
    write_hosted_http_runtime_state_document(materialization_dir, &runtime_state)
}
fn read_hosted_http_runtime_state(
    materialization_dir: &Path,
) -> io::Result<Option<SoracloudHostedHttpRuntimeStateV1>> {
    let state = read_json_optional(
        &hosted_http_runtime_state_path(materialization_dir),
        SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_MAX_BYTES,
        "Soracloud hosted HTTP runtime state",
    )?;
    state
        .map(|state| {
            validate_hosted_http_runtime_state_bounds(&state)?;
            Ok(state)
        })
        .transpose()
}
fn build_native_service_data_dir(state_dir: &Path, service_name: &str) -> PathBuf {
    state_dir
        .join("service_data")
        .join(storage_path_component(service_name))
}
fn write_hosted_http_runtime_state_document(
    materialization_dir: &Path,
    runtime_state: &SoracloudHostedHttpRuntimeStateV1,
) -> eyre::Result<()> {
    validate_hosted_http_runtime_state_bounds(runtime_state)?;
    write_json_atomic_bounded(
        &hosted_http_runtime_state_path(materialization_dir),
        runtime_state,
        SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_MAX_BYTES,
        "Soracloud hosted HTTP runtime state",
    )
    .map_err(eyre::Report::from)
}
fn validate_hosted_http_runtime_state_bounds(
    runtime_state: &SoracloudHostedHttpRuntimeStateV1,
) -> io::Result<()> {
    if runtime_state.schema_version != SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported Soracloud hosted HTTP runtime state schema version {}; expected {}",
                runtime_state.schema_version, SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1
            ),
        ));
    }
    if runtime_state.replicas.len() > SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_MAX_REPLICAS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soracloud hosted HTTP runtime state exceeds its replica count limit",
        ));
    }
    if [
        Some(runtime_state.service_name.as_str()),
        Some(runtime_state.service_version.as_str()),
        runtime_state.listen_base_url.as_deref(),
        runtime_state.last_error.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(runtime_state.replicas.iter().flat_map(|replica| {
        [
            Some(replica.placement_incarnation.as_str()),
            replica.listen_base_url.as_deref(),
            replica.last_error.as_deref(),
        ]
        .into_iter()
        .flatten()
    }))
    .any(|value| value.len() > SORACLOUD_RUNTIME_STATE_MAX_STRING_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soracloud hosted HTTP runtime state contains an oversized string",
        ));
    }
    if runtime_state
        .replicas
        .iter()
        .any(|replica| Hash::from_str(&replica.placement_incarnation).is_err())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Soracloud hosted HTTP runtime state contains an invalid placement incarnation",
        ));
    }
    Ok(())
}
fn runtime_error_summary(error: &eyre::Report) -> String {
    const MAX_RUNTIME_ERROR_BYTES: usize = 4096;
    let mut parts = Vec::new();
    for cause in error.chain() {
        let text = cause.to_string();
        let text = text.trim();
        if text.is_empty() || parts.iter().any(|existing| existing == text) {
            continue;
        }
        parts.push(text.to_owned());
    }
    let mut summary = if parts.is_empty() {
        error.to_string()
    } else {
        parts.join(": ")
    };
    if summary.len() > MAX_RUNTIME_ERROR_BYTES {
        summary.truncate(MAX_RUNTIME_ERROR_BYTES);
        summary.push_str("...");
    }
    summary
}
fn persist_hosted_http_replica_runtime_state(
    materialization_dir: &Path,
    service_name: &str,
    service_version: &str,
    process_generation: u64,
    replica_slot: u16,
    placement_incarnation: &str,
    health_status: SoraServiceHealthStatusV1,
    listen_base_url: Option<&str>,
    pid: Option<u32>,
    accounted_egress_bytes: u64,
    last_error: Option<String>,
) -> eyre::Result<SoracloudHostedHttpReplicaRuntimeStateV1> {
    let updated_at_ms = soracloud_runtime_observed_at_ms();
    let replica_runtime_state = SoracloudHostedHttpReplicaRuntimeStateV1 {
        replica_slot,
        placement_incarnation: placement_incarnation.to_owned(),
        health_status,
        listen_base_url: listen_base_url.map(ToOwned::to_owned),
        pid,
        last_error: last_error.clone(),
        updated_at_ms,
    };
    write_hosted_http_runtime_state_document(
        materialization_dir,
        &SoracloudHostedHttpRuntimeStateV1 {
            schema_version: SORACLOUD_HOSTED_HTTP_RUNTIME_STATE_VERSION_V1,
            service_name: service_name.to_owned(),
            service_version: service_version.to_owned(),
            process_generation,
            health_status,
            listen_base_url: listen_base_url.map(ToOwned::to_owned),
            pid,
            accounted_egress_bytes,
            replicas: vec![replica_runtime_state.clone()],
            last_error,
            updated_at_ms,
        },
    )?;
    Ok(replica_runtime_state)
}
fn aggregate_hosted_http_revision_health_status(
    replicas: &[SoracloudHostedHttpReplicaRuntimeStateV1],
) -> SoraServiceHealthStatusV1 {
    if replicas
        .iter()
        .any(|replica| replica.health_status == SoraServiceHealthStatusV1::Healthy)
    {
        return SoraServiceHealthStatusV1::Healthy;
    }
    if replicas
        .iter()
        .any(|replica| replica.health_status == SoraServiceHealthStatusV1::Hydrating)
    {
        return SoraServiceHealthStatusV1::Hydrating;
    }
    if replicas
        .iter()
        .any(|replica| replica.health_status == SoraServiceHealthStatusV1::Degraded)
    {
        return SoraServiceHealthStatusV1::Degraded;
    }
    replicas
        .first()
        .map_or(SoraServiceHealthStatusV1::Degraded, |replica| {
            replica.health_status
        })
}
fn aggregate_hosted_http_revision_listener(
    replicas: &[SoracloudHostedHttpReplicaRuntimeStateV1],
) -> Option<&str> {
    replicas
        .iter()
        .find(|replica| {
            replica.health_status == SoraServiceHealthStatusV1::Healthy
                && replica.listen_base_url.is_some()
        })
        .and_then(|replica| replica.listen_base_url.as_deref())
}
fn aggregate_hosted_http_revision_pid(
    replicas: &[SoracloudHostedHttpReplicaRuntimeStateV1],
) -> Option<u32> {
    replicas
        .iter()
        .find(|replica| {
            replica.health_status == SoraServiceHealthStatusV1::Healthy && replica.pid.is_some()
        })
        .and_then(|replica| replica.pid)
}
fn aggregate_hosted_http_revision_last_error(
    replicas: &[SoracloudHostedHttpReplicaRuntimeStateV1],
) -> Option<String> {
    replicas
        .iter()
        .find_map(|replica| replica.last_error.clone())
}
fn hosted_http_replica_slot_dir_name(replica_slot: u16) -> String {
    format!("replica-{replica_slot:04}")
}
fn hosted_http_replica_materialization_dir(service_dir: &Path, replica_slot: u16) -> PathBuf {
    service_dir
        .join("replicas")
        .join(hosted_http_replica_slot_dir_name(replica_slot))
}
fn build_hosted_http_local_replica_plans(
    service_dir: &Path,
    placements: &[SoraInrouReplicaPlacementV1],
    runtime_state: Option<&SoracloudHostedHttpRuntimeStateV1>,
    hydration_complete: bool,
    hosted_http_lease_active: bool,
) -> Vec<SoracloudRuntimeReplicaPlan> {
    if !hosted_http_lease_active || placements.is_empty() {
        return Vec::new();
    }
    let observed_replicas = runtime_state
        .map(|state| {
            state
                .replicas
                .iter()
                .cloned()
                .map(|replica| (replica.replica_slot, replica))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let default_health = if !hydration_complete {
        SoraServiceHealthStatusV1::Hydrating
    } else {
        SoraServiceHealthStatusV1::Degraded
    };
    placements
        .iter()
        .map(|placement| {
            let replica_slot = placement.replica_slot;
            let materialization_dir =
                hosted_http_replica_materialization_dir(service_dir, replica_slot);
            let placement_incarnation = placement.placement_incarnation.to_string();
            let observed = observed_replicas
                .get(&replica_slot)
                .filter(|replica| replica.placement_incarnation == placement_incarnation);
            SoracloudRuntimeReplicaPlan {
                replica_slot,
                lease_started_height: placement.lease_started_height,
                placement_incarnation,
                host_availability: placement.host_availability,
                validator_account_id: placement.validator_account_id.to_string(),
                peer_id: placement.peer_id.clone(),
                materialization_dir: materialization_dir.display().to_string(),
                health_status: observed.map_or(default_health, |replica| replica.health_status),
                listen_base_url: observed.and_then(|replica| replica.listen_base_url.clone()),
                pid: observed.and_then(|replica| replica.pid),
                last_error: observed.and_then(|replica| replica.last_error.clone()),
            }
        })
        .collect()
}
fn project_hosted_http_replica_plan(
    plan: &SoracloudRuntimeServicePlan,
    replica_slot: u16,
) -> eyre::Result<SoracloudRuntimeServicePlan> {
    let mut replica_plan = plan.clone();
    let replica_materialization_dir = hosted_http_replica_materialization_dir(
        &PathBuf::from(&plan.materialization_dir),
        replica_slot,
    );
    replica_plan.materialization_dir = replica_materialization_dir.display().to_string();
    replica_plan.local_replica_slots = vec![replica_slot];
    let assigned_replica = plan
        .local_replicas
        .iter()
        .find(|replica| replica.replica_slot == replica_slot)
        .cloned()
        .ok_or_else(|| {
            eyre::eyre!(
                "local Inrou replica slot {replica_slot} has no authenticated placement identity"
            )
        })?;
    if assigned_replica.placement_incarnation.trim().is_empty()
        || assigned_replica.validator_account_id.trim().is_empty()
        || assigned_replica.peer_id.trim().is_empty()
    {
        eyre::bail!(
            "local Inrou replica slot {replica_slot} has an incomplete authenticated placement identity"
        );
    }
    replica_plan.local_replicas = vec![assigned_replica];
    replica_plan.effective_env.insert(
        "SORACLOUD_REPLICA_SLOT".to_owned(),
        replica_slot.to_string(),
    );
    replica_plan.effective_env.insert(
        "SORACLOUD_SERVICE_VERSION".to_owned(),
        plan.service_version.clone(),
    );
    for volume in &mut replica_plan.lease_volumes {
        volume.local_materialization_dir = hosted_http_per_replica_volume_materialization_dir(
            &PathBuf::from(&volume.local_materialization_dir),
            replica_slot,
        )
        .display()
        .to_string();
    }
    Ok(replica_plan)
}
fn hosted_http_per_replica_volume_materialization_dir(
    volume_dir: &Path,
    replica_slot: u16,
) -> PathBuf {
    let replica_dir_name = hosted_http_replica_slot_dir_name(replica_slot);
    match (volume_dir.parent(), volume_dir.file_name()) {
        (Some(parent), Some(volume_name)) => parent.join(replica_dir_name).join(volume_name),
        _ => volume_dir.join(replica_dir_name),
    }
}
fn build_hosted_http_service_volume_dir(
    state_dir: &Path,
    service_name: &str,
    service_version: &str,
    lease_started_height: u64,
    volume_name: &str,
) -> PathBuf {
    build_native_service_data_dir(state_dir, service_name)
        .join("revisions")
        .join(storage_path_component(service_version))
        .join(format!("lease-height-{lease_started_height:020}"))
        .join("volumes")
        .join("per-replica")
        .join(storage_path_component(volume_name))
}
#[cfg(any(target_os = "linux", test))]
struct InrouDataVolumeMount {
    mount_path: String,
    kind: InrouDataVolumeMountKind,
}
#[cfg(any(target_os = "linux", test))]
struct InrouVolumeSystemdArtifacts {
    mount_unit_name: String,
    mount_unit: String,
    attestation_unit_name: String,
    attestation_unit: String,
    attestation_script_path: String,
    attestation_script: String,
}
#[cfg(any(target_os = "linux", test))]
enum InrouDataVolumeMountKind {
    BlockDevice {
        device_serial: String,
        filesystem_type: String,
        filesystem_uuid: String,
        mount_options: String,
        initialize_filesystem: bool,
    },
}
#[cfg(any(target_os = "linux", test))]
struct PortableVmLeaseDisk {
    mount_path: String,
    image_path: PathBuf,
    image_name: OsString,
    #[cfg(all(test, unix))]
    binding_path: PathBuf,
    binding_name: OsString,
    #[cfg(all(test, unix))]
    initialized_marker_path: PathBuf,
    initialized_marker_name: OsString,
    directory: PinnedInrouDirectory,
    binding: Hash,
    exact_bytes: u64,
    image_format: &'static str,
    device_serial: String,
    filesystem_type: String,
    filesystem_uuid: String,
    mount_options: String,
    initialize_filesystem: bool,
}
#[cfg(any(target_os = "linux", test))]
impl std::fmt::Debug for PortableVmLeaseDisk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortableVmLeaseDisk")
            .field("mount_path", &self.mount_path)
            .field("image_path", &"<redacted>")
            .field("binding_path", &"<redacted>")
            .field("initialized_marker_path", &"<redacted>")
            .field("binding", &self.binding)
            .field("exact_bytes", &self.exact_bytes)
            .field("image_format", &self.image_format)
            .field("device_serial", &self.device_serial)
            .field("filesystem_type", &self.filesystem_type)
            .field("filesystem_uuid", &self.filesystem_uuid)
            .field("mount_options", &self.mount_options)
            .field("initialize_filesystem", &self.initialize_filesystem)
            .finish()
    }
}
#[cfg(any(target_os = "linux", test))]
struct PortableVmNetworkPlan {
    netdev: String,
    listen_base_url: String,
    public_listener: TcpListener,
    backend_reservation: TcpListener,
    expected_backend: SocketAddr,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PortableVmChildIdentity {
    uid: u32,
    gid: u32,
    supplementary_gids: Vec<u32>,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InrouDiskCustody {
    uid: u32,
    gid: u32,
    mode: u32,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortableVmKvmDeviceAccess {
    uid: u32,
    gid: u32,
    mode: u32,
    hard_links: u64,
    rdev: u64,
    is_character_device: bool,
}
struct PortableVmQmpControl {
    #[cfg(target_os = "linux")]
    reader: io::BufReader<UnixStream>,
}
struct InrouDurableEgressCheckpoint {
    path: PathBuf,
    reporter_key_digest: [u8; 32],
    accounted_egress_bytes: Mutex<u64>,
}
impl std::fmt::Debug for InrouDurableEgressCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InrouDurableEgressCheckpoint")
            .field("path", &"<redacted>")
            .field("reporter_key_digest", &"<redacted>")
            .field("accounted_egress_bytes", &"<redacted>")
            .finish()
    }
}
impl InrouDurableEgressCheckpoint {
    fn load_or_create(
        state_dir: &Path,
        service_name: &str,
        lease_started_height: u64,
        reporting_epoch: u64,
        service_version: &str,
        replica_slot: u16,
        placement_incarnation: &Hash,
        validator_account_id: &AccountId,
        authoritative_checkpoint: Option<HostedHttpReporterCheckpointState>,
    ) -> io::Result<Arc<Self>> {
        if authoritative_checkpoint.is_some_and(|checkpoint| {
            checkpoint.lease_started_height != lease_started_height
                || checkpoint.reporting_epoch != reporting_epoch
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authoritative Inrou reporter checkpoint belongs to another lease incarnation or reporting epoch",
            ));
        }
        let directory = prepare_inrou_egress_checkpoint_dir(
            &state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR),
        )?;
        let reporter_key_digest = inrou_egress_reporter_key_digest(
            service_name,
            lease_started_height,
            reporting_epoch,
            service_version,
            replica_slot,
            placement_incarnation,
            validator_account_id,
        )?;
        let path = directory.join(format!("{}.bin", hex::encode(reporter_key_digest)));
        let recovered = match fs::symlink_metadata(&path) {
            Ok(_) => read_inrou_durable_egress_checkpoint(&path, &reporter_key_digest)?,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && authoritative_checkpoint.is_none() =>
            {
                write_inrou_durable_egress_checkpoint(&path, &reporter_key_digest, 0)?;
                0
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "durable Inrou reporter checkpoint {} is missing although an on-chain reporter checkpoint already exists",
                        path.display()
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        if authoritative_checkpoint
            .is_some_and(|authoritative| recovered < authoritative.accounted_egress_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "durable Inrou reporter checkpoint {} rolled back to {recovered} bytes behind authoritative state {}",
                    path.display(),
                    authoritative_checkpoint
                        .expect("checked authoritative checkpoint")
                        .accounted_egress_bytes
                ),
            ));
        }
        Ok(Arc::new(Self {
            path,
            reporter_key_digest,
            accounted_egress_bytes: Mutex::new(recovered),
        }))
    }

    fn accounted_egress_bytes(&self) -> u64 {
        *self.accounted_egress_bytes.lock()
    }

    fn advance_to(&self, accounted_egress_bytes: u64) -> io::Result<()> {
        let mut current = self.accounted_egress_bytes.lock();
        if accounted_egress_bytes < *current {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable Inrou reporter checkpoint must never decrease",
            ));
        }
        if accounted_egress_bytes == *current {
            return Ok(());
        }
        write_inrou_durable_egress_checkpoint(
            &self.path,
            &self.reporter_key_digest,
            accounted_egress_bytes,
        )?;
        *current = accounted_egress_bytes;
        Ok(())
    }
}

fn inrou_egress_reporter_key_digest(
    service_name: &str,
    lease_started_height: u64,
    reporting_epoch: u64,
    service_version: &str,
    replica_slot: u16,
    placement_incarnation: &Hash,
    validator_account_id: &AccountId,
) -> io::Result<[u8; 32]> {
    let encoded = norito::to_bytes(&(
        "soracloud:inrou-egress-reporter-key:v1",
        service_name.to_owned(),
        lease_started_height,
        reporting_epoch,
        service_version.to_owned(),
        replica_slot,
        *placement_incarnation,
        validator_account_id.clone(),
    ))
    .map_err(|error| io::Error::other(format!("encode Inrou reporter identity: {error}")))?;
    Ok(*Hash::new(encoded).as_ref())
}

#[cfg(unix)]
fn prepare_inrou_egress_checkpoint_dir(path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    // Runtime configuration deliberately permits peer-local relative state
    // roots. Anchor them before walking ancestors so `Path::ancestors()` does
    // not finish at the empty relative path while retaining every custody
    // check for the actual filesystem path.
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Inrou egress checkpoint directory must have a parent",
        )
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    // Relative paths end with an empty `Path` sentinel when walked through
    // `ancestors()`. It does not name a filesystem entry (`.` is validated
    // through the canonical pass below), so asking for its metadata would
    // reject every fresh relative runtime directory with `ENOENT`.
    for (index, ancestor) in parent
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty())
        .enumerate()
    {
        let metadata = fs::symlink_metadata(ancestor)?;
        let replaceable = metadata.mode() & 0o022 != 0;
        let sticky = metadata.mode() & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || (replaceable && (index == 0 || !sticky))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Inrou egress checkpoint ancestor {} is symlinked or replaceable",
                    ancestor.display()
                ),
            ));
        }
    }
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path)?;
            fs::File::open(parent)?.sync_all()?;
        }
        Err(error) => return Err(error),
    }
    let named = fs::symlink_metadata(&path)?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || named.uid() != effective_uid
        || named.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Inrou egress checkpoint directory {} must be a runtime-owned, owner-private real directory",
                path.display()
            ),
        ));
    }
    let canonical = fs::canonicalize(&path)?;
    for (index, ancestor) in canonical.ancestors().enumerate() {
        let metadata = fs::metadata(ancestor)?;
        let replaceable = metadata.mode() & 0o022 != 0;
        let sticky = metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || (replaceable && (index == 0 || !sticky))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Inrou egress checkpoint custody permits replacement through {}",
                    ancestor.display()
                ),
            ));
        }
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC)
                .bits() as i32,
        )
        .open(&canonical)?;
    let opened = directory.metadata()?;
    if opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Inrou egress checkpoint directory changed or lost private custody while opening",
        ));
    }
    Ok(canonical)
}

#[cfg(not(unix))]
fn prepare_inrou_egress_checkpoint_dir(_path: &Path) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable Inrou egress accounting requires enforceable owner-private filesystem custody",
    ))
}

fn encode_inrou_durable_egress_checkpoint(
    reporter_key_digest: &[u8; 32],
    accounted_egress_bytes: u64,
) -> [u8; SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1] {
    let mut record = [0_u8; SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1];
    record[..8].copy_from_slice(SORACLOUD_INROU_EGRESS_CHECKPOINT_MAGIC_V1);
    record[8..40].copy_from_slice(reporter_key_digest);
    record[40..48].copy_from_slice(&accounted_egress_bytes.to_le_bytes());
    let checksum = blake3::hash(&record[..48]);
    record[48..].copy_from_slice(checksum.as_bytes());
    record
}

fn read_inrou_durable_egress_checkpoint(
    path: &Path,
    expected_reporter_key_digest: &[u8; 32],
) -> io::Result<u64> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "durable Inrou egress checkpoint {} must be runtime-owned and owner-private",
                    path.display()
                ),
            ));
        }
    }
    let record = read_soracloud_regular_file_bounded(
        path,
        SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1 as u64,
        "durable Inrou egress checkpoint",
    )?;
    if record.len() != SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1
        || &record[..8] != SORACLOUD_INROU_EGRESS_CHECKPOINT_MAGIC_V1
        || &record[8..40] != expected_reporter_key_digest
        || &record[48..] != blake3::hash(&record[..48]).as_bytes()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "durable Inrou egress checkpoint {} is corrupt or belongs to another reporter",
                path.display()
            ),
        ));
    }
    Ok(u64::from_le_bytes(
        record[40..48]
            .try_into()
            .expect("checked durable checkpoint record width"),
    ))
}

fn write_inrou_durable_egress_checkpoint(
    path: &Path,
    reporter_key_digest: &[u8; 32],
    accounted_egress_bytes: u64,
) -> io::Result<()> {
    let record =
        encode_inrou_durable_egress_checkpoint(reporter_key_digest, accounted_egress_bytes);
    write_bytes_atomic(path, &record)?;
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "durable Inrou egress checkpoint {} lost private single-link custody",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn parse_inrou_egress_checkpoint_file_name(file_name: &std::ffi::OsStr) -> Option<[u8; 32]> {
    let file_name = file_name.to_str()?;
    let digest = file_name.strip_suffix(".bin")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let decoded = hex::decode(digest).ok()?;
    decoded.try_into().ok()
}

#[cfg(unix)]
fn validate_inrou_egress_checkpoint_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() != SORACLOUD_INROU_EGRESS_CHECKPOINT_RECORD_BYTES_V1 as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "durable Inrou egress checkpoint entry {} is not a private, single-link, fixed-size regular file",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn reconcile_inrou_egress_checkpoint_directory(
    state_dir: &Path,
    retained_digests: &BTreeSet<[u8; 32]>,
    maximum_entries: usize,
) -> io::Result<usize> {
    let directory = prepare_inrou_egress_checkpoint_dir(
        &state_dir.join(SORACLOUD_INROU_EGRESS_CHECKPOINT_DIR),
    )?;
    let directory_handle = fs::File::open(&directory)?;
    let directory_before = directory_handle.metadata()?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&directory)? {
        if entries.len() == maximum_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "durable Inrou egress checkpoint directory exceeds its {maximum_entries}-entry scan bound"
                ),
            ));
        }
        entries.push(entry?);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut stale = Vec::new();
    for entry in entries {
        let path = entry.path();
        let digest =
            parse_inrou_egress_checkpoint_file_name(&entry.file_name()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected entry in durable Inrou egress checkpoint directory: {}",
                        path.display()
                    ),
                )
            })?;
        let metadata = fs::symlink_metadata(&path)?;
        validate_inrou_egress_checkpoint_file_metadata(&path, &metadata)?;
        read_inrou_durable_egress_checkpoint(&path, &digest)?;
        if !retained_digests.contains(&digest) {
            stale.push((path, metadata.dev(), metadata.ino()));
        }
    }
    for (path, expected_device, expected_inode) in &stale {
        let metadata = fs::symlink_metadata(path)?;
        validate_inrou_egress_checkpoint_file_metadata(path, &metadata)?;
        if metadata.dev() != *expected_device || metadata.ino() != *expected_inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "stale durable Inrou egress checkpoint {} changed identity before removal",
                    path.display()
                ),
            ));
        }
        fs::remove_file(path)?;
    }
    if !stale.is_empty() {
        let directory_after = fs::symlink_metadata(&directory)?;
        if directory_after.file_type().is_symlink()
            || !directory_after.is_dir()
            || directory_after.dev() != directory_before.dev()
            || directory_after.ino() != directory_before.ino()
            || directory_after.uid() != directory_before.uid()
            || directory_after.mode() != directory_before.mode()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable Inrou egress checkpoint directory changed identity during pruning",
            ));
        }
        directory_handle.sync_all()?;
    }
    Ok(stale.len())
}

#[cfg(not(unix))]
fn reconcile_inrou_egress_checkpoint_directory(
    _state_dir: &Path,
    _retained_digests: &BTreeSet<[u8; 32]>,
    _maximum_entries: usize,
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable Inrou egress accounting requires enforceable filesystem custody",
    ))
}

#[derive(Clone)]
struct PortableVmEgressAccounting {
    accounted_egress_bytes: Arc<AtomicU64>,
    remaining_egress_bytes: Arc<AtomicU64>,
    exhausted: Arc<AtomicBool>,
    update_gate: Arc<RwLock<()>>,
    durable_checkpoint: Option<Arc<InrouDurableEgressCheckpoint>>,
}
impl PortableVmEgressAccounting {
    fn new(accounted_egress_bytes: u64) -> Self {
        Self::new_with_gate(accounted_egress_bytes, Arc::new(RwLock::new(())))
    }

    fn new_with_gate(accounted_egress_bytes: u64, update_gate: Arc<RwLock<()>>) -> Self {
        Self {
            accounted_egress_bytes: Arc::new(AtomicU64::new(accounted_egress_bytes)),
            remaining_egress_bytes: Arc::new(AtomicU64::new(
                u64::MAX.saturating_sub(accounted_egress_bytes),
            )),
            exhausted: Arc::new(AtomicBool::new(accounted_egress_bytes == u64::MAX)),
            update_gate,
            durable_checkpoint: None,
        }
    }

    fn new_durable_with_gate(
        accounted_egress_bytes: u64,
        update_gate: Arc<RwLock<()>>,
        durable_checkpoint: Arc<InrouDurableEgressCheckpoint>,
    ) -> io::Result<Self> {
        if durable_checkpoint.accounted_egress_bytes() != accounted_egress_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable Inrou reporter checkpoint does not match its recovered counter",
            ));
        }
        let mut accounting = Self::new_with_gate(accounted_egress_bytes, update_gate);
        accounting.durable_checkpoint = Some(durable_checkpoint);
        Ok(accounting)
    }

    fn accounted_egress_bytes(&self) -> u64 {
        self.accounted_egress_bytes.load(AtomicOrdering::Acquire)
    }

    fn advance_floor(&self, accounted_egress_bytes: u64) -> io::Result<()> {
        let _guard = self.update_gate.write();
        let current = self.accounted_egress_bytes();
        if accounted_egress_bytes <= current {
            return Ok(());
        }
        let delta = accounted_egress_bytes - current;
        let remaining = self.remaining_egress_bytes.load(AtomicOrdering::Acquire);
        if delta > remaining {
            self.exhausted.store(true, AtomicOrdering::Release);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inrou revision egress accounting floor exceeds the remaining counter budget",
            ));
        }
        if let Some(durable_checkpoint) = self.durable_checkpoint.as_ref() {
            if let Err(error) = durable_checkpoint.advance_to(accounted_egress_bytes) {
                self.exhausted.store(true, AtomicOrdering::Release);
                return Err(error);
            }
        }
        self.remaining_egress_bytes
            .store(remaining - delta, AtomicOrdering::Release);
        self.accounted_egress_bytes
            .fetch_max(accounted_egress_bytes, AtomicOrdering::AcqRel);
        if accounted_egress_bytes == u64::MAX {
            self.exhausted.store(true, AtomicOrdering::Release);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct PortableVmReplicaEgressAccounting {
    // The revision budget is charged only by the Linux portable-VM bridge.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    revision: PortableVmEgressAccounting,
    reporter: PortableVmEgressAccounting,
}
impl PortableVmReplicaEgressAccounting {
    #[cfg(test)]
    fn new(revision: PortableVmEgressAccounting, reporter_accounted_egress_bytes: u64) -> Self {
        let reporter = PortableVmEgressAccounting::new_with_gate(
            reporter_accounted_egress_bytes,
            Arc::clone(&revision.update_gate),
        );
        Self { revision, reporter }
    }

    fn from_shared(
        revision: PortableVmEgressAccounting,
        reporter: PortableVmEgressAccounting,
    ) -> io::Result<Self> {
        if !Arc::ptr_eq(&revision.update_gate, &reporter.update_gate) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inrou revision and reporter accounting do not share an update gate",
            ));
        }
        Ok(Self { revision, reporter })
    }

    #[cfg(any(target_os = "linux", test))]
    fn precharge(&self, requested: u64) -> io::Result<u64> {
        if requested == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Inrou egress precharge must be positive",
            ));
        }
        let _guard = self.revision.update_gate.write();
        if self.exhausted() {
            return Err(inrou_egress_accounting_exhausted_error());
        }
        let requested = requested.min(SORACLOUD_INROU_EGRESS_RESERVATION_BYTES as u64);
        let revision_current = self.revision.accounted_egress_bytes();
        let reporter_current = self.reporter.accounted_egress_bytes();
        let revision_remaining = self
            .revision
            .remaining_egress_bytes
            .load(AtomicOrdering::Acquire);
        let reporter_remaining = self
            .reporter
            .remaining_egress_bytes
            .load(AtomicOrdering::Acquire);
        if revision_remaining != u64::MAX.saturating_sub(revision_current)
            || reporter_remaining != u64::MAX.saturating_sub(reporter_current)
        {
            self.fail_closed();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inrou egress accounting counter and remaining budget diverged",
            ));
        }
        let reserved = requested.min(revision_remaining).min(reporter_remaining);
        if reserved == 0 {
            self.fail_closed();
            return Err(inrou_egress_accounting_exhausted_error());
        }
        let revision_next = revision_current
            .checked_add(reserved)
            .ok_or_else(inrou_egress_accounting_exhausted_error)?;
        let reporter_next = reporter_current
            .checked_add(reserved)
            .ok_or_else(inrou_egress_accounting_exhausted_error)?;
        if let Some(durable_checkpoint) = self.reporter.durable_checkpoint.as_ref() {
            if durable_checkpoint.accounted_egress_bytes() != reporter_current {
                self.fail_closed();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable Inrou reporter checkpoint diverged from its in-memory counter",
                ));
            }
            if let Err(error) = durable_checkpoint.advance_to(reporter_next) {
                self.fail_closed();
                return Err(error);
            }
        } else if !cfg!(test) {
            self.fail_closed();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "production Inrou reporter accounting has no durable checkpoint",
            ));
        }
        self.revision
            .accounted_egress_bytes
            .store(revision_next, AtomicOrdering::Release);
        self.reporter
            .accounted_egress_bytes
            .store(reporter_next, AtomicOrdering::Release);
        self.revision
            .remaining_egress_bytes
            .store(u64::MAX - revision_next, AtomicOrdering::Release);
        self.reporter
            .remaining_egress_bytes
            .store(u64::MAX - reporter_next, AtomicOrdering::Release);
        if revision_next == u64::MAX || reporter_next == u64::MAX {
            self.fail_closed();
        }
        Ok(reserved)
    }

    #[cfg(test)]
    fn revision_accounted_egress_bytes(&self) -> u64 {
        self.revision.accounted_egress_bytes()
    }

    fn reporter_accounted_egress_bytes(&self) -> u64 {
        self.reporter.accounted_egress_bytes()
    }

    #[cfg(any(target_os = "linux", test))]
    fn exhausted(&self) -> bool {
        self.revision.exhausted.load(AtomicOrdering::Acquire)
            || self.reporter.exhausted.load(AtomicOrdering::Acquire)
    }

    #[cfg(any(target_os = "linux", test))]
    fn fail_closed(&self) {
        self.revision.exhausted.store(true, AtomicOrdering::Release);
        self.reporter.exhausted.store(true, AtomicOrdering::Release);
    }
}
#[cfg(any(target_os = "linux", test))]
fn inrou_egress_accounting_exhausted_error() -> io::Error {
    io::Error::other("Inrou revision egress accounting reached u64::MAX")
}
struct PortableVmLoopbackBridge {
    listen_address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
#[cfg(target_os = "linux")]
struct InrouOwnerSlotLock {
    slot: usize,
    _file: fs::File,
}
#[cfg(target_os = "linux")]
impl InrouOwnerSlotLock {
    fn require_identity(&self, identity: &PortableVmChildIdentity) -> eyre::Result<()> {
        if self.slot != inrou_firewall_identity_slot(identity)? {
            eyre::bail!("Inrou owner slot lock does not bind this exact child UID/GID");
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
struct InrouLoopbackOwnerFirewall {
    iptables_binary: PathBuf,
    _slot_lock: InrouOwnerSlotLock,
    chain: InrouOwnedIptablesChain,
    owns_chain: bool,
}
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct InrouOwnedIptablesChain {
    name: &'static str,
    marker: &'static str,
    hook: &'static str,
}
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN_SPEC: InrouOwnedIptablesChain =
    InrouOwnedIptablesChain {
        name: SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN,
        marker: "iroha-inrou-owned-v1-retired-unslotted",
        hook: "OUTPUT",
    };
#[cfg(target_os = "linux")]
const SORACLOUD_INROU_IPTABLES_CHAIN_SPECS: [InrouOwnedIptablesChain; 4] = [
    InrouOwnedIptablesChain {
        name: SORACLOUD_INROU_IPTABLES_CHAINS[0],
        marker: SORACLOUD_INROU_IPTABLES_CHAIN_MARKERS[0],
        hook: "OUTPUT",
    },
    InrouOwnedIptablesChain {
        name: SORACLOUD_INROU_IPTABLES_CHAINS[1],
        marker: SORACLOUD_INROU_IPTABLES_CHAIN_MARKERS[1],
        hook: "OUTPUT",
    },
    InrouOwnedIptablesChain {
        name: SORACLOUD_INROU_IPTABLES_CHAINS[2],
        marker: SORACLOUD_INROU_IPTABLES_CHAIN_MARKERS[2],
        hook: "OUTPUT",
    },
    InrouOwnedIptablesChain {
        name: SORACLOUD_INROU_IPTABLES_CHAINS[3],
        marker: SORACLOUD_INROU_IPTABLES_CHAIN_MARKERS[3],
        hook: "OUTPUT",
    },
];
#[cfg(any(target_os = "linux", test))]
type PortableVmBackendConnector =
    Arc<dyn Fn(SocketAddr, &AtomicBool) -> Option<TcpStream> + Send + Sync>;
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
struct PortableVmGuestMachineProfile {
    machine_type: &'static str,
    root_label: &'static str,
    block_device: &'static str,
    #[cfg(target_os = "linux")]
    net_device: &'static str,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
struct PortableVmBundleBinding {
    expected_hash: Hash,
    exact_bytes: u64,
    maximum_bytes: u64,
}
#[cfg(target_os = "linux")]
fn resolve_inrou_qemu_img_executable() -> Option<PathBuf> {
    let candidate = Path::new("/usr/bin/qemu-img");
    let named = fs::symlink_metadata(candidate).ok()?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || named.uid() != 0
        || named.mode() & 0o111 == 0
        || named.mode() & 0o022 != 0
    {
        return None;
    }
    candidate
        .ancestors()
        .skip(1)
        .all(|ancestor| {
            fs::symlink_metadata(ancestor).ok().is_some_and(|metadata| {
                !metadata.file_type().is_symlink()
                    && metadata.is_dir()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
            })
        })
        .then(|| candidate.to_path_buf())
}
#[cfg(target_os = "linux")]
fn resolve_inrou_iptables_executable() -> Option<PathBuf> {
    [
        Path::new("/usr/sbin/iptables"),
        Path::new("/sbin/iptables"),
        Path::new("/usr/bin/iptables"),
        Path::new("/bin/iptables"),
    ]
    .into_iter()
    .find_map(admit_inrou_root_custodied_executable_entry)
}
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InrouExecutablePathMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
#[cfg(target_os = "linux")]
fn admit_inrou_root_custodied_executable_entry(candidate: &Path) -> Option<PathBuf> {
    admit_inrou_root_custodied_executable_entry_with(
        candidate,
        |path| {
            let metadata = fs::symlink_metadata(path).ok()?;
            Some(InrouExecutablePathMetadata {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                links: metadata.nlink(),
                size: metadata.size(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            })
        },
        |path| fs::read_link(path).ok(),
    )
}
#[cfg(target_os = "linux")]
fn admit_inrou_root_custodied_executable_entry_with(
    candidate: &Path,
    mut metadata: impl FnMut(&Path) -> Option<InrouExecutablePathMetadata>,
    mut read_link: impl FnMut(&Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let text = candidate.to_str()?;
    let safe_text = |value: &str| {
        !value.is_empty()
            && !value.contains("//")
            && !value.contains('\\')
            && !value.ends_with('/')
            && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    };
    if !text.starts_with('/')
        || !safe_text(text)
        || text.split('/').any(|part| matches!(part, "." | ".."))
    {
        return None;
    }
    let trusted_directory = |entry: InrouExecutablePathMetadata| {
        entry.mode & 0o170000 == 0o040000
            && entry.uid == 0
            && entry.gid == 0
            && entry.mode & 0o022 == 0
    };
    let mut pending: std::collections::VecDeque<String> =
        text.split('/').skip(1).map(str::to_owned).collect();
    let mut current = PathBuf::from("/");
    let root = metadata(&current)?;
    if !trusted_directory(root) {
        return None;
    }
    let mut observed = vec![(current.clone(), root, None)];
    let mut links = 0_u8;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            current.pop();
            continue;
        }
        let component = current.join(part);
        let entry = metadata(&component)?;
        let mut target = None;
        if entry.mode & 0o170000 == 0o120000 {
            links = links.checked_add(1)?;
            if links > 40 || entry.uid != 0 || entry.gid != 0 || entry.links != 1 {
                return None;
            }
            let link = read_link(&component)?;
            let link_text = link.to_str()?;
            if !safe_text(link_text) {
                return None;
            }
            let absolute = link_text.starts_with('/');
            if absolute {
                current = PathBuf::from("/");
            }
            let parts = link_text.strip_prefix('/').unwrap_or(link_text);
            for part in parts.split('/').rev() {
                pending.push_front(part.to_owned());
            }
            target = Some(link);
        } else {
            if !pending.is_empty() && !trusted_directory(entry) {
                return None;
            }
            current = component.clone();
        }
        observed.push((component, entry, target));
    }
    let resolved = metadata(&current)?;
    if resolved.mode & 0o170000 != 0o100000
        || resolved.uid != 0
        || resolved.gid != 0
        || resolved.links != 1
        || resolved.mode & 0o111 == 0
        || resolved.mode & 0o7022 != 0
    {
        return None;
    }
    for (path, before, target) in observed {
        if metadata(&path)? != before || (target.is_some() && read_link(&path) != target) {
            return None;
        }
    }
    // Keep the admitted entry name: xtables dispatches using argv[0], so
    // executing its canonical xtables-nft-multi target changes semantics.
    Some(candidate.to_path_buf())
}

#[cfg(any(target_os = "linux", test))]
fn validate_portable_vm_kvm_identity(
    identity: &PortableVmChildIdentity,
    device: PortableVmKvmDeviceAccess,
) -> eyre::Result<()> {
    if !device.is_character_device
        || device.uid != 0
        || device.hard_links != 1
        || device.rdev != SORACLOUD_INROU_KVM_DEVICE_RDEV
        || device.mode & 0o007 != 0
    {
        eyre::bail!(
            "`/dev/kvm` must be one direct root-owned Linux KVM character device (major 10, minor 232) with no world access"
        );
    }
    if device.mode & 0o070 != 0o060 {
        eyre::bail!("`/dev/kvm` must grant its owning group exact read/write access");
    }
    if device.gid == 0 {
        eyre::bail!(
            "`/dev/kvm` group is root, so the dedicated non-root QEMU identity cannot receive exact group access"
        );
    }
    if identity.gid == device.gid {
        eyre::bail!(
            "the `/dev/kvm` group must remain distinct from the dedicated primary gid that protects QEMU disks"
        );
    }
    let expected_supplementary_gids = vec![device.gid];
    if identity.supplementary_gids != expected_supplementary_gids {
        eyre::bail!(
            "KVM PortableVM supplementary gids must be exactly {:?}, derived only from the direct `/dev/kvm` group",
            expected_supplementary_gids
        );
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn validate_portable_vm_child_identity_values(
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    if iroha_config::parameters::defaults::soracloud_runtime::inrou_portable_vm_identity_slot(
        identity.uid,
        identity.gid,
    )
    .is_none()
    {
        eyre::bail!(
            "dedicated Inrou QEMU uid {} and primary gid {} must be one equal canonical slot pair in {}..{} (upper bound exclusive)",
            identity.uid,
            identity.gid,
            SORACLOUD_INROU_ID_BASE,
            SORACLOUD_INROU_ID_MAX_EXCLUSIVE,
        );
    }
    if let Some(gid) = identity
        .supplementary_gids
        .iter()
        .copied()
        .find(|gid| inrou_supplementary_gid_is_host_reserved(*gid))
    {
        eyre::bail!(
            "Inrou QEMU supplementary gid {gid} is a Linux overflow, nobody, dynamic-service, container, foreign, or unchanged-credential sentinel id"
        );
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn inrou_firewall_identity_slot(identity: &PortableVmChildIdentity) -> eyre::Result<usize> {
    iroha_config::parameters::defaults::soracloud_runtime::inrou_portable_vm_identity_slot(
        identity.uid,
        identity.gid,
    )
    .and_then(|slot| usize::try_from(slot).ok())
    .filter(|slot| {
        *slot
            < iroha_config::parameters::defaults::soracloud_runtime::
                INROU_PORTABLE_VM_ID_SLOT_COUNT as usize
    })
    .ok_or_else(|| {
        eyre::eyre!(
            "Inrou firewall custody requires one canonical PortableVM uid/gid slot in {}..{} (upper bound exclusive)",
            SORACLOUD_INROU_ID_BASE,
            SORACLOUD_INROU_ID_MAX_EXCLUSIVE,
        )
    })
}
#[cfg(target_os = "linux")]
fn inrou_service_identity_name(identity: &PortableVmChildIdentity) -> eyre::Result<String> {
    let slot = iroha_config::parameters::defaults::soracloud_runtime::
        inrou_portable_vm_identity_slot(identity.uid, identity.gid)
        .ok_or_else(|| {
            eyre::eyre!(
                "Inrou service identity requires one equal canonical uid/gid slot pair in {}..{} (upper bound exclusive)",
                SORACLOUD_INROU_ID_BASE,
                SORACLOUD_INROU_ID_MAX_EXCLUSIVE,
            )
        })?;
    Ok(format!("{SORACLOUD_INROU_SERVICE_IDENTITY_PREFIX}{slot}"))
}
#[cfg(any(target_os = "linux", test))]
fn inrou_supplementary_gid_is_host_reserved(gid: u32) -> bool {
    matches!(gid, 65_534 | 65_535)
        || (60_001..=60_705).contains(&gid)
        || (61_184..=65_519).contains(&gid)
        || (524_288..=1_879_048_191).contains(&gid)
        || (2_147_352_576..=2_147_418_111).contains(&gid)
        || gid >= 1 << 31
}
#[cfg(target_os = "linux")]
fn read_inrou_root_custodied_identity_file(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> eyre::Result<String> {
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)
            .wrap_err_with(|| format!("inspect {label} path component {}", component.display()))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (index == 0 && !metadata.is_file())
            || (index != 0 && !metadata.is_dir())
        {
            eyre::bail!(
                "{label} path component {} must be direct, root-owned, and non-writable by group/other",
                component.display()
            );
        }
    }
    read_soracloud_regular_text_bounded(path, maximum_bytes, label).map_err(eyre::Report::from)
}
#[cfg(target_os = "linux")]
fn read_optional_inrou_root_custodied_identity_file(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> eyre::Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_inrou_root_custodied_identity_file(path, maximum_bytes, label).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).wrap_err_with(|| format!("inspect optional {label}")),
    }
}
#[cfg(target_os = "linux")]
fn validate_inrou_local_nsswitch(contents: &str) -> eyre::Result<()> {
    let mut required = BTreeMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((database, sources)) = line.split_once(':') else {
            continue;
        };
        let database = database.trim().to_ascii_lowercase();
        if !matches!(database.as_str(), "passwd" | "group" | "subid") {
            continue;
        }
        if required.insert(database.clone(), sources.trim()).is_some() {
            eyre::bail!("/etc/nsswitch.conf repeats the `{database}` database");
        }
    }
    for database in ["passwd", "group"] {
        let sources = required
            .get(database)
            .ok_or_else(|| eyre::eyre!("/etc/nsswitch.conf omits `{database}: files`"))?;
        if sources.split_ascii_whitespace().collect::<Vec<_>>() != ["files"] {
            eyre::bail!(
                "Inrou PortableVM requires deterministic `{database}: files` NSS resolution; found `{sources}`"
            );
        }
    }
    if let Some(sources) = required.get("subid")
        && sources.split_ascii_whitespace().collect::<Vec<_>>() != ["files"]
    {
        eyre::bail!(
            "Inrou PortableVM requires deterministic `subid: files` resolution when that database is declared; found `{sources}`"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn inrou_configured_decimal_identity_names(identity: &PortableVmChildIdentity) -> BTreeSet<String> {
    [identity.uid, identity.gid]
        .into_iter()
        .chain(identity.supplementary_gids.iter().copied())
        .map(|id| id.to_string())
        .collect()
}
#[cfg(target_os = "linux")]
fn validate_inrou_reserved_passwd(
    contents: &str,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<PathBuf> {
    let service_identity_name = inrou_service_identity_name(identity)?;
    let forbidden_names = inrou_configured_decimal_identity_names(identity);
    let mut names = BTreeSet::new();
    let mut target_shell = None;
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0].is_empty() || !names.insert(fields[0]) {
            eyre::bail!(
                "local passwd database has a malformed or duplicate-name record on line {}",
                line_index.saturating_add(1)
            );
        }
        if forbidden_names.contains(fields[0]) {
            eyre::bail!(
                "local passwd name `{}` collides with a configured numeric Inrou identity",
                fields[0]
            );
        }
        let record_uid = fields[2].parse::<u32>().wrap_err_with(|| {
            format!(
                "parse local passwd uid on line {}",
                line_index.saturating_add(1)
            )
        })?;
        let record_gid = fields[3].parse::<u32>().wrap_err_with(|| {
            format!(
                "parse local passwd primary gid on line {}",
                line_index.saturating_add(1)
            )
        })?;
        let is_target_name = fields[0] == service_identity_name.as_str();
        let is_target_uid = record_uid == identity.uid;
        if is_target_name || is_target_uid {
            if !(is_target_name && is_target_uid) || target_shell.is_some() {
                eyre::bail!(
                    "local passwd must contain exactly one `{}` record with uid {}",
                    service_identity_name,
                    identity.uid
                );
            }
            if fields[1] != "x"
                || record_gid != identity.gid
                || fields[5] != SORACLOUD_INROU_SERVICE_HOME
                || !matches!(
                    fields[6],
                    "/usr/sbin/nologin" | "/sbin/nologin" | "/usr/bin/false" | "/bin/false"
                )
            {
                eyre::bail!(
                    "the `{}` passwd record must use `x`, primary gid {}, home `{}`, and a literal trusted nologin/false shell",
                    service_identity_name,
                    identity.gid,
                    SORACLOUD_INROU_SERVICE_HOME
                );
            }
            target_shell = Some(PathBuf::from(fields[6]));
        } else if record_gid == identity.gid {
            eyre::bail!(
                "dedicated Inrou primary gid {} is assigned to another passwd account `{}`",
                identity.gid,
                fields[0]
            );
        }
    }
    target_shell.ok_or_else(|| {
        eyre::eyre!(
            "local passwd must reserve uid {} as the locked `{}` service account",
            identity.uid,
            service_identity_name
        )
    })
}
#[cfg(target_os = "linux")]
fn validate_inrou_reserved_group(
    contents: &str,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    let service_identity_name = inrou_service_identity_name(identity)?;
    let forbidden_names = inrou_configured_decimal_identity_names(identity);
    let mut names = BTreeSet::new();
    let mut found_target = false;
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0].is_empty() || !names.insert(fields[0]) {
            eyre::bail!(
                "local group database has a malformed or duplicate-name record on line {}",
                line_index.saturating_add(1)
            );
        }
        if forbidden_names.contains(fields[0]) {
            eyre::bail!(
                "local group name `{}` collides with a configured numeric Inrou gid",
                fields[0]
            );
        }
        let record_gid = fields[2].parse::<u32>().wrap_err_with(|| {
            format!(
                "parse local group gid on line {}",
                line_index.saturating_add(1)
            )
        })?;
        let is_target_name = fields[0] == service_identity_name.as_str();
        let is_target_gid = record_gid == identity.gid;
        if is_target_name || is_target_gid {
            if !(is_target_name && is_target_gid) || found_target {
                eyre::bail!(
                    "local group must contain exactly one `{}` record with gid {}",
                    service_identity_name,
                    identity.gid
                );
            }
            if fields[1] != "x" || !fields[3].is_empty() {
                eyre::bail!(
                    "the `{}` primary group must use `x` and have no explicit members",
                    service_identity_name
                );
            }
            found_target = true;
        } else if fields[3]
            .split(',')
            .any(|member| member == service_identity_name.as_str())
        {
            eyre::bail!(
                "the `{}` service account must not be listed in supplementary group `{}`",
                service_identity_name,
                fields[0]
            );
        }
    }
    if !found_target {
        eyre::bail!(
            "local group must reserve gid {} as the empty `{}` primary group",
            identity.gid,
            service_identity_name
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_inrou_reserved_shadow(
    contents: &str,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    let service_identity_name = inrou_service_identity_name(identity)?;
    let mut names = BTreeSet::new();
    let mut found_target = false;
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 9 || fields[0].is_empty() || !names.insert(fields[0]) {
            eyre::bail!(
                "local shadow database has a malformed or duplicate-name record on line {}",
                line_index.saturating_add(1)
            );
        }
        if fields[0] == service_identity_name.as_str() {
            if found_target || !matches!(fields[1].as_bytes().first(), Some(b'!' | b'*')) {
                eyre::bail!(
                    "the `{}` shadow record must occur once with a locked password",
                    service_identity_name
                );
            }
            found_target = true;
        }
    }
    if !found_target {
        eyre::bail!(
            "local shadow must contain a locked `{}` record",
            service_identity_name
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_inrou_reserved_gshadow(
    contents: &str,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    let service_identity_name = inrou_service_identity_name(identity)?;
    let mut names = BTreeSet::new();
    let mut found_target = false;
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0].is_empty() || !names.insert(fields[0]) {
            eyre::bail!(
                "local gshadow database has a malformed or duplicate-name record on line {}",
                line_index.saturating_add(1)
            );
        }
        if fields[0] == service_identity_name.as_str() {
            if found_target
                || !matches!(fields[1].as_bytes().first(), Some(b'!' | b'*'))
                || !fields[2].is_empty()
                || !fields[3].is_empty()
            {
                eyre::bail!(
                    "the `{}` gshadow record must occur once, be locked, and have no administrators or members",
                    service_identity_name
                );
            }
            found_target = true;
        } else if fields[2]
            .split(',')
            .chain(fields[3].split(','))
            .any(|name| name == service_identity_name.as_str())
        {
            eyre::bail!(
                "the `{}` service account must not administer or join gshadow group `{}`",
                service_identity_name,
                fields[0]
            );
        }
    }
    if !found_target {
        eyre::bail!(
            "local gshadow must contain a locked empty `{}` record",
            service_identity_name
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_inrou_subordinate_id_unmapped(
    contents: &str,
    database: &str,
    id: u32,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    let service_identity_name = inrou_service_identity_name(identity)?;
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 3 || fields[0].is_empty() {
            eyre::bail!(
                "local {database} database has a malformed record on line {}",
                line_index.saturating_add(1)
            );
        }
        if fields[0] == service_identity_name.as_str() || fields[0] == id.to_string() {
            eyre::bail!(
                "local {database} must not delegate a range to Inrou owner `{}` on line {}",
                fields[0],
                line_index.saturating_add(1)
            );
        }
        let start = fields[1].parse::<u32>().wrap_err_with(|| {
            format!(
                "parse local {database} range start on line {}",
                line_index.saturating_add(1)
            )
        })?;
        let count = fields[2].parse::<u32>().wrap_err_with(|| {
            format!(
                "parse local {database} range count on line {}",
                line_index.saturating_add(1)
            )
        })?;
        if count == 0 {
            eyre::bail!(
                "local {database} range on line {} must be nonempty",
                line_index.saturating_add(1)
            );
        }
        let end_exclusive = u64::from(start)
            .checked_add(u64::from(count))
            .filter(|end| *end <= u64::from(u32::MAX) + 1)
            .ok_or_else(|| {
                eyre::eyre!(
                    "local {database} range on line {} overflows Linux uid_t/gid_t",
                    line_index.saturating_add(1)
                )
            })?;
        if u64::from(id) >= u64::from(start) && u64::from(id) < end_exclusive {
            eyre::bail!(
                "dedicated Inrou id {id} falls within local {database} range {start}:{count}"
            );
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn ensure_inrou_service_shell_custody(shell: &Path) -> eyre::Result<()> {
    admit_inrou_root_custodied_executable_entry(shell).ok_or_else(|| {
        eyre::eyre!(
            "Inrou service shell {} must resolve through root-custodied entries to one non-privileged, singly-linked executable",
            shell.display()
        )
    })?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn ensure_portable_vm_identity_reserved(identity: &PortableVmChildIdentity) -> eyre::Result<()> {
    const IDENTITY_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
    let nsswitch = read_inrou_root_custodied_identity_file(
        Path::new("/etc/nsswitch.conf"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou NSS configuration",
    )?;
    validate_inrou_local_nsswitch(&nsswitch)?;
    let passwd = read_inrou_root_custodied_identity_file(
        Path::new("/etc/passwd"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local passwd database",
    )?;
    let shell = validate_inrou_reserved_passwd(&passwd, identity)?;
    let group = read_inrou_root_custodied_identity_file(
        Path::new("/etc/group"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local group database",
    )?;
    validate_inrou_reserved_group(&group, identity)?;
    let shadow = read_inrou_root_custodied_identity_file(
        Path::new("/etc/shadow"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local shadow database",
    )?;
    validate_inrou_reserved_shadow(&shadow, identity)?;
    let gshadow = read_inrou_root_custodied_identity_file(
        Path::new("/etc/gshadow"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local gshadow database",
    )?;
    validate_inrou_reserved_gshadow(&gshadow, identity)?;
    match fs::symlink_metadata(SORACLOUD_INROU_SERVICE_HOME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            eyre::bail!("the Inrou service home `{SORACLOUD_INROU_SERVICE_HOME}` must not exist")
        }
        Err(error) => return Err(error).wrap_err("inspect the canonical Inrou service home"),
    }
    ensure_inrou_service_shell_custody(&shell)?;
    let subuid = read_optional_inrou_root_custodied_identity_file(
        Path::new("/etc/subuid"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local subordinate uid database",
    )?;
    if let Some(subuid) = subuid {
        validate_inrou_subordinate_id_unmapped(&subuid, "subuid", identity.uid, identity)?;
    }
    let subgid = read_optional_inrou_root_custodied_identity_file(
        Path::new("/etc/subgid"),
        IDENTITY_FILE_MAX_BYTES,
        "Inrou local subordinate gid database",
    )?;
    if let Some(subgid) = subgid {
        validate_inrou_subordinate_id_unmapped(&subgid, "subgid", identity.gid, identity)?;
        for supplementary_gid in &identity.supplementary_gids {
            validate_inrou_subordinate_id_unmapped(
                &subgid,
                "subgid",
                *supplementary_gid,
                identity,
            )?;
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn inspect_inrou_kvm_device() -> eyre::Result<PortableVmKvmDeviceAccess> {
    let path = Path::new("/dev/kvm");
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = fs::symlink_metadata(ancestor)
            .wrap_err_with(|| format!("inspect `/dev/kvm` ancestor {}", ancestor.display()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            eyre::bail!(
                "`/dev/kvm` ancestor {} must be a direct root-owned non-writable directory",
                ancestor.display()
            );
        }
    }
    let metadata = fs::symlink_metadata(path).wrap_err("inspect direct `/dev/kvm`")?;
    Ok(PortableVmKvmDeviceAccess {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        hard_links: metadata.nlink(),
        rdev: metadata.rdev(),
        is_character_device: metadata.file_type().is_char_device(),
    })
}
#[cfg(target_os = "linux")]
fn portable_vm_child_identity(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
) -> eyre::Result<PortableVmChildIdentity> {
    if rustix::process::geteuid().as_raw() != 0 {
        eyre::bail!(
            "Inrou PortableVM hosting must start from uid 0 so `setpriv` can establish a dedicated QEMU identity before exec"
        );
    }
    let uid = config
        .portable_vm_uid
        .ok_or_else(|| eyre::eyre!("Inrou PortableVM hosting requires portable_vm_uid"))?
        .get();
    let gid = config
        .portable_vm_gid
        .ok_or_else(|| eyre::eyre!("Inrou PortableVM hosting requires portable_vm_gid"))?
        .get();
    let kvm_device = inspect_inrou_kvm_device()?;
    let supplementary_gids = vec![kvm_device.gid];
    let identity = PortableVmChildIdentity {
        uid,
        gid,
        supplementary_gids,
    };
    validate_portable_vm_child_identity_values(&identity)?;
    validate_portable_vm_kvm_identity(&identity, kvm_device)?;
    Ok(identity)
}
#[cfg(any(target_os = "linux", test))]
fn resolve_inrou_bundle_member_path(
    bundle_root: &Path,
    declared_path: &str,
) -> eyre::Result<PathBuf> {
    let relative_components = canonical_inrou_bundle_member_components(declared_path)?;
    let bundle_root = fs::canonicalize(bundle_root)
        .wrap_err_with(|| format!("canonicalize {}", bundle_root.display()))?;
    let candidate = relative_components
        .iter()
        .fold(bundle_root.clone(), |path, component| path.join(component));
    let canonical = fs::canonicalize(&candidate)
        .wrap_err_with(|| format!("canonicalize Inrou bundle member {}", candidate.display()))?;
    if !canonical.starts_with(&bundle_root) {
        eyre::bail!(
            "Inrou bundle member `{declared_path}` resolves outside {}",
            bundle_root.display()
        );
    }
    if !canonical.is_file() {
        eyre::bail!(
            "Inrou bundle member `{declared_path}` must resolve to a regular file under {}",
            bundle_root.display()
        );
    }
    Ok(canonical)
}
#[cfg(test)]
fn validate_reusable_inrou_disk(path: &Path, exact_bytes: Option<u64>) -> eyre::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect reusable Inrou disk {}", path.display()))?;
    validate_reusable_inrou_disk_metadata(&metadata, path, exact_bytes)
}

fn validate_reusable_inrou_disk_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    exact_bytes: Option<u64>,
) -> eyre::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        eyre::bail!(
            "reusable Inrou disk {} must be a regular file",
            path.display()
        );
    }
    if metadata.len() == 0 {
        eyre::bail!("reusable Inrou disk {} must not be empty", path.display());
    }
    if let Some(exact_bytes) = exact_bytes
        && metadata.len() != exact_bytes
    {
        eyre::bail!(
            "reusable Inrou disk {} has {} bytes instead of the required {exact_bytes}",
            path.display(),
            metadata.len()
        );
    }
    #[cfg(unix)]
    {
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.nlink() != 1 {
            eyre::bail!(
                "reusable Inrou disk {} must have exactly one hard link",
                path.display()
            );
        }
        if metadata.uid() != effective_uid {
            eyre::bail!(
                "reusable Inrou disk {} is owned by uid {} instead of the runtime uid {effective_uid}",
                path.display(),
                metadata.uid()
            );
        }
        if metadata.mode() & 0o200 == 0 || metadata.mode() & 0o077 != 0 {
            eyre::bail!(
                "reusable Inrou disk {} must be owner-writable and inaccessible to group or other users",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_reusable_inrou_disk_file_at(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    file: &fs::File,
    exact_bytes: Option<u64>,
) -> eyre::Result<()> {
    validate_inrou_single_component(name)?;
    let path = directory.path().join(name);
    let before = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
    .wrap_err_with(|| format!("inspect reusable Inrou disk {}", path.display()))?;
    let opened_before = file.metadata()?;
    validate_reusable_inrou_disk_metadata(&opened_before, &path, exact_bytes)?;
    if !inrou_stat_matches_metadata(&before, &opened_before) {
        eyre::bail!(
            "reusable Inrou disk {} changed while it was opened",
            path.display()
        );
    }
    let opened_after = file.metadata()?;
    let after = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if opened_before.dev() != opened_after.dev()
        || opened_before.ino() != opened_after.ino()
        || opened_before.len() != opened_after.len()
        || !inrou_stat_matches_metadata(&after, &opened_after)
    {
        eyre::bail!(
            "reusable Inrou disk {} changed during descriptor-relative validation",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn open_reusable_inrou_disk_at(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    exact_bytes: Option<u64>,
    writable: bool,
) -> eyre::Result<Option<fs::File>> {
    validate_inrou_single_component(name)?;
    let before = match rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(before) => before,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io::Error::from(error)).wrap_err("inspect reusable Inrou disk"),
    };
    let mut flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    if writable {
        flags =
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    }
    let file = fs::File::from(
        rustix::fs::openat(&directory.directory, name, flags, rustix::fs::Mode::empty())
            .map_err(io::Error::from)?,
    );
    let opened = file.metadata()?;
    if !inrou_stat_matches_metadata(&before, &opened) {
        eyre::bail!(
            "reusable Inrou disk {} changed while it was opened",
            directory.path().join(name).display()
        );
    }
    validate_reusable_inrou_disk_file_at(directory, name, &file, exact_bytes)?;
    Ok(Some(file))
}
#[cfg(test)]
fn validate_inrou_disk_under_exact_custody(
    path: &Path,
    delegated_file: &fs::File,
    exact_bytes: u64,
    custody: InrouDiskCustody,
) -> eyre::Result<()> {
    let named = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect delegated Inrou disk {}", path.display()))?;
    if named.file_type().is_symlink() || !named.is_file() || named.len() != exact_bytes {
        eyre::bail!(
            "delegated Inrou disk {} must be an exact-length regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        if named.nlink() != 1
            || named.uid() != custody.uid
            || named.gid() != custody.gid
            || named.mode() & 0o7777 != custody.mode
        {
            eyre::bail!(
                "delegated Inrou disk {} is outside exact uid {}, gid {}, mode {:04o} custody",
                path.display(),
                custody.uid,
                custody.gid,
                custody.mode,
            );
        }
        let opened = delegated_file.metadata()?;
        let named_after = fs::symlink_metadata(path)?;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || named_after.dev() != opened.dev()
            || named_after.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.uid() != custody.uid
            || opened.gid() != custody.gid
            || opened.mode() & 0o7777 != custody.mode
            || opened.len() != exact_bytes
        {
            eyre::bail!(
                "delegated Inrou disk {} changed during exact custody validation",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn validate_inrou_disk_under_exact_custody_at(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    delegated_file: &fs::File,
    exact_bytes: u64,
    custody: InrouDiskCustody,
) -> eyre::Result<()> {
    validate_inrou_single_component(name)?;
    let path = directory.path().join(name);
    let named = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
    .wrap_err_with(|| format!("inspect delegated Inrou disk {}", path.display()))?;
    let opened = delegated_file.metadata()?;
    let named_after = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        || named.st_nlink as u64 != 1
        || named.st_uid != custody.uid
        || named.st_gid != custody.gid
        || u32::from(named.st_mode) & 0o7777 != custody.mode
        || u64::try_from(named.st_size).ok() != Some(exact_bytes)
        || !inrou_stat_matches_metadata(&named, &opened)
        || !inrou_stat_matches_metadata(&named_after, &opened)
        || opened.nlink() != 1
        || opened.uid() != custody.uid
        || opened.gid() != custody.gid
        || opened.mode() & 0o7777 != custody.mode
        || opened.len() != exact_bytes
    {
        eyre::bail!(
            "delegated Inrou disk {} changed during exact descriptor-relative custody validation",
            path.display()
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
struct InrouWriteLease<'a> {
    file: &'a fs::File,
    active: bool,
}
#[cfg(target_os = "linux")]
impl InrouWriteLease<'_> {
    fn release(mut self) -> io::Result<()> {
        set_inrou_linux_file_lease(self.file, rustix::process::FlockType::Unlocked)?;
        verify_inrou_linux_file_lease(self.file, rustix::process::FlockType::Unlocked)?;
        self.active = false;
        Ok(())
    }
}
#[cfg(target_os = "linux")]
impl Drop for InrouWriteLease<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) =
                set_inrou_linux_file_lease(self.file, rustix::process::FlockType::Unlocked)
        {
            iroha_logger::error!(?error, "failed to release the Inrou QEMU disk write lease");
        }
    }
}
#[cfg(target_os = "linux")]
fn acquire_inrou_write_lease(file: &fs::File) -> io::Result<InrouWriteLease<'_>> {
    // Linux F_SETLEASE/F_WRLCK. Unlike an advisory record lock, a write lease
    // fails while any conflicting open file description exists and therefore
    // closes the SCM_RIGHTS race that a sequential procfs scan cannot close.
    const F_SETOWN: i32 = 8;
    const F_SETSIG: i32 = 10;
    inrou_linux_fcntl_with_arg(file, F_SETOWN, rustix::process::getpid().as_raw_pid())?;
    inrou_linux_fcntl_with_arg(file, F_SETSIG, rustix::process::Signal::URG.as_raw())?;
    set_inrou_linux_file_lease(file, rustix::process::FlockType::WriteLock)?;
    if let Err(error) = verify_inrou_linux_file_lease(file, rustix::process::FlockType::WriteLock) {
        let _ = set_inrou_linux_file_lease(file, rustix::process::FlockType::Unlocked);
        return Err(error);
    }
    Ok(InrouWriteLease { file, active: true })
}
#[cfg(target_os = "linux")]
fn set_inrou_linux_file_lease(
    file: &fs::File,
    lease: rustix::process::FlockType,
) -> io::Result<()> {
    const F_SETLEASE: i32 = 1_024;
    inrou_linux_fcntl_with_arg(file, F_SETLEASE, lease as i16 as i32).map(|_| ())
}
#[cfg(target_os = "linux")]
fn verify_inrou_linux_file_lease(
    file: &fs::File,
    expected: rustix::process::FlockType,
) -> io::Result<()> {
    const F_GETLEASE: i32 = 1_025;
    let actual = inrou_linux_fcntl(file, F_GETLEASE)?;
    if actual == expected as i16 as i32 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Linux returned lease type {actual} instead of {}",
            expected as i16 as i32
        )))
    }
}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn inrou_linux_fcntl_with_arg(file: &fs::File, command: i32, argument: i32) -> io::Result<i32> {
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    // SAFETY: `file.as_raw_fd()` is live for this call; these Linux fcntl
    // commands consume one integer variadic argument and do not access memory.
    let result = unsafe { fcntl(file.as_raw_fd(), command, argument) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn inrou_linux_fcntl(file: &fs::File, command: i32) -> io::Result<i32> {
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    // SAFETY: `file.as_raw_fd()` is live for this call and F_GETLEASE takes no
    // variadic argument and does not access user memory.
    let result = unsafe { fcntl(file.as_raw_fd(), command) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
#[cfg(target_os = "linux")]
fn reclaim_inrou_qemu_file_if_present(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    validate_inrou_single_component(name)?;
    let path = directory.path().join(name);
    let named_before = match rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error))
                .wrap_err_with(|| format!("inspect {}", path.display()));
        }
    };
    let mode = u32::from(named_before.st_mode) & 0o7777;
    let private_runtime_file = named_before.st_gid == 0 && mode == 0o600;
    let delegated_qemu_file = named_before.st_gid == identity.gid && mode == 0o660;
    if rustix::fs::FileType::from_raw_mode(named_before.st_mode)
        != rustix::fs::FileType::RegularFile
        || named_before.st_nlink as u64 != 1
        || named_before.st_uid != 0
        || (!private_runtime_file && !delegated_qemu_file)
    {
        eyre::bail!(
            "reusable Inrou QEMU file {} is outside root/dedicated-child custody",
            path.display()
        );
    }
    let file = fs::File::from(
        rustix::fs::openat(
            &directory.directory,
            name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened = file.metadata()?;
    if !inrou_stat_matches_metadata(&named_before, &opened) {
        eyre::bail!("reusable Inrou QEMU file changed while it was reclaimed");
    }
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))?;
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::ROOT),
    )?;
    let reclaimed = file.metadata()?;
    let write_lease = acquire_inrou_write_lease(&file).wrap_err_with(|| {
        format!(
            "acquire an exclusive Linux write lease for reclaimed Inrou QEMU disk {}; the backing filesystem must support leases and no stale descriptor may remain",
            path.display()
        )
    })?;
    ensure_no_process_open_file(&reclaimed, std::process::id(), file.as_raw_fd())?;
    let named_after = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if !inrou_stat_matches_metadata(&named_after, &reclaimed)
        || named_after.st_uid != 0
        || named_after.st_gid != 0
        || u32::from(named_after.st_mode) & 0o7777 != 0o600
        || named_after.st_nlink as u64 != 1
    {
        eyre::bail!("reusable Inrou QEMU file changed after stale-fd exclusion");
    }
    validate_reusable_inrou_disk_file_at(directory, name, &file, None)?;
    write_lease
        .release()
        .wrap_err("release the reclaimed Inrou QEMU disk write lease")
}
#[cfg(target_os = "linux")]
fn ensure_no_process_open_file(
    target: &fs::Metadata,
    custody_pid: u32,
    custody_fd: std::os::fd::RawFd,
) -> eyre::Result<()> {
    let processes = fs::read_dir("/proc").wrap_err("enumerate procfs for stale Inrou QEMU fds")?;
    for process in processes {
        let process = process.wrap_err("enumerate procfs process entry")?;
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let descriptors = match fs::read_dir(process.path().join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("inspect procfs descriptors for process {pid}"));
            }
        };
        for descriptor in descriptors {
            let descriptor = match descriptor {
                Ok(descriptor) => descriptor,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!("enumerate procfs descriptors for process {pid}")
                    });
                }
            };
            let descriptor_fd = descriptor
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<std::os::fd::RawFd>().ok());
            if pid == custody_pid && descriptor_fd == Some(custody_fd) {
                continue;
            }
            let opened = match fs::metadata(descriptor.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .wrap_err_with(|| format!("inspect procfs descriptor for process {pid}"));
                }
            };
            if opened.dev() == target.dev() && opened.ino() == target.ino() {
                eyre::bail!("process {pid} still has the reclaimed Inrou QEMU disk open");
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn ensure_no_process_with_inrou_identity(identity: &PortableVmChildIdentity) -> eyre::Result<()> {
    let processes =
        fs::read_dir("/proc").wrap_err("enumerate procfs for the Inrou QEMU identity")?;
    for process in processes {
        let process = process.wrap_err("enumerate procfs process entry")?;
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        match read_inrou_proc_status(pid) {
            Ok(status) => {
                if !inrou_proc_status_matches_identity(&status, identity)? {
                    continue;
                }
                eyre::bail!(
                    "dedicated Inrou uid {} or primary gid {} is already active in process {pid}; the first-release identity and group must be locked and exclusive to one QEMU",
                    identity.uid,
                    identity.gid,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("inspect procfs process {pid}"));
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn prepare_inrou_qemu_directory_chain(
    anchor: &Path,
    target_parent: &Path,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    let anchor = fs::canonicalize(anchor)
        .wrap_err_with(|| format!("canonicalize Inrou runtime root {}", anchor.display()))?;
    let target_parent = fs::canonicalize(target_parent).wrap_err_with(|| {
        format!(
            "canonicalize Inrou QEMU file parent {}",
            target_parent.display()
        )
    })?;
    if !target_parent.starts_with(&anchor) {
        eyre::bail!(
            "Inrou QEMU file parent {} escapes runtime root {}",
            target_parent.display(),
            anchor.display()
        );
    }
    for ancestor in anchor.ancestors().skip(1) {
        let metadata = fs::metadata(ancestor)?;
        let child_can_traverse = metadata.mode() & 0o001 != 0
            || (metadata.gid() == identity.gid
                || identity.supplementary_gids.contains(&metadata.gid()))
                && metadata.mode() & 0o010 != 0
            || metadata.uid() == identity.uid && metadata.mode() & 0o100 != 0;
        if !metadata.is_dir() || !child_can_traverse {
            eyre::bail!(
                "dedicated Inrou QEMU identity cannot traverse ancestor {}",
                ancestor.display()
            );
        }
    }
    let mut directories = target_parent
        .ancestors()
        .take_while(|path| path.starts_with(&anchor))
        .collect::<Vec<_>>();
    directories.reverse();
    for directory in directories {
        let named = fs::symlink_metadata(directory)?;
        if named.file_type().is_symlink()
            || !named.is_dir()
            || named.uid() != 0
            || named.mode() & 0o022 != 0
        {
            eyre::bail!(
                "Inrou QEMU ancestor {} must be root-owned, direct, and non-writable",
                directory.display()
            );
        }
        let mut options = fs::OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt as _;
        options.read(true).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC)
                .bits() as i32,
        );
        let opened = options.open(directory)?;
        let opened_metadata = opened.metadata()?;
        if opened_metadata.dev() != named.dev() || opened_metadata.ino() != named.ino() {
            eyre::bail!("Inrou QEMU ancestor changed while it was opened");
        }
        rustix::fs::fchown(
            &opened,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::from_raw(identity.gid)),
        )?;
        rustix::fs::fchmod(&opened, rustix::fs::Mode::from_raw_mode(0o710))?;
        let after = opened.metadata()?;
        let named_after = fs::symlink_metadata(directory)?;
        if after.dev() != named_after.dev()
            || after.ino() != named_after.ino()
            || after.uid() != 0
            || after.gid() != identity.gid
            || after.mode() & 0o7777 != 0o710
        {
            eyre::bail!("Inrou QEMU ancestor did not retain exact delegated custody");
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn prepare_inrou_qemu_file_access(
    anchor: &Path,
    path: &Path,
    identity: &PortableVmChildIdentity,
    writable: bool,
) -> eyre::Result<fs::File> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("Inrou QEMU file must have a parent"))?;
    prepare_inrou_qemu_directory_chain(anchor, parent, identity)?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() || !named.is_file() || named.nlink() != 1 || named.uid() != 0
    {
        eyre::bail!(
            "Inrou QEMU file {} must be a singly-linked root-owned regular file",
            path.display()
        );
    }
    let mut options = fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt as _;
    options
        .read(true)
        .write(writable)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        eyre::bail!("Inrou QEMU file changed while it was opened");
    }
    let mode = if writable { 0o660 } else { 0o640 };
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::from_raw(identity.gid)),
    )?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode))?;
    let opened_after = file.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    if opened_after.dev() != named_after.dev()
        || opened_after.ino() != named_after.ino()
        || opened_after.uid() != 0
        || opened_after.gid() != identity.gid
        || opened_after.mode() & 0o7777 != mode
        || opened_after.nlink() != 1
    {
        eyre::bail!("Inrou QEMU file did not retain exact delegated custody");
    }
    Ok(file)
}
struct PinnedInrouDirectory {
    display_path: PathBuf,
    directory: fs::File,
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn inrou_mode_from_u32(mode: u32) -> io::Result<rustix::fs::Mode> {
    let raw_mode = rustix::fs::RawMode::try_from(mode).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Inrou file mode {mode:#o} does not fit this host"),
        )
    })?;
    Ok(rustix::fs::Mode::from_raw_mode(raw_mode))
}

impl std::fmt::Debug for PinnedInrouDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedInrouDirectory")
            .field("display_path", &self.display_path)
            .field("directory", &"<pinned>")
            .finish()
    }
}

impl PinnedInrouDirectory {
    fn path(&self) -> &Path {
        &self.display_path
    }

    #[cfg(any(target_os = "linux", test))]
    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            display_path: self.display_path.clone(),
            directory: self.directory.try_clone()?,
        })
    }

    #[cfg(unix)]
    #[cfg(any(target_os = "linux", test))]
    fn open_existing_child_directory(&self, name: &OsStr) -> io::Result<Self> {
        validate_inrou_single_component(name)?;
        let before =
            rustix::fs::statat(&self.directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Inrou directory entry {} is not a real directory",
                    self.display_path.join(name).display()
                ),
            ));
        }
        let child = fs::File::from(
            rustix::fs::openat(
                &self.directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let opened = child.metadata()?;
        let after =
            rustix::fs::statat(&self.directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
        if !opened.is_dir()
            || !inrou_stat_identity_matches_metadata(&before, &opened)
            || !inrou_stat_identity_matches_metadata(&after, &opened)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Inrou directory entry {} changed while it was opened",
                    self.display_path.join(name).display()
                ),
            ));
        }
        Ok(Self {
            display_path: self.display_path.join(name),
            directory: child,
        })
    }

    #[cfg(unix)]
    #[cfg(any(target_os = "linux", test))]
    fn open_or_create_child_directory(&self, name: &OsStr, mode: u32) -> io::Result<Self> {
        validate_inrou_single_component(name)?;
        let mode = inrou_mode_from_u32(mode)?;
        let created = match rustix::fs::mkdirat(&self.directory, name, mode) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(io::Error::from(error)),
        };
        let child = self.open_existing_child_directory(name)?;
        if created {
            rustix::fs::fchmod(&child.directory, mode).map_err(io::Error::from)?;
            self.directory.sync_all()?;
        }
        Ok(child)
    }
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn write_inrou_atomic_file_at<T>(
    directory: &PinnedInrouDirectory,
    final_name: &OsStr,
    replace_existing: bool,
    write: impl FnOnce(&mut fs::File) -> io::Result<(T, u64)>,
) -> io::Result<T> {
    validate_inrou_single_component(final_name)?;
    let mut created = None;
    for _ in 0..128 {
        let sequence = SORACLOUD_ATOMIC_WRITE_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let staging_name = OsString::from(format!(
            ".{}.{}.{}.inrou-tmp",
            final_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        match rustix::fs::openat(
            &directory.directory,
            &staging_name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => {
                created = Some((fs::File::from(file), staging_name));
                break;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    let Some((mut staging, staging_name)) = created else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exhausted descriptor-relative Inrou staging names",
        ));
    };
    let initial = staging.metadata()?;
    let identity = (initial.dev(), initial.ino());
    let result = (|| -> io::Result<T> {
        let (value, expected_bytes) = write(&mut staging)?;
        staging.sync_all()?;
        let opened = staging.metadata()?;
        let named = rustix::fs::statat(
            &directory.directory,
            &staging_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        if !opened.is_file()
            || opened.dev() != identity.0
            || opened.ino() != identity.1
            || opened.nlink() != 1
            || opened.uid() != rustix::process::geteuid().as_raw()
            || opened.mode() & 0o7777 != 0o600
            || opened.len() != expected_bytes
            || !inrou_stat_matches_metadata(&named, &opened)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor-relative Inrou staging file changed identity",
            ));
        }
        if replace_existing {
            rustix::fs::renameat(
                &directory.directory,
                &staging_name,
                &directory.directory,
                final_name,
            )
            .map_err(io::Error::from)?;
        } else {
            rename_inrou_no_replace_at(
                &directory.directory,
                &staging_name,
                &directory.directory,
                final_name,
            )?;
        }
        let published = rustix::fs::statat(
            &directory.directory,
            final_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let opened_after = staging.metadata()?;
        if opened_after.dev() != identity.0
            || opened_after.ino() != identity.1
            || !inrou_stat_matches_metadata(&published, &opened_after)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor-relative Inrou publication changed identity",
            ));
        }
        directory.directory.sync_all()?;
        Ok(value)
    })();
    if result.is_err()
        && let Ok(named) = rustix::fs::statat(
            &directory.directory,
            &staging_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        && named.st_dev as u64 == identity.0
        && named.st_ino as u64 == identity.1
    {
        let _ = rustix::fs::unlinkat(
            &directory.directory,
            &staging_name,
            rustix::fs::AtFlags::empty(),
        );
        let _ = directory.directory.sync_all();
    }
    result
}

#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn write_inrou_bytes_at(
    directory: &PinnedInrouDirectory,
    final_name: &OsStr,
    bytes: &[u8],
    replace_existing: bool,
) -> io::Result<()> {
    write_inrou_atomic_file_at(directory, final_name, replace_existing, |file| {
        file.write_all(bytes)?;
        Ok(((), u64::try_from(bytes.len()).unwrap_or(u64::MAX)))
    })
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn remove_inrou_tree_entry_at(
    parent: &PinnedInrouDirectory,
    name: &OsStr,
    depth: usize,
    entries_seen: &mut usize,
) -> io::Result<()> {
    validate_inrou_single_component(name)?;
    if depth > usize::from(SORA_INROU_PORTABLE_PATH_MAX_COMPONENTS_V1).saturating_add(8) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Inrou descriptor-relative cleanup exceeded its depth bound",
        ));
    }
    *entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Inrou cleanup entry count overflow",
        )
    })?;
    if *entries_seen > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Inrou descriptor-relative cleanup exceeded its entry bound",
        ));
    }
    let before = match rustix::fs::statat(
        &parent.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(before) => before,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(io::Error::from(error)),
    };
    match rustix::fs::FileType::from_raw_mode(before.st_mode) {
        rustix::fs::FileType::Directory => {
            let child = parent.open_existing_child_directory(name)?;
            let entries = rustix::fs::Dir::read_from(&child.directory).map_err(io::Error::from)?;
            for entry in entries {
                let entry = entry.map_err(io::Error::from)?;
                let child_name = OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string();
                if child_name == OsStr::new(".") || child_name == OsStr::new("..") {
                    continue;
                }
                remove_inrou_tree_entry_at(&child, &child_name, depth + 1, entries_seen)?;
            }
            child.directory.sync_all()?;
            let opened = child.directory.metadata()?;
            let named_after = rustix::fs::statat(
                &parent.directory,
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            // Removing descendant directories changes this directory's link count. Preserve the
            // original device/inode check across the recursive mutation, then require the final
            // name and pinned descriptor to agree exactly.
            if before.st_dev as u64 != opened.dev()
                || before.st_ino as u64 != opened.ino()
                || !inrou_stat_matches_metadata(&named_after, &opened)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Inrou directory changed before descriptor-relative removal",
                ));
            }
            rustix::fs::unlinkat(&parent.directory, name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(io::Error::from)?;
        }
        rustix::fs::FileType::RegularFile => {
            let file = fs::File::from(
                rustix::fs::openat(
                    &parent.directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io::Error::from)?,
            );
            let opened = file.metadata()?;
            let named_after = rustix::fs::statat(
                &parent.directory,
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            if !inrou_stat_matches_metadata(&before, &opened)
                || !inrou_stat_matches_metadata(&named_after, &opened)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Inrou file changed before descriptor-relative removal",
                ));
            }
            rustix::fs::unlinkat(&parent.directory, name, rustix::fs::AtFlags::empty())
                .map_err(io::Error::from)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Inrou cleanup refused a symlink or special filesystem entry",
            ));
        }
    }
    parent.directory.sync_all()
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn reset_inrou_child_directory(
    parent: &PinnedInrouDirectory,
    name: &OsStr,
    mode: u32,
) -> io::Result<PinnedInrouDirectory> {
    let mut entries_seen = 0;
    remove_inrou_tree_entry_at(parent, name, 0, &mut entries_seen)?;
    parent.open_or_create_child_directory(name, mode)
}

fn validate_inrou_single_component(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Inrou descriptor-relative name must be one normal path component",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn rename_inrou_no_replace_at(
    old_directory: &fs::File,
    old_name: &OsStr,
    new_directory: &fs::File,
    new_name: &OsStr,
) -> io::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        return rustix::fs::renameat_with(
            old_directory,
            old_name,
            new_directory,
            new_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    {
        let _ = (old_directory, old_name, new_directory, new_name);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-relative no-replace Inrou publication is unsupported on this Unix host",
        ))
    }
}

#[cfg(unix)]
fn inrou_stat_identity_matches_metadata(stat: &rustix::fs::Stat, metadata: &fs::Metadata) -> bool {
    stat.st_dev as u64 == metadata.dev() && stat.st_ino as u64 == metadata.ino()
}

#[cfg(unix)]
fn inrou_stat_matches_metadata(stat: &rustix::fs::Stat, metadata: &fs::Metadata) -> bool {
    inrou_stat_identity_matches_metadata(stat, metadata) && stat.st_nlink as u64 == metadata.nlink()
}

#[cfg(unix)]
fn ensure_secure_inrou_disk_directory(path: &Path) -> eyre::Result<PinnedInrouDirectory> {
    ensure_secure_inrou_disk_directory_with_hook(path, |_| Ok(()))
}

#[cfg(unix)]
fn ensure_secure_inrou_disk_directory_with_hook(
    path: &Path,
    mut after_component_stat: impl FnMut(&Path) -> io::Result<()>,
) -> eyre::Result<PinnedInrouDirectory> {
    let original = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .wrap_err("resolve the current directory for an Inrou disk path")?
            .join(path)
    };
    let components = original
        .components()
        .map(|component| match component {
            std::path::Component::RootDir => Ok(None),
            std::path::Component::Normal(name) => Ok(Some(name.to_os_string())),
            _ => Err(eyre::eyre!(
                "Inrou disk path {} must be an absolute canonical component chain",
                original.display()
            )),
        })
        .collect::<eyre::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if components.is_empty() {
        eyre::bail!("the filesystem root cannot be an Inrou disk directory");
    }

    let effective_uid = rustix::process::geteuid().as_raw();
    let mut current = fs::File::from(
        rustix::fs::open(
            Path::new("/"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)
        .wrap_err("pin the filesystem root for Inrou disk traversal")?,
    );
    let root_metadata = current.metadata()?;
    if !root_metadata.is_dir()
        || (root_metadata.uid() != 0 && root_metadata.uid() != effective_uid)
        || (root_metadata.mode() & 0o022 != 0 && root_metadata.mode() & 0o1000 == 0)
    {
        eyre::bail!("the filesystem root does not satisfy Inrou directory custody");
    }

    let mut display_path = PathBuf::from("/");
    for (index, name) in components.iter().enumerate() {
        display_path.push(name);
        let created = match rustix::fs::mkdirat(&current, name, rustix::fs::Mode::RWXU) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => {
                return Err(io::Error::from(error))
                    .wrap_err_with(|| format!("create {}", display_path.display()));
            }
        };
        let before = rustix::fs::statat(&current, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .wrap_err_with(|| format!("inspect {}", display_path.display()))?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            eyre::bail!(
                "Inrou disk path {} contains a symlink or non-directory component {}",
                original.display(),
                display_path.display()
            );
        }
        after_component_stat(&display_path)?;
        let child = fs::File::from(
            rustix::fs::openat(
                &current,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)
            .wrap_err_with(|| format!("pin {}", display_path.display()))?,
        );
        if created {
            rustix::fs::fchmod(&child, rustix::fs::Mode::RWXU)
                .map_err(io::Error::from)
                .wrap_err_with(|| format!("secure {}", display_path.display()))?;
            current
                .sync_all()
                .wrap_err_with(|| format!("sync {}", display_path.display()))?;
        }
        let opened = child.metadata()?;
        let after = rustix::fs::statat(&current, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
            .wrap_err_with(|| format!("re-inspect {}", display_path.display()))?;
        if !opened.is_dir()
            || !inrou_stat_identity_matches_metadata(&before, &opened)
            || !inrou_stat_identity_matches_metadata(&after, &opened)
        {
            eyre::bail!(
                "Inrou disk ancestor {} changed while it was opened",
                display_path.display()
            );
        }
        let is_final = index + 1 == components.len();
        if (is_final && opened.uid() != effective_uid)
            || (!is_final && opened.uid() != 0 && opened.uid() != effective_uid)
        {
            eyre::bail!(
                "Inrou disk directory {} is owned by untrusted uid {} instead of the runtime uid {effective_uid}",
                display_path.display(),
                opened.uid()
            );
        }
        let writable_by_others = opened.mode() & 0o022 != 0;
        let protected_by_sticky_bit = opened.mode() & 0o1000 != 0;
        if writable_by_others && (is_final || !protected_by_sticky_bit) {
            eyre::bail!(
                "Inrou disk directory custody permits path replacement through {}",
                display_path.display()
            );
        }
        current = child;
    }
    Ok(PinnedInrouDirectory {
        display_path,
        directory: current,
    })
}

#[cfg(not(unix))]
fn ensure_secure_inrou_disk_directory(_path: &Path) -> eyre::Result<PinnedInrouDirectory> {
    eyre::bail!("descriptor-pinned Inrou storage requires a Unix host")
}
#[cfg(unix)]
struct InrouDiskStagingFile {
    name: OsString,
    file: fs::File,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn create_unique_inrou_disk_staging_file(
    directory: &PinnedInrouDirectory,
    final_file_name: &str,
) -> eyre::Result<InrouDiskStagingFile> {
    validate_inrou_single_component(OsStr::new(final_file_name))?;
    for _ in 0..128 {
        let mut suffix = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut suffix)
            .map_err(|error| eyre::eyre!("Inrou disk staging OS RNG failed: {error}"))?;
        let name = OsString::from(format!(
            ".{final_file_name}.inrou-stage-{}",
            hex::encode(suffix)
        ));
        let file = match rustix::fs::openat(
            &directory.directory,
            &name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => fs::File::from(file),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).wrap_err("create Inrou disk staging file");
            }
        };
        let metadata = file.metadata()?;
        let named = rustix::fs::statat(
            &directory.directory,
            &name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || !inrou_stat_matches_metadata(&named, &metadata)
        {
            let _ = rustix::fs::unlinkat(&directory.directory, &name, rustix::fs::AtFlags::empty());
            eyre::bail!("exclusive Inrou disk staging file did not retain exact custody");
        }
        return Ok(InrouDiskStagingFile {
            name,
            device: metadata.dev(),
            inode: metadata.ino(),
            file,
        });
    }
    eyre::bail!("failed to allocate an exclusive Inrou disk staging file")
}

#[cfg(unix)]
fn remove_inrou_disk_staging_file(
    directory: &PinnedInrouDirectory,
    staging: &InrouDiskStagingFile,
) -> eyre::Result<()> {
    let named = match rustix::fs::statat(
        &directory.directory,
        &staging.name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error)).wrap_err("inspect Inrou disk staging file");
        }
    };
    if named.st_dev as u64 != staging.device || named.st_ino as u64 != staging.inode {
        eyre::bail!(
            "refused to remove a replaced Inrou disk staging name {}",
            directory.path().join(&staging.name).display()
        );
    }
    rustix::fs::unlinkat(
        &directory.directory,
        &staging.name,
        rustix::fs::AtFlags::empty(),
    )
    .map_err(io::Error::from)
    .wrap_err("remove exact Inrou disk staging file")?;
    directory.directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn install_staged_inrou_disk(
    directory: &PinnedInrouDirectory,
    staging: &mut InrouDiskStagingFile,
    final_name: &OsStr,
    exact_bytes: Option<u64>,
) -> eyre::Result<()> {
    validate_inrou_single_component(final_name)?;
    validate_reusable_inrou_disk_file_at(directory, &staging.name, &staging.file, exact_bytes)?;
    staging.file.sync_all()?;
    rename_inrou_no_replace_at(
        &directory.directory,
        &staging.name,
        &directory.directory,
        final_name,
    )
    .wrap_err_with(|| {
        format!(
            "atomically install new staged Inrou disk {} as {} without replacing existing state",
            directory.path().join(&staging.name).display(),
            directory.path().join(final_name).display()
        )
    })?;
    directory.directory.sync_all()?;
    validate_reusable_inrou_disk_file_at(directory, final_name, &staging.file, exact_bytes)
}

#[cfg(unix)]
fn read_inrou_sidecar_at(
    directory: &PinnedInrouDirectory,
    name: &OsStr,
    maximum_bytes: u64,
    label: &str,
) -> eyre::Result<Option<String>> {
    validate_inrou_single_component(name)?;
    let path = directory.path().join(name);
    let before = match rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(before) => before,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(io::Error::from(error))
                .wrap_err_with(|| format!("inspect {label} {}", path.display()));
        }
    };
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink as u64 != 1
        || before.st_uid != rustix::process::geteuid().as_raw()
        || u32::from(before.st_mode) & 0o7777 != 0o600
        || before.st_size < 0
        || u64::try_from(before.st_size).unwrap_or(u64::MAX) > maximum_bytes
    {
        eyre::bail!(
            "{label} {} must be a bounded singly-linked owner-private regular file",
            path.display()
        );
    }
    let mut file = fs::File::from(
        rustix::fs::openat(
            &directory.directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened_before = file.metadata()?;
    if !inrou_stat_matches_metadata(&before, &opened_before) {
        eyre::bail!("{label} {} changed while it was opened", path.display());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        eyre::bail!("{label} {} exceeds its byte limit", path.display());
    }
    let opened_after = file.metadata()?;
    let after = rustix::fs::statat(
        &directory.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if opened_before.dev() != opened_after.dev()
        || opened_before.ino() != opened_after.ino()
        || opened_before.len() != opened_after.len()
        || !inrou_stat_matches_metadata(&after, &opened_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        eyre::bail!("{label} {} changed while it was read", path.display());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| eyre::eyre!("decode {label} {}: {error}", path.display()))
}

#[cfg(unix)]
fn write_inrou_sidecar_no_replace_at(
    directory: &PinnedInrouDirectory,
    final_name: &OsStr,
    bytes: &[u8],
    label: &str,
) -> eyre::Result<()> {
    validate_inrou_single_component(final_name)?;
    let final_display = directory.path().join(final_name);
    for _ in 0..128 {
        let mut suffix = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut suffix)
            .map_err(|error| eyre::eyre!("{label} staging OS RNG failed: {error}"))?;
        let staging_name = OsString::from(format!(
            ".{}.inrou-sidecar-stage-{}",
            final_name.to_string_lossy(),
            hex::encode(suffix)
        ));
        let mut staging = match rustix::fs::openat(
            &directory.directory,
            &staging_name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => fs::File::from(file),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => {
                return Err(io::Error::from(error)).wrap_err_with(|| format!("stage {label}"));
            }
        };
        let initial = staging.metadata()?;
        let identity = (initial.dev(), initial.ino());
        let prepare = (|| -> eyre::Result<()> {
            staging.write_all(bytes)?;
            staging.sync_all()?;
            let opened = staging.metadata()?;
            let named = rustix::fs::statat(
                &directory.directory,
                &staging_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            if !opened.is_file()
                || opened.dev() != identity.0
                || opened.ino() != identity.1
                || opened.nlink() != 1
                || opened.uid() != rustix::process::geteuid().as_raw()
                || opened.mode() & 0o7777 != 0o600
                || opened.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                || !inrou_stat_matches_metadata(&named, &opened)
            {
                eyre::bail!("staged {label} did not retain exact custody");
            }
            Ok(())
        })();
        if let Err(error) = prepare {
            let current = rustix::fs::statat(
                &directory.directory,
                &staging_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            if current.is_ok_and(|stat| {
                stat.st_dev as u64 == identity.0 && stat.st_ino as u64 == identity.1
            }) {
                let _ = rustix::fs::unlinkat(
                    &directory.directory,
                    &staging_name,
                    rustix::fs::AtFlags::empty(),
                );
            }
            return Err(error);
        }
        if let Err(error) = rename_inrou_no_replace_at(
            &directory.directory,
            &staging_name,
            &directory.directory,
            final_name,
        ) {
            let current = rustix::fs::statat(
                &directory.directory,
                &staging_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            );
            if current.is_ok_and(|stat| {
                stat.st_dev as u64 == identity.0 && stat.st_ino as u64 == identity.1
            }) {
                let _ = rustix::fs::unlinkat(
                    &directory.directory,
                    &staging_name,
                    rustix::fs::AtFlags::empty(),
                );
            }
            return Err(io::Error::from(error)).wrap_err_with(|| {
                format!(
                    "install {label} {} without replacing existing state",
                    final_display.display()
                )
            });
        }
        let published = rustix::fs::statat(
            &directory.directory,
            final_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let opened = staging.metadata()?;
        if opened.dev() != identity.0
            || opened.ino() != identity.1
            || !inrou_stat_matches_metadata(&published, &opened)
        {
            eyre::bail!("published {label} changed identity during installation");
        }
        directory.directory.sync_all()?;
        return Ok(());
    }
    eyre::bail!("failed to allocate an exclusive {label} staging file")
}
fn exact_inrou_replica_placement(
    plan: &SoracloudRuntimeServicePlan,
) -> eyre::Result<&SoracloudRuntimeReplicaPlan> {
    match (
        plan.local_replica_slots.as_slice(),
        plan.local_replicas.as_slice(),
    ) {
        ([replica_slot], [placement])
            if *replica_slot != 0
                && placement.replica_slot == *replica_slot
                && !placement.placement_incarnation.trim().is_empty()
                && !placement.validator_account_id.trim().is_empty()
                && !placement.peer_id.trim().is_empty() =>
        {
            Ok(placement)
        }
        slots => eyre::bail!(
            "an Inrou worker plan must identify exactly one authenticated nonzero replica placement, found {slots:?}"
        ),
    }
}
#[cfg(any(target_os = "linux", test))]
fn inrou_root_disk_binding(
    bundle: &SoraDeploymentBundleV1,
    service_plan: &SoracloudRuntimeServicePlan,
    inrou_plan: &SoracloudRuntimeInrouPlan,
    root_volume: &SoracloudRuntimeLeaseVolumePlan,
) -> eyre::Result<Hash> {
    let placement = exact_inrou_replica_placement(service_plan)?;
    let image = bundle
        .container
        .inrou
        .as_ref()
        .and_then(|inrou| inrou.guest_images.get(&inrou_plan.selected_guest_isa))
        .ok_or_else(|| {
            eyre::eyre!("selected Inrou guest image is absent from the signed bundle")
        })?;
    if image.rootfs_image_path != inrou_plan.rootfs_image_path {
        eyre::bail!("selected Inrou rootfs does not match the signed bundle");
    }
    if root_volume.kind != SoraLeaseVolumeKindV1::PersistentRootLeaseVolume
        || root_volume.volume_name != inrou_plan.root_volume_name
    {
        eyre::bail!("selected Inrou root volume does not match the signed runtime plan");
    }
    Ok(Hash::new(Encode::encode(&(
        "soracloud.inrou.root-disk-binding.v1".to_owned(),
        service_plan.service_name.clone(),
        service_plan.service_version.clone(),
        (
            placement.replica_slot,
            placement.placement_incarnation.clone(),
            placement.validator_account_id.clone(),
            placement.peer_id.clone(),
        ),
        bundle.container.bundle_hash,
        inrou_plan.selected_guest_isa,
        image.clone(),
        root_volume.volume_name.clone(),
        (
            root_volume.kind,
            root_volume.storage_class,
            root_volume.mount_path.clone(),
            root_volume.max_total_bytes,
            root_volume.lease_started_height,
            root_volume.authoritative_generation,
        ),
    ))))
}
#[cfg(test)]
fn inrou_root_disk_binding_path(root_disk_path: &Path) -> eyre::Result<PathBuf> {
    let file_name = root_disk_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre::eyre!("Inrou root disk path must end in a UTF-8 file name"))?;
    Ok(root_disk_path.with_file_name(format!("{file_name}.binding-v1")))
}
fn inrou_root_disk_binding_name(root_disk_name: &OsStr) -> eyre::Result<OsString> {
    let file_name = root_disk_name
        .to_str()
        .ok_or_else(|| eyre::eyre!("Inrou root disk name must be UTF-8"))?;
    validate_inrou_single_component(root_disk_name)?;
    Ok(OsString::from(format!("{file_name}.binding-v1")))
}
#[cfg(unix)]
fn validate_optional_inrou_root_disk_binding(
    directory: &PinnedInrouDirectory,
    root_disk_name: &OsStr,
    expected_binding: Hash,
) -> eyre::Result<bool> {
    let binding_name = inrou_root_disk_binding_name(root_disk_name)?;
    let Some(actual) = read_inrou_sidecar_at(
        directory,
        &binding_name,
        128,
        "Inrou persistent root-disk binding",
    )?
    else {
        return Ok(false);
    };
    if actual != expected_binding.to_string() {
        eyre::bail!(
            "Inrou persistent root disk {} is bound to a different authenticated replica contract",
            directory.path().join(root_disk_name).display()
        );
    }
    Ok(true)
}
#[cfg(unix)]
fn write_inrou_root_disk_binding(
    directory: &PinnedInrouDirectory,
    root_disk_name: &OsStr,
    binding: Hash,
) -> eyre::Result<()> {
    let binding_name = inrou_root_disk_binding_name(root_disk_name)?;
    write_inrou_sidecar_no_replace_at(
        directory,
        &binding_name,
        binding.to_string().as_bytes(),
        "Inrou persistent root-disk binding",
    )?;
    if !validate_optional_inrou_root_disk_binding(directory, root_disk_name, binding)? {
        eyre::bail!("Inrou persistent root-disk binding disappeared after installation");
    }
    Ok(())
}

#[cfg(unix)]
struct PreparedInrouRootDisk {
    // Only the Linux portable-VM launcher attaches the prepared root disk by path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    image_path: PathBuf,
    image_name: OsString,
    directory: PinnedInrouDirectory,
    exact_bytes: u64,
}

#[cfg(unix)]
impl std::fmt::Debug for PreparedInrouRootDisk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedInrouRootDisk")
            .field("image_path", &"<redacted>")
            .field("image_name", &self.image_name)
            .field("directory", &self.directory)
            .field("exact_bytes", &self.exact_bytes)
            .finish()
    }
}

#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ensure_inrou_portable_root_disk(
    base_rootfs_image_path: &Path,
    root_volume: &SoracloudRuntimeLeaseVolumePlan,
    disk_binding: Hash,
) -> eyre::Result<PreparedInrouRootDisk> {
    let root_volume_dir =
        ensure_secure_inrou_disk_directory(Path::new(&root_volume.local_materialization_dir))?;
    let root_disk_name = OsString::from("rootfs.ext4");
    let root_disk_path = root_volume_dir.path().join(&root_disk_name);
    let (mut base_file, base_metadata) = open_soracloud_regular_file_no_follow(
        base_rootfs_image_path,
        "Inrou immutable base rootfs",
    )
    .wrap_err_with(|| format!("open {}", base_rootfs_image_path.display()))?;
    let base_size = base_metadata.len();
    if base_size > root_volume.max_total_bytes {
        eyre::bail!(
            "Inrou base rootfs {} exceeds root lease budget {} bytes for volume `{}`",
            base_rootfs_image_path.display(),
            root_volume.max_total_bytes,
            root_volume.volume_name
        );
    }
    let root_disk_exists =
        open_reusable_inrou_disk_at(&root_volume_dir, &root_disk_name, Some(base_size), false)?
            .is_some();
    let binding_exists =
        validate_optional_inrou_root_disk_binding(&root_volume_dir, &root_disk_name, disk_binding)?;
    if root_disk_exists {
        if !binding_exists {
            eyre::bail!(
                "existing Inrou persistent root disk {} has no authenticated replica binding",
                root_disk_path.display()
            );
        }
        return Ok(PreparedInrouRootDisk {
            image_path: root_disk_path,
            image_name: root_disk_name,
            directory: root_volume_dir,
            exact_bytes: base_size,
        });
    }
    if !binding_exists {
        write_inrou_root_disk_binding(&root_volume_dir, &root_disk_name, disk_binding)?;
    }
    let mut staging = create_unique_inrou_disk_staging_file(&root_volume_dir, "rootfs.ext4")?;
    let staging_path = root_volume_dir.path().join(&staging.name);
    let prepare_result = (|| -> eyre::Result<()> {
        let copied = io::copy(&mut base_file, &mut staging.file).wrap_err_with(|| {
            format!(
                "copy immutable Inrou rootfs {} into {}",
                base_rootfs_image_path.display(),
                staging_path.display()
            )
        })?;
        if copied != base_size {
            eyre::bail!(
                "Inrou immutable base rootfs changed length while it was copied: expected {base_size} bytes, copied {copied}"
            );
        }
        staging
            .file
            .sync_all()
            .wrap_err_with(|| format!("sync staged root disk {}", staging_path.display()))?;
        let opened_after = base_file.metadata()?;
        let named_after = fs::symlink_metadata(base_rootfs_image_path)?;
        if !same_soracloud_regular_file(&base_metadata, &opened_after)
            || !same_soracloud_regular_file(&opened_after, &named_after)
        {
            eyre::bail!("Inrou immutable base rootfs changed while it was copied");
        }
        Ok(())
    })();
    if let Err(error) = prepare_result {
        remove_inrou_disk_staging_file(&root_volume_dir, &staging)?;
        return Err(error);
    }
    let install_result = install_staged_inrou_disk(
        &root_volume_dir,
        &mut staging,
        &root_disk_name,
        Some(base_size),
    );
    if let Err(error) = install_result {
        remove_inrou_disk_staging_file(&root_volume_dir, &staging)?;
        return Err(error);
    }
    Ok(PreparedInrouRootDisk {
        image_path: root_disk_path,
        image_name: root_disk_name,
        directory: root_volume_dir,
        exact_bytes: base_size,
    })
}
#[cfg(any(target_os = "linux", test))]
fn inrou_lease_disk_binding(
    plan: &SoracloudRuntimeServicePlan,
    volume: &SoracloudRuntimeLeaseVolumePlan,
    filesystem_uuid: &str,
) -> eyre::Result<Hash> {
    let placement = exact_inrou_replica_placement(plan)?;
    Ok(Hash::new(Encode::encode(&(
        "soracloud.inrou.lease-disk-binding.v1".to_owned(),
        plan.service_name.clone(),
        plan.service_version.clone(),
        (
            placement.replica_slot,
            placement.placement_incarnation.clone(),
            placement.validator_account_id.clone(),
            placement.peer_id.clone(),
        ),
        plan.bundle_hash.clone(),
        volume.volume_name.clone(),
        (
            volume.kind,
            volume.storage_class,
            volume.mount_path.clone(),
            volume.max_total_bytes,
            volume.lease_started_height,
            volume.authoritative_generation,
        ),
        (
            INROU_PORTABLE_VOLUME_FILESYSTEM.to_owned(),
            filesystem_uuid.to_owned(),
        ),
    ))))
}
#[cfg(test)]
fn inrou_lease_disk_sidecar_path(image_path: &Path, suffix: &str) -> eyre::Result<PathBuf> {
    let file_name = image_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre::eyre!("Inrou lease disk path must end in a UTF-8 file name"))?;
    Ok(image_path.with_file_name(format!("{file_name}.{suffix}")))
}
#[cfg(any(target_os = "linux", test))]
fn inrou_lease_disk_sidecar_name(image_name: &OsStr, suffix: &str) -> eyre::Result<OsString> {
    let file_name = image_name
        .to_str()
        .ok_or_else(|| eyre::eyre!("Inrou lease disk name must be UTF-8"))?;
    validate_inrou_single_component(image_name)?;
    Ok(OsString::from(format!("{file_name}.{suffix}")))
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn validate_optional_inrou_lease_disk_sidecar(
    directory: &PinnedInrouDirectory,
    sidecar_name: &OsStr,
    expected_binding: Hash,
    label: &str,
) -> eyre::Result<bool> {
    let Some(actual) = read_inrou_sidecar_at(directory, sidecar_name, 128, label)? else {
        return Ok(false);
    };
    if actual != expected_binding.to_string() {
        eyre::bail!(
            "{label} {} does not match the admitted Inrou lease-disk identity",
            directory.path().join(sidecar_name).display()
        );
    }
    Ok(true)
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn write_inrou_lease_disk_sidecar(
    directory: &PinnedInrouDirectory,
    sidecar_name: &OsStr,
    binding: Hash,
    label: &str,
) -> eyre::Result<()> {
    write_inrou_sidecar_no_replace_at(
        directory,
        sidecar_name,
        binding.to_string().as_bytes(),
        label,
    )?;
    if !validate_optional_inrou_lease_disk_sidecar(directory, sidecar_name, binding, label)? {
        eyre::bail!("{label} disappeared after atomic installation");
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn ensure_inrou_portable_lease_disks(
    _qemu_img: &Path,
    plan: &SoracloudRuntimeServicePlan,
) -> eyre::Result<Vec<PortableVmLeaseDisk>> {
    exact_inrou_replica_placement(plan)?;
    let mut disks = Vec::new();
    for volume in plan
        .lease_volumes
        .iter()
        .filter(|volume| volume.kind != SoraLeaseVolumeKindV1::PersistentRootLeaseVolume)
    {
        validate_inrou_data_volume_mount_path(&volume.volume_name, &volume.mount_path)?;
        let device_serial = portable_vm_block_device_serial(&volume.volume_name)?;
        let filesystem_uuid = inrou_lease_filesystem_uuid(plan, volume)?;
        let volume_dir =
            ensure_secure_inrou_disk_directory(Path::new(&volume.local_materialization_dir))?;
        let image_name = OsString::from("lease.raw");
        let image_path = volume_dir.path().join(&image_name);
        let binding = inrou_lease_disk_binding(plan, volume, &filesystem_uuid)?;
        let binding_name = inrou_lease_disk_sidecar_name(&image_name, "binding-v1")?;
        #[cfg(all(test, unix))]
        let binding_path = volume_dir.path().join(&binding_name);
        let initialized_marker_name = inrou_lease_disk_sidecar_name(&image_name, "initialized-v1")?;
        #[cfg(all(test, unix))]
        let initialized_marker_path = volume_dir.path().join(&initialized_marker_name);
        let image_exists = open_reusable_inrou_disk_at(
            &volume_dir,
            &image_name,
            Some(volume.max_total_bytes),
            false,
        )?
        .is_some();
        let binding_exists = validate_optional_inrou_lease_disk_sidecar(
            &volume_dir,
            &binding_name,
            binding,
            "Inrou lease-disk binding",
        )?;
        if image_exists && !binding_exists {
            eyre::bail!(
                "existing Inrou lease disk {} has no authenticated V1 binding",
                image_path.display()
            );
        }
        if !binding_exists {
            write_inrou_lease_disk_sidecar(
                &volume_dir,
                &binding_name,
                binding,
                "Inrou lease-disk binding",
            )?;
        }
        let initialized = validate_optional_inrou_lease_disk_sidecar(
            &volume_dir,
            &initialized_marker_name,
            binding,
            "Inrou lease-disk initialized marker",
        )?;
        if initialized && !image_exists {
            eyre::bail!(
                "Inrou lease disk {} is missing despite its initialized marker",
                image_path.display()
            );
        }
        if !image_exists {
            let mut staging = create_unique_inrou_disk_staging_file(&volume_dir, "lease.raw")?;
            let create_result = (|| -> eyre::Result<()> {
                // A raw QEMU disk is exactly a sparse regular file of the
                // admitted length. Sizing the already-open staging descriptor
                // avoids exporting a replaceable host pathname to qemu-img.
                staging.file.set_len(volume.max_total_bytes)?;
                staging.file.sync_all()?;
                install_staged_inrou_disk(
                    &volume_dir,
                    &mut staging,
                    &image_name,
                    Some(volume.max_total_bytes),
                )
            })();
            if let Err(error) = create_result {
                remove_inrou_disk_staging_file(&volume_dir, &staging)?;
                return Err(error);
            }
        }
        disks.push(PortableVmLeaseDisk {
            mount_path: volume.mount_path.clone(),
            image_path,
            image_name,
            #[cfg(all(test, unix))]
            binding_path,
            binding_name,
            #[cfg(all(test, unix))]
            initialized_marker_path,
            initialized_marker_name,
            directory: volume_dir,
            binding,
            exact_bytes: volume.max_total_bytes,
            image_format: "raw",
            device_serial,
            filesystem_type: INROU_PORTABLE_VOLUME_FILESYSTEM.to_owned(),
            filesystem_uuid,
            mount_options: INROU_PORTABLE_VOLUME_MOUNT_OPTIONS.to_owned(),
            initialize_filesystem: !initialized,
        });
    }
    Ok(disks)
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn mark_inrou_portable_lease_disks_initialized(
    disks: &[PortableVmLeaseDisk],
    delegated_files: &[fs::File],
    custody: InrouDiskCustody,
) -> eyre::Result<()> {
    if disks.len() != delegated_files.len() {
        eyre::bail!(
            "authenticated Inrou lease-disk initialization requires one retained descriptor per disk"
        );
    }
    for (disk, delegated_file) in disks.iter().zip(delegated_files) {
        validate_inrou_disk_under_exact_custody_at(
            &disk.directory,
            &disk.image_name,
            delegated_file,
            disk.exact_bytes,
            custody,
        )?;
        if !validate_optional_inrou_lease_disk_sidecar(
            &disk.directory,
            &disk.binding_name,
            disk.binding,
            "Inrou lease-disk binding",
        )? {
            eyre::bail!("Inrou lease-disk binding disappeared before initialization commit");
        }
        write_inrou_lease_disk_sidecar(
            &disk.directory,
            &disk.initialized_marker_name,
            disk.binding,
            "Inrou lease-disk initialized marker",
        )?;
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn inrou_lease_filesystem_uuid(
    plan: &SoracloudRuntimeServicePlan,
    volume: &SoracloudRuntimeLeaseVolumePlan,
) -> eyre::Result<String> {
    let placement = exact_inrou_replica_placement(plan)?;
    let digest = Hash::new(Encode::encode(&(
        "iroha.soracloud.inrou.lease-filesystem-uuid.v1".to_owned(),
        plan.service_name.clone(),
        plan.service_version.clone(),
        (
            placement.replica_slot,
            placement.placement_incarnation.clone(),
            placement.validator_account_id.clone(),
            placement.peer_id.clone(),
        ),
        plan.bundle_hash.clone(),
        volume.volume_name.clone(),
        (
            volume.kind,
            volume.storage_class,
            volume.mount_path.clone(),
            volume.max_total_bytes,
            volume.lease_started_height,
            volume.authoritative_generation,
        ),
        INROU_PORTABLE_VOLUME_FILESYSTEM.to_owned(),
    )));
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest.as_ref()[..16]);
    // RFC 9562 UUID version 8 reserves this layout for application-defined,
    // deterministic identifiers; the variant remains RFC-compatible.
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&uuid[..4]),
        hex::encode(&uuid[4..6]),
        hex::encode(&uuid[6..8]),
        hex::encode(&uuid[8..10]),
        hex::encode(&uuid[10..]),
    ))
}
#[cfg(any(target_os = "linux", test))]
fn validate_inrou_data_volume_mount_path(volume_name: &str, mount_path: &str) -> eyre::Result<()> {
    let canonical_name = volume_name
        .parse::<Name>()
        .wrap_err_with(|| format!("parse Inrou lease volume name `{volume_name}`"))?;
    let expected = sora_inrou_data_volume_mount_path_v1(&canonical_name)
        .wrap_err("validate portable Inrou lease volume name")?;
    if mount_path != expected {
        eyre::bail!(
            "Inrou lease volume `{volume_name}` must mount at its exact canonical guest path `{expected}`"
        );
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn validate_inrou_guest_data_mount_path(mount_path: &str) -> eyre::Result<()> {
    let relative = mount_path
        .strip_prefix(SORA_INROU_DATA_VOLUME_MOUNT_ROOT_V1)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|suffix| !suffix.is_empty() && !suffix.contains('/'))
        .ok_or_else(|| {
            eyre::eyre!(
                "Inrou data-volume mount `{mount_path}` must be one exact canonical child of `{SORA_INROU_DATA_VOLUME_MOUNT_ROOT_V1}`"
            )
        })?;
    validate_inrou_data_volume_mount_path(relative, mount_path)
}
#[cfg(target_os = "linux")]
fn build_inrou_portable_data_volume_mounts(
    lease_disks: &[PortableVmLeaseDisk],
) -> Vec<InrouDataVolumeMount> {
    lease_disks
        .iter()
        .map(|disk| InrouDataVolumeMount {
            mount_path: disk.mount_path.clone(),
            kind: InrouDataVolumeMountKind::BlockDevice {
                device_serial: disk.device_serial.clone(),
                filesystem_type: disk.filesystem_type.clone(),
                filesystem_uuid: disk.filesystem_uuid.clone(),
                mount_options: disk.mount_options.clone(),
                initialize_filesystem: disk.initialize_filesystem,
            },
        })
        .collect()
}
#[cfg(any(target_os = "linux", test))]
fn portable_vm_block_device_serial(volume_name: &str) -> eyre::Result<String> {
    let canonical_name = volume_name
        .parse::<Name>()
        .wrap_err_with(|| format!("parse Inrou lease volume name `{volume_name}`"))?;
    let _ = sora_inrou_data_volume_mount_path_v1(&canonical_name)
        .wrap_err("validate portable Inrou lease volume name")?;
    let serial = format!("sora-{volume_name}");
    debug_assert!(serial.len() <= 20);
    Ok(serial)
}
#[cfg(any(target_os = "linux", test))]
fn build_portable_vm_network_plan(guest_port: u16) -> eyre::Result<PortableVmNetworkPlan> {
    let public_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .wrap_err("bind supervisor-owned loopback listener for PortableVm")?;
    let public_address = public_listener
        .local_addr()
        .wrap_err("query supervisor-owned PortableVm listener")?;
    let backend_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .wrap_err("reserve the QEMU loopback host-forward port")?;
    let expected_backend = backend_reservation
        .local_addr()
        .wrap_err("query reserved QEMU host-forward port")?;
    let netdev_parts = [
        "user".to_owned(),
        "id=net0".to_owned(),
        "ipv6=off".to_owned(),
        "restrict=on".to_owned(),
        format!(
            "hostfwd=tcp:127.0.0.1:{}-:{guest_port}",
            expected_backend.port()
        ),
    ];
    Ok(PortableVmNetworkPlan {
        netdev: netdev_parts.join(","),
        listen_base_url: format!("http://{public_address}"),
        public_listener,
        backend_reservation,
        expected_backend,
    })
}
#[cfg(target_os = "linux")]
impl InrouLoopbackOwnerFirewall {
    fn install(
        public_listener: &TcpListener,
        child_identity: &PortableVmChildIdentity,
    ) -> eyre::Result<Self> {
        let slot_lock = acquire_inrou_iptables_lock(inrou_firewall_identity_slot(child_identity)?)?;
        Self::install_with_lock(public_listener, child_identity, slot_lock)
    }

    fn install_with_lock(
        public_listener: &TcpListener,
        child_identity: &PortableVmChildIdentity,
        slot_lock: InrouOwnerSlotLock,
    ) -> eyre::Result<Self> {
        slot_lock.require_identity(child_identity)?;
        let supervisor_uid = rustix::process::geteuid().as_raw();
        if supervisor_uid != 0 {
            eyre::bail!("Inrou loopback ownership firewall requires the root supervisor identity");
        }
        let iptables_binary = resolve_inrou_iptables_executable().ok_or_else(|| {
            eyre::eyre!(
                "Inrou PortableVM hosting requires root-owned `/usr/sbin/iptables`, `/sbin/iptables`, `/usr/bin/iptables`, or `/bin/iptables`"
            )
        })?;
        let public_address = public_listener
            .local_addr()
            .wrap_err("query the Inrou public loopback listener")?;
        if public_address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || public_address.port() == 0 {
            eyre::bail!("Inrou ownership firewall requires one concrete IPv4 loopback listener");
        }
        let slot = inrou_firewall_identity_slot(child_identity)?;
        let chain = SORACLOUD_INROU_IPTABLES_CHAIN_SPECS[slot];
        let mut firewall = Self {
            iptables_binary,
            _slot_lock: slot_lock,
            chain,
            owns_chain: false,
        };
        firewall.reject_preexisting_owned_chain(SORACLOUD_INROU_RETIRED_IPTABLES_CHAIN_SPEC)?;
        firewall.reject_preexisting_owned_chain(chain)?;
        firewall.create_owned_chain(chain)?;
        run_inrou_iptables_command(
            &firewall.iptables_binary,
            &planned_inrou_loopback_owner_rule(chain, public_address.port(), supervisor_uid),
        )
        .wrap_err("install the Inrou public-listener owner firewall")?;
        run_inrou_iptables_command(
            &firewall.iptables_binary,
            &inrou_iptables_output_jump_args(chain, "-I", true),
        )
        .wrap_err("install the single owned Inrou OUTPUT jump")?;
        drain_inrou_pre_firewall_connections(public_listener)
            .wrap_err("drain pre-firewall Inrou public connections")?;
        Ok(firewall)
    }

    fn reject_preexisting_owned_chain(&self, chain: InrouOwnedIptablesChain) -> eyre::Result<()> {
        let binary = self.binary_for_chain(chain);
        let chain_exists = inrou_iptables_chain_exists(binary, chain.name)?;
        let jump_exists = inrou_iptables_rule_exists(
            binary,
            chain.hook,
            &inrou_iptables_hook_jump_args(chain, "-C", false),
        )?;
        if chain_exists || jump_exists {
            eyre::bail!(
                "preexisting Inrou firewall chain `{}` or its {} jump has ambiguous ownership; refusing automatic reconciliation and requiring explicit operator cleanup",
                chain.name,
                chain.hook
            );
        }
        Ok(())
    }

    fn create_owned_chain(&mut self, chain: InrouOwnedIptablesChain) -> eyre::Result<()> {
        let binary = self.iptables_binary.clone();
        self.reject_preexisting_owned_chain(chain)?;
        run_inrou_iptables_command(&binary, &inrou_iptables_chain_control_args(chain, "-N"))
            .wrap_err("create the owned Inrou firewall chain")?;
        self.owns_chain = true;
        run_inrou_iptables_command(&binary, &inrou_iptables_chain_marker_args(chain, "-A"))
            .wrap_err("mark the owned Inrou firewall chain")?;
        Ok(())
    }

    fn remove_owned_jumps(&self, chain: InrouOwnedIptablesChain) -> eyre::Result<()> {
        let binary = self.binary_for_chain(chain);
        for _ in 0..SORACLOUD_INROU_IPTABLES_MAX_OWNED_JUMPS {
            if !inrou_iptables_rule_exists(
                binary,
                chain.hook,
                &inrou_iptables_hook_jump_args(chain, "-C", false),
            )? {
                return Ok(());
            }
            run_inrou_iptables_command(binary, &inrou_iptables_hook_jump_args(chain, "-D", false))
                .wrap_err_with(|| format!("remove a stale owned Inrou {} jump", chain.hook))?;
        }
        if inrou_iptables_rule_exists(
            binary,
            chain.hook,
            &inrou_iptables_hook_jump_args(chain, "-C", false),
        )? {
            eyre::bail!(
                "more than {SORACLOUD_INROU_IPTABLES_MAX_OWNED_JUMPS} Inrou {} jumps exist; refusing ambiguous firewall reconciliation",
                chain.hook
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) -> eyre::Result<()> {
        self.cleanup_chain(self.chain)
    }

    fn cleanup_chain(&mut self, chain: InrouOwnedIptablesChain) -> eyre::Result<()> {
        if !self.owns_chain {
            return Ok(());
        }
        self.remove_owned_jumps(chain)?;
        let binary = self.binary_for_chain(chain).to_path_buf();
        run_inrou_iptables_command(&binary, &inrou_iptables_chain_control_args(chain, "-F"))
            .wrap_err("flush the owned Inrou firewall chain during cleanup")?;
        if let Err(error) =
            run_inrou_iptables_command(&binary, &inrou_iptables_chain_control_args(chain, "-X"))
        {
            let marker_error =
                run_inrou_iptables_command(&binary, &inrou_iptables_chain_marker_args(chain, "-A"))
                    .err();
            return Err(error).wrap_err_with(|| {
                marker_error.map_or_else(
                    || format!("delete the owned Inrou firewall chain `{}`", chain.name),
                    |marker_error| {
                        format!(
                            "delete the owned Inrou firewall chain `{}`; restoring its ownership marker also failed: {marker_error}",
                            chain.name
                        )
                    },
                )
            });
        }
        self.owns_chain = false;
        Ok(())
    }

    fn binary_for_chain(&self, _chain: InrouOwnedIptablesChain) -> &Path {
        &self.iptables_binary
    }
}
#[cfg(target_os = "linux")]
impl Drop for InrouLoopbackOwnerFirewall {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            iroha_logger::warn!(
                ?error,
                "failed to reconcile the owned Inrou firewall chain during cleanup"
            );
        }
    }
}
#[cfg(target_os = "linux")]
fn planned_inrou_loopback_owner_rule(
    chain: InrouOwnedIptablesChain,
    port: u16,
    supervisor_uid: u32,
) -> Vec<String> {
    vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-I".to_owned(),
        chain.name.to_owned(),
        "1".to_owned(),
        "-o".to_owned(),
        "lo".to_owned(),
        "-p".to_owned(),
        "tcp".to_owned(),
        "-d".to_owned(),
        Ipv4Addr::LOCALHOST.to_string(),
        "--dport".to_owned(),
        port.to_string(),
        "-m".to_owned(),
        "owner".to_owned(),
        "!".to_owned(),
        "--uid-owner".to_owned(),
        supervisor_uid.to_string(),
        "-j".to_owned(),
        "REJECT".to_owned(),
        "--reject-with".to_owned(),
        "tcp-reset".to_owned(),
    ]
}
#[cfg(target_os = "linux")]
fn inrou_iptables_output_jump_args(
    chain: InrouOwnedIptablesChain,
    operation: &str,
    include_position: bool,
) -> Vec<String> {
    inrou_iptables_hook_jump_args(chain, operation, include_position)
}
#[cfg(target_os = "linux")]
fn inrou_iptables_hook_jump_args(
    chain: InrouOwnedIptablesChain,
    operation: &str,
    include_position: bool,
) -> Vec<String> {
    let mut args = vec![
        "-w".to_owned(),
        "5".to_owned(),
        operation.to_owned(),
        chain.hook.to_owned(),
    ];
    if include_position {
        args.push("1".to_owned());
    }
    args.extend(["-j".to_owned(), chain.name.to_owned()]);
    args
}
#[cfg(target_os = "linux")]
fn inrou_iptables_chain_control_args(
    chain: InrouOwnedIptablesChain,
    operation: &str,
) -> Vec<String> {
    vec![
        "-w".to_owned(),
        "5".to_owned(),
        operation.to_owned(),
        chain.name.to_owned(),
    ]
}
#[cfg(target_os = "linux")]
fn inrou_iptables_chain_marker_args(
    chain: InrouOwnedIptablesChain,
    operation: &str,
) -> Vec<String> {
    vec![
        "-w".to_owned(),
        "5".to_owned(),
        operation.to_owned(),
        chain.name.to_owned(),
        "-m".to_owned(),
        "comment".to_owned(),
        "--comment".to_owned(),
        chain.marker.to_owned(),
        "-j".to_owned(),
        "RETURN".to_owned(),
    ]
}
#[cfg(target_os = "linux")]
fn acquire_inrou_iptables_lock(slot: usize) -> eyre::Result<InrouOwnerSlotLock> {
    let lock_path = SORACLOUD_INROU_IPTABLES_LOCK_PATHS
        .get(slot)
        .map(|path| Path::new(*path))
        .ok_or_else(|| eyre::eyre!("Inrou firewall slot {slot} is outside the canonical range"))?;
    let lock_parent = lock_path
        .parent()
        .ok_or_else(|| eyre::eyre!("Inrou firewall lock path has no parent"))?;
    for ancestor in lock_parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).wrap_err_with(|| {
            format!(
                "inspect Inrou firewall lock ancestor {}",
                ancestor.display()
            )
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            eyre::bail!(
                "Inrou firewall lock ancestor {} must be a root-owned, non-writable directory without symlink indirection",
                ancestor.display()
            );
        }
    }
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options
        .open(lock_path)
        .wrap_err_with(|| format!("open Inrou firewall lock {}", lock_path.display()))?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(lock_path)?;
    if !opened.is_file()
        || opened.nlink() != 1
        || opened.uid() != 0
        || opened.gid() != 0
        || opened.mode() & 0o7777 != 0o600
        || named.file_type().is_symlink()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        eyre::bail!(
            "Inrou firewall lock {} must be one root-owned, owner-private regular file",
            lock_path.display()
        );
    }
    lock_inrou_owner_slot(file, slot)
}
#[cfg(target_os = "linux")]
fn lock_inrou_owner_slot(file: fs::File, slot: usize) -> eyre::Result<InrouOwnerSlotLock> {
    if slot >= SORACLOUD_INROU_IPTABLES_LOCK_PATHS.len() {
        eyre::bail!("Inrou owner lock slot is outside the canonical range");
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).wrap_err(
        format!(
            "acquire the Inrou firewall slot-{slot} lock; another supervisor for that canonical identity may be active"
        ),
    )?;
    Ok(InrouOwnerSlotLock { slot, _file: file })
}
#[cfg(target_os = "linux")]
fn run_inrou_iptables_status(
    program: &Path,
    args: &[String],
) -> eyre::Result<std::process::ExitStatus> {
    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    let mut command = Command::new(program);
    sanitize_host_command_environment(&mut command);
    command
        .args(&borrowed)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .wrap_err_with(|| format!("spawn {} {}", program.display(), borrowed.join(" ")))?;
    let started_at = std::time::Instant::now();
    loop {
        let poll = match child.try_wait() {
            Ok(poll) => poll,
            Err(error) => {
                let termination = terminate_inrou_iptables_child_bounded(&mut child);
                return Err(error).wrap_err_with(|| {
                    format!(
                        "poll {} {}{}",
                        program.display(),
                        borrowed.join(" "),
                        termination
                    )
                });
            }
        };
        match poll {
            Some(status) => return Ok(status),
            None if started_at.elapsed() < SORACLOUD_INROU_IPTABLES_COMMAND_TIMEOUT => {
                thread::sleep(Duration::from_millis(10));
            }
            None => {
                let termination = terminate_inrou_iptables_child_bounded(&mut child);
                eyre::bail!(
                    "{} {} exceeded its {:?} Inrou firewall deadline{}",
                    program.display(),
                    borrowed.join(" "),
                    SORACLOUD_INROU_IPTABLES_COMMAND_TIMEOUT,
                    termination,
                );
            }
        }
    }
}
#[cfg(target_os = "linux")]
fn terminate_inrou_iptables_child_bounded(child: &mut std::process::Child) -> String {
    let kill_error = child.kill().err();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut reap_error = None;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                reap_error = Some("did not exit before the one-second reap deadline".to_owned());
                break;
            }
            Err(error) => {
                reap_error = Some(format!("reaping the command failed: {error}"));
                break;
            }
        }
    }
    let mut suffix = String::new();
    if let Some(error) = kill_error {
        suffix.push_str(&format!("; terminating the command failed: {error}"));
    }
    if let Some(error) = reap_error {
        suffix.push_str("; ");
        suffix.push_str(&error);
    }
    suffix
}
#[cfg(target_os = "linux")]
fn run_inrou_iptables_command(program: &Path, args: &[String]) -> eyre::Result<()> {
    let status = run_inrou_iptables_status(program, args)?;
    if !status.success() {
        eyre::bail!(
            "{} {} failed with status {status}",
            program.display(),
            args.join(" ")
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn inrou_iptables_chain_exists(program: &Path, chain: &str) -> eyre::Result<bool> {
    let list = vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-L".to_owned(),
        chain.to_owned(),
        "-n".to_owned(),
    ];
    let status = run_inrou_iptables_status(program, &list)?;
    if status.success() {
        return Ok(true);
    }
    let output_probe = vec![
        "-w".to_owned(),
        "5".to_owned(),
        "-L".to_owned(),
        "OUTPUT".to_owned(),
        "-n".to_owned(),
    ];
    let probe_status = run_inrou_iptables_status(program, &output_probe)?;
    if !probe_status.success() {
        eyre::bail!(
            "iptables could not distinguish missing chain `{chain}` from an unavailable filter table (statuses {status} and {probe_status})"
        );
    }
    Ok(false)
}
#[cfg(target_os = "linux")]
fn inrou_iptables_rule_exists(
    program: &Path,
    chain: &str,
    check_args: &[String],
) -> eyre::Result<bool> {
    let status = run_inrou_iptables_status(program, check_args)?;
    if status.success() {
        return Ok(true);
    }
    if !inrou_iptables_chain_exists(program, chain)? {
        eyre::bail!("iptables chain `{chain}` disappeared while its Inrou rules were checked");
    }
    Ok(false)
}
#[cfg(target_os = "linux")]
fn drain_inrou_pre_firewall_connections(listener: &TcpListener) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}
impl PortableVmLoopbackBridge {
    #[cfg(target_os = "linux")]
    fn start(
        public_listener: TcpListener,
        backend: SocketAddr,
        egress_accounting: PortableVmReplicaEgressAccounting,
        qmp_control: Arc<Mutex<PortableVmQmpControl>>,
        namespace_attestation: inrou_namespace::InrouNamespaceAttestation,
        cgroup_attestation: inrou_cgroup::InrouCgroupAttestation,
        guest_port: u16,
    ) -> io::Result<Self> {
        let connector = Arc::new(move |expected_backend: SocketAddr, stop: &AtomicBool| {
            if namespace_attestation
                .attest_live(&cgroup_attestation)
                .is_err()
            {
                return None;
            }
            let deadline = std::time::Instant::now() + SORACLOUD_INROU_QMP_SESSION_ATTEST_TIMEOUT;
            loop {
                if stop.load(AtomicOrdering::Acquire) {
                    return None;
                }
                if let Some(mut control) = qmp_control.try_lock() {
                    if attest_inrou_qmp_host_forward(
                        &mut control,
                        guest_port,
                        expected_backend,
                        deadline,
                        Some(stop),
                    )
                    .is_err()
                    {
                        return None;
                    }
                    drop(control);
                    return namespace_attestation
                        .connect_private_loopback(&cgroup_attestation, expected_backend)
                        .ok();
                }
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(1));
            }
        });
        Self::start_with_connector(public_listener, backend, egress_accounting, connector)
    }

    #[cfg(any(target_os = "linux", test))]
    fn start_with_connector(
        public_listener: TcpListener,
        backend: SocketAddr,
        egress_accounting: PortableVmReplicaEgressAccounting,
        connector: PortableVmBackendConnector,
    ) -> io::Result<Self> {
        if backend.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || backend.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PortableVm bridge backend must be a concrete loopback endpoint",
            ));
        }
        let listen_address = public_listener.local_addr()?;
        if listen_address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || listen_address.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PortableVm public listener must be a concrete loopback endpoint",
            ));
        }
        public_listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_egress_accounting = egress_accounting;
        let worker = thread::Builder::new()
            .name("inrou-port-forward".to_owned())
            .spawn(move || {
                let mut sessions = Vec::<thread::JoinHandle<()>>::new();
                while !worker_stop.load(AtomicOrdering::Acquire) {
                    for index in (0..sessions.len()).rev() {
                        if sessions[index].is_finished() {
                            let session = sessions.swap_remove(index);
                            let _ = session.join();
                        }
                    }
                    match public_listener.accept() {
                        Ok((client, _peer)) => {
                            if sessions.len() >= SORACLOUD_INROU_BRIDGE_MAX_CONNECTIONS {
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            let session_stop = Arc::clone(&worker_stop);
                            let session_egress_accounting = worker_egress_accounting.clone();
                            let session_connector = Arc::clone(&connector);
                            match thread::Builder::new()
                                .name("inrou-port-session".to_owned())
                                .stack_size(SORACLOUD_INROU_BRIDGE_SESSION_STACK_BYTES)
                                .spawn(move || {
                                    bridge_portable_vm_connection(
                                        client,
                                        backend,
                                        session_stop,
                                        session_egress_accounting,
                                        session_connector,
                                    );
                                }) {
                                Ok(session) => sessions.push(session),
                                Err(error) => {
                                    iroha_logger::warn!(
                                        ?error,
                                        "failed to spawn bounded Inrou port-forward session"
                                    );
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => {
                            iroha_logger::warn!(
                                ?error,
                                "supervisor-owned Inrou port-forward listener failed"
                            );
                            break;
                        }
                    }
                }
                for session in sessions {
                    let _ = session.join();
                }
            })?;
        Ok(Self {
            listen_address,
            stop,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) {
        if !self.stop.swap(true, AtomicOrdering::AcqRel) {
            let _ = TcpStream::connect_timeout(&self.listen_address, Duration::from_millis(100));
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for PortableVmLoopbackBridge {
    fn drop(&mut self) {
        self.stop();
    }
}
#[cfg(any(target_os = "linux", test))]
fn bridge_portable_vm_connection(
    client: TcpStream,
    backend: SocketAddr,
    global_stop: Arc<AtomicBool>,
    egress_accounting: PortableVmReplicaEgressAccounting,
    connector: PortableVmBackendConnector,
) {
    let Some(server) = connector(backend, &global_stop) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    if global_stop.load(AtomicOrdering::Acquire) {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    }
    for stream in [&client, &server] {
        if stream.set_nodelay(true).is_err()
            || stream
                .set_read_timeout(Some(SORACLOUD_INROU_BRIDGE_IO_POLL))
                .is_err()
            || stream
                .set_write_timeout(Some(SORACLOUD_INROU_BRIDGE_IO_POLL))
                .is_err()
        {
            let _ = client.shutdown(Shutdown::Both);
            let _ = server.shutdown(Shutdown::Both);
            return;
        }
    }
    let Ok(client_reader) = client.try_clone() else {
        return;
    };
    let Ok(server_writer) = server.try_clone() else {
        return;
    };
    let session_stop = Arc::new(AtomicBool::new(false));
    let upstream_global_stop = Arc::clone(&global_stop);
    let upstream_session_stop = Arc::clone(&session_stop);
    let upstream = thread::Builder::new()
        .name("inrou-port-upstream".to_owned())
        .stack_size(SORACLOUD_INROU_BRIDGE_SESSION_STACK_BYTES)
        .spawn(move || {
            bridge_portable_vm_direction(
                client_reader,
                server_writer,
                &upstream_global_stop,
                &upstream_session_stop,
                None,
            );
        });
    bridge_portable_vm_direction(
        server,
        client,
        &global_stop,
        &session_stop,
        Some(&egress_accounting),
    );
    session_stop.store(true, AtomicOrdering::Release);
    if let Ok(upstream) = upstream {
        let _ = upstream.join();
    }
}
#[cfg(any(target_os = "linux", test))]
fn bridge_portable_vm_direction(
    mut reader: TcpStream,
    mut writer: TcpStream,
    global_stop: &AtomicBool,
    session_stop: &AtomicBool,
    egress_accounting: Option<&PortableVmReplicaEgressAccounting>,
) {
    let mut buffer = [0_u8; 16 * 1024];
    while !global_stop.load(AtomicOrdering::Acquire) && !session_stop.load(AtomicOrdering::Acquire)
    {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if write_inrou_bridge_buffer_bounded(
                    &mut writer,
                    &buffer[..read],
                    global_stop,
                    session_stop,
                    egress_accounting,
                )
                .is_err()
                {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    scrub_inrou_bridge_buffer(&mut buffer);
    session_stop.store(true, AtomicOrdering::Release);
    let _ = reader.shutdown(Shutdown::Both);
    let _ = writer.shutdown(Shutdown::Both);
}
#[cfg(any(target_os = "linux", test))]
fn scrub_inrou_bridge_buffer(buffer: &mut [u8]) {
    buffer.fill(0);
    let _ = std::hint::black_box(buffer);
}
#[cfg(any(target_os = "linux", test))]
fn write_inrou_bridge_buffer_bounded<W: io::Write>(
    writer: &mut W,
    mut payload: &[u8],
    global_stop: &AtomicBool,
    session_stop: &AtomicBool,
    egress_accounting: Option<&PortableVmReplicaEgressAccounting>,
) -> io::Result<()> {
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_BRIDGE_WRITE_TIMEOUT;
    while !payload.is_empty() {
        if global_stop.load(AtomicOrdering::Acquire) || session_stop.load(AtomicOrdering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Inrou bridge stopped during a buffered write",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Inrou bridge buffered write exceeded its absolute deadline",
            ));
        }
        let reserved = if let Some(accounting) = egress_accounting {
            let requested = u64::try_from(payload.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Inrou bridge buffer length exceeds the u64 accounting range",
                )
            })?;
            match accounting.precharge(requested) {
                Ok(reserved) => usize::try_from(reserved).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Inrou durable egress precharge exceeds the platform buffer range",
                    )
                })?,
                Err(error) => {
                    global_stop.store(true, AtomicOrdering::Release);
                    return Err(error);
                }
            }
        } else {
            payload.len()
        };
        let mut charged_payload = &payload[..reserved];
        while !charged_payload.is_empty() {
            if global_stop.load(AtomicOrdering::Acquire)
                || session_stop.load(AtomicOrdering::Acquire)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Inrou bridge stopped during a durably charged write",
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Inrou bridge durably charged write exceeded its absolute deadline",
                ));
            }
            match writer.write(charged_payload) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Inrou bridge socket stopped accepting durably charged bytes",
                    ));
                }
                Ok(written) => {
                    if written > charged_payload.len() {
                        if let Some(accounting) = egress_accounting {
                            accounting.fail_closed();
                        }
                        global_stop.store(true, AtomicOrdering::Release);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Inrou bridge writer reported more bytes than it received",
                        ));
                    }
                    charged_payload = &charged_payload[written..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Inrou bridge durably charged write exceeded its absolute deadline",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        payload = &payload[reserved..];
        if egress_accounting.is_some_and(PortableVmReplicaEgressAccounting::exhausted) {
            global_stop.store(true, AtomicOrdering::Release);
        }
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn write_inrou_cloud_init_documents(
    materialization_dir: &PinnedInrouDirectory,
    cache_key: &HostedHttpWorkerCacheKey,
    network_config: &str,
    user_data: &str,
) -> eyre::Result<PinnedInrouDirectory> {
    let seed_root =
        reset_inrou_child_directory(materialization_dir, OsStr::new("inrou_cloud_init"), 0o700)
            .wrap_err("reset descriptor-pinned Inrou cloud-init directory")?;
    let metadata = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        sanitize_path_component(&format!(
            "{}-{}-{}-{}",
            cache_key.service_name,
            cache_key.service_version,
            cache_key.process_generation,
            cache_key.replica_slot
        )),
        sanitize_path_component(&format!(
            "inrou-{}-{}",
            cache_key.service_name, cache_key.replica_slot
        ))
    );
    write_inrou_bytes_at(
        &seed_root,
        OsStr::new("meta-data"),
        metadata.as_bytes(),
        false,
    )
    .wrap_err("write Inrou cloud-init meta-data")?;
    write_inrou_bytes_at(
        &seed_root,
        OsStr::new("network-config"),
        network_config.as_bytes(),
        false,
    )
    .wrap_err("write Inrou cloud-init network-config")?;
    write_inrou_bytes_at(
        &seed_root,
        OsStr::new("user-data"),
        user_data.as_bytes(),
        false,
    )
    .wrap_err("write Inrou cloud-init user-data")?;
    Ok(seed_root)
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn stage_portable_vm_bundle_block_device(
    materialization_dir: &PinnedInrouDirectory,
    bundle_cache_path: &Path,
    expected_hash: Hash,
    maximum_bytes: u64,
) -> eyre::Result<(PathBuf, u64)> {
    let mut bundle_bytes =
        read_and_verify_cached_artifact(bundle_cache_path, expected_hash, maximum_bytes).map_err(
            |error| {
                eyre::eyre!(
                    "verify PortableVm block-device bundle {}: {}",
                    bundle_cache_path.display(),
                    error.message
                )
            },
        )?;
    if bundle_bytes.is_empty() {
        eyre::bail!("PortableVm bundle block device cannot be empty");
    }
    let exact_bytes = u64::try_from(bundle_bytes.len())
        .wrap_err("PortableVm bundle length does not fit into u64")?;
    let padded_bytes = bundle_bytes
        .len()
        .checked_add(INROU_PORTABLE_BLOCK_SECTOR_BYTES - 1)
        .ok_or_else(|| eyre::eyre!("PortableVm bundle block-device length overflow"))?
        / INROU_PORTABLE_BLOCK_SECTOR_BYTES
        * INROU_PORTABLE_BLOCK_SECTOR_BYTES;
    bundle_bytes.resize(padded_bytes, 0);
    let bundle_path = materialization_dir
        .path()
        .join(INROU_PORTABLE_BUNDLE_BLOCK_MEMBER);
    write_inrou_bytes_at(
        materialization_dir,
        OsStr::new(INROU_PORTABLE_BUNDLE_BLOCK_MEMBER),
        &bundle_bytes,
        true,
    )
    .wrap_err_with(|| format!("stage verified bundle block {}", bundle_path.display()))?;
    Ok((bundle_path, exact_bytes))
}
#[cfg(any(target_os = "linux", test))]
fn portable_vm_kernel_cmdline(profile: PortableVmGuestMachineProfile) -> String {
    format!(
        "root=LABEL={} rw rootwait rootfstype=ext4 panic=1 quiet loglevel=0",
        profile.root_label
    )
}
#[cfg(any(target_os = "linux", test))]
fn portable_vm_vcpu_count(
    resources: &iroha_data_model::soracloud::SoraResourceLimitsV1,
) -> eyre::Result<u32> {
    resources
        .validate_for_inrou()
        .map_err(|error| eyre::eyre!("invalid Inrou V1 resource contract: {error}"))?;
    let count = resources.cpu_millis.get().div_ceil(1_000).max(1);
    if count > SORA_INROU_MAX_VCPUS_V1 {
        eyre::bail!("Inrou V1 resource contract exceeds the qualified vCPU ceiling");
    }
    Ok(count)
}
#[cfg(target_os = "linux")]
fn portable_vm_memory_mib(resources: &iroha_data_model::soracloud::SoraResourceLimitsV1) -> u64 {
    debug_assert!(resources.validate_for_inrou().is_ok());
    resources.memory_bytes.get() / (1024 * 1024)
}
#[cfg(target_os = "linux")]
fn append_portable_vm_drive(
    command: &mut Command,
    profile: PortableVmGuestMachineProfile,
    drive_id: &str,
    file_path: &Path,
    format: &str,
    read_only: bool,
    discard_on_unmap: bool,
) -> eyre::Result<()> {
    append_portable_vm_drive_with_serial(
        command,
        profile,
        drive_id,
        file_path,
        format,
        read_only,
        discard_on_unmap,
        None,
    )
}
#[cfg(any(target_os = "linux", test))]
fn append_portable_vm_drive_with_serial(
    command: &mut Command,
    profile: PortableVmGuestMachineProfile,
    drive_id: &str,
    file_path: &Path,
    format: &str,
    read_only: bool,
    discard_on_unmap: bool,
    serial: Option<&str>,
) -> eyre::Result<()> {
    let file_path = qemu_option_path(file_path)?;
    let mut device = format!("{},drive={drive_id}", profile.block_device);
    if let Some(serial) = serial {
        device.push_str(",serial=");
        device.push_str(serial);
    }
    command
        .arg("-drive")
        .arg(format!(
            "if=none,id={drive_id},format={format},readonly={},discard={},file={}",
            if read_only { "on" } else { "off" },
            if discard_on_unmap { "unmap" } else { "ignore" },
            file_path,
        ))
        .arg("-device")
        .arg(device);
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn append_portable_vm_vvfat_drive(
    command: &mut Command,
    profile: PortableVmGuestMachineProfile,
    seed_root: &Path,
) -> eyre::Result<()> {
    let seed_root = qemu_option_path(seed_root)?;
    command
        .arg("-blockdev")
        .arg(format!(
            "driver=vvfat,node-name=seed,dir={seed_root},label=cidata,read-only=on"
        ))
        .arg("-device")
        .arg(format!("{},drive=seed", profile.block_device));
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn qemu_option_path(path: &Path) -> eyre::Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| eyre::eyre!("QEMU option path is not valid UTF-8: {}", path.display()))?;
    Ok(path.replace(',', ",,"))
}
fn validate_inrou_v1_network_policy(network_policy: &SoraNetworkPolicyV1) -> eyre::Result<()> {
    match network_policy {
        SoraNetworkPolicyV1::Open => {
            eyre::bail!("Inrou V1 forbids unrestricted network egress")
        }
        SoraNetworkPolicyV1::Isolated => Ok(()),
        SoraNetworkPolicyV1::Allowlist(_) => eyre::bail!(
            "Inrou V1 forbids allowlisted egress; the only release network policy is isolated"
        ),
    }
}
fn validate_inrou_runtime_topology(
    bundle: &SoraDeploymentBundleV1,
    service_name: &str,
    service_version: &str,
) -> eyre::Result<()> {
    if bundle.container.runtime != SoraContainerRuntimeV1::Inrou {
        return Ok(());
    }
    if bundle.service.execution_plane
        != iroha_data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
    {
        eyre::bail!(
            "Inrou service `{service_name}` revision `{service_version}` must use the hosted HTTP execution plane"
        );
    }
    if bundle.service.replicas.get() > SORA_HTTP_SERVICE_REPLICA_MAX_V1 {
        eyre::bail!(
            "Inrou V1 service `{service_name}` revision `{service_version}` exceeds the {SORA_HTTP_SERVICE_REPLICA_MAX_V1}-replica runtime limit"
        );
    }
    validate_inrou_v1_network_policy(&bundle.container.capabilities.network).wrap_err_with(|| {
        format!(
            "validate Inrou V1 network policy for service `{service_name}` revision `{service_version}`"
        )
    })
}
#[cfg(any(target_os = "linux", test))]
fn sanitize_host_command_environment(command: &mut Command) {
    command.env_clear();
    #[cfg(not(windows))]
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    #[cfg(windows)]
    {
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
    }
}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn build_inrou_portable_vm_command(
    namespace_plan: &inrou_namespace::InrouNamespacePlan,
    identity: &PortableVmChildIdentity,
    launch_barrier: &inrou_cgroup::InrouLaunchBarrier,
    expected_cgroup_path: &str,
) -> eyre::Result<Command> {
    require_inrou_self_exec_dispatch_armed()?;
    validate_portable_vm_child_identity_values(identity)?;
    inrou_cgroup::validate_inrou_cgroup_owner_identity(
        expected_cgroup_path,
        identity.uid,
        identity.gid,
    )?;
    let mut next_descriptor = 3;
    let mut inherited_descriptors = Vec::with_capacity(namespace_plan.binding_files().len() + 4);
    inherited_descriptors.push(duplicate_inrou_launcher_descriptor(
        launch_barrier.child_gate_reader()?,
        &mut next_descriptor,
    )?);
    inherited_descriptors.push(duplicate_inrou_launcher_descriptor(
        launch_barrier.child_ack_writer()?,
        &mut next_descriptor,
    )?);
    let supervisor = fs::File::from(
        rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .wrap_err("open the exact Inrou supervisor lifetime pidfd")?,
    );
    let cgroup_directory = inrou_cgroup::open_inrou_watchdog_directory(expected_cgroup_path)?;
    for descriptor in [&supervisor, &cgroup_directory] {
        inherited_descriptors.push(duplicate_inrou_launcher_descriptor(
            descriptor,
            &mut next_descriptor,
        )?);
    }
    for binding in namespace_plan.binding_files() {
        inherited_descriptors.push(duplicate_inrou_launcher_descriptor(
            binding,
            &mut next_descriptor,
        )?);
    }
    let gate_fd = inherited_descriptors[0].as_raw_fd();
    let acknowledgement_fd = inherited_descriptors[1].as_raw_fd();
    let supervisor_pidfd = inherited_descriptors[2].as_raw_fd();
    let cgroup_directory_fd = inherited_descriptors[3].as_raw_fd();
    let binding_fds = inherited_descriptors[4..]
        .iter()
        .map(|descriptor| descriptor.as_raw_fd())
        .collect::<Vec<_>>();
    let binding_map = namespace_plan.launcher_binding_map(&binding_fds)?;
    let namespace_arguments = namespace_plan.command_arguments(identity, &binding_fds)?;
    let mut command = Command::new("/proc/self/exe");
    sanitize_host_command_environment(&mut command);
    // SAFETY: every descriptor and bound is prevalidated in the parent. The
    // closure performs only child-local F_SETFD syscalls and constructs no
    // errors or allocations. The already-open dynamic descriptor numbers
    // reserve themselves before std creates its private spawn-error channel,
    // so no fixed-target remap can overwrite that channel or stdio.
    unsafe {
        command.pre_exec(move || {
            for descriptor in &inherited_descriptors {
                rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
                    .map_err(io::Error::from)?;
            }
            Ok(())
        });
    }
    command
        .current_dir("/")
        .arg(inrou_cgroup::INROU_INTERNAL_LAUNCHER_ARG_V1)
        .arg(gate_fd.to_string())
        .arg(acknowledgement_fd.to_string())
        .arg(expected_cgroup_path)
        .arg(supervisor_pidfd.to_string())
        .arg(cgroup_directory_fd.to_string())
        .arg(binding_map.len().to_string());
    for binding in binding_map {
        command
            .arg(if binding.writable {
                "--bind-fd"
            } else {
                "--ro-bind-fd"
            })
            .arg(binding.descriptor.to_string())
            .arg(binding.sandbox_path);
    }
    command
        .arg(namespace_plan.launcher())
        .args(namespace_arguments);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn require_inrou_self_exec_dispatch_armed() -> eyre::Result<()> {
    if !INROU_SELF_EXEC_DISPATCH_ARMED.load(AtomicOrdering::Acquire) {
        eyre::bail!(
            "Inrou V1 requires the stock iroha3d or iroha3d_taira first-instruction self-exec dispatcher; external wrapper executables are not an admitted launch path"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn duplicate_inrou_launcher_descriptor(
    source: &fs::File,
    minimum: &mut RawFd,
) -> eyre::Result<OwnedFd> {
    if *minimum < 3 {
        eyre::bail!("Inrou launcher descriptor floor overlaps stdio");
    }
    let descriptor = rustix::io::fcntl_dupfd_cloexec(source, *minimum)
        .wrap_err("duplicate retained Inrou launcher descriptor above stdio")?;
    let raw = descriptor.as_raw_fd();
    if raw < *minimum || raw <= 2 {
        eyre::bail!("kernel returned an invalid Inrou launcher descriptor");
    }
    *minimum = raw
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("Inrou launcher descriptor range overflow"))?;
    Ok(descriptor)
}
#[cfg(any(target_os = "linux", test))]
fn append_inrou_startup_probe_qemu_args(
    command: &mut Command,
    guest_isa: SoraInrouGuestIsaV1,
    netdev: &str,
    probe: iroha_config::parameters::inrou_startup_probe::InrouStartupProbeShapeV1,
) {
    let profile = portable_vm_guest_machine_profile(guest_isa);
    command
        // The production machine, host CPU, vCPU, and memory-backend shape is
        // exercised without booting a kernel or attaching service artifacts.
        .arg("-object")
        .arg(format!(
            "memory-backend-ram,id=vmmem,size={}M,share=on",
            probe.memory_mib()
        ))
        .arg("-machine")
        .arg(format!(
            "{},accel=kvm,memory-backend=vmmem",
            profile.machine_type
        ))
        .arg("-cpu")
        .arg("host")
        .arg("-smp")
        .arg(probe.vcpus().to_string())
        .arg("-S")
        .arg("-nodefaults")
        .arg("-display")
        .arg("none")
        .arg("-monitor")
        .arg("none")
        .arg("-netdev")
        .arg(netdev);
}
#[cfg(target_os = "linux")]
fn configure_inrou_qmp_stdio(command: &mut Command) -> io::Result<UnixStream> {
    let (supervisor, child) = UnixStream::pair()?;
    let child_output = child.try_clone()?;
    command
        .arg("-qmp")
        .arg("stdio")
        .arg("-serial")
        .arg("none")
        .stdin(Stdio::from(OwnedFd::from(child)))
        .stdout(Stdio::from(OwnedFd::from(child_output)));
    Ok(supervisor)
}
#[cfg(any(target_os = "linux", all(test, unix)))]
fn finish_inrou_startup_probe_stderr_bounded(
    drain: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
    cancellation: &std::os::unix::net::UnixStream,
) -> eyre::Result<(Vec<u8>, bool)> {
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT;
    while !drain.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !drain.is_finished() {
        // A failed cgroup cleanup may leave a descendant holding stderr open.
        // Cancel its anonymous read endpoint so this probe cannot leave a
        // permanently blocked drain thread behind, even without peer EOF.
        cancellation
            .shutdown(Shutdown::Read)
            .wrap_err("cancel unfinished Inrou startup-probe stderr capture")?;
    }
    finish_inrou_stdout_drain_bounded(drain)
}
#[cfg(any(target_os = "linux", test))]
fn require_inrou_launcher_running(child: &mut std::process::Child) -> eyre::Result<()> {
    if let Some(status) = child
        .try_wait()
        .wrap_err("poll the Inrou namespace launcher")?
    {
        eyre::bail!("Inrou namespace launcher exited before QMP attestation with status {status}");
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn inrou_startup_probe_stderr_context(diagnostics: &eyre::Result<(Vec<u8>, bool)>) -> String {
    match diagnostics {
        Ok((bytes, truncated)) => {
            // Keep a single readable diagnostic line; never emit terminal controls.
            let text = String::from_utf8_lossy(bytes)
                .chars()
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect::<String>();
            let text = text.trim();
            format!(
                "Inrou startup-probe diagnostics: {}{}",
                if text.is_empty() {
                    "(stderr was empty)"
                } else {
                    text
                },
                if *truncated {
                    " [stderr truncated at 16384 bytes]"
                } else {
                    ""
                },
            )
        }
        Err(error) => format!("Inrou startup-probe stderr capture failed: {error:#}"),
    }
}
#[cfg(any(target_os = "linux", test))]
fn drain_host_command_stdout_bounded(
    mut reader: impl io::Read,
    maximum_bytes: usize,
) -> io::Result<(Vec<u8>, bool)> {
    if maximum_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host-command stdout limit must be positive",
        ));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(maximum_bytes).map_err(|error| {
        io::Error::other(format!(
            "reserve bounded host-command stdout buffer: {error}"
        ))
    })?;
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let retained = maximum_bytes.saturating_sub(output.len()).min(read);
        output.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    Ok((output, truncated))
}
#[cfg(any(target_os = "linux", test))]
fn run_host_command_capture_stdout_bounded(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    maximum_stdout_bytes: usize,
) -> eyre::Result<Vec<u8>> {
    let (status, output) = run_host_command_capture_stdout_status_bounded(
        program,
        args,
        timeout,
        maximum_stdout_bytes,
    )?;
    if !status.success() {
        eyre::bail!(
            "{} {} failed with status {}",
            program.display(),
            args.join(" "),
            status,
        );
    }
    Ok(output)
}
#[cfg(any(target_os = "linux", test))]
fn run_host_command_capture_stdout_status_bounded(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    maximum_stdout_bytes: usize,
) -> eyre::Result<(std::process::ExitStatus, Vec<u8>)> {
    if timeout.is_zero() {
        eyre::bail!("host-command execution deadline must be positive");
    }
    let mut command = Command::new(program);
    sanitize_host_command_environment(&mut command);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .wrap_err_with(|| format!("spawn {} {}", program.display(), args.join(" ")))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let termination = terminate_inrou_child_bounded(&mut child);
            eyre::bail!(
                "stdout pipe was not available for {} {}{}",
                program.display(),
                args.join(" "),
                inrou_termination_error_suffix(&termination),
            );
        }
    };
    let drain = match thread::Builder::new()
        .name("inrou-host-command-stdout".to_owned())
        .spawn(move || drain_host_command_stdout_bounded(stdout, maximum_stdout_bytes))
    {
        Ok(drain) => drain,
        Err(error) => {
            let termination = terminate_inrou_child_bounded(&mut child);
            return Err(error).wrap_err_with(|| {
                format!(
                    "spawn bounded host-command stdout drain{}",
                    inrou_termination_error_suffix(&termination)
                )
            });
        }
    };
    let started_at = std::time::Instant::now();
    let status = loop {
        let poll = match child.try_wait() {
            Ok(poll) => poll,
            Err(error) => {
                let termination = terminate_inrou_child_bounded(&mut child);
                finish_inrou_stdout_drain_bounded(drain).ok();
                return Err(error).wrap_err_with(|| {
                    format!(
                        "poll {} {}{}",
                        program.display(),
                        args.join(" "),
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        match poll {
            Some(status) => break status,
            None if started_at.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            None => {
                let termination = terminate_inrou_child_bounded(&mut child);
                finish_inrou_stdout_drain_bounded(drain).ok();
                eyre::bail!(
                    "{} {} exceeded its {:?} execution deadline{}",
                    program.display(),
                    args.join(" "),
                    timeout,
                    inrou_termination_error_suffix(&termination),
                );
            }
        }
    };
    let (output, truncated) = finish_inrou_stdout_drain_bounded(drain)?;
    if truncated {
        eyre::bail!(
            "{} {} exceeded the {maximum_stdout_bytes}-byte stdout limit",
            program.display(),
            args.join(" "),
        );
    }
    Ok((status, output))
}
#[cfg(any(target_os = "linux", test))]
fn finish_inrou_stdout_drain_bounded(
    drain: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
) -> eyre::Result<(Vec<u8>, bool)> {
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT;
    while !drain.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !drain.is_finished() {
        eyre::bail!(
            "host-command stdout drain did not stop within {:?}",
            SORACLOUD_INROU_LOG_DRAIN_STOP_TIMEOUT
        );
    }
    drain
        .join()
        .map_err(|_| eyre::eyre!("host-command stdout drain panicked"))?
        .wrap_err("drain bounded host-command stdout")
}
#[cfg(all(test, not(windows)))]
fn run_host_command(program: &Path, args: &[&str]) -> eyre::Result<()> {
    run_host_command_with_timeout(program, args, Duration::from_secs(10 * 60))
}
#[cfg(all(test, not(windows)))]
fn run_host_command_with_timeout(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> eyre::Result<()> {
    let mut command = Command::new(program);
    sanitize_host_command_environment(&mut command);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .wrap_err_with(|| format!("spawn {} {}", program.display(), args.join(" ")))?;
    let started_at = std::time::Instant::now();
    loop {
        let poll = match child.try_wait() {
            Ok(poll) => poll,
            Err(error) => {
                let termination = terminate_inrou_child_bounded(&mut child);
                return Err(error).wrap_err_with(|| {
                    format!(
                        "poll {} {}{}",
                        program.display(),
                        args.join(" "),
                        inrou_termination_error_suffix(&termination)
                    )
                });
            }
        };
        match poll {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                eyre::bail!(
                    "{} {} failed with status {}",
                    program.display(),
                    args.join(" "),
                    status,
                );
            }
            None if started_at.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(25));
            }
            None => {
                let termination = terminate_inrou_child_bounded(&mut child);
                eyre::bail!(
                    "{} {} exceeded its {:?} execution deadline{}",
                    program.display(),
                    args.join(" "),
                    timeout,
                    inrou_termination_error_suffix(&termination),
                );
            }
        }
    }
}
#[cfg(any(target_os = "linux", test))]
fn build_inrou_portable_network_config() -> String {
    String::from(concat!(
        "version: 2\n",
        "ethernets:\n",
        "  inrou0:\n",
        "    match:\n",
        "      name: \"e*\"\n",
        "    dhcp4: true\n",
        "    dhcp6: false\n"
    ))
}
#[cfg(any(target_os = "linux", test))]
fn build_inrou_user_data(
    _plan: &SoracloudRuntimeServicePlan,
    cache_key: &HostedHttpWorkerCacheKey,
    guest_port: u16,
    resources: &SoraResourceLimitsV1,
    data_volume_mounts: &[InrouDataVolumeMount],
    stop_grace: Duration,
    allowlist_hosts_overlay: Option<&str>,
    portable_bundle: Option<PortableVmBundleBinding>,
) -> eyre::Result<String> {
    (*resources)
        .validate_for_inrou()
        .map_err(|error| eyre::eyre!("invalid exact Inrou V1 guest resource limits: {error}"))?;
    for mount in data_volume_mounts {
        validate_inrou_guest_data_mount_path(&mount.mount_path)?;
    }
    let volume_systemd_artifacts = data_volume_mounts
        .iter()
        .map(build_inrou_volume_systemd_artifacts)
        .collect::<eyre::Result<Vec<_>>>()?;
    if let Some(bundle) = portable_bundle {
        if bundle.exact_bytes == 0 {
            eyre::bail!("PortableVm bundle exact byte length must be positive");
        }
        if bundle.exact_bytes > bundle.maximum_bytes {
            eyre::bail!(
                "PortableVm bundle exact byte length {} exceeds its {}-byte bound",
                bundle.exact_bytes,
                bundle.maximum_bytes
            );
        }
    }
    let mut prepare_script = String::from("#!/bin/sh\nset -eu\numask 077\n");
    prepare_script.push_str(
        "if [ -L /var/lib/soracloud/materialization ]; then\n\
           echo 'Inrou materialization root must not be a symbolic link' >&2\n\
           exit 1\n\
         fi\n\
         mkdir -p -- /var/lib/soracloud/materialization\n\
         chown root:root -- /var/lib/soracloud/materialization\n\
         chmod 0755 -- /var/lib/soracloud/materialization\n\
         if [ -L /var/lib/soracloud/service ]; then\n\
           echo 'Inrou service state root must not be a symbolic link' >&2\n\
           exit 1\n\
         fi\n\
         mkdir -p -- /var/lib/soracloud/service\n\
         chown inrou:inrou -- /var/lib/soracloud/service\n\
         chmod 0750 -- /var/lib/soracloud/service\n\
         if [ -L /var/lib/soracloud/volumes ]; then\n\
           echo 'Inrou data-volume root must not be a symbolic link' >&2\n\
           exit 1\n\
         fi\n\
         mkdir -p -- /var/lib/soracloud/volumes\n\
         chown root:root -- /var/lib/soracloud/volumes\n\
         chmod 0755 -- /var/lib/soracloud/volumes\n",
    );
    prepare_script.push_str("hardening_marker=");
    prepare_script.push_str(&shell_single_quote(INROU_GUEST_HARDENING_MARKER_PATH));
    prepare_script.push('\n');
    prepare_script.push_str("rm -f -- \"$hardening_marker\"\n");
    prepare_script.push_str(
        "root_shadow_entry=$(getent shadow root 2>/dev/null || true)\n\
         if [ -z \"$root_shadow_entry\" ]; then\n\
           echo 'Inrou guest root shadow entry is unavailable' >&2\n\
           exit 1\n\
         fi\n\
         root_password_hash=${root_shadow_entry#*:}\n\
         root_password_hash=${root_password_hash%%:*}\n\
         case \"$root_password_hash\" in\n\
           '!'*|'*'*) ;;\n\
           *)\n\
             echo 'Inrou guest root password must remain locked' >&2\n\
             exit 1\n\
             ;;\n\
         esac\n\
         root_passwd_entry=$(getent passwd root 2>/dev/null || true)\n\
         root_shell=${root_passwd_entry##*:}\n\
         if [ -z \"$root_passwd_entry\" ] || [ \"$root_shell\" != '/usr/sbin/nologin' ]; then\n\
           echo 'Inrou guest root shell must be /usr/sbin/nologin' >&2\n\
           exit 1\n\
         fi\n\
         for unit in ssh.service ssh.socket sshd.service sshd.socket; do\n\
           mask_path=/etc/systemd/system/$unit\n\
           if [ ! -L \"$mask_path\" ] || [ \"$(readlink -f -- \"$mask_path\" 2>/dev/null || true)\" != '/dev/null' ]; then\n\
             echo \"Inrou guest SSH unit is not masked: $unit\" >&2\n\
             exit 1\n\
           fi\n\
           if systemctl --quiet is-active \"$unit\"; then\n\
             echo \"Inrou guest SSH unit is active despite its mask: $unit\" >&2\n\
             exit 1\n\
           fi\n\
         done\n",
    );
    prepare_script.push_str("hardening_tmp=$(mktemp \"$hardening_marker.XXXXXX\")\n");
    prepare_script.push_str("cleanup_hardening_marker() {\n");
    prepare_script.push_str("  cleanup_status=$?\n");
    prepare_script.push_str("  trap - EXIT HUP INT TERM\n");
    prepare_script.push_str(
        "  [ -z \"$hardening_tmp\" ] || rm -f -- \"$hardening_tmp\" 2>/dev/null || true\n",
    );
    prepare_script.push_str("  exit \"$cleanup_status\"\n");
    prepare_script.push_str("}\n");
    prepare_script.push_str("trap cleanup_hardening_marker EXIT\n");
    prepare_script.push_str("trap 'exit 129' HUP\n");
    prepare_script.push_str("trap 'exit 130' INT\n");
    prepare_script.push_str("trap 'exit 143' TERM\n");
    prepare_script.push_str("printf '%s' ");
    prepare_script.push_str(&shell_single_quote(INROU_GUEST_HARDENING_MARKER_BODY));
    prepare_script.push_str(" > \"$hardening_tmp\"\n");
    prepare_script.push_str("chown root:root -- \"$hardening_tmp\"\n");
    prepare_script.push_str("chmod 0444 -- \"$hardening_tmp\"\n");
    prepare_script.push_str("mv -- \"$hardening_tmp\" \"$hardening_marker\"\n");
    prepare_script.push_str("hardening_tmp=''\n");
    prepare_script.push_str("trap - EXIT HUP INT TERM\n");
    if let Some(bundle) = portable_bundle {
        let relative_entrypoint =
            canonical_inrou_bundle_member_components(&cache_key.entrypoint)?.join("/");
        let guest_entrypoint = format!(
            "{}/{}",
            INROU_PORTABLE_BUNDLE_GUEST_ROOT, relative_entrypoint
        );
        prepare_script.push_str("bundle_root=");
        prepare_script.push_str(&shell_single_quote(INROU_PORTABLE_BUNDLE_GUEST_ROOT));
        prepare_script.push('\n');
        prepare_script.push_str("bundle_entrypoint=");
        prepare_script.push_str(&shell_single_quote(&guest_entrypoint));
        prepare_script.push('\n');
        prepare_script.push_str("bundle_entrypoint_relative=");
        prepare_script.push_str(&shell_single_quote(&relative_entrypoint));
        prepare_script.push('\n');
        prepare_script.push_str("bundle_expected_hash=");
        prepare_script.push_str(&shell_single_quote(&bundle.expected_hash.to_string()));
        prepare_script.push('\n');
        prepare_script.push_str("bundle_exact_bytes=");
        prepare_script.push_str(&shell_single_quote(&bundle.exact_bytes.to_string()));
        prepare_script.push('\n');
        prepare_script.push_str("bundle_max_bytes=");
        prepare_script.push_str(&shell_single_quote(&bundle.maximum_bytes.to_string()));
        prepare_script.push('\n');
        prepare_script.push_str("if ! command -v python3 >/dev/null 2>&1; then\n");
        prepare_script.push_str(
            "  echo 'Inrou PortableVm bundle materialization requires python3 in the guest image' >&2\n",
        );
        prepare_script.push_str("  exit 1\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("if ! command -v tar >/dev/null 2>&1; then\n");
        prepare_script.push_str(
            "  echo 'Inrou PortableVm bundle materialization requires tar in the guest image' >&2\n",
        );
        prepare_script.push_str("  exit 1\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("bundle_device=");
        prepare_script.push_str(&shell_single_quote(&format!(
            "/dev/disk/by-id/virtio-{INROU_PORTABLE_BUNDLE_DEVICE_SERIAL}"
        )));
        prepare_script.push('\n');
        prepare_script.push_str("attempt=0\n");
        prepare_script
            .push_str("while [ ! -b \"$bundle_device\" ] && [ \"$attempt\" -lt 50 ]; do\n");
        prepare_script.push_str("  attempt=$((attempt + 1))\n");
        prepare_script.push_str("  sleep 0.2\n");
        prepare_script.push_str("done\n");
        prepare_script.push_str("if [ ! -b \"$bundle_device\" ]; then\n");
        prepare_script.push_str(
            "  echo \"Inrou PortableVm bundle block device not found: $bundle_device\" >&2\n",
        );
        prepare_script.push_str("  exit 1\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("bundle_orphan=''\n");
        prepare_script
            .push_str("for candidate in /var/lib/soracloud/materialization/.bundle-backup.*; do\n");
        prepare_script.push_str(
            "  if [ ! -e \"$candidate\" ] && [ ! -L \"$candidate\" ]; then continue; fi\n",
        );
        prepare_script.push_str("  if [ -n \"$bundle_orphan\" ]; then\n");
        prepare_script.push_str(
            "    echo 'multiple interrupted PortableVm bundle backups require operator recovery' >&2\n",
        );
        prepare_script.push_str("    exit 1\n");
        prepare_script.push_str("  fi\n");
        prepare_script.push_str("  if [ ! -d \"$candidate\" ] || [ -L \"$candidate\" ]; then\n");
        prepare_script
            .push_str("    echo 'PortableVm bundle recovery backup is not a real directory' >&2\n");
        prepare_script.push_str("    exit 1\n");
        prepare_script.push_str("  fi\n");
        prepare_script.push_str("  bundle_orphan=$candidate\n");
        prepare_script.push_str("done\n");
        prepare_script.push_str("if [ -n \"$bundle_orphan\" ]; then\n");
        prepare_script.push_str("  if [ -e \"$bundle_root\" ] || [ -L \"$bundle_root\" ]; then\n");
        prepare_script.push_str(
            "    echo 'PortableVm bundle has both a live root and an interrupted recovery backup' >&2\n",
        );
        prepare_script.push_str("    exit 1\n");
        prepare_script.push_str("  fi\n");
        prepare_script.push_str("  mv -- \"$bundle_orphan\" \"$bundle_root\"\n");
        prepare_script.push_str("fi\n");
        prepare_script
            .push_str("bundle_tmp=$(mktemp /run/inrou-prepare/soracloud-bundle.XXXXXX.tgz)\n");
        prepare_script.push_str(
            "bundle_stage=$(mktemp -d /var/lib/soracloud/materialization/.bundle-stage.XXXXXX)\n",
        );
        prepare_script.push_str("bundle_backup=''\n");
        prepare_script.push_str("cleanup_bundle_materialization() {\n");
        prepare_script.push_str("  cleanup_status=$?\n");
        prepare_script.push_str("  trap - EXIT HUP INT TERM\n");
        prepare_script.push_str(
            "  if [ -n \"$bundle_backup\" ] && [ ! -e \"$bundle_root\" ] && [ ! -L \"$bundle_root\" ]; then\n",
        );
        prepare_script.push_str(
            "    if mv -- \"$bundle_backup\" \"$bundle_root\"; then bundle_backup=''; else echo 'failed to restore the previous PortableVm bundle; preserving recovery backup' >&2; fi\n",
        );
        prepare_script.push_str("  fi\n");
        prepare_script
            .push_str("  [ -z \"$bundle_tmp\" ] || rm -f -- \"$bundle_tmp\" 2>/dev/null || true\n");
        prepare_script.push_str(
            "  [ -z \"$bundle_stage\" ] || rm -rf -- \"$bundle_stage\" 2>/dev/null || true\n",
        );
        prepare_script.push_str("  exit \"$cleanup_status\"\n");
        prepare_script.push_str("}\n");
        prepare_script.push_str("trap cleanup_bundle_materialization EXIT\n");
        prepare_script.push_str("trap 'exit 129' HUP\n");
        prepare_script.push_str("trap 'exit 130' INT\n");
        prepare_script.push_str("trap 'exit 143' TERM\n");
        prepare_script.push_str(
            "python3 - \"$bundle_device\" \"$bundle_tmp\" \"$bundle_expected_hash\" \"$bundle_exact_bytes\" \"$bundle_max_bytes\" <<'PY'\n",
        );
        prepare_script.push_str("import hashlib\n");
        prepare_script.push_str("import sys\n");
        prepare_script
            .push_str("source, dest, expected_hash = sys.argv[1], sys.argv[2], sys.argv[3]\n");
        prepare_script.push_str("exact_bytes = int(sys.argv[4])\n");
        prepare_script.push_str("maximum_bytes = int(sys.argv[5])\n");
        prepare_script.push_str("if exact_bytes <= 0 or exact_bytes > maximum_bytes:\n");
        prepare_script
            .push_str("    raise RuntimeError('PortableVm bundle length binding is invalid')\n");
        prepare_script.push_str("hasher = hashlib.blake2b(digest_size=32)\n");
        prepare_script.push_str("total = 0\n");
        prepare_script.push_str("remaining = exact_bytes\n");
        prepare_script.push_str("with open(source, 'rb', buffering=0) as source_handle:\n");
        prepare_script.push_str("    with open(dest, 'wb') as handle:\n");
        prepare_script.push_str("        while remaining:\n");
        prepare_script.push_str("            chunk = source_handle.read(min(65536, remaining))\n");
        prepare_script.push_str("            if not chunk:\n");
        prepare_script.push_str(
            "                raise RuntimeError('PortableVm bundle block device ended before its authenticated length')\n",
        );
        prepare_script.push_str("            total += len(chunk)\n");
        prepare_script.push_str("            remaining -= len(chunk)\n");
        prepare_script.push_str("            hasher.update(chunk)\n");
        prepare_script.push_str("            handle.write(chunk)\n");
        prepare_script.push_str("if total != exact_bytes:\n");
        prepare_script.push_str(
            "    raise RuntimeError('PortableVm bundle block-device length verification failed')\n",
        );
        prepare_script.push_str("digest = bytearray(hasher.digest())\n");
        prepare_script.push_str("digest[-1] |= 1\n");
        prepare_script.push_str("if digest.hex() != expected_hash:\n");
        prepare_script
            .push_str("    raise RuntimeError('PortableVm bundle hash verification failed')\n");
        prepare_script.push_str("PY\n");
        prepare_script.push_str("tar -xzf \"$bundle_tmp\" -C \"$bundle_stage\"\n");
        prepare_script.push_str("stage_entrypoint=\"$bundle_stage/$bundle_entrypoint_relative\"\n");
        prepare_script.push_str("if [ ! -x \"$stage_entrypoint\" ]; then\n");
        prepare_script.push_str(
            "  echo 'verified PortableVm bundle does not contain an executable entrypoint' >&2\n",
        );
        prepare_script.push_str("  exit 1\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("chown -R root:root -- \"$bundle_stage\"\n");
        prepare_script.push_str("chmod -R a+rX,go-w,u-s,g-s -- \"$bundle_stage\"\n");
        prepare_script.push_str("if [ -e \"$bundle_root\" ] || [ -L \"$bundle_root\" ]; then\n");
        prepare_script.push_str(
            "  bundle_backup=$(mktemp -d /var/lib/soracloud/materialization/.bundle-backup.XXXXXX)\n",
        );
        prepare_script.push_str("  rmdir \"$bundle_backup\"\n");
        prepare_script.push_str("  mv -- \"$bundle_root\" \"$bundle_backup\"\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("if ! mv -- \"$bundle_stage\" \"$bundle_root\"; then\n");
        prepare_script
            .push_str("  [ -z \"$bundle_backup\" ] || mv -- \"$bundle_backup\" \"$bundle_root\"\n");
        prepare_script.push_str("  bundle_backup=''\n");
        prepare_script.push_str("  exit 1\n");
        prepare_script.push_str("fi\n");
        prepare_script.push_str("bundle_stage=''\n");
        prepare_script.push_str("[ -z \"$bundle_backup\" ] || rm -rf -- \"$bundle_backup\"\n");
        prepare_script.push_str("bundle_backup=''\n");
        prepare_script.push_str("rm -f -- \"$bundle_tmp\"\n");
        prepare_script.push_str("bundle_tmp=''\n");
        prepare_script.push_str("trap - EXIT HUP INT TERM\n");
    }
    if allowlist_hosts_overlay.is_some() {
        prepare_script.push_str("if [ -f /etc/soracloud/allowlist-hosts ]; then\n");
        prepare_script
            .push_str("  hosts_tmp=$(mktemp /run/inrou-prepare/soracloud-hosts.XXXXXX)\n");
        prepare_script.push_str("  cleanup_hosts_overlay() {\n");
        prepare_script.push_str("    cleanup_status=$?\n");
        prepare_script.push_str("    trap - EXIT HUP INT TERM\n");
        prepare_script
            .push_str("    [ -z \"$hosts_tmp\" ] || rm -f -- \"$hosts_tmp\" 2>/dev/null || true\n");
        prepare_script.push_str("    exit \"$cleanup_status\"\n");
        prepare_script.push_str("  }\n");
        prepare_script.push_str("  trap cleanup_hosts_overlay EXIT\n");
        prepare_script.push_str("  trap 'exit 129' HUP\n");
        prepare_script.push_str("  trap 'exit 130' INT\n");
        prepare_script.push_str("  trap 'exit 143' TERM\n");
        prepare_script.push_str("  cp -- /etc/hosts \"$hosts_tmp\"\n");
        prepare_script.push_str(
            "  while IFS= read -r line; do grep -qxF \"$line\" \"$hosts_tmp\" || echo \"$line\" >> \"$hosts_tmp\"; done < /etc/soracloud/allowlist-hosts\n",
        );
        prepare_script.push_str("  cat -- \"$hosts_tmp\" > /etc/hosts\n");
        prepare_script.push_str("  rm -f -- \"$hosts_tmp\"\n");
        prepare_script.push_str("  hosts_tmp=''\n");
        prepare_script.push_str("  trap - EXIT HUP INT TERM\n");
        prepare_script.push_str("fi\n");
    }
    if !data_volume_mounts.is_empty() {
        for mount in data_volume_mounts {
            prepare_script.push_str("mount_path=");
            prepare_script.push_str(&shell_single_quote(&mount.mount_path));
            prepare_script.push('\n');
            prepare_script.push_str("if [ -L \"$mount_path\" ]; then\n");
            prepare_script.push_str(
                "  echo \"Inrou volume mount path must not be a symbolic link: $mount_path\" >&2\n",
            );
            prepare_script.push_str("  exit 1\n");
            prepare_script.push_str("fi\n");
            prepare_script.push_str("if ! mkdir -p \"$mount_path\"; then\n");
            prepare_script
                .push_str("  echo \"Inrou volume mount path is unavailable: $mount_path\" >&2\n");
            prepare_script.push_str("  exit 1\n");
            prepare_script.push_str("fi\n");
            prepare_script.push_str("if ! command -v mountpoint >/dev/null 2>&1; then\n");
            prepare_script.push_str(
                "  echo 'Inrou PortableVm block volumes require mountpoint in the guest image' >&2\n",
            );
            prepare_script.push_str("  exit 1\n");
            prepare_script.push_str("fi\n");
            prepare_script.push_str("if mountpoint -q \"$mount_path\"; then\n");
            prepare_script.push_str(
                "  echo \"Inrou volume mount path must not be pre-mounted: $mount_path\" >&2\n",
            );
            prepare_script.push_str("  exit 1\n");
            prepare_script.push_str("fi\n");
            match &mount.kind {
                InrouDataVolumeMountKind::BlockDevice {
                    device_serial,
                    filesystem_type,
                    filesystem_uuid,
                    mount_options: _,
                    initialize_filesystem,
                } => {
                    prepare_script.push_str("mount_path=");
                    prepare_script.push_str(&shell_single_quote(&mount.mount_path));
                    prepare_script.push('\n');
                    prepare_script.push_str("device_path=");
                    prepare_script.push_str(&shell_single_quote(&format!(
                        "/dev/disk/by-id/virtio-{device_serial}"
                    )));
                    prepare_script.push('\n');
                    prepare_script.push_str("attempt=0\n");
                    prepare_script.push_str(
                        "while [ ! -b \"$device_path\" ] && [ \"$attempt\" -lt 50 ]; do\n",
                    );
                    prepare_script.push_str("  attempt=$((attempt + 1))\n");
                    prepare_script.push_str("  sleep 0.2\n");
                    prepare_script.push_str("done\n");
                    prepare_script.push_str("if [ ! -b \"$device_path\" ]; then\n");
                    prepare_script.push_str(
                        "  echo \"Inrou PortableVm volume device not found: $device_path\" >&2\n",
                    );
                    prepare_script.push_str("  exit 1\n");
                    prepare_script.push_str("fi\n");
                    prepare_script
                        .push_str("for required_tool in blkid mountpoint readlink stat; do\n");
                    prepare_script
                        .push_str("  if ! command -v \"$required_tool\" >/dev/null 2>&1; then\n");
                    prepare_script.push_str(
                        "    echo \"Inrou PortableVm block volumes require $required_tool in the guest image\" >&2\n",
                    );
                    prepare_script.push_str("    exit 1\n");
                    prepare_script.push_str("  fi\n");
                    prepare_script.push_str("done\n");
                    prepare_script.push_str("expected_device=$(readlink -f -- \"$device_path\")\n");
                    prepare_script.push_str("if [ ! -b \"$expected_device\" ]; then\n");
                    prepare_script.push_str(
                        "  echo \"Inrou PortableVm volume device identity is unavailable: $device_path\" >&2\n",
                    );
                    prepare_script.push_str("  exit 1\n");
                    prepare_script.push_str("fi\n");
                    prepare_script.push_str("expected_filesystem=");
                    prepare_script.push_str(&shell_single_quote(filesystem_type));
                    prepare_script.push('\n');
                    prepare_script.push_str("expected_uuid=");
                    prepare_script.push_str(&shell_single_quote(filesystem_uuid));
                    prepare_script.push('\n');
                    if *initialize_filesystem {
                        prepare_script
                            .push_str("if ! command -v mkfs.ext4 >/dev/null 2>&1; then\n");
                        prepare_script.push_str(
                            "  echo 'Inrou PortableVm block-volume initialization requires mkfs.ext4 in the guest image' >&2\n",
                        );
                        prepare_script.push_str("  exit 1\n");
                        prepare_script.push_str("fi\n");
                        prepare_script.push_str("blkid_status=0\n");
                        prepare_script.push_str(
                            "blkid -p \"$expected_device\" >/dev/null 2>&1 || blkid_status=$?\n",
                        );
                        prepare_script.push_str("case \"$blkid_status\" in\n");
                        prepare_script.push_str("  0)\n");
                        prepare_script.push_str(
                            "    existing_filesystem=$(blkid -s TYPE -o value \"$expected_device\" 2>/dev/null || true)\n",
                        );
                        prepare_script.push_str(
                            "    existing_uuid=$(blkid -s UUID -o value \"$expected_device\" 2>/dev/null || true)\n",
                        );
                        prepare_script.push_str(
                            "    if [ \"$existing_filesystem\" != \"$expected_filesystem\" ] || [ \"$existing_uuid\" != \"$expected_uuid\" ]; then\n",
                        );
                        prepare_script.push_str(
                            "      echo \"new Inrou PortableVm volume contains an unexpected filesystem identity: $device_path\" >&2\n",
                        );
                        prepare_script.push_str("      exit 1\n");
                        prepare_script.push_str("    fi\n");
                        prepare_script.push_str("    ;;\n");
                        prepare_script.push_str("  2)\n");
                        prepare_script.push_str(
                            "    mkfs.ext4 -F -E nodiscard -U \"$expected_uuid\" \"$expected_device\"\n",
                        );
                        prepare_script.push_str("    ;;\n");
                        prepare_script.push_str("  *)\n");
                        prepare_script.push_str(
                            "    echo \"unable to classify new Inrou PortableVm volume: $device_path\" >&2\n",
                        );
                        prepare_script.push_str("    exit 1\n");
                        prepare_script.push_str("    ;;\n");
                        prepare_script.push_str("esac\n");
                    }
                    prepare_script.push_str("actual_filesystem=$(blkid -s TYPE -o value \"$expected_device\" 2>/dev/null || true)\n");
                    prepare_script.push_str("actual_uuid=$(blkid -s UUID -o value \"$expected_device\" 2>/dev/null || true)\n");
                    prepare_script.push_str("if [ \"$actual_filesystem\" != \"$expected_filesystem\" ] || [ \"$actual_uuid\" != \"$expected_uuid\" ]; then\n");
                    prepare_script.push_str(
                        "  echo \"Inrou PortableVm volume has missing or unexpected filesystem identity: $device_path\" >&2\n",
                    );
                    prepare_script.push_str("  exit 1\n");
                    prepare_script.push_str("fi\n");
                }
            }
            prepare_script.push_str("chown root:root -- \"$mount_path\"\n");
            prepare_script.push_str("chmod 0700 -- \"$mount_path\"\n");
            prepare_script.push_str("mountpoint_owner=$(stat -c '%u:%g' -- \"$mount_path\")\n");
            prepare_script.push_str("mountpoint_mode=$(stat -c '%a' -- \"$mount_path\")\n");
            prepare_script.push_str(
                "if [ \"$mountpoint_owner\" != '0:0' ] || [ \"$mountpoint_mode\" != '700' ]; then\n",
            );
            prepare_script.push_str(
                "  echo \"Inrou PortableVm mountpoint custody attestation failed: $mount_path\" >&2\n",
            );
            prepare_script.push_str("  exit 1\n");
            prepare_script.push_str("fi\n");
        }
    }
    let mut launcher_script = String::from("#!/bin/sh\nset -eu\n");
    for (key, value) in &cache_key.effective_env {
        launcher_script.push_str("export ");
        launcher_script.push_str(key);
        launcher_script.push('=');
        launcher_script.push_str(&shell_single_quote(value));
        launcher_script.push('\n');
    }
    launcher_script.push_str("export PORT=");
    launcher_script.push_str(&shell_single_quote(&guest_port.to_string()));
    launcher_script.push('\n');
    launcher_script.push_str("mkdir -p -- /var/lib/soracloud/service/tmp\n");
    launcher_script.push_str("chmod 0700 -- /var/lib/soracloud/service/tmp\n");
    launcher_script.push_str("export TMPDIR=/var/lib/soracloud/service/tmp\n");
    launcher_script.push_str("export TMP=/var/lib/soracloud/service/tmp\n");
    launcher_script.push_str("export TEMP=/var/lib/soracloud/service/tmp\n");
    let launcher_entrypoint = match portable_bundle {
        Some(_) => format!(
            "{}/{}",
            INROU_PORTABLE_BUNDLE_GUEST_ROOT,
            canonical_inrou_bundle_member_components(&cache_key.entrypoint)?.join("/")
        ),
        None => cache_key.entrypoint.clone(),
    };
    launcher_script.push_str("exec ");
    launcher_script.push_str(&shell_single_quote(&launcher_entrypoint));
    for arg in &cache_key.args {
        launcher_script.push(' ');
        launcher_script.push_str(&shell_single_quote(arg));
    }
    launcher_script.push('\n');
    let mut prepare_unit = String::new();
    prepare_unit.push_str("[Unit]\n");
    prepare_unit.push_str("Description=Prepare Soracloud Inrou service custody\n");
    prepare_unit.push_str("After=network-online.target\n");
    prepare_unit.push_str("Wants=network-online.target\n");
    prepare_unit.push_str("Before=inrou-app.service\n\n");
    prepare_unit.push_str("[Service]\n");
    prepare_unit.push_str("Type=oneshot\n");
    prepare_unit.push_str("User=root\n");
    prepare_unit.push_str("Group=root\n");
    prepare_unit.push_str("UMask=0077\n");
    prepare_unit.push_str("NoNewPrivileges=true\n");
    prepare_unit.push_str("LimitCORE=0\n");
    prepare_unit.push_str("CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER\n");
    prepare_unit.push_str("AmbientCapabilities=\n");
    prepare_unit.push_str("RestrictSUIDSGID=true\n");
    prepare_unit.push_str("ProtectSystem=strict\n");
    prepare_unit.push_str("RuntimeDirectory=inrou-prepare\n");
    prepare_unit.push_str("RuntimeDirectoryMode=0700\n");
    prepare_unit.push_str(
        "ReadWritePaths=/etc/hosts /run/inrou-prepare /var/lib/soracloud/materialization /var/lib/soracloud/service /var/lib/soracloud/volumes\n",
    );
    prepare_unit.push_str("ProtectHome=true\n");
    prepare_unit.push_str("ProtectKernelTunables=true\n");
    prepare_unit.push_str("ProtectKernelModules=true\n");
    prepare_unit.push_str("ProtectKernelLogs=true\n");
    prepare_unit.push_str("ProtectControlGroups=true\n");
    prepare_unit.push_str("ProtectClock=true\n");
    prepare_unit.push_str("ProtectHostname=true\n");
    prepare_unit.push_str("LockPersonality=true\n");
    prepare_unit.push_str("RestrictRealtime=true\n");
    prepare_unit.push_str("RestrictNamespaces=true\n");
    prepare_unit.push_str("RemoveIPC=true\n");
    prepare_unit.push_str("RestrictAddressFamilies=AF_UNIX\n");
    prepare_unit.push_str("StandardOutput=null\n");
    prepare_unit.push_str("StandardError=null\n");
    prepare_unit.push_str("ExecStart=/usr/local/bin/inrou-prepare.sh\n");
    prepare_unit.push_str("RemainAfterExit=yes\n");
    let mut service_unit = String::new();
    service_unit.push_str("[Unit]\n");
    service_unit.push_str("Description=Soracloud Inrou service\n");
    service_unit.push_str("Requires=inrou-prepare.service\n");
    service_unit.push_str("After=network-online.target inrou-prepare.service\n");
    service_unit.push_str("Wants=network-online.target\n");
    for (mount, artifacts) in data_volume_mounts.iter().zip(&volume_systemd_artifacts) {
        service_unit.push_str("Requires=");
        service_unit.push_str(&artifacts.mount_unit_name);
        service_unit.push(' ');
        service_unit.push_str(&artifacts.attestation_unit_name);
        service_unit.push('\n');
        service_unit.push_str("After=");
        service_unit.push_str(&artifacts.mount_unit_name);
        service_unit.push(' ');
        service_unit.push_str(&artifacts.attestation_unit_name);
        service_unit.push('\n');
        service_unit.push_str("BindsTo=");
        service_unit.push_str(&artifacts.mount_unit_name);
        service_unit.push('\n');
        service_unit.push_str("AssertPathIsMountPoint=");
        service_unit.push_str(&systemd_quote_path(&mount.mount_path));
        service_unit.push('\n');
    }
    service_unit.push('\n');
    service_unit.push_str("[Service]\n");
    service_unit.push_str("Type=simple\n");
    service_unit.push_str("User=inrou\n");
    service_unit.push_str("Group=inrou\n");
    service_unit.push_str("WorkingDirectory=/var/lib/soracloud/service\n");
    service_unit.push_str("UMask=0077\n");
    service_unit.push_str("NoNewPrivileges=true\n");
    service_unit.push_str("LimitCORE=0\n");
    service_unit.push_str("LimitNOFILE=");
    service_unit.push_str(&resources.max_open_files_per_process.get().to_string());
    service_unit.push('\n');
    service_unit.push_str("TasksMax=");
    service_unit.push_str(&resources.max_tasks.get().to_string());
    service_unit.push('\n');
    service_unit.push_str("CPUAccounting=true\n");
    service_unit.push_str("CPUQuotaPeriodSec=100ms\n");
    service_unit.push_str("CPUQuota=");
    service_unit.push_str(&(resources.cpu_millis.get() / 10).to_string());
    service_unit.push_str("%\n");
    service_unit.push_str("MemoryAccounting=true\n");
    service_unit.push_str("MemoryMax=");
    service_unit.push_str(&resources.memory_bytes.get().to_string());
    service_unit.push('\n');
    service_unit.push_str("MemorySwapMax=0\n");
    service_unit.push_str("CapabilityBoundingSet=\n");
    service_unit.push_str("AmbientCapabilities=\n");
    service_unit.push_str("RestrictSUIDSGID=true\n");
    service_unit.push_str("ProtectSystem=strict\n");
    service_unit.push_str("ProtectHome=true\n");
    service_unit.push_str("PrivateMounts=true\n");
    service_unit.push_str("PrivateDevices=true\n");
    service_unit.push_str("ProtectKernelTunables=true\n");
    service_unit.push_str("ProtectKernelModules=true\n");
    service_unit.push_str("ProtectKernelLogs=true\n");
    service_unit.push_str("ProtectControlGroups=true\n");
    service_unit.push_str("ProtectClock=true\n");
    service_unit.push_str("ProtectHostname=true\n");
    service_unit.push_str("LockPersonality=true\n");
    service_unit.push_str("RestrictRealtime=true\n");
    service_unit.push_str("RestrictNamespaces=true\n");
    service_unit.push_str("RemoveIPC=true\n");
    service_unit.push_str("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n");
    // `ProtectSystem=strict` makes the guest root hierarchy read-only, while
    // `ReadWritePaths=` reopens only the capped service tmpfs and separately
    // leased data volumes. `PrivateTmp=` must remain disabled for the tenant:
    // it would introduce independent writable /tmp and /var/tmp trees outside
    // the declared ephemeral-storage cap. Block the remaining conventional
    // memory-backed file namespaces as well; anonymous memory and memfd usage
    // remain confined by the VM memory contract.
    service_unit.push_str("ReadOnlyPaths=/var/lib/soracloud/materialization /tmp /var/tmp /run\n");
    service_unit.push_str("InaccessiblePaths=/dev/shm /dev/mqueue\n");
    service_unit.push_str(
        "TemporaryFileSystem=/var/lib/soracloud/service:rw,nosuid,nodev,noexec,mode=0700,uid=1000,gid=1000,size=",
    );
    service_unit.push_str(&resources.ephemeral_storage_bytes.get().to_string());
    service_unit.push('\n');
    service_unit.push_str("ReadWritePaths=");
    service_unit.push_str(&systemd_quote_path("/var/lib/soracloud/service"));
    for mount in data_volume_mounts {
        service_unit.push(' ');
        service_unit.push_str(&systemd_quote_path(&mount.mount_path));
    }
    service_unit.push('\n');
    service_unit.push_str("Restart=always\n");
    service_unit.push_str("RestartSec=2\n");
    service_unit.push_str("TimeoutStopSec=");
    service_unit.push_str(&stop_grace.as_millis().to_string());
    service_unit.push_str("ms\n");
    service_unit.push_str("StandardOutput=null\n");
    service_unit.push_str("StandardError=null\n");
    service_unit.push_str("ExecStart=/usr/local/bin/inrou-launch.sh\n\n");
    service_unit.push_str("[Install]\n");
    service_unit.push_str("WantedBy=multi-user.target\n");
    let mut user_data = String::from("#cloud-config\n");
    user_data.push_str("disable_root: true\n");
    user_data.push_str("ssh_pwauth: false\n");
    user_data.push_str("users:\n");
    user_data.push_str("  - name: root\n");
    user_data.push_str("    shell: /usr/sbin/nologin\n");
    user_data.push_str("    lock_passwd: true\n");
    user_data.push_str("  - name: inrou\n");
    user_data.push_str("    gecos: Inrou Tenant\n");
    user_data.push_str("    uid: 1000\n");
    user_data.push_str("    groups: []\n");
    user_data.push_str("    shell: /usr/sbin/nologin\n");
    user_data.push_str("    lock_passwd: true\n");
    user_data.push_str("write_files:\n");
    user_data.push_str("  - path: /usr/local/bin/inrou-prepare.sh\n");
    user_data.push_str("    owner: root:root\n");
    user_data.push_str("    permissions: '0755'\n");
    user_data.push_str("    content: |\n");
    user_data.push_str(&yaml_block_literal(&prepare_script, 6));
    user_data.push_str("  - path: /usr/local/bin/inrou-launch.sh\n");
    user_data.push_str("    owner: root:root\n");
    user_data.push_str("    permissions: '0755'\n");
    user_data.push_str("    content: |\n");
    user_data.push_str(&yaml_block_literal(&launcher_script, 6));
    for artifacts in &volume_systemd_artifacts {
        user_data.push_str("  - path: ");
        user_data.push_str(&artifacts.attestation_script_path);
        user_data.push('\n');
        user_data.push_str("    owner: root:root\n");
        user_data.push_str("    permissions: '0755'\n");
        user_data.push_str("    content: |\n");
        user_data.push_str(&yaml_block_literal(&artifacts.attestation_script, 6));
        user_data.push_str("  - path: /etc/systemd/system/");
        user_data.push_str(&artifacts.mount_unit_name);
        user_data.push('\n');
        user_data.push_str("    owner: root:root\n");
        user_data.push_str("    permissions: '0644'\n");
        user_data.push_str("    content: |\n");
        user_data.push_str(&yaml_block_literal(&artifacts.mount_unit, 6));
        user_data.push_str("  - path: /etc/systemd/system/");
        user_data.push_str(&artifacts.attestation_unit_name);
        user_data.push('\n');
        user_data.push_str("    owner: root:root\n");
        user_data.push_str("    permissions: '0644'\n");
        user_data.push_str("    content: |\n");
        user_data.push_str(&yaml_block_literal(&artifacts.attestation_unit, 6));
    }
    user_data.push_str("  - path: /etc/systemd/system/inrou-prepare.service\n");
    user_data.push_str("    owner: root:root\n");
    user_data.push_str("    permissions: '0644'\n");
    user_data.push_str("    content: |\n");
    user_data.push_str(&yaml_block_literal(&prepare_unit, 6));
    user_data.push_str("  - path: /etc/systemd/system/inrou-app.service\n");
    user_data.push_str("    owner: root:root\n");
    user_data.push_str("    permissions: '0644'\n");
    user_data.push_str("    content: |\n");
    user_data.push_str(&yaml_block_literal(&service_unit, 6));
    if let Some(hosts_overlay) = allowlist_hosts_overlay {
        user_data.push_str("  - path: /etc/soracloud/allowlist-hosts\n");
        user_data.push_str("    owner: root:root\n");
        user_data.push_str("    permissions: '0644'\n");
        user_data.push_str("    content: |\n");
        user_data.push_str(&yaml_block_literal(hosts_overlay, 6));
    }
    user_data.push_str("runcmd:\n");
    user_data.push_str("  - mkdir -p /var/lib/soracloud\n");
    user_data.push_str("  - chown root:root /var/lib/soracloud\n");
    user_data.push_str("  - chmod 0755 /var/lib/soracloud\n");
    user_data
        .push_str("  - install -d -o root -g root -m 0755 /var/lib/soracloud/materialization\n");
    user_data.push_str("  - install -d -o inrou -g inrou -m 0750 /var/lib/soracloud/service\n");
    user_data.push_str("  - install -d -o root -g root -m 0755 /var/lib/soracloud/volumes\n");
    user_data.push_str("  - usermod --lock --shell /usr/sbin/nologin root\n");
    user_data.push_str("  - systemctl daemon-reload\n");
    user_data
        .push_str("  - systemctl mask --now ssh.service ssh.socket sshd.service sshd.socket\n");
    user_data.push_str("  - systemctl enable --now inrou-app.service\n");
    Ok(user_data)
}
#[cfg(any(target_os = "linux", test))]
fn yaml_block_literal(contents: &str, indent: usize) -> String {
    let padding = " ".repeat(indent);
    let mut output = String::new();
    for line in contents.lines() {
        output.push_str(&padding);
        output.push_str(line);
        output.push('\n');
    }
    output
}
#[cfg(any(target_os = "linux", test))]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
#[cfg(any(target_os = "linux", test))]
fn systemd_quote_path(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len().saturating_add(2));
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}
#[cfg(any(target_os = "linux", test))]
fn systemd_escape_path(value: &str) -> eyre::Result<String> {
    if value == "/" {
        return Ok("-".to_owned());
    }
    let relative = value
        .strip_prefix('/')
        .filter(|relative| !relative.is_empty() && !relative.ends_with('/'))
        .ok_or_else(|| eyre::eyre!("systemd mount-unit path must be absolute and canonical"))?;
    let mut escaped = String::with_capacity(relative.len());
    for byte in relative.bytes() {
        match byte {
            b'/' => escaped.push('-'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b':' | b'_' | b'.' => {
                escaped.push(char::from(byte));
            }
            _ => escaped.push_str(&format!(r"\x{byte:02x}")),
        }
    }
    Ok(escaped)
}
#[cfg(any(target_os = "linux", test))]
fn is_canonical_inrou_filesystem_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value.as_bytes()[14] == b'8'
        && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}
#[cfg(any(target_os = "linux", test))]
fn build_inrou_volume_systemd_artifacts(
    mount: &InrouDataVolumeMount,
) -> eyre::Result<InrouVolumeSystemdArtifacts> {
    validate_inrou_guest_data_mount_path(&mount.mount_path)?;
    let volume_name = mount
        .mount_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| eyre::eyre!("Inrou volume mount path has no volume name"))?;
    let InrouDataVolumeMountKind::BlockDevice {
        device_serial,
        filesystem_type,
        filesystem_uuid,
        mount_options,
        ..
    } = &mount.kind;
    if filesystem_type != INROU_PORTABLE_VOLUME_FILESYSTEM {
        eyre::bail!(
            "Inrou V1 volume `{volume_name}` must use `{INROU_PORTABLE_VOLUME_FILESYSTEM}`"
        );
    }
    if mount_options != INROU_PORTABLE_VOLUME_MOUNT_OPTIONS {
        eyre::bail!("Inrou V1 volume `{volume_name}` must use the exact hardened mount options");
    }
    if !is_canonical_inrou_filesystem_uuid(filesystem_uuid) {
        eyre::bail!("Inrou V1 volume `{volume_name}` has a noncanonical filesystem UUID");
    }
    let unit_stem = systemd_escape_path(&mount.mount_path)?;
    let mount_unit_name = format!("{unit_stem}.mount");
    let attestation_unit_name = format!("{unit_stem}-inrou-attest.service");
    let attestation_script_path = format!("/usr/local/bin/inrou-volume-{volume_name}-attest.sh");
    let device_path = format!("/dev/disk/by-id/virtio-{device_serial}");

    let mount_unit = format!(
        "[Unit]\n\
         Description=Mount Soracloud Inrou volume {volume_name}\n\
         Requires=inrou-prepare.service\n\
         After=inrou-prepare.service\n\
         Before={attestation_unit_name} inrou-app.service\n\n\
         [Mount]\n\
         What={device_path}\n\
         Where={}\n\
         Type={filesystem_type}\n\
         Options={mount_options}\n\
         DirectoryMode=0700\n\
         TimeoutSec=15s\n",
        mount.mount_path,
    );
    let attestation_script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         umask 077\n\
         mount_path={}\n\
         device_path={}\n\
         expected_filesystem={}\n\
         expected_uuid={}\n\
         for required_tool in blkid findmnt mktemp mountpoint readlink stat sync; do\n\
           if ! command -v \"$required_tool\" >/dev/null 2>&1; then\n\
             echo \"Inrou volume attestation requires $required_tool\" >&2\n\
             exit 1\n\
           fi\n\
         done\n\
         if [ ! -b \"$device_path\" ] || ! mountpoint -q \"$mount_path\"; then\n\
           echo 'Inrou volume device or mount is unavailable' >&2\n\
           exit 1\n\
         fi\n\
         expected_device=$(readlink -f -- \"$device_path\")\n\
         mounted_device=$(findmnt -n -o SOURCE --target \"$mount_path\")\n\
         mounted_device=$(readlink -f -- \"$mounted_device\")\n\
         mounted_target=$(findmnt -n -o TARGET --target \"$mount_path\")\n\
         mounted_filesystem=$(findmnt -n -o FSTYPE --target \"$mount_path\")\n\
         mounted_options=$(findmnt -n -o OPTIONS --target \"$mount_path\")\n\
         expected_device_identity=$(stat -c '%t:%T' -- \"$expected_device\")\n\
         mounted_device_identity=$(stat -c '%t:%T' -- \"$mounted_device\")\n\
         mounted_uuid=$(blkid -s UUID -o value \"$mounted_device\" 2>/dev/null || true)\n\
         if [ \"$mounted_target\" != \"$mount_path\" ] || [ \"$mounted_device_identity\" != \"$expected_device_identity\" ] || [ \"$mounted_filesystem\" != \"$expected_filesystem\" ] || [ \"$mounted_uuid\" != \"$expected_uuid\" ]; then\n\
           echo 'Inrou mounted volume identity attestation failed' >&2\n\
           exit 1\n\
         fi\n\
         for required_option in rw nosuid nodev noexec nosymfollow errors=remount-ro; do\n\
           case \",$mounted_options,\" in\n\
             *\",$required_option,\"*) ;;\n\
             *) echo \"Inrou volume omits required option $required_option\" >&2; exit 1 ;;\n\
           esac\n\
         done\n\
         chown inrou:inrou -- \"$mount_path\"\n\
         chmod 0700 -- \"$mount_path\"\n\
         mounted_owner=$(stat -c '%u:%g' -- \"$mount_path\")\n\
         mounted_mode=$(stat -c '%a' -- \"$mount_path\")\n\
         if [ \"$mounted_owner\" != '1000:1000' ] || [ \"$mounted_mode\" != '700' ]; then\n\
           echo 'Inrou mounted volume custody attestation failed' >&2\n\
           exit 1\n\
         fi\n\
         probe_path=''\n\
         cleanup_probe() {{\n\
           status=$?\n\
           trap - EXIT HUP INT TERM\n\
           [ -z \"$probe_path\" ] || rm -f -- \"$probe_path\" 2>/dev/null || true\n\
           exit \"$status\"\n\
         }}\n\
         trap cleanup_probe EXIT\n\
         trap 'exit 129' HUP\n\
         trap 'exit 130' INT\n\
         trap 'exit 143' TERM\n\
         probe_path=$(mktemp \"$mount_path/.inrou-attest.XXXXXX\")\n\
         printf '%s\\n' 'inrou-volume-attestation-v1' > \"$probe_path\"\n\
         sync -f \"$probe_path\"\n\
         rm -f -- \"$probe_path\"\n\
         probe_path=''\n\
         sync -f \"$mount_path\"\n\
         trap - EXIT HUP INT TERM\n",
        shell_single_quote(&mount.mount_path),
        shell_single_quote(&device_path),
        shell_single_quote(filesystem_type),
        shell_single_quote(filesystem_uuid),
    );
    let attestation_unit = format!(
        "[Unit]\n\
         Description=Attest Soracloud Inrou volume {volume_name}\n\
         Requires={mount_unit_name}\n\
         After={mount_unit_name}\n\
         BindsTo={mount_unit_name}\n\
         Before=inrou-app.service\n\
         AssertPathIsMountPoint={}\n\n\
         [Service]\n\
         Type=oneshot\n\
         User=root\n\
         Group=root\n\
         UMask=0077\n\
         NoNewPrivileges=true\n\
         LimitCORE=0\n\
         CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER\n\
         AmbientCapabilities=\n\
         RestrictSUIDSGID=true\n\
         ProtectSystem=strict\n\
         ReadWritePaths={}\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateMounts=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectKernelLogs=true\n\
         ProtectControlGroups=true\n\
         ProtectClock=true\n\
         ProtectHostname=true\n\
         LockPersonality=true\n\
         RestrictRealtime=true\n\
         RestrictNamespaces=true\n\
         RemoveIPC=true\n\
         RestrictAddressFamilies=AF_UNIX\n\
         StandardOutput=null\n\
         StandardError=null\n\
         ExecStart={attestation_script_path}\n\
         RemainAfterExit=yes\n",
        systemd_quote_path(&mount.mount_path),
        systemd_quote_path(&mount.mount_path),
    );
    Ok(InrouVolumeSystemdArtifacts {
        mount_unit_name,
        mount_unit,
        attestation_unit_name,
        attestation_unit,
        attestation_script_path,
        attestation_script,
    })
}
fn sanitize_env_var_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_uppercase());
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "VOLUME".to_owned()
    } else {
        sanitized
    }
}
#[cfg(any(target_os = "linux", test))]
#[cfg(unix)]
fn ensure_native_bundle_extracted(
    bundle_cache_path: &Path,
    bundle_hash: Hash,
    parent: &PinnedInrouDirectory,
    root_name: &OsStr,
    entrypoint: &str,
    limits: BundleArchiveLimits,
) -> eyre::Result<PinnedInrouDirectory> {
    validate_inrou_single_component(root_name)?;
    recover_interrupted_inrou_bundle_swap(parent, root_name)?;
    let (mut archive, archive_fingerprint) = open_verified_cached_soracloud_artifact(
        bundle_cache_path,
        bundle_hash,
        limits.max_compressed_bytes,
    )
    .map_err(|error| {
        eyre::eyre!(
            "verify native Inrou bundle {}: {}",
            bundle_cache_path.display(),
            error.message
        )
    })?;
    let (staging_name, staging_root, staging_identity) =
        create_unique_inrou_materialization_directory(parent, root_name, "stage")
            .wrap_err("create private Inrou bundle staging root")?;
    let transaction_result = (|| -> eyre::Result<PinnedInrouDirectory> {
        let summary = visit_gzip_ustar(&mut archive, limits, |entry, payload| {
            materialize_inrou_bundle_entry(&staging_root, entry, payload)
        })
        .map_err(|error| {
            eyre::eyre!(
                "validate native Inrou bundle archive {}: {error}",
                bundle_cache_path.display()
            )
        })?;
        if summary.file_count() == 0 {
            eyre::bail!("native Inrou bundle archive must contain at least one regular file");
        }
        validate_opened_soracloud_artifact_after_read(
            &archive,
            bundle_cache_path,
            &archive_fingerprint,
            summary.compressed_bytes(),
        )
        .map_err(|error| {
            eyre::eyre!(
                "revalidate native Inrou bundle {} after archive decode: {}",
                bundle_cache_path.display(),
                error.message
            )
        })?;
        ensure_inrou_entrypoint_present_at(&staging_root, entrypoint)
            .wrap_err("validate staged native Inrou entrypoint")?;
        staging_root.directory.sync_all()?;
        install_staged_inrou_bundle(&staging_name, staging_identity, parent, root_name)
    })();
    if transaction_result.is_err() {
        remove_owned_inrou_materialization_directory(parent, &staging_name, staging_identity)
            .wrap_err("clean failed Inrou bundle staging root")?;
    }
    transaction_result
}
#[cfg(any(target_os = "linux", test))]
fn inrou_bundle_archive_limits(
    config: &iroha_config::parameters::actual::SoracloudRuntimeInrou,
    bundle_cache_max_bytes: u64,
) -> BundleArchiveLimits {
    BundleArchiveLimits {
        max_compressed_bytes: config
            .bundle_archive_max_compressed_bytes
            .get()
            .min(bundle_cache_max_bytes),
        max_decoded_bytes: config.bundle_archive_max_decoded_bytes.get(),
        max_entries: config.bundle_archive_max_entries.get(),
        max_file_bytes: config.bundle_archive_max_file_bytes.get(),
        max_total_file_bytes: config.bundle_archive_max_total_file_bytes.get(),
    }
}
#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InrouMaterializationDirectoryIdentity {
    device: u64,
    inode: u64,
}
#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
impl InrouMaterializationDirectoryIdentity {
    #[cfg(any(target_os = "linux", test))]
    fn from_directory(directory: &PinnedInrouDirectory) -> io::Result<Self> {
        let metadata = directory.directory.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Inrou materialization transaction path {} is not a directory",
                    directory.path().display()
                ),
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn matches_stat(self, stat: &rustix::fs::Stat) -> bool {
        stat.st_dev as u64 == self.device && stat.st_ino as u64 == self.inode
    }
}
#[cfg(target_os = "linux")]
fn read_inrou_qmp_message(
    reader: &mut io::BufReader<UnixStream>,
    deadline: std::time::Instant,
    stop: Option<&AtomicBool>,
) -> eyre::Result<norito::json::Value> {
    let mut line = Vec::new();
    loop {
        if stop.is_some_and(|stop| stop.load(AtomicOrdering::Acquire)) {
            eyre::bail!("Inrou QMP response was cancelled during bridge shutdown");
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            eyre::bail!("Inrou QMP response exceeded its absolute deadline");
        }
        reader
            .get_mut()
            .set_read_timeout(Some(remaining.min(SORACLOUD_INROU_QMP_IO_POLL)))
            .wrap_err("set bounded Inrou QMP read timeout")?;
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error).wrap_err("read Inrou QMP response"),
        };
        if available.is_empty() {
            eyre::bail!("Inrou QMP closed before a complete response");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index.saturating_add(1));
        if line.len().saturating_add(take) > SORACLOUD_INROU_QMP_MAX_MESSAGE_BYTES {
            eyre::bail!(
                "Inrou QMP response exceeded the {}-byte message limit",
                SORACLOUD_INROU_QMP_MAX_MESSAGE_BYTES
            );
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    while matches!(line.last(), Some(b'\r' | b'\n')) {
        let _ = line.pop();
    }
    norito::json::from_slice(&line).wrap_err("decode bounded Inrou QMP JSON response")
}
#[cfg(target_os = "linux")]
fn read_inrou_qmp_command_response(
    reader: &mut io::BufReader<UnixStream>,
    expected_id: &str,
    deadline: std::time::Instant,
    stop: Option<&AtomicBool>,
) -> eyre::Result<norito::json::Value> {
    for _ in 0..SORACLOUD_INROU_QMP_MAX_MESSAGES_PER_COMMAND {
        let message = read_inrou_qmp_message(reader, deadline, stop)?;
        if message.get("id").and_then(norito::json::Value::as_str) != Some(expected_id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            eyre::bail!("Inrou QMP command `{expected_id}` failed: {error:?}");
        }
        return message
            .get("return")
            .cloned()
            .ok_or_else(|| eyre::eyre!("Inrou QMP command `{expected_id}` omitted `return`"));
    }
    eyre::bail!(
        "Inrou QMP did not return command id `{expected_id}` within its bounded message window"
    )
}
#[cfg(target_os = "linux")]
fn request_inrou_qmp_system_powerdown(
    control: &mut PortableVmQmpControl,
    timeout: Duration,
) -> eyre::Result<()> {
    const COMMAND_ID: &str = "inrou-system-powerdown";
    let deadline = std::time::Instant::now() + timeout;
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        eyre::bail!("Inrou QMP system_powerdown request has no bounded execution window");
    }
    control
        .reader
        .get_mut()
        .set_write_timeout(Some(remaining.min(SORACLOUD_INROU_QMP_IO_POLL)))?;
    control
        .reader
        .get_mut()
        .write_all(b"{\"execute\":\"system_powerdown\",\"id\":\"inrou-system-powerdown\"}\n")?;
    let response =
        read_inrou_qmp_command_response(&mut control.reader, COMMAND_ID, deadline, None)?;
    if !response.is_object() {
        eyre::bail!("Inrou QMP system_powerdown response must be an empty object");
    }
    if response
        .as_object()
        .is_some_and(|response| !response.is_empty())
    {
        eyre::bail!("Inrou QMP system_powerdown response must be an empty object");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn request_inrou_qmp_quit(
    control: &mut PortableVmQmpControl,
    timeout: Duration,
) -> eyre::Result<()> {
    const COMMAND_ID: &str = "inrou-startup-probe-quit";
    let deadline = std::time::Instant::now() + timeout;
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        eyre::bail!("Inrou QMP quit request has no bounded execution window");
    }
    control
        .reader
        .get_mut()
        .set_write_timeout(Some(remaining.min(SORACLOUD_INROU_QMP_IO_POLL)))?;
    control
        .reader
        .get_mut()
        .write_all(b"{\"execute\":\"quit\",\"id\":\"inrou-startup-probe-quit\"}\n")?;
    let response =
        read_inrou_qmp_command_response(&mut control.reader, COMMAND_ID, deadline, None)?;
    if response
        .as_object()
        .is_none_or(|response| !response.is_empty())
    {
        eyre::bail!("Inrou QMP quit response must be an empty object");
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn validate_inrou_qmp_kvm_info(info: &norito::json::Value) -> eyre::Result<()> {
    let object = info
        .as_object()
        .ok_or_else(|| eyre::eyre!("Inrou QMP KVM response must be an object"))?;
    if object.len() != 2
        || object.get("enabled").and_then(norito::json::Value::as_bool) != Some(true)
        || object.get("present").and_then(norito::json::Value::as_bool) != Some(true)
    {
        eyre::bail!(
            "Inrou QMP must attest exactly `enabled=true` and `present=true` for Linux KVM"
        );
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn attest_inrou_qmp_kvm(
    control: &mut PortableVmQmpControl,
    deadline: std::time::Instant,
) -> eyre::Result<()> {
    const COMMAND_ID: &str = "inrou-kvm";
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        eyre::bail!("Inrou QMP KVM attestation exceeded its absolute deadline");
    }
    control
        .reader
        .get_mut()
        .set_write_timeout(Some(remaining.min(SORACLOUD_INROU_QMP_IO_POLL)))?;
    control
        .reader
        .get_mut()
        .write_all(b"{\"execute\":\"query-kvm\",\"id\":\"inrou-kvm\"}\n")?;
    let info = read_inrou_qmp_command_response(&mut control.reader, COMMAND_ID, deadline, None)?;
    validate_inrou_qmp_kvm_info(&info)
}
#[cfg(any(target_os = "linux", test))]
fn parse_inrou_qmp_usernet_forward(
    output: &str,
    expected_guest_port: u16,
) -> eyre::Result<SocketAddr> {
    let mut forwards = Vec::new();
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields
            .first()
            .is_none_or(|protocol| !protocol.contains("[HOST_FORWARD]"))
        {
            continue;
        }
        if fields.len() < 6 || fields[0] != "TCP[HOST_FORWARD]" {
            eyre::bail!("Inrou QMP reported an unsupported host-forward record");
        }
        let source_ip = fields[2]
            .parse::<IpAddr>()
            .wrap_err("parse QEMU usernet host-forward source address")?;
        let source_port = fields[3]
            .parse::<u16>()
            .wrap_err("parse QEMU usernet host-forward source port")?;
        let guest_port = fields[5]
            .parse::<u16>()
            .wrap_err("parse QEMU usernet host-forward guest port")?;
        if source_ip != IpAddr::V4(Ipv4Addr::LOCALHOST)
            || source_port == 0
            || guest_port != expected_guest_port
        {
            eyre::bail!("Inrou QMP reported a host forward outside its exact binding");
        }
        forwards.push(SocketAddr::new(source_ip, source_port));
    }
    if forwards.len() != 1 {
        eyre::bail!(
            "Inrou QMP must report exactly one process-owned TCP host forward, found {}",
            forwards.len()
        );
    }
    Ok(forwards[0])
}
#[cfg(target_os = "linux")]
fn query_inrou_qmp_usernet_forward(
    control: &mut PortableVmQmpControl,
    guest_port: u16,
    deadline: std::time::Instant,
    stop: Option<&AtomicBool>,
) -> eyre::Result<SocketAddr> {
    if stop.is_some_and(|stop| stop.load(AtomicOrdering::Acquire)) {
        eyre::bail!("Inrou QMP forwarding attestation was cancelled");
    }
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        eyre::bail!("Inrou QMP forwarding attestation exceeded its absolute deadline");
    }
    control
        .reader
        .get_mut()
        .set_write_timeout(Some(remaining.min(SORACLOUD_INROU_QMP_IO_POLL)))?;
    control.reader.get_mut().write_all(
        b"{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"info usernet\"},\"id\":\"inrou-usernet\"}\n",
    )?;
    let usernet =
        read_inrou_qmp_command_response(&mut control.reader, "inrou-usernet", deadline, stop)?
            .as_str()
            .ok_or_else(|| eyre::eyre!("Inrou QMP usernet response must be text"))?
            .to_owned();
    parse_inrou_qmp_usernet_forward(&usernet, guest_port)
}
#[cfg(target_os = "linux")]
fn attest_inrou_qmp_host_forward(
    control: &mut PortableVmQmpControl,
    guest_port: u16,
    expected_backend: SocketAddr,
    deadline: std::time::Instant,
    stop: Option<&AtomicBool>,
) -> eyre::Result<()> {
    let actual = query_inrou_qmp_usernet_forward(control, guest_port, deadline, stop)?;
    if actual != expected_backend {
        eyre::bail!("live Inrou QEMU forwarding changed from {expected_backend} to {actual}");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_inrou_qemu_proc_status(
    status: &str,
    identity: &PortableVmChildIdentity,
) -> eyre::Result<()> {
    const REQUIRED_FIELDS: [&str; 9] = [
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    ];
    let mut fields = BTreeMap::new();
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if (REQUIRED_FIELDS.contains(&name) || name == "Seccomp")
            && fields.insert(name, value.trim()).is_some()
        {
            eyre::bail!("Inrou QEMU process status repeats `{name}`");
        }
    }
    let required = |name: &str| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| eyre::eyre!("Inrou QEMU process status omitted `{name}`"))
    };
    let parse_ids = |name: &str| -> eyre::Result<Vec<u32>> {
        required(name)?
            .split_ascii_whitespace()
            .map(|value| {
                value
                    .parse::<u32>()
                    .wrap_err_with(|| format!("parse Inrou QEMU process `{name}` value"))
            })
            .collect()
    };
    if parse_ids("Uid")? != vec![identity.uid; 4] {
        eyre::bail!("Inrou QEMU process did not retain the exact configured uid");
    }
    if parse_ids("Gid")? != vec![identity.gid; 4] {
        eyre::bail!("Inrou QEMU process did not retain the exact configured gid");
    }
    if parse_ids("Groups")? != identity.supplementary_gids {
        eyre::bail!("Inrou QEMU process did not retain the exact supplementary groups");
    }
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let capabilities = u128::from_str_radix(required(name)?, 16)
            .wrap_err_with(|| format!("parse Inrou QEMU process `{name}` value"))?;
        if capabilities != 0 {
            eyre::bail!("Inrou QEMU process retained capabilities in `{name}`");
        }
    }
    if required("NoNewPrivs")? != "1" {
        eyre::bail!("Inrou QEMU process did not enable NoNewPrivs");
    }
    if required("Seccomp")? != "2" {
        eyre::bail!("Inrou QEMU process did not enter seccomp filter mode");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn read_inrou_proc_status(pid: u32) -> io::Result<String> {
    let path = PathBuf::from(format!("/proc/{pid}/status"));
    let mut bytes = Vec::new();
    fs::File::open(&path)?
        .take(SORACLOUD_INROU_PROC_STATUS_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SORACLOUD_INROU_PROC_STATUS_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Inrou QEMU process status exceeds its fixed byte limit",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
#[cfg(target_os = "linux")]
fn inrou_proc_status_field<'a>(status: &'a str, name: &str) -> io::Result<&'a str> {
    let prefix = format!("{name}:");
    let mut fields = status.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = fields.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("procfs status omitted {name}"),
        )
    })?;
    if fields.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("procfs status repeated {name}"),
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn inrou_proc_status_ids(status: &str, name: &str) -> io::Result<Vec<u32>> {
    inrou_proc_status_field(status, name)?
        .split_ascii_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn inrou_proc_status_quad_ids(status: &str, name: &str) -> io::Result<[u32; 4]> {
    inrou_proc_status_ids(status, name)?
        .try_into()
        .map_err(|_ids: Vec<u32>| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("procfs status {name} must contain four credentials"),
            )
        })
}

#[cfg(target_os = "linux")]
fn inrou_proc_status_matches_identity(
    status: &str,
    identity: &PortableVmChildIdentity,
) -> io::Result<bool> {
    let uids = inrou_proc_status_quad_ids(status, "Uid")?;
    let gids = inrou_proc_status_quad_ids(status, "Gid")?;
    let groups = inrou_proc_status_ids(status, "Groups")?;
    Ok(uids.contains(&identity.uid)
        || gids.contains(&identity.gid)
        || groups.contains(&identity.gid))
}
#[cfg(target_os = "linux")]
fn query_inrou_qmp_host_forward(
    child: &mut std::process::Child,
    stream: UnixStream,
    namespace_plan: &Arc<inrou_namespace::InrouNamespacePlan>,
    identity: &PortableVmChildIdentity,
    cgroup_attestation: &inrou_cgroup::InrouCgroupAttestation,
    guest_port: u16,
) -> eyre::Result<(
    SocketAddr,
    PortableVmQmpControl,
    inrou_namespace::InrouNamespaceAttestation,
)> {
    let deadline = std::time::Instant::now() + SORACLOUD_INROU_QMP_ATTEST_TIMEOUT;
    let namespace_attestation =
        namespace_plan.discover_and_attest_qemu(child, cgroup_attestation, identity, deadline)?;
    require_inrou_launcher_running(child)?;
    let mut control = PortableVmQmpControl {
        reader: io::BufReader::new(stream),
    };
    let greeting = read_inrou_qmp_message(&mut control.reader, deadline, None)?;
    if greeting
        .get("QMP")
        .and_then(norito::json::Value::as_object)
        .is_none()
    {
        eyre::bail!("Inrou QMP endpoint did not send a canonical greeting");
    }
    namespace_attestation.attest_live(cgroup_attestation)?;
    control
        .reader
        .get_mut()
        .set_write_timeout(Some(SORACLOUD_INROU_QMP_IO_POLL))?;
    control
        .reader
        .get_mut()
        .write_all(b"{\"execute\":\"qmp_capabilities\",\"id\":\"inrou-capabilities\"}\n")?;
    let capabilities =
        read_inrou_qmp_command_response(&mut control.reader, "inrou-capabilities", deadline, None)?;
    if !capabilities.is_object() {
        eyre::bail!("Inrou QMP capabilities response must be an object");
    }
    namespace_attestation.attest_live(cgroup_attestation)?;
    attest_inrou_qmp_kvm(&mut control, deadline)?;
    namespace_attestation.attest_live(cgroup_attestation)?;
    let forward = query_inrou_qmp_usernet_forward(&mut control, guest_port, deadline, None)?;
    if let Some(status) = child.try_wait()? {
        eyre::bail!("Inrou QEMU exited during QMP attestation with status {status}");
    }
    namespace_attestation.attest_live(cgroup_attestation)?;
    Ok((forward, control, namespace_attestation))
}
#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn random_inrou_materialization_name(root_name: &OsStr, role: &str) -> io::Result<OsString> {
    let mut suffix = [0_u8; 16];
    OsRng.try_fill_bytes(&mut suffix).map_err(|error| {
        io::Error::other(format!(
            "Inrou materialization transaction OS RNG failed: {error}"
        ))
    })?;
    let mut name = OsString::from(".");
    name.push(root_name);
    name.push(format!(".inrou-{role}-{}", hex::encode(suffix)));
    Ok(name)
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn create_unique_inrou_materialization_directory(
    parent: &PinnedInrouDirectory,
    root_name: &OsStr,
    role: &str,
) -> io::Result<(
    OsString,
    PinnedInrouDirectory,
    InrouMaterializationDirectoryIdentity,
)> {
    validate_inrou_single_component(root_name)?;
    for _ in 0..128 {
        let name = random_inrou_materialization_name(root_name, role)?;
        match rustix::fs::mkdirat(&parent.directory, &name, rustix::fs::Mode::RWXU) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
        let created = rustix::fs::statat(
            &parent.directory,
            &name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        let staging = match parent.open_existing_child_directory(&name) {
            Ok(staging) => staging,
            Err(error) => {
                if rustix::fs::statat(
                    &parent.directory,
                    &name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .is_ok_and(|named| named.st_dev == created.st_dev && named.st_ino == created.st_ino)
                {
                    let _ = rustix::fs::unlinkat(
                        &parent.directory,
                        &name,
                        rustix::fs::AtFlags::REMOVEDIR,
                    );
                    let _ = parent.directory.sync_all();
                }
                return Err(error);
            }
        };
        let identity = InrouMaterializationDirectoryIdentity::from_directory(&staging)?;
        let setup = (|| -> io::Result<()> {
            rustix::fs::fchmod(&staging.directory, rustix::fs::Mode::RWXU)
                .map_err(io::Error::from)?;
            let named = rustix::fs::statat(
                &parent.directory,
                &name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            if !identity.matches_stat(&named) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "private Inrou materialization directory changed during creation",
                ));
            }
            parent.directory.sync_all()
        })();
        if let Err(error) = setup {
            if rustix::fs::statat(
                &parent.directory,
                &name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .is_ok_and(|named| identity.matches_stat(&named))
            {
                let _ =
                    rustix::fs::unlinkat(&parent.directory, &name, rustix::fs::AtFlags::REMOVEDIR);
                let _ = parent.directory.sync_all();
            }
            return Err(error);
        }
        return Ok((name, staging, identity));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create a unique Inrou materialization transaction directory",
    ))
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn recover_interrupted_inrou_bundle_swap(
    parent: &PinnedInrouDirectory,
    root_name: &OsStr,
) -> eyre::Result<()> {
    validate_inrou_single_component(root_name)?;
    let mut backup_prefix = OsString::from(".");
    backup_prefix.push(root_name);
    backup_prefix.push(".inrou-backup-");
    let backup_prefix = backup_prefix.as_bytes();
    let mut backup = None;
    let entries = rustix::fs::Dir::read_from(&parent.directory)
        .map_err(io::Error::from)
        .wrap_err_with(|| format!("read directory {}", parent.path().display()))?;
    for entry in entries {
        let entry = entry.map_err(io::Error::from)?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        if !name.as_bytes().starts_with(backup_prefix) {
            continue;
        }
        if backup.is_some() {
            eyre::bail!(
                "multiple interrupted Inrou bundle recovery backups exist under {}; operator recovery is required",
                parent.path().display()
            );
        }
        let backup_directory = parent
            .open_existing_child_directory(name)
            .wrap_err("inspect interrupted Inrou bundle recovery backup")?;
        let identity = InrouMaterializationDirectoryIdentity::from_directory(&backup_directory)?;
        backup = Some((name.to_os_string(), backup_directory, identity));
    }
    let Some((backup_name, backup_directory, backup_identity)) = backup else {
        return Ok(());
    };
    match rustix::fs::statat(
        &parent.directory,
        root_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => {
            parent
                .open_existing_child_directory(root_name)
                .wrap_err("inspect live Inrou bundle beside interrupted recovery backup")?;
            eyre::bail!(
                "Inrou bundle has both a live root and an interrupted recovery backup {}; operator recovery is required",
                parent.path().join(&backup_name).display()
            );
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io::Error::from(error)).wrap_err("inspect Inrou bundle root"),
    }
    let named_backup = rustix::fs::statat(
        &parent.directory,
        &backup_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if !backup_identity.matches_stat(&named_backup) {
        eyre::bail!("interrupted Inrou bundle recovery backup changed before restoration");
    }
    rename_inrou_no_replace_at(
        &parent.directory,
        &backup_name,
        &parent.directory,
        root_name,
    )
    .wrap_err("restore interrupted Inrou bundle recovery backup")?;
    let restored = rustix::fs::statat(
        &parent.directory,
        root_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    let opened = backup_directory.directory.metadata()?;
    if !backup_identity.matches_stat(&restored)
        || opened.dev() != backup_identity.device
        || opened.ino() != backup_identity.inode
    {
        eyre::bail!("restored interrupted Inrou bundle changed identity during rename");
    }
    parent.directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn materialize_inrou_bundle_entry(
    staging_root: &PinnedInrouDirectory,
    entry: &BundleArchiveEntry,
    payload: &mut dyn io::Read,
) -> io::Result<()> {
    let (leaf, parents) = entry
        .path_components()
        .split_last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty archive path"))?;
    let mut parent = staging_root.try_clone()?;
    for component in parents {
        parent = parent.open_or_create_child_directory(OsStr::new(component), 0o755)?;
    }
    let leaf = OsStr::new(leaf);
    validate_inrou_single_component(leaf)?;
    match entry.kind() {
        BundleArchiveEntryKind::Directory => {
            let target = parent.open_or_create_child_directory(leaf, 0o755)?;
            rustix::fs::fchmod(&target.directory, inrou_mode_from_u32(entry.mode())?)
                .map_err(io::Error::from)?;
            target.directory.sync_all()?;
            let named = rustix::fs::statat(
                &parent.directory,
                leaf,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            let opened = target.directory.metadata()?;
            if !inrou_stat_matches_metadata(&named, &opened)
                || opened.mode() & 0o7777 != entry.mode()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Inrou archive directory changed during materialization",
                ));
            }
        }
        BundleArchiveEntryKind::File => {
            let mut file = fs::File::from(
                rustix::fs::openat(
                    &parent.directory,
                    leaf,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    inrou_mode_from_u32(entry.mode())?,
                )
                .map_err(io::Error::from)?,
            );
            let observed = io::copy(payload, &mut file)?;
            if observed != entry.size() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "archive file {} declared {} bytes but yielded {observed}",
                        entry.path(),
                        entry.size()
                    ),
                ));
            }
            file.flush()?;
            rustix::fs::fchmod(&file, inrou_mode_from_u32(entry.mode())?)
                .map_err(io::Error::from)?;
            file.sync_all()?;
            let opened = file.metadata()?;
            let named = rustix::fs::statat(
                &parent.directory,
                leaf,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)?;
            if !opened.is_file()
                || opened.nlink() != 1
                || opened.uid() != rustix::process::geteuid().as_raw()
                || opened.mode() & 0o7777 != entry.mode()
                || opened.len() != entry.size()
                || !inrou_stat_matches_metadata(&named, &opened)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Inrou archive file changed during materialization",
                ));
            }
        }
    }
    parent.directory.sync_all()
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn move_inrou_bundle_root_to_unique_backup(
    parent: &PinnedInrouDirectory,
    root_name: &OsStr,
) -> io::Result<OsString> {
    for _ in 0..128 {
        let backup_name = random_inrou_materialization_name(root_name, "backup")?;
        match rename_inrou_no_replace_at(
            &parent.directory,
            root_name,
            &parent.directory,
            &backup_name,
        ) {
            Ok(()) => return Ok(backup_name),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate an Inrou bundle recovery backup name",
    ))
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn install_staged_inrou_bundle(
    staging_name: &OsStr,
    staging_identity: InrouMaterializationDirectoryIdentity,
    parent: &PinnedInrouDirectory,
    root_name: &OsStr,
) -> eyre::Result<PinnedInrouDirectory> {
    validate_inrou_single_component(staging_name)?;
    validate_inrou_single_component(root_name)?;
    let existing = match rustix::fs::statat(
        &parent.directory,
        root_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => {
            let directory = parent
                .open_existing_child_directory(root_name)
                .wrap_err("inspect existing Inrou bundle root")?;
            let identity = InrouMaterializationDirectoryIdentity::from_directory(&directory)?;
            Some((directory, identity))
        }
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(io::Error::from(error)).wrap_err("inspect Inrou bundle root"),
    };
    let mut backup = None;
    if let Some((existing_directory, existing_identity)) = existing {
        let named_before = rustix::fs::statat(
            &parent.directory,
            root_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        if !existing_identity.matches_stat(&named_before) {
            eyre::bail!("existing Inrou bundle changed before backup");
        }
        let backup_name = move_inrou_bundle_root_to_unique_backup(parent, root_name)
            .wrap_err("allocate Inrou bundle recovery backup path")?;
        let named_backup = rustix::fs::statat(
            &parent.directory,
            &backup_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io::Error::from)?;
        if !existing_identity.matches_stat(&named_backup)
            || InrouMaterializationDirectoryIdentity::from_directory(&existing_directory)?
                != existing_identity
        {
            eyre::bail!("Inrou bundle recovery backup changed identity during rename");
        }
        parent.directory.sync_all()?;
        backup = Some((backup_name, existing_identity));
    }
    let staged_before = rustix::fs::statat(
        &parent.directory,
        staging_name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if !staging_identity.matches_stat(&staged_before) {
        eyre::bail!("staged Inrou bundle changed before installation");
    }
    if let Err(install_error) = rename_inrou_no_replace_at(
        &parent.directory,
        staging_name,
        &parent.directory,
        root_name,
    ) {
        if let Some((backup_name, backup_identity)) = backup.as_ref() {
            let restored = rename_inrou_no_replace_at(
                &parent.directory,
                backup_name,
                &parent.directory,
                root_name,
            );
            return match restored {
                Ok(()) => {
                    let restored = rustix::fs::statat(
                        &parent.directory,
                        root_name,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(io::Error::from)?;
                    if !backup_identity.matches_stat(&restored) {
                        eyre::bail!(
                            "restored Inrou bundle root changed identity after installation failure"
                        );
                    }
                    parent.directory.sync_all()?;
                    Err(io::Error::from(install_error)).wrap_err("install staged Inrou bundle")
                }
                Err(restore_error) => Err(eyre::eyre!(
                    "failed to install staged Inrou bundle ({install_error}) and failed to restore its recovery backup ({restore_error})"
                )),
            };
        }
        return Err(io::Error::from(install_error)).wrap_err("install staged Inrou bundle");
    }
    let installed = parent
        .open_existing_child_directory(root_name)
        .wrap_err("pin installed Inrou bundle root")?;
    if InrouMaterializationDirectoryIdentity::from_directory(&installed)? != staging_identity {
        eyre::bail!("installed Inrou bundle root changed identity during rename");
    }
    parent.directory.sync_all()?;
    if let Some((backup_name, backup_identity)) = backup {
        remove_owned_inrou_materialization_directory(parent, &backup_name, backup_identity)
            .wrap_err("remove committed Inrou bundle recovery backup")?;
    }
    Ok(installed)
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn remove_owned_inrou_materialization_directory(
    parent: &PinnedInrouDirectory,
    name: &OsStr,
    expected_identity: InrouMaterializationDirectoryIdentity,
) -> eyre::Result<()> {
    validate_inrou_single_component(name)?;
    let named = match rustix::fs::statat(
        &parent.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(named) => named,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(io::Error::from(error)).wrap_err("inspect Inrou transaction root");
        }
    };
    if !expected_identity.matches_stat(&named) {
        eyre::bail!(
            "owned Inrou transaction path {} changed identity before cleanup",
            parent.path().join(name).display()
        );
    }
    let owned = parent
        .open_existing_child_directory(name)
        .wrap_err("pin owned Inrou transaction root before cleanup")?;
    if InrouMaterializationDirectoryIdentity::from_directory(&owned)? != expected_identity {
        eyre::bail!("owned Inrou transaction directory changed while it was opened for cleanup");
    }
    let entries = rustix::fs::Dir::read_from(&owned.directory).map_err(io::Error::from)?;
    let mut entries_seen = 0;
    for entry in entries {
        let entry = entry.map_err(io::Error::from)?;
        let child_name = OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string();
        if child_name == OsStr::new(".") || child_name == OsStr::new("..") {
            continue;
        }
        remove_inrou_tree_entry_at(&owned, &child_name, 1, &mut entries_seen)?;
    }
    owned.directory.sync_all()?;
    let named_after = rustix::fs::statat(
        &parent.directory,
        name,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    if !expected_identity.matches_stat(&named_after) {
        eyre::bail!("owned Inrou transaction directory changed before final removal");
    }
    rustix::fs::unlinkat(&parent.directory, name, rustix::fs::AtFlags::REMOVEDIR)
        .map_err(io::Error::from)?;
    parent.directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn ensure_inrou_entrypoint_present_at(
    bundle_root: &PinnedInrouDirectory,
    entrypoint: &str,
) -> eyre::Result<()> {
    let components = canonical_inrou_bundle_member_components(entrypoint)?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| eyre::eyre!("Inrou entrypoint must have at least one component"))?;
    let mut parent = bundle_root.try_clone()?;
    for component in parents {
        parent = parent
            .open_existing_child_directory(OsStr::new(component))
            .wrap_err_with(|| format!("open Inrou entrypoint parent `{component}`"))?;
    }
    let leaf = OsStr::new(leaf);
    let named = rustix::fs::statat(
        &parent.directory,
        leaf,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)?;
    let file = fs::File::from(
        rustix::fs::openat(
            &parent.directory,
            leaf,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.mode() & 0o111 == 0
        || !inrou_stat_matches_metadata(&named, &opened)
    {
        eyre::bail!(
            "Inrou entrypoint `{entrypoint}` must be an executable regular file under {}",
            bundle_root.path().display()
        );
    }
    Ok(())
}
fn probe_hosted_http_health(
    listen_base_url: &str,
    healthcheck_path: Option<&str>,
) -> eyre::Result<()> {
    let parsed = reqwest::Url::parse(listen_base_url)
        .wrap_err_with(|| format!("parse hosted-HTTP listener URL `{listen_base_url}`"))?;
    if parsed.scheme() != "http"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port().is_none()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        eyre::bail!(
            "hosted-HTTP listener URL `{listen_base_url}` must be an explicit IPv4 loopback HTTP origin"
        );
    }
    let port = parsed
        .port()
        .ok_or_else(|| eyre::eyre!("hosted-HTTP listener URL has no explicit port"))?;
    let Some(path) = healthcheck_path else {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))
            .wrap_err_with(|| format!("connect to hosted-HTTP listener `{address}`"))?;
        drop(stream);
        return Ok(());
    };
    let request_path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let url = format!("{listen_base_url}{request_path}");
    let parsed_health_url = reqwest::Url::parse(&url)
        .wrap_err_with(|| format!("parse hosted-HTTP healthcheck URL `{url}`"))?;
    if parsed_health_url.scheme() != parsed.scheme()
        || parsed_health_url.host_str() != parsed.host_str()
        || parsed_health_url.port() != parsed.port()
        || !parsed_health_url.username().is_empty()
        || parsed_health_url.password().is_some()
    {
        eyre::bail!("hosted-HTTP healthcheck must remain on the configured loopback origin");
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .wrap_err("build hosted-HTTP healthcheck client")?
        .get(parsed_health_url)
        .send()
        .wrap_err_with(|| format!("probe hosted-HTTP healthcheck {url}"))?;
    if !response.status().is_success() {
        eyre::bail!(
            "hosted-HTTP healthcheck {url} returned {}",
            response.status()
        );
    }
    Ok(())
}
#[cfg(test)]
fn fetch_hosted_http_text(listen_base_url: &str, path: &str) -> eyre::Result<String> {
    let request_path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let url = format!("{listen_base_url}{request_path}");
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .wrap_err("build hosted-HTTP client")?
        .get(&url)
        .send()
        .wrap_err_with(|| format!("fetch hosted-HTTP response {url}"))?;
    if !response.status().is_success() {
        eyre::bail!("hosted-HTTP request {url} returned {}", response.status());
    }
    response
        .text()
        .wrap_err_with(|| format!("read hosted-HTTP response body {url}"))
}
fn remote_hydration_nonce(
    manifest_cid_hex: &str,
    provider_id: &[u8; 32],
    expected_hash: Hash,
) -> String {
    let manifest_prefix = manifest_cid_hex
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    let provider_prefix = hex::encode(provider_id).chars().take(8).collect::<String>();
    let hash_prefix = expected_hash
        .to_string()
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("sc-{manifest_prefix}-{provider_prefix}-{hash_prefix}")
}
fn parse_canonical_remote_hex_32(raw: &str, label: &str) -> eyre::Result<[u8; 32]> {
    let bytes = hex::decode(raw).wrap_err_with(|| format!("decode {label}"))?;
    let digest = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| eyre::eyre!("{label} must decode to exactly 32 bytes"))?;
    if hex::encode(digest) != raw {
        eyre::bail!("{label} must use exact canonical lowercase hexadecimal");
    }
    Ok(digest)
}
fn validate_remote_manifest_response(
    source: &RemoteHydrationSource,
    response: StorageManifestResponseDto,
    maximum_payload_bytes: u64,
) -> eyre::Result<VerifiedRemoteManifest> {
    if maximum_payload_bytes == 0 {
        eyre::bail!("remote Soracloud hydration payload limit must be positive");
    }
    if response.manifest_id_hex != source.manifest_cid_hex {
        eyre::bail!(
            "remote manifest identifier does not match the committed replication-order CID"
        );
    }
    let requested_cid = hex::decode(&source.manifest_cid_hex)
        .wrap_err("decode committed replication-order manifest CID")?;
    if hex::encode(&requested_cid) != source.manifest_cid_hex {
        eyre::bail!("committed replication-order manifest CID is not canonical lowercase hex");
    }
    let expected_manifest_digest =
        parse_canonical_remote_hex_32(&source.manifest_digest_hex, "committed manifest digest")?;
    let response_manifest_digest =
        parse_canonical_remote_hex_32(&response.manifest_digest_hex, "remote manifest digest")?;
    if response_manifest_digest != expected_manifest_digest {
        eyre::bail!("remote manifest digest does not match committed ledger state");
    }
    let payload_digest =
        parse_canonical_remote_hex_32(&response.payload_digest_hex, "remote payload digest")?;
    let manifest = sorafs_manifest::decode_manifest_v1_base64_canonical(&response.manifest_b64)
        .wrap_err("decode exact canonical remote manifest payload")?;
    sorafs_manifest::validate_manifest(
        &manifest,
        &sorafs_manifest::PinPolicyConstraints::default(),
    )
    .wrap_err("validate remote manifest")?;
    if manifest.root_cid != requested_cid {
        eyre::bail!("decoded remote manifest root CID does not match committed ledger state");
    }
    let decoded_manifest_digest = manifest
        .digest()
        .wrap_err("digest decoded canonical remote manifest")?;
    if decoded_manifest_digest.as_bytes() != &expected_manifest_digest {
        eyre::bail!("decoded remote manifest digest does not match committed ledger state");
    }
    if manifest.content_length == 0
        || manifest.content_length != response.content_length
        || manifest.content_length > maximum_payload_bytes
    {
        eyre::bail!(
            "remote manifest content length is zero, inconsistent, or exceeds the configured hydration limit"
        );
    }
    let chunk_count = usize::try_from(response.chunk_count)
        .wrap_err("convert remote manifest chunk count to usize")?;
    if chunk_count == 0 || chunk_count > sorafs_car::CAR_PLAN_MAX_CHUNKS {
        eyre::bail!("remote manifest chunk count is outside the supported range");
    }
    let chunker_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    if response.chunk_profile_handle != chunker_handle
        || source.chunker_handle.as_deref() != Some(chunker_handle.as_str())
    {
        eyre::bail!(
            "remote manifest chunk profile does not match the canonical manifest and replication order"
        );
    }
    Ok(VerifiedRemoteManifest {
        manifest,
        manifest_id_hex: response.manifest_id_hex,
        manifest_digest: expected_manifest_digest,
        payload_digest,
        chunk_count,
        chunker_handle,
    })
}
fn required_plan_usize(plan: &norito::json::native::Map, field: &str) -> eyre::Result<usize> {
    let value = plan
        .get(field)
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `{field}`"))?;
    usize::try_from(value).wrap_err_with(|| format!("convert remote plan `{field}` to usize"))
}
fn required_plan_bool(plan: &norito::json::native::Map, field: &str) -> eyre::Result<bool> {
    plan.get(field)
        .and_then(norito::json::Value::as_bool)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `{field}`"))
}
fn parse_remote_hydration_file(
    value: &norito::json::Value,
    index: usize,
) -> eyre::Result<RemoteHydrationFile> {
    let file = value
        .as_object()
        .ok_or_else(|| eyre::eyre!("remote plan file {index} is not an object"))?;
    let path_values = file
        .get("path")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre::eyre!("remote plan file {index} missing `path`"))?;
    let mut path = Vec::new();
    path.try_reserve_exact(path_values.len())
        .wrap_err_with(|| format!("reserve remote plan file {index} path"))?;
    for (component_index, component) in path_values.iter().enumerate() {
        let component = component.as_str().ok_or_else(|| {
            eyre::eyre!("remote plan file {index} path component {component_index} is not a string")
        })?;
        path.push(component.to_owned());
    }
    let offset = file
        .get("offset")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan file {index} missing `offset`"))?;
    let size = file
        .get("size")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan file {index} missing `size`"))?;
    let first_chunk = file
        .get("first_chunk")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan file {index} missing `first_chunk`"))?;
    let chunk_count = file
        .get("chunk_count")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan file {index} missing `chunk_count`"))?;
    Ok(RemoteHydrationFile {
        path,
        offset,
        size,
        first_chunk: usize::try_from(first_chunk)
            .wrap_err_with(|| format!("convert remote plan file {index} first chunk"))?,
        chunk_count: usize::try_from(chunk_count)
            .wrap_err_with(|| format!("convert remote plan file {index} chunk count"))?,
    })
}
fn parse_remote_hydration_plan_page(
    expected_manifest_id_hex: &str,
    body: &[u8],
    maximum_files: usize,
) -> eyre::Result<RemoteHydrationPlanPage> {
    let value: norito::json::Value =
        norito::json::from_slice(body).wrap_err("decode remote plan response as JSON")?;
    let manifest_id_hex = value
        .get("manifest_id_hex")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `manifest_id_hex`"))?
        .to_owned();
    if manifest_id_hex != expected_manifest_id_hex {
        eyre::bail!("remote plan manifest identifier does not match the requested manifest");
    }
    let plan = value
        .get("plan")
        .and_then(norito::json::Value::as_object)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `plan` object"))?;
    let chunker_handle = plan
        .get("chunk_profile_handle")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `chunk_profile_handle`"))?
        .to_owned();
    let content_length = plan
        .get("content_length")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `content_length`"))?;
    let payload_digest = parse_canonical_remote_hex_32(
        plan.get("payload_digest_blake3")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre::eyre!("remote plan response missing `payload_digest_blake3`"))?,
        "remote plan payload digest",
    )?;
    let chunk_count = required_plan_usize(plan, "chunk_count")?;
    let returned_chunk_count = required_plan_usize(plan, "returned_chunk_count")?;
    let chunk_digest_count = required_plan_usize(plan, "chunk_digest_count")?;
    let returned_chunk_digest_count = required_plan_usize(plan, "returned_chunk_digest_count")?;
    let file_count = required_plan_usize(plan, "file_count")?;
    let returned_file_count = required_plan_usize(plan, "returned_file_count")?;
    let offset = required_plan_usize(plan, "offset")?;
    let limit = required_plan_usize(plan, "limit")?;
    let truncated_chunks = required_plan_bool(plan, "truncated_chunks")?;
    let truncated_chunk_digests = required_plan_bool(plan, "truncated_chunk_digests")?;
    let truncated_files = required_plan_bool(plan, "truncated_files")?;
    if limit == 0
        || limit > SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT
        || chunk_count == 0
        || chunk_count > sorafs_car::CAR_PLAN_MAX_CHUNKS
        || chunk_digest_count != chunk_count
        || file_count == 0
        || file_count > maximum_files
        || offset > chunk_count.max(file_count)
    {
        eyre::bail!("remote plan page geometry is outside the supported range");
    }
    let chunks_value = plan
        .get("chunks")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `chunks` array"))?;
    let chunk_digests = plan
        .get("chunk_digests_blake3")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `chunk_digests_blake3` array"))?;
    let files_value = plan
        .get("files")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre::eyre!("remote plan response missing `files` array"))?;
    if chunks_value.len() != returned_chunk_count
        || chunk_digests.len() != returned_chunk_digest_count
        || chunk_digests.len() != chunks_value.len()
        || files_value.len() != returned_file_count
        || chunks_value.len() > limit
        || files_value.len() > limit
    {
        eyre::bail!("remote plan returned counts do not match page arrays");
    }
    let expected_returned_chunks = chunk_count
        .saturating_sub(offset.min(chunk_count))
        .min(limit);
    let expected_returned_files = file_count.saturating_sub(offset.min(file_count)).min(limit);
    let expected_truncated_chunks =
        offset.min(chunk_count).saturating_add(returned_chunk_count) < chunk_count;
    let expected_truncated_files =
        offset.min(file_count).saturating_add(returned_file_count) < file_count;
    if returned_chunk_count != expected_returned_chunks
        || returned_chunk_digest_count != expected_returned_chunks
        || returned_file_count != expected_returned_files
        || truncated_chunks != expected_truncated_chunks
        || truncated_chunk_digests != truncated_chunks
        || truncated_files != expected_truncated_files
    {
        eyre::bail!("remote plan pagination flags or counts are inconsistent");
    }
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(chunks_value.len())
        .wrap_err("reserve remote plan chunk page")?;
    for (index, chunk) in chunks_value.iter().enumerate() {
        let chunk = chunk
            .as_object()
            .ok_or_else(|| eyre::eyre!("remote plan chunk {index} is not an object"))?;
        let chunk_index = chunk
            .get("chunk_index")
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| eyre::eyre!("remote plan chunk {index} missing `chunk_index`"))?;
        let chunk_index = usize::try_from(chunk_index)
            .wrap_err_with(|| format!("convert remote plan chunk {index} index"))?;
        let expected_index = offset
            .checked_add(index)
            .ok_or_else(|| eyre::eyre!("remote plan chunk index overflow"))?;
        if chunk_index != expected_index {
            eyre::bail!("remote plan chunk page is not contiguous at index {expected_index}");
        }
        let offset = chunk
            .get("offset")
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| eyre::eyre!("remote plan chunk {index} missing `offset`"))?;
        let length = chunk
            .get("length")
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| eyre::eyre!("remote plan chunk {index} missing `length`"))?;
        let digest_hex = chunk
            .get("digest_blake3")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre::eyre!("remote plan chunk {index} missing `digest_blake3`"))?;
        let digest = parse_canonical_remote_hex_32(
            digest_hex,
            &format!("remote plan chunk {index} digest"),
        )?;
        let listed_digest = chunk_digests[index]
            .as_str()
            .ok_or_else(|| eyre::eyre!("remote plan chunk digest {index} is not a string"))?;
        if parse_canonical_remote_hex_32(
            listed_digest,
            &format!("remote plan listed chunk {index} digest"),
        )? != digest
        {
            eyre::bail!("remote plan chunk digest arrays disagree at index {chunk_index}");
        }
        let length = u32::try_from(length)
            .wrap_err_with(|| format!("convert remote plan chunk {index} length to u32"))?;
        if length == 0 || u64::from(length) > SORACLOUD_REMOTE_CHUNK_MAX_RESPONSE_BYTES {
            eyre::bail!("remote plan chunk {chunk_index} length is outside the supported range");
        }
        chunks.push(RemoteHydrationChunk {
            index: chunk_index,
            offset,
            length,
            digest,
        });
    }
    let mut files = Vec::new();
    files
        .try_reserve_exact(files_value.len())
        .wrap_err("reserve remote plan file page")?;
    for (index, file) in files_value.iter().enumerate() {
        files.push(parse_remote_hydration_file(
            file,
            offset
                .checked_add(index)
                .ok_or_else(|| eyre::eyre!("remote plan file index overflow"))?,
        )?);
    }
    Ok(RemoteHydrationPlanPage {
        chunker_handle,
        content_length,
        payload_digest,
        chunk_count,
        file_count,
        offset,
        limit,
        truncated_chunks,
        truncated_files,
        chunks,
        files,
    })
}
fn fetch_remote_hydration_plan_pages(
    client: &reqwest::blocking::Client,
    base_url: &reqwest::Url,
    manifest: &VerifiedRemoteManifest,
    maximum_files: u32,
) -> eyre::Result<RemoteHydrationPlan> {
    let maximum_files =
        usize::try_from(maximum_files).wrap_err("convert Soracloud remote file limit")?;
    let descriptor =
        sorafs_manifest::chunker_registry::lookup(manifest.manifest.chunking.profile_id)
            .ok_or_else(|| eyre::eyre!("remote manifest names an unregistered chunk profile"))?;
    let minimum_chunk_bytes = u64::try_from(descriptor.profile.min_size)
        .wrap_err("convert registered minimum chunk size")?;
    let maximum_chunks_for_payload = manifest
        .manifest
        .content_length
        .div_ceil(minimum_chunk_bytes.max(1));
    if u64::try_from(manifest.chunk_count).unwrap_or(u64::MAX) > maximum_chunks_for_payload {
        eyre::bail!("remote manifest chunk count exceeds registered chunk-profile geometry");
    }
    let mut offset = 0_usize;
    let mut chunks = Vec::new();
    let mut files = Vec::new();
    let mut expected_counts: Option<(usize, usize)> = None;
    loop {
        let mut url = base_url
            .join(&format!(
                "v1/sorafs/storage/plan/{}",
                manifest.manifest_id_hex
            ))
            .wrap_err("build remote Soracloud hydration plan URL")?;
        url.query_pairs_mut()
            .append_pair("limit", &SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT.to_string())
            .append_pair("offset", &offset.to_string());
        let response = client
            .get(url.clone())
            .send()
            .wrap_err_with(|| format!("fetch remote Soracloud hydration plan page {offset}"))?;
        if !response.status().is_success() {
            eyre::bail!(
                "remote Soracloud hydration plan page {offset} returned {}",
                response.status()
            );
        }
        let body = read_soracloud_http_response_bounded(
            response,
            SORACLOUD_REMOTE_HYDRATION_PLAN_MAX_RESPONSE_BYTES,
            "remote Soracloud hydration plan",
        )
        .wrap_err_with(|| format!("read remote Soracloud hydration plan page {offset}"))?;
        let page =
            parse_remote_hydration_plan_page(&manifest.manifest_id_hex, &body, maximum_files)?;
        if page.offset != offset
            || page.limit != SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT
            || page.chunker_handle != manifest.chunker_handle
            || page.content_length != manifest.manifest.content_length
            || page.payload_digest != manifest.payload_digest
            || page.chunk_count != manifest.chunk_count
        {
            eyre::bail!("remote Soracloud hydration plan page does not match its manifest");
        }
        match expected_counts {
            Some(counts) if counts != (page.chunk_count, page.file_count) => {
                eyre::bail!("remote Soracloud hydration plan counts changed between pages");
            }
            None => {
                expected_counts = Some((page.chunk_count, page.file_count));
                chunks
                    .try_reserve_exact(page.chunk_count)
                    .wrap_err("reserve complete remote Soracloud chunk plan")?;
                files
                    .try_reserve_exact(page.file_count)
                    .wrap_err("reserve complete remote Soracloud file plan")?;
            }
            Some(_) => {}
        }
        chunks.extend(page.chunks);
        files.extend(page.files);
        if !page.truncated_chunks && !page.truncated_files {
            break;
        }
        offset = offset
            .checked_add(SORACLOUD_REMOTE_HYDRATION_PAGE_LIMIT)
            .ok_or_else(|| eyre::eyre!("remote Soracloud hydration page offset overflow"))?;
        let Some((chunk_count, file_count)) = expected_counts else {
            eyre::bail!("remote Soracloud hydration plan did not establish counts");
        };
        if offset >= chunk_count.max(file_count) && (page.truncated_chunks || page.truncated_files)
        {
            eyre::bail!("remote Soracloud hydration plan pagination made no progress");
        }
    }
    let Some((chunk_count, file_count)) = expected_counts else {
        eyre::bail!("remote Soracloud hydration plan returned no pages");
    };
    if chunks.len() != chunk_count || files.len() != file_count {
        eyre::bail!("remote Soracloud hydration plan was incomplete");
    }
    let plan = RemoteHydrationPlan {
        manifest_id_hex: manifest.manifest_id_hex.clone(),
        chunker_handle: manifest.chunker_handle.clone(),
        content_length: manifest.manifest.content_length,
        payload_digest: manifest.payload_digest,
        chunks,
        files,
    };
    let car_plan = remote_hydration_car_plan(&plan, manifest)?;
    if compute_chunk_plan_digest_sha3(&car_plan.chunks) != manifest.manifest.chunk_digest_sha3_256 {
        eyre::bail!("remote Soracloud chunk plan does not match the canonical manifest");
    }
    Ok(plan)
}
fn remote_hydration_car_plan(
    plan: &RemoteHydrationPlan,
    manifest: &VerifiedRemoteManifest,
) -> eyre::Result<CarBuildPlan> {
    let descriptor =
        sorafs_manifest::chunker_registry::lookup(manifest.manifest.chunking.profile_id)
            .ok_or_else(|| eyre::eyre!("remote manifest names an unregistered chunk profile"))?;
    for (expected_index, chunk) in plan.chunks.iter().enumerate() {
        if chunk.index != expected_index {
            eyre::bail!(
                "complete remote Soracloud chunk plan is not contiguous at index {expected_index}"
            );
        }
    }
    let chunks = plan
        .chunks
        .iter()
        .map(|chunk| CarChunk {
            offset: chunk.offset,
            length: chunk.length,
            digest: chunk.digest,
        })
        .collect();
    let files = plan
        .files
        .iter()
        .map(|file| FilePlan {
            path: file.path.clone(),
            first_chunk: file.first_chunk,
            chunk_count: file.chunk_count,
            size: file.size,
        })
        .collect();
    let car_plan = CarBuildPlan {
        chunk_profile: descriptor.profile,
        payload_digest: blake3::Hash::from(plan.payload_digest),
        content_length: plan.content_length,
        chunks,
        files,
    };
    car_plan
        .validate()
        .wrap_err("validate complete remote Soracloud CAR plan")?;
    validate_remote_hydration_file_plan(plan, &car_plan)?;
    Ok(car_plan)
}
fn verify_remote_hydration_payload(
    payload: &[u8],
    plan: &RemoteHydrationPlan,
    manifest: &VerifiedRemoteManifest,
) -> eyre::Result<()> {
    if u64::try_from(payload.len()).ok() != Some(plan.content_length)
        || blake3::hash(payload).as_bytes() != &plan.payload_digest
    {
        eyre::bail!("remote Soracloud payload does not match the authenticated plan");
    }
    let car_plan = remote_hydration_car_plan(plan, manifest)?;
    let writer = CarWriter::with_expected_roots(
        &car_plan,
        payload,
        vec![manifest.manifest.root_cid.clone()],
    )
    .wrap_err("bind remote Soracloud payload to its canonical CAR plan")?;
    let stats = writer
        .write_to(io::sink())
        .wrap_err("verify remote Soracloud payload CAR commitments")?;
    if stats.dag_codec != manifest.manifest.dag_codec.0
        || stats.car_archive_digest.as_bytes() != &manifest.manifest.car_digest
        || stats.car_size != manifest.manifest.car_size
        || compute_por_root(payload, &car_plan)
            .wrap_err("derive remote Soracloud payload PoR root")?
            != manifest.manifest.por_root
    {
        eyre::bail!("remote Soracloud payload does not match canonical CAR manifest fields");
    }
    Ok(())
}
fn parse_sorafs_manifest_digest_hex(raw: &str) -> eyre::Result<[u8; 32]> {
    let bytes = hex::decode(raw).wrap_err("decode SoraFS manifest digest hex")?;
    let digest = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        eyre::eyre!(
            "SoraFS manifest digest hex must decode to 32 bytes, got {}",
            bytes.len()
        )
    })?;
    if hex::encode(digest) != raw {
        eyre::bail!("SoraFS manifest digest must use exact canonical lowercase hexadecimal");
    }
    Ok(digest)
}
fn parse_canonical_sorafs_content_cid(raw: &str) -> eyre::Result<Vec<u8>> {
    const MAX_CONTENT_CID_TEXT_BYTES: usize = 512;
    if raw.is_empty() || raw.len() > MAX_CONTENT_CID_TEXT_BYTES {
        eyre::bail!(
            "SoraFS content CID must contain between 1 and {MAX_CONTENT_CID_TEXT_BYTES} bytes"
        );
    }
    let cid = decode_content_cid(raw)
        .ok_or_else(|| eyre::eyre!("decode published Inrou guest-image SoraFS content CID"))?;
    if encode_content_cid(&cid) != raw {
        eyre::bail!("SoraFS content CID must use exact canonical lowercase multibase base32");
    }
    Ok(cid)
}
#[cfg(any(target_os = "linux", test))]
fn canonical_inrou_bundle_member_components(declared_path: &str) -> eyre::Result<Vec<String>> {
    const MAX_PATH_BYTES: usize = 256;
    if declared_path.len() > MAX_PATH_BYTES {
        eyre::bail!(
            "Inrou bundle member `{declared_path}` exceeds the {MAX_PATH_BYTES}-byte portable path bound"
        );
    }
    let relative = declared_path
        .strip_prefix('/')
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| {
            eyre::eyre!(
                "Inrou bundle member `{declared_path}` must be a nonempty canonical absolute path"
            )
        })?;
    let components = relative
        .split('/')
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if components.is_empty() || components.len() > SORA_INROU_PORTABLE_PATH_MAX_COMPONENTS_V1 {
        eyre::bail!("Inrou bundle member `{declared_path}` exceeds the portable component bound");
    }
    if components
        .iter()
        .any(|component| !is_portable_inrou_member_component(component) || component.len() > 255)
    {
        eyre::bail!("Inrou bundle member `{declared_path}` contains a nonportable path component");
    }
    if format!("/{}", components.join("/")) != declared_path {
        eyre::bail!("Inrou bundle member `{declared_path}` is not in canonical path form");
    }
    Ok(components)
}
fn canonical_published_inrou_member_components(declared_path: &str) -> eyre::Result<Vec<String>> {
    const MAX_COMPONENT_BYTES: usize = 255;
    const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
    let relative = declared_path
        .strip_prefix("/inrou/")
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| {
            eyre::eyre!(
                "published Inrou guest-image member `{declared_path}` must live under `/inrou/`"
            )
        })?;
    if relative.len() > MAX_RELATIVE_PATH_BYTES {
        eyre::bail!(
            "published Inrou guest-image member `{declared_path}` exceeds the portable path bound"
        );
    }
    let components = relative
        .split('/')
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if components.is_empty() || components.len() > SORA_INROU_PORTABLE_PATH_MAX_COMPONENTS_V1 {
        eyre::bail!(
            "published Inrou guest-image member `{declared_path}` exceeds the portable component bound"
        );
    }
    for component in &components {
        if !is_portable_inrou_member_component(component) || component.len() > MAX_COMPONENT_BYTES {
            eyre::bail!(
                "published Inrou guest-image member `{declared_path}` contains a nonportable path component"
            );
        }
    }
    if format!("/inrou/{}", components.join("/")) != declared_path {
        eyre::bail!(
            "published Inrou guest-image member `{declared_path}` is not in canonical path form"
        );
    }
    Ok(components)
}
fn is_portable_inrou_member_component(component: &str) -> bool {
    if !component.is_ascii()
        || component.is_empty()
        || component == "."
        || component == ".."
        || component
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
        || component.ends_with('.')
    {
        return false;
    }
    let Some(basename) = component.split('.').next() else {
        return false;
    };
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
        .iter()
        .any(|reserved| basename.eq_ignore_ascii_case(reserved))
    {
        return false;
    }
    if let (Some(prefix), Some(suffix)) = (basename.get(..3), basename.get(3..)) {
        let reserved_prefix =
            prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT");
        if reserved_prefix && suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9') {
            return false;
        }
    }
    true
}
fn validate_published_inrou_guest_image_files(
    plan: &SoracloudRuntimeInrouPlan,
    files: &[SorafsHydratedFileLayout],
) -> eyre::Result<()> {
    let mut expected = BTreeSet::new();
    let mut portable_collision_keys = BTreeSet::new();
    for declared_path in [
        Some(plan.kernel_image_path.as_str()),
        Some(plan.rootfs_image_path.as_str()),
        plan.initrd_image_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let components = canonical_published_inrou_member_components(declared_path)?;
        if !portable_collision_keys.insert(
            components
                .iter()
                .map(|component| component.to_ascii_lowercase())
                .collect::<Vec<_>>(),
        ) {
            eyre::bail!(
                "published Inrou guest-image manifest contains path members that collide on portable filesystems"
            );
        }
        if !expected.insert(components) {
            eyre::bail!(
                "published Inrou guest-image manifest repeats required member `{declared_path}`"
            );
        }
    }
    let actual = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if actual.len() != files.len() || actual != expected {
        eyre::bail!(
            "published Inrou guest-image artifact must contain exactly the selected image kernel, rootfs, and optional initrd members"
        );
    }
    Ok(())
}
fn validate_remote_hydration_file_plan(
    plan: &RemoteHydrationPlan,
    car_plan: &CarBuildPlan,
) -> eyre::Result<()> {
    if plan.files.len() != car_plan.files.len() {
        eyre::bail!("remote Soracloud file plan length does not match canonical CAR layout");
    }
    let mut expected_offset = 0_u64;
    for (index, (remote, canonical)) in plan.files.iter().zip(&car_plan.files).enumerate() {
        if remote.path != canonical.path
            || remote.size != canonical.size
            || remote.first_chunk != canonical.first_chunk
            || remote.chunk_count != canonical.chunk_count
        {
            eyre::bail!(
                "remote Soracloud file {index} does not match the reconstructed canonical CAR plan"
            );
        }
        if remote.offset != expected_offset {
            eyre::bail!(
                "remote Soracloud file {index} offset {} does not match canonical CAR layout offset {expected_offset}",
                remote.offset
            );
        }
        expected_offset = expected_offset
            .checked_add(canonical.size)
            .ok_or_else(|| eyre::eyre!("remote Soracloud canonical file offset overflow"))?;
    }
    if expected_offset != car_plan.content_length {
        eyre::bail!(
            "remote Soracloud file plan length does not cover the canonical CAR payload exactly"
        );
    }
    Ok(())
}
#[cfg(test)]
fn canonical_remote_hydration_file_layouts(
    plan: &RemoteHydrationPlan,
    car_plan: &CarBuildPlan,
) -> eyre::Result<Vec<SorafsHydratedFileLayout>> {
    validate_remote_hydration_file_plan(plan, car_plan)?;
    let mut offset = 0_u64;
    car_plan
        .files
        .iter()
        .map(|file| {
            let layout = SorafsHydratedFileLayout {
                path: file.path.clone(),
                offset,
                size: file.size,
            };
            offset = offset
                .checked_add(file.size)
                .ok_or_else(|| eyre::eyre!("remote Soracloud canonical file offset overflow"))?;
            Ok(layout)
        })
        .collect()
}
#[derive(Debug)]
struct SorafsStreamMaterializationFile {
    target: PathBuf,
    offset: u64,
    size: u64,
}
fn plan_operator_preseed_sorafs_files(
    files: &[SorafsHydratedFileLayout],
    target_root: &Path,
    content_length: u64,
    maximum_files: u32,
    maximum_total_bytes: u64,
) -> eyre::Result<Vec<SorafsStreamMaterializationFile>> {
    if files.is_empty() {
        eyre::bail!("operator-preseed SoraFS directory artifact did not declare any files");
    }
    let maximum_files = usize::try_from(maximum_files)
        .wrap_err("convert operator-preseed SoraFS materialization file limit")?;
    if files.len() > maximum_files {
        eyre::bail!(
            "operator-preseed SoraFS directory artifact declares {} files, above the configured limit of {maximum_files}",
            files.len()
        );
    }
    if content_length == 0 || content_length > maximum_total_bytes {
        eyre::bail!(
            "operator-preseed SoraFS directory artifact length {content_length} is outside the configured materialization byte budget of {maximum_total_bytes} bytes"
        );
    }
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(files.len())
        .wrap_err("reserve operator-preseed SoraFS materialization plan")?;
    let mut targets = BTreeSet::new();
    for file in files {
        if file.size == 0 {
            eyre::bail!(
                "operator-preseed SoraFS file `{}` must not be empty",
                file.path.join("/")
            );
        }
        let end = file.offset.checked_add(file.size).ok_or_else(|| {
            eyre::eyre!(
                "operator-preseed SoraFS file `{}` range overflows u64",
                file.path.join("/")
            )
        })?;
        if end > content_length {
            eyre::bail!(
                "operator-preseed SoraFS file `{}` range {}..{} exceeds payload length {content_length}",
                file.path.join("/"),
                file.offset,
                end
            );
        }
        let target = sorafs_hydrated_file_target(target_root, &file.path)?;
        if !targets.insert(target.clone()) {
            eyre::bail!(
                "operator-preseed SoraFS directory artifact repeats file path `{}`",
                file.path.join("/")
            );
        }
        planned.push(SorafsStreamMaterializationFile {
            target,
            offset: file.offset,
            size: file.size,
        });
    }
    planned.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then_with(|| left.size.cmp(&right.size))
            .then_with(|| left.target.cmp(&right.target))
    });
    let mut payload_cursor = 0_u64;
    for file in &planned {
        if file.offset != payload_cursor {
            eyre::bail!(
                "operator-preseed SoraFS file ranges are not an exact contiguous payload partition"
            );
        }
        payload_cursor = payload_cursor
            .checked_add(file.size)
            .ok_or_else(|| eyre::eyre!("operator-preseed SoraFS payload range overflow"))?;
    }
    if payload_cursor != content_length {
        eyre::bail!("operator-preseed SoraFS file ranges do not cover the complete payload");
    }
    for target in &targets {
        let mut parent = target.parent();
        while let Some(candidate) = parent {
            if candidate == target_root {
                break;
            }
            if targets.contains(candidate) {
                eyre::bail!(
                    "operator-preseed SoraFS directory artifact uses a file as another file's parent"
                );
            }
            parent = candidate.parent();
        }
    }
    Ok(planned)
}
#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn open_or_create_inrou_directory_chain(
    root: &PinnedInrouDirectory,
    components: &[&OsStr],
) -> io::Result<PinnedInrouDirectory> {
    let mut current = root.try_clone()?;
    for component in components {
        current = current.open_or_create_child_directory(component, 0o755)?;
    }
    Ok(current)
}

#[cfg(unix)]
#[cfg(any(target_os = "linux", test))]
fn materialize_operator_preseed_sorafs_files(
    store: &StorageBackend,
    manifest: &StoredManifest,
    files: &[SorafsHydratedFileLayout],
    target_root: &PinnedInrouDirectory,
    maximum_files: u32,
    maximum_total_bytes: u64,
) -> eyre::Result<()> {
    let planned = plan_operator_preseed_sorafs_files(
        files,
        target_root.path(),
        manifest.content_length(),
        maximum_files,
        maximum_total_bytes,
    )?;
    let mut payload_hasher = blake3::Hasher::new();
    for planned_file in &planned {
        let relative = planned_file
            .target
            .strip_prefix(target_root.path())
            .map_err(|_| {
                eyre::eyre!("operator-preseed materialization target escaped its pinned root")
            })?;
        let components = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(component) => Ok(component),
                _ => Err(eyre::eyre!(
                    "operator-preseed materialization target is not canonical"
                )),
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let (leaf, parents) = components.split_last().ok_or_else(|| {
            eyre::eyre!("operator-preseed materialization target has no file name")
        })?;
        let parent = open_or_create_inrou_directory_chain(target_root, parents)?;
        match rustix::fs::statat(
            &parent.directory,
            *leaf,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(named) => {
                if rustix::fs::FileType::from_raw_mode(named.st_mode)
                    != rustix::fs::FileType::RegularFile
                {
                    eyre::bail!(
                        "operator-preseed materialization target {} is not a regular file",
                        planned_file.target.display()
                    );
                }
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(io::Error::from(error))
                    .wrap_err_with(|| format!("inspect {}", planned_file.target.display()));
            }
        }
        write_inrou_atomic_file_at(&parent, leaf, true, |file| {
            let end = planned_file
                .offset
                .checked_add(planned_file.size)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "operator-preseed materialization range overflow",
                    )
                })?;
            let mut cursor = planned_file.offset;
            while cursor < end {
                let remaining = end - cursor;
                let read_len =
                    usize::try_from(remaining.min(SORACLOUD_LOCAL_HYDRATION_STREAM_CHUNK_BYTES))
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "operator-preseed read length does not fit this host",
                            )
                        })?;
                let chunk = store
                    .read_payload_range(manifest.manifest_id(), cursor, read_len)
                    .map_err(|error| {
                        io::Error::other(format!(
                            "read chunk-backed operator-preseed payload at {cursor}: {error}"
                        ))
                    })?;
                if chunk.len() != read_len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "operator-preseed payload range was truncated",
                    ));
                }
                payload_hasher.update(&chunk);
                file.write_all(&chunk)?;
                cursor = cursor
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "operator-preseed read length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "operator-preseed payload cursor overflow",
                        )
                    })?;
            }
            Ok(((), planned_file.size))
        })
        .wrap_err_with(|| format!("stream {}", planned_file.target.display()))?;
    }
    if payload_hasher.finalize().as_bytes() != manifest.payload_digest() {
        eyre::bail!(
            "operator-preseed SoraFS guest-image payload does not match admitted storage metadata"
        );
    }
    target_root.directory.sync_all()?;
    Ok(())
}
#[cfg(test)]
fn materialize_sorafs_payload_files(
    payload: &[u8],
    files: &[SorafsHydratedFileLayout],
    target_root: &Path,
    maximum_files: u32,
    maximum_file_bytes: u64,
    maximum_total_bytes: u64,
) -> eyre::Result<()> {
    if files.is_empty() {
        eyre::bail!("published SoraFS directory artifact did not declare any files");
    }
    let maximum_files =
        usize::try_from(maximum_files).wrap_err("convert SoraFS materialization file limit")?;
    if files.len() > maximum_files {
        eyre::bail!(
            "published SoraFS directory artifact declares {} files, above the configured limit of {maximum_files}",
            files.len()
        );
    }
    if u64::try_from(payload.len()).unwrap_or(u64::MAX) > maximum_total_bytes {
        eyre::bail!(
            "published SoraFS directory artifact exceeds the configured materialization byte limit"
        );
    }
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(files.len())
        .wrap_err("reserve SoraFS materialization plan")?;
    let mut targets = BTreeSet::new();
    for file in files {
        if file.size > maximum_file_bytes {
            eyre::bail!(
                "published SoraFS file `{}` exceeds the configured per-file byte limit",
                file.path.join("/")
            );
        }
        let start = usize::try_from(file.offset).wrap_err_with(|| {
            format!(
                "convert published SoraFS file `{}` offset to usize",
                file.path.join("/")
            )
        })?;
        let size = usize::try_from(file.size).wrap_err_with(|| {
            format!(
                "convert published SoraFS file `{}` size to usize",
                file.path.join("/")
            )
        })?;
        let end = start.checked_add(size).ok_or_else(|| {
            eyre::eyre!(
                "published SoraFS file `{}` range overflows host usize",
                file.path.join("/")
            )
        })?;
        if end > payload.len() {
            eyre::bail!(
                "published SoraFS file `{}` range {}..{} exceeds payload length {}",
                file.path.join("/"),
                start,
                end,
                payload.len()
            );
        }
        let target = sorafs_hydrated_file_target(target_root, &file.path)?;
        if !targets.insert(target.clone()) {
            eyre::bail!(
                "published SoraFS directory artifact repeats file path `{}`",
                file.path.join("/")
            );
        }
        planned.push(SorafsMaterializationFile { target, start, end });
    }
    planned.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| left.target.cmp(&right.target))
    });
    let mut payload_cursor = 0_usize;
    for file in &planned {
        if file.start != payload_cursor {
            eyre::bail!(
                "published SoraFS directory artifact file ranges are not an exact contiguous payload partition"
            );
        }
        payload_cursor = file.end;
    }
    if payload_cursor != payload.len() {
        eyre::bail!(
            "published SoraFS directory artifact file ranges do not cover the complete payload"
        );
    }
    for target in &targets {
        let mut parent = target.parent();
        while let Some(candidate) = parent {
            if candidate == target_root {
                break;
            }
            if targets.contains(candidate) {
                eyre::bail!(
                    "published SoraFS directory artifact uses a file as another file's parent"
                );
            }
            parent = candidate.parent();
        }
    }
    materialize_sorafs_directory_transaction(payload, &planned, target_root, maximum_total_bytes)
}
#[cfg(test)]
#[derive(Debug)]
struct SorafsMaterializationFile {
    target: PathBuf,
    start: usize,
    end: usize,
}
#[cfg(test)]
fn materialize_sorafs_directory_transaction(
    payload: &[u8],
    planned: &[SorafsMaterializationFile],
    target_root: &Path,
    maximum_existing_bytes: u64,
) -> eyre::Result<()> {
    let parent = target_root
        .parent()
        .ok_or_else(|| eyre::eyre!("SoraFS materialization root must have a parent"))?;
    let root_name = target_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre::eyre!("SoraFS materialization root must use valid UTF-8"))?;
    ensure_existing_directory_is_not_symlink(parent, "SoraFS materialization parent")?;
    let payload_digest_hex = hex::encode(blake3::hash(payload).as_bytes());
    let transaction_suffix = &payload_digest_hex[..16];
    let staging_root = parent.join(format!(".{root_name}.sorafs-stage-{transaction_suffix}"));
    let backup_root = parent.join(format!(".{root_name}.sorafs-backup-{transaction_suffix}"));
    recover_sorafs_materialization_swap(
        payload,
        planned,
        target_root,
        &staging_root,
        &backup_root,
        parent,
    )?;
    fs::create_dir(&staging_root)
        .wrap_err_with(|| format!("create SoraFS staging root {}", staging_root.display()))?;
    let transaction_result = (|| -> eyre::Result<()> {
        if target_root.exists() {
            ensure_existing_directory_is_not_symlink(
                target_root,
                "existing SoraFS materialization root",
            )?;
            let maximum_entries = planned.len().saturating_mul(8).max(1_024);
            let mut copied_entries = 0_usize;
            let mut copied_bytes = 0_u64;
            copy_sorafs_materialization_tree(
                target_root,
                &staging_root,
                maximum_entries,
                maximum_existing_bytes,
                &mut copied_entries,
                &mut copied_bytes,
            )?;
        }
        for file in planned {
            let relative = file.target.strip_prefix(target_root).map_err(|_| {
                eyre::eyre!("SoraFS materialization target escaped its declared root")
            })?;
            let staged_target = staging_root.join(relative);
            if let Some(parent) = staged_target.parent() {
                fs::create_dir_all(parent)
                    .wrap_err_with(|| format!("create {}", parent.display()))?;
            }
            write_bytes_atomic(&staged_target, &payload[file.start..file.end])
                .wrap_err_with(|| format!("stage {}", staged_target.display()))?;
            fs::File::open(&staged_target)
                .and_then(|file| file.sync_all())
                .wrap_err_with(|| format!("sync {}", staged_target.display()))?;
        }
        sync_directory_if_supported(&staging_root)?;
        if target_root.exists() {
            fs::rename(target_root, &backup_root).wrap_err_with(|| {
                format!(
                    "move existing SoraFS materialization {} to recovery backup {}",
                    target_root.display(),
                    backup_root.display()
                )
            })?;
            sync_directory_if_supported(parent)?;
            if let Err(error) = fs::rename(&staging_root, target_root) {
                let restore_result = fs::rename(&backup_root, target_root);
                return match restore_result {
                    Ok(()) => Err(error).wrap_err_with(|| {
                        format!(
                            "install staged SoraFS materialization {}",
                            target_root.display()
                        )
                    }),
                    Err(restore_error) => Err(eyre::eyre!(
                        "failed to install staged SoraFS materialization ({error}) and failed to restore its backup ({restore_error})"
                    )),
                };
            }
            sync_directory_if_supported(parent)?;
            fs::remove_dir_all(&backup_root).wrap_err_with(|| {
                format!(
                    "remove committed SoraFS materialization backup {}",
                    backup_root.display()
                )
            })?;
        } else {
            fs::rename(&staging_root, target_root).wrap_err_with(|| {
                format!(
                    "install staged SoraFS materialization {}",
                    target_root.display()
                )
            })?;
        }
        sync_directory_if_supported(parent)?;
        Ok(())
    })();
    if transaction_result.is_err() && staging_root.exists() {
        remove_owned_materialization_directory(&staging_root)?;
    }
    transaction_result
}
#[cfg(test)]
fn recover_sorafs_materialization_swap(
    payload: &[u8],
    planned: &[SorafsMaterializationFile],
    target_root: &Path,
    staging_root: &Path,
    backup_root: &Path,
    parent: &Path,
) -> eyre::Result<()> {
    if backup_root.exists() {
        ensure_existing_directory_is_not_symlink(
            backup_root,
            "SoraFS materialization recovery backup",
        )?;
        if target_root.exists() {
            ensure_existing_directory_is_not_symlink(
                target_root,
                "recovered SoraFS materialization root",
            )?;
            if !sorafs_materialization_matches(payload, planned, target_root)? {
                eyre::bail!(
                    "SoraFS materialization has both a recovery backup and an unverified live root"
                );
            }
            remove_owned_materialization_directory(backup_root)?;
        } else {
            fs::rename(backup_root, target_root).wrap_err_with(|| {
                format!(
                    "restore interrupted SoraFS materialization backup {}",
                    backup_root.display()
                )
            })?;
        }
        sync_directory_if_supported(parent)?;
    }
    if staging_root.exists() {
        remove_owned_materialization_directory(staging_root)?;
        sync_directory_if_supported(parent)?;
    }
    Ok(())
}
#[cfg(test)]
fn sorafs_materialization_matches(
    payload: &[u8],
    planned: &[SorafsMaterializationFile],
    target_root: &Path,
) -> eyre::Result<bool> {
    for file in planned {
        let relative = file
            .target
            .strip_prefix(target_root)
            .map_err(|_| eyre::eyre!("SoraFS recovery target escaped its declared root"))?;
        let target = target_root.join(relative);
        let metadata = match fs::symlink_metadata(&target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).wrap_err_with(|| format!("inspect {}", target.display()));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(false);
        }
        if !soracloud_file_matches_bytes(&target, &payload[file.start..file.end])
            .wrap_err_with(|| format!("compare {}", target.display()))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
#[cfg(test)]
fn soracloud_file_matches_bytes(path: &Path, expected: &[u8]) -> io::Result<bool> {
    let (mut file, fingerprint) =
        open_soracloud_regular_file_no_follow(path, "existing SoraFS materialization member")?;
    if fingerprint.len() != u64::try_from(expected.len()).unwrap_or(u64::MAX) {
        return Ok(false);
    }
    let mut compared = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    while compared < expected.len() {
        let read_capacity = buffer.len().min(expected.len() - compared);
        let read = file.read(&mut buffer[..read_capacity])?;
        if read == 0 || buffer[..read] != expected[compared..compared + read] {
            return Ok(false);
        }
        compared += read;
    }
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Ok(false);
    }
    let opened_after = file.metadata()?;
    let named_after = fs::symlink_metadata(path)?;
    Ok(same_soracloud_regular_file(&fingerprint, &opened_after)
        && same_soracloud_regular_file(&opened_after, &named_after))
}
#[cfg(test)]
fn copy_sorafs_materialization_tree(
    source: &Path,
    destination: &Path,
    maximum_entries: usize,
    maximum_bytes: u64,
    copied_entries: &mut usize,
    copied_bytes: &mut u64,
) -> eyre::Result<()> {
    for entry in
        fs::read_dir(source).wrap_err_with(|| format!("read directory {}", source.display()))?
    {
        let entry = entry.wrap_err_with(|| format!("read entry under {}", source.display()))?;
        *copied_entries = copied_entries
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("existing SoraFS materialization entry count overflow"))?;
        if *copied_entries > maximum_entries {
            eyre::bail!(
                "existing SoraFS materialization exceeds the bounded entry count of {maximum_entries}"
            );
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .wrap_err_with(|| format!("inspect {}", source_path.display()))?;
        if metadata.file_type().is_symlink() {
            eyre::bail!(
                "existing SoraFS materialization contains forbidden symlink {}",
                source_path.display()
            );
        }
        if metadata.is_dir() {
            fs::create_dir(&destination_path)
                .wrap_err_with(|| format!("create {}", destination_path.display()))?;
            copy_sorafs_materialization_tree(
                &source_path,
                &destination_path,
                maximum_entries,
                maximum_bytes,
                copied_entries,
                copied_bytes,
            )?;
        } else if metadata.is_file() {
            *copied_bytes = copied_bytes.checked_add(metadata.len()).ok_or_else(|| {
                eyre::eyre!("existing SoraFS materialization byte count overflow")
            })?;
            if *copied_bytes > maximum_bytes {
                eyre::bail!(
                    "existing SoraFS materialization exceeds the bounded byte count of {maximum_bytes}"
                );
            }
            fs::copy(&source_path, &destination_path).wrap_err_with(|| {
                format!(
                    "copy existing SoraFS materialization {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            fs::File::open(&destination_path)
                .and_then(|file| file.sync_all())
                .wrap_err_with(|| format!("sync {}", destination_path.display()))?;
        } else {
            eyre::bail!(
                "existing SoraFS materialization contains unsupported filesystem entry {}",
                source_path.display()
            );
        }
    }
    sync_directory_if_supported(destination)?;
    Ok(())
}
#[cfg(test)]
fn ensure_existing_directory_is_not_symlink(path: &Path, label: &str) -> eyre::Result<()> {
    let metadata = fs::symlink_metadata(path).wrap_err_with(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        eyre::bail!("{label} must be an existing directory and must not be a symlink");
    }
    Ok(())
}
#[cfg(test)]
fn remove_owned_materialization_directory(path: &Path) -> eyre::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("inspect owned SoraFS transaction path {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        eyre::bail!(
            "owned SoraFS transaction path {} is not a real directory",
            path.display()
        );
    }
    fs::remove_dir_all(path)
        .wrap_err_with(|| format!("remove owned SoraFS transaction path {}", path.display()))
}
#[cfg(all(test, unix))]
fn sync_directory_if_supported(path: &Path) -> eyre::Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .wrap_err_with(|| format!("sync directory {}", path.display()))
}
#[cfg(all(test, not(unix)))]
fn sync_directory_if_supported(_path: &Path) -> eyre::Result<()> {
    Ok(())
}
fn sorafs_hydrated_file_target(root: &Path, components: &[String]) -> eyre::Result<PathBuf> {
    if components.is_empty() {
        eyre::bail!("published SoraFS directory artifact file path must not be empty");
    }
    let mut path = root.to_path_buf();
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('/')
            || component.contains('\\')
            || component.contains('\0')
            || component.chars().any(char::is_control)
            || component.len() > 255
        {
            eyre::bail!(
                "published SoraFS directory artifact contains unsafe path component `{component}`"
            );
        }
        path.push(component);
    }
    Ok(path)
}
fn collect_remote_hydration_sources(
    view: &StateView<'_>,
    state: &State,
) -> Result<Vec<RemoteHydrationSource>, iroha_core::state::DaIndexHydrationError> {
    let mut sources =
        BTreeMap::<(Reverse<u64>, Reverse<u64>, String, String), RemoteHydrationSource>::new();
    for (_order_id, record) in view.world().replication_orders().iter() {
        let iroha_data_model::sorafs::pin_registry::ReplicationOrderStatus::Completed(
            completed_epoch,
        ) = record.status
        else {
            continue;
        };
        if !manifest_is_committed(view, state, record.manifest_digest.as_bytes())? {
            continue;
        }
        if record.canonical_order.is_empty()
            || record.canonical_order.len() > SORAFS_REPLICATION_ORDER_MAX_CANONICAL_BYTES_V1
        {
            iroha_logger::warn!(
                manifest_digest = %hex::encode(record.manifest_digest.as_bytes()),
                canonical_bytes = record.canonical_order.len(),
                "rejected oversized canonical SoraFS replication order during Soracloud hydration"
            );
            continue;
        }
        let order = match norito::decode_from_bytes_with_limits::<ReplicationOrderV1>(
            &record.canonical_order,
            SORAFS_REPLICATION_ORDER_DECODE_LIMITS_V1,
        ) {
            Ok(order) => order,
            Err(error) => {
                iroha_logger::warn!(
                    ?error,
                    manifest_digest = %hex::encode(record.manifest_digest.as_bytes()),
                    "failed to decode canonical SoraFS replication order during Soracloud hydration"
                );
                continue;
            }
        };
        if let Err(error) = order.validate() {
            iroha_logger::warn!(
                ?error,
                manifest_digest = %hex::encode(record.manifest_digest.as_bytes()),
                "rejected invalid canonical SoraFS replication order during Soracloud hydration"
            );
            continue;
        }
        let Ok(canonical_order) = norito::to_bytes(&order) else {
            continue;
        };
        if canonical_order != record.canonical_order
            || order.order_id != *record.order_id.as_bytes()
            || order.manifest_digest != *record.manifest_digest.as_bytes()
            || order.manifest_cid.as_slice() != record.manifest_root_cid.as_bytes()
        {
            iroha_logger::warn!(
                manifest_digest = %hex::encode(record.manifest_digest.as_bytes()),
                "rejected substituted canonical SoraFS replication order during Soracloud hydration"
            );
            continue;
        }
        let mut provider_ids = BTreeSet::new();
        for completion in record.provider_completions.iter().filter(|completion| {
            completion.assignment_revision == record.assignment_revision
                && completion.completion_epoch >= record.issued_epoch
                && completion.completion_epoch <= completed_epoch
                && completion.completion_authority.is_valid()
                && completion.finalized_anchor.is_valid()
                && order
                    .assignments
                    .iter()
                    .any(|assignment| assignment.provider_id == *completion.provider_id.as_bytes())
        }) {
            provider_ids.insert(*completion.provider_id.as_bytes());
            if provider_ids.len() > SORACLOUD_REMOTE_HYDRATION_MAX_PROVIDERS_PER_SOURCE {
                let _ = provider_ids.pop_last();
            }
        }
        if provider_ids.is_empty() {
            continue;
        }
        let manifest_digest_hex = hex::encode(record.manifest_digest.as_bytes());
        let manifest_cid_hex = hex::encode(&order.manifest_cid);
        let chunker_handle = Some(order.chunking_profile.clone());
        let key = (
            Reverse(completed_epoch),
            Reverse(record.issued_epoch),
            manifest_digest_hex.clone(),
            manifest_cid_hex.clone(),
        );
        {
            let entry = sources.entry(key).or_insert_with(|| RemoteHydrationSource {
                manifest_digest_hex,
                manifest_cid_hex,
                chunker_handle,
                provider_ids: Vec::new(),
            });
            for provider_id in provider_ids {
                if let Err(index) = entry.provider_ids.binary_search(&provider_id) {
                    entry.provider_ids.insert(index, provider_id);
                    if entry.provider_ids.len()
                        > SORACLOUD_REMOTE_HYDRATION_MAX_PROVIDERS_PER_SOURCE
                    {
                        let _ = entry.provider_ids.pop();
                    }
                }
            }
        }
        if sources.len() > SORACLOUD_REMOTE_HYDRATION_MAX_SOURCES {
            let _ = sources.pop_last();
        }
    }
    Ok(sources.into_values().collect())
}
fn manifest_is_committed(
    view: &StateView<'_>,
    state: &State,
    manifest_digest: &[u8; 32],
) -> Result<bool, iroha_core::state::DaIndexHydrationError> {
    let digest = ManifestDigest::new(*manifest_digest);
    let has_active_pin = view
        .world()
        .pin_manifests()
        .get(&digest)
        .is_some_and(|record| record.status.is_active());
    Ok(has_active_pin || state.find_da_commitment_by_manifest(&digest)?.is_some())
}
fn sanitize_path_component(raw: &str) -> String {
    raw.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect()
}
fn storage_path_component(raw: &str) -> String {
    const READABLE_PREFIX_CHARS: usize = 32;
    let readable = sanitize_path_component(raw)
        .chars()
        .take(READABLE_PREFIX_CHARS)
        .collect::<String>();
    let readable = readable.trim_matches('.');
    let readable = if readable.is_empty() {
        "item"
    } else {
        readable
    };
    format!(
        "sc-{readable}-{}",
        hex::encode(Hash::new(raw.as_bytes()).as_ref())
    )
}
fn build_effective_service_environment(
    bundle: &SoraDeploymentBundleV1,
    deployment: &SoraServiceDeploymentStateV1,
) -> eyre::Result<BTreeMap<String, String>> {
    let mut effective_env = bundle.container.env.clone();
    for export in &bundle.container.config_exports {
        let entry = deployment
            .service_configs
            .get(export.config_name())
            .ok_or_else(|| {
                eyre::eyre!(
                    "service `{}` revision `{}` config export references missing authoritative config `{}`",
                    bundle.service.service_name,
                    bundle.service.service_version,
                    export.config_name()
                )
            })?;
        if let SoraConfigExportTargetV1::Env(var_name) = &export.target {
            effective_env.insert(var_name.clone(), entry.value_json.get().clone());
        }
    }
    Ok(effective_env)
}
fn sanitized_relative_export_path(relative_path: &str) -> Result<PathBuf, ()> {
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.ends_with('/')
        || relative_path.contains('\\')
    {
        return Err(());
    }
    let mut path = PathBuf::new();
    for component in relative_path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(());
        }
        path.push(component);
    }
    Ok(path)
}
fn prune_nested_directory_tree(
    root: &Path,
    desired: &BTreeMap<String, BTreeSet<String>>,
) -> eyre::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for service_entry in fs::read_dir(root).wrap_err_with(|| format!("read {}", root.display()))? {
        let service_entry = service_entry?;
        if !service_entry.file_type()?.is_dir() {
            continue;
        }
        let service_name = service_entry.file_name().to_string_lossy().into_owned();
        let service_path = service_entry.path();
        let Some(desired_versions) = desired.get(&service_name) else {
            fs::remove_dir_all(&service_path)
                .wrap_err_with(|| format!("remove stale {}", service_path.display()))?;
            continue;
        };
        for version_entry in fs::read_dir(&service_path)
            .wrap_err_with(|| format!("read {}", service_path.display()))?
        {
            let version_entry = version_entry?;
            if !version_entry.file_type()?.is_dir() {
                continue;
            }
            let version_name = version_entry.file_name().to_string_lossy().into_owned();
            if !desired_versions.contains(&version_name) {
                let version_path = version_entry.path();
                fs::remove_dir_all(&version_path)
                    .wrap_err_with(|| format!("remove stale {}", version_path.display()))?;
            }
        }
        let mut remaining = fs::read_dir(&service_path)?;
        if remaining.next().is_none() {
            fs::remove_dir_all(&service_path)
                .wrap_err_with(|| format!("remove empty {}", service_path.display()))?;
        }
    }
    Ok(())
}
fn prune_flat_directory_tree(root: &Path, desired: &BTreeSet<String>) -> eyre::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).wrap_err_with(|| format!("read {}", root.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !desired.contains(&name) {
            let path = entry.path();
            fs::remove_dir_all(&path)
                .wrap_err_with(|| format!("remove stale {}", path.display()))?;
        }
    }
    Ok(())
}
static SORACLOUD_ATOMIC_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Debug, PartialEq, Eq)]
struct SoracloudAtomicFileIdentity {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    modified_nanoseconds: Option<u128>,
}
impl SoracloudAtomicFileIdentity {
    fn from_metadata(metadata: &fs::Metadata, path: &Path) -> io::Result<Self> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("atomic Soracloud file {} is not regular", path.display()),
            ));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "atomic Soracloud file {} must have one hard link, found {}",
                    path.display(),
                    metadata.nlink()
                ),
            ));
        }
        Ok(Self {
            bytes: metadata.len(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(not(unix))]
            modified_nanoseconds: metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })
    }
    fn same_file_as(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            let _ = other;
            true
        }
    }
}
fn write_json_atomic<T>(path: &Path, value: &T) -> io::Result<()>
where
    T: norito::json::JsonSerialize + ?Sized,
{
    let payload = norito::json::to_json(value)
        .map_err(|error| io::Error::other(format!("serialize json: {error}")))?;
    write_bytes_atomic(path, payload.as_bytes())
}
fn write_json_atomic_bounded<T>(
    path: &Path,
    value: &T,
    maximum_bytes: u64,
    label: &str,
) -> io::Result<()>
where
    T: norito::json::JsonSerialize + ?Sized,
{
    let payload = norito::json::to_json(value)
        .map_err(|error| io::Error::other(format!("serialize {label}: {error}")))?;
    if u64::try_from(payload.len()).unwrap_or(u64::MAX) > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "serialized {label} requires {} bytes, exceeding the {maximum_bytes}-byte limit",
                payload.len()
            ),
        ));
    }
    write_bytes_atomic(path, payload.as_bytes())
}
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_file(path, |file| {
        file.write_all(bytes)?;
        Ok(((), u64::try_from(bytes.len()).unwrap_or(u64::MAX)))
    })
}
fn write_atomic_file<T>(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<(T, u64)>,
) -> io::Result<T> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path must have a parent"))?;
    fs::create_dir_all(parent)?;
    let parent_before = fs::symlink_metadata(parent)?;
    if !parent_before.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "atomic Soracloud write parent {} is not a directory",
                parent.display()
            ),
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic Soracloud write path must have a file name",
        )
    })?;
    let file_name = file_name.to_string_lossy();
    let mut created = None;
    for _ in 0..128 {
        let sequence = SORACLOUD_ATOMIC_WRITE_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let tmp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&tmp_path) {
            Ok(file) => {
                created = Some((file, tmp_path));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let Some((mut file, tmp_path)) = created else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "exhausted exclusive temporary names for atomic Soracloud destination {}",
                path.display()
            ),
        ));
    };
    let created_identity =
        SoracloudAtomicFileIdentity::from_metadata(&file.metadata()?, &tmp_path)?;
    let result = (|| {
        let (value, expected_bytes) = write(&mut file)?;
        file.sync_all()?;
        let written_identity =
            SoracloudAtomicFileIdentity::from_metadata(&file.metadata()?, &tmp_path)?;
        if written_identity.bytes != expected_bytes
            || !written_identity.same_file_as(&created_identity)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "atomic Soracloud temporary file {} changed identity while being written",
                    tmp_path.display()
                ),
            ));
        }
        drop(file);
        fs::rename(&tmp_path, path)?;
        let installed =
            SoracloudAtomicFileIdentity::from_metadata(&fs::symlink_metadata(path)?, path)?;
        if installed != written_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "atomic Soracloud destination {} changed identity during installation",
                    path.display()
                ),
            ));
        }
        #[cfg(unix)]
        {
            let parent_after = fs::symlink_metadata(parent)?;
            if parent_before.dev() != parent_after.dev()
                || parent_before.ino() != parent_after.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "atomic Soracloud write parent {} changed identity",
                        parent.display()
                    ),
                ));
            }
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(value)
    })();
    if result.is_err()
        && let Ok(metadata) = fs::symlink_metadata(&tmp_path)
        && SoracloudAtomicFileIdentity::from_metadata(&metadata, &tmp_path)
            .is_ok_and(|identity| identity.same_file_as(&created_identity))
    {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}
fn reset_directory(root: &Path) -> io::Result<()> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::create_dir_all(root)?;
    Ok(())
}
fn write_service_config_materializations(
    version_dir: &Path,
    config_root: &Path,
    config_exports_root: &Path,
    effective_env_path: &Path,
    plan: &SoracloudRuntimeServicePlan,
    deployment: &SoraServiceDeploymentStateV1,
) -> eyre::Result<()> {
    reset_directory(config_root).wrap_err_with(|| format!("reset {}", config_root.display()))?;
    reset_directory(config_exports_root)
        .wrap_err_with(|| format!("reset {}", config_exports_root.display()))?;
    write_json_atomic(
        &version_dir.join("service_configs.json"),
        &deployment.service_configs,
    )
    .wrap_err_with(|| {
        format!(
            "write {}",
            version_dir.join("service_configs.json").display()
        )
    })?;
    write_json_atomic(effective_env_path, &plan.effective_env)
        .wrap_err_with(|| format!("write {}", effective_env_path.display()))?;
    for (config_name, entry) in &deployment.service_configs {
        let relative_path = sanitized_relative_material_path(config_name).map_err(|_| {
            eyre::eyre!("invalid authoritative service config name `{config_name}`")
        })?;
        write_bytes_atomic(
            &config_root.join(relative_path),
            entry.value_json.get().as_bytes(),
        )
        .wrap_err_with(|| {
            format!(
                "write materialized config `{config_name}` under {}",
                config_root.display()
            )
        })?;
    }
    for export in &plan.config_exports {
        let SoraConfigExportTargetV1::File(relative_path) = &export.target else {
            continue;
        };
        let entry = deployment
            .service_configs
            .get(export.config_name())
            .ok_or_else(|| {
                eyre::eyre!(
                    "service config export `{}` references missing authoritative config `{}`",
                    export.target_identifier(),
                    export.config_name()
                )
            })?;
        let relative_path = sanitized_relative_export_path(relative_path).map_err(|_| {
            eyre::eyre!(
                "invalid service config export file path `{relative_path}` for config `{}`",
                export.config_name()
            )
        })?;
        write_bytes_atomic(
            &config_exports_root.join(relative_path),
            entry.value_json.get().as_bytes(),
        )
        .wrap_err_with(|| {
            format!(
                "write exported config `{}` under {}",
                export.config_name(),
                config_exports_root.display()
            )
        })?;
    }
    Ok(())
}
fn write_service_secret_materializations(
    version_dir: &Path,
    secret_envelopes_root: &Path,
    deployment: &SoraServiceDeploymentStateV1,
) -> eyre::Result<()> {
    reset_directory(secret_envelopes_root)
        .wrap_err_with(|| format!("reset {}", secret_envelopes_root.display()))?;
    write_json_atomic(
        &version_dir.join("service_secret_envelopes.json"),
        &deployment.service_secrets,
    )
    .wrap_err_with(|| {
        format!(
            "write {}",
            version_dir.join("service_secret_envelopes.json").display()
        )
    })?;
    for (secret_name, entry) in &deployment.service_secrets {
        let relative_path = sanitized_relative_material_path(secret_name).map_err(|_| {
            eyre::eyre!("invalid authoritative service secret name `{secret_name}`")
        })?;
        write_json_atomic(&secret_envelopes_root.join(&relative_path), entry).wrap_err_with(
            || {
                format!(
                    "write materialized secret envelope `{secret_name}` under {}",
                    secret_envelopes_root.display()
                )
            },
        )?;
    }
    Ok(())
}
fn read_json_optional<T>(path: &Path, maximum_bytes: u64, label: &str) -> io::Result<Option<T>>
where
    T: norito::json::JsonDeserialize,
{
    let payload = match read_soracloud_regular_file_bounded(path, maximum_bytes, label) {
        Ok(payload) => payload,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} is empty: {}", path.display()),
        ));
    }
    norito::json::from_slice(&payload)
        .map(Some)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("deserialize json: {error}"),
            )
        })
}
#[cfg(test)]
#[path = "soracloud_runtime/tests.rs"]
mod tests;
