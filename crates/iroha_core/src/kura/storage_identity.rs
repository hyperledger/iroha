#[derive(Debug, Clone)]
struct StableCanonicalBlockStoreMetadata {
    data: StableSidecarMetadata,
    index: StableSidecarMetadata,
    hashes: StableSidecarMetadata,
    commit_marker: StableSidecarMetadata,
}
#[derive(Debug, Clone)]
struct StableSidecarDirectoryMetadata {
    expected_path: PathBuf,
    canonical_path: Option<PathBuf>,
    metadata: Option<SecureMetadata>,
}
#[derive(Debug, Clone)]
struct StableSidecarMetadata {
    canonical_path: PathBuf,
    file: SecureMetadata,
    directory: SecureMetadata,
}
#[derive(Debug)]
struct StableSidecarRead<B> {
    bytes: B,
    #[expect(
        dead_code,
        reason = "TODO: connect descriptor-bound progress publication and durability receipts; retain the original namespace identity checked by recovery controls"
    )]
    metadata: StableSidecarMetadata,
}
/// Exact directory generation covered by a completed progress-pair durability barrier.
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "TODO: connect descriptor-bound progress publication and durability receipts; retain the original namespace identity checked by recovery controls"
)]
struct ProgressDirectoryDurabilityMetadata {
    expected_path: PathBuf,
    canonical_path: PathBuf,
    entry_name: Option<std::ffi::OsString>,
    metadata: SecureMetadata,
}
#[derive(Debug)]
struct BoundProgressDirectory {
    expected_path: PathBuf,
    canonical_path: PathBuf,
    /// Entry name relative to the next bound ancestor; `None` only for Kura root.
    entry_name: Option<std::ffi::OsString>,
    file: std::fs::File,
    metadata: SecureMetadata,
}
#[derive(Debug)]
struct BoundProgressNamespace {
    data_path: PathBuf,
    index_path: PathBuf,
    /// Bound directories in durability order: immediate parent through Kura root.
    directories: Vec<BoundProgressDirectory>,
}

/// Match the native device bits exposed by `std::os::unix::fs::MetadataExt`.
///
/// Darwin's signed device IDs are sign-extended by the standard library, while
/// Linux exposes unsigned IDs. Widen first, then retain the low 64 bits so both
/// representations remain identical to the file metadata without numeric casts.
#[cfg(unix)]
pub(crate) fn unix_device_identity(device: rustix::fs::Dev) -> u64 {
    let bytes = i128::from(device).to_le_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(all(test, unix))]
#[test]
fn unix_device_identity_matches_native_metadata() {
    use std::os::unix::fs::MetadataExt as _;
    let file = tempfile::tempfile().expect("temporary file");
    let native = rustix::fs::fstat(&file).expect("native file identity");
    let metadata = file.metadata().expect("standard file identity");
    assert_eq!(unix_device_identity(native.st_dev), metadata.dev());
    assert_eq!(unix_device_identity(0), 0);
    assert_eq!(unix_device_identity(1), 1);
}

#[cfg(all(test, target_vendor = "apple"))]
#[test]
fn unix_device_identity_preserves_signed_device_bits() {
    assert_eq!(unix_device_identity(-1), u64::MAX);
    assert_eq!(unix_device_identity(i32::MIN), u64::MAX - 2_147_483_647);
}
