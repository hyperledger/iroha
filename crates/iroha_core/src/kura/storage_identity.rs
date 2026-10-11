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
struct StableSidecarDirectoryInventory {
    directory: StableSidecarDirectoryMetadata,
    files: BTreeMap<PathBuf, StableSidecarMetadata>,
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
    metadata: StableSidecarMetadata,
}
/// Exact directory generation covered by a completed progress-pair durability barrier.
#[derive(Debug, Clone)]
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
