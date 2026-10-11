//! Secure, deterministic planning for Musubi V1 source packages.
//!
//! This module deliberately starts from manifest-declared roots and additions. It does not
//! inventory the package directory and then subtract an ignore list. Callers are expected to
//! translate a validated `Musubi.toml` into [`PackageLayout`], pass the original manifest and
//! verification lock documents to [`plan_package`], and use the resulting immutable plan for a
//! clean compiler check and `SoraFS` CAR construction. Filesystem-backed planning is qualified on
//! native Unix and Windows through retained filesystem authority.
use crate::{
    lockfile::{MUSUBI_MAX_VERIFICATION_LOCK_BYTES_V1, render_verification_lock},
    manifest::Inheritable,
    workspace::WorkspaceMember,
};
pub use iroha_data_model::musubi::MusubiArtifactDescriptorV1;
use iroha_data_model::{
    musubi::{
        MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1, MusubiAbiBindingV1, MusubiArchiveCommitmentV1,
        MusubiContentDigestV1, MusubiDependencyReqV1, MusubiDescriptionV1, MusubiDocumentRefV1,
        MusubiKeywordV1, MusubiPublicationV1, MusubiRegistrySnapshotV1, MusubiReleaseIdV1,
        MusubiReleaseManifestV1, MusubiReleaseMetadataV1, MusubiResolutionProofV1,
        MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1,
        validate_musubi_portable_path_set_v1,
    },
    sorafs::pin_registry::{ChunkerProfileHandle, ManifestRootCid},
};
use iroha_model_base::name::Name;
use ivm::{SyscallPolicy, syscalls::compute_abi_hash};
#[cfg(all(test, unix))]
use norito::codec::Decode;
use norito::codec::Encode;
use sorafs_car::{
    CarBuildPlan, CarWriteStats, CarWriter, FileEntry, chunker_registry::default_descriptor,
    compute_chunk_plan_digest_sha3, compute_por_root,
};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt, fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    str::FromStr,
};
/// Maximum total bytes in a Musubi V1 normalized source tree.
pub const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes in a Musubi V1 `CARv2` archive.
pub const MAX_CAR_BYTES: u64 = 96 * 1024 * 1024;
/// Maximum number of regular files in a Musubi V1 source tree.
pub const MAX_SOURCE_FILES: usize = 4_096;
/// Maximum number of chunks in a Musubi V1 source CAR plan.
pub const MAX_SOURCE_CHUNKS: usize = 16_384;
const MANIFEST_PATH: &str = "Musubi.toml";
const VERIFICATION_LOCK_PATH: &str = "Musubi.lock";
const BUNDLE_RELEASE_PATH: &str = ".musubi/semantic-release.norito";
const BUNDLE_DESCRIPTOR_PATH: &str = ".musubi/artifact-descriptor.norito";
const BUNDLE_VERIFICATION_LOCK_PATH: &str = ".musubi/verification-lock.norito";
const MAX_PATH_COMPONENTS: usize = 64;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 4 * 1024;
// Count every directory entry, including empty and excluded directories, so a selected tree can
// never make the planner retain or recurse through an unbounded ambient namespace. This permits
// the full file ceiling even when every file has a distinct maximum-depth directory chain.
const MAX_SOURCE_ENTRIES: usize = MAX_SOURCE_FILES * MAX_PATH_COMPONENTS;
// `read_dir` names are retained only long enough to impose deterministic byte ordering. Keep one
// unusually wide selected directory from consuming the whole tree-wide traversal budget at once.
const MAX_DIRECTORY_ENTRIES: usize = MAX_SOURCE_FILES * 2;
const SOURCE_TREE_DOMAIN: &[u8] = b"musubi-source-tree-v1\0";
const ARTIFACT_DESCRIPTOR_DOMAIN: &[u8] = b"musubi-artifact-descriptor-v1\0";
const BUNDLE_DOMAIN: &[u8] = b"musubi-bundle-v1\0";
/// A manifest-derived positive selection of package files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageLayout {
    root: PathBuf,
    library: Option<PathBuf>,
    contracts: Vec<PathBuf>,
    tests: Vec<PathBuf>,
    readme: Option<PathBuf>,
    license: Option<PathBuf>,
    includes: Vec<PathBuf>,
    external: Vec<ExternalSelection>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalSelection {
    root: PathBuf,
    selector: PathBuf,
    shape: SelectionShape,
}
impl PackageLayout {
    /// Start a package layout rooted at `root` with no source selectors.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            library: None,
            contracts: Vec::new(),
            tests: Vec::new(),
            readme: None,
            license: None,
            includes: Vec::new(),
            external: Vec::new(),
        }
    }
    /// Return the package root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Set the declared library source directory.
    pub fn set_library(&mut self, path: impl Into<PathBuf>) {
        self.library = Some(path.into());
    }
    /// Add one declared local `.ko` contract source file.
    pub fn add_contract(&mut self, path: impl Into<PathBuf>) {
        self.contracts.push(path.into());
    }
    /// Add one declared test file or directory.
    pub fn add_test(&mut self, path: impl Into<PathBuf>) {
        self.tests.push(path.into());
    }
    /// Set the declared readme file.
    pub fn set_readme(&mut self, path: impl Into<PathBuf>) {
        self.readme = Some(path.into());
    }
    /// Set the declared license file.
    pub fn set_license(&mut self, path: impl Into<PathBuf>) {
        self.license = Some(path.into());
    }
    /// Add one explicit positive include file or directory.
    pub fn add_include(&mut self, path: impl Into<PathBuf>) {
        self.includes.push(path.into());
    }
    fn add_external(
        &mut self,
        root: impl Into<PathBuf>,
        selector: impl Into<PathBuf>,
        shape: SelectionShape,
    ) {
        self.external.push(ExternalSelection {
            root: root.into(),
            selector: selector.into(),
            shape,
        });
    }
}
/// One immutable file selected for a clean package tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFile {
    path: String,
    components: Vec<String>,
    bytes: Vec<u8>,
}
impl PlannedFile {
    /// Return the canonical portable archive path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Return the exact file payload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// A read-only inventory of selected source files, without registry or publication authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageInventory {
    files: Vec<PlannedFile>,
    source_bytes: u64,
}
impl PackageInventory {
    /// Return selected source files in canonical portable path order.
    #[must_use]
    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }
    /// Return the total selected source payload size.
    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
}
/// A bounded, byte-ordered package file plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackagePlan {
    files: Vec<PlannedFile>,
    source_bytes: u64,
}
impl PackagePlan {
    /// Return files in strict UTF-8 byte order by canonical portable path.
    #[must_use]
    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }
    /// Return the generated normalized verification lock bytes.
    #[must_use]
    pub fn verification_lock(&self) -> &[u8] {
        self.required_file(VERIFICATION_LOCK_PATH)
    }
    /// Return the canonicalized package manifest bytes.
    #[must_use]
    pub fn canonical_manifest(&self) -> &[u8] {
        self.required_file(MANIFEST_PATH)
    }
    /// Build deterministic source-tree, descriptor, and bundle commitment materials.
    ///
    /// # Errors
    ///
    /// Returns an error when `SoraFS` rejects a portable bundle path, the semantic manifest or
    /// exact verification lock is invalid, or their release and lock-digest bindings differ.
    pub fn commitment_materials(
        &self,
        semantic_release_manifest: &MusubiSemanticReleaseManifestV1,
        verification_lock: &MusubiVerificationLockV1,
    ) -> Result<PackageCommitments, PackageError> {
        validate_sorafs_bundle_paths(&self.files)?;
        validate_semantic_release_encoded_bound(semantic_release_manifest)?;
        let rendered_lock = render_verification_lock(verification_lock).map_err(|error| {
            PackageError::InvalidBundleBinding(format!(
                "typed verification lock cannot be rendered: {error}"
            ))
        })?;
        if self.verification_lock() != rendered_lock.as_bytes() {
            return Err(PackageError::InvalidBundleBinding(
                "source-tree and typed verification locks do not match".to_owned(),
            ));
        }
        let verification_lock_bytes = encode_verification_lock_bounded(verification_lock)?;
        semantic_release_manifest
            .validate_verification_lock(verification_lock)
            .map_err(|error| PackageError::InvalidBundleBinding(error.to_string()))?;
        let semantic_release_bytes = semantic_release_manifest.encode();
        let source_tree_material = source_tree_material(&self.files);
        let source_tree_digest =
            MusubiContentDigestV1::new(domain_digest(SOURCE_TREE_DOMAIN, &source_tree_material));
        let descriptor = MusubiArtifactDescriptorV1::new(
            semantic_release_manifest.semantic_digest(),
            source_tree_digest,
            verification_lock.digest(),
            self.source_bytes,
            u32::try_from(self.files.len()).expect("Musubi V1 file bound fits u32"),
        )
        .map_err(|error| PackageError::InvalidBundleBinding(error.to_string()))?;
        let descriptor_material = descriptor_commitment_material(&descriptor);
        let descriptor_digest = MusubiContentDigestV1::new(domain_digest(
            ARTIFACT_DESCRIPTOR_DOMAIN,
            &descriptor_material,
        ));
        let bundle_material = bundle_commitment_material(
            &semantic_release_bytes,
            &descriptor_material,
            &source_tree_material,
            &verification_lock_bytes,
        );
        let bundle_digest =
            MusubiContentDigestV1::new(domain_digest(BUNDLE_DOMAIN, &bundle_material));
        Ok(PackageCommitments {
            source_tree_digest,
            descriptor,
            descriptor_digest,
            bundle_digest,
        })
    }
    /// Consume the plan and construct its bounded deterministic `SoraFS` `CARv2` bundle.
    ///
    /// The CAR directory DAG contains the normalized source tree and verification lock plus the
    /// exact semantic release manifest and typed artifact descriptor. Providers can therefore
    /// attest to parsing the bundle rather than merely storing an opaque byte string.
    ///
    /// # Errors
    ///
    /// Returns an error if `SoraFS` rejects the logical plan, the V1 chunk ceiling is exceeded,
    /// writing fails, or the final CAR exceeds 96 MiB.
    pub fn into_car(
        self,
        semantic_release_manifest: &MusubiSemanticReleaseManifestV1,
        verification_lock: &MusubiVerificationLockV1,
    ) -> Result<PackageCar, PackageError> {
        let commitments =
            self.commitment_materials(semantic_release_manifest, verification_lock)?;
        let semantic_release_bytes = semantic_release_manifest.encode();
        let verification_lock_bytes = encode_verification_lock_bounded(verification_lock)?;
        let source_file_count = self.files.len();
        let source_bytes = self.source_bytes;
        let mut entries = self
            .files
            .into_iter()
            .map(|file| FileEntry {
                path: file.components,
                data: file.bytes,
            })
            .collect::<Vec<_>>();
        entries.push(FileEntry {
            path: BUNDLE_RELEASE_PATH.split('/').map(str::to_owned).collect(),
            data: semantic_release_bytes,
        });
        entries.push(FileEntry {
            path: BUNDLE_DESCRIPTOR_PATH
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: commitments.descriptor.encode(),
        });
        entries.push(FileEntry {
            path: BUNDLE_VERIFICATION_LOCK_PATH
                .split('/')
                .map(str::to_owned)
                .collect(),
            data: verification_lock_bytes,
        });
        let (plan, payload) = CarBuildPlan::from_files(entries)
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        plan.validate_for_ingest()
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        enforce_chunk_limit(plan.chunks.len())?;
        let mut output = BoundedWriter::new(MAX_CAR_BYTES);
        let writer = CarWriter::new(&plan, &payload)
            .map_err(|error| PackageError::CarWrite(error.to_string()))?;
        let stats = match writer.write_to(&mut output) {
            Ok(stats) => stats,
            Err(_) if output.exceeded => {
                return Err(PackageError::CarTooLarge {
                    bytes: output.attempted,
                    maximum: MAX_CAR_BYTES,
                });
            }
            Err(error) => return Err(PackageError::CarWrite(error.to_string())),
        };
        enforce_car_limit(stats.car_size)?;
        Ok(PackageCar {
            plan,
            payload,
            bytes: output.bytes,
            stats,
            commitments,
            source_file_count,
            source_bytes,
        })
    }
    fn required_file(&self, path: &str) -> &[u8] {
        self.files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .ok()
            .and_then(|index| self.files.get(index))
            .map(PlannedFile::bytes)
            .expect("package planner always injects canonical manifest and lock")
    }
}
/// A deterministic, bounded `SoraFS` CAR generated from a [`PackagePlan`].
#[derive(Debug)]
pub struct PackageCar {
    plan: CarBuildPlan,
    payload: Vec<u8>,
    bytes: Vec<u8>,
    stats: CarWriteStats,
    commitments: PackageCommitments,
    source_file_count: usize,
    source_bytes: u64,
}
impl PackageCar {
    /// Return the exact validated `SoraFS` plan used to write this package CAR.
    ///
    /// The plan covers the positive source tree plus the three mandatory semantic-release,
    /// artifact-descriptor, and verification-lock bundle entries. Its ordered chunk inventory is
    /// the canonical witness for the archive commitment's content length, chunk count, and
    /// chunk-plan digest. The commitment's file count remains the source-tree count and therefore
    /// excludes those three bundle entries.
    #[must_use]
    pub const fn plan(&self) -> &CarBuildPlan {
        &self.plan
    }
    /// Return the exact concatenated source payload expected by the CAR plan.
    #[must_use]
    #[cfg(all(test, unix))]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Return the complete deterministic `CARv2` bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Return `SoraFS` writer statistics and roots.
    #[must_use]
    pub const fn stats(&self) -> &CarWriteStats {
        &self.stats
    }
    /// Return all normalized source-tree, descriptor, and bundle commitments.
    #[must_use]
    pub const fn commitments(&self) -> &PackageCommitments {
        &self.commitments
    }
    /// Return the source-tree file count, excluding three mandatory bundle metadata entries.
    #[must_use]
    #[cfg(all(test, unix))]
    pub const fn source_file_count(&self) -> usize {
        self.source_file_count
    }
    /// Return source-tree bytes, excluding the three mandatory bundle metadata entries.
    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
    /// Derive and validate the complete immutable registry archive commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if the CAR lacks its single canonical root, its plan/profile is
    /// inconsistent, `PoR` derivation fails, a count overflows, or a V1 commitment bound is
    /// violated.
    pub fn archive_commitment(&self) -> Result<MusubiArchiveCommitmentV1, PackageError> {
        if self.stats.root_cids.len() != 1 || self.stats.chunk_profile != self.plan.chunk_profile {
            return Err(PackageError::CarPlan(
                "package CAR must have one root and one consistent chunk profile".to_owned(),
            ));
        }
        let root_cid = ManifestRootCid::try_from(self.stats.root_cids[0].clone())
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        let descriptor = default_descriptor();
        if descriptor.profile != self.plan.chunk_profile {
            return Err(PackageError::CarPlan(
                "package CAR chunk profile is not the registered V1 default".to_owned(),
            ));
        }
        let por_root = compute_por_root(&self.payload, &self.plan)
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        let commitment = MusubiArchiveCommitmentV1 {
            root_cid,
            chunker: ChunkerProfileHandle {
                profile_id: descriptor.id.0,
                namespace: descriptor.namespace.to_owned(),
                name: descriptor.name.to_owned(),
                semver: descriptor.semver.to_owned(),
                multihash_code: descriptor.multihash_code,
            },
            chunk_plan_digest: MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(
                &self.plan.chunks,
            )),
            por_root: MusubiContentDigestV1::new(por_root),
            content_length: self.plan.content_length,
            car_digest: MusubiContentDigestV1::new(*self.stats.car_archive_digest.as_bytes()),
            car_size: self.stats.car_size,
            bundle_digest: self.commitments.bundle_digest(),
            source_tree_digest: self.commitments.source_tree_digest(),
            descriptor_digest: self.commitments.descriptor_digest(),
            file_count: u32::try_from(self.source_file_count).map_err(|_| {
                PackageError::TooManyFiles {
                    count: self.source_file_count,
                    maximum: MAX_SOURCE_FILES,
                }
            })?,
            chunk_count: u32::try_from(self.plan.chunks.len()).map_err(|_| {
                PackageError::TooManyChunks {
                    count: self.plan.chunks.len(),
                    maximum: MAX_SOURCE_CHUNKS,
                }
            })?,
        };
        commitment
            .validate()
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        Ok(commitment)
    }
}
/// All canonical materials and digests needed by the archive-commitment layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageCommitments {
    source_tree_digest: MusubiContentDigestV1,
    descriptor: MusubiArtifactDescriptorV1,
    descriptor_digest: MusubiContentDigestV1,
    bundle_digest: MusubiContentDigestV1,
}
impl PackageCommitments {
    /// Return the domain-separated source-tree digest.
    #[must_use]
    pub const fn source_tree_digest(&self) -> MusubiContentDigestV1 {
        self.source_tree_digest
    }
    /// Return the typed artifact descriptor.
    #[must_use]
    #[cfg(all(test, unix))]
    pub const fn descriptor(&self) -> &MusubiArtifactDescriptorV1 {
        &self.descriptor
    }
    /// Return the descriptor digest.
    #[must_use]
    pub const fn descriptor_digest(&self) -> MusubiContentDigestV1 {
        self.descriptor_digest
    }
    /// Return the domain-separated bundle digest.
    #[must_use]
    pub const fn bundle_digest(&self) -> MusubiContentDigestV1 {
        self.bundle_digest
    }
}
/// Error returned while planning or encoding a secure package.
#[derive(Debug)]
pub enum PackageError {
    /// Secure filesystem-backed package planning is unsupported on this platform.
    UnsupportedPlatform,
    /// A filesystem operation failed.
    Io {
        /// Operation being performed without secret-bearing input.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// The package root is not a real directory.
    InvalidRoot(PathBuf),
    /// A selector was absolute, empty, traversing, or otherwise invalid.
    InvalidSelector(PathBuf),
    /// A selector had the wrong file kind.
    WrongFileKind {
        /// Declared selector.
        path: PathBuf,
        /// Required kind.
        expected: &'static str,
    },
    /// A referenced Kotodama file or source-relative path is invalid.
    InvalidSource {
        /// Portable referring or referenced file path.
        path: String,
        /// Bounded compiler diagnostic or path failure.
        reason: String,
    },
    /// A path was not valid portable UTF-8.
    NonPortablePath(String),
    /// Two selected names collide on portable case/Unicode-normalizing filesystems.
    PathCollision {
        /// First selected path.
        first: String,
        /// Conflicting selected path.
        second: String,
    },
    /// A selected entry was a symlink.
    Symlink(PathBuf),
    /// A selected regular file had more than one hard link.
    Hardlink(PathBuf),
    /// A selected entry was neither a regular file nor a directory.
    SpecialFile(PathBuf),
    /// A selected path belongs to a generated, VCS, or local configuration root.
    ExcludedPath(PathBuf),
    /// A selected path is a known credential or private-key location.
    SensitivePath(PathBuf),
    /// Selected bytes contain a known credential/private-key marker.
    SensitiveContent {
        /// Portable path of the rejected file.
        path: String,
        /// Stable marker class; never contains the matched secret.
        marker: &'static str,
    },
    /// The normalized source tree exceeds the file-count ceiling.
    TooManyFiles {
        /// Planned file count.
        count: usize,
        /// V1 maximum.
        maximum: usize,
    },
    /// Positive-set traversal exceeded its filesystem-entry ceiling.
    TooManyEntries {
        /// Number of selected filesystem entries visited.
        count: usize,
        /// V1 traversal maximum.
        maximum: usize,
    },
    /// The normalized source tree exceeds the payload-byte ceiling.
    SourceTooLarge {
        /// Planned source bytes.
        bytes: u64,
        /// V1 maximum.
        maximum: u64,
    },
    /// The typed verification-lock payload exceeds bundle-metadata admission.
    VerificationLockTooLarge {
        /// Exact canonical Norito payload bytes.
        bytes: u64,
        /// V1 bundle-metadata maximum.
        maximum: u64,
    },
    /// The typed semantic-release payload exceeds bundle-metadata admission.
    SemanticReleaseTooLarge {
        /// Exact canonical Norito payload bytes.
        bytes: u64,
        /// V1 bundle-metadata maximum.
        maximum: u64,
    },
    /// The `SoraFS` plan exceeds the chunk-count ceiling.
    TooManyChunks {
        /// Planned chunk count.
        count: usize,
        /// V1 maximum.
        maximum: usize,
    },
    /// The generated CAR exceeds the encoded-byte ceiling.
    CarTooLarge {
        /// Encoded or attempted CAR bytes.
        bytes: u64,
        /// V1 maximum.
        maximum: u64,
    },
    /// A TOML document was invalid or lacked its V1 marker.
    InvalidDocument {
        /// Stable document name.
        document: &'static str,
        /// Parse or schema-marker failure.
        reason: String,
    },
    /// Typed semantic release and verification-lock bindings were inconsistent.
    InvalidBundleBinding(String),
    /// `SoraFS` rejected the logical source plan.
    CarPlan(String),
    /// `SoraFS` could not encode the CAR.
    CarWrite(String),
}
impl fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str(
                "secure Musubi package planning requires native Unix or Windows retained filesystem authority",
            ),
            Self::Io { operation, path, source } => write!(
                formatter,
                "failed to {operation} `{}`: {source}",
                path.display()
            ),
            Self::InvalidRoot(path) => write!(
                formatter,
                "package root `{}` must be a real directory",
                path.display()
            ),
            Self::InvalidSelector(path) => write!(
                formatter,
                "package selector `{}` must be a confined relative path",
                path.display()
            ),
            Self::WrongFileKind { path, expected } => write!(
                formatter,
                "package selector `{}` must be {expected}",
                path.display()
            ),
            Self::InvalidSource { path, reason } => {
                write!(formatter, "invalid Kotodama source `{path}`: {reason}")
            }
            Self::NonPortablePath(path) => {
                write!(formatter, "package path `{path}` is not portable UTF-8")
            }
            Self::PathCollision { first, second } => write!(
                formatter,
                "package paths `{first}` and `{second}` have a portable case/Unicode collision"
            ),
            Self::Symlink(path) => write!(
                formatter,
                "symlink `{}` is forbidden in a package",
                path.display()
            ),
            Self::Hardlink(path) => write!(
                formatter,
                "hard-linked file `{}` is forbidden in a package",
                path.display()
            ),
            Self::SpecialFile(path) => write!(
                formatter,
                "special file `{}` is forbidden in a package",
                path.display()
            ),
            Self::ExcludedPath(path) => write!(
                formatter,
                "generated, VCS, or local configuration path `{}` cannot be packaged",
                path.display()
            ),
            Self::SensitivePath(path) => write!(
                formatter,
                "credential or private-key path `{}` cannot be packaged",
                path.display()
            ),
            Self::SensitiveContent { path, marker } => write!(
                formatter,
                "package file `{path}` contains forbidden {marker} material"
            ),
            Self::TooManyFiles { count, maximum } => write!(
                formatter,
                "package has {count} files; Musubi V1 permits at most {maximum}"
            ),
            Self::TooManyEntries { count, maximum } => write!(
                formatter,
                "package traversal visited {count} filesystem entries; Musubi V1 permits at most {maximum}"
            ),
            Self::SourceTooLarge { bytes, maximum } => write!(
                formatter,
                "package has {bytes} source bytes; Musubi V1 permits at most {maximum}"
            ),
            Self::VerificationLockTooLarge { bytes, maximum } => write!(
                formatter,
                "typed verification lock has {bytes} bytes; Musubi V1 bundle metadata permits at most {maximum}"
            ),
            Self::SemanticReleaseTooLarge { bytes, maximum } => write!(
                formatter,
                "typed semantic release has {bytes} bytes; Musubi V1 bundle metadata permits at most {maximum}"
            ),
            Self::TooManyChunks { count, maximum } => write!(
                formatter,
                "package has {count} chunks; Musubi V1 permits at most {maximum}"
            ),
            Self::CarTooLarge { bytes, maximum } => write!(
                formatter,
                "package CAR has {bytes} bytes; Musubi V1 permits at most {maximum}"
            ),
            Self::InvalidDocument { document, reason } => {
                write!(formatter, "invalid {document}: {reason}")
            }
            Self::InvalidBundleBinding(reason) => {
                write!(formatter, "invalid semantic release bundle: {reason}")
            }
            Self::CarPlan(reason) => write!(formatter, "invalid SoraFS package plan: {reason}"),
            Self::CarWrite(reason) => write!(formatter, "failed to encode package CAR: {reason}"),
        }
    }
}
impl Error for PackageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
/// Canonicalize and validate a Musubi V1 package manifest.
///
/// The TOML parser rejects duplicate keys. Semantic unknown-field validation remains the
/// responsibility of the manifest module before it constructs [`PackageLayout`].
///
/// # Errors
///
/// Returns an error for malformed TOML or a missing/non-V1 `manifest-version` marker.
pub fn canonicalize_manifest_toml(input: &str) -> Result<Vec<u8>, PackageError> {
    let (table, bytes) = canonicalize_toml(MANIFEST_PATH, input)?;
    if table
        .get("manifest-version")
        .and_then(toml::Value::as_integer)
        != Some(1)
    {
        return Err(PackageError::InvalidDocument {
            document: MANIFEST_PATH,
            reason: "`manifest-version = 1` is required".to_owned(),
        });
    }
    Ok(bytes)
}
/// Canonicalize and validate a generated Musubi V1 verification lock.
///
/// Exact graph normalization (including deterministic node and edge ordering) belongs to the
/// lockfile module. This helper makes its TOML representation canonical and enforces the reset
/// markers so an old consumer lock cannot enter a release bundle.
///
/// # Errors
///
/// Returns an error for malformed TOML or missing `schema = "musubi-lock"`/`version = 1`.
#[cfg(all(test, unix))]
pub fn normalize_verification_lock_toml(input: &str) -> Result<Vec<u8>, PackageError> {
    let (table, bytes) = canonicalize_toml(VERIFICATION_LOCK_PATH, input)?;
    let schema_matches = table.get("schema").and_then(toml::Value::as_str) == Some("musubi-lock");
    let version_matches = table.get("version").and_then(toml::Value::as_integer) == Some(1);
    if !schema_matches || !version_matches {
        return Err(PackageError::InvalidDocument {
            document: VERIFICATION_LOCK_PATH,
            reason:
                "`schema = \"musubi-lock\"` and `version = 1` are required; regenerate the lockfile"
                    .to_owned(),
        });
    }
    reject_consumer_only_lock_fields(&toml::Value::Table(table))?;
    Ok(bytes)
}
/// Plan a clean, positive-set Musubi V1 source tree.
///
/// `manifest_toml` is parsed and rendered canonically. `verification_lock` must be the
/// exact typed graph generated for publication. Its source-tree TOML and provider-facing
/// Norito representation are both derived from this one value, so they cannot diverge.
/// Manifest selectors and their explicit Kotodama include/import closure are visited.
///
/// # Errors
///
/// Returns an error for invalid documents, unsafe paths or
/// filesystem objects, credential material, inconsistent filesystem identity, or a V1
/// resource-limit violation.
pub fn plan_package(
    layout: &PackageLayout,
    manifest_toml: &str,
    verification_lock: &MusubiVerificationLockV1,
) -> Result<PackagePlan, PackageError> {
    if !cfg!(any(unix, windows)) {
        return Err(PackageError::UnsupportedPlatform);
    }
    let manifest = canonicalize_manifest_toml(manifest_toml)?;
    let lock = render_verification_lock(verification_lock)
        .map_err(|error| PackageError::InvalidDocument {
            document: VERIFICATION_LOCK_PATH,
            reason: error.to_string(),
        })?
        .into_bytes();
    let root = validate_root(layout.root())?;
    let mut collector = Collector::new(root)?;
    collector.insert_virtual(MANIFEST_PATH, manifest)?;
    collector.insert_virtual(VERIFICATION_LOCK_PATH, lock)?;
    collect_package_sources(layout, &mut collector)?;
    let inventory = collector.finish()?;
    Ok(PackagePlan {
        files: inventory.files,
        source_bytes: inventory.source_bytes,
    })
}
/// Inspect the same bounded positive source set without creating publication evidence or files.
///
/// The inventory includes a canonical projection of the supplied manifest, but no generated
/// verification lock. It neither resolves dependencies nor loads registry configuration.
///
/// # Errors
/// Returns an error for unsafe or sensitive source files, invalid manifests, unsupported platforms,
/// or the same source size, count, and path limits enforced during packaging.
pub fn inventory_package(
    layout: &PackageLayout,
    manifest_toml: &str,
) -> Result<PackageInventory, PackageError> {
    if !cfg!(any(unix, windows)) {
        return Err(PackageError::UnsupportedPlatform);
    }
    let manifest = canonicalize_manifest_toml(manifest_toml)?;
    let mut collector = Collector::new(validate_root(layout.root())?)?;
    collector.insert_virtual(MANIFEST_PATH, manifest)?;
    collect_package_sources(layout, &mut collector)?;
    collector.finish()
}
fn collect_package_sources(
    layout: &PackageLayout,
    collector: &mut Collector,
) -> Result<(), PackageError> {
    if let Some(path) = &layout.library {
        collector.collect_selector(path, SelectionShape::Directory)?;
    }
    for path in &layout.contracts {
        #[expect(
            clippy::case_sensitive_file_extension_comparisons,
            reason = "portable Musubi contract sources require the canonical lowercase .ko suffix"
        )]
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".ko"))
        {
            return Err(PackageError::WrongFileKind {
                path: path.clone(),
                expected: "one `.ko` contract source file",
            });
        }
        collector.collect_selector(path, SelectionShape::File)?;
    }
    for path in &layout.tests {
        collector.collect_selector(path, SelectionShape::Either)?;
    }
    if let Some(path) = &layout.readme {
        collector.collect_selector(path, SelectionShape::File)?;
    }
    if let Some(path) = &layout.license {
        collector.collect_selector(path, SelectionShape::File)?;
    }
    for path in &layout.includes {
        collector.collect_selector(path, SelectionShape::Either)?;
    }
    collector.collect_source_dependencies()?;
    for selection in &layout.external {
        let root = validate_root(&selection.root)?;
        let mut external = Collector::new(root.clone())?;
        external.collect_selector(&selection.selector, selection.shape)?;
        external.collect_source_dependencies()?;
        let external_entries = external.visited_entries;
        let external_plan = external.finish()?;
        collector.consume_entries(external_entries)?;
        for file in external_plan.files {
            let original = format!("external:{}:{}", root.display(), file.path);
            collector.insert(original, file.path, file.components, file.bytes)?;
        }
    }
    Ok(())
}
/// Derive the positive file selection for one fully resolved workspace package.
///
/// Path-bearing `[workspace.package]` values are selected relative to the workspace
/// root and retain their portable manifest spelling in the clean package tree.
pub fn package_layout_for_member(workspace_root: &Path, member: &WorkspaceMember) -> PackageLayout {
    let mut layout = PackageLayout::new(&member.package_root);
    if let Some(library) = &member.manifest.library {
        layout.set_library(library.source_dir.to_path_buf());
    }
    for target in &member.manifest.contracts {
        layout.add_contract(target.path.to_path_buf());
    }
    for target in &member.manifest.tests {
        layout.add_test(target.path.to_path_buf());
    }
    let package = member
        .manifest
        .package
        .as_ref()
        .expect("loaded package members always have package metadata");
    if let Some(readme) = &member.package.readme {
        if inherited(package.readme.as_ref()) && workspace_root != member.package_root {
            layout.add_external(workspace_root, readme.to_path_buf(), SelectionShape::File);
        } else {
            layout.set_readme(readme.to_path_buf());
        }
    }
    if let Some(license) = &member.package.license_file {
        if inherited(package.license_file.as_ref()) && workspace_root != member.package_root {
            layout.add_external(workspace_root, license.to_path_buf(), SelectionShape::File);
        } else {
            layout.set_license(license.to_path_buf());
        }
    }
    for include in &member.package.include {
        if inherited(package.include.as_ref()) && workspace_root != member.package_root {
            layout.add_external(
                workspace_root,
                include.to_path_buf(),
                SelectionShape::Either,
            );
        } else {
            layout.add_include(include.to_path_buf());
        }
    }
    layout
}
fn inherited<T>(value: Option<&Inheritable<T>>) -> bool {
    matches!(value, Some(Inheritable::Workspace))
}
/// Render one clean publishable package manifest with workspace and local path state removed.
///
/// Effective normal dependencies are retained as canonical registry package/range pairs.
/// Development dependencies never enter the publication manifest.
pub fn publication_manifest_toml(member: &WorkspaceMember) -> Result<String, PackageError> {
    let mut root = toml::Table::new();
    root.insert("manifest-version".to_owned(), toml::Value::Integer(1));
    let resolved = &member.package;
    let mut package = toml::Table::new();
    package.insert(
        "namespace".to_owned(),
        toml::Value::String(resolved.selector.namespace.to_string()),
    );
    package.insert(
        "name".to_owned(),
        toml::Value::String(resolved.selector.name.to_string()),
    );
    package.insert(
        "version".to_owned(),
        toml::Value::String(resolved.version.to_string()),
    );
    package.insert("edition".to_owned(), toml::Value::String("1".to_owned()));
    package.insert(
        "abi-version".to_owned(),
        toml::Value::Integer(i64::from(resolved.abi_version)),
    );
    insert_optional_string(&mut package, "description", resolved.description.as_deref());
    insert_optional_path(&mut package, "readme", resolved.readme.as_ref());
    insert_optional_string(&mut package, "license", resolved.license.as_deref());
    insert_optional_path(&mut package, "license-file", resolved.license_file.as_ref());
    insert_optional_string(&mut package, "repository", resolved.repository.as_deref());
    if !resolved.keywords.is_empty() {
        package.insert(
            "keywords".to_owned(),
            toml::Value::Array(
                resolved
                    .keywords
                    .iter()
                    .cloned()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
    }
    if !resolved.include.is_empty() {
        package.insert(
            "include".to_owned(),
            toml::Value::Array(
                resolved
                    .include
                    .iter()
                    .map(|path| toml::Value::String(path.to_string()))
                    .collect(),
            ),
        );
    }
    root.insert("package".to_owned(), toml::Value::Table(package));
    if let Some(library) = &member.manifest.library {
        let mut library_table = toml::Table::new();
        library_table.insert(
            "source-dir".to_owned(),
            toml::Value::String(library.source_dir.to_string()),
        );
        library_table.insert(
            "exports".to_owned(),
            toml::Value::Array(
                library
                    .exports
                    .iter()
                    .map(|export| toml::Value::String(export.to_string()))
                    .collect(),
            ),
        );
        root.insert("lib".to_owned(), toml::Value::Table(library_table));
    }
    insert_targets(&mut root, "contract", &member.manifest.contracts);
    insert_targets(&mut root, "test", &member.manifest.tests);
    if !member.dependencies.is_empty() {
        let mut dependencies = toml::Table::new();
        for (alias, effective) in &member.dependencies {
            let (package, requirement) =
                effective
                    .dependency
                    .publication_requirement()
                    .map_err(|error| PackageError::InvalidDocument {
                        document: MANIFEST_PATH,
                        reason: format!("dependency `{alias}`: {error}"),
                    })?;
            let mut dependency = toml::Table::new();
            dependency.insert(
                "package".to_owned(),
                toml::Value::String(package.to_string()),
            );
            dependency.insert(
                "version".to_owned(),
                toml::Value::String(requirement.to_string()),
            );
            dependencies.insert(alias.to_string(), toml::Value::Table(dependency));
        }
        root.insert("dependencies".to_owned(), toml::Value::Table(dependencies));
    }
    let rendered = toml::to_string(&root).map_err(|error| PackageError::InvalidDocument {
        document: MANIFEST_PATH,
        reason: error.to_string(),
    })?;
    crate::manifest::parse_manifest(&rendered).map_err(|error| PackageError::InvalidDocument {
        document: MANIFEST_PATH,
        reason: error.to_string(),
    })?;
    Ok(rendered)
}
/// Construct the canonical archive-independent release semantics for a clean package.
pub fn semantic_release_manifest(
    member: &WorkspaceMember,
    release: MusubiReleaseIdV1,
    verification_lock: &MusubiVerificationLockV1,
    interface_digest: MusubiContentDigestV1,
) -> Result<MusubiSemanticReleaseManifestV1, PackageError> {
    if release != verification_lock.root
        || release.package.name != member.package.selector.name
        || release.version != member.package.version
    {
        return Err(PackageError::InvalidBundleBinding(
            "workspace package, release root, and verification lock disagree".to_owned(),
        ));
    }
    validate_verification_lock_encoded_bound(verification_lock)?;
    let description = member
        .package
        .description
        .as_deref()
        .map(MusubiDescriptionV1::new)
        .transpose()
        .map_err(bundle_parse_error)?;
    let readme = member
        .package
        .readme
        .as_ref()
        .map(|value| MusubiDocumentRefV1::new(value.as_str()))
        .transpose()
        .map_err(bundle_parse_error)?;
    let license_text = member.package.license.as_deref().or_else(|| {
        member
            .package
            .license_file
            .as_ref()
            .map(crate::manifest::PortablePath::as_str)
    });
    let license = license_text
        .map(MusubiDocumentRefV1::new)
        .transpose()
        .map_err(bundle_parse_error)?;
    let repository = member
        .package
        .repository
        .as_deref()
        .map(MusubiDocumentRefV1::new)
        .transpose()
        .map_err(bundle_parse_error)?;
    let keywords = member
        .package
        .keywords
        .iter()
        .map(|keyword| keyword.parse::<MusubiKeywordV1>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(bundle_parse_error)?;
    let dependencies = verification_lock
        .root_dependencies
        .iter()
        .map(|edge| MusubiDependencyReqV1 {
            alias: edge.alias.clone(),
            package: edge.package.clone(),
            requirement: edge.requirement.clone(),
        })
        .collect();
    let exports = member
        .manifest
        .library
        .as_ref()
        .map_or_else(Vec::new, |library| library.exports.clone());
    let mut semantic = MusubiSemanticReleaseManifestV1 {
        release,
        edition: member.package.edition,
        abi: MusubiAbiBindingV1::new(compute_abi_hash(SyscallPolicy::AbiV1))
            .map_err(bundle_parse_error)?,
        dependencies,
        exports,
        interface_digest,
        metadata: MusubiReleaseMetadataV1 {
            description,
            readme,
            license,
            repository,
            keywords,
        },
        verification_lock_digest: verification_lock.digest(),
    };
    semantic.canonicalize();
    semantic.validate().map_err(bundle_parse_error)?;
    validate_semantic_release_encoded_bound(&semantic)?;
    Ok(semantic)
}
/// Bind clean bundle semantics and an exact verification graph to one immutable archive.
pub fn publication_claim(
    semantic: &MusubiSemanticReleaseManifestV1,
    archive: &MusubiArchiveCommitmentV1,
    snapshot: MusubiRegistrySnapshotV1,
    verification_lock: MusubiVerificationLockV1,
) -> Result<MusubiPublicationV1, PackageError> {
    validate_semantic_release_encoded_bound(semantic)?;
    validate_verification_lock_encoded_bound(&verification_lock)?;
    semantic
        .validate()
        .map_err(|error| PackageError::InvalidBundleBinding(error.to_string()))?;
    archive
        .validate()
        .map_err(|error| PackageError::InvalidBundleBinding(error.to_string()))?;
    let manifest = MusubiReleaseManifestV1 {
        release: semantic.release.clone(),
        edition: semantic.edition,
        abi: semantic.abi,
        dependencies: semantic.dependencies.clone(),
        exports: semantic.exports.clone(),
        interface_digest: semantic.interface_digest,
        metadata: semantic.metadata.clone(),
        archive_id: archive.archive_id(),
        verification_lock_digest: semantic.verification_lock_digest,
    };
    let publication = MusubiPublicationV1 {
        manifest,
        resolution: MusubiResolutionProofV1 {
            snapshot,
            lock: verification_lock,
        },
    };
    publication
        .validate()
        .map_err(|error| PackageError::InvalidBundleBinding(error.to_string()))?;
    if publication.manifest.semantic_manifest() != *semantic {
        return Err(PackageError::InvalidBundleBinding(
            "registry release changed the packaged semantic manifest".to_owned(),
        ));
    }
    Ok(publication)
}
fn bundle_parse_error(error: iroha_model_base::error::ParseError) -> PackageError {
    PackageError::InvalidBundleBinding(error.to_string())
}
fn insert_optional_string(table: &mut toml::Table, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        table.insert(key.to_owned(), toml::Value::String(value.to_owned()));
    }
}
fn insert_optional_path(
    table: &mut toml::Table,
    key: &str,
    value: Option<&crate::manifest::PortablePath>,
) {
    if let Some(value) = value {
        table.insert(key.to_owned(), toml::Value::String(value.to_string()));
    }
}
fn insert_targets(root: &mut toml::Table, key: &str, targets: &[crate::manifest::LocalTarget]) {
    if targets.is_empty() {
        return;
    }
    root.insert(
        key.to_owned(),
        toml::Value::Array(
            targets
                .iter()
                .map(|target| {
                    let mut table = toml::Table::new();
                    table.insert(
                        "name".to_owned(),
                        toml::Value::String(target.name.to_string()),
                    );
                    table.insert(
                        "path".to_owned(),
                        toml::Value::String(target.path.to_string()),
                    );
                    toml::Value::Table(table)
                })
                .collect(),
        ),
    );
}
fn canonicalize_toml(
    document: &'static str,
    input: &str,
) -> Result<(toml::Table, Vec<u8>), PackageError> {
    let table = input
        .parse::<toml::Table>()
        .map_err(|error| PackageError::InvalidDocument {
            document,
            reason: error.to_string(),
        })?;
    let mut output = toml::to_string(&table).map_err(|error| PackageError::InvalidDocument {
        document,
        reason: error.to_string(),
    })?;
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok((table, output.into_bytes()))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionShape {
    File,
    Directory,
    Either,
}
struct Collector {
    root: PathBuf,
    authority: iroha_fs::OwnerDirectory,
    files: BTreeMap<String, PlannedFile>,
    collision_origins: BTreeMap<String, String>,
    source_bytes: u64,
    visited_entries: usize,
}
impl Collector {
    fn new(root: PathBuf) -> Result<Self, PackageError> {
        let authority = iroha_fs::OwnerDirectory::open(&root)
            .map_err(|source| io_error("retain package root", &root, source))?;
        Ok(Self {
            root,
            authority,
            files: BTreeMap::new(),
            collision_origins: BTreeMap::new(),
            source_bytes: 0,
            visited_entries: 0,
        })
    }
    fn consume_entries(&mut self, count: usize) -> Result<(), PackageError> {
        let Some(next) = self.visited_entries.checked_add(count) else {
            return Err(PackageError::TooManyEntries {
                count: usize::MAX,
                maximum: MAX_SOURCE_ENTRIES,
            });
        };
        enforce_entry_limit(next, MAX_SOURCE_ENTRIES)?;
        self.visited_entries = next;
        Ok(())
    }
    fn insert_virtual(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), PackageError> {
        if let Some(marker) = sensitive_content_marker(&bytes) {
            return Err(PackageError::SensitiveContent {
                path: path.to_owned(),
                marker,
            });
        }
        let components = canonical_portable_components(path)?;
        self.insert(path.to_owned(), path.to_owned(), components, bytes)
    }
    /// Extend positive manifest selections only through explicit source declarations.
    fn collect_source_dependencies(&mut self) -> Result<(), PackageError> {
        use kotodama_lang::{
            ast::SourceDirectiveKind,
            source::{FrontendBudget, SourceFile, SourceId},
        };

        let mut pending = VecDeque::new();
        let mut visited = BTreeSet::new();
        // Selected directories may contain bare fragments or non-compiling draft files.
        // Only complete entry units seed the closure; referenced files are parsed below
        // using the grammar selected by their include/import declaration.
        for file in self.files.values().filter(|file| {
            Path::new(&file.path)
                .extension()
                .is_some_and(|extension| extension == "ko")
        }) {
            let Ok(text) = std::str::from_utf8(&file.bytes) else {
                continue;
            };
            // Resolve filesystem references from the original spelling; archive paths may
            // already have been normalized to NFC by the portable-path policy.
            let referrer = self
                .collision_origins
                .get(&portable_collision_key(&file.components))
                .unwrap_or(&file.path);
            let source = SourceFile::new(SourceId(0), referrer.as_str(), text);
            if let Ok(program) = kotodama_lang::parser::parse_source(&source, FrontendBudget::v1())
            {
                visited.insert((referrer.clone(), false));
                pending.push_back((referrer.clone(), program.directives));
            }
        }
        while let Some((referrer, directives)) = pending.pop_front() {
            for directive in directives {
                let (relative, fragment) = match directive.kind {
                    SourceDirectiveKind::Include { path } => (path, true),
                    SourceDirectiveKind::Import { path, .. } => (path, false),
                    SourceDirectiveKind::ContractTypeImport { .. } => continue,
                    SourceDirectiveKind::ContractImport { path: relative, .. } => {
                        let path = kotodama_lang::linker::resolve_contract_artifact_path(
                            &referrer, &relative,
                        )
                        .map_err(|error| PackageError::InvalidSource {
                            path: referrer.clone(),
                            reason: error.to_string(),
                        })?;
                        self.collect_selector(Path::new(&path), SelectionShape::File)?;
                        continue;
                    }
                };
                let path = kotodama_lang::linker::resolve_source_path(&referrer, &relative)
                    .map_err(|error| PackageError::InvalidSource {
                        path: referrer.clone(),
                        reason: error.to_string(),
                    })?;
                if !visited.insert((path.clone(), fragment)) {
                    continue;
                }
                self.collect_selector(Path::new(&path), SelectionShape::File)?;
                let canonical = canonical_portable_components(&path)?.join("/");
                let file =
                    self.files
                        .get(&canonical)
                        .ok_or_else(|| PackageError::InvalidSource {
                            path: path.clone(),
                            reason: "source was not retained in the package".into(),
                        })?;
                let text = std::str::from_utf8(&file.bytes).map_err(|error| {
                    PackageError::InvalidSource {
                        path: path.clone(),
                        reason: error.to_string(),
                    }
                })?;
                let source = SourceFile::new(SourceId(0), path.as_str(), text);
                let parsed = if fragment {
                    kotodama_lang::parser::parse_fragment_source(&source, FrontendBudget::v1())
                } else {
                    kotodama_lang::parser::parse_source(&source, FrontendBudget::v1())
                };
                let program = parsed.map_err(|diagnostics| PackageError::InvalidSource {
                    path: path.clone(),
                    reason: diagnostics.render_human(),
                })?;
                pending.push_back((path, program.directives));
            }
        }
        Ok(())
    }
    fn collect_selector(
        &mut self,
        selector: &Path,
        shape: SelectionShape,
    ) -> Result<(), PackageError> {
        self.authority
            .revalidate()
            .map_err(|source| io_error("revalidate package root", &self.root, source))?;
        let relative = validate_selector(selector)?;
        self.consume_entries(1)?;
        if relative.as_os_str().is_empty() {
            if matches!(shape, SelectionShape::File) {
                return Err(PackageError::WrongFileKind {
                    path: selector.to_path_buf(),
                    expected: "a regular file",
                });
            }
            return self.collect_directory(Path::new(""));
        }
        reject_explicit_excluded_or_sensitive(&relative)?;
        validate_no_symlink_chain(&self.root, &relative)?;
        let physical = self.root.join(&relative);
        let metadata = fs::symlink_metadata(&physical)
            .map_err(|source| io_error("inspect package selector", &relative, source))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(PackageError::Symlink(relative));
        }
        if metadata.is_file() {
            if matches!(shape, SelectionShape::Directory) {
                return Err(PackageError::WrongFileKind {
                    path: relative,
                    expected: "a directory",
                });
            }
            self.collect_file(&relative)
        } else if metadata.is_dir() {
            if matches!(shape, SelectionShape::File) {
                return Err(PackageError::WrongFileKind {
                    path: relative,
                    expected: "a regular file",
                });
            }
            self.collect_directory(&relative)
        } else {
            Err(PackageError::SpecialFile(relative))
        }
    }
    fn collect_directory(&mut self, relative: &Path) -> Result<(), PackageError> {
        validate_portable_relative_path(relative)?;
        let physical = self.root.join(relative);
        validate_confined_directory(&self.root, relative)?;
        let entries = fs::read_dir(&physical)
            .map_err(|source| io_error("read package directory", relative, source))?;
        let mut ordered = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| io_error("read package entry", relative, source))?;
            let name = entry.file_name().into_string().map_err(|name| {
                PackageError::NonPortablePath(relative.join(name).to_string_lossy().into_owned())
            })?;
            canonical_portable_component(&name)?;
            enforce_entry_limit(ordered.len() + 1, MAX_DIRECTORY_ENTRIES)?;
            self.consume_entries(1)?;
            ordered.push((name, entry));
        }
        ordered.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        for (name, entry) in ordered {
            let child = relative.join(&name);
            let linked = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect package entry", &child, source))?;
            if metadata_is_link_or_reparse(&linked) {
                return Err(PackageError::Symlink(child));
            }
            if is_sensitive_component(&name) {
                return Err(PackageError::SensitivePath(child));
            }
            if is_excluded_directory(&name) {
                continue;
            }
            if linked.is_file() && is_fixed_generated_file(&child) {
                continue;
            }
            if linked.is_dir() {
                self.collect_directory(&child)?;
            } else if linked.is_file() {
                self.collect_file(&child)?;
            } else {
                return Err(PackageError::SpecialFile(child));
            }
        }
        Ok(())
    }
    fn collect_file(&mut self, relative: &Path) -> Result<(), PackageError> {
        if is_fixed_generated_file(relative) {
            return Ok(());
        }
        let original = relative_to_utf8(relative)?;
        let components = canonical_portable_components(&original)?;
        let canonical = components.join("/");
        if self
            .collision_origins
            .get(&portable_collision_key(&components))
            .is_some_and(|existing| existing == &original)
        {
            return Ok(());
        }
        enforce_file_limit(self.files.len().saturating_add(1))?;
        let physical = self.root.join(relative);
        validate_no_symlink_chain(&self.root, relative)?;
        validate_confined_parent(&self.root, relative)?;
        let linked = fs::symlink_metadata(&physical)
            .map_err(|source| io_error("inspect package file", relative, source))?;
        if metadata_is_link_or_reparse(&linked) {
            return Err(PackageError::Symlink(relative.to_path_buf()));
        }
        if !linked.is_file() {
            return Err(PackageError::SpecialFile(relative.to_path_buf()));
        }
        #[cfg(unix)]
        if linked.nlink() != 1 {
            return Err(PackageError::Hardlink(relative.to_path_buf()));
        }
        let next_size =
            self.source_bytes
                .checked_add(linked.len())
                .ok_or(PackageError::SourceTooLarge {
                    bytes: u64::MAX,
                    maximum: MAX_SOURCE_BYTES,
                })?;
        enforce_source_limit(next_size)?;
        let remaining =
            usize::try_from(MAX_SOURCE_BYTES - self.source_bytes).map_err(|source| {
                io_error(
                    "bound package source read",
                    relative,
                    io::Error::other(source),
                )
            })?;
        let bytes = iroha_fs::read_regular(&physical, remaining)
            .map_err(|source| io_error("read stable package file", relative, source))?
            .to_vec();
        validate_confined_file(&self.root, relative)?;
        if let Some(marker) = sensitive_content_marker(&bytes) {
            return Err(PackageError::SensitiveContent {
                path: canonical,
                marker,
            });
        }
        self.insert(original, canonical, components, bytes)
    }
    fn insert(
        &mut self,
        original: String,
        canonical: String,
        components: Vec<String>,
        bytes: Vec<u8>,
    ) -> Result<(), PackageError> {
        let collision_key = portable_collision_key(&components);
        if let Some(first) = self.collision_origins.get(&collision_key) {
            if first != &original {
                return Err(PackageError::PathCollision {
                    first: first.clone(),
                    second: original,
                });
            }
            return Ok(());
        }
        enforce_file_limit(self.files.len().saturating_add(1))?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| PackageError::SourceTooLarge {
            bytes: u64::MAX,
            maximum: MAX_SOURCE_BYTES,
        })?;
        let next_size =
            self.source_bytes
                .checked_add(byte_len)
                .ok_or(PackageError::SourceTooLarge {
                    bytes: u64::MAX,
                    maximum: MAX_SOURCE_BYTES,
                })?;
        enforce_source_limit(next_size)?;
        self.collision_origins.insert(collision_key, original);
        self.files.insert(
            canonical.clone(),
            PlannedFile {
                path: canonical,
                components,
                bytes,
            },
        );
        self.source_bytes = next_size;
        Ok(())
    }
    fn finish(self) -> Result<PackageInventory, PackageError> {
        self.authority
            .revalidate()
            .map_err(|source| io_error("revalidate complete package", &self.root, source))?;
        enforce_file_limit(self.files.len())?;
        enforce_source_limit(self.source_bytes)?;
        let files = self.files.into_values().collect::<Vec<_>>();
        validate_musubi_portable_path_set_v1(files.iter().map(|file| file.components.as_slice()))
            .map_err(|error| PackageError::CarPlan(error.to_string()))?;
        Ok(PackageInventory {
            files,
            source_bytes: self.source_bytes,
        })
    }
}
fn validate_root(root: &Path) -> Result<PathBuf, PackageError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect package root", root, source))?;
    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(PackageError::InvalidRoot(root.to_path_buf()));
    }
    fs::canonicalize(root).map_err(|source| io_error("canonicalize package root", root, source))
}
fn validate_selector(selector: &Path) -> Result<PathBuf, PackageError> {
    if selector.is_absolute() {
        return Err(PackageError::InvalidSelector(selector.to_path_buf()));
    }
    let mut output = PathBuf::new();
    for component in selector.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                let value = component.to_str().ok_or_else(|| {
                    PackageError::NonPortablePath(selector.to_string_lossy().into_owned())
                })?;
                canonical_portable_component(value)?;
                output.push(value);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PackageError::InvalidSelector(selector.to_path_buf()));
            }
        }
    }
    validate_portable_relative_path(&output)?;
    Ok(output)
}
fn validate_portable_relative_path(path: &Path) -> Result<(), PackageError> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let portable = relative_to_utf8(path)?;
    canonical_portable_components(&portable).map(|_| ())
}
fn validate_no_symlink_chain(root: &Path, relative: &Path) -> Result<(), PackageError> {
    let mut current = root.to_path_buf();
    let mut shown = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        current.push(component);
        shown.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|source| io_error("inspect selected path", &shown, source))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(PackageError::Symlink(shown));
        }
    }
    Ok(())
}
fn validate_confined_directory(root: &Path, relative: &Path) -> Result<(), PackageError> {
    validate_no_symlink_chain(root, relative)?;
    let physical = root.join(relative);
    let metadata = fs::symlink_metadata(&physical)
        .map_err(|source| io_error("inspect package directory", relative, source))?;
    if metadata_is_link_or_reparse(&metadata) {
        return Err(PackageError::Symlink(relative.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(PackageError::SpecialFile(relative.to_path_buf()));
    }
    let canonical = fs::canonicalize(&physical)
        .map_err(|source| io_error("canonicalize package directory", relative, source))?;
    if !canonical.starts_with(root) {
        return Err(PackageError::InvalidSelector(relative.to_path_buf()));
    }
    Ok(())
}
fn validate_confined_parent(root: &Path, relative: &Path) -> Result<(), PackageError> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let canonical = fs::canonicalize(root.join(parent))
        .map_err(|source| io_error("canonicalize package file parent", parent, source))?;
    if !canonical.starts_with(root) {
        return Err(PackageError::InvalidSelector(relative.to_path_buf()));
    }
    Ok(())
}
fn validate_confined_file(root: &Path, relative: &Path) -> Result<(), PackageError> {
    // TODO: Replace these before/after namespace checks with retained, handle-relative directory
    // traversal when safe Rust exposes a portable no-follow/open-beneath primitive. The stable
    // file handle prevents final-entry substitution, while these checks fail ordinary ancestor
    // swaps; a deliberately timed ancestor ABA race remains an OS-specific fuzz gate.
    validate_no_symlink_chain(root, relative)?;
    let canonical = fs::canonicalize(root.join(relative))
        .map_err(|source| io_error("canonicalize package file", relative, source))?;
    if !canonical.starts_with(root) {
        return Err(PackageError::InvalidSelector(relative.to_path_buf()));
    }
    Ok(())
}
fn reject_explicit_excluded_or_sensitive(relative: &Path) -> Result<(), PackageError> {
    for component in relative.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        let value = component.to_str().ok_or_else(|| {
            PackageError::NonPortablePath(relative.to_string_lossy().into_owned())
        })?;
        if is_sensitive_component(value) {
            return Err(PackageError::SensitivePath(relative.to_path_buf()));
        }
        if is_excluded_directory(value) {
            return Err(PackageError::ExcludedPath(relative.to_path_buf()));
        }
    }
    Ok(())
}
fn relative_to_utf8(path: &Path) -> Result<String, PackageError> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(PackageError::NonPortablePath(
                path.to_string_lossy().into_owned(),
            ));
        };
        components.push(
            component
                .to_str()
                .ok_or_else(|| PackageError::NonPortablePath(path.to_string_lossy().into_owned()))?
                .to_owned(),
        );
    }
    if components.is_empty() {
        return Err(PackageError::NonPortablePath(String::new()));
    }
    Ok(components.join("/"))
}
fn canonical_portable_components(path: &str) -> Result<Vec<String>, PackageError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(PackageError::NonPortablePath(path.to_owned()));
    }
    let raw = path.split('/').collect::<Vec<_>>();
    if raw.len() > MAX_PATH_COMPONENTS {
        return Err(PackageError::NonPortablePath(path.to_owned()));
    }
    let mut canonical = Vec::with_capacity(raw.len());
    for component in raw {
        canonical.push(canonical_portable_component(component)?);
    }
    let bytes = canonical
        .iter()
        .map(String::len)
        .sum::<usize>()
        .saturating_add(canonical.len().saturating_sub(1));
    if bytes > MAX_PATH_BYTES {
        return Err(PackageError::NonPortablePath(path.to_owned()));
    }
    Ok(canonical)
}
fn canonical_portable_component(component: &str) -> Result<String, PackageError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_PATH_COMPONENT_BYTES
        || component.contains(['/', '\\', ':'])
        || component.chars().any(|character| {
            character.is_control()
                || is_bidi_control(character)
                || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
        })
        || component.ends_with(['.', ' '])
        || is_reserved_component(component)
    {
        return Err(PackageError::NonPortablePath(component.to_owned()));
    }
    normalize_nfc(component).map_err(|()| PackageError::NonPortablePath(component.to_owned()))
}
fn normalize_nfc(component: &str) -> Result<String, ()> {
    let mut output = String::with_capacity(component.len());
    let mut segment = String::new();
    let flush = |segment: &mut String, output: &mut String| -> Result<(), ()> {
        if segment.is_empty() {
            return Ok(());
        }
        let canonical = Name::normalize(segment).map_err(|_| ())?;
        let normalized = Name::from_str(&canonical).map_err(|_| ())?;
        output.push_str(normalized.as_ref());
        segment.clear();
        Ok(())
    };
    for character in component.chars() {
        if matches!(character, '@' | '#' | '$') || character.is_whitespace() {
            flush(&mut segment, &mut output)?;
            output.push(character);
        } else {
            segment.push(character);
        }
    }
    flush(&mut segment, &mut output)?;
    Ok(output)
}
fn portable_collision_key(components: &[String]) -> String {
    components
        .join("/")
        .chars()
        // Uppercase-then-lowercase also collapses multi-scalar mappings such as
        // `Straße`/`STRASSE` and final/non-final sigma. Rejecting these conservatively keeps one
        // package valid on Unicode-aware case-insensitive filesystems without platform probing.
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}
fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        true
    }
}
fn is_reserved_component(component: &str) -> bool {
    let basename = component.split('.').next().unwrap_or(component);
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
        .iter()
        .any(|reserved| basename.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    if let (Some(prefix), Some(suffix)) = (basename.get(..3), basename.get(3..)) {
        let numbered = prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT");
        let reserved_digit = suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9');
        return numbered && (reserved_digit || matches!(suffix, "¹" | "²" | "³"));
    }
    false
}
fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}
fn is_fixed_generated_file(path: &Path) -> bool {
    matches!(path.to_str(), Some(MANIFEST_PATH | VERIFICATION_LOCK_PATH))
}
pub fn is_excluded_directory(component: &str) -> bool {
    matches!(
        component.to_ascii_lowercase().as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | ".cargo"
            | ".config"
            | ".iroha"
            | ".musubi"
            | ".gradle"
            | ".idea"
            | ".vscode"
            | "target"
            | "dist"
            | "build"
            | "out"
            | "coverage"
            | "node_modules"
    )
}
pub fn is_sensitive_component(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "musubi.networks.toml" | "musubi.networks.lock"
    ) || lower == ".env"
        || lower.starts_with(".env.")
        || lower == ".envrc"
        || matches!(
            lower.as_str(),
            ".ssh"
                | ".gnupg"
                | ".aws"
                | ".azure"
                | ".kube"
                | ".docker"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | ".git-credentials"
                | ".authinfo"
                | ".authinfo.gpg"
                | "credentials"
                | "credentials.json"
                | "application_default_credentials.json"
                | "service-account.json"
                | "service_account.json"
                | "secrets"
                | "secrets.toml"
                | "private_key"
                | "private-key"
                | "secret_key"
                | "secret-key"
                | "mnemonic"
                | "id_rsa"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
        )
        || lower.starts_with("credentials.")
        || lower.starts_with("secrets.")
        || lower.contains("validator_secrets")
        || [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
}
fn sensitive_content_marker(bytes: &[u8]) -> Option<&'static str> {
    const FIXED: &[(&[u8], &str)] = &[
        (b"-----BEGIN PRIVATE KEY-----", "PKCS#8 private key"),
        (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "encrypted PKCS#8 private key",
        ),
        (b"-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
        (b"-----BEGIN DSA PRIVATE KEY-----", "DSA private key"),
        (b"-----BEGIN EC PRIVATE KEY-----", "EC private key"),
        (
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
            "OpenSSH private key",
        ),
        (
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "OpenPGP private key",
        ),
        (b"AGE-SECRET-KEY-", "age private key"),
    ];
    for (needle, label) in FIXED {
        if contains_ascii_case_insensitive(bytes, needle) {
            return Some(label);
        }
    }
    if contains_aws_access_key(bytes) {
        return Some("AWS access key");
    }
    for line in bytes.split(|byte| *byte == b'\n') {
        if sensitive_assignment(line) {
            return Some("credential assignment");
        }
    }
    None
}
#[cfg(all(test, unix))]
fn reject_consumer_only_lock_fields(value: &toml::Value) -> Result<(), PackageError> {
    const FORBIDDEN: &[&str] = &[
        "cache-path",
        "cache_path",
        "source-plan",
        "source_plan",
        "timestamp",
        "created-at",
        "created_at",
        "updated-at",
        "updated_at",
        "credential",
        "credentials",
        "provider-url",
        "provider_url",
        "bearer-token",
        "bearer_token",
        "stream-token",
        "stream_token",
        "private-key",
        "private_key",
    ];
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                if FORBIDDEN.iter().any(|forbidden| key == forbidden) {
                    return Err(PackageError::InvalidDocument {
                        document: VERIFICATION_LOCK_PATH,
                        reason: format!(
                            "consumer-only or secret-bearing field `{key}` is forbidden in a verification lock"
                        ),
                    });
                }
                reject_consumer_only_lock_fields(child)?;
            }
        }
        toml::Value::Array(values) => {
            for child in values {
                reject_consumer_only_lock_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn sensitive_assignment(line: &[u8]) -> bool {
    let input = trim_ascii(line);
    if sensitive_assignment_at(input) {
        return true;
    }
    // Retry only at object/statement boundaries. Each retry consumes at least one delimiter and
    // `sensitive_assignment_at` never scans the remaining line tail, keeping a maximum-size
    // single-line source bounded linearly rather than turning minified input into quadratic work.
    input.iter().enumerate().any(|(index, byte)| {
        matches!(*byte, b'{' | b'[' | b',' | b';' | b'#')
            && sensitive_assignment_at(&input[index + 1..])
    })
}
fn sensitive_assignment_at(line: &[u8]) -> bool {
    const KEYS: &[&[u8]] = &[
        b"private_key",
        b"private-key",
        b"privateKey",
        b"account_private_key",
        b"accountPrivateKey",
        b"iroha_private_key",
        b"irohaPrivateKey",
        b"secret_key",
        b"secret-key",
        b"secretKey",
        b"identity_private_key",
        b"identityPrivateKey",
        b"client_secret",
        b"client-secret",
        b"clientSecret",
        b"api_key",
        b"api-key",
        b"apiKey",
        b"access_token",
        b"access-token",
        b"accessToken",
        b"refresh_token",
        b"refresh-token",
        b"refreshToken",
        b"bearer_token",
        b"bearer-token",
        b"bearerToken",
        b"stream_token",
        b"stream-token",
        b"streamToken",
        b"aws_secret_access_key",
        b"awsSecretAccessKey",
        b"mnemonic",
        b"password",
        b"passphrase",
    ];
    const POWERSHELL_ENV_PREFIX: &[u8] = b"$env:";
    let mut input = trim_ascii_start(line);
    let mut allow_whitespace_separator = false;
    for (prefix, whitespace_separator) in [
        (b"export".as_slice(), false),
        (b"set".as_slice(), false),
        (b"setx".as_slice(), true),
        (b"let".as_slice(), false),
        (b"const".as_slice(), false),
        (b"var".as_slice(), false),
        (b"local".as_slice(), false),
        (b"readonly".as_slice(), false),
        (b"declare".as_slice(), false),
    ] {
        if input.len() > prefix.len()
            && input[..prefix.len()].eq_ignore_ascii_case(prefix)
            && input[prefix.len()].is_ascii_whitespace()
        {
            input = trim_ascii_start(&input[prefix.len()..]);
            allow_whitespace_separator = whitespace_separator;
            break;
        }
    }
    if input.len() > POWERSHELL_ENV_PREFIX.len()
        && input[..POWERSHELL_ENV_PREFIX.len()].eq_ignore_ascii_case(POWERSHELL_ENV_PREFIX)
    {
        input = &input[POWERSHELL_ENV_PREFIX.len()..];
    }
    let key_quote = input
        .first()
        .copied()
        .filter(|byte| matches!(byte, b'"' | b'\''));
    if key_quote.is_some() {
        input = &input[1..];
    }
    let Some(key) = KEYS
        .iter()
        .find(|key| input.len() >= key.len() && input[..key.len()].eq_ignore_ascii_case(key))
    else {
        return false;
    };
    input = &input[key.len()..];
    if key_quote.is_some() && input.first().copied() == key_quote {
        input = &input[1..];
    }
    let separated_by_whitespace = input.first().is_some_and(u8::is_ascii_whitespace);
    input = trim_ascii_start(input);
    let separator = input.first().copied();
    if matches!(separator, Some(b'=' | b':')) {
        input = trim_ascii_start(&input[1..]);
    } else if !(allow_whitespace_separator && separated_by_whitespace) {
        return false;
    }
    let value = match input.first().copied() {
        Some(quote @ (b'"' | b'\'')) => {
            let rest = &input[1..];
            let end = quoted_assignment_value_end(rest, quote);
            &rest[..end]
        }
        _ if separator == Some(b':') => {
            let end = input
                .iter()
                .position(|byte| matches!(byte, b',' | b';' | b'#' | b'}' | b']'))
                .unwrap_or(input.len());
            &input[..end]
        }
        _ => {
            let end = input
                .iter()
                .position(|byte| {
                    byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'#' | b']')
                })
                .unwrap_or(input.len());
            &input[..end]
        }
    };
    let value = trim_ascii(value);
    value.len() >= 24 && !is_secret_placeholder_reference(value)
}
fn quoted_assignment_value_end(value: &[u8], quote: u8) -> usize {
    let mut backslashes = 0_usize;
    for (index, byte) in value.iter().copied().enumerate() {
        if byte == quote && backslashes.is_multiple_of(2) {
            return index;
        }
        if byte == b'\\' {
            backslashes = backslashes.saturating_add(1);
        } else {
            backslashes = 0;
        }
    }
    value.len()
}
fn is_secret_placeholder_reference(value: &[u8]) -> bool {
    let identifier = |bytes: &[u8]| {
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };
    (value.starts_with(b"${")
        && value.ends_with(b"}")
        && identifier(&value[2..value.len().saturating_sub(1)]))
        || (value.starts_with(b"$") && identifier(&value[1..]))
        || (value.starts_with(b"%")
            && value.ends_with(b"%")
            && value.len() > 2
            && identifier(&value[1..value.len() - 1]))
}
fn contains_aws_access_key(bytes: &[u8]) -> bool {
    bytes.windows(20).any(|window| {
        matches!(&window[..4], b"AKIA" | b"ASIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}
fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}
fn source_tree_material(files: &[PlannedFile]) -> Vec<u8> {
    let mut output = Vec::new();
    append_frame(&mut output, SOURCE_TREE_DOMAIN);
    output.extend_from_slice(
        &u32::try_from(files.len())
            .expect("Musubi V1 file bound fits u32")
            .to_be_bytes(),
    );
    for file in files {
        append_frame(&mut output, file.path.as_bytes());
        output.extend_from_slice(
            &u64::try_from(file.bytes.len())
                .expect("Musubi V1 source bound fits u64")
                .to_be_bytes(),
        );
        output.extend_from_slice(blake3::hash(&file.bytes).as_bytes());
    }
    output
}
fn validate_sorafs_bundle_paths(files: &[PlannedFile]) -> Result<(), PackageError> {
    let mut entries = files
        .iter()
        .map(|file| FileEntry {
            path: file.components.clone(),
            data: Vec::new(),
        })
        .collect::<Vec<_>>();
    for path in [
        BUNDLE_RELEASE_PATH,
        BUNDLE_DESCRIPTOR_PATH,
        BUNDLE_VERIFICATION_LOCK_PATH,
    ] {
        entries.push(FileEntry {
            path: path.split('/').map(str::to_owned).collect(),
            data: Vec::new(),
        });
    }
    validate_musubi_portable_path_set_v1(entries.iter().map(|entry| entry.path.as_slice()))
        .map_err(|error| PackageError::CarPlan(error.to_string()))?;
    CarBuildPlan::from_files(entries)
        .map(|_| ())
        .map_err(|error| PackageError::CarPlan(error.to_string()))
}
fn descriptor_commitment_material(descriptor: &MusubiArtifactDescriptorV1) -> Vec<u8> {
    let mut output = Vec::new();
    append_frame(&mut output, ARTIFACT_DESCRIPTOR_DOMAIN);
    append_frame(&mut output, &descriptor.encode());
    output
}
fn bundle_commitment_material(
    semantic_release_manifest: &[u8],
    descriptor_material: &[u8],
    source_tree_material: &[u8],
    verification_lock: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    append_frame(&mut output, BUNDLE_DOMAIN);
    append_frame(&mut output, semantic_release_manifest);
    append_frame(&mut output, descriptor_material);
    append_frame(&mut output, source_tree_material);
    append_frame(&mut output, verification_lock);
    output
}
fn append_frame(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("bounded commitment material length fits u64")
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
}
fn domain_digest(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(
        &u64::try_from(material.len())
            .expect("bounded commitment material length fits u64")
            .to_be_bytes(),
    );
    hasher.update(material);
    *hasher.finalize().as_bytes()
}
fn enforce_file_limit(count: usize) -> Result<(), PackageError> {
    if count > MAX_SOURCE_FILES {
        return Err(PackageError::TooManyFiles {
            count,
            maximum: MAX_SOURCE_FILES,
        });
    }
    Ok(())
}
fn enforce_entry_limit(count: usize, maximum: usize) -> Result<(), PackageError> {
    if count > maximum {
        return Err(PackageError::TooManyEntries { count, maximum });
    }
    Ok(())
}
fn enforce_source_limit(bytes: u64) -> Result<(), PackageError> {
    if bytes > MAX_SOURCE_BYTES {
        return Err(PackageError::SourceTooLarge {
            bytes,
            maximum: MAX_SOURCE_BYTES,
        });
    }
    Ok(())
}
fn encode_verification_lock_bounded(
    verification_lock: &MusubiVerificationLockV1,
) -> Result<Vec<u8>, PackageError> {
    encode_verification_lock_bounded_with_limit(
        verification_lock,
        MUSUBI_MAX_VERIFICATION_LOCK_BYTES_V1,
    )
}
fn validate_semantic_release_encoded_bound(
    semantic_release: &MusubiSemanticReleaseManifestV1,
) -> Result<u64, PackageError> {
    validate_semantic_release_encoded_bound_with_limit(
        semantic_release,
        MUSUBI_MAX_BUNDLE_METADATA_FILE_BYTES_V1,
    )
}
fn validate_semantic_release_encoded_bound_with_limit(
    semantic_release: &MusubiSemanticReleaseManifestV1,
    maximum: u64,
) -> Result<u64, PackageError> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let payload_len = norito::core::encoded_payload_len(semantic_release).map_err(|error| {
        PackageError::InvalidBundleBinding(format!(
            "typed semantic release cannot be sized: {error}"
        ))
    })?;
    let payload_len =
        u64::try_from(payload_len).map_err(|_| PackageError::SemanticReleaseTooLarge {
            bytes: u64::MAX,
            maximum,
        })?;
    if payload_len > maximum {
        return Err(PackageError::SemanticReleaseTooLarge {
            bytes: payload_len,
            maximum,
        });
    }
    Ok(payload_len)
}
fn encode_verification_lock_bounded_with_limit(
    verification_lock: &MusubiVerificationLockV1,
    maximum: u64,
) -> Result<Vec<u8>, PackageError> {
    let payload_len =
        validate_verification_lock_encoded_bound_with_limit(verification_lock, maximum)?;
    let bytes = verification_lock.encode();
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != payload_len {
        return Err(PackageError::InvalidBundleBinding(
            "typed verification-lock length changed between admission and encoding".to_owned(),
        ));
    }
    Ok(bytes)
}
fn validate_verification_lock_encoded_bound(
    verification_lock: &MusubiVerificationLockV1,
) -> Result<u64, PackageError> {
    validate_verification_lock_encoded_bound_with_limit(
        verification_lock,
        MUSUBI_MAX_VERIFICATION_LOCK_BYTES_V1,
    )
}
fn validate_verification_lock_encoded_bound_with_limit(
    verification_lock: &MusubiVerificationLockV1,
    maximum: u64,
) -> Result<u64, PackageError> {
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let payload_len = norito::core::encoded_payload_len(verification_lock).map_err(|error| {
        PackageError::InvalidBundleBinding(format!(
            "typed verification lock cannot be sized: {error}"
        ))
    })?;
    let payload_len =
        u64::try_from(payload_len).map_err(|_| PackageError::VerificationLockTooLarge {
            bytes: u64::MAX,
            maximum,
        })?;
    if payload_len > maximum {
        return Err(PackageError::VerificationLockTooLarge {
            bytes: payload_len,
            maximum,
        });
    }
    Ok(payload_len)
}
fn enforce_chunk_limit(count: usize) -> Result<(), PackageError> {
    if count > MAX_SOURCE_CHUNKS {
        return Err(PackageError::TooManyChunks {
            count,
            maximum: MAX_SOURCE_CHUNKS,
        });
    }
    Ok(())
}
fn enforce_car_limit(bytes: u64) -> Result<(), PackageError> {
    if bytes > MAX_CAR_BYTES {
        return Err(PackageError::CarTooLarge {
            bytes,
            maximum: MAX_CAR_BYTES,
        });
    }
    Ok(())
}
fn io_error(operation: &'static str, path: &Path, source: io::Error) -> PackageError {
    PackageError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: u64,
    attempted: u64,
    exceeded: bool,
}
impl BoundedWriter {
    fn new(maximum: u64) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            attempted: 0,
            exceeded: false,
        }
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let additional = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("CAR write length does not fit u64"))?;
        self.attempted = u64::try_from(self.bytes.len())
            .ok()
            .and_then(|written| written.checked_add(additional))
            .unwrap_or(u64::MAX);
        if self.attempted > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("Musubi V1 CAR byte ceiling exceeded"));
        }
        self.bytes
            .try_reserve_exact(buffer.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::workspace::load_workspace;
    use iroha::crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        musubi::{
            MUSUBI_REGISTRY_VERSION_V1, MusubiAbiBindingV1, MusubiContentDigestV1,
            MusubiDependencyReqV1, MusubiKotodamaEditionV1, MusubiPackageIdV1,
            MusubiPackageScopeV1, MusubiReleaseIdV1, MusubiReleaseMetadataV1,
            MusubiSeedIngressReceiptBindingV1, MusubiSeedIngressReceiptV1,
            MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1,
        },
        sorafs::capacity::ProviderId,
    };
    use iroha_model_base::topology::DataSpaceId;
    use iroha_musubi_service::{
        AuthenticatedMusubiPublicationRuntimeClientV1, InMemoryMusubiPublicationServiceJournalV1,
        MusubiProviderReadbackBackendV1, MusubiProviderReadbackRequestV1,
        MusubiProviderReadbackResponseV1, MusubiPublicationPrivateServiceV1,
        MusubiPublicationServiceBackendErrorV1, MusubiPublicationServiceConfigurationV1,
        MusubiPublicationServiceJournalBindingV1, MusubiPublicationSystemClockV1,
        MusubiSeedIngressBackendV1, MusubiSeedIngressCarPlanV1, MusubiSeedIngressStageRequestV1,
        MusubiStorageCoordinationBackendV1, MusubiStorageCoordinationRequestV1,
        MusubiStorageCoordinationResponseV1, SoftwareMusubiPublicationRuntimeAuthorizationSignerV1,
        SoftwareMusubiSeedIngressReceiptSignerV1,
    };
    use std::{
        fs,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tempfile::tempdir;
    const MANIFEST: &str = r#"
manifest-version = 1

[package]
name = "demo"
version = "1.0.0"
"#;
    const SENSITIVE_PATH_COMPONENTS: [&str; 10] = [
        ".envrc",
        ".git-credentials",
        ".authinfo.gpg",
        "credentials.yaml",
        "application_default_credentials.json",
        "service-account.json",
        "secrets.json",
        "private_key",
        "secret-key",
        "mnemonic",
    ];
    fn base_layout(root: &Path) -> PackageLayout {
        let mut layout = PackageLayout::new(root);
        layout.set_library("src");
        layout
    }
    fn semantic_release() -> (MusubiSemanticReleaseManifestV1, MusubiVerificationLockV1) {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "demo".parse().expect("package name"),
        );
        let release = MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version"));
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: release.clone(),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let semantic = MusubiSemanticReleaseManifestV1 {
            release,
            edition: MusubiKotodamaEditionV1::V1,
            abi: MusubiAbiBindingV1::new([8; 32]).expect("ABI"),
            dependencies: Vec::new(),
            exports: Vec::new(),
            interface_digest: MusubiContentDigestV1::new([9; 32]),
            metadata: MusubiReleaseMetadataV1::default(),
            verification_lock_digest: lock.digest(),
        };
        (semantic, lock)
    }
    struct ExactPackageSeedBackend {
        provider: ProviderId,
        operation_id: [u8; 32],
        binding: MusubiSeedIngressReceiptBindingV1,
        commitment: MusubiArchiveCommitmentV1,
        plan: CarBuildPlan,
        car: Vec<u8>,
        admitted: Arc<AtomicBool>,
    }
    impl MusubiSeedIngressBackendV1 for ExactPackageSeedBackend {
        fn provider_id(&self) -> ProviderId {
            self.provider
        }
        fn stage_exact_car(
            &mut self,
            operation_id: [u8; 32],
            binding: &MusubiSeedIngressReceiptBindingV1,
            commitment: &MusubiArchiveCommitmentV1,
            plan: &CarBuildPlan,
            car: &[u8],
        ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
            if operation_id != self.operation_id
                || binding != &self.binding
                || commitment != &self.commitment
                || plan != &self.plan
                || car != self.car.as_slice()
            {
                return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
            }
            self.admitted.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn verify_staged_car(
            &self,
            operation_id: [u8; 32],
            binding: &MusubiSeedIngressReceiptBindingV1,
            commitment: &MusubiArchiveCommitmentV1,
            plan: &CarBuildPlan,
            car: &[u8],
        ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
            if !self.admitted.load(Ordering::SeqCst)
                || operation_id != self.operation_id
                || binding != &self.binding
                || commitment != &self.commitment
                || plan != &self.plan
                || car != self.car.as_slice()
            {
                return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
            }
            Ok(())
        }
    }
    struct UnusedPackageStorageBackend;
    impl MusubiStorageCoordinationBackendV1 for UnusedPackageStorageBackend {
        fn verify_current_registration(
            &self,
            _request: &MusubiStorageCoordinationRequestV1,
        ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        }

        fn coordinate_storage(
            &mut self,
            _request: &iroha_musubi_service::VerifiedStorageCoordinationRequestV1<'_>,
        ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1>
        {
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        }
    }
    struct UnusedPackageReadbackBackend;
    impl MusubiProviderReadbackBackendV1 for UnusedPackageReadbackBackend {
        fn verify_current_target(
            &self,
            _request: &MusubiProviderReadbackRequestV1,
        ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        }
        fn readback_provider(
            &mut self,
            _request: &MusubiProviderReadbackRequestV1,
        ) -> Result<MusubiProviderReadbackResponseV1, MusubiPublicationServiceBackendErrorV1>
        {
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        }
    }
    #[test]
    fn captures_declared_contract_source_closure_without_unrelated_files() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("contracts/parts")).unwrap();
        fs::create_dir_all(temp.path().join("modules")).unwrap();
        fs::write(
            temp.path().join("contracts/app.ko"),
            r#"seiyaku App {
            include "parts/state.ko";
            import "../modules/math.ko" as arithmetic;
            import seiyaku "pool.to" as Pool;
            view fn value() authorize(anyone) -> int { return arithmetic::twice(total); }
        }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("contracts/parts/state.ko"),
            r#"include "../init.ko"; state int total;"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("contracts/init.ko"),
            "hajimari() { total = 0; }",
        )
        .unwrap();
        fs::write(
            temp.path().join("modules/math.ko"),
            r#"module Math {
            include "operations.ko";
        }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("modules/operations.ko"),
            "export fn twice(int _ value) -> int { return value * 2; }",
        )
        .unwrap();
        fs::write(
            temp.path().join("modules/unrelated.ko"),
            "not even valid source",
        )
        .unwrap();
        fs::write(temp.path().join("contracts/pool.to"), [0, 255, 1]).unwrap();
        let mut layout = PackageLayout::new(temp.path());
        layout.add_contract("contracts/app.ko");
        let plan = plan_package(&layout, MANIFEST, &semantic_release().1).unwrap();
        assert_eq!(
            plan.files()
                .iter()
                .map(PlannedFile::path)
                .collect::<Vec<_>>(),
            [
                "Musubi.lock",
                "Musubi.toml",
                "contracts/app.ko",
                "contracts/init.ko",
                "contracts/parts/state.ko",
                "contracts/pool.to",
                "modules/math.ko",
                "modules/operations.ko",
            ]
        );
    }
    #[test]
    fn source_dependencies_resolve_before_portable_unicode_path_normalization() {
        let temp = tempdir().expect("tempdir");
        let directory = "cafe\u{301}";
        fs::create_dir(temp.path().join(directory)).unwrap();
        fs::write(
            temp.path().join(directory).join("app.ko"),
            r#"seiyaku App { include "part.ko"; }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join(directory).join("part.ko"),
            "state int total;",
        )
        .unwrap();
        let mut layout = PackageLayout::new(temp.path());
        layout.add_contract(format!("{directory}/app.ko"));
        let plan = plan_package(&layout, MANIFEST, &semantic_release().1).unwrap();
        assert!(
            plan.files()
                .iter()
                .any(|file| file.path() == "café/part.ko")
        );
    }
    #[test]
    fn source_dependencies_preserve_package_path_confinement() {
        let temp = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        let root = temp.path().join("app.ko");
        fs::write(&root, r#"seiyaku App { include "../outside.ko"; }"#).unwrap();
        let mut layout = PackageLayout::new(temp.path());
        layout.add_contract("app.ko");
        assert!(matches!(
            plan_package(&layout, MANIFEST, &semantic_release().1),
            Err(PackageError::InvalidSource { .. })
        ));
        fs::write(outside.path().join("part.ko"), "state int total;").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("part.ko"),
            temp.path().join("linked.ko"),
        )
        .unwrap();
        fs::write(&root, r#"seiyaku App { include "linked.ko"; }"#).unwrap();
        assert!(matches!(
            plan_package(&layout, MANIFEST, &semantic_release().1),
            Err(PackageError::Symlink(_))
        ));
        fs::write(&root, r#"seiyaku App { import "missing.ko" as helper; }"#).unwrap();
        assert!(matches!(
            plan_package(&layout, MANIFEST, &semantic_release().1),
            Err(PackageError::Io { .. })
        ));
    }
    #[test]
    fn plans_only_positive_files_in_byte_order() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/z.ko"), b"z").expect("z");
        fs::write(temp.path().join("src/a.ko"), b"a").expect("a");
        fs::write(temp.path().join("undeclared-secret.txt"), b"do not scan").expect("extra");
        let plan =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        let paths = plan
            .files()
            .iter()
            .map(PlannedFile::path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            ["Musubi.lock", "Musubi.toml", "src/a.ko", "src/z.ko"]
        );
        assert!(!paths.contains(&"undeclared-secret.txt"));
    }
    #[test]
    fn injects_canonical_documents_instead_of_disk_copies() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn main() {}").expect("source");
        fs::write(temp.path().join(MANIFEST_PATH), b"not the manifest").expect("disk manifest");
        fs::write(temp.path().join(VERIFICATION_LOCK_PATH), b"not the lock").expect("disk lock");
        let mut layout = base_layout(temp.path());
        layout.add_include(".");
        let plan = plan_package(&layout, MANIFEST, &semantic_release().1).expect("plan");
        assert_eq!(
            plan.canonical_manifest(),
            canonicalize_manifest_toml(MANIFEST).unwrap()
        );
        assert_eq!(
            plan.verification_lock(),
            render_verification_lock(&semantic_release().1)
                .expect("render verification lock")
                .as_bytes()
        );
    }
    #[test]
    fn canonical_toml_is_order_independent_and_requires_v1_markers() {
        let left = canonicalize_manifest_toml("manifest-version=1\nname='x'\n").expect("left");
        let right =
            canonicalize_manifest_toml("name = 'x'\nmanifest-version = 1\n").expect("right");
        assert_eq!(left, right);
        assert!(left.ends_with(b"\n"));
        assert!(matches!(
            canonicalize_manifest_toml("manifest-version=2"),
            Err(PackageError::InvalidDocument { .. })
        ));
        assert!(matches!(
            normalize_verification_lock_toml("version=3"),
            Err(PackageError::InvalidDocument { .. })
        ));
        assert!(matches!(
            normalize_verification_lock_toml(
                "schema='musubi-lock'\nversion=1\n[[package]]\ncache_path='/tmp/source'\n"
            ),
            Err(PackageError::InvalidDocument { .. })
        ));
    }
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture verifies one complete workspace-manifest publication projection"
    )]
    fn workspace_publication_manifest_resolves_inheritance_and_removes_local_state() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("app/src")).expect("app source");
        fs::create_dir_all(temp.path().join("dep/src")).expect("dep source");
        fs::create_dir_all(temp.path().join("shared")).expect("shared include");
        fs::write(temp.path().join("README.md"), "workspace readme").expect("readme");
        fs::write(temp.path().join("shared/note.txt"), "included").expect("include");
        fs::write(temp.path().join("app/src/lib.ko"), "module App {}").expect("app module");
        fs::write(temp.path().join("dep/src/lib.ko"), "module Dep {}").expect("dep module");
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[workspace]
members = ["app", "dep"]
[workspace.package]
namespace = "apps.sora"
version = "1.0.0"
edition = "1"
abi-version = 1
readme = "README.md"
include = ["shared"]
"#,
        )
        .expect("workspace manifest");
        fs::write(
            temp.path().join("app/Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = { workspace = true }
name = "app"
version = { workspace = true }
edition = { workspace = true }
abi-version = { workspace = true }
readme = { workspace = true }
include = { workspace = true }
[lib]
exports = []
[dependencies]
dep = { path = "../dep", package = "libs.sora/dep", version = "^1.0.0" }
[dev-dependencies]
test-kit = { package = "libs.sora/test-kit", version = "^1.0.0" }
"#,
        )
        .expect("app manifest");
        fs::write(
            temp.path().join("dep/Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "libs.sora"
name = "dep"
version = "1.2.0"
edition = "1"
abi-version = 1
[lib]
exports = []
"#,
        )
        .expect("dep manifest");
        let workspace = load_workspace(&temp.path().join("app")).expect("workspace");
        let member = workspace
            .members()
            .values()
            .find(|member| member.package.selector.to_string() == "apps.sora/app")
            .expect("app member");
        let rendered = publication_manifest_toml(member).expect("publication manifest");
        let manifest = crate::manifest::parse_manifest(&rendered).expect("strict clean manifest");
        assert!(manifest.workspace.is_none());
        assert!(manifest.dev_dependencies.is_empty());
        let dependency_alias: iroha_model_base::name::Name =
            "dep".parse().expect("dependency alias");
        assert!(matches!(
            &manifest.dependencies[&dependency_alias],
            crate::manifest::DependencySpec::Concrete(
                crate::manifest::ConcreteDependency::Registry { .. }
            )
        ));
        let clean_package = manifest.resolve_package(None).expect("concrete package");
        assert_eq!(
            clean_package
                .readme
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("README.md")
        );
        assert_eq!(
            clean_package
                .include
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["shared"]
        );
        let layout = package_layout_for_member(workspace.root(), member);
        let plan = plan_package(&layout, &rendered, &semantic_release().1).expect("package plan");
        let paths = plan
            .files()
            .iter()
            .map(PlannedFile::path)
            .collect::<Vec<_>>();
        assert!(paths.contains(&"README.md"));
        assert!(paths.contains(&"shared/note.txt"));
        assert!(paths.contains(&"src/lib.ko"));
    }
    #[test]
    fn publication_manifest_rejects_local_only_normal_path_dependencies() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("app/src")).expect("app source");
        fs::create_dir_all(temp.path().join("dep/src")).expect("dep source");
        fs::write(temp.path().join("app/src/lib.ko"), "module App {}").expect("app module");
        fs::write(temp.path().join("dep/src/lib.ko"), "module Dep {}").expect("dep module");
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[workspace]
members = ["app", "dep"]
"#,
        )
        .expect("workspace manifest");
        fs::write(
            temp.path().join("app/Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "app"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
exports = []
[dependencies]
dep = { path = "../dep" }
"#,
        )
        .expect("app manifest");
        fs::write(
            temp.path().join("dep/Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "dep"
version = "1.0.0"
edition = "1"
abi-version = 1
[lib]
exports = []
"#,
        )
        .expect("dep manifest");
        let workspace = load_workspace(&temp.path().join("app")).expect("workspace");
        let member = workspace
            .members()
            .values()
            .find(|member| member.package.selector.to_string() == "apps.sora/app")
            .expect("app member");
        assert!(matches!(
            publication_manifest_toml(member),
            Err(PackageError::InvalidDocument { reason, .. })
                if reason.contains("publishable normal path dependency")
        ));
    }
    #[test]
    fn semantic_release_manifest_binds_typed_interface_and_metadata() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("src")).expect("source");
        fs::write(temp.path().join("src/lib.ko"), "module Demo {}").expect("module");
        fs::write(temp.path().join("README.md"), "readme").expect("readme");
        fs::write(
            temp.path().join("Musubi.toml"),
            r#"manifest-version = 1
[package]
namespace = "apps.sora"
name = "demo"
version = "1.0.0"
edition = "1"
abi-version = 1
description = "Typed package"
readme = "README.md"
license = "Apache-2.0"
repository = "https://example.com/musubi"
keywords = ["contracts", "typed"]
[lib]
exports = []
"#,
        )
        .expect("manifest");
        let workspace = load_workspace(temp.path()).expect("workspace");
        let member = workspace.members().values().next().expect("member");
        let (_, lock) = semantic_release();
        let interface = MusubiContentDigestV1::new([42; 32]);
        let semantic = semantic_release_manifest(member, lock.root.clone(), &lock, interface)
            .expect("semantic release");
        assert_eq!(semantic.interface_digest, interface);
        assert_eq!(
            semantic
                .metadata
                .description
                .as_ref()
                .map(MusubiDescriptionV1::as_str),
            Some("Typed package")
        );
        assert_eq!(semantic.metadata.keywords.len(), 2);
        assert_eq!(semantic.verification_lock_digest, lock.digest());
    }
    #[test]
    fn excludes_generated_roots_but_rejects_explicit_selection() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("src/target")).expect("target");
        fs::write(temp.path().join("src/target/generated.ko"), b"generated").expect("generated");
        // Worktrees may represent `.git` as a marker file rather than a directory. Ambient
        // traversal must exclude both forms.
        fs::write(temp.path().join("src/.git"), b"gitdir: ../../metadata").expect("git marker");
        fs::write(temp.path().join("src/lib.ko"), b"source").expect("source");
        let plan =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        assert!(
            !plan
                .files()
                .iter()
                .any(|file| file.path().contains("target"))
        );
        assert!(!plan.files().iter().any(|file| file.path() == "src/.git"));
        let mut explicit = PackageLayout::new(temp.path());
        explicit.add_include("src/target");
        assert!(matches!(
            plan_package(&explicit, MANIFEST, &semantic_release().1),
            Err(PackageError::ExcludedPath(_))
        ));
        let mut explicit_marker = PackageLayout::new(temp.path());
        explicit_marker.add_include("src/.git");
        assert!(matches!(
            plan_package(&explicit_marker, MANIFEST, &semantic_release().1),
            Err(PackageError::ExcludedPath(_))
        ));
    }
    #[test]
    fn rejects_overdeep_empty_directory_trees_before_recursing_past_v1_bounds() {
        let temp = tempdir().expect("tempdir");
        let mut directory = temp.path().join("src");
        fs::create_dir(&directory).expect("src");
        for index in 0..MAX_PATH_COMPONENTS {
            directory.push(format!("d{index}"));
            fs::create_dir(&directory).expect("nested directory");
        }
        assert!(matches!(
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1),
            Err(PackageError::NonPortablePath(_))
        ));
    }
    #[test]
    fn rejects_traversal_absolute_and_portable_reserved_paths() {
        let temp = tempdir().expect("tempdir");
        let mut traversal = PackageLayout::new(temp.path());
        traversal.add_include("../outside");
        assert!(matches!(
            plan_package(&traversal, MANIFEST, &semantic_release().1),
            Err(PackageError::InvalidSelector(_))
        ));
        let mut absolute = PackageLayout::new(temp.path());
        absolute.add_include(temp.path());
        assert!(matches!(
            plan_package(&absolute, MANIFEST, &semantic_release().1),
            Err(PackageError::InvalidSelector(_))
        ));
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/CON.ko"), b"reserved").expect("reserved");
        assert!(matches!(
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1),
            Err(PackageError::NonPortablePath(_))
        ));
    }
    #[test]
    fn rejects_every_portable_reserved_and_control_name_class() {
        for component in [
            "CON",
            "con.txt",
            "PRN.log",
            "AUX",
            "NUL.tar",
            "CLOCK$.ko",
            "CONIN$.txt",
            "CONOUT$.txt",
            "COM1.ko",
            "com\u{b9}.ko",
            "LPT9.ko",
            "lpt\u{b2}.ko",
            "trailing.",
            "trailing ",
            "colon:name",
            "question?name",
            "bidirectional\u{202e}name",
        ] {
            assert!(
                matches!(
                    canonical_portable_component(component),
                    Err(PackageError::NonPortablePath(_))
                ),
                "portable reserved/control name was accepted: {component:?}"
            );
        }
        for component in ["COM0.ko", "COM10.ko", "LPT0.ko", "console.ko"] {
            assert!(
                canonical_portable_component(component).is_ok(),
                "non-reserved portable name was rejected: {component:?}"
            );
        }
    }
    #[test]
    fn rejects_case_and_unicode_equivalent_collisions() {
        // Exercise the logical-path index directly: common macOS filesystems collapse these
        // names before `read_dir`, while the portable package check must behave identically on
        // case-sensitive and case-insensitive hosts.
        let case = tempdir().expect("tempdir");
        let mut collector =
            Collector::new(case.path().to_path_buf()).expect("retained package root");
        collector
            .insert_virtual("src/Foo.ko", b"one".to_vec())
            .expect("first case spelling");
        assert!(matches!(
            collector.insert_virtual("src/foo.ko", b"two".to_vec()),
            Err(PackageError::PathCollision { .. })
        ));
        let unicode = tempdir().expect("tempdir");
        let mut collector =
            Collector::new(unicode.path().to_path_buf()).expect("retained package root");
        collector
            .insert_virtual("src/caf\u{e9}.ko", b"one".to_vec())
            .expect("first Unicode spelling");
        assert!(matches!(
            collector.insert_virtual("src/cafe\u{301}.ko", b"two".to_vec()),
            Err(PackageError::PathCollision { .. })
        ));
        let caseless = tempdir().expect("tempdir");
        let mut collector =
            Collector::new(caseless.path().to_path_buf()).expect("retained package root");
        collector
            .insert_virtual("src/Straße.ko", b"one".to_vec())
            .expect("first full case mapping");
        assert!(matches!(
            collector.insert_virtual("src/STRASSE.ko", b"two".to_vec()),
            Err(PackageError::PathCollision { .. })
        ));
        let prefix = tempdir().expect("tempdir");
        let mut collector =
            Collector::new(prefix.path().to_path_buf()).expect("retained package root");
        collector
            .insert_virtual("Foo", b"one".to_vec())
            .expect("case-sensitive file spelling");
        collector
            .insert_virtual("foo/z.ko", b"two".to_vec())
            .expect("case-sensitive directory spelling");
        assert!(matches!(collector.finish(), Err(PackageError::CarPlan(_))));
    }
    #[test]
    fn normalizes_a_single_decomposed_unicode_path() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/cafe\u{301}.ko"), b"source").expect("source");
        let plan =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        assert!(
            plan.files()
                .iter()
                .any(|file| file.path() == "src/caf\u{e9}.ko")
        );
    }
    #[test]
    fn rejects_sensitive_paths_and_contents_without_echoing_secrets() {
        assert!(is_sensitive_component("Musubi.networks.toml"));
        assert!(is_sensitive_component("Musubi.networks.lock"));
        assert!(is_sensitive_component("MUSUBI.NETWORKS.TOML"));
        for path in SENSITIVE_PATH_COMPONENTS {
            assert!(is_sensitive_component(path), "{path}");
        }
        let path_case = tempdir().expect("tempdir");
        fs::create_dir(path_case.path().join("src")).expect("src");
        fs::write(path_case.path().join("src/id_ed25519"), b"secret").expect("key");
        assert!(matches!(
            plan_package(
                &base_layout(path_case.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::SensitivePath(_))
        ));
        let content_case = tempdir().expect("tempdir");
        fs::create_dir(content_case.path().join("src")).expect("src");
        fs::write(
            content_case.path().join("src/lib.ko"),
            b"-----BEGIN PRIVATE KEY-----\nvery-secret-value",
        )
        .expect("source");
        let error = plan_package(
            &base_layout(content_case.path()),
            MANIFEST,
            &semantic_release().1,
        )
        .expect_err("private key must fail");
        assert!(matches!(error, PackageError::SensitiveContent { .. }));
        assert!(!error.to_string().contains("very-secret-value"));
        assert_eq!(
            sensitive_content_marker(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque"),
            Some("encrypted PKCS#8 private key")
        );
        assert_eq!(
            sensitive_content_marker(b"-----BEGIN DSA PRIVATE KEY-----\nopaque"),
            Some("DSA private key")
        );
        for assignment in [
            b"export PRIVATE_KEY=0123456789abcdef0123456789abcdef".as_slice(),
            b"set CLIENT_SECRET=0123456789abcdef0123456789abcdef".as_slice(),
            b"setx API_KEY 0123456789abcdef0123456789abcdef".as_slice(),
            b"setx \"API_KEY\" \"0123456789abcdef0123456789abcdef\"".as_slice(),
            b"$env:ACCESS_TOKEN = '0123456789abcdef0123456789abcdef'".as_slice(),
            b"\"refresh_token\": \"0123456789abcdef0123456789abcdef\"".as_slice(),
            b"{'clientSecret':'0123456789abcdef0123456789abcdef'}".as_slice(),
            b"{\"safe\":1,\"refreshToken\":\"0123456789abcdef0123456789abcdef\"}".as_slice(),
            b"password = \"correct horse battery staple 1234\"".as_slice(),
            b"passphrase='A!long:punc?tuation/value+0123456789'".as_slice(),
            b"let apiKey = \"0123456789abcdef0123456789abcdef\"".as_slice(),
            b"const clientSecret = '0123456789abcdef0123456789abcdef'".as_slice(),
            b"password: correct horse battery staple 1234".as_slice(),
            b"password = \"short\\\"0123456789abcdef0123456789abcdef\"".as_slice(),
            b"password = 0123456789abcdef0123456789abcdef".as_slice(),
        ] {
            assert!(
                sensitive_assignment(assignment),
                "credential assignment was accepted"
            );
        }
        assert!(!sensitive_assignment(b"export PRIVATE_KEY=${PRIVATE_KEY}"));
        assert!(!sensitive_assignment(
            b"export PRIVATE_KEY=${A_VERY_LONG_PRIVATE_KEY_PLACEHOLDER}"
        ));
        assert!(sensitive_assignment(
            b"export PRIVATE_KEY=${PLACEHOLDER}0123456789abcdef0123456789abcdef"
        ));
        assert!(!sensitive_assignment(
            b"set API_KEY=%A_VERY_LONG_API_KEY_NAME%"
        ));
        assert!(!sensitive_assignment(b"password = short-placeholder"));
        assert!(!sensitive_assignment(
            b"{\"apiKeySuffix\":\"0123456789abcdef0123456789abcdef\"}"
        ));
        let exported_secret = tempdir().expect("tempdir");
        fs::create_dir(exported_secret.path().join("src")).expect("src");
        fs::write(
            exported_secret.path().join("src/lib.ko"),
            b"export CLIENT_SECRET=0123456789abcdef0123456789abcdef",
        )
        .expect("credential-bearing source");
        assert!(matches!(
            plan_package(
                &base_layout(exported_secret.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::SensitiveContent {
                marker: "credential assignment",
                ..
            })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_hardlinks_special_files_and_non_utf8_paths() {
        use std::{
            ffi::OsString,
            os::unix::{ffi::OsStringExt as _, fs::symlink, net::UnixListener},
        };
        let symlinks = tempdir().expect("tempdir");
        fs::create_dir(symlinks.path().join("src")).expect("src");
        fs::write(symlinks.path().join("outside.ko"), b"outside").expect("outside");
        symlink("../outside.ko", symlinks.path().join("src/link.ko")).expect("symlink");
        assert!(matches!(
            plan_package(
                &base_layout(symlinks.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::Symlink(_))
        ));
        let ancestor = tempdir().expect("tempdir");
        fs::create_dir(ancestor.path().join("src")).expect("src");
        fs::create_dir(ancestor.path().join("outside")).expect("outside directory");
        fs::write(ancestor.path().join("outside/secret.ko"), b"outside").expect("outside");
        symlink("../outside", ancestor.path().join("src/linked"))
            .expect("ancestor directory symlink");
        let mut escaped_include = PackageLayout::new(ancestor.path());
        escaped_include.add_include("src/linked/secret.ko");
        assert!(matches!(
            plan_package(&escaped_include, MANIFEST, &semantic_release().1),
            Err(PackageError::Symlink(path)) if path == Path::new("src/linked")
        ));
        let linked_root_parent = tempdir().expect("tempdir");
        let real_root = linked_root_parent.path().join("real-root");
        fs::create_dir(&real_root).expect("real root");
        let linked_root = linked_root_parent.path().join("linked-root");
        symlink(&real_root, &linked_root).expect("linked package root");
        assert!(matches!(
            plan_package(
                &PackageLayout::new(&linked_root),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::InvalidRoot(path)) if path == linked_root
        ));
        let hardlinks = tempdir().expect("tempdir");
        fs::create_dir(hardlinks.path().join("src")).expect("src");
        fs::write(hardlinks.path().join("src/a.ko"), b"source").expect("source");
        fs::hard_link(
            hardlinks.path().join("src/a.ko"),
            hardlinks.path().join("src/b.ko"),
        )
        .expect("hardlink");
        assert!(matches!(
            plan_package(
                &base_layout(hardlinks.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::Hardlink(_))
        ));
        let special = tempdir().expect("tempdir");
        fs::create_dir(special.path().join("src")).expect("src");
        let _socket = UnixListener::bind(special.path().join("src/socket")).expect("socket");
        assert!(matches!(
            plan_package(
                &base_layout(special.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::SpecialFile(_))
        ));
        let non_utf8 = tempdir().expect("tempdir");
        fs::create_dir(non_utf8.path().join("src")).expect("src");
        let mut non_utf8_selector = PackageLayout::new(non_utf8.path());
        non_utf8_selector.add_include(PathBuf::from(OsString::from_vec(vec![
            0xff, b'.', b'k', b'o',
        ])));
        assert!(matches!(
            plan_package(&non_utf8_selector, MANIFEST, &semantic_release().1),
            Err(PackageError::NonPortablePath(_))
        ));
        if fs::write(
            non_utf8
                .path()
                .join("src")
                .join(OsString::from_vec(vec![0xff, b'.', b'k', b'o'])),
            b"source",
        )
        .is_err()
        {
            // Some filesystems (including the default macOS filesystem) reject a raw
            // non-UTF-8 directory entry before Musubi can observe it.
            return;
        }
        assert!(matches!(
            plan_package(
                &base_layout(non_utf8.path()),
                MANIFEST,
                &semantic_release().1
            ),
            Err(PackageError::NonPortablePath(_))
        ));
    }
    #[test]
    fn exposed_car_plan_exactly_binds_the_archive_commitment() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn demo() {}").expect("source");
        let package =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        let (semantic, lock) = semantic_release();
        let car = package.into_car(&semantic, &lock).expect("CAR");
        let plan = car.plan();
        let commitment = car.archive_commitment().expect("archive commitment");
        plan.validate().expect("exposed plan validates");
        assert_eq!(plan.payload_digest, blake3::hash(car.payload()));
        assert_eq!(plan.content_length, commitment.content_length);
        assert_eq!(
            plan.chunks.len(),
            usize::try_from(commitment.chunk_count).expect("chunk count fits usize")
        );
        assert_eq!(
            commitment.chunk_plan_digest,
            MusubiContentDigestV1::new(compute_chunk_plan_digest_sha3(&plan.chunks))
        );
        let mandatory_bundle_paths = [
            BUNDLE_RELEASE_PATH,
            BUNDLE_DESCRIPTOR_PATH,
            BUNDLE_VERIFICATION_LOCK_PATH,
        ];
        for path in mandatory_bundle_paths {
            assert_eq!(
                plan.files
                    .iter()
                    .filter(|file| file.path.join("/") == path)
                    .count(),
                1,
                "the canonical bundle must contain {path} exactly once"
            );
        }
        let source_file_count =
            usize::try_from(commitment.file_count).expect("source file count fits usize");
        assert_eq!(source_file_count, car.source_file_count());
        assert_eq!(
            plan.files.len(),
            source_file_count + mandatory_bundle_paths.len()
        );
        let wire_plan = iroha_musubi_service::MusubiSeedIngressCarPlanV1::from_car_build_plan(
            plan,
            &commitment,
        )
        .expect("package plan converts to the exact seed-ingress witness");
        assert_eq!(
            wire_plan
                .to_car_build_plan(&commitment)
                .expect("seed-ingress witness reconstructs the package plan"),
            *plan
        );
    }
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture verifies the complete package-CAR private seed admission path"
    )]
    fn produced_package_car_is_admitted_by_the_private_seed_service() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn admitted() {}").expect("source");
        let package =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        let (semantic, lock) = semantic_release();
        let car = package
            .into_car(&semantic, &lock)
            .expect("producer package CAR");
        let commitment = car.archive_commitment().expect("archive commitment");
        let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(car.plan(), &commitment)
            .expect("seed-ingress witness");
        let publisher_key = KeyPair::try_from_seed(
            b"musubi-package-service-publisher".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("publisher key");
        let publisher = AccountId::new(publisher_key.public_key().clone());
        let authorization_signer = SoftwareMusubiPublicationRuntimeAuthorizationSignerV1::new(
            publisher.clone(),
            publisher_key,
        )
        .expect("publisher signer");
        let genesis_block_hash = [0x45; 32];
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(genesis_block_hash)),
        );
        let runtime = AuthenticatedMusubiPublicationRuntimeClientV1::from_authorization_signer(
            network_id,
            publisher.clone(),
            Arc::new(authorization_signer),
            Duration::from_secs(5),
        )
        .expect("authenticated runtime");
        let broker_key = KeyPair::try_from_seed(
            b"musubi-package-service-broker".to_vec(),
            Algorithm::Ed25519,
        )
        .expect("broker key");
        let broker = AccountId::new(broker_key.public_key().clone());
        let provider = ProviderId::new([0x43; 32]);
        let operation_id = [0x44; 32];
        let binding = MusubiSeedIngressReceiptBindingV1 {
            network_id,
            publisher,
            ingress_broker: broker.clone(),
            seed_provider: provider,
            semantic_release_manifest_digest: semantic.semantic_digest(),
            archive_id: commitment.archive_id(),
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [0x46; 32],
        };
        let request = MusubiSeedIngressStageRequestV1 {
            version: 1,
            operation_id,
            binding: binding.clone(),
            commitment: commitment.clone(),
            plan_digest: witness.canonical_digest().expect("plan digest"),
            plan_length: witness.canonical_len().expect("plan length"),
        };
        let mut car_reader = car.bytes();
        let prepared = runtime
            .prepare_seed_ingress_request(
                &url::Url::parse("https://seed.example/").expect("publication root"),
                &request,
                car.plan(),
                &mut car_reader,
            )
            .expect("memory-only prepared request");
        assert!(prepared.authorization_expires_at_ms() > prepared.authorization_issued_at_ms());
        let config = MusubiPublicationServiceConfigurationV1 {
            network_id,
            ingress_broker: broker.clone(),
            seed_provider: provider,
            max_future_clock_skew_ms: 2_000,
            receipt_lifetime_ms: 60_000,
        };
        let journal_binding = MusubiPublicationServiceJournalBindingV1::from_configuration(&config);
        let admitted = Arc::new(AtomicBool::new(false));
        let seed_backend = ExactPackageSeedBackend {
            provider,
            operation_id,
            binding,
            commitment,
            plan: car.plan().clone(),
            car: car.bytes().to_vec(),
            admitted: Arc::clone(&admitted),
        };
        let receipt_signer = SoftwareMusubiSeedIngressReceiptSignerV1::new(broker, broker_key)
            .expect("receipt signer");
        let mut service = MusubiPublicationPrivateServiceV1::new(
            config,
            Box::new(MusubiPublicationSystemClockV1),
            Box::new(receipt_signer),
            Box::new(
                InMemoryMusubiPublicationServiceJournalV1::new(journal_binding, 4, 8)
                    .expect("bounded journal"),
            ),
            Box::new(seed_backend),
            Box::new(UnusedPackageStorageBackend),
            Box::new(UnusedPackageReadbackBackend),
        )
        .expect("private seed service");
        let response = service.handle(prepared.as_private_http_request());
        assert_eq!(response.status, 200);
        assert!(admitted.load(Ordering::SeqCst));
        let receipt: MusubiSeedIngressReceiptV1 =
            norito::decode_canonical(&response.body).expect("seed receipt");
        receipt
            .verify(prepared.binding(), receipt.payload.issued_at_ms)
            .expect("exact producer receipt binding");
    }
    #[test]
    fn exact_source_payload_ceiling_leaves_room_for_bundle_metadata() {
        let (semantic, lock) = semantic_release();
        let manifest = canonicalize_manifest_toml(MANIFEST).expect("canonical manifest");
        let verification_lock = render_verification_lock(&lock)
            .expect("verification lock")
            .into_bytes();
        let maximum = usize::try_from(MAX_SOURCE_BYTES).expect("source ceiling fits usize");
        let source_length = maximum
            .checked_sub(manifest.len())
            .and_then(|remaining| remaining.checked_sub(verification_lock.len()))
            .expect("fixture metadata fits below the source ceiling");
        let plan = PackagePlan {
            files: vec![
                PlannedFile {
                    path: VERIFICATION_LOCK_PATH.to_owned(),
                    components: vec![VERIFICATION_LOCK_PATH.to_owned()],
                    bytes: verification_lock,
                },
                PlannedFile {
                    path: MANIFEST_PATH.to_owned(),
                    components: vec![MANIFEST_PATH.to_owned()],
                    bytes: manifest,
                },
                PlannedFile {
                    path: "src/lib.ko".to_owned(),
                    components: vec!["src".to_owned(), "lib.ko".to_owned()],
                    bytes: vec![b'x'; source_length],
                },
            ],
            source_bytes: MAX_SOURCE_BYTES,
        };
        let car = plan
            .into_car(&semantic, &lock)
            .expect("source-limit package still fits the larger bundle/CAR ceilings");
        let commitment = car
            .archive_commitment()
            .expect("source-limit bundle has a valid archive commitment");
        assert!(commitment.content_length > MAX_SOURCE_BYTES);
        assert!(
            commitment.content_length
                <= iroha_data_model::musubi::MUSUBI_MAX_BUNDLE_PAYLOAD_BYTES_V1
        );
    }
    #[test]
    fn typed_bundle_metadata_is_admitted_before_allocation() {
        let (semantic, lock) = semantic_release();
        let expected = lock.encode();
        let exact = u64::try_from(expected.len()).expect("encoded lock length fits u64");
        assert_eq!(
            encode_verification_lock_bounded_with_limit(&lock, exact)
                .expect("exact typed-lock byte bound"),
            expected
        );
        assert!(matches!(
            encode_verification_lock_bounded_with_limit(&lock, exact - 1),
            Err(PackageError::VerificationLockTooLarge { bytes, maximum })
                if bytes == exact && maximum == exact - 1
        ));
        let semantic_exact = u64::try_from(semantic.encode().len())
            .expect("encoded semantic-release length fits u64");
        assert_eq!(
            validate_semantic_release_encoded_bound_with_limit(&semantic, semantic_exact)
                .expect("exact semantic-release byte bound"),
            semantic_exact
        );
        assert!(matches!(
            validate_semantic_release_encoded_bound_with_limit(&semantic, semantic_exact - 1),
            Err(PackageError::SemanticReleaseTooLarge { bytes, maximum })
                if bytes == semantic_exact && maximum == semantic_exact - 1
        ));
    }
    #[test]
    fn commitments_and_car_are_deterministic() {
        let left = tempdir().expect("tempdir");
        let right = tempdir().expect("tempdir");
        for root in [left.path(), right.path()] {
            fs::create_dir(root.join("src")).expect("src");
        }
        fs::write(left.path().join("src/b.ko"), b"b").expect("b");
        fs::write(left.path().join("src/a.ko"), b"a").expect("a");
        fs::write(right.path().join("src/a.ko"), b"a").expect("a");
        fs::write(right.path().join("src/b.ko"), b"b").expect("b");
        let left_plan = plan_package(&base_layout(left.path()), MANIFEST, &semantic_release().1)
            .expect("left plan");
        let right_plan = plan_package(&base_layout(right.path()), MANIFEST, &semantic_release().1)
            .expect("right plan");
        let (semantic, lock) = semantic_release();
        let left_commitments = left_plan
            .commitment_materials(&semantic, &lock)
            .expect("left commitments");
        let right_commitments = right_plan
            .commitment_materials(&semantic, &lock)
            .expect("right commitments");
        assert_eq!(left_commitments, right_commitments);
        assert_eq!(left_commitments.descriptor().version, 1);
        assert_eq!(
            left_commitments
                .descriptor()
                .semantic_release_manifest_digest,
            semantic.semantic_digest()
        );
        assert_eq!(
            left_commitments.descriptor().verification_lock_digest,
            lock.digest()
        );
        let encoded_descriptor = left_commitments.descriptor().encode();
        let decoded_descriptor =
            MusubiArtifactDescriptorV1::decode(&mut encoded_descriptor.as_slice())
                .expect("decode descriptor");
        assert_eq!(&decoded_descriptor, left_commitments.descriptor());
        let left_car = left_plan.into_car(&semantic, &lock).expect("left CAR");
        let right_car = right_plan.into_car(&semantic, &lock).expect("right CAR");
        assert_eq!(left_car.bytes(), right_car.bytes());
        assert_eq!(left_car.commitments(), &left_commitments);
        assert_eq!(left_car.source_file_count(), 4);
        assert_eq!(left_car.plan().files.len(), 7);
        assert!(
            left_car
                .plan()
                .files
                .iter()
                .any(|file| file.path.join("/") == BUNDLE_RELEASE_PATH)
        );
        assert!(
            left_car
                .plan()
                .files
                .iter()
                .any(|file| file.path.join("/") == BUNDLE_DESCRIPTOR_PATH)
        );
        assert!(
            left_car
                .plan()
                .files
                .iter()
                .any(|file| file.path.join("/") == BUNDLE_VERIFICATION_LOCK_PATH)
        );
        assert!(left_car.bytes().len() as u64 <= MAX_CAR_BYTES);
        assert!(left_car.plan().chunks.len() <= MAX_SOURCE_CHUNKS);
        let left_archive = left_car
            .archive_commitment()
            .expect("left archive commitment");
        let right_archive = right_car
            .archive_commitment()
            .expect("right archive commitment");
        assert_eq!(left_archive, right_archive);
        assert_eq!(left_archive.file_count, 4);
        assert_eq!(
            usize::try_from(left_archive.chunk_count).expect("chunk count fits usize"),
            left_car.plan().chunks.len()
        );
        assert_eq!(left_archive.archive_id(), right_archive.archive_id());
        assert_eq!(
            left_archive.car_digest.as_bytes(),
            left_car.stats().car_archive_digest.as_bytes()
        );
        let publication = publication_claim(
            &semantic,
            &left_archive,
            MusubiRegistrySnapshotV1 {
                finalized_height: 10,
                finalized_block_hash: [7; 32],
                index_revision: 3,
            },
            lock,
        )
        .expect("archive-bound publication claim");
        assert_eq!(publication.manifest.archive_id, left_archive.archive_id());
        assert_eq!(publication.manifest.semantic_manifest(), semantic);
        assert!(!publication.manifest.release_digest().is_zero());
    }
    #[test]
    fn semantic_bundle_rejects_a_different_exact_lock() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn demo() {}").expect("source");
        let plan =
            plan_package(&base_layout(temp.path()), MANIFEST, &semantic_release().1).expect("plan");
        let (semantic, mut lock) = semantic_release();
        lock.version = 2;
        assert!(matches!(
            plan.commitment_materials(&semantic, &lock),
            Err(PackageError::InvalidBundleBinding(_))
        ));
    }
    #[test]
    fn semantic_bundle_rejects_unproven_direct_dependencies() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn demo() {}").expect("source");
        let (mut semantic, lock) = semantic_release();
        let plan = plan_package(&base_layout(temp.path()), MANIFEST, &lock).expect("plan");
        semantic.dependencies.push(MusubiDependencyReqV1 {
            alias: "dependency".parse().expect("dependency alias"),
            package: MusubiPackageIdV1::new(
                DataSpaceId::new(8),
                MusubiPackageScopeV1::DataspaceRoot,
                "dependency".parse().expect("dependency name"),
            ),
            requirement: "^1.0.0".parse().expect("dependency requirement"),
        });
        semantic
            .validate()
            .expect("semantic manifest remains independently valid");
        lock.validate()
            .expect("verification lock remains independently valid");
        assert!(matches!(
            plan.commitment_materials(&semantic, &lock),
            Err(PackageError::InvalidBundleBinding(reason))
                if reason.contains("dependency counts differ")
        ));
    }
    #[test]
    fn commitment_materials_apply_sorafs_portable_path_validation_first() {
        // `PackagePlan` fields are private to this module, so production callers cannot bypass
        // the positive-set collector. This malformed internal fixture pins the additional SoraFS
        // validation at the commitment boundary itself.
        let malformed = PackagePlan {
            files: vec![PlannedFile {
                path: "bad?.ko".to_owned(),
                components: vec!["bad?.ko".to_owned()],
                bytes: b"source".to_vec(),
            }],
            source_bytes: 6,
        };
        let (semantic, lock) = semantic_release();
        assert!(matches!(
            malformed.commitment_materials(&semantic, &lock),
            Err(PackageError::CarPlan(_))
        ));
    }
    #[test]
    fn commitment_materials_reject_casefold_colliding_internal_plans() {
        let malformed = PackagePlan {
            files: vec![
                PlannedFile {
                    path: "src/Foo.ko".to_owned(),
                    components: vec!["src".to_owned(), "Foo.ko".to_owned()],
                    bytes: b"one".to_vec(),
                },
                PlannedFile {
                    path: "src/foo.ko".to_owned(),
                    components: vec!["src".to_owned(), "foo.ko".to_owned()],
                    bytes: b"two".to_vec(),
                },
            ],
            source_bytes: 6,
        };
        let (semantic, lock) = semantic_release();
        assert!(matches!(
            malformed.commitment_materials(&semantic, &lock),
            Err(PackageError::CarPlan(_))
        ));
    }
    #[test]
    fn semantic_bundle_rejects_two_individually_valid_lock_representations() {
        let temp = tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("src")).expect("src");
        fs::write(temp.path().join("src/lib.ko"), b"fn demo() {}").expect("source");
        let (original_semantic, original_lock) = semantic_release();
        let plan = plan_package(&base_layout(temp.path()), MANIFEST, &original_lock).expect("plan");
        let mut different_lock = original_lock;
        different_lock.root.version = "1.0.1".parse().expect("different version");
        let mut different_semantic = original_semantic;
        different_semantic.release = different_lock.root.clone();
        different_semantic.verification_lock_digest = different_lock.digest();
        assert!(different_lock.validate().is_ok());
        assert!(different_semantic.validate().is_ok());
        assert!(matches!(
            plan.commitment_materials(&different_semantic, &different_lock),
            Err(PackageError::InvalidBundleBinding(reason))
                if reason.contains("source-tree and typed verification locks")
        ));
    }
    #[test]
    fn limit_guards_report_exact_v1_ceilings() {
        assert!(enforce_file_limit(MAX_SOURCE_FILES).is_ok());
        assert!(matches!(
            enforce_file_limit(MAX_SOURCE_FILES + 1),
            Err(PackageError::TooManyFiles {
                maximum: MAX_SOURCE_FILES,
                ..
            })
        ));
        assert_eq!(MAX_DIRECTORY_ENTRIES, MAX_SOURCE_FILES * 2);
        assert_eq!(MAX_SOURCE_ENTRIES, MAX_SOURCE_FILES * MAX_PATH_COMPONENTS);
        assert!(enforce_entry_limit(MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_ENTRIES).is_ok());
        assert!(matches!(
            enforce_entry_limit(MAX_DIRECTORY_ENTRIES + 1, MAX_DIRECTORY_ENTRIES),
            Err(PackageError::TooManyEntries {
                maximum: MAX_DIRECTORY_ENTRIES,
                ..
            })
        ));
        assert!(enforce_entry_limit(MAX_SOURCE_ENTRIES, MAX_SOURCE_ENTRIES).is_ok());
        assert!(matches!(
            enforce_entry_limit(MAX_SOURCE_ENTRIES + 1, MAX_SOURCE_ENTRIES),
            Err(PackageError::TooManyEntries {
                maximum: MAX_SOURCE_ENTRIES,
                ..
            })
        ));
        assert!(enforce_source_limit(MAX_SOURCE_BYTES).is_ok());
        assert!(matches!(
            enforce_source_limit(MAX_SOURCE_BYTES + 1),
            Err(PackageError::SourceTooLarge {
                maximum: MAX_SOURCE_BYTES,
                ..
            })
        ));
        assert!(enforce_chunk_limit(MAX_SOURCE_CHUNKS).is_ok());
        assert!(matches!(
            enforce_chunk_limit(MAX_SOURCE_CHUNKS + 1),
            Err(PackageError::TooManyChunks {
                maximum: MAX_SOURCE_CHUNKS,
                ..
            })
        ));
        assert!(enforce_car_limit(MAX_CAR_BYTES).is_ok());
        assert!(matches!(
            enforce_car_limit(MAX_CAR_BYTES + 1),
            Err(PackageError::CarTooLarge {
                maximum: MAX_CAR_BYTES,
                ..
            })
        ));
    }
}
#[cfg(test)]
mod platform_tests {
    use super::*;
    use crate::workspace::load_workspace;
    #[cfg(not(any(unix, windows)))]
    use iroha_data_model::musubi::{
        MUSUBI_REGISTRY_VERSION_V1, MusubiPackageIdV1, MusubiPackageScopeV1, MusubiReleaseIdV1,
        MusubiVerificationLockV1,
    };
    #[cfg(not(any(unix, windows)))]
    use iroha_model_base::topology::DataSpaceId;
    use tempfile::tempdir;
    #[cfg(not(any(unix, windows)))]
    #[test]
    fn package_planning_fails_before_parsing_or_inspecting_the_root() {
        let package = MusubiPackageIdV1::new(
            DataSpaceId::new(7),
            MusubiPackageScopeV1::DataspaceRoot,
            "unsupported".parse().expect("package name"),
        );
        let lock = MusubiVerificationLockV1 {
            schema: MusubiVerificationLockV1::SCHEMA.to_owned(),
            version: MUSUBI_REGISTRY_VERSION_V1,
            root: MusubiReleaseIdV1::new(package, "1.0.0".parse().expect("version")),
            root_dependencies: Vec::new(),
            nodes: Vec::new(),
        };
        let parent = tempfile::tempdir().expect("temporary parent");
        let requested = parent.path().join("must-remain-absent");
        let layout = PackageLayout::new(&requested);
        let error = plan_package(&layout, "not valid TOML", &lock)
            .expect_err("non-Unix package planning must fail");
        assert!(matches!(error, PackageError::UnsupportedPlatform));
        assert!(!requested.exists());
    }

    #[test]
    fn contract_only_inventory_uses_the_positive_source_set_without_a_lock() {
        let temp = tempdir().expect("package directory");
        let root = temp.path();
        let manifest = include_str!("../../../examples/coffee-club/Musubi.toml");
        for (path, source) in [
            ("Musubi.toml", manifest),
            (
                "contracts/coffee-club.ko",
                include_str!("../../../examples/coffee-club/contracts/coffee-club.ko"),
            ),
            (
                "tests/coffee-club.test.ko",
                include_str!("../../../examples/coffee-club/tests/coffee-club.test.ko"),
            ),
            ("unselected.txt", "not in the package"),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().expect("source parent")).expect("source directory");
            fs::write(path, source).expect("source file");
        }
        let workspace = load_workspace(root).expect("contract-only workspace");
        let member = workspace.members().values().next().expect("root package");
        let normalized = publication_manifest_toml(member).expect("publication manifest");
        assert!(
            crate::manifest::parse_manifest(&normalized)
                .expect("normalized manifest")
                .library
                .is_none()
        );
        let layout = package_layout_for_member(workspace.root(), member);
        let inventory =
            inventory_package(&layout, &normalized).expect("read-only source inventory");
        assert_eq!(
            inventory
                .files()
                .iter()
                .map(PlannedFile::path)
                .collect::<Vec<_>>(),
            vec![
                "Musubi.toml",
                "contracts/coffee-club.ko",
                "tests/coffee-club.test.ko"
            ]
        );
        assert_eq!(
            inventory.source_bytes(),
            inventory
                .files()
                .iter()
                .map(|file| file.bytes().len() as u64)
                .sum::<u64>()
        );
        assert!(!root.join("Musubi.lock").exists());
        assert!(!root.join("target").exists());
        assert!(!root.join("src").exists());
        fs::write(
            root.join("contracts/coffee-club.ko"),
            "-----BEGIN PRIVATE KEY-----\nfixture",
        )
        .expect("unsafe selected source");
        assert!(matches!(
            inventory_package(&layout, &normalized),
            Err(PackageError::SensitiveContent { .. })
        ));
    }
}
