//! Bounded, content-addressed FASTPQ artifact bytes, separate from pipeline metadata.
//!
//! Storage never establishes proof validity, source finality, or spend authority.
//! A recovered byte vector must undergo fresh bounded proof verification against
//! independently authenticated expectations before it can be used as evidence.
//! `[kura.fastpq_artifacts]` supplies immutable byte/count caps, including the
//! one unpublished temporary; startup and every read/write enforce those caps.
//! Defaults are 1 MiB per complete artifact, 1,024 stable records and 256 MiB
//! aggregate file bytes. Full stores refuse new content; no unreferenced-record
//! inference authorizes deletion. Changing the supplied Config after construction
//! cannot change the live instance policy.
//! TODO: connect authenticated reference publication and authority-aware retention
//! to the qualified compact producer before enabling production use.

use std::{
    fs::File,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use iroha_config::parameters::actual::KuraFastpqArtifactPolicy;
use iroha_crypto::Hash;

use super::{BoundProgressNamespace, Error, Kura, KuraInstanceIdentity, Result};

pub(super) const DIRECTORY: &str = "fastpq_artifacts_v1";
pub(super) const TEMPORARY: &str = "pending.tmp";
const KIND: &str = "FASTPQ artifact";

/// Untrusted content reference, with no claim about proof validity or durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastpqStoredArtifactReference {
    digest: [u8; 32],
    byte_len: u64,
}

impl FastpqStoredArtifactReference {
    /// Keep advertised bytes verbatim for exact comparison on bounded recovery.
    ///
    /// In particular, this does not normalize an advertised hash through
    /// `Hash::prehashed`, which could alter its encoded marker bit.
    pub const fn from_advertised(digest: [u8; 32], byte_len: u64) -> Self {
        Self { digest, byte_len }
    }

    /// Hash of the exact complete stored bytes, still untrusted on an advertised reference.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Exact advertised complete artifact length.
    pub const fn byte_len(self) -> u64 {
        self.byte_len
    }

    fn for_bytes(bytes: &[u8]) -> Self {
        Self {
            digest: *Hash::new(bytes).as_ref(),
            byte_len: bytes.len() as u64,
        }
    }

    fn file_name(self) -> String {
        format!("{}.norito", hex::encode(self.digest))
    }
}

/// A successful exact-byte write/readback and file/directory durability barrier.
///
/// Only Kura's persistence operation can construct this receipt. It is a point-in-time
/// storage acknowledgement; it is neither proof verification nor protection against
/// subsequent media corruption. It retains its issuing Kura instance identity.
/// Serialized metadata must never recreate this type.
#[derive(Debug)]
#[must_use = "publish a reference only after receiving its durable storage receipt"]
pub struct FastpqDurableArtifactReceipt {
    reference: FastpqStoredArtifactReference,
    issuer: KuraInstanceIdentity,
}

impl FastpqDurableArtifactReceipt {
    /// Extract content metadata. Reading it later requires a fresh bounded read and proof check.
    pub const fn reference(&self) -> FastpqStoredArtifactReference {
        self.reference
    }

    /// Check issuance by this exact live Kura instance, without reattesting stored bytes.
    pub fn is_from(&self, kura: &Kura) -> bool {
        self.issuer.matches(kura)
    }
}

#[derive(Default)]
struct Inventory {
    stable_count: usize,
    total_bytes: u64,
    temporary: bool,
}

fn invalid(path: impl Into<PathBuf>, message: &'static str) -> Error {
    Error::IO(
        std::io::Error::new(ErrorKind::InvalidData, message),
        path.into(),
    )
}

impl Kura {
    /// Persist bounded opaque FASTPQ artifact bytes without replacing any existing content.
    ///
    /// This method does not decode or admit compact proofs. Its caller must first verify
    /// the artifact under the appropriate proof and authentication policy. The receipt
    /// acknowledges only storage; references belong in a separate bounded metadata record.
    ///
    /// # Errors
    /// Fails for invalid limits, size/quota excess, conflicting content, unsafe namespace
    /// entries, unavailable Kura mutation authority, insufficient configured Kura capacity
    /// after existing reservations, or any failed durability barrier.
    pub fn persist_fastpq_artifact(&self, bytes: &[u8]) -> Result<FastpqDurableArtifactReceipt> {
        let limits = self.fastpq_artifact_policy;
        let directory = self.store_root.join(DIRECTORY);
        Self::validate_fastpq_artifact_limits(limits, &directory)?;
        if bytes.is_empty() || bytes.len() > limits.max_artifact_bytes.get() {
            return Err(invalid(
                directory,
                "FASTPQ artifact is empty or exceeds its byte cap",
            ));
        }
        let reference = FastpqStoredArtifactReference::for_bytes(bytes);
        // The complete artifact operation retains each exact physical release
        // source until all sibling fences and resource accounting have retired.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let (
            mut prune_releases,
            mut canonical_releases,
            mut geometry_releases,
            mut sidecar_releases,
        ) = (
            self.prune_lock.defer_notifications(),
            self.canonical_chain_lock.defer_notifications(),
            self.lane_geometry_lock.defer_notifications(),
            self.sidecar_lock.defer_notifications(),
        );
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _prune_guard = prune_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _prune_guard = self.prune_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(1);
        self.ensure_prune_recovery_not_required()?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _canonical_guard = canonical_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _canonical_guard = self.canonical_chain_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(2);
        self.durable_mutation_authorized()?;
        // Preserve Kura's capacity-owner lock order: pending canonical bytes
        // require block-store locks before either geometry or sidecar locks.
        let pending_canonical_bytes =
            self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _geometry_guard = geometry_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _geometry_guard = self.lane_geometry_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(3);
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _sidecar_guard = sidecar_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _sidecar_guard = self.sidecar_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(4);
        // Recovery and publication own sequential, disjoint path snapshots.
        // Any error leaves their common resource owner unavailable.
        let mut usage_mutation = self
            .begin_total_disk_usage_mutation()
            .with_resource_children(2);
        let namespace = self.open_fastpq_artifact_namespace(true)?;
        let mut inventory = self.inventory_fastpq_artifacts(&namespace, limits)?;
        if inventory.temporary {
            let temporary_child = usage_mutation.resource_child(vec![directory.join(TEMPORARY)]);
            self.discard_fastpq_artifact_temporary(&namespace, limits)?;
            inventory = self.inventory_fastpq_artifacts(&namespace, limits)?;
            temporary_child.finish();
        } else {
            usage_mutation.resource_batch(0).finish();
        }
        let path = directory.join(reference.file_name());
        let publication_child =
            usage_mutation.resource_child(vec![path.clone(), directory.join(TEMPORARY)]);
        let existing = self.read_bound_regular_file_bytes_locked(
            &namespace,
            &path,
            limits.max_artifact_bytes.get(),
            KIND,
        )?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(invalid(
                    path,
                    "FASTPQ content address contains different bytes",
                ));
            }
        } else {
            if inventory.stable_count >= limits.max_artifacts.get()
                || inventory
                    .total_bytes
                    .checked_add(reference.byte_len)
                    .is_none_or(|total| total > limits.max_total_bytes.get())
            {
                return Err(invalid(path, "FASTPQ artifact storage quota exhausted"));
            }
            // This unrelated payload must not consume capacity reserved for
            // pending canonical blocks, terminal outcomes, carrier components
            // or prune recovery. One no-clobber temporary adds the same bytes
            // as the final object; an exact retry adds no physical payload.
            self.validate_publication_disk_peak_locked(
                pending_canonical_bytes,
                reference.byte_len,
                &path,
            )?;
            if !self.publish_bound_noclobber_file_locked(
                &namespace,
                &path,
                &directory.join(TEMPORARY),
                bytes,
                KIND,
            )? {
                return Err(invalid(path, "FASTPQ artifact appeared during publication"));
            }
        }
        // Existing bytes might be a previous publication whose directory sync
        // failed. Presence never skips this exact-object sync/readback barrier.
        let (mut file, metadata) = self.open_bound_regular_file_with_exact_bytes_locked(
            &namespace,
            &path,
            bytes,
            limits.max_artifact_bytes.get(),
            KIND,
        )?;
        sync_artifact_file(&file).map_err(|error| Error::IO(error, path.clone()))?;
        self.sync_bound_evidence_namespace(&namespace, KIND)?;
        self.verify_bound_open_regular_file_exact_bytes_after_namespace_mutation_locked(
            &namespace,
            &path,
            &mut file,
            &metadata,
            bytes,
            limits.max_artifact_bytes.get(),
            KIND,
        )?;
        self.inventory_fastpq_artifacts(&namespace, limits)?;
        self.validate_fastpq_artifact_root()?;
        publication_child.finish();
        usage_mutation.finish_resources_before_disk_rescan();
        Ok(FastpqDurableArtifactReceipt {
            reference,
            issuer: self.instance_identity(),
        })
    }

    /// Recover exact bounded bytes for an untrusted reference, without decoding a proof.
    ///
    /// Recovery never returns a durable receipt or a verified proof. Fresh proof verification
    /// and separately authenticated source/spend expectations remain mandatory.
    ///
    /// # Errors
    /// Fails for invalid limits/references, missing or changed content, unsafe namespace
    /// entries, quota excess, and unavailable canonical storage. Reads create no directories.
    pub fn read_fastpq_artifact(
        &self,
        reference: FastpqStoredArtifactReference,
    ) -> Result<Vec<u8>> {
        let limits = self.fastpq_artifact_policy;
        let directory = self.store_root.join(DIRECTORY);
        Self::validate_fastpq_artifact_limits(limits, &directory)?;
        if reference.byte_len == 0 || reference.byte_len > limits.max_artifact_bytes.get() as u64 {
            return Err(invalid(
                directory,
                "FASTPQ artifact reference exceeds its byte cap",
            ));
        }
        // The complete artifact operation retains each exact physical release
        // source until all sibling fences and resource accounting have retired.
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let (mut prune_releases, mut canonical_releases, mut sidecar_releases) = (
            self.prune_lock.defer_notifications(),
            self.canonical_chain_lock.defer_notifications(),
            self.sidecar_lock.defer_notifications(),
        );
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _prune_guard = prune_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _prune_guard = self.prune_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(1);
        self.ensure_prune_recovery_not_required()?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _canonical_guard = canonical_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _canonical_guard = self.canonical_chain_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(2);
        self.durable_mutation_authorized()?;
        #[cfg(not(all(test, sumeragi_core_mutation = "HC358")))]
        let _sidecar_guard = sidecar_releases.lock();
        #[cfg(all(test, sumeragi_core_mutation = "HC358"))]
        let _sidecar_guard = self.sidecar_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        original_release_tests::fence_boundary(3);
        let namespace = self.open_fastpq_artifact_namespace(false)?;
        self.inventory_fastpq_artifacts(&namespace, limits)?;
        let path = directory.join(reference.file_name());
        let bytes = self
            .read_bound_regular_file_bytes_locked(
                &namespace,
                &path,
                usize::try_from(reference.byte_len)?,
                KIND,
            )?
            .ok_or_else(|| invalid(path.clone(), "FASTPQ artifact reference is absent"))?;
        if FastpqStoredArtifactReference::for_bytes(&bytes) != reference {
            return Err(invalid(
                path,
                "FASTPQ artifact content or exact length differs from reference",
            ));
        }
        self.validate_fastpq_artifact_root()?;
        Ok(bytes)
    }

    fn validate_fastpq_artifact_limits(
        limits: KuraFastpqArtifactPolicy,
        directory: &Path,
    ) -> Result<()> {
        limits.validate().map_err(|error| {
            Error::IO(
                std::io::Error::new(ErrorKind::InvalidInput, error.to_string()),
                directory.to_path_buf(),
            )
        })
    }

    /// Validate existing retained FASTPQ bytes against the immutable configured policy.
    /// This bounded owner scan runs at initialization/re-audit, never at metric scrape.
    pub(super) fn validate_fastpq_artifact_inventory_on_startup(&self) -> Result<()> {
        let directory = self.store_root.join(DIRECTORY);
        Self::validate_fastpq_artifact_limits(self.fastpq_artifact_policy, &directory)?;
        let _sidecar_guard = self.sidecar_lock.lock();
        #[cfg(all(test, unix, not(target_os = "espidf")))]
        super::original_inventory_release_tests::fence_boundary(self, 3);
        // Missing storage remains valid even on a platform that cannot publish artifacts.
        // Supported platforms still bind that absence to the live Kura root identity.
        #[cfg(all(unix, not(target_os = "espidf")))]
        self.validate_fastpq_artifact_root()?;
        if self.canonical_sidecar_directory(&directory)?.is_none() {
            return Ok(());
        }
        let namespace = self.open_fastpq_artifact_namespace(false)?;
        self.inventory_fastpq_artifacts(&namespace, self.fastpq_artifact_policy)?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "espidf")))]
    fn validate_fastpq_artifact_root(&self) -> Result<()> {
        if !self.bound_storage_directory_unchanged(&self.store_root_directory) {
            return Err(invalid(
                &self.store_root,
                "FASTPQ artifact Kura root identity changed",
            ));
        }
        Ok(())
    }

    #[cfg(not(all(unix, not(target_os = "espidf"))))]
    fn validate_fastpq_artifact_root(&self) -> Result<()> {
        Err(Error::IO(
            std::io::Error::new(
                ErrorKind::Unsupported,
                "FASTPQ artifact storage requires descriptor-bound directory operations",
            ),
            self.store_root.clone(),
        ))
    }

    fn open_fastpq_artifact_namespace(&self, create: bool) -> Result<BoundProgressNamespace> {
        self.validate_fastpq_artifact_root()?;
        #[cfg(all(unix, not(target_os = "espidf")))]
        if create {
            self.open_or_create_bound_storage_child_directory(
                &self.store_root_directory,
                std::ffi::OsStr::new(DIRECTORY),
            )?;
        }
        #[cfg(not(all(unix, not(target_os = "espidf"))))]
        let _ = create;
        let directory = self.store_root.join(DIRECTORY);
        self.open_bound_progress_namespace(&directory.join("content"), &directory.join(TEMPORARY))
    }

    fn inventory_fastpq_artifacts(
        &self,
        namespace: &BoundProgressNamespace,
        limits: KuraFastpqArtifactPolicy,
    ) -> Result<Inventory> {
        let directory = self.store_root.join(DIRECTORY);
        let before = self.stable_sidecar_directory_metadata(&directory)?;
        let entries =
            std::fs::read_dir(&directory).map_err(|error| Error::IO(error, directory.clone()))?;
        let mut inventory = Inventory::default();
        // A counter, not an unbounded vector/map: stop before metadata work for
        // any entry beyond the configured stable count plus one temporary.
        for (index, entry) in entries.enumerate() {
            if index > limits.max_artifacts.get() {
                return Err(invalid(
                    &directory,
                    "FASTPQ artifact directory entry cap exceeded",
                ));
            }
            let entry = entry.map_err(|error| Error::IO(error, directory.clone()))?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(invalid(path, "FASTPQ artifact filename is not canonical"));
            };
            let temporary = name == TEMPORARY;
            if !temporary {
                let hash = name.strip_suffix(".norito").unwrap_or_default();
                if hash.len() != Hash::LENGTH * 2
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid(
                        path,
                        "FASTPQ artifact filename is not a lowercase content hash",
                    ));
                }
                inventory.stable_count += 1;
                if inventory.stable_count > limits.max_artifacts.get() {
                    return Err(invalid(
                        path,
                        "FASTPQ stable artifact count exceeds its cap",
                    ));
                }
            } else {
                inventory.temporary = true;
            }
            let metadata = Self::regular_sidecar_metadata_for(&self.store_root, &path, &directory)?
                .ok_or_else(|| {
                    invalid(path.clone(), "FASTPQ artifact vanished during inventory")
                })?;
            let size = metadata.file.len();
            if (!temporary && size == 0) || size > limits.max_artifact_bytes.get() as u64 {
                return Err(invalid(
                    path,
                    "FASTPQ artifact inventory has an invalid payload size",
                ));
            }
            inventory.total_bytes = inventory
                .total_bytes
                .checked_add(size)
                .filter(|total| *total <= limits.max_total_bytes.get())
                .ok_or_else(|| {
                    invalid(path, "FASTPQ artifact inventory exceeds aggregate byte cap")
                })?;
        }
        let after = self.stable_sidecar_directory_metadata(&directory)?;
        if !Self::stable_sidecar_directory_metadata_unchanged(&before, &after)
            || !Self::progress_mutation_namespace_unchanged(namespace)
        {
            return Err(invalid(
                directory,
                "FASTPQ artifact directory changed during bounded inventory",
            ));
        }
        self.validate_fastpq_artifact_root()?;
        Ok(inventory)
    }

    fn discard_fastpq_artifact_temporary(
        &self,
        namespace: &BoundProgressNamespace,
        limits: KuraFastpqArtifactPolicy,
    ) -> Result<()> {
        let directory = self.store_root.join(DIRECTORY);
        let path = directory.join(TEMPORARY);
        let metadata = Self::regular_sidecar_metadata_for(&self.store_root, &path, &directory)?
            .ok_or_else(|| invalid(path.clone(), "FASTPQ temporary disappeared before recovery"))?;
        if metadata.file.len() > limits.max_artifact_bytes.get() as u64 {
            return Err(invalid(path, "FASTPQ temporary exceeds its byte cap"));
        }
        let file = Self::open_bound_progress_file(namespace, &path, &metadata)?;
        // A temporary has never earned a reference. Discard only the exact
        // descriptor-bound, single-link object; never promote recovered bytes
        // based solely on their presence or apparent proof structure.
        Self::remove_bound_progress_file_if_matches(namespace, &path, &file, &metadata)
            .map_err(|error| Error::IO(error, path))?;
        self.sync_bound_evidence_namespace(namespace, KIND)
    }
}

fn sync_artifact_file(file: &File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_FILE_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other(
            "injected FASTPQ artifact file sync failure",
        ));
    }
    file.sync_all()
}

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_FILE_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, unix, not(target_os = "espidf")))]
mod tests {
    use super::*;
    use std::num::{NonZeroU64, NonZeroUsize};

    fn configured_fixture(policy: KuraFastpqArtifactPolicy) -> std::sync::Arc<Kura> {
        let mut kura = Kura::blank_kura_for_testing();
        std::sync::Arc::get_mut(&mut kura)
            .expect("unshared fixture construction")
            .fastpq_artifact_policy = policy;
        kura
    }

    fn limits(file: usize, count: usize, total: u64) -> KuraFastpqArtifactPolicy {
        KuraFastpqArtifactPolicy {
            max_artifact_bytes: NonZeroUsize::new(file).unwrap(),
            max_artifacts: NonZeroUsize::new(count).unwrap(),
            max_total_bytes: NonZeroU64::new(total).unwrap(),
        }
    }

    fn generous() -> KuraFastpqArtifactPolicy {
        limits(1024, 16, 16 * 1024)
    }

    fn path(kura: &Kura, reference: FastpqStoredArtifactReference) -> PathBuf {
        kura.store_root.join(DIRECTORY).join(reference.file_name())
    }

    #[test]
    fn durable_roundtrip_and_idempotent_retry_keep_one_exact_artifact() {
        let kura = configured_fixture(generous());
        let bytes = b"opaque complete nominal proof wrapper";
        let first = kura.persist_fastpq_artifact(bytes).unwrap();
        let reference = first.reference();
        assert_eq!(reference.byte_len(), bytes.len() as u64);
        assert_eq!(reference.digest(), *Hash::new(bytes).as_ref());
        assert_eq!(kura.read_fastpq_artifact(reference).unwrap(), bytes);
        let second = kura.persist_fastpq_artifact(bytes).unwrap();
        assert_eq!(second.reference(), reference);
        assert_eq!(
            std::fs::read_dir(kura.store_root.join(DIRECTORY))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn absent_read_does_not_create_a_storage_directory() {
        let kura = configured_fixture(generous());
        let reference = FastpqStoredArtifactReference::for_bytes(b"absent");
        assert!(kura.read_fastpq_artifact(reference).is_err());
        assert!(!kura.store_root.join(DIRECTORY).exists());
    }

    #[test]
    fn receipt_issuer_is_distinct_even_for_identical_content_in_two_stores() {
        let first = configured_fixture(generous());
        let second = configured_fixture(generous());
        let left = first.persist_fastpq_artifact(b"abc").unwrap();
        let right = second.persist_fastpq_artifact(b"abc").unwrap();
        assert_eq!(left.reference(), right.reference());
        assert!(left.is_from(&first));
        assert!(!left.is_from(&second));
        assert!(right.is_from(&second));
        assert!(!right.is_from(&first));
    }

    #[test]
    fn empty_oversized_and_inconsistent_requests_fail_before_directory_creation() {
        for (bytes, policy) in [
            (&b""[..], generous()),
            (&b"too big"[..], limits(3, 1, 3)),
            (&b"a"[..], limits(8, 1, 4)),
            (&b"a"[..], limits(1, usize::MAX, 1)),
            (&b"a"[..], limits(usize::MAX, 1, u64::MAX)),
        ] {
            let kura = configured_fixture(policy);
            assert!(kura.persist_fastpq_artifact(bytes).is_err());
            assert!(!kura.store_root.join(DIRECTORY).exists());
        }
    }

    #[test]
    fn reference_caps_and_exact_lengths_are_checked() {
        let kura = configured_fixture(generous());
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        for length in [0, 2, 4, 1025, u64::MAX] {
            let changed =
                FastpqStoredArtifactReference::from_advertised(reference.digest(), length);
            assert!(
                kura.read_fastpq_artifact(changed).is_err(),
                "length {length}"
            );
        }
        assert_eq!(kura.read_fastpq_artifact(reference).unwrap(), b"abc");
    }

    #[test]
    fn advertised_hash_is_not_normalized_and_content_is_rehashed() {
        let kura = configured_fixture(generous());
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        for index in 0..32 {
            let mut digest = reference.digest();
            digest[index] ^= 1;
            let changed = FastpqStoredArtifactReference::from_advertised(digest, 3);
            assert_eq!(changed.digest(), digest);
            // Give the forged address the actual original bytes. Presence and
            // matching length are insufficient, including the hash marker bit.
            std::fs::copy(path(&kura, reference), path(&kura, changed)).unwrap();
            assert!(kura.read_fastpq_artifact(changed).is_err());
            std::fs::remove_file(path(&kura, changed)).unwrap();
        }
    }

    #[test]
    fn changed_content_is_neither_read_nor_overwritten_on_retry() {
        let kura = configured_fixture(generous());
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        std::fs::write(path(&kura, reference), b"xyz").unwrap();
        assert!(kura.read_fastpq_artifact(reference).is_err());
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert_eq!(std::fs::read(path(&kura, reference)).unwrap(), b"xyz");
    }

    #[test]
    fn stable_count_quota_rejects_new_content_but_permits_exact_retry() {
        let policy = limits(8, 1, 16);
        let kura = configured_fixture(policy);
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        assert!(kura.persist_fastpq_artifact(b"def").is_err());
        assert!(!path(&kura, FastpqStoredArtifactReference::for_bytes(b"def")).exists());
        assert_eq!(
            kura.persist_fastpq_artifact(b"abc").unwrap().reference(),
            reference
        );
        assert!(!kura.store_root.join(DIRECTORY).join(TEMPORARY).exists());
    }

    #[test]
    fn aggregate_byte_quota_is_reserved_before_writing() {
        let policy = limits(4, 8, 6);
        let kura = configured_fixture(policy);
        let _first = kura.persist_fastpq_artifact(b"abc").unwrap();
        let _second = kura.persist_fastpq_artifact(b"def").unwrap();
        assert!(kura.persist_fastpq_artifact(b"g").is_err());
        assert!(!path(&kura, FastpqStoredArtifactReference::for_bytes(b"g")).exists());
        assert_eq!(
            std::fs::read_dir(kura.store_root.join(DIRECTORY))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn interrupted_empty_partial_and_complete_temporaries_are_discarded_without_publication() {
        for temporary in [&b""[..], &b"part"[..], &b"complete-but-unreferenced"[..]] {
            let kura = configured_fixture(generous());
            let _initial = kura.persist_fastpq_artifact(b"initial").unwrap();
            let temp = kura.store_root.join(DIRECTORY).join(TEMPORARY);
            std::fs::write(&temp, temporary).unwrap();
            let result = kura
                .persist_fastpq_artifact(b"fresh-verified-caller-bytes")
                .unwrap();
            assert!(!temp.exists());
            if !temporary.is_empty() {
                assert!(!path(&kura, FastpqStoredArtifactReference::for_bytes(temporary)).exists());
            }
            assert_eq!(
                kura.read_fastpq_artifact(result.reference()).unwrap(),
                b"fresh-verified-caller-bytes"
            );
        }
    }

    #[test]
    fn temporary_bytes_participate_in_recovery_caps() {
        for (temporary, policy) in [
            (&b"12345"[..], limits(4, 2, 8)),
            (&b"1234"[..], limits(4, 2, 6)),
        ] {
            let kura = configured_fixture(policy);
            let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
            let temp = kura.store_root.join(DIRECTORY).join(TEMPORARY);
            std::fs::write(&temp, temporary).unwrap();
            assert!(kura.persist_fastpq_artifact(b"x").is_err());
            assert!(kura.read_fastpq_artifact(reference).is_err());
            assert_eq!(std::fs::read(&temp).unwrap(), temporary);
        }
    }

    #[test]
    fn unknown_names_subdirectories_and_too_many_entries_fail_closed() {
        for name in ["unrecognized", "ABC.norito", "../not-used"] {
            let kura = configured_fixture(generous());
            let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
            let directory = kura.store_root.join(DIRECTORY);
            if name == "../not-used" {
                std::fs::create_dir(directory.join("child")).unwrap();
            } else {
                std::fs::write(directory.join(name), b"x").unwrap();
            }
            assert!(kura.read_fastpq_artifact(reference).is_err());
            assert!(kura.persist_fastpq_artifact(b"new").is_err());
        }
        let kura = configured_fixture(limits(1024, 1, 16384));
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        std::fs::write(
            path(&kura, FastpqStoredArtifactReference::for_bytes(b"def")),
            b"def",
        )
        .unwrap();
        assert!(kura.read_fastpq_artifact(reference).is_err());
    }

    #[test]
    fn symlink_and_hardlink_artifacts_are_rejected_without_touching_targets() {
        use std::os::unix::fs::symlink;
        for symlink_attack in [true, false] {
            let kura = configured_fixture(generous());
            let outside = tempfile::tempdir().unwrap();
            let target = outside.path().join("target");
            std::fs::write(&target, b"abc").unwrap();
            let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
            std::fs::remove_file(path(&kura, reference)).unwrap();
            if symlink_attack {
                symlink(&target, path(&kura, reference)).unwrap();
            } else {
                std::fs::hard_link(&target, path(&kura, reference)).unwrap();
            }
            assert!(kura.read_fastpq_artifact(reference).is_err());
            assert!(kura.persist_fastpq_artifact(b"abc").is_err());
            assert_eq!(std::fs::read(&target).unwrap(), b"abc");
        }
    }

    #[test]
    fn symlink_directory_and_temporary_are_never_followed_or_removed() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let kura = configured_fixture(generous());
        symlink(outside.path(), kura.store_root.join(DIRECTORY)).unwrap();
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);

        let kura = configured_fixture(generous());
        let _initial = kura.persist_fastpq_artifact(b"abc").unwrap();
        let target = outside.path().join("target");
        std::fs::write(&target, b"private").unwrap();
        let temp = kura.store_root.join(DIRECTORY).join(TEMPORARY);
        symlink(&target, &temp).unwrap();
        assert!(kura.persist_fastpq_artifact(b"def").is_err());
        assert!(
            std::fs::symlink_metadata(&temp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"private");
    }

    #[test]
    fn retained_kura_root_identity_rejects_a_replaced_root() {
        let kura = configured_fixture(generous());
        let root = kura.store_root.clone();
        let moved = root.with_extension("moved-fastpq-test");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        let result = kura.persist_fastpq_artifact(b"abc");
        let empty = std::fs::read_dir(&root).unwrap().count() == 0;
        std::fs::remove_dir(&root).unwrap();
        std::fs::rename(&moved, &root).unwrap();
        assert!(result.is_err());
        assert!(empty);
    }

    #[test]
    fn existing_file_requires_a_fresh_file_sync_before_every_receipt() {
        let kura = configured_fixture(generous());
        let reference = FastpqStoredArtifactReference::for_bytes(b"abc");
        for _ in 0..2 {
            FAIL_NEXT_FILE_SYNC.with(|flag| flag.set(true));
            assert!(kura.persist_fastpq_artifact(b"abc").is_err());
            assert_eq!(std::fs::read(path(&kura, reference)).unwrap(), b"abc");
        }
        assert_eq!(
            kura.persist_fastpq_artifact(b"abc").unwrap().reference(),
            reference
        );
    }

    #[test]
    fn publication_and_retry_directory_sync_failures_never_mint_receipts() {
        let kura = configured_fixture(generous());
        let reference = FastpqStoredArtifactReference::for_bytes(b"abc");
        for _ in 0..2 {
            super::super::FAIL_NEXT_INDEXED_SIDECAR_DIR_SYNC.with(|flag| flag.set(true));
            assert!(kura.persist_fastpq_artifact(b"abc").is_err());
            assert_eq!(std::fs::read(path(&kura, reference)).unwrap(), b"abc");
        }
        assert_eq!(
            kura.persist_fastpq_artifact(b"abc").unwrap().reference(),
            reference
        );
    }

    #[test]
    fn ancestor_sync_failure_is_also_retried_for_existing_content() {
        let kura = configured_fixture(generous());
        let reference = kura.persist_fastpq_artifact(b"abc").unwrap().reference();
        super::super::fail_progress_sidecar_ancestor_sync_for_tests(0, 1);
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert_eq!(
            kura.persist_fastpq_artifact(b"abc").unwrap().reference(),
            reference
        );
    }

    #[test]
    fn temporary_removal_sync_failure_stops_fresh_publication() {
        let kura = configured_fixture(generous());
        let _initial = kura.persist_fastpq_artifact(b"abc").unwrap();
        let temp = kura.store_root.join(DIRECTORY).join(TEMPORARY);
        std::fs::write(&temp, b"partial").unwrap();
        super::super::FAIL_NEXT_INDEXED_SIDECAR_DIR_SYNC.with(|flag| flag.set(true));
        assert!(kura.persist_fastpq_artifact(b"def").is_err());
        assert!(!path(&kura, FastpqStoredArtifactReference::for_bytes(b"def")).exists());
        let receipt = kura.persist_fastpq_artifact(b"def").unwrap();
        assert_eq!(
            kura.read_fastpq_artifact(receipt.reference()).unwrap(),
            b"def"
        );
    }

    #[test]
    fn artifact_mutations_invalidate_the_total_disk_usage_cache() {
        let kura = configured_fixture(generous());
        let before = kura.refresh_total_disk_usage_bytes().unwrap();
        let enforced_before = kura.refresh_disk_usage_bytes().unwrap();
        let _receipt = kura.persist_fastpq_artifact(b"abc").unwrap();
        assert_eq!(kura.refresh_total_disk_usage_bytes().unwrap(), before + 3);
        assert_eq!(
            kura.refresh_disk_usage_bytes().unwrap(),
            enforced_before + 3
        );
    }

    #[test]
    fn failed_publication_counts_retained_bytes_without_minting_a_receipt() {
        let kura = configured_fixture(generous());
        let before = kura.refresh_total_disk_usage_bytes().unwrap();
        FAIL_NEXT_FILE_SYNC.with(|flag| flag.set(true));
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert_eq!(kura.refresh_total_disk_usage_bytes().unwrap(), before + 3);
        let _retry = kura.persist_fastpq_artifact(b"abc").unwrap();
        assert_eq!(kura.refresh_total_disk_usage_bytes().unwrap(), before + 3);
    }

    #[test]
    fn discarded_temporary_bytes_are_removed_from_global_disk_usage() {
        let kura = configured_fixture(generous());
        let _initial = kura.persist_fastpq_artifact(b"abc").unwrap();
        let temp = kura.store_root.join(DIRECTORY).join(TEMPORARY);
        std::fs::write(&temp, b"partial").unwrap();
        let before = kura.refresh_total_disk_usage_bytes().unwrap();
        let _next = kura.persist_fastpq_artifact(b"de").unwrap();
        assert!(!temp.exists());
        assert_eq!(
            kura.refresh_total_disk_usage_bytes().unwrap(),
            before - 7 + 2
        );
    }

    #[test]
    fn multi_megabyte_artifact_roundtrips_at_exact_capacity_in_separate_store() {
        let bytes = vec![0xA5; 8 * 1024 * 1024 + 37];
        let policy = limits(bytes.len(), 1, bytes.len() as u64);
        let kura = configured_fixture(policy);
        let receipt = kura.persist_fastpq_artifact(&bytes).unwrap();
        assert_eq!(receipt.reference().byte_len(), bytes.len() as u64);
        assert_eq!(
            kura.read_fastpq_artifact(receipt.reference()).unwrap(),
            bytes
        );
        assert!(kura.persist_fastpq_artifact(b"another").is_err());
        assert_eq!(kura.fastpq_proof_queue_len_for_testing(), 0);
    }

    #[test]
    fn configured_capacity_refuses_content_exceeding_remaining_disk_budget() {
        let mut kura = configured_fixture(generous());
        let before = kura.refresh_disk_usage_bytes().unwrap();
        // The artifact policy permits the content, but the disk budget does not.
        std::sync::Arc::get_mut(&mut kura)
            .unwrap()
            .max_disk_usage_bytes = before.checked_add(2).unwrap();
        let reference = FastpqStoredArtifactReference::for_bytes(b"abc");
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert!(!path(&kura, reference).exists());
        assert!(!kura.store_root.join(DIRECTORY).join(TEMPORARY).exists());
        assert_eq!(kura.refresh_disk_usage_bytes().unwrap(), before);
    }

    #[test]
    fn configured_capacity_accepts_exact_fit_and_retry_but_rejects_new_content() {
        let mut kura = configured_fixture(generous());
        let before = kura.refresh_disk_usage_bytes().unwrap();
        let limit = before.checked_add(3).unwrap();
        std::sync::Arc::get_mut(&mut kura)
            .unwrap()
            .max_disk_usage_bytes = limit;
        let first = kura.persist_fastpq_artifact(b"abc").unwrap();
        let retry = kura.persist_fastpq_artifact(b"abc").unwrap();
        assert_eq!(first.reference(), retry.reference());
        assert_eq!(kura.refresh_disk_usage_bytes().unwrap(), before + 3);
        assert!(kura.persist_fastpq_artifact(b"d").is_err());
        assert!(!path(&kura, FastpqStoredArtifactReference::for_bytes(b"d")).exists());
        assert!(!kura.store_root.join(DIRECTORY).join(TEMPORARY).exists());
        assert_eq!(
            kura.read_fastpq_artifact(first.reference()).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn emergency_startup_cannot_publish_or_restore_artifact_evidence() {
        let kura = Kura::blank_kura_for_testing_in_emergency_fast_mode();
        let reference = FastpqStoredArtifactReference::for_bytes(b"abc");
        assert!(kura.persist_fastpq_artifact(b"abc").is_err());
        assert!(kura.read_fastpq_artifact(reference).is_err());
        assert!(!kura.store_root.join(DIRECTORY).exists());
    }

    fn observe_actual_physical_fixture(kura: &Kura) -> super::super::IndexResourceCounts {
        let counts = kura
            .physical_resource_scope()
            .unwrap()
            .observe(kura.evidence_resource_limits())
            .unwrap();
        let values = super::super::PHYSICAL_RESOURCE_FAMILIES
            .iter()
            .map(|family| (*family, counts[*family as usize]))
            .collect::<Vec<_>>();
        kura.resource_inventory
            .initialize(
                kura.resource_inventory.reconciliation_generation().unwrap(),
                &values,
            )
            .unwrap();
        counts
    }

    #[test]
    fn immutable_resources_count_empty_and_partial_temporary_cleanup_with_actual_bytes() {
        use super::super::ResourceFamily;
        for temporary_bytes in [Vec::new(), vec![9_u8; 4]] {
            let kura = configured_fixture(limits(8, 2, 16));
            let _first = kura.persist_fastpq_artifact(b"abc").unwrap();
            let temporary = kura.store_root.join(DIRECTORY).join(TEMPORARY);
            std::fs::write(&temporary, &temporary_bytes).unwrap();
            let before = observe_actual_physical_fixture(&kura);
            let first_evidence = before[ResourceFamily::EvidenceKeyRecords as usize];
            assert!(
                first_evidence.persisted_entries >= 2,
                "an empty pending.tmp still occupies a record"
            );
            assert_eq!(
                first_evidence.temporary_index_bytes,
                temporary_bytes.len() as u64
            );
            let receipt = kura.persist_fastpq_artifact(b"de").unwrap();
            let evidence = kura
                .resource_inventory
                .component_usage_for_tests(ResourceFamily::EvidenceKeyRecords)
                .unwrap();
            assert_eq!(evidence.persisted_entries, first_evidence.persisted_entries);
            assert_eq!(evidence.index_bytes, first_evidence.index_bytes + 2);
            assert_eq!(evidence.temporary_index_bytes, 0);
            assert_eq!(
                kura.resource_inventory
                    .component_usage_for_tests(ResourceFamily::StorageBytes)
                    .unwrap()
                    .storage_bytes,
                before[ResourceFamily::StorageBytes as usize].storage_bytes + 2
                    - temporary_bytes.len() as u64
            );
            assert!(!temporary.exists());
            assert_eq!(
                std::fs::read_dir(kura.store_root.join(DIRECTORY))
                    .unwrap()
                    .count(),
                2
            );
            assert_eq!(
                kura.read_fastpq_artifact(receipt.reference()).unwrap(),
                b"de"
            );
            let _retry = kura.persist_fastpq_artifact(b"de").unwrap();
            assert_eq!(
                kura.resource_inventory
                    .component_usage_for_tests(ResourceFamily::EvidenceKeyRecords)
                    .unwrap(),
                evidence
            );
        }
    }

    #[test]
    fn failed_artifact_sync_keeps_physical_resources_unavailable_until_complete_reaudit() {
        use super::super::ResourceFamily;
        let kura = configured_fixture(generous());
        observe_actual_physical_fixture(&kura);
        FAIL_NEXT_FILE_SYNC.with(|flag| flag.set(true));
        assert!(
            kura.persist_fastpq_artifact(b"retained after failed barrier")
                .is_err()
        );
        let reference = FastpqStoredArtifactReference::for_bytes(b"retained after failed barrier");
        assert_eq!(
            std::fs::read(path(&kura, reference)).unwrap(),
            b"retained after failed barrier"
        );
        for family in [
            ResourceFamily::EvidenceKeyRecords,
            ResourceFamily::StorageBytes,
        ] {
            assert!(
                kura.resource_inventory
                    .component_usage_for_tests(family)
                    .is_err()
            );
        }
        let receipt = kura
            .persist_fastpq_artifact(b"retained after failed barrier")
            .unwrap();
        assert_eq!(receipt.reference(), reference);
        assert!(
            kura.resource_inventory
                .component_usage_for_tests(ResourceFamily::EvidenceKeyRecords)
                .is_err(),
            "a later successful receipt cannot erase an earlier accounting fault"
        );
        kura.validate_fastpq_artifact_inventory_on_startup()
            .unwrap();
        let observed = observe_actual_physical_fixture(&kura);
        assert_eq!(
            kura.resource_inventory
                .component_usage_for_tests(ResourceFamily::EvidenceKeyRecords)
                .unwrap(),
            observed[ResourceFamily::EvidenceKeyRecords as usize]
        );
    }

    fn actual_config(
        root: &Path,
        policy: KuraFastpqArtifactPolicy,
    ) -> iroha_config::parameters::actual::Kura {
        use iroha_config::parameters::defaults::kura as defaults;
        iroha_config::parameters::actual::Kura {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(root.to_path_buf()),
            max_disk_usage_bytes: defaults::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: defaults::BLOCKS_IN_MEMORY,
            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: policy,
            debug_output_new_blocks: false,
            fsync_mode: defaults::FSYNC_MODE,
            fsync_interval: defaults::FSYNC_INTERVAL,
        }
    }

    #[test]
    fn configured_startup_applies_retained_count_and_aggregate_caps_before_accepting_store() {
        for invalid in [
            "stable-count",
            "aggregate-with-temp",
            "per-artifact",
            "known-marker-name",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let config = actual_config(directory.path(), limits(8, 1, 8));
            let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
                &config,
                &iroha_config::parameters::actual::LaneConfig::default(),
            )
            .unwrap();
            let first = kura.persist_fastpq_artifact(b"12345678").unwrap();
            drop(kura);
            let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
                &config,
                &iroha_config::parameters::actual::LaneConfig::default(),
            )
            .expect("a retained namespace exactly at its configured caps reopens");
            assert_eq!(
                kura.read_fastpq_artifact(first.reference()).unwrap(),
                b"12345678"
            );
            let namespace = kura.store_root.join(DIRECTORY);
            match invalid {
                "stable-count" => {
                    std::fs::write(
                        namespace.join(FastpqStoredArtifactReference::for_bytes(b"x").file_name()),
                        b"x",
                    )
                    .unwrap();
                }
                "aggregate-with-temp" => {
                    std::fs::write(namespace.join(TEMPORARY), b"x").unwrap();
                }
                "per-artifact" => {
                    std::fs::write(path(&kura, first.reference()), b"123456789").unwrap();
                }
                "known-marker-name" => {
                    std::fs::write(namespace.join(super::super::COUNT_FILE_NAME), b"x").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                kura.validate_fastpq_artifact_inventory_on_startup()
                    .is_err(),
                "{invalid}"
            );
            let inventory_before = std::fs::read_dir(&namespace)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            drop(kura);
            let reopened = Kura::open_test_kura_with_configured_lane_config(
                &config,
                &iroha_config::parameters::actual::LaneConfig::default(),
            );
            assert!(reopened.is_err(), "{invalid}");
            let error = reopened.expect_err("invalid FASTPQ inventory fails startup");
            assert!(
                matches!(&error, Error::IO(source, _) if source.to_string().contains("FASTPQ")),
                "{invalid}: {error}"
            );
            let inventory_after = std::fs::read_dir(&namespace)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), std::fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                inventory_after, inventory_before,
                "startup quota rejection never deletes retained evidence"
            );
        }
    }

    #[test]
    fn configured_constructor_rejects_invalid_policy_before_creating_store() {
        let parent = tempfile::tempdir().unwrap();
        let store = parent.path().join("must-remain-absent");
        let config = actual_config(&store, limits(8, 1, 7));
        assert!(
            Kura::open_test_kura_with_configured_lane_config(
                &config,
                &iroha_config::parameters::actual::LaneConfig::default()
            )
            .is_err()
        );
        assert!(!store.exists());
    }

    #[test]
    fn constructed_policy_cannot_be_replaced_by_later_config_changes() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = actual_config(directory.path(), limits(8, 2, 16));
        let (kura, _) = Kura::open_test_kura_with_configured_lane_config(
            &config,
            &iroha_config::parameters::actual::LaneConfig::default(),
        )
        .unwrap();
        config.fastpq_artifacts = limits(16, 4, 64);
        assert!(config.fastpq_artifacts.validate().is_ok());
        assert!(kura.persist_fastpq_artifact(b"ninebytes").is_err());
        let receipt = kura.persist_fastpq_artifact(b"eightbyt").unwrap();
        assert_eq!(
            kura.read_fastpq_artifact(receipt.reference()).unwrap(),
            b"eightbyt"
        );
        assert_eq!(kura.fastpq_artifact_policy, limits(8, 2, 16));
    }
}

/// Original physical notification custody for retained FASTPQ artifact APIs.
#[cfg(all(test, unix, not(target_os = "espidf")))]
mod original_release_tests {
    include!("fastpq_artifact_release_tests.rs");
}
