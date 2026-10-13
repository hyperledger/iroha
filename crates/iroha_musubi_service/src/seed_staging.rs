//! Durable, separate seed custody for the already verified private Musubi ingress route.
//!
//! An issued receipt does not make this CAR a finalized provider pin. This owner retains its
//! exact bytes for a higher-layer finalized-registration owner. This local backend grants no
//! ledger authority. Receipt expiry alone never removes staged bytes.
use crate::{
    MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1, MusubiPublicationServiceBackendErrorV1,
    MusubiSeedIngressBackendV1, MusubiSeedIngressCarPlanV1,
};
use iroha_data_model::{
    musubi::{
        MUSUBI_MAX_CAR_BYTES_V1, MusubiArchiveCommitmentV1, MusubiSeedIngressReceiptBindingV1,
        MusubiSeedIngressReceiptV1,
    },
    sorafs::capacity::ProviderId,
};
use iroha_fs::{FileSnapshot, PrivateDirectory};
use sorafs_car::{CarBuildPlan, musubi::MusubiBundleVerifierV1};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read as _, Write as _},
    path::Path,
};
const OWNER_LOCK_FILE: &str = "seed-owner.lock";

const STAGE_MAGIC: [u8; 16] = *b"musubi-seed-v1\0\0";
const STAGE_HEADER_BYTES: usize = 32;
const MAX_STAGE_METADATA_BYTES: usize = 64 * 1024;
const MAX_STAGE_RECORDS: u32 = 1_024;
const MAX_STAGE_RECORD_BYTES: u64 = STAGE_HEADER_BYTES as u64
    + MAX_STAGE_METADATA_BYTES as u64
    + MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1 as u64
    + MUSUBI_MAX_CAR_BYTES_V1;
const STAGE_SUFFIX: &str = ".seed";

/// Closed failure for the private seed-custody directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MusubiSeedStagingErrorV1 {
    /// The configured root, its ancestry, or a resident record is unsafe or substituted.
    Invalid,
    /// Another process owns the staging directory.
    Locked,
    /// An exact operation conflicts with immutable resident bytes or identity.
    Conflict,
    /// The fixed aggregate retention limit is exhausted.
    Capacity,
    /// Storage or local allocation is temporarily unavailable.
    Unavailable,
}
impl MusubiSeedStagingErrorV1 {
    fn backend(self) -> MusubiPublicationServiceBackendErrorV1 {
        match self {
            Self::Locked | Self::Capacity | Self::Unavailable => {
                MusubiPublicationServiceBackendErrorV1::Retryable
            }
            Self::Invalid | Self::Conflict => MusubiPublicationServiceBackendErrorV1::Permanent,
        }
    }
}

#[derive(
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
    Clone,
    Debug,
    PartialEq,
    Eq,
)]
#[norito_schema(name = "iroha_musubi_service::seed_staging::StagedSeedMetadataV1")]
struct StagedSeedMetadataV1 {
    version: u8,
    operation_id: [u8; 32],
    binding: MusubiSeedIngressReceiptBindingV1,
    commitment: MusubiArchiveCommitmentV1,
}
struct StagedSeedRecordV1 {
    metadata: StagedSeedMetadataV1,
    plan: CarBuildPlan,
    car: Vec<u8>,
}

/// A bounded, process-exclusive seed backend for one exact provider and deployment root.
///
/// The original owner-private directory and lock are retained through the canonical native
/// filesystem owner. Records are published without replacement under strict owner-read-only
/// custody (Unix 0400 or Windows protected read-only DACL). An interrupted write leaves a visible
/// tombstone; this owner never deletes or repairs staged bytes on expiry or restart.
pub struct MusubiSeedStagingBackendV1 {
    provider: ProviderId,
    directory: PrivateDirectory,
    lock: File,
    lock_snapshot: FileSnapshot,
    max_records: u32,
    max_total_bytes: u64,
}
impl std::fmt::Debug for MusubiSeedStagingBackendV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MusubiSeedStagingBackendV1")
            .field("provider", &self.provider)
            .field("max_records", &self.max_records)
            .field("max_total_bytes", &self.max_total_bytes)
            .finish_non_exhaustive()
    }
}
impl MusubiSeedStagingBackendV1 {
    /// Explicitly initialize an empty native owner-private seed directory once.
    ///
    /// The owner marker is installed before staging becomes possible. Ordinary [`Self::open`]
    /// never recreates this marker, even when every original record has been deleted.
    /// # Errors
    /// Refuses nonempty or unsafe storage, invalid bounds, a concurrent owner, and native I/O.
    pub fn initialize(
        root: &Path,
        provider: ProviderId,
        max_records: u32,
        max_total_bytes: u64,
    ) -> Result<Self, MusubiSeedStagingErrorV1> {
        Self::open_inner(root, provider, max_records, max_total_bytes, true)
    }
    /// Pin an already initialized private directory under the configured retention limits.
    ///
    /// # Errors
    /// Rejects unsafe ancestry, a missing owner marker, a competing process, invalid limits,
    /// unsafe resident entry names or metadata, or inventory beyond the configured ceilings.
    pub fn open(
        root: &Path,
        provider: ProviderId,
        max_records: u32,
        max_total_bytes: u64,
    ) -> Result<Self, MusubiSeedStagingErrorV1> {
        Self::open_inner(root, provider, max_records, max_total_bytes, false)
    }
    fn open_inner(
        root: &Path,
        provider: ProviderId,
        max_records: u32,
        max_total_bytes: u64,
        initialize: bool,
    ) -> Result<Self, MusubiSeedStagingErrorV1> {
        if max_records == 0
            || max_records > MAX_STAGE_RECORDS
            || max_total_bytes == 0
            || max_total_bytes > MAX_STAGE_RECORD_BYTES * u64::from(MAX_STAGE_RECORDS)
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let directory =
            PrivateDirectory::open_exact(root).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if initialize
            && !directory
                .entries(1)
                .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?
                .is_empty()
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let lock = if initialize {
            directory.create_lock(OWNER_LOCK_FILE)
        } else {
            directory.open_existing_lock(OWNER_LOCK_FILE)
        }
        .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let lock_snapshot =
            FileSnapshot::private_journal(&lock).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if lock
            .metadata()
            .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?
            .len()
            != 0
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => MusubiSeedStagingErrorV1::Locked,
            fs::TryLockError::Error(_) => MusubiSeedStagingErrorV1::Unavailable,
        })?;
        let backend = Self {
            provider,
            directory,
            lock,
            lock_snapshot,
            max_records,
            max_total_bytes,
        };
        backend.inventory()?;
        Ok(backend)
    }

    /// Read the exact locally retained plan and CAR matching a signed receipt and commitment.
    ///
    /// This authenticates local byte custody only. It does not prove archive registration,
    /// native finality, a provider pin or permission to publish. The daemon's finalized seed
    /// capability independently establishes those prerequisites before calling this method.
    /// # Errors
    /// Refuses changed receipt/commitment, unsafe custody, malformed bytes or allocation failure.
    pub fn read_staged_car(
        &self,
        receipt: &MusubiSeedIngressReceiptV1,
        commitment: &MusubiArchiveCommitmentV1,
    ) -> Result<(CarBuildPlan, Vec<u8>), MusubiSeedStagingErrorV1> {
        let binding = &receipt.payload.binding;
        receipt
            .verify(binding, receipt.payload.issued_at_ms)
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if binding.seed_provider != self.provider || commitment.archive_id() != binding.archive_id {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let key = record_name(binding)?;
        let record = self.read_record(&key)?;
        if record.metadata.binding != *binding || record.metadata.commitment != *commitment {
            return Err(MusubiSeedStagingErrorV1::Conflict);
        }
        Ok((record.plan, record.car))
    }

    fn verify_custody(&self) -> Result<(), MusubiSeedStagingErrorV1> {
        self.directory
            .revalidate()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let named = self
            .directory
            .open_read(OWNER_LOCK_FILE)
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if FileSnapshot::private_journal(&self.lock).ok() != Some(self.lock_snapshot)
            || FileSnapshot::private_journal(&named).ok() != Some(self.lock_snapshot)
            || named
                .metadata()
                .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?
                .len()
                != 0
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        self.directory
            .revalidate()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)
    }
    fn inventory(&self) -> Result<(u32, u64), MusubiSeedStagingErrorV1> {
        self.verify_custody()?;
        let mut records = 0u32;
        let mut bytes = 0u64;
        let mut refusal = None;
        self.directory
            .visit_private_files(MAX_STAGE_RECORDS as usize + 1, |name, metadata| {
                let result = (|| {
                    if name == OWNER_LOCK_FILE {
                        if !metadata.is_empty() || metadata.is_read_only() {
                            return Err(MusubiSeedStagingErrorV1::Invalid);
                        }
                        return Ok(());
                    }
                    let hex_key = name
                        .to_str()
                        .and_then(|value| value.strip_suffix(STAGE_SUFFIX))
                        .ok_or(MusubiSeedStagingErrorV1::Invalid)?;
                    if hex_key.len() != 64
                        || !hex_key
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                        || !metadata.is_read_only()
                        || metadata.len() < STAGE_HEADER_BYTES as u64
                        || metadata.len() > MAX_STAGE_RECORD_BYTES
                    {
                        return Err(MusubiSeedStagingErrorV1::Invalid);
                    }
                    records = records
                        .checked_add(1)
                        .ok_or(MusubiSeedStagingErrorV1::Capacity)?;
                    bytes = bytes
                        .checked_add(metadata.len())
                        .ok_or(MusubiSeedStagingErrorV1::Capacity)?;
                    if records > self.max_records || bytes > self.max_total_bytes {
                        return Err(MusubiSeedStagingErrorV1::Capacity);
                    }
                    Ok(())
                })();
                result.map_err(|error| {
                    refusal = Some(error);
                    io::Error::other("invalid seed inventory")
                })
            })
            .map_err(|_| refusal.unwrap_or(MusubiSeedStagingErrorV1::Invalid))?;
        self.verify_custody()?;
        Ok((records, bytes))
    }

    fn read_record(&self, name: &str) -> Result<StagedSeedRecordV1, MusubiSeedStagingErrorV1> {
        self.verify_custody()?;
        let mut file = self
            .directory
            .open_borrowed_read_only(
                OsStr::new(name),
                usize::try_from(MAX_STAGE_RECORD_BYTES)
                    .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?,
            )
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    MusubiSeedStagingErrorV1::Conflict
                } else {
                    MusubiSeedStagingErrorV1::Invalid
                }
            })?;
        let before = file
            .snapshot()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let length = file.len().map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let mut header = [0u8; STAGE_HEADER_BYTES];
        file.read_exact(&mut header)
            .map_err(|error| read_error(&error))?;
        if header[..16] != STAGE_MAGIC {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let metadata_len = u32::from_be_bytes(header[16..20].try_into().expect("fixed header"));
        let plan_len = u32::from_be_bytes(header[20..24].try_into().expect("fixed header"));
        let car_len = u64::from_be_bytes(header[24..32].try_into().expect("fixed header"));
        if metadata_len == 0
            || metadata_len as usize > MAX_STAGE_METADATA_BYTES
            || plan_len == 0
            || plan_len as usize > MUSUBI_MAX_SEED_INGRESS_PLAN_BYTES_V1
            || car_len == 0
            || car_len > MUSUBI_MAX_CAR_BYTES_V1
            || STAGE_HEADER_BYTES as u64 + u64::from(metadata_len) + u64::from(plan_len) + car_len
                != length
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let mut metadata_bytes = bounded_buffer(metadata_len as usize)?;
        let mut plan_bytes = bounded_buffer(plan_len as usize)?;
        let mut car = bounded_buffer(
            usize::try_from(car_len).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?,
        )?;
        file.read_exact(&mut metadata_bytes)
            .and_then(|()| file.read_exact(&mut plan_bytes))
            .and_then(|()| file.read_exact(&mut car))
            .map_err(|error| read_error(&error))?;
        let mut tail = [0u8; 1];
        if file.read(&mut tail).map_err(|error| read_error(&error))? != 0
            || file.snapshot().ok() != Some(before)
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        self.verify_custody()?;
        let metadata: StagedSeedMetadataV1 = norito::decode_canonical_with_limits(
            &metadata_bytes,
            norito::canonical_decode_limits(metadata_bytes.len()),
        )
        .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if metadata.version != 1
            || metadata.operation_id == [0; 32]
            || metadata.binding.validate().is_err()
            || metadata.commitment.validate().is_err()
            || metadata.binding.archive_id != metadata.commitment.archive_id()
            || metadata.binding.seed_provider != self.provider
            || metadata.binding.car_body_digest != metadata.commitment.car_digest
            || metadata.binding.car_body_length != metadata.commitment.car_size
            || record_name(&metadata.binding)? != name
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let witness: MusubiSeedIngressCarPlanV1 = norito::decode_canonical_with_limits(
            &plan_bytes,
            norito::canonical_decode_limits(plan_bytes.len()),
        )
        .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if witness
            .canonical_bytes()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?
            != plan_bytes
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let plan = witness
            .to_car_build_plan(&metadata.commitment)
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        verify_exact_bundle(&metadata.binding, &metadata.commitment, &plan, &car)?;
        if file.snapshot().ok() != Some(before) {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        self.verify_custody()?;
        Ok(StagedSeedRecordV1 {
            metadata,
            plan,
            car,
        })
    }
}
impl MusubiSeedIngressBackendV1 for MusubiSeedStagingBackendV1 {
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
        self.stage(operation_id, binding, commitment, plan, car)
            .map_err(MusubiSeedStagingErrorV1::backend)
    }
    fn verify_staged_car(
        &self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        let name = record_name(binding).map_err(MusubiSeedStagingErrorV1::backend)?;
        let retained = self
            .read_record(&name)
            .map_err(MusubiSeedStagingErrorV1::backend)?;
        if retained.metadata.operation_id != operation_id
            || retained.metadata.binding != *binding
            || retained.metadata.commitment != *commitment
            || retained.plan != *plan
            || retained.car != car
        {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        Ok(())
    }
}
impl MusubiSeedStagingBackendV1 {
    fn stage(
        &mut self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiSeedStagingErrorV1> {
        if operation_id == [0; 32]
            || binding.seed_provider != self.provider
            || binding.validate().is_err()
            || commitment.validate().is_err()
            || binding.archive_id != commitment.archive_id()
            || binding.car_body_digest != commitment.car_digest
            || binding.car_body_length != commitment.car_size
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        verify_exact_bundle(binding, commitment, plan, car)?;
        let witness = MusubiSeedIngressCarPlanV1::from_car_build_plan(plan, commitment)
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let plan_bytes = witness
            .canonical_bytes()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let metadata = StagedSeedMetadataV1 {
            version: 1,
            operation_id,
            binding: binding.clone(),
            commitment: commitment.clone(),
        };
        let metadata_bytes =
            norito::encode_canonical(&metadata).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        if metadata_bytes.is_empty() || metadata_bytes.len() > MAX_STAGE_METADATA_BYTES {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        let name = record_name(binding)?;
        self.verify_custody()?;
        match self.read_record(&name) {
            Ok(existing) => {
                if existing.metadata == metadata && existing.plan == *plan && existing.car == car {
                    return Ok(());
                }
                return Err(MusubiSeedStagingErrorV1::Conflict);
            }
            Err(MusubiSeedStagingErrorV1::Conflict) => {} // absent exact record, never an unsafe entry
            Err(error) => return Err(error),
        }
        let (count, occupied) = self.inventory()?;
        let new_bytes = STAGE_HEADER_BYTES as u64
            + metadata_bytes.len() as u64
            + plan_bytes.len() as u64
            + car.len() as u64;
        if count >= self.max_records
            || occupied
                .checked_add(new_bytes)
                .is_none_or(|total| total > self.max_total_bytes)
        {
            return Err(MusubiSeedStagingErrorV1::Capacity);
        }
        let pending = format!("{name}.pending");
        let mut file = self
            .directory
            .create_borrowed_private(
                OsStr::new(&pending),
                usize::try_from(new_bytes).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?,
            )
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    MusubiSeedStagingErrorV1::Invalid
                } else {
                    MusubiSeedStagingErrorV1::Unavailable
                }
            })?;
        let mut header = [0u8; STAGE_HEADER_BYTES];
        header[..16].copy_from_slice(&STAGE_MAGIC);
        header[16..20].copy_from_slice(
            &u32::try_from(metadata_bytes.len())
                .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?
                .to_be_bytes(),
        );
        header[20..24].copy_from_slice(
            &u32::try_from(plan_bytes.len())
                .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?
                .to_be_bytes(),
        );
        header[24..32].copy_from_slice(
            &u64::try_from(car.len())
                .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?
                .to_be_bytes(),
        );
        file.write_all(&header)
            .and_then(|()| file.write_all(&metadata_bytes))
            .and_then(|()| file.write_all(&plan_bytes))
            .and_then(|()| file.write_all(car))
            .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?;
        self.verify_custody()?;
        let sealed = file
            .seal_read_only()
            .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?;
        let installed_file = sealed
            .publish_new_name(OsStr::new(&name))
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    MusubiSeedStagingErrorV1::Conflict
                } else {
                    MusubiSeedStagingErrorV1::Unavailable
                }
            })?;
        let installed_snapshot = installed_file
            .snapshot()
            .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
        let installed = self.read_record(&name)?;
        if installed.metadata != metadata
            || installed.plan != *plan
            || installed.car != car
            || installed_file.snapshot().ok() != Some(installed_snapshot)
        {
            return Err(MusubiSeedStagingErrorV1::Invalid);
        }
        Ok(())
    }
}

fn verify_exact_bundle(
    binding: &MusubiSeedIngressReceiptBindingV1,
    commitment: &MusubiArchiveCommitmentV1,
    plan: &CarBuildPlan,
    car: &[u8],
) -> Result<(), MusubiSeedStagingErrorV1> {
    if u64::try_from(car.len()).ok() != Some(commitment.car_size)
        || blake3::hash(car).as_bytes() != commitment.car_digest.as_bytes()
    {
        return Err(MusubiSeedStagingErrorV1::Invalid);
    }
    let verified = MusubiBundleVerifierV1::verify(plan, car, commitment)
        .map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
    if verified.semantic_release().semantic_digest() != binding.semantic_release_manifest_digest {
        return Err(MusubiSeedStagingErrorV1::Invalid);
    }
    Ok(())
}
fn record_name(
    binding: &MusubiSeedIngressReceiptBindingV1,
) -> Result<String, MusubiSeedStagingErrorV1> {
    let encoded =
        norito::encode_canonical(binding).map_err(|_| MusubiSeedStagingErrorV1::Invalid)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroha.musubi.seed-staging-key.v1");
    hasher.update(&encoded);
    Ok(format!(
        "{}{}",
        hex::encode(hasher.finalize().as_bytes()),
        STAGE_SUFFIX
    ))
}
fn bounded_buffer(length: usize) -> Result<Vec<u8>, MusubiSeedStagingErrorV1> {
    norito::core::reserve_decode_allocation(length)
        .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| MusubiSeedStagingErrorV1::Unavailable)?;
    buffer.resize(length, 0);
    Ok(buffer)
}
fn read_error(error: &std::io::Error) -> MusubiSeedStagingErrorV1 {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        MusubiSeedStagingErrorV1::Invalid
    } else {
        MusubiSeedStagingErrorV1::Unavailable
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_test_support::fixture;
    struct PrivateTestRoot {
        directory: PrivateDirectory,
        parent: tempfile::TempDir,
    }
    impl PrivateTestRoot {
        fn path(&self) -> &Path {
            self.directory.path()
        }
    }
    fn private_root() -> PrivateTestRoot {
        let parent = tempfile::tempdir().expect("seed test workspace");
        let directory = PrivateDirectory::open_or_create(parent.path().join("private"))
            .expect("native private seed root");
        PrivateTestRoot { directory, parent }
    }

    #[test]
    fn local_seed_read_requires_exact_signed_receipt_and_retained_commitment() {
        use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
        use iroha_data_model::musubi::{
            MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptPayloadV1,
        };
        let (binding, commitment, plan, car) = fixture();
        let root = private_root();
        let mut owner = MusubiSeedStagingBackendV1::initialize(
            root.path(),
            binding.seed_provider,
            2,
            MAX_STAGE_RECORD_BYTES * 2,
        )
        .unwrap();
        owner
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .unwrap();
        let key = KeyPair::try_from_seed(vec![0x32; 32], Algorithm::Ed25519).unwrap();
        let signed_receipt = |binding: MusubiSeedIngressReceiptBindingV1| {
            let payload = MusubiSeedIngressReceiptPayloadV1 {
                version: 1,
                binding,
                issued_at_ms: 1_000,
                expires_at_ms: 61_000,
            };
            MusubiSeedIngressReceiptV1 {
                approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                    public_key: key.public_key().clone(),
                    signature: SignatureOf::try_from_hash(
                        key.private_key(),
                        payload.signing_hash(),
                    )
                    .unwrap(),
                }],
                payload,
            }
        };
        let receipt = signed_receipt(binding.clone());
        let before = root.directory.entries(4).unwrap();
        assert_eq!(
            owner.read_staged_car(&receipt, &commitment).unwrap(),
            (plan.clone(), car.clone())
        );
        let mut changed = receipt.clone();
        changed.payload.binding.nonce[0] ^= 1;
        assert_eq!(
            owner.read_staged_car(&changed, &commitment),
            Err(MusubiSeedStagingErrorV1::Invalid)
        );
        let mut another_binding = binding.clone();
        another_binding.nonce[0] ^= 1;
        let changed = signed_receipt(another_binding);
        assert_eq!(
            owner.read_staged_car(&changed, &commitment),
            Err(MusubiSeedStagingErrorV1::Conflict)
        );
        let mut other_commitment = commitment.clone();
        other_commitment.file_count += 1;
        assert!(owner.read_staged_car(&receipt, &other_commitment).is_err());
        assert_eq!(root.directory.entries(4).unwrap(), before);
        drop(owner);
        let owner = MusubiSeedStagingBackendV1::open(
            root.path(),
            binding.seed_provider,
            2,
            MAX_STAGE_RECORD_BYTES * 2,
        )
        .unwrap();
        assert_eq!(
            owner.read_staged_car(&receipt, &commitment).unwrap(),
            (plan, car)
        );
    }

    #[test]
    fn exact_seed_survives_restart_and_conflicting_operation_cannot_replace_it() {
        let (binding, commitment, plan, car) = fixture();
        let temporary = private_root();
        let root = temporary.path().to_owned();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            &root,
            binding.seed_provider,
            2,
            MAX_STAGE_RECORD_BYTES * 2,
        )
        .expect("stage owner");
        assert_eq!(backend.provider_id(), binding.seed_provider);
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("first verified stage");
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("idempotent stage");
        backend
            .verify_staged_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("completed receipt can use exact retained bytes");
        assert_eq!(
            backend.verify_staged_car([0x62; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(
            backend.stage_exact_car([0x62; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        let name = record_name(&binding).expect("binding key");
        let staged = backend.read_record(&name).expect("read exact stage");
        assert_eq!(staged.metadata.operation_id, [0x61; 32]);
        assert_eq!(staged.plan, plan);
        assert_eq!(staged.car, car);
        assert_eq!(backend.inventory().expect("inventory").0, 1);
        drop(backend);
        let backend = MusubiSeedStagingBackendV1::open(
            &root,
            binding.seed_provider,
            2,
            MAX_STAGE_RECORD_BYTES * 2,
        )
        .expect("restart stage owner");
        assert_eq!(backend.read_record(&name).expect("restart bytes").car, car);
        backend
            .verify_staged_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("restarted owner retains exact completed receipt bytes");
    }

    #[test]
    fn seed_root_refuses_parallel_owner_tombstones_and_capacity_overrun() {
        let (binding, commitment, plan, car) = fixture();
        let temporary = private_root();
        let root = temporary.path().to_owned();
        let owner = MusubiSeedStagingBackendV1::initialize(&root, binding.seed_provider, 1, 1)
            .expect("stage owner");
        assert!(matches!(
            MusubiSeedStagingBackendV1::open(&root, binding.seed_provider, 1, 1),
            Err(MusubiSeedStagingErrorV1::Locked),
        ));
        drop(owner);
        let mut owner = MusubiSeedStagingBackendV1::open(&root, binding.seed_provider, 1, 1)
            .expect("reopened stage owner");
        assert_eq!(
            owner.stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Retryable),
        );
        assert_eq!(owner.inventory().expect("unchanged inventory"), (0, 0));
        drop(owner);
        fs::write(root.join("interrupted.pending"), b"tombstone").expect("tombstone");
        assert!(matches!(
            MusubiSeedStagingBackendV1::open(&root, binding.seed_provider, 1, 1),
            Err(MusubiSeedStagingErrorV1::Invalid),
        ));
    }

    #[test]
    fn substituted_seed_file_is_never_followed_or_recovered() {
        let (binding, commitment, plan, car) = fixture();
        let temporary = private_root();
        let root = temporary.path().to_owned();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            &root,
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .expect("stage owner");
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("first verified stage");
        let name = record_name(&binding).expect("binding key");
        let staged = root.join(&name);
        fs::remove_file(&staged).expect("remove staged fixture");
        assert_eq!(
            backend.verify_staged_car([0x61; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert!(
            !staged.exists(),
            "cached receipt check never recreates lost custody"
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink("untrusted-target", &staged).expect("substitute symlink");
        #[cfg(windows)]
        temporary
            .directory
            .create_child(&name)
            .expect("substitute wrong native type");
        assert!(matches!(
            backend.read_record(&name),
            Err(MusubiSeedStagingErrorV1::Invalid),
        ));
        assert_eq!(
            backend.verify_staged_car([0x61; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        drop(backend);
        assert!(matches!(
            MusubiSeedStagingBackendV1::open(
                &root,
                binding.seed_provider,
                1,
                MAX_STAGE_RECORD_BYTES
            ),
            Err(MusubiSeedStagingErrorV1::Invalid),
        ));
    }

    #[test]
    fn torn_record_is_invalid_while_transient_io_is_retryable() {
        let (binding, commitment, plan, car) = fixture();
        let temporary = private_root();
        let root = temporary.path().to_owned();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            &root,
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .expect("stage owner");
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .expect("verified stage");
        let name = record_name(&binding).expect("binding key");
        let staged = root.join(&name);
        fs::remove_file(&staged).expect("remove original fixture");
        let mut torn = temporary
            .directory
            .create_borrowed_private(OsStr::new(&name), 4)
            .unwrap();
        torn.write_all(b"torn").unwrap();
        drop(torn.seal_read_only().unwrap());
        assert!(matches!(
            backend.read_record(&name),
            Err(MusubiSeedStagingErrorV1::Invalid),
        ));
        assert_eq!(
            read_error(&std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            MusubiSeedStagingErrorV1::Invalid,
        );
        assert_eq!(
            read_error(&std::io::Error::other("temporary device fault")),
            MusubiSeedStagingErrorV1::Unavailable,
        );
    }
    #[test]
    fn ordinary_open_never_creates_or_repairs_a_missing_owner_marker() {
        let temporary = private_root();
        let provider = ProviderId::new([1; 32]);
        assert!(matches!(
            MusubiSeedStagingBackendV1::open(temporary.path(), provider, 1, MAX_STAGE_RECORD_BYTES),
            Err(MusubiSeedStagingErrorV1::Invalid)
        ));
        assert!(temporary.directory.entries(1).unwrap().is_empty());
        drop(
            MusubiSeedStagingBackendV1::initialize(
                temporary.path(),
                provider,
                1,
                MAX_STAGE_RECORD_BYTES,
            )
            .unwrap(),
        );
        assert!(
            MusubiSeedStagingBackendV1::initialize(
                temporary.path(),
                provider,
                1,
                MAX_STAGE_RECORD_BYTES
            )
            .is_err()
        );
        fs::remove_file(temporary.path().join(OWNER_LOCK_FILE)).unwrap();
        assert!(
            MusubiSeedStagingBackendV1::open(temporary.path(), provider, 1, MAX_STAGE_RECORD_BYTES)
                .is_err()
        );
        assert!(temporary.directory.entries(1).unwrap().is_empty());
    }
    #[test]
    fn pending_seed_writer_survives_refusal_and_blocks_new_staging_without_cleanup() {
        let temporary = private_root();
        let (binding, commitment, plan, car) = fixture();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            temporary.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        let name = format!("{}.pending", record_name(&binding).unwrap());
        let mut pending = temporary
            .directory
            .create_borrowed_private(OsStr::new(&name), 4)
            .unwrap();
        pending.write_all(b"part").unwrap();
        drop(pending);
        let before = temporary.directory.entries(2).unwrap();
        assert_eq!(
            backend.stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );
        assert_eq!(temporary.directory.entries(2).unwrap(), before);
        assert_eq!(
            temporary.directory.read(&name, 4).unwrap().as_slice(),
            b"part"
        );
        drop(backend);
        assert!(matches!(
            MusubiSeedStagingBackendV1::open(
                temporary.path(),
                binding.seed_provider,
                1,
                MAX_STAGE_RECORD_BYTES
            ),
            Err(MusubiSeedStagingErrorV1::Invalid)
        ));
        assert_eq!(
            temporary.directory.read(&name, 4).unwrap().as_slice(),
            b"part"
        );
    }
    #[test]
    fn seed_payload_allocation_refusal_preserves_original_record_for_retry() {
        let temporary = private_root();
        let (binding, commitment, plan, car) = fixture();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            temporary.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .unwrap();
        let name = record_name(&binding).unwrap();
        let before = temporary
            .directory
            .open_borrowed_read_only(
                OsStr::new(&name),
                usize::try_from(MAX_STAGE_RECORD_BYTES).expect("record cap fits usize"),
            )
            .unwrap()
            .snapshot()
            .unwrap();
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || backend.read_record(&name),
        );
        assert!(matches!(
            refused,
            Err(MusubiSeedStagingErrorV1::Unavailable)
        ));
        assert_eq!(
            temporary
                .directory
                .open_borrowed_read_only(
                    OsStr::new(&name),
                    usize::try_from(MAX_STAGE_RECORD_BYTES).expect("record cap fits usize")
                )
                .unwrap()
                .snapshot()
                .unwrap(),
            before
        );
        assert_eq!(backend.read_record(&name).unwrap().car, car);
    }
    #[test]
    fn resident_seed_without_original_lock_is_never_reopened_or_erased() {
        let temporary = private_root();
        let (binding, commitment, plan, car) = fixture();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            temporary.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .unwrap();
        drop(backend);
        fs::remove_file(temporary.path().join(OWNER_LOCK_FILE)).unwrap();
        let before = temporary.directory.entries(2).unwrap();
        assert!(
            MusubiSeedStagingBackendV1::open(
                temporary.path(),
                binding.seed_provider,
                1,
                MAX_STAGE_RECORD_BYTES
            )
            .is_err()
        );
        assert!(
            MusubiSeedStagingBackendV1::initialize(
                temporary.path(),
                binding.seed_provider,
                1,
                MAX_STAGE_RECORD_BYTES
            )
            .is_err()
        );
        assert_eq!(temporary.directory.entries(2).unwrap(), before);
    }
    #[cfg(unix)]
    #[test]
    fn changed_native_namespace_or_fifo_is_refused_without_touching_replacement() {
        let temporary = private_root();
        let (binding, commitment, plan, car) = fixture();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            temporary.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        let displaced = temporary.parent.path().join("displaced");
        fs::rename(temporary.path(), &displaced).unwrap();
        let replacement = PrivateDirectory::open_or_create(temporary.path()).unwrap();
        assert_eq!(
            backend.stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent)
        );
        assert!(replacement.entries(1).unwrap().is_empty());
        assert_eq!(fs::read_dir(&displaced).unwrap().count(), 1);
        drop(backend);
        let directory = private_root();
        let backend = MusubiSeedStagingBackendV1::initialize(
            directory.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        let name = record_name(&binding).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(directory.path().join(&name))
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            backend.read_record(&name),
            Err(MusubiSeedStagingErrorV1::Invalid)
        ));
    }
    #[cfg(windows)]
    #[test]
    fn windows_retained_seed_custody_denies_lock_replacement_and_unsealed_records() {
        let temporary = private_root();
        let (binding, commitment, plan, car) = fixture();
        let mut backend = MusubiSeedStagingBackendV1::initialize(
            temporary.path(),
            binding.seed_provider,
            1,
            MAX_STAGE_RECORD_BYTES,
        )
        .unwrap();
        assert!(fs::rename(temporary.path(), temporary.parent.path().join("displaced")).is_err());
        assert!(fs::remove_file(temporary.path().join(OWNER_LOCK_FILE)).is_err());
        backend
            .stage_exact_car([0x61; 32], &binding, &commitment, &plan, &car)
            .unwrap();
        let name = record_name(&binding).unwrap();
        assert!(
            fs::write(temporary.path().join(&name), b"rewrite").is_err(),
            "actual owner-read-only DACL denies writes"
        );
        assert_eq!(backend.read_record(&name).unwrap().car, car);
        fs::remove_file(temporary.path().join(&name)).unwrap();
        temporary
            .directory
            .write_atomic(&name, b"writable", iroha_fs::PublishMode::CreateNew)
            .unwrap();
        assert!(matches!(
            backend.read_record(&name),
            Err(MusubiSeedStagingErrorV1::Invalid)
        ));
        assert!(backend.inventory().is_err());
    }
}
