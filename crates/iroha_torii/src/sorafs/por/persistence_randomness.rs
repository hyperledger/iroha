// PoR challenge persistence and pinned randomness-provider state.
#[derive(Debug, Clone)]
struct ChallengeRecord {
    challenge: PorChallengeV1,
    proof_digest: Option<[u8; 32]>,
    proof_submitted_at: Option<u64>,
    responded_at: Option<u64>,
    verdict: Option<RecordedVerdict>,
    repair_task_id: Option<[u8; 32]>,
}
impl ChallengeRecord {
    #[cfg(test)]
    fn from_challenge(challenge: PorChallengeV1) -> Self {
        Self {
            challenge,
            proof_digest: None,
            proof_submitted_at: None,
            responded_at: None,
            verdict: None,
            repair_task_id: None,
        }
    }
    #[cfg(test)]
    fn ensure_consistency(
        &self,
        manifest_digest: [u8; 32],
        provider_id: [u8; 32],
    ) -> Result<(), PorCoordinatorError> {
        if self.challenge.manifest_digest != manifest_digest {
            return Err(PorCoordinatorError::ManifestMismatch {
                expected: self.challenge.manifest_digest,
                actual: manifest_digest,
                expected_hex: hex::encode(self.challenge.manifest_digest),
                actual_hex: hex::encode(manifest_digest),
            });
        }
        if self.challenge.provider_id != provider_id {
            return Err(PorCoordinatorError::ProviderMismatch {
                expected: self.challenge.provider_id,
                actual: provider_id,
                expected_hex: hex::encode(self.challenge.provider_id),
                actual_hex: hex::encode(provider_id),
            });
        }
        Ok(())
    }
    #[cfg(test)]
    fn validate_verdict_transition(
        &self,
        verdict: &AuditVerdictV1,
    ) -> Result<(), PorCoordinatorError> {
        if verdict.decided_at < self.challenge.issued_at {
            return Err(PorCoordinatorError::VerdictBeforeChallenge {
                decided_at: verdict.decided_at,
                issued_at: self.challenge.issued_at,
            });
        }
        match (self.proof_digest, verdict.proof_digest) {
            (Some(expected), Some(actual)) if expected != actual => {
                return Err(PorCoordinatorError::ProofDigestMismatch {
                    expected,
                    actual,
                    expected_hex: hex::encode(expected),
                    actual_hex: hex::encode(actual),
                });
            }
            (Some(_), None) => return Err(PorCoordinatorError::MissingVerdictProofDigest),
            (None, Some(_)) => return Err(PorCoordinatorError::UnexpectedVerdictProofDigest),
            (None, None)
                if matches!(
                    verdict.outcome,
                    AuditOutcomeV1::Success | AuditOutcomeV1::Repaired
                ) =>
            {
                return Err(PorCoordinatorError::MissingProofForSuccessfulVerdict);
            }
            _ => {}
        }
        if let Some(submitted_at) = self.proof_submitted_at
            && verdict.decided_at < submitted_at
        {
            return Err(PorCoordinatorError::VerdictBeforeProof {
                decided_at: verdict.decided_at,
                submitted_at,
            });
        }
        Ok(())
    }
    #[cfg(test)]
    fn to_status(&self) -> PorChallengeStatusV1 {
        let mut status = PorChallengeStatusV1 {
            version: POR_CHALLENGE_STATUS_VERSION_V1,
            challenge_id: self.challenge.challenge_id,
            manifest_digest: self.challenge.manifest_digest,
            provider_id: self.challenge.provider_id,
            epoch_id: self.challenge.epoch_id,
            drand_round: self.challenge.drand_round,
            status: if self.proof_digest.is_some() {
                PorChallengeOutcome::ProofSubmitted
            } else {
                PorChallengeOutcome::AwaitingProof
            },
            sample_count: self.challenge.sample_count,
            forced: self.challenge.forced,
            issued_at: self.challenge.issued_at,
            responded_at: self.responded_at,
            proof_digest: self.proof_digest,
            repair_task_id: self.repair_task_id,
            failure_reason: None,
            verifier_latency_ms: None,
        };
        if let Some(verdict) = &self.verdict {
            status.status = match verdict.outcome {
                AuditOutcomeV1::Success => PorChallengeOutcome::Verified,
                AuditOutcomeV1::Failed => PorChallengeOutcome::Failed,
                AuditOutcomeV1::Repaired => PorChallengeOutcome::Repaired,
            };
            if verdict.outcome != AuditOutcomeV1::Success {
                status.failure_reason.clone_from(&verdict.failure_reason);
            }
        }
        status
    }
    fn validate_persisted(&self) -> Result<(), String> {
        self.challenge
            .validate()
            .map_err(|error| error.to_string())?;
        if self.proof_digest.is_some() != self.proof_submitted_at.is_some() {
            return Err(
                "proof digest and submission timestamp must both be present or absent".to_owned(),
            );
        }
        if let Some(submitted_at) = self.proof_submitted_at
            && (submitted_at < self.challenge.issued_at
                || submitted_at > self.challenge.deadline_at)
        {
            return Err("proof submission timestamp is outside the challenge window".to_owned());
        }
        let expected_responded_at = match &self.verdict {
            None => {
                if self.repair_task_id.is_some() {
                    return Err("repair task cannot exist without a verdict".to_owned());
                }
                self.proof_submitted_at
            }
            Some(verdict) => {
                if verdict.decided_at < self.challenge.issued_at
                    || self
                        .proof_submitted_at
                        .is_some_and(|submitted_at| verdict.decided_at < submitted_at)
                {
                    return Err("verdict timestamp predates its challenge or proof".to_owned());
                }
                if verdict.proof_digest != self.proof_digest {
                    return Err(
                        "verdict proof digest does not match recorded proof state".to_owned()
                    );
                }
                match verdict.outcome {
                    AuditOutcomeV1::Success => {
                        if verdict.failure_reason.is_some()
                            || self.proof_digest.is_none()
                            || self.repair_task_id.is_some()
                        {
                            return Err(
                                "successful verdict has inconsistent proof, reason, or repair state"
                                    .to_owned(),
                            );
                        }
                    }
                    AuditOutcomeV1::Failed => {
                        if verdict
                            .failure_reason
                            .as_deref()
                            .is_none_or(|reason| reason.trim().is_empty())
                            || self.repair_task_id
                                != Some(sorafs_repair_task_id_v1(por_repair_source_identity_v1(
                                    self.challenge.challenge_id,
                                )))
                        {
                            return Err(
                                "failed verdict is missing its reason or native repair task"
                                    .to_owned(),
                            );
                        }
                    }
                    AuditOutcomeV1::Repaired => {
                        if verdict
                            .failure_reason
                            .as_deref()
                            .is_none_or(|reason| reason.trim().is_empty())
                            || self.proof_digest.is_none()
                            || self.repair_task_id.is_some()
                        {
                            return Err(
                                "repaired verdict is missing a proof or failure reason".to_owned()
                            );
                        }
                    }
                }
                if verdict.canonical_digest == [0; 32] {
                    return Err("verdict canonical digest cannot be zero".to_owned());
                }
                self.proof_submitted_at
            }
        };
        if self.responded_at != expected_responded_at {
            return Err("responded_at does not match the persisted lifecycle".to_owned());
        }
        Ok(())
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::ChallengeRecordSnapshot")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct ChallengeRecordSnapshot {
    challenge: PorChallengeV1,
    proof_digest: Option<[u8; 32]>,
    proof_submitted_at: Option<u64>,
    responded_at: Option<u64>,
    verdict: Option<RecordedVerdictSnapshot>,
    repair_task_id: Option<[u8; 32]>,
}
impl<'a> norito::core::DecodeFromSlice<'a> for ChallengeRecordSnapshot {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        norito::core::decode_field_canonical::<ChallengeRecordSnapshot>(bytes)
    }
}
impl From<&ChallengeRecord> for ChallengeRecordSnapshot {
    fn from(record: &ChallengeRecord) -> Self {
        Self {
            challenge: record.challenge.clone(),
            proof_digest: record.proof_digest,
            proof_submitted_at: record.proof_submitted_at,
            responded_at: record.responded_at,
            verdict: record.verdict.as_ref().map(RecordedVerdictSnapshot::from),
            repair_task_id: record.repair_task_id,
        }
    }
}
impl ChallengeRecordSnapshot {
    fn into_record(self) -> Result<ChallengeRecord, PorPersistenceError> {
        let verdict = match self.verdict {
            Some(snapshot) => Some(snapshot.into_recorded_verdict()?),
            None => None,
        };
        Ok(ChallengeRecord {
            challenge: self.challenge,
            proof_digest: self.proof_digest,
            proof_submitted_at: self.proof_submitted_at,
            responded_at: self.responded_at,
            verdict,
            repair_task_id: self.repair_task_id,
        })
    }
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::ForcedProviderSnapshot")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct ForcedProviderSnapshot {
    provider_id: [u8; 32],
    epochs: Vec<u64>,
}
impl ForcedProviderSnapshot {
    fn into_set(self) -> BTreeSet<u64> {
        self.epochs.into_iter().collect()
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ForcedProviderSnapshot {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        norito::core::decode_field_canonical::<ForcedProviderSnapshot>(bytes)
    }
}
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::PorCoordinatorSnapshot")]
struct PorCoordinatorSnapshot {
    version: u8,
    status_generation: u64,
    records: Vec<ChallengeRecordSnapshot>,
    forced: Vec<ForcedProviderSnapshot>,
    prepared_weekly_report: Option<PreparedWeeklyReportV1>,
}
impl<'a> norito::core::DecodeFromSlice<'a> for PorCoordinatorSnapshot {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::Error> {
        norito::core::decode_field_canonical::<PorCoordinatorSnapshot>(bytes)
    }
}
const SECURE_TEMP_RETRIES: usize = 8;
type RetainedSecureMetadata = crate::secure_file_metadata::SecureMetadata;

#[derive(Debug)]
struct SecureParent {
    absolute: PathBuf,
    path: PathBuf,
    metadata: RetainedSecureMetadata,
    #[cfg(windows)]
    pinned_directories: Vec<(PathBuf, RetainedSecureMetadata)>,
}

impl SecureParent {
    #[cfg(any(windows, feature = "app_api"))]
    fn revalidate(&self) -> Result<(), SecureFileError> {
        #[cfg(windows)]
        revalidate_windows_secure_directories(&self.pinned_directories)?;

        let current = crate::secure_file_metadata::from_path(&self.path)?;
        validate_secure_parent_metadata(&self.path, &current)?;
        if !crate::secure_file_metadata::same_file(&self.metadata, &current) {
            return Err(SecureFileError::UnsafePath(format!(
                "persistence parent {} changed identity while it was in use",
                self.path.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum SecureFileError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsafe persistence path: {0}")]
    UnsafePath(String),
    #[error("persistence payload exceeds {limit} bytes")]
    Oversize { limit: usize },
    #[error("existing immutable artefact conflicts with canonical bytes")]
    Conflict,
}
#[derive(Debug)]
enum SecureAtomicWriteError {
    BeforePublication(SecureFileError),
    CommitUncertain(SecureFileError),
}
impl From<SecureFileError> for SecureAtomicWriteError {
    fn from(error: SecureFileError) -> Self {
        Self::BeforePublication(error)
    }
}
impl SecureAtomicWriteError {
    fn into_inner(self) -> SecureFileError {
        match self {
            Self::BeforePublication(error) | Self::CommitUncertain(error) => error,
        }
    }
}
fn validate_secure_parent_metadata(
    path: &Path,
    metadata: &RetainedSecureMetadata,
) -> Result<(), SecureFileError> {
    if !crate::secure_file_metadata::is_direct_directory(metadata) {
        return Err(SecureFileError::UnsafePath(format!(
            "persistence directory {} is not a direct directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(SecureFileError::UnsafePath(format!(
                "persistence directory {} must be owned by this process user and private",
                path.display()
            )));
        }
    }
    Ok(())
}
fn absolute_secure_path(path: &Path) -> Result<PathBuf, SecureFileError> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(SecureFileError::UnsafePath(
            "parent-directory components are forbidden".to_owned(),
        ));
    }
    let candidate = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut absolute = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SecureFileError::UnsafePath(
                    "parent-directory components are forbidden".to_owned(),
                ));
            }
            _ => absolute.push(component.as_os_str()),
        }
    }
    if absolute.file_name().is_none() {
        return Err(SecureFileError::UnsafePath(
            "persistence path must name a file".to_owned(),
        ));
    }
    Ok(absolute)
}
#[cfg(unix)]
fn ensure_secure_parent(path: &Path) -> Result<SecureParent, SecureFileError> {
    let absolute = absolute_secure_path(path)?;
    let parent = absolute
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| SecureFileError::UnsafePath("persistence path has no parent".to_owned()))?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SecureFileError::UnsafePath(format!(
                        "ancestor {} is not a regular directory",
                        cursor.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let containing_directory = cursor.parent().map(Path::to_path_buf);
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                builder.create(&cursor)?;
                if let Some(containing_directory) = containing_directory
                    && !containing_directory.as_os_str().is_empty()
                {
                    crate::durable_fs::sync_direct_directory(&containing_directory)?;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = crate::secure_file_metadata::from_path(&parent)?;
    validate_secure_parent_metadata(&parent, &metadata)?;
    Ok(SecureParent {
        absolute,
        path: parent,
        metadata,
    })
}

#[cfg(not(any(unix, windows)))]
fn ensure_secure_parent(_path: &Path) -> Result<SecureParent, SecureFileError> {
    Err(SecureFileError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure persistence directories are unsupported on this platform",
    )))
}

#[cfg(windows)]
fn ensure_secure_parent(path: &Path) -> Result<SecureParent, SecureFileError> {
    let absolute = absolute_secure_path(path)?;
    let parent = absolute
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| SecureFileError::UnsafePath("persistence path has no parent".to_owned()))?;
    let mut cursor = PathBuf::new();
    let mut pinned_directories = Vec::new();
    for component in parent.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let containing_directory = cursor.parent().map(Path::to_path_buf);
        let (metadata, created) = match crate::secure_file_metadata::from_path(&cursor) {
            Ok(metadata) => (metadata, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&cursor) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                (crate::secure_file_metadata::from_path(&cursor)?, true)
            }
            Err(error) => return Err(error.into()),
        };
        validate_secure_parent_metadata(&cursor, &metadata)?;
        revalidate_windows_secure_directories(&pinned_directories)?;
        if created
            && let Some(containing_directory) = containing_directory
            && !containing_directory.as_os_str().is_empty()
        {
            crate::durable_fs::sync_direct_directory(&containing_directory)?;
            revalidate_windows_secure_directories(&pinned_directories)?;
        }
        pinned_directories.push((cursor.clone(), metadata));
    }
    let metadata = crate::secure_file_metadata::from_path(&parent)?;
    validate_secure_parent_metadata(&parent, &metadata)?;
    revalidate_windows_secure_directories(&pinned_directories)?;
    Ok(SecureParent {
        absolute,
        path: parent,
        metadata,
        pinned_directories,
    })
}

#[cfg(windows)]
fn revalidate_windows_secure_directories(
    directories: &[(PathBuf, RetainedSecureMetadata)],
) -> Result<(), SecureFileError> {
    for (path, before) in directories {
        let after = crate::secure_file_metadata::from_path(path)?;
        validate_secure_parent_metadata(path, &after)?;
        if !crate::secure_file_metadata::same_file(before, &after) {
            return Err(SecureFileError::UnsafePath(format!(
                "persistence directory {} changed identity while it was in use",
                path.display()
            )));
        }
    }
    Ok(())
}
fn validate_secure_file_metadata(
    path: &Path,
    metadata: &RetainedSecureMetadata,
) -> Result<(), SecureFileError> {
    if !crate::secure_file_metadata::is_direct_file(metadata)
        || crate::secure_file_metadata::number_of_links(metadata) != Some(1)
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} is not a direct, single-link regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    let effective_uid = rustix::process::geteuid().as_raw();
    #[cfg(unix)]
    if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
        return Err(SecureFileError::UnsafePath(format!(
            "{} must be owned by this process user, private, and singly linked",
            path.display()
        )));
    }
    Ok(())
}
fn secure_read_bytes(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, SecureFileError> {
    let parent = ensure_secure_parent(path)?;
    let filename = parent.absolute.file_name().ok_or_else(|| {
        SecureFileError::UnsafePath("persistence path must name a file".to_owned())
    })?;
    let parent_file = open_secure_parent_directory(&parent)?;
    revalidate_secure_parent_for_path_operations(&parent)?;
    let bytes = secure_read_bytes_in_parent(&parent_file, filename, &parent.absolute, max_bytes)?;
    revalidate_secure_parent_for_path_operations(&parent)?;
    Ok(bytes)
}
fn open_secure_parent_directory(parent: &SecureParent) -> Result<File, SecureFileError> {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options
            .access_mode(0)
            // Keep the parent usable by readers and writers, but deny rename/delete sharing
            // while path-based Windows operations depend on this identity.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    options.read(true);
    let directory = options.open(&parent.path)?;
    let opened = crate::secure_file_metadata::from_file(&directory)?;
    validate_secure_parent_metadata(&parent.path, &opened)?;
    if !crate::secure_file_metadata::same_file(&parent.metadata, &opened) {
        return Err(SecureFileError::UnsafePath(
            "persistence parent changed while pinning its directory handle".to_owned(),
        ));
    }
    revalidate_secure_parent_for_path_operations(parent)?;
    Ok(directory)
}

#[cfg_attr(
    not(windows),
    expect(
        clippy::unnecessary_wraps,
        reason = "Windows path operations require fallible parent revalidation; descriptor-relative platforms share the same interface"
    )
)]
fn revalidate_secure_parent_for_path_operations(
    parent: &SecureParent,
) -> Result<(), SecureFileError> {
    #[cfg(windows)]
    return parent.revalidate();
    #[cfg(not(windows))]
    {
        let _ = parent;
        Ok(())
    }
}

fn sync_secure_parent_directory(
    _parent: &SecureParent,
    _directory: &File,
) -> Result<(), SecureFileError> {
    #[cfg(unix)]
    {
        _directory.sync_all()?;
        let durable = crate::secure_file_metadata::from_file(_directory)?;
        validate_secure_parent_metadata(&_parent.path, &durable)?;
        if !crate::secure_file_metadata::same_file(&_parent.metadata, &durable) {
            return Err(SecureFileError::UnsafePath(format!(
                "persistence parent {} changed while its directory entry was synchronized",
                _parent.path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        _parent.revalidate()?;
        crate::durable_fs::sync_direct_directory(&_parent.path)?;
        _parent.revalidate()?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = _parent;
        return Err(SecureFileError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "durable directory synchronization is unsupported on this platform",
        )));
    }
    #[cfg(any(unix, windows))]
    Ok(())
}
#[cfg(all(unix, not(target_os = "espidf")))]
fn verify_secure_named_file(
    parent: &File,
    name: &std::ffi::OsStr,
    path: &Path,
    metadata: &RetainedSecureMetadata,
) -> Result<rustix::fs::Stat, SecureFileError> {
    let named = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    validate_secure_file_metadata(path, metadata)?;
    if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
        || crate::utils::stat_device_identity(&named) != metadata.dev()
        || named.st_ino != metadata.ino()
        || named.st_nlink as u64 != 1
        || u64::try_from(named.st_size).ok() != Some(metadata.len())
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed relative to its pinned parent",
            path.display()
        )));
    }
    Ok(named)
}
#[cfg(any(not(unix), target_os = "espidf"))]
fn verify_secure_named_file(
    _parent: &File,
    _name: &std::ffi::OsStr,
    path: &Path,
    metadata: &RetainedSecureMetadata,
) -> Result<(), SecureFileError> {
    let named = crate::secure_file_metadata::from_path(path)?;
    validate_secure_file_metadata(path, metadata)?;
    validate_secure_file_metadata(path, &named)?;
    if !crate::secure_file_metadata::same_file(metadata, &named)
        || !crate::secure_file_metadata::unchanged(metadata, &named)
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed while being inspected",
            path.display()
        )));
    }
    Ok(())
}
#[cfg(all(unix, not(target_os = "espidf")))]
fn secure_read_bytes_in_parent(
    parent: &File,
    name: &std::ffi::OsStr,
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SecureFileError> {
    let before = match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(std::io::Error::from(error).into()),
    };
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        || before.st_nlink as u64 != 1
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > max_bytes as u64)
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} is not one bounded regular file",
            path.display()
        )));
    }
    let mut file = File::from(
        rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let opened = crate::secure_file_metadata::from_file(&file)?;
    let opened_named = verify_secure_named_file(parent, name, path, &opened)?;
    if opened_named.st_dev != before.st_dev || opened_named.st_ino != before.st_ino {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed while being opened",
            path.display()
        )));
    }
    let capacity = usize::try_from(opened.len())
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(std::io::Error::other)?;
    std::io::Read::by_ref(&mut file)
        .take(
            u64::try_from(max_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(SecureFileError::Oversize { limit: max_bytes });
    }
    let after_metadata = crate::secure_file_metadata::from_file(&file)?;
    let after = verify_secure_named_file(parent, name, path, &after_metadata)?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
        || after_metadata.len() != bytes.len() as u64
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed while being read",
            path.display()
        )));
    }
    Ok(Some(bytes))
}
#[cfg(any(not(unix), target_os = "espidf"))]
fn secure_read_bytes_in_parent(
    _parent: &File,
    _name: &std::ffi::OsStr,
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SecureFileError> {
    let before = match crate::secure_file_metadata::from_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_secure_file_metadata(path, &before)?;
    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if before.len() > max_bytes_u64 {
        return Err(SecureFileError::Oversize { limit: max_bytes });
    }

    #[cfg(windows)]
    let mut file = crate::secure_file_metadata::open_direct_file(path)?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        options.open(path)?
    };
    let opened_before = crate::secure_file_metadata::from_file(&file)?;
    let named_after_open = crate::secure_file_metadata::from_path(path)?;
    validate_secure_file_metadata(path, &opened_before)?;
    validate_secure_file_metadata(path, &named_after_open)?;
    if !crate::secure_file_metadata::same_file(&before, &opened_before)
        || !crate::secure_file_metadata::unchanged(&before, &opened_before)
        || !crate::secure_file_metadata::same_file(&opened_before, &named_after_open)
        || !crate::secure_file_metadata::unchanged(&opened_before, &named_after_open)
        || opened_before.len() > max_bytes_u64
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed while being opened",
            path.display()
        )));
    }

    let capacity = usize::try_from(opened_before.len())
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(std::io::Error::other)?;
    std::io::Read::by_ref(&mut file)
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(SecureFileError::Oversize { limit: max_bytes });
    }
    let opened_after = crate::secure_file_metadata::from_file(&file)?;
    let named_after_read = crate::secure_file_metadata::from_path(path)?;
    validate_secure_file_metadata(path, &opened_after)?;
    validate_secure_file_metadata(path, &named_after_read)?;
    if !crate::secure_file_metadata::same_file(&opened_before, &opened_after)
        || !crate::secure_file_metadata::unchanged(&opened_before, &opened_after)
        || !crate::secure_file_metadata::same_file(&opened_after, &named_after_read)
        || !crate::secure_file_metadata::unchanged(&opened_after, &named_after_read)
        || !crate::secure_file_metadata::same_file(&before, &named_after_read)
        || !crate::secure_file_metadata::unchanged(&before, &named_after_read)
        || u64::try_from(bytes.len()).ok() != Some(opened_before.len())
    {
        return Err(SecureFileError::UnsafePath(format!(
            "{} changed while being read",
            path.display()
        )));
    }
    Ok(Some(bytes))
}
#[cfg(all(unix, not(target_os = "espidf")))]
fn create_secure_temporary_file(
    parent: &File,
    parent_path: &Path,
    filename: &str,
) -> Result<(File, std::ffi::OsString, PathBuf), SecureFileError> {
    for _ in 0..SECURE_TEMP_RETRIES {
        let nonce: [u8; 16] = rand::random();
        let name = std::ffi::OsString::from(format!(".{filename}.{}.tmp", hex::encode(nonce)));
        let file = match rustix::fs::openat(
            parent,
            &name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let path = parent_path.join(&name);
        let metadata = crate::secure_file_metadata::from_file(&file)?;
        if let Err(error) = verify_secure_named_file(parent, &name, &path, &metadata) {
            let _ = rustix::fs::unlinkat(parent, &name, rustix::fs::AtFlags::empty());
            return Err(error);
        }
        return Ok((file, name, path));
    }
    Err(SecureFileError::UnsafePath(
        "failed to allocate a unique temporary file".to_owned(),
    ))
}
#[cfg(any(not(unix), target_os = "espidf"))]
fn create_secure_temporary_file(
    _parent: &File,
    parent_path: &Path,
    filename: &str,
) -> Result<(File, std::ffi::OsString, PathBuf), SecureFileError> {
    for _ in 0..SECURE_TEMP_RETRIES {
        let nonce: [u8; 16] = rand::random();
        let name = std::ffi::OsString::from(format!(".{filename}.{}.tmp", hex::encode(nonce)));
        let path = parent_path.join(&name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;

            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            options
                // Deny competing writers for the complete staging lifetime. Delete sharing is
                // required so the open temporary file can be atomically renamed into place.
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        match options.open(&path) {
            Ok(file) => {
                let metadata = crate::secure_file_metadata::from_file(&file)?;
                if let Err(error) = verify_secure_named_file(_parent, &name, &path, &metadata) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                return Ok((file, name, path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(SecureFileError::UnsafePath(
        "failed to allocate a unique temporary file".to_owned(),
    ))
}
#[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
fn link_secure_file_noreplace(
    parent: &File,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    rustix::fs::linkat(
        parent,
        source_name,
        parent,
        destination_name,
        rustix::fs::AtFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    if let Err(unlink_error) =
        rustix::fs::unlinkat(parent, source_name, rustix::fs::AtFlags::empty())
    {
        let rollback = rustix::fs::unlinkat(parent, destination_name, rustix::fs::AtFlags::empty());
        return match rollback {
            Ok(()) => Err(std::io::Error::from(unlink_error)),
            Err(rollback_error) => Err(std::io::Error::other(format!(
                "failed to unlink temporary publication ({unlink_error}) and to roll back its destination ({rollback_error})"
            ))),
        };
    }
    Ok(())
}
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn publish_secure_file_noreplace(
    parent: &File,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let result = rustix::fs::renameat_with(
        parent,
        source_name,
        parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    );
    match result {
        Ok(()) => Ok(()),
        Err(error) if rename_noreplace_is_unavailable(error) => {
            link_secure_file_noreplace(parent, source_name, destination_name)
        }
        Err(error) => Err(std::io::Error::from(error)),
    }
}
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn rename_noreplace_is_unavailable(error: rustix::io::Errno) -> bool {
    let code = error.raw_os_error();
    code == libc::ENOSYS || code == libc::EINVAL || code == libc::EOPNOTSUPP
}
#[cfg(target_os = "redox")]
fn publish_secure_file_noreplace(
    parent: &File,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        parent,
        source_name,
        parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}
#[cfg(all(
    unix,
    not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "espidf",
        target_os = "redox"
    ))
))]
fn publish_secure_file_noreplace(
    parent: &File,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    link_secure_file_noreplace(parent, source_name, destination_name)
}
#[cfg(any(not(unix), target_os = "espidf"))]
fn publish_secure_file_noreplace(
    _parent: &File,
    _source_name: &std::ffi::OsStr,
    _destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic descriptor-relative no-replace publication is unsupported on this platform",
    ))
}
#[cfg(unix)]
fn publish_secure_file_replace(
    parent: &File,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
    _source_path: &Path,
    _destination_path: &Path,
) -> std::io::Result<()> {
    rustix::fs::renameat(parent, source_name, parent, destination_name)
        .map_err(std::io::Error::from)
}
#[cfg(not(unix))]
fn publish_secure_file_replace(
    _parent: &File,
    _source_name: &std::ffi::OsStr,
    _destination_name: &std::ffi::OsStr,
    source_path: &Path,
    destination_path: &Path,
) -> std::io::Result<()> {
    fs::rename(source_path, destination_path)
}
#[cfg(all(unix, not(target_os = "espidf")))]
fn unlink_secure_temporary_file(
    parent: &File,
    source_name: &std::ffi::OsStr,
    _source_path: &Path,
) -> std::io::Result<()> {
    rustix::fs::unlinkat(parent, source_name, rustix::fs::AtFlags::empty())
        .map_err(std::io::Error::from)
}
#[cfg(any(not(unix), target_os = "espidf"))]
fn unlink_secure_temporary_file(
    _parent: &File,
    _source_name: &std::ffi::OsStr,
    source_path: &Path,
) -> std::io::Result<()> {
    fs::remove_file(source_path)
}
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
const HAS_RENAME_NOREPLACE: bool = true;
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
const HAS_RENAME_NOREPLACE: bool = false;
#[cfg(all(unix, not(any(target_os = "espidf", target_os = "redox"))))]
const HAS_LINK_NOREPLACE: bool = true;
#[cfg(not(all(unix, not(any(target_os = "espidf", target_os = "redox")))))]
const HAS_LINK_NOREPLACE: bool = false;
fn secure_noreplace_publication_is_supported() -> bool {
    HAS_RENAME_NOREPLACE || HAS_LINK_NOREPLACE
}
fn secure_atomic_write_with_outcome(
    path: &Path,
    bytes: &[u8],
    max_bytes: usize,
    replace_existing: bool,
) -> Result<(), SecureAtomicWriteError> {
    if bytes.len() > max_bytes {
        return Err(SecureAtomicWriteError::BeforePublication(
            SecureFileError::Oversize { limit: max_bytes },
        ));
    }
    let parent = ensure_secure_parent(path)?;
    let filename = parent
        .absolute
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            SecureFileError::UnsafePath("persistence filename is not UTF-8".to_owned())
        })?;
    let filename_os = std::ffi::OsStr::new(filename);
    let parent_file = open_secure_parent_directory(&parent)?;
    revalidate_secure_parent_for_path_operations(&parent)?;
    let existing =
        secure_read_bytes_in_parent(&parent_file, filename_os, &parent.absolute, max_bytes)?;
    revalidate_secure_parent_for_path_operations(&parent)?;
    if let Some(existing) = existing {
        if existing == bytes {
            sync_secure_parent_directory(&parent, &parent_file)
                .map_err(SecureAtomicWriteError::CommitUncertain)?;
            return Ok(());
        }
        if !replace_existing {
            return Err(SecureAtomicWriteError::BeforePublication(
                SecureFileError::Conflict,
            ));
        }
    }
    if !replace_existing && !secure_noreplace_publication_is_supported() {
        return Err(SecureAtomicWriteError::BeforePublication(
            SecureFileError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "atomic descriptor-relative no-replace publication is unsupported on this platform",
            )),
        ));
    }
    revalidate_secure_parent_for_path_operations(&parent)?;
    let (mut file, temp_name, temp_path) =
        create_secure_temporary_file(&parent_file, &parent.path, filename)?;
    let mut publication_reached = false;
    let result: Result<(), SecureFileError> = (|| {
        revalidate_secure_parent_for_path_operations(&parent)?;
        let temporary_empty = crate::secure_file_metadata::from_file(&file)?;
        verify_secure_named_file(&parent_file, &temp_name, &temp_path, &temporary_empty)?;
        if temporary_empty.len() != 0 {
            return Err(SecureFileError::UnsafePath(format!(
                "{} was not empty when it was created",
                temp_path.display()
            )));
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        let temporary_ready = crate::secure_file_metadata::from_file(&file)?;
        verify_secure_named_file(&parent_file, &temp_name, &temp_path, &temporary_ready)?;
        if !crate::secure_file_metadata::same_file(&temporary_empty, &temporary_ready)
            || u64::try_from(bytes.len()).ok() != Some(temporary_ready.len())
        {
            return Err(SecureFileError::UnsafePath(format!(
                "{} changed identity or length while it was written",
                temp_path.display()
            )));
        }
        revalidate_secure_parent_for_path_operations(&parent)?;
        if replace_existing {
            publish_secure_file_replace(
                &parent_file,
                &temp_name,
                filename_os,
                &temp_path,
                &parent.absolute,
            )?;
            publication_reached = true;
        } else {
            match publish_secure_file_noreplace(&parent_file, &temp_name, filename_os) {
                Ok(()) => {
                    publication_reached = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    unlink_secure_temporary_file(&parent_file, &temp_name, &temp_path)?;
                    return match secure_read_bytes_in_parent(
                        &parent_file,
                        filename_os,
                        &parent.absolute,
                        max_bytes,
                    )? {
                        Some(existing) if existing == bytes => {
                            publication_reached = true;
                            sync_secure_parent_directory(&parent, &parent_file)?;
                            Ok(())
                        }
                        Some(_) => Err(SecureFileError::Conflict),
                        None => Err(SecureFileError::Io(error)),
                    };
                }
                Err(error) => return Err(error.into()),
            }
        }
        revalidate_secure_parent_for_path_operations(&parent)?;
        let published = crate::secure_file_metadata::from_file(&file)?;
        verify_secure_named_file(&parent_file, filename_os, &parent.absolute, &published)?;
        if !crate::secure_file_metadata::same_file(&temporary_ready, &published)
            || u64::try_from(bytes.len()).ok() != Some(published.len())
        {
            return Err(SecureFileError::UnsafePath(format!(
                "{} changed identity or length during publication",
                parent.absolute.display()
            )));
        }
        sync_secure_parent_directory(&parent, &parent_file)?;
        let durable = crate::secure_file_metadata::from_file(&file)?;
        verify_secure_named_file(&parent_file, filename_os, &parent.absolute, &durable)?;
        if !crate::secure_file_metadata::unchanged(&published, &durable) {
            return Err(SecureFileError::UnsafePath(format!(
                "{} changed while its directory entry was synchronized",
                parent.absolute.display()
            )));
        }
        revalidate_secure_parent_for_path_operations(&parent)?;
        Ok(())
    })();
    if result.is_err() && !publication_reached {
        if revalidate_secure_parent_for_path_operations(&parent).is_ok() {
            let _ = unlink_secure_temporary_file(&parent_file, &temp_name, &temp_path);
        }
    }
    result.map_err(|error| {
        if publication_reached {
            SecureAtomicWriteError::CommitUncertain(error)
        } else {
            SecureAtomicWriteError::BeforePublication(error)
        }
    })
}
fn secure_atomic_write(
    path: &Path,
    bytes: &[u8],
    max_bytes: usize,
    replace_existing: bool,
) -> Result<(), SecureFileError> {
    secure_atomic_write_with_outcome(path, bytes, max_bytes, replace_existing)
        .map_err(SecureAtomicWriteError::into_inner)
}
/// Errors that may occur when reading or writing PoR persistence snapshots.
#[derive(Debug, Error)]
pub enum PorPersistenceError {
    /// Underlying filesystem I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to serialize the snapshot payload.
    #[error("encode error: {0}")]
    Encode(#[source] norito::core::Error),
    /// Failed to deserialize persisted state.
    #[error("decode error: {0}")]
    Decode(String),
    /// Persistence path, size, ownership, or atomicity policy failed.
    #[error("secure persistence error: {0}")]
    Secure(String),
    /// The new snapshot reached its destination, but post-publication durability checks failed.
    #[error(
        "persistence commit may already be durable; restart and reconcile before continuing: {0}"
    )]
    CommitUncertain(String),
    /// Snapshot version on disk does not match the supported one.
    #[error("unsupported snapshot version {found}")]
    UnsupportedVersion {
        /// Version byte found in the snapshot file.
        found: u8,
    },
    /// Encountered an unexpected flag while parsing snapshot contents.
    #[error("invalid flag value {value}")]
    InvalidFlag {
        /// Flag value carrying invalid data.
        value: u8,
    },
}
#[derive(Debug)]
struct PorPersistence {
    path: PathBuf,
    #[cfg(test)]
    fail_after_publication_once: std::sync::atomic::AtomicBool,
}
struct LoadedPorCoordinatorState {
    records: Arc<DashMap<[u8; 32], ChallengeRecord>>,
    forced: Arc<RwLock<HashMap<[u8; 32], BTreeSet<u64>>>>,
    prepared_weekly_report: Arc<RwLock<Option<PreparedWeeklyReportV1>>>,
    status_generation: u64,
}
impl PorPersistence {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            #[cfg(test)]
            fail_after_publication_once: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Load persisted coordinator state from disk if present.
    ///
    /// # Errors
    ///
    /// Returns [`PorPersistenceError`] when the snapshot cannot be read or decoded.
    fn load(&self) -> Result<LoadedPorCoordinatorState, PorPersistenceError> {
        let records = Arc::new(DashMap::new());
        let forced = Arc::new(RwLock::new(HashMap::new()));
        let prepared_weekly_report = Arc::new(RwLock::new(None));
        let Some(bytes) = secure_read_bytes(&self.path, MAX_POR_COORDINATOR_SNAPSHOT_BYTES)
            .map_err(|error| PorPersistenceError::Secure(error.to_string()))?
        else {
            return Ok(LoadedPorCoordinatorState {
                records,
                forced,
                prepared_weekly_report,
                status_generation: 1,
            });
        };
        let snapshot = decode_from_bytes_with_limits::<PorCoordinatorSnapshot>(
            &bytes,
            por_coordinator_decode_limits(),
        )
        .map_err(|err| PorPersistenceError::Decode(err.to_string()))?;
        let canonical = to_bytes(&snapshot).map_err(PorPersistenceError::Encode)?;
        if canonical != bytes {
            return Err(PorPersistenceError::Decode(
                "snapshot is not canonically encoded".to_owned(),
            ));
        }
        if snapshot.version != POR_COORDINATOR_SNAPSHOT_VERSION_V1 {
            return Err(PorPersistenceError::UnsupportedVersion {
                found: snapshot.version,
            });
        }
        if snapshot.status_generation == 0 {
            return Err(PorPersistenceError::Decode(
                "snapshot status generation must be non-zero".to_owned(),
            ));
        }
        let status_generation = snapshot.status_generation;
        if snapshot.records.len() > MAX_POR_COORDINATOR_RECORDS
            || snapshot.forced.len() > MAX_POR_COORDINATOR_FORCED_PROVIDERS
        {
            return Err(PorPersistenceError::Decode(
                "snapshot entry count exceeds production bounds".to_owned(),
            ));
        }
        let minimum_status_generation = u64::try_from(snapshot.records.len())
            .expect("PoR snapshot record bound fits u64")
            .checked_add(1)
            .expect("PoR snapshot record bound leaves generation headroom");
        if status_generation < minimum_status_generation {
            return Err(PorPersistenceError::Decode(format!(
                "snapshot status generation {status_generation} is below the record floor {minimum_status_generation}"
            )));
        }
        let mut expected_forced = HashMap::<[u8; 32], BTreeSet<u64>>::new();
        let mut previous_challenge_id = None;
        for record in snapshot.records {
            let record = record.into_record()?;
            record
                .validate_persisted()
                .map_err(PorPersistenceError::Decode)?;
            if previous_challenge_id
                .is_some_and(|previous| previous >= record.challenge.challenge_id)
            {
                return Err(PorPersistenceError::Decode(
                    "snapshot challenge records are not strictly ordered".to_owned(),
                ));
            }
            previous_challenge_id = Some(record.challenge.challenge_id);
            if record.challenge.forced {
                expected_forced
                    .entry(record.challenge.provider_id)
                    .or_default()
                    .insert(record.challenge.epoch_id);
            }
            if records
                .insert(record.challenge.challenge_id, record)
                .is_some()
            {
                return Err(PorPersistenceError::Decode(
                    "snapshot contains a duplicate challenge id".to_owned(),
                ));
            }
        }
        let mut forced_guard = forced.write();
        let mut previous_provider_id = None;
        for provider in snapshot.forced {
            if provider.provider_id.iter().all(|byte| *byte == 0)
                || provider.epochs.len() > 65_536
                || previous_provider_id.is_some_and(|previous| previous >= provider.provider_id)
            {
                return Err(PorPersistenceError::Decode(
                    "snapshot contains invalid or unordered forced-provider state".to_owned(),
                ));
            }
            previous_provider_id = Some(provider.provider_id);
            if provider.epochs.is_empty()
                || provider.epochs.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(PorPersistenceError::Decode(
                    "forced-provider epochs must be non-empty and strictly ordered".to_owned(),
                ));
            }
            forced_guard.insert(provider.provider_id, provider.into_set());
        }
        if *forced_guard != expected_forced {
            return Err(PorPersistenceError::Decode(
                "forced-provider index does not match forced challenge records".to_owned(),
            ));
        }
        drop(forced_guard);
        if let Some(prepared) = snapshot.prepared_weekly_report {
            prepared.report.validate().map_err(|error| {
                PorPersistenceError::Decode(format!("prepared weekly report is invalid: {error}"))
            })?;
            let expected_generated_at = canonical_weekly_report_generated_at(prepared.report.cycle)
                .map_err(|error| {
                    PorPersistenceError::Decode(format!(
                        "prepared weekly report cycle is invalid: {error}"
                    ))
                })?;
            if prepared.report.generated_at != expected_generated_at {
                return Err(PorPersistenceError::Decode(
                    "prepared weekly report does not use its canonical cycle boundary".to_owned(),
                ));
            }
            *prepared_weekly_report.write() = Some(prepared);
        }
        Ok(LoadedPorCoordinatorState {
            records,
            forced,
            prepared_weekly_report,
            status_generation,
        })
    }
    /// Store the supplied coordinator snapshot to disk.
    ///
    /// # Errors
    ///
    /// Returns [`PorPersistenceError`] when the snapshot cannot be encoded or written.
    fn store(
        &self,
        status_generation: u64,
        records: &[ChallengeRecord],
        forced: &[([u8; 32], Vec<u64>)],
        prepared_weekly_report: Option<&PreparedWeeklyReportV1>,
    ) -> Result<(), PorPersistenceError> {
        let snapshot = PorCoordinatorSnapshot {
            version: POR_COORDINATOR_SNAPSHOT_VERSION_V1,
            status_generation,
            records: records.iter().map(ChallengeRecordSnapshot::from).collect(),
            forced: forced
                .iter()
                .map(|(provider_id, epochs)| ForcedProviderSnapshot {
                    provider_id: *provider_id,
                    epochs: epochs.clone(),
                })
                .collect(),
            prepared_weekly_report: prepared_weekly_report.cloned(),
        };
        let bytes = to_bytes(&snapshot).map_err(PorPersistenceError::Encode)?;
        match secure_atomic_write_with_outcome(
            &self.path,
            &bytes,
            MAX_POR_COORDINATOR_SNAPSHOT_BYTES,
            true,
        ) {
            Ok(()) => {
                #[cfg(test)]
                if self
                    .fail_after_publication_once
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(PorPersistenceError::CommitUncertain(
                        "injected failure after snapshot publication".to_owned(),
                    ));
                }
                Ok(())
            }
            Err(SecureAtomicWriteError::BeforePublication(error)) => {
                Err(PorPersistenceError::Secure(error.to_string()))
            }
            Err(SecureAtomicWriteError::CommitUncertain(error)) => {
                Err(PorPersistenceError::CommitUncertain(error.to_string()))
            }
        }
    }
}
#[cfg(feature = "app_api")]
/// Errors produced by the verified drand randomness provider.
#[derive(Debug, Error)]
pub enum RandomnessError {
    /// Pinned trust, transport, or persistence configuration is unsafe.
    #[error("invalid drand configuration: {0}")]
    Configuration(String),
    /// A network endpoint failed before producing a verified beacon.
    #[error("drand endpoint failure: {0}")]
    Endpoint(String),
    /// Fewer agreeing endpoints than the configured strict majority responded.
    #[error("drand quorum unavailable: {agreeing} agreeing responses; {required} required")]
    QuorumUnavailable {
        /// Largest agreeing response group.
        agreeing: usize,
        /// Required agreement threshold.
        required: usize,
    },
    /// Verified beacon timing does not satisfy pinned freshness constraints.
    #[error("drand beacon timing invalid: {0}")]
    Timing(String),
    /// A verified round regressed below durable high-water state.
    #[error("drand round rollback: received {received}, durable high-water is {high_water}")]
    Rollback {
        /// Received round.
        received: u64,
        /// Durable high-water round.
        high_water: u64,
    },
    /// The same round produced different verified bytes.
    #[error("drand equivocation detected at round {round}")]
    Equivocation {
        /// Conflicting round.
        round: u64,
    },
    /// Durable high-water state failed closed.
    #[error("drand state persistence failure: {0}")]
    Persistence(String),
}
#[cfg(feature = "app_api")]
/// Trait supplying randomness used to schedule PoR challenges.
#[async_trait]
pub trait RandomnessProvider: Send + Sync {
    /// Produce randomness for the specified epoch, returning the commitment used to plan challenges.
    ///
    /// # Errors
    ///
    /// Returns [`RandomnessError`] when transport, verification, quorum,
    /// freshness, replay, or durable-state checks fail.
    async fn randomness_for_epoch(
        &self,
        epoch_id: u64,
        now_secs: u64,
        response_window_secs: u64,
    ) -> Result<PorRandomness, RandomnessError>;
}
#[cfg(feature = "app_api")]
const DRAND_STATE_VERSION_V1: u8 = 1;
#[cfg(feature = "app_api")]
const MAX_DRAND_DNS_ADDRESSES: usize = 16;
#[cfg(feature = "app_api")]
const MIN_DRAND_RESPONSE_BYTES: usize = 128;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::sorafs::por::DrandHighWaterStateV1")]
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, NoritoSerialize, NoritoDeserialize)]
struct DrandHighWaterStateV1 {
    version: u8,
    round: u64,
    randomness: [u8; 32],
    signature: [u8; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
}
#[cfg(feature = "app_api")]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VerifiedDrandBeacon {
    round: u64,
    randomness: [u8; 32],
    signature: [u8; iroha_crypto::drand::DRAND_SIGNATURE_BYTES],
}
#[cfg(feature = "app_api")]
#[derive(Debug)]
struct DrandEndpoint {
    root: url::Url,
    host: String,
    port: u16,
    pinned_addrs: Vec<SocketAddr>,
    client: reqwest::Client,
}
#[cfg(feature = "app_api")]
#[derive(Debug)]
struct SecureStateOwnerLock {
    path: PathBuf,
    file: File,
    identity: RetainedSecureMetadata,
    parent: SecureParent,
    parent_directory: File,
}
#[cfg(feature = "app_api")]
impl SecureStateOwnerLock {
    fn acquire(state_path: &Path, label: &str) -> Result<Self, RandomnessError> {
        let parent = ensure_secure_parent(state_path)
            .map_err(|error| RandomnessError::Persistence(format!("{label} state: {error}")))?;
        let filename = parent
            .absolute
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                RandomnessError::Persistence(format!(
                    "{label} state ownership path is not canonical UTF-8"
                ))
            })?;
        let path = parent.path.join(format!(".{filename}.owner.lock"));
        let parent_directory = open_secure_parent_directory(&parent).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        parent.revalidate().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        let before_open = match crate::secure_file_metadata::from_path(&path) {
            Ok(metadata) => {
                validate_secure_file_metadata(&path, &metadata).map_err(|error| {
                    RandomnessError::Persistence(format!("{label} state lock: {error}"))
                })?;
                if metadata.len() != 0 {
                    return Err(RandomnessError::Persistence(format!(
                        "{label} state ownership lock is not empty"
                    )));
                }
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(RandomnessError::Persistence(format!(
                    "{label} state lock: {error}"
                )));
            }
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;

            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            options
                // Lock contenders need read/write sharing, but delete sharing would allow a
                // second pathname to replace the file while this owner still holds its lock.
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(&path).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        let opened = crate::secure_file_metadata::from_file(&file).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&path, &opened).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        if opened.len() != 0 {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock is not empty"
            )));
        }
        if before_open.as_ref().is_some_and(|before| {
            !crate::secure_file_metadata::same_file(before, &opened)
                || !crate::secure_file_metadata::unchanged(before, &opened)
        }) {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock changed while opening"
            )));
        }
        let linked = crate::secure_file_metadata::from_path(&path).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&path, &linked).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        if !crate::secure_file_metadata::same_file(&opened, &linked)
            || !crate::secure_file_metadata::unchanged(&opened, &linked)
        {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock path changed while opening"
            )));
        }
        parent.revalidate().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(RandomnessError::Persistence(format!(
                    "{label} state ownership lock is already held"
                )));
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(RandomnessError::Persistence(format!(
                    "{label} state lock: {error}"
                )));
            }
        }
        file.sync_all().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        sync_secure_parent_directory(&parent, &parent_directory).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        let identity = crate::secure_file_metadata::from_file(&file).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        let locked_link = crate::secure_file_metadata::from_path(&path).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&path, &identity).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&path, &locked_link).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        if !crate::secure_file_metadata::same_file(&opened, &identity)
            || !crate::secure_file_metadata::unchanged(&opened, &identity)
            || !crate::secure_file_metadata::same_file(&identity, &locked_link)
            || !crate::secure_file_metadata::unchanged(&identity, &locked_link)
        {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock changed while acquiring ownership"
            )));
        }
        parent.revalidate().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        let owner = Self {
            path,
            file,
            identity,
            parent,
            parent_directory,
        };
        owner.verify(label)?;
        Ok(owner)
    }
    fn verify(&self, label: &str) -> Result<(), RandomnessError> {
        self.parent.revalidate().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        let opened_parent = crate::secure_file_metadata::from_file(&self.parent_directory)
            .map_err(|error| {
                RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
            })?;
        validate_secure_parent_metadata(&self.parent.path, &opened_parent).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        if !crate::secure_file_metadata::same_file(&self.parent.metadata, &opened_parent) {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock parent changed identity"
            )));
        }
        let opened = crate::secure_file_metadata::from_file(&self.file).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        let linked = crate::secure_file_metadata::from_path(&self.path).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&self.path, &opened).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        validate_secure_file_metadata(&self.path, &linked).map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock: {error}"))
        })?;
        if opened.len() != 0 || linked.len() != 0 {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock is not empty"
            )));
        }
        if !crate::secure_file_metadata::same_file(&self.identity, &opened)
            || !crate::secure_file_metadata::unchanged(&self.identity, &opened)
            || !crate::secure_file_metadata::same_file(&opened, &linked)
            || !crate::secure_file_metadata::unchanged(&opened, &linked)
        {
            return Err(RandomnessError::Persistence(format!(
                "{label} state ownership lock identity, revision, or link count changed"
            )));
        }
        self.parent.revalidate().map_err(|error| {
            RandomnessError::Persistence(format!("{label} state lock parent: {error}"))
        })?;
        Ok(())
    }
}
#[cfg(feature = "app_api")]
/// HTTPS drand provider with pinned chain metadata, DNS, quorum, and durable replay state.
#[derive(Debug)]
pub struct DrandHttpRandomnessProvider {
    public_key: [u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES],
    genesis_time: u64,
    period_secs: u64,
    epoch_interval_secs: u64,
    quorum: usize,
    max_body_bytes: usize,
    max_beacon_age_secs: u64,
    max_future_skew_secs: u64,
    endpoints: Vec<DrandEndpoint>,
    state_path: PathBuf,
    state_owner_lock: SecureStateOwnerLock,
    state: Mutex<Option<DrandHighWaterStateV1>>,
    commit_lock: tokio::sync::Mutex<()>,
}
#[cfg(feature = "app_api")]
impl DrandHttpRandomnessProvider {
    /// Construct a provider after validating trust roots, endpoints, DNS, and persisted state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid trust roots, timing or quorum bounds, unsafe
    /// or duplicate endpoints, DNS or HTTP-client setup failures, or failure to
    /// lock, load, or verify the persisted randomness state.
    pub fn from_config(
        config: &iroha_config::parameters::actual::SorafsPorDrand,
        epoch_interval_secs: u64,
    ) -> Result<Self, RandomnessError> {
        use iroha_crypto::drand::{
            UNCHAINED_G1_RFC9380_SCHEME, is_valid_unchained_g1_rfc9380_public_key,
        };
        if config.scheme != UNCHAINED_G1_RFC9380_SCHEME {
            return Err(RandomnessError::Configuration(format!(
                "scheme must be `{UNCHAINED_G1_RFC9380_SCHEME}`"
            )));
        }
        if config.chain_hash.iter().all(|byte| *byte == 0) {
            return Err(RandomnessError::Configuration(
                "chain hash must be pinned".to_owned(),
            ));
        }
        if !is_valid_unchained_g1_rfc9380_public_key(&config.public_key) {
            return Err(RandomnessError::Configuration(
                "public key is not a canonical non-identity G2 point".to_owned(),
            ));
        }
        if config.genesis_time == 0 || config.period_secs == 0 || epoch_interval_secs == 0 {
            return Err(RandomnessError::Configuration(
                "genesis_time and period_secs must be non-zero".to_owned(),
            ));
        }
        if config.max_endpoints < 3
            || config.endpoints.len() < 3
            || config.endpoints.len() > config.max_endpoints
            || config.max_endpoints
                > iroha_config::parameters::defaults::sorafs::por::DRAND_MAX_ENDPOINTS
        {
            return Err(RandomnessError::Configuration(format!(
                "between 3 and {} drand endpoints are required",
                iroha_config::parameters::defaults::sorafs::por::DRAND_MAX_ENDPOINTS
            )));
        }
        let quorum = usize::from(config.quorum);
        if quorum <= config.endpoints.len() / 2 || quorum >= config.endpoints.len() {
            return Err(RandomnessError::Configuration(
                "drand quorum must be a strict majority and tolerate one endpoint outage"
                    .to_owned(),
            ));
        }
        if config.connect_timeout.is_zero() || config.request_timeout.is_zero() {
            return Err(RandomnessError::Configuration(
                "drand timeouts must be non-zero".to_owned(),
            ));
        }
        if config.max_body_bytes < MIN_DRAND_RESPONSE_BYTES || config.max_body_bytes > 64 * 1024 {
            return Err(RandomnessError::Configuration(format!(
                "max_body_bytes must be between {MIN_DRAND_RESPONSE_BYTES} and 65536"
            )));
        }
        if config.max_beacon_age_secs < config.period_secs
            || config.max_future_skew_secs > config.max_beacon_age_secs
        {
            return Err(RandomnessError::Configuration(
                "drand freshness/skew bounds are inconsistent".to_owned(),
            ));
        }
        let chain_hex = hex::encode(config.chain_hash);
        let expected_path = format!("/v2/chains/{chain_hex}");
        let mut seen_hosts = BTreeSet::new();
        let mut endpoints = Vec::with_capacity(config.endpoints.len());
        for raw_root in &config.endpoints {
            let root = url::Url::parse(raw_root).map_err(|error| {
                RandomnessError::Configuration(format!("invalid drand endpoint: {error}"))
            })?;
            let host = validate_drand_endpoint(raw_root, &root, &expected_path)?;
            if !seen_hosts.insert(host.clone()) {
                return Err(RandomnessError::Configuration(format!(
                    "duplicate drand endpoint host `{host}`"
                )));
            }
            let port = root.port_or_known_default().ok_or_else(|| {
                RandomnessError::Configuration("drand endpoint has no HTTPS port".to_owned())
            })?;
            let pinned_addrs = resolve_public_endpoint(&host, port)?;
            let client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(config.connect_timeout)
                .timeout(config.request_timeout)
                .resolve_to_addrs(&host, &pinned_addrs)
                .build()
                .map_err(|error| RandomnessError::Configuration(error.to_string()))?;
            endpoints.push(DrandEndpoint {
                root,
                host,
                port,
                pinned_addrs,
                client,
            });
        }
        let state_owner_lock = SecureStateOwnerLock::acquire(&config.state_path, "drand")?;
        let loaded = load_drand_state(&config.state_path, &config.public_key)?;
        state_owner_lock.verify("drand")?;
        Ok(Self {
            public_key: config.public_key,
            genesis_time: config.genesis_time,
            period_secs: config.period_secs,
            epoch_interval_secs,
            quorum,
            max_body_bytes: config.max_body_bytes,
            max_beacon_age_secs: config.max_beacon_age_secs,
            max_future_skew_secs: config.max_future_skew_secs,
            endpoints,
            state_path: config.state_path.clone(),
            state_owner_lock,
            state: Mutex::new(loaded),
            commit_lock: tokio::sync::Mutex::new(()),
        })
    }
    fn expected_round(&self, epoch_id: u64, now_secs: u64) -> Result<u64, RandomnessError> {
        let target = epoch_id
            .checked_mul(self.epoch_interval_secs)
            .ok_or_else(|| RandomnessError::Timing("epoch target overflow".to_owned()))?;
        if target > now_secs.saturating_add(self.max_future_skew_secs) {
            return Err(RandomnessError::Timing(
                "PoR epoch target is in the future".to_owned(),
            ));
        }
        if target < self.genesis_time {
            return Err(RandomnessError::Timing(
                "PoR epoch target predates pinned drand genesis".to_owned(),
            ));
        }
        let round = target
            .saturating_sub(self.genesis_time)
            .checked_div(self.period_secs)
            .and_then(|offset| offset.checked_add(1))
            .ok_or_else(|| RandomnessError::Timing("round arithmetic overflow".to_owned()))?;
        let timestamp = self
            .genesis_time
            .checked_add(
                round
                    .saturating_sub(1)
                    .checked_mul(self.period_secs)
                    .ok_or_else(|| {
                        RandomnessError::Timing("round timestamp overflow".to_owned())
                    })?,
            )
            .ok_or_else(|| RandomnessError::Timing("round timestamp overflow".to_owned()))?;
        if timestamp > target {
            return Err(RandomnessError::Timing(
                "computed round is in the future".to_owned(),
            ));
        }
        if target.saturating_sub(timestamp) > self.max_beacon_age_secs {
            return Err(RandomnessError::Timing(format!(
                "round {round} exceeds configured freshness"
            )));
        }
        Ok(round)
    }
    async fn fetch_endpoint(
        &self,
        endpoint: &DrandEndpoint,
        round: u64,
    ) -> Result<VerifiedDrandBeacon, RandomnessError> {
        revalidate_pinned_dns(endpoint).await?;
        let url = format!("{}/rounds/{round}", endpoint.root.as_str());
        let mut response = endpoint
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| RandomnessError::Endpoint(error.to_string()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(RandomnessError::Endpoint(format!(
                "{} returned status {}",
                endpoint.host,
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_body_bytes as u64)
        {
            return Err(RandomnessError::Endpoint(format!(
                "{} response exceeds byte limit",
                endpoint.host
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| RandomnessError::Endpoint(error.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                return Err(RandomnessError::Endpoint(format!(
                    "{} response exceeds byte limit",
                    endpoint.host
                )));
            }
            body.extend_from_slice(&chunk);
        }
        parse_and_verify_drand_response(&body, round, &self.public_key)
    }
    async fn commit_high_water(&self, beacon: &VerifiedDrandBeacon) -> Result<(), RandomnessError> {
        let _commit = self.commit_lock.lock().await;
        self.state_owner_lock.verify("drand")?;
        let next = {
            let state = self.state.lock();
            if let Some(previous) = state.as_ref() {
                if beacon.round < previous.round {
                    return Err(RandomnessError::Rollback {
                        received: beacon.round,
                        high_water: previous.round,
                    });
                }
                if beacon.round == previous.round {
                    if beacon.randomness != previous.randomness
                        || beacon.signature != previous.signature
                    {
                        return Err(RandomnessError::Equivocation {
                            round: beacon.round,
                        });
                    }
                    return Ok(());
                }
            }
            DrandHighWaterStateV1 {
                version: DRAND_STATE_VERSION_V1,
                round: beacon.round,
                randomness: beacon.randomness,
                signature: beacon.signature,
            }
        };
        let state_path = self.state_path.clone();
        let persisted = next.clone();
        crate::panic_recovery::join_recoverable(crate::panic_recovery::spawn_blocking_recoverable(
            move || store_secure_state(&state_path, &persisted, "drand"),
        ))
        .await
        .map_err(|error| RandomnessError::Persistence(error.to_string()))??;
        self.state_owner_lock.verify("drand")?;
        let mut state = self.state.lock();
        *state = Some(next);
        Ok(())
    }
}
#[cfg(feature = "app_api")]
#[async_trait]
impl RandomnessProvider for DrandHttpRandomnessProvider {
    async fn randomness_for_epoch(
        &self,
        epoch_id: u64,
        now_secs: u64,
        response_window_secs: u64,
    ) -> Result<PorRandomness, RandomnessError> {
        let round = self.expected_round(epoch_id, now_secs)?;
        let results = futures::future::join_all(
            self.endpoints
                .iter()
                .map(|endpoint| self.fetch_endpoint(endpoint, round)),
        )
        .await;
        let beacon = select_drand_quorum(results.into_iter().flatten(), self.quorum)?;
        self.commit_high_water(&beacon).await?;
        Ok(PorRandomness {
            epoch_id,
            issued_at_unix: now_secs,
            response_window_secs,
            drand_round: beacon.round,
            drand_randomness: beacon.randomness,
            drand_signature: beacon.signature,
        })
    }
}
#[cfg(feature = "app_api")]
fn select_drand_quorum(
    beacons: impl IntoIterator<Item = VerifiedDrandBeacon>,
    quorum: usize,
) -> Result<VerifiedDrandBeacon, RandomnessError> {
    let mut groups = BTreeMap::<VerifiedDrandBeacon, usize>::new();
    for beacon in beacons {
        *groups.entry(beacon).or_default() += 1;
    }
    let agreeing = groups.values().copied().max().unwrap_or(0);
    groups
        .into_iter()
        .find_map(|(beacon, count)| (count >= quorum).then_some(beacon))
        .ok_or(RandomnessError::QuorumUnavailable {
            agreeing,
            required: quorum,
        })
}
#[cfg(feature = "app_api")]
fn validate_drand_endpoint(
    raw_endpoint: &str,
    endpoint: &url::Url,
    expected_path: &str,
) -> Result<String, RandomnessError> {
    if endpoint.as_str().len() > 2_048
        || endpoint.scheme() != "https"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != expected_path
        || endpoint.port().is_some_and(|port| port != 443)
    {
        return Err(RandomnessError::Configuration(format!(
            "drand endpoint must be canonical `https://<host>{expected_path}`"
        )));
    }
    let host = endpoint.host_str().ok_or_else(|| {
        RandomnessError::Configuration("drand endpoint host is missing".to_owned())
    })?;
    if host.parse::<IpAddr>().is_ok()
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host == "localhost"
    {
        return Err(RandomnessError::Configuration(
            "drand endpoint must use a canonical lowercase public DNS name".to_owned(),
        ));
    }
    let canonical = format!("https://{host}{expected_path}");
    if raw_endpoint != canonical || endpoint.as_str() != canonical {
        return Err(RandomnessError::Configuration(format!(
            "drand endpoint must use exact canonical spelling `{canonical}`"
        )));
    }
    Ok(host.to_owned())
}
#[cfg(feature = "app_api")]
fn resolve_public_endpoint(host: &str, port: u16) -> Result<Vec<SocketAddr>, RandomnessError> {
    let mut addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| RandomnessError::Configuration(format!("DNS for `{host}`: {error}")))?
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > MAX_DRAND_DNS_ADDRESSES {
        return Err(RandomnessError::Configuration(format!(
            "DNS for `{host}` must yield 1..={MAX_DRAND_DNS_ADDRESSES} addresses"
        )));
    }
    if addresses
        .iter()
        .any(|address| !crate::utils::is_public_ip(address.ip()))
    {
        return Err(RandomnessError::Configuration(format!(
            "DNS for `{host}` resolved to a non-public address"
        )));
    }
    Ok(addresses)
}
#[cfg(feature = "app_api")]
async fn revalidate_pinned_dns(endpoint: &DrandEndpoint) -> Result<(), RandomnessError> {
    let mut current = tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(|error| RandomnessError::Endpoint(format!("DNS revalidation: {error}")))?
        .collect::<Vec<_>>();
    current.sort_unstable();
    current.dedup();
    if current.is_empty()
        || current.len() > MAX_DRAND_DNS_ADDRESSES
        || current
            .iter()
            .any(|address| !crate::utils::is_public_ip(address.ip()))
        || current != endpoint.pinned_addrs
    {
        return Err(RandomnessError::Endpoint(format!(
            "DNS rebinding or address-set change detected for `{}`",
            endpoint.host
        )));
    }
    Ok(())
}
#[cfg(feature = "app_api")]
fn parse_and_verify_drand_response(
    body: &[u8],
    expected_round: u64,
    public_key: &[u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES],
) -> Result<VerifiedDrandBeacon, RandomnessError> {
    let value: JsonValue = json::from_slice(body)
        .map_err(|error| RandomnessError::Endpoint(format!("invalid drand JSON: {error}")))?;
    let object = value.as_object().ok_or_else(|| {
        RandomnessError::Endpoint("drand response must be a JSON object".to_owned())
    })?;
    if object.len() != 2 || !object.contains_key("round") || !object.contains_key("signature") {
        return Err(RandomnessError::Endpoint(
            "drand v2 response must contain exactly round and signature".to_owned(),
        ));
    }
    let round = object
        .get("round")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| RandomnessError::Endpoint("drand round must be a u64".to_owned()))?;
    if round != expected_round {
        return Err(RandomnessError::Endpoint(format!(
            "drand returned round {round}; expected {expected_round}"
        )));
    }
    fn decode_canonical_hex<const N: usize>(
        value: Option<&JsonValue>,
        field: &str,
    ) -> Result<[u8; N], RandomnessError> {
        let text = value.and_then(JsonValue::as_str).ok_or_else(|| {
            RandomnessError::Endpoint(format!("drand {field} must be a hex string"))
        })?;
        if text.len() != N * 2
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RandomnessError::Endpoint(format!(
                "drand {field} must be canonical lowercase {N}-byte hex"
            )));
        }
        let bytes = hex::decode(text)
            .map_err(|error| RandomnessError::Endpoint(format!("invalid {field}: {error}")))?;
        bytes
            .try_into()
            .map_err(|_| RandomnessError::Endpoint(format!("drand {field} has invalid length")))
    }
    let signature = decode_canonical_hex(object.get("signature"), "signature")?;
    let randomness =
        iroha_crypto::drand::verify_unchained_g1_rfc9380(public_key, round, &signature, None)
            .map_err(|error| RandomnessError::Endpoint(error.to_string()))?;
    Ok(VerifiedDrandBeacon {
        round,
        randomness,
        signature,
    })
}
#[cfg(feature = "app_api")]
fn load_drand_state(
    path: &Path,
    public_key: &[u8; iroha_crypto::drand::DRAND_PUBLIC_KEY_BYTES],
) -> Result<Option<DrandHighWaterStateV1>, RandomnessError> {
    let Some(bytes) = read_secure_state(path, 4 * 1024, "drand")? else {
        return Ok(None);
    };
    let state: DrandHighWaterStateV1 = decode_from_bytes(&bytes)
        .map_err(|error| RandomnessError::Persistence(error.to_string()))?;
    let canonical =
        to_bytes(&state).map_err(|error| RandomnessError::Persistence(error.to_string()))?;
    if canonical != bytes || state.version != DRAND_STATE_VERSION_V1 || state.round == 0 {
        return Err(RandomnessError::Persistence(
            "drand state is non-canonical or has an unsupported version".to_owned(),
        ));
    }
    iroha_crypto::drand::verify_unchained_g1_rfc9380(
        public_key,
        state.round,
        &state.signature,
        Some(&state.randomness),
    )
    .map_err(|error| RandomnessError::Persistence(error.to_string()))?;
    Ok(Some(state))
}
#[cfg(feature = "app_api")]
fn read_secure_state(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, RandomnessError> {
    secure_read_bytes(path, max_bytes)
        .map_err(|error| RandomnessError::Persistence(format!("{label} state: {error}")))
}
#[cfg(feature = "app_api")]
fn store_secure_state<T: norito::core::NoritoSerialize>(
    path: &Path,
    value: &T,
    label: &str,
) -> Result<(), RandomnessError> {
    let bytes = to_bytes(value).map_err(|error| RandomnessError::Persistence(error.to_string()))?;
    secure_atomic_write(path, &bytes, 64 * 1024 * 1024, true)
        .map_err(|error| RandomnessError::Persistence(format!("{label} state: {error}")))
}
