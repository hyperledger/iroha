//! One original prepared output owner with resumable exact-descriptor publication.
//!
//! The surrounding DKG attempt owns the directory path and pinned descriptor.
//! Preparation and publication borrow that exact source, so every refusal retains
//! the same phase owner, private bytes and completed-file progress.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBuffer, PrepaidBufferError};
use iroha_core::beacon::credential::{
    GlobalBeaconCredentialEncodeErrorV1, PreparedGlobalBeaconCredentialV1,
};
use norito::json::{BoundedJsonError, JsonSerialize as _, JsonWriteSink};

/// Exact final-output source failure; no local I/O condition is protocol invalidity.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExportError {
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    #[error(transparent)]
    Buffer(#[from] PrepaidBufferError),
    #[error(transparent)]
    Credential(#[from] GlobalBeaconCredentialEncodeErrorV1),
    #[error(transparent)]
    Encoding(#[from] norito::Error),
    #[error(transparent)]
    Json(#[from] BoundedJsonError),
    #[error("beacon export descriptor operation failed")]
    Io(#[source] std::io::Error),
    #[error("beacon export original directory or file identity changed")]
    Custody,
    #[error("beacon export prepared source or phase changed")]
    Phase,
}

struct ByteWriter<'a>(&'a mut ChargedBuffer<u8>);
impl std::io::Write for ByteWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct CountJson(usize);
impl JsonWriteSink for CountJson {
    fn push(&mut self, value: char) -> std::result::Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0u8; 4]))
    }
    fn push_str(&mut self, value: &str) -> std::result::Result<(), BoundedJsonError> {
        self.0 = self
            .0
            .checked_add(value.len())
            .filter(|n| *n <= MAX_PUBLIC_BYTES)
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        Ok(())
    }
}
struct WriteJson<'a>(&'a mut ChargedBuffer<u8>);
impl JsonWriteSink for WriteJson<'_> {
    fn push(&mut self, value: char) -> std::result::Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0u8; 4]))
    }
    fn push_str(&mut self, value: &str) -> std::result::Result<(), BoundedJsonError> {
        self.0
            .append(value.as_bytes())
            .map_err(|_| BoundedJsonError::LengthMismatch)
    }
}
#[derive(JsonSerialize)]
struct ProviderRef<'a> {
    signer_index: u16,
    validator: &'a PeerId,
    handle: &'a str,
    revision: u64,
    policy_digest: [u8; 32],
}

#[derive(Default)]
pub(super) struct FileProgress {
    descriptor: Option<File>,
    // Only an exclusively created descriptor may initialize its exact mode.
    // Refusal retains this stage; restored descriptors never enter it.
    pending_mode: Option<rustix::fs::Mode>,
    offset: usize,
    synced: bool,
    complete: bool,
}
impl FileProgress {
    pub(super) fn complete(&self) -> bool {
        self.complete
    }
    #[cfg(test)]
    pub(super) fn is_synced(&self) -> bool {
        self.synced
    }
    /// Observe the original held file's inode without exposing or reopening its descriptor.
    #[cfg(test)]
    pub(super) fn retained_inode(&self) -> std::result::Result<u64, ExportError> {
        self.descriptor
            .as_ref()
            .ok_or(ExportError::Phase)?
            .metadata()
            .map(|metadata| metadata.ino())
            .map_err(ExportError::Io)
    }
}
struct Outputs {
    credential: PreparedGlobalBeaconCredentialV1,
    public: ChargedBuffer<u8>,
    provider: ChargedBuffer<u8>,
    pending: ChargedBuffer<u8>,
}
impl Outputs {
    fn bytes(&self, index: usize) -> std::result::Result<&[u8], ExportError> {
        match index {
            0 => self.credential.encoded().ok_or(ExportError::Phase),
            1 if self.pending.as_slice().len() == 96 => Ok(self.pending.as_slice()),
            2 => Ok(self.public.as_slice()),
            3 => Ok(self.provider.as_slice()),
            _ => Err(ExportError::Phase),
        }
    }
}
impl Drop for Outputs {
    fn drop(&mut self) {
        self.pending.as_mut_slice().zeroize();
    }
}

const FILES: [(&str, bool); 4] = [
    (GLOBAL_BEACON_PARTIAL_SIGNER_CREDENTIAL_NAME_V1, true),
    (ROTATION_PENDING_SHARE_NAME, true),
    ("public-session.norito", false),
    ("provider.json", false),
];

/// Original canonical output names, used by actual file/drop/reload controls.
#[cfg(test)]
pub(super) fn output_names() -> [&'static str; 4] {
    FILES.map(|(name, _)| name)
}

/// A reload may select only no outputs or a complete four-file prefix.
/// Actual content, modes, named inode and descriptor barriers are checked later.
pub(super) fn complete_output_prefix(
    directory: &Directory,
) -> std::result::Result<bool, ExportError> {
    revalidate_directory(directory)?;
    let mut present = 0;
    for (name, _) in FILES {
        match rustix::fs::statat(&directory.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => present += 1,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(ExportError::Io(error.into())),
        }
    }
    revalidate_directory(directory)?;
    match present {
        0 => Ok(false),
        4 => Ok(true),
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC117")))]
        _ => Err(ExportError::Custody),
        #[cfg(all(test, sumeragi_daemon_mutation = "HC117"))]
        _ => Ok(false),
    }
}

/// Move-only source for every byte and exact file descriptor of one final seat export.
pub(crate) struct PreparedSeatExport {
    directory_identity: DirectoryIdentity,
    public: ValidatedGlobalThresholdBeaconSessionV1,
    seat: u16,
    source: Option<iroha_core::beacon::GlobalBeaconAggregateOwnerV1>,
    outputs: Outputs,
    files: [FileProgress; 4],
    terminal_custody_failure: bool,
    budget: AllocationBudget,
    provider_handle_hash: [u8; 32],
    provider_revision: u64,
}
impl PreparedSeatExport {
    /// Prepare both public files and the secret output backing before extracting a share.
    pub(crate) fn new(
        directory: &Directory,
        public: &ValidatedGlobalThresholdBeaconSessionV1,
        seat: u16,
        handle: &str,
        revision: u64,
        budget: &AllocationBudget,
    ) -> std::result::Result<Self, ExportError> {
        let digest = global_beacon_partial_signer_public_inventory_digest_v1(
            public.network_id,
            &[(public.record(), seat)],
        )
        .map_err(GlobalBeaconCredentialEncodeErrorV1::from)?;
        let credential = PreparedGlobalBeaconCredentialV1::new(
            public.network_id,
            handle,
            revision,
            digest,
            [(public, seat)],
            budget,
        )?;
        let validator = &public.adaptive_dkg.recipient_keys[usize::from(seat - 1)].validator;
        let provider = ProviderRef {
            signer_index: seat,
            validator,
            handle,
            revision,
            policy_digest: digest,
        };
        let mut count = CountJson(0);
        provider.json_serialize_to(&mut count)?;
        let public_len = norito::canonical_frame_len(public.record())?;
        if count.0 == 0 || public_len == 0 || public_len > MAX_PUBLIC_BYTES {
            return Err(ExportError::Phase);
        }
        let total = count
            .0
            .checked_add(96)
            .and_then(|bytes| bytes.checked_add(public_len))
            .ok_or(AllocationRefusal::DemandOverflow)?;
        let mut reservation = budget.try_reserve_bytes(total)?;
        let mut public_bytes = ChargedBuffer::from_reservation(public_len, &mut reservation)?;
        let mut provider_bytes = ChargedBuffer::from_reservation(count.0, &mut reservation)?;
        let pending = ChargedBuffer::from_reservation(96, &mut reservation)?;
        norito::core::write_canonical_to_writer(
            public.record(),
            &mut ByteWriter(&mut public_bytes),
        )?;
        provider.json_serialize_to(&mut WriteJson(&mut provider_bytes))?;
        if public_bytes.as_slice().len() != public_len || provider_bytes.as_slice().len() != count.0
        {
            return Err(ExportError::Phase);
        }
        let directory_identity = DirectoryIdentity::new(directory)?;
        Ok(Self {
            directory_identity,
            public: public.clone(),
            seat,
            source: None,
            outputs: Outputs {
                credential,
                public: public_bytes,
                provider: provider_bytes,
                pending,
            },
            files: std::array::from_fn(|_| FileProgress::default()),
            terminal_custody_failure: false,
            budget: budget.clone(),
            provider_handle_hash: Hash::new(handle.as_bytes()).into(),
            provider_revision: revision,
        })
    }

    /// Observe the actual retained source without introducing a test-only protocol owner.
    #[cfg(test)]
    pub(super) fn source_is_empty(&self) -> bool {
        self.source.is_none()
    }
    /// Borrow the same original retained ciphertext used by production export.
    #[cfg(test)]
    pub(super) fn source_checkpoint(&self) -> Option<&[u8]> {
        self.source
            .as_ref()
            .map(|source| source.encrypted_checkpoint())
    }

    /// Move the authenticated original aggregate owner once, retaining it on every refusal.
    /// Private/public equations and actual native source validation precede this move.
    pub(crate) fn accept(
        &mut self,
        source: iroha_core::beacon::GlobalBeaconAggregateOwnerV1,
    ) -> std::result::Result<
        (),
        (
            iroha_core::beacon::GlobalBeaconAggregateOwnerV1,
            ExportError,
        ),
    > {
        if self.source.is_some()
            || !source.authenticated_session().ptr_eq(&self.public)
            || source.signer_index() != self.seat
            || !source.belongs_to(&self.budget)
            || source.binding().provider_handle_hash != self.provider_handle_hash
            || source.binding().provider_revision != self.provider_revision
        {
            return Err((source, ExportError::Phase));
        }
        self.source = Some(source);
        Ok(())
    }

    fn encode_original_outputs(&mut self) -> std::result::Result<(), ExportError> {
        let source = self.source.as_ref().ok_or(ExportError::Phase)?;
        if !source.authenticated_session().ptr_eq(&self.public)
            || source.signer_index() != self.seat
            || !source.belongs_to(&self.budget)
            || source.binding().provider_handle_hash != self.provider_handle_hash
            || source.binding().provider_revision != self.provider_revision
        {
            return Err(ExportError::Phase);
        }
        if self.outputs.pending.as_slice().is_empty() {
            source
                .write_pending_share_for_runtime_custody(&mut ByteWriter(&mut self.outputs.pending))
                .map_err(ExportError::Io)?;
        }
        if self.outputs.pending.as_slice().len() != 96 {
            return Err(ExportError::Phase);
        }
        if self.outputs.credential.encoded().is_none() {
            encode_global_beacon_partial_signer_credential_v1(
                &mut self.outputs.credential,
                std::iter::once(source.credential_source()),
            )?;
        }
        Ok(())
    }

    /// Complete encoding and resume publication through the original descriptors and offsets.
    /// No failure consumes this owner or opens an existing output as a replacement destination.
    pub(crate) fn publish(
        &mut self,
        directory: &Directory,
    ) -> std::result::Result<(), ExportError> {
        if self.terminal_custody_failure {
            return Err(ExportError::Custody);
        }
        if !self.directory_identity.matches(directory)? {
            self.terminal_custody_failure = true;
            return Err(ExportError::Custody);
        }
        self.encode_original_outputs()?;
        for (index, (name, private)) in FILES.iter().copied().enumerate() {
            let result = publish_file(
                directory,
                name,
                private,
                self.outputs.bytes(index)?,
                &mut self.files[index],
            );
            if matches!(result, Err(ExportError::Custody)) {
                self.terminal_custody_failure = true;
            }
            result?;
        }
        Ok(())
    }

    /// Whether all four exact outputs have been durably verified under their original names.
    /// Adopt only complete existing exact output files after authenticating the aggregate.
    /// Partial/mixed outputs cannot manufacture a replacement destination or original offset.
    pub(crate) fn restore_complete(
        &mut self,
        directory: &Directory,
    ) -> std::result::Result<(), ExportError> {
        if self.terminal_custody_failure || !self.directory_identity.matches(directory)? {
            self.terminal_custody_failure = true;
            return Err(ExportError::Custody);
        }
        self.encode_original_outputs()?;
        for (index, (name, private)) in FILES.iter().copied().enumerate() {
            restore_published_file(
                directory,
                name,
                private,
                self.outputs.bytes(index)?,
                &mut self.files[index],
            )?;
        }
        directory.file.sync_all().map_err(ExportError::Io)?;
        revalidate_directory(directory)?;
        for (index, (name, private)) in FILES.iter().copied().enumerate() {
            restore_published_file(
                directory,
                name,
                private,
                self.outputs.bytes(index)?,
                &mut self.files[index],
            )?;
        }
        Ok(())
    }

    pub(crate) fn complete(&self) -> bool {
        self.files.iter().all(|file| file.complete)
    }
}

// The surrounding attempt owns the exact charged directory path and descriptor.
// Export preparation borrows it so a failed constructor cannot consume that owner.
struct DirectoryIdentity {
    metadata: std::fs::Metadata,
    path: Hash,
}
impl DirectoryIdentity {
    fn new(directory: &Directory) -> std::result::Result<Self, ExportError> {
        use std::os::unix::ffi::OsStrExt as _;
        revalidate_directory(directory)?;
        Ok(Self {
            metadata: directory.file.metadata().map_err(ExportError::Io)?,
            path: Hash::new(directory.path.as_os_str().as_bytes()),
        })
    }
    fn matches(&self, directory: &Directory) -> std::result::Result<bool, ExportError> {
        use std::os::unix::ffi::OsStrExt as _;
        let now = directory.file.metadata().map_err(ExportError::Io)?;
        Ok(self.metadata.dev() == now.dev()
            && self.metadata.ino() == now.ino()
            && self.metadata.uid() == now.uid()
            && self.metadata.gid() == now.gid()
            && self.metadata.mode() == now.mode()
            && self.path == Hash::new(directory.path.as_os_str().as_bytes()))
    }
}

// Recheck every canonical ancestor and the held inode. This performs no pathname
// allocation and never substitutes a freshly opened directory for the original writer.
pub(super) fn revalidate_directory(directory: &Directory) -> std::result::Result<(), ExportError> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = File::from(
        rustix::fs::open("/", flags, Mode::empty()).map_err(|e| ExportError::Io(e.into()))?,
    );
    validate_directory(&current.metadata().map_err(ExportError::Io)?)
        .map_err(|_| ExportError::Custody)?;
    for part in directory.path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = File::from(
                    rustix::fs::openat(&current, name, flags, Mode::empty())
                        .map_err(|e| ExportError::Io(e.into()))?,
                );
                validate_directory(&current.metadata().map_err(ExportError::Io)?)
                    .map_err(|_| ExportError::Custody)?;
            }
            _ => return Err(ExportError::Custody),
        }
    }
    let held = directory.file.metadata().map_err(ExportError::Io)?;
    let named = current.metadata().map_err(ExportError::Io)?;
    validate_directory(&held).map_err(|_| ExportError::Custody)?;
    if held.dev() != named.dev()
        || held.ino() != named.ino()
        || held.uid() != named.uid()
        || held.gid() != named.gid()
        || held.mode() != named.mode()
    {
        return Err(ExportError::Custody);
    }
    Ok(())
}
fn validate_output(
    file: &File,
    private: bool,
    expected_length: usize,
) -> std::result::Result<(), ExportError> {
    let m = file.metadata().map_err(ExportError::Io)?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || m.mode() & 0o7777 != if private { 0o600 } else { 0o644 }
        || m.len() != u64::try_from(expected_length).map_err(|_| ExportError::Phase)?
    {
        return Err(ExportError::Custody);
    }
    Ok(())
}
pub(super) fn prepare_file_bytes(
    directory: &Directory,
    name: &str,
    private: bool,
    bytes: &[u8],
    progress: &mut FileProgress,
) -> std::result::Result<(), ExportError> {
    prepare_file_bytes_with_mode(directory, name, private, bytes, progress, |file, mode| {
        rustix::fs::fchmod(file, mode).map_err(std::io::Error::from)
    })
}
fn prepare_file_bytes_with_mode(
    directory: &Directory,
    name: &str,
    private: bool,
    bytes: &[u8],
    progress: &mut FileProgress,
    mut initialize_mode: impl FnMut(&File, rustix::fs::Mode) -> std::io::Result<()>,
) -> std::result::Result<(), ExportError> {
    use rustix::fs::{Mode, OFlags};
    revalidate_directory(directory)?;
    let mode = Mode::from_raw_mode(if private { 0o600 } else { 0o644 });
    if progress.descriptor.is_none() {
        let file = File::from(
            rustix::fs::openat(
                &directory.file,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
            )
            .map_err(|e| ExportError::Io(e.into()))?,
        );
        // Install custody before metadata/fsync/write can refuse: never recreate this file.
        progress.descriptor = Some(file);
        progress.pending_mode = Some(mode);
    }
    let file = progress
        .descriptor
        .as_mut()
        .expect("original file retained");
    if let Some(original_mode) = progress.pending_mode {
        // openat's mode is filtered by the caller's umask. Normalize only this
        // newly created, still-empty original file. Do not repair existing or
        // published files, or overwrite their exact custody checks on retry.
        let metadata = file.metadata().map_err(ExportError::Io)?;
        if original_mode != mode
            || progress.offset != 0
            || progress.synced
            || progress.complete
            || !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.len() != 0
            || metadata.mode() & 0o7777 & !(if private { 0o600 } else { 0o644 }) != 0
        {
            return Err(ExportError::Custody);
        }
        validate_named_output(directory, name, file)?;
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC198")))]
        initialize_mode(file, mode).map_err(ExportError::Io)?;
        #[cfg(all(test, sumeragi_daemon_mutation = "HC198"))]
        let _ = &mut initialize_mode;
        validate_output(file, private, 0)?;
        progress.pending_mode = None;
    }
    validate_output(file, private, progress.offset)?;
    verify_prefix(file, &bytes[..progress.offset])?;
    write_remaining(file, bytes, &mut progress.offset, |file, bytes, offset| {
        std::os::unix::fs::FileExt::write_at(file, bytes, offset)
    })?;
    Ok(())
}

pub(super) fn publish_file(
    directory: &Directory,
    name: &str,
    private: bool,
    bytes: &[u8],
    progress: &mut FileProgress,
) -> std::result::Result<(), ExportError> {
    use rustix::fs::{Mode, OFlags};
    prepare_file_bytes(directory, name, private, bytes, progress)?;
    let file = progress.descriptor.as_mut().ok_or(ExportError::Phase)?;
    if !progress.synced {
        file.sync_all().map_err(ExportError::Io)?;
        progress.synced = true;
    }
    validate_output(file, private, bytes.len())?;
    verify_prefix(file, bytes)?;
    let named = File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| ExportError::Io(e.into()))?,
    );
    if !same_file(
        &file.metadata().map_err(ExportError::Io)?,
        &named.metadata().map_err(ExportError::Io)?,
    ) {
        return Err(ExportError::Custody);
    }
    directory.file.sync_all().map_err(ExportError::Io)?;
    revalidate_directory(directory)?;
    progress.complete = true;
    Ok(())
}

/// Retain and verify an existing output, then finish its real durability barrier.
/// A sync refusal keeps this exact descriptor and source progress for retry.
/// No byte is written/recreated; visibility alone never means durable completion.
pub(super) fn restore_published_file(
    directory: &Directory,
    name: &str,
    private: bool,
    bytes: &[u8],
    progress: &mut FileProgress,
) -> std::result::Result<(), ExportError> {
    restore_published_file_with(directory, name, private, bytes, progress, |file| {
        file.sync_all()
    })
}
fn restore_published_file_with(
    directory: &Directory,
    name: &str,
    private: bool,
    bytes: &[u8],
    progress: &mut FileProgress,
    mut sync: impl FnMut(&File) -> std::io::Result<()>,
) -> std::result::Result<(), ExportError> {
    revalidate_directory(directory)?;
    if progress.descriptor.is_none() {
        let descriptor = File::from(
            rustix::fs::openat(
                &directory.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| ExportError::Io(e.into()))?,
        );
        // Own the original descriptor before metadata, reads or fsync may refuse.
        progress.descriptor = Some(descriptor);
    }
    let descriptor = progress.descriptor.as_ref().ok_or(ExportError::Phase)?;
    validate_output(descriptor, private, bytes.len())?;
    verify_prefix(descriptor, bytes)?;
    progress.offset = bytes.len();
    validate_named_output(directory, name, descriptor)?;
    if !progress.synced {
        sync(descriptor).map_err(ExportError::Io)?;
        progress.synced = true;
    }
    sync(&directory.file).map_err(ExportError::Io)?;
    validate_output(descriptor, private, bytes.len())?;
    verify_prefix(descriptor, bytes)?;
    revalidate_directory(directory)?;
    validate_named_output(directory, name, descriptor)?;
    progress.complete = true;
    Ok(())
}

fn validate_named_output(
    directory: &Directory,
    name: &str,
    descriptor: &File,
) -> std::result::Result<(), ExportError> {
    let named = File::from(
        rustix::fs::openat(
            &directory.file,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| ExportError::Io(e.into()))?,
    );
    if !same_file(
        &descriptor.metadata().map_err(ExportError::Io)?,
        &named.metadata().map_err(ExportError::Io)?,
    ) {
        return Err(ExportError::Custody);
    }
    Ok(())
}

fn write_remaining(
    file: &File,
    bytes: &[u8],
    offset: &mut usize,
    mut write: impl FnMut(&File, &[u8], u64) -> std::io::Result<usize>,
) -> std::result::Result<(), ExportError> {
    while *offset < bytes.len() {
        let at = u64::try_from(*offset).map_err(|_| ExportError::Phase)?;
        let wrote = write(file, &bytes[*offset..], at).map_err(ExportError::Io)?;
        if wrote == 0 {
            return Err(ExportError::Io(std::io::ErrorKind::WriteZero.into()));
        }
        if wrote > bytes.len() - *offset {
            return Err(ExportError::Phase);
        }
        *offset += wrote;
    }
    Ok(())
}
fn verify_prefix(file: &File, expected: &[u8]) -> std::result::Result<(), ExportError> {
    use std::os::unix::fs::FileExt as _;
    let mut scratch = Zeroizing::new([0u8; 4096]);
    let mut offset = 0;
    while offset < expected.len() {
        let length = (expected.len() - offset).min(scratch.len());
        let read = file
            .read_at(
                &mut scratch[..length],
                u64::try_from(offset).map_err(|_| ExportError::Phase)?,
            )
            .map_err(ExportError::Io)?;
        if read == 0 || scratch[..read] != expected[offset..offset + read] {
            return Err(ExportError::Custody);
        }
        offset += read;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
