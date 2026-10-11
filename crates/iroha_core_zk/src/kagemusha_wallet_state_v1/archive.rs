//! Immutable, incarnation-bound archive records over the provider filesystem interface.

use std::io;

use super::Error;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletCustodyDirV1 as Dir, KagemushaWalletEntryNameV1 as Name,
    KagemushaWalletFsV1 as Fs, KagemushaWalletSlotIdV1 as Slot,
    kagemusha_wallet_provider_digest_v1 as digest,
};

// The fixed metadata consists of a Norito header, four 32-byte arrays, an enum key,
// version and bounded length prefixes. This upper bound excludes the payload itself.
pub(super) const METADATA_BOUND: usize = 1024;

/// Immutable archive identity. Checkpoint order is part of the name and encoded binding.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ArchiveKey")]
pub enum ArchiveKey {
    /// Immutable generation-zero native nonce/source choices; never a completion authority.
    BootstrapPreparation,
    /// Immutable reference to the exact frozen Bootstrap capsule before Advance.
    BootstrapFrozen,
    /// Exact frozen pre-signing inputs, keyed by the G1 capsule digest.
    Capsule([u8; 32]),
    /// Exact local witness snapshot retained before the associated capsule is selected.
    /// Its descriptor becomes authoritative only through the selected capsule/manifest.
    SourceCustody([u8; 32]),
    /// Content-addressed persistent index node or bounded auxiliary object.
    Object([u8; 32]),
    /// A sequential sub-proof for one released sequence.
    Checkpoint {
        /// Released head sequence.
        sequence: u128,
        /// Zero-based sub-proof ordinal.
        ordinal: u32,
    },
    /// The single self-verified Ω recorded for one head.
    Fold(u128),
    /// Separate exact Payment retained until its earned fee has a finalized payout.
    FeeClaim([u8; 32]),
}

impl ArchiveKey {
    fn name(self) -> String {
        match self {
            Self::BootstrapPreparation => "bootstrap-preparation.arc".into(),
            Self::BootstrapFrozen => "bootstrap-frozen.arc".into(),
            Self::Capsule(digest) => format!("c-{}.arc", hex::encode(digest)),
            Self::SourceCustody(digest) => format!("s-{}.arc", hex::encode(digest)),
            Self::Object(digest) => format!("o-{}.arc", hex::encode(digest)),
            Self::Checkpoint { sequence, ordinal } => {
                format!("p-{sequence:032x}-{ordinal:08x}.arc")
            }
            Self::Fold(sequence) => format!("f-{sequence:032x}.arc"),
            Self::FeeClaim(credit) => format!("q-{}.arc", hex::encode(credit)),
        }
    }
}

/// Non-backup durable archive, held under the same exclusive lifetime as Advance.
///
/// `put` must publish both copies durably and refuse different bytes at an existing key.
/// A successful `get` must authenticate incarnation, key and content. Read failures must
/// never be reported as absence. An uncertain `put` is retried with exactly the same bytes.
/// Archive storage is not a completion authority.
pub trait ArchiveStore {
    /// Scheme and wallet incarnation to which every record is bound.
    fn binding(&self) -> ([u8; 32], [u8; 32]);
    /// Read a record, with definitive absence distinct from unavailability.
    ///
    /// # Errors
    /// Storage failure, conflicting copies, malformed record or wrong binding.
    fn get(&mut self, key: ArchiveKey, max_bytes: usize) -> Result<Option<Vec<u8>>, Error>;
    /// Publish one immutable record, or adopt exactly matching existing bytes durably.
    ///
    /// # Errors
    /// I/O errors may follow publication; callers must reconcile, never infer no commit.
    fn put(&mut self, key: ArchiveKey, bytes: &[u8]) -> Result<(), Error>;
    /// Remove both copies after a source-selected manifest has durably authorized collection.
    /// Absence is idempotent; unavailability and uncertain directory durability are errors.
    ///
    /// # Errors
    /// Failed removal or directory synchronization. No error restores deleted data.
    fn remove(&mut self, key: ArchiveKey) -> Result<(), Error>;
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ArchiveEnvelope")]
pub(super) struct Envelope {
    pub(super) version: u16,
    pub(super) scheme_id: [u8; 32],
    pub(super) wallet_id: [u8; 32],
    pub(super) key: ArchiveKey,
    pub(super) content_digest: [u8; 32],
    pub(super) content: Vec<u8>,
}

/// Redundant immutable archive below `slots/<slot>/archive/`.
///
/// Construct only while the matching Advance provider holds the exclusive custody lock.
/// Its filesystem handle must name that provider's root. This store never opens a second
/// root or writes provider markers. Platform adapters must retain protected-data access
/// throughout a coordinator call; this raw filesystem trait cannot itself probe it.
/// Checksums detect corruption; selected capsule authenticity still comes from the provider
/// marker, and Ω authenticity from the native proof verification boundary.
pub struct FsArchive<F> {
    fs: F,
    directory: Dir,
    scheme_id: [u8; 32],
    wallet_id: [u8; 32],
}

impl<F: Fs> FsArchive<F> {
    /// Bind to an already prepared slot archive. Does not create an enrollment or take a lock.
    ///
    /// # Errors
    /// Rejects zero identities or an unavailable archive directory.
    pub fn new(fs: F, slot: Slot, scheme_id: [u8; 32], wallet_id: [u8; 32]) -> Result<Self, Error> {
        if scheme_id == [0; 32] || wallet_id == [0; 32] {
            return Err(Error::Invalid("archive identity"));
        }
        let mut directory = Dir::root();
        for component in ["slots", slot.dir_name().as_str(), "archive"] {
            directory =
                directory.child(&Name::new(component).ok_or(Error::Invalid("archive directory"))?);
        }
        fs.list(&directory)?;
        Ok(Self {
            fs,
            directory,
            scheme_id,
            wallet_id,
        })
    }

    fn read_copy(
        &self,
        name: &str,
        key: ArchiveKey,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let bytes = match self.fs.read(
            &self.directory,
            name,
            max_bytes
                .checked_add(METADATA_BOUND)
                .ok_or(Error::Invalid("archive size overflow"))?,
        ) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Storage(e)),
        };
        let envelope: Envelope = decode(&bytes)?;
        if envelope.content.len() > max_bytes {
            return Err(Error::WitnessLost("archive payload size"));
        }
        if envelope.version != 1
            || envelope.key != key
            || envelope.scheme_id != self.scheme_id
            || envelope.wallet_id != self.wallet_id
            || envelope.content_digest != digest("wallet-archive-content", &envelope.content)
        {
            return Err(Error::WitnessLost("archive authentication"));
        }
        Ok(Some(envelope.content))
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let replace = match self.fs.read(&self.directory, name, bytes.len()) {
            Ok(existing) => {
                if existing != bytes {
                    return Err(Error::WitnessLost("immutable archive conflict"));
                }
                // Fresh inode adoption is required after an uncertain/lost writeback. Merely
                // syncing an existing inode again can succeed after the OS cleared its error.
                true
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let stage = self.fs.staging_name()?;
        let mut file = self.fs.create_new(&self.directory, &stage)?;
        self.fs.write_all(&mut file, bytes)?;
        self.fs.sync_staged(&file)?;
        if replace {
            self.fs.rename_replace(&self.directory, &stage, name)?;
        } else {
            self.fs.rename_noreplace(&self.directory, &stage, name)?;
        }
        self.fs.sync_dir(&self.directory)?;
        Ok(())
    }
}

impl<F: Fs> FsArchive<F> {
    /// Enumerate standalone archive records for explicit diagnostics only.
    ///
    /// # Errors
    /// Unavailable storage or an unexpected archive entry.
    pub fn keys(&mut self) -> Result<Vec<ArchiveKey>, Error> {
        let mut keys = std::collections::BTreeSet::new();
        for entry in self.fs.list(&self.directory)? {
            if entry.name.strip_prefix(".tmp-").is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                continue;
            }
            let name = entry.name.strip_suffix(".r").unwrap_or(&entry.name);
            let key = parse_key(name).ok_or(Error::WitnessLost("archive entry name"))?;
            keys.insert(key);
        }
        Ok(keys.into_iter().collect())
    }
}

impl<F: Fs> ArchiveStore for FsArchive<F> {
    fn remove(&mut self, key: ArchiveKey) -> Result<(), Error> {
        let name = key.name();
        for name in [name.clone(), format!("{name}.r")] {
            match self.fs.unlink(&self.directory, &name) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            self.fs.sync_dir(&self.directory)?;
        }
        Ok(())
    }

    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme_id, self.wallet_id)
    }

    fn get(&mut self, key: ArchiveKey, max_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
        let name = key.name();
        let first = self.read_copy(&name, key, max_bytes);
        let second = self.read_copy(&format!("{name}.r"), key, max_bytes);
        match (first, second) {
            (Ok(Some(a)), Ok(Some(b))) if a != b => {
                Err(Error::WitnessLost("archive copies conflict"))
            }
            (Ok(Some(a)), _) | (_, Ok(Some(a))) => Ok(Some(a)),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(None), Ok(None)) => Ok(None),
        }
    }

    fn put(&mut self, key: ArchiveKey, bytes: &[u8]) -> Result<(), Error> {
        let envelope = Envelope {
            version: 1,
            scheme_id: self.scheme_id,
            wallet_id: self.wallet_id,
            key,
            content_digest: digest("wallet-archive-content", bytes),
            content: bytes.to_vec(),
        };
        let bytes = encode(&envelope)?;
        let name = key.name();
        self.publish(&name, &bytes)?;
        self.publish(&format!("{name}.r"), &bytes)?;
        Ok(())
    }
}

fn parse_key(name: &str) -> Option<ArchiveKey> {
    let key = if name == "bootstrap-preparation.arc" {
        ArchiveKey::BootstrapPreparation
    } else if name == "bootstrap-frozen.arc" {
        ArchiveKey::BootstrapFrozen
    } else if let Some(raw) = name.strip_prefix("c-").and_then(|s| s.strip_suffix(".arc")) {
        ArchiveKey::Capsule(hex::decode(raw).ok()?.try_into().ok()?)
    } else if let Some(raw) = name.strip_prefix("s-").and_then(|s| s.strip_suffix(".arc")) {
        ArchiveKey::SourceCustody(hex::decode(raw).ok()?.try_into().ok()?)
    } else if let Some(raw) = name.strip_prefix("o-").and_then(|s| s.strip_suffix(".arc")) {
        ArchiveKey::Object(hex::decode(raw).ok()?.try_into().ok()?)
    } else if let Some(raw) = name.strip_prefix("q-").and_then(|s| s.strip_suffix(".arc")) {
        ArchiveKey::FeeClaim(hex::decode(raw).ok()?.try_into().ok()?)
    } else if let Some(raw) = name.strip_prefix("f-").and_then(|s| s.strip_suffix(".arc")) {
        ArchiveKey::Fold(u128::from_str_radix(raw, 16).ok()?)
    } else {
        let (sequence, ordinal) = name
            .strip_prefix("p-")?
            .strip_suffix(".arc")?
            .split_once('-')?;
        ArchiveKey::Checkpoint {
            sequence: u128::from_str_radix(sequence, 16).ok()?,
            ordinal: u32::from_str_radix(ordinal, 16).ok()?,
        }
    };
    (key.name() == name).then_some(key)
}

pub(super) fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = norito::encode_canonical(value).map_err(|_| Error::Invalid("archive encoding"))?;
    Ok(bytes)
}

pub(super) fn decode<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| Error::WitnessLost("canonical archive record"))
}

impl<A: ArchiveStore> super::ObjectStore for A {
    fn read_object(&mut self, expected: &[u8; 32], max_bytes: usize) -> Result<Vec<u8>, Error> {
        let bytes = self
            .get(ArchiveKey::Object(*expected), max_bytes)?
            .ok_or(Error::WitnessLost("index object"))?;
        if crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(&bytes)
            != *expected
        {
            return Err(Error::WitnessLost("index object digest"));
        }
        Ok(bytes)
    }
    fn write_object(&mut self, bytes: &[u8], max_bytes: usize) -> Result<[u8; 32], Error> {
        if bytes.len() > max_bytes {
            return Err(Error::Invalid("index object size"));
        }
        let digest =
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(bytes);
        self.put(ArchiveKey::Object(digest), bytes)?;
        Ok(digest)
    }
}

#[cfg(test)]
#[path = "archive/tests.rs"]
mod tests;
