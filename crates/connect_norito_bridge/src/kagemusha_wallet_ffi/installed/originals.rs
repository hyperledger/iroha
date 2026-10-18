//! Read-only actual source directories routed only by the authenticated complete catalog.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    AuthenticatedProducerInventoryV1, EncodedDirectoryOriginalsV1, EncodedTransportV1,
    PROVING_KEY_MAX_BYTES_V1, ProducerInventoryV1,
};
use iroha_core_zk::kagemusha_wallet_proofs_v1::Error as OriginalError;
use iroha_fs::{FileIdentity, PrivateDirectory};
use std::{
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

/// Clones share retained native ancestry and immutable metadata; never PK buffers.
/// Complete admission may temporarily snapshot bounded compressed public DATA.
#[derive(Clone)]
pub(super) struct CatalogOriginals {
    _selected: Arc<selection::AuthenticatedBase>,
    source: CatalogReader,
}

/// Original DATA routing only. The enclosing owner retains the independently authenticated
/// selection; this reader cannot authenticate an inventory or qualify a wallet source.
#[derive(Clone)]
struct CatalogReader {
    metadata: Arc<PrivateDirectory>,
    wallet: Arc<EncodedDirectoryOriginalsV1>,
    roles: Arc<BTreeMap<[u8; 32], BlobV1>>,
    // The exact transport this reader routes; another attempt must select the same rows.
    transport: Arc<EncodedTransportV1>,
    // Set by any failed live open or read through any clone; such a reader is never reused.
    failed: Arc<AtomicBool>,
}

/// Exact carrier metadata, checked against the authenticated selection on every attempt
/// before an admitted graph is loaded or reused. It opens no original and grants nothing.
pub(super) struct CatalogMetadata<'a> {
    root: &'a Path,
    directory: PrivateDirectory,
    transport: Vec<u8>,
}

fn insert(roles: &mut BTreeMap<[u8; 32], BlobV1>, blob: BlobV1) -> Result<()> {
    if blob.bytes == 0 || blob.sha256 == [0; 32] || blob.bytes > PROVING_KEY_MAX_BYTES_V1 as u64 {
        return Err(Failure::code(INVALID));
    }
    if let Some(previous) = roles.get_mut(&blob.sha256) {
        if *previous != blob {
            return Err(Failure::code(INVALID));
        }
    } else {
        roles.insert(blob.sha256, blob);
    }
    Ok(())
}

impl<'a> CatalogMetadata<'a> {
    pub(super) fn open(
        root: &'a [u8],
        pack: &[u8],
        catalog: &[u8],
        selected: &selection::AuthenticatedBase,
    ) -> Result<Self> {
        if root.is_empty() || root.len() > ROOT_MAX || root.contains(&0) {
            return Err(Failure::code(INVALID));
        }
        let root = Path::new(std::str::from_utf8(root).map_err(|_| Failure::code(INVALID))?);
        if !root.is_absolute() {
            return Err(Failure::code(INVALID));
        }
        let metadata = PrivateDirectory::open_exact(root).map_err(storage)?;
        require_metadata_inventory(&metadata)?;
        // All five financial offering paths have fixed current Native roles.
        // A signed transport row cannot substitute a different path.
        for (name, bytes, cap) in [
            ("verifier-pack.norito", pack, VERIFIER_PACK_MAX_BYTES_V1),
            ("producer-inventory.norito", catalog, CATALOG_MAX_BYTES_V1),
        ] {
            let actual = metadata.read(name, cap).map_err(storage)?;
            if actual.as_slice() != bytes {
                return Err(Failure::code(INVALID));
            }
        }
        let transport = metadata
            .read("transport.json", 32 * 1024 * 1024)
            .map_err(storage)?;
        selected.require_transport_selection(&transport)?;
        let financial = selected.financial.as_ref().ok_or(Failure::code(INVALID))?;
        let financial_original = metadata
            .read("financial-originals.json", ENVELOPE_MAX)
            .map_err(storage)?;
        if financial_original.as_slice() != financial.original()?.as_slice() {
            return Err(Failure::code(INVALID));
        }
        Ok(Self {
            root,
            directory: metadata,
            transport: transport.to_vec(),
        })
    }

    /// Kernel identity of the opened carrier root; part of the memo key.
    pub(super) fn identity(&self) -> Result<FileIdentity> {
        self.directory.identity().map_err(storage)
    }
}

impl CatalogOriginals {
    pub(super) fn from_authenticated(
        authenticated: &AuthenticatedProducerInventoryV1,
        metadata: CatalogMetadata<'_>,
        selected: Arc<selection::AuthenticatedBase>,
    ) -> Result<Self> {
        let inventory = authenticated.inventory();
        let transport = require_transport(inventory, &metadata.transport)?;
        let source = CatalogReader::open(metadata.directory, metadata.root, inventory, &transport)?;
        Ok(Self {
            _selected: selected,
            source,
        })
    }

    /// Share this admitted reader with another owner (design §9.1). The fresh inventory must
    /// select exactly the transport this reader routes, under the same retained root; then
    /// custody is closed over every observed original and every stored frame is re-hashed.
    /// The clone shares the observed map and retains the fresh authenticated selection.
    pub(super) fn reuse(
        &self,
        authenticated: &AuthenticatedProducerInventoryV1,
        metadata: &CatalogMetadata<'_>,
        selected: Arc<selection::AuthenticatedBase>,
    ) -> Result<Self> {
        let transport = require_transport(authenticated.inventory(), &metadata.transport)?;
        self.source.reuse(&metadata.directory, &transport)?;
        Ok(Self {
            _selected: selected,
            source: self.source.clone(),
        })
    }

    /// Keep the public snapshot inside admission and close actual filesystem
    /// custody before returning any complete source owner to the runtime.
    pub(super) fn with_snapshot<T, E>(
        &self,
        body: impl FnOnce(&mut dyn OriginalSourceV1) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<OriginalError>,
    {
        self.source.with_snapshot(body)
    }
}

impl CatalogReader {
    fn open(
        metadata: PrivateDirectory,
        root: &Path,
        inventory: &ProducerInventoryV1,
        transport: &EncodedTransportV1,
    ) -> Result<Self> {
        // The exact current financial roles are the only source directories. This
        // method creates no files and replaces no authority or old missing original.
        let wallet =
            EncodedDirectoryOriginalsV1::open_existing(root.join("wallet-originals"), transport)
                .map_err(storage)?;
        let mut roles = BTreeMap::new();
        for record in &inventory.originals {
            for blob in [record.descriptor, record.verifying_key, record.proving_key] {
                insert(&mut roles, blob)?;
            }
        }
        if transport
            .originals()
            .iter()
            .map(|row| row.original)
            .ne(roles.values().copied())
        {
            return Err(Failure::code(INVALID));
        }
        // The immediately following admission snapshot verifies every unique
        // stored/decoded original once. Opening this DATA reader grants nothing.
        metadata.revalidate().map_err(storage)?;
        Ok(Self {
            metadata: Arc::new(metadata),
            wallet: Arc::new(wallet),
            roles: Arc::new(roles),
            transport: Arc::new(transport.clone()),
            failed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Admit this reader for another owner. A reader whose live open or read failed, another
    /// transport or another root object is refused. Otherwise the root ancestry is checked,
    /// each observed original must keep its native snapshot and each stored frame its
    /// transport hash, and the root ancestry is closed again.
    fn reuse(&self, root: &PrivateDirectory, transport: &EncodedTransportV1) -> Result<()> {
        if self.failed.load(Ordering::SeqCst)
            || *self.transport != *transport
            || self.metadata.identity().map_err(storage)? != root.identity().map_err(storage)?
        {
            return Err(Failure::code(INVALID));
        }
        self.metadata.revalidate().map_err(storage)?;
        self.wallet
            .revalidate_admitted()
            .map_err(|_| Failure::code(INVALID))?;
        self.metadata.revalidate().map_err(storage)
    }

    fn with_snapshot<T, E>(
        &self,
        body: impl FnOnce(&mut dyn OriginalSourceV1) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<OriginalError>,
    {
        self.metadata
            .revalidate()
            .map_err(|_| E::from(OriginalError::Inventory))?;
        let result = self.wallet.with_snapshot(body);
        // Close metadata ancestry on both success and failure. The wallet's own
        // closing pass checks each captured original against its observed map,
        // which this same reader retains for all later live proof imports.
        self.metadata
            .revalidate()
            .map_err(|_| E::from(OriginalError::Inventory))?;
        result
    }
}
impl OriginalSourceV1 for CatalogOriginals {
    fn open(&mut self, sha256: [u8; 32]) -> std::result::Result<Box<dyn Read + '_>, OriginalError> {
        self.source.open(sha256)
    }
}
impl OriginalSourceV1 for CatalogReader {
    fn open(&mut self, sha256: [u8; 32]) -> std::result::Result<Box<dyn Read + '_>, OriginalError> {
        let opened = self
            .metadata
            .revalidate()
            .map_err(|_| OriginalError::Inventory)
            .and_then(|()| {
                self.roles.get(&sha256).ok_or(OriginalError::Inventory)?;
                self.wallet.open_original(sha256)
            });
        match opened {
            Ok(reader) => Ok(Box::new(Watched {
                reader,
                failed: Arc::clone(&self.failed),
            })),
            Err(error) => {
                self.failed.store(true, Ordering::SeqCst);
                Err(error)
            }
        }
    }
}
/// A live original read: any custody or integrity refusal marks the shared reader failed,
/// so an admitted graph that a live owner found changed is never reused. Bytes and errors
/// pass through unchanged.
struct Watched {
    reader: Box<dyn Read>,
    failed: Arc<AtomicBool>,
}
impl Read for Watched {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(output);
        if read.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        read
    }
}
fn require_metadata_inventory(metadata: &PrivateDirectory) -> Result<()> {
    const NAMES: [&str; 5] = [
        "financial-originals.json",
        "producer-inventory.norito",
        "transport.json",
        "verifier-pack.norito",
        "wallet-originals",
    ];
    let entries = metadata.entries(NAMES.len() + 1).map_err(storage)?;
    if entries.len() != NAMES.len()
        || entries
            .iter()
            .zip(NAMES)
            .any(|(actual, expected)| actual.as_os_str() != std::ffi::OsStr::new(expected))
    {
        return Err(Failure::code(INVALID));
    }
    Ok(())
}
fn storage(error: std::io::Error) -> Failure {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::NotFound
    ) {
        Failure::code(INVALID)
    } else {
        Failure::unavailable(
            UNAVAILABLE,
            advance::KagemushaWalletUnavailableV1::from_io(&error),
        )
    }
}
fn closed(blobs: impl IntoIterator<Item = BlobV1>) -> Result<Vec<BlobV1>> {
    let mut originals = BTreeMap::new();
    for blob in blobs {
        if originals
            .insert(blob.sha256, blob)
            .is_some_and(|previous| previous != blob)
        {
            return Err(Failure::code(INVALID));
        }
    }
    Ok(originals.into_values().collect())
}
fn require_transport(inventory: &ProducerInventoryV1, bytes: &[u8]) -> Result<EncodedTransportV1> {
    let transport = EncodedTransportV1::from_json(bytes).map_err(storage)?;
    let wallet = closed(
        inventory
            .originals
            .iter()
            .flat_map(|r| [r.descriptor, r.verifying_key, r.proving_key]),
    )?;
    if transport
        .originals()
        .iter()
        .map(|row| row.original)
        .ne(wallet)
    {
        return Err(Failure::code(INVALID));
    }
    Ok(transport)
}

#[cfg(test)]
mod tests;
