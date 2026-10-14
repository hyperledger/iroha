//! Read-only actual source directories routed only by the authenticated complete catalog.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    AuthenticatedProducerInventoryV1, EncodedDirectoryOriginalsV1, EncodedTransportV1,
    PROVING_KEY_MAX_BYTES_V1, ProducerInventoryV1,
};
use iroha_core_zk::kagemusha_wallet_proofs_v1::Error as OriginalError;
use iroha_fs::PrivateDirectory;
use std::{io::Read, path::Path};

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

impl CatalogOriginals {
    pub(super) fn from_authenticated(
        authenticated: &AuthenticatedProducerInventoryV1,
        root: &[u8],
        pack: &[u8],
        catalog: &[u8],
        selected: Arc<selection::AuthenticatedBase>,
    ) -> Result<Self> {
        let inventory = authenticated.inventory();
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
        let transport = require_transport(inventory, &transport)?;
        let source = CatalogReader::open(metadata, root, inventory, &transport)?;
        Ok(Self {
            _selected: selected,
            source,
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
        })
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
        self.metadata
            .revalidate()
            .map_err(|_| OriginalError::Inventory)?;
        self.roles.get(&sha256).ok_or(OriginalError::Inventory)?;
        self.wallet.open_original(sha256)
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
