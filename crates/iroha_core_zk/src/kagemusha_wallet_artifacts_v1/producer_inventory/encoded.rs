//! Lossless mobile carrier DATA. Signed identities always name decoded originals.
//!
//! The storage envelope grants no source authority. Every read retains no-follow
//! custody and checks both identities; native source qualification remains required.
//! Raw compiler inputs have a separate owner and are never a mobile fallback.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{self, BufRead as _, BufReader, Read, Write},
    path::Path,
    sync::Mutex,
};

use iroha_fs::{FileSnapshot, PendingPrivateFile, PrivateDirectory, SealedPrivateFile};
use rand::rand_core::TryRngCore as _;
use sha2::{Digest as _, Sha256};

use super::{
    ARTIFACT_MAX_COUNT_V1, BlobV1, CATALOG_MAX_BYTES_V1, DirectoryOriginalsV1, Error,
    OriginalCustodyFailure, OriginalSourceV1, PROVING_KEY_MAX_BYTES_V1,
};
use crate::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1, artifact_digest,
};

/// Absolute encoded-file ceiling, including bounded zstd overhead.
pub const ENCODED_ORIGINAL_MAX_BYTES_V1: usize = PROVING_KEY_MAX_BYTES_V1 + (4 << 20);
/// Closed original transport JSON ceiling.
pub const TRANSPORT_MAX_BYTES_V1: usize = 32 << 20;
const ROWS: usize = ARTIFACT_MAX_COUNT_V1 * 3;
const WINDOW_LOG: u32 = 23;
const SCHEMA: &str = "iroha.kagemusha.wallet-artifact-original-transport.v1";

#[path = "encoded/snapshot.rs"]
mod snapshot;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn custody(error: io::Error) -> io::Error {
    io::Error::other(OriginalCustodyFailure(error))
}

/// Raw signed identity and physical identity of its single bounded zstd frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedOriginalV1 {
    /// Actual original selected by the authenticated producer catalog.
    pub original: BlobV1,
    /// Exact compressed file retained under the raw original's hexadecimal address.
    pub stored: BlobV1,
}

impl EncodedOriginalV1 {
    fn validate(self) -> io::Result<()> {
        if self.original.bytes == 0
            || self.original.bytes > PROVING_KEY_MAX_BYTES_V1 as u64
            || self.stored.bytes == 0
            || self.stored.bytes > ENCODED_ORIGINAL_MAX_BYTES_V1 as u64
            || self.original.sha256 == [0; 32]
            || self.stored.sha256 == [0; 32]
        {
            return Err(invalid("encoded original identity exceeds bounds"));
        }
        Ok(())
    }
}

/// Canonical transport metadata only; no signature, source or installation grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedTransportV1 {
    originals: Vec<EncodedOriginalV1>,
}

impl EncodedTransportV1 {
    /// Validate the nonempty, unique ascending raw-address closure.
    /// # Errors
    /// Excessive rows, unsorted/duplicate addresses or invalid finite identities.
    pub fn new(originals: Vec<EncodedOriginalV1>) -> io::Result<Self> {
        if originals.is_empty() || originals.len() > ROWS {
            return Err(invalid("encoded transport row bound"));
        }
        let mut previous = None;
        for row in &originals {
            row.validate()?;
            if previous.is_some_and(|digest| digest >= row.original.sha256) {
                return Err(invalid("encoded transport is not uniquely ascending"));
            }
            previous = Some(row.original.sha256);
        }
        Ok(Self { originals })
    }

    /// Exact ascending raw/stored metadata; the catalog must independently select it.
    pub fn originals(&self) -> &[EncodedOriginalV1] {
        &self.originals
    }

    /// Encode the mandatory current representation with one final LF.
    pub fn to_json(&self) -> Vec<u8> {
        let mut output =
            format!("{{\"schema\":\"{SCHEMA}\",\"encoding\":\"zstd\",\"walletOriginals\":[");
        for (index, row) in self.originals.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            write!(
                output,
                "{{\"bytes\":{},\"sha256\":\"{}\",\"storedBytes\":{},\"storedSha256\":\"{}\"}}",
                row.original.bytes,
                hex::encode(row.original.sha256),
                row.stored.bytes,
                hex::encode(row.stored.sha256)
            )
            .expect("writing to a String is infallible");
        }
        output.push_str("]}\n");
        output.into_bytes()
    }

    /// Decode only the exact closed canonical zstd representation, with bounded JSON work.
    /// # Errors
    /// Raw/unknown representation, unknown fields, unsafe extents, duplicate identities,
    /// noncanonical order, whitespace, numeric spelling, or excessive JSON complexity.
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        use norito::json::{JsonPreflightLimits, Value};
        let limits = JsonPreflightLimits::new(
            TRANSPORT_MAX_BYTES_V1,
            ROWS * 5 + 8,
            512,
            128,
            TRANSPORT_MAX_BYTES_V1,
            ROWS,
            ROWS,
            ROWS * 4 + 4,
            ROWS * 5 + 4,
            4,
        );
        norito::json::preflight_slice(bytes, limits)
            .map_err(|_| invalid("transport JSON limits"))?;
        let value: Value =
            norito::json::from_slice(bytes).map_err(|_| invalid("transport JSON"))?;
        let object = value
            .as_object()
            .ok_or_else(|| invalid("transport object"))?;
        if object.len() != 3
            || object.get("schema").and_then(Value::as_str) != Some(SCHEMA)
            || object.get("encoding").and_then(Value::as_str) != Some("zstd")
        {
            return Err(invalid("mandatory encoded transport schema"));
        }
        let rows = object
            .get("walletOriginals")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("transport rows"))?;
        let mut originals = Vec::with_capacity(rows.len());
        for row in rows {
            let row = row.as_object().ok_or_else(|| invalid("transport row"))?;
            if row.len() != 4 {
                return Err(invalid("closed encoded row required"));
            }
            let length = |key| {
                row.get(key)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("transport byte length"))
            };
            let hash = |key| -> io::Result<[u8; 32]> {
                let text = row
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("transport hash"))?;
                if text.len() != 64
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid("canonical SHA-256 required"));
                }
                hex::decode(text)
                    .map_err(|_| invalid("transport hash"))?
                    .try_into()
                    .map_err(|_| invalid("transport hash extent"))
            };
            originals.push(EncodedOriginalV1 {
                original: BlobV1 {
                    bytes: length("bytes")?,
                    sha256: hash("sha256")?,
                },
                stored: BlobV1 {
                    bytes: length("storedBytes")?,
                    sha256: hash("storedSha256")?,
                },
            });
        }
        let result = Self::new(originals)?;
        if result.to_json() != bytes {
            return Err(invalid("canonical encoded transport required"));
        }
        Ok(result)
    }
}

trait StoredSource: Read {
    fn recheck(&self) -> io::Result<()>;
}

impl StoredSource for SealedPrivateFile {
    fn recheck(&self) -> io::Result<()> {
        self.revalidate()
    }
}

struct StoredReader<R = SealedPrivateFile> {
    file: R,
    expected: BlobV1,
    hash: Sha256,
    bytes: u64,
}

impl<R: StoredSource> StoredReader<R> {
    fn recheck(&self) -> io::Result<()> {
        // The immutable retained baseline already contains every snapshot field.
        // Keep this fence even for buffered decoded output, without rebuilding
        // a second snapshot and repeating the native custody checks twice.
        self.file.recheck()
    }
    fn finish(&self) -> io::Result<()> {
        self.recheck()?;
        let hash: [u8; 32] = self.hash.clone().finalize().into();
        if self.bytes != self.expected.bytes || hash != self.expected.sha256 {
            return Err(invalid("encoded original length or hash mismatch"));
        }
        Ok(())
    }
}
impl<R: StoredSource> Read for StoredReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.recheck()?;
        let result = self.file.read(output);
        self.recheck()?;
        let count = result?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("stored length overflow"))?;
        if self.bytes > self.expected.bytes {
            return Err(invalid("extended encoded original"));
        }
        self.hash.update(&output[..count]);
        Ok(count)
    }
}

type Decoder<R> = zstd::stream::read::Decoder<'static, BufReader<StoredReader<R>>>;
struct DecodedOriginal<R = SealedPrivateFile> {
    decoder: Option<Decoder<R>>,
    expected: BlobV1,
    hash: Sha256,
    bytes: u64,
    failed: bool,
}
impl<R: StoredSource> DecodedOriginal<R> {
    fn read_checked(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(invalid("encoded reader already refused"));
        }
        if output.is_empty() {
            return Ok(0);
        }
        let Some(decoder) = self.decoder.as_mut() else {
            return Ok(0);
        };
        // Recheck even when the decoder satisfies this read from its own buffers.
        decoder.get_ref().get_ref().recheck()?;
        let bound = output.len().min(
            usize::try_from(self.expected.bytes - self.bytes + 1)
                .map_err(|_| invalid("decoded remaining extent"))?,
        );
        let count = decoder.read(&mut output[..bound])?;
        decoder.get_ref().get_ref().recheck()?;
        self.bytes += count as u64;
        if self.bytes > self.expected.bytes {
            return Err(invalid("decoded original exceeds signed extent"));
        }
        self.hash.update(&output[..count]);
        if count == 0 || self.bytes == self.expected.bytes {
            // Close the entire frame before returning the final declared original byte.
            let mut excess = [0_u8; 1];
            if count != 0 && decoder.read(&mut excess)? != 0 {
                return Err(invalid("decoded original exceeds signed extent"));
            }
            let mut stored = self
                .decoder
                .take()
                .ok_or_else(|| invalid("decoder state"))?
                .finish();
            if !stored.fill_buf()?.is_empty() {
                return Err(invalid("trailing bytes or additional zstd frame"));
            }
            stored.get_ref().finish()?;
            let hash: [u8; 32] = self.hash.clone().finalize().into();
            if self.bytes != self.expected.bytes || hash != self.expected.sha256 {
                return Err(invalid("decoded original length or hash mismatch"));
            }
        }
        Ok(count)
    }
}
impl<R: StoredSource> Read for DecodedOriginal<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.read_checked(output).map_err(|error| {
            self.failed = true;
            custody(error)
        })
    }
}

fn decode_stored<R: StoredSource>(
    file: R,
    identity: EncodedOriginalV1,
) -> io::Result<DecodedOriginal<R>> {
    let stored = StoredReader {
        file,
        expected: identity.stored,
        hash: Sha256::new(),
        bytes: 0,
    };
    stored.recheck()?;
    let mut buffered = BufReader::with_capacity(64 << 10, stored);
    if buffered.fill_buf()?.get(..4) != Some(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(invalid("one standard zstd frame required"));
    }
    let mut decoder = zstd::stream::read::Decoder::with_buffer(buffered)?.single_frame();
    decoder.window_log_max(WINDOW_LOG)?;
    Ok(DecodedOriginal {
        decoder: Some(decoder),
        expected: identity.original,
        hash: Sha256::new(),
        bytes: 0,
        failed: false,
    })
}

/// Existing immutable mobile source, retaining native ancestry and encoded metadata.
/// Decoded bytes are streamed in memory; there is no decoded disk cache or raw fallback.
pub struct EncodedDirectoryOriginalsV1 {
    directory: PrivateDirectory,
    originals: BTreeMap<[u8; 32], EncodedOriginalV1>,
    observed: Mutex<BTreeMap<[u8; 32], FileSnapshot>>,
}
impl EncodedDirectoryOriginalsV1 {
    /// Retain the exact private directory. Metadata is DATA until independently selected.
    /// # Errors
    /// Unsafe ancestry, invalid original closure or native storage failure.
    pub fn open_existing(
        path: impl AsRef<Path>,
        transport: &EncodedTransportV1,
    ) -> io::Result<Self> {
        Ok(Self {
            directory: PrivateDirectory::open_exact(path)?,
            originals: transport
                .originals
                .iter()
                .map(|row| (row.original.sha256, *row))
                .collect(),
            observed: Mutex::new(BTreeMap::new()),
        })
    }
    fn retained_file(
        &self,
        digest: [u8; 32],
    ) -> io::Result<Option<(SealedPrivateFile, FileSnapshot)>> {
        self.directory.revalidate()?;
        let identity = self
            .originals
            .get(&digest)
            .ok_or_else(|| invalid("original outside transport"))?;
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| invalid("original custody ownership poisoned"))?;
        let Some(file) = self
            .directory
            .open_retained_read_only_optional(hex::encode(digest), ENCODED_ORIGINAL_MAX_BYTES_V1)?
        else {
            if observed.contains_key(&digest) {
                return Err(invalid("retained encoded original disappeared"));
            }
            return Ok(None);
        };
        if file.len()? != identity.stored.bytes {
            return Err(invalid("encoded file extent differs"));
        }
        let snapshot = file.snapshot()?;
        if observed
            .get(&digest)
            .is_some_and(|previous| *previous != snapshot)
        {
            return Err(invalid("retained encoded original was replaced or changed"));
        }
        observed.insert(digest, snapshot);
        drop(observed);
        Ok(Some((file, snapshot)))
    }

    fn reader(&self, digest: [u8; 32]) -> io::Result<Option<DecodedOriginal>> {
        let Some((file, _)) = self.retained_file(digest)? else {
            return Ok(None);
        };
        let identity = *self
            .originals
            .get(&digest)
            .ok_or_else(|| invalid("original outside transport"))?;
        let decoded = decode_stored(file, identity)?;
        self.directory.revalidate()?;
        Ok(Some(decoded))
    }

    /// Open a bounded owned decoder that retains sealed source custody on every read.
    /// # Errors
    /// Absent initial original is unavailable; malformed or changed custody is invalid.
    pub fn open_original(&self, digest: [u8; 32]) -> Result<Box<dyn Read>, Error> {
        self.reader(digest)
            .map_err(|_| Error::Inventory)?
            .ok_or(Error::Unavailable)
            .map(|reader| -> Box<dyn Read> { Box::new(reader) })
    }

    /// Verify both whole identities through a bounded stream and synchronize ancestry.
    /// # Errors
    /// Wrong raw identity, missing/changed file, invalid encoding, bounds, either hash
    /// or scratch allocation failure.
    pub fn verify_original(&self, identity: BlobV1) -> io::Result<()> {
        if self.originals.get(&identity.sha256).map(|row| row.original) != Some(identity) {
            return Err(invalid("original differs from selected transport"));
        }
        let mut reader = self
            .reader(identity.sha256)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let mut buffer = super::original_stream_buffer()?;
        while reader
            .read(&mut buffer)
            .map_err(|_| invalid("encoded original custody or integrity failure"))?
            != 0
        {}
        self.directory.sync()?;
        self.directory.revalidate()
    }
}
impl OriginalSourceV1 for EncodedDirectoryOriginalsV1 {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.open_original(digest)
    }
}

struct StoredWriter {
    file: PendingPrivateFile,
    hash: Sha256,
    bytes: u64,
}
impl Write for StoredWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.file.write(bytes)?;
        self.hash.update(&bytes[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Encode and immutably publish one original using the fixed mobile representation.
/// This helper cannot choose a catalog; callers independently authenticate identities.
/// # Errors
/// Changed raw source, conflicting encoded destination, resource or custody failure.
pub fn encode_original(
    source: &DirectoryOriginalsV1,
    destination: &PrivateDirectory,
    identity: BlobV1,
) -> io::Result<EncodedOriginalV1> {
    if identity.bytes == 0
        || identity.bytes > PROVING_KEY_MAX_BYTES_V1 as u64
        || identity.sha256 == [0; 32]
    {
        return Err(invalid("raw encoding identity bound"));
    }
    let mut input = source
        .open_original(identity.sha256)
        .map_err(io::Error::other)?;
    let mut nonce = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(io::Error::other)?;
    let file = destination.create_retained_private(
        format!("encoded-{}.partial", hex::encode(nonce)),
        ENCODED_ORIGINAL_MAX_BYTES_V1,
    )?;
    let mut encoder = zstd::stream::write::Encoder::new(
        StoredWriter {
            file,
            hash: Sha256::new(),
            bytes: 0,
        },
        1,
    )?;
    encoder.window_log(WINDOW_LOG)?;
    encoder.include_checksum(true)?;
    encoder.set_pledged_src_size(Some(identity.bytes))?;
    let mut total = 0_u64;
    let mut hash = Sha256::new();
    let mut buffer = super::original_stream_buffer()?;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > identity.bytes {
            return Err(invalid("raw source extended while encoding"));
        }
        hash.update(&buffer[..count]);
        encoder.write_all(&buffer[..count])?;
    }
    let actual: [u8; 32] = hash.finalize().into();
    if total != identity.bytes || actual != identity.sha256 {
        return Err(invalid("raw source differs while encoding"));
    }
    let writer = encoder.finish()?;
    let transport_identity = EncodedOriginalV1 {
        original: identity,
        stored: BlobV1 {
            bytes: writer.bytes,
            sha256: writer.hash.finalize().into(),
        },
    };
    transport_identity.validate()?;
    let sealed = writer.file.seal_read_only()?;
    match sealed.publish_new_name(hex::encode(identity.sha256)) {
        Ok(file) => file.revalidate()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let transport = EncodedTransportV1::new(vec![transport_identity])?;
    EncodedDirectoryOriginalsV1::open_existing(destination.path(), &transport)?
        .verify_original(identity)?;
    source.root()?;
    Ok(transport_identity)
}

/// Repackage a pinned signed carrier as bounded encoded DATA without changing its proofs.
/// The destination must already be an empty exact private directory (or an exact retry).
/// Pack/catalog signatures and every raw/stored original are checked. This does not admit
/// genesis, run source reconstruction, sign a runtime, or grant wallet installation.
/// # Errors
/// Invalid signed selection, changed source, conflicting destination or bounded I/O failure.
pub fn encode_wallet_carrier_v1(
    pack: &[u8],
    catalog: &[u8],
    installation: InstallationV1,
    raw: &DirectoryOriginalsV1,
    destination: impl AsRef<Path>,
) -> io::Result<()> {
    let installed = InstalledVerifierPackV1::load(pack, installation).map_err(io::Error::other)?;
    let authenticated = installed
        .authenticate_producer_inventory(catalog)
        .map_err(io::Error::other)?;
    let mut identities = BTreeMap::new();
    for record in &authenticated.inventory().originals {
        for blob in [record.descriptor, record.verifying_key, record.proving_key] {
            if identities
                .insert(blob.sha256, blob)
                .is_some_and(|previous| previous != blob)
            {
                return Err(invalid("conflicting authenticated original extents"));
            }
        }
    }
    let root = PrivateDirectory::open_exact(destination)?;
    require_carrier_entries(&root, false)?;
    if root.path().starts_with(raw.root()?) || raw.root()?.starts_with(root.path()) {
        return Err(invalid(
            "encoded output must be separate from raw source custody",
        ));
    }
    root.ensure_child("wallet-originals")?;
    let target = PrivateDirectory::open_exact(root.path().join("wallet-originals"))?;
    let mut originals = Vec::with_capacity(identities.len());
    for identity in identities.into_values() {
        originals.push(encode_original(raw, &target, identity)?);
    }
    let transport = EncodedTransportV1::new(originals)?.to_json();
    let financial = financial_json(pack, catalog, &transport)?;
    for (name, bytes) in [
        ("verifier-pack.norito", pack),
        ("producer-inventory.norito", catalog),
        ("transport.json", &transport),
        ("financial-originals.json", &financial),
    ] {
        super::transport_metadata::publish_metadata(&root, name, bytes)?;
    }
    raw.root()?;
    target.revalidate()?;
    require_carrier_entries(&root, true)?;
    root.sync()?;
    root.revalidate()
}

fn require_carrier_entries(root: &PrivateDirectory, complete: bool) -> io::Result<()> {
    const NAMES: [&str; 5] = [
        "financial-originals.json",
        "producer-inventory.norito",
        "transport.json",
        "verifier-pack.norito",
        "wallet-originals",
    ];
    let entries = root.entries(NAMES.len() + 1)?;
    if (complete && entries.len() != NAMES.len())
        || entries.iter().any(|entry| {
            !NAMES
                .iter()
                .any(|name| entry.as_os_str() == std::ffi::OsStr::new(name))
        })
    {
        return Err(invalid(
            "encoded carrier must contain exactly the five named roles",
        ));
    }
    Ok(())
}

pub(super) fn financial_json(pack: &[u8], catalog: &[u8], transport: &[u8]) -> io::Result<Vec<u8>> {
    if pack.is_empty()
        || pack.len() > VERIFIER_PACK_MAX_BYTES_V1
        || catalog.is_empty()
        || catalog.len() > CATALOG_MAX_BYTES_V1
        || transport.is_empty()
        || transport.len() > TRANSPORT_MAX_BYTES_V1
    {
        return Err(invalid("financial metadata bounds"));
    }
    let digest = artifact_digest(b"producer-catalog", catalog);
    let pack = BlobV1::of(pack);
    let catalog = BlobV1::of(catalog);
    let transport = BlobV1::of(transport);
    Ok(format!("{{\"producerCatalogDigest\":\"{}\",\"producerInventory\":{{\"bytes\":{},\"sha256\":\"{}\"}},\"schema\":\"iroha.kagemusha.wallet-financial-originals.v1\",\"transport\":{{\"bytes\":{},\"sha256\":\"{}\"}},\"verifierPack\":{{\"bytes\":{},\"sha256\":\"{}\"}}}}\n",
        hex::encode(digest), catalog.bytes, hex::encode(catalog.sha256), transport.bytes,
        hex::encode(transport.sha256), pack.bytes, hex::encode(pack.sha256)).into_bytes())
}

#[cfg(test)]
#[path = "encoded/tests.rs"]
mod tests;
