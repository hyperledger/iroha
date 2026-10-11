//! Bounded immutable registration originals authenticated by the existing native finality owner.
//! Content addresses protect transport custody only. Only actual successful Global Register
//! execution under the independently installed genesis yields the returned asset capability.
use crate::kagemusha_wallet_artifacts_v1::producer_inventory::BlobV1;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::kagemusha_wallet::registration_finality::{
        KagemushaWalletRegistrationDataV1, KagemushaWalletRegistrationErrorV1,
        project_kagemusha_wallet_registration_v1,
    },
    kagemusha::KagemushaWalletSchemeV1,
    query::CommittedTransaction,
    sumeragi_finality::{
        FinalityError, FinalityReadError, MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityCheckpoint,
        SumeragiFinalityProof, SumeragiFinalityVerifier,
    },
};
use iroha_fs::PrivateDirectory;
use std::{
    io::{self, Read as _},
    path::Path,
};

mod builder;
pub use builder::{RegistrationSelectionV1, publish_registration_source_v1};
mod finalized;
pub use finalized::{
    FinalizedKagemushaWalletRegistrationV1, verify_finalized_kagemusha_wallet_registration_v1,
};
#[cfg(test)]
mod native_tests;

/// Whole canonical locator and fixed-size inventory; contains no caller-selected checkpoint.
pub const REGISTRATION_SOURCE_MAX_BYTES_V1: usize = 8192;
/// Complete proof/committed-transaction frame ceiling, with bounded membership/committee overhead.
pub const REGISTRATION_PROOF_MAX_BYTES_V1: usize = MAX_FINALITY_BLOCK_BYTES + 4 * 1024 * 1024;
/// One fixed-size linked inventory entry, independent of the history length.
pub const REGISTRATION_ENTRY_MAX_BYTES_V1: usize = 1024;

/// DATA inventory selecting exact immutable originals, never registration authority.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha.kagemusha.wallet.registration_inventory.v1")]
pub struct RegistrationInventoryV1 {
    /// Exactly version one.
    pub version: u16,
    /// Requested exact registered asset/incarnation/scale digest.
    pub asset_digest: [u8; 32],
    /// Direct Register position in the successful external transaction.
    pub instruction_index: u32,
    /// Exact canonical CommittedTransaction, authenticated only against the final verified block.
    pub committed: BlobV1,
    /// First exact canonical RegistrationEntryV1; its ordinal is one.
    pub first: BlobV1,
    /// Exact number of consecutive proofs, including selected genesis; at least two.
    pub proof_count: u64,
}
/// DATA link naming one proof and the exact next link; the terminal link must be absent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha.kagemusha.wallet.registration_entry.v1")]
pub struct RegistrationEntryV1 {
    /// Exactly version one.
    pub version: u16,
    /// Consecutive authenticated height, beginning at one.
    pub ordinal: u64,
    /// Original canonical native SumeragiFinalityProof.
    pub proof: BlobV1,
    /// Exact next entry, or None precisely at the declared final proof.
    pub next: Option<BlobV1>,
}
/// Bounded local transport DATA supplied separately from the signed application release.
/// Every child name is a content hash; no per-role or per-token path is accepted.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.wallet.registration_source.v1")]
pub struct RegistrationSourceV1 {
    /// Exactly version one.
    pub version: u16,
    /// Existing absolute owner-private directory, never created or repaired during admission.
    pub originals_root: String,
    /// Fixed-size DATA inventory; all bytes are authenticated by native verification below.
    pub inventory: RegistrationInventoryV1,
}
/// Admission failure preserves absent originals, temporary I/O, and corrupt custody distinctly.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationErrorV1 {
    /// An explicitly named required immutable original is initially absent.
    #[error("required registration original is absent")]
    Absent,
    /// Genuine native I/O unavailability; this never grants permission to recreate custody.
    #[error("registration original storage unavailable: {0}")]
    Unavailable(io::Error),
    /// Native custody, immutable identity, content address or exact extent changed.
    #[error("registration original custody refused: {0}")]
    Custody(&'static str),
    /// Noncanonical, malformed, out-of-order or foreign source DATA.
    #[error("invalid registration original: {0}")]
    Invalid(&'static str),
    /// Native finality read or verification failed; original decoder resource causes remain typed.
    #[error(transparent)]
    Finality(#[from] FinalityReadError),
    /// Actual successful instruction extraction failed.
    #[error(transparent)]
    Registration(#[from] KagemushaWalletRegistrationErrorV1),
    /// Caller cancellation stopped bounded progress without producing an asset capability.
    #[error("registration source read cancelled")]
    Cancelled,
}
impl From<FinalityError> for RegistrationErrorV1 {
    fn from(error: FinalityError) -> Self {
        Self::Finality(error.into())
    }
}
fn storage(error: io::Error) -> RegistrationErrorV1 {
    #[cfg(unix)]
    if error.raw_os_error().is_some_and(|code| {
        code == rustix::io::Errno::LOOP.raw_os_error()
            || code == rustix::io::Errno::NOTDIR.raw_os_error()
    }) {
        return RegistrationErrorV1::Custody("private source object kind changed");
    }
    if matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::PermissionDenied
    ) || error.raw_os_error().is_none()
    {
        RegistrationErrorV1::Custody("private source identity or access changed")
    } else {
        RegistrationErrorV1::Unavailable(error)
    }
}
fn length(blob: BlobV1, maximum: usize) -> Result<usize, RegistrationErrorV1> {
    let length =
        usize::try_from(blob.bytes).map_err(|_| RegistrationErrorV1::Invalid("original extent"))?;
    if length == 0 || length > maximum || blob.sha256 == [0; 32] {
        return Err(RegistrationErrorV1::Invalid("original bound or hash"));
    }
    Ok(length)
}
impl RegistrationSourceV1 {
    /// Validate bounded canonical DATA; no ledger or application authority is produced.
    /// # Errors
    /// Rejects unsupported version, invalid path/inventory or unbounded declared originals.
    pub fn validate(&self) -> Result<(), RegistrationErrorV1> {
        let path = Path::new(&self.originals_root);
        if self.version != 1
            || self.inventory.version != 1
            || self.originals_root.is_empty()
            || self.originals_root.len() > 4096
            || self.originals_root.contains('\0')
            || !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || self.inventory.asset_digest == [0; 32]
            || self.inventory.proof_count < 2
        {
            return Err(RegistrationErrorV1::Invalid("source inventory"));
        }
        length(self.inventory.first, REGISTRATION_ENTRY_MAX_BYTES_V1)?;
        length(self.inventory.committed, REGISTRATION_PROOF_MAX_BYTES_V1)?;
        Ok(())
    }
    /// Encode one validated bounded canonical source locator.
    /// # Errors
    /// Invalid DATA, codec failure or oversized frame.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, RegistrationErrorV1> {
        self.validate()?;
        let bytes = norito::encode_canonical(self)
            .map_err(|_| RegistrationErrorV1::Invalid("source encoding"))?;
        if bytes.len() > REGISTRATION_SOURCE_MAX_BYTES_V1 {
            return Err(RegistrationErrorV1::Invalid("source bound"));
        }
        Ok(bytes)
    }
    /// Decode one complete canonical source locator within the fixed cap.
    /// # Errors
    /// Empty, excessive, trailing, noncanonical or invalid DATA.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RegistrationErrorV1> {
        if bytes.is_empty() || bytes.len() > REGISTRATION_SOURCE_MAX_BYTES_V1 {
            return Err(RegistrationErrorV1::Invalid("source bound"));
        }
        let source: Self = decode(bytes)?;
        source.validate()?;
        Ok(source)
    }
}
fn decode<T: norito::core::NoritoSerialize + for<'a> norito::core::NoritoDeserialize<'a>>(
    bytes: &[u8],
) -> Result<T, RegistrationErrorV1> {
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| RegistrationErrorV1::Invalid("canonical frame"))
}
fn read_original(
    directory: &PrivateDirectory,
    blob: BlobV1,
    maximum: usize,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, RegistrationErrorV1> {
    let size = length(blob, maximum)?;
    directory.revalidate().map_err(storage)?;
    let mut file = directory
        .open_retained_read_only_optional(hex::encode(blob.sha256), maximum)
        .map_err(storage)?
        .ok_or(RegistrationErrorV1::Absent)?;
    let snapshot = file.snapshot().map_err(storage)?;
    if file.len().map_err(storage)? != blob.bytes {
        return Err(RegistrationErrorV1::Custody("original extent"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| {
        RegistrationErrorV1::Unavailable(io::Error::other("registration allocation unavailable"))
    })?;
    let mut buffer = [0_u8; 65536];
    while bytes.len() < size {
        if cancelled() {
            return Err(RegistrationErrorV1::Cancelled);
        }
        file.revalidate().map_err(storage)?;
        let maximum = (size - bytes.len()).min(buffer.len());
        let read = file.read(&mut buffer[..maximum]);
        file.revalidate().map_err(storage)?;
        directory.revalidate().map_err(storage)?;
        let count = read.map_err(RegistrationErrorV1::Unavailable)?;
        if count == 0 {
            return Err(RegistrationErrorV1::Custody("truncated original"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let mut extra = [0_u8; 1];
    let last_read = file.read(&mut extra);
    file.revalidate().map_err(storage)?;
    directory.revalidate().map_err(storage)?;
    if file.snapshot().map_err(storage)? != snapshot || BlobV1::of(&bytes) != blob {
        return Err(RegistrationErrorV1::Custody(
            "changed or substituted original",
        ));
    }
    if last_read.map_err(RegistrationErrorV1::Unavailable)? != 0 {
        return Err(RegistrationErrorV1::Custody("extended original"));
    }
    directory.revalidate().map_err(storage)?;
    Ok(bytes)
}

/// Authenticate an arbitrary-length prefix with bounded per-original memory and native checkpoints.
/// Only the independently installed genesis owner seeds verification. Every checkpoint below is
/// produced in this call by the native verifier; caller checkpoints are not accepted. No native
/// platform, wallet slot, provider or signing key is acquired while processing these public originals.
/// # Errors
/// Refuses invalid scope, missing/unavailable/changed originals, malformed inventory links,
/// cancelled work, failed native finality or anything other than exact successful Global Register.
pub fn verify_registration_source_v1(
    source: &RegistrationSourceV1,
    genesis: &SumeragiFinalityVerifier,
    scheme: &KagemushaWalletSchemeV1,
    mut cancelled: impl FnMut() -> bool,
) -> Result<FinalizedKagemushaWalletRegistrationV1, RegistrationErrorV1> {
    source.validate()?;
    scheme
        .validate()
        .map_err(|_| RegistrationErrorV1::Invalid("selected scheme"))?;
    let network = genesis.initial_epoch().network_id;
    if genesis.root_scope() != SumeragiRootScope::Global || scheme.network_id != *network.as_bytes()
    {
        return Err(RegistrationErrorV1::Invalid("selected global network"));
    }
    let directory = PrivateDirectory::open_exact(&source.originals_root).map_err(storage)?;
    let mut selected = source.inventory.first;
    let mut cursor: Option<SumeragiFinalityCheckpoint> = None;
    for ordinal in 1..=source.inventory.proof_count {
        if cancelled() {
            return Err(RegistrationErrorV1::Cancelled);
        }
        let entry: RegistrationEntryV1 = decode(&read_original(
            &directory,
            selected,
            REGISTRATION_ENTRY_MAX_BYTES_V1,
            &mut cancelled,
        )?)?;
        if entry.version != 1
            || entry.ordinal != ordinal
            || entry.next.is_some() != (ordinal < source.inventory.proof_count)
        {
            return Err(RegistrationErrorV1::Invalid(
                "entry count, ordinal or terminal link",
            ));
        }
        if let Some(next) = entry.next {
            length(next, REGISTRATION_ENTRY_MAX_BYTES_V1)?;
        }
        let proof: SumeragiFinalityProof = decode(&read_original(
            &directory,
            entry.proof,
            REGISTRATION_PROOF_MAX_BYTES_V1,
            &mut cancelled,
        )?)?;
        if proof.height() != ordinal
            || proof.committee.len() > 31
            || proof.block_wire.len() > MAX_FINALITY_BLOCK_BYTES
        {
            return Err(RegistrationErrorV1::Invalid(
                "proof height or decoded bound",
            ));
        }
        let mut verifier = match &cursor {
            Some(checkpoint) => SumeragiFinalityVerifier::from_trusted_checkpoint(
                checkpoint,
                &network,
                genesis.chain_id(),
            )?,
            None => genesis.clone(),
        };
        let verified = if ordinal == 1 {
            match verifier.verify_retained_decision(&proof) {
                Ok(value) => value,
                Err(_) => verifier.verify(&proof)?,
            }
        } else {
            verifier.verify(&proof)?
        };
        if ordinal == source.inventory.proof_count {
            let committed: CommittedTransaction = decode(&read_original(
                &directory,
                source.inventory.committed,
                REGISTRATION_PROOF_MAX_BYTES_V1,
                &mut cancelled,
            )?)?;
            let result = verify_finalized_kagemusha_wallet_registration_v1(
                &verified,
                &committed,
                network,
                genesis.chain_id(),
                scheme,
                source.inventory.asset_digest,
                usize::try_from(source.inventory.instruction_index)
                    .map_err(|_| RegistrationErrorV1::Invalid("instruction index"))?,
            )?;
            directory.revalidate().map_err(storage)?;
            if cancelled() {
                return Err(RegistrationErrorV1::Cancelled);
            }
            return Ok(result);
        }
        cursor = Some(verifier.export_checkpoint(&proof)?);
        selected = entry
            .next
            .ok_or(RegistrationErrorV1::Invalid("missing next link"))?;
    }
    Err(RegistrationErrorV1::Invalid(
        "missing terminal registration",
    ))
}
#[cfg(test)]
mod tests;
