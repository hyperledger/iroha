//! Deterministic operator-side packaging of public, authenticated registration originals.
use super::*;
use std::io::{Read, Write as _};

/// Independently selected native trust and the exact requested registration scope.
#[derive(Clone, Copy)]
pub struct RegistrationSelectionV1<'a> {
    /// Authenticated installed genesis; no caller-created checkpoint is accepted.
    pub genesis: &'a SumeragiFinalityVerifier,
    /// Independently authenticated application scheme original.
    pub scheme: &'a KagemushaWalletSchemeV1,
    /// Exact token/incarnation/scale requested by the operator.
    pub asset_digest: [u8; 32],
    /// Direct Register position in the final committed transaction.
    pub instruction_index: u32,
}
fn input(
    mut reader: impl Read,
    maximum: usize,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, RegistrationErrorV1> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 65536];
    loop {
        if cancelled() {
            return Err(RegistrationErrorV1::Cancelled);
        }
        let count = reader
            .read(&mut chunk)
            .map_err(RegistrationErrorV1::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|size| size > maximum)
        {
            return Err(RegistrationErrorV1::Invalid("input frame bound"));
        }
        bytes.try_reserve(count).map_err(|_| {
            RegistrationErrorV1::Unavailable(io::Error::other(
                "registration allocation unavailable",
            ))
        })?;
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.is_empty() {
        return Err(RegistrationErrorV1::Invalid("empty input"));
    }
    Ok(bytes)
}
fn put(
    directory: &PrivateDirectory,
    bytes: &[u8],
    maximum: usize,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<BlobV1, RegistrationErrorV1> {
    let blob = BlobV1::of(bytes);
    length(blob, maximum)?;
    match read_original(directory, blob, maximum, cancelled) {
        Ok(existing) if existing == bytes => return Ok(blob),
        Ok(_) => return Err(RegistrationErrorV1::Custody("content address collision")),
        Err(RegistrationErrorV1::Absent) => {}
        Err(error) => return Err(error),
    }
    let mut writer = directory
        .create_retained_private(hex::encode(blob.sha256), maximum)
        .map_err(storage)?;
    for chunk in bytes.chunks(65536) {
        if cancelled() {
            return Err(RegistrationErrorV1::Cancelled);
        }
        writer.write_all(chunk).map_err(storage)?;
    }
    writer.seal_read_only().map_err(storage)?;
    directory.revalidate().map_err(storage)?;
    Ok(blob)
}

/// Publish a new immutable package using bounded readers of already available ledger originals.
///
/// Proof readers are ordered from genesis through the registration block. A double-ended iterator
/// permits reverse hash-link construction without retaining the prefix in RAM; an operator can
/// map a range of ordinal filenames to readers. The finished transport is then verified forwards
/// by the existing native verifier. Only after actual successful Register authentication is the
/// canonical `registration-source.norito` sealed in the new output child. Content and inventory
/// hashes are deterministic; the locator contains this deployment's absolute output path.
///
/// This API never broadens transaction-query visibility, signs, registers an asset or regenerates
/// proofs. The asset/reserve owner supplies originals through existing authenticated exports.
/// Partial failed output remains for inspection and cannot be reused or replaced by this API.
/// # Errors
/// Refuses existing output, unsafe custody, oversized/malformed/foreign originals, invalid
/// finality or registration, I/O unavailability and cancellation. No source locator is published
/// before verification; an uncertain final publication must be recovered from its exact bytes.
pub fn publish_registration_source_v1<R: Read>(
    parent: &PrivateDirectory,
    output_name: &str,
    selection: RegistrationSelectionV1<'_>,
    committed: impl Read,
    proofs: impl DoubleEndedIterator<Item = io::Result<R>> + ExactSizeIterator,
    mut cancelled: impl FnMut() -> bool,
) -> Result<(RegistrationSourceV1, FinalizedKagemushaWalletRegistrationV1), RegistrationErrorV1> {
    let count =
        u64::try_from(proofs.len()).map_err(|_| RegistrationErrorV1::Invalid("proof count"))?;
    if count < 2 || selection.asset_digest == [0; 32] {
        return Err(RegistrationErrorV1::Invalid("registration selection"));
    }
    selection
        .scheme
        .validate()
        .map_err(|_| RegistrationErrorV1::Invalid("selected scheme"))?;
    if cancelled() {
        return Err(RegistrationErrorV1::Cancelled);
    }
    let output = parent.create_child(output_name).map_err(storage)?;
    let originals = output.create_child("originals").map_err(storage)?;
    let committed_bytes = input(committed, REGISTRATION_PROOF_MAX_BYTES_V1, &mut cancelled)?;
    let _: CommittedTransaction = decode(&committed_bytes)?;
    let committed = put(
        &originals,
        &committed_bytes,
        REGISTRATION_PROOF_MAX_BYTES_V1,
        &mut cancelled,
    )?;
    drop(committed_bytes);
    let mut next = None;
    let mut ordinal = count;
    for reader in proofs.rev() {
        let bytes = input(
            reader.map_err(RegistrationErrorV1::Unavailable)?,
            REGISTRATION_PROOF_MAX_BYTES_V1,
            &mut cancelled,
        )?;
        let proof: SumeragiFinalityProof = decode(&bytes)?;
        if proof.height() != ordinal
            || proof.committee.len() > 31
            || proof.block_wire.len() > MAX_FINALITY_BLOCK_BYTES
        {
            return Err(RegistrationErrorV1::Invalid("proof order or decoded bound"));
        }
        drop(proof);
        let proof = put(
            &originals,
            &bytes,
            REGISTRATION_PROOF_MAX_BYTES_V1,
            &mut cancelled,
        )?;
        drop(bytes);
        let entry = RegistrationEntryV1 {
            version: 1,
            ordinal,
            proof,
            next,
        };
        let bytes = norito::encode_canonical(&entry)
            .map_err(|_| RegistrationErrorV1::Invalid("entry encoding"))?;
        next = Some(put(
            &originals,
            &bytes,
            REGISTRATION_ENTRY_MAX_BYTES_V1,
            &mut cancelled,
        )?);
        ordinal = ordinal
            .checked_sub(1)
            .ok_or(RegistrationErrorV1::Invalid("proof count"))?;
    }
    if ordinal != 0 {
        return Err(RegistrationErrorV1::Invalid("proof count"));
    }
    let source = RegistrationSourceV1 {
        version: 1,
        originals_root: originals
            .path()
            .to_str()
            .ok_or(RegistrationErrorV1::Invalid("source path encoding"))?
            .to_owned(),
        inventory: RegistrationInventoryV1 {
            version: 1,
            asset_digest: selection.asset_digest,
            instruction_index: selection.instruction_index,
            committed,
            first: next.ok_or(RegistrationErrorV1::Invalid("proof count"))?,
            proof_count: count,
        },
    };
    let registration = verify_registration_source_v1(
        &source,
        selection.genesis,
        selection.scheme,
        &mut cancelled,
    )?;
    let bytes = source.encode_canonical()?;
    if cancelled() {
        return Err(RegistrationErrorV1::Cancelled);
    }
    let mut manifest = output
        .create_retained_private(
            "registration-source.norito",
            REGISTRATION_SOURCE_MAX_BYTES_V1,
        )
        .map_err(storage)?;
    manifest.write_all(&bytes).map_err(storage)?;
    manifest.seal_read_only().map_err(storage)?;
    originals.revalidate().map_err(storage)?;
    output.revalidate().map_err(storage)?;
    parent.revalidate().map_err(storage)?;
    Ok((source, registration))
}
