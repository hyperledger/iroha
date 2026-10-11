//! Local producer for the canonical native registration transport; no signing or network writes.
use crate::{Run, RunContext, cli_output::print_with_optional_text};
use clap::Args;
use eyre::{Result, WrapErr as _, ensure};
use iroha_core_zk::kagemusha_wallet_registration_v1::{
    REGISTRATION_PROOF_MAX_BYTES_V1, RegistrationSelectionV1, publish_registration_source_v1,
};
use iroha_data_model::{
    kagemusha::{KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1, KagemushaWalletSchemeV1},
    sumeragi_finality::{
        FinalityValidator, SumeragiFinalityProof, SumeragiFinalityVerifier, authenticated_genesis,
    },
};
use iroha_fs::{FileSnapshot, PrivateDirectory, SealedPrivateFile};
use sha2::{Digest as _, Sha256};
use std::{
    io::{self, Read as _},
    path::PathBuf,
};

/// Package one successful Global registration under explicitly selected operator trust.
#[derive(Args, Debug)]
pub(crate) struct RegistrationPackageArgs {
    /// Canonical owner-private directory containing sealed scheme.norito, committed.norito
    /// and proof-00000000000000000001.norito through the selected registration height.
    #[arg(long, value_name = "DIR")]
    input_dir: PathBuf,
    /// Independently authenticated SHA-256 of the entire first canonical finality proof.
    /// Obtain it from the deployment owner, never from an untrusted package.
    #[arg(long, value_name = "HEX", value_parser = digest)]
    genesis_sha256: [u8; 32],
    /// Independently authenticated SHA-256 of the canonical application scheme original.
    #[arg(long, value_name = "HEX", value_parser = digest)]
    scheme_sha256: [u8; 32],
    /// Chain label selected with the independently authenticated genesis.
    #[arg(long, value_name = "ID")]
    chain_id: String,
    /// Requested asset/incarnation/scale digest; this selects data, not authority.
    #[arg(long, value_name = "HEX", value_parser = digest)]
    asset_digest: [u8; 32],
    /// Direct Register instruction position in committed.norito (zero based).
    #[arg(long)]
    instruction_index: u32,
    /// Exact consecutive proof count, including genesis and the registration block.
    #[arg(long)]
    proof_count: usize,
    /// Existing canonical owner-private parent for the new package directory.
    #[arg(long, value_name = "DIR")]
    output_parent: PathBuf,
    /// Fresh direct child name; existing or partial packages are never overwritten.
    #[arg(long, value_name = "NAME")]
    output_name: String,
}

fn digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected exactly 64 lowercase hexadecimal characters".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes).map_err(|error| error.to_string())?;
    if bytes == [0; 32] {
        return Err("zero digest is not a selected identity".into());
    }
    Ok(bytes)
}

/// Hold a bounded immutable input through its final read, including path and content snapshots.
struct OriginalReader {
    file: SealedPrivateFile,
    snapshot: FileSnapshot,
}
impl OriginalReader {
    fn open(directory: &PrivateDirectory, name: &str, maximum: usize) -> io::Result<Self> {
        let file = directory.open_retained_read_only(name, maximum)?;
        let snapshot = file.snapshot()?;
        Ok(Self { file, snapshot })
    }
}
impl io::Read for OriginalReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.file.revalidate()?;
        let read = self.file.read(output);
        self.file.revalidate()?;
        if self.file.snapshot()? != self.snapshot {
            return Err(io::Error::other("registration input changed while reading"));
        }
        read
    }
}

fn proof_readers(
    directory: &PrivateDirectory,
    count: usize,
) -> impl DoubleEndedIterator<Item = io::Result<OriginalReader>> + ExactSizeIterator + '_ {
    (0..count).map(|index| {
        OriginalReader::open(
            directory,
            &format!("proof-{:020}.norito", index + 1),
            REGISTRATION_PROOF_MAX_BYTES_V1,
        )
    })
}

fn pinned_original(
    directory: &PrivateDirectory,
    name: &str,
    maximum: usize,
    expected: [u8; 32],
) -> Result<Vec<u8>> {
    let mut reader = OriginalReader::open(directory, name, maximum)?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    ensure!(!bytes.is_empty(), "empty registration input {name}");
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
        "selected SHA-256 differs for {name}"
    );
    Ok(bytes)
}

fn genesis_verifier(bytes: &[u8], chain_id: &str) -> Result<SumeragiFinalityVerifier> {
    let proof: SumeragiFinalityProof =
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))?;
    ensure!(
        proof.height() == 1,
        "selected trust original must be genesis"
    );
    let block = iroha_genesis::decode_signed_genesis(&proof.block_wire)?;
    // The caller already pinned the complete original. The existing native reader verifies
    // its block/transaction signatures, commitments and signed epoch before selecting a root.
    let epoch = authenticated_genesis(&block).map(|genesis| genesis.into_parts().0)?;
    let validators = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let verifier = SumeragiFinalityVerifier::new(&block, chain_id, validators)?;
    // Authenticate the supplied genesis execution/finality original too. Keep the returned
    // owner empty so the publisher must verify every proof again, beginning at height one.
    verifier.clone().verify(&proof)?;
    Ok(verifier)
}

#[derive(Debug, norito::derive::JsonSerialize)]
struct RegistrationPackageReport {
    schema: &'static str,
    source_path: String,
    source_sha256: String,
    asset_digest: String,
    scheme_id: String,
    block_hash: String,
    transaction_hash: String,
    registered_height: u64,
    proof_count: usize,
}

impl RegistrationPackageArgs {
    pub(super) fn preflight(&self) -> Result<()> {
        ensure!(
            self.proof_count >= 2,
            "--proof-count must include genesis and a non-genesis registration block"
        );
        ensure!(
            !self.chain_id.is_empty()
                && self.chain_id.len() <= 1024
                && !self.chain_id.chars().any(char::is_control),
            "--chain-id must contain 1..=1024 bytes without control characters"
        );
        ensure!(
            !self.output_name.is_empty()
                && self.output_name != "."
                && self.output_name != ".."
                && !self
                    .output_name
                    .bytes()
                    .any(|b| matches!(b, b'/' | b'\\' | 0)),
            "--output-name must be a fresh direct child name"
        );
        Ok(())
    }

    fn package(&self) -> Result<RegistrationPackageReport> {
        self.preflight()?;
        let input = PrivateDirectory::open_exact(&self.input_dir)
            .wrap_err("open sealed registration inputs")?;
        let first = pinned_original(
            &input,
            "proof-00000000000000000001.norito",
            REGISTRATION_PROOF_MAX_BYTES_V1,
            self.genesis_sha256,
        )?;
        let genesis = genesis_verifier(&first, &self.chain_id)?;
        drop(first);
        let scheme_original = pinned_original(
            &input,
            "scheme.norito",
            KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
            self.scheme_sha256,
        )?;
        let scheme: KagemushaWalletSchemeV1 = norito::decode_canonical_with_limits(
            &scheme_original,
            norito::canonical_decode_limits(scheme_original.len()),
        )?;
        scheme.validate()?;
        let parent = PrivateDirectory::open_exact(&self.output_parent)
            .wrap_err("open registration output parent")?;
        let committed =
            OriginalReader::open(&input, "committed.norito", REGISTRATION_PROOF_MAX_BYTES_V1)?;
        let (source, registration) = publish_registration_source_v1(
            &parent,
            &self.output_name,
            RegistrationSelectionV1 {
                genesis: &genesis,
                scheme: &scheme,
                asset_digest: self.asset_digest,
                instruction_index: self.instruction_index,
            },
            committed,
            proof_readers(&input, self.proof_count),
            || false,
        )
        .wrap_err("verify and publish registration package (failed partial output is retained)")?;
        input.revalidate()?;
        Ok(RegistrationPackageReport {
            schema: "iroha.offline.registration-package.v1",
            source_path: self
                .output_parent
                .join(&self.output_name)
                .join("registration-source.norito")
                .display()
                .to_string(),
            source_sha256: hex::encode(Sha256::digest(source.encode_canonical()?)),
            asset_digest: hex::encode(registration.asset().asset_digest()),
            scheme_id: hex::encode(registration.scheme().scheme_id()),
            block_hash: hex::encode(registration.block_hash()),
            transaction_hash: hex::encode(registration.transaction_hash()),
            registered_height: registration.height(),
            proof_count: self.proof_count,
        })
    }
}
impl Run for RegistrationPackageArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = self.package()?;
        let text = format!(
            "verified registration at height {} → {}",
            report.registered_height, report.source_path
        );
        print_with_optional_text(context, Some(text), &report)
    }
}

#[cfg(test)]
mod tests;
