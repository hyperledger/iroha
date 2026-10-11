//! Offline game settlement verification anchored to an independently pinned native checkpoint.
//!
//! The downloaded bundle supplies only untrusted carriers. None of its fields can select the
//! trusted network, validator context, transaction, session, profile or expected outcome.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Args;
use eyre::{Result, WrapErr, ensure, eyre};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    block::{
        SignedBlock, decode_framed_signed_block,
        proofs::{BlockProofs, TrustedBlockProofAnchor},
    },
    game::game_message_hash_v1,
    isi::game::SettleGameSessionV1,
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, SumeragiFinalityProof,
        SumeragiFinalityVerifier, VerifiedSumeragiBlock,
    },
    transaction::signed::TransactionEntrypoint,
};
use norito::json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const BUNDLE_FORMAT: &str = "iroha.execution.settlement-bundle";
const BATCH_FORMAT: &str = "iroha.execution.finality-batch";
const INDEX_FORMAT: &str = "iroha.execution.settlement-index";

const MAX_JSON_BYTES: usize = 96 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FINALITY_BYTES: usize = 36 * 1024 * 1024;
const MAX_BLOCK_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROOFS_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINALITY_HEIGHTS: usize = 256;
const MAX_INDEX_BYTES: usize = 1024 * 1024;
const MAX_PREFIX_BATCHES: usize = 4096;
const DEFAULT_TOTAL_HEIGHTS: u64 = 65_536;
const HARD_TOTAL_HEIGHTS: u64 = 1_048_576;
const DEFAULT_TOTAL_ARCHIVES: u64 = 4 * 1024 * 1024 * 1024;
const HARD_TOTAL_ARCHIVES: u64 = 64 * 1024 * 1024 * 1024;

/// Public artifact path plus expectations obtained outside the artifact's transport.
#[derive(Debug, Args)]
pub struct VerifySettlementArgs {
    /// First-release settlement bundle or index of adjacent, bounded JSON carrier files.
    #[arg(long, value_name = "PATH")]
    bundle: PathBuf,
    /// Independently pinned exact genesis-derived network identity.
    #[arg(long)]
    network_id: NetworkId,
    /// Independently authenticated canonical checkpoint, never selected by the bundle.
    #[arg(long, value_name = "PATH")]
    trusted_checkpoint: PathBuf,
    /// Canonical entrypoint hash retained when the wallet signed the settlement.
    #[arg(long)]
    expected_entry_hash: Hash,
    /// Independently selected game session.
    #[arg(long)]
    session_id: Hash,
    /// Release-pinned compiled execution profile.
    #[arg(long)]
    profile_id: Hash,
    /// Expected domain-separated generic outcome commitment.
    #[arg(long)]
    outcome_hash: Hash,
    /// Explicit total finality work budget; increasing it does not change the original trust pin.
    #[arg(long, default_value_t = DEFAULT_TOTAL_HEIGHTS)]
    max_finality_heights: u64,
    /// Total decoded carrier byte budget across all batches (including the final block/proofs).
    #[arg(long, default_value_t = DEFAULT_TOTAL_ARCHIVES)]
    max_finality_archive_bytes: u64,
}

struct Bundle {
    finality: Vec<Vec<u8>>,
    block: Vec<u8>,
    proofs: Vec<u8>,
}
struct FileReference {
    file: String,
    sha256: String,
    bytes: usize,
}
struct BundleIndex {
    finality_batches: Vec<FileReference>,
    settlement_bundle: FileReference,
}
/// One verifier survives every file boundary. No continuation file can choose an anchor.
#[derive(Clone)]
struct FinalityStream {
    verifier: SumeragiFinalityVerifier,
    pinned_tip: SumeragiFinalityProof,
    latest: Option<VerifiedSumeragiBlock>,
    latest_proof: Option<SumeragiFinalityProof>,
    heights: u64,
    archive_bytes: u64,
    max_heights: u64,
    max_archive_bytes: u64,
}
impl FinalityStream {
    fn new(args: &VerifySettlementArgs) -> Result<Self> {
        ensure!(
            (1..=HARD_TOTAL_HEIGHTS).contains(&args.max_finality_heights),
            "total finality height budget must be 1..={HARD_TOTAL_HEIGHTS}"
        );
        ensure!(
            (1..=HARD_TOTAL_ARCHIVES).contains(&args.max_finality_archive_bytes),
            "total carrier byte budget must be 1..={HARD_TOTAL_ARCHIVES}"
        );
        let bytes = read_public_file(&args.trusted_checkpoint, MAX_FINALITY_CHECKPOINT_BYTES)
            .wrap_err("read independently pinned native checkpoint")?;
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&bytes)
            .wrap_err("decode independently pinned native checkpoint")?;
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &args.network_id,
            checkpoint.chain_id(),
        )
        .wrap_err("pinned native checkpoint rejected")?;
        let mut stream = Self {
            verifier,
            pinned_tip: checkpoint.tip().clone(),
            latest: None,
            latest_proof: None,
            heights: 0,
            archive_bytes: 0,
            max_heights: args.max_finality_heights,
            max_archive_bytes: args.max_finality_archive_bytes,
        };
        stream.charge_bytes(bytes.len())?;
        Ok(stream)
    }
    fn charge_bytes(&mut self, bytes: usize) -> Result<()> {
        let next = self
            .archive_bytes
            .checked_add(u64::try_from(bytes)?)
            .ok_or_else(|| eyre!("total carrier byte counter overflow"))?;
        ensure!(
            next <= self.max_archive_bytes,
            "total carrier byte budget exceeded"
        );
        self.archive_bytes = next;
        Ok(())
    }
    fn consume(&mut self, chain: &[Vec<u8>]) -> Result<()> {
        ensure!(
            !chain.is_empty() && chain.len() <= MAX_FINALITY_HEIGHTS,
            "each finality batch must contain 1..=256 heights"
        );
        let next = self
            .heights
            .checked_add(u64::try_from(chain.len())?)
            .ok_or_else(|| eyre!("total height counter overflow"))?;
        ensure!(
            next <= self.max_heights,
            "total finality height budget exceeded"
        );
        for bytes in chain {
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_FINALITY_BYTES,
                "finality carrier exceeds its bound"
            );
            self.charge_bytes(bytes.len())?;
            let proof: SumeragiFinalityProof = archive(bytes)?;
            let verified = if self.heights == 0 {
                self.verifier.verify_same_decision(&self.pinned_tip, &proof)
            } else {
                self.verifier.verify(&proof)
            }
            .wrap_err("pinned native checkpoint finality chain rejected")?;
            self.latest = Some(verified);
            self.latest_proof = Some(proof);
            self.heights += 1;
        }
        Ok(())
    }
}
fn limits(encoded_len: usize) -> norito::DecodeLimits {
    let canonical = norito::canonical_decode_limits(encoded_len);
    norito::DecodeLimits::new(
        canonical.max_sequence_elements(),
        canonical.max_field_bytes(),
        canonical.max_total_elements(),
        // Versioned blocks decode several nested owned representations of an
        // execution instruction. Use Norito's bounded aggregate allocation
        // policy rather than a smaller, unqualified multiplier for those copies.
        canonical.max_total_allocated_bytes(),
        128,
    )
}
fn archive<T>(bytes: &[u8]) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(bytes, limits(bytes.len()))
        .map_err(|error| eyre!("noncanonical bounded finality carrier: {error}"))
}
fn base64_bytes(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| eyre!("carrier must be base64 text"))?;
    ensure!(
        !text.is_empty() && text.len() <= maximum.div_ceil(3) * 4,
        "carrier exceeds its encoded bound"
    );
    let bytes = STANDARD.decode(text).wrap_err("invalid carrier base64")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum && STANDARD.encode(&bytes) == text,
        "carrier is empty, oversized or noncanonical base64"
    );
    Ok(bytes)
}
fn parse_json(bytes: &[u8], maximum: usize, elements: usize) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "bundle exceeds the JSON bound"
    );
    let json_limits = norito::DecodeLimits::new(elements, maximum, elements * 8, maximum * 4, 8);
    norito::json::preflight_slice(
        bytes,
        norito::json::JsonPreflightLimits::from_decode_limits(maximum, json_limits),
    )
    .map_err(|error| eyre!("invalid bundle JSON geometry: {error}"))?;
    norito::with_decode_limits_scope(json_limits, || norito::json::from_slice(bytes))
        .wrap_err("decode bounded bundle JSON")
}
fn parse_chain(value: &Value) -> Result<Vec<Vec<u8>>> {
    let chain = value
        .get("finality_chain_base64")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("missing finality chain"))?;
    ensure!(
        !chain.is_empty() && chain.len() <= MAX_FINALITY_HEIGHTS,
        "each finality batch must contain 1..=256 heights"
    );
    let mut total = 0usize;
    chain
        .iter()
        .map(|proof| {
            let bytes = base64_bytes(proof, MAX_FINALITY_BYTES)?;
            total += bytes.len();
            ensure!(
                total <= MAX_TOTAL_ARCHIVE_BYTES,
                "aggregate carrier bound exceeded"
            );
            Ok(bytes)
        })
        .collect()
}
fn parse_prefix(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let value = parse_json(bytes, MAX_JSON_BYTES, 1024)?;
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("finality batch must be an object"))?;
    ensure!(
        fields.len() == 3
            && value["format"].as_str() == Some(BATCH_FORMAT)
            && fields.contains_key("version")
            && fields.contains_key("finality_chain_base64")
            && value["version"].as_u64() == Some(1),
        "unexpected finality batch fields or version"
    );
    parse_chain(&value)
}
fn parse_bundle(bytes: &[u8]) -> Result<Bundle> {
    let value = parse_json(bytes, MAX_JSON_BYTES, 1024)?;
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("bundle must be an object"))?;
    ensure!(
        fields.len() == 5
            && value["format"].as_str() == Some(BUNDLE_FORMAT)
            && [
                "format",
                "version",
                "finality_chain_base64",
                "executed_block_wire_base64",
                "block_proofs_base64"
            ]
            .iter()
            .all(|key| fields.contains_key(*key)),
        "unexpected bundle fields"
    );
    ensure!(
        value.get("version").and_then(Value::as_u64) == Some(1),
        "unsupported bundle version"
    );
    let finality = parse_chain(&value)?;
    let total: usize = finality.iter().map(Vec::len).sum();
    let block = base64_bytes(&value["executed_block_wire_base64"], MAX_BLOCK_BYTES)?;
    let proofs = base64_bytes(&value["block_proofs_base64"], MAX_PROOFS_BYTES)?;
    ensure!(
        total + block.len() + proofs.len() <= MAX_TOTAL_ARCHIVE_BYTES,
        "aggregate carrier bound exceeded"
    );
    Ok(Bundle {
        finality,
        block,
        proofs,
    })
}
fn file_reference(value: &Value) -> Result<FileReference> {
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("file reference must be an object"))?;
    ensure!(
        fields.len() == 3
            && ["file", "sha256", "bytes"]
                .iter()
                .all(|name| fields.contains_key(*name)),
        "unexpected file reference fields"
    );
    let file = value["file"]
        .as_str()
        .ok_or_else(|| eyre!("file reference needs a basename"))?;
    let stem = file
        .strip_suffix(".json")
        .ok_or_else(|| eyre!("file reference must end in .json"))?;
    ensure!(
        !stem.is_empty()
            && file.len() <= 128
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "file reference must be a flat ASCII basename"
    );
    let sha256 = value["sha256"]
        .as_str()
        .ok_or_else(|| eyre!("file reference needs a SHA-256 digest"))?;
    ensure!(
        sha256.len() == 64
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "file digest must be 64 lowercase hexadecimal characters"
    );
    let bytes = value["bytes"]
        .as_u64()
        .ok_or_else(|| eyre!("file byte length must be a positive JSON integer"))?;
    ensure!(
        (1..=MAX_JSON_BYTES as u64).contains(&bytes),
        "referenced JSON file exceeds its bound"
    );
    Ok(FileReference {
        file: file.to_owned(),
        sha256: sha256.to_owned(),
        bytes: usize::try_from(bytes)?,
    })
}
fn parse_index(bytes: &[u8], max_archive_bytes: u64) -> Result<BundleIndex> {
    let value = parse_json(bytes, MAX_INDEX_BYTES, MAX_PREFIX_BATCHES + 1)?;
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("bundle index must be an object"))?;
    ensure!(
        fields.len() == 4
            && value["format"].as_str() == Some(INDEX_FORMAT)
            && ["format", "version", "finality_batches", "settlement_bundle"]
                .iter()
                .all(|key| fields.contains_key(*key))
            && value["version"].as_u64() == Some(1),
        "unexpected bundle index fields or version"
    );
    let batches = value["finality_batches"]
        .as_array()
        .ok_or_else(|| eyre!("index requires ordered finality batches"))?;
    ensure!(
        batches.len() <= MAX_PREFIX_BATCHES,
        "index permits at most 4096 prefix batches"
    );
    let finality_batches = batches
        .iter()
        .map(file_reference)
        .collect::<Result<Vec<_>>>()?;
    let settlement_bundle = file_reference(&value["settlement_bundle"])?;
    let mut names = BTreeSet::new();
    let mut total_json = 0u64;
    for reference in finality_batches
        .iter()
        .chain(std::iter::once(&settlement_bundle))
    {
        ensure!(names.insert(&reference.file), "duplicate file reference");
        total_json = total_json
            .checked_add(reference.bytes as u64)
            .ok_or_else(|| eyre!("total JSON counter overflow"))?;
    }
    // Base64 plus bounded JSON framing is admitted separately from decoded
    // bytes. Declared sizes are checked against actual files before any reads.
    ensure!(
        total_json
            <= max_archive_bytes
                .saturating_mul(2)
                .saturating_add(MAX_INDEX_BYTES as u64),
        "total indexed JSON work budget exceeded"
    );
    Ok(BundleIndex {
        finality_batches,
        settlement_bundle,
    })
}
fn read_public_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).wrap_err("inspect public finality file")?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= maximum as u64,
        "finality input must be a bounded direct regular file"
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK)
                .bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path).wrap_err("open public finality file")?;
    let opened = file.metadata().wrap_err("inspect opened finality file")?;
    ensure!(
        opened.is_file() && opened.len() == metadata.len(),
        "finality file changed before opening"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .wrap_err("read bounded finality file")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum && bytes.len() as u64 == opened.len(),
        "finality file changed or exceeded its bound while reading"
    );
    Ok(bytes)
}
fn read_reference(directory: &Path, reference: &FileReference) -> Result<Vec<u8>> {
    let bytes = read_public_file(&directory.join(&reference.file), reference.bytes)?;
    ensure!(
        bytes.len() == reference.bytes && hex::encode(Sha256::digest(&bytes)) == reference.sha256,
        "indexed finality file length or SHA-256 mismatch"
    );
    Ok(bytes)
}
fn bundle_directory(path: &Path) -> Result<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .wrap_err("resolve selected finality bundle directory")
}
fn block_from_wire(bytes: &[u8]) -> Result<SignedBlock> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BLOCK_BYTES,
        "executed block wire exceeds its byte bound"
    );
    let block = norito::core::with_decode_limits_scope(limits(bytes.len()), || {
        decode_framed_signed_block(bytes)
    })
    .wrap_err("decode exact executed SignedBlockWire")?;
    Ok(block)
}
impl VerifySettlementArgs {
    pub fn verify(&self) -> Result<Value> {
        // Both bounded representations use one pinned verifier and the same admission limits.
        let mut stream = FinalityStream::new(self)?;
        let bytes = read_public_file(&self.bundle, MAX_JSON_BYTES)?;
        let value = parse_json(&bytes, MAX_JSON_BYTES, MAX_PREFIX_BATCHES + 1)?;
        let format = value
            .get("format")
            .and_then(Value::as_str)
            .map(str::to_owned);
        drop(value);
        let bundle = match format.as_deref() {
            Some(BUNDLE_FORMAT) => parse_bundle(&bytes)?,
            Some(INDEX_FORMAT) => {
                let index = parse_index(&bytes, self.max_finality_archive_bytes)?;
                ensure!(
                    index.finality_batches.len() as u64 + 1 <= self.max_finality_heights,
                    "indexed batch count exceeds total finality height budget"
                );
                let directory = bundle_directory(&self.bundle)?;
                for reference in &index.finality_batches {
                    // Only one prefix's JSON and decoded carriers live at once.
                    let prefix = read_reference(&directory, reference)?;
                    stream.consume(&parse_prefix(&prefix)?)?;
                }
                parse_bundle(&read_reference(&directory, &index.settlement_bundle)?)?
            }
            _ => return Err(eyre!("unsupported first-release settlement format")),
        };
        self.verify_carriers_with_stream(bundle, stream)
    }
    #[cfg(test)]
    fn verify_carriers(&self, bundle: Bundle) -> Result<Value> {
        self.verify_carriers_with_stream(bundle, FinalityStream::new(self)?)
    }
    fn verify_carriers_with_stream(
        &self,
        bundle: Bundle,
        mut stream: FinalityStream,
    ) -> Result<Value> {
        stream.consume(&bundle.finality)?;
        stream.charge_bytes(bundle.block.len())?;
        stream.charge_bytes(bundle.proofs.len())?;
        let finality = stream
            .latest
            .as_ref()
            .ok_or_else(|| eyre!("empty finality chain"))?;
        // Authenticate finality before decoding the larger block and Merkle carriers.
        let block = block_from_wire(&bundle.block)?;
        let entry_hash =
            HashOf::<TransactionEntrypoint>::from_untyped_unchecked(self.expected_entry_hash);
        // Only the native verifier produces this capability from the independently
        // selected checkpoint; the transport cannot promote a candidate context.
        let anchor = TrustedBlockProofAnchor::from_verified_finality(&block, finality, &entry_hash)
            .wrap_err("finality does not authenticate the exact executed block and target entry")?;
        let proofs: BlockProofs = archive(&bundle.proofs)?;
        ensure!(
            proofs.verify(&anchor),
            "authenticated input/output proof mismatch"
        );
        // The verified proof joins the exact Network output to the anchored input
        // index. Internal outputs never select a wallet transaction or its result.
        let entry = block
            .network_entrypoint_at(usize::try_from(anchor.entry_index())?)
            .ok_or_else(|| eyre!("target entry absent from authenticated block"))?;
        ensure!(
            proofs.output_proof.output().result().is_ok(),
            "authenticated transaction was rejected, not settled"
        );
        let TransactionEntrypoint::External(transaction) = entry else {
            return Err(eyre!(
                "settlement verifier requires an external wallet transaction"
            ));
        };
        ensure!(
            transaction.network_id() == Some(&self.network_id),
            "authenticated settlement transaction belongs to a different network"
        );
        transaction
            .verify_signature()
            .wrap_err("authenticated settlement wallet signature is invalid")?;
        let matches = transaction
            .instructions()
            .explicit_instructions()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<SettleGameSessionV1>())
            .filter(|instruction| instruction.session_id == self.session_id)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "target transaction must contain exactly one explicit settlement for the expected session"
        );
        let settlement = matches[0];
        let profile =
            iroha_core_privacy::execution_proofs::compiled_execution_profile_v1(&self.profile_id)
                .ok_or_else(|| eyre!("expected profile is not compiled into this verifier"))?;
        let statement = &settlement.proof.statement;
        ensure!(
            settlement.proof.profile_id == self.profile_id
                && statement.network_id == self.network_id
                && statement.session_id == self.session_id
                && statement.outcome_hash == self.outcome_hash,
            "settlement differs from the independently selected profile, network, session or outcome"
        );
        ensure!(
            game_message_hash_v1(&self.network_id, "session-outcome", &settlement.outcome)
                == self.outcome_hash,
            "settlement outcome commitment mismatch"
        );
        let outcome =
            iroha_core_privacy::execution_proofs::verify_execution_proof_v1(&settlement.proof)
                .wrap_err("independent native execution proof verification failed")?;
        ensure!(
            outcome == settlement.outcome,
            "native verified outcome differs from finalized settlement"
        );
        // Export only after all application witnesses and caller expectations pass.
        let checkpoint = stream
            .verifier
            .export_checkpoint(
                stream
                    .latest_proof
                    .as_ref()
                    .expect("verified nonempty finality chain"),
            )?
            .encode_canonical()?;
        Ok(norito::json!({
            "version": 1, "verified": true, "verification": "native_checkpoint_finalized_settlement",
            "network_id": (self.network_id.to_string()), "session_id": (self.session_id.to_string()),
            "profile_id": (self.profile_id.to_string()), "profile_qualified": (profile.qualified), "outcome_hash": (self.outcome_hash.to_string()),
            "entry_hash": (self.expected_entry_hash.to_string()), "block_height": (anchor.block_height().get().to_string()),
            "block_hash": (anchor.block_hash().to_string()), "context_id": (finality.context_id().to_string()),
            "checkpoint_base64": (STANDARD.encode(checkpoint)),
            "finality_heights_verified": (stream.heights), "archive_bytes_verified": (stream.archive_bytes),
            "outcome": outcome
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::CertifiedTestChain,
    };
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    use iroha_data_model::{
        account::AccountId,
        block::{CommitCertificate, builder::BlockBuilder},
        execution_proofs::{ExecutionProofEnvelopeV1, ExecutionPublicInputsV1},
        game::GameOutcomeV1,
        testing::native_finality::NativeFinalityFixture,
        transaction::{FeePaymentIntent, TransactionResultInner, signed::TransactionBuilder},
        trigger::DataTriggerSequence,
    };
    use std::sync::OnceLock;

    struct Fixture {
        block: SignedBlock,
        finality: SumeragiFinalityProof,
        block_proofs: BlockProofs,
        alternate_block_proofs: BlockProofs,
        native: NativeFinalityFixture,
        checkpoint_path: PathBuf,
        _directory: tempfile::TempDir,
    }
    fn fixture_network() -> NetworkId {
        static NETWORK: OnceLock<NetworkId> = OnceLock::new();
        *NETWORK
            .get_or_init(|| NativeFinalityFixture::start("execution-finality-tests").network_id())
    }
    fn checked_keypair(algorithm: Algorithm) -> KeyPair {
        KeyPair::try_random_with_algorithm(algorithm)
            .unwrap_or_else(|error| panic!("{algorithm:?} fixture key generation failed: {error}"))
    }
    fn make_fixture(
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
        rejected: bool,
    ) -> Fixture {
        make_fixture_after(instructions, rejected, None)
    }
    // Actual native BLS/PoP finality over explicitly synthetic application outputs.
    // This fixture performs no World execution, funding, staking, or settlement.
    fn make_fixture_after(
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
        rejected: bool,
        previous: Option<&Fixture>,
    ) -> Fixture {
        make_fixture_with_signature(instructions, rejected, previous, true)
    }
    fn make_fixture_with_signature(
        instructions: Vec<iroha_data_model::isi::InstructionBox>,
        rejected: bool,
        previous: Option<&Fixture>,
        valid_signature: bool,
    ) -> Fixture {
        let mut native = previous.map_or_else(
            || NativeFinalityFixture::start("execution-finality-tests"),
            |parent| parent.native.clone(),
        );
        let transaction_key = checked_keypair(Algorithm::Ed25519);
        let alternate_transaction_key = checked_keypair(Algorithm::Ed25519);
        let transaction = TransactionBuilder::new(
            native.network_id(),
            AccountId::new(transaction_key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions);
        let transaction = if valid_signature {
            transaction
                .try_sign(transaction_key.private_key())
                .expect("fixture transaction signature")
        } else {
            // Keep the envelope structurally canonical while proving that an authentic
            // signature from a different wallet cannot authorize the selected authority.
            let signature = Signature::try_new(
                alternate_transaction_key.private_key(),
                &transaction.payload_hash_bytes(),
            )
            .expect("actual foreign wallet signature");
            let signed = transaction.build_with_signature(signature);
            assert!(signed.verify_signature().is_err());
            signed
        };
        let entry_hash = transaction.hash_as_entrypoint();
        let alternate_transaction = TransactionBuilder::new(
            native.network_id(),
            AccountId::new(alternate_transaction_key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .try_sign(alternate_transaction_key.private_key())
        .expect("alternate fixture transaction signature");
        let alternate_entry_hash = alternate_transaction.hash_as_entrypoint();
        let mut builder = BlockBuilder::new(native.next_header());
        builder.push_transaction(transaction);
        builder.push_transaction(alternate_transaction);
        let mut block = builder
            .try_build_with_signature(0, transaction_key.private_key())
            .expect("fixture signed proposal");
        let results = vec![
            if rejected {
                Err(
                    iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                        iroha_data_model::ValidationFail::NotPermitted("fixture rejection".into()),
                    ),
                )
            } else {
                TransactionResultInner::Ok(DataTriggerSequence::default())
            },
            TransactionResultInner::Ok(DataTriggerSequence::default()),
        ];
        NativeFinalityFixture::install_network_results(&mut block, results);
        let block_proofs = block
            .network_execution_proof(&entry_hash)
            .expect("target proof");
        let alternate_block_proofs = block
            .network_execution_proof(&alternate_entry_hash)
            .expect("alternate proof");
        let finality = native.certify(block.clone());
        let directory = tempfile::tempdir().unwrap();
        let checkpoint_path = directory.path().join("checkpoint.nrt");
        fs::write(
            &checkpoint_path,
            native.checkpoint().encode_canonical().unwrap(),
        )
        .unwrap();
        Fixture {
            block,
            finality,
            block_proofs,
            alternate_block_proofs,
            native,
            checkpoint_path,
            _directory: directory,
        }
    }
    fn alter_qc(
        proof: &mut SumeragiFinalityProof,
        mutate: impl FnOnce(&mut iroha_sumeragi::message::Qc),
    ) {
        let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
        let certificate = block.commit_certificate().unwrap();
        let mut qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
        mutate(&mut qc);
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            certificate.consensus_header().to_vec(),
            norito::encode_canonical(&qc).unwrap(),
            certificate.result_preimage().to_vec(),
            certificate.availability().to_vec(),
        )));
        proof.block_wire = block.encode_wire().unwrap();
    }

    fn bundle(fixture: &Fixture) -> Bundle {
        Bundle {
            finality: vec![norito::encode_canonical(&fixture.finality).expect("finality archive")],
            block: fixture.block.encode_wire().expect("executed wire"),
            proofs: norito::encode_canonical(&fixture.block_proofs).expect("entry proofs"),
        }
    }
    fn write_reference(directory: &Path, file: &str, value: &Value) -> Value {
        let bytes = norito::json::to_json(value)
            .expect("fixture JSON")
            .into_bytes();
        fs::write(directory.join(file), &bytes).unwrap();
        norito::json!({"file":file,"sha256":(hex::encode(Sha256::digest(&bytes))),"bytes":(bytes.len() as u64)})
    }
    fn write_index(directory: &Path, prefix: &[Vec<u8>], target: &Fixture) -> PathBuf {
        let mut references = Vec::new();
        if !prefix.is_empty() {
            references.push(write_reference(directory, "finality-000001.json", &norito::json!({
                "format":(BATCH_FORMAT),"version":1,"finality_chain_base64":(prefix.iter().map(|bytes| STANDARD.encode(bytes)).collect::<Vec<_>>())
            })));
        }
        let target_bundle = bundle(target);
        let final_reference = write_reference(
            directory,
            "settlement-finality.json",
            &norito::json!({
                "format":(BUNDLE_FORMAT),"version":1,"finality_chain_base64":(target_bundle.finality.iter().map(|bytes| STANDARD.encode(bytes)).collect::<Vec<_>>()),
                "executed_block_wire_base64":(STANDARD.encode(&target_bundle.block)),
                "block_proofs_base64":(STANDARD.encode(&target_bundle.proofs))
            }),
        );
        let index = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":references,"settlement_bundle":final_reference});
        let path = directory.join("settlement-index.json");
        fs::write(&path, norito::json::to_json(&index).unwrap()).unwrap();
        path
    }
    fn expectations(fixture: &Fixture) -> VerifySettlementArgs {
        VerifySettlementArgs {
            bundle: PathBuf::from("unused-fixture.json"),
            network_id: fixture.native.network_id(),
            trusted_checkpoint: fixture.checkpoint_path.clone(),
            expected_entry_hash: Hash::from(fixture.block_proofs.entry_hash),
            session_id: Hash::new(b"expected session"),
            profile_id: iroha_core_privacy::execution_proofs::race_profile_id_v1(),
            outcome_hash: Hash::new(b"expected outcome"),
            max_finality_heights: DEFAULT_TOTAL_HEIGHTS,
            max_finality_archive_bytes: DEFAULT_TOTAL_ARCHIVES,
        }
    }
    #[test]
    fn continuation_authenticates_257_heights_without_reanchoring_and_rejects_gaps() {
        let mut fixtures = vec![make_fixture(Vec::new(), false)];
        for _ in 1..258 {
            fixtures.push(make_fixture_after(Vec::new(), false, fixtures.last()));
        }
        let encoded = fixtures
            .iter()
            .map(|fixture| norito::encode_canonical(&fixture.finality).unwrap())
            .collect::<Vec<_>>();
        let args = expectations(&fixtures[0]);
        let mut stream = FinalityStream::new(&args).unwrap();
        stream
            .consume(&encoded[..256])
            .expect("first bounded authenticated batch");
        assert_eq!(stream.heights, 256);
        let boundary = stream.clone();
        stream
            .consume(&encoded[256..257])
            .expect("authenticated continuation from original pin");
        assert_eq!(stream.heights, 257);
        assert_eq!(stream.latest.as_ref().unwrap().height(), 258);

        for bad in [&encoded[255..256], &encoded[257..258]] {
            assert!(
                boundary
                    .clone()
                    .consume(bad)
                    .unwrap_err()
                    .to_string()
                    .contains("pinned native checkpoint"),
                "duplicate or missing boundary height must fail"
            );
        }
        let mut reordered = encoded[..2].to_vec();
        reordered.swap(0, 1);
        assert!(
            FinalityStream::new(&args)
                .unwrap()
                .consume(&reordered)
                .is_err()
        );
        let mut missing = encoded[..256].to_vec();
        missing.remove(127);
        assert!(
            FinalityStream::new(&args)
                .unwrap()
                .consume(&missing)
                .is_err()
        );
        let mut foreign = expectations(&fixtures[0]);
        foreign.trusted_checkpoint = fixtures[1].checkpoint_path.clone();
        assert!(
            FinalityStream::new(&foreign)
                .unwrap()
                .consume(&encoded[..1])
                .is_err()
        );
        foreign = expectations(&fixtures[0]);
        foreign.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"foreign network"),
        ));
        assert!(FinalityStream::new(&foreign).is_err());
        let mut work = boundary.clone();
        work.max_heights = 256;
        assert!(
            work.consume(&encoded[256..257])
                .unwrap_err()
                .to_string()
                .contains("height budget")
        );
        let mut work = boundary;
        work.max_archive_bytes = work.archive_bytes;
        assert!(
            work.consume(&encoded[256..257])
                .unwrap_err()
                .to_string()
                .contains("byte budget")
        );

        // Exercise the actual on-disk index and final block/Merkle path. It must
        // reach the unrelated-settlement rejection only after all 257 QCs and
        // exact final executed block inclusion have authenticated.
        let directory = tempfile::tempdir().unwrap();
        let mut args = expectations(&fixtures[256]);
        args.trusted_checkpoint = fixtures[0].checkpoint_path.clone();
        args.bundle = write_index(directory.path(), &encoded[..256], &fixtures[256]);
        assert!(
            args.verify()
                .unwrap_err()
                .to_string()
                .contains("exactly one explicit settlement")
        );
        fs::write(directory.path().join("finality-000001.json"), b"{}").unwrap();
        assert!(
            args.verify()
                .unwrap_err()
                .to_string()
                .contains("length or SHA-256 mismatch")
        );
    }
    #[test]
    fn original_epoch_boundary_continues_native_finality_across_files() {
        // Actual original Core execution and native finality verification, with a genuinely
        // proved DKG seeded as component prestate. This is not a live ceremony test.
        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        let checkpoint = build_checkpoint(&chain.state().view(), 9).unwrap();
        let first = build_proof(&chain.state().view(), 9).unwrap();
        chain.commit(Vec::new());
        let boundary = build_proof(&chain.state().view(), 10).unwrap();
        chain.commit(Vec::new());
        let child = build_proof(&chain.state().view(), 11).unwrap();
        let fixture = make_fixture(Vec::new(), false);
        let mut args = expectations(&fixture);
        args.network_id = checkpoint.network_id();
        fs::write(
            &args.trusted_checkpoint,
            checkpoint.encode_canonical().unwrap(),
        )
        .unwrap();
        let mut stream = FinalityStream::new(&args).unwrap();
        stream
            .consume(&[norito::encode_canonical(&first).unwrap()])
            .unwrap();
        stream
            .consume(&[norito::encode_canonical(&boundary).unwrap()])
            .unwrap();
        let verified = stream.latest.as_ref().unwrap();
        assert_eq!(verified.height(), 10);
        let selected = verified
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .unwrap()
            .next
            .clone();
        assert_eq!(
            selected.generation(),
            verified.commitment().schedule.current.generation()
        );
        assert_eq!(
            selected.authorization.epoch,
            verified.commitment().schedule.current.authorization.epoch + 1
        );
        let certificate = verified.block().commit_certificate().unwrap();
        let qc: iroha_sumeragi::message::Qc =
            norito::decode_canonical(certificate.commit_qc()).unwrap();
        assert_eq!(qc.signers.count_ones(), 3);
        stream
            .consume(&[norito::encode_canonical(&child).unwrap()])
            .expect("authenticated epoch successor across another file boundary");
        assert_eq!(stream.heights, 3);
        assert_eq!(
            stream
                .latest
                .as_ref()
                .unwrap()
                .commitment()
                .schedule
                .current,
            selected
        );
        assert!(
            stream
                .consume(&[norito::encode_canonical(&boundary).unwrap()])
                .is_err()
        );
    }
    #[test]
    fn continuation_index_rejects_extra_trust_paths_duplicates_and_oversized_work() {
        let reference =
            norito::json!({"file":"finality-000001.json","sha256":("00".repeat(32)),"bytes":1});
        let target =
            norito::json!({"file":"settlement-finality.json","sha256":("00".repeat(32)),"bytes":1});
        let encode = |value: &Value| norito::json::to_json(value).unwrap().into_bytes();
        assert_eq!(
            bundle_directory(Path::new("settlement-index.json")).unwrap(),
            std::env::current_dir().unwrap().canonicalize().unwrap()
        );
        assert!(parse_prefix(&encode(&norito::json!({"format":(BATCH_FORMAT),"version":1,"finality_chain_base64":(vec!["AQ=="]),"trusted_context_id":"endpoint-selected"}))).is_err());
        let empty = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":(Vec::<Value>::new()),"settlement_bundle":(target.clone())});
        assert!(parse_index(&encode(&empty), DEFAULT_TOTAL_ARCHIVES).is_ok());
        let duplicates = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":(vec![reference.clone(), reference.clone()]),"settlement_bundle":(target.clone())});
        assert!(parse_index(&encode(&duplicates), DEFAULT_TOTAL_ARCHIVES).is_err());
        let injected = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":(vec![reference]),"settlement_bundle":(target.clone()),"trusted_context_id":"endpoint-selected"});
        assert!(parse_index(&encode(&injected), DEFAULT_TOTAL_ARCHIVES).is_err());
        for path in [
            "../secret.json",
            "/secret.json",
            "https://endpoint/file.json",
            "nested/file.json",
            ".hidden.json",
        ] {
            assert!(
                file_reference(&norito::json!({"file":path,"sha256":("00".repeat(32)),"bytes":1}))
                    .is_err()
            );
        }
        let oversized = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":(vec![norito::json!({"file":"batch.json","sha256":("00".repeat(32)),"bytes":(MAX_JSON_BYTES)})]),"settlement_bundle":target});
        assert!(parse_index(&encode(&oversized), 1).is_err());
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(Vec::new(), false);
        let mut args = expectations(&fixture);
        args.bundle = write_index(directory.path(), &[], &fixture);
        assert!(
            args.verify()
                .unwrap_err()
                .to_string()
                .contains("exactly one explicit settlement")
        );
        fs::remove_file(directory.path().join("settlement-finality.json")).unwrap();
        assert!(args.verify().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn continuation_index_never_follows_a_referenced_symlink() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("real.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("real.json", directory.path().join("linked.json")).unwrap();
        let reference = FileReference {
            file: "linked.json".to_owned(),
            sha256: hex::encode(Sha256::digest(b"{}")),
            bytes: 2,
        };
        assert!(read_reference(directory.path(), &reference).is_err());
    }
    #[test]
    fn valid_finality_cannot_turn_an_unrelated_transaction_into_a_settlement() {
        let fixture = make_fixture(Vec::new(), false);
        let mut args = expectations(&fixture);
        let error = args
            .verify_carriers(bundle(&fixture))
            .expect_err("not a settlement");
        assert!(
            error
                .to_string()
                .contains("exactly one explicit settlement"),
            "{error:#}"
        );
        let foreign = make_fixture(Vec::new(), false);
        args.trusted_checkpoint = foreign.checkpoint_path.clone();
        assert!(
            args.verify_carriers(bundle(&fixture))
                .expect_err("self-consistent untrusted roster")
                .to_string()
                .contains("pinned native checkpoint")
        );
    }
    #[test]
    fn wrong_entry_merkle_path_and_modified_executed_wire_are_rejected() {
        let fixture = make_fixture(Vec::new(), false);
        let args = expectations(&fixture);
        let mut swapped = bundle(&fixture);
        swapped.proofs =
            norito::encode_canonical(&fixture.alternate_block_proofs).expect("alternate proofs");
        assert!(
            args.verify_carriers(swapped)
                .expect_err("swapped entry proof")
                .to_string()
                .contains("input/output proof mismatch")
        );
        let mut wrong_output = fixture.block_proofs.clone();
        wrong_output.output_proof = fixture.alternate_block_proofs.output_proof.clone();
        assert!(
            wrong_output
                .output_proof
                .verify(&wrong_output.output_commitment),
            "the alternate output is included in the same authenticated output tree"
        );
        let mut swapped_output = bundle(&fixture);
        swapped_output.proofs = norito::encode_canonical(&wrong_output).expect("swapped output");
        assert!(
            args.verify_carriers(swapped_output)
                .expect_err("output for another network input")
                .to_string()
                .contains("input/output proof mismatch")
        );
        let mut modified = bundle(&fixture);
        modified.block.push(0);
        assert!(args.verify_carriers(modified).is_err());
        let mut skipped = bundle(&fixture);
        skipped.finality.push(skipped.finality[0].clone());
        assert!(
            args.verify_carriers(skipped)
                .expect_err("repeated height")
                .to_string()
                .contains("pinned native checkpoint")
        );
    }
    #[test]
    fn authenticated_output_must_belong_to_selected_input() {
        let fixture = make_fixture(vec![invalid_settlement().into()], true);
        let mut mismatched_proofs = fixture.block_proofs.clone();
        mismatched_proofs.output_proof = fixture.alternate_block_proofs.output_proof.clone();
        let mut mismatched = bundle(&fixture);
        mismatched.proofs =
            norito::encode_canonical(&mismatched_proofs).expect("mismatched proofs");
        assert!(
            expectations(&fixture)
                .verify_carriers(mismatched)
                .expect_err("another input's successful output cannot replace the rejection")
                .to_string()
                .contains("input/output proof mismatch")
        );

        let mut args = expectations(&fixture);
        args.expected_entry_hash = fixture.alternate_block_proofs.entry_hash.into();
        let mut alternate = bundle(&fixture);
        alternate.proofs =
            norito::encode_canonical(&fixture.alternate_block_proofs).expect("alternate proofs");
        assert!(
            args.verify_carriers(alternate)
                .expect_err("the selected successful input has no settlement")
                .to_string()
                .contains("exactly one explicit settlement")
        );
    }
    #[test]
    fn consecutive_finality_authenticates_target_without_accepting_another_parent() {
        let parent = make_fixture(Vec::new(), false);
        let child = make_fixture_after(Vec::new(), false, Some(&parent));
        let mut args = expectations(&child);
        args.trusted_checkpoint = parent.checkpoint_path.clone();
        let mut carriers = bundle(&child);
        carriers.finality.insert(
            0,
            norito::encode_canonical(&parent.finality).expect("parent"),
        );
        // Passing finality and inclusion reaches the actual application instruction check.
        assert!(
            args.verify_carriers(carriers)
                .expect_err("no settlement")
                .to_string()
                .contains("exactly one explicit settlement")
        );
        assert!(
            args.verify_carriers(bundle(&child))
                .expect_err("skipped pinned height")
                .to_string()
                .contains("pinned native checkpoint")
        );

        // A self-consistent foreign parent cannot replace a linked successor.
        let foreign_parent = make_fixture(Vec::new(), false);
        let foreign_child = make_fixture_after(Vec::new(), false, Some(&foreign_parent));
        let mut carriers = bundle(&foreign_child);
        carriers.finality.insert(
            0,
            norito::encode_canonical(&parent.finality).expect("parent"),
        );
        assert!(
            args.verify_carriers(carriers)
                .expect_err("untrusted successor committee")
                .to_string()
                .contains("pinned native checkpoint")
        );
    }
    #[test]
    fn invalid_quorum_pop_and_wrong_network_never_authenticate_inclusion() {
        let fixture = make_fixture(Vec::new(), false);
        let args = expectations(&fixture);
        for tamper in 0..4 {
            let mut finality = fixture.finality.clone();
            match tamper {
                0 => alter_qc(&mut finality, |qc| qc.agg_sig.0[0] ^= 1),
                1 => finality.committee[0].proof_of_possession[0] ^= 1,
                2 => alter_qc(&mut finality, |qc| {
                    qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1]).unwrap();
                }),
                _ => finality.committee.swap(0, 1),
            }
            let mut carriers = bundle(&fixture);
            carriers.finality[0] = norito::encode_canonical(&finality).expect("tampered finality");
            assert!(
                args.verify_carriers(carriers)
                    .expect_err("invalid certificate")
                    .to_string()
                    .contains("pinned native checkpoint")
            );
        }
        let mut wrong_network = expectations(&fixture);
        wrong_network.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"foreign genesis"),
        ));
        assert!(
            wrong_network
                .verify_carriers(bundle(&fixture))
                .expect_err("wrong network")
                .to_string()
                .contains("pinned native checkpoint")
        );
    }
    fn invalid_settlement() -> SettleGameSessionV1 {
        let network_id = fixture_network();
        let session_id = Hash::new(b"expected session");
        let outcome = GameOutcomeV1 {
            terminal_tick: 6,
            winner_slots: vec![0],
            result: vec![0],
        };
        SettleGameSessionV1 {
            session_id,
            outcome: outcome.clone(),
            proof: ExecutionProofEnvelopeV1 {
                version: 1,
                profile_id: iroha_core_privacy::execution_proofs::race_profile_id_v1(),
                statement: ExecutionPublicInputsV1 {
                    network_id,
                    session_id,
                    manifest_hash: Hash::new(b"manifest"),
                    roster_hash: Hash::new(b"roster"),
                    transcript_root: Hash::new(b"transcript"),
                    dispute_root: Hash::new(b"dispute"),
                    outcome_hash: game_message_hash_v1(&network_id, "session-outcome", &outcome),
                },
                proof_bytes: vec![0],
            },
        }
    }
    #[test]
    fn large_execution_envelopes_decode_under_bounded_native_policy() {
        for payload_bytes in [2 * 1024 * 1024, 4 * 1024 * 1024 - 16 * 1024] {
            // These bytes exercise the block/ISI codec only. They are deliberately
            // not a valid proof; the separate genuine-proof test checks actual proof and ledger binding.
            let mut settlement = invalid_settlement();
            settlement.proof.proof_bytes = vec![0xA5; payload_bytes];
            let expected = settlement.proof.proof_bytes.clone();
            let fixture = make_fixture(vec![settlement.into()], false);
            let mut wire = fixture
                .block
                .encode_wire()
                .expect("large executed block wire");
            let decoded = block_from_wire(&wire).expect("bounded large execution envelope");
            let entry = decoded
                .network_entrypoints()
                .find(|entry| entry.hash() == fixture.block_proofs.entry_hash)
                .expect("same target entry");
            let TransactionEntrypoint::External(transaction) = entry else {
                panic!("expected wallet transaction");
            };
            let decoded_settlement = transaction
                .instructions()
                .explicit_instructions()
                .find_map(|isi| isi.as_any().downcast_ref::<SettleGameSessionV1>())
                .expect("same typed settlement");
            assert_eq!(decoded_settlement.proof.proof_bytes, expected);
            wire.push(0);
            assert!(
                block_from_wire(&wire).is_err(),
                "trailing wire bytes rejected"
            );
        }
        assert!(block_from_wire(&[]).is_err());
        assert!(block_from_wire(&vec![0; MAX_BLOCK_BYTES + 1]).is_err());
    }
    #[test]
    fn included_settlement_must_succeed_match_expectations_and_pass_native_proof_verification() {
        let settlement = invalid_settlement();
        let fixture = make_fixture(vec![settlement.clone().into()], true);
        assert!(
            expectations(&fixture)
                .verify_carriers(bundle(&fixture))
                .expect_err("rejected transaction")
                .to_string()
                .contains("was rejected")
        );
        let fixture = make_fixture(vec![settlement.clone().into()], false);
        let mut args = expectations(&fixture);
        assert!(
            args.verify_carriers(bundle(&fixture))
                .expect_err("wrong expected outcome")
                .to_string()
                .contains("independently selected")
        );
        args.outcome_hash = settlement.proof.statement.outcome_hash;
        assert!(
            args.verify_carriers(bundle(&fixture))
                .expect_err("invalid native proof despite signed QC")
                .to_string()
                .contains("native execution proof verification")
        );
        let duplicated = make_fixture(vec![settlement.clone().into(), settlement.into()], false);
        assert!(
            expectations(&duplicated)
                .verify_carriers(bundle(&duplicated))
                .expect_err("ambiguous duplicate settlement")
                .to_string()
                .contains("exactly one")
        );
    }
    #[test]
    #[ignore = "expensive end-to-end native execution proof and finalized settlement qualification"]
    fn genuine_execution_proof_and_finalized_settlement_verify_together() {
        use iroha_core_privacy::execution_proofs::{
            prove_race_v1, race_result_v1, race_transcript_root_v1, replay_race_v1,
        };
        use iroha_data_model::{
            execution_proofs::{
                RaceDnfEventV1, RaceInputFrameV1, RaceProverRequestV1, RaceReplayV1, RaceTrackV1,
            },
            game::{
                GameAccessV1, GameAdmissionBodyV1, GameAdmissionParticipantV1, GameManifestV1,
                GameOutcomeV1, GamePayoutPolicyV1, game_roster_hash_v1,
            },
        };
        use norito::codec::Encode as _;
        let network_id = fixture_network();
        let session_id = Hash::new(b"expected session");
        let profile_id = iroha_core_privacy::execution_proofs::race_profile_id_v1();
        let replay = RaceReplayV1 {
            track: RaceTrackV1::NeonTokyo,
            player_count: 2,
            frames: (0..6)
                .map(|tick| RaceInputFrameV1 {
                    tick,
                    controls: vec![1, 1],
                })
                .collect(),
            dnf_events: vec![RaceDnfEventV1 {
                tick: 6,
                slots: vec![0, 1],
            }],
        };
        let manifest = GameManifestV1 {
            version: 1,
            application_id: Hash::new(b"finality application"),
            profile_id,
            application_parameters: replay.track.encode(),
            min_participants: 2,
            max_participants: 2,
            batch_ticks: 6,
            max_ticks: 5400,
            max_input_bytes: 12,
            max_participant_data_bytes: 1,
            access: GameAccessV1::Public,
            payout_policy: GamePayoutPolicyV1::EqualWinnersOrRefund,
        };
        let result =
            race_result_v1(&replay_race_v1(&replay).expect("reference replay")).expect("outcome");
        let outcome = GameOutcomeV1 {
            terminal_tick: result.ticks,
            winner_slots: result.winners.clone(),
            result: result.encode(),
        };
        let outcome_hash = game_message_hash_v1(&network_id, "session-outcome", &outcome);
        let admission = GameAdmissionBodyV1 {
            version: 1,
            participants: (0..2)
                .map(|slot| {
                    let wallet = checked_keypair(Algorithm::Ed25519);
                    let input = checked_keypair(Algorithm::Ed25519);
                    GameAdmissionParticipantV1 {
                        account: AccountId::new(wallet.public_key().clone()),
                        input_key: input.public_key().clone(),
                        application_data: vec![slot],
                    }
                })
                .collect(),
            wagers: vec![],
            resources: vec![],
        };
        let proof = prove_race_v1(RaceProverRequestV1 {
            statement: ExecutionPublicInputsV1 {
                network_id,
                session_id,
                manifest_hash: game_message_hash_v1(&network_id, "session-manifest", &manifest),
                roster_hash: game_roster_hash_v1(&network_id, &session_id, &admission),
                transcript_root: race_transcript_root_v1(&network_id, &replay),
                dispute_root: Hash::new(b"finality fixture history"),
                outcome_hash,
            },
            manifest,
            admission,
            replay,
            checkpoint_state: None,
        })
        .expect("genuine native proof");
        let parent = make_fixture(Vec::new(), false);
        let fixture = make_fixture_after(
            vec![
                SettleGameSessionV1 {
                    session_id,
                    proof,
                    outcome: outcome.clone(),
                }
                .into(),
            ],
            false,
            Some(&parent),
        );
        let mut args = expectations(&fixture);
        args.outcome_hash = outcome_hash;
        args.trusted_checkpoint = parent.checkpoint_path.clone();
        let mut carriers = bundle(&fixture);
        carriers.finality.insert(
            0,
            norito::encode_canonical(&parent.finality).expect("parent finality"),
        );
        let verdict = args
            .verify_carriers(carriers)
            .expect("independently authenticated finalized settlement");
        assert_eq!(verdict["verified"].as_bool(), Some(true));
        assert_eq!(verdict["block_height"].as_str(), Some("3"));
        let promoted = SumeragiFinalityCheckpoint::decode_canonical(
            &STANDARD
                .decode(verdict["checkpoint_base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(promoted.height(), 3);
        assert_eq!(promoted.network_id(), args.network_id);
        assert_eq!(
            verdict["outcome"],
            norito::json::to_value(&outcome).expect("outcome JSON")
        );
        // Exercise both public artifact entrypoints with the same genuine proof
        // and the original external parent-context pin. Neither format may
        // replace that pin or bypass the actual execution verifier.
        let directory = tempfile::tempdir().unwrap();
        let parent_finality = norito::encode_canonical(&parent.finality).unwrap();
        let mut complete = bundle(&fixture);
        complete.finality.insert(0, parent_finality.clone());
        let single = norito::json!({"format":(BUNDLE_FORMAT),"version":1,
            "finality_chain_base64":(complete.finality.iter().map(|bytes| STANDARD.encode(bytes)).collect::<Vec<_>>()),
            "executed_block_wire_base64":(STANDARD.encode(&complete.block)),
            "block_proofs_base64":(STANDARD.encode(&complete.proofs))});
        args.bundle = directory.path().join("single-settlement.json");
        fs::write(&args.bundle, norito::json::to_json(&single).unwrap()).unwrap();
        assert_eq!(
            args.verify()
                .expect("tagged genuine single-file settlement"),
            verdict
        );
        args.bundle = write_index(directory.path(), &[parent_finality], &fixture);
        assert_eq!(
            args.verify().expect("tagged genuine indexed settlement"),
            verdict
        );
    }
    #[test]
    fn native_finality_cannot_replace_the_selected_wallet_signature() {
        let fixture =
            make_fixture_with_signature(vec![invalid_settlement().into()], false, None, false);
        assert!(
            expectations(&fixture)
                .verify_carriers(bundle(&fixture))
                .unwrap_err()
                .to_string()
                .contains("wallet signature")
        );
    }
    #[test]
    fn checkpoint_files_are_canonical_bounded_and_count_towards_the_local_budget() {
        let fixture = make_fixture(Vec::new(), false);
        let mut args = expectations(&fixture);
        let bytes = fs::read(&args.trusted_checkpoint).unwrap();
        args.max_finality_archive_bytes = bytes.len() as u64;
        let mut stream = FinalityStream::new(&args).unwrap();
        assert_eq!(stream.archive_bytes, bytes.len() as u64);
        assert!(
            stream
                .consume(&bundle(&fixture).finality)
                .unwrap_err()
                .to_string()
                .contains("byte budget")
        );
        args.max_finality_archive_bytes -= 1;
        assert!(FinalityStream::new(&args).is_err());
        args.max_finality_archive_bytes = DEFAULT_TOTAL_ARCHIVES;
        let mut trailing = bytes.clone();
        trailing.push(0);
        for rejected in [vec![], vec![0; 32], trailing] {
            fs::write(&args.trusted_checkpoint, rejected).unwrap();
            assert!(FinalityStream::new(&args).is_err());
        }
        let file = fs::File::create(&args.trusted_checkpoint).unwrap();
        file.set_len(MAX_FINALITY_CHECKPOINT_BYTES as u64 + 1)
            .unwrap();
        assert!(FinalityStream::new(&args).is_err());
        fs::write(&args.trusted_checkpoint, bytes).unwrap();
        assert!(FinalityStream::new(&args).is_ok());
    }
    #[test]
    fn cli_requires_native_checkpoint_and_rejects_the_retired_scalar_pin() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            args: VerifySettlementArgs,
        }
        let fixture = make_fixture(Vec::new(), false);
        let selected = expectations(&fixture);
        let mut args = vec![
            "verify-settlement".to_owned(),
            "--bundle".into(),
            "bundle.json".into(),
            "--network-id".into(),
            selected.network_id.to_string(),
            "--trusted-checkpoint".into(),
            selected.trusted_checkpoint.to_string_lossy().into_owned(),
            "--expected-entry-hash".into(),
            selected.expected_entry_hash.to_string(),
            "--session-id".into(),
            selected.session_id.to_string(),
            "--profile-id".into(),
            selected.profile_id.to_string(),
            "--outcome-hash".into(),
            selected.outcome_hash.to_string(),
        ];
        assert_eq!(
            Command::try_parse_from(&args)
                .unwrap()
                .args
                .trusted_checkpoint,
            selected.trusted_checkpoint
        );
        args[5] = "--trusted-context-id".into();
        args[6] = Hash::new(b"retired scalar pin").to_string();
        assert!(Command::try_parse_from(&args).is_err());
    }
    #[test]
    fn first_release_formats_are_closed_and_old_version_only_drafts_reject() {
        let bytes = |value: &Value| norito::json::to_json(value).unwrap().into_bytes();
        let current = norito::json!({"format":(BUNDLE_FORMAT),"version":1,
            "finality_chain_base64":(vec!["AQ=="]),"executed_block_wire_base64":"Ag==","block_proofs_base64":"Aw=="});
        assert!(parse_bundle(&bytes(&current)).is_ok());
        let mut no_format = current.clone();
        no_format.as_object_mut().unwrap().remove("format");
        assert!(parse_bundle(&bytes(&no_format)).is_err());
        for format in [BATCH_FORMAT, INDEX_FORMAT, "unknown"] {
            let mut wrong = current.clone();
            wrong
                .as_object_mut()
                .unwrap()
                .insert("format".into(), Value::from(format));
            assert!(parse_bundle(&bytes(&wrong)).is_err());
        }
        let mut wrong_version = current.clone();
        wrong_version
            .as_object_mut()
            .unwrap()
            .insert("version".into(), Value::from(2u64));
        assert!(parse_bundle(&bytes(&wrong_version)).is_err());
        let prefix = norito::json!({"format":(BATCH_FORMAT),"version":1,"finality_chain_base64":(vec!["AQ=="])});
        assert!(parse_prefix(&bytes(&prefix)).is_ok());
        assert!(
            parse_prefix(&bytes(
                &norito::json!({"version":1,"finality_chain_base64":(vec!["AQ=="])})
            ))
            .is_err()
        );
        let index = norito::json!({"format":(INDEX_FORMAT),"version":1,"finality_batches":(Vec::<Value>::new()),
            "settlement_bundle":{"file":"settlement-finality.json","sha256":("00".repeat(32)),"bytes":1}});
        assert!(parse_index(&bytes(&index), DEFAULT_TOTAL_ARCHIVES).is_ok());
        let mut draft_index = index.clone();
        draft_index.as_object_mut().unwrap().remove("format");
        draft_index
            .as_object_mut()
            .unwrap()
            .insert("version".into(), Value::from(2u64));
        assert!(parse_index(&bytes(&draft_index), DEFAULT_TOTAL_ARCHIVES).is_err());
        let fixture = make_fixture(Vec::new(), false);
        let directory = tempfile::tempdir().unwrap();
        let mut args = expectations(&fixture);
        args.bundle = directory.path().join("draft.json");
        for draft in [no_format, draft_index] {
            fs::write(&args.bundle, bytes(&draft)).unwrap();
            assert!(
                args.verify()
                    .unwrap_err()
                    .to_string()
                    .contains("first-release settlement format")
            );
        }
    }
    #[test]
    fn bundle_does_not_accept_a_transport_selected_trust_context() {
        let value = br#"{"format":"iroha.execution.settlement-bundle","version":1,"finality_chain_base64":["AQ=="],"executed_block_wire_base64":"AQ==","block_proofs_base64":"AQ==","trusted_context_id":"forged"}"#;
        assert!(parse_bundle(value).is_err());
        for name in [
            "trusted_checkpoint",
            "trusted_checkpoint_base64",
            "checkpoint_base64",
        ] {
            let mut injected: Value = norito::json::from_slice(value).unwrap();
            let fields = injected.as_object_mut().unwrap();
            fields.remove("trusted_context_id");
            fields.insert(name.into(), Value::from("endpoint-selected"));
            assert!(parse_bundle(norito::json::to_json(&injected).unwrap().as_bytes()).is_err());
        }
        assert!(parse_bundle(br#"{"format":"iroha.execution.settlement-bundle","version":1,"finality_chain_base64":[],"executed_block_wire_base64":"AQ==","block_proofs_base64":"AQ=="}"#).is_err());
    }
    #[test]
    fn bundle_rejects_noncanonical_base64_and_unbounded_chains() {
        assert!(base64_bytes(&Value::from("AR=="), 1).is_err());
        assert!(base64_bytes(&Value::from("AQI="), 1).is_err());
        let value = norito::json!({"format":(BUNDLE_FORMAT),"version":1,"finality_chain_base64":(vec!["AQ==";257]),"executed_block_wire_base64":"AQ==","block_proofs_base64":"AQ=="});
        assert!(parse_bundle(norito::json::to_json(&value).expect("json").as_bytes()).is_err());
    }
}
