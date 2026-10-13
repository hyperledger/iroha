//! Authenticated native verification for Torii block-entry proofs.
//!
//! The JavaScript SDK's pure Merkle helper deliberately cannot establish a trust anchor. This
//! module accepts the exact executed block wire and Torii's canonical finality/proof archives,
//! verifies native finality under an independently selected complete checkpoint, and only then asks
//! the data model to derive its non-serializable `TrustedBlockProofAnchor` capability.
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    block::{
        SignedBlock, decode_framed_signed_block,
        proofs::{
            AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1, BlockProofs,
            TrustedBlockProofAnchor,
        },
    },
    sumeragi_finality::{
        FinalityReadError, MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint,
        SumeragiFinalityProof, SumeragiFinalityVerifier,
    },
    transaction::signed::TransactionEntrypoint,
};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::{fmt, str::FromStr as _};
/// First-release authenticated block-proof bridge version.
const AUTHENTICATED_BLOCK_PROOFS_VERSION_V1: u8 = 1;
/// Maximum canonical Norito bytes accepted for one bridge finality proof.
const AUTHENTICATED_BLOCK_PROOFS_MAX_FINALITY_PROOF_BYTES_V1: usize = 36 * 1024 * 1024;
/// Maximum canonical Norito bytes accepted for one block-proof response.
const AUTHENTICATED_BLOCK_PROOFS_MAX_PROOF_BYTES_V1: usize = 16 * 1024 * 1024;
/// Bounded inputs for one authenticated block-proof verification.
///
/// The caller independently selects the complete `trusted_checkpoint_norito`.
/// The target must equal its exact authenticated decision or immediately extend it.
#[napi(object, use_nullable = true)]
pub struct JsAuthenticatedBlockProofInputV1 {
    /// Exact bridge ABI version. The first release requires `1`.
    pub version: u8,
    /// Application-pinned exact genesis-derived network identity.
    pub network_id: String,
    /// Independently authenticated canonical native checkpoint; never selected by this response.
    pub trusted_checkpoint_norito: Buffer,
    /// Application-selected, marked 32-byte transaction entrypoint hash.
    pub expected_entry_hash: Buffer,
    /// Canonical Norito `SumeragiFinalityProof` for the target block.
    pub finality_proof_norito: Buffer,
    /// Exact canonical executed `SignedBlockWire` bytes for the target block.
    pub executed_block_wire: Buffer,
    /// Canonical Norito `BlockProofs` bytes returned by Torii.
    pub block_proofs_norito: Buffer,
}
/// Authenticated native verdict for one Torii `BlockProofs` response.
///
/// Finality is valid whenever this object is returned. `valid` additionally
/// states whether the requested input/output proofs match the finality-bound
/// executed block. A malformed or unauthenticated input rejects the promise.
#[napi(object, use_nullable = true)]
pub struct JsAuthenticatedBlockProofVerdictV1 {
    /// Whether all input, output, geometry, root, and transcript checks passed.
    pub valid: bool,
    /// Stable verdict code (`valid` or `block_proofs_mismatch`).
    pub code: String,
    /// Authenticated block height, rendered losslessly as a decimal string.
    pub block_height: String,
    /// Authenticated block-header hash in lowercase hexadecimal.
    pub block_hash_hex: String,
    /// Authenticated executed-block-wire hash in lowercase hexadecimal.
    pub executed_block_wire_hash_hex: String,
    /// Authenticated target entrypoint hash in lowercase hexadecimal.
    pub entry_hash_hex: String,
    /// Authenticated native decision digest for diagnostics; not a trust root.
    pub context_id_hex: String,
    /// Complete checkpoint to promote only after every application proof succeeds; null otherwise.
    pub checkpoint_norito: Option<Buffer>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationErrorCode {
    UnsupportedVersion,
    InvalidNetworkId,
    InvalidCheckpoint,
    InvalidEntryHash,
    EmptyInput,
    InputTooLarge,
    NonCanonicalFinalityProof,
    NonCanonicalBlockProofs,
    NonCanonicalBlockWire,
    FinalityRejected,
    LocalUnavailable,
    AnchorRejected,
}
impl VerificationErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidNetworkId => "invalid_network_id",
            Self::InvalidCheckpoint => "invalid_checkpoint",
            Self::InvalidEntryHash => "invalid_entry_hash",
            Self::EmptyInput => "empty_input",
            Self::InputTooLarge => "input_too_large",
            Self::NonCanonicalFinalityProof => "noncanonical_finality_proof",
            Self::NonCanonicalBlockProofs => "noncanonical_block_proofs",
            Self::NonCanonicalBlockWire => "noncanonical_block_wire",
            Self::FinalityRejected => "finality_rejected",
            Self::LocalUnavailable => "local_unavailable",
            Self::AnchorRejected => "anchor_rejected",
        }
    }
}
#[derive(Debug)]
struct VerificationError {
    code: VerificationErrorCode,
    message: String,
    // Retain the actual unfinished finality attempt until the terminal N-API projection.
    original: Option<FinalityReadError>,
}
impl VerificationError {
    fn new(code: VerificationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            original: None,
        }
    }
    fn from_finality(error: FinalityReadError) -> Self {
        match error {
            original @ (FinalityReadError::DecodeResource(_)
            | FinalityReadError::ScratchLimit(_)
            | FinalityReadError::Allocator(_)) => Self {
                code: VerificationErrorCode::LocalUnavailable,
                message: String::new(),
                original: Some(original),
            },
            // TODO: migrate the earlier original genesis JSON and archive reads to
            // captured typed attempts too; this repair closes the new finality owner API.
            completed => Self::new(
                VerificationErrorCode::FinalityRejected,
                completed.to_string(),
            ),
        }
    }
    fn into_napi(self) -> napi::Error {
        let status = if self.original.is_some() {
            napi::Status::GenericFailure
        } else {
            napi::Status::InvalidArg
        };
        napi::Error::new(status, self.to_string())
    }
}
impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(original) = &self.original {
            return write!(
                formatter,
                "authenticated_block_proofs_v1/local_unavailable: {original}"
            );
        }
        write!(
            formatter,
            "authenticated_block_proofs_v1/{}: {}",
            self.code.as_str(),
            self.message
        )
    }
}
struct RawVerificationInputV1<'a> {
    version: u8,
    network_id: &'a str,
    trusted_checkpoint_norito: &'a [u8],
    expected_entry_hash: &'a [u8],
    finality_proof_norito: &'a [u8],
    executed_block_wire: &'a [u8],
    block_proofs_norito: &'a [u8],
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedBlockProofVerdictV1 {
    valid: bool,
    block_height: u64,
    block_hash_hex: String,
    executed_block_wire_hash_hex: String,
    entry_hash_hex: String,
    context_id_hex: String,
    checkpoint_norito: Option<Vec<u8>>,
}
impl From<AuthenticatedBlockProofVerdictV1> for JsAuthenticatedBlockProofVerdictV1 {
    fn from(verdict: AuthenticatedBlockProofVerdictV1) -> Self {
        Self {
            valid: verdict.valid,
            code: if verdict.valid {
                "valid".to_owned()
            } else {
                "block_proofs_mismatch".to_owned()
            },
            block_height: verdict.block_height.to_string(),
            block_hash_hex: verdict.block_hash_hex,
            executed_block_wire_hash_hex: verdict.executed_block_wire_hash_hex,
            entry_hash_hex: verdict.entry_hash_hex,
            context_id_hex: verdict.context_id_hex,
            checkpoint_norito: verdict.checkpoint_norito.map(Buffer::from),
        }
    }
}
/// Verify one Torii `BlockProofs` response through Rust-authenticated finality.
///
/// The CPU-heavy BLS and Merkle work runs outside the Node event loop. Every
/// archive is size-checked before decoding and must be an exact canonical V1
/// re-encoding. Cryptographic or binding failures reject the promise; a valid
/// finality chain carrying mismatched block proofs resolves to `valid: false`.
#[allow(clippy::trailing_empty_array, reason = "generated N-API callback ABI")]
#[napi(js_name = "blockProofsVerifyAuthenticatedV1")]
pub async fn block_proofs_verify_authenticated_v1(
    input: JsAuthenticatedBlockProofInputV1,
) -> napi::Result<JsAuthenticatedBlockProofVerdictV1> {
    tokio::task::spawn_blocking(move || {
        verify_raw_v1(RawVerificationInputV1 {
            version: input.version,
            network_id: &input.network_id,
            trusted_checkpoint_norito: input.trusted_checkpoint_norito.as_ref(),
            expected_entry_hash: input.expected_entry_hash.as_ref(),
            finality_proof_norito: input.finality_proof_norito.as_ref(),
            executed_block_wire: input.executed_block_wire.as_ref(),
            block_proofs_norito: input.block_proofs_norito.as_ref(),
        })
        .map(JsAuthenticatedBlockProofVerdictV1::from)
    })
    .await
    .map_err(|error| {
        napi::Error::new(
            napi::Status::GenericFailure,
            format!("authenticated BlockProofs verifier task failed: {error}"),
        )
    })?
    .map_err(VerificationError::into_napi)
}
fn verify_raw_v1(
    input: RawVerificationInputV1<'_>,
) -> Result<AuthenticatedBlockProofVerdictV1, VerificationError> {
    if input.version != AUTHENTICATED_BLOCK_PROOFS_VERSION_V1 {
        return Err(VerificationError::new(
            VerificationErrorCode::UnsupportedVersion,
            format!(
                "version {} is unsupported; expected {AUTHENTICATED_BLOCK_PROOFS_VERSION_V1}",
                input.version
            ),
        ));
    }
    let network_id = NetworkId::from_str(input.network_id).map_err(|error| {
        VerificationError::new(
            VerificationErrorCode::InvalidNetworkId,
            format!("network_id is not canonical: {error}"),
        )
    })?;
    if network_id.to_string() != input.network_id {
        return Err(VerificationError::new(
            VerificationErrorCode::InvalidNetworkId,
            "network_id must use the canonical checked genesis-hash literal",
        ));
    }
    enforce_archive_size(
        input.trusted_checkpoint_norito,
        MAX_FINALITY_CHECKPOINT_BYTES,
        "trusted_checkpoint_norito",
    )?;
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(input.trusted_checkpoint_norito)
        .map_err(|error| {
            VerificationError::new(VerificationErrorCode::InvalidCheckpoint, error.to_string())
        })?;
    let expected_entry_hash = parse_entry_hash(input.expected_entry_hash)?;
    let finality = decode_finality_proof(input.finality_proof_norito, "finality_proof_norito")?;
    let mut finality_verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &checkpoint,
        &network_id,
        checkpoint.chain_id(),
    )
    .map_err(VerificationError::from_finality)?;
    let verified = if finality.height() == checkpoint.height() {
        finality_verifier.verify_same_decision(checkpoint.tip(), &finality)
    } else {
        finality_verifier.verify(&finality)
    }
    .map_err(VerificationError::from_finality)?;
    // Authenticate bounded checkpoint/finality inputs before decoding the execution
    // and Merkle carriers. An invalid QC cannot reach those decoders. Bind the block before
    // touching the proof archive so a wrong wire cannot amplify through it.
    let block = decode_executed_block_wire(input.executed_block_wire)?;
    // The exact candidate wire is bound only through the authenticated native capability.
    let anchor =
        TrustedBlockProofAnchor::from_verified_finality(&block, &verified, &expected_entry_hash)
            .map_err(|error| {
                VerificationError::new(
                    VerificationErrorCode::AnchorRejected,
                    format!("finality-bound executed block could not derive an anchor: {error}"),
                )
            })?;
    let block_proofs = decode_block_proofs(input.block_proofs_norito)?;
    let valid = block_proofs.verify(&anchor);
    let checkpoint_norito = if valid {
        Some(
            finality_verifier
                .export_checkpoint(&finality)
                .map_err(VerificationError::from_finality)?
                .encode_canonical()
                .map_err(|error| {
                    VerificationError::new(
                        VerificationErrorCode::FinalityRejected,
                        error.to_string(),
                    )
                })?,
        )
    } else {
        None
    };
    Ok(AuthenticatedBlockProofVerdictV1 {
        valid,
        block_height: anchor.block_height().get(),
        block_hash_hex: hex::encode(anchor.block_hash().as_ref()),
        executed_block_wire_hash_hex: hex::encode(anchor.executed_block_wire_hash().as_ref()),
        entry_hash_hex: hex::encode(anchor.entry_hash().as_ref()),
        context_id_hex: hex::encode(verified.context_id().as_ref()),
        checkpoint_norito,
    })
}
fn parse_entry_hash(bytes: &[u8]) -> Result<HashOf<TransactionEntrypoint>, VerificationError> {
    parse_marked_hash(
        bytes,
        "expected_entry_hash",
        VerificationErrorCode::InvalidEntryHash,
    )
    .map(HashOf::<TransactionEntrypoint>::from_untyped_unchecked)
}
fn parse_marked_hash(
    bytes: &[u8],
    label: &'static str,
    code: VerificationErrorCode,
) -> Result<Hash, VerificationError> {
    let exact: [u8; Hash::LENGTH] = bytes.try_into().map_err(|_| {
        VerificationError::new(
            code,
            format!(
                "{label} must contain exactly {} marked hash bytes",
                Hash::LENGTH
            ),
        )
    })?;
    let hash = Hash::from_str(&hex::encode(exact)).map_err(|error| {
        VerificationError::new(code, format!("{label} is not a marked Iroha hash: {error}"))
    })?;
    Ok(hash)
}
fn decode_finality_proof(
    bytes: &[u8],
    label: &'static str,
) -> Result<SumeragiFinalityProof, VerificationError> {
    enforce_archive_size(
        bytes,
        AUTHENTICATED_BLOCK_PROOFS_MAX_FINALITY_PROOF_BYTES_V1,
        label,
    )?;
    decode_canonical_archive(
        bytes,
        label,
        VerificationErrorCode::NonCanonicalFinalityProof,
    )
}
fn decode_block_proofs(bytes: &[u8]) -> Result<BlockProofs, VerificationError> {
    const LABEL: &str = "block_proofs_norito";
    enforce_archive_size(bytes, AUTHENTICATED_BLOCK_PROOFS_MAX_PROOF_BYTES_V1, LABEL)?;
    decode_canonical_archive(bytes, LABEL, VerificationErrorCode::NonCanonicalBlockProofs)
}
fn decode_canonical_archive<T>(
    bytes: &[u8],
    label: &'static str,
    code: VerificationErrorCode,
) -> Result<T, VerificationError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let limits = authenticated_decode_limits(bytes.len());
    norito::decode_canonical_with_limits(bytes, limits).map_err(|error| {
        VerificationError::new(
            code,
            format!("{label} is not bounded canonical Norito: {error}"),
        )
    })
}
fn decode_executed_block_wire(bytes: &[u8]) -> Result<SignedBlock, VerificationError> {
    const LABEL: &str = "executed_block_wire";
    enforce_archive_size(
        bytes,
        AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
        LABEL,
    )?;
    let limits = authenticated_decode_limits(bytes.len());
    let block =
        norito::core::with_decode_limits_scope(limits, || decode_framed_signed_block(bytes))
            // TODO: give the host terminal ABI a distinct local-unavailable outcome. The
            // canonical decoder retains the original cause up to this fixed JS boundary.
            .map_err(|error| {
                VerificationError::new(
                    VerificationErrorCode::NonCanonicalBlockWire,
                    format!("{LABEL} did not decode as SignedBlockWire: {error}"),
                )
            })?;
    Ok(block)
}
fn authenticated_decode_limits(encoded_len: usize) -> norito::DecodeLimits {
    let canonical = norito::canonical_decode_limits(encoded_len);
    norito::DecodeLimits::new(
        canonical.max_sequence_elements(),
        canonical.max_field_bytes(),
        canonical.max_total_elements(),
        encoded_len.saturating_mul(12).saturating_add(1024 * 1024),
        128,
    )
}
fn enforce_archive_size(
    bytes: &[u8],
    maximum: usize,
    label: &'static str,
) -> Result<(), VerificationError> {
    if bytes.is_empty() {
        return Err(VerificationError::new(
            VerificationErrorCode::EmptyInput,
            format!("{label} must not be empty"),
        ));
    }
    if bytes.len() > maximum {
        return Err(VerificationError::new(
            VerificationErrorCode::InputTooLarge,
            format!("{label} exceeds its {maximum}-byte limit"),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair, MerkleTreeCommitment};
    use iroha_data_model::{
        account::AccountId,
        block::{
            CommitCertificate, builder::BlockBuilder, execution_output::ExecutionOutputV1,
            proofs::ExecutionReceiptProof,
        },
        isi::Log,
        level::Level,
        testing::native_finality::NativeFinalityFixture,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use std::num::NonZeroU64;

    struct Fixture {
        native: NativeFinalityFixture,
        block: SignedBlock,
        finality: SumeragiFinalityProof,
        block_proofs: BlockProofs,
        alternate_block_proofs: BlockProofs,
        checkpoint: Vec<u8>,
        network: String,
    }
    #[test]
    fn captured_finality_reader_owner_stays_local_until_terminal_js_projection() {
        let frame = norito::encode_canonical(&vec![1_u8; 32]).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let attempt = norito::with_decode_limits_scope(limits, || {
            norito::core::classify_decode_attempt(|| norito::decode_canonical::<Vec<u8>>(&frame))
        })
        .unwrap_err();
        let original = attempt.local_refusal().unwrap();
        let error = VerificationError::from_finality(attempt.into());
        assert_eq!(error.code, VerificationErrorCode::LocalUnavailable);
        let Some(FinalityReadError::DecodeResource(retained)) = error.original.as_ref() else {
            panic!("actual finality decoder owner must be retained")
        };
        assert_eq!(retained.local_refusal(), Some(original));
        let terminal = error.into_napi();
        assert_eq!(terminal.status, napi::Status::GenericFailure);
        assert!(
            terminal
                .reason
                .starts_with("authenticated_block_proofs_v1/local_unavailable:")
        );
        assert_eq!(
            norito::decode_canonical::<Vec<u8>>(&frame).unwrap(),
            vec![1_u8; 32]
        );
        let invalid = VerificationError::from_finality(
            iroha_data_model::sumeragi_finality::FinalityError("original completed failure".into())
                .into(),
        );
        assert!(invalid.original.is_none());
        assert_eq!(invalid.code, VerificationErrorCode::FinalityRejected);
        let invalid = invalid.into_napi();
        assert_eq!(invalid.status, napi::Status::InvalidArg);
        assert_eq!(
            invalid.reason,
            "authenticated_block_proofs_v1/finality_rejected: current finality: original completed failure"
        );
    }

    fn make_fixture() -> Fixture {
        extend(NativeFinalityFixture::start("js-native-block-proofs"))
    }
    fn extend(mut native: NativeFinalityFixture) -> Fixture {
        let mut builder = BlockBuilder::new(native.next_header());
        for _ in 0..2 {
            let key = KeyPair::try_random_with_algorithm(Algorithm::Ed25519).unwrap();
            let tx = TransactionBuilder::new(
                native.network_id(),
                AccountId::new(key.public_key().clone()),
                FeePaymentIntent::authority(vec![], None),
            )
            .with_instructions([Log::new(Level::INFO, "native proof fixture".into())])
            .sign(key.private_key());
            builder.push_transaction(tx);
        }
        let mut block = builder.build(iroha_data_model::block::BlockSignatures::default());
        NativeFinalityFixture::install_network_results(&mut block, vec![Ok(Vec::new()); 2]);
        let entries: Vec<_> = block.network_input_hashes().collect();
        let block_proofs = block.network_execution_proof(&entries[0]).unwrap();
        let alternate_block_proofs = block.network_execution_proof(&entries[1]).unwrap();
        let finality = native.certify(block.clone());
        let checkpoint = native.checkpoint().encode_canonical().unwrap();
        let network = native.network_id().to_string();
        Fixture {
            native,
            block,
            finality,
            block_proofs,
            alternate_block_proofs,
            checkpoint,
            network,
        }
    }
    fn verify_typed(
        fixture: &Fixture,
        proof: &SumeragiFinalityProof,
        block: &SignedBlock,
        proofs: &BlockProofs,
        network: &str,
        checkpoint: &[u8],
    ) -> Result<AuthenticatedBlockProofVerdictV1, VerificationError> {
        let finality = norito::encode_canonical(proof).unwrap();
        let wire = block.encode_wire().unwrap();
        let proofs = norito::encode_canonical(proofs).unwrap();
        verify_raw_v1(RawVerificationInputV1 {
            version: 1,
            network_id: network,
            trusted_checkpoint_norito: checkpoint,
            expected_entry_hash: fixture.block_proofs.entry_hash.as_ref(),
            finality_proof_norito: &finality,
            executed_block_wire: &wire,
            block_proofs_norito: &proofs,
        })
    }
    fn verify(fixture: &Fixture) -> Result<AuthenticatedBlockProofVerdictV1, VerificationError> {
        verify_typed(
            fixture,
            &fixture.finality,
            &fixture.block,
            &fixture.block_proofs,
            &fixture.network,
            &fixture.checkpoint,
        )
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
    fn assert_rejected_finality(fixture: &Fixture, proof: &SumeragiFinalityProof) {
        let error = verify_typed(
            fixture,
            proof,
            &fixture.block,
            &fixture.block_proofs,
            &fixture.network,
            &fixture.checkpoint,
        )
        .unwrap_err();
        assert_eq!(error.code, VerificationErrorCode::FinalityRejected);
    }
    #[test]
    fn real_finality_block_wire_and_proofs_produce_authenticated_verdict() {
        let fixture = make_fixture();
        let verdict = verify(&fixture).unwrap();
        assert!(verdict.valid);
        assert_eq!(verdict.block_height, 2);
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(
            verdict.checkpoint_norito.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(checkpoint.height(), 2);
        assert_eq!(checkpoint.block_hash(), fixture.block.hash());
        let verifier = fixture.native.verifier();
        let authenticated = verifier
            .verify_same_decision(&fixture.finality, &fixture.finality)
            .unwrap();
        assert_eq!(
            verdict.context_id_hex,
            hex::encode(authenticated.context_id().as_ref())
        );
    }
    #[test]
    fn exported_boundary_authenticates_fixture() {
        let fixture = make_fixture();
        let input = JsAuthenticatedBlockProofInputV1 {
            version: 1,
            network_id: fixture.network,
            trusted_checkpoint_norito: Buffer::from(fixture.checkpoint),
            expected_entry_hash: Buffer::from(fixture.block_proofs.entry_hash.as_ref().to_vec()),
            finality_proof_norito: Buffer::from(
                norito::encode_canonical(&fixture.finality).unwrap(),
            ),
            executed_block_wire: Buffer::from(fixture.block.encode_wire().unwrap()),
            block_proofs_norito: Buffer::from(
                norito::encode_canonical(&fixture.block_proofs).unwrap(),
            ),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let verdict = runtime
            .block_on(block_proofs_verify_authenticated_v1(input))
            .unwrap();
        assert!(verdict.valid);
        assert_eq!(verdict.code, "valid");
        assert_eq!(verdict.block_height, "2");
        assert!(verdict.checkpoint_norito.is_some());
    }
    #[test]
    fn forged_qc_pop_and_roster_fail_before_anchor_derivation() {
        let fixture = make_fixture();
        let mut forged = fixture.finality.clone();
        alter_qc(&mut forged, |qc| qc.agg_sig.0[0] ^= 0x80);
        assert_rejected_finality(&fixture, &forged);
        let bytes = norito::encode_canonical(&forged).unwrap();
        let preflight = verify_raw_v1(RawVerificationInputV1 {
            version: 1,
            network_id: &fixture.network,
            trusted_checkpoint_norito: &fixture.checkpoint,
            expected_entry_hash: fixture.block_proofs.entry_hash.as_ref(),
            finality_proof_norito: &bytes,
            executed_block_wire: &[],
            block_proofs_norito: &[],
        })
        .unwrap_err();
        assert_eq!(preflight.code, VerificationErrorCode::FinalityRejected);
        let mut forged = fixture.finality.clone();
        forged.committee[0].proof_of_possession[0] ^= 0x80;
        assert_rejected_finality(&fixture, &forged);
        let mut forged = fixture.finality.clone();
        forged.committee.swap(0, 1);
        assert_rejected_finality(&fixture, &forged);
        let mut forged = fixture.finality.clone();
        alter_qc(&mut forged, |qc| {
            qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1]).unwrap()
        });
        assert_rejected_finality(&fixture, &forged);
    }
    #[test]
    fn wrong_network_checkpoint_header_height_and_wire_fail_closed() {
        let fixture = make_fixture();
        let foreign = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"foreign network",
        )))
        .to_string();
        let error = verify_typed(
            &fixture,
            &fixture.finality,
            &fixture.block,
            &fixture.block_proofs,
            &foreign,
            &fixture.checkpoint,
        )
        .unwrap_err();
        assert_eq!(error.code, VerificationErrorCode::FinalityRejected);
        let other = make_fixture();
        let error = verify_typed(
            &fixture,
            &fixture.finality,
            &fixture.block,
            &fixture.block_proofs,
            &fixture.network,
            &other.checkpoint,
        )
        .unwrap_err();
        assert_eq!(error.code, VerificationErrorCode::FinalityRejected);
        let mut wrong = fixture.finality.clone();
        wrong.block_header.set_view_change_index(1);
        assert_rejected_finality(&fixture, &wrong);
        let mut wrong = fixture.finality.clone();
        alter_qc(&mut wrong, |qc| qc.height += 1);
        assert_rejected_finality(&fixture, &wrong);
        let error = verify_typed(
            &fixture,
            &fixture.finality,
            &other.block,
            &fixture.block_proofs,
            &fixture.network,
            &fixture.checkpoint,
        )
        .unwrap_err();
        assert_eq!(error.code, VerificationErrorCode::AnchorRejected);
    }
    #[test]
    fn exact_successor_promotes_complete_checkpoint_and_stale_or_skipped_proofs_reject() {
        let first = make_fixture();
        let second = extend(first.native.clone());
        let third = extend(second.native.clone());
        let verified = verify_typed(
            &second,
            &second.finality,
            &second.block,
            &second.block_proofs,
            &second.network,
            &first.checkpoint,
        )
        .unwrap();
        assert!(verified.valid);
        assert_eq!(
            verified.checkpoint_norito.as_deref(),
            Some(second.checkpoint.as_slice()),
            "checkpoint promotion must retain the exact verified successor"
        );
        assert_eq!(
            SumeragiFinalityCheckpoint::decode_canonical(
                verified.checkpoint_norito.as_ref().unwrap()
            )
            .unwrap()
            .height(),
            3
        );
        let stale = verify_typed(
            &first,
            &first.finality,
            &first.block,
            &first.block_proofs,
            &first.network,
            &second.checkpoint,
        )
        .unwrap_err();
        assert_eq!(stale.code, VerificationErrorCode::FinalityRejected);
        let skipped = verify_typed(
            &third,
            &third.finality,
            &third.block,
            &third.block_proofs,
            &third.network,
            &first.checkpoint,
        )
        .unwrap_err();
        assert_eq!(skipped.code, VerificationErrorCode::FinalityRejected);
    }
    #[test]
    fn root_geometry_result_and_transcript_mutations_return_invalid_verdicts_without_checkpoint() {
        let fixture = make_fixture();
        let assert_invalid = |proofs: &BlockProofs| {
            let verdict = verify_typed(
                &fixture,
                &fixture.finality,
                &fixture.block,
                proofs,
                &fixture.network,
                &fixture.checkpoint,
            )
            .unwrap();
            assert!(!verdict.valid);
            assert!(verdict.checkpoint_norito.is_none());
        };
        let mut changed = fixture.block_proofs.clone();
        changed.entry_commitment = MerkleTreeCommitment::new(
            HashOf::from_untyped_unchecked(Hash::new(b"forged root")),
            changed.entry_commitment.leaf_count(),
        );
        assert_invalid(&changed);
        let mut changed = fixture.block_proofs.clone();
        changed.entry_commitment = MerkleTreeCommitment::new(
            *changed.entry_commitment.root(),
            NonZeroU64::new(changed.entry_commitment.leaf_count().get() + 1).unwrap(),
        );
        assert_invalid(&changed);
        let mut changed = fixture.block_proofs.clone();
        let ExecutionOutputV1::Network(row) = changed.output_proof.output() else {
            panic!("network fixture")
        };
        changed.output_proof = ExecutionReceiptProof::new(
            ExecutionOutputV1::network_output_limit_rejection(row.input_index),
            changed.output_proof.proof().clone(),
        );
        assert_invalid(&changed);
        let mut changed = fixture.block_proofs.clone();
        changed
            .fastpq_transcripts
            .insert(Hash::new(b"forged transcript"), Vec::new());
        assert_invalid(&changed);
        assert_invalid(&fixture.alternate_block_proofs);
    }
    #[test]
    fn raw_boundary_rejects_malformed_checkpoint_unmarked_hash_and_noncanonical_archives() {
        let fixture = make_fixture();
        let finality = norito::encode_canonical(&fixture.finality).unwrap();
        let proofs = norito::encode_canonical(&fixture.block_proofs).unwrap();
        let wire = fixture.block.encode_wire().unwrap();
        let mut entry: [u8; 32] = *fixture.block_proofs.entry_hash.as_ref();
        entry[31] &= !1;
        let run = |checkpoint: &[u8], entry: &[u8], finality: &[u8], wire: &[u8], proofs: &[u8]| {
            verify_raw_v1(RawVerificationInputV1 {
                version: 1,
                network_id: &fixture.network,
                trusted_checkpoint_norito: checkpoint,
                expected_entry_hash: entry,
                finality_proof_norito: finality,
                executed_block_wire: wire,
                block_proofs_norito: proofs,
            })
            .unwrap_err()
            .code
        };
        assert_eq!(
            run(
                &[1],
                fixture.block_proofs.entry_hash.as_ref(),
                &finality,
                &wire,
                &proofs
            ),
            VerificationErrorCode::InvalidCheckpoint
        );
        assert_eq!(
            run(&fixture.checkpoint, &entry, &finality, &wire, &proofs),
            VerificationErrorCode::InvalidEntryHash
        );
        assert_eq!(
            run(
                &fixture.checkpoint,
                fixture.block_proofs.entry_hash.as_ref(),
                &finality,
                &[1],
                &[]
            ),
            VerificationErrorCode::NonCanonicalBlockWire
        );
        for retired_scalar_anchor in [vec![0; 32], vec![1; 32]] {
            assert_eq!(
                run(
                    &retired_scalar_anchor,
                    fixture.block_proofs.entry_hash.as_ref(),
                    &finality,
                    &wire,
                    &proofs
                ),
                VerificationErrorCode::InvalidCheckpoint,
            );
        }
        let mut malformed = fixture.checkpoint.clone();
        malformed.push(0);
        assert_eq!(
            run(
                &malformed,
                fixture.block_proofs.entry_hash.as_ref(),
                &finality,
                &wire,
                &proofs
            ),
            VerificationErrorCode::InvalidCheckpoint
        );
        let mut malformed = finality.clone();
        malformed.push(0);
        assert_eq!(
            run(
                &fixture.checkpoint,
                fixture.block_proofs.entry_hash.as_ref(),
                &malformed,
                &wire,
                &proofs
            ),
            VerificationErrorCode::NonCanonicalFinalityProof
        );
        let mut malformed = proofs.clone();
        malformed.push(0);
        assert_eq!(
            run(
                &fixture.checkpoint,
                fixture.block_proofs.entry_hash.as_ref(),
                &finality,
                &wire,
                &malformed
            ),
            VerificationErrorCode::NonCanonicalBlockProofs
        );
        let mut headerless = vec![wire[0]];
        headerless.extend_from_slice(&wire[1 + norito::core::Header::SIZE..]);
        assert_eq!(
            run(
                &fixture.checkpoint,
                fixture.block_proofs.entry_hash.as_ref(),
                &finality,
                &headerless,
                &proofs
            ),
            VerificationErrorCode::NonCanonicalBlockWire
        );
    }
    #[test]
    fn size_preflight_rejects_before_decode() {
        let oversized = vec![0; AUTHENTICATED_BLOCK_PROOFS_MAX_FINALITY_PROOF_BYTES_V1 + 1];
        assert_eq!(
            decode_finality_proof(&oversized, "oversized")
                .unwrap_err()
                .code,
            VerificationErrorCode::InputTooLarge
        );
        assert_eq!(
            decode_block_proofs(&[]).unwrap_err().code,
            VerificationErrorCode::EmptyInput
        );
    }
}
