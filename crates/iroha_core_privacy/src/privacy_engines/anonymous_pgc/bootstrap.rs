//! Native proof that a complete Anonymous-PGC account table starts from a
//! bounded, nonnegative public total supply.
//!
//! Every encrypted balance receives both a generalized Schnorr well-formedness proof and an exact
//! unsigned 32-bit bit-decomposition proof. A final Schnorr proof shows that the aggregate right
//! component opens to the declared total supply. Since the closed profile contains at most 64
//! accounts, `64 * (2^32 - 1)` is far below the P-256 scalar order; aggregate equality in the group
//! is therefore equality of the represented integers, not merely equality modulo the scalar field.
use super::{
    AnonymousPgcError, AnonymousPgcParametersV1, AnonymousPgcReadError, TwistedElGamalCiphertextV1,
    TwistedElGamalPublicKeyV1, fixed_array::FixedProofArray,
};
use crate::privacy_engines::p256::{
    CanonicalScalarV1, CompressedPointV1, P256EngineError, SecretScalarV1, TranscriptBindingV1,
    TranscriptV1, health_checked_p256_rng_v1, random_nonzero_scalar,
};
use p256::{ProjectivePoint, Scalar};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
/// Closed suite for the complete PGC account-bootstrap proof.
pub const PGC_BOOTSTRAP_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.account-bootstrap.p256.sha256.v1";
/// Canonical bootstrap-proof wire version.
pub const PGC_BOOTSTRAP_PROOF_VERSION_V1: u8 = 1;
/// Only admissible initial account-state epoch for a first-release bootstrap.
pub const PGC_BOOTSTRAP_INITIAL_EPOCH_V1: u64 = 1;
/// Closed first-release account-table sizes.
pub const PGC_BOOTSTRAP_ACCOUNT_COUNTS_V1: [usize; 3] = [16, 32, 64];
/// Maximum exact canonical namespace bytes absorbed by a bootstrap transcript.
pub const MAX_PGC_BOOTSTRAP_NAMESPACE_BYTES_V1: usize = 256;
/// Maximum canonical bytes accepted for one complete bootstrap proof.
pub const MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1: usize = 4 * 1024 * 1024;
/// Largest possible sum before applying the public `u32` supply restriction.
pub const PGC_BOOTSTRAP_MAX_AGGREGATE_BALANCE_V1: u64 = 64_u64 * u32::MAX as u64;
/// Domain separator for the canonical bootstrap-table digest.
pub const PGC_BOOTSTRAP_TABLE_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.anonymous-pgc.account-bootstrap.table.v1";
/// Closed field framing absorbed by the canonical bootstrap-table digest.
pub const PGC_BOOTSTRAP_TABLE_DIGEST_SCHEMA_V1: &[u8] = b"namespace_len:u32be|namespace:bytes|initial_root:32|initial_epoch:u64be|total_supply:u32be|account_count:u32be|accounts[index:u32be,public_key:33,cipher_left:33,cipher_right:33]";
const WELL_FORMED_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.account-bootstrap.well-formed.v1";
const RANGE_SUITE_V1: &[u8] = b"iroha.anonymous-pgc.account-bootstrap.range32.v1";
const AGGREGATE_SUPPLY_SUITE_V1: &[u8] =
    b"iroha.anonymous-pgc.account-bootstrap.aggregate-supply.v1";
const RANGE_BITS: usize = 32;
const MAX_PROVER_RESTARTS: usize = 128;
fn bootstrap_proof_decode_limits(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    payload_len: usize,
) -> norito::DecodeLimits {
    let account_count = statement.account_count();
    norito::DecodeLimits::new(
        account_count,
        payload_len,
        account_count,
        MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1.saturating_mul(4),
        24,
    )
}
/// Public input for one complete PGC account bootstrap.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousPgcBootstrapStatementV1<'a> {
    namespace_encoding: &'a [u8],
    initial_root: [u8; 32],
    initial_epoch: u64,
    total_supply: u32,
    public_keys: &'a [TwistedElGamalPublicKeyV1],
    encrypted_balances: &'a [TwistedElGamalCiphertextV1],
    transcript_binding: TranscriptBindingV1<'a>,
    bootstrap_table_digest: [u8; 32],
}
impl<'a> AnonymousPgcBootstrapStatementV1<'a> {
    /// Construct a fully bound account-bootstrap statement.
    ///
    /// `namespace_encoding` must be the exact canonical Norito encoding of the already validated
    /// PGC [`iroha_data_model::privacy::PrivacyNamespaceV1`]. Keeping it as opaque bytes here
    /// avoids coupling the native cryptographic substrate to the runtime data model while still
    /// binding the complete namespace.
    ///
    /// # Errors
    ///
    /// Rejects an initial epoch other than the exact first-release value before validating or
    /// allocating for any other statement field. Also rejects an empty/oversized namespace, zero
    /// root/supply, unsupported account count, length mismatch, unsorted or duplicate keys,
    /// malformed points, or governed transcript-digest mismatches.
    pub fn new(
        namespace_encoding: &'a [u8],
        initial_root: [u8; 32],
        initial_epoch: u64,
        total_supply: u32,
        public_keys: &'a [TwistedElGamalPublicKeyV1],
        encrypted_balances: &'a [TwistedElGamalCiphertextV1],
        transcript_binding: TranscriptBindingV1<'a>,
    ) -> Result<Self, AnonymousPgcError> {
        if initial_epoch != PGC_BOOTSTRAP_INITIAL_EPOCH_V1 {
            return Err(AnonymousPgcError::InvalidBootstrapEpoch {
                actual: initial_epoch,
                expected: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
            });
        }
        super::validate_binding(&transcript_binding)?;
        if namespace_encoding.is_empty()
            || namespace_encoding.len() > MAX_PGC_BOOTSTRAP_NAMESPACE_BYTES_V1
        {
            return Err(AnonymousPgcError::InvalidBootstrapNamespaceLength {
                actual: namespace_encoding.len(),
                max: MAX_PGC_BOOTSTRAP_NAMESPACE_BYTES_V1,
            });
        }
        if initial_root == [0; 32] {
            return Err(AnonymousPgcError::ZeroBootstrapRoot);
        }
        if total_supply == 0 {
            return Err(AnonymousPgcError::ZeroPgcTotalSupply);
        }
        let count = public_keys.len();
        if !PGC_BOOTSTRAP_ACCOUNT_COUNTS_V1.contains(&count) {
            return Err(AnonymousPgcError::InvalidBootstrapAccountCount { count });
        }
        if encrypted_balances.len() != count {
            return Err(AnonymousPgcError::BootstrapLengthMismatch {
                public_keys: count,
                encrypted_balances: encrypted_balances.len(),
            });
        }
        for (index, key) in public_keys.iter().enumerate() {
            let _ = key.point.to_projective()?;
            if index > 0 && public_keys[index - 1].point >= key.point {
                return Err(AnonymousPgcError::BootstrapKeysNotStrictlyIncreasing);
            }
        }
        for ciphertext in encrypted_balances {
            ciphertext.validate()?;
        }
        let bootstrap_table_digest = bootstrap_table_digest(
            namespace_encoding,
            initial_root,
            initial_epoch,
            total_supply,
            public_keys,
            encrypted_balances,
        )?;
        Ok(Self {
            namespace_encoding,
            initial_root,
            initial_epoch,
            total_supply,
            public_keys,
            encrypted_balances,
            transcript_binding,
            bootstrap_table_digest,
        })
    }
    /// Exact canonical namespace encoding.
    #[must_use]
    pub const fn namespace_encoding(&self) -> &'a [u8] {
        self.namespace_encoding
    }
    /// Declared canonical initial account-state root.
    #[must_use]
    pub const fn initial_root(&self) -> [u8; 32] {
        self.initial_root
    }
    /// Declared canonical initial account-state epoch (exactly one).
    #[must_use]
    pub const fn initial_epoch(&self) -> u64 {
        self.initial_epoch
    }
    /// Exact public supply established by this bootstrap.
    #[must_use]
    pub const fn total_supply(&self) -> u32 {
        self.total_supply
    }
    /// Number of accounts in the complete table.
    #[must_use]
    pub const fn account_count(&self) -> usize {
        self.public_keys.len()
    }
    /// Ordered public keys in the complete table.
    #[must_use]
    pub const fn public_keys(&self) -> &'a [TwistedElGamalPublicKeyV1] {
        self.public_keys
    }
    /// Ordered initial encrypted balances in the complete table.
    #[must_use]
    pub const fn encrypted_balances(&self) -> &'a [TwistedElGamalCiphertextV1] {
        self.encrypted_balances
    }
    /// Digest of every explicit public bootstrap field in canonical order.
    #[must_use]
    pub const fn bootstrap_table_digest(&self) -> [u8; 32] {
        self.bootstrap_table_digest
    }
}
/// Secret openings for every encrypted balance in bootstrap-table order.
#[derive(Clone, Copy, Debug)]
pub struct AnonymousPgcBootstrapWitnessV1<'a> {
    /// Exact nonnegative account balances.
    pub balances: &'a [u32],
    /// Independent encryption randomizers.
    pub randomness: &'a [SecretScalarV1],
}
/// Generalized Schnorr proof that one bootstrap ciphertext is well formed.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::PgcBootstrapWellFormedProofV1"
)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcBootstrapWellFormedProofV1 {
    announcement_left: CompressedPointV1,
    announcement_right: CompressedPointV1,
    randomness_response: CanonicalScalarV1,
    balance_response: CanonicalScalarV1,
}
/// Exact unsigned 32-bit proof for one encrypted balance's right component.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::PgcBootstrapUnsignedRangeProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcBootstrapUnsignedRangeProofV1 {
    bit_commitments: FixedProofArray<CompressedPointV1, RANGE_BITS>,
    branch_challenges: FixedProofArray<CanonicalScalarV1, { RANGE_BITS * 2 }>,
    branch_responses: FixedProofArray<CanonicalScalarV1, { RANGE_BITS * 2 }>,
}
/// Complete proof for one ordered bootstrap account.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::PgcBootstrapAccountProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcBootstrapAccountProofV1 {
    well_formed: PgcBootstrapWellFormedProofV1,
    unsigned_range: PgcBootstrapUnsignedRangeProofV1,
}
/// Schnorr proof that aggregate plaintext equals the exact public supply.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::PgcBootstrapAggregateSupplyProofV1"
)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct PgcBootstrapAggregateSupplyProofV1 {
    announcement: CompressedPointV1,
    randomness_response: CanonicalScalarV1,
}
/// Canonical proof for one complete PGC pool bootstrap.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::AnonymousPgcBootstrapProofV1"
)]
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::NoritoSerialize, norito::derive::NoritoDeserialize,
)]
#[norito(decode_from_slice)]
pub struct AnonymousPgcBootstrapProofV1 {
    version: u8,
    accounts: Vec<PgcBootstrapAccountProofV1>,
    aggregate_supply: PgcBootstrapAggregateSupplyProofV1,
}
impl AnonymousPgcBootstrapProofV1 {
    /// Encode this proof as canonical Norito.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        norito::codec::encode_adaptive(self)
    }
    /// Decode exactly one canonical proof and validate its closed shape.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, trailing, malformed, noncanonical, unknown-version, or
    /// incorrectly shaped proof bytes. Canonicality is authenticated by fallible fixed-V1
    /// streaming comparison before any equation. Original local refusals remain typed.
    pub fn decode_exact(
        bytes: &[u8],
        statement: &AnonymousPgcBootstrapStatementV1<'_>,
    ) -> Result<Self, AnonymousPgcReadError> {
        if bytes.len() > MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1 {
            return Err(AnonymousPgcError::EncodingTooLarge {
                actual: bytes.len(),
                max: MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
            }
            .into());
        }
        let proof = norito::core::classify_decode_attempt(|| {
            let proof = norito::codec::decode_exact_from_slice_with_limits::<Self>(
                bytes,
                bootstrap_proof_decode_limits(statement, bytes.len()),
            )?;
            // Authenticate the same fixed-V1 bare layout against the borrowed
            // source without a second proof Vec or infallible re-encoding.
            norito::codec::verify_exact_payload(&proof, bytes)?;
            Ok(proof)
        })?;
        proof.validate_shape(statement)?;
        Ok(proof)
    }

    fn validate_shape(
        &self,
        statement: &AnonymousPgcBootstrapStatementV1<'_>,
    ) -> Result<(), AnonymousPgcError> {
        if self.version != PGC_BOOTSTRAP_PROOF_VERSION_V1 {
            return Err(AnonymousPgcError::UnsupportedBootstrapProofVersion {
                version: self.version,
            });
        }
        if self.accounts.len() != statement.account_count() {
            return Err(AnonymousPgcError::InvalidBootstrapProofShape);
        }
        for account in &self.accounts {
            account.validate()?;
        }
        self.aggregate_supply.validate()
    }
}
impl PgcBootstrapWellFormedProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        let _ = self.announcement_left.to_projective()?;
        let _ = self.announcement_right.to_projective()?;
        let _ = self.randomness_response.to_scalar()?;
        let _ = self.balance_response.to_scalar()?;
        Ok(())
    }
}
impl PgcBootstrapUnsignedRangeProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        for point in self.bit_commitments.iter() {
            let _ = point.to_projective()?;
        }
        for scalar in self
            .branch_challenges
            .iter()
            .chain(self.branch_responses.iter())
        {
            let _ = scalar.to_scalar()?;
        }
        Ok(())
    }
}
impl PgcBootstrapAccountProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        self.well_formed.validate()?;
        self.unsigned_range.validate()
    }
}
impl PgcBootstrapAggregateSupplyProofV1 {
    fn validate(&self) -> Result<(), AnonymousPgcError> {
        let _ = self.announcement.to_projective()?;
        let _ = self.randomness_response.to_scalar()?;
        Ok(())
    }
}
/// Opaque evidence that every bootstrap equation verified as one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAnonymousPgcBootstrapV1 {
    total_supply: u32,
    account_count: usize,
    bootstrap_table_digest: [u8; 32],
}
impl VerifiedAnonymousPgcBootstrapV1 {
    /// Verified exact public supply.
    #[must_use]
    pub const fn total_supply(self) -> u32 {
        self.total_supply
    }
    /// Verified account-table size.
    #[must_use]
    pub const fn account_count(self) -> usize {
        self.account_count
    }
    /// Verified digest of the complete ordered public table and metadata.
    #[must_use]
    pub const fn bootstrap_table_digest(self) -> [u8; 32] {
        self.bootstrap_table_digest
    }
}
fn bootstrap_table_digest(
    namespace_encoding: &[u8],
    initial_root: [u8; 32],
    initial_epoch: u64,
    total_supply: u32,
    public_keys: &[TwistedElGamalPublicKeyV1],
    encrypted_balances: &[TwistedElGamalCiphertextV1],
) -> Result<[u8; 32], AnonymousPgcError> {
    let namespace_len = u32::try_from(namespace_encoding.len())
        .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?;
    let account_count = u32::try_from(public_keys.len())
        .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?;
    let mut hash = Sha256::new();
    hash.update(PGC_BOOTSTRAP_TABLE_DIGEST_DOMAIN_V1);
    hash.update(namespace_len.to_be_bytes());
    hash.update(namespace_encoding);
    hash.update(initial_root);
    hash.update(initial_epoch.to_be_bytes());
    hash.update(total_supply.to_be_bytes());
    hash.update(account_count.to_be_bytes());
    for (index, (key, ciphertext)) in public_keys.iter().zip(encrypted_balances).enumerate() {
        hash.update(
            u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?
                .to_be_bytes(),
        );
        hash.update(key.point.as_bytes());
        hash.update(ciphertext.left.as_bytes());
        hash.update(ciphertext.right.as_bytes());
    }
    Ok(hash.finalize().into())
}
fn bootstrap_transcript(
    suite: &'static [u8],
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
) -> Result<TranscriptV1, AnonymousPgcError> {
    let mut transcript = TranscriptV1::new(suite, &statement.transcript_binding)?;
    transcript.append_message(b"bootstrap_profile", PGC_BOOTSTRAP_SUITE_V1)?;
    transcript.append_message(b"bootstrap_version", &[PGC_BOOTSTRAP_PROOF_VERSION_V1])?;
    transcript.append_message(b"namespace", statement.namespace_encoding)?;
    transcript.append_message(b"initial_root", &statement.initial_root)?;
    transcript.append_message(b"initial_epoch", &statement.initial_epoch.to_be_bytes())?;
    transcript.append_message(b"total_supply", &statement.total_supply.to_be_bytes())?;
    transcript.append_message(
        b"account_count",
        &u32::try_from(statement.account_count())
            .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?
            .to_be_bytes(),
    )?;
    transcript.append_message(b"bootstrap_table_digest", &statement.bootstrap_table_digest)?;
    for (index, (key, ciphertext)) in statement
        .public_keys
        .iter()
        .zip(statement.encrypted_balances)
        .enumerate()
    {
        transcript.append_message(
            b"account_index",
            &u32::try_from(index)
                .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"public_key", &key.point)?;
        transcript.append_point(b"encrypted_balance_left", &ciphertext.left)?;
        transcript.append_point(b"encrypted_balance_right", &ciphertext.right)?;
    }
    Ok(transcript)
}
fn append_role_and_ordinal(
    transcript: &mut TranscriptV1,
    role: &[u8],
    ordinal: u32,
) -> Result<(), AnonymousPgcError> {
    transcript.append_message(b"proof_role", role)?;
    transcript.append_message(b"proof_ordinal", &ordinal.to_be_bytes())?;
    Ok(())
}
fn sum_points(values: impl IntoIterator<Item = ProjectivePoint>) -> ProjectivePoint {
    values
        .into_iter()
        .fold(ProjectivePoint::IDENTITY, |sum, value| sum + value)
}
fn prove_well_formed<R>(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    index: usize,
    balance: u32,
    randomness: Scalar,
    rng: &mut R,
) -> Result<PgcBootstrapWellFormedProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    let key = statement.public_keys[index].point.to_projective()?;
    let ciphertext = statement.encrypted_balances[index];
    let balance = Scalar::from(u64::from(balance));
    if key * randomness != ciphertext.left.to_projective()?
        || parameters.g * randomness + parameters.h * balance != ciphertext.right.to_projective()?
    {
        return Err(AnonymousPgcError::InvalidBootstrapWitness);
    }
    for _ in 0..MAX_PROVER_RESTARTS {
        let randomness_mask = random_nonzero_scalar(rng)?;
        let balance_mask = random_nonzero_scalar(rng)?;
        let Ok(announcement_left) = CompressedPointV1::from_projective(key * randomness_mask)
        else {
            continue;
        };
        let Ok(announcement_right) = CompressedPointV1::from_projective(
            parameters.g * randomness_mask + parameters.h * balance_mask,
        ) else {
            continue;
        };
        let mut transcript = bootstrap_transcript(WELL_FORMED_SUITE_V1, statement)?;
        append_role_and_ordinal(
            &mut transcript,
            b"account-well-formed",
            u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
        )?;
        transcript.append_point(b"announcement_left", &announcement_left)?;
        transcript.append_point(b"announcement_right", &announcement_right)?;
        let challenge = transcript
            .challenge_nonzero_scalar(b"challenge", 0)?
            .to_scalar()?;
        return Ok(PgcBootstrapWellFormedProofV1 {
            announcement_left,
            announcement_right,
            randomness_response: CanonicalScalarV1::from_scalar(
                randomness_mask + challenge * randomness,
            ),
            balance_response: CanonicalScalarV1::from_scalar(balance_mask + challenge * balance),
        });
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_well_formed(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    index: usize,
    proof: &PgcBootstrapWellFormedProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let mut transcript = bootstrap_transcript(WELL_FORMED_SUITE_V1, statement)?;
    append_role_and_ordinal(
        &mut transcript,
        b"account-well-formed",
        u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
    )?;
    transcript.append_point(b"announcement_left", &proof.announcement_left)?;
    transcript.append_point(b"announcement_right", &proof.announcement_right)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    let randomness_response = proof.randomness_response.to_scalar()?;
    let balance_response = proof.balance_response.to_scalar()?;
    let key = statement.public_keys[index].point.to_projective()?;
    let ciphertext = statement.encrypted_balances[index];
    if key * randomness_response
        != proof.announcement_left.to_projective()? + ciphertext.left.to_projective()? * challenge
        || parameters.g * randomness_response + parameters.h * balance_response
            != proof.announcement_right.to_projective()?
                + ciphertext.right.to_projective()? * challenge
    {
        return Err(AnonymousPgcError::BootstrapProofEquationFailed);
    }
    Ok(())
}
fn prove_unsigned_range<R>(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    index: usize,
    balance: u32,
    randomness: Scalar,
    rng: &mut R,
) -> Result<PgcBootstrapUnsignedRangeProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    let commitment = statement.encrypted_balances[index].right.to_projective()?;
    if commitment != parameters.h * Scalar::from(u64::from(balance)) + parameters.g * randomness {
        return Err(AnonymousPgcError::InvalidBootstrapWitness);
    }
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    for _ in 0..MAX_PROVER_RESTARTS {
        let mut bit_blindings = Vec::with_capacity(RANGE_BITS);
        let mut partial_blinding = Scalar::ZERO;
        for _ in 0..RANGE_BITS - 1 {
            let bit_blinding = random_nonzero_scalar(rng)?;
            partial_blinding += bit_blinding;
            bit_blindings.push(bit_blinding);
        }
        bit_blindings.push(randomness - partial_blinding);
        let mut bit_commitments = Vec::with_capacity(RANGE_BITS);
        let mut failed = false;
        for (bit, bit_blinding) in bit_blindings.iter().copied().enumerate() {
            let bit_value = u64::from((balance >> bit) & 1) << bit;
            match CompressedPointV1::from_projective(
                parameters.h * Scalar::from(bit_value) + parameters.g * bit_blinding,
            ) {
                Ok(point) => bit_commitments.push(point),
                Err(P256EngineError::IdentityPoint) => {
                    failed = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if failed {
            continue;
        }
        let summed_commitments = sum_points(
            bit_commitments
                .iter()
                .map(|point| point.to_projective())
                .collect::<Result<Vec<_>, _>>()?,
        );
        if summed_commitments != commitment {
            return Err(AnonymousPgcError::InvalidBootstrapWitness);
        }
        let mut challenges = vec![Scalar::ZERO; RANGE_BITS * 2];
        let mut responses = vec![Scalar::ZERO; RANGE_BITS * 2];
        let mut real_masks = vec![Scalar::ZERO; RANGE_BITS];
        let mut announcements = Vec::with_capacity(RANGE_BITS * 2);
        for bit in 0..RANGE_BITS {
            let selected = usize::from(((balance >> bit) & 1) != 0);
            let simulated = 1 - selected;
            real_masks[bit] = random_nonzero_scalar(rng)?;
            challenges[bit * 2 + simulated] = random_nonzero_scalar(rng)?;
            responses[bit * 2 + simulated] = random_nonzero_scalar(rng)?;
            let bit_commitment = bit_commitments[bit].to_projective()?;
            let weight = parameters.h * Scalar::from(1_u64 << bit);
            for branch in 0..2 {
                let announcement = if branch == selected {
                    parameters.g * real_masks[bit]
                } else {
                    let branch_statement = if branch == 0 {
                        bit_commitment
                    } else {
                        bit_commitment - weight
                    };
                    parameters.g * responses[bit * 2 + branch]
                        - branch_statement * challenges[bit * 2 + branch]
                };
                let Ok(announcement) = CompressedPointV1::from_projective(announcement) else {
                    failed = true;
                    break;
                };
                announcements.push(announcement);
            }
            if failed {
                break;
            }
        }
        if failed {
            continue;
        }
        let mut transcript = bootstrap_transcript(RANGE_SUITE_V1, statement)?;
        append_role_and_ordinal(
            &mut transcript,
            b"account-balance-range32",
            u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
        )?;
        transcript.append_point(b"balance_commitment", &commitment_encoded)?;
        for (bit, point) in bit_commitments.iter().enumerate() {
            transcript.append_message(
                b"bit_index",
                &u32::try_from(bit)
                    .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?
                    .to_be_bytes(),
            )?;
            transcript.append_point(b"bit_commitment", point)?;
            transcript.append_point(b"branch_zero_announcement", &announcements[bit * 2])?;
            transcript.append_point(b"branch_one_announcement", &announcements[bit * 2 + 1])?;
        }
        for bit in 0..RANGE_BITS {
            let selected = usize::from(((balance >> bit) & 1) != 0);
            let simulated = 1 - selected;
            let challenge = transcript
                .challenge_nonzero_scalar(
                    b"bit_challenge",
                    u32::try_from(bit)
                        .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
                )?
                .to_scalar()?;
            challenges[bit * 2 + selected] = challenge - challenges[bit * 2 + simulated];
            responses[bit * 2 + selected] =
                real_masks[bit] + challenges[bit * 2 + selected] * bit_blindings[bit];
        }
        let proof = PgcBootstrapUnsignedRangeProofV1 {
            bit_commitments: bit_commitments
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidBootstrapRangeProofShape)?,
            branch_challenges: challenges
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidBootstrapRangeProofShape)?,
            branch_responses: responses
                .into_iter()
                .map(CanonicalScalarV1::from_scalar)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| AnonymousPgcError::InvalidBootstrapRangeProofShape)?,
        };
        proof.validate()?;
        return Ok(proof);
    }
    Err(AnonymousPgcError::ProverRestartExhausted)
}
fn verify_unsigned_range(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    index: usize,
    proof: &PgcBootstrapUnsignedRangeProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let commitment = statement.encrypted_balances[index].right.to_projective()?;
    let commitment_encoded = CompressedPointV1::from_projective(commitment)?;
    let summed_commitments = sum_points(
        proof
            .bit_commitments
            .iter()
            .map(|point| point.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    if summed_commitments != commitment {
        return Err(AnonymousPgcError::BootstrapProofEquationFailed);
    }
    let mut announcements = Vec::with_capacity(RANGE_BITS * 2);
    for bit in 0..RANGE_BITS {
        let bit_commitment = proof.bit_commitments[bit].to_projective()?;
        let weight = parameters.h * Scalar::from(1_u64 << bit);
        for branch in 0..2 {
            let branch_statement = if branch == 0 {
                bit_commitment
            } else {
                bit_commitment - weight
            };
            announcements.push(CompressedPointV1::from_projective(
                parameters.g * proof.branch_responses[bit * 2 + branch].to_scalar()?
                    - branch_statement * proof.branch_challenges[bit * 2 + branch].to_scalar()?,
            )?);
        }
    }
    let mut transcript = bootstrap_transcript(RANGE_SUITE_V1, statement)?;
    append_role_and_ordinal(
        &mut transcript,
        b"account-balance-range32",
        u32::try_from(index).map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
    )?;
    transcript.append_point(b"balance_commitment", &commitment_encoded)?;
    for (bit, point) in proof.bit_commitments.iter().enumerate() {
        transcript.append_message(
            b"bit_index",
            &u32::try_from(bit)
                .map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?
                .to_be_bytes(),
        )?;
        transcript.append_point(b"bit_commitment", point)?;
        transcript.append_point(b"branch_zero_announcement", &announcements[bit * 2])?;
        transcript.append_point(b"branch_one_announcement", &announcements[bit * 2 + 1])?;
    }
    for bit in 0..RANGE_BITS {
        let challenge = transcript
            .challenge_nonzero_scalar(
                b"bit_challenge",
                u32::try_from(bit).map_err(|_| AnonymousPgcError::InvalidBootstrapProofShape)?,
            )?
            .to_scalar()?;
        if proof.branch_challenges[bit * 2].to_scalar()?
            + proof.branch_challenges[bit * 2 + 1].to_scalar()?
            != challenge
        {
            return Err(AnonymousPgcError::BootstrapProofEquationFailed);
        }
    }
    Ok(())
}
fn prove_aggregate_supply<R>(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    aggregate_randomness: Scalar,
    rng: &mut R,
) -> Result<PgcBootstrapAggregateSupplyProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    let parameters = AnonymousPgcParametersV1::get()?;
    let aggregate_right = sum_points(
        statement
            .encrypted_balances
            .iter()
            .map(|ciphertext| ciphertext.right.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    let zero_plaintext_statement =
        aggregate_right - parameters.h * Scalar::from(u64::from(statement.total_supply));
    if zero_plaintext_statement != parameters.g * aggregate_randomness {
        return Err(AnonymousPgcError::InvalidBootstrapWitness);
    }
    // Scalar and challenge rejection sampling already enforce their fixed bounds.
    let mask = random_nonzero_scalar(rng)?;
    let announcement = CompressedPointV1::from_projective(parameters.g * mask)?;
    let mut transcript = bootstrap_transcript(AGGREGATE_SUPPLY_SUITE_V1, statement)?;
    transcript.append_message(b"proof_role", b"aggregate-exact-supply")?;
    transcript.append_point(b"announcement", &announcement)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    Ok(PgcBootstrapAggregateSupplyProofV1 {
        announcement,
        randomness_response: CanonicalScalarV1::from_scalar(
            mask + challenge * aggregate_randomness,
        ),
    })
}
fn verify_aggregate_supply(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    proof: &PgcBootstrapAggregateSupplyProofV1,
) -> Result<(), AnonymousPgcError> {
    proof.validate()?;
    let parameters = AnonymousPgcParametersV1::get()?;
    let aggregate_right = sum_points(
        statement
            .encrypted_balances
            .iter()
            .map(|ciphertext| ciphertext.right.to_projective())
            .collect::<Result<Vec<_>, _>>()?,
    );
    let zero_plaintext_statement =
        aggregate_right - parameters.h * Scalar::from(u64::from(statement.total_supply));
    let mut transcript = bootstrap_transcript(AGGREGATE_SUPPLY_SUITE_V1, statement)?;
    transcript.append_message(b"proof_role", b"aggregate-exact-supply")?;
    transcript.append_point(b"announcement", &proof.announcement)?;
    let challenge = transcript
        .challenge_nonzero_scalar(b"challenge", 0)?
        .to_scalar()?;
    if parameters.g * proof.randomness_response.to_scalar()?
        != proof.announcement.to_projective()? + zero_plaintext_statement * challenge
    {
        return Err(AnonymousPgcError::BootstrapProofEquationFailed);
    }
    Ok(())
}
fn validate_witness(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    witness: &AnonymousPgcBootstrapWitnessV1<'_>,
) -> Result<Scalar, AnonymousPgcError> {
    let count = statement.account_count();
    if witness.balances.len() != count || witness.randomness.len() != count {
        return Err(AnonymousPgcError::InvalidBootstrapWitness);
    }
    let mut aggregate_balance = 0_u64;
    let mut aggregate_randomness = Scalar::ZERO;
    for index in 0..count {
        aggregate_balance = aggregate_balance
            .checked_add(u64::from(witness.balances[index]))
            .ok_or(AnonymousPgcError::InvalidBootstrapWitness)?;
        aggregate_randomness += witness.randomness[index].expose_scalar();
        if super::encrypt_with_randomness(
            statement.public_keys[index],
            witness.balances[index],
            &witness.randomness[index],
        )? != statement.encrypted_balances[index]
        {
            return Err(AnonymousPgcError::InvalidBootstrapWitness);
        }
    }
    if aggregate_balance != u64::from(statement.total_supply) {
        return Err(AnonymousPgcError::InvalidBootstrapWitness);
    }
    Ok(aggregate_randomness)
}
/// Prove bounded account openings and exact aggregate supply for a complete bootstrap table.
///
/// # Errors
///
/// Rejects a false opening, wrong witness length, aggregate mismatch, prohibited identity
/// intermediate, entropy exhaustion, or proof exceeding the closed 4 MiB wire cap.
pub fn prove_bootstrap<R>(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    witness: &AnonymousPgcBootstrapWitnessV1<'_>,
    rng: &mut R,
) -> Result<AnonymousPgcBootstrapProofV1, AnonymousPgcError>
where
    R: CryptoRng + RngCore,
{
    super::validate_binding(&statement.transcript_binding)?;
    let aggregate_randomness = validate_witness(statement, witness)?;
    let mut checked_rng = health_checked_p256_rng_v1(rng)?;
    let mut accounts = Vec::with_capacity(statement.account_count());
    for index in 0..statement.account_count() {
        accounts.push(PgcBootstrapAccountProofV1 {
            well_formed: prove_well_formed(
                statement,
                index,
                witness.balances[index],
                witness.randomness[index].expose_scalar(),
                &mut checked_rng,
            )?,
            unsigned_range: prove_unsigned_range(
                statement,
                index,
                witness.balances[index],
                witness.randomness[index].expose_scalar(),
                &mut checked_rng,
            )?,
        });
    }
    let proof = AnonymousPgcBootstrapProofV1 {
        version: PGC_BOOTSTRAP_PROOF_VERSION_V1,
        accounts,
        aggregate_supply: prove_aggregate_supply(
            statement,
            aggregate_randomness,
            &mut checked_rng,
        )?,
    };
    proof.validate_shape(statement)?;
    let encoded_len = proof.encode().len();
    if encoded_len > MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1 {
        return Err(AnonymousPgcError::EncodingTooLarge {
            actual: encoded_len,
            max: MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1,
        });
    }
    verify_bootstrap(statement, &proof).map_err(|_| AnonymousPgcError::ProverSelfCheckFailed)?;
    Ok(proof)
}
/// Verify every bootstrap account and the exact aggregate supply as one unit.
///
/// # Errors
///
/// Rejects malformed proof material, any changed public/transcript field, failed ciphertext
/// well-formedness, a value outside the unsigned 32-bit domain, or aggregate supply mismatch.
pub fn verify_bootstrap(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    proof: &AnonymousPgcBootstrapProofV1,
) -> Result<VerifiedAnonymousPgcBootstrapV1, AnonymousPgcError> {
    super::validate_binding(&statement.transcript_binding)?;
    proof.validate_shape(statement)?;
    for (index, account) in proof.accounts.iter().enumerate() {
        verify_well_formed(statement, index, &account.well_formed)?;
        verify_unsigned_range(statement, index, &account.unsigned_range)?;
    }
    verify_aggregate_supply(statement, &proof.aggregate_supply)?;
    Ok(VerifiedAnonymousPgcBootstrapV1 {
        total_supply: statement.total_supply,
        account_count: statement.account_count(),
        bootstrap_table_digest: statement.bootstrap_table_digest,
    })
}
/// Decode and verify canonical opaque bootstrap-proof bytes.
///
/// # Errors
///
/// Returns the same failures as [`AnonymousPgcBootstrapProofV1::decode_exact`]
/// and [`verify_bootstrap`].
pub fn verify_bootstrap_encoded(
    statement: &AnonymousPgcBootstrapStatementV1<'_>,
    proof_bytes: &[u8],
) -> Result<VerifiedAnonymousPgcBootstrapV1, AnonymousPgcReadError> {
    let proof = AnonymousPgcBootstrapProofV1::decode_exact(proof_bytes, statement)?;
    verify_bootstrap(statement, &proof).map_err(Into::into)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::anonymous_pgc::TwistedElGamalKeyPairV1;
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    const TEST_NAMESPACE: &[u8] = b"canonical-norito:anonymous-pgc:taira-pool-7";
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::tests::LegacyUnsignedRangeProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyUnsignedRangeProofV1 {
        bit_commitments: Vec<CompressedPointV1>,
        branch_challenges: Vec<CanonicalScalarV1>,
        branch_responses: Vec<CanonicalScalarV1>,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::tests::LegacyAccountProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyAccountProofV1 {
        well_formed: PgcBootstrapWellFormedProofV1,
        unsigned_range: LegacyUnsignedRangeProofV1,
    }
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::privacy_engines::anonymous_pgc::bootstrap::tests::LegacyBootstrapProofV1"
    )]
    #[derive(norito::derive::NoritoSerialize)]
    struct LegacyBootstrapProofV1 {
        version: u8,
        accounts: Vec<LegacyAccountProofV1>,
        aggregate_supply: PgcBootstrapAggregateSupplyProofV1,
    }
    struct KatRng {
        seed: [u8; 32],
        counter: u64,
    }
    impl KatRng {
        fn new(seed: [u8; 32]) -> Self {
            Self { seed, counter: 0 }
        }
    }
    impl RngCore for KatRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_be_bytes(bytes)
        }
        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_be_bytes(bytes)
        }
        fn fill_bytes(&mut self, destination: &mut [u8]) {
            let mut offset = 0;
            while offset < destination.len() {
                let mut hash = Sha256::new();
                hash.update(b"iroha.anonymous-pgc.bootstrap.kat-rng.v1");
                hash.update(self.seed);
                hash.update(self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block: [u8; 32] = hash.finalize().into();
                let take = (destination.len() - offset).min(block.len());
                destination[offset..offset + take].copy_from_slice(&block[..take]);
                offset += take;
            }
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }
    impl CryptoRng for KatRng {}
    struct PeriodicRng;
    impl RngCore for PeriodicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("PGC bootstrap must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("PGC bootstrap must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("PGC bootstrap must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = ((index % 16) as u8).wrapping_mul(19).wrapping_add(7);
            }
            Ok(())
        }
    }
    impl CryptoRng for PeriodicRng {}
    fn secret(value: u64) -> SecretScalarV1 {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        SecretScalarV1::from_bytes(bytes).expect("nonzero test scalar")
    }
    fn binding() -> TranscriptBindingV1<'static> {
        let parameters = AnonymousPgcParametersV1::get().expect("parameters");
        TranscriptBindingV1 {
            network_id: &[0x91; 32],
            genesis_hash: [0x91; 32],
            action_index: 3,
            statement_digest: [0x92; 32],
            parameter_id: [0x93; 32],
            parameter_digest: parameters.parameter_digest(),
            verifier_digest: [0x94; 32],
            statement_schema_digest: [0x95; 32],
            engine_manifest_digest: [0x96; 32],
            generator_digest: parameters.generator_digest(),
        }
    }
    struct Fixture {
        public_keys: Vec<TwistedElGamalPublicKeyV1>,
        encrypted_balances: Vec<TwistedElGamalCiphertextV1>,
        balances: Vec<u32>,
        randomness: Vec<SecretScalarV1>,
        initial_root: [u8; 32],
        initial_epoch: u64,
        total_supply: u32,
    }
    impl Fixture {
        fn new_16() -> Self {
            let balances = (0_u32..16).collect::<Vec<_>>();
            Self::from_balances(balances, 10_000)
        }
        fn boundary_64() -> Self {
            let mut balances = vec![0_u32; 64];
            balances[17] = u32::MAX;
            Self::from_balances(balances, 20_000)
        }
        fn from_balances(balances: Vec<u32>, key_base: u64) -> Self {
            let mut key_pairs = (0..balances.len())
                .map(|index| {
                    TwistedElGamalKeyPairV1::from_secret(secret(
                        key_base + u64::try_from(index).expect("test index fits u64") + 1,
                    ))
                    .expect("key pair")
                })
                .collect::<Vec<_>>();
            key_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
            let public_keys = key_pairs
                .iter()
                .map(TwistedElGamalKeyPairV1::public_key)
                .collect::<Vec<_>>();
            let randomness = (0..balances.len())
                .map(|index| {
                    secret(key_base + 1_000 + u64::try_from(index).expect("test index fits u64"))
                })
                .collect::<Vec<_>>();
            let encrypted_balances = public_keys
                .iter()
                .copied()
                .zip(&balances)
                .zip(&randomness)
                .map(|((key, balance), randomness)| {
                    super::super::encrypt_with_randomness(key, *balance, randomness)
                        .expect("encrypted balance")
                })
                .collect::<Vec<_>>();
            let total = balances
                .iter()
                .try_fold(0_u64, |sum, value| sum.checked_add(u64::from(*value)))
                .expect("fixture sum");
            Self {
                public_keys,
                encrypted_balances,
                balances,
                randomness,
                initial_root: [0xa1; 32],
                initial_epoch: PGC_BOOTSTRAP_INITIAL_EPOCH_V1,
                total_supply: u32::try_from(total).expect("fixture supply fits u32"),
            }
        }
        fn statement(&self) -> AnonymousPgcBootstrapStatementV1<'_> {
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                self.initial_root,
                self.initial_epoch,
                self.total_supply,
                &self.public_keys,
                &self.encrypted_balances,
                binding(),
            )
            .expect("bootstrap statement")
        }
        fn witness(&self) -> AnonymousPgcBootstrapWitnessV1<'_> {
            AnonymousPgcBootstrapWitnessV1 {
                balances: &self.balances,
                randomness: &self.randomness,
            }
        }
        fn prove(&self) -> AnonymousPgcBootstrapProofV1 {
            let mut rng = KatRng::new([0xb1; 32]);
            prove_bootstrap(&self.statement(), &self.witness(), &mut rng).expect("bootstrap proof")
        }
    }
    fn mutate_scalar(value: CanonicalScalarV1) -> CanonicalScalarV1 {
        CanonicalScalarV1::from_scalar(value.to_scalar().expect("scalar") + Scalar::ONE)
    }
    fn negate_point(value: CompressedPointV1) -> CompressedPointV1 {
        CompressedPointV1::from_projective(-value.to_projective().expect("point"))
            .expect("nonidentity inverse")
    }
    #[test]
    fn complete_n16_bootstrap_is_canonical_and_returns_verified_public_values() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let encoded = proof.encode();
        assert!(encoded.len() <= MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1);
        let decoded =
            AnonymousPgcBootstrapProofV1::decode_exact(&encoded, &statement).expect("decode");
        assert_eq!(decoded, proof);
        assert_eq!(decoded.encode(), encoded);
        let direct = verify_bootstrap(&statement, &proof).expect("direct verify");
        let encoded_effect =
            verify_bootstrap_encoded(&statement, &encoded).expect("encoded verify");
        assert_eq!(direct, encoded_effect);
        assert_eq!(direct.total_supply(), fixture.total_supply);
        assert_eq!(direct.account_count(), 16);
        assert_eq!(
            direct.bootstrap_table_digest(),
            statement.bootstrap_table_digest()
        );
    }
    #[test]
    fn bootstrap_known_answer_vector_is_stable() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let proof = fixture.prove();
        verify_bootstrap(&statement, &proof).expect("verify");
        assert_eq!(
            (
                hex::encode(
                    AnonymousPgcParametersV1::get()
                        .expect("parameters")
                        .parameter_digest()
                ),
                hex::encode(statement.bootstrap_table_digest()),
                proof.encode().len(),
                hex::encode(Sha256::digest(proof.encode())),
            ),
            (
                "ca09d19ed5f3bb56ba7432a67b7ad14697c4874ab7870ea53441e4df0624bd7b".to_owned(),
                "e785c256e2682ad5a82649b8ace70906088b2822d979ffd75b40150e686295e6".to_owned(),
                90_035,
                "db5d4c8201c268ac3bca0a9f1dfe53264535e7d47df8fc7876636718ea15f03d".to_owned(),
            )
        );
    }
    #[test]
    fn complete_n64_zero_and_u32_max_boundary_fits_cap_and_verifies() {
        let fixture = Fixture::boundary_64();
        assert!(fixture.balances.contains(&0));
        assert!(fixture.balances.contains(&u32::MAX));
        assert_eq!(fixture.total_supply, u32::MAX);
        let statement = fixture.statement();
        let proof = fixture.prove();
        let encoded = proof.encode();
        assert!(encoded.len() <= MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1);
        assert_eq!(
            AnonymousPgcBootstrapProofV1::decode_exact(&encoded, &statement)
                .expect("strict n64 decode")
                .encode(),
            encoded
        );
        let verified =
            verify_bootstrap_encoded(&statement, &encoded).expect("n64 bootstrap verifies");
        assert_eq!(verified.total_supply(), u32::MAX);
        assert_eq!(verified.account_count(), 64);
        assert_eq!(
            verified.bootstrap_table_digest(),
            statement.bootstrap_table_digest()
        );
    }
    #[test]
    fn aggregate_integer_bound_cannot_wrap_the_p256_scalar_order() {
        const P256_ORDER_BE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut maximum_sum_be = [0_u8; 32];
        maximum_sum_be[24..].copy_from_slice(&PGC_BOOTSTRAP_MAX_AGGREGATE_BALANCE_V1.to_be_bytes());
        assert_eq!(
            PGC_BOOTSTRAP_MAX_AGGREGATE_BALANCE_V1,
            64_u64 * u64::from(u32::MAX)
        );
        assert!(maximum_sum_be < P256_ORDER_BE);
        assert_eq!(
            Scalar::from(PGC_BOOTSTRAP_MAX_AGGREGATE_BALANCE_V1),
            (0..64).fold(Scalar::ZERO, |sum, _| {
                sum + Scalar::from(u64::from(u32::MAX))
            })
        );
    }
    #[test]
    fn rejects_wrong_witness_opening_lengths_and_aggregate_sum() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let mut rng = KatRng::new([0xb2; 32]);
        let wrong_lengths = AnonymousPgcBootstrapWitnessV1 {
            balances: &fixture.balances[..15],
            randomness: &fixture.randomness,
        };
        assert!(matches!(
            prove_bootstrap(&statement, &wrong_lengths, &mut rng),
            Err(AnonymousPgcError::InvalidBootstrapWitness)
        ));
        let mut wrong_balances = fixture.balances.clone();
        wrong_balances[4] += 1;
        let wrong_opening = AnonymousPgcBootstrapWitnessV1 {
            balances: &wrong_balances,
            randomness: &fixture.randomness,
        };
        assert!(matches!(
            prove_bootstrap(&statement, &wrong_opening, &mut rng),
            Err(AnonymousPgcError::InvalidBootstrapWitness)
        ));
        let mut wrong_randomness = fixture
            .randomness
            .iter()
            .enumerate()
            .map(|(index, _)| secret(40_000 + u64::try_from(index).expect("index")))
            .collect::<Vec<_>>();
        wrong_randomness.swap(0, 1);
        let wrong_opening = AnonymousPgcBootstrapWitnessV1 {
            balances: &fixture.balances,
            randomness: &wrong_randomness,
        };
        assert!(matches!(
            prove_bootstrap(&statement, &wrong_opening, &mut rng),
            Err(AnonymousPgcError::InvalidBootstrapWitness)
        ));
        let wrong_supply = AnonymousPgcBootstrapStatementV1::new(
            TEST_NAMESPACE,
            fixture.initial_root,
            fixture.initial_epoch,
            fixture.total_supply + 1,
            &fixture.public_keys,
            &fixture.encrypted_balances,
            binding(),
        )
        .expect("wrong-supply public statement is structurally valid");
        assert!(matches!(
            prove_bootstrap(&wrong_supply, &fixture.witness(), &mut rng),
            Err(AnonymousPgcError::InvalidBootstrapWitness)
        ));
    }
    #[test]
    fn complete_bootstrap_rejects_short_period_entropy_before_proof_emission() {
        let fixture = Fixture::new_16();
        assert!(matches!(
            prove_bootstrap(&fixture.statement(), &fixture.witness(), &mut PeriodicRng,),
            Err(AnonymousPgcError::P256(
                P256EngineError::RandomnessHealthCheckFailed
            ))
        ));
    }
    #[test]
    fn proof_binds_every_public_bootstrap_component() {
        let fixture = Fixture::new_16();
        let proof = fixture.prove();
        let baseline = fixture.statement().bootstrap_table_digest();
        let changed_namespace = AnonymousPgcBootstrapStatementV1::new(
            b"canonical-norito:anonymous-pgc:different-pool",
            fixture.initial_root,
            fixture.initial_epoch,
            fixture.total_supply,
            &fixture.public_keys,
            &fixture.encrypted_balances,
            binding(),
        )
        .expect("changed namespace");
        assert_ne!(changed_namespace.bootstrap_table_digest(), baseline);
        assert!(verify_bootstrap(&changed_namespace, &proof).is_err());
        let mut changed_root = fixture.initial_root;
        changed_root[0] ^= 1;
        let changed_root_statement = AnonymousPgcBootstrapStatementV1::new(
            TEST_NAMESPACE,
            changed_root,
            fixture.initial_epoch,
            fixture.total_supply,
            &fixture.public_keys,
            &fixture.encrypted_balances,
            binding(),
        )
        .expect("changed root");
        assert_ne!(changed_root_statement.bootstrap_table_digest(), baseline);
        assert!(verify_bootstrap(&changed_root_statement, &proof).is_err());
        let changed_supply = AnonymousPgcBootstrapStatementV1::new(
            TEST_NAMESPACE,
            fixture.initial_root,
            fixture.initial_epoch,
            fixture.total_supply + 1,
            &fixture.public_keys,
            &fixture.encrypted_balances,
            binding(),
        )
        .expect("changed supply public field");
        assert_ne!(changed_supply.bootstrap_table_digest(), baseline);
        assert!(verify_bootstrap(&changed_supply, &proof).is_err());
        let mut alternative_pairs = (50_000_u64..50_016)
            .map(|value| TwistedElGamalKeyPairV1::from_secret(secret(value)).expect("key"))
            .collect::<Vec<_>>();
        alternative_pairs.sort_by_key(TwistedElGamalKeyPairV1::public_key);
        let alternative_keys = alternative_pairs
            .iter()
            .map(TwistedElGamalKeyPairV1::public_key)
            .collect::<Vec<_>>();
        let changed_keys = AnonymousPgcBootstrapStatementV1::new(
            TEST_NAMESPACE,
            fixture.initial_root,
            fixture.initial_epoch,
            fixture.total_supply,
            &alternative_keys,
            &fixture.encrypted_balances,
            binding(),
        )
        .expect("changed ordered keys");
        assert_ne!(changed_keys.bootstrap_table_digest(), baseline);
        assert!(verify_bootstrap(&changed_keys, &proof).is_err());
        for component in 0..2 {
            let mut encrypted = fixture.encrypted_balances.clone();
            match component {
                0 => encrypted[3].left = negate_point(encrypted[3].left),
                1 => encrypted[3].right = negate_point(encrypted[3].right),
                _ => unreachable!(),
            }
            let changed = AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &encrypted,
                binding(),
            )
            .expect("changed ciphertext");
            assert_ne!(changed.bootstrap_table_digest(), baseline);
            assert!(verify_bootstrap(&changed, &proof).is_err());
        }
    }
    #[test]
    fn proof_binds_chain_action_and_every_governed_transcript_digest() {
        let fixture = Fixture::new_16();
        let proof = fixture.prove();
        let base = binding();
        let mut changed_bindings = Vec::new();
        let mut changed = base;
        changed.network_id = &[0x92; 32];
        changed.genesis_hash = [0x92; 32];
        changed_bindings.push(changed);
        let mut changed = base;
        changed.genesis_hash[0] ^= 1;
        assert!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                changed
            )
            .is_err(),
            "network/genesis disagreement must reject before proof evaluation"
        );
        let mut changed = base;
        changed.action_index += 1;
        changed_bindings.push(changed);
        let mut changed = base;
        changed.statement_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = base;
        changed.parameter_id[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = base;
        changed.verifier_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = base;
        changed.statement_schema_digest[0] ^= 1;
        changed_bindings.push(changed);
        let mut changed = base;
        changed.engine_manifest_digest[0] ^= 1;
        changed_bindings.push(changed);
        for changed_binding in changed_bindings {
            let changed = AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                changed_binding,
            )
            .expect("changed valid binding");
            assert!(verify_bootstrap(&changed, &proof).is_err());
        }
        let mut changed_parameter = base;
        changed_parameter.parameter_digest[0] ^= 1;
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                changed_parameter,
            ),
            Err(AnonymousPgcError::ParameterDigestMismatch)
        ));
        let mut changed_generator = base;
        changed_generator.generator_digest[0] ^= 1;
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                changed_generator,
            ),
            Err(AnonymousPgcError::GeneratorDigestMismatch)
        ));
    }
    #[test]
    fn rejects_reordered_duplicate_and_malformed_public_tables() {
        let fixture = Fixture::new_16();
        let mut reordered_keys = fixture.public_keys.clone();
        let mut reordered_ciphertexts = fixture.encrypted_balances.clone();
        reordered_keys.swap(0, 1);
        reordered_ciphertexts.swap(0, 1);
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &reordered_keys,
                &reordered_ciphertexts,
                binding(),
            ),
            Err(AnonymousPgcError::BootstrapKeysNotStrictlyIncreasing)
        ));
        let mut duplicate_keys = fixture.public_keys.clone();
        duplicate_keys[1] = duplicate_keys[0];
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &duplicate_keys,
                &fixture.encrypted_balances,
                binding(),
            ),
            Err(AnonymousPgcError::BootstrapKeysNotStrictlyIncreasing)
        ));
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys[..15],
                &fixture.encrypted_balances[..15],
                binding(),
            ),
            Err(AnonymousPgcError::InvalidBootstrapAccountCount { count: 15 })
        ));
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances[..15],
                binding(),
            ),
            Err(AnonymousPgcError::BootstrapLengthMismatch { .. })
        ));
        assert!(TwistedElGamalPublicKeyV1::from_sec1_bytes(&[0; 33]).is_err());
        assert!(TwistedElGamalCiphertextV1::from_sec1_bytes(&[0; 33], &[0; 33]).is_err());
    }
    #[test]
    fn decoder_and_equations_reject_all_proof_family_tampering() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let mut changed = proof.clone();
        changed.accounts[0].well_formed.announcement_left =
            negate_point(changed.accounts[0].well_formed.announcement_left);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.accounts[0].well_formed.balance_response =
            mutate_scalar(changed.accounts[0].well_formed.balance_response);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.accounts[0].unsigned_range.bit_commitments[0] =
            negate_point(changed.accounts[0].unsigned_range.bit_commitments[0]);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.accounts[0].unsigned_range.branch_challenges[0] =
            mutate_scalar(changed.accounts[0].unsigned_range.branch_challenges[0]);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.accounts[0].unsigned_range.branch_responses[0] =
            mutate_scalar(changed.accounts[0].unsigned_range.branch_responses[0]);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.aggregate_supply.announcement = negate_point(changed.aggregate_supply.announcement);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut changed = proof.clone();
        changed.aggregate_supply.randomness_response =
            mutate_scalar(changed.aggregate_supply.randomness_response);
        assert!(verify_bootstrap(&statement, &changed).is_err());
        let mut noncanonical_point = proof.clone();
        noncanonical_point.accounts[0].well_formed.announcement_left =
            CompressedPointV1::from_unchecked_bytes([0; 33]);
        assert!(verify_bootstrap(&statement, &noncanonical_point).is_err());
        assert!(
            AnonymousPgcBootstrapProofV1::decode_exact(&noncanonical_point.encode(), &statement)
                .is_err()
        );
        let mut noncanonical_scalar = proof;
        noncanonical_scalar.accounts[0]
            .unsigned_range
            .branch_responses[0] = CanonicalScalarV1::from_unchecked_bytes([0xff; 32]);
        assert!(verify_bootstrap(&statement, &noncanonical_scalar).is_err());
        assert!(
            AnonymousPgcBootstrapProofV1::decode_exact(&noncanonical_scalar.encode(), &statement)
                .is_err()
        );
    }
    #[test]
    fn decoder_rejects_truncation_trailing_bombs_versions_shapes_and_cap() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let encoded = proof.encode();
        for end in [0, 1, encoded.len() / 2, encoded.len() - 1] {
            assert!(
                AnonymousPgcBootstrapProofV1::decode_exact(&encoded[..end], &statement).is_err()
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(AnonymousPgcBootstrapProofV1::decode_exact(&trailing, &statement).is_err());
        for offset in 0..encoded.len().min(16) {
            let mut length_prefix_bomb = encoded.clone();
            length_prefix_bomb[offset] = 0xff;
            assert!(
                AnonymousPgcBootstrapProofV1::decode_exact(&length_prefix_bomb, &statement)
                    .is_err()
            );
        }
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(
                &vec![0; MAX_PGC_BOOTSTRAP_PROOF_BYTES_V1 + 1],
                &statement,
            ),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::EncodingTooLarge { .. }
            ))
        ));
        let mut unknown_version = proof.clone();
        unknown_version.version += 1;
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(&unknown_version.encode(), &statement),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::UnsupportedBootstrapProofVersion { .. }
            ))
        ));
        let mut wrong_account_shape = proof.clone();
        wrong_account_shape.accounts.pop();
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(&wrong_account_shape.encode(), &statement),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::InvalidBootstrapProofShape
            ))
        ));
        let mut oversized_accounts = proof.clone();
        oversized_accounts
            .accounts
            .push(oversized_accounts.accounts[0].clone());
        let oversized = oversized_accounts.encode();
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(&oversized, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
        let encoded_count = 17_u64.to_le_bytes();
        let count_offset = oversized
            .windows(encoded_count.len())
            .position(|window| window == encoded_count)
            .expect("oversized account count is present in canonical wire");
        let mut forged = oversized;
        forged[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(&forged, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
        let legacy = LegacyBootstrapProofV1 {
            version: proof.version,
            accounts: proof
                .accounts
                .iter()
                .map(|account| LegacyAccountProofV1 {
                    well_formed: account.well_formed,
                    unsigned_range: LegacyUnsignedRangeProofV1 {
                        bit_commitments: account.unsigned_range.bit_commitments.to_vec(),
                        branch_challenges: account.unsigned_range.branch_challenges.to_vec(),
                        branch_responses: account.unsigned_range.branch_responses.to_vec(),
                    },
                })
                .collect(),
            aggregate_supply: proof.aggregate_supply,
        };
        let legacy_bytes = norito::codec::encode_adaptive(&legacy);
        assert_ne!(legacy_bytes, proof.encode());
        assert!(matches!(
            AnonymousPgcBootstrapProofV1::decode_exact(&legacy_bytes, &statement),
            Err(AnonymousPgcReadError::Codec(ref original)) if original.local_refusal().is_none()
        ));
    }
    #[test]
    fn statement_rejects_noncanonical_epoch_before_all_other_validation() {
        for epoch in [0, 2, 11, u64::MAX] {
            let result = AnonymousPgcBootstrapStatementV1::new(
                &[],
                [0; 32],
                epoch,
                0,
                &[],
                &[],
                TranscriptBindingV1 {
                    network_id: &[0; 32],
                    genesis_hash: [0; 32],
                    action_index: 0,
                    statement_digest: [0; 32],
                    parameter_id: [0; 32],
                    parameter_digest: [0; 32],
                    verifier_digest: [0; 32],
                    statement_schema_digest: [0; 32],
                    engine_manifest_digest: [0; 32],
                    generator_digest: [0; 32],
                },
            );
            assert!(matches!(
                result,
                Err(AnonymousPgcError::InvalidBootstrapEpoch { actual, expected })
                    if actual == epoch && expected == PGC_BOOTSTRAP_INITIAL_EPOCH_V1
            ));
        }
    }
    #[test]
    fn statement_rejects_zero_and_oversized_namespace_root_and_supply() {
        let fixture = Fixture::new_16();
        for namespace in [
            Vec::new(),
            vec![1; MAX_PGC_BOOTSTRAP_NAMESPACE_BYTES_V1 + 1],
        ] {
            assert!(matches!(
                AnonymousPgcBootstrapStatementV1::new(
                    &namespace,
                    fixture.initial_root,
                    fixture.initial_epoch,
                    fixture.total_supply,
                    &fixture.public_keys,
                    &fixture.encrypted_balances,
                    binding(),
                ),
                Err(AnonymousPgcError::InvalidBootstrapNamespaceLength { .. })
            ));
        }
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                [0; 32],
                fixture.initial_epoch,
                fixture.total_supply,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                binding(),
            ),
            Err(AnonymousPgcError::ZeroBootstrapRoot)
        ));
        assert!(matches!(
            AnonymousPgcBootstrapStatementV1::new(
                TEST_NAMESPACE,
                fixture.initial_root,
                fixture.initial_epoch,
                0,
                &fixture.public_keys,
                &fixture.encrypted_balances,
                binding(),
            ),
            Err(AnonymousPgcError::ZeroPgcTotalSupply)
        ));
    }
    #[test]
    fn bootstrap_decoder_preserves_original_enclosing_refusal_and_same_source_retry() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let bytes = fixture.prove().encode();
        let pointer = bytes.as_ptr();
        let limit = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let first = norito::with_decode_limits_scope(limit, || {
            verify_bootstrap_encoded(&statement, &bytes)
        })
        .unwrap_err();
        let AnonymousPgcReadError::Codec(first) = first else {
            panic!("actual decoder refusal must retain codec owner")
        };
        let retained = first.local_refusal().expect("original enclosing quota");
        assert_eq!(
            retained.kind(),
            norito::core::DecodeLocalRefusalKind::EnclosingLimit
        );
        let norito::Error::ScopedDecodeResource(original) = first.error() else {
            panic!("original scoped error")
        };
        assert_eq!(
            retained.resource_error(),
            first.error().decode_resource_error().unwrap()
        );
        assert_eq!(retained.to_string(), original.to_string());
        let second = norito::with_decode_limits_scope(limit, || {
            verify_bootstrap_encoded(&statement, &bytes)
        })
        .unwrap_err();
        let AnonymousPgcReadError::Codec(second) = second else {
            panic!("second original decoder refusal")
        };
        let second_owner = second.local_refusal().unwrap();
        assert_eq!(retained.resource_error(), second_owner.resource_error());
        assert_ne!(
            retained, second_owner,
            "equal quotas cannot share original scope identity"
        );
        assert_eq!(bytes.as_ptr(), pointer);
        let retried = verify_bootstrap_encoded(&statement, &bytes)
            .expect("fresh unconstrained original-source retry");
        assert_eq!(retried.account_count(), 16);
        assert_eq!(retried.total_supply(), fixture.total_supply);
        assert_eq!(bytes.as_ptr(), pointer);
    }
    #[test]
    fn bootstrap_decoder_intrinsic_and_malformed_refusals_never_become_local_capacity() {
        let fixture = Fixture::new_16();
        let statement = fixture.statement();
        let proof = fixture.prove();
        let mut too_many = proof.clone();
        too_many.accounts.push(proof.accounts[0].clone());
        let oversized = too_many.encode();
        let mut trailing = proof.encode();
        trailing.push(0);
        for bytes in [oversized.as_slice(), trailing.as_slice(), &[]] {
            let error = verify_bootstrap_encoded(&statement, bytes).unwrap_err();
            let AnonymousPgcReadError::Codec(original) = error else {
                panic!("actual structural wire refusal")
            };
            assert!(original.local_refusal().is_none());
        }
        let mut wrong_version = proof;
        wrong_version.version += 1;
        assert!(matches!(
            verify_bootstrap_encoded(&statement, &wrong_version.encode()),
            Err(AnonymousPgcReadError::Relation(
                AnonymousPgcError::UnsupportedBootstrapProofVersion { .. }
            ))
        ));
    }
}
