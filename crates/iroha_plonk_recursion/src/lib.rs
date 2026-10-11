//! Native KAGEMUSHA PIPA-AS-v1 accumulation (Lambda §§3.3–3.4 and §8).
//!
//! [`AccumulatorT`] and [`FoldInput`] are checked, **undecided** claims.
//! [`verify_fold`] checks only the succinct IPA equation: acceptance requires
//! deciding its returned accumulator. [`create_fold`] constructs the non-hiding
//! opening of `h - h(z)e_0`, using the pinned generator prefix and no hiding
//! generator. Salt is an explicit canonical base-field input, outside the
//! 1,088-byte IPA body. No API silently inserts or removes a fold input.
//!
//! The [`transcript`] and [`codec`] modules provide the constrained base-field
//! sponge, canonical message cells and full-width challenge map. [`verifier`]
//! and [`accumulation_circuit`] implement complete succinct circuit predicates;
//! [`obligation`] constrains incoming modes and the fixed per-operation ledger.
//! Consuming relations must bind every authenticated source and selected claim,
//! close both generator decisions and qualify the composed recursive artifacts.
//! Component tests do not establish full-lineage or release qualification.

mod accumulation;
pub mod accumulation_circuit;
mod claim;
pub mod codec;
pub mod obligation;
pub mod transcript;
pub mod verifier;

pub use accumulation::{FoldConfig, FoldWitness, create_fold, verify_fold};
pub use claim::{AccumulatorT, CorrectedInput, FoldInput};

use core::fmt;

use iroha_plonk::{pcs::ipa::IpaError, transcript::TranscriptError};

/// The fixed number of rounds in PIPA-AS-v1 and transported accumulators.
pub const K: usize = K_U32 as usize;
const K_U32: u32 = 16;
/// The pinned generator-prefix length.
pub const GENERATORS: usize = 1 << K;
/// Canonical `G || u[0..16]` bytes, without a curve or version discriminator.
pub const ACCUMULATOR_BYTES: usize = 32 * (1 + K);
/// The non-hiding IPA body: sixteen L/R pairs, c and the unabsorbed G suffix.
pub const FOLD_BODY_BYTES: usize = 32 * (2 * K + 2);
/// Canonical local witness: a 32-byte base-field salt followed by the body.
pub const FOLD_WITNESS_BYTES: usize = 32 + FOLD_BODY_BYTES;

/// Compressed Pallas `ACC_TRIV.G = sum_{i<2^16} g_i`, pinned by an independent sum KAT.
pub const PALLAS_TRIVIAL_GENERATOR: [u8; 32] = [
    0x23, 0x60, 0x9c, 0xe8, 0x02, 0x05, 0x95, 0x1c, 0x69, 0x8e, 0x4e, 0x09, 0x0e, 0x67, 0xcc, 0xb5,
    0x09, 0xaa, 0x74, 0xdf, 0xa8, 0x7f, 0x83, 0x31, 0xbb, 0x4d, 0x24, 0x5c, 0xb8, 0x88, 0x09, 0x3b,
];
/// Compressed Vesta `ACC_TRIV.G = sum_{i<2^16} g_i`, pinned by an independent sum KAT.
pub const VESTA_TRIVIAL_GENERATOR: [u8; 32] = [
    0xaf, 0x12, 0x8a, 0xda, 0x6b, 0xeb, 0x4a, 0x2a, 0x69, 0xe0, 0x5e, 0x05, 0x98, 0x27, 0x38, 0x9c,
    0xaa, 0x46, 0x8a, 0x3d, 0x6e, 0xd3, 0x88, 0xb1, 0x4f, 0x54, 0x97, 0xc9, 0xb1, 0xfa, 0xa0, 0xb8,
];

/// An invalid encoding, claim, fold input or IPA equation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The explicit operation signal cancelled the fold or decision.
    Cancelled,
    /// A kernel resource or shape failure, never an invalid incoming proof.
    Kernel(iroha_pasta::msm::MsmError),
    /// A fixed-width wire value has a different length.
    Length {
        /// Required number of bytes or elements.
        expected: usize,
        /// Supplied number of bytes or elements.
        actual: usize,
    },
    /// A point or scalar is not canonically encoded, or a point is identity.
    Encoding(TranscriptError),
    /// Source k is outside 1..=16.
    SourceK,
    /// A normalized input has a nonzero entry in its required zero prefix.
    Padding,
    /// A real source challenge or an IPA round challenge is zero.
    ZeroChallenge {
        /// Index in the normalized sixteen-round vector.
        round: usize,
    },
    /// A fold requires at least one explicitly supplied input.
    EmptyInputs,
    /// At least one source-k16 slot is required; short-only callers must
    /// explicitly supply the pinned trivial accumulator as an additional slot.
    MissingFullLengthInput,
    /// The slot count cannot be represented by the transcript framing.
    InputCount,
    /// The pinned parameters do not cover the required prefix.
    Parameters(IpaError),
    /// The claim does not equal the independent complete-kernel commitment.
    Undecidable,
    /// The corrected commitment equals the original claim.
    NotCorrected,
    /// The succinct fold equation is false.
    FoldEquation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::Kernel(error) => write!(f, "kernel: {error}"),
            Self::Length { expected, actual } => write!(f, "length {actual}, expected {expected}"),
            Self::Encoding(error) => write!(f, "encoding: {error}"),
            Self::SourceK => f.write_str("source k must be in 1..=16"),
            Self::Padding => f.write_str("nonzero entry in the checked challenge prefix"),
            Self::ZeroChallenge { round } => write!(f, "zero challenge at round {round}"),
            Self::EmptyInputs => f.write_str("a fold requires at least one input"),
            Self::MissingFullLengthInput => {
                f.write_str("fold requires an explicit source-k16 slot")
            }
            Self::InputCount => f.write_str("fold input count is not representable"),
            Self::Parameters(error) => write!(f, "parameters: {error}"),
            Self::Undecidable => f.write_str("the accumulator does not decide"),
            Self::NotCorrected => f.write_str("corrected and original commitments are equal"),
            Self::FoldEquation => f.write_str("the succinct fold equation is false"),
        }
    }
}

impl std::error::Error for Error {}
impl Error {
    /// Cancellation is a hard operational failure and never authorizes a burn.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
            || matches!(self, Self::Parameters(error) if error.is_cancelled())
            || matches!(self, Self::Kernel(iroha_pasta::msm::MsmError::Cancelled))
    }
}
impl From<iroha_pasta::Cancelled> for Error {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}
impl From<iroha_pasta::msm::MsmError> for Error {
    fn from(error: iroha_pasta::msm::MsmError) -> Self {
        if matches!(error, iroha_pasta::msm::MsmError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Kernel(error)
        }
    }
}

impl From<TranscriptError> for Error {
    fn from(value: TranscriptError) -> Self {
        Self::Encoding(value)
    }
}

#[cfg(test)]
mod tests;

pub mod operation;
