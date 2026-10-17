//! Resource-bounded word-oriented SHA-256 AIR witness for zk-X509.
//!
//! The Boolean circuit in [`super::sha256_air`] is a useful differential
//! oracle, but one gate per bit does not fit the first-release CRL envelope.
//! This chip stores every 32-bit word once with a Boolean decomposition and
//! uses fixed operation rows for sigma, choice, majority, and modular
//! addition. Its local identities have degree at most three. Every word
//! definition and operand read is additionally bound by four independently
//! challenged address-sorted grand products. The complete 4 KiB CRL,
//! including those copy rows, fits the compiled SHA segment row ceiling.
//!
//! This module deliberately does not claim activation readiness. A segmented
//! proof must still bind input/output words to the DER, accumulator, and
//! projection segments and commit the main trace before deriving the copy
//! challenges.
use super::air::{U32RangeAirRowV1, ZkX509AirErrorV1};
#[cfg(test)]
use super::io_air::{
    ZkX509IoChallengesV1, ZkX509IoEndpointV1, ZkX509IoSegmentRoleV1, ZkX509IoTraceV1,
};
use super::private_table::PrivateTableV1;
#[cfg(test)]
use crate::privacy_engines::transparent_stark::PrivacyOuterDigestV1;
use crate::privacy_engines::transparent_stark::{
    GoldilocksFieldV1 as F, TransparentStarkErrorV1, TransparentTranscriptV1,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};
/// Manifest descriptor for the resource-bounded local SHA-256 chip.
pub const ZK_X509_SHA256_WORD_AIR_DESCRIPTOR_V1: &[u8] = b"sha256-word-air-v1-incompatible:u32-range-row=packed-plus32bits:sigma-degree3:choose-degree2:majority-degree3:add-up-to5-plus-u32-constant:carry-3bits:local-rows-per-block=1728:local-initial-rows=8:word-copy=four-independent-transcript-challenged-address-value-write-grand-products:sorted-address-step-0-or1:exactly-one-write-per-address:read-value-equals-write:memory-rows-per-block=2136:memory-fixed-rows=16:fixed-canonical-topology:physical-segment-offset-and-copy-product-continuations:shared-sha-call-bus-binding-required";
/// Native rows in each verifier-fixed SHA batch segment.
pub const SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1: usize = 1 << 19;
/// Verifier-fixed number of SHA batch segments.
pub const SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1: usize = 5;
const SHA256_INITIAL_STATE_V1: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const SHA256_ROUND_CONSTANTS_V1: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];
#[cfg(test)]
const WORD_AIR_ROWS_PER_BLOCK_V1: usize = 1_728;
#[cfg(test)]
const INITIAL_WORD_AIR_ROWS_V1: usize = 8;
#[cfg(test)]
const WORD_MEMORY_ROWS_PER_BLOCK_V1: usize = 2_136;
#[cfg(test)]
const FIXED_WORD_MEMORY_ROWS_V1: usize = 16;
pub const WORD_MEMORY_PERMUTATION_LANES_V1: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordMemoryAccessV1 {
    pub(crate) address: F,
    pub(crate) value: F,
    pub(crate) is_write: F,
}
impl WordMemoryAccessV1 {
    fn read(address: WordIdV1, value: F) -> Result<Self, ZkX509Sha256WordAirErrorV1> {
        Ok(Self {
            address: F(
                u64::try_from(address.0).map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?
            ),
            value,
            is_write: F::ZERO,
        })
    }
    fn write(address: WordIdV1, value: F) -> Result<Self, ZkX509Sha256WordAirErrorV1> {
        Ok(Self {
            address: F(
                u64::try_from(address.0).map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?
            ),
            value,
            is_write: F::ONE,
        })
    }
    fn validate(self, word_count: usize) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        let word_count =
            u64::try_from(word_count).map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        if self.address.0 >= word_count
            || self.value.0 > u64::from(u32::MAX)
            || self.is_write.mul(self.is_write.sub(F::ONE)) != F::ZERO
        {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
        }
        Ok(())
    }
}
/// One independent tuple-compression lane for the word-copy argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509WordMemoryLaneChallengesV1 {
    pub(crate) beta: F,
    pub(crate) address: F,
    pub(crate) value: F,
    pub(crate) is_write: F,
}
/// Four independently sampled lanes for the word-copy argument.
///
/// The main and address-sorted word traces must already be committed before
/// these challenges are sampled. At the maximum first-release access count,
/// each lane's permutation-collision bound is below `2^-43`; four independent
/// lanes put this local event below `2^-172`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkX509WordMemoryChallengesV1 {
    pub(crate) lanes: [ZkX509WordMemoryLaneChallengesV1; WORD_MEMORY_PERMUTATION_LANES_V1],
}
#[cfg(test)]
impl ZkX509WordMemoryChallengesV1 {
    fn validate(self) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        for lane in self.lanes {
            let coefficients = [lane.beta, lane.address, lane.value, lane.is_write];
            if coefficients
                .iter()
                .any(|coefficient| F::canonical(coefficient.0).is_none() || *coefficient == F::ZERO)
            {
                return Err(ZkX509Sha256WordAirErrorV1::WordMemoryChallenge);
            }
        }
        if self
            .lanes
            .iter()
            .enumerate()
            .any(|(index, lane)| self.lanes[..index].contains(lane))
        {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemoryChallenge);
        }
        Ok(())
    }
}
/// Derive the four word-copy lanes from a transcript after trace commitment.
pub fn derive_sha256_word_memory_challenges_v1(
    transcript: &mut TransparentTranscriptV1,
) -> Result<ZkX509WordMemoryChallengesV1, TransparentStarkErrorV1> {
    let mut sampled = [F::ZERO; WORD_MEMORY_PERMUTATION_LANES_V1 * 4];
    for (index, challenge) in sampled.iter_mut().enumerate() {
        let label = match index % 4 {
            0 => b"zk-x509-sha-word-copy-beta-v1".as_slice(),
            1 => b"zk-x509-sha-word-copy-address-v1".as_slice(),
            2 => b"zk-x509-sha-word-copy-value-v1".as_slice(),
            _ => b"zk-x509-sha-word-copy-write-v1".as_slice(),
        };
        *challenge = transcript.challenge_field(label)?;
    }
    Ok(ZkX509WordMemoryChallengesV1 {
        lanes: core::array::from_fn(|lane| ZkX509WordMemoryLaneChallengesV1 {
            beta: sampled[lane * 4],
            address: sampled[lane * 4 + 1],
            value: sampled[lane * 4 + 2],
            is_write: sampled[lane * 4 + 3],
        }),
    })
}
#[derive(Clone, PartialEq, Eq)]
pub struct WordMemoryTraceV1 {
    pub(crate) execution: Vec<WordMemoryAccessV1>,
    pub(crate) sorted: Vec<WordMemoryAccessV1>,
}
impl core::fmt::Debug for WordMemoryTraceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WordMemoryTraceV1 { private_words: [REDACTED] }")
    }
}
impl Drop for WordMemoryTraceV1 {
    fn drop(&mut self) {
        zeroize_word_accesses_v1(&mut self.execution);
        zeroize_word_accesses_v1(&mut self.sorted);
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordMemoryPermutationRowV1 {
    pub(crate) execution: WordMemoryAccessV1,
    pub(crate) sorted: WordMemoryAccessV1,
    pub(crate) execution_product_before: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_before: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) execution_product_after: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_after: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
}
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WordMemoryPermutationArgumentV1 {
    pub(crate) rows: Vec<WordMemoryPermutationRowV1>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256WordSegmentContinuationV1 {
    pub(crate) segment_index: u8,
    pub(crate) global_row_start: usize,
    pub(crate) global_row_end: usize,
    pub(crate) local_row_start: usize,
    pub(crate) local_row_end: usize,
    pub(crate) memory_row_start: usize,
    pub(crate) memory_row_end: usize,
    pub(crate) execution_product_start: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) execution_product_end: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_start: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    pub(crate) sorted_product_end: [F; WORD_MEMORY_PERMUTATION_LANES_V1],
}
/// Challenge-dependent auxiliary copy trace plus every physical-segment
/// continuation value.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkX509Sha256WordSegmentedTraceV1 {
    pub(crate) copy_argument: WordMemoryPermutationArgumentV1,
    pub(crate) segments: Vec<Sha256WordSegmentContinuationV1>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordIdV1(pub(crate) usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigmaThirdV1 {
    Rotate(u8),
    Shift(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordOperationV1 {
    Sigma {
        input: WordIdV1,
        rotate_first: u8,
        rotate_second: u8,
        third: SigmaThirdV1,
        output: WordIdV1,
    },
    Choose {
        x: WordIdV1,
        y: WordIdV1,
        z: WordIdV1,
        output: WordIdV1,
    },
    Majority {
        x: WordIdV1,
        y: WordIdV1,
        z: WordIdV1,
        output: WordIdV1,
    },
    Add {
        inputs: [WordIdV1; 5],
        arity: u8,
        constant: u32,
        output: WordIdV1,
        carry: u8,
        carry_bits: [F; 3],
    },
}
impl WordOperationV1 {
    pub(crate) fn same_topology(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Sigma {
                    input,
                    rotate_first,
                    rotate_second,
                    third,
                    output,
                },
                Self::Sigma {
                    input: other_input,
                    rotate_first: other_first,
                    rotate_second: other_second,
                    third: other_third,
                    output: other_output,
                },
            ) => {
                input == other_input
                    && rotate_first == other_first
                    && rotate_second == other_second
                    && third == other_third
                    && output == other_output
            }
            (
                Self::Choose { x, y, z, output },
                Self::Choose {
                    x: other_x,
                    y: other_y,
                    z: other_z,
                    output: other_output,
                },
            )
            | (
                Self::Majority { x, y, z, output },
                Self::Majority {
                    x: other_x,
                    y: other_y,
                    z: other_z,
                    output: other_output,
                },
            ) => x == other_x && y == other_y && z == other_z && output == other_output,
            (
                Self::Add {
                    inputs,
                    arity,
                    constant,
                    output,
                    ..
                },
                Self::Add {
                    inputs: other_inputs,
                    arity: other_arity,
                    constant: other_constant,
                    output: other_output,
                    ..
                },
            ) => {
                inputs == other_inputs
                    && arity == other_arity
                    && constant == other_constant
                    && output == other_output
            }
            _ => false,
        }
    }
}
/// Local word-chip construction or constraint failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkX509Sha256WordAirErrorV1 {
    /// Message length or row arithmetic overflowed.
    #[error("zk-X509 word SHA-256 AIR input is too large")]
    InputTooLarge,
    /// One word is not a canonical 32-bit decomposition.
    #[error("zk-X509 word SHA-256 AIR range row is invalid")]
    WordRange,
    /// Padding, word identifiers, or operation topology is non-canonical.
    #[error("zk-X509 word SHA-256 AIR topology is invalid")]
    Topology,
    /// A sigma, choose, or majority identity is unsatisfied.
    #[error("zk-X509 word SHA-256 AIR bitwise identity is invalid")]
    Bitwise,
    /// A modular-addition or carry identity is unsatisfied.
    #[error("zk-X509 word SHA-256 AIR addition identity is invalid")]
    Addition,
    /// The execution and address-sorted word tables are malformed or inconsistent.
    #[error("zk-X509 word SHA-256 AIR memory identity is invalid")]
    WordMemory,
    /// Word-copy challenges are zero, non-canonical, or duplicate.
    #[cfg(test)]
    #[error("zk-X509 word SHA-256 AIR memory challenges are invalid")]
    WordMemoryChallenge,
    /// A word-copy grand-product transition or final equality is invalid.
    #[cfg(test)]
    #[error("zk-X509 word SHA-256 AIR permutation product is invalid")]
    WordMemoryPermutation,
    /// A physical SHA segment boundary or copy-product continuation is invalid.
    #[cfg(test)]
    #[error("zk-X509 word SHA-256 AIR segment continuation is invalid")]
    SegmentContinuation,
    /// DER/accumulator channel cells are not bound to this SHA invocation.
    #[cfg(test)]
    #[error("zk-X509 word SHA-256 AIR cross-segment I/O binding is invalid")]
    IoBinding,
    /// Final output words do not reconstruct the stored digest.
    #[error("zk-X509 word SHA-256 AIR digest is invalid")]
    Digest,
}
impl From<ZkX509AirErrorV1> for ZkX509Sha256WordAirErrorV1 {
    fn from(_: ZkX509AirErrorV1) -> Self {
        Self::WordRange
    }
}
/// Complete local word-oriented SHA-256 witness.
#[derive(Clone, PartialEq, Eq)]
pub struct ZkX509Sha256WordCircuitV1 {
    words: Vec<U32RangeAirRowV1>,
    input_words: Vec<WordIdV1>,
    operations: Vec<WordOperationV1>,
    output_words: [WordIdV1; 8],
    memory: WordMemoryTraceV1,
    message_len: usize,
    digest: [u8; 32],
}
impl core::fmt::Debug for ZkX509Sha256WordCircuitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkX509Sha256WordCircuitV1 { private_witness: [REDACTED] }")
    }
}
impl Drop for ZkX509Sha256WordCircuitV1 {
    fn drop(&mut self) {
        zeroize_word_rows_v1(&mut self.words);
        zeroize_word_operations_v1(&mut self.operations);
        self.digest.zeroize();
        self.message_len.zeroize();
        // The memory field has its own clearing Drop, including cloned owners.
    }
}
impl ZkX509Sha256WordCircuitV1 {
    /// Constrained SHA-256 digest.
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Borrow the canonical word definitions for the segmented STARK builder.
    pub(crate) fn stark_words_v1(&self) -> &[U32RangeAirRowV1] {
        &self.words
    }
    /// Borrow the canonical operation schedule for the segmented STARK builder.
    pub(crate) fn stark_operations_v1(&self) -> &[WordOperationV1] {
        &self.operations
    }
    /// Canonical padded-message word identifiers in byte-stream order.
    pub(crate) fn stark_input_words_v1(&self) -> &[WordIdV1] {
        &self.input_words
    }
    /// Exact output word identifiers in digest order.
    pub(crate) const fn stark_output_words_v1(&self) -> [WordIdV1; 8] {
        self.output_words
    }
    /// Exact unpadded private message length.
    pub(crate) const fn stark_message_len_v1(&self) -> usize {
        self.message_len
    }
    /// Borrow the native execution and address-sorted word-memory tables.
    pub(crate) const fn stark_memory_v1(&self) -> &WordMemoryTraceV1 {
        &self.memory
    }
    /// Conceptual base rows after splitting wide bitwise rows to 64 columns.
    #[cfg(test)]
    pub(crate) fn air_rows(&self) -> usize {
        self.words.len()
            + self
                .operations
                .iter()
                .map(|operation| match operation {
                    WordOperationV1::Sigma { .. } | WordOperationV1::Add { .. } => 1,
                    WordOperationV1::Choose { .. } | WordOperationV1::Majority { .. } => 4,
                })
                .sum::<usize>()
    }
    /// Exact global word-copy rows for this message.
    #[cfg(test)]
    pub(crate) fn word_memory_rows(&self) -> usize {
        self.memory.execution.len()
    }
    /// Exact local plus global-copy rows for this message.
    #[cfg(test)]
    pub(crate) fn total_air_rows(&self) -> Result<usize, ZkX509Sha256WordAirErrorV1> {
        self.air_rows()
            .checked_add(self.word_memory_rows())
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)
    }
    /// Validate every local identity and the exact compiled topology.
    pub(crate) fn validate(&self) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        for word in &self.words {
            word.validate()?;
        }
        if self.words.len() < SHA256_INITIAL_STATE_V1.len()
            || !self.words[..SHA256_INITIAL_STATE_V1.len()]
                .iter()
                .copied()
                .eq(SHA256_INITIAL_STATE_V1.map(U32RangeAirRowV1::from_u32))
        {
            return Err(ZkX509Sha256WordAirErrorV1::Topology);
        }
        let padded = self.input_bytes()?;
        let message = padded
            .get(..self.message_len)
            .ok_or(ZkX509Sha256WordAirErrorV1::Topology)?;
        if sha256_padding_v1(message)?.as_slice() != padded.as_slice() {
            return Err(ZkX509Sha256WordAirErrorV1::Topology);
        }
        let canonical = build_sha256_word_circuit_unchecked_v1(message)?;
        if self.input_words != canonical.input_words
            || self.output_words != canonical.output_words
            || self.words.len() != canonical.words.len()
            || self.operations.len() != canonical.operations.len()
            || self
                .operations
                .iter()
                .zip(&canonical.operations)
                .any(|(actual, expected)| !actual.same_topology(expected))
            || self.memory.execution.len() != canonical.memory.execution.len()
            || self.memory.sorted.len() != canonical.memory.sorted.len()
        {
            return Err(ZkX509Sha256WordAirErrorV1::Topology);
        }
        drop(canonical);
        for operation in &self.operations {
            self.validate_operation(operation)?;
        }
        self.validate_memory_shape()?;
        if digest_from_words_v1(&self.words, &self.output_words)? != self.digest {
            return Err(ZkX509Sha256WordAirErrorV1::Digest);
        }
        Ok(())
    }
    /// Validate local identities plus the transcript-challenged global copy
    /// argument used by the segmented proof.
    #[cfg(test)]
    pub(crate) fn validate_with_word_memory_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        let segmented = self.build_segmented_trace_v1(challenges)?;
        self.validate_segmented_trace_v1(challenges, &segmented)
    }
    /// Build the copy auxiliary trace and exact compiled physical-segment
    /// continuation states.
    #[cfg(test)]
    pub(crate) fn build_segmented_trace_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
    ) -> Result<ZkX509Sha256WordSegmentedTraceV1, ZkX509Sha256WordAirErrorV1> {
        let (segment_rows, max_segments) = compiled_sha_segment_shape_v1();
        self.build_segmented_trace_with_shape_v1(challenges, segment_rows, max_segments)
    }
    /// Validate every copy row and every boundary under the compiled shape.
    #[cfg(test)]
    pub(crate) fn validate_segmented_trace_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
        trace: &ZkX509Sha256WordSegmentedTraceV1,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        let (segment_rows, max_segments) = compiled_sha_segment_shape_v1();
        self.validate_segmented_trace_with_shape_v1(challenges, trace, segment_rows, max_segments)
    }
    #[cfg(test)]
    fn build_segmented_trace_with_shape_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
        segment_rows: usize,
        max_segments: usize,
    ) -> Result<ZkX509Sha256WordSegmentedTraceV1, ZkX509Sha256WordAirErrorV1> {
        self.validate()?;
        challenges.validate()?;
        let copy_argument = self.build_word_memory_argument_v1(challenges)?;
        self.validate_word_memory_argument_v1(challenges, &copy_argument)?;
        let segments = build_sha256_segment_continuations_v1(
            self.air_rows(),
            self.word_memory_rows(),
            &copy_argument,
            segment_rows,
            max_segments,
        )?;
        Ok(ZkX509Sha256WordSegmentedTraceV1 {
            copy_argument,
            segments,
        })
    }
    #[cfg(test)]
    fn validate_segmented_trace_with_shape_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
        trace: &ZkX509Sha256WordSegmentedTraceV1,
        segment_rows: usize,
        max_segments: usize,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        self.validate()?;
        self.validate_word_memory_argument_v1(challenges, &trace.copy_argument)?;
        validate_sha256_segment_continuations_v1(
            self.air_rows(),
            self.word_memory_rows(),
            &trace.copy_argument,
            &trace.segments,
            segment_rows,
            max_segments,
        )
    }
    /// Bind this invocation's exact unpadded input and digest bytes to the
    /// global DER/accumulator byte-channel argument.
    #[cfg(test)]
    pub(crate) fn validate_cross_segment_io_v1(
        &self,
        io_challenges: ZkX509IoChallengesV1,
        io_trace: &ZkX509IoTraceV1,
        input_channel: u32,
        digest_channel: u32,
        sha_instance: u16,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        self.validate()?;
        io_trace
            .validate(io_challenges)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::IoBinding)?;
        let endpoint = ZkX509IoEndpointV1 {
            role: ZkX509IoSegmentRoleV1::Sha256,
            instance: sha_instance,
        };
        let padded = self.input_bytes()?;
        let message = padded
            .get(..self.message_len)
            .ok_or(ZkX509Sha256WordAirErrorV1::Topology)?;
        io_trace
            .validate_endpoint_bytes(input_channel, endpoint, false, message)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::IoBinding)?;
        io_trace
            .validate_endpoint_bytes(digest_channel, endpoint, true, &self.digest)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::IoBinding)
    }
    fn validate_memory_shape(&self) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        let expected = word_memory_execution_v1(&self.words, &self.operations, &self.output_words)?;
        if self.memory.execution.as_slice() != expected.as_slice() {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
        }
        validate_sorted_word_memory_v1(&self.memory.sorted, self.words.len())
    }
    #[cfg(test)]
    fn build_word_memory_argument_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
    ) -> Result<WordMemoryPermutationArgumentV1, ZkX509Sha256WordAirErrorV1> {
        if self.memory.execution.len() != self.memory.sorted.len() {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.memory.execution.len())
            .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let mut execution_product = [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1];
        let mut sorted_product = [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1];
        for (execution, sorted) in self
            .memory
            .execution
            .iter()
            .copied()
            .zip(self.memory.sorted.iter().copied())
        {
            let execution_product_before = execution_product;
            let sorted_product_before = sorted_product;
            for lane in 0..WORD_MEMORY_PERMUTATION_LANES_V1 {
                execution_product[lane] = execution_product[lane].mul(
                    compress_word_memory_access_v1(execution, challenges.lanes[lane]),
                );
                sorted_product[lane] = sorted_product[lane].mul(compress_word_memory_access_v1(
                    sorted,
                    challenges.lanes[lane],
                ));
            }
            rows.push(WordMemoryPermutationRowV1 {
                execution,
                sorted,
                execution_product_before,
                sorted_product_before,
                execution_product_after: execution_product,
                sorted_product_after: sorted_product,
            });
        }
        Ok(WordMemoryPermutationArgumentV1 { rows })
    }
    #[cfg(test)]
    fn validate_word_memory_argument_v1(
        &self,
        challenges: ZkX509WordMemoryChallengesV1,
        argument: &WordMemoryPermutationArgumentV1,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        challenges.validate()?;
        if argument.rows.len() != self.memory.execution.len() || argument.rows.is_empty() {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation);
        }
        let mut expected_execution_before = [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1];
        let mut expected_sorted_before = [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1];
        for (index, row) in argument.rows.iter().enumerate() {
            if row.execution != self.memory.execution[index]
                || row.sorted != self.memory.sorted[index]
                || row.execution_product_before != expected_execution_before
                || row.sorted_product_before != expected_sorted_before
            {
                return Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation);
            }
            for lane in 0..WORD_MEMORY_PERMUTATION_LANES_V1 {
                let expected_execution_after = row.execution_product_before[lane].mul(
                    compress_word_memory_access_v1(row.execution, challenges.lanes[lane]),
                );
                let expected_sorted_after = row.sorted_product_before[lane].mul(
                    compress_word_memory_access_v1(row.sorted, challenges.lanes[lane]),
                );
                if row.execution_product_after[lane] != expected_execution_after
                    || row.sorted_product_after[lane] != expected_sorted_after
                {
                    return Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation);
                }
            }
            expected_execution_before = row.execution_product_after;
            expected_sorted_before = row.sorted_product_after;
        }
        if expected_execution_before != expected_sorted_before {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation);
        }
        Ok(())
    }
    fn input_bytes(&self) -> Result<Zeroizing<Vec<u8>>, ZkX509Sha256WordAirErrorV1> {
        if self.input_words.is_empty() || self.input_words.len() % 16 != 0 {
            return Err(ZkX509Sha256WordAirErrorV1::Topology);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(self.input_words.len().saturating_mul(4))
            .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        for id in &self.input_words {
            bytes.extend_from_slice(&word_value_v1(&self.words, *id)?.to_be_bytes());
        }
        Ok(bytes)
    }
    fn validate_operation(
        &self,
        operation: &WordOperationV1,
    ) -> Result<(), ZkX509Sha256WordAirErrorV1> {
        match operation {
            WordOperationV1::Sigma {
                input,
                rotate_first,
                rotate_second,
                third,
                output,
            } => {
                let input = word_row_v1(&self.words, *input)?;
                let output = word_row_v1(&self.words, *output)?;
                for bit in 0..32 {
                    let first = input.bits[(bit + usize::from(*rotate_first)) % 32];
                    let second = input.bits[(bit + usize::from(*rotate_second)) % 32];
                    let third = match third {
                        SigmaThirdV1::Rotate(distance) => {
                            input.bits[(bit + usize::from(*distance)) % 32]
                        }
                        SigmaThirdV1::Shift(distance) => input
                            .bits
                            .get(bit + usize::from(*distance))
                            .copied()
                            .unwrap_or(F::ZERO),
                    };
                    let expected = xor_three_v1(first, second, third);
                    if output.bits[bit] != expected {
                        return Err(ZkX509Sha256WordAirErrorV1::Bitwise);
                    }
                }
            }
            WordOperationV1::Choose { x, y, z, output } => {
                let x = word_row_v1(&self.words, *x)?;
                let y = word_row_v1(&self.words, *y)?;
                let z = word_row_v1(&self.words, *z)?;
                let output = word_row_v1(&self.words, *output)?;
                for bit in 0..32 {
                    let expected = x.bits[bit]
                        .mul(y.bits[bit])
                        .add(F::ONE.sub(x.bits[bit]).mul(z.bits[bit]));
                    if output.bits[bit] != expected {
                        return Err(ZkX509Sha256WordAirErrorV1::Bitwise);
                    }
                }
            }
            WordOperationV1::Majority { x, y, z, output } => {
                let x = word_row_v1(&self.words, *x)?;
                let y = word_row_v1(&self.words, *y)?;
                let z = word_row_v1(&self.words, *z)?;
                let output = word_row_v1(&self.words, *output)?;
                for bit in 0..32 {
                    let xy = x.bits[bit].mul(y.bits[bit]);
                    let xz = x.bits[bit].mul(z.bits[bit]);
                    let yz = y.bits[bit].mul(z.bits[bit]);
                    let xyz = xy.mul(z.bits[bit]);
                    if output.bits[bit] != xy.add(xz).add(yz).sub(F(2).mul(xyz)) {
                        return Err(ZkX509Sha256WordAirErrorV1::Bitwise);
                    }
                }
            }
            WordOperationV1::Add {
                inputs,
                arity,
                constant,
                output,
                carry,
                carry_bits,
            } => {
                if !(1..=5).contains(arity)
                    || carry_bits
                        .iter()
                        .any(|bit| bit.mul(bit.sub(F::ONE)) != F::ZERO)
                    || u64::from(*carry)
                        != carry_bits
                            .iter()
                            .enumerate()
                            .map(|(bit, value)| value.0 << bit)
                            .sum::<u64>()
                {
                    return Err(ZkX509Sha256WordAirErrorV1::Addition);
                }
                let mut sum = F(u64::from(*constant));
                for id in &inputs[..usize::from(*arity)] {
                    sum = sum.add(word_row_v1(&self.words, *id)?.value);
                }
                let expected = word_row_v1(&self.words, *output)?
                    .value
                    .add(F(1_u64 << 32).mul(F(u64::from(*carry))));
                if sum != expected {
                    return Err(ZkX509Sha256WordAirErrorV1::Addition);
                }
            }
        }
        Ok(())
    }
}
struct WordBuilderV1 {
    words: Vec<U32RangeAirRowV1>,
    input_words: Vec<WordIdV1>,
    operations: Vec<WordOperationV1>,
}
impl Drop for WordBuilderV1 {
    fn drop(&mut self) {
        zeroize_word_rows_v1(&mut self.words);
        zeroize_word_operations_v1(&mut self.operations);
    }
}
impl WordBuilderV1 {
    fn new(blocks: usize) -> Result<Self, ZkX509Sha256WordAirErrorV1> {
        // Every block has 16 input definitions, 48 three-operation schedule
        // expansions, 64 eight-operation rounds and 8 final additions. Reserve
        // the exact topology before private writes so Vec never reallocates
        // private decompositions or carries while constructing a valid circuit.
        let operations = blocks
            .checked_mul(664)
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let inputs = blocks
            .checked_mul(16)
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let words = operations
            .checked_add(inputs)
            .and_then(|n| n.checked_add(8))
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let mut builder = Self {
            words: Vec::new(),
            input_words: Vec::new(),
            operations: Vec::new(),
        };
        builder
            .words
            .try_reserve_exact(words)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        builder
            .input_words
            .try_reserve_exact(inputs)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        builder
            .operations
            .try_reserve_exact(operations)
            .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        Ok(builder)
    }
    fn allocate(&mut self, value: u32) -> WordIdV1 {
        let id = WordIdV1(self.words.len());
        self.words.push(U32RangeAirRowV1::from_u32(value));
        id
    }
    fn value(&self, id: WordIdV1) -> u32 {
        self.words[id.0].value.0 as u32
    }
    fn input(&mut self, value: u32) -> WordIdV1 {
        let id = self.allocate(value);
        self.input_words.push(id);
        id
    }
    fn sigma(
        &mut self,
        input: WordIdV1,
        rotate_first: u8,
        rotate_second: u8,
        third: SigmaThirdV1,
    ) -> WordIdV1 {
        let value = self.value(input);
        let third_value = match third {
            SigmaThirdV1::Rotate(distance) => value.rotate_right(u32::from(distance)),
            SigmaThirdV1::Shift(distance) => value >> distance,
        };
        let output = self.allocate(
            value.rotate_right(u32::from(rotate_first))
                ^ value.rotate_right(u32::from(rotate_second))
                ^ third_value,
        );
        self.operations.push(WordOperationV1::Sigma {
            input,
            rotate_first,
            rotate_second,
            third,
            output,
        });
        output
    }
    fn choose(&mut self, x: WordIdV1, y: WordIdV1, z: WordIdV1) -> WordIdV1 {
        let output =
            self.allocate((self.value(x) & self.value(y)) ^ (!self.value(x) & self.value(z)));
        self.operations
            .push(WordOperationV1::Choose { x, y, z, output });
        output
    }
    fn majority(&mut self, x: WordIdV1, y: WordIdV1, z: WordIdV1) -> WordIdV1 {
        let output = self.allocate(
            (self.value(x) & self.value(y))
                ^ (self.value(x) & self.value(z))
                ^ (self.value(y) & self.value(z)),
        );
        self.operations
            .push(WordOperationV1::Majority { x, y, z, output });
        output
    }
    fn add(&mut self, inputs: &[WordIdV1], constant: u32) -> WordIdV1 {
        debug_assert!(!inputs.is_empty() && inputs.len() <= 5);
        let sum = inputs.iter().fold(u64::from(constant), |sum, id| {
            sum + u64::from(self.value(*id))
        });
        let output = self.allocate(sum as u32);
        let carry = (sum >> 32) as u8;
        let mut padded = [inputs[0]; 5];
        padded[..inputs.len()].copy_from_slice(inputs);
        self.operations.push(WordOperationV1::Add {
            inputs: padded,
            arity: inputs.len() as u8,
            constant,
            output,
            carry,
            carry_bits: core::array::from_fn(|bit| F(u64::from((carry >> bit) & 1))),
        });
        output
    }
}
/// Build and validate the resource-bounded SHA-256 word chip.
pub fn build_sha256_word_circuit_v1(
    message: &[u8],
) -> Result<ZkX509Sha256WordCircuitV1, ZkX509Sha256WordAirErrorV1> {
    let circuit = build_sha256_word_circuit_unchecked_v1(message)?;
    circuit.validate()?;
    Ok(circuit)
}
/// Exact conceptual local rows for one message length.
#[cfg(test)]
pub fn sha256_word_air_rows_for_message_len_v1(
    message_len: usize,
) -> Result<usize, ZkX509Sha256WordAirErrorV1> {
    let padded_len = sha256_padded_len_v1(message_len)?;
    padded_len
        .checked_div(64)
        .and_then(|blocks| blocks.checked_mul(WORD_AIR_ROWS_PER_BLOCK_V1))
        .and_then(|rows| rows.checked_add(INITIAL_WORD_AIR_ROWS_V1))
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)
}
/// Exact global word-copy rows for one message length.
#[cfg(test)]
pub fn sha256_word_memory_rows_for_message_len_v1(
    message_len: usize,
) -> Result<usize, ZkX509Sha256WordAirErrorV1> {
    let padded_len = sha256_padded_len_v1(message_len)?;
    padded_len
        .checked_div(64)
        .and_then(|blocks| blocks.checked_mul(WORD_MEMORY_ROWS_PER_BLOCK_V1))
        .and_then(|rows| rows.checked_add(FIXED_WORD_MEMORY_ROWS_V1))
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)
}
/// Exact local plus global-copy rows for one message length.
#[cfg(test)]
pub fn sha256_word_total_rows_for_message_len_v1(
    message_len: usize,
) -> Result<usize, ZkX509Sha256WordAirErrorV1> {
    sha256_word_air_rows_for_message_len_v1(message_len)?
        .checked_add(sha256_word_memory_rows_for_message_len_v1(message_len)?)
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)
}
fn build_sha256_word_circuit_unchecked_v1(
    message: &[u8],
) -> Result<ZkX509Sha256WordCircuitV1, ZkX509Sha256WordAirErrorV1> {
    let padded = sha256_padding_v1(message)?;
    let mut builder = WordBuilderV1::new(padded.len() / 64)?;
    #[cfg(test)]
    let private_allocations = (builder.words.as_ptr(), builder.operations.as_ptr());
    let mut state = SHA256_INITIAL_STATE_V1.map(|word| builder.allocate(word));
    for block in padded.chunks_exact(64) {
        let mut schedule = Vec::with_capacity(64);
        for bytes in block.chunks_exact(4) {
            schedule.push(builder.input(u32::from_be_bytes(
                bytes.try_into().expect("four-byte SHA-256 word"),
            )));
        }
        for index in 16..64 {
            let sigma_zero = builder.sigma(schedule[index - 15], 7, 18, SigmaThirdV1::Shift(3));
            let sigma_one = builder.sigma(schedule[index - 2], 17, 19, SigmaThirdV1::Shift(10));
            schedule.push(builder.add(
                &[
                    schedule[index - 16],
                    sigma_zero,
                    schedule[index - 7],
                    sigma_one,
                ],
                0,
            ));
        }
        let original = state;
        let mut work = state;
        for round in 0..64 {
            let sigma_one = builder.sigma(work[4], 6, 11, SigmaThirdV1::Rotate(25));
            let choose = builder.choose(work[4], work[5], work[6]);
            let t1 = builder.add(
                &[work[7], sigma_one, choose, schedule[round]],
                SHA256_ROUND_CONSTANTS_V1[round],
            );
            let sigma_zero = builder.sigma(work[0], 2, 13, SigmaThirdV1::Rotate(22));
            let majority = builder.majority(work[0], work[1], work[2]);
            let t2 = builder.add(&[sigma_zero, majority], 0);
            let next_a = builder.add(&[t1, t2], 0);
            let next_e = builder.add(&[work[3], t1], 0);
            work = [
                next_a, work[0], work[1], work[2], next_e, work[4], work[5], work[6],
            ];
        }
        state = core::array::from_fn(|index| builder.add(&[original[index], work[index]], 0));
    }
    let digest = digest_from_words_v1(&builder.words, &state)?;
    let memory = build_word_memory_trace_v1(&builder.words, &builder.operations, &state)?;
    #[cfg(test)]
    assert_eq!(
        private_allocations,
        (builder.words.as_ptr(), builder.operations.as_ptr()),
        "private word and carry buffers must not reallocate"
    );
    Ok(ZkX509Sha256WordCircuitV1 {
        words: core::mem::take(&mut builder.words),
        input_words: core::mem::take(&mut builder.input_words),
        operations: core::mem::take(&mut builder.operations),
        output_words: state,
        memory,
        message_len: message.len(),
        digest,
    })
}
fn build_word_memory_trace_v1(
    words: &[U32RangeAirRowV1],
    operations: &[WordOperationV1],
    output_words: &[WordIdV1; 8],
) -> Result<WordMemoryTraceV1, ZkX509Sha256WordAirErrorV1> {
    let execution = word_memory_execution_v1(words, operations, output_words)?;
    let mut sorted = PrivateTableV1::new(execution.to_vec(), zeroize_word_accesses_v1);
    // Each address is an immutable word: all read ties have exactly the same
    // complete tuple, so unstable in-place sorting preserves canonical bytes
    // without allocating an uncleared stable-sort copy of private events.
    sorted.sort_unstable_by_key(|access| {
        (
            access.address.0,
            if access.is_write == F::ONE {
                0_u8
            } else {
                1_u8
            },
        )
    });
    validate_sorted_word_memory_v1(&sorted, words.len())?;
    Ok(WordMemoryTraceV1 {
        execution: execution.into_vec(),
        sorted: sorted.into_vec(),
    })
}
fn word_memory_execution_v1(
    words: &[U32RangeAirRowV1],
    operations: &[WordOperationV1],
    output_words: &[WordIdV1; 8],
) -> Result<PrivateTableV1<WordMemoryAccessV1>, ZkX509Sha256WordAirErrorV1> {
    let read_count = operations
        .iter()
        .try_fold(0_usize, |count, operation| {
            count.checked_add(match operation {
                WordOperationV1::Sigma { .. } => 1,
                WordOperationV1::Choose { .. } | WordOperationV1::Majority { .. } => 3,
                WordOperationV1::Add { arity, .. } => usize::from(*arity),
            })
        })
        .and_then(|count| count.checked_add(output_words.len()))
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    let capacity = words
        .len()
        .checked_add(read_count)
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    let mut accesses = PrivateTableV1::new(Vec::new(), zeroize_word_accesses_v1);
    accesses
        .try_reserve_exact(capacity)
        .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    for (address, word) in words.iter().enumerate() {
        accesses.push(WordMemoryAccessV1::write(WordIdV1(address), word.value)?);
    }
    for operation in operations {
        match operation {
            WordOperationV1::Sigma { input, .. } => {
                push_word_read_v1(&mut accesses, words, *input)?;
            }
            WordOperationV1::Choose { x, y, z, .. } | WordOperationV1::Majority { x, y, z, .. } => {
                for input in [*x, *y, *z] {
                    push_word_read_v1(&mut accesses, words, input)?;
                }
            }
            WordOperationV1::Add { inputs, arity, .. } => {
                if !(1..=5).contains(arity) {
                    return Err(ZkX509Sha256WordAirErrorV1::Topology);
                }
                for input in &inputs[..usize::from(*arity)] {
                    push_word_read_v1(&mut accesses, words, *input)?;
                }
            }
        }
    }
    for output in output_words {
        push_word_read_v1(&mut accesses, words, *output)?;
    }
    if accesses.len() != capacity {
        return Err(ZkX509Sha256WordAirErrorV1::Topology);
    }
    Ok(accesses)
}
fn push_word_read_v1(
    accesses: &mut Vec<WordMemoryAccessV1>,
    words: &[U32RangeAirRowV1],
    address: WordIdV1,
) -> Result<(), ZkX509Sha256WordAirErrorV1> {
    accesses.push(WordMemoryAccessV1::read(
        address,
        word_row_v1(words, address)?.value,
    )?);
    Ok(())
}
fn validate_sorted_word_memory_v1(
    sorted: &[WordMemoryAccessV1],
    word_count: usize,
) -> Result<(), ZkX509Sha256WordAirErrorV1> {
    let first = sorted
        .first()
        .ok_or(ZkX509Sha256WordAirErrorV1::WordMemory)?;
    if word_count == 0 || first.address != F::ZERO || first.is_write != F::ONE {
        return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
    }
    first.validate(word_count)?;
    for pair in sorted.windows(2) {
        let previous = pair[0];
        let current = pair[1];
        current.validate(word_count)?;
        if current.address == previous.address {
            if current.is_write != F::ZERO || current.value != previous.value {
                return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
            }
        } else if current.address == previous.address.add(F::ONE) {
            if current.is_write != F::ONE {
                return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
            }
        } else {
            return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
        }
    }
    let last_address =
        F(u64::try_from(word_count - 1).map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?);
    if sorted.last().map(|access| access.address) != Some(last_address) {
        return Err(ZkX509Sha256WordAirErrorV1::WordMemory);
    }
    Ok(())
}
#[cfg(test)]
fn compress_word_memory_access_v1(
    access: WordMemoryAccessV1,
    challenges: ZkX509WordMemoryLaneChallengesV1,
) -> F {
    challenges
        .beta
        .add(challenges.address.mul(access.address))
        .add(challenges.value.mul(access.value))
        .add(challenges.is_write.mul(access.is_write))
}
#[cfg(test)]
const fn compiled_sha_segment_shape_v1() -> (usize, usize) {
    (
        SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1,
        SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1,
    )
}
#[cfg(test)]
fn build_sha256_segment_continuations_v1(
    local_rows: usize,
    memory_rows: usize,
    copy_argument: &WordMemoryPermutationArgumentV1,
    segment_rows: usize,
    max_segments: usize,
) -> Result<Vec<Sha256WordSegmentContinuationV1>, ZkX509Sha256WordAirErrorV1> {
    if segment_rows == 0
        || max_segments == 0
        || memory_rows != copy_argument.rows.len()
        || memory_rows == 0
    {
        return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
    }
    let total_rows = local_rows
        .checked_add(memory_rows)
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    let segment_count = total_rows.div_ceil(segment_rows);
    if segment_count == 0 || segment_count > max_segments || segment_count > usize::from(u8::MAX) {
        return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
    }
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(segment_count)
        .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    for index in 0..segment_count {
        let global_row_start = index
            .checked_mul(segment_rows)
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let global_row_end = global_row_start
            .checked_add(segment_rows)
            .map(|end| end.min(total_rows))
            .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
        let local_row_start = global_row_start.min(local_rows);
        let local_row_end = global_row_end.min(local_rows);
        let memory_row_start = global_row_start.saturating_sub(local_rows).min(memory_rows);
        let memory_row_end = global_row_end.saturating_sub(local_rows).min(memory_rows);
        let (execution_product_start, sorted_product_start) =
            word_copy_products_at_v1(copy_argument, memory_row_start)?;
        let (execution_product_end, sorted_product_end) =
            word_copy_products_at_v1(copy_argument, memory_row_end)?;
        segments.push(Sha256WordSegmentContinuationV1 {
            segment_index: u8::try_from(index)
                .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?,
            global_row_start,
            global_row_end,
            local_row_start,
            local_row_end,
            memory_row_start,
            memory_row_end,
            execution_product_start,
            execution_product_end,
            sorted_product_start,
            sorted_product_end,
        });
    }
    Ok(segments)
}
#[cfg(test)]
fn validate_sha256_segment_continuations_v1(
    local_rows: usize,
    memory_rows: usize,
    copy_argument: &WordMemoryPermutationArgumentV1,
    segments: &[Sha256WordSegmentContinuationV1],
    segment_rows: usize,
    max_segments: usize,
) -> Result<(), ZkX509Sha256WordAirErrorV1> {
    let expected = build_sha256_segment_continuations_v1(
        local_rows,
        memory_rows,
        copy_argument,
        segment_rows,
        max_segments,
    )?;
    if segments != expected {
        return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
    }
    let first = segments
        .first()
        .ok_or(ZkX509Sha256WordAirErrorV1::SegmentContinuation)?;
    if first.segment_index != 0
        || first.global_row_start != 0
        || first.local_row_start != 0
        || first.memory_row_start != 0
        || first.execution_product_start != [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1]
        || first.sorted_product_start != [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1]
    {
        return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
    }
    for pair in segments.windows(2) {
        let previous = pair[0];
        let current = pair[1];
        if current.segment_index != previous.segment_index + 1
            || current.global_row_start != previous.global_row_end
            || current.local_row_start != previous.local_row_end
            || current.memory_row_start != previous.memory_row_end
            || current.execution_product_start != previous.execution_product_end
            || current.sorted_product_start != previous.sorted_product_end
        {
            return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
        }
    }
    let last = segments
        .last()
        .ok_or(ZkX509Sha256WordAirErrorV1::SegmentContinuation)?;
    if last.local_row_end != local_rows
        || last.memory_row_end != memory_rows
        || last
            .global_row_end
            .checked_sub(last.global_row_start)
            .is_none_or(|active_rows| active_rows == 0 || active_rows > segment_rows)
        || last.execution_product_end != last.sorted_product_end
    {
        return Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation);
    }
    Ok(())
}
#[cfg(test)]
fn word_copy_products_at_v1(
    argument: &WordMemoryPermutationArgumentV1,
    row_offset: usize,
) -> Result<
    (
        [F; WORD_MEMORY_PERMUTATION_LANES_V1],
        [F; WORD_MEMORY_PERMUTATION_LANES_V1],
    ),
    ZkX509Sha256WordAirErrorV1,
> {
    if row_offset == 0 {
        return Ok((
            [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1],
            [F::ONE; WORD_MEMORY_PERMUTATION_LANES_V1],
        ));
    }
    let row = argument
        .rows
        .get(row_offset - 1)
        .ok_or(ZkX509Sha256WordAirErrorV1::SegmentContinuation)?;
    Ok((row.execution_product_after, row.sorted_product_after))
}
fn xor_three_v1(x: F, y: F, z: F) -> F {
    let xy = x.mul(y);
    let xz = x.mul(z);
    let yz = y.mul(z);
    x.add(y)
        .add(z)
        .sub(F(2).mul(xy.add(xz).add(yz)))
        .add(F(4).mul(xy.mul(z)))
}
fn word_row_v1(
    words: &[U32RangeAirRowV1],
    id: WordIdV1,
) -> Result<&U32RangeAirRowV1, ZkX509Sha256WordAirErrorV1> {
    words.get(id.0).ok_or(ZkX509Sha256WordAirErrorV1::Topology)
}
fn word_value_v1(
    words: &[U32RangeAirRowV1],
    id: WordIdV1,
) -> Result<u32, ZkX509Sha256WordAirErrorV1> {
    u32::try_from(word_row_v1(words, id)?.value.0)
        .map_err(|_| ZkX509Sha256WordAirErrorV1::WordRange)
}
fn digest_from_words_v1(
    words: &[U32RangeAirRowV1],
    output: &[WordIdV1; 8],
) -> Result<[u8; 32], ZkX509Sha256WordAirErrorV1> {
    let mut digest = [0_u8; 32];
    for (index, id) in output.iter().enumerate() {
        digest[index * 4..(index + 1) * 4]
            .copy_from_slice(&word_value_v1(words, *id)?.to_be_bytes());
    }
    Ok(digest)
}
fn sha256_padded_len_v1(message_len: usize) -> Result<usize, ZkX509Sha256WordAirErrorV1> {
    let with_marker = message_len
        .checked_add(1)
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    let remainder = with_marker % 64;
    let zero_padding = if remainder <= 56 {
        56 - remainder
    } else {
        64 + 56 - remainder
    };
    with_marker
        .checked_add(zero_padding)
        .and_then(|length| length.checked_add(8))
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)
}
fn sha256_padding_v1(message: &[u8]) -> Result<Zeroizing<Vec<u8>>, ZkX509Sha256WordAirErrorV1> {
    let bit_length = u64::try_from(message.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    let padded_len = sha256_padded_len_v1(message.len())?;
    let mut padded = Zeroizing::new(Vec::new());
    padded
        .try_reserve_exact(padded_len)
        .map_err(|_| ZkX509Sha256WordAirErrorV1::InputTooLarge)?;
    padded.extend_from_slice(message);
    padded.push(0x80);
    padded.resize(padded_len - 8, 0);
    padded.extend_from_slice(&bit_length.to_be_bytes());
    Ok(padded)
}

fn zeroize_word_rows_v1(words: &mut [U32RangeAirRowV1]) {
    for word in words.iter_mut() {
        word.value.zeroize_v1();
        for bit in &mut word.bits {
            bit.zeroize_v1();
        }
    }
    #[cfg(test)]
    tests::record_raw_erasure_v1(words.len() * 33, || {
        words
            .iter()
            .all(|word| word.value == F::ZERO && word.bits.iter().all(|bit| *bit == F::ZERO))
    });
}

fn zeroize_word_operations_v1(operations: &mut [WordOperationV1]) {
    for operation in operations.iter_mut() {
        if let WordOperationV1::Add {
            carry, carry_bits, ..
        } = operation
        {
            carry.zeroize();
            for bit in carry_bits {
                bit.zeroize_v1();
            }
        }
    }
    #[cfg(test)]
    tests::record_raw_erasure_v1(operations.len(), || {
        operations.iter().all(|operation| {
            !matches!(operation, WordOperationV1::Add { carry, carry_bits, .. }
            if *carry != 0 || carry_bits.iter().any(|bit| *bit != F::ZERO))
        })
    });
}

fn zeroize_word_accesses_v1(accesses: &mut [WordMemoryAccessV1]) {
    for access in accesses.iter_mut() {
        access.address.zeroize_v1();
        access.value.zeroize_v1();
        access.is_write.zeroize_v1();
    }
    #[cfg(test)]
    tests::record_raw_erasure_v1(accesses.len() * 3, || {
        accesses.iter().all(|access| {
            access.address == F::ZERO && access.value == F::ZERO && access.is_write == F::ZERO
        })
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::zk_x509::io_air::{
        ZkX509IoAirErrorV1, ZkX509IoChannelDeclarationV1, ZkX509IoChannelWitnessV1,
        build_zk_x509_io_trace_v1, derive_zk_x509_io_challenges_v1,
    };
    use crate::privacy_engines::zk_x509::profile::{
        ZK_X509_MAX_CRL_BYTES_V1, ZK_X509_TARGET_SOUNDNESS_BITS_V1,
    };
    use sha2::{Digest as _, Sha256};
    thread_local! {
        static RAW_ERASURE: core::cell::Cell<Option<(usize, bool)>> = const { core::cell::Cell::new(None) };
    }
    pub(super) fn record_raw_erasure_v1(cells: usize, cleared: impl FnOnce() -> bool) {
        RAW_ERASURE.with(|observed| {
            if let Some((previous, all_cleared)) = observed.get() {
                observed.set(Some((previous + cells, all_cleared && cleared())));
            }
        });
    }
    fn observe_raw_erasure_v1(operation: impl FnOnce()) -> (usize, bool) {
        struct Scope;
        impl Drop for Scope {
            fn drop(&mut self) {
                RAW_ERASURE.set(None);
            }
        }
        RAW_ERASURE.set(Some((0, true)));
        let _scope = Scope;
        operation();
        RAW_ERASURE.get().unwrap()
    }

    #[test]
    fn raw_word_private_owners_clear_on_success_partial_error_and_unwind() {
        let caller = b"private SHA words remain caller-owned";
        let circuit = build_sha256_word_circuit_v1(caller).unwrap();
        let expected_digest: [u8; 32] = Sha256::digest(caller).into();
        assert_eq!(circuit.digest(), expected_digest);
        assert_eq!(
            format!("{circuit:?}"),
            "ZkX509Sha256WordCircuitV1 { private_witness: [REDACTED] }"
        );
        assert_eq!(
            format!("{:?}", circuit.memory),
            "WordMemoryTraceV1 { private_words: [REDACTED] }"
        );
        let expected = circuit.words.len() * 33
            + circuit.operations.len()
            + (circuit.memory.execution.len() + circuit.memory.sorted.len()) * 3;
        assert_eq!(
            observe_raw_erasure_v1(|| drop(circuit.clone())),
            (expected, true)
        );
        assert!(circuit.words.iter().any(|word| word.value != F::ZERO));
        let unwound = observe_raw_erasure_v1(|| {
            assert!(
                std::panic::catch_unwind(|| {
                    let _owned = circuit.clone();
                    panic!("test-only private word owner unwind");
                })
                .is_err()
            );
        });
        assert_eq!(unwound, (expected, true));
        // Definitions have already populated the guarded table before this
        // malformed operand fails. Observe those actual cells before free.
        let operations = [WordOperationV1::Sigma {
            input: WordIdV1(usize::MAX),
            rotate_first: 7,
            rotate_second: 18,
            third: SigmaThirdV1::Shift(3),
            output: WordIdV1(0),
        }];
        let partial = observe_raw_erasure_v1(|| {
            assert!(
                word_memory_execution_v1(&circuit.words, &operations, &circuit.output_words)
                    .is_err()
            );
        });
        assert_eq!(partial, (circuit.words.len() * 3, true));
        let builder = observe_raw_erasure_v1(|| {
            let mut builder = WordBuilderV1::new(1).unwrap();
            let first = builder.allocate(u32::MAX);
            builder.add(&[first, first], u32::MAX);
        });
        assert_eq!(builder, (2 * 33 + 1, true));
        assert_eq!(caller, b"private SHA words remain caller-owned");
    }

    #[test]
    fn raw_word_allocation_and_in_place_sort_preserve_digest_and_tie_bytes() {
        for length in [0, 1, 55, 56, 63, 64, 65, 129] {
            let message = vec![0x91; length];
            let circuit = build_sha256_word_circuit_v1(&message).unwrap();
            let blocks = sha256_padded_len_v1(length).unwrap() / 64;
            assert_eq!(circuit.words.len(), 8 + blocks * 680);
            assert_eq!(circuit.operations.len(), blocks * 664);
            assert_eq!(circuit.input_words.len(), blocks * 16);
            let expected_digest: [u8; 32] = Sha256::digest(&message).into();
            assert_eq!(circuit.digest(), expected_digest);
            let mut reference = circuit.memory.execution.clone();
            reference.sort_by_key(|access| (access.address.0, u8::from(access.is_write != F::ONE)));
            assert_eq!(circuit.memory.sorted, reference);
            assert!(reference.windows(2).any(|pair| pair[0] == pair[1]));
            zeroize_word_accesses_v1(&mut reference);
            let bytes: Zeroizing<Vec<u8>> = circuit.input_bytes().unwrap();
            assert_eq!(&bytes[..length], message);
        }
        assert!(WordBuilderV1::new(usize::MAX).is_err());
    }
    fn test_digest_v1(value: u64) -> PrivacyOuterDigestV1 {
        PrivacyOuterDigestV1::from_bytes(
            value
                .to_be_bytes()
                .repeat(6)
                .try_into()
                .expect("48 fixture bytes"),
        )
    }
    fn word_memory_challenges() -> ZkX509WordMemoryChallengesV1 {
        ZkX509WordMemoryChallengesV1 {
            lanes: [
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(11),
                    address: F(13),
                    value: F(17),
                    is_write: F(19),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(23),
                    address: F(29),
                    value: F(31),
                    is_write: F(37),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(41),
                    address: F(43),
                    value: F(47),
                    is_write: F(53),
                },
                ZkX509WordMemoryLaneChallengesV1 {
                    beta: F(59),
                    address: F(61),
                    value: F(67),
                    is_write: F(71),
                },
            ],
        }
    }
    fn io_endpoint(role: ZkX509IoSegmentRoleV1, instance: u16) -> ZkX509IoEndpointV1 {
        ZkX509IoEndpointV1 { role, instance }
    }
    fn io_challenges() -> ZkX509IoChallengesV1 {
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"zk-x509-sha-io-test",
            &test_digest_v1(0x61),
            &test_digest_v1(0x62),
        )
        .expect("I/O transcript");
        let execution_root = test_digest_v1(0x63).to_bytes();
        let sorted_root = test_digest_v1(0x64).to_bytes();
        transcript
            .absorb(
                b"zk-x509-io-trace-commitments-v1",
                &[&execution_root, &sorted_root],
            )
            .expect("I/O trace commitments");
        derive_zk_x509_io_challenges_v1(&mut transcript).expect("I/O challenges")
    }
    fn io_witness(
        channel: u32,
        producer: ZkX509IoEndpointV1,
        consumer: ZkX509IoEndpointV1,
        value: &[u8],
        public: bool,
    ) -> ZkX509IoChannelWitnessV1 {
        ZkX509IoChannelWitnessV1 {
            declaration: ZkX509IoChannelDeclarationV1 {
                channel,
                producer,
                consumers: vec![consumer],
                byte_len: value.len() as u32,
                public_value: public.then(|| value.to_vec()),
            },
            producer_value: value.to_vec(),
            consumer_values: vec![value.to_vec()],
        }
    }
    #[test]
    fn word_chip_matches_sha256_and_exact_row_schedule() {
        for message in [
            Vec::new(),
            b"abc".to_vec(),
            vec![0x11; 55],
            vec![0x22; 56],
            vec![0x33; 64],
            vec![0x44; 65],
        ] {
            let circuit = build_sha256_word_circuit_v1(&message).expect("word SHA-256 circuit");
            assert_eq!(circuit.digest(), <[u8; 32]>::from(Sha256::digest(&message)));
            assert_eq!(
                circuit.air_rows(),
                sha256_word_air_rows_for_message_len_v1(message.len()).expect("rows")
            );
            assert_eq!(
                circuit.word_memory_rows(),
                sha256_word_memory_rows_for_message_len_v1(message.len())
                    .expect("word-memory rows")
            );
            assert_eq!(
                circuit.total_air_rows().expect("total rows"),
                sha256_word_total_rows_for_message_len_v1(message.len()).expect("total rows")
            );
            circuit.validate().expect("valid word circuit");
            circuit
                .validate_with_word_memory_v1(word_memory_challenges())
                .expect("valid word-copy argument");
            let segmented = circuit
                .build_segmented_trace_v1(word_memory_challenges())
                .expect("compiled segmented trace");
            circuit
                .validate_segmented_trace_v1(word_memory_challenges(), &segmented)
                .expect("valid compiled segment continuations");
        }
    }
    #[test]
    fn word_chip_and_copy_argument_fit_the_compiled_crl_sha_row_envelope() {
        let local_rows =
            sha256_word_air_rows_for_message_len_v1(ZK_X509_MAX_CRL_BYTES_V1).expect("CRL rows");
        let memory_rows = sha256_word_memory_rows_for_message_len_v1(ZK_X509_MAX_CRL_BYTES_V1)
            .expect("CRL memory rows");
        let total_rows = sha256_word_total_rows_for_message_len_v1(ZK_X509_MAX_CRL_BYTES_V1)
            .expect("CRL total rows");
        assert_eq!(local_rows, 112_328);
        assert_eq!(memory_rows, 138_856);
        assert_eq!(total_rows, 251_184);
        let capacity =
            SHA256_WORD_FIXED_BATCH_SEGMENT_ROWS_V1 * SHA256_WORD_FIXED_BATCH_SEGMENT_COUNT_V1;
        assert_eq!(capacity, 2_621_440);
        assert!(total_rows <= capacity);
        let (segment_rows, max_segments) = compiled_sha_segment_shape_v1();
        assert_eq!(segment_rows, 524_288);
        assert_eq!(max_segments, 5);
        assert_eq!(total_rows.div_ceil(segment_rows), 1);
        // For a nonzero multiset-difference polynomial, Schwartz-Zippel gives
        // at most N/p per independent lane. Here N < 2^20, Goldilocks p >
        // 2^63, and four transcript-independent lanes therefore contribute
        // less than 2^-172 collision probability, exceeding the 128-bit floor.
        assert!(memory_rows < 1 << 20);
        const { assert!(crate::privacy_engines::transparent_stark::GOLDILOCKS_MODULUS_V1 > 1 << 63) };
        assert_eq!(WORD_MEMORY_PERMUTATION_LANES_V1, 4);
        assert!(
            WORD_MEMORY_PERMUTATION_LANES_V1 * (63 - 20)
                > usize::from(ZK_X509_TARGET_SOUNDNESS_BITS_V1)
        );
    }
    #[test]
    fn word_topology_range_bitwise_addition_and_digest_mutations_fail_closed() {
        let circuit = build_sha256_word_circuit_v1(b"adversarial").expect("word circuit");
        let mut changed = circuit.clone();
        changed.output_words[0] = WordIdV1(0);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::Topology)
        );
        let mut changed = circuit.clone();
        changed.words[0] = U32RangeAirRowV1::from_u32(SHA256_INITIAL_STATE_V1[0] ^ 1);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::Topology)
        );
        let mut changed = circuit.clone();
        changed.words[37].bits[5] = F(2);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::WordRange)
        );
        let mut changed = circuit.clone();
        let sigma_output = match changed.operations[0] {
            WordOperationV1::Sigma { output, .. } => output,
            _ => panic!("first operation is sigma"),
        };
        changed.words[sigma_output.0].bits[0] = F::ONE.sub(changed.words[sigma_output.0].bits[0]);
        let mut packed = F::ZERO;
        for (bit, value) in changed.words[sigma_output.0]
            .bits
            .iter()
            .copied()
            .enumerate()
        {
            packed = packed.add(value.mul(F(1_u64 << bit)));
        }
        changed.words[sigma_output.0].value = packed;
        assert_eq!(changed.validate(), Err(ZkX509Sha256WordAirErrorV1::Bitwise));
        let mut changed = circuit.clone();
        let add = changed
            .operations
            .iter_mut()
            .find(
                |operation| matches!(operation, WordOperationV1::Add { carry, .. } if *carry != 0),
            )
            .expect("fixture has a nonzero carry");
        if let WordOperationV1::Add { carry_bits, .. } = add {
            carry_bits[0] = F::ONE.sub(carry_bits[0]);
        }
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::Addition)
        );
        let mut changed = circuit.clone();
        let read = changed
            .memory
            .execution
            .iter_mut()
            .find(|access| access.is_write == F::ZERO)
            .expect("fixture has reads");
        read.address = read.address.add(F::ONE);
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::WordMemory)
        );
        let mut changed = circuit.clone();
        let target_address = changed.memory.sorted[0].address;
        for access in changed
            .memory
            .sorted
            .iter_mut()
            .take_while(|access| access.address == target_address)
        {
            access.value = access.value.add(F::ONE);
        }
        changed
            .validate()
            .expect("a consistent forged sorted group needs the permutation");
        assert_eq!(
            changed.validate_with_word_memory_v1(word_memory_challenges()),
            Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation)
        );
        let mut changed = circuit.clone();
        changed.memory.sorted[1].is_write = F::ONE;
        assert_eq!(
            changed.validate(),
            Err(ZkX509Sha256WordAirErrorV1::WordMemory)
        );
        let challenges = word_memory_challenges();
        let mut argument = circuit
            .build_word_memory_argument_v1(challenges)
            .expect("permutation argument");
        argument.rows[2].execution_product_after[1] =
            argument.rows[2].execution_product_after[1].add(F::ONE);
        assert_eq!(
            circuit.validate_word_memory_argument_v1(challenges, &argument),
            Err(ZkX509Sha256WordAirErrorV1::WordMemoryPermutation)
        );
        let mut changed = circuit;
        changed.digest[0] ^= 1;
        assert_eq!(changed.validate(), Err(ZkX509Sha256WordAirErrorV1::Digest));
    }
    #[test]
    fn word_memory_challenges_are_commitment_bound_and_fail_closed() {
        let profile = test_digest_v1(0x11);
        let public = test_digest_v1(0x22);
        let main_root = test_digest_v1(0x33).to_bytes();
        let sorted_root = test_digest_v1(0x44).to_bytes();
        let mut transcript = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"zk-x509-test-suite",
            &profile,
            &public,
        )
        .expect("transcript");
        transcript
            .absorb(
                b"zk-x509-sha-word-trace-commitments-v1",
                &[&main_root, &sorted_root],
            )
            .expect("absorb trace roots");
        let sampled = derive_sha256_word_memory_challenges_v1(&mut transcript)
            .expect("word-memory challenges");
        sampled.validate().expect("valid sampled challenges");
        let mut changed_root = main_root;
        changed_root[0] ^= 1;
        let mut changed = TransparentTranscriptV1::new(
            super::super::stark::ZK_X509_DIGEST_CONTEXT_V1,
            b"zk-x509-test-suite",
            &profile,
            &public,
        )
        .expect("transcript");
        changed
            .absorb(
                b"zk-x509-sha-word-trace-commitments-v1",
                &[&changed_root, &sorted_root],
            )
            .expect("absorb changed roots");
        assert_ne!(
            sampled,
            derive_sha256_word_memory_challenges_v1(&mut changed)
                .expect("changed word-memory challenges")
        );
        let mut invalid = word_memory_challenges();
        invalid.lanes[0].beta = F::ZERO;
        assert_eq!(
            invalid.validate(),
            Err(ZkX509Sha256WordAirErrorV1::WordMemoryChallenge)
        );
        let mut duplicate = word_memory_challenges();
        duplicate.lanes[2] = duplicate.lanes[1];
        assert_eq!(
            duplicate.validate(),
            Err(ZkX509Sha256WordAirErrorV1::WordMemoryChallenge)
        );
    }
    #[test]
    fn every_physical_segment_boundary_field_and_product_lane_is_bound() {
        let circuit =
            build_sha256_word_circuit_v1(b"segment-boundary-adversary").expect("word circuit");
        let challenges = word_memory_challenges();
        let segment_rows = 257;
        let max_segments = 32;
        let trace = circuit
            .build_segmented_trace_with_shape_v1(challenges, segment_rows, max_segments)
            .expect("tiny segmented trace");
        assert!(trace.segments.len() > 4);
        circuit
            .validate_segmented_trace_with_shape_v1(challenges, &trace, segment_rows, max_segments)
            .expect("valid tiny segment continuations");
        let assert_rejected = |changed: &ZkX509Sha256WordSegmentedTraceV1| {
            assert_eq!(
                validate_sha256_segment_continuations_v1(
                    circuit.air_rows(),
                    circuit.word_memory_rows(),
                    &changed.copy_argument,
                    &changed.segments,
                    segment_rows,
                    max_segments,
                ),
                Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation)
            );
        };
        for segment in 0..trace.segments.len() {
            let mut changed = trace.clone();
            changed.segments[segment].segment_index =
                changed.segments[segment].segment_index.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].global_row_start =
                changed.segments[segment].global_row_start.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].global_row_end =
                changed.segments[segment].global_row_end.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].local_row_start =
                changed.segments[segment].local_row_start.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].local_row_end =
                changed.segments[segment].local_row_end.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].memory_row_start =
                changed.segments[segment].memory_row_start.wrapping_add(1);
            assert_rejected(&changed);
            let mut changed = trace.clone();
            changed.segments[segment].memory_row_end =
                changed.segments[segment].memory_row_end.wrapping_add(1);
            assert_rejected(&changed);
            for lane in 0..WORD_MEMORY_PERMUTATION_LANES_V1 {
                let mut changed = trace.clone();
                changed.segments[segment].execution_product_start[lane] =
                    changed.segments[segment].execution_product_start[lane].add(F::ONE);
                assert_rejected(&changed);
                let mut changed = trace.clone();
                changed.segments[segment].execution_product_end[lane] =
                    changed.segments[segment].execution_product_end[lane].add(F::ONE);
                assert_rejected(&changed);
                let mut changed = trace.clone();
                changed.segments[segment].sorted_product_start[lane] =
                    changed.segments[segment].sorted_product_start[lane].add(F::ONE);
                assert_rejected(&changed);
                let mut changed = trace.clone();
                changed.segments[segment].sorted_product_end[lane] =
                    changed.segments[segment].sorted_product_end[lane].add(F::ONE);
                assert_rejected(&changed);
            }
        }
        assert_eq!(
            circuit.build_segmented_trace_with_shape_v1(
                challenges,
                segment_rows,
                trace.segments.len() - 1,
            ),
            Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation)
        );
        assert_eq!(
            circuit.build_segmented_trace_with_shape_v1(challenges, 0, max_segments),
            Err(ZkX509Sha256WordAirErrorV1::SegmentContinuation)
        );
    }
    #[test]
    fn strict_der_sha_crl_commitment_and_public_digest_endpoints_are_bound() {
        let message = b"exact private CRL DER";
        let circuit = build_sha256_word_circuit_v1(message).expect("word circuit");
        let sha = io_endpoint(ZkX509IoSegmentRoleV1::Sha256, 7);
        let der = io_endpoint(ZkX509IoSegmentRoleV1::StrictDer, 1);
        let commitment = io_endpoint(ZkX509IoSegmentRoleV1::CrlCommitment, 0);
        let public = io_endpoint(ZkX509IoSegmentRoleV1::PublicInput, 0);
        let digest = circuit.digest();
        let witnesses = vec![
            io_witness(0, der, sha, message, false),
            io_witness(1, sha, commitment, &digest, false),
            io_witness(2, commitment, public, &digest, true),
        ];
        let challenges = io_challenges();
        let trace =
            build_zk_x509_io_trace_v1(&witnesses, challenges).expect("cross-segment I/O trace");
        circuit
            .validate_cross_segment_io_v1(challenges, &trace, 0, 1, 7)
            .expect("bound SHA endpoints");
        trace
            .validate_public_channel(2, &digest)
            .expect("bound public CRL commitment digest");
        let mut wrong_input = witnesses.clone();
        wrong_input[0].producer_value[0] ^= 1;
        wrong_input[0].consumer_values[0][0] ^= 1;
        let trace = build_zk_x509_io_trace_v1(&wrong_input, challenges)
            .expect("internally consistent forged input channel");
        assert_eq!(
            circuit.validate_cross_segment_io_v1(challenges, &trace, 0, 1, 7),
            Err(ZkX509Sha256WordAirErrorV1::IoBinding)
        );
        let mut wrong_digest = witnesses.clone();
        wrong_digest[1].producer_value[3] ^= 1;
        wrong_digest[1].consumer_values[0][3] ^= 1;
        let trace = build_zk_x509_io_trace_v1(&wrong_digest, challenges)
            .expect("internally consistent forged digest channel");
        assert_eq!(
            circuit.validate_cross_segment_io_v1(challenges, &trace, 0, 1, 7),
            Err(ZkX509Sha256WordAirErrorV1::IoBinding)
        );
        let mut wrong_public = witnesses;
        wrong_public[2]
            .declaration
            .public_value
            .as_mut()
            .expect("public")[9] ^= 1;
        wrong_public[2].producer_value[9] ^= 1;
        wrong_public[2].consumer_values[0][9] ^= 1;
        let trace = build_zk_x509_io_trace_v1(&wrong_public, challenges)
            .expect("internally consistent forged public channel");
        assert_eq!(
            trace.validate_public_channel(2, &digest),
            Err(ZkX509IoAirErrorV1::PublicInput)
        );
    }
}
