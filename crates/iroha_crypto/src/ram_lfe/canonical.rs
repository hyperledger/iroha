//! Canonical V1 function identity, policy and commitment owners.
//!
//! Every commitment is one fixed domain followed by one canonical Norito frame
//! of a named V1 record. Public records use the marked Iroha Blake2b [`Hash`].
//! The commitments whose preimage is private use BLAKE3 derive-key with a
//! clearing hash state and stay raw 32-byte values, so they cannot be confused
//! with a marked Iroha hash.
//!
//! The function identity depends on the hidden tape, the program key, the class,
//! the exact plaintext semantics and the lifetime query limit. It contains no
//! encryption, evaluation, opening or PRF key, so it survives rotation of every
//! one of them.

use super::{
    Hash, HiddenRamFheProgram, RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES, RamLfeError,
    class::{RamLfeClassV1, ram_lfe_v1_plaintext_semantics_hash},
    clearing::ClearingArray,
    policy_secret,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::fmt;
use zeroize::{Zeroize as _, Zeroizing};

const FUNCTION_IDENTITY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.function_identity";
const PROFILE_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.profile";
const RELATION_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.relation";
const ENCRYPTION_KEY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.key.encryption";
const EVALUATION_KEY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.key.evaluation";
const OPENING_KEY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.key.opening";
const PRF_KEY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.key.prf";
const POLICY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.policy";
const INPUT_CIPHERTEXT_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.ciphertext.input";
const OUTPUT_CIPHERTEXT_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.ciphertext.output";
const ASSOCIATED_DATA_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.associated_data";
const EXECUTION_CONTEXT_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.execution_context";

const FUNCTION_CONTEXT: &str = "iroha.ram_lfe.v1.function_commitment";
const INITIALIZER_KEY_CONTEXT: &str = "iroha.ram_lfe.v1.initializer_key";
const MEMORY_BLINDING_CONTEXT: &str = "iroha.ram_lfe.v1.memory_blinding";
const INITIALIZED_MEMORY_CONTEXT: &str = "iroha.ram_lfe.v1.initialized_memory";
const ORDERED_OUTPUT_CONTEXT: &str = "iroha.ram_lfe.v1.ordered_output";

/// Blake2b domains owned by this crate for the canonical V1 contract.
///
/// No domain is a prefix of another, so `domain || frame` is unambiguous.
pub const RAM_LFE_V1_PUBLIC_DOMAINS: [&[u8]; 13] = [
    super::class::PLAINTEXT_SEMANTICS_DOMAIN,
    FUNCTION_IDENTITY_DOMAIN,
    PROFILE_DOMAIN,
    RELATION_DOMAIN,
    ENCRYPTION_KEY_DOMAIN,
    EVALUATION_KEY_DOMAIN,
    OPENING_KEY_DOMAIN,
    PRF_KEY_DOMAIN,
    POLICY_DOMAIN,
    INPUT_CIPHERTEXT_DOMAIN,
    OUTPUT_CIPHERTEXT_DOMAIN,
    ASSOCIATED_DATA_DOMAIN,
    EXECUTION_CONTEXT_DOMAIN,
];

/// BLAKE3 derive-key contexts for the secret-bearing V1 preimages.
pub const RAM_LFE_V1_PRIVATE_CONTEXTS: [&str; 6] = [
    FUNCTION_CONTEXT,
    INITIALIZER_KEY_CONTEXT,
    super::initialization::CONTEXT_V1,
    MEMORY_BLINDING_CONTEXT,
    INITIALIZED_MEMORY_CONTEXT,
    ORDERED_OUTPUT_CONTEXT,
];

/// Upper bound, in bits, on what the opened output of one execution discloses.
///
/// An output is at most 64 scalars of the field of 257 elements, and
/// `2^512 < 257^64 < 2^513`.
pub const RAM_LFE_V1_OUTPUT_LEAKAGE_BITS: u32 = 513;

/// Domain-separated Iroha Blake2b digest of public bytes.
pub(super) fn public_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    Hash::new_from_chunks(&[domain, bytes])
}

fn encoding_error(error: &norito::core::Error) -> RamLfeError {
    RamLfeError::TranscriptEncoding(error.to_string())
}

/// Domain-separated digest of one canonical Norito frame of a public record.
fn public_commitment<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<Hash, RamLfeError> {
    let frame = norito::encode_canonical(value).map_err(|error| encoding_error(&error))?;
    Ok(public_digest(domain, &frame))
}

/// BLAKE3 derive-key commitment of one canonical Norito frame of a private record.
fn private_commitment<T: norito::NoritoSerialize>(
    context: &'static str,
    value: &T,
) -> Result<[u8; 32], RamLfeError> {
    policy_secret::commit_canonical(context, value).map_err(|error| encoding_error(&error))
}

/// Define one commitment frame and record its field order.
///
/// The declared field order is the protocol. Tests compare the recorded order
/// with the field rows of `specs/ram_lfe_execution_proof.md`.
macro_rules! commitment_frame {
    (
        $(#[$meta:meta])*
        struct $name:ident<$lifetime:lifetime> as $schema:tt {
            $($field:ident: $type:ty,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Encode, norito::NoritoSchema)]
        #[norito_schema(name = $schema, frame = $schema)]
        pub(super) struct $name<$lifetime> {
            $(pub(super) $field: $type,)+
        }

        #[cfg(test)]
        impl $name<'_> {
            /// Full schema and frame name.
            pub(super) const FRAME: &'static str = $schema;
            /// Field names in canonical frame order.
            pub(super) const FIELDS: &'static [&'static str] = &[$(stringify!($field)),+];
        }
    };
    (
        $(#[$meta:meta])*
        struct $name:ident as $schema:tt {
            $($field:ident: $type:ty,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Encode, norito::NoritoSchema)]
        #[norito_schema(name = $schema, frame = $schema)]
        pub(super) struct $name {
            $(pub(super) $field: $type,)+
        }

        #[cfg(test)]
        impl $name {
            /// Full schema and frame name.
            pub(super) const FRAME: &'static str = $schema;
            /// Field names in canonical frame order.
            pub(super) const FIELDS: &'static [&'static str] = &[$(stringify!($field)),+];
        }
    };
}
pub(super) use commitment_frame;

commitment_frame! {
    // Large public byte strings are committed by length and digest, so no second
    // frame-sized copy is made. The outer domain separates every role.
    struct OpaqueBytesInputV1 as "iroha_crypto::ram_lfe::RamLfeOpaqueBytesInputV1" {
        length: u64,
        digest: Hash,
    }
}

fn opaque_commitment(domain: &[u8], bytes: &[u8]) -> Result<Hash, RamLfeError> {
    public_commitment(
        domain,
        &OpaqueBytesInputV1 {
            length: u64::try_from(bytes.len()).map_err(|_| {
                RamLfeError::InvalidCanonicalValue("committed byte length does not fit into u64")
            })?,
            digest: Hash::new(bytes),
        },
    )
}

fn nonempty_opaque_commitment(
    domain: &[u8],
    bytes: &[u8],
    empty: &'static str,
) -> Result<Hash, RamLfeError> {
    if bytes.is_empty() {
        return Err(RamLfeError::InvalidCanonicalValue(empty));
    }
    opaque_commitment(domain, bytes)
}

macro_rules! public_commitment_type {
    ($(#[$meta:meta])* $name:ident, $schema:tt) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Encode,
            Decode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(name = $schema)]
        pub struct $name(Hash);

        impl $name {
            /// Borrow the marked Iroha Blake2b digest.
            #[must_use]
            pub const fn as_hash(&self) -> &Hash {
                &self.0
            }
        }
    };
}

macro_rules! opaque_commitment_type {
    (
        $(#[$meta:meta])* $name:ident, $schema:tt, $domain:expr, $empty:literal,
        $(#[$commit_meta:meta])* $commit:ident
    ) => {
        public_commitment_type!($(#[$meta])* $name, $schema);

        impl $name {
            $(#[$commit_meta])*
            ///
            /// # Errors
            /// Rejects empty input and reports a canonical encoding failure.
            pub fn $commit(bytes: &[u8]) -> Result<Self, RamLfeError> {
                nonempty_opaque_commitment($domain, bytes, $empty).map(Self)
            }
        }
    };
}

macro_rules! private_commitment_type {
    ($(#[$meta:meta])* $name:ident, $schema:tt) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Encode,
            Decode,
            IntoSchema,
            norito::NoritoSchema,
        )]
        #[norito_schema(name = $schema)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Borrow the raw BLAKE3 commitment. It carries no Iroha hash marker.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

macro_rules! clearing_secret_type {
    ($(#[$meta:meta])* $name:ident, $redacted:literal, $zero:literal) => {
        $(#[$meta])*
        pub struct $name(ClearingArray<u8, 32>);

        impl $name {
            /// Exact secret length in bytes.
            pub const LENGTH: usize = 32;

            /// Generate a fresh secret from the operating-system random source.
            ///
            /// The source writes directly into the secret's heap allocation.
            ///
            /// # Errors
            /// Returns [`RamLfeError::RandomnessUnavailable`] when the source fails.
            #[cfg(feature = "rand")]
            pub fn generate() -> Result<Self, RamLfeError> {
                use rand_core::TryRngCore as _;
                let mut bytes = ClearingArray::zeroed();
                rand_core::OsRng
                    .try_fill_bytes(bytes.as_mut_slice())
                    .map_err(|_| RamLfeError::RandomnessUnavailable)?;
                Self::checked(bytes)
            }

            /// Import an existing 32-byte secret.
            ///
            /// The bytes are copied into the secret's heap allocation and the
            /// argument is cleared. A copy the caller keeps is not covered.
            /// The import cannot establish the caller's entropy. Passwords,
            /// labels and truncated or reduced values are not valid secrets.
            ///
            /// # Errors
            /// Rejects the all-zero value, which no random source produces.
            pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, RamLfeError> {
                let owner = ClearingArray::copy_of(&bytes);
                bytes.zeroize();
                Self::checked(owner)
            }

            fn checked(bytes: ClearingArray<u8, 32>) -> Result<Self, RamLfeError> {
                if bytes.is_zero() {
                    return Err(RamLfeError::InvalidCanonicalValue($zero));
                }
                Ok(Self(bytes))
            }

            pub(super) fn expose(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($redacted)
            }
        }
    };
}

clearing_secret_type!(
    /// High-entropy program key held by the program owner and the evaluator.
    ///
    /// It blinds the tape commitment, seeds the per-execution state lanes and
    /// blinds each initialized-memory commitment. It is not an encryption,
    /// opening or PRF key and has no wire encoding.
    ///
    /// The 32 bytes live in one heap allocation for the whole life of the key:
    /// moving the key moves a pointer, and the allocation is cleared on drop,
    /// on an error return and during unwinding. Copies made by the caller are
    /// not covered.
    RamLfeProgramKeyV1,
    "[REDACTED RAM-LFE program key]",
    "program key must not be all zero"
);

clearing_secret_type!(
    /// Fresh blinding held by the authorized opener for one output commitment.
    ///
    /// The opener discloses it, with the ordered output, only to the party
    /// entitled to the opened result. It lives in one heap allocation that is
    /// cleared on drop, on an error return and during unwinding.
    RamLfeOutputBlindingV1,
    "[REDACTED RAM-LFE output blinding]",
    "output blinding must not be all zero"
);

private_commitment_type!(
    /// Blinded commitment to the hidden tape under one class and program key.
    RamLfeFunctionCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeFunctionCommitmentV1"
);
private_commitment_type!(
    /// Commitment to the program key that seeds the per-execution state lanes,
    /// bound to the class and the function commitment it belongs to.
    RamLfeInitializerCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeInitializerCommitmentV1"
);
private_commitment_type!(
    /// Blinded commitment to the state lanes initialized for one execution.
    RamLfeInitializedMemoryCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeInitializedMemoryCommitmentV1"
);
private_commitment_type!(
    /// Hiding commitment to one ordered opened output.
    RamLfeOutputCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeOutputCommitmentV1"
);

public_commitment_type!(
    /// Stable logical function identity: the digest of
    /// [`RamLfeFunctionIdentityV1`]. It does not depend on any key a policy rotates.
    RamLfeFunctionIdV1,
    "iroha_crypto::ram_lfe::RamLfeFunctionIdV1"
);
public_commitment_type!(
    /// Commitment to one complete [`RamLfePolicyV1`].
    RamLfePolicyCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfePolicyCommitmentV1"
);
public_commitment_type!(
    /// Digest of the public associated data bound into one execution.
    RamLfeAssociatedDataHashV1,
    "iroha_crypto::ram_lfe::RamLfeAssociatedDataHashV1"
);

// TODO(C.3): no encryption profile defines the bytes behind the profile, key and
// ciphertext commitments below. They commit opaque caller-supplied bytes until C.3
// selects the profile and fixes each canonical encoding.
opaque_commitment_type!(
    /// Identity of one complete encryption profile.
    RamLfeProfileIdV1,
    "iroha_crypto::ram_lfe::RamLfeProfileIdV1",
    PROFILE_DOMAIN,
    "profile descriptor must not be empty",
    /// Commit the canonical bytes of a complete encryption-profile descriptor.
    from_descriptor
);
opaque_commitment_type!(
    /// Identity of the semantic relation a policy's proofs must satisfy.
    RamLfeRelationIdV1,
    "iroha_crypto::ram_lfe::RamLfeRelationIdV1",
    RELATION_DOMAIN,
    "relation descriptor must not be empty",
    /// Commit the canonical bytes of a complete relation descriptor.
    from_descriptor
);
opaque_commitment_type!(
    /// Commitment to the public encryption key clients encrypt inputs under.
    RamLfeEncryptionKeyCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeEncryptionKeyCommitmentV1",
    ENCRYPTION_KEY_DOMAIN,
    "encryption key material must not be empty",
    /// Commit the canonical bytes of the public encryption key.
    commit
);
opaque_commitment_type!(
    /// Commitment to the public evaluation keys the evaluator computes with.
    RamLfeEvaluationKeyCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeEvaluationKeyCommitmentV1",
    EVALUATION_KEY_DOMAIN,
    "evaluation key material must not be empty",
    /// Commit the canonical bytes of the complete public evaluation-key set.
    commit
);
opaque_commitment_type!(
    /// Commitment to the public material an opening proof verifies against.
    RamLfeOpeningKeyCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeOpeningKeyCommitmentV1",
    OPENING_KEY_DOMAIN,
    "opening key material must not be empty",
    /// Commit the canonical bytes of the public opening-verification material.
    commit
);
opaque_commitment_type!(
    /// Commitment to the public material an identifier-PRF proof verifies against.
    ///
    /// The PRF secret stays with the authorized opener. It never enters this
    /// commitment and is never given to the evaluator.
    RamLfePrfKeyCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfePrfKeyCommitmentV1",
    PRF_KEY_DOMAIN,
    "PRF key material must not be empty",
    /// Commit the canonical bytes of the public PRF-verification material.
    commit
);
opaque_commitment_type!(
    /// Commitment to the exact canonical input ciphertext frame.
    RamLfeInputCiphertextCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeInputCiphertextCommitmentV1",
    INPUT_CIPHERTEXT_DOMAIN,
    "input ciphertext must not be empty",
    /// Commit the exact canonical bytes of the submitted input ciphertext.
    commit
);
opaque_commitment_type!(
    /// Commitment to the exact canonical output ciphertext frame.
    RamLfeOutputCiphertextCommitmentV1,
    "iroha_crypto::ram_lfe::RamLfeOutputCiphertextCommitmentV1",
    OUTPUT_CIPHERTEXT_DOMAIN,
    "output ciphertext must not be empty",
    /// Commit the exact canonical bytes of the evaluated output ciphertext.
    commit
);
opaque_commitment_type!(
    /// Identity of one execution: the digest of the fields that make it unique.
    ///
    /// The data model commits the network, the program and the replay scope and
    /// nonce (`RamLfeExecutionContextV1`). The receipt commitment is not an
    /// input: the receipt contains the initialized-memory commitment this
    /// identity blinds.
    RamLfeExecutionContextIdV1,
    "iroha_crypto::ram_lfe::RamLfeExecutionContextIdV1",
    EXECUTION_CONTEXT_DOMAIN,
    "execution context must not be empty",
    /// Commit the canonical bytes of one execution-context record.
    commit
);

impl RamLfeAssociatedDataHashV1 {
    /// Commit the public associated data of one execution.
    ///
    /// # Errors
    /// Rejects more than [`RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES`] bytes.
    pub fn commit(associated_data: &[u8]) -> Result<Self, RamLfeError> {
        if associated_data.len() > RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES {
            return Err(RamLfeError::InvalidCanonicalValue(
                "associated data exceeds 512 bytes",
            ));
        }
        opaque_commitment(ASSOCIATED_DATA_DOMAIN, associated_data).map(Self)
    }
}

// Borrowed private fields stream into the clearing hash state; no owned
// preimage is created.
commitment_frame! {
    struct FunctionCommitmentInputV1<'a> as "iroha_crypto::ram_lfe::RamLfeFunctionCommitmentInputV1" {
        plaintext_semantics: Hash,
        class: RamLfeClassV1,
        program_key: &'a [u8],
        instruction_count: u16,
        tape: &'a [u8],
    }
}

commitment_frame! {
    // The class and the function commitment make this commitment differ for
    // every function identity, so reusing one program key for two functions
    // is not visible in it.
    struct InitializerKeyInputV1<'a> as "iroha_crypto::ram_lfe::RamLfeInitializerKeyInputV1" {
        plaintext_semantics: Hash,
        class: RamLfeClassV1,
        function_commitment: &'a [u8],
        program_key: &'a [u8],
    }
}

commitment_frame! {
    struct MemoryBlindingInputV1<'a> as "iroha_crypto::ram_lfe::RamLfeMemoryBlindingInputV1" {
        function_identity: Hash,
        associated_data_hash: Hash,
        execution_context: Hash,
        program_key: &'a [u8],
    }
}

commitment_frame! {
    struct InitializedMemoryInputV1<'a> as "iroha_crypto::ram_lfe::RamLfeInitializedMemoryInputV1" {
        function_identity: Hash,
        associated_data_hash: Hash,
        blinding: &'a [u8],
        lanes: &'a [u8],
    }
}

commitment_frame! {
    struct OrderedOutputInputV1<'a> as "iroha_crypto::ram_lfe::RamLfeOrderedOutputInputV1" {
        blinding: &'a [u8],
        output_count: u16,
        scalars: &'a [u8],
    }
}

/// Serialize scalars as consecutive little-endian `u16` values in a clearing owner.
fn scalar_bytes(scalars: &[u16]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(scalars.len() * 2));
    for scalar in scalars {
        bytes.extend_from_slice(&scalar.to_le_bytes());
    }
    bytes
}

impl RamLfeInitializedMemoryCommitmentV1 {
    /// Commit the state lanes initialized for one execution.
    ///
    /// The commitment is blinded. The blinding is a keyed pseudorandom function
    /// of the program key, the function identity, the associated data and the
    /// execution context, and it never leaves a clearing owner. A party without
    /// the program key cannot test a guess of the lanes against the commitment,
    /// even when an opened output discloses candidate lanes. Two executions
    /// with the same associated data have the same lanes and two different
    /// commitments.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn commit(
        key: &RamLfeProgramKeyV1,
        function: RamLfeFunctionIdV1,
        associated_data: RamLfeAssociatedDataHashV1,
        execution: RamLfeExecutionContextIdV1,
        memory: &super::reference::RamLfeInitialMemoryV1,
    ) -> Result<Self, RamLfeError> {
        let mut blinding = ClearingArray::<u8, 32>::zeroed();
        policy_secret::commit_canonical_into(
            MEMORY_BLINDING_CONTEXT,
            &MemoryBlindingInputV1 {
                function_identity: function.0,
                associated_data_hash: associated_data.0,
                execution_context: execution.0,
                program_key: key.expose(),
            },
            &mut blinding,
        )
        .map_err(|error| encoding_error(&error))?;
        let lanes = scalar_bytes(memory.lanes());
        private_commitment(
            INITIALIZED_MEMORY_CONTEXT,
            &InitializedMemoryInputV1 {
                function_identity: function.0,
                associated_data_hash: associated_data.0,
                blinding: blinding.as_slice(),
                lanes: &lanes,
            },
        )
        .map(Self)
    }
}

impl RamLfeOutputCommitmentV1 {
    /// Commit one ordered opened output under a fresh opener blinding.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn commit(
        output: &super::reference::RamLfeOrderedOutputV1,
        blinding: &RamLfeOutputBlindingV1,
    ) -> Result<Self, RamLfeError> {
        let scalars = scalar_bytes(output.scalars());
        private_commitment(
            ORDERED_OUTPUT_CONTEXT,
            &OrderedOutputInputV1 {
                blinding: blinding.expose(),
                output_count: u16::try_from(output.scalars().len())
                    .expect("validated output count"),
                scalars: &scalars,
            },
        )
        .map(Self)
    }
}

/// Lifetime query limit committed by a function identity.
///
/// The limit bounds how much of the hidden function accepted executions can
/// disclose, and how many identifiers one account can derive. It is counted
/// per function identity on one network, across every program registration,
/// policy, encryption-key rotation, associated-data value and replay scope that
/// names the identity:
///
/// - `total` is charged once when a receipt is accepted;
/// - `per_beneficiary` is charged once when an opening of a receipt of that
///   beneficiary is accepted, and a receipt is opened at most once.
///
/// Counts are lifetime counts. Nothing resets them, and a charge is applied in
/// the same atomic State transition that accepts the receipt or the opening.
/// A consumer may refuse a query the limit admits; it never admits one the
/// limit refuses.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeQueryLimitV1")]
pub struct RamLfeQueryLimitV1 {
    /// Receipts accepted over the lifetime of the function identity on one network.
    pub total: u64,
    /// Openings accepted for one beneficiary over that lifetime.
    pub per_beneficiary: u32,
}

impl RamLfeQueryLimitV1 {
    /// Build a query limit.
    ///
    /// # Errors
    /// Rejects a zero limit and a per-beneficiary limit above the total.
    pub fn new(total: u64, per_beneficiary: u32) -> Result<Self, RamLfeError> {
        let limit = Self {
            total,
            per_beneficiary,
        };
        limit.validate()?;
        Ok(limit)
    }

    /// Reject a limit no function identity may commit to.
    ///
    /// A zero limit admits no query, so it would commit a function nothing can
    /// use. A per-beneficiary limit above the total could never be reached.
    ///
    /// # Errors
    /// Returns [`RamLfeError::InvalidCanonicalValue`] for either zero limit and
    /// for a per-beneficiary limit above the total.
    pub fn validate(&self) -> Result<(), RamLfeError> {
        if self.total == 0 {
            return Err(RamLfeError::InvalidCanonicalValue(
                "query limit total must not be zero",
            ));
        }
        if self.per_beneficiary == 0 {
            return Err(RamLfeError::InvalidCanonicalValue(
                "query limit per beneficiary must not be zero",
            ));
        }
        if u64::from(self.per_beneficiary) > self.total {
            return Err(RamLfeError::InvalidCanonicalValue(
                "query limit per beneficiary exceeds the total",
            ));
        }
        Ok(())
    }

    // TODO(R.12): no State transition calls `charge_receipt` yet. The receipt consumer
    // of R.12 applies the charge in the transition that accepts the receipt.
    /// Charge one accepted receipt against the total.
    ///
    /// `accepted_receipts` is the persisted count before this receipt. The
    /// result is the count to persist with it.
    ///
    /// # Errors
    /// Returns [`RamLfeError::ReceiptLimitExhausted`] when the identity has
    /// already accepted `total` receipts.
    pub const fn charge_receipt(&self, accepted_receipts: u64) -> Result<u64, RamLfeError> {
        if accepted_receipts >= self.total {
            return Err(RamLfeError::ReceiptLimitExhausted { limit: self.total });
        }
        Ok(accepted_receipts + 1)
    }

    // TODO(R.8): no State transition calls `charge_opening` yet. The opening consumer
    // of R.8 applies the charge in the transition that accepts the opening.
    /// Charge one accepted opening against one beneficiary's limit.
    ///
    /// `beneficiary_openings` is the persisted count of that beneficiary before
    /// this opening. The result is the count to persist with it.
    ///
    /// # Errors
    /// Returns [`RamLfeError::BeneficiaryOpeningLimitExhausted`] when the
    /// beneficiary has already had `per_beneficiary` openings.
    pub const fn charge_opening(&self, beneficiary_openings: u32) -> Result<u32, RamLfeError> {
        if beneficiary_openings >= self.per_beneficiary {
            return Err(RamLfeError::BeneficiaryOpeningLimitExhausted {
                limit: self.per_beneficiary,
            });
        }
        Ok(beneficiary_openings + 1)
    }

    /// Upper bound, in bits, on what every accepted execution of the function
    /// identity discloses through opened outputs: `513 * total`.
    ///
    /// The bound covers accepted receipts on one network. A ciphertext that
    /// never became an accepted receipt, and another function identity that
    /// shares the tape, are outside it.
    #[must_use]
    pub fn output_leakage_bound_bits(&self) -> u128 {
        u128::from(self.total) * u128::from(RAM_LFE_V1_OUTPUT_LEAKAGE_BITS)
    }
}

/// Stable logical identity of one hidden function.
///
/// The record is public. Its two commitments hide the tape and the program key.
/// It names no encryption, evaluation, opening or PRF key.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfeFunctionIdentityV1")]
pub struct RamLfeFunctionIdentityV1 {
    /// Declared program class.
    pub class: RamLfeClassV1,
    /// Digest of the exact plaintext-semantics descriptor.
    pub plaintext_semantics: Hash,
    /// Blinded commitment to the complete hidden tape.
    pub function: RamLfeFunctionCommitmentV1,
    /// Commitment to the program key that seeds the state lanes.
    pub initializer: RamLfeInitializerCommitmentV1,
    /// Lifetime query limit of this identity. Another limit is another
    /// identity, with other state lanes.
    pub query_limit: RamLfeQueryLimitV1,
}

impl RamLfeFunctionIdentityV1 {
    /// Commit a hidden program under one class, program key and query limit.
    ///
    /// # Errors
    /// Rejects an invalid query limit and a program outside the declared class,
    /// and reports a canonical encoding failure.
    pub fn commit(
        class: RamLfeClassV1,
        key: &RamLfeProgramKeyV1,
        program: &HiddenRamFheProgram,
        query_limit: RamLfeQueryLimitV1,
    ) -> Result<Self, RamLfeError> {
        query_limit.validate()?;
        let report = class.membership(program)?;
        let plaintext_semantics = ram_lfe_v1_plaintext_semantics_hash();
        let function = RamLfeFunctionCommitmentV1(private_commitment(
            FUNCTION_CONTEXT,
            &FunctionCommitmentInputV1 {
                plaintext_semantics,
                class,
                program_key: key.expose(),
                instruction_count: report.instruction_count(),
                tape: program.tape_bytes(),
            },
        )?);
        let initializer = RamLfeInitializerCommitmentV1(private_commitment(
            INITIALIZER_KEY_CONTEXT,
            &InitializerKeyInputV1 {
                plaintext_semantics,
                class,
                function_commitment: function.as_bytes(),
                program_key: key.expose(),
            },
        )?);
        Ok(Self {
            class,
            plaintext_semantics,
            function,
            initializer,
            query_limit,
        })
    }

    /// Reject an identity this build does not implement.
    ///
    /// # Errors
    /// Returns [`RamLfeError::InvalidCanonicalValue`] for any other
    /// plaintext-semantics digest and for an invalid query limit.
    pub fn validate(&self) -> Result<(), RamLfeError> {
        if self.plaintext_semantics != ram_lfe_v1_plaintext_semantics_hash() {
            return Err(RamLfeError::InvalidCanonicalValue(
                "function identity names unknown plaintext semantics",
            ));
        }
        self.query_limit.validate()
    }

    /// Return the stable logical function identity.
    ///
    /// # Errors
    /// Rejects unknown plaintext semantics and an invalid query limit, and
    /// reports a canonical encoding failure.
    pub fn id(&self) -> Result<RamLfeFunctionIdV1, RamLfeError> {
        self.validate()?;
        public_commitment(FUNCTION_IDENTITY_DOMAIN, self).map(RamLfeFunctionIdV1)
    }

    /// Check that a program key and hidden program open this identity.
    ///
    /// # Errors
    /// Returns [`RamLfeError::CommitmentMismatch`] for any other key, tape or
    /// class, and the class error when the program is outside the declared class.
    pub fn verify_opening(
        &self,
        key: &RamLfeProgramKeyV1,
        program: &HiddenRamFheProgram,
    ) -> Result<(), RamLfeError> {
        self.validate()?;
        if Self::commit(self.class, key, program, self.query_limit)? != *self {
            return Err(RamLfeError::CommitmentMismatch);
        }
        Ok(())
    }
}

/// The one canonical V1 RAM-LFE policy.
///
/// It binds the function identity (full function, initializer, class, plaintext
/// semantics and query limit), the encryption profile, the encryption,
/// evaluation, opening and PRF key commitments, and the semantic relation
/// identity. Validators take every field from committed State. A prover
/// supplies none.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::RamLfePolicyV1")]
pub struct RamLfePolicyV1 {
    /// Stable logical function identity record.
    pub function: RamLfeFunctionIdentityV1,
    /// Complete encryption profile.
    pub profile: RamLfeProfileIdV1,
    /// Public encryption key clients encrypt under.
    pub encryption_key: RamLfeEncryptionKeyCommitmentV1,
    /// Public evaluation keys the evaluator computes with.
    pub evaluation_key: RamLfeEvaluationKeyCommitmentV1,
    /// Public material opening proofs verify against.
    pub opening_key: RamLfeOpeningKeyCommitmentV1,
    /// Public material identifier-PRF proofs verify against.
    pub prf_key: RamLfePrfKeyCommitmentV1,
    /// Semantic relation every proof under this policy must satisfy.
    pub relation: RamLfeRelationIdV1,
}

impl RamLfePolicyV1 {
    /// Reject a policy whose function identity this build does not implement.
    ///
    /// # Errors
    /// Returns [`RamLfeError::InvalidCanonicalValue`] for unknown plaintext
    /// semantics and for an invalid query limit.
    pub fn validate(&self) -> Result<(), RamLfeError> {
        self.function.validate()
    }

    /// Commit the complete policy.
    ///
    /// # Errors
    /// Rejects an invalid function identity and reports a canonical encoding failure.
    pub fn commitment(&self) -> Result<RamLfePolicyCommitmentV1, RamLfeError> {
        self.validate()?;
        public_commitment(POLICY_DOMAIN, self).map(RamLfePolicyCommitmentV1)
    }

    /// Replace the encryption key pair, keeping the logical function.
    ///
    /// A new encryption key pair has new evaluation keys and new opening
    /// verification material. The function identity with its query limit, the
    /// profile, the PRF key and the relation are unchanged, so derived
    /// identifiers stay stable and the query counts continue.
    #[must_use]
    pub const fn rotate_encryption_keys(
        &self,
        encryption_key: RamLfeEncryptionKeyCommitmentV1,
        evaluation_key: RamLfeEvaluationKeyCommitmentV1,
        opening_key: RamLfeOpeningKeyCommitmentV1,
    ) -> Self {
        Self {
            function: self.function,
            profile: self.profile,
            encryption_key,
            evaluation_key,
            opening_key,
            prf_key: self.prf_key,
            relation: self.relation,
        }
    }
}

/// Field order of every borrowed commitment frame of this module.
#[cfg(test)]
pub(super) const COMMITMENT_FRAMES: [(&str, &[&str]); 6] = [
    (OpaqueBytesInputV1::FRAME, OpaqueBytesInputV1::FIELDS),
    (
        FunctionCommitmentInputV1::FRAME,
        FunctionCommitmentInputV1::FIELDS,
    ),
    (InitializerKeyInputV1::FRAME, InitializerKeyInputV1::FIELDS),
    (MemoryBlindingInputV1::FRAME, MemoryBlindingInputV1::FIELDS),
    (
        InitializedMemoryInputV1::FRAME,
        InitializedMemoryInputV1::FIELDS,
    ),
    (OrderedOutputInputV1::FRAME, OrderedOutputInputV1::FIELDS),
];

#[cfg(test)]
#[path = "canonical_tests.rs"]
mod tests;
