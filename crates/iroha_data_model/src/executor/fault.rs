//! Bounded deterministic IVM execution faults and their authenticated origin.
//!
//! Local execution refusals, host custody failures and application rejections are
//! separate outcomes. Source text and machine-local diagnostic state are not wire fields.

/// Stable failure codes returned by fallible numeric syscalls in `r11`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[repr(u64)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::NumericFaultV1")]
pub enum NumericFaultV1 {
    /// The canonical result exceeds the signed 512-bit integer domain.
    #[codec(index = 1)]
    MantissaOverflow = 1,
    /// The canonical exact decimal result requires a scale greater than 28.
    #[codec(index = 2)]
    ScaleOverflow = 2,
    /// Division by zero was requested.
    #[codec(index = 3)]
    DivisionByZero = 3,
    /// An exact quotient has a non-terminating decimal expansion.
    #[codec(index = 4)]
    RepeatingDecimal = 4,
    /// An exact terminating quotient needs more than 28 decimal places.
    #[codec(index = 5)]
    ExactDivisionScaleOverflow = 5,
    /// A requested output scale is outside `0..=28`.
    #[codec(index = 6)]
    InvalidScale = 6,
    /// An exact conversion would discard a fractional component or exceed its target.
    #[codec(index = 7)]
    InexactConversion = 7,
    /// A negative value was converted to the nominal quantity domain.
    #[codec(index = 8)]
    NegativeQuantity = 8,
    /// Quantity subtraction would produce a negative value.
    #[codec(index = 9)]
    QuantityUnderflow = 9,
    /// A rounded operation received an unknown rounding-mode tag.
    #[codec(index = 10)]
    InvalidRoundingMode = 10,
    /// A fallible operation received an unknown failure-mode tag.
    #[codec(index = 11)]
    InvalidFailureMode = 11,
    /// A register required to be zero by the syscall contract was nonzero.
    #[codec(index = 12)]
    ReservedRegisterNonZero = 12,
    /// Integer square root received a negative operand.
    #[codec(index = 13)]
    NegativeSquareRoot = 13,
}
impl NumericFaultV1 {
    /// Decode a stable ABI tag.
    #[must_use]
    pub const fn from_tag(tag: u64) -> Option<Self> {
        Some(match tag {
            1 => Self::MantissaOverflow,
            2 => Self::ScaleOverflow,
            3 => Self::DivisionByZero,
            4 => Self::RepeatingDecimal,
            5 => Self::ExactDivisionScaleOverflow,
            6 => Self::InvalidScale,
            7 => Self::InexactConversion,
            8 => Self::NegativeQuantity,
            9 => Self::QuantityUnderflow,
            10 => Self::InvalidRoundingMode,
            11 => Self::InvalidFailureMode,
            12 => Self::ReservedRegisterNonZero,
            13 => Self::NegativeSquareRoot,
            _ => return None,
        })
    }
    /// Return the stable ABI tag.
    #[must_use]
    pub const fn tag(self) -> u64 {
        self as u64
    }
}
/// Stable pointer/envelope validation fault codes.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[repr(u64)]
#[norito(tag = "kind", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::PointerAbiFaultV1")]
pub enum PointerAbiFaultV1 {
    /// The guest address does not identify public readable memory.
    #[codec(index = 1)]
    InvalidAddress = 1,
    /// The pointer type identifier is unknown.
    #[codec(index = 2)]
    UnknownType = 2,
    /// The pointer type is known but disallowed by ABI V1.
    #[codec(index = 3)]
    TypeNotAllowed = 3,
    /// The pointer has a known but unexpected type.
    #[codec(index = 4)]
    WrongType = 4,
    /// The outer envelope version is unsupported.
    #[codec(index = 5)]
    InvalidEnvelopeVersion = 5,
    /// A declared length exceeds the hard bound for its type.
    #[codec(index = 6)]
    OversizedLength = 6,
    /// The declared envelope is truncated or its length arithmetic overflows.
    #[codec(index = 7)]
    TruncatedEnvelope = 7,
    /// The payload digest does not authenticate the snapshotted payload.
    #[codec(index = 8)]
    PayloadHashMismatch = 8,
    /// The schema-bound Norito frame is malformed or uses invalid flags.
    #[codec(index = 9)]
    MalformedFrame = 9,
    /// The schema hash does not match the pointer type's V1 schema.
    #[codec(index = 10)]
    SchemaMismatch = 10,
    /// The value has a non-minimal or otherwise noncanonical representation.
    #[codec(index = 11)]
    NonCanonical = 11,
}
impl PointerAbiFaultV1 {
    /// Decode a stable ABI tag.
    #[must_use]
    pub const fn from_tag(tag: u64) -> Option<Self> {
        Some(match tag {
            1 => Self::InvalidAddress,
            2 => Self::UnknownType,
            3 => Self::TypeNotAllowed,
            4 => Self::WrongType,
            5 => Self::InvalidEnvelopeVersion,
            6 => Self::OversizedLength,
            7 => Self::TruncatedEnvelope,
            8 => Self::PayloadHashMismatch,
            9 => Self::MalformedFrame,
            10 => Self::SchemaMismatch,
            11 => Self::NonCanonical,
            _ => return None,
        })
    }
    /// Return the stable ABI tag.
    #[must_use]
    pub const fn tag(self) -> u64 {
        self as u64
    }
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
/// Bounded deterministic failure of a started IVM invocation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::IvmFaultV1")]
pub struct IvmFaultV1 {
    /// Exact deterministic failure category.
    pub kind: IvmFaultKindV1,
    /// Origin retained before nested execution is unwound.
    pub site: IvmFaultSiteV1,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
/// Authenticated location of the originating execution fault.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::IvmFaultSiteV1")]
pub struct IvmFaultSiteV1 {
    /// Canonical complete artifact hash, or raw code hash for a generic program.
    pub code_hash: iroha_crypto::Hash,
    /// Exact invocation selector under this artifact identity.
    pub selector: IvmInvocationSelectorV1,
    /// Stage and executable-relative position; never a fabricated source location.
    pub position: IvmFaultPositionV1,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
/// Selector identity under one exact artifact hash.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::IvmInvocationSelectorV1")]
pub enum IvmInvocationSelectorV1 {
    /// Generic bytecode has no public contract entrypoint.
    #[codec(index = 0)]
    Generic,
    /// Zero-based ordinal in the authenticated CNTR entrypoint table.
    #[codec(index = 1)]
    Entrypoint(u32),
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
/// Execution stage without invented instruction positions.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::IvmFaultPositionV1")]
pub enum IvmFaultPositionV1 {
    /// Root argument/call-table preparation failed before instruction execution.
    #[codec(index = 0)]
    Initialization,
    /// PC measured from the executable stream; its end is valid for `MissingHalt`.
    #[codec(index = 1)]
    Execute {
        /// Byte offset in this artifact's executable instruction stream.
        pc_offset: u64,
    },
    /// The host rejected the completed return at its canonical boundary.
    #[codec(index = 2)]
    ReturnValidation,
}
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "value")]
/// Closed consensus fault tags, independent of presentation text.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::executor::fault::IvmFaultKindV1")]
pub enum IvmFaultKindV1 {
    /// The deterministic instruction or syscall gas allowance was exhausted.
    #[codec(index = 0)]
    OutOfGas,
    /// The guest exceeded its deterministic VM memory bounds.
    #[codec(index = 1)]
    MemoryLimitExceeded,
    /// The guest used memory with insufficient region permissions.
    #[codec(index = 2)]
    MemoryAccessViolation,
    /// The guest used an improperly aligned address.
    #[codec(index = 3)]
    MisalignedAccess,
    /// The guest accessed outside the VM memory domain.
    #[codec(index = 4)]
    MemoryOutOfBounds,
    /// Executable instructions or host input could not be decoded.
    #[codec(index = 5)]
    DecodeError,
    /// An instruction opcode was not valid.
    #[codec(index = 6)]
    InvalidOpcode,
    /// The instruction selected an unknown syscall.
    #[codec(index = 7)]
    UnknownSyscall,
    /// The canonical host intentionally rejects this known syscall.
    #[codec(index = 8)]
    UnsupportedSyscall,
    /// A deterministic gas formula overflowed its canonical domain.
    #[codec(index = 9)]
    GasCostOverflow,
    /// A checked numeric operation failed with its exact ABI code.
    #[codec(index = 10)]
    Numeric(NumericFaultV1),
    /// A pointer envelope failed with its exact ABI code.
    #[codec(index = 11)]
    PointerAbi(PointerAbiFaultV1),
    /// A guest assertion failed.
    #[codec(index = 12)]
    AssertionFailed,
    /// The deterministic completed-cycle allowance was exhausted.
    #[codec(index = 13)]
    ExceededMaxCycles,
    /// Guest-selected metadata was invalid during execution.
    #[codec(index = 14)]
    InvalidMetadata,
    /// The guest selected an invalid logical vector length.
    #[codec(index = 15)]
    InvalidVectorLength,
    /// The executable stream ended without a terminating instruction.
    #[codec(index = 16)]
    MissingHalt,
    /// The artifact did not enable the requested vector extension.
    #[codec(index = 17)]
    VectorExtensionDisabled,
    /// The artifact did not enable the requested ZK extension.
    #[codec(index = 18)]
    ZkExtensionDisabled,
    /// The replicated state already contains the nullifier.
    #[codec(index = 19)]
    NullifierAlreadyUsed,
    /// The running guest attempted an unauthorized operation.
    #[codec(index = 20)]
    PermissionDenied,
    /// The guest violated deterministic privacy-tag rules.
    #[codec(index = 21)]
    PrivacyViolation,
    /// The guest selected a register outside the VM register domain.
    #[codec(index = 22)]
    RegisterOutOfBounds,
    /// A canonical Norito envelope or value was invalid.
    #[codec(index = 23)]
    NoritoInvalid,
    /// The selected pointer type is not allowed by ABI V1.
    #[codec(index = 24)]
    AbiTypeNotAllowed,
    /// The retained effect count exceeded the consensus limit.
    #[codec(index = 25)]
    HostOutputItemsExceeded,
    /// The retained effect bytes exceeded the consensus limit.
    #[codec(index = 26)]
    HostOutputBytesExceeded,
    /// The deterministic static AMX estimate exceeded its governed budget.
    #[codec(index = 27)]
    AmxBudgetExceeded,
    /// A nested call targeted an already active contract address.
    #[codec(index = 28)]
    ReentrantCall,
    /// A nested call exceeded the canonical call-depth limit.
    #[codec(index = 29)]
    CallDepthExceeded,
}
impl core::fmt::Display for IvmFaultV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:?} in {} {:?} at {:?}",
            self.kind, self.site.code_hash, self.site.selector, self.site.position
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_roundtrip_exact_binary_json_and_reject_unbounded_fields() {
        let mut kinds = vec![
            IvmFaultKindV1::OutOfGas,
            IvmFaultKindV1::MemoryLimitExceeded,
            IvmFaultKindV1::MemoryAccessViolation,
            IvmFaultKindV1::MisalignedAccess,
            IvmFaultKindV1::MemoryOutOfBounds,
            IvmFaultKindV1::DecodeError,
            IvmFaultKindV1::InvalidOpcode,
            IvmFaultKindV1::UnknownSyscall,
            IvmFaultKindV1::UnsupportedSyscall,
            IvmFaultKindV1::GasCostOverflow,
            IvmFaultKindV1::Numeric(NumericFaultV1::DivisionByZero),
            IvmFaultKindV1::PointerAbi(PointerAbiFaultV1::WrongType),
            IvmFaultKindV1::AssertionFailed,
            IvmFaultKindV1::ExceededMaxCycles,
            IvmFaultKindV1::InvalidMetadata,
            IvmFaultKindV1::InvalidVectorLength,
            IvmFaultKindV1::MissingHalt,
            IvmFaultKindV1::VectorExtensionDisabled,
            IvmFaultKindV1::ZkExtensionDisabled,
            IvmFaultKindV1::NullifierAlreadyUsed,
            IvmFaultKindV1::PermissionDenied,
            IvmFaultKindV1::PrivacyViolation,
            IvmFaultKindV1::RegisterOutOfBounds,
            IvmFaultKindV1::NoritoInvalid,
            IvmFaultKindV1::AbiTypeNotAllowed,
            IvmFaultKindV1::HostOutputItemsExceeded,
            IvmFaultKindV1::HostOutputBytesExceeded,
            IvmFaultKindV1::AmxBudgetExceeded,
            IvmFaultKindV1::ReentrantCall,
            IvmFaultKindV1::CallDepthExceeded,
        ];
        kinds.extend(
            (1..=13).map(|tag| IvmFaultKindV1::Numeric(NumericFaultV1::from_tag(tag).unwrap())),
        );
        kinds.extend(
            (1..=11)
                .map(|tag| IvmFaultKindV1::PointerAbi(PointerAbiFaultV1::from_tag(tag).unwrap())),
        );
        for kind in kinds {
            for selector in [
                IvmInvocationSelectorV1::Generic,
                IvmInvocationSelectorV1::Entrypoint(u32::MAX),
            ] {
                for position in [
                    IvmFaultPositionV1::Initialization,
                    IvmFaultPositionV1::Execute {
                        pc_offset: u64::MAX,
                    },
                    IvmFaultPositionV1::ReturnValidation,
                ] {
                    let fault = IvmFaultV1 {
                        kind,
                        site: IvmFaultSiteV1 {
                            code_hash: iroha_crypto::Hash::new(b"exact artifact"),
                            selector,
                            position,
                        },
                    };
                    let bytes = norito::to_bytes(&fault).unwrap();
                    assert!(
                        bytes.len() <= 1024,
                        "fixed fault fields must remain bounded"
                    );
                    assert_eq!(
                        norito::decode_from_bytes::<IvmFaultV1>(&bytes).unwrap(),
                        fault
                    );
                    let json = norito::json::to_json(&fault).unwrap();
                    assert!(json.len() <= 1024);
                    assert_eq!(norito::json::from_json::<IvmFaultV1>(&json).unwrap(), fault);
                    assert_eq!(
                        norito::json::to_json_bounded(&fault, json.len()).unwrap(),
                        json
                    );
                    assert!(norito::json::to_json_bounded(&fault, json.len() - 1).is_err());
                    let injected = json.replacen('{', "{\"message\":\"untrusted\",", 1);
                    assert!(norito::json::from_json::<IvmFaultV1>(&injected).is_err());
                }
            }
        }
    }

    #[test]
    fn runtime_fault_codec_indices_are_complete_and_explicit() {
        let source = include_str!("fault.rs");
        let body = source
            .split_once("pub enum IvmFaultKindV1 {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let lines: Vec<_> = body.lines().map(str::trim).collect();
        let actual: Vec<_> = lines
            .windows(2)
            .filter_map(|pair| {
                let index = pair[0]
                    .strip_prefix("#[codec(index = ")?
                    .strip_suffix(")]")?
                    .parse::<u32>()
                    .unwrap();
                let name = pair[1].split(['(', ',']).next().unwrap();
                Some((index, name))
            })
            .collect();
        let names = [
            "OutOfGas",
            "MemoryLimitExceeded",
            "MemoryAccessViolation",
            "MisalignedAccess",
            "MemoryOutOfBounds",
            "DecodeError",
            "InvalidOpcode",
            "UnknownSyscall",
            "UnsupportedSyscall",
            "GasCostOverflow",
            "Numeric",
            "PointerAbi",
            "AssertionFailed",
            "ExceededMaxCycles",
            "InvalidMetadata",
            "InvalidVectorLength",
            "MissingHalt",
            "VectorExtensionDisabled",
            "ZkExtensionDisabled",
            "NullifierAlreadyUsed",
            "PermissionDenied",
            "PrivacyViolation",
            "RegisterOutOfBounds",
            "NoritoInvalid",
            "AbiTypeNotAllowed",
            "HostOutputItemsExceeded",
            "HostOutputBytesExceeded",
            "AmxBudgetExceeded",
            "ReentrantCall",
            "CallDepthExceeded",
        ];
        let expected: Vec<_> = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| (u32::try_from(index).unwrap(), name))
            .collect();
        assert_eq!(
            actual, expected,
            "fault schema changes require an intentional ABI descriptor change"
        );
    }

    #[test]
    fn exact_numeric_json_preserves_the_existing_abi_code() {
        assert_eq!(NumericFaultV1::DivisionByZero.tag(), 3);
        assert_eq!(
            norito::json::to_json(&IvmFaultKindV1::Numeric(NumericFaultV1::DivisionByZero))
                .unwrap(),
            r#"{"kind":"Numeric","value":{"kind":"DivisionByZero","value":null}}"#
        );
        assert!(
            norito::json::from_json::<IvmFaultKindV1>(r#"{"kind":"Other","value":null}"#).is_err()
        );
    }
}
