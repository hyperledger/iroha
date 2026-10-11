//! Typed local-test rejection expectations and assertion sites shared by the compiler and the
//! in-process runner.
use iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor;
use ivm_abi::error::VmTrapKind;

/// Exact reason requested by a test-only nested invocation.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "kotodama_lang::testing::RejectionExpectation")]
pub enum RejectionExpectation {
    /// Explicitly accept any rejection through `test::expect_any_reject_as`.
    Any,
    /// Invocation did not have the required entrypoint permission.
    PermissionDenied,
    /// Input could not be encoded against the declared argument schema.
    InvalidArguments,
    /// Runtime emitted the specified nominal contract error and variant.
    Contract {
        /// Complete expected nominal error schema.
        descriptor: ContractErrorTypeDescriptor,
        /// Exact enum-local variant code.
        code: u32,
    },
    /// Runtime reached the specifically selected VM trap category.
    Trap(RejectionTrap),
}

macro_rules! rejection_traps {
    ($($name:ident => $trap:ident),+ $(,)?) => {
        /// Compiler-owned runtime-trap selectors; contract errors require nominal variants.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode)]
        pub enum RejectionTrap {
            $(#[doc = concat!("Require the `", stringify!($trap), "` runtime trap.")]
            $name,)+
        }
        impl RejectionTrap {
            /// Exact VM category selected by this constant.
            pub const fn trap_kind(self) -> VmTrapKind {
                match self { $(Self::$name => VmTrapKind::$trap,)+ }
            }
            /// Canonical source spelling of this test-only selector.
            pub const fn source_name(self) -> &'static str {
                match self { $(Self::$name => concat!("test::Rejection::", stringify!($name)),)+ }
            }
        }
        /// Every accepted exact test selector, including pre-runtime rejection stages.
        pub const REJECTION_SELECTORS: &[&str] = &[
            "test::Rejection::PermissionDenied", "test::Rejection::InvalidArguments",
            $(concat!("test::Rejection::", stringify!($name)),)+
        ];
        impl RejectionExpectation {
            /// Resolve a compiler-owned stage or runtime-trap literal.
            pub fn from_selector(name: &str) -> Option<Self> {
                Some(match name {
                    "test::Rejection::PermissionDenied" => Self::PermissionDenied,
                    "test::Rejection::InvalidArguments" => Self::InvalidArguments,
                    $(concat!("test::Rejection::", stringify!($name)) => Self::Trap(RejectionTrap::$name),)+
                    _ => return None,
                })
            }
        }
    };
}
rejection_traps! {
    OutOfGas => OutOfGas, OutOfMemory => OutOfMemory, MemoryFault => MemoryFault,
    DecodeError => DecodeError, InvalidOpcode => InvalidOpcode, UnknownSyscall => UnknownSyscall,
    NotImplemented => NotImplemented, SyscallGasQuoteExceeded => SyscallGasQuoteExceeded,
    SyscallMeteringModeMismatch => SyscallMeteringModeMismatch, GasCostOverflow => GasCostOverflow,
    NumericFault => NumericFault, PointerAbiFault => PointerAbiFault,
    AssertionFailed => AssertionFailed, ExceededMaxCycles => ExceededMaxCycles,
    InvalidMetadata => InvalidMetadata, UnsupportedProgramVersion => UnsupportedProgramVersion,
    UnsupportedProgramFeatureBits => UnsupportedProgramFeatureBits,
    UnsupportedProgramAbiVersion => UnsupportedProgramAbiVersion,
    ProgramVectorLengthTooLarge => ProgramVectorLengthTooLarge,
    ArtifactAbiHashMismatch => ArtifactAbiHashMismatch,
    GenericSyscallNotAllowed => GenericSyscallNotAllowed, InvalidVectorLength => InvalidVectorLength,
    MissingHalt => MissingHalt, RuntimePermissionDenied => PermissionDenied,
    PrivacyViolation => PrivacyViolation, RegisterOutOfBounds => RegisterOutOfBounds,
    NoritoInvalid => NoritoInvalid, AbiTypeNotAllowed => AbiTypeNotAllowed,
    HostOutputBudgetExceeded => HostOutputBudgetExceeded, AmxBudgetExceeded => AmxBudgetExceeded,
}
/// Which local-test assertion failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::Encode, norito::Decode)]
pub enum AssertionKind {
    /// `test::assert(condition, message:)`.
    Assert,
    /// `test::assert_eq(actual:, expected:, message:)`.
    AssertEq,
}
/// Compiler-emitted description of one `test::assert` or `test::assert_eq` call site.
///
/// Test-mode lowering embeds the canonical Norito encoding of this record in the test projection
/// and hands it to the host-private assertion syscall only when the assertion fails, so the
/// runner can report the exact source location, the asserted source text, the author's literal
/// message, and the compared values. The record never appears in production artifacts.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "kotodama_lang::testing::AssertionSite")]
pub struct AssertionSite {
    /// Which assertion builtin failed.
    pub kind: AssertionKind,
    /// Compiler source identity of the file containing the call.
    pub source_id: u32,
    /// First UTF-8 byte of the call expression.
    pub byte_start: u32,
    /// UTF-8 byte after the call expression.
    pub byte_end: u32,
    /// The `message:` argument when it is a string literal.
    pub message: Option<String>,
    /// Kotodama type of the compared values for `test::assert_eq`.
    pub value_type: Option<String>,
}
impl AssertionSite {
    /// Largest encoded site record accepted by the host.
    pub const MAX_ENCODED_BYTES: usize = 16 * 1024;
}
/// Compiler-emitted source location of one `test::` helper call (`invoke_kotoage`,
/// `expect_reject_as`, `actor_account`, ...).
///
/// Test-mode lowering hands the canonical Norito encoding of this record to the host-private
/// call-site helper immediately before the helper call it describes, so a failing seiyaku call or
/// a misused fixture actor is reported at the call's own `file:line:column` rather than at the
/// enclosing test declaration. The record never appears in production artifacts.
#[derive(Clone, Debug, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "kotodama_lang::testing::TestCallSite")]
pub struct TestCallSite {
    /// Compiler source identity of the file containing the call.
    pub source_id: u32,
    /// First UTF-8 byte of the call expression.
    pub byte_start: u32,
    /// UTF-8 byte after the call expression.
    pub byte_end: u32,
}
impl TestCallSite {
    /// Largest encoded call-site record accepted by the host.
    pub const MAX_ENCODED_BYTES: usize = 256;
}
impl RejectionExpectation {
    /// Compare an observed runtime failure without matching human-readable error text.
    pub fn matches_runtime(&self, error: &ivm_abi::VMError, trap: Option<VmTrapKind>) -> bool {
        match self {
            Self::Any => true,
            Self::Contract { descriptor, code } => matches!(error.as_unmetered(),
                ivm_abi::VMError::ContractAbort { error_type, schema_hash, code: actual, .. }
                    if error_type == &descriptor.identity && schema_hash == &descriptor.schema_hash() && actual == code),
            Self::Trap(expected) => trap == Some(expected.trap_kind()),
            Self::PermissionDenied | Self::InvalidArguments => false,
        }
    }
    /// Validate decoded expectations before running any nested contract.
    pub fn validate(&self) -> bool {
        match self {
            Self::Contract { descriptor, code } => {
                descriptor.validate() && descriptor.variant(*code).is_some()
            }
            _ => true,
        }
    }
    /// Human-readable expected reason, preserving its nominal namespace.
    pub fn description(&self) -> String {
        match self {
            Self::Any => "any rejection (explicitly requested)".to_owned(),
            Self::PermissionDenied => "invocation PermissionDenied".to_owned(),
            Self::InvalidArguments => "argument-schema InvalidArguments".to_owned(),
            Self::Trap(trap) => trap.source_name().to_owned(),
            Self::Contract { descriptor, code } => format!(
                "{}::{} (code {code})",
                descriptor.identity,
                descriptor
                    .variant(*code)
                    .map_or("<invalid>", |variant| variant.name.as_str())
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assertion_sites_roundtrip_the_canonical_codec() {
        for site in [
            AssertionSite {
                kind: AssertionKind::Assert,
                source_id: 7,
                byte_start: 10,
                byte_end: 40,
                message: Some("balance should be 5 after init".to_owned()),
                value_type: None,
            },
            AssertionSite {
                kind: AssertionKind::AssertEq,
                source_id: 0,
                byte_start: 0,
                byte_end: 1,
                message: None,
                value_type: Some("Option<int>".to_owned()),
            },
        ] {
            let bytes = ivm_abi::codec::encode_canonical_norito(&site).expect("encode site");
            assert!(bytes.len() < AssertionSite::MAX_ENCODED_BYTES);
            let decoded: AssertionSite = norito::decode_canonical(&bytes).expect("decode site");
            assert_eq!(decoded, site);
        }
    }
    #[test]
    fn call_sites_roundtrip_the_canonical_codec() {
        for site in [
            TestCallSite {
                source_id: 0,
                byte_start: 0,
                byte_end: 0,
            },
            TestCallSite {
                source_id: u32::MAX,
                byte_start: 1_048_000,
                byte_end: u32::MAX,
            },
        ] {
            let bytes = ivm_abi::codec::encode_canonical_norito(&site).expect("encode call site");
            assert!(bytes.len() <= TestCallSite::MAX_ENCODED_BYTES);
            let decoded: TestCallSite = norito::decode_canonical(&bytes).expect("decode call site");
            assert_eq!(decoded, site);
        }
    }
    #[test]
    fn selector_inventory_is_exact_and_roundtrips_the_canonical_codec() {
        for name in REJECTION_SELECTORS {
            let expected = RejectionExpectation::from_selector(name).expect("registered selector");
            let bytes =
                ivm_abi::codec::encode_canonical_norito(&expected).expect("encode expectation");
            let decoded: RejectionExpectation =
                norito::decode_canonical(&bytes).expect("decode expectation");
            assert_eq!(expected, decoded);
            assert!(decoded.validate());
            assert!(!decoded.description().is_empty());
        }
        assert!(RejectionExpectation::from_selector("test::Rejection::ContractAbort").is_none());
        assert!(RejectionExpectation::from_selector("PermissionDenied").is_none());
    }
    #[test]
    fn nominal_expectations_validate_the_exact_variant_schema() {
        let descriptor = ivm_abi::error_types::list_error_type();
        let expected = RejectionExpectation::Contract {
            code: descriptor.variants[0].code,
            descriptor: descriptor.clone(),
        };
        assert!(expected.validate());
        assert!(expected.description().contains(&descriptor.identity));
        assert!(
            !RejectionExpectation::Contract {
                descriptor,
                code: 0
            }
            .validate()
        );
        assert!(RejectionExpectation::Any.validate());
    }
    #[test]
    fn matching_retains_nominal_identity_schema_and_stage_boundaries() {
        let descriptor = ivm_abi::error_types::list_error_type();
        let code = descriptor.variants[0].code;
        let expected = RejectionExpectation::Contract {
            descriptor: descriptor.clone(),
            code,
        };
        let error = ivm_abi::VMError::ContractAbort {
            contract: "test".into(),
            name: "Failure".to_owned(),
            message: None,
            error_type: descriptor.identity.clone(),
            schema_hash: descriptor.schema_hash(),
            code,
        };
        assert!(expected.matches_runtime(&error, Some(VmTrapKind::ContractAbort)));
        assert!(expected.matches_runtime(
            &ivm_abi::VMError::Metered {
                gas: 1,
                source: Box::new(error.clone())
            },
            Some(VmTrapKind::ContractAbort)
        ));
        let wrong_type = ivm_abi::VMError::ContractAbort {
            message: None,
            contract: "test".into(),
            name: "Failure".to_owned(),
            error_type: "Other".to_owned(),
            schema_hash: descriptor.schema_hash(),
            code,
        };
        let wrong_schema = ivm_abi::VMError::ContractAbort {
            message: None,
            contract: "test".into(),
            name: "Failure".to_owned(),
            error_type: descriptor.identity.clone(),
            schema_hash: [0; 32],
            code,
        };
        let wrong_code = ivm_abi::VMError::ContractAbort {
            message: None,
            contract: "test".into(),
            name: "Failure".to_owned(),
            error_type: descriptor.identity.clone(),
            schema_hash: descriptor.schema_hash(),
            code: code + 1,
        };
        for error in [
            wrong_type,
            wrong_schema,
            wrong_code,
            ivm_abi::VMError::OutOfGas,
        ] {
            assert!(!expected.matches_runtime(&error, Some(VmTrapKind::ContractAbort)));
        }
        assert!(!RejectionExpectation::PermissionDenied.matches_runtime(
            &ivm_abi::VMError::PermissionDenied,
            Some(VmTrapKind::PermissionDenied)
        ));
        assert!(
            RejectionExpectation::Trap(RejectionTrap::OutOfGas)
                .matches_runtime(&ivm_abi::VMError::OutOfGas, Some(VmTrapKind::OutOfGas))
        );
        assert!(RejectionExpectation::Any.matches_runtime(&ivm_abi::VMError::OutOfGas, None));
    }
}

#[cfg(test)]
mod frame_identity_tests;
