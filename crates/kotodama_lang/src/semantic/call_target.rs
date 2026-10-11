//! Resolved call identities retained through typed analysis and IR lowering.
use super::*;

/// A call identity chosen by resolution, never inferred from a lowered name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallTarget {
    /// A source function, renamed only by the module linker.
    User(String),
    /// An exact public method from an admitted compiled contract.
    Contract(ContractMethod),
    /// A registry builtin selected through its canonical source surface.
    Builtin(Builtin),
    /// An operation emitted exclusively by typed semantic lowering.
    Intrinsic(CompilerIntrinsic),
}
impl CallTarget {
    /// Diagnostic spelling of this already-resolved target.
    pub fn name(&self) -> &str {
        match self {
            Self::User(name) => name,
            Self::Contract(method) => &method.descriptor().name,
            Self::Builtin(builtin) => builtin.name(),
            Self::Intrinsic(intrinsic) => intrinsic.name(),
        }
    }
    /// Return the registry identity only for a builtin call.
    pub const fn builtin(&self) -> Option<Builtin> {
        match self {
            Self::Builtin(builtin) => Some(*builtin),
            _ => None,
        }
    }
    /// Return the source function identity only for a user call.
    pub fn user_name(&self) -> Option<&str> {
        match self {
            Self::User(name) => Some(name),
            _ => None,
        }
    }
    /// Return the lowering identity only for a compiler intrinsic.
    pub const fn intrinsic(&self) -> Option<CompilerIntrinsic> {
        match self {
            Self::Intrinsic(intrinsic) => Some(*intrinsic),
            _ => None,
        }
    }
    /// Whether this operation evaluates its error argument only on failure.
    pub const fn is_lazy_sum_error(&self) -> bool {
        matches!(
            self,
            Self::Intrinsic(
                CompilerIntrinsic::Expect
                    | CompilerIntrinsic::OptionOkOr
                    | CompilerIntrinsic::ResultOrErr
            )
        )
    }
}
impl std::fmt::Display for CallTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}
/// Closed vocabulary of compiler operations that are not source function names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerIntrinsic {
    /// Bind an address to its immutable compile-time contract interface.
    ContractAt,
    /// Emit one authenticated native event through its canonical typed record.
    EmitEvent,
    /// Compiler operation `STATE_MAP_GET_INTRINSIC`.
    StateMapGet,
    /// Compiler operation `STATE_PAGE_INTRINSIC`.
    StatePage,
    /// Compiler operation `STATE_TAKE_INTRINSIC`.
    StateTake,
    /// Compiler operation `LIST_LEN_INTRINSIC`.
    ListLen,
    /// Compiler operation `LIST_GET_INTRINSIC`.
    ListGet,
    /// Compiler operation `LIST_SET_INTRINSIC`.
    ListSet,
    /// Compiler operation `LIST_PUSH_INTRINSIC`.
    ListPush,
    /// Compiler operation `LIST_TRY_SET_INTRINSIC`.
    ListTrySet,
    /// Compiler operation `LIST_TRY_PUSH_INTRINSIC`.
    ListTryPush,
    /// Compiler operation `LIST_POP_INTRINSIC`.
    ListPop,
    /// Compiler operation `LIST_CONTAINS_INTRINSIC`.
    ListContains,
    /// Compiler operation `LIST_TAKE_INTRINSIC`.
    ListTake,
    /// Compiler operation `LIST_ENUMERATE_INTRINSIC`.
    ListEnumerate,
    /// Fresh outer-list copy at an argument or return capacity boundary.
    ListWiden,
    /// Compiler operation `DECIMAL_MUL_DIV_ROUND_INTRINSIC`.
    DecimalMulDivRound,
    /// Compiler operation `QUANTITY_MUL_DIV_ROUND_INTRINSIC`.
    QuantityMulDivRound,
    /// Compiler operation `DECIMAL_DIV_ROUND_INTRINSIC`.
    DecimalDivRound,
    /// Compiler operation `QUANTITY_DIV_ROUND_INTRINSIC`.
    QuantityDivRound,
    /// Compiler operation `QUANTITY_RATIO_ROUND_INTRINSIC`.
    QuantityRatioRound,
    /// Compiler operation `DECIMAL_TO_INT_TRUNC_INTRINSIC`.
    DecimalToIntTrunc,
    /// Compiler operation `DECIMAL_TO_INT_ROUND_INTRINSIC`.
    DecimalToIntRound,
    /// Compiler operation `OPTION_OK_OR_INTRINSIC`.
    OptionOkOr,
    /// Compiler operation `RESULT_OR_ERR_INTRINSIC`.
    ResultOrErr,
    /// Compiler operation `is_some`.
    IsSome,
    /// Compiler operation `is_none`.
    IsNone,
    /// Compiler operation `is_ok`.
    IsOk,
    /// Compiler operation `is_err`.
    IsErr,
    /// Compiler operation `unwrap_or`.
    UnwrapOr,
    /// Compiler operation `unwrap_err_or`.
    UnwrapErrOr,
    /// Compiler operation `expect`.
    Expect,
}
impl CompilerIntrinsic {
    /// Internal diagnostic spelling; this does not expose a callable source alias.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ContractAt => "<contract reference>",
            Self::EmitEvent => "emit",
            Self::StateMapGet => STATE_MAP_GET_INTRINSIC,
            Self::StatePage => STATE_PAGE_INTRINSIC,
            Self::StateTake => STATE_TAKE_INTRINSIC,
            Self::ListLen => LIST_LEN_INTRINSIC,
            Self::ListGet => LIST_GET_INTRINSIC,
            Self::ListSet => LIST_SET_INTRINSIC,
            Self::ListPush => LIST_PUSH_INTRINSIC,
            Self::ListTrySet => LIST_TRY_SET_INTRINSIC,
            Self::ListTryPush => LIST_TRY_PUSH_INTRINSIC,
            Self::ListPop => LIST_POP_INTRINSIC,
            Self::ListContains => LIST_CONTAINS_INTRINSIC,
            Self::ListTake => LIST_TAKE_INTRINSIC,
            Self::ListEnumerate => LIST_ENUMERATE_INTRINSIC,
            Self::ListWiden => "<list capacity widening>",
            Self::DecimalMulDivRound => DECIMAL_MUL_DIV_ROUND_INTRINSIC,
            Self::QuantityMulDivRound => QUANTITY_MUL_DIV_ROUND_INTRINSIC,
            Self::DecimalDivRound => DECIMAL_DIV_ROUND_INTRINSIC,
            Self::QuantityDivRound => QUANTITY_DIV_ROUND_INTRINSIC,
            Self::QuantityRatioRound => QUANTITY_RATIO_ROUND_INTRINSIC,
            Self::DecimalToIntTrunc => DECIMAL_TO_INT_TRUNC_INTRINSIC,
            Self::DecimalToIntRound => DECIMAL_TO_INT_ROUND_INTRINSIC,
            Self::OptionOkOr => OPTION_OK_OR_INTRINSIC,
            Self::ResultOrErr => RESULT_OR_ERR_INTRINSIC,
            Self::IsSome => "is_some",
            Self::IsNone => "is_none",
            Self::IsOk => "is_ok",
            Self::IsErr => "is_err",
            Self::UnwrapOr => "unwrap_or",
            Self::UnwrapErrOr => "unwrap_err_or",
            Self::Expect => "expect",
        }
    }
}
impl std::fmt::Display for CompilerIntrinsic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Resolved imported method; its declaration never depends on a source spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractMethod {
    /// Admitted complete contract interface and artifact identity.
    pub contract: Arc<ImportedContractInterface>,
    /// Exact ordinal in the authenticated public entrypoint table.
    pub entrypoint: u32,
}
impl ContractMethod {
    /// Exact target declaration selected by semantic analysis.
    pub fn descriptor(&self) -> &ivm_abi::metadata::EmbeddedEntrypointDescriptor {
        &self.contract.interface.entrypoints[self.entrypoint as usize]
    }
}
